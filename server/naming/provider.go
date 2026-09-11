// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"

	"github.com/agntcy/dir/utils/logging"
)

var providerLogger = logging.Logger("naming/provider")

// KeyLookupWithScheme defines the interface for looking up public keys with a URL scheme.
type KeyLookupWithScheme interface {
	// LookupKeysWithScheme retrieves public keys for the given domain using the specified scheme.
	LookupKeysWithScheme(ctx context.Context, domain, scheme string) ([]PublicKey, error)
}

// MethodLookup resolves the keys a name's owner may sign with. One
// implementation is registered per protocol prefix. The provider then checks
// that one of the record's signers holds a returned key; for a method that
// derives its keys from the signers' own certificates that check is a
// consistency check, not the trust decision.
type MethodLookup interface {
	// Method names the verification method for results and logs.
	Method() VerificationMethod

	// LookupKeys returns the owner's published keys for the name. A nil error
	// comes with a non-nil result. Failures caused by an unavailable
	// dependency rather than by the record wrap ErrTransient so the caller
	// can retry instead of recording a verdict.
	LookupKeys(ctx context.Context, name *ParsedName, evidence Evidence) (*LookupResult, error)
}

// Provider handles name ownership verification for OASF records.
// It routes to the verification method registered for the name's protocol prefix.
type Provider struct {
	lookups map[string]MethodLookup
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithLookup registers the verification method for a protocol prefix such as
// ANSProtocol. A later registration for the same prefix replaces the earlier
// one; a nil lookup leaves the prefix unregistered. The prefix must be one
// ParseName recognizes, otherwise the method could never be reached, so an
// unknown prefix is a wiring mistake and panics.
func WithLookup(protocol string, lookup MethodLookup) ProviderOption {
	if !slices.Contains(verifiablePrefixes, protocol) {
		panic(fmt.Sprintf("naming: no name grammar for protocol prefix %q", protocol))
	}

	return func(p *Provider) {
		if lookup == nil {
			return
		}

		p.lookups[protocol] = lookup
	}
}

// WithWellKnownLookup registers JWKS well-known verification for https:// and
// http:// names using the given fetcher. A nil fetcher registers nothing.
func WithWellKnownLookup(wk KeyLookupWithScheme) ProviderOption {
	return func(p *Provider) {
		if wk == nil {
			return
		}

		p.lookups[HTTPSProtocol] = wellKnownLookup{scheme: "https", fetcher: wk}
		p.lookups[HTTPProtocol] = wellKnownLookup{scheme: "http", fetcher: wk}
	}
}

// NewProvider creates a new naming provider with the given options.
func NewProvider(opts ...ProviderOption) *Provider {
	p := &Provider{lookups: make(map[string]MethodLookup)}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// Method names the verification method registered for a protocol prefix
// (HTTPSProtocol, ANSProtocol, ...), or MethodNone when none is.
func (p *Provider) Method(protocol string) VerificationMethod {
	lookup, ok := p.lookups[protocol]
	if !ok {
		return MethodNone
	}

	return lookup.Method()
}

// Verify checks whether one of the record's signers is authorized for the name.
// The protocol prefix of the record name selects the verification method:
//   - https://domain/path -> JWKS well-known file via HTTPS
//   - http://domain/path -> JWKS well-known file via HTTP (testing only)
//   - ans://v1.0.0.host/path -> Agent Name Service transparency log
//   - domain/path -> no verification (protocol prefix required)
//
// The method runs once per record with every signer's certificate as evidence;
// its published keys are then matched against every signer's key.
func (p *Provider) Verify(ctx context.Context, recordName string, signers []Signer) *Result {
	result := &Result{}

	parsed := ParseName(recordName)
	if parsed == nil {
		result.Method = string(MethodNone)
		result.Error = "could not parse record name"

		providerLogger.Debug("Name parsing failed", "recordName", recordName)

		return result
	}

	result.Domain = parsed.Domain
	providerLogger.Debug("Verifying name ownership",
		"domain", parsed.Domain,
		"protocol", parsed.Protocol,
		"recordName", recordName)

	lookup, ok := p.lookups[parsed.Protocol]
	if !ok {
		result.Method = string(MethodNone)
		result.Error = unconfiguredError(parsed.Protocol)

		providerLogger.Debug("No verification method for name", "domain", parsed.Domain, "protocol", parsed.Protocol)

		return result
	}

	result.Method = string(lookup.Method())

	if len(signers) == 0 {
		result.Error = "no signing keys attached to record"

		return result
	}

	lookupResult, err := lookup.LookupKeys(ctx, parsed, evidenceOf(signers))
	if err != nil {
		result.Error = err.Error()
		result.Transient = errors.Is(err, ErrTransient)

		if retry, ok := errors.AsType[*RetryAfterError](err); ok {
			result.RetryAfter = retry.Until
		}

		providerLogger.Debug("Key lookup failed", "domain", parsed.Domain, "method", result.Method, "transient", result.Transient, "error", err)

		return result
	}

	if lookupResult == nil || len(lookupResult.Keys) == 0 {
		result.Error = "no keys found for domain"

		providerLogger.Debug("No keys found for domain", "domain", parsed.Domain, "method", result.Method)

		return result
	}

	matchedKey := matchSigners(signers, lookupResult.Keys)
	if matchedKey == nil {
		result.Error = "signing key does not match any domain key"

		providerLogger.Debug("Key mismatch", "domain", parsed.Domain, "method", result.Method, "domainKeyCount", len(lookupResult.Keys))

		return result
	}

	result.Verified = true
	result.MatchedKeyID = matchedKey.ID
	result.Details = lookupResult.Details

	providerLogger.Info("Name ownership verified",
		"recordName", recordName,
		"domain", parsed.Domain,
		"method", result.Method,
		"keyID", matchedKey.ID,
		"keyType", matchedKey.Type)

	return result
}

// unconfiguredError explains why a name selected no verification method.
func unconfiguredError(protocol string) string {
	if protocol == "" {
		return "name has no protocol prefix"
	}

	return fmt.Sprintf("no verification method registered for protocol %q", protocol)
}

// evidenceOf collects the certificates attached to the signers.
func evidenceOf(signers []Signer) Evidence {
	var evidence Evidence

	for _, signer := range signers {
		if len(signer.Certificate) > 0 {
			evidence.Certificates = append(evidence.Certificates, signer.Certificate)
		}
	}

	return evidence
}

// matchSigners returns the first published key equal to any signer's key.
func matchSigners(signers []Signer, keys []PublicKey) *PublicKey {
	for _, signer := range signers {
		if len(signer.Key) == 0 {
			continue
		}

		if matched, ok := MatchKey(signer.Key, keys); ok {
			return matched
		}
	}

	return nil
}

// wellKnownLookup adapts a KeyLookupWithScheme to the MethodLookup interface
// for one URL scheme.
type wellKnownLookup struct {
	scheme  string
	fetcher KeyLookupWithScheme
}

func (l wellKnownLookup) Method() VerificationMethod {
	return MethodWellKnown
}

func (l wellKnownLookup) LookupKeys(ctx context.Context, name *ParsedName, _ Evidence) (*LookupResult, error) {
	keys, err := l.fetcher.LookupKeysWithScheme(ctx, name.Domain, l.scheme)
	if err != nil {
		if isNetworkFailure(err) {
			return nil, fmt.Errorf("%w: JWKS lookup failed: %w", ErrTransient, err)
		}

		return nil, fmt.Errorf("JWKS lookup failed: %w", err)
	}

	return &LookupResult{Keys: keys}, nil
}

// isNetworkFailure reports whether a JWKS fetch failed before the server
// answered: a resolver, dial, TLS or deadline problem rather than a missing or
// malformed key set.
func isNetworkFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if _, ok := errors.AsType[*url.Error](err); ok {
		return true
	}

	_, ok := errors.AsType[net.Error](err)

	return ok
}
