// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"context"
	"errors"
	"fmt"

	"github.com/agntcy/dir/utils/logging"
)

var providerLogger = logging.Logger("naming/provider")

// KeyLookupWithScheme defines the interface for looking up public keys with a URL scheme.
type KeyLookupWithScheme interface {
	// LookupKeysWithScheme retrieves public keys for the given domain using the specified scheme.
	LookupKeysWithScheme(ctx context.Context, domain, scheme string) ([]PublicKey, error)
}

// MethodLookup resolves the keys a name's owner may sign with. One
// implementation is registered per protocol prefix.
type MethodLookup interface {
	// Method names the verification method for results and logs.
	Method() VerificationMethod

	// LookupKeys returns the owner's published keys for the name. Failures
	// caused by an unavailable dependency rather than by the record wrap
	// ErrTransient so the caller can retry instead of recording a verdict.
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
// ANSProtocol. A later registration for the same prefix replaces the earlier one.
func WithLookup(protocol string, lookup MethodLookup) ProviderOption {
	return func(p *Provider) {
		p.lookups[protocol] = lookup
	}
}

// WithWellKnownLookup registers JWKS well-known verification for https:// and
// http:// names using the given fetcher.
func WithWellKnownLookup(wk KeyLookupWithScheme) ProviderOption {
	return func(p *Provider) {
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

// Supports reports whether a verification method is registered for the
// protocol prefix (HTTPSProtocol, ANSProtocol, ...).
func (p *Provider) Supports(protocol string) bool {
	_, ok := p.lookups[protocol]

	return ok
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

	if len(lookupResult.Keys) == 0 {
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
		"domain", parsed.Domain,
		"method", result.Method,
		"keyID", matchedKey.ID,
		"keyType", matchedKey.Type)

	return result
}

// unconfiguredError explains why a name selected no verification method.
func unconfiguredError(protocol string) string {
	switch protocol {
	case HTTPSProtocol, HTTPProtocol:
		return "JWKS verification not configured"
	case ANSProtocol:
		return "ANS verification not configured (reconciler name.ans.enabled / daemon reconciler.name.ans.enabled)"
	default:
		return "no verification protocol specified in name (use https://, http:// or ans:// prefix)"
	}
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
		return nil, fmt.Errorf("JWKS lookup failed: %w", err)
	}

	return &LookupResult{Keys: keys}, nil
}
