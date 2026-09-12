// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package naming provides name ownership verification for OASF records.
// A record name carries a protocol prefix that selects the verification
// method: JWKS well-known files (RFC 7517, inspired by AT Protocol) for
// https:// and http:// names, and the Agent Name Service transparency log
// for ans:// names.
package naming

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PublicKey represents a public key published for a name's owner.
type PublicKey struct {
	// ID is an optional identifier for the key (kid in JWK, or the certificate
	// fingerprint for ANS).
	ID string

	// Type is the key algorithm (e.g., "ed25519", "ecdsa-p256", "rsa").
	Type string

	// Key is the raw public key bytes in DER format for comparison.
	Key []byte

	// KeyBase64 is the original base64-encoded key string.
	KeyBase64 string
}

// Signer is one party that signed the record: the public key that produced
// the signature, as DER SubjectPublicKeyInfo, and, when the signature carried
// one, the DER X.509 certificate holding that key.
type Signer struct {
	Key         []byte
	Certificate []byte
}

// Evidence is the record-side material a verification method may consult in
// addition to the name.
type Evidence struct {
	// Certificates are the DER certificates attached to the record's signatures.
	Certificates [][]byte
}

// LookupResult is what a MethodLookup returns for a name.
type LookupResult struct {
	// Keys are the public keys the name's owner is authorized to sign with.
	Keys []PublicKey

	// Details is method-specific JSON persisted alongside a successful
	// verification. Nil when the method records none.
	Details json.RawMessage
}

// Result represents the outcome of a name verification attempt.
type Result struct {
	// Verified is true if a signing key matches a key published for the name.
	Verified bool

	// Domain is the domain that was verified.
	Domain string

	// Method is the verification method that was attempted ("wellknown",
	// "ans"), or "none" when the name selects no method.
	Method string

	// Error contains the error message if verification failed.
	Error string

	// MatchedKeyID is the ID of the key that matched (if available).
	MatchedKeyID string

	// Details is the method's JSON to persist with a verified result.
	Details json.RawMessage

	// Transient reports a failure caused by an unavailable dependency rather
	// than by the record, so the caller should retry soon instead of recording
	// a verdict. Only ever set together with Verified == false.
	Transient bool

	// RetryAfter is the earliest time the method wants the caller to retry a
	// transient failure. Zero when the method leaves the schedule to the caller.
	RetryAfter time.Time
}

// VerificationMethod represents the method used to verify name ownership.
type VerificationMethod string

const (
	// MethodWellKnown indicates verification via JWKS well-known file (RFC 7517).
	MethodWellKnown VerificationMethod = "wellknown"

	// MethodANS indicates verification via the Agent Name Service transparency log.
	MethodANS VerificationMethod = "ans"

	// MethodNone indicates no verification was possible.
	MethodNone VerificationMethod = "none"
)

// ErrTransient marks a lookup failure caused by an unavailable dependency
// (DNS, a transparency log) rather than by the record. Methods wrap it into
// the errors they return; Verify turns it into Result.Transient.
var ErrTransient = errors.New("transient verification failure")

// Transient marks err as caused by an unavailable dependency rather than by the
// record: errors.Is(err, ErrTransient) reports it and the text is unchanged.
func Transient(err error) *TransientError {
	return &TransientError{err: err}
}

// TransientError is the marker Transient wraps an error in.
type TransientError struct {
	err error
}

func (e *TransientError) Error() string {
	return e.err.Error()
}

func (e *TransientError) Unwrap() error {
	return e.err
}

// Is reports the error as transient.
func (e *TransientError) Is(target error) bool {
	return target == ErrTransient //nolint:errorlint // sentinel identity is the contract of an Is method
}

// RetryAfterError is a transient failure that also names the earliest time a
// retry makes sense, for example while a method's circuit breaker for a
// dependency is open. It matches ErrTransient in errors.Is.
type RetryAfterError struct {
	// Until is when the caller should retry.
	Until time.Time

	// Err is the underlying failure.
	Err error
}

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("%v (retry after %s)", e.Err, e.Until.UTC().Format(time.RFC3339))
}

// Unwrap returns the underlying failure.
func (e *RetryAfterError) Unwrap() error {
	return e.Err
}

// Is reports the error as transient.
func (e *RetryAfterError) Is(target error) bool {
	return target == ErrTransient //nolint:errorlint // sentinel identity is the contract of an Is method
}
