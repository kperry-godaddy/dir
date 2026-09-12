// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

var (
	errLookupFailed = errors.New("lookup failed")

	keyA  = []byte("key-a")
	keyB  = []byte("key-b")
	certA = []byte("cert-a")
	certB = []byte("cert-b")
)

// fakeSchemeLookup records the scheme it was called with and returns fixed keys.
type fakeSchemeLookup struct {
	keys   []PublicKey
	err    error
	scheme string
}

func (f *fakeSchemeLookup) LookupKeysWithScheme(_ context.Context, _, scheme string) ([]PublicKey, error) {
	f.scheme = scheme

	return f.keys, f.err
}

// fakeMethodLookup is a MethodLookup with scripted results.
type fakeMethodLookup struct {
	method   VerificationMethod
	result   *LookupResult
	err      error
	calls    int
	evidence Evidence
	name     *ParsedName
}

func (f *fakeMethodLookup) Method() VerificationMethod {
	return f.method
}

func (f *fakeMethodLookup) LookupKeys(_ context.Context, name *ParsedName, evidence Evidence) (*LookupResult, error) {
	f.calls++
	f.name = name
	f.evidence = evidence

	return f.result, f.err
}

// want is the subset of Result a test asserts on.
type want struct {
	verified   bool
	method     string
	keyID      string
	err        string
	transient  bool
	details    string
	retryAfter time.Time
}

func assertResult(t *testing.T, got *Result, w want) {
	t.Helper()

	if got.Verified != w.verified {
		t.Errorf("Verified = %v, want %v (error %q)", got.Verified, w.verified, got.Error)
	}

	if got.Method != w.method {
		t.Errorf("Method = %q, want %q", got.Method, w.method)
	}

	if got.MatchedKeyID != w.keyID {
		t.Errorf("MatchedKeyID = %q, want %q", got.MatchedKeyID, w.keyID)
	}

	if got.Error != w.err {
		t.Errorf("Error = %q, want %q", got.Error, w.err)
	}

	if got.Transient != w.transient {
		t.Errorf("Transient = %v, want %v", got.Transient, w.transient)
	}

	if string(got.Details) != w.details {
		t.Errorf("Details = %q, want %q", got.Details, w.details)
	}

	if !got.RetryAfter.Equal(w.retryAfter) {
		t.Errorf("RetryAfter = %v, want %v", got.RetryAfter, w.retryAfter)
	}

	if got.Verified && got.Transient {
		t.Errorf("Transient must never be set on a verified result")
	}
}

func TestProviderVerifyWellKnown(t *testing.T) {
	tests := []struct {
		name       string
		keys       []PublicKey
		lookupErr  error
		recordName string
		signers    []Signer
		want       want
		wantScheme string
	}{
		{
			name:       "https name verified",
			keys:       []PublicKey{{ID: "kid-1", Key: keyA}},
			recordName: "https://example.org/agent",
			signers:    []Signer{{Key: keyA}},
			want:       want{verified: true, method: "wellknown", keyID: "kid-1"},
			wantScheme: "https",
		},
		{
			name:       "http name uses the http scheme",
			keys:       []PublicKey{{ID: "kid-1", Key: keyA}},
			recordName: "http://localhost:8080/agent",
			signers:    []Signer{{Key: keyA}},
			want:       want{verified: true, method: "wellknown", keyID: "kid-1"},
			wantScheme: "http",
		},
		{
			name:       "any signer may match",
			keys:       []PublicKey{{ID: "kid-2", Key: keyB}},
			recordName: "https://example.org/agent",
			signers:    []Signer{{Key: keyA}, {Key: keyB}},
			want:       want{verified: true, method: "wellknown", keyID: "kid-2"},
			wantScheme: "https",
		},
		{
			name:       "no matching key records the attempted method",
			keys:       []PublicKey{{ID: "kid-1", Key: keyB}},
			recordName: "https://example.org/agent",
			signers:    []Signer{{Key: keyA}},
			want:       want{method: "wellknown", err: "signing key does not match any domain key"},
			wantScheme: "https",
		},
		{
			name:       "lookup error records the attempted method",
			lookupErr:  errLookupFailed,
			recordName: "https://example.org/agent",
			signers:    []Signer{{Key: keyA}},
			want:       want{method: "wellknown", err: "JWKS lookup failed: lookup failed"},
			wantScheme: "https",
		},
		{
			name:       "empty key set is a failure",
			recordName: "https://example.org/agent",
			signers:    []Signer{{Key: keyA}},
			want:       want{method: "wellknown", err: "no keys found for domain"},
			wantScheme: "https",
		},
		{
			name:       "no signers fails before any lookup",
			keys:       []PublicKey{{ID: "kid-1", Key: keyA}},
			recordName: "https://example.org/agent",
			want:       want{method: "wellknown", err: "no signing keys attached to record"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wk := &fakeSchemeLookup{keys: tt.keys, err: tt.lookupErr}
			provider := NewProvider(WithWellKnownLookup(wk))

			got := provider.Verify(context.Background(), tt.recordName, tt.signers)

			assertResult(t, got, tt.want)

			if wk.scheme != tt.wantScheme {
				t.Errorf("well-known scheme = %q, want %q", wk.scheme, tt.wantScheme)
			}
		})
	}
}

func TestProviderVerifyUnconfigured(t *testing.T) {
	tests := []struct {
		name       string
		options    []ProviderOption
		recordName string
		want       want
	}{
		{
			name:       "unparseable name",
			options:    []ProviderOption{WithWellKnownLookup(&fakeSchemeLookup{})},
			recordName: "invalid",
			want:       want{method: "none", err: "could not parse record name"},
		},
		{
			name:       "name without protocol selects no method",
			options:    []ProviderOption{WithWellKnownLookup(&fakeSchemeLookup{})},
			recordName: "example.org/agent",
			want:       want{method: "none", err: "name has no protocol prefix"},
		},
		{
			name:       "https name without well-known lookup",
			recordName: "https://example.org/agent",
			want:       want{method: "none", err: `no verification method registered for protocol "https://"`},
		},
		{
			name:       "ans name without ans lookup",
			options:    []ProviderOption{WithWellKnownLookup(&fakeSchemeLookup{})},
			recordName: "ans://v1.0.0.agent.example.com",
			want:       want{method: "none", err: `no verification method registered for protocol "ans://"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(tt.options...)

			got := provider.Verify(context.Background(), tt.recordName, []Signer{{Key: keyA}})

			assertResult(t, got, tt.want)
		})
	}
}

func TestProviderVerifyRegisteredMethod(t *testing.T) {
	details := json.RawMessage(`{"v":1,"agentId":"a"}`)
	retryAt := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		lookup  *fakeMethodLookup
		signers []Signer
		want    want
	}{
		{
			name: "verified with details",
			lookup: &fakeMethodLookup{
				method: MethodANS,
				result: &LookupResult{Keys: []PublicKey{{ID: "SHA256:aa", Key: keyA}}, Details: details},
			},
			signers: []Signer{{Key: keyA, Certificate: certA}},
			want:    want{verified: true, method: "ans", keyID: "SHA256:aa", details: string(details)},
		},
		{
			name: "transient failure",
			lookup: &fakeMethodLookup{
				method: MethodANS,
				err:    Transient(errors.New("ans dns: timeout")),
			},
			signers: []Signer{{Key: keyA, Certificate: certA}},
			want:    want{method: "ans", err: "ans dns: timeout", transient: true},
		},
		{
			name: "retry-after failure is transient and carries the time",
			lookup: &fakeMethodLookup{
				method: MethodANS,
				err:    fmt.Errorf("ans status-token: %w", &RetryAfterError{Until: retryAt, Err: errors.New("log host unreachable")}),
			},
			signers: []Signer{{Key: keyA, Certificate: certA}},
			want: want{
				method:     "ans",
				err:        "ans status-token: log host unreachable (retry after 2026-09-11T12:00:00Z)",
				transient:  true,
				retryAfter: retryAt,
			},
		},
		{
			name: "terminal failure is not transient",
			lookup: &fakeMethodLookup{
				method: MethodANS,
				err:    errors.New("ans certificate: no attached certificate names this agent"),
			},
			signers: []Signer{{Key: keyA}},
			want:    want{method: "ans", err: "ans certificate: no attached certificate names this agent"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(WithLookup(ANSProtocol, tt.lookup))

			got := provider.Verify(context.Background(), "ans://v1.0.0.agent.example.com/assistant", tt.signers)

			assertResult(t, got, tt.want)
		})
	}
}

func TestProviderVerifyPassesEvidenceOncePerRecord(t *testing.T) {
	ml := &fakeMethodLookup{
		method: MethodANS,
		result: &LookupResult{Keys: []PublicKey{{ID: "SHA256:aa", Key: keyA}}},
	}
	provider := NewProvider(WithLookup(ANSProtocol, ml))

	signers := []Signer{
		{Key: []byte("other"), Certificate: certA},
		{Key: keyA, Certificate: certB},
		{Key: []byte("no-certificate")},
	}

	got := provider.Verify(context.Background(), "ans://v1.0.0.agent.example.com", signers)

	if !got.Verified {
		t.Fatalf("Verified = false, error %q", got.Error)
	}

	if ml.calls != 1 {
		t.Errorf("lookup calls = %d, want 1", ml.calls)
	}

	if len(ml.evidence.Certificates) != 2 {
		t.Fatalf("evidence certificates = %d, want 2 (signers without a certificate contribute none)", len(ml.evidence.Certificates))
	}

	if string(ml.evidence.Certificates[0]) != string(certA) || string(ml.evidence.Certificates[1]) != string(certB) {
		t.Errorf("evidence certificates = %q, want [%q %q]", ml.evidence.Certificates, certA, certB)
	}

	if ml.name == nil || ml.name.Version != "v1.0.0" || ml.name.Domain != "agent.example.com" {
		t.Errorf("lookup received name %+v, want version v1.0.0 and domain agent.example.com", ml.name)
	}

	if got.Domain != "agent.example.com" {
		t.Errorf("Domain = %q, want agent.example.com", got.Domain)
	}
}

func TestWithLookupOverridesWellKnown(t *testing.T) {
	wk := &fakeSchemeLookup{keys: []PublicKey{{ID: "kid-1", Key: keyA}}}
	custom := &fakeMethodLookup{
		method: VerificationMethod("custom"),
		result: &LookupResult{Keys: []PublicKey{{ID: "custom-1", Key: keyA}}},
	}

	provider := NewProvider(WithWellKnownLookup(wk), WithLookup(HTTPSProtocol, custom))

	got := provider.Verify(context.Background(), "https://example.org/agent", []Signer{{Key: keyA}})

	if !got.Verified || got.MatchedKeyID != "custom-1" || got.Method != "custom" {
		t.Fatalf("got %+v, want the later registration for https:// to win", got)
	}

	if wk.scheme != "" {
		t.Errorf("well-known lookup was called with scheme %q, want no call", wk.scheme)
	}
}

func TestProviderMethod(t *testing.T) {
	provider := NewProvider(
		WithWellKnownLookup(&fakeSchemeLookup{}),
		WithLookup(ANSProtocol, &fakeMethodLookup{method: MethodANS}),
	)

	tests := []struct {
		name     string
		protocol string
		want     VerificationMethod
	}{
		{name: "https", protocol: HTTPSProtocol, want: MethodWellKnown},
		{name: "http", protocol: HTTPProtocol, want: MethodWellKnown},
		{name: "ans", protocol: ANSProtocol, want: MethodANS},
		{name: "empty", protocol: "", want: MethodNone},
		{name: "unregistered", protocol: "did://", want: MethodNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := provider.Method(tt.protocol); got != tt.want {
				t.Errorf("Method(%q) = %q, want %q", tt.protocol, got, tt.want)
			}
		})
	}

	if got := NewProvider().Method(HTTPSProtocol); got != MethodNone {
		t.Errorf("Method(https) on an empty provider = %q, want %q", got, MethodNone)
	}
}

func TestWithLookupRejectsUnknownPrefix(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithLookup accepted a prefix ParseName cannot route")
		}
	}()

	WithLookup("did://", &fakeMethodLookup{method: "did"})
}

func TestNilLookupsRegisterNothing(t *testing.T) {
	provider := NewProvider(WithWellKnownLookup(nil), WithLookup(ANSProtocol, nil))

	for _, protocol := range VerifiablePrefixes() {
		if got := provider.Method(protocol); got != MethodNone {
			t.Errorf("Method(%q) = %q after nil registrations, want %q", protocol, got, MethodNone)
		}
	}

	got := provider.Verify(context.Background(), "https://example.org/agent", []Signer{{Key: keyA}})
	assertResult(t, got, want{method: "none", err: `no verification method registered for protocol "https://"`})
}

func TestProviderVerifyGuardsLookupContract(t *testing.T) {
	tests := []struct {
		name    string
		lookup  *fakeMethodLookup
		signers []Signer
		want    want
	}{
		{
			name:    "nil result with nil error is no keys",
			lookup:  &fakeMethodLookup{method: MethodANS},
			signers: []Signer{{Key: keyA, Certificate: certA}},
			want:    want{method: "ans", err: "no keys found for domain"},
		},
		{
			name:    "empty signer key never matches an empty published key",
			lookup:  &fakeMethodLookup{method: MethodANS, result: &LookupResult{Keys: []PublicKey{{ID: "empty"}}}},
			signers: []Signer{{Certificate: certA}},
			want:    want{method: "ans", err: "signing key does not match any domain key"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(WithLookup(ANSProtocol, tt.lookup))

			got := provider.Verify(context.Background(), "ans://v1.0.0.agent.example.com", tt.signers)

			assertResult(t, got, tt.want)
		})
	}
}

func TestWellKnownLookupPropagatesTransientFailures(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantTransient bool
	}{
		{name: "fetcher marks the failure transient", err: Transient(errors.New("JWKS at https://example.org returned HTTP 503")), wantTransient: true},
		{name: "wrapped transient failure", err: fmt.Errorf("lookup: %w", Transient(context.DeadlineExceeded)), wantTransient: true},
		{name: "malformed key set", err: errors.New("failed to parse JWK set"), wantTransient: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(WithWellKnownLookup(&fakeSchemeLookup{err: tt.err}))

			got := provider.Verify(context.Background(), "https://example.org/agent", []Signer{{Key: keyA}})

			if got.Verified {
				t.Fatal("Verify() = verified on a failed lookup")
			}

			if got.Transient != tt.wantTransient {
				t.Errorf("Transient = %v, want %v (error %q)", got.Transient, tt.wantTransient, got.Error)
			}
		})
	}
}

func TestTransient(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	err := Transient(cause)

	if !errors.Is(err, ErrTransient) {
		t.Error("errors.Is(Transient(err), ErrTransient) = false")
	}

	if !errors.Is(err, cause) {
		t.Error("Transient(err) hides its cause from errors.Is")
	}

	if err.Error() != cause.Error() {
		t.Errorf("Transient(err).Error() = %q, want the cause text %q", err.Error(), cause.Error())
	}

	if errors.Is(errors.New("other"), ErrTransient) {
		t.Error("an unmarked error reports transient")
	}
}

func TestRetryAfterError(t *testing.T) {
	cause := errors.New("log host unreachable")
	until := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	err := &RetryAfterError{Until: until, Err: cause}

	if !errors.Is(err, ErrTransient) {
		t.Error("errors.Is(err, ErrTransient) = false, want true")
	}

	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false, want true through Unwrap")
	}

	if errors.Is(err, errLookupFailed) {
		t.Error("errors.Is(err, unrelated) = true, want false")
	}

	if got, wantMsg := err.Error(), "log host unreachable (retry after 2026-09-11T12:00:00Z)"; got != wantMsg {
		t.Errorf("Error() = %q, want %q", got, wantMsg)
	}
}
