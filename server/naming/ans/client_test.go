// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
)

// expiredContext returns a context whose deadline has passed.
func expiredContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)

	<-ctx.Done()

	return ctx
}

// canceledContext returns a context its caller has canceled.
func canceledContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	return ctx
}

// childOf returns a fetch context derived from lookupCtx with a deadline far
// away, so it ends only when lookupCtx does.
func childOf(t *testing.T, lookupCtx context.Context) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(lookupCtx, time.Hour)
	t.Cleanup(cancel)

	return ctx
}

func TestCountsAsStrike(t *testing.T) {
	requestErr := func(cause error) error {
		return &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: &url.Error{
			Op: "Get", URL: testBadgeURL + "/status-token", Err: cause,
		}}
	}

	live := func(t *testing.T) (context.Context, context.Context) {
		t.Helper()

		return t.Context(), t.Context()
	}
	fetchExpired := func(t *testing.T) (context.Context, context.Context) {
		t.Helper()

		return expiredContext(t), t.Context()
	}
	lookupExpired := func(t *testing.T) (context.Context, context.Context) {
		t.Helper()

		lookupCtx := expiredContext(t)

		return childOf(t, lookupCtx), lookupCtx
	}
	lookupCanceled := func(t *testing.T) (context.Context, context.Context) {
		t.Helper()

		lookupCtx := canceledContext(t)

		return childOf(t, lookupCtx), lookupCtx
	}

	tests := []struct {
		name     string
		err      error
		contexts func(t *testing.T) (context.Context, context.Context)
		want     bool
	}{
		{name: "fetch deadline fired while the lookup had budget", err: requestErr(context.DeadlineExceeded), contexts: fetchExpired, want: true},
		{name: "bare deadline from the fetch deadline", err: fmt.Errorf("fake: %w", context.DeadlineExceeded), contexts: fetchExpired, want: true},
		{name: "lookup deadline fired", err: requestErr(context.DeadlineExceeded), contexts: lookupExpired},
		{name: "deadline without an expired context", err: requestErr(context.DeadlineExceeded), contexts: live},
		{name: "caller canceled", err: requestErr(context.Canceled), contexts: lookupCanceled},
		{name: "bare cancellation", err: context.Canceled, contexts: lookupCanceled},
		{name: "connection refused", err: requestErr(errBoom), contexts: live, want: true},
		{name: "tls handshake failed", err: requestErr(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), contexts: live, want: true},
		{name: "http 503", err: &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable}, contexts: live},
		{name: "http 404", err: &scitt.TransportError{Type: scitt.TransportErrNotFound, StatusCode: http.StatusNotFound}, contexts: live},
		{name: "invalid response", err: &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "response body exceeds maximum size"}, contexts: live},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetchCtx, lookupCtx := tt.contexts(t)

			if got := countsAsStrike(tt.err, fetchCtx, lookupCtx); got != tt.want {
				t.Errorf("countsAsStrike() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCauseText(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "transport error exposes its cause",
			err:  &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: errBoom},
			want: "boom",
		},
		{
			name: "transport error without a cause prints itself",
			err:  &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable, Message: "unexpected status code 503"},
			want: "HTTP error (503): unexpected status code 503",
		},
		{
			name: "other errors print themselves",
			err:  fmt.Errorf("fake log client: %w", context.DeadlineExceeded),
			want: "fake log client: context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := causeText(tt.err); got != tt.want {
				t.Errorf("causeText() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCircuitBreakerAttribution checks which fetch failures the breaker holds
// against the log: only a fetch that had its own budget and did not answer.
func TestCircuitBreakerAttribution(t *testing.T) {
	const timeout = 100 * time.Millisecond

	tests := []struct {
		name     string
		setup    func(f *fixture) context.Context
		wantErr  string
		wantOpen bool
	}{
		{
			name: "slow dns leaves the log no budget",
			setup: func(f *fixture) context.Context {
				f.dns.delay = timeout - 20*time.Millisecond
				f.client.block = true

				return f.t.Context()
			},
			wantErr: "ans status-token: timed out",
		},
		{
			name: "hanging log takes a strike per fetch",
			setup: func(f *fixture) context.Context {
				f.client.block = true

				return f.t.Context()
			},
			wantErr:  "ans status-token: timed out",
			wantOpen: true,
		},
		{
			name: "caller cancellation never counts",
			setup: func(f *fixture) context.Context {
				ctx, cancel := context.WithCancel(f.t.Context())
				f.client.block = true
				f.client.onCall = cancel

				return ctx
			},
			wantErr: "ans status-token: canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.Timeout = timeout
			ctx := tt.setup(f)
			v := f.build()

			for i := range breakerThreshold {
				_, err := v.LookupKeys(ctx, f.name, f.evidence)
				assertLookupError(t, err, tt.wantErr, true)

				if _, ok := errors.AsType[*naming.RetryAfterError](err); ok {
					t.Fatalf("lookup %d: circuit opened before %d strikes", i+1, breakerThreshold)
				}
			}

			_, err := v.LookupKeys(ctx, f.name, f.evidence)
			if _, open := errors.AsType[*naming.RetryAfterError](err); open != tt.wantOpen {
				t.Errorf("circuit open after %d lookups = %v, want %v (error %v)", breakerThreshold, open, tt.wantOpen, err)
			}

			if failures := v.breaker.failures[testLogHost]; failures != 0 {
				t.Errorf("breaker holds %d failures against %s, want none", failures, testLogHost)
			}

			wantCalls := breakerThreshold + 1
			if tt.wantOpen {
				wantCalls = breakerThreshold
			}

			if got := f.client.callCount(); got != wantCalls {
				t.Errorf("log called %d times, want %d", got, wantCalls)
			}
		})
	}
}
