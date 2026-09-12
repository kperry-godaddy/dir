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

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
)

var errBoom = errors.New("boom")

func TestClassifyPredicates(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		wantTransient  bool
		wantConnection bool
		wantDescribe   string
	}{
		{
			name:         "dns record not found is terminal",
			err:          verify.ErrRecordNotFound,
			wantDescribe: "unexpected failure",
		},
		{
			name:          "dns timeout",
			err:           &verify.DNSError{Type: verify.DNSErrorTimeout, Fqdn: "_ans-badge.agent.example.com"},
			wantTransient: true,
			wantDescribe:  "DNS lookup timed out",
		},
		{
			name:          "dns lookup failed hides the resolver address",
			err:           &verify.DNSError{Type: verify.DNSErrorLookupFailed, Fqdn: "_ans-badge.agent.example.com", Reason: "read udp 127.0.0.1:53: connection refused"},
			wantTransient: true,
			wantDescribe:  "DNS lookup failed",
		},
		{
			name:         "dns not found",
			err:          &verify.DNSError{Type: verify.DNSErrorNotFound},
			wantDescribe: "DNS record not found",
		},
		{
			name:           "connection failure",
			err:            &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: errBoom},
			wantTransient:  true,
			wantConnection: true,
			wantDescribe:   "transparency log unreachable",
		},
		{
			name:         "invalid response without status",
			err:          &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "no valid keys found in root keys response"},
			wantDescribe: "invalid response from the transparency log",
		},
		{
			name:          "http 503",
			err:           &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable},
			wantTransient: true,
			wantDescribe:  "transparency log returned HTTP 503",
		},
		{
			name:          "http 429",
			err:           &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusTooManyRequests},
			wantTransient: true,
			wantDescribe:  "transparency log returned HTTP 429",
		},
		{
			name:          "http 302",
			err:           &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusFound},
			wantTransient: true,
			wantDescribe:  "transparency log returned HTTP 302",
		},
		{
			name:          "http 403 from a proxy",
			err:           &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusForbidden},
			wantTransient: true,
			wantDescribe:  "transparency log returned HTTP 403",
		},
		{
			name:          "http 404 is transient",
			err:           &scitt.TransportError{Type: scitt.TransportErrNotFound, StatusCode: http.StatusNotFound},
			wantTransient: true,
			wantDescribe:  "not found on the transparency log (HTTP 404)",
		},
		{
			name:          "not found without a status code",
			err:           &scitt.TransportError{Type: scitt.TransportErrNotFound},
			wantTransient: true,
			wantDescribe:  "not found on the transparency log (HTTP 404)",
		},
		{
			name:         "http 410",
			err:          &scitt.TransportError{Type: scitt.TransportErrAgentTerminal, StatusCode: http.StatusGone},
			wantDescribe: "agent is in a terminal state (HTTP 410)",
		},
		{
			name:         "http 501",
			err:          &scitt.TransportError{Type: scitt.TransportErrNotSupported, StatusCode: http.StatusNotImplemented},
			wantDescribe: "transparency log returned HTTP 501",
		},
		{
			name:         "base64 decode",
			err:          &scitt.TransportError{Type: scitt.TransportErrBase64Decode},
			wantDescribe: "invalid response from the transparency log",
		},
		{
			name: "tls verification through the transport error",
			err: &scitt.TransportError{Type: scitt.TransportErrHTTPError, Cause: &url.Error{
				Op: "Get", URL: "https://log.example.com/v1/agents/x/status-token",
				Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			}},
			wantTransient:  true,
			wantConnection: true,
			wantDescribe:   "TLS handshake failed",
		},
		{
			name:           "unknown authority",
			err:            x509.UnknownAuthorityError{},
			wantTransient:  true,
			wantConnection: true,
			wantDescribe:   "TLS handshake failed",
		},
		{
			name:           "hostname mismatch",
			err:            x509.HostnameError{Host: "log.example.com"},
			wantTransient:  true,
			wantConnection: true,
			wantDescribe:   "TLS handshake failed",
		},
		{
			name:          "deadline",
			err:           context.DeadlineExceeded,
			wantTransient: true,
			wantDescribe:  "timed out",
		},
		{
			name:          "wrapped deadline",
			err:           fmt.Errorf("fetch: %w", context.DeadlineExceeded),
			wantTransient: true,
			wantDescribe:  "timed out",
		},
		{
			name:          "canceled",
			err:           context.Canceled,
			wantTransient: true,
			wantDescribe:  "canceled",
		},
		{
			name: "canceled inside a transport error is connection-shaped",
			err: &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: &url.Error{
				Op: "Get", URL: "https://log.example.com/v1/agents/x/status-token", Err: context.Canceled,
			}},
			wantTransient:  true,
			wantConnection: true,
			wantDescribe:   "canceled",
		},
		{
			name:          "pending agent",
			err:           errAgentPending,
			wantTransient: true,
			wantDescribe:  "unexpected failure",
		},
		{
			name:          "token expired",
			err:           &scitt.TokenError{Type: scitt.TokenErrExpired, Exp: 100, Now: 200},
			wantTransient: true,
			wantDescribe:  "status token expired at 100, now 200",
		},
		{
			name:         "terminal status",
			err:          &scitt.TokenError{Type: scitt.TokenErrTerminalStatus, Status: scitt.StatusRevoked},
			wantDescribe: "agent status REVOKED is terminal",
		},
		{
			name:         "missing field",
			err:          &scitt.TokenError{Type: scitt.TokenErrMissingField, Message: "agent_id"},
			wantDescribe: "invalid status token payload",
		},
		{
			name:          "unknown key id",
			err:           &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID, Kid: [4]byte{0x0a, 0x0b, 0x0c, 0x0d}},
			wantTransient: true,
			wantDescribe:  "signed by unknown key id 0a0b0c0d",
		},
		{
			name:         "issuer mismatch",
			err:          &scitt.SignatureError{Type: scitt.SigErrIssuerMismatch},
			wantDescribe: "issuer does not match the signing key",
		},
		{
			name:         "bad signature",
			err:          &scitt.SignatureError{Type: scitt.SigErrSignatureInvalid},
			wantDescribe: "signature verification failed",
		},
		{
			name:         "cose",
			err:          &scitt.CoseError{Type: scitt.CoseErrNotACoseSign1},
			wantDescribe: "malformed COSE_Sign1 structure",
		},
		{
			name:         "merkle",
			err:          &scitt.MerkleError{Type: scitt.MerkleErrInvalidProof},
			wantDescribe: "invalid inclusion proof",
		},
		{
			name:          "retry after",
			err:           &naming.RetryAfterError{Until: time.Unix(0, 0), Err: errBoom},
			wantTransient: true,
			wantDescribe:  "unexpected failure",
		},
		{
			name:          "stage error keeps its transient cause",
			err:           failWith(stageDNS, &verify.DNSError{Type: verify.DNSErrorTimeout}, "DNS lookup timed out"),
			wantTransient: true,
			wantDescribe:  "DNS lookup timed out",
		},
		{
			name:         "unknown error is terminal",
			err:          errBoom,
			wantDescribe: "unexpected failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransient(tt.err); got != tt.wantTransient {
				t.Errorf("isTransient() = %v, want %v", got, tt.wantTransient)
			}

			if got := isConnectionFailure(tt.err); got != tt.wantConnection {
				t.Errorf("isConnectionFailure() = %v, want %v", got, tt.wantConnection)
			}

			if got := describe(tt.err); got != tt.wantDescribe {
				t.Errorf("describe() = %q, want %q", got, tt.wantDescribe)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	terminal := fail(stageCertificate, "no attached certificate names this agent")
	transient := failWith(stageDNS, &verify.DNSError{Type: verify.DNSErrorTimeout}, "DNS lookup timed out")
	retry := &naming.RetryAfterError{Until: time.Unix(1_700_000_000, 0), Err: fail(stageLog, "circuit open")}

	pending := failWith(stageStatusToken, errAgentPending, "agent status PENDING_DNS does not allow connections")

	tests := []struct {
		name          string
		err           error
		wantErr       string
		wantTransient bool
		wantRetry     bool
	}{
		{name: "nil", err: nil},
		{name: "terminal passes through", err: terminal, wantErr: "ans certificate: no attached certificate names this agent"},
		{name: "transient is marked", err: transient, wantErr: "ans dns: DNS lookup timed out", wantTransient: true},
		{name: "pending agent is marked", err: pending, wantErr: "ans status-token: agent status PENDING_DNS does not allow connections", wantTransient: true},
		{name: "retry after is kept", err: retry, wantErr: "ans log: circuit open (retry after 2023-11-14T22:13:20Z)", wantTransient: true, wantRetry: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.err)

			if tt.err == nil {
				if got != nil {
					t.Fatalf("classify(nil) = %v, want nil", got)
				}

				return
			}

			if got.Error() != tt.wantErr {
				t.Errorf("classify() = %q, want %q", got.Error(), tt.wantErr)
			}

			if errors.Is(got, naming.ErrTransient) != tt.wantTransient {
				t.Errorf("errors.Is(ErrTransient) = %v, want %v", !tt.wantTransient, tt.wantTransient)
			}

			if !errors.Is(got, tt.err) {
				t.Error("classify() dropped the original error from the chain")
			}

			if _, ok := errors.AsType[*naming.RetryAfterError](got); ok != tt.wantRetry {
				t.Errorf("RetryAfterError in chain = %v, want %v", ok, tt.wantRetry)
			}
		})
	}
}

func TestStageError(t *testing.T) {
	cause := &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable}
	err := failWith(stageReceipt, cause, "transparency log returned HTTP 503")

	if err.Error() != "ans receipt: transparency log returned HTTP 503" {
		t.Errorf("Error() = %q", err.Error())
	}

	if got, ok := errors.AsType[*scitt.TransportError](err); !ok || got != cause {
		t.Error("failWith() did not keep the cause in the chain")
	}

	if got := fail(stageBadgeURL, "x").Error(); got != "ans badge-url: x" {
		t.Errorf("fail().Error() = %q", got)
	}
}

func TestStatusCause(t *testing.T) {
	tests := []struct {
		name        string
		status      scitt.AgentStatus
		wantPending bool
	}{
		{name: "pending dns", status: "PENDING_DNS", wantPending: true},
		{name: "unknown status", status: "SOMETHING_NEW", wantPending: true},
		{name: "revoked", status: scitt.StatusRevoked},
		{name: "expired", status: scitt.StatusExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := statusCause(tt.status)

			if (got != nil) != tt.wantPending {
				t.Fatalf("statusCause(%q) = %v, want pending %v", tt.status, got, tt.wantPending)
			}

			if tt.wantPending && !errors.Is(got, errAgentPending) {
				t.Errorf("statusCause(%q) = %v, want errAgentPending", tt.status, got)
			}
		})
	}
}
