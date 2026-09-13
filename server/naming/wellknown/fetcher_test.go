// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package wellknown

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/agntcy/dir/server/naming"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func testKeySet(t *testing.T) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jwk.FromRaw(priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	if err := key.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatal(err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func TestLookupKeysWithScheme(t *testing.T) {
	keySet := testKeySet(t)

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		wantKeys      int
		wantErr       string
		wantTransient bool
	}{
		{
			name:     "key set is parsed",
			handler:  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(keySet) },
			wantKeys: 1,
		},
		{
			name:    "not found is terminal",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) },
			wantErr: "returned HTTP 404",
		},
		{
			name:    "forbidden is terminal",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
			wantErr: "returned HTTP 403",
		},
		{
			name:          "server error is transient",
			handler:       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			wantErr:       "returned HTTP 503",
			wantTransient: true,
		},
		{
			name:          "throttling is transient",
			handler:       func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTooManyRequests) },
			wantErr:       "returned HTTP 429",
			wantTransient: true,
		},
		{
			name:    "malformed body is terminal",
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>maintenance</html>")) },
			wantErr: "failed to parse JWKS",
		},
		{
			name: "oversized body is terminal",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat(" ", maxJWKSBytes+1)))
			},
			wantErr: "exceeds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			host := strings.TrimPrefix(server.URL, "http://")

			keys, err := NewFetcher().LookupKeysWithScheme(t.Context(), host, "http")

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LookupKeysWithScheme() error = %v, want containing %q", err, tt.wantErr)
				}

				if errors.Is(err, naming.ErrTransient) != tt.wantTransient {
					t.Errorf("transient = %v, want %v (error %v)", !tt.wantTransient, tt.wantTransient, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("LookupKeysWithScheme() error = %v", err)
			}

			if len(keys) != tt.wantKeys {
				t.Fatalf("LookupKeysWithScheme() returned %d keys, want %d", len(keys), tt.wantKeys)
			}

			if keys[0].ID != "kid-1" {
				t.Errorf("key ID = %q, want kid-1", keys[0].ID)
			}
		})
	}
}

func TestLookupKeysWithSchemeUnreachableHostIsTransient(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	host := strings.TrimPrefix(server.URL, "http://")
	server.Close()

	_, err := NewFetcher().LookupKeysWithScheme(t.Context(), host, "http")
	if err == nil {
		t.Fatal("LookupKeysWithScheme() succeeded against a closed server")
	}

	if !errors.Is(err, naming.ErrTransient) {
		t.Errorf("connection failure is not transient: %v", err)
	}

	if !strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "dial tcp") {
		t.Errorf("error = %q, want the kind of failure without the transport's text", err)
	}
}

func TestFetchFailure(t *testing.T) {
	const jwksURL = "https://example.com/.well-known/jwks.json"

	tests := []struct {
		name          string
		err           error
		want          string
		wantTransient bool
	}{
		{
			name: "unknown host is terminal",
			err:  &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true},
			want: "host not found",
		},
		{
			name:          "other dns failure is transient",
			err:           &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true},
			want:          "connection failed",
			wantTransient: true,
		},
		{
			name:          "deadline is transient",
			err:           context.DeadlineExceeded,
			want:          "request timed out",
			wantTransient: true,
		},
		{
			name:          "network timeout is transient",
			err:           &net.DNSError{Err: "i/o timeout", Name: "example.com", IsTimeout: true},
			want:          "request timed out",
			wantTransient: true,
		},
		{
			name:          "untrusted certificate is transient",
			err:           &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			want:          "TLS certificate not trusted",
			wantTransient: true,
		},
		{
			name:          "refused connection is transient",
			err:           errors.New("dial tcp 10.0.0.1:443: connect: connection refused"),
			want:          "connection failed",
			wantTransient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fetchFailure(jwksURL, &url.Error{Op: "Get", URL: jwksURL, Err: tt.err})

			if !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "10.0.0.1") {
				t.Fatalf("fetchFailure() = %q, want containing %q and no transport text", err, tt.want)
			}

			if errors.Is(err, naming.ErrTransient) != tt.wantTransient {
				t.Errorf("transient = %v, want %v", !tt.wantTransient, tt.wantTransient)
			}
		})
	}
}
