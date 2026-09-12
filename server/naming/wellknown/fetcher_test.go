// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package wellknown

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
}
