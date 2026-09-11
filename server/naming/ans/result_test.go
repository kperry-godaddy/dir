// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestKeyTypeOf(t *testing.T) {
	ecKey := func(curve elliptic.Curve) *ecdsa.PublicKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		return &key.PublicKey
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  any
		want string
	}{
		{name: "p256", key: ecKey(elliptic.P256()), want: "ecdsa-p256"},
		{name: "p384", key: ecKey(elliptic.P384()), want: "ecdsa-p384"},
		{name: "p521", key: ecKey(elliptic.P521()), want: "ecdsa-p521"},
		{name: "p224", key: ecKey(elliptic.P224()), want: "ecdsa"},
		{name: "ed25519", key: edPub, want: "ed25519"},
		{name: "rsa", key: &rsaKey.PublicKey, want: "rsa"},
		{name: "unknown", key: x25519.PublicKey(), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyTypeOf(tt.key); got != tt.want {
				t.Errorf("keyTypeOf() = %q, want %q", got, tt.want)
			}
		})
	}
}
