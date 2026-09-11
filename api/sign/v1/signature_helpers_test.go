// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package v1

import "testing"

func TestSignatureKeyCertificate(t *testing.T) {
	tests := []struct {
		name         string
		sig          *Signature
		wantKeyBased bool
		wantCert     string
		wantOK       bool
	}{
		{name: "nil signature", sig: nil, wantKeyBased: true},
		{name: "key-based without certificate", sig: &Signature{Signature: "c2ln"}, wantKeyBased: true},
		{name: "key-based with certificate", sig: &Signature{Signature: "c2ln", Certificate: "Y2VydA=="}, wantKeyBased: true, wantCert: "Y2VydA==", wantOK: true},
		{name: "keyless carries its certificate in the bundle", sig: &Signature{ContentBundle: "{}", Certificate: "Y2VydA=="}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sig.IsKeyBased(); got != tt.wantKeyBased {
				t.Errorf("IsKeyBased() = %v, want %v", got, tt.wantKeyBased)
			}

			cert, ok := tt.sig.KeyCertificate()
			if cert != tt.wantCert || ok != tt.wantOK {
				t.Errorf("KeyCertificate() = (%q, %v), want (%q, %v)", cert, ok, tt.wantCert, tt.wantOK)
			}
		})
	}
}
