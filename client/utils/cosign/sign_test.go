// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package cosign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/stretchr/testify/require"
)

const testKeyPassword = "pw"

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

// newSelfSignedCert issues a self-signed identity certificate for key naming
// the agent ans://v1.0.0.agent.example.com in its URI SAN.
func newSelfSignedCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{{Scheme: "ans", Host: "v1.0.0.agent.example.com"}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func certificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func publicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// importCosignKey wraps key in the encrypted Cosign private-key format the way
// "cosign import-key-pair" does and returns the encrypted PEM bytes.
func importCosignKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "identity-key.pem")
	require.NoError(t, os.WriteFile(path, privateKeyPEM(t, key), 0o600))

	keys, err := cosign.ImportKeyPair(path, func(bool) ([]byte, error) {
		return []byte(testKeyPassword), nil
	})
	require.NoError(t, err)

	return string(keys.PrivateBytes)
}

func TestSelectCertificateForKey(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)
	other := newTestKey(t)
	leaf := newSelfSignedCert(t, signer)
	otherCert := newSelfSignedCert(t, other)

	tests := []struct {
		name    string
		bundle  []byte
		wantRaw []byte
		wantErr string
	}{
		{
			name:    "matching certificate",
			bundle:  certificatePEM(leaf),
			wantRaw: leaf.Raw,
		},
		{
			name:    "mismatched certificate",
			bundle:  certificatePEM(otherCert),
			wantErr: "none of the 1 certificates match the signing key",
		},
		{
			name:    "chain with leaf last",
			bundle:  append(certificatePEM(otherCert), certificatePEM(leaf)...),
			wantRaw: leaf.Raw,
		},
		{
			name:    "public key block only",
			bundle:  publicKeyPEM(t, signer),
			wantErr: "no CERTIFICATE PEM block found",
		},
		{
			name:    "der instead of pem",
			bundle:  leaf.Raw,
			wantErr: "no CERTIFICATE PEM block found",
		},
		{
			name:    "private key block",
			bundle:  append(certificatePEM(leaf), privateKeyPEM(t, signer)...),
			wantErr: "contains a private key block",
		},
		{
			name:    "malformed certificate",
			bundle:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}),
			wantErr: "parsing certificate 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := selectCertificateForKey(tt.bundle, &signer.PublicKey)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, cert)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantRaw, cert.Raw)
		})
	}
}

func TestSignBlobWithKeyAttachesMatchingCertificate(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)
	leaf := newSelfSignedCert(t, signer)
	payload := []byte("bafyreib-record-cid")

	sig, pub, err := SignBlobWithKey(t.Context(), payload, &signv1.SignWithKey{
		PrivateKey:  importCosignKey(t, signer),
		Password:    []byte(testKeyPassword),
		Certificate: new(string(certificatePEM(leaf))),
	})
	require.NoError(t, err)

	require.Equal(t, base64.StdEncoding.EncodeToString(leaf.Raw), sig.GetCertificate())
	require.Empty(t, sig.GetContentBundle())
	require.NotEmpty(t, sig.GetAlgorithm())
	require.NotEmpty(t, sig.GetSignedAt())
	require.Contains(t, pub.GetKey(), "PUBLIC KEY")

	rawSig, err := base64.StdEncoding.DecodeString(sig.GetSignature())
	require.NoError(t, err)

	digest := sha256.Sum256(payload)
	require.True(t, ecdsa.VerifyASN1(&signer.PublicKey, digest[:], rawSig), "signature must verify with the certificate key")
}

func TestSignBlobWithKeyWithoutCertificate(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)

	sig, pub, err := SignBlobWithKey(t.Context(), []byte("payload"), &signv1.SignWithKey{
		PrivateKey: importCosignKey(t, signer),
		Password:   []byte(testKeyPassword),
	})
	require.NoError(t, err)
	require.Empty(t, sig.GetCertificate())
	require.NotEmpty(t, sig.GetSignature())
	require.NotEmpty(t, pub.GetKey())
}

func TestSignBlobWithKeyRejectsMismatchedCertificate(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)
	otherCert := newSelfSignedCert(t, newTestKey(t))

	sig, pub, err := SignBlobWithKey(t.Context(), []byte("payload"), &signv1.SignWithKey{
		PrivateKey:  importCosignKey(t, signer),
		Password:    []byte(testKeyPassword),
		Certificate: new(string(certificatePEM(otherCert))),
	})
	require.ErrorContains(t, err, "none of the 1 certificates match the signing key")
	require.Nil(t, sig)
	require.Nil(t, pub)
}

func TestSignBlobWithKeyRequiresPrivateKey(t *testing.T) {
	t.Parallel()

	sig, pub, err := SignBlobWithKey(t.Context(), []byte("payload"), &signv1.SignWithKey{})
	require.ErrorContains(t, err, "private_key is required")
	require.Nil(t, sig)
	require.Nil(t, pub)
}

func TestSignBlobWithKeyRejectsUnloadableKeyReference(t *testing.T) {
	t.Parallel()

	sig, pub, err := SignBlobWithKey(t.Context(), []byte("payload"), &signv1.SignWithKey{
		PrivateKey: filepath.Join(t.TempDir(), "missing.key"),
	})
	require.ErrorContains(t, err, "loading private key from reference")
	require.Nil(t, sig)
	require.Nil(t, pub)
}
