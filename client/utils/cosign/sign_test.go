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
	"encoding/asn1"
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

// issueCertificate self-signs an identity certificate for key naming the agent
// ans://v1.0.0.agent.example.com in its URI SAN.
func issueCertificate(t *testing.T, key *ecdsa.PrivateKey, notBefore, notAfter time.Time, extensions ...pkix.Extension) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "agent.example.com"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		KeyUsage:        x509.KeyUsageDigitalSignature,
		URIs:            []*url.URL{{Scheme: "ans", Host: "v1.0.0.agent.example.com"}},
		ExtraExtensions: extensions,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func newSelfSignedCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	now := time.Now()

	return issueCertificate(t, key, now.Add(-time.Hour), now.Add(24*time.Hour))
}

// newOversizedCert issues a certificate whose DER exceeds MaxCertificateDERSize.
func newOversizedCert(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	now := time.Now()
	padding := pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1},
		Value: make([]byte, MaxCertificateDERSize),
	}

	return issueCertificate(t, key, now.Add(-time.Hour), now.Add(24*time.Hour), padding)
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

func writeKeyFile(t *testing.T, encryptedKey string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "import-cosign.key")
	require.NoError(t, os.WriteFile(path, []byte(encryptedKey), 0o600))

	return path
}

func TestParseCertificateBundle(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)
	leaf := newSelfSignedCert(t, signer)
	issuer := newSelfSignedCert(t, newTestKey(t))

	tests := []struct {
		name    string
		bundle  []byte
		wantRaw [][]byte
		wantErr string
	}{
		{
			name:    "single certificate",
			bundle:  certificatePEM(leaf),
			wantRaw: [][]byte{leaf.Raw},
		},
		{
			name:    "chain keeps order",
			bundle:  append(certificatePEM(leaf), certificatePEM(issuer)...),
			wantRaw: [][]byte{leaf.Raw, issuer.Raw},
		},
		{
			name:    "skips blocks of other types",
			bundle:  append(publicKeyPEM(t, signer), certificatePEM(leaf)...),
			wantRaw: [][]byte{leaf.Raw},
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
			wantErr: "certificate contains a private key block",
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

			certs, err := ParseCertificateBundle(tt.bundle)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, certs)

				return
			}

			require.NoError(t, err)
			require.Len(t, certs, len(tt.wantRaw))

			for i, cert := range certs {
				require.Equal(t, tt.wantRaw[i], cert.Raw)
			}
		})
	}
}

func TestSelectCertificateForKey(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	signer := newTestKey(t)
	current := issueCertificate(t, signer, now.Add(-time.Hour), now.Add(time.Hour))
	expired := issueCertificate(t, signer, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	future := issueCertificate(t, signer, now.Add(24*time.Hour), now.Add(48*time.Hour))
	other := newSelfSignedCert(t, newTestKey(t))

	tests := []struct {
		name    string
		bundle  []byte
		wantRaw []byte
		wantErr string
	}{
		{
			name:    "matching certificate",
			bundle:  certificatePEM(current),
			wantRaw: current.Raw,
		},
		{
			name:    "mismatched certificate",
			bundle:  certificatePEM(other),
			wantErr: "none of the 1 certificates match the signing key",
		},
		{
			name:    "chain with leaf last",
			bundle:  append(certificatePEM(other), certificatePEM(current)...),
			wantRaw: current.Raw,
		},
		{
			name:    "prefers the currently valid match",
			bundle:  append(certificatePEM(expired), certificatePEM(current)...),
			wantRaw: current.Raw,
		},
		{
			name:    "falls back to the first match when none is valid",
			bundle:  append(certificatePEM(expired), certificatePEM(future)...),
			wantRaw: expired.Raw,
		},
		{
			name:    "unparsable bundle",
			bundle:  publicKeyPEM(t, signer),
			wantErr: "no CERTIFICATE PEM block found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, err := selectCertificateForKey(tt.bundle, &signer.PublicKey, now)
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

func TestSignBlobWithKey(t *testing.T) {
	t.Parallel()

	signer := newTestKey(t)
	leaf := newSelfSignedCert(t, signer)
	encryptedKey := importCosignKey(t, signer)
	password := []byte(testKeyPassword)

	tests := []struct {
		name            string
		request         *signv1.SignWithKey
		wantCertificate bool
		wantErr         string
	}{
		{
			name: "attaches the matching certificate",
			request: &signv1.SignWithKey{
				PrivateKey:  encryptedKey,
				Password:    password,
				Certificate: new(string(certificatePEM(leaf))),
			},
			wantCertificate: true,
		},
		{
			name:    "signs without a certificate",
			request: &signv1.SignWithKey{PrivateKey: encryptedKey, Password: password},
		},
		{
			name:    "loads the key from a file reference",
			request: &signv1.SignWithKey{PrivateKey: writeKeyFile(t, encryptedKey), Password: password},
		},
		{
			name: "rejects a mismatched certificate",
			request: &signv1.SignWithKey{
				PrivateKey:  encryptedKey,
				Password:    password,
				Certificate: new(string(certificatePEM(newSelfSignedCert(t, newTestKey(t))))),
			},
			wantErr: "none of the 1 certificates match the signing key",
		},
		{
			name: "rejects an oversized certificate",
			request: &signv1.SignWithKey{
				PrivateKey:  encryptedKey,
				Password:    password,
				Certificate: new(string(certificatePEM(newOversizedCert(t, signer)))),
			},
			wantErr: "verifiers accept at most 16384 bytes",
		},
		{
			name:    "requires a private key",
			request: &signv1.SignWithKey{},
			wantErr: "private_key is required",
		},
		{
			name:    "rejects an unloadable key reference",
			request: &signv1.SignWithKey{PrivateKey: filepath.Join(t.TempDir(), "missing.key")},
			wantErr: "loading private key from reference",
		},
		{
			name:    "rejects an inline key with the wrong password",
			request: &signv1.SignWithKey{PrivateKey: encryptedKey, Password: []byte("wrong")},
			wantErr: "loading inline private key: decrypt",
		},
		{
			name:    "rejects an inline key that is not in the cosign format",
			request: &signv1.SignWithKey{PrivateKey: string(privateKeyPEM(t, signer))},
			wantErr: "loading inline private key: unsupported pem type: PRIVATE KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			payload := []byte("bafyreib-record-cid")

			sig, pub, err := SignBlobWithKey(t.Context(), payload, tt.request)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.NotContains(t, err.Error(), "-----BEGIN", "errors must not echo key material")
				require.Nil(t, sig)
				require.Nil(t, pub)

				return
			}

			require.NoError(t, err)
			require.Empty(t, sig.GetContentBundle())
			require.NotEmpty(t, sig.GetAlgorithm())
			require.NotEmpty(t, sig.GetSignedAt())
			require.Contains(t, pub.GetKey(), "PUBLIC KEY")

			if tt.wantCertificate {
				require.Equal(t, base64.StdEncoding.EncodeToString(leaf.Raw), sig.GetCertificate())
			} else {
				require.Empty(t, sig.GetCertificate())
			}

			rawSig, err := base64.StdEncoding.DecodeString(sig.GetSignature())
			require.NoError(t, err)

			digest := sha256.Sum256(payload)
			require.True(t, ecdsa.VerifyASN1(&signer.PublicKey, digest[:], rawSig), "signature must verify with the signing key")
		})
	}
}
