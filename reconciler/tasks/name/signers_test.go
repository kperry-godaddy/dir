// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	signersTestCID  = "baeareitestsigners000000000000000000000000000000000000000000000"
	signersTestHost = "agent.example.com"
	signersTestSAN  = "ans://v1.0.0.agent.example.com"
)

// testIdentity is a key with a self-signed certificate naming an ANS URI.
type testIdentity struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestIdentity(t *testing.T, uriSAN string) testIdentity {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test identity"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if uriSAN != "" {
		uri, err := url.Parse(uriSAN)
		require.NoError(t, err)

		template.URIs = []*url.URL{uri}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testIdentity{key: key, cert: cert}
}

// signCID produces what cosign's key signer produces for the test record: an
// ASN.1 DER ECDSA signature over SHA-256 of the CID, base64-encoded.
func signCID(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	digest := sha256.Sum256([]byte(signersTestCID))

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(sig)
}

func encodeCert(cert *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(cert.Raw)
}

// signedBy is a key-based signature over the CID by the identity's own key.
func signedBy(t *testing.T, id testIdentity) *signv1.Signature {
	t.Helper()

	return &signv1.Signature{
		Signature:   signCID(t, id.key),
		Certificate: encodeCert(id.cert),
		Algorithm:   "ecdsa-p256",
	}
}

func randomSignature(t *testing.T) string {
	t.Helper()

	junk := make([]byte, 64)
	_, err := rand.Read(junk)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(junk)
}

func TestCertificateSigners(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	attacker := newTestIdentity(t, "")
	impostor := newTestIdentity(t, signersTestSAN)

	victimKey, err := x509.MarshalPKIXPublicKey(&victim.key.PublicKey)
	require.NoError(t, err)

	impostorKey, err := x509.MarshalPKIXPublicKey(&impostor.key.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		sigs      func(t *testing.T) []*signv1.Signature
		wantKeys  [][]byte
		wantCerts [][]byte
	}{
		{
			name: "valid binding yields the certificate and its key",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{signedBy(t, victim)}
			},
			wantKeys:  [][]byte{victimKey},
			wantCerts: [][]byte{victim.cert.Raw},
		},
		{
			name: "copied victim certificate with random signature bytes yields nothing",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: randomSignature(t), Certificate: encodeCert(victim.cert)}}
			},
		},
		{
			name: "victim certificate with a signature by a different key yields nothing",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: signCID(t, attacker.key), Certificate: encodeCert(victim.cert)}}
			},
		},
		{
			name: "self-signed certificate bearing the victim SAN signed by its own key is a signer here and is left to the verifier's attestation check",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{signedBy(t, impostor)}
			},
			wantKeys:  [][]byte{impostorKey},
			wantCerts: [][]byte{impostor.cert.Raw},
		},
		{
			name: "forty junk signers plus one real yield exactly the real one",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				sigs := make([]*signv1.Signature, 0, 41)
				for range 40 {
					sigs = append(sigs, &signv1.Signature{Signature: randomSignature(t), Certificate: encodeCert(victim.cert)})
				}

				return append(sigs, signedBy(t, victim))
			},
			wantKeys:  [][]byte{victimKey},
			wantCerts: [][]byte{victim.cert.Raw},
		},
		{
			name: "oidc signature with a content bundle is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				sig := signedBy(t, victim)
				sig.ContentBundle = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`

				return []*signv1.Signature{sig}
			},
		},
		{
			name: "oversize certificate is skipped before decoding",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				sig := signedBy(t, victim)
				sig.Certificate = strings.Repeat("A", maxEncodedCertificateSize+4)

				return []*signv1.Signature{sig}
			},
		},
		{
			name: "duplicate certificate DER is reported once",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{signedBy(t, victim), signedBy(t, victim)}
			},
			wantKeys:  [][]byte{victimKey},
			wantCerts: [][]byte{victim.cert.Raw},
		},
		{
			name: "signature without a certificate is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: signCID(t, victim.key)}}
			},
		},
		{
			name: "certificate that is not base64 is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: signCID(t, victim.key), Certificate: "not base64!"}}
			},
		},
		{
			name: "certificate that is not DER is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: signCID(t, victim.key), Certificate: base64.StdEncoding.EncodeToString([]byte("not a certificate"))}}
			},
		},
		{
			name: "signature that is not base64 is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: "not base64!", Certificate: encodeCert(victim.cert)}}
			},
		},
		{
			name: "certificate naming the record host is listed before others",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{signedBy(t, attacker), signedBy(t, victim)}
			},
			wantKeys:  [][]byte{victimKey, mustMarshalKey(t, &attacker.key.PublicKey)},
			wantCerts: [][]byte{victim.cert.Raw, attacker.cert.Raw},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signers, err := certificateSigners(t.Context(), signersTestCID, signersTestHost, tc.sigs(t))
			require.NoError(t, err)

			require.Len(t, signers, len(tc.wantKeys))

			for i, signer := range signers {
				assert.Equal(t, tc.wantKeys[i], signer.Key, "signer %d key", i)
				assert.Equal(t, tc.wantCerts[i], signer.Certificate, "signer %d certificate", i)
			}
		})
	}
}

func TestCertificateSigners_CanceledContext(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := certificateSigners(ctx, signersTestCID, signersTestHost, []*signv1.Signature{signedBy(t, victim)})
	require.ErrorIs(t, err, context.Canceled)
}

func TestNamesHost(t *testing.T) {
	tests := []struct {
		name string
		san  string
		host string
		want bool
	}{
		{name: "ans uri under the host", san: "ans://v1.0.0.agent.example.com", host: "agent.example.com", want: true},
		{name: "host comparison ignores case", san: "ans://v1.0.0.Agent.Example.com", host: "AGENT.example.com", want: true},
		{name: "ans uri with a path", san: "ans://v2.1.0.agent.example.com/assistant", host: "agent.example.com", want: true},
		{name: "ans uri for another host", san: "ans://v1.0.0.other.example.com", host: "agent.example.com", want: false},
		{name: "https uri is not an ans name", san: "https://v1.0.0.agent.example.com", host: "agent.example.com", want: false},
		{name: "no uri", san: "", host: "agent.example.com", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := newTestIdentity(t, tc.san)
			assert.Equal(t, tc.want, namesHost(id.cert, tc.host))
		})
	}
}

func mustMarshalKey(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)

	return der
}
