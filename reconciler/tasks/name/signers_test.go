// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	signersTestCID = "baeareitestsigners000000000000000000000000000000000000000000000"
	signersTestSAN = "ans://v1.0.0.agent.example.com"
	rsaTestBits    = 2048
)

// testIdentity is a key with a self-signed certificate, optionally naming an
// ANS URI.
type testIdentity struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func newTestIdentity(t *testing.T, uriSAN string) testIdentity {
	t.Helper()

	return newTestIdentityWithKey(t, newECDSAKey(t, elliptic.P256()), uriSAN)
}

func newTestIdentityWithKey(t *testing.T, key crypto.Signer, uriSAN string) testIdentity {
	t.Helper()

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

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testIdentity{key: key, cert: cert}
}

func newECDSAKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	return key
}

func ecdsaKey(curve elliptic.Curve) func(t *testing.T) crypto.Signer {
	return func(t *testing.T) crypto.Signer {
		t.Helper()

		return newECDSAKey(t, curve)
	}
}

func newEd25519Key(t *testing.T) crypto.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return key
}

func newRSAKey(t *testing.T) crypto.Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, rsaTestBits)
	require.NoError(t, err)

	return key
}

// signPayload produces what the registry's key signer produces: the payload
// signed through sigstore's default signer for the key type, base64-encoded.
func signPayload(t *testing.T, key crypto.Signer, payload string) string {
	t.Helper()

	sv, err := signature.LoadDefaultSignerVerifier(key, options.WithED25519ph())
	require.NoError(t, err)

	sig, err := sv.SignMessage(bytes.NewReader([]byte(payload)))
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(sig)
}

func signCID(t *testing.T, key crypto.Signer) string {
	t.Helper()

	return signPayload(t, key, signersTestCID)
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
	}
}

func randomSignature(t *testing.T) string {
	t.Helper()

	junk := make([]byte, 64)
	_, err := rand.Read(junk)
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(junk)
}

func mustMarshalKey(t *testing.T, key crypto.PublicKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)

	return der
}

// junkSignatures are copies of the identity's certificate with random
// signature bytes.
func junkSignatures(t *testing.T, id testIdentity, count int) []*signv1.Signature {
	t.Helper()

	sigs := make([]*signv1.Signature, 0, count)
	for range count {
		sigs = append(sigs, &signv1.Signature{Signature: randomSignature(t), Certificate: encodeCert(id.cert)})
	}

	return sigs
}

// A signature made through the registry's signer binds its certificate for
// every key type the signer supports.
func TestCertificateSigners_BindsEverySignerKeyType(t *testing.T) {
	tests := []struct {
		name string
		key  func(t *testing.T) crypto.Signer
	}{
		{name: "ecdsa p-256", key: ecdsaKey(elliptic.P256())},
		{name: "ecdsa p-384", key: ecdsaKey(elliptic.P384())},
		{name: "ecdsa p-521", key: ecdsaKey(elliptic.P521())},
		{name: "ed25519", key: newEd25519Key},
		{name: "rsa 2048", key: newRSAKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := newTestIdentityWithKey(t, tc.key(t), signersTestSAN)

			signers, _, err := certificateSigners(t.Context(), signersTestCID, []*signv1.Signature{signedBy(t, id)})
			require.NoError(t, err)

			require.Len(t, signers, 1)
			assert.Equal(t, mustMarshalKey(t, id.key.Public()), signers[0].Key)
			assert.Equal(t, id.cert.Raw, signers[0].Certificate)
		})
	}
}

func TestCertificateSigners(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	attacker := newTestIdentity(t, "")
	impostor := newTestIdentity(t, signersTestSAN)

	victimKey := mustMarshalKey(t, victim.key.Public())
	attackerKey := mustMarshalKey(t, attacker.key.Public())
	impostorKey := mustMarshalKey(t, impostor.key.Public())

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
			name: "valid signature replayed from another record yields nothing",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{{Signature: signPayload(t, victim.key, taskTestOtherCID), Certificate: encodeCert(victim.cert)}}
			},
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
			name: "forty junk signatures plus one real yield exactly the real one",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return append(junkSignatures(t, victim, 40), signedBy(t, victim))
			},
			wantKeys:  [][]byte{victimKey},
			wantCerts: [][]byte{victim.cert.Raw},
		},
		{
			name: "real signature within the examined cap is found behind junk",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return append(junkSignatures(t, victim, maxSignaturesExamined-1), signedBy(t, victim))
			},
			wantKeys:  [][]byte{victimKey},
			wantCerts: [][]byte{victim.cert.Raw},
		},
		{
			name: "three hundred junk signatures ahead of the real one hit the cap and leave it unexamined",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return append(junkSignatures(t, victim, 300), signedBy(t, victim))
			},
		},
		{
			name: "keyless signature with a content bundle is skipped",
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
			name: "oversize signature is skipped before decoding",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				sig := signedBy(t, victim)
				sig.Signature = strings.Repeat("A", maxEncodedSignatureSize+4)

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
			name: "certificate with a key the registry never signs with is skipped",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				id := newTestIdentityWithKey(t, newECDSAKey(t, elliptic.P224()), signersTestSAN)
				digest := sha256.Sum256([]byte(signersTestCID))

				raw, err := id.key.Sign(rand.Reader, digest[:], crypto.SHA256)
				require.NoError(t, err)

				return []*signv1.Signature{{Signature: base64.StdEncoding.EncodeToString(raw), Certificate: encodeCert(id.cert)}}
			},
		},
		{
			name: "signers are listed in signature order",
			sigs: func(t *testing.T) []*signv1.Signature {
				t.Helper()

				return []*signv1.Signature{signedBy(t, attacker), signedBy(t, victim)}
			},
			wantKeys:  [][]byte{attackerKey, victimKey},
			wantCerts: [][]byte{attacker.cert.Raw, victim.cert.Raw},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signers, _, err := certificateSigners(t.Context(), signersTestCID, tc.sigs(t))
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

	_, _, err := certificateSigners(ctx, signersTestCID, []*signv1.Signature{signedBy(t, victim)})
	require.ErrorIs(t, err, context.Canceled)
}

func TestCertificateSignersReportsTheCap(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)

	tests := []struct {
		name       string
		sigs       []*signv1.Signature
		wantCapped bool
		wantCount  int
	}{
		{name: "one real signature is not capped", sigs: []*signv1.Signature{signedBy(t, victim)}, wantCount: 1},
		{name: "exactly the limit is not capped", sigs: junkSignatures(t, victim, maxSignaturesExamined), wantCapped: false},
		{name: "one over the limit is capped", sigs: junkSignatures(t, victim, maxSignaturesExamined+1), wantCapped: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signers, capped, err := certificateSigners(t.Context(), signersTestCID, tc.sigs)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCapped, capped)
			assert.Len(t, signers, tc.wantCount)
		})
	}
}

func TestRejectedCertificatesCount(t *testing.T) {
	var rejected rejectedCertificates

	for _, why := range []certificateRejection{rejectionNone, rejectionOversized, rejectionMalformed, rejectionMalformed, rejectionUnsupportedKey, rejectionUnbound} {
		rejected.count(why)
	}

	assert.Equal(t, rejectedCertificates{oversized: 1, malformed: 2, unsupportedKey: 1, unbound: 1}, rejected)
	assert.Equal(t, 5, rejected.total())
}
