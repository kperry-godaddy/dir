// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/fxamacker/cbor/v2"
)

// testOrigin is the origin the synthetic log claims as receipt issuer.
const testOrigin = "example-log"

// testLog is a synthetic transparency log: one ES256 signing key, its 4-byte
// key id, and the origin its receipts claim as issuer. Every artifact it mints
// follows the layouts the SDK's own tests verify against.
type testLog struct {
	key    *ecdsa.PrivateKey
	kid    [4]byte
	origin string
}

func mintLog(t *testing.T) *testLog {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}

	sum := sha256.Sum256(spkiOf(t, &key.PublicKey))

	var kid [4]byte

	copy(kid[:], sum[:4])

	return &testLog{key: key, kid: kid, origin: testOrigin}
}

// rootKeyLine renders the log's verification key as one /root-keys line:
// origin+hex(kid)+base64(0x02 || SPKI DER).
func (l *testLog) rootKeyLine(t *testing.T) string {
	t.Helper()

	spki := spkiOf(t, &l.key.PublicKey)

	return l.origin + "+" + hex.EncodeToString(l.kid[:]) + "+" + base64.StdEncoding.EncodeToString(append([]byte{0x02}, spki...))
}

// tokenClaims are the status-token payload fields a test controls.
type tokenClaims struct {
	agentID       string
	ansName       string
	status        string
	iat           int64
	exp           int64
	identityCerts []string
}

// statusToken mints a COSE_Sign1 status token with the int-keyed payload the
// reference log emits: fingerprints as "SHA256:<hex>" strings.
func (l *testLog) statusToken(t *testing.T, claims tokenClaims) []byte {
	t.Helper()

	certs := make([]map[int64]any, 0, len(claims.identityCerts))
	for _, fp := range claims.identityCerts {
		certs = append(certs, map[int64]any{1: fp, 2: "X509-OV-CLIENT"})
	}

	payload := map[int64]any{
		1: claims.agentID,
		2: claims.status,
		3: claims.iat,
		4: claims.exp,
		5: claims.ansName,
		6: certs,
	}

	protected := map[int64]any{
		1: int64(-7),
		3: "application/ans-status-token+cbor",
		4: l.kid[:],
	}

	return l.coseSign1(t, protected, map[int64]any{}, mustCBOR(t, payload))
}

// receipt mints a COSE_Sign1 receipt over event with the inclusion proof in
// the unprotected header. An empty path with treeSize 1 is a single-leaf tree.
func (l *testLog) receipt(t *testing.T, event []byte, treeSize, leafIndex uint64, path [][]byte, iat int64) []byte {
	t.Helper()

	protected := map[int64]any{
		1:   int64(-7),
		4:   l.kid[:],
		395: int64(1),
		15:  map[int64]any{1: l.origin, 6: iat},
	}

	if path == nil {
		path = [][]byte{}
	}

	unprotected := map[int64]any{
		396: map[int64]any{-1: treeSize, -2: leafIndex, -3: path},
	}

	return l.coseSign1(t, protected, unprotected, event)
}

// coseSign1 signs payload under the protected header with ES256 and returns
// the tag-18 COSE_Sign1 encoding. r and s are written with FillBytes so the
// P1363 signature is always 64 bytes.
func (l *testLog) coseSign1(t *testing.T, protected, unprotected map[int64]any, payload []byte) []byte {
	t.Helper()

	protectedBytes := mustCBOR(t, protected)

	digest, err := scitt.ComputeSigStructureDigest(protectedBytes, payload)
	if err != nil {
		t.Fatalf("sig structure digest: %v", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, l.key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	return mustCBOR(t, cbor.Tag{Number: 18, Content: []any{protectedBytes, unprotected, payload, sig}})
}

func mustCBOR(t *testing.T, value any) []byte {
	t.Helper()

	encoded, err := cbor.Marshal(value)
	if err != nil {
		t.Fatalf("cbor marshal: %v", err)
	}

	return encoded
}

func spkiOf(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	return spki
}

// identityCert is a minted ANS identity certificate with its signing key.
type identityCert struct {
	der         []byte
	key         crypto.Signer
	fingerprint string
}

// mintIdentityCert mints a self-signed P-256 identity certificate whose only
// SAN is the ANS name URI.
func mintIdentityCert(t *testing.T, ansName string, notBefore, notAfter time.Time) identityCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate identity key: %v", err)
	}

	return mintIdentityCertWithKey(t, ansName, notBefore, notAfter, key)
}

func mintIdentityCertWithKey(t *testing.T, ansName string, notBefore, notAfter time.Time, key crypto.Signer) identityCert {
	t.Helper()

	uri, err := url.Parse(ansName)
	if err != nil {
		t.Fatalf("parse ans name: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return identityCert{der: der, key: key, fingerprint: verify.CertFingerprintFromDER(der).String()}
}

// eventJSON renders an ANS event envelope naming the agent under idKey
// ("ansId" for the reference log, "agentId" for the older shape).
func eventJSON(t *testing.T, idKey, agentID, ansName string) []byte {
	t.Helper()

	envelope := map[string]any{
		"payload": map[string]any{
			"logId": "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b",
			"producer": map[string]any{
				"event": map[string]any{
					idKey:       agentID,
					"ansName":   ansName,
					"eventType": "AGENT_REGISTERED",
				},
				"keyId":     "ra-key",
				"signature": "detached-jws",
			},
		},
		"schemaVersion": "V2",
	}

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	return encoded
}

// TestMintedFixturesVerify checks the minting helpers against the SDK
// verifiers, so a helper regression cannot masquerade as a verifier bug.
func TestMintedFixturesVerify(t *testing.T) {
	log := mintLog(t)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	cert := mintIdentityCert(t, "ans://v1.0.0.agent.example.com", now.Add(-time.Hour), now.Add(time.Hour))

	keys, err := scitt.NewKeyStore([]string{log.rootKeyLine(t)})
	if err != nil {
		t.Fatalf("NewKeyStore() error = %v", err)
	}

	token := log.statusToken(t, tokenClaims{
		agentID:       "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10",
		ansName:       "ans://v1.0.0.agent.example.com",
		status:        "ACTIVE",
		iat:           now.Unix() - 60,
		exp:           now.Unix() + 3600,
		identityCerts: []string{cert.fingerprint},
	})

	verified, err := scitt.VerifyStatusTokenAt(token, keys, 0, now.Unix())
	if err != nil {
		t.Fatalf("VerifyStatusTokenAt() error = %v", err)
	}

	if !scitt.MatchesIdentityCert(&verified.Payload, verify.CertFingerprintFromDER(cert.der).Bytes()) {
		t.Error("minted token does not attest the minted certificate")
	}

	event := eventJSON(t, "ansId", "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10", "ans://v1.0.0.agent.example.com")

	receipt, err := scitt.VerifyReceipt(log.receipt(t, event, 1, 0, nil, now.Unix()), keys)
	if err != nil {
		t.Fatalf("VerifyReceipt() error = %v", err)
	}

	if receipt.TreeSize != 1 || receipt.LeafIndex != 0 || string(receipt.EventBytes) != string(event) {
		t.Errorf("VerifyReceipt() = treeSize %d leafIndex %d, want 1 0 with the event bytes", receipt.TreeSize, receipt.LeafIndex)
	}

	if receipt.Iss == nil || *receipt.Iss != testOrigin {
		t.Errorf("receipt issuer = %v, want %s", receipt.Iss, testOrigin)
	}
}
