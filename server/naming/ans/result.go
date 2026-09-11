// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/url"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
	"github.com/agntcy/dir/server/naming/ans/details"
)

// buildResult renders the matched certificates as published keys together
// with the verification details.
func buildResult(want agentName, target badgeTarget, token *scitt.VerifiedStatusToken, matched []*x509.Certificate) (*naming.LookupResult, error) {
	keys := make([]naming.PublicKey, 0, len(matched))

	for _, cert := range matched {
		der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, failWith(stageCertificate, err, "certificate public key cannot be encoded")
		}

		keys = append(keys, naming.PublicKey{
			ID:        verify.CertFingerprintFromDER(cert.Raw).String(),
			Type:      keyTypeOf(cert.PublicKey),
			Key:       der,
			KeyBase64: base64.StdEncoding.EncodeToString(der),
		})
	}

	receiptURL, err := url.JoinPath(target.LogBase, "v1", "agents", target.AgentID, "receipt")
	if err != nil {
		return nil, failWith(stageReceipt, err, "cannot build the receipt URL")
	}

	encoded, err := json.Marshal(details.Details{
		Version:     details.Version,
		AnsName:     want.String(),
		AgentHost:   want.host,
		AgentID:     target.AgentID,
		LogURL:      target.LogBase,
		ReceiptURL:  receiptURL,
		AgentStatus: string(token.Payload.Status),
	})
	if err != nil {
		return nil, failWith(stageReceipt, err, "cannot encode verification details")
	}

	return &naming.LookupResult{Keys: keys, Details: encoded}, nil
}

// keyTypeOf names the algorithm of a certificate public key the way the
// naming API reports key types.
func keyTypeOf(pub crypto.PublicKey) string {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsaKeyType(key)
	case ed25519.PublicKey:
		return "ed25519"
	case *rsa.PublicKey:
		return "rsa"
	default:
		return "unknown"
	}
}

func ecdsaKeyType(key *ecdsa.PublicKey) string {
	switch key.Curve {
	case elliptic.P256():
		return "ecdsa-p256"
	case elliptic.P384():
		return "ecdsa-p384"
	case elliptic.P521():
		return "ecdsa-p521"
	default:
		return "ecdsa"
	}
}
