// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/client/utils/cosign"
	"github.com/agntcy/dir/server/naming"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	// maxEncodedSignatureSize bounds one attached signature. The largest key
	// the registry signs with produces well under a kilobyte; the bound is
	// applied to the encoded length so an oversize value is never decoded.
	maxEncodedSignatureSize = 2 << 10

	// maxSignaturesExamined caps the signatures examined per record, so a
	// flood of junk signatures bounds the work of a run.
	maxSignaturesExamined = 256
)

var maxEncodedCertificateSize = base64.StdEncoding.EncodedLen(cosign.MaxCertificateDERSize)

// certificateSigners returns the record's certificate-bound signers: for each
// key-based signature carrying a certificate whose key produced the signature
// over the record CID, the certificate and its key. A copied certificate with
// a foreign signature yields nothing. Signatures are re-verified here because
// the signature task's rows do not carry the certificate and may not have run
// yet for the record.
//
// Duplicated certificates are reported once, in the order of their first
// signature. At most maxSignaturesExamined signatures are examined.
func certificateSigners(ctx context.Context, cid string, sigs []*signv1.Signature) ([]naming.Signer, error) {
	if len(sigs) > maxSignaturesExamined {
		logger.Warn("Examining only the first signatures of the record",
			"cid", cid, "signatures", len(sigs), "limit", maxSignaturesExamined)

		sigs = sigs[:maxSignaturesExamined]
	}

	var signers []naming.Signer

	seen := make(map[string]struct{})

	for _, sig := range sigs {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("certificate signers: %w", err)
		}

		cert, ok := boundCertificate(cid, sig)
		if !ok {
			continue
		}

		if _, dup := seen[string(cert.Raw)]; dup {
			continue
		}

		seen[string(cert.Raw)] = struct{}{}

		key, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			logger.Debug("Skipping signature: certificate key cannot be marshaled", "cid", cid, "error", err)

			continue
		}

		signers = append(signers, naming.Signer{Key: key, Certificate: cert.Raw})
	}

	return signers, nil
}

// boundCertificate parses the certificate attached to a key-based signature
// and returns it only when its key verifies the signature over the CID under
// the algorithm the registry signs with for that key type. The verifier is
// built from the parsed key, never from a string, so no key reference of any
// kind is ever resolved here.
func boundCertificate(cid string, sig *signv1.Signature) (*x509.Certificate, bool) {
	encodedCert, ok := sig.KeyCertificate()
	if !ok {
		return nil, false
	}

	if len(encodedCert) > maxEncodedCertificateSize {
		logger.Debug("Skipping signature: certificate exceeds the size limit",
			"cid", cid, "encodedLength", len(encodedCert), "limit", maxEncodedCertificateSize)

		return nil, false
	}

	if len(sig.GetSignature()) > maxEncodedSignatureSize {
		logger.Debug("Skipping signature: signature exceeds the size limit",
			"cid", cid, "encodedLength", len(sig.GetSignature()), "limit", maxEncodedSignatureSize)

		return nil, false
	}

	der, err := base64.StdEncoding.DecodeString(encodedCert)
	if err != nil {
		logger.Debug("Skipping signature: certificate is not base64", "cid", cid, "error", err)

		return nil, false
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		logger.Debug("Skipping signature: certificate does not parse", "cid", cid, "error", err)

		return nil, false
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig.GetSignature())
	if err != nil {
		logger.Debug("Skipping signature: signature is not base64", "cid", cid, "error", err)

		return nil, false
	}

	verifier, err := signature.LoadDefaultVerifier(cert.PublicKey, options.WithED25519ph())
	if err != nil {
		logger.Debug("Skipping signature: unsupported certificate key", "cid", cid, "error", err)

		return nil, false
	}

	if err := verifier.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader([]byte(cid))); err != nil {
		logger.Debug("Skipping signature: certificate key did not produce it", "cid", cid, "error", err)

		return nil, false
	}

	return cert, true
}
