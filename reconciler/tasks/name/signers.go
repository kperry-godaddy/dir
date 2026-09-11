// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/server/naming"
	"github.com/sigstore/sigstore/pkg/signature"
)

// maxCertificateDERSize bounds one attached certificate. Identity certificates
// are a few kilobytes; the bound is applied to the encoded length so an
// oversize value is never decoded.
const maxCertificateDERSize = 16 << 10

var maxEncodedCertificateSize = base64.StdEncoding.EncodedLen(maxCertificateDERSize)

// certificateSigners returns the signers of an ans:// record. A signer is a
// key-based signature that carries a certificate whose key produced the
// signature over the record CID, so the certificates the verifier sees are
// exactly those whose keys signed the record. A copied certificate with a
// foreign signature yields nothing.
//
// Every signature is examined and the result is deduplicated by certificate,
// so junk signatures pushed onto a record cannot crowd out the real one.
// Signers whose certificate names an ans:// URI under host are listed first;
// the order is a preference for the verifier, not a filter.
func certificateSigners(ctx context.Context, cid, host string, sigs []*signv1.Signature) ([]naming.Signer, error) {
	var preferred, others []naming.Signer

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

		signer := naming.Signer{Key: key, Certificate: cert.Raw}

		if namesHost(cert, host) {
			preferred = append(preferred, signer)
		} else {
			others = append(others, signer)
		}
	}

	return append(preferred, others...), nil
}

// boundCertificate parses the certificate attached to a key-based signature
// and returns it only when its key verifies the signature over the CID. The
// verifier is built from the parsed key, never from a string, so no key
// reference of any kind is ever resolved here.
func boundCertificate(cid string, sig *signv1.Signature) (*x509.Certificate, bool) {
	if sig.GetContentBundle() != "" || sig.GetCertificate() == "" {
		return nil, false
	}

	if len(sig.GetCertificate()) > maxEncodedCertificateSize {
		logger.Debug("Skipping signature: certificate exceeds the size limit",
			"cid", cid, "encodedLength", len(sig.GetCertificate()), "limit", maxEncodedCertificateSize)

		return nil, false
	}

	der, err := base64.StdEncoding.DecodeString(sig.GetCertificate())
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

	verifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
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

// namesHost reports whether the certificate carries an ans:// URI whose host
// ends in "." + host, the shape of an ANS identity certificate for the record.
func namesHost(cert *x509.Certificate, host string) bool {
	suffix := "." + strings.ToLower(host)

	for _, uri := range cert.URIs {
		if uri.Scheme+"://" == naming.ANSProtocol && strings.HasSuffix(strings.ToLower(uri.Host), suffix) {
			return true
		}
	}

	return false
}
