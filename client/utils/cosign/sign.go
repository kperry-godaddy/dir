// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	csignature "github.com/sigstore/cosign/v3/pkg/signature"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	DefaultFulcioTimeout             = 30 * time.Second
	DefaultTimestampAuthorityTimeout = 30 * time.Second
	DefaultRekorTimeout              = 90 * time.Second
)

// SignBlobWithOIDC signs a blob using OIDC authentication.
func SignBlobWithOIDC(ctx context.Context, payload []byte, req *signv1.SignWithOIDC) (*signv1.Signature, *signv1.PublicKey, error) {
	signingTime := time.Now()

	// Get signing options from configuration
	signOpts, err := getOIDCSigningOptions(ctx, req, signingTime)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signing options: %w", err)
	}

	// Generate an ephemeral keypair for signing.
	signKeypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ephemeral keypair: %w", err)
	}

	// Get the public key in PEM format to return to the client.
	publicKeyPEM, err := signKeypair.GetPublicKeyPem()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Sign the payload
	sigBundle, err := sign.Bundle(&sign.PlainData{Data: payload}, signKeypair, signOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign record: %w", err)
	}

	// Marshal bundle to JSON using protobuf
	sigBundleJSON, err := protojson.Marshal(sigBundle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	signature := &signv1.Signature{
		Signature:     base64.StdEncoding.EncodeToString(sigBundle.GetMessageSignature().GetSignature()),
		Certificate:   base64.StdEncoding.EncodeToString(sigBundle.GetVerificationMaterial().GetCertificate().GetRawBytes()),
		ContentType:   sigBundle.GetMediaType(),
		ContentBundle: string(sigBundleJSON),
		SignedAt:      signingTime.UTC().Format(time.RFC3339),
	}
	publicKey := &signv1.PublicKey{
		Key: publicKeyPEM,
	}

	return signature, publicKey, nil
}

// SignBlobWithKey signs a blob using a private key.
// Supports both inline PEM content and key references (file paths, URLs, KMS URIs).
// When the request carries a certificate bundle, the certificate whose public
// key matches the signing key is attached to the signature; the match is
// checked before signing so a mismatch never invokes the signer.
func SignBlobWithKey(ctx context.Context, payload []byte, req *signv1.SignWithKey) (*signv1.Signature, *signv1.PublicKey, error) {
	sv, err := loadSignerVerifier(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	pubKey, err := sv.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("getting public key: %w", err)
	}

	var certificate string

	if bundle := req.GetCertificate(); bundle != "" {
		cert, err := selectCertificateForKey([]byte(bundle), pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("selecting certificate: %w", err)
		}

		certificate = base64.StdEncoding.EncodeToString(cert.Raw)
	}

	sig, err := sv.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("signing blob: %w", err)
	}

	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("getting public key: %w", err)
	}

	sigResult := &signv1.Signature{
		SignedAt:    time.Now().UTC().Format(time.RFC3339),
		Signature:   base64.StdEncoding.EncodeToString(sig),
		Algorithm:   detectKeyAlgorithm(string(publicKeyPEM)),
		Certificate: certificate,
	}
	publicKey := &signv1.PublicKey{
		Key: string(publicKeyPEM),
	}

	return sigResult, publicKey, nil
}

// loadSignerVerifier loads the request's private key, first as inline PEM and
// then as a key reference (file path, URL, KMS URI, etc.).
func loadSignerVerifier(ctx context.Context, req *signv1.SignWithKey) (signature.SignerVerifier, error) {
	privateKey := req.GetPrivateKey()
	if privateKey == "" {
		return nil, errors.New("private_key is required")
	}

	sv, err := cosign.LoadPrivateKey([]byte(privateKey), req.GetPassword(), nil)
	if err == nil {
		return sv, nil
	}

	sv, err = csignature.SignerVerifierFromKeyRef(ctx, privateKey, func(_ bool) ([]byte, error) {
		return req.GetPassword(), nil
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("loading private key from reference: %w", err)
	}

	return sv, nil
}

// selectCertificateForKey returns the first certificate in the PEM bundle whose
// public key equals signer. The bundle may hold a single certificate or a chain;
// it must not contain private keys.
func selectCertificateForKey(pemBundle []byte, signer crypto.PublicKey) (*x509.Certificate, error) {
	certs, err := parseCertificateBundle(pemBundle)
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		if cryptoutils.EqualKeys(signer, cert.PublicKey) == nil {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("none of the %d certificates match the signing key", len(certs))
}

// parseCertificateBundle parses every CERTIFICATE block in the PEM bundle. Blocks
// of other types are ignored, except private keys, which are rejected so a key
// file passed by mistake is never sent on as a certificate.
func parseCertificateBundle(pemBundle []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for rest := pemBundle; ; {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, errors.New("certificate file contains a private key block; pass only certificates")
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate %d: %w", len(certs)+1, err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE PEM block found (DER is not accepted; convert with: openssl x509 -inform der -outform pem)")
	}

	return certs, nil
}

// getOIDCSigningOptions returns bundle options configured from SignOptionsOIDC.
func getOIDCSigningOptions(ctx context.Context, req *signv1.SignWithOIDC, signatureTime time.Time) (sign.BundleOptions, error) {
	opts := req.GetOptions().GetDefaultOptions()

	// Construct signing config from request
	signingConfig, err := root.NewSigningConfig(
		root.SigningConfigMediaType02,
		// Fulcio URLs
		[]root.Service{
			{
				URL:                 opts.GetFulcioUrl(),
				MajorAPIVersion:     1,
				ValidityPeriodStart: signatureTime.Add(-time.Hour),
				ValidityPeriodEnd:   signatureTime.Add(time.Hour),
			},
		},
		// OIDC Provider URLs
		[]root.Service{
			{
				URL:                 opts.GetOidcProviderUrl(),
				MajorAPIVersion:     1,
				ValidityPeriodStart: signatureTime.Add(-time.Hour),
				ValidityPeriodEnd:   signatureTime.Add(time.Hour),
			},
		},
		// Rekor URLs
		[]root.Service{
			{
				URL:                 opts.GetRekorUrl(),
				MajorAPIVersion:     1,
				ValidityPeriodStart: signatureTime.Add(-time.Hour),
				ValidityPeriodEnd:   signatureTime.Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: v1.ServiceSelector_ANY,
		},
		// TSA URLs
		[]root.Service{
			{
				URL:                 opts.GetTimestampUrl(),
				MajorAPIVersion:     1,
				ValidityPeriodStart: signatureTime.Add(-time.Hour),
				ValidityPeriodEnd:   signatureTime.Add(time.Hour),
			},
		},
		root.ServiceConfiguration{
			Selector: v1.ServiceSelector_ANY,
		},
	)
	if err != nil {
		return sign.BundleOptions{}, fmt.Errorf("failed to get signing config: %w", err)
	}

	// Get signing options based on the signing config
	signOpts := sign.BundleOptions{
		Context: ctx,
		CertificateProviderOptions: &sign.CertificateProviderOptions{
			IDToken: req.GetIdToken(),
		},
	}
	{
		// Configure Fulcio certificate provider
		fulcioURL, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), []uint32{1}, signatureTime)
		if err != nil {
			return sign.BundleOptions{}, fmt.Errorf("failed to select fulcio URL: %w", err)
		}

		signOpts.CertificateProvider = sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioURL.URL,
			Timeout: DefaultFulcioTimeout,
			Retries: 1,
		})

		// Configure timestamp authorities
		tsaURLs, err := root.SelectServices(signingConfig.TimestampAuthorityURLs(),
			signingConfig.TimestampAuthorityURLsConfig(), []uint32{1}, signatureTime)
		if err != nil {
			return sign.BundleOptions{}, fmt.Errorf("failed to select timestamp authority URL: %w", err)
		}

		for _, tsaURL := range tsaURLs {
			signOpts.TimestampAuthorities = append(signOpts.TimestampAuthorities,
				sign.NewTimestampAuthority(&sign.TimestampAuthorityOptions{
					URL:     tsaURL.URL,
					Timeout: DefaultTimestampAuthorityTimeout,
					Retries: 1,
				}))
		}

		// Configure Rekor transparency logs (unless skip_tlog is set)
		if !opts.GetSkipTlog() {
			rekorURLs, err := root.SelectServices(signingConfig.RekorLogURLs(),
				signingConfig.RekorLogURLsConfig(), []uint32{1}, signatureTime)
			if err != nil {
				return sign.BundleOptions{}, fmt.Errorf("failed to select rekor URL: %w", err)
			}

			for _, rekorURL := range rekorURLs {
				signOpts.TransparencyLogs = append(signOpts.TransparencyLogs,
					sign.NewRekor(&sign.RekorOptions{
						BaseURL: rekorURL.URL,
						Timeout: DefaultRekorTimeout,
						Retries: 1,
					}))
			}
		}
	}

	return signOpts, nil
}
