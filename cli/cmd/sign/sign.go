// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:wrapcheck
package sign

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/cli/presenter"
	ctxUtils "github.com/agntcy/dir/cli/util/context"
	"github.com/agntcy/dir/client"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/env"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "sign",
	Short: "Sign record using identity-based OIDC or key-based signing",
	Long: `This command signs the record using identity-based signing.
It uses a short-lived signing certificate issued by Sigstore Fulcio
along with a local ephemeral signing key and OIDC identity.

Verification data is attached to the signed record,
and the transparency log is pushed to Sigstore Rekor.

This command opens a browser window to authenticate the user
with the default OIDC provider.

Key-based signing:
Pass --key with a KMS URI or an encrypted Cosign/Sigstore private key.
Wrap an existing key, such as an ANS identity key, with
"cosign import-key-pair --key <key.pem>", or generate a new one with
"cosign generate-key-pair". Add --certificate to attach the X.509
certificate that belongs to the key; records named ans://... are verified
through that certificate, and the command prints its fingerprint.

Password for encrypted private keys:
When using an encrypted private key, the password can be provided via:
  1. COSIGN_PASSWORD environment variable
  2. --password-stdin to explicitly read it from standard input
  3. Interactive terminal prompt (if running in a terminal)

In a non-interactive environment, standard input is read only when
--password-stdin is set. Otherwise, COSIGN_PASSWORD is used when present and an
empty password is used when it is absent. Local and inline PEM keys must use the
encrypted Cosign/Sigstore private-key format.

Usage examples:

1. Sign a record using OIDC:

	dirctl sign <record-cid>

2. Sign a record using key file:

	dirctl sign <record-cid> --key /path/to/cosign.key

3. Sign with encrypted key (password from env):

	COSIGN_PASSWORD=mypassword dirctl sign <record-cid> --key cosign.key

4. Sign with password from standard input:

	printf '%s' "$KEY_PASSWORD" | dirctl sign <record-cid> --key cosign.key --password-stdin

5. Sign an ans:// record with the ANS identity key and certificate:

	COSIGN_PASSWORD=mypassword dirctl sign <record-cid> \
	  --key import-cosign.key --certificate identity-cert.pem

6. Output formats:

	# Get signing result as JSON
	dirctl sign <record-cid> --output json
	
	# Sign with key and JSON output
	dirctl sign <record-cid> --key <key-file> --output json
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var recordCID string

		if len(args) > 1 {
			return errors.New("only one record CID is allowed")
		} else if len(args) == 1 {
			recordCID = args[0]
		} else {
			return errors.New("record CID is required")
		}

		return runCommand(cmd, recordCID)
	},
}

func runCommand(cmd *cobra.Command, recordCID string) error {
	// Get the client from the context
	c, ok := ctxUtils.GetClientFromContext(cmd.Context())
	if !ok {
		return errors.New("failed to get client from context")
	}

	resp, err := signRecord(cmd.Context(), c, recordCID)
	if err != nil {
		return fmt.Errorf("failed to sign record: %w", err)
	}

	return printSignResult(cmd, resp.GetSignature(), time.Now())
}

// Sign signs the record with the configured signing options. "dirctl push
// --sign" and "dirctl import --sign" share it and report success themselves.
func Sign(ctx context.Context, c *client.Client, recordCID string) error {
	_, err := signRecord(ctx, c, recordCID)

	return err
}

func signRecord(ctx context.Context, c *client.Client, recordCID string) (*signv1.SignResponse, error) {
	provider, err := signProvider(*opts)
	if err != nil {
		return nil, err
	}

	resp, err := c.Sign(ctx, &signv1.SignRequest{
		RecordRef: &corev1.RecordRef{Cid: recordCID},
		Provider:  provider,
	})
	if err != nil {
		if opts.Key != "" {
			err = formatPrivateKeyError(err)
		}

		return nil, fmt.Errorf("failed to sign record: %w", err)
	}

	return resp, nil
}

// signProvider builds the signing request for the configured options: a key
// reference, a pre-issued OIDC token, or an interactive OIDC login.
func signProvider(o Options) (*signv1.SignRequestProvider, error) {
	switch {
	case o.Key != "":
		return keyProvider(o)

	case o.OIDCToken != "":
		return oidcProvider(o, o.OIDCToken), nil

	default:
		token, err := oauthflow.OIDConnect(o.OIDCProviderURL, o.OIDCClientID, o.OIDCClientSecret, "", oauthflow.DefaultIDTokenGetter)
		if err != nil {
			return nil, fmt.Errorf("failed to get OIDC token: %w", err)
		}

		return oidcProvider(o, token.RawString), nil
	}
}

// keyProvider builds a key-based signing request. The key can be a file path,
// URL, KMS URI, etc.; the certificate is resolved before the password is read
// so a bad --certificate fails without prompting.
func keyProvider(o Options) (*signv1.SignRequestProvider, error) {
	certificate, err := resolveCertificate(o)
	if err != nil {
		return nil, err
	}

	pw, err := readPrivateKeyPassword()()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	key := &signv1.SignWithKey{
		PrivateKey: o.Key,
		Password:   pw,
	}
	if certificate != "" {
		key.Certificate = &certificate
	}

	return &signv1.SignRequestProvider{
		Request: &signv1.SignRequestProvider_Key{Key: key},
	}, nil
}

func oidcProvider(o Options, token string) *signv1.SignRequestProvider {
	return &signv1.SignRequestProvider{
		Request: &signv1.SignRequestProvider_Oidc{
			Oidc: &signv1.SignWithOIDC{
				IdToken: token,
				Options: &signv1.SignOptionsOIDC{
					FulcioUrl:        o.FulcioURL,
					RekorUrl:         o.RekorURL,
					TimestampUrl:     o.TimestampURL,
					OidcProviderUrl:  o.OIDCProviderURL,
					OidcClientId:     o.OIDCClientID,
					OidcClientSecret: o.OIDCClientSecret,
					SkipTlog:         o.SkipTlog,
				},
			},
		},
	}
}

// resolveCertificate reads the --certificate PEM file. It returns "" when no
// certificate was requested. The file is read here because the request carries
// the certificate inline and, unlike the private key, it is public material.
func resolveCertificate(o Options) (string, error) {
	if o.Certificate == "" {
		return "", nil
	}

	if o.Key == "" {
		return "", errors.New("--certificate requires --key: a certificate can only be attached to a key-based signature")
	}

	data, err := os.ReadFile(o.Certificate) //nolint:gosec // operator-supplied path from a flag
	if err != nil {
		return "", fmt.Errorf("reading certificate file: %w", err)
	}

	if !containsCertificateBlock(data) {
		return "", fmt.Errorf("certificate file %q contains no CERTIFICATE PEM block", o.Certificate)
	}

	return string(data), nil
}

func containsCertificateBlock(data []byte) bool {
	for rest := data; ; {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}

		if block.Type == "CERTIFICATE" {
			return true
		}
	}
}

// signOutcome is printed when a certificate was attached to a key-based
// signature. Structured output modes print it as one object.
type signOutcome struct {
	Signed                 bool   `json:"signed"`
	CertificateFingerprint string `json:"certificate_fingerprint"`
}

func (o signOutcome) String() string {
	return "signed (certificate " + o.CertificateFingerprint + ")"
}

// printSignResult reports the signature. Key-based signatures that carry a
// certificate also report its fingerprint, and a certificate outside its
// validity period is warned about on stderr. OIDC signatures keep the plain
// "signed" output; their Fulcio certificate is not the user's to track.
func printSignResult(cmd *cobra.Command, sig *signv1.Signature, now time.Time) error {
	if sig.GetContentBundle() != "" || sig.GetCertificate() == "" {
		return presenter.PrintMessage(cmd, "signature", "Record is", "signed")
	}

	cert, err := decodeCertificate(sig.GetCertificate())
	if err != nil {
		return fmt.Errorf("decoding attached certificate: %w", err)
	}

	if warning := certificateValidityWarning(cert, now); warning != "" {
		presenter.Errorf(cmd, "Warning: %s\n", warning)
	}

	return presenter.PrintMessage(cmd, "signature", "Record is", signOutcome{
		Signed:                 true,
		CertificateFingerprint: certificateFingerprint(cert),
	})
}

func decodeCertificate(encoded string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

// certificateFingerprint renders the SHA-256 fingerprint of the certificate in
// the "SHA256:<hex>" form the ANS transparency log reports for identity
// certificates, so the two can be compared directly.
func certificateFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)

	return "SHA256:" + hex.EncodeToString(sum[:])
}

// certificateValidityWarning describes why the certificate is not valid at now,
// or returns "" when it is.
func certificateValidityWarning(cert *x509.Certificate, now time.Time) string {
	switch {
	case now.Before(cert.NotBefore):
		return fmt.Sprintf("certificate %s is not valid before %s; name verification will fail until then",
			certificateFingerprint(cert), cert.NotBefore.UTC().Format(time.RFC3339))

	case now.After(cert.NotAfter):
		return fmt.Sprintf("certificate %s expired at %s; renew it and re-sign the record or name verification will fail",
			certificateFingerprint(cert), cert.NotAfter.UTC().Format(time.RFC3339))

	default:
		return ""
	}
}

func formatPrivateKeyError(err error) error {
	// cosign.LoadPrivateKey currently returns unsupported PEM types as an
	// untyped error, so preserve the original error while adding actionable
	// guidance for dirctl users.
	if strings.Contains(err.Error(), "unsupported pem type") { //nolint:errorlint // cosign exposes no typed/sentinel error
		return fmt.Errorf(
			"unsupported private key format: expected an encrypted Cosign/Sigstore private key; "+
				"wrap an existing key with \"cosign import-key-pair --key <key.pem>\" "+
				"or generate one with \"cosign generate-key-pair\": %w",
			err,
		)
	}

	if strings.Contains(err.Error(), "decrypt:") { //nolint:errorlint // cosign exposes no typed/sentinel error
		return fmt.Errorf(
			"failed to decrypt private key: set COSIGN_PASSWORD or use --password-stdin: %w",
			err,
		)
	}

	return err
}

type privateKeyPasswordReader struct {
	lookupPassword func() (string, bool)
	passwordStdin  bool
	stdin          io.Reader
	isTerminal     func() bool
	readTerminal   func(bool) ([]byte, error)
}

func (r privateKeyPasswordReader) read() ([]byte, error) {
	pw, ok := r.lookupPassword()

	switch {
	case ok:
		return []byte(pw), nil
	case r.passwordStdin:
		return io.ReadAll(r.stdin)
	case r.isTerminal():
		return r.readTerminal(true)
	default:
		// Match the previous EOF behavior without blocking indefinitely on an
		// unrelated or permanently open stdin stream. This also allows passwordless
		// local keys and key references that do not consume a password (for example KMS).
		return []byte{}, nil
	}
}

func readPrivateKeyPassword() func() ([]byte, error) {
	return privateKeyPasswordReader{
		lookupPassword: func() (string, bool) {
			return env.LookupEnv(env.VariablePassword)
		},
		passwordStdin: opts.PasswordStdin,
		stdin:         os.Stdin,
		isTerminal:    cosign.IsTerminal,
		readTerminal:  cosign.GetPassFromTerm,
	}.read
}
