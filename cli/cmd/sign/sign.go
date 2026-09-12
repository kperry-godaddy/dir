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
	cosignutil "github.com/agntcy/dir/client/utils/cosign"
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
The password is taken from the first of these sources that applies:
  1. COSIGN_PASSWORD, when set; an empty value is accepted
  2. standard input, when --password-stdin is set
  3. an interactive terminal prompt

Set COSIGN_PASSWORD to skip the prompt. A non-interactive process without
COSIGN_PASSWORD or --password-stdin uses an empty password, which also fits
key references that take none, such as KMS URIs. Local and inline PEM keys
must use the encrypted Cosign/Sigstore private-key format.

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
	c, ok := ctxUtils.GetClientFromContext(cmd.Context())
	if !ok {
		return errors.New("failed to get client from context")
	}

	sig, err := signRecord(cmd.Context(), c, recordCID, *opts, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	return printSignResult(cmd, sig)
}

// Sign signs the record with the flag-bound signing options and returns the
// stored signature. Warnings a user should see before signing, such as an
// attached certificate outside its validity period, go to stderr. "dirctl
// push --sign" and "dirctl import --sign" call it and report the certificate
// with PrintCertificate.
func Sign(ctx context.Context, c *client.Client, recordCID string, stderr io.Writer) (*signv1.Signature, error) {
	return signRecord(ctx, c, recordCID, *opts, stderr)
}

// CheckFlags reports a flag-bound signing option combination that can never
// sign, so a command can refuse before it pushes anything.
func CheckFlags() error {
	return checkOptions(*opts)
}

func checkOptions(o Options) error {
	if o.Certificate != "" && o.Key == "" {
		return errors.New("--certificate requires --key: a certificate can only be attached to a key-based signature")
	}

	return nil
}

func signRecord(ctx context.Context, c *client.Client, recordCID string, o Options, stderr io.Writer) (*signv1.Signature, error) {
	provider, err := signProvider(o, stderr)
	if err != nil {
		return nil, err
	}

	resp, err := c.Sign(ctx, &signv1.SignRequest{
		RecordRef: &corev1.RecordRef{Cid: recordCID},
		Provider:  provider,
	})
	if err != nil {
		if o.Key != "" {
			return nil, formatPrivateKeyError(err)
		}

		return nil, err
	}

	return resp.GetSignature(), nil
}

// signProvider builds the signing request for the configured options: a key
// reference, a pre-issued OIDC token, or an interactive OIDC login.
func signProvider(o Options, stderr io.Writer) (*signv1.SignRequestProvider, error) {
	if err := checkOptions(o); err != nil {
		return nil, err
	}

	switch {
	case o.Key != "":
		return keyProvider(o, stderr)

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
func keyProvider(o Options, stderr io.Writer) (*signv1.SignRequestProvider, error) {
	certificate, err := resolveCertificate(o, time.Now(), stderr)
	if err != nil {
		return nil, err
	}

	pw, err := readPrivateKeyPassword(o.PasswordStdin)()
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

// resolveCertificate reads the --certificate PEM bundle and returns it, or ""
// when none was requested. When no certificate in the bundle is valid at now,
// each one is reported on stderr before any signing or password prompt; the
// client attaches a valid one when there is any.
func resolveCertificate(o Options, now time.Time, stderr io.Writer) (string, error) {
	if o.Certificate == "" {
		return "", nil
	}

	data, err := os.ReadFile(o.Certificate) //nolint:gosec // operator-supplied path from a flag
	if err != nil {
		return "", fmt.Errorf("reading certificate file: %w", err)
	}

	certs, err := cosignutil.ParseCertificateBundle(data)
	if err != nil {
		return "", fmt.Errorf("certificate file %q: %w", o.Certificate, err)
	}

	warnings := make([]string, 0, len(certs))

	for _, cert := range certs {
		warning := certificateValidityWarning(cert, now)
		if warning == "" {
			return string(data), nil
		}

		warnings = append(warnings, warning)
	}

	for _, warning := range warnings {
		warn(stderr, warning)
	}

	return string(data), nil
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

// printSignResult reports the stored signature. A key-based signature with a
// certificate also reports the certificate's fingerprint.
func printSignResult(cmd *cobra.Command, sig *signv1.Signature) error {
	cert, ok := attachedCertificate(sig, cmd.ErrOrStderr())
	if !ok {
		return presenter.PrintMessage(cmd, "signature", "Record is", "signed")
	}

	return presenter.PrintMessage(cmd, "signature", "Record is", signOutcome{
		Signed:                 true,
		CertificateFingerprint: certificateFingerprint(cert),
	})
}

// PrintCertificate reports the certificate attached to a key-based signature
// for commands whose own result owns stdout: human output gets a line, the
// structured formats get it on stderr. A signature without a certificate
// prints nothing.
func PrintCertificate(cmd *cobra.Command, sig *signv1.Signature) {
	cert, ok := attachedCertificate(sig, cmd.ErrOrStderr())
	if !ok {
		return
	}

	presenter.PrintSmartf(cmd, "Signed with certificate %s\n", certificateFingerprint(cert))
}

// attachedCertificate decodes the certificate of a key-based signature. One
// that cannot be decoded is reported as a warning rather than an error: the
// signature is already stored, so the command has done its work.
func attachedCertificate(sig *signv1.Signature, stderr io.Writer) (*x509.Certificate, bool) {
	encoded, ok := sig.KeyCertificate()
	if !ok {
		return nil, false
	}

	cert, err := decodeCertificate(encoded)
	if err != nil {
		warn(stderr, fmt.Sprintf("the stored signature carries a certificate this dirctl cannot decode: %v", err))

		return nil, false
	}

	return cert, true
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
		return fmt.Sprintf("certificate %s is not valid before %s; a record signed with it fails name verification until then",
			certificateFingerprint(cert), cert.NotBefore.UTC().Format(time.RFC3339))

	case now.After(cert.NotAfter):
		return fmt.Sprintf("certificate %s expired at %s; a record signed with it fails name verification until the certificate is renewed and the record re-signed",
			certificateFingerprint(cert), cert.NotAfter.UTC().Format(time.RFC3339))

	default:
		return ""
	}
}

func warn(w io.Writer, message string) {
	_, _ = fmt.Fprintln(w, "Warning:", message)
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
			"failed to decrypt private key: the password is wrong or missing; set COSIGN_PASSWORD or use --password-stdin: %w",
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

func readPrivateKeyPassword(passwordStdin bool) func() ([]byte, error) {
	return privateKeyPasswordReader{
		lookupPassword: func() (string, bool) {
			return env.LookupEnv(env.VariablePassword)
		},
		passwordStdin: passwordStdin,
		stdin:         os.Stdin,
		isTerminal:    cosign.IsTerminal,
		readTerminal:  cosign.GetPassFromTerm,
	}.read
}
