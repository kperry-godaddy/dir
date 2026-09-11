// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	"github.com/agntcy/dir/cli/presenter"
	ctxUtils "github.com/agntcy/dir/cli/util/context"
	"github.com/agntcy/dir/client"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
)

const testKeyPassword = "pw"

type trackingReader struct {
	read bool
}

func (r *trackingReader) Read([]byte) (int, error) {
	r.read = true

	return 0, io.EOF
}

func TestAddSigningFlagsRegistersPasswordStdin(t *testing.T) {
	original := opts.PasswordStdin

	t.Cleanup(func() {
		opts.PasswordStdin = original
	})

	flags := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	AddSigningFlags(flags)

	if err := flags.Parse([]string{"--password-stdin"}); err != nil {
		t.Fatalf("parse --password-stdin: %v", err)
	}

	if !opts.PasswordStdin {
		t.Fatal("--password-stdin did not enable stdin password reading")
	}
}

func TestPrivateKeyPasswordReaderDefaultsToEmptyWithoutTerminal(t *testing.T) {
	t.Parallel()

	stdin := &trackingReader{}
	reader := privateKeyPasswordReader{
		lookupPassword: func() (string, bool) { return "", false },
		passwordStdin:  false,
		stdin:          stdin,
		isTerminal:     func() bool { return false },
		readTerminal: func(bool) ([]byte, error) {
			t.Fatal("terminal reader must not be called")

			return nil, errors.New("unreachable")
		},
	}

	password, err := reader.read()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if len(password) != 0 {
		t.Fatalf("password = %q, want empty password", password)
	}

	if stdin.read {
		t.Fatal("password reader attempted to read non-interactive stdin")
	}
}

func TestPrivateKeyPasswordReaderUsesEnvironmentBeforeStdin(t *testing.T) {
	t.Parallel()

	stdin := &trackingReader{}
	reader := privateKeyPasswordReader{
		lookupPassword: func() (string, bool) { return "", true },
		passwordStdin:  true,
		stdin:          stdin,
		isTerminal: func() bool {
			t.Fatal("terminal detection must not be called")

			return false
		},
		readTerminal: func(bool) ([]byte, error) {
			t.Fatal("terminal reader must not be called")

			return nil, errors.New("unreachable")
		},
	}

	password, err := reader.read()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if len(password) != 0 {
		t.Fatalf("password = %q, want empty password", password)
	}

	if stdin.read {
		t.Fatal("password reader ignored COSIGN_PASSWORD precedence")
	}
}

func TestPrivateKeyPasswordReaderReadsStdinOnlyWhenRequested(t *testing.T) {
	t.Parallel()

	const want = "secret"

	reader := privateKeyPasswordReader{
		lookupPassword: func() (string, bool) { return "", false },
		passwordStdin:  true,
		stdin:          strings.NewReader(want),
		isTerminal: func() bool {
			t.Fatal("terminal detection must not be called")

			return false
		},
		readTerminal: func(bool) ([]byte, error) {
			t.Fatal("terminal reader must not be called")

			return nil, errors.New("unreachable")
		},
	}

	password, err := reader.read()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if string(password) != want {
		t.Fatalf("password = %q, want %q", password, want)
	}
}

func TestPrivateKeyPasswordReaderUsesTerminal(t *testing.T) {
	t.Parallel()

	const want = "terminal-secret"

	reader := privateKeyPasswordReader{
		lookupPassword: func() (string, bool) { return "", false },
		passwordStdin:  false,
		stdin:          &trackingReader{},
		isTerminal:     func() bool { return true },
		readTerminal: func(confirm bool) ([]byte, error) {
			if !confirm {
				t.Fatal("terminal password must request confirmation")
			}

			return []byte(want), nil
		},
	}

	password, err := reader.read()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if string(password) != want {
		t.Fatalf("password = %q, want %q", password, want)
	}
}

func TestReadPrivateKeyPasswordUsesEnvironment(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "secret")

	password, err := readPrivateKeyPassword(false)()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if string(password) != "secret" {
		t.Fatalf("password = %q, want %q", password, "secret")
	}
}

func TestFormatPrivateKeyError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cause        error
		wantGuidance []string
		wantVerbatim bool
	}{
		{
			name:         "unsupported pem type gets cosign guidance",
			cause:        errors.New("unsupported pem type: PRIVATE KEY"),
			wantGuidance: []string{"cosign generate-key-pair", "cosign import-key-pair --key <key.pem>"},
		},
		{
			name:         "decrypt failure gets password guidance",
			cause:        errors.New("decrypt: invalid password"),
			wantGuidance: []string{"COSIGN_PASSWORD", "--password-stdin"},
		},
		{
			name:         "other errors pass through",
			cause:        errors.New("key file not found"),
			wantVerbatim: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := formatPrivateKeyError(tt.cause)
			if !errors.Is(got, tt.cause) {
				t.Fatalf("formatPrivateKeyError() = %v, does not preserve the cause", got)
			}

			if tt.wantVerbatim && got.Error() != tt.cause.Error() {
				t.Fatalf("formatPrivateKeyError() = %q, want the cause unchanged", got)
			}

			for _, guidance := range tt.wantGuidance {
				if !strings.Contains(got.Error(), guidance) {
					t.Fatalf("formatPrivateKeyError() = %q, want containing %q", got, guidance)
				}
			}
		})
	}
}

// newTestKey generates a P-256 identity key.
func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

// newTestCertificate issues a self-signed identity certificate for key, valid
// between notBefore and notAfter.
func newTestCertificate(t *testing.T, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         []*url.URL{{Scheme: "ans", Host: "v1.0.0.agent.example.com"}},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return cert
}

func writeTestFile(t *testing.T, name string, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}

func certificatePEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// importCosignKey writes key in the encrypted Cosign private-key format the way
// "cosign import-key-pair" does and returns the path of the key file.
func importCosignKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	keys, err := cosign.ImportKeyPair(writeTestFile(t, "identity-key.pem", privateKeyPEM(t, key)), func(bool) ([]byte, error) {
		return []byte(testKeyPassword), nil
	})
	if err != nil {
		t.Fatalf("import key pair: %v", err)
	}

	return writeTestFile(t, "import-cosign.key", keys.PrivateBytes)
}

func TestAddSigningFlagsRegistersCertificate(t *testing.T) {
	original := opts.Certificate

	t.Cleanup(func() {
		opts.Certificate = original
	})

	flags := pflag.NewFlagSet("sign", pflag.ContinueOnError)
	AddSigningFlags(flags)

	if err := flags.Parse([]string{"--certificate", "identity-cert.pem"}); err != nil {
		t.Fatalf("parse --certificate: %v", err)
	}

	if opts.Certificate != "identity-cert.pem" {
		t.Fatalf("opts.Certificate = %q, want %q", opts.Certificate, "identity-cert.pem")
	}
}

func TestResolveCertificate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t)
	cert := newTestCertificate(t, key, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newTestCertificate(t, key, now.Add(-2*time.Hour), now.Add(-time.Hour))
	certPath := writeTestFile(t, "identity-cert.pem", certificatePEM(cert))
	expiredPath := writeTestFile(t, "expired-cert.pem", certificatePEM(expired))
	chainPath := writeTestFile(t, "chain.pem", append(certificatePEM(cert), certificatePEM(expired)...))
	publicKeyPath := writeTestFile(t, "key.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a certificate")}))
	keyPath := writeTestFile(t, "identity-key.pem", privateKeyPEM(t, key))

	tests := []struct {
		name        string
		options     Options
		want        string
		wantErr     string
		wantWarning string
	}{
		{
			name:    "no certificate requested",
			options: Options{Key: "cosign.key"},
		},
		{
			name:    "unreadable file",
			options: Options{Key: "cosign.key", Certificate: filepath.Join(t.TempDir(), "missing.pem")},
			wantErr: "reading certificate file",
		},
		{
			name:    "file without certificate block",
			options: Options{Key: "cosign.key", Certificate: publicKeyPath},
			wantErr: "no CERTIFICATE PEM block found",
		},
		{
			name:    "private key passed as certificate",
			options: Options{Key: "cosign.key", Certificate: keyPath},
			wantErr: "contains a private key block",
		},
		{
			name:    "valid certificate",
			options: Options{Key: "cosign.key", Certificate: certPath},
			want:    string(certificatePEM(cert)),
		},
		{
			name:        "expired certificate warns before signing",
			options:     Options{Key: "cosign.key", Certificate: expiredPath},
			want:        string(certificatePEM(expired)),
			wantWarning: "Warning: certificate " + certificateFingerprint(expired) + " expired at 2026-09-11T11:00:00Z",
		},
		{
			name:        "chain warns about each certificate outside its validity",
			options:     Options{Key: "cosign.key", Certificate: chainPath},
			want:        string(append(certificatePEM(cert), certificatePEM(expired)...)),
			wantWarning: "Warning: certificate " + certificateFingerprint(expired) + " expired at",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stderr bytes.Buffer

			got, err := resolveCertificate(tt.options, now, &stderr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveCertificate() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("resolveCertificate() error = %v", err)
			}

			if got != tt.want {
				t.Fatalf("resolveCertificate() = %q, want %q", got, tt.want)
			}

			assertStderr(t, &stderr, tt.wantWarning)

			if tt.wantWarning != "" && strings.Count(stderr.String(), "Warning:") != 1 {
				t.Fatalf("stderr = %q, want exactly one warning", stderr.String())
			}
		})
	}
}

func TestKeyProvider(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "secret")

	now := time.Now()
	cert := newTestCertificate(t, newTestKey(t), now.Add(-time.Hour), now.Add(time.Hour))
	certPath := writeTestFile(t, "identity-cert.pem", certificatePEM(cert))

	tests := []struct {
		name            string
		options         Options
		wantCertificate *string
		wantErr         string
	}{
		{
			name:            "attaches the certificate",
			options:         Options{Key: "cosign.key", Certificate: certPath},
			wantCertificate: new(string(certificatePEM(cert))),
		},
		{
			name:    "without certificate",
			options: Options{Key: "cosign.key"},
		},
		{
			name:    "unreadable certificate fails before the password is read",
			options: Options{Key: "cosign.key", Certificate: filepath.Join(t.TempDir(), "missing.pem")},
			wantErr: "reading certificate file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer

			provider, err := keyProvider(tt.options, &stderr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("keyProvider() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("keyProvider() error = %v", err)
			}

			key := provider.GetKey()
			if key.GetPrivateKey() != tt.options.Key || string(key.GetPassword()) != "secret" {
				t.Fatalf("keyProvider() key = %q password = %q", key.GetPrivateKey(), key.GetPassword())
			}

			if tt.wantCertificate == nil && key.Certificate != nil {
				t.Fatalf("keyProvider() attached certificate %q without --certificate", key.GetCertificate())
			}

			if tt.wantCertificate != nil && key.GetCertificate() != *tt.wantCertificate {
				t.Fatalf("keyProvider() certificate = %q, want the PEM file contents", key.GetCertificate())
			}
		})
	}
}

func TestSignProvider(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "secret")

	tests := []struct {
		name    string
		options Options
		check   func(t *testing.T, provider *signv1.SignRequestProvider)
		wantErr string
	}{
		{
			name:    "certificate without key",
			options: Options{Certificate: "identity-cert.pem"},
			wantErr: "--certificate requires --key",
		},
		{
			name:    "key",
			options: Options{Key: "cosign.key"},
			check: func(t *testing.T, provider *signv1.SignRequestProvider) {
				t.Helper()

				if provider.GetKey().GetPrivateKey() != "cosign.key" {
					t.Fatalf("signProvider() = %v, want a key provider for cosign.key", provider)
				}
			},
		},
		{
			name:    "oidc token",
			options: Options{OIDCToken: "token", FulcioURL: "https://fulcio.example.com", SkipTlog: true},
			check: func(t *testing.T, provider *signv1.SignRequestProvider) {
				t.Helper()

				oidc := provider.GetOidc()
				if oidc.GetIdToken() != "token" || oidc.GetOptions().GetFulcioUrl() != "https://fulcio.example.com" || !oidc.GetOptions().GetSkipTlog() {
					t.Fatalf("signProvider() = %v, want the OIDC options carried over", oidc)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := signProvider(tt.options, io.Discard)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("signProvider() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("signProvider() error = %v", err)
			}

			tt.check(t, provider)
		})
	}
}

func TestCertificateFingerprint(t *testing.T) {
	t.Parallel()

	cert := &x509.Certificate{Raw: []byte("abc")}

	const want = "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	if got := certificateFingerprint(cert); got != want {
		t.Fatalf("certificateFingerprint() = %q, want %q", got, want)
	}
}

func TestCertificateValidityWarning(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t)

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		want      string
	}{
		{
			name:      "valid",
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(time.Hour),
		},
		{
			name:      "not yet valid",
			notBefore: now.Add(time.Hour),
			notAfter:  now.Add(2 * time.Hour),
			want:      "is not valid before 2026-09-11T13:00:00Z",
		},
		{
			name:      "expired",
			notBefore: now.Add(-2 * time.Hour),
			notAfter:  now.Add(-time.Hour),
			want:      "expired at 2026-09-11T11:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert := newTestCertificate(t, key, tt.notBefore, tt.notAfter)

			got := certificateValidityWarning(cert, now)
			if tt.want == "" && got != "" {
				t.Fatalf("certificateValidityWarning() = %q, want no warning", got)
			}

			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Fatalf("certificateValidityWarning() = %q, want containing %q", got, tt.want)
			}
		})
	}
}

// assertStderr requires stderr to be empty when want is "" and to contain want
// otherwise.
func assertStderr(t *testing.T, stderr *bytes.Buffer, want string) {
	t.Helper()

	if want == "" && stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want nothing", stderr.String())
	}

	if !strings.Contains(stderr.String(), want) {
		t.Fatalf("stderr = %q, want containing %q", stderr.String(), want)
	}
}

// assertErrorContains requires err to mention every want.
func assertErrorContains(t *testing.T, err error, wants ...string) {
	t.Helper()

	if err == nil {
		t.Fatalf("got no error, want one containing %q", wants)
	}

	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want containing %q", err, want)
		}
	}
}

func newOutputCommand(t *testing.T, format string) (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	presenter.AddOutputFlags(cmd)

	if err := cmd.Flags().Set("output", format); err != nil {
		t.Fatalf("set --output %s: %v", format, err)
	}

	return cmd, &stdout, &stderr
}

const undecodableWarning = "Warning: the stored signature carries a certificate this dirctl cannot decode"

func TestPrintSignResult(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cert := newTestCertificate(t, newTestKey(t), now.Add(-time.Hour), now.Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)

	tests := []struct {
		name       string
		format     string
		signature  *signv1.Signature
		wantStdout string
		wantJSON   map[string]any
		wantStderr string
	}{
		{
			name:       "human without certificate",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln"},
			wantStdout: "Record is: signed\n",
		},
		{
			name:       "json without certificate",
			format:     "json",
			signature:  &signv1.Signature{Signature: "c2ln"},
			wantStdout: "\"signed\"\n",
		},
		{
			name:       "raw without certificate",
			format:     "raw",
			signature:  &signv1.Signature{Signature: "c2ln"},
			wantStdout: "signed",
		},
		{
			name:       "oidc signature keeps plain output",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: encoded, ContentBundle: "{}"},
			wantStdout: "Record is: signed\n",
		},
		{
			name:       "human with certificate",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: encoded},
			wantStdout: "Record is: signed (certificate " + certificateFingerprint(cert) + ")\n",
		},
		{
			name:      "json with certificate",
			format:    "json",
			signature: &signv1.Signature{Signature: "c2ln", Certificate: encoded},
			wantJSON:  map[string]any{"signed": true, "certificate_fingerprint": certificateFingerprint(cert)},
		},
		{
			name:       "undecodable certificate degrades to plain output",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: "not-base64!"},
			wantStdout: "Record is: signed\n",
			wantStderr: undecodableWarning,
		},
		{
			name:       "certificate that is not x509 degrades to plain output",
			format:     "json",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: base64.StdEncoding.EncodeToString([]byte("garbage"))},
			wantStdout: "\"signed\"\n",
			wantStderr: undecodableWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, stdout, stderr := newOutputCommand(t, tt.format)

			if err := printSignResult(cmd, tt.signature); err != nil {
				t.Fatalf("printSignResult() error = %v", err)
			}

			if tt.wantStdout != "" && stdout.String() != tt.wantStdout {
				t.Fatalf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}

			if tt.wantJSON != nil {
				var got map[string]any
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("stdout %q is not one JSON object: %v", stdout.String(), err)
				}

				if got["signed"] != tt.wantJSON["signed"] || got["certificate_fingerprint"] != tt.wantJSON["certificate_fingerprint"] {
					t.Fatalf("stdout = %v, want %v", got, tt.wantJSON)
				}
			}

			assertStderr(t, stderr, tt.wantStderr)
		})
	}
}

func TestPrintCertificate(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cert := newTestCertificate(t, newTestKey(t), now.Add(-time.Hour), now.Add(time.Hour))
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)
	summary := "Signed with certificate " + certificateFingerprint(cert) + "\n"

	tests := []struct {
		name       string
		format     string
		signature  *signv1.Signature
		wantStdout string
		wantStderr string
	}{
		{
			name:       "human prints the fingerprint on stdout",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: encoded},
			wantStdout: summary,
		},
		{
			name:       "json keeps stdout for the command result",
			format:     "json",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: encoded},
			wantStderr: summary,
		},
		{
			name:       "raw keeps stdout for the command result",
			format:     "raw",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: encoded},
			wantStderr: summary,
		},
		{
			name:      "signature without certificate prints nothing",
			format:    "human",
			signature: &signv1.Signature{Signature: "c2ln"},
		},
		{
			name:      "oidc signature prints nothing",
			format:    "human",
			signature: &signv1.Signature{Signature: "c2ln", Certificate: encoded, ContentBundle: "{}"},
		},
		{
			name:       "undecodable certificate warns",
			format:     "human",
			signature:  &signv1.Signature{Signature: "c2ln", Certificate: "not-base64!"},
			wantStderr: undecodableWarning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, stdout, stderr := newOutputCommand(t, tt.format)

			PrintCertificate(cmd, tt.signature)

			if stdout.String() != tt.wantStdout {
				t.Fatalf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}

			assertStderr(t, stderr, tt.wantStderr)
		})
	}
}

// referrerStore accepts every referrer the client pushes, which is all the
// signing flow needs from the server: signatures are computed client-side.
type referrerStore struct {
	storev1.UnimplementedStoreServiceServer
}

func (referrerStore) PushReferrer(stream storev1.StoreService_PushReferrerServer) error {
	if _, err := stream.Recv(); err != nil {
		return err //nolint:wrapcheck // test double
	}

	return stream.Send(&storev1.PushReferrerResponse{Success: true}) //nolint:wrapcheck // test double
}

// newSigningClient connects a client to an in-process store that accepts
// referrers.
func newSigningClient(t *testing.T) *client.Client {
	t.Helper()

	lc := net.ListenConfig{}

	lis, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	server := grpc.NewServer()
	storev1.RegisterStoreServiceServer(server, referrerStore{})

	go func() { _ = server.Serve(lis) }()

	t.Cleanup(server.Stop)

	c, err := client.New(t.Context(), client.WithConfig(&client.Config{
		ServerAddress: lis.Addr().String(),
		AuthMode:      "insecure",
	}))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	t.Cleanup(func() { _ = c.Close() })

	return c
}

func TestSignRecord(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)

	now := time.Now()
	key := newTestKey(t)
	cert := newTestCertificate(t, key, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newTestCertificate(t, key, now.Add(-2*time.Hour), now.Add(-time.Hour))
	keyPath := importCosignKey(t, key)
	certPath := writeTestFile(t, "identity-cert.pem", certificatePEM(cert))
	expiredPath := writeTestFile(t, "expired-cert.pem", certificatePEM(expired))
	unencryptedKeyPath := writeTestFile(t, "plain-key.pem", privateKeyPEM(t, key))
	c := newSigningClient(t)

	tests := []struct {
		name            string
		options         Options
		wantCertificate string
		wantStderr      string
		wantErr         []string
	}{
		{
			name:            "key with certificate",
			options:         Options{Key: keyPath, Certificate: certPath},
			wantCertificate: base64.StdEncoding.EncodeToString(cert.Raw),
		},
		{
			name:    "key without certificate",
			options: Options{Key: keyPath},
		},
		{
			name:            "expired certificate is warned about and still attached",
			options:         Options{Key: keyPath, Certificate: expiredPath},
			wantCertificate: base64.StdEncoding.EncodeToString(expired.Raw),
			wantStderr:      "Warning: certificate " + certificateFingerprint(expired) + " expired at",
		},
		{
			name:    "certificate without key fails before signing",
			options: Options{Certificate: certPath},
			wantErr: []string{"--certificate requires --key"},
		},
		{
			name:    "unencrypted key gets cosign guidance",
			options: Options{Key: unencryptedKeyPath},
			wantErr: []string{"unsupported private key format", "cosign import-key-pair --key <key.pem>", "unsupported pem type: PRIVATE KEY"},
		},
		{
			name:    "oidc failures pass through without key guidance",
			options: Options{OIDCToken: "token", FulcioURL: "http://127.0.0.1:1", TimestampURL: "http://127.0.0.1:1", SkipTlog: true},
			wantErr: []string{"failed to sign record"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer

			sig, err := signRecord(t.Context(), c, "bafyreib-record-cid", tt.options, &stderr)
			if len(tt.wantErr) > 0 {
				assertErrorContains(t, err, tt.wantErr...)

				return
			}

			if err != nil {
				t.Fatalf("signRecord() error = %v", err)
			}

			if sig.GetSignature() == "" || sig.GetContentBundle() != "" {
				t.Fatalf("signRecord() = %v, want a key-based signature", sig)
			}

			if sig.GetCertificate() != tt.wantCertificate {
				t.Fatalf("signRecord() certificate = %q, want %q", sig.GetCertificate(), tt.wantCertificate)
			}

			assertStderr(t, &stderr, tt.wantStderr)
		})
	}
}

func TestSignRecordReportsWrongPassword(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "wrong")

	keyPath := importCosignKey(t, newTestKey(t))

	_, err := signRecord(t.Context(), newSigningClient(t), "bafyreib-record-cid", Options{Key: keyPath}, io.Discard)
	assertErrorContains(t, err, "failed to decrypt private key", "COSIGN_PASSWORD", "--password-stdin")
}

// withOptions swaps the flag-bound options for the test and restores them.
func withOptions(t *testing.T, o Options) {
	t.Helper()

	original := *opts
	*opts = o

	t.Cleanup(func() { *opts = original })
}

func TestSignUsesFlagBoundOptions(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)

	now := time.Now()
	key := newTestKey(t)
	cert := newTestCertificate(t, key, now.Add(-time.Hour), now.Add(time.Hour))
	withOptions(t, Options{Key: importCosignKey(t, key), Certificate: writeTestFile(t, "identity-cert.pem", certificatePEM(cert))})

	var stderr bytes.Buffer

	sig, err := Sign(t.Context(), newSigningClient(t), "bafyreib-record-cid", &stderr)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if sig.GetCertificate() != base64.StdEncoding.EncodeToString(cert.Raw) {
		t.Fatalf("Sign() certificate = %q, want the identity certificate", sig.GetCertificate())
	}

	assertStderr(t, &stderr, "")
}

func TestRunCommand(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", testKeyPassword)

	now := time.Now()
	key := newTestKey(t)
	cert := newTestCertificate(t, key, now.Add(-time.Hour), now.Add(time.Hour))
	withOptions(t, Options{Key: importCosignKey(t, key), Certificate: writeTestFile(t, "identity-cert.pem", certificatePEM(cert))})

	cmd, stdout, stderr := newOutputCommand(t, "human")
	cmd.SetContext(ctxUtils.SetClientForContext(t.Context(), newSigningClient(t)))

	if err := runCommand(cmd, "bafyreib-record-cid"); err != nil {
		t.Fatalf("runCommand() error = %v", err)
	}

	if want := "Record is: signed (certificate " + certificateFingerprint(cert) + ")\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}

	assertStderr(t, stderr, "")
}

func TestRunCommandReportsSigningErrors(t *testing.T) {
	withOptions(t, Options{Certificate: "identity-cert.pem"})

	cmd, stdout, _ := newOutputCommand(t, "human")
	cmd.SetContext(ctxUtils.SetClientForContext(t.Context(), newSigningClient(t)))

	err := runCommand(cmd, "bafyreib-record-cid")
	assertErrorContains(t, err, "--certificate requires --key")

	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing", stdout.String())
	}
}

func TestRunCommandRequiresClient(t *testing.T) {
	t.Parallel()

	cmd, _, _ := newOutputCommand(t, "human")
	cmd.SetContext(t.Context())

	err := runCommand(cmd, "bafyreib-record-cid")
	if err == nil || !strings.Contains(err.Error(), "failed to get client from context") {
		t.Fatalf("runCommand() error = %v, want the missing-client error", err)
	}
}
