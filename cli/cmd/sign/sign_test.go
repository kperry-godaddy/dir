// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/cli/presenter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

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
	original := opts.PasswordStdin

	t.Cleanup(func() {
		opts.PasswordStdin = original
	})
	t.Setenv("COSIGN_PASSWORD", "secret")

	opts.PasswordStdin = false

	password, err := readPrivateKeyPassword()()
	if err != nil {
		t.Fatalf("read password: %v", err)
	}

	if string(password) != "secret" {
		t.Fatalf("password = %q, want %q", password, "secret")
	}
}

func TestFormatPrivateKeyErrorAddsCosignGuidance(t *testing.T) {
	t.Parallel()

	cause := errors.New("unsupported pem type: PRIVATE KEY")
	err := formatPrivateKeyError(cause)

	if !errors.Is(err, cause) {
		t.Fatalf("formatted error does not preserve cause: %v", err)
	}

	if !strings.Contains(err.Error(), "cosign generate-key-pair") {
		t.Fatalf("formatted error %q does not include key-generation guidance", err)
	}

	if !strings.Contains(err.Error(), "cosign import-key-pair --key <key.pem>") {
		t.Fatalf("formatted error %q does not include key-import guidance", err)
	}
}

func TestFormatPrivateKeyErrorAddsPasswordGuidance(t *testing.T) {
	t.Parallel()

	cause := errors.New("decrypt: invalid password")
	err := formatPrivateKeyError(cause)

	if !errors.Is(err, cause) {
		t.Fatalf("formatted error does not preserve cause: %v", err)
	}

	if !strings.Contains(err.Error(), "COSIGN_PASSWORD") || !strings.Contains(err.Error(), "--password-stdin") {
		t.Fatalf("formatted error %q does not include password guidance", err)
	}
}

func TestFormatPrivateKeyErrorLeavesOtherErrorsUnchanged(t *testing.T) {
	t.Parallel()

	cause := errors.New("key file not found")
	got := formatPrivateKeyError(cause)

	if !errors.Is(got, cause) {
		t.Fatalf("formatted error does not preserve cause: %v", got)
	}

	if strings.Contains(got.Error(), "unsupported private key format") {
		t.Fatalf("formatPrivateKeyError(%v) added unrelated guidance: %v", cause, got)
	}
}

// newTestCertificate issues a self-signed identity certificate for a fresh
// P-256 key, valid between notBefore and notAfter.
func newTestCertificate(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

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

	now := time.Now()
	cert := newTestCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	certPath := writeTestFile(t, "identity-cert.pem", certificatePEM(cert))
	publicKeyPath := writeTestFile(t, "key.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a certificate")}))

	tests := []struct {
		name    string
		options Options
		want    string
		wantErr string
	}{
		{
			name:    "no certificate requested",
			options: Options{Key: "cosign.key"},
		},
		{
			name:    "certificate without key",
			options: Options{Certificate: certPath},
			wantErr: "--certificate requires --key",
		},
		{
			name:    "unreadable file",
			options: Options{Key: "cosign.key", Certificate: filepath.Join(t.TempDir(), "missing.pem")},
			wantErr: "reading certificate file",
		},
		{
			name:    "file without certificate block",
			options: Options{Key: "cosign.key", Certificate: publicKeyPath},
			wantErr: "contains no CERTIFICATE PEM block",
		},
		{
			name:    "valid certificate",
			options: Options{Key: "cosign.key", Certificate: certPath},
			want:    string(certificatePEM(cert)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveCertificate(tt.options)
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
		})
	}
}

func TestKeyProviderAttachesCertificate(t *testing.T) {
	t.Setenv("COSIGN_PASSWORD", "secret")

	now := time.Now()
	cert := newTestCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	certPath := writeTestFile(t, "identity-cert.pem", certificatePEM(cert))

	provider, err := keyProvider(Options{Key: "cosign.key", Certificate: certPath})
	if err != nil {
		t.Fatalf("keyProvider() error = %v", err)
	}

	key := provider.GetKey()
	if key.GetPrivateKey() != "cosign.key" || string(key.GetPassword()) != "secret" {
		t.Fatalf("keyProvider() key = %q password = %q", key.GetPrivateKey(), key.GetPassword())
	}

	if key.GetCertificate() != string(certificatePEM(cert)) {
		t.Fatalf("keyProvider() certificate = %q, want the PEM file contents", key.GetCertificate())
	}

	provider, err = keyProvider(Options{Key: "cosign.key"})
	if err != nil {
		t.Fatalf("keyProvider() without certificate error = %v", err)
	}

	if provider.GetKey().Certificate != nil {
		t.Fatalf("keyProvider() without --certificate set certificate %q", provider.GetKey().GetCertificate())
	}

	if _, err := keyProvider(Options{Certificate: certPath}); err == nil {
		t.Fatal("keyProvider() accepted --certificate without --key")
	}
}

func TestSignProviderUsesOIDCToken(t *testing.T) {
	t.Parallel()

	provider, err := signProvider(Options{OIDCToken: "token", FulcioURL: "https://fulcio.example.com", SkipTlog: true})
	if err != nil {
		t.Fatalf("signProvider() error = %v", err)
	}

	oidc := provider.GetOidc()
	if oidc.GetIdToken() != "token" || oidc.GetOptions().GetFulcioUrl() != "https://fulcio.example.com" || !oidc.GetOptions().GetSkipTlog() {
		t.Fatalf("signProvider() = %v, want the OIDC options carried over", oidc)
	}
}

func TestCertificateFingerprint(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cert := newTestCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	sum := sha256.Sum256(cert.Raw)
	want := "SHA256:" + hex.EncodeToString(sum[:])

	if got := certificateFingerprint(cert); got != want {
		t.Fatalf("certificateFingerprint() = %q, want %q", got, want)
	}

	if digest := strings.TrimPrefix(certificateFingerprint(cert), "SHA256:"); digest != strings.ToLower(digest) {
		t.Fatalf("certificateFingerprint() digest = %q, want lowercase hex", digest)
	}
}

func TestCertificateValidityWarning(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)

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

			cert := newTestCertificate(t, tt.notBefore, tt.notAfter)

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

func TestPrintSignResult(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cert := newTestCertificate(t, now.Add(-time.Hour), now.Add(time.Hour))
	expired := newTestCertificate(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	encoded := base64.StdEncoding.EncodeToString(cert.Raw)

	tests := []struct {
		name        string
		format      string
		signature   *signv1.Signature
		wantStdout  string
		wantJSON    map[string]any
		wantWarning bool
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
			name:        "expired certificate warns",
			format:      "json",
			signature:   &signv1.Signature{Signature: "c2ln", Certificate: base64.StdEncoding.EncodeToString(expired.Raw)},
			wantJSON:    map[string]any{"signed": true, "certificate_fingerprint": certificateFingerprint(expired)},
			wantWarning: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, stdout, stderr := newOutputCommand(t, tt.format)

			if err := printSignResult(cmd, tt.signature, now); err != nil {
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

			if tt.wantWarning != strings.Contains(stderr.String(), "Warning: certificate") {
				t.Fatalf("stderr = %q, want warning = %v", stderr.String(), tt.wantWarning)
			}
		})
	}
}

func TestPrintSignResultRejectsMalformedCertificate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		certificate string
	}{
		{name: "not base64", certificate: "not-base64!"},
		{name: "not a certificate", certificate: base64.StdEncoding.EncodeToString([]byte("garbage"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cmd, _, _ := newOutputCommand(t, "human")

			err := printSignResult(cmd, &signv1.Signature{Signature: "c2ln", Certificate: tt.certificate}, time.Now())
			if err == nil || !strings.Contains(err.Error(), "decoding attached certificate") {
				t.Fatalf("printSignResult() error = %v, want decoding error", err)
			}
		})
	}
}
