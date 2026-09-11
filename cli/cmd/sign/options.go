// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package sign

import (
	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/cli/presenter"
	"github.com/spf13/pflag"
)

var opts = &Options{}

type Options struct {
	// Key signing options
	Key           string
	Certificate   string
	PasswordStdin bool

	// OIDC signing options
	FulcioURL        string
	RekorURL         string
	TimestampURL     string
	SkipTlog         bool
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCToken        string
}

func AddSigningFlags(flags *pflag.FlagSet) {
	flags.StringVar(&opts.Key, "key", "",
		`Private key for signing: a KMS URI (awskms://, gcpkms://, azurekms://,
hashivault://, pkcs11:), a file path, an HTTP(S) URL, env://VAR, k8s://NAMESPACE/SECRET
or gitlab://PROJECT. File and inline PEM keys must use the encrypted Cosign/Sigstore
format: wrap an existing key with "cosign import-key-pair --key <key.pem>" or
generate one with "cosign generate-key-pair". Set COSIGN_PASSWORD to skip the
password prompt.`)
	flags.StringVar(&opts.Certificate, "certificate", "",
		`PEM file with the X.509 certificate, or chain, for --key. Only the
certificate whose public key matches the signing key is attached to the
signature; requires --key. Records named ans://... are verified through the
ANS identity certificate attached here.`)
	flags.BoolVar(&opts.PasswordStdin, "password-stdin", false,
		"Read the private key password from standard input; do not combine with other stdin input flags")
	flags.StringVar(&opts.FulcioURL, "fulcio-url", signv1.DefaultFulcioURL,
		"Sigstore Fulcio URL")
	flags.StringVar(&opts.RekorURL, "rekor-url", signv1.DefaultRekorURL,
		"Sigstore Rekor URL")
	flags.StringVar(&opts.TimestampURL, "timestamp-url", signv1.DefaultTimestampURL,
		"Sigstore Timestamp URL")
	flags.BoolVar(&opts.SkipTlog, "skip-tlog", false,
		"Skip uploading signature to transparency log (Rekor)")
	flags.StringVar(&opts.OIDCProviderURL, "oidc-provider-url", signv1.DefaultOIDCProviderURL,
		"OIDC Provider URL")
	flags.StringVar(&opts.OIDCClientID, "oidc-client-id", signv1.DefaultOIDCClientID,
		"OIDC Client ID")
	flags.StringVar(&opts.OIDCClientSecret, "oidc-client-secret", "",
		"OIDC Client Secret (required for confidential OIDC clients)")
	flags.StringVar(&opts.OIDCToken, "oidc-token", "",
		"OIDC Token for non-interactive signing")
}

func init() {
	flags := Command.Flags()

	// Add signing flags
	AddSigningFlags(flags)

	// Add output format flags
	presenter.AddOutputFlags(Command)
}
