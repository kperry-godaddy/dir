// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"github.com/agntcy/dir/cli/presenter"
	"github.com/spf13/cobra"
)

// Command is the parent command for naming operations.
var Command = &cobra.Command{
	Use:   "naming",
	Short: "Name verification operations",
	Long: `Name verification operations.

This command group provides access to name ownership verification:

- verify: Check if a record has verified name ownership

Name verification proves that a record's signing key is authorized by the
domain claimed in the record's name. This enables trustworthy human-readable
naming (e.g., "https://cisco.com/marketing-agent").

Protocol prefixes (required for verification):
- https://domain/path - verify using JWKS well-known file (RFC 7517)
- http://domain/path - verify using JWKS via HTTP (testing only)
- ans://vX.Y.Z.host[/path] - verify through the Agent Name Service (ANS)

Records without a protocol prefix will not be verified.

Verification methods:
- JWKS well-known file: <scheme>://<domain>/.well-known/jwks.json
- ANS: sign the record with the agent's ANS identity key using key-based
  signing and --certificate <identity-cert.pem>. The reconciler checks the
  certificate against the agent's _ans-badge DNS record and transparency log.
  OIDC signatures cannot verify an ans:// name.

Examples:

1. Check name verification status:
   dirctl naming verify <cid>

2. Check with JSON output:
   dirctl naming verify <cid> --output json
`,
}

func init() {
	// Add all naming subcommands
	Command.AddCommand(verifyCmd)

	// Add output format flags to naming subcommands
	presenter.AddOutputFlags(verifyCmd)
}
