// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:wrapcheck
package naming

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	namingv1 "github.com/agntcy/dir/api/naming/v1"
	"github.com/agntcy/dir/cli/presenter"
	ctxUtils "github.com/agntcy/dir/cli/util/context"
	"github.com/agntcy/dir/cli/util/reference"
	"github.com/agntcy/dir/server/naming"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

var verifyCmd = &cobra.Command{
	Use:   "verify <cid-or-name[:version]>",
	Short: "Check if a record has verified name ownership",
	Long: `Check if a record has verified name ownership.

This command checks whether a record has a stored name verification.
It queries the server for an existing verification result that was created
during the signing process.

You can specify the record by:
- CID directly (e.g., "bafyreib...")
- Name (e.g., "cisco.com/agent") - uses the latest version
- Name with version (e.g., "cisco.com/agent:v1.0.0")

Name verification proves that the signing key is authorized by the domain
claimed in the record's name field. Verification is performed automatically
when a record is signed using 'dirctl sign'.

The record's name must include a protocol prefix to specify the verification method:
- https://domain/path - verify using JWKS well-known file (RFC 7517)
- http://domain/path - verify using JWKS via HTTP (testing only)
- ans://vX.Y.Z.host[/path] - verify through the Agent Name Service (ANS)

Verification methods:
- JWKS well-known file at <scheme>://<domain>/.well-known/jwks.json
- ANS: the record must be signed with the agent's ANS identity key using
  key-based signing with --certificate <identity-cert.pem>; the certificate is
  checked against the agent's _ans-badge DNS record and its transparency log.
  OIDC signatures cannot verify an ans:// name.

The server automatically re-verifies records based on TTL to ensure
domain ownership remains valid.

Usage examples:

1. Check name verification status by CID:
   dirctl naming verify <cid>

2. Check name verification status by name:
   dirctl naming verify cisco.com/agent

3. Check name verification status by name and version:
   dirctl naming verify cisco.com/agent:v1.0.0

4. Check with JSON output:
   dirctl naming verify <cid-or-name> --output json
`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVerifyCommand(cmd, args[0])
	},
}

func runVerifyCommand(cmd *cobra.Command, input string) error {
	// Get the client from the context
	c, ok := ctxUtils.GetClientFromContext(cmd.Context())
	if !ok {
		return errors.New("failed to get client from context")
	}

	// Parse the input to determine if it's a CID or name reference
	ref := reference.Parse(input)

	var cid string

	if ref.IsCID() {
		// Direct CID lookup
		cid = input
	} else {
		// Name-based lookup - resolve to CID first
		resolvedCID, err := reference.ResolveToCID(cmd.Context(), c, input)
		if err != nil {
			return err
		}

		cid = resolvedCID
	}

	// Get verification info by CID
	resp, err := c.GetVerificationInfo(cmd.Context(), cid)
	if err != nil {
		return fmt.Errorf("failed to get verification info: %w", err)
	}

	return outputVerificationResult(cmd, cid, resp)
}

func outputVerificationResult(cmd *cobra.Command, cid string, resp *namingv1.GetVerificationInfoResponse) error {
	if !resp.GetVerified() {
		errMsg := resp.GetErrorMessage()
		if errMsg == "" {
			errMsg = "no verification found"
		}

		// Output the result
		result := map[string]any{
			"cid":      cid,
			"verified": false,
			"message":  errMsg,
		}

		return presenter.PrintMessage(cmd, "Name Verification", "No name verification found", result)
	}

	return presenter.PrintMessage(cmd, "Name Verification", "Record has verified name ownership", verificationFields(cid, resp.GetVerification()))
}

// verificationFields flattens a verification into the fields the command prints.
// Every arm reports cid and verified, plus domain, method, key_id, and
// verified_at so scripts read the same keys whichever method verified the name.
// An arm this dirctl does not know is reported verbatim rather than as
// unverified, so an older CLI never misreports a newer server.
func verificationFields(cid string, v *namingv1.Verification) map[string]any {
	switch {
	case v.GetDomain() != nil:
		dv := v.GetDomain()

		return map[string]any{
			"cid":         cid,
			"verified":    true,
			"domain":      dv.GetDomain(),
			"method":      dv.GetMethod(),
			"key_id":      dv.GetKeyId(),
			"verified_at": dv.GetVerifiedAt().AsTime().Format(time.RFC3339),
		}

	case v.GetAns() != nil:
		av := v.GetAns()

		return map[string]any{
			"cid":              cid,
			"verified":         true,
			"domain":           naming.ExtractDomain(av.GetAnsName()),
			"method":           "ans",
			"key_id":           av.GetCertFingerprint(),
			"verified_at":      av.GetVerifiedAt().AsTime().Format(time.RFC3339),
			"ans_name":         av.GetAnsName(),
			"agent_id":         av.GetAgentId(),
			"log_url":          av.GetLogUrl(),
			"receipt_uri":      av.GetReceiptUri(),
			"cert_fingerprint": av.GetCertFingerprint(),
			"agent_status":     av.GetAgentStatus(),
		}

	default:
		return unsupportedVerificationFields(cid, v)
	}
}

func unsupportedVerificationFields(cid string, v *namingv1.Verification) map[string]any {
	fields := map[string]any{
		"cid":      cid,
		"verified": true,
		"message":  fmt.Sprintf("unsupported verification type %T; upgrade dirctl", v.GetInfo()),
	}

	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(v)
	if err != nil {
		fields["info"] = err.Error()

		return fields
	}

	var info map[string]any
	if err := json.Unmarshal(raw, &info); err != nil {
		fields["info"] = string(raw)

		return fields
	}

	fields["info"] = info

	return fields
}
