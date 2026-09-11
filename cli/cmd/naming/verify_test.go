// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	namingv1 "github.com/agntcy/dir/api/naming/v1"
	"github.com/agntcy/dir/cli/presenter"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testCID = "bafyreibtestcid"

func TestVerificationFields(t *testing.T) {
	t.Parallel()

	verifiedAt := time.Date(2026, time.September, 11, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name         string
		verification *namingv1.Verification
		want         map[string]any
		wantInfo     bool
	}{
		{
			name: "domain verification",
			verification: namingv1.NewDomainVerification(&namingv1.DomainVerification{
				Domain:     "cisco.com",
				Method:     "wellknown",
				KeyId:      "key-1",
				VerifiedAt: timestamppb.New(verifiedAt),
			}),
			want: map[string]any{
				"cid":         testCID,
				"verified":    true,
				"domain":      "cisco.com",
				"method":      "wellknown",
				"key_id":      "key-1",
				"verified_at": "2026-09-11T10:30:00Z",
			},
		},
		{
			name: "ans verification",
			verification: namingv1.NewAnsVerification(&namingv1.AnsVerification{
				AnsName:         "ans://v1.0.0.agent.example.com/demo",
				AgentId:         "0f5a2a5e-6d5c-4d3e-9f6a-1b2c3d4e5f60",
				LogUrl:          "https://log.example.com",
				ReceiptUri:      "https://log.example.com/v1/agents/0f5a2a5e-6d5c-4d3e-9f6a-1b2c3d4e5f60/receipt",
				CertFingerprint: "SHA256:abcd",
				AgentStatus:     "ACTIVE",
				VerifiedAt:      timestamppb.New(verifiedAt),
			}),
			want: map[string]any{
				"cid":              testCID,
				"verified":         true,
				"domain":           "agent.example.com",
				"method":           "ans",
				"key_id":           "SHA256:abcd",
				"verified_at":      "2026-09-11T10:30:00Z",
				"ans_name":         "ans://v1.0.0.agent.example.com/demo",
				"agent_id":         "0f5a2a5e-6d5c-4d3e-9f6a-1b2c3d4e5f60",
				"log_url":          "https://log.example.com",
				"receipt_uri":      "https://log.example.com/v1/agents/0f5a2a5e-6d5c-4d3e-9f6a-1b2c3d4e5f60/receipt",
				"cert_fingerprint": "SHA256:abcd",
				"agent_status":     "ACTIVE",
			},
		},
		{
			name: "ans verification with unparseable name",
			verification: namingv1.NewAnsVerification(&namingv1.AnsVerification{
				AnsName:         "ans://not-a-versioned-host",
				CertFingerprint: "SHA256:abcd",
				AgentStatus:     "WARNING",
				VerifiedAt:      timestamppb.New(verifiedAt),
			}),
			want: map[string]any{
				"cid":              testCID,
				"verified":         true,
				"domain":           "",
				"method":           "ans",
				"key_id":           "SHA256:abcd",
				"verified_at":      "2026-09-11T10:30:00Z",
				"ans_name":         "ans://not-a-versioned-host",
				"agent_id":         "",
				"log_url":          "",
				"receipt_uri":      "",
				"cert_fingerprint": "SHA256:abcd",
				"agent_status":     "WARNING",
			},
		},
		{
			name:         "nil info",
			verification: &namingv1.Verification{},
			want: map[string]any{
				"cid":      testCID,
				"verified": true,
				"message":  "unsupported verification type <nil>; upgrade dirctl",
			},
			wantInfo: true,
		},
		{
			name:         "nil verification",
			verification: nil,
			want: map[string]any{
				"cid":      testCID,
				"verified": true,
				"message":  "unsupported verification type <nil>; upgrade dirctl",
			},
			wantInfo: true,
		},
		{
			name:         "empty arm",
			verification: &namingv1.Verification{Info: &namingv1.Verification_Domain{}},
			want: map[string]any{
				"cid":      testCID,
				"verified": true,
				"message":  "unsupported verification type *v1.Verification_Domain; upgrade dirctl",
			},
			wantInfo: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := verificationFields(testCID, tt.verification)

			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("field %q = %v, want %v", key, got[key], want)
				}
			}

			if _, hasInfo := got["info"]; hasInfo != tt.wantInfo {
				t.Errorf("info present = %v, want %v (fields %v)", hasInfo, tt.wantInfo, got)
			}

			wantLen := len(tt.want)
			if tt.wantInfo {
				wantLen++
			}

			if len(got) != wantLen {
				t.Errorf("got %d fields %v, want %d", len(got), got, wantLen)
			}
		})
	}
}

func TestOutputVerificationResultJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response *namingv1.GetVerificationInfoResponse
		want     map[string]any
	}{
		{
			name: "ans verification",
			response: &namingv1.GetVerificationInfoResponse{
				Verified: true,
				Verification: namingv1.NewAnsVerification(&namingv1.AnsVerification{
					AnsName:         "ans://v1.0.0.agent.example.com",
					AgentId:         "agent-1",
					CertFingerprint: "SHA256:abcd",
					AgentStatus:     "ACTIVE",
					VerifiedAt:      timestamppb.New(time.Date(2026, time.September, 11, 10, 30, 0, 0, time.UTC)),
				}),
			},
			want: map[string]any{
				"cid":          testCID,
				"verified":     true,
				"domain":       "agent.example.com",
				"method":       "ans",
				"key_id":       "SHA256:abcd",
				"agent_id":     "agent-1",
				"agent_status": "ACTIVE",
				"verified_at":  "2026-09-11T10:30:00Z",
			},
		},
		{
			name:     "not verified",
			response: &namingv1.GetVerificationInfoResponse{Verified: false, ErrorMessage: new("transient: ans dns: lookup timed out")},
			want: map[string]any{
				"cid":      testCID,
				"verified": false,
				"message":  "transient: ans dns: lookup timed out",
			},
		},
		{
			name:     "not verified without message",
			response: &namingv1.GetVerificationInfoResponse{Verified: false},
			want: map[string]any{
				"cid":      testCID,
				"verified": false,
				"message":  "no verification found",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer

			cmd := &cobra.Command{}
			cmd.SetOut(&stdout)
			presenter.AddOutputFlags(cmd)

			if err := cmd.Flags().Set("output", "json"); err != nil {
				t.Fatalf("set --output json: %v", err)
			}

			if err := outputVerificationResult(cmd, testCID, tt.response); err != nil {
				t.Fatalf("outputVerificationResult() error = %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("output %q is not a JSON object: %v", stdout.String(), err)
			}

			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("field %q = %v, want %v", key, got[key], want)
				}
			}
		})
	}
}
