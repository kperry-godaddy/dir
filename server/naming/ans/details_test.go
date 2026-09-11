// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeDetails(t *testing.T) {
	valid := Details{
		Version:     DetailsVersion,
		AnsName:     "ans://v1.0.0.agent.example.com",
		AgentID:     "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10",
		LogURL:      "https://log.example.com",
		ReceiptURI:  "https://log.example.com/v1/agents/5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10/receipt",
		AgentStatus: "ACTIVE",
		TreeSize:    42,
		LeafIndex:   7,
	}

	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		raw     string
		want    *Details
		wantErr string
	}{
		{name: "round trip", raw: string(encoded), want: &valid},
		{name: "unknown version", raw: `{"v":2}`, wantErr: "unsupported version 2"},
		{name: "missing version", raw: `{"ansName":"x"}`, wantErr: "unsupported version 0"},
		{name: "malformed json", raw: `{"v":1,`, wantErr: "ans details:"},
		{name: "empty", raw: ``, wantErr: "ans details:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeDetails([]byte(tt.raw))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeDetails() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("DecodeDetails() unexpected error: %v", err)
			}

			if *got != *tt.want {
				t.Errorf("DecodeDetails() = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func TestDetailsJSONKeys(t *testing.T) {
	encoded, err := json.Marshal(Details{Version: DetailsVersion})
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{`"v":1`, `"ansName"`, `"agentId"`, `"logUrl"`, `"receiptUri"`, `"agentStatus"`, `"treeSize"`, `"leafIndex"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("encoded details %s lack key %s", encoded, key)
		}
	}
}
