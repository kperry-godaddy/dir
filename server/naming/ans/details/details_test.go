// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package details

import (
	"encoding/json"
	"strings"
	"testing"
)

// v1Row is a row exactly as the first release of the verifier wrote it. It
// must keep decoding under every later schema version.
const v1Row = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentHost":"agent.example.com",` +
	`"agentId":"5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10","logUrl":"https://log.example.com",` +
	`"receiptUrl":"https://log.example.com/v1/agents/5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10/receipt","agentStatus":"ACTIVE"}`

func TestDecode(t *testing.T) {
	current := Details{
		Version:     Version,
		AnsName:     "ans://v1.0.0.agent.example.com",
		AgentHost:   "agent.example.com",
		AgentID:     "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10",
		LogURL:      "https://log.example.com",
		ReceiptURL:  "https://log.example.com/v1/agents/5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10/receipt",
		AgentStatus: "ACTIVE",
	}

	encoded, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}

	v1 := current
	v1.Version = 1

	tests := []struct {
		name    string
		raw     string
		want    *Details
		wantErr string
	}{
		{name: "round trip", raw: string(encoded), want: &current},
		{name: "first schema version still decodes", raw: v1Row, want: &v1},
		{name: "unknown fields are ignored", raw: `{"v":1,"ansName":"ans://v1.0.0.a.example.com","future":true}`, want: &Details{Version: 1, AnsName: "ans://v1.0.0.a.example.com"}},
		{name: "newer version", raw: `{"v":99}`, wantErr: "unsupported version 99"},
		{name: "missing version", raw: `{"ansName":"x"}`, wantErr: "unsupported version 0"},
		{name: "negative version", raw: `{"v":-1}`, wantErr: "unsupported version -1"},
		{name: "malformed json", raw: `{"v":1,`, wantErr: "ans details:"},
		{name: "empty", raw: ``, wantErr: "ans details:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode([]byte(tt.raw))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Decode() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("Decode() unexpected error: %v", err)
			}

			if *got != *tt.want {
				t.Errorf("Decode() = %+v, want %+v", *got, *tt.want)
			}
		})
	}
}

func TestJSONKeys(t *testing.T) {
	encoded, err := json.Marshal(Details{Version: Version})
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{`"v":1`, `"ansName"`, `"agentHost"`, `"agentId"`, `"logUrl"`, `"receiptUrl"`, `"agentStatus"`} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("encoded details %s lack key %s", encoded, key)
		}
	}

	if strings.Contains(string(encoded), "treeSize") || strings.Contains(string(encoded), "leafIndex") {
		t.Errorf("encoded details %s carry unverified receipt position fields", encoded)
	}
}
