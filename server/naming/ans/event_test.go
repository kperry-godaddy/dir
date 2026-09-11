// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"strings"
	"testing"
)

func TestDecodeEvent(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantAgentID string
		wantAnsName string
		wantErr     string
	}{
		{
			name:        "ansId names the agent",
			raw:         `{"payload":{"producer":{"event":{"ansId":"` + testAgentID + `","ansName":"` + testAnsName + `"}}}}`,
			wantAgentID: testAgentID,
			wantAnsName: testAnsName,
		},
		{
			name:        "agentId is read when ansId is absent",
			raw:         `{"payload":{"producer":{"event":{"agentId":"` + testAgentID + `","ansName":"` + testAnsName + `"}}}}`,
			wantAgentID: testAgentID,
			wantAnsName: testAnsName,
		},
		{
			name:        "ansId wins over agentId",
			raw:         `{"payload":{"producer":{"event":{"ansId":"` + testAgentID + `","agentId":"` + otherAgentID + `"}}}}`,
			wantAgentID: testAgentID,
		},
		{
			name:    "envelope without an event",
			raw:     `{"payload":{"producer":{}}}`,
			wantErr: "envelope carries no agent event",
		},
		{
			name:    "event without an agent id",
			raw:     `{"payload":{"producer":{"event":{"ansName":"` + testAnsName + `"}}}}`,
			wantErr: "envelope carries no agent event",
		},
		{
			name:    "not json",
			raw:     "not json",
			wantErr: "decode event envelope",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := decodeEvent([]byte(tt.raw))

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("decodeEvent() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("decodeEvent() error = %v", err)
			}

			if event.agentID() != tt.wantAgentID {
				t.Errorf("agentID() = %q, want %q", event.agentID(), tt.wantAgentID)
			}

			if event.AnsName != tt.wantAnsName {
				t.Errorf("AnsName = %q, want %q", event.AnsName, tt.wantAnsName)
			}
		})
	}
}
