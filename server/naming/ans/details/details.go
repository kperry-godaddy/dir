// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package details is the method-specific JSON persisted with a verified
// ans:// record. The verifier writes it and the API server reads it; the
// package has no other dependencies so the API server does not link the
// verification stack to decode it.
package details

import (
	"encoding/json"
	"fmt"
)

// Version is the schema version written into Details.Version. Readers accept
// every version up to it, so a bump must keep older rows decodable.
const Version = 1

// Details is the persisted verification record of an ans:// name.
type Details struct {
	// Version is the schema version the row was written with.
	Version int `json:"v"`

	// AnsName is the verified ANS name (e.g. "ans://v1.0.0.agent.example.com").
	AnsName string `json:"ansName"`

	// AgentHost is the agent host of the ANS name (e.g. "agent.example.com").
	AgentHost string `json:"agentHost"`

	// AgentID is the agent identifier in the transparency log.
	AgentID string `json:"agentId"`

	// LogURL is the base URL of the transparency log that attested the certificate.
	LogURL string `json:"logUrl"`

	// ReceiptURL is the URL of the agent's SCITT receipt on the log.
	ReceiptURL string `json:"receiptUrl"`

	// AgentStatus is the status the log reported (ACTIVE, WARNING, DEPRECATED).
	AgentStatus string `json:"agentStatus"`
}

// Decode parses persisted details. Rows written by an older schema version
// decode with their known fields; rows written by a newer version are
// rejected.
func Decode(raw []byte) (*Details, error) {
	var d Details
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("ans details: %w", err)
	}

	if d.Version < 1 || d.Version > Version {
		return nil, fmt.Errorf("ans details: unsupported version %d", d.Version)
	}

	return &d, nil
}
