// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package ans verifies ans:// record names through the Agent Name Service:
// the record's signing key must belong to an identity certificate that the
// agent's transparency log attests for the agent named by the record.
package ans

import (
	"encoding/json"
	"fmt"
)

// DetailsVersion is the schema version written into Details.Version.
const DetailsVersion = 1

// Details is the method-specific JSON persisted with a verified ans://
// record and returned through the naming API. It is written by the
// verifier and decoded by the API server, so both use this one type.
type Details struct {
	// Version is DetailsVersion; readers reject other values.
	Version int `json:"v"`

	// AnsName is the verified ANS name (e.g. "ans://v1.0.0.agent.example.com").
	AnsName string `json:"ansName"`

	// AgentID is the agent identifier in the transparency log.
	AgentID string `json:"agentId"`

	// LogURL is the base URL of the transparency log that attested the certificate.
	LogURL string `json:"logUrl"`

	// ReceiptURI is the URL of the agent's SCITT receipt on the log.
	ReceiptURI string `json:"receiptUri"`

	// AgentStatus is the status the log reported (ACTIVE, WARNING, DEPRECATED).
	AgentStatus string `json:"agentStatus"`

	// TreeSize and LeafIndex are the receipt's position claims. They are
	// recorded as the log reported them; the receipt signature does not cover
	// them and they are not checked against a published checkpoint.
	TreeSize  uint64 `json:"treeSize"`
	LeafIndex uint64 `json:"leafIndex"`
}

// DecodeDetails parses persisted details and rejects unknown schema versions.
func DecodeDetails(raw []byte) (*Details, error) {
	var details Details
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("ans details: %w", err)
	}

	if details.Version != DetailsVersion {
		return nil, fmt.Errorf("ans details: unsupported version %d", details.Version)
	}

	return &details, nil
}
