// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"regexp"
	"slices"
	"strings"

	"github.com/agntcy/dir/utils/logging"
)

var nameLogger = logging.Logger("naming/name")

// Protocol prefixes for name verification.
const (
	// HTTPSProtocol indicates JWKS well-known verification via HTTPS.
	HTTPSProtocol = "https://"

	// HTTPProtocol indicates JWKS well-known verification via HTTP (testing only).
	HTTPProtocol = "http://"

	// ANSProtocol indicates Agent Name Service verification. The name is an ANS
	// name, ans://v{MAJOR}.{MINOR}.{PATCH}.{agentHost}[/path], and the signing
	// key is proven through the agent's identity certificate as attested by the
	// agent's transparency log.
	ANSProtocol = "ans://"
)

// verifiablePrefixes lists every protocol prefix that selects a verification
// method. The database query that picks records for verification and the API
// server's name resolution both derive their prefix lists from it.
var verifiablePrefixes = []string{HTTPSProtocol, HTTPProtocol, ANSProtocol}

// ansHostPattern splits the host of an ANS name into its version label and the
// agent host: "v1.0.0.agent.example.com" -> "v1.0.0", "agent.example.com".
// Version components are unsigned integers without leading zeros.
var ansHostPattern = regexp.MustCompile(`^(v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\.(.+)$`)

// ParsedName represents a parsed record name with optional protocol prefix.
type ParsedName struct {
	// Protocol is the verification protocol (https://, http://, ans://, or empty).
	Protocol string
	// Domain is the domain part of the name. For ANS names it is the agent host
	// without the version label.
	Domain string
	// Path is the optional path after the domain.
	Path string
	// FullName is the original name without protocol prefix.
	FullName string
	// Version is the ANS version label as written in the name (e.g. "v1.0.0").
	// Empty for non-ANS names.
	Version string
}

// VerifiablePrefixes returns the protocol prefixes that make a record name
// verifiable. The returned slice is a copy.
func VerifiablePrefixes() []string {
	return slices.Clone(verifiablePrefixes)
}

// ParseName parses a record name, extracting any protocol prefix.
//
// Expected formats:
//   - "https://cisco.com/agent" -> Protocol: "https://", Domain: "cisco.com", Path: "agent"
//   - "http://localhost:8080/agent" -> Protocol: "http://", Domain: "localhost:8080", Path: "agent"
//   - "ans://v1.0.0.agent.example.com/agent" -> Protocol: "ans://", Domain: "agent.example.com", Version: "v1.0.0", Path: "agent"
//   - "cisco.com/agent" -> Protocol: "", Domain: "cisco.com", Path: "agent" (no verification)
//   - "cisco.com" -> Protocol: "", Domain: "cisco.com", Path: ""
//
// Returns nil if the name is invalid.
func ParseName(name string) *ParsedName {
	if name == "" {
		return nil
	}

	result := &ParsedName{}

	// Check for protocol prefix
	remaining := name

	for _, prefix := range verifiablePrefixes {
		if strings.HasPrefix(name, prefix) {
			result.Protocol = prefix
			remaining = strings.TrimPrefix(name, prefix)

			break
		}
	}

	result.FullName = remaining

	// Split domain and path
	if host, path, found := strings.Cut(remaining, "/"); found {
		result.Domain = host
		result.Path = path
	} else {
		result.Domain = remaining
	}

	if result.Protocol == ANSProtocol {
		match := ansHostPattern.FindStringSubmatch(result.Domain)
		if match == nil {
			nameLogger.Debug("Invalid ANS name: host must be v{major}.{minor}.{patch}.{agentHost}", "host", result.Domain)

			return nil
		}

		result.Version = match[1]
		result.Domain = match[2]
	}

	// Validate domain (must contain at least one dot or be localhost with port)
	if !strings.Contains(result.Domain, ".") && !strings.HasPrefix(result.Domain, "localhost") {
		nameLogger.Debug("Invalid domain: no dot found and not localhost", "domain", result.Domain)

		return nil
	}

	return result
}

// ExtractDomain extracts the domain from a record name.
// This is a convenience function that wraps ParseName.
//
// Returns empty string if the name is invalid.
func ExtractDomain(name string) string {
	parsed := ParseName(name)
	if parsed == nil {
		return ""
	}

	return parsed.Domain
}
