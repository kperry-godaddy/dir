// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
)

// badgeTarget is the transparency log and agent a badge record points at.
type badgeTarget struct {
	// LogBase is the log's origin, scheme://host, without a trailing slash.
	LogBase string

	// LogHost is the normalized host, the key for the allow-list and the breaker.
	LogHost string

	// AgentID is the lowercase agent UUID from the badge path.
	AgentID string
}

// agentIDPattern matches an RFC 4122 UUID in either case.
var agentIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// badgePathSegments is the segment count of /v1/agents/{agentId} split on
// "/": the empty segment before the leading slash plus three.
const badgePathSegments = 4

// parseBadgeURL is the SSRF gate between a DNS record anyone can publish and
// the HTTPS requests the verifier makes. The URL must be https and name
// exactly /v1/agents/{agentId} with a UUID agent id; query, fragment,
// userinfo, dot or empty segments and trailing slashes are rejected. The
// caller checks the normalized host against the allow-list.
//
// The SDK's verify.URLValidator is not reused: it accepts port 443 only,
// which fails the local demo and any non-default port, and it does not check
// the path shape.
func parseBadgeURL(raw string) (badgeTarget, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return badgeTarget{}, fail(stageBadgeURL, "badge URL is not a valid URL")
	}

	if u.Scheme != "https" {
		return badgeTarget{}, fail(stageBadgeURL, fmt.Sprintf("badge URL scheme %q is not https", u.Scheme))
	}

	if u.User != nil {
		return badgeTarget{}, fail(stageBadgeURL, "badge URL must not carry userinfo")
	}

	if u.RawQuery != "" || u.ForceQuery {
		return badgeTarget{}, fail(stageBadgeURL, "badge URL must not carry a query")
	}

	if u.Fragment != "" {
		return badgeTarget{}, fail(stageBadgeURL, "badge URL must not carry a fragment")
	}

	if u.Host == "" {
		return badgeTarget{}, fail(stageBadgeURL, "badge URL has no host")
	}

	host, err := ansconfig.NormalizeHost(u.Host)
	if err != nil {
		return badgeTarget{}, failWith(stageBadgeURL, err, "badge URL host is malformed")
	}

	agentID, err := parseBadgePath(u.EscapedPath())
	if err != nil {
		return badgeTarget{}, err
	}

	return badgeTarget{LogBase: "https://" + host, LogHost: host, AgentID: agentID}, nil
}

// parseBadgePath returns the agent id from a path that is exactly
// /v1/agents/{agentId}. It works on the escaped path so percent-encoding
// cannot spell the literal segments.
func parseBadgePath(path string) (string, error) {
	segments := strings.Split(path, "/")
	if len(segments) != badgePathSegments || segments[0] != "" || segments[1] != "v1" || segments[2] != "agents" {
		return "", fail(stageBadgeURL, "badge URL path must be /v1/agents/{agentId}")
	}

	if !agentIDPattern.MatchString(segments[3]) {
		return "", fail(stageBadgeURL, "badge URL agent id is not a UUID")
	}

	return strings.ToLower(segments[3]), nil
}
