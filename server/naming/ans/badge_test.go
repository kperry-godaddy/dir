// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"strings"
	"testing"
)

func TestParseBadgeURL(t *testing.T) {
	const id = "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10"

	canonical := badgeTarget{LogBase: "https://log.example.com", LogHost: "log.example.com", AgentID: id}

	tests := []struct {
		name    string
		raw     string
		want    badgeTarget
		wantErr string
	}{
		{name: "canonical", raw: "https://log.example.com/v1/agents/" + id, want: canonical},
		{name: "explicit port", raw: "https://localhost:18081/v1/agents/" + id, want: badgeTarget{LogBase: "https://localhost:18081", LogHost: "localhost:18081", AgentID: id}},
		{name: "default port dropped", raw: "https://log.example.com:443/v1/agents/" + id, want: canonical},
		{name: "host lowercased", raw: "https://LOG.Example.COM/v1/agents/" + id, want: canonical},
		{name: "agent id lowercased", raw: "https://log.example.com/v1/agents/" + strings.ToUpper(id), want: canonical},
		{name: "ipv6 host", raw: "https://[::1]:18081/v1/agents/" + id, want: badgeTarget{LogBase: "https://[::1]:18081", LogHost: "[::1]:18081", AgentID: id}},
		{name: "http scheme", raw: "http://log.example.com/v1/agents/" + id, wantErr: `scheme "http" is not https`},
		{name: "empty", raw: "", wantErr: "scheme"},
		{name: "userinfo", raw: "https://user:secret@log.example.com/v1/agents/" + id, wantErr: "userinfo"},
		{name: "query", raw: "https://log.example.com/v1/agents/" + id + "?x=1", wantErr: "query"},
		{name: "empty query", raw: "https://log.example.com/v1/agents/" + id + "?", wantErr: "query"},
		{name: "fragment", raw: "https://log.example.com/v1/agents/" + id + "#frag", wantErr: "fragment"},
		{name: "trailing slash", raw: "https://log.example.com/v1/agents/" + id + "/", wantErr: "path"},
		{name: "extra segment", raw: "https://log.example.com/v1/agents/" + id + "/status-token", wantErr: "path"},
		{name: "missing agent id", raw: "https://log.example.com/v1/agents", wantErr: "path"},
		{name: "wrong prefix", raw: "https://log.example.com/v2/agents/" + id, wantErr: "path"},
		{name: "dot segment", raw: "https://log.example.com/v1/agents/../" + id, wantErr: "path"},
		{name: "empty segment", raw: "https://log.example.com//v1/agents/" + id, wantErr: "path"},
		{name: "percent-encoded prefix", raw: "https://log.example.com/%761/agents/" + id, wantErr: "path"},
		{name: "percent-encoded agent id", raw: "https://log.example.com/v1/agents/%35" + id[1:], wantErr: "agent id"},
		{name: "not a uuid", raw: "https://log.example.com/v1/agents/not-a-uuid", wantErr: "agent id"},
		{name: "no host", raw: "https:///v1/agents/" + id, wantErr: "host"},
		{name: "not a url", raw: "https://log.example.com:abc/v1/agents/" + id, wantErr: "not a valid URL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseBadgeURL(tt.raw)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseBadgeURL(%q) error = %v, want containing %q", tt.raw, err, tt.wantErr)
				}

				if !strings.HasPrefix(err.Error(), "ans badge-url: ") {
					t.Errorf("parseBadgeURL(%q) error %q lacks the stage prefix", tt.raw, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("parseBadgeURL(%q) unexpected error: %v", tt.raw, err)
			}

			if got != tt.want {
				t.Errorf("parseBadgeURL(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}
