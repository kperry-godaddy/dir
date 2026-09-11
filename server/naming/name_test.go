// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"slices"
	"testing"
)

func TestParseName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *ParsedName
		wantNil bool
	}{
		{
			name:  "simple domain",
			input: "cisco.com",
			want: &ParsedName{
				Domain:   "cisco.com",
				FullName: "cisco.com",
			},
		},
		{
			name:  "domain with path",
			input: "cisco.com/agent",
			want: &ParsedName{
				Domain:   "cisco.com",
				Path:     "agent",
				FullName: "cisco.com/agent",
			},
		},
		{
			name:  "https protocol",
			input: "https://example.org/test",
			want: &ParsedName{
				Protocol: HTTPSProtocol,
				Domain:   "example.org",
				Path:     "test",
				FullName: "example.org/test",
			},
		},
		{
			name:  "http protocol with port",
			input: "http://localhost:8080/agent",
			want: &ParsedName{
				Protocol: HTTPProtocol,
				Domain:   "localhost:8080",
				Path:     "agent",
				FullName: "localhost:8080/agent",
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantNil: true,
		},
		{
			name:    "no dot in domain and not localhost",
			input:   "invalid",
			wantNil: true,
		},
		{
			name:  "localhost with port is valid",
			input: "http://localhost:8080/agent",
			want: &ParsedName{
				Protocol: HTTPProtocol,
				Domain:   "localhost:8080",
				Path:     "agent",
				FullName: "localhost:8080/agent",
			},
		},
		{
			name:  "ans name",
			input: "ans://v1.0.0.agent.example.com",
			want: &ParsedName{
				Protocol: ANSProtocol,
				Domain:   "agent.example.com",
				Version:  "v1.0.0",
				FullName: "v1.0.0.agent.example.com",
			},
		},
		{
			name:  "ans name with path",
			input: "ans://v2.10.3.agent.example.com/assistant",
			want: &ParsedName{
				Protocol: ANSProtocol,
				Domain:   "agent.example.com",
				Path:     "assistant",
				Version:  "v2.10.3",
				FullName: "v2.10.3.agent.example.com/assistant",
			},
		},
		{
			name:  "ans name preserves host case",
			input: "ans://v1.0.0.Agent.Example.COM",
			want: &ParsedName{
				Protocol: ANSProtocol,
				Domain:   "Agent.Example.COM",
				Version:  "v1.0.0",
				FullName: "v1.0.0.Agent.Example.COM",
			},
		},
		{
			name:    "ans name without v prefix",
			input:   "ans://1.0.0.agent.example.com",
			wantNil: true,
		},
		{
			name:    "ans name with two-part version",
			input:   "ans://v1.0.agent.example.com",
			wantNil: true,
		},
		{
			name:    "ans name with leading zero in version",
			input:   "ans://v01.0.0.agent.example.com",
			wantNil: true,
		},
		{
			name:    "ans name without host",
			input:   "ans://v1.0.0",
			wantNil: true,
		},
		{
			name:    "ans name with host lacking a dot",
			input:   "ans://v1.0.0.agent",
			wantNil: true,
		},
		{
			name:    "ans name with uppercase scheme is not verifiable",
			input:   "ANS://v1.0.0.agent.example.com",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseName(tt.input)

			if tt.wantNil {
				if got != nil {
					t.Errorf("ParseName(%q) = %+v, want nil", tt.input, got)
				}

				return
			}

			if got == nil {
				t.Fatalf("ParseName(%q) = nil, want %+v", tt.input, tt.want)

				return
			}

			if got.Protocol != tt.want.Protocol {
				t.Errorf("ParseName(%q).Protocol = %q, want %q", tt.input, got.Protocol, tt.want.Protocol)
			}

			if got.Domain != tt.want.Domain {
				t.Errorf("ParseName(%q).Domain = %q, want %q", tt.input, got.Domain, tt.want.Domain)
			}

			if got.Path != tt.want.Path {
				t.Errorf("ParseName(%q).Path = %q, want %q", tt.input, got.Path, tt.want.Path)
			}

			if got.Version != tt.want.Version {
				t.Errorf("ParseName(%q).Version = %q, want %q", tt.input, got.Version, tt.want.Version)
			}

			if got.FullName != tt.want.FullName {
				t.Errorf("ParseName(%q).FullName = %q, want %q", tt.input, got.FullName, tt.want.FullName)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple domain",
			input: "cisco.com",
			want:  "cisco.com",
		},
		{
			name:  "domain with path",
			input: "cisco.com/agent",
			want:  "cisco.com",
		},
		{
			name:  "https protocol",
			input: "https://example.org",
			want:  "example.org",
		},
		{
			name:  "http protocol with localhost",
			input: "http://localhost:8080/agent",
			want:  "localhost:8080",
		},
		{
			name:  "ans protocol returns the agent host",
			input: "ans://v1.0.0.agent.example.com/assistant",
			want:  "agent.example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "no dot and not localhost",
			input: "invalid",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDomain(tt.input)
			if got != tt.want {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestVerifiablePrefixes(t *testing.T) {
	want := []string{HTTPSProtocol, HTTPProtocol, ANSProtocol}

	got := VerifiablePrefixes()
	if !slices.Equal(got, want) {
		t.Fatalf("VerifiablePrefixes() = %v, want %v", got, want)
	}

	// Callers must not be able to mutate the package list through the returned slice.
	got[0] = "mutated://"

	if again := VerifiablePrefixes(); !slices.Equal(again, want) {
		t.Fatalf("VerifiablePrefixes() after mutation = %v, want %v", again, want)
	}
}
