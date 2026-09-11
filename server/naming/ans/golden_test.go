// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"encoding/json"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
)

// The files under testdata/ were captured from the ANS reference
// implementation (github.com/agentnameservice/ans, commit recorded in
// fixture.json) running its demo stack. The transparency log listens on
// plain HTTP at 127.0.0.1:18081 while the badge URLs it publishes use the
// configured public base https://localhost:18081, which is what fixture.json
// records. Capture commands, run from the ans checkout:
//
//	scripts/demo/start.sh --with-dns
//	scripts/demo/run-lifecycle.sh dir-fixture.example.com 1.0.0
//	ID=$(cat data/demo/last-agent-id)
//	TL=http://127.0.0.1:18081
//	curl -fsS "$TL/root-keys" > testdata/root-keys.txt
//	curl -fsS "$TL/v1/agents/$ID/status-token" > testdata/status-token.cbor
//	until curl -fsS "$TL/v1/agents/$ID/receipt" > testdata/receipt.cbor; do sleep 2; done
//	curl -fsS -H "Authorization: Bearer $RA_API_KEY" \
//	  "http://127.0.0.1:18080/v2/ans/agents/$ID/certificates/identity" |
//	  jq -r '.[0].certificatePEM' > testdata/identity-cert.pem
//	scripts/demo/stop.sh
//
// fixture.json holds the agent id, the ANS name, the badge URL, the capture
// time the test pins its clock to, and the ans commit.

type goldenFixture struct {
	AgentID        string `json:"agentId"`
	AnsName        string `json:"ansName"`
	BadgeURL       string `json:"badgeUrl"`
	CapturedAtUnix int64  `json:"capturedAtUnix"`
	AnsCommit      string `json:"ansCommit"`
}

// golden is the captured material wired into the verifier's dependencies.
type golden struct {
	fixture  goldenFixture
	rootKeys []string
	certDER  []byte
	name     *naming.ParsedName
	logBase  string
	logHost  string
	dns      verify.DNSResolver
	log      scitt.Client
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return data
}

func loadGolden(t *testing.T) golden {
	t.Helper()

	var g golden
	if err := json.Unmarshal(readTestdata(t, "fixture.json"), &g.fixture); err != nil {
		t.Fatalf("decode fixture.json: %v", err)
	}

	g.rootKeys = strings.Fields(string(readTestdata(t, "root-keys.txt")))

	block, _ := pem.Decode(readTestdata(t, "identity-cert.pem"))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("identity-cert.pem does not hold a PEM certificate")
	}

	g.certDER = block.Bytes

	badge, err := url.Parse(g.fixture.BadgeURL)
	if err != nil {
		t.Fatalf("parse badge url: %v", err)
	}

	g.logBase = badge.Scheme + "://" + badge.Host
	g.logHost = badge.Host

	g.name = naming.ParseName(g.fixture.AnsName)
	if g.name == nil {
		t.Fatalf("fixture ans name %q does not parse", g.fixture.AnsName)
	}

	version, err := models.ParseVersion(g.name.Version)
	if err != nil {
		t.Fatal(err)
	}

	records := []verify.AnsBadgeRecord{{FormatVersion: "ans-badge1", Version: &version, URL: g.fixture.BadgeURL}}
	g.dns = verify.NewMockDNSResolver().WithRecords(g.name.Domain, records)
	g.log = scitt.NewMockClient().
		WithRootKeys(g.rootKeys).
		WithStatusToken(g.fixture.AgentID, readTestdata(t, "status-token.cbor")).
		WithReceipt(g.fixture.AgentID, readTestdata(t, "receipt.cbor"))

	return g
}

func TestGoldenFixtures(t *testing.T) {
	g := loadGolden(t)
	capturedAt := time.Unix(g.fixture.CapturedAtUnix, 0)

	tests := []struct {
		name string
		cfg  ansconfig.Config
	}{
		{
			name: "pinned root keys",
			cfg:  ansconfig.Config{TrustedLogHosts: []string{g.logHost}, RootKeys: g.rootKeys},
		},
		{
			name: "fetched root keys",
			cfg:  ansconfig.Config{TrustedLogHosts: []string{g.logHost}, AllowUnpinnedRootKeys: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.cfg,
				WithDNSResolver(g.dns),
				WithLogClientFactory(func(string) (scitt.Client, error) { return g.log, nil }),
				WithClock(func() time.Time { return capturedAt }),
			)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			got, err := v.LookupKeys(t.Context(), g.name, naming.Evidence{Certificates: [][]byte{g.certDER}})
			if err != nil {
				t.Fatalf("LookupKeys() error = %v", err)
			}

			assertGoldenResult(t, g, got)
		})
	}
}

func assertGoldenResult(t *testing.T, g golden, got *naming.LookupResult) {
	t.Helper()

	if len(got.Keys) != 1 {
		t.Fatalf("LookupKeys() returned %d keys, want 1", len(got.Keys))
	}

	if want := verify.CertFingerprintFromDER(g.certDER).String(); got.Keys[0].ID != want {
		t.Errorf("key ID = %q, want %q", got.Keys[0].ID, want)
	}

	details, err := DecodeDetails(got.Details)
	if err != nil {
		t.Fatalf("DecodeDetails() error = %v", err)
	}

	want := Details{
		Version:     DetailsVersion,
		AnsName:     g.fixture.AnsName,
		AgentID:     g.fixture.AgentID,
		LogURL:      g.logBase,
		ReceiptURI:  g.logBase + "/v1/agents/" + g.fixture.AgentID + "/receipt",
		AgentStatus: "ACTIVE",
		TreeSize:    details.TreeSize,
		LeafIndex:   details.LeafIndex,
	}

	if *details != want {
		t.Errorf("details = %+v, want %+v", *details, want)
	}

	if details.TreeSize == 0 {
		t.Error("TreeSize was not recorded from the receipt")
	}
}
