// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	"github.com/agntcy/dir/server/naming/ans/details"
)

const (
	testHost     = "agent.example.com"
	testVersion  = "v1.0.0"
	testAnsName  = "ans://v1.0.0.agent.example.com"
	testAgentID  = "5b1b6cc4-4b3e-4d4e-9a7d-2c1e7a6f9a10"
	otherAgentID = "0e4c1d2a-7f6b-4c3d-8e9f-a1b2c3d4e5f6"
	testLogHost  = "log.example.com"
	testLogBase  = "https://log.example.com"
	testBadgeURL = testLogBase + "/v1/agents/" + testAgentID
)

var testNow = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

// fakeLogClient is a scripted scitt.Client that counts calls, can run a hook
// on each call, and can hold a request open until its context ends.
type fakeLogClient struct {
	mu          sync.Mutex
	rootKeys    []string
	rootKeysErr error
	token       []byte
	tokenErr    error
	receipt     []byte
	receiptErr  error
	block       bool
	onCall      func()
	calls       int
	agentIDs    []string
	base        string
}

func (c *fakeLogClient) FetchRootKeys(ctx context.Context) ([]string, error) {
	if err := c.enter(ctx, ""); err != nil {
		return nil, err
	}

	if c.rootKeysErr != nil {
		return nil, c.rootKeysErr
	}

	return c.rootKeys, nil
}

func (c *fakeLogClient) FetchStatusToken(ctx context.Context, agentID string) ([]byte, error) {
	if err := c.enter(ctx, agentID); err != nil {
		return nil, err
	}

	if c.tokenErr != nil {
		return nil, c.tokenErr
	}

	return c.token, nil
}

func (c *fakeLogClient) FetchReceipt(ctx context.Context, agentID string) ([]byte, error) {
	if err := c.enter(ctx, agentID); err != nil {
		return nil, err
	}

	if c.receiptErr != nil {
		return nil, c.receiptErr
	}

	return c.receipt, nil
}

func (c *fakeLogClient) enter(ctx context.Context, agentID string) error {
	c.mu.Lock()
	c.calls++

	if agentID != "" {
		c.agentIDs = append(c.agentIDs, agentID)
	}

	block, onCall := c.block, c.onCall
	c.mu.Unlock()

	if onCall != nil {
		onCall()
	}

	if block {
		<-ctx.Done()

		return fmt.Errorf("fake log client: %w", ctx.Err())
	}

	return nil
}

func (c *fakeLogClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.calls
}

// countingResolver counts badge lookups on top of the SDK mock and can hold
// each answer back for a while.
type countingResolver struct {
	verify.DNSResolver

	calls int
	delay time.Duration
}

func (r *countingResolver) FindBadgeForVersion(ctx context.Context, fqdn models.Fqdn, version models.Version) (*verify.AnsBadgeRecord, error) {
	r.calls++

	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, ctx.Err() //nolint:wrapcheck // test double
		}
	}

	return r.DNSResolver.FindBadgeForVersion(ctx, fqdn, version) //nolint:wrapcheck // pass-through test double
}

// fixture is a complete, passing verification scenario that individual cases
// mutate before calling lookup.
type fixture struct {
	t          *testing.T
	log        *testLog
	cert       identityCert
	dns        *countingResolver
	client     *fakeLogClient
	clock      time.Time
	cfg        ansconfig.Config
	name       *naming.ParsedName
	evidence   naming.Evidence
	factoryErr error
	realClient bool
	verifier   *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	log := mintLog(t)
	cert := mintIdentityCert(t, testAnsName, testNow.Add(-time.Hour), testNow.Add(24*time.Hour))

	f := &fixture{
		t:        t,
		log:      log,
		cert:     cert,
		clock:    testNow,
		name:     naming.ParseName(testAnsName),
		evidence: naming.Evidence{Certificates: [][]byte{cert.der}},
		cfg: ansconfig.Config{
			Enabled:         true,
			TrustedLogHosts: []string{testLogHost},
			RootKeys:        []string{log.rootKeyLine(t)},
		},
		client: &fakeLogClient{rootKeys: []string{log.rootKeyLine(t)}},
	}

	f.setBadgeURL(testBadgeURL)
	f.setToken(f.claims())
	f.setReceipt(eventJSON(t, "ansId", testAgentID, testAnsName))

	return f
}

func (f *fixture) claims() tokenClaims {
	return tokenClaims{
		agentID:       testAgentID,
		ansName:       testAnsName,
		status:        "ACTIVE",
		iat:           testNow.Unix() - 60,
		exp:           testNow.Unix() + 3600,
		identityCerts: []string{f.cert.fingerprint},
	}
}

func (f *fixture) setToken(claims tokenClaims) {
	f.client.token = f.log.statusToken(f.t, claims)
}

func (f *fixture) setReceipt(event []byte) {
	f.client.receipt = f.log.receipt(f.t, event, 1, 0, nil, testNow.Unix())
}

func (f *fixture) setBadgeURL(raw string) {
	version, _ := models.ParseVersion(testVersion)
	records := []verify.AnsBadgeRecord{{FormatVersion: "ans-badge1", Version: &version, URL: raw}}
	f.dns = &countingResolver{DNSResolver: verify.NewMockDNSResolver().WithRecords(testHost, records)}
}

func (f *fixture) setDNSError(err error) {
	f.dns = &countingResolver{DNSResolver: verify.NewMockDNSResolver().WithError(testHost, err)}
}

// mintCert mints another identity certificate valid at the fixture clock.
func (f *fixture) mintCert(ansName string) identityCert {
	return mintIdentityCert(f.t, ansName, testNow.Add(-time.Hour), testNow.Add(time.Hour))
}

func (f *fixture) build() *Verifier {
	if f.verifier != nil {
		return f.verifier
	}

	opts := []Option{
		WithDNSResolver(f.dns),
		WithClock(func() time.Time { return f.clock }),
	}

	if !f.realClient {
		opts = append(opts, WithLogClientFactory(func(base string) (scitt.Client, error) {
			f.client.base = base

			if f.factoryErr != nil {
				return nil, f.factoryErr
			}

			return f.client, nil
		}))
	}

	v, err := NewVerifier(f.cfg, opts...)
	if err != nil {
		f.t.Fatalf("NewVerifier() error = %v", err)
	}

	f.verifier = v

	return v
}

func (f *fixture) lookup() (*naming.LookupResult, error) {
	return f.build().LookupKeys(f.t.Context(), f.name, f.evidence)
}

// lookupCase is one LookupKeys scenario.
type lookupCase struct {
	name          string
	setup         func(f *fixture)
	wantErr       string
	wantTransient bool
	wantKeys      int
	wantKeyType   string
	wantStatus    string
	wantNoDNS     bool
	wantNoLog     bool
}

func runLookupCases(t *testing.T, cases []lookupCase) {
	t.Helper()

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			if tt.setup != nil {
				tt.setup(f)
			}

			got, err := f.lookup()

			assertNetworkUse(t, f, tt)

			if tt.wantErr != "" {
				assertLookupError(t, err, tt.wantErr, tt.wantTransient)

				return
			}

			assertLookupResult(t, got, err, tt)
		})
	}
}

func assertNetworkUse(t *testing.T, f *fixture, tt lookupCase) {
	t.Helper()

	if tt.wantNoDNS && f.dns.calls != 0 {
		t.Errorf("DNS was queried %d times, want none", f.dns.calls)
	}

	if (tt.wantNoDNS || tt.wantNoLog) && f.client.callCount() != 0 {
		t.Errorf("transparency log was called %d times, want none", f.client.callCount())
	}
}

func assertLookupError(t *testing.T, err error, wantErr string, wantTransient bool) {
	t.Helper()

	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("LookupKeys() error = %v, want containing %q", err, wantErr)
	}

	if errors.Is(err, naming.ErrTransient) != wantTransient {
		t.Errorf("LookupKeys() transient = %v, want %v", !wantTransient, wantTransient)
	}
}

func assertLookupResult(t *testing.T, got *naming.LookupResult, err error, tt lookupCase) {
	t.Helper()

	if err != nil {
		t.Fatalf("LookupKeys() unexpected error: %v", err)
	}

	if len(got.Keys) != tt.wantKeys {
		t.Fatalf("LookupKeys() returned %d keys, want %d", len(got.Keys), tt.wantKeys)
	}

	if tt.wantKeyType != "" && got.Keys[0].Type != tt.wantKeyType {
		t.Errorf("key type = %q, want %q", got.Keys[0].Type, tt.wantKeyType)
	}

	d, err := details.Decode(got.Details)
	if err != nil {
		t.Fatalf("details.Decode() error = %v", err)
	}

	if d.AgentStatus != tt.wantStatus {
		t.Errorf("AgentStatus = %q, want %q", d.AgentStatus, tt.wantStatus)
	}
}

func TestLookupKeysCertificateStage(t *testing.T) {
	runLookupCases(t, []lookupCase{
		{
			name: "no certificates makes no network call",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{}
			},
			wantErr:   "ans certificate: no certificate attached to the record's signatures",
			wantNoDNS: true,
		},
		{
			name: "certificate for another host",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{f.mintCert("ans://v1.0.0.other.example.com").der}}
			},
			wantErr:   "ans certificate: no attached certificate names this agent",
			wantNoDNS: true,
		},
		{
			name: "certificate for another version",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{f.mintCert("ans://v1.0.1.agent.example.com").der}}
			},
			wantErr:   "ans certificate: no attached certificate names this agent",
			wantNoDNS: true,
		},
		{
			name: "certificate without an ans uri san",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{f.mintCert("spiffe://trust.example.com/agent").der}}
			},
			wantErr:   "ans certificate: no attached certificate names this agent",
			wantNoDNS: true,
		},
		{
			name: "expired certificate",
			setup: func(f *fixture) {
				expired := mintIdentityCert(f.t, testAnsName, testNow.Add(-2*time.Hour), testNow.Add(-time.Minute))
				f.evidence = naming.Evidence{Certificates: [][]byte{expired.der}}
			},
			wantErr:   "ans certificate: certificate expired or not yet valid",
			wantNoDNS: true,
		},
		{
			name: "certificate not yet valid",
			setup: func(f *fixture) {
				future := mintIdentityCert(f.t, testAnsName, testNow.Add(time.Minute), testNow.Add(time.Hour))
				f.evidence = naming.Evidence{Certificates: [][]byte{future.der}}
			},
			wantErr:   "ans certificate: certificate expired or not yet valid",
			wantNoDNS: true,
		},
		{
			name: "oversized and unparsable certificates are skipped",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{make([]byte, maxCertificateBytes+1), []byte("junk"), f.cert.der}}
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "version label outside uint32",
			setup: func(f *fixture) {
				f.name = &naming.ParsedName{Protocol: naming.ANSProtocol, Domain: testHost, Version: "v4294967296.0.0"}
			},
			wantErr:   "ans name: version",
			wantNoDNS: true,
		},
	})
}

func TestLookupKeysDNSStage(t *testing.T) {
	runLookupCases(t, []lookupCase{
		{
			name: "no badge record",
			setup: func(f *fixture) {
				f.dns = &countingResolver{DNSResolver: verify.NewMockDNSResolver()}
			},
			wantErr:   "ans dns: no _ans-badge record for agent.example.com version v1.0.0",
			wantNoLog: true,
		},
		{
			name: "legacy _ra-badge record is accepted",
			setup: func(f *fixture) {
				version, _ := models.ParseVersion(testVersion)
				records := []verify.AnsBadgeRecord{{FormatVersion: "ra-badge1", Version: &version, URL: testBadgeURL}}
				f.dns = &countingResolver{DNSResolver: verify.NewMockDNSResolver().WithRaBadgeRecords(testHost, records)}
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "badge record for another version only",
			setup: func(f *fixture) {
				version, _ := models.ParseVersion("v2.0.0")
				records := []verify.AnsBadgeRecord{{FormatVersion: "ans-badge1", Version: &version, URL: testBadgeURL}}
				f.dns = &countingResolver{DNSResolver: verify.NewMockDNSResolver().WithRecords(testHost, records)}
			},
			wantErr:   "ans dns: no _ans-badge record for agent.example.com version v1.0.0",
			wantNoLog: true,
		},
		{
			name: "dns timeout",
			setup: func(f *fixture) {
				f.setDNSError(&verify.DNSError{Type: verify.DNSErrorTimeout, Fqdn: "_ans-badge." + testHost})
			},
			wantErr:       "ans dns: DNS lookup timed out",
			wantTransient: true,
			wantNoLog:     true,
		},
		{
			name: "dns lookup failed",
			setup: func(f *fixture) {
				f.setDNSError(&verify.DNSError{Type: verify.DNSErrorLookupFailed, Fqdn: "_ans-badge." + testHost, Reason: "server misbehaving"})
			},
			wantErr:       "ans dns: DNS lookup failed",
			wantTransient: true,
			wantNoLog:     true,
		},
		{
			name: "unexpected resolver error is terminal",
			setup: func(f *fixture) {
				f.setDNSError(errBoom)
			},
			wantErr:   "ans dns: unexpected failure",
			wantNoLog: true,
		},
		{
			name: "host is not a dns name",
			setup: func(f *fixture) {
				const name = "ans://v1.0.0.bad_host.example.com"

				f.name = naming.ParseName(name)
				f.evidence = naming.Evidence{Certificates: [][]byte{f.mintCert(name).der}}
			},
			wantErr:   `ans dns: host "bad_host.example.com" is not a valid DNS name`,
			wantNoLog: true,
		},
	})
}

func TestLookupKeysBadgeStage(t *testing.T) {
	runLookupCases(t, []lookupCase{
		{
			name: "log host not allow-listed",
			setup: func(f *fixture) {
				f.setBadgeURL("https://evil.example.com/v1/agents/" + testAgentID)
			},
			wantErr:   `ans badge-url: log host "evil.example.com" is not a trusted transparency log`,
			wantNoLog: true,
		},
		{
			name: "log host on an unexpected port",
			setup: func(f *fixture) {
				f.setBadgeURL("https://log.example.com:8443/v1/agents/" + testAgentID)
			},
			wantErr:   `ans badge-url: log host "log.example.com:8443" is not a trusted transparency log`,
			wantNoLog: true,
		},
		{
			name: "trusted host configured with the default port in mixed case",
			setup: func(f *fixture) {
				f.cfg.TrustedLogHosts = []string{" LOG.Example.COM:443 "}
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "badge path is not the agent resource",
			setup: func(f *fixture) {
				f.setBadgeURL(testBadgeURL + "/status-token")
			},
			wantErr:   "ans badge-url: badge URL path must be /v1/agents/{agentId}",
			wantNoLog: true,
		},
		{
			name: "badge url carries a query",
			setup: func(f *fixture) {
				f.setBadgeURL(testBadgeURL + "?x=1")
			},
			wantErr:   "ans badge-url: badge URL must not carry a query",
			wantNoLog: true,
		},
		{
			name: "badge agent id is not a uuid",
			setup: func(f *fixture) {
				f.setBadgeURL(testLogBase + "/v1/agents/not-a-uuid")
			},
			wantErr:   "ans badge-url: badge URL agent id is not a UUID",
			wantNoLog: true,
		},
		{
			name: "log client cannot be created",
			setup: func(f *fixture) {
				f.factoryErr = errBoom
			},
			wantErr:   "ans log: cannot create a client for the transparency log",
			wantNoLog: true,
		},
	})
}

func TestLookupKeysRootKeysStage(t *testing.T) {
	unpinned := func(f *fixture) {
		f.cfg.RootKeys = nil
		f.cfg.AllowUnpinnedRootKeys = true
	}

	runLookupCases(t, []lookupCase{
		{
			name:       "fetched root keys verify the log",
			setup:      unpinned,
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "root keys fetch fails with 500",
			setup: func(f *fixture) {
				unpinned(f)
				f.client.rootKeysErr = &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusInternalServerError}
			},
			wantErr:       "ans root-keys: transparency log returned HTTP 500",
			wantTransient: true,
		},
		{
			name: "malformed root keys",
			setup: func(f *fixture) {
				unpinned(f)
				f.client.rootKeys = []string{"not-a-root-key"}
			},
			wantErr: "ans root-keys: transparency log served malformed root keys",
		},
		{
			name: "empty root keys",
			setup: func(f *fixture) {
				unpinned(f)
				f.client.rootKeys = nil
			},
			wantErr: "ans root-keys: transparency log served no root keys",
		},
		{
			name: "pinned keys reject a log signing with another key",
			setup: func(f *fixture) {
				f.client.token = mintLog(f.t).statusToken(f.t, f.claims())
			},
			wantErr:       "ans status-token: signed by unknown key id",
			wantTransient: true,
		},
	})
}

func TestLookupKeysStatusTokenStage(t *testing.T) {
	withClaims := func(mutate func(claims *tokenClaims)) func(f *fixture) {
		return func(f *fixture) {
			claims := f.claims()
			mutate(&claims)
			f.setToken(claims)
		}
	}

	runLookupCases(t, []lookupCase{
		{
			name:    "token names another agent",
			setup:   withClaims(func(claims *tokenClaims) { claims.agentID = otherAgentID }),
			wantErr: "ans status-token: token names agent " + otherAgentID + ", expected " + testAgentID,
		},
		{
			name:    "token names another host",
			setup:   withClaims(func(claims *tokenClaims) { claims.ansName = "ans://v1.0.0.other.example.com" }),
			wantErr: "ans status-token: token names ans://v1.0.0.other.example.com, expected ans://v1.0.0.agent.example.com",
		},
		{
			name:    "token names another version",
			setup:   withClaims(func(claims *tokenClaims) { claims.ansName = "ans://v2.0.0.agent.example.com" }),
			wantErr: "ans status-token: token names ans://v2.0.0.agent.example.com, expected ans://v1.0.0.agent.example.com",
		},
		{
			name: "uppercase record host matches the lowercase token name",
			setup: func(f *fixture) {
				f.name = naming.ParseName("ans://v1.0.0.Agent.Example.COM")
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name:       "uppercase token name matches the record",
			setup:      withClaims(func(claims *tokenClaims) { claims.ansName = "ans://v1.0.0.AGENT.example.com" }),
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "certificate not attested",
			setup: func(f *fixture) {
				claims := f.claims()
				claims.identityCerts = []string{f.mintCert(testAnsName).fingerprint}
				f.setToken(claims)
			},
			wantErr: "ans certificate: no attached certificate is attested for this agent",
		},
		{
			name:       "deprecated agent is accepted",
			setup:      withClaims(func(claims *tokenClaims) { claims.status = "DEPRECATED" }),
			wantKeys:   1,
			wantStatus: "DEPRECATED",
		},
		{
			name:       "warning agent is accepted",
			setup:      withClaims(func(claims *tokenClaims) { claims.status = "WARNING" }),
			wantKeys:   1,
			wantStatus: "WARNING",
		},
		{
			name:    "revoked agent",
			setup:   withClaims(func(claims *tokenClaims) { claims.status = "REVOKED" }),
			wantErr: "ans status-token: agent status REVOKED is terminal",
		},
		{
			name:          "pending agent is transient",
			setup:         withClaims(func(claims *tokenClaims) { claims.status = "PENDING_DNS" }),
			wantErr:       "ans status-token: agent status PENDING_DNS does not allow connections",
			wantTransient: true,
		},
		{
			name:          "unknown status is transient",
			setup:         withClaims(func(claims *tokenClaims) { claims.status = "SOMETHING_NEW" }),
			wantErr:       "ans status-token: agent status SOMETHING_NEW does not allow connections",
			wantTransient: true,
		},
		{
			name: "status token 410",
			setup: func(f *fixture) {
				f.client.tokenErr = &scitt.TransportError{Type: scitt.TransportErrAgentTerminal, StatusCode: http.StatusGone}
			},
			wantErr: "ans status-token: agent is in a terminal state (HTTP 410)",
		},
		{
			name: "status token 404 is transient",
			setup: func(f *fixture) {
				f.client.tokenErr = &scitt.TransportError{Type: scitt.TransportErrNotFound, StatusCode: http.StatusNotFound}
			},
			wantErr:       "ans status-token: not found on the transparency log (HTTP 404)",
			wantTransient: true,
		},
		{
			name: "status token 501",
			setup: func(f *fixture) {
				f.client.tokenErr = &scitt.TransportError{Type: scitt.TransportErrNotSupported, StatusCode: http.StatusNotImplemented}
			},
			wantErr: "ans status-token: transparency log returned HTTP 501",
		},
		{
			name:          "status token expired",
			setup:         withClaims(func(claims *tokenClaims) { claims.exp = testNow.Unix() - 60 }),
			wantErr:       "ans status-token: status token expired at",
			wantTransient: true,
		},
		{
			name: "status token tampered",
			setup: func(f *fixture) {
				f.client.token[len(f.client.token)-1] ^= 0x01
			},
			wantErr: "ans status-token: signature verification failed",
		},
		{
			name: "status token is not cose",
			setup: func(f *fixture) {
				f.client.token = []byte("nope")
			},
			wantErr: "ans status-token: malformed COSE_Sign1 structure",
		},
		{
			name: "two certificates one attested",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{f.mintCert(testAnsName).der, f.cert.der}}
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "duplicate certificates collapse to one key",
			setup: func(f *fixture) {
				f.evidence = naming.Evidence{Certificates: [][]byte{f.cert.der, f.cert.der}}
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "matched certificates are capped",
			setup: func(f *fixture) {
				claims := f.claims()
				f.evidence = naming.Evidence{}

				for range maxMatchedCertificates + 1 {
					cert := f.mintCert(testAnsName)
					f.evidence.Certificates = append(f.evidence.Certificates, cert.der)
					claims.identityCerts = append(claims.identityCerts, cert.fingerprint)
				}

				f.setToken(claims)
			},
			wantKeys:   maxMatchedCertificates,
			wantStatus: "ACTIVE",
		},
		{
			name: "ed25519 identity certificate",
			setup: func(f *fixture) {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					f.t.Fatal(err)
				}

				f.cert = mintIdentityCertWithKey(f.t, testAnsName, testNow.Add(-time.Hour), testNow.Add(time.Hour), key)
				f.evidence = naming.Evidence{Certificates: [][]byte{f.cert.der}}
				f.setToken(f.claims())
			},
			wantKeys:    1,
			wantKeyType: "ed25519",
			wantStatus:  "ACTIVE",
		},
		{
			name: "total time budget exhausted",
			setup: func(f *fixture) {
				f.cfg.Timeout = 50 * time.Millisecond
				f.client.block = true
			},
			wantErr:       "ans status-token: timed out",
			wantTransient: true,
		},
	})
}

func TestLookupKeysReceiptStage(t *testing.T) {
	runLookupCases(t, []lookupCase{
		{
			name: "receipt 503 is transient",
			setup: func(f *fixture) {
				f.client.receiptErr = &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable}
			},
			wantErr:       "ans receipt: transparency log returned HTTP 503",
			wantTransient: true,
		},
		{
			name: "receipt 404 is transient",
			setup: func(f *fixture) {
				f.client.receiptErr = &scitt.TransportError{Type: scitt.TransportErrNotFound, StatusCode: http.StatusNotFound}
			},
			wantErr:       "ans receipt: not found on the transparency log (HTTP 404)",
			wantTransient: true,
		},
		{
			name: "receipt 410 is terminal",
			setup: func(f *fixture) {
				f.client.receiptErr = &scitt.TransportError{Type: scitt.TransportErrAgentTerminal, StatusCode: http.StatusGone}
			},
			wantErr: "ans receipt: agent is in a terminal state (HTTP 410)",
		},
		{
			name: "receipt names another agent",
			setup: func(f *fixture) {
				f.setReceipt(eventJSON(f.t, "ansId", otherAgentID, testAnsName))
			},
			wantErr: "ans receipt: receipt event names agent " + otherAgentID + ", expected " + testAgentID,
		},
		{
			name: "receipt names another host",
			setup: func(f *fixture) {
				f.setReceipt(eventJSON(f.t, "ansId", testAgentID, "ans://v1.0.0.other.example.com"))
			},
			wantErr: "ans receipt: receipt event names ans://v1.0.0.other.example.com, expected ans://v1.0.0.agent.example.com",
		},
		{
			name: "receipt event keyed by agentId",
			setup: func(f *fixture) {
				f.setReceipt(eventJSON(f.t, "agentId", testAgentID, testAnsName))
			},
			wantKeys:   1,
			wantStatus: "ACTIVE",
		},
		{
			name: "receipt payload is not an envelope",
			setup: func(f *fixture) {
				f.setReceipt([]byte("not json"))
			},
			wantErr: "ans receipt: event payload is not an ANS event envelope",
		},
		{
			name: "receipt envelope without an event",
			setup: func(f *fixture) {
				f.setReceipt([]byte(`{"payload":{"producer":{}}}`))
			},
			wantErr: "ans receipt: event payload is not an ANS event envelope",
		},
		{
			name: "receipt signed by an unknown key",
			setup: func(f *fixture) {
				f.client.receipt = mintLog(f.t).receipt(f.t, eventJSON(f.t, "ansId", testAgentID, testAnsName), 1, 0, nil, testNow.Unix())
			},
			wantErr:       "ans receipt: signed by unknown key id",
			wantTransient: true,
		},
		{
			name: "receipt tampered",
			setup: func(f *fixture) {
				f.client.receipt[len(f.client.receipt)-1] ^= 0x01
			},
			wantErr: "ans receipt: signature verification failed",
		},
		{
			name: "receipt issuer differs from the root key origin",
			setup: func(f *fixture) {
				f.log.origin = "someone-else"
				f.setReceipt(eventJSON(f.t, "ansId", testAgentID, testAnsName))
			},
			wantErr: "ans receipt: issuer does not match the signing key",
		},
	})
}

func TestLookupKeysResult(t *testing.T) {
	f := newFixture(t)

	sibling := scitt.ComputeLeafHash([]byte("another event"))
	f.client.receipt = f.log.receipt(t, eventJSON(t, "ansId", testAgentID, testAnsName), 2, 1, [][]byte{sibling[:]}, testNow.Unix())

	got, err := f.lookup()
	if err != nil {
		t.Fatalf("LookupKeys() error = %v", err)
	}

	if len(got.Keys) != 1 {
		t.Fatalf("LookupKeys() returned %d keys, want 1", len(got.Keys))
	}

	key := got.Keys[0]
	wantDER := spkiOf(t, f.cert.key.Public())

	if key.ID != f.cert.fingerprint {
		t.Errorf("key ID = %q, want %q", key.ID, f.cert.fingerprint)
	}

	if key.Type != "ecdsa-p256" {
		t.Errorf("key type = %q, want ecdsa-p256", key.Type)
	}

	if !bytes.Equal(key.Key, wantDER) {
		t.Error("key DER does not match the certificate's SubjectPublicKeyInfo")
	}

	if key.KeyBase64 != base64.StdEncoding.EncodeToString(wantDER) {
		t.Error("KeyBase64 does not encode the key DER")
	}

	d, err := details.Decode(got.Details)
	if err != nil {
		t.Fatalf("details.Decode() error = %v", err)
	}

	want := details.Details{
		Version:     details.Version,
		AnsName:     testAnsName,
		AgentHost:   naming.ParseName(testAnsName).Domain,
		AgentID:     testAgentID,
		LogURL:      testLogBase,
		ReceiptURL:  testLogBase + "/v1/agents/" + testAgentID + "/receipt",
		AgentStatus: "ACTIVE",
	}

	if *d != want {
		t.Errorf("details = %+v, want %+v", *d, want)
	}

	if f.client.base != testLogBase {
		t.Errorf("log client base = %q, want %q", f.client.base, testLogBase)
	}

	if len(f.client.agentIDs) != 2 || f.client.agentIDs[0] != testAgentID || f.client.agentIDs[1] != testAgentID {
		t.Errorf("log fetched agent ids %v, want the badge agent twice", f.client.agentIDs)
	}

	if f.dns.calls != 1 {
		t.Errorf("DNS queried %d times, want 1", f.dns.calls)
	}
}

func TestVerifierMethod(t *testing.T) {
	f := newFixture(t)

	if got := f.build().Method(); got != naming.MethodANS {
		t.Errorf("Method() = %q, want %q", got, naming.MethodANS)
	}

	var _ naming.MethodLookup = f.build()
}

func TestCircuitBreakerTripsOnConnectionFailures(t *testing.T) {
	f := newFixture(t)
	f.client.tokenErr = &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: errBoom}

	for i := range breakerThreshold {
		_, err := f.lookup()
		if !errors.Is(err, naming.ErrTransient) {
			t.Fatalf("lookup %d: error = %v, want transient", i+1, err)
		}

		if _, ok := errors.AsType[*naming.RetryAfterError](err); ok {
			t.Fatalf("lookup %d: circuit opened before %d failures", i+1, breakerThreshold)
		}
	}

	_, err := f.lookup()

	retry, ok := errors.AsType[*naming.RetryAfterError](err)
	if !ok {
		t.Fatalf("lookup after %d failures: error = %v, want RetryAfterError", breakerThreshold, err)
	}

	if want := testNow.Add(breakerCooldown); !retry.Until.Equal(want) {
		t.Errorf("RetryAfter.Until = %s, want %s", retry.Until, want)
	}

	if !errors.Is(err, naming.ErrTransient) || !strings.Contains(err.Error(), "ans log: transparency log log.example.com is unavailable") {
		t.Errorf("open-circuit error = %v", err)
	}

	if f.client.callCount() != breakerThreshold {
		t.Errorf("log called %d times, want %d (fail fast while open)", f.client.callCount(), breakerThreshold)
	}

	f.clock = testNow.Add(breakerCooldown + time.Second)
	f.client.tokenErr = nil

	got, err := f.lookup()
	if err != nil || len(got.Keys) != 1 {
		t.Fatalf("lookup after cooldown = %v, %v; want one key", got, err)
	}

	if f.client.callCount() != breakerThreshold+2 {
		t.Errorf("log called %d times after cooldown, want %d", f.client.callCount(), breakerThreshold+2)
	}
}

func TestCircuitBreakerIgnoresHTTPStatus(t *testing.T) {
	f := newFixture(t)
	f.client.tokenErr = &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable}

	for range breakerThreshold + 1 {
		_, err := f.lookup()
		if !errors.Is(err, naming.ErrTransient) {
			t.Fatalf("error = %v, want transient", err)
		}

		if _, ok := errors.AsType[*naming.RetryAfterError](err); ok {
			t.Fatal("HTTP 503 opened the circuit")
		}
	}

	if f.client.callCount() != breakerThreshold+1 {
		t.Errorf("log called %d times, want %d", f.client.callCount(), breakerThreshold+1)
	}
}

func TestCircuitBreakerResetsOnSuccess(t *testing.T) {
	f := newFixture(t)
	connErr := &scitt.TransportError{Type: scitt.TransportErrHTTPError, Message: "request failed", Cause: errBoom}

	f.client.tokenErr = connErr

	for range breakerThreshold - 1 {
		if _, err := f.lookup(); !errors.Is(err, naming.ErrTransient) {
			t.Fatalf("error = %v, want transient", err)
		}
	}

	f.client.tokenErr = nil

	if _, err := f.lookup(); err != nil {
		t.Fatalf("lookup after reset error = %v", err)
	}

	f.client.tokenErr = connErr

	for range breakerThreshold - 1 {
		_, err := f.lookup()
		if _, ok := errors.AsType[*naming.RetryAfterError](err); ok {
			t.Fatal("success did not reset the failure count")
		}
	}

	if want := 2*(breakerThreshold-1) + 2; f.client.callCount() != want {
		t.Errorf("log called %d times, want %d", f.client.callCount(), want)
	}
}

// tlsLog serves the fixture's artifacts over TLS the way a real log would.
type tlsLog struct {
	server   *httptest.Server
	mu       sync.Mutex
	redirect bool
	moved    int
}

func startTLSLog(t *testing.T, f *fixture) *tlsLog {
	t.Helper()

	l := &tlsLog{}
	mux := http.NewServeMux()

	mux.HandleFunc("/root-keys", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(f.log.rootKeyLine(t) + "\n"))
	})
	mux.HandleFunc("/v1/agents/"+testAgentID+"/status-token", func(w http.ResponseWriter, r *http.Request) {
		if l.redirect {
			http.Redirect(w, r, "/v1/agents/"+testAgentID+"/status-token-moved", http.StatusFound)

			return
		}

		_, _ = w.Write(f.client.token)
	})
	mux.HandleFunc("/v1/agents/"+testAgentID+"/status-token-moved", func(w http.ResponseWriter, _ *http.Request) {
		l.mu.Lock()
		l.moved++
		l.mu.Unlock()

		_, _ = w.Write(f.client.token)
	})
	mux.HandleFunc("/v1/agents/"+testAgentID+"/receipt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(f.client.receipt)
	})

	l.server = httptest.NewTLSServer(mux)
	t.Cleanup(l.server.Close)

	host := strings.TrimPrefix(l.server.URL, "https://")

	f.realClient = true
	f.cfg.TrustedLogHosts = []string{host}
	f.cfg.CAFile = writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.server.Certificate().Raw}))
	f.setBadgeURL(l.server.URL + "/v1/agents/" + testAgentID)

	return l
}

func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestLookupKeysOverTLS(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(f *fixture, l *tlsLog)
		wantErr       string
		wantTransient bool
	}{
		{
			name: "pinned keys",
		},
		{
			name: "fetched keys",
			setup: func(f *fixture, _ *tlsLog) {
				f.cfg.RootKeys = nil
				f.cfg.AllowUnpinnedRootKeys = true
			},
		},
		{
			name: "redirect from a trusted host is not followed",
			setup: func(_ *fixture, l *tlsLog) {
				l.redirect = true
			},
			wantErr: "ans status-token: transparency log returned HTTP 302",
		},
		{
			name: "untrusted server certificate",
			setup: func(f *fixture, _ *tlsLog) {
				f.cfg.CAFile = ""
			},
			wantErr:       "ans status-token: TLS handshake failed",
			wantTransient: true,
		},
		{
			name: "connection refused",
			setup: func(_ *fixture, l *tlsLog) {
				l.server.Close()
			},
			wantErr:       "ans status-token: transparency log unreachable",
			wantTransient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			l := startTLSLog(t, f)

			if tt.setup != nil {
				tt.setup(f, l)
			}

			got, err := f.lookup()

			if l.moved != 0 {
				t.Errorf("redirect target was fetched %d times", l.moved)
			}

			if tt.wantErr != "" {
				assertLookupError(t, err, tt.wantErr, tt.wantTransient)

				return
			}

			if err != nil {
				t.Fatalf("LookupKeys() error = %v", err)
			}

			d, err := details.Decode(got.Details)
			if err != nil {
				t.Fatalf("details.Decode() error = %v", err)
			}

			if d.LogURL != l.server.URL {
				t.Errorf("LogURL = %q, want %q", d.LogURL, l.server.URL)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	line := mintLog(t).rootKeyLine(t)
	cert := mintIdentityCert(t, testAnsName, testNow, testNow.Add(time.Hour))
	caFile := writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.der}))
	junkFile := writeFile(t, "junk.pem", []byte("junk"))
	missingFile := filepath.Join(t.TempDir(), "missing.pem")

	pinned := func(mutate func(cfg *ansconfig.Config)) ansconfig.Config {
		cfg := ansconfig.Config{Enabled: true, TrustedLogHosts: []string{testLogHost}, RootKeys: []string{line}}
		if mutate != nil {
			mutate(&cfg)
		}

		return cfg
	}

	tests := []struct {
		name      string
		cfg       ansconfig.Config
		wantErr   string
		wantHosts []string
	}{
		{name: "pinned keys", cfg: pinned(nil), wantHosts: []string{testLogHost}},
		{name: "unpinned keys with opt-in", cfg: pinned(func(cfg *ansconfig.Config) { cfg.RootKeys = nil; cfg.AllowUnpinnedRootKeys = true })},
		{
			name: "hosts are normalized",
			cfg: pinned(func(cfg *ansconfig.Config) {
				cfg.TrustedLogHosts = []string{" LOG.Example.com:443 ", "Other.example.com:8443"}
			}),
			wantHosts: []string{"log.example.com", "other.example.com:8443"},
		},
		{name: "ca file", cfg: pinned(func(cfg *ansconfig.Config) { cfg.CAFile = caFile })},
		{name: "dns server", cfg: pinned(func(cfg *ansconfig.Config) { cfg.DNSServer = "127.0.0.1:1" })},
		{name: "disabled configuration", cfg: pinned(func(cfg *ansconfig.Config) { cfg.Enabled = false }), wantErr: "enabled configuration"},
		{name: "malformed root key", cfg: pinned(func(cfg *ansconfig.Config) { cfg.RootKeys = []string{"not-a-key"} }), wantErr: "ans: root_keys"},
		{name: "no trusted hosts", cfg: pinned(func(cfg *ansconfig.Config) { cfg.TrustedLogHosts = nil }), wantErr: "ans: trusted_log_hosts"},
		{name: "malformed trusted host", cfg: pinned(func(cfg *ansconfig.Config) { cfg.TrustedLogHosts = []string{"https://log.example.com"} }), wantErr: "must not contain a scheme or path"},
		{name: "unpinned keys without opt-in", cfg: pinned(func(cfg *ansconfig.Config) { cfg.RootKeys = nil }), wantErr: "root_keys is empty"},
		{name: "negative timeout", cfg: pinned(func(cfg *ansconfig.Config) { cfg.Timeout = -time.Second }), wantErr: "timeout must not be negative"},
		{name: "dns server without port", cfg: pinned(func(cfg *ansconfig.Config) { cfg.DNSServer = "127.0.0.1" }), wantErr: "dns_server must be host:port"},
		{name: "missing ca file", cfg: pinned(func(cfg *ansconfig.Config) { cfg.CAFile = missingFile }), wantErr: "ans: ca_file"},
		{name: "ca file without certificates", cfg: pinned(func(cfg *ansconfig.Config) { cfg.CAFile = junkFile }), wantErr: "contains no PEM certificates"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.cfg)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewVerifier() error = %v, want containing %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("NewVerifier() unexpected error: %v", err)
			}

			if v == nil {
				t.Fatal("NewVerifier() returned nil")
			}

			if tt.wantHosts == nil {
				return
			}

			if len(v.trustedHosts) != len(tt.wantHosts) {
				t.Errorf("trusted hosts = %v, want %v", v.trustedHosts, tt.wantHosts)
			}

			for _, host := range tt.wantHosts {
				if _, ok := v.trustedHosts[host]; !ok {
					t.Errorf("trusted hosts %v lack %q", v.trustedHosts, host)
				}
			}
		})
	}
}

func TestLookupKeysWithConfiguredDNSServer(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{name: "server does not answer", server: "127.0.0.1:1"},
		{name: "server cannot be dialed", server: "256.256.256.256:53"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.DNSServer = tt.server
			f.cfg.Timeout = time.Second

			v, err := NewVerifier(f.cfg, WithClock(func() time.Time { return f.clock }))
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}

			_, err = v.LookupKeys(t.Context(), f.name, f.evidence)
			if err == nil || !errors.Is(err, naming.ErrTransient) || !strings.Contains(err.Error(), "ans dns:") {
				t.Fatalf("LookupKeys() error = %v, want a transient dns failure", err)
			}
		})
	}
}
