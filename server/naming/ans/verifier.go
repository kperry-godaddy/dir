// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/models"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	"github.com/agntcy/dir/server/naming"
	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	"github.com/agntcy/dir/server/naming/ans/details"
	"github.com/agntcy/dir/utils/logging"
)

const (
	// maxCertificateBytes bounds one attached certificate before it is parsed.
	maxCertificateBytes = 16 << 10

	// maxMatchedCertificates caps the keys returned for one record. It applies
	// after the attestation match, so junk certificates cannot crowd out a
	// real one.
	maxMatchedCertificates = 16

	// statusTokenClockSkew is the tolerance applied to the status token expiry.
	statusTokenClockSkew = 30 * time.Second

	// breakerThreshold is the number of consecutive connection-level failures
	// that opens a log host's circuit.
	breakerThreshold = 3

	// breakerCooldown is how long an open circuit fails fast.
	breakerCooldown = 10 * time.Minute
)

var logger = logging.Logger("naming/ans")

// Verifier verifies ans:// names through the Agent Name Service: the record's
// signing key must belong to an identity certificate that the agent's
// transparency log attests for the agent the name resolves to. It implements
// naming.MethodLookup and is safe for concurrent use.
type Verifier struct {
	cfg          ansconfig.Config
	trustedHosts map[string]struct{}
	pinnedKeys   *scitt.KeyStore
	transport    *http.Transport
	dns          verify.DNSResolver
	newLogClient func(base string) (scitt.Client, error)
	clock        scitt.ClockFunc
	breaker      *breaker
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithDNSResolver replaces the resolver used for the _ans-badge lookups.
func WithDNSResolver(resolver verify.DNSResolver) Option {
	return func(v *Verifier) {
		v.dns = resolver
	}
}

// WithLogClientFactory replaces how a client for a transparency log origin
// (scheme://host) is built.
func WithLogClientFactory(factory func(base string) (scitt.Client, error)) Option {
	return func(v *Verifier) {
		v.newLogClient = factory
	}
}

// WithClock replaces the clock used for certificate validity, status token
// expiry, and the circuit breaker.
func WithClock(clock scitt.ClockFunc) Option {
	return func(v *Verifier) {
		v.clock = clock
	}
}

// NewVerifier builds a verifier from a validated configuration. Pinned root
// keys are parsed here so a malformed line fails startup, and one HTTP
// transport with ca_file appended to the system roots is shared by every
// log connection. No network call is made.
func NewVerifier(cfg ansconfig.Config, opts ...Option) (*Verifier, error) {
	trusted, err := trustedHostSet(cfg.TrustedLogHosts)
	if err != nil {
		return nil, err
	}

	v := &Verifier{
		cfg:          cfg,
		trustedHosts: trusted,
		clock:        time.Now,
		breaker:      newBreaker(),
	}

	if len(cfg.RootKeys) > 0 {
		keys, err := scitt.NewKeyStore(cfg.RootKeys)
		if err != nil {
			return nil, fmt.Errorf("ans: root_keys: %w", err)
		}

		v.pinnedKeys = keys
	} else {
		logger.Warn("ANS root keys are not pinned; trust in the transparency logs rests on TLS to the trusted hosts",
			"trustedLogHosts", cfg.TrustedLogHosts)
	}

	v.transport, err = newTransport(cfg.CAFile)
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.dns == nil {
		v.dns = defaultResolver(cfg.DNSServer)
	}

	if v.newLogClient == nil {
		v.newLogClient = v.httpLogClient
	}

	return v, nil
}

// Method names the verification method for results and logs.
func (v *Verifier) Method() naming.VerificationMethod {
	return naming.MethodANS
}

// LookupKeys runs the trust path for one record: the attached certificates
// first without any network call, then DNS, the badge URL gate, the log's
// keys, the status token, and the receipt. Failures caused by an unavailable
// dependency wrap naming.ErrTransient; an open circuit for the log host
// returns a naming.RetryAfterError. The whole lookup runs within the
// configured timeout.
func (v *Verifier) LookupKeys(ctx context.Context, name *naming.ParsedName, evidence naming.Evidence) (*naming.LookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, v.cfg.GetTimeout())
	defer cancel()

	result, err := v.lookup(ctx, name, evidence)
	if err != nil {
		return nil, classify(err)
	}

	return result, nil
}

func (v *Verifier) lookup(ctx context.Context, name *naming.ParsedName, evidence naming.Evidence) (*naming.LookupResult, error) {
	want, err := newAgentName(name)
	if err != nil {
		return nil, err
	}

	candidates, err := v.filterCertificates(want, evidence)
	if err != nil {
		return nil, err
	}

	target, err := v.resolveTarget(ctx, want)
	if err != nil {
		return nil, err
	}

	if until, open := v.breaker.openUntil(target.LogHost, v.clock()); open {
		return nil, &naming.RetryAfterError{
			Until: until,
			Err:   fail(stageLog, fmt.Sprintf("transparency log %s is unavailable; circuit open", target.LogHost)),
		}
	}

	client, err := v.newLogClient(target.LogBase)
	if err != nil {
		return nil, failWith(stageLog, err, "cannot create a client for the transparency log")
	}

	keys, err := v.keysFor(ctx, client, target)
	if err != nil {
		return nil, err
	}

	token, err := v.verifyStatusToken(ctx, client, keys, target, want)
	if err != nil {
		return nil, err
	}

	matched := matchCertificates(&token.Payload, candidates)
	if len(matched) == 0 {
		return nil, fail(stageCertificate, "no attached certificate is attested for this agent")
	}

	if err := v.verifyReceipt(ctx, client, keys, target, want); err != nil {
		return nil, err
	}

	return buildResult(want, target, token, matched)
}

// agentName is the structural identity of an ANS name: the lowercase agent
// host and the parsed version. Names are compared structurally so that
// "ans://v1.0.0.Agent.Example.COM" and "ans://v1.0.0.agent.example.com" agree.
type agentName struct {
	host    string
	version models.Version
}

func newAgentName(name *naming.ParsedName) (agentName, error) {
	version, err := models.ParseVersion(name.Version)
	if err != nil {
		return agentName{}, failWith(stageName, err, fmt.Sprintf("version %q is not a valid ANS version", name.Version))
	}

	return agentName{host: strings.ToLower(name.Domain), version: version}, nil
}

// matches reports whether raw parses to the same host and version.
func (n agentName) matches(raw string) bool {
	parsed, err := verify.ParseAnsName(raw)

	return err == nil && n.equals(parsed)
}

func (n agentName) equals(parsed *verify.AnsName) bool {
	return parsed != nil && parsed.Host == n.host && parsed.Version.Equal(n.version)
}

func (n agentName) String() string {
	return naming.ANSProtocol + n.version.String() + "." + n.host
}

// filterCertificates keeps the attached certificates that name this agent and
// are valid at the current time. It makes no network call.
func (v *Verifier) filterCertificates(want agentName, evidence naming.Evidence) ([]*x509.Certificate, error) {
	if len(evidence.Certificates) == 0 {
		return nil, fail(stageCertificate, "no certificate attached to the record's signatures")
	}

	now := v.clock()
	outsideValidity := 0

	var kept []*x509.Certificate

	for _, der := range evidence.Certificates {
		cert, ok := parseCandidate(der, want)
		if !ok {
			continue
		}

		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			outsideValidity++

			logger.Warn("Skipping certificate outside its validity window",
				"fingerprint", verify.CertFingerprintFromDER(der).String(),
				"notBefore", cert.NotBefore,
				"notAfter", cert.NotAfter)

			continue
		}

		kept = append(kept, cert)
	}

	if len(kept) == 0 {
		if outsideValidity > 0 {
			return nil, fail(stageCertificate, "certificate expired or not yet valid")
		}

		return nil, fail(stageCertificate, "no attached certificate names this agent")
	}

	return kept, nil
}

// parseCandidate parses one attached certificate and reports whether its URI
// SAN names the agent.
func parseCandidate(der []byte, want agentName) (*x509.Certificate, bool) {
	if len(der) > maxCertificateBytes {
		logger.Warn("Skipping oversized certificate", "bytes", len(der), "limit", maxCertificateBytes)

		return nil, false
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		logger.Warn("Skipping unparsable certificate", "error", err)

		return nil, false
	}

	if !want.equals(verify.CertIdentityFromX509(cert).AnsName()) {
		logger.Warn("Skipping certificate that does not name this agent",
			"fingerprint", verify.CertFingerprintFromDER(der).String(),
			"uris", cert.URIs,
			"ansName", want.String())

		return nil, false
	}

	return cert, true
}

// resolveTarget finds the agent's badge record in DNS and checks the URL it
// carries against the allow-list before any request is made.
func (v *Verifier) resolveTarget(ctx context.Context, want agentName) (badgeTarget, error) {
	fqdn, err := models.NewFqdn(want.host)
	if err != nil {
		return badgeTarget{}, failWith(stageDNS, err, fmt.Sprintf("host %q is not a valid DNS name", want.host))
	}

	record, err := v.dns.FindBadgeForVersion(ctx, fqdn, want.version)
	if err != nil {
		if errors.Is(err, verify.ErrRecordNotFound) {
			return badgeTarget{}, fail(stageDNS, fmt.Sprintf("no _ans-badge record for %s version %s", want.host, want.version))
		}

		logger.Debug("Badge lookup failed", "fqdn", fqdn.String(), "error", err)

		return badgeTarget{}, failWith(stageDNS, err, describe(err))
	}

	logger.Debug("Resolved badge record",
		"fqdn", fqdn.String(),
		"version", want.version.String(),
		"source", badgeSourceName(record.Source),
		"url", record.URL)

	target, err := parseBadgeURL(record.URL)
	if err != nil {
		return badgeTarget{}, err
	}

	if _, ok := v.trustedHosts[target.LogHost]; !ok {
		return badgeTarget{}, fail(stageBadgeURL, fmt.Sprintf("log host %q is not in name.ans.trusted_log_hosts", target.LogHost))
	}

	return target, nil
}

func badgeSourceName(source verify.BadgeRecordSource) string {
	if source == verify.BadgeRecordSourceRaBadge {
		return "_ra-badge"
	}

	return "_ans-badge"
}

// keysFor returns the key store that verifies the log's signatures: the
// pinned root keys, or the ones fetched from the log when none are pinned.
func (v *Verifier) keysFor(ctx context.Context, client scitt.Client, target badgeTarget) (scitt.KeyLookup, error) {
	if v.pinnedKeys != nil {
		return v.pinnedKeys, nil
	}

	lines, err := client.FetchRootKeys(ctx)
	v.observe(target.LogHost, err)

	if err != nil {
		return nil, failWith(stageRootKeys, err, describe(err))
	}

	if len(lines) == 0 {
		return nil, fail(stageRootKeys, "transparency log served no root keys")
	}

	keys, err := scitt.NewKeyStore(lines)
	if err != nil {
		return nil, failWith(stageRootKeys, err, "transparency log served malformed root keys")
	}

	logger.Debug("Fetched root keys", "logBase", target.LogBase, "keys", keys.Len())

	return keys, nil
}

// observe feeds one log request outcome to the breaker and logs a trip.
func (v *Verifier) observe(host string, err error) {
	if until, tripped := v.breaker.observe(host, err, v.clock()); tripped {
		logger.Warn("Transparency log circuit opened after consecutive connection failures",
			"logHost", host,
			"failures", breakerThreshold,
			"until", until,
			"error", err)
	}
}

// verifyStatusToken fetches and verifies the agent's status token and checks
// that it names this agent and allows connections.
func (v *Verifier) verifyStatusToken(ctx context.Context, client scitt.Client, keys scitt.KeyLookup, target badgeTarget, want agentName) (*scitt.VerifiedStatusToken, error) {
	tokenBytes, err := client.FetchStatusToken(ctx, target.AgentID)
	v.observe(target.LogHost, err)

	if err != nil {
		return nil, failWith(stageStatusToken, err, describe(err))
	}

	token, err := scitt.VerifyStatusTokenAt(tokenBytes, keys, statusTokenClockSkew, v.clock().Unix())
	if err != nil {
		logger.Debug("Status token rejected", "agentId", target.AgentID, "logBase", target.LogBase, "error", err)

		return nil, failWith(stageStatusToken, err, describe(err))
	}

	payload := &token.Payload

	if payload.AgentID != target.AgentID {
		return nil, fail(stageStatusToken, fmt.Sprintf("token names agent %s, expected %s", payload.AgentID, target.AgentID))
	}

	if !want.matches(payload.AnsName) {
		return nil, fail(stageStatusToken, fmt.Sprintf("token names %s, expected %s", payload.AnsName, want))
	}

	if !payload.Status.IsValidForConnection() {
		return nil, fail(stageStatusToken, fmt.Sprintf("agent status %s does not allow connections", payload.Status))
	}

	logger.Debug("Status token verified",
		"agentId", target.AgentID,
		"logBase", target.LogBase,
		"status", payload.Status,
		"identityCerts", len(payload.ValidIdentityCerts))

	return token, nil
}

// matchCertificates returns the candidates the status token attests as the
// agent's identity certificates, deduplicated by fingerprint and capped at
// maxMatchedCertificates.
func matchCertificates(payload *scitt.StatusTokenPayload, candidates []*x509.Certificate) []*x509.Certificate {
	seen := make(map[[32]byte]struct{}, len(candidates))

	var matched []*x509.Certificate

	for _, cert := range candidates {
		fingerprint := verify.CertFingerprintFromDER(cert.Raw)
		if _, dup := seen[fingerprint.Bytes()]; dup {
			continue
		}

		seen[fingerprint.Bytes()] = struct{}{}

		if !scitt.MatchesIdentityCert(payload, fingerprint.Bytes()) {
			logger.Debug("Certificate is not attested by the status token", "fingerprint", fingerprint.String())

			continue
		}

		logger.Debug("Matched attested certificate", "fingerprint", fingerprint.String())

		matched = append(matched, cert)
		if len(matched) == maxMatchedCertificates {
			break
		}
	}

	return matched
}

// verifyReceipt fetches and verifies the agent's receipt and checks that the
// logged event names this agent.
//
// The receipt signature covers the event payload only. Tree size, leaf index
// and the inclusion path travel in the unsigned COSE header; the SDK checks
// that they are well-formed and walks the path to a root it compares with
// nothing. The receipt therefore proves that the log signed this event and
// nothing about the event's position in the tree, so the position is logged
// and not recorded.
func (v *Verifier) verifyReceipt(ctx context.Context, client scitt.Client, keys scitt.KeyLookup, target badgeTarget, want agentName) error {
	receiptBytes, err := client.FetchReceipt(ctx, target.AgentID)
	v.observe(target.LogHost, err)

	if err != nil {
		return failWith(stageReceipt, err, describe(err))
	}

	receipt, err := scitt.VerifyReceipt(receiptBytes, keys)
	if err != nil {
		logger.Debug("Receipt rejected", "agentId", target.AgentID, "logBase", target.LogBase, "error", err)

		return failWith(stageReceipt, err, describe(err))
	}

	event, err := decodeEvent(receipt.EventBytes)
	if err != nil {
		return failWith(stageReceipt, err, "event payload is not an ANS event envelope")
	}

	if event.agentID() != target.AgentID {
		return fail(stageReceipt, fmt.Sprintf("receipt event names agent %s, expected %s", event.agentID(), target.AgentID))
	}

	if !want.matches(event.AnsName) {
		return fail(stageReceipt, fmt.Sprintf("receipt event names %s, expected %s", event.AnsName, want))
	}

	logger.Debug("Receipt verified",
		"agentId", target.AgentID,
		"logBase", target.LogBase,
		"treeSize", receipt.TreeSize,
		"leafIndex", receipt.LeafIndex)

	return nil
}

// eventEnvelope is the part of the log's event envelope the verifier reads:
// {"payload":{"producer":{"event":{...}}}}.
type eventEnvelope struct {
	Payload eventPayload `json:"payload"`
}

type eventPayload struct {
	Producer eventProducer `json:"producer"`
}

type eventProducer struct {
	Event *producerEvent `json:"event"`
}

// producerEvent names the agent an event is about. The reference log writes
// ansId; older envelopes wrote agentId.
type producerEvent struct {
	AnsID   string `json:"ansId"`
	AgentID string `json:"agentId"`
	AnsName string `json:"ansName"`
}

func (e *producerEvent) agentID() string {
	if e.AnsID != "" {
		return e.AnsID
	}

	return e.AgentID
}

var errNotAnEvent = errors.New("envelope carries no agent event")

func decodeEvent(raw []byte) (*producerEvent, error) {
	var envelope eventEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode event envelope: %w", err)
	}

	event := envelope.Payload.Producer.Event
	if event == nil || event.agentID() == "" {
		return nil, errNotAnEvent
	}

	return event, nil
}

// buildResult renders the matched certificates as published keys together
// with the verification details.
func buildResult(want agentName, target badgeTarget, token *scitt.VerifiedStatusToken, matched []*x509.Certificate) (*naming.LookupResult, error) {
	keys := make([]naming.PublicKey, 0, len(matched))

	for _, cert := range matched {
		der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return nil, failWith(stageCertificate, err, "certificate public key cannot be encoded")
		}

		keys = append(keys, naming.PublicKey{
			ID:        verify.CertFingerprintFromDER(cert.Raw).String(),
			Type:      keyTypeOf(cert.PublicKey),
			Key:       der,
			KeyBase64: base64.StdEncoding.EncodeToString(der),
		})
	}

	receiptURL, err := url.JoinPath(target.LogBase, "v1", "agents", target.AgentID, "receipt")
	if err != nil {
		return nil, failWith(stageReceipt, err, "cannot build the receipt URL")
	}

	encoded, err := json.Marshal(details.Details{
		Version:     details.Version,
		AnsName:     want.String(),
		AgentHost:   want.host,
		AgentID:     target.AgentID,
		LogURL:      target.LogBase,
		ReceiptURL:  receiptURL,
		AgentStatus: string(token.Payload.Status),
	})
	if err != nil {
		return nil, failWith(stageReceipt, err, "cannot encode verification details")
	}

	return &naming.LookupResult{Keys: keys, Details: encoded}, nil
}

// keyTypeOf names the algorithm of a certificate public key the way the
// naming API reports key types.
func keyTypeOf(pub crypto.PublicKey) string {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsaKeyType(key)
	case ed25519.PublicKey:
		return "ed25519"
	case *rsa.PublicKey:
		return "rsa"
	default:
		return "unknown"
	}
}

func ecdsaKeyType(key *ecdsa.PublicKey) string {
	switch key.Curve {
	case elliptic.P256():
		return "ecdsa-p256"
	case elliptic.P384():
		return "ecdsa-p384"
	case elliptic.P521():
		return "ecdsa-p521"
	default:
		return "ecdsa"
	}
}

// trustedHostSet normalizes the configured log hosts into a lookup set.
func trustedHostSet(hosts []string) (map[string]struct{}, error) {
	if len(hosts) == 0 {
		return nil, errors.New("ans: trusted_log_hosts must list at least one transparency-log host")
	}

	set := make(map[string]struct{}, len(hosts))

	for _, host := range hosts {
		normalized, err := ansconfig.NormalizeHost(host)
		if err != nil {
			return nil, fmt.Errorf("ans: trusted_log_hosts: %w", err)
		}

		set[normalized] = struct{}{}
	}

	return set, nil
}

// newTransport clones the default transport with the system roots plus the
// certificates in caFile, so a mixed list of public and private logs works.
func newTransport(caFile string) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("ans: system certificate pool: %w", err)
	}

	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile) //nolint:gosec // operator-supplied path from configuration
		if err != nil {
			return nil, fmt.Errorf("ans: ca_file: %w", err)
		}

		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("ans: ca_file %q contains no PEM certificates", caFile)
		}
	}

	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // http.DefaultTransport is documented as an *http.Transport
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	return transport, nil
}

// defaultResolver builds the SDK resolver, pointed at server (host:port) for
// both UDP and TCP when one is configured.
func defaultResolver(server string) verify.DNSResolver {
	resolver := verify.NewStandardDNSResolver()
	if server == "" {
		return resolver
	}

	dialer := &net.Dialer{}

	return resolver.WithResolver(&net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, server)
			if err != nil {
				return nil, fmt.Errorf("ans dns: dial %s: %w", network, err)
			}

			return conn, nil
		},
	})
}

// httpLogClient builds the SDK client for one log origin: the shared
// transport, no redirects, and the lookup's time budget as the request timeout.
func (v *Verifier) httpLogClient(base string) (scitt.Client, error) {
	httpClient := &http.Client{
		Transport: v.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	client, err := scitt.NewHTTPClient(base, scitt.WithHTTPClient(httpClient), scitt.WithTimeout(v.cfg.GetTimeout()))
	if err != nil {
		return nil, fmt.Errorf("ans log client: %w", err)
	}

	return client, nil
}
