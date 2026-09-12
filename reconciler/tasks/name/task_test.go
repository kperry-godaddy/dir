// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:nilnil
package name

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	coretypes "github.com/agntcy/dir/api/core/types"
	corev1 "github.com/agntcy/dir/api/core/v1"
	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/client/utils/verify"
	gormdb "github.com/agntcy/dir/server/database/gorm"
	"github.com/agntcy/dir/server/naming"
	"github.com/agntcy/dir/server/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	taskTestCID      = signersTestCID
	taskTestOtherCID = "baeareitestsigners111111111111111111111111111111111111111111111"
	taskTestANSName  = "ans://v1.0.0.agent.example.com/assistant"
	taskTestHTTPS    = "https://example.com/agent"
	taskTestDetails  = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentId":"agent-1"}`
	victimKeyID      = "SHA256:victim"
	dnsTimeoutText   = "ans dns: lookup timed out"
	taskTestTTL      = 7 * 24 * time.Hour
	taskTestInterval = time.Hour
	ansProtocol      = "ans://"
)

var (
	fixedNow       = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	errLookupDown  = errors.New("transport down")
	errAgentRevoke = errors.New("ans status-token: agent revoked")
	errDNSTimeout  = errors.Join(errors.New(dnsTimeoutText), naming.ErrTransient)

	// existingVerifiedAt is when a verified row built by existingRow last verified.
	existingVerifiedAt = fixedNow.Add(-2 * time.Hour)
)

// --- fakes ---

type fakeRecord struct {
	coretypes.Record

	cid, name string
}

func (r *fakeRecord) GetCid() string  { return r.cid }
func (r *fakeRecord) GetName() string { return r.name }

var _ verify.Fetcher = (*fakeFetcher)(nil)

type fakeFetcher struct {
	signatures []*signv1.Signature
	publicKeys []string
	sigErr     error
	keyErr     error

	sigCalls, keyCalls int
}

func (f *fakeFetcher) PullSignatures(_ context.Context, ref *corev1.RecordRef) ([]*signv1.Signature, error) {
	f.sigCalls++

	if ref.GetCid() != taskTestCID {
		return nil, errors.New("unexpected cid")
	}

	return f.signatures, f.sigErr
}

func (f *fakeFetcher) PullPublicKeys(_ context.Context, ref *corev1.RecordRef) ([]string, error) {
	f.keyCalls++

	if ref.GetCid() != taskTestCID {
		return nil, errors.New("unexpected cid")
	}

	return f.publicKeys, f.keyErr
}

type fakeDB struct {
	types.DatabaseAPI

	records    []coretypes.Record
	recordsErr error
	existing   *gormdb.NameVerification
	getErr     error

	createErr error
	updateErr error

	created []types.NameVerificationObject
	updated []types.NameVerificationObject
}

func (f *fakeDB) GetRecordsNeedingVerification(time.Duration) ([]coretypes.Record, error) {
	return f.records, f.recordsErr
}

func (f *fakeDB) GetVerificationByCID(string) (types.NameVerificationObject, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}

	if f.existing == nil {
		return nil, gormdb.ErrVerificationNotFound
	}

	return f.existing, nil
}

func (f *fakeDB) CreateNameVerification(v types.NameVerificationObject) error {
	f.created = append(f.created, v)

	return f.createErr
}

func (f *fakeDB) UpdateNameVerification(v types.NameVerificationObject) error {
	f.updated = append(f.updated, v)

	return f.updateErr
}

func (f *fakeDB) writes() int {
	return len(f.created) + len(f.updated)
}

// fakeLookup is the ans:// method: it records the evidence it was given and
// answers with configured keys or an error. onLookup, when set, runs first.
type fakeLookup struct {
	keys     []naming.PublicKey
	details  json.RawMessage
	err      error
	onLookup func()

	calls    int
	evidence naming.Evidence
	name     *naming.ParsedName
}

func (l *fakeLookup) Method() naming.VerificationMethod { return naming.MethodANS }

func (l *fakeLookup) LookupKeys(_ context.Context, name *naming.ParsedName, evidence naming.Evidence) (*naming.LookupResult, error) {
	l.calls++
	l.evidence = evidence
	l.name = name

	if l.onLookup != nil {
		l.onLookup()
	}

	if l.err != nil {
		return nil, l.err
	}

	return &naming.LookupResult{Keys: l.keys, Details: l.details}, nil
}

// fakeKeyLookup is the JWKS well-known fetcher for https:// and http:// names.
type fakeKeyLookup struct {
	keys []naming.PublicKey
	err  error

	calls  int
	domain string
	scheme string
}

func (l *fakeKeyLookup) LookupKeysWithScheme(_ context.Context, domain, scheme string) ([]naming.PublicKey, error) {
	l.calls++
	l.domain = domain
	l.scheme = scheme

	return l.keys, l.err
}

// --- helpers ---

func newTestTask(t *testing.T, cfg Config, db *fakeDB, fetcher *fakeFetcher, provider *naming.Provider) *Task {
	t.Helper()

	task, err := NewTask(cfg, db, fetcher, provider)
	require.NoError(t, err)

	task.now = func() time.Time { return fixedNow }

	return task
}

func ansProvider(lookup *fakeLookup) *naming.Provider {
	return naming.NewProvider(naming.WithLookup(ansProtocol, lookup))
}

func publishedKey(t *testing.T, id testIdentity) naming.PublicKey {
	t.Helper()

	return naming.PublicKey{ID: victimKeyID, Type: "ecdsa-p256", Key: mustMarshalKey(t, id.key.Public())}
}

func ansRecords() []coretypes.Record {
	return []coretypes.Record{&fakeRecord{cid: taskTestCID, name: taskTestANSName}}
}

func at(offset time.Duration) *time.Time {
	when := fixedNow.Add(offset)

	return &when
}

// existingRow is a stored row of the given status: a verified one carries the
// victim key, details and existingVerifiedAt; a failed one carries the
// revocation error; a pending one was created three hours ago.
func existingRow(status string, failures int) *gormdb.NameVerification {
	row := &gormdb.NameVerification{
		RecordCID:           taskTestCID,
		Method:              string(naming.MethodANS),
		Status:              status,
		ConsecutiveFailures: failures,
		CreatedAt:           fixedNow.Add(-3 * time.Hour),
		UpdatedAt:           fixedNow.Add(-time.Hour),
	}

	switch status {
	case gormdb.VerificationStatusVerified:
		verifiedAt := existingVerifiedAt
		row.KeyID = victimKeyID
		row.Details = taskTestDetails
		row.VerifiedAt = &verifiedAt
	case gormdb.VerificationStatusFailed:
		row.Error = errAgentRevoke.Error()
	default:
		row.Error = "transient: earlier"
	}

	return row
}

// pendingSinceRow is a pending row that stopped being served at the given
// offset from now: a demoted verified row when it has a verification time, a
// row created pending otherwise.
func pendingSinceRow(since time.Duration, demoted bool, failures int) *gormdb.NameVerification {
	row := existingRow(gormdb.VerificationStatusPending, failures)
	row.CreatedAt = fixedNow.Add(since)

	if demoted {
		verifiedAt := fixedNow.Add(since - taskTestTTL)
		row.CreatedAt = fixedNow.Add(-30 * 24 * time.Hour)
		row.KeyID = victimKeyID
		row.Details = taskTestDetails
		row.VerifiedAt = &verifiedAt
	}

	return row
}

func verifiedResult() *naming.Result {
	return &naming.Result{Verified: true, Domain: "agent.example.com", Method: string(naming.MethodANS), MatchedKeyID: victimKeyID, Details: json.RawMessage(taskTestDetails)}
}

func transientResult(errMsg string) *naming.Result {
	return &naming.Result{Domain: "agent.example.com", Method: string(naming.MethodANS), Error: errMsg, Transient: true}
}

func retryAfterResult(errMsg string, until time.Time) *naming.Result {
	result := transientResult(errMsg)
	result.RetryAfter = until

	return result
}

func terminalResult(errMsg string) *naming.Result {
	return &naming.Result{Domain: "agent.example.com", Method: string(naming.MethodANS), Error: errMsg}
}

// --- basics ---

func TestTask_Name_Interval_IsEnabled(t *testing.T) {
	task, err := NewTask(Config{Enabled: true, Interval: 2 * time.Minute}, nil, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, "name", task.Name())
	assert.Equal(t, 2*time.Minute, task.Interval())
	assert.True(t, task.IsEnabled())

	disabled, err := NewTask(Config{}, nil, nil, nil)
	require.NoError(t, err)
	assert.False(t, disabled.IsEnabled())
	assert.Equal(t, DefaultInterval, disabled.Interval())
}

func TestTask_Run_NoRecords(t *testing.T) {
	db := &fakeDB{}
	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{}, ansProvider(&fakeLookup{}))

	require.NoError(t, task.Run(t.Context()))
	assert.Equal(t, 0, db.writes())
}

func TestTask_Run_DatabaseError(t *testing.T) {
	db := &fakeDB{recordsErr: errors.New("db unavailable")}
	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{}, ansProvider(&fakeLookup{}))

	err := task.Run(t.Context())
	require.ErrorContains(t, err, "get records needing name verification")
	require.ErrorContains(t, err, "db unavailable")
}

// --- ans lane ---

func TestTask_Run_ANSCertificateSignersAreBound(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}, details: json.RawMessage(taskTestDetails)}
	fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}
	db := &fakeDB{records: ansRecords()}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(lookup))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)
	assert.Empty(t, db.updated)

	row := db.created[0]
	assert.Equal(t, taskTestCID, row.GetRecordCID())
	assert.Equal(t, string(naming.MethodANS), row.GetMethod())
	assert.Equal(t, gormdb.VerificationStatusVerified, row.GetStatus())
	assert.Equal(t, victimKeyID, row.GetKeyID())
	assert.JSONEq(t, taskTestDetails, row.GetDetails())
	assert.Empty(t, row.GetError())
	require.NotNil(t, row.GetVerifiedAt())
	assert.Equal(t, fixedNow, *row.GetVerifiedAt())
	assert.Equal(t, 0, row.GetConsecutiveFailures())
	assert.Nil(t, row.GetNextAttemptAt())

	assert.Equal(t, 1, lookup.calls, "exactly one Verify per record")
	assert.Equal(t, [][]byte{victim.cert.Raw}, lookup.evidence.Certificates)
	assert.Equal(t, "agent.example.com", lookup.name.Domain)
	assert.Equal(t, "v1.0.0", lookup.name.Version)
	assert.Equal(t, 1, fetcher.sigCalls)
	assert.Equal(t, 1, fetcher.keyCalls)
}

// Every name gets both signer kinds: the certificates bound to the record's
// signatures and the public keys attached to it.
func TestTask_Run_BothSignerKindsReachTheMethod(t *testing.T) {
	certified := newTestIdentity(t, signersTestSAN)
	keyed := newTestIdentity(t, "")

	certifiedKey := publishedKey(t, certified)
	keyedKey := naming.PublicKey{ID: "SHA256:keyed", Type: "ecdsa-p256", Key: mustMarshalKey(t, keyed.key.Public())}

	tests := []struct {
		name      string
		record    string
		published naming.PublicKey
		wantKeyID string
	}{
		{name: "ans name verified through a public-key signer", record: taskTestANSName, published: keyedKey, wantKeyID: "SHA256:keyed"},
		{name: "ans name verified through a certificate-bound signer", record: taskTestANSName, published: certifiedKey, wantKeyID: victimKeyID},
		{name: "https name verified through a public-key signer", record: taskTestHTTPS, published: keyedKey, wantKeyID: "SHA256:keyed"},
		{name: "https name verified through a certificate-bound signer", record: taskTestHTTPS, published: certifiedKey, wantKeyID: victimKeyID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ans := &fakeLookup{keys: []naming.PublicKey{tc.published}}
			wellKnown := &fakeKeyLookup{keys: []naming.PublicKey{tc.published}}
			provider := naming.NewProvider(naming.WithLookup(ansProtocol, ans), naming.WithWellKnownLookup(wellKnown))

			fetcher := &fakeFetcher{
				signatures: []*signv1.Signature{signedBy(t, certified)},
				publicKeys: []string{base64.StdEncoding.EncodeToString(keyedKey.Key)},
			}
			db := &fakeDB{records: []coretypes.Record{&fakeRecord{cid: taskTestCID, name: tc.record}}}

			task := newTestTask(t, Config{Enabled: true}, db, fetcher, provider)
			require.NoError(t, task.Run(t.Context()))

			require.Len(t, db.created, 1)
			assert.Equal(t, gormdb.VerificationStatusVerified, db.created[0].GetStatus())
			assert.Equal(t, tc.wantKeyID, db.created[0].GetKeyID())
			assert.Equal(t, 1, fetcher.sigCalls)
			assert.Equal(t, 1, fetcher.keyCalls)
			assert.Equal(t, 1, ans.calls+wellKnown.calls, "exactly one Verify per record")
		})
	}
}

func TestTask_Run_ANSCopiedCertificateIsNotVerified(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}}
	fetcher := &fakeFetcher{signatures: []*signv1.Signature{{Signature: randomSignature(t), Certificate: encodeCert(victim.cert)}}}
	db := &fakeDB{records: ansRecords()}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(lookup))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)

	row := db.created[0]
	assert.Equal(t, gormdb.VerificationStatusFailed, row.GetStatus())
	assert.Equal(t, string(naming.MethodANS), row.GetMethod())
	assert.Equal(t, "no signing keys attached to record", row.GetError())
	assert.Nil(t, row.GetNextAttemptAt())
	assert.Equal(t, 0, lookup.calls, "an unbound certificate never reaches the method")
}

func TestTask_Run_ANSOneLookupForManySigners(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	other := newTestIdentity(t, "")
	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}}
	fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, other), signedBy(t, victim)}}
	db := &fakeDB{records: ansRecords()}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(lookup))
	require.NoError(t, task.Run(t.Context()))

	assert.Equal(t, 1, lookup.calls)
	assert.Equal(t, [][]byte{other.cert.Raw, victim.cert.Raw}, lookup.evidence.Certificates, "certificates are offered in signature order")
	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusVerified, db.created[0].GetStatus())
}

func TestTask_Run_UnsupportedProtocolIsSkippedWithoutWrites(t *testing.T) {
	fetcher := &fakeFetcher{}
	db := &fakeDB{records: ansRecords()}
	provider := naming.NewProvider(naming.WithWellKnownLookup(&fakeKeyLookup{}))

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, provider)
	require.NoError(t, task.Run(t.Context()))

	assert.Equal(t, 0, db.writes())
	assert.Equal(t, 0, fetcher.sigCalls)
	assert.Equal(t, 0, fetcher.keyCalls)
}

func TestTask_Run_UnparsableNameIsTerminal(t *testing.T) {
	db := &fakeDB{records: []coretypes.Record{&fakeRecord{cid: taskTestCID, name: "ans://agent.example.com/no-version"}}}
	fetcher := &fakeFetcher{}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(&fakeLookup{}))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusFailed, db.created[0].GetStatus())
	assert.Equal(t, string(naming.MethodNone), db.created[0].GetMethod())
	assert.Equal(t, "could not parse record name", db.created[0].GetError())
	assert.Equal(t, 0, fetcher.sigCalls+fetcher.keyCalls)
}

// A registry that cannot be read says nothing about the record: the row is
// pending with a fixed message, retried on the next run, and the cause stays
// in the log.
func TestTask_Run_FetcherErrorIsTransientWithFixedText(t *testing.T) {
	registryErr := errors.New("registry unavailable: dial tcp 10.0.0.1:5000")

	tests := []struct {
		name    string
		fetcher *fakeFetcher
	}{
		{name: "signatures cannot be pulled", fetcher: &fakeFetcher{sigErr: registryErr}},
		{name: "public keys cannot be pulled", fetcher: &fakeFetcher{keyErr: registryErr}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &fakeLookup{}
			db := &fakeDB{records: ansRecords()}

			task := newTestTask(t, Config{Enabled: true, Interval: taskTestInterval}, db, tc.fetcher, ansProvider(lookup))
			require.NoError(t, task.Run(t.Context()))

			require.Len(t, db.created, 1)

			row := db.created[0]
			assert.Equal(t, gormdb.VerificationStatusPending, row.GetStatus())
			assert.Equal(t, string(naming.MethodANS), row.GetMethod())
			assert.Equal(t, "transient: "+unreadableSignaturesMessage, row.GetError())
			assert.NotContains(t, row.GetError(), "10.0.0.1")
			assert.Equal(t, 1, row.GetConsecutiveFailures())
			assert.Equal(t, at(taskTestInterval/2), row.GetNextAttemptAt())
			assert.Equal(t, 0, lookup.calls)
		})
	}
}

// --- jwks lane ---

func TestTask_Run_HTTPSUsesPublicKeys(t *testing.T) {
	pemIdentity := newTestIdentity(t, "")
	derIdentity := newTestIdentity(t, "")

	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(pemIdentity.key.Public())
	require.NoError(t, err)

	derKey := mustMarshalKey(t, derIdentity.key.Public())

	wellKnown := &fakeKeyLookup{keys: []naming.PublicKey{{ID: "kid-der", Type: "ecdsa-p256", Key: derKey}}}
	fetcher := &fakeFetcher{publicKeys: []string{string(pemKey), base64.StdEncoding.EncodeToString(derKey), "not a key", ""}}
	db := &fakeDB{records: []coretypes.Record{&fakeRecord{cid: taskTestCID, name: taskTestHTTPS}}}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, naming.NewProvider(naming.WithWellKnownLookup(wellKnown)))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)

	row := db.created[0]
	assert.Equal(t, gormdb.VerificationStatusVerified, row.GetStatus())
	assert.Equal(t, string(naming.MethodWellKnown), row.GetMethod())
	assert.Equal(t, "kid-der", row.GetKeyID(), "the base64 DER key must be decoded and matched")
	assert.Empty(t, row.GetDetails())

	assert.Equal(t, 1, wellKnown.calls)
	assert.Equal(t, "example.com", wellKnown.domain)
	assert.Equal(t, "https", wellKnown.scheme)
	assert.Equal(t, 1, fetcher.keyCalls)
	assert.Equal(t, 1, fetcher.sigCalls)
}

func TestTask_Run_HTTPSWithoutPublicKeysIsTerminal(t *testing.T) {
	wellKnown := &fakeKeyLookup{}
	db := &fakeDB{records: []coretypes.Record{&fakeRecord{cid: taskTestCID, name: taskTestHTTPS}}}

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{}, naming.NewProvider(naming.WithWellKnownLookup(wellKnown)))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusFailed, db.created[0].GetStatus())
	assert.Equal(t, string(naming.MethodWellKnown), db.created[0].GetMethod())
	assert.Equal(t, "no signing keys attached to record", db.created[0].GetError())
	assert.Equal(t, 0, wellKnown.calls)
}

func TestPublicKeyDER(t *testing.T) {
	id := newTestIdentity(t, "")
	der := mustMarshalKey(t, id.key.Public())

	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(id.key.Public())
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     string
		want    []byte
		wantErr bool
	}{
		{name: "pem", key: string(pemKey), want: der},
		{name: "base64 der", key: base64.StdEncoding.EncodeToString(der), want: der},
		{name: "base64 that is not a public key", key: base64.StdEncoding.EncodeToString([]byte("not a key")), wantErr: true},
		{name: "empty", key: "", wantErr: true},
		{name: "neither", key: "not a key!", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicKeyDER(tc.key)

			if tc.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// --- state machine ---

func TestTransition(t *testing.T) {
	p := policy{ttl: taskTestTTL, interval: taskTestInterval}
	retryAfter := retryAfterResult(errLookupDown.Error(), fixedNow.Add(10*time.Minute))

	verified := &gormdb.NameVerification{
		RecordCID: taskTestCID, Method: string(naming.MethodANS), KeyID: victimKeyID,
		Status: gormdb.VerificationStatusVerified, Details: taskTestDetails, VerifiedAt: &fixedNow,
	}
	revoked := &gormdb.NameVerification{
		RecordCID: taskTestCID, Method: string(naming.MethodANS),
		Status: gormdb.VerificationStatusFailed, Error: errAgentRevoke.Error(),
	}
	unavailable := &gormdb.NameVerification{
		RecordCID: taskTestCID, Method: string(naming.MethodANS),
		Status: gormdb.VerificationStatusFailed, Error: "verification unavailable for 24h; last: ans dns: lookup timed out",
	}

	pending := func(failures int, next *time.Time) *gormdb.NameVerification {
		return &gormdb.NameVerification{
			RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusPending,
			Error: "transient: ans dns: lookup timed out", ConsecutiveFailures: failures, NextAttemptAt: next,
		}
	}
	demoted := func(failures int, next *time.Time) *gormdb.NameVerification {
		row := pending(failures, next)
		row.KeyID = victimKeyID
		row.Details = taskTestDetails
		row.VerifiedAt = &existingVerifiedAt

		return row
	}
	keptVerified := func(errMsg string, failures int, next *time.Time) *gormdb.NameVerification {
		row := demoted(failures, next)
		row.Status = gormdb.VerificationStatusVerified
		row.Error = errMsg

		return row
	}

	tests := []struct {
		name     string
		existing *gormdb.NameVerification
		result   *naming.Result
		want     *gormdb.NameVerification
		wantKind outcomeKind
	}{
		{
			name:     "verified result with no row",
			result:   verifiedResult(),
			want:     verified,
			wantKind: outcomeVerified,
		},
		{
			name:     "verified result on a pending row resets the schedule",
			existing: existingRow(gormdb.VerificationStatusPending, 5),
			result:   verifiedResult(),
			want:     verified,
			wantKind: outcomeVerified,
		},
		{
			name:     "terminal failure on a verified row clears the verdict columns",
			existing: existingRow(gormdb.VerificationStatusVerified, 2),
			result:   terminalResult(errAgentRevoke.Error()),
			want:     revoked,
			wantKind: outcomeFailed,
		},
		{
			name:     "terminal failure without text gets the generic message",
			result:   terminalResult(""),
			want:     &gormdb.NameVerification{RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusFailed, Error: "verification failed"},
			wantKind: outcomeFailed,
		},
		{
			name:     "transient with no row creates a pending row due on the next run",
			result:   transientResult(dnsTimeoutText),
			want:     pending(1, at(taskTestInterval/2)),
			wantKind: outcomeTransient,
		},
		{
			name:     "third strike on a pending row lands two intervals out",
			existing: existingRow(gormdb.VerificationStatusPending, 2),
			result:   transientResult(dnsTimeoutText),
			want:     pending(3, at(2*taskTestInterval)),
			wantKind: outcomeTransient,
		},
		{
			name:     "backoff is capped at a day",
			existing: existingRow(gormdb.VerificationStatusPending, 6),
			result:   transientResult(dnsTimeoutText),
			want:     pending(7, at(maxRetryDelay)),
			wantKind: outcomeTransient,
		},
		{
			name:     "transient on a verified row before its ttl keeps it verified",
			existing: existingRow(gormdb.VerificationStatusVerified, 0),
			result:   transientResult(dnsTimeoutText),
			want:     keptVerified("transient: ans dns: lookup timed out", 1, at(taskTestInterval/2)),
			wantKind: outcomeTransient,
		},
		{
			name:     "transient on a verified row past its ttl makes it pending and keeps what it verified",
			existing: pendingSinceRow(0, true, 0),
			result:   transientResult(dnsTimeoutText),
			want: func() *gormdb.NameVerification {
				row := demoted(1, at(taskTestInterval/2))
				expired := fixedNow.Add(-taskTestTTL)
				row.VerifiedAt = &expired

				return row
			}(),
			wantKind: outcomeTransient,
		},
		{
			name: "transient on a verified row without a verification time makes it pending",
			existing: func() *gormdb.NameVerification {
				row := existingRow(gormdb.VerificationStatusVerified, 0)
				row.VerifiedAt = nil

				return row
			}(),
			result: transientResult(dnsTimeoutText),
			want: func() *gormdb.NameVerification {
				row := demoted(1, at(taskTestInterval/2))
				row.VerifiedAt = nil

				return row
			}(),
			wantKind: outcomeTransient,
		},
		{
			name:     "transient on a failed row keeps failed and its own error",
			existing: existingRow(gormdb.VerificationStatusFailed, 0),
			result:   transientResult(dnsTimeoutText),
			want: &gormdb.NameVerification{
				RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusFailed,
				Error: errAgentRevoke.Error(), ConsecutiveFailures: 1, NextAttemptAt: at(taskTestInterval / 2),
			},
			wantKind: outcomeTransient,
		},
		{
			name:     "retry-after on a pending row sets the schedule without a strike",
			existing: existingRow(gormdb.VerificationStatusPending, 3),
			result:   retryAfter,
			want: &gormdb.NameVerification{
				RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusPending,
				Error: "transient: transport down", ConsecutiveFailures: 3, NextAttemptAt: at(10 * time.Minute),
			},
			wantKind: outcomeTransient,
		},
		{
			name:     "retry-after on a verified row keeps the verdict without a strike",
			existing: existingRow(gormdb.VerificationStatusVerified, 0),
			result:   retryAfter,
			want:     keptVerified("transient: transport down", 0, at(10*time.Minute)),
			wantKind: outcomeTransient,
		},
		{
			name:   "retry-after with no row creates a pending row without a strike",
			result: retryAfter,
			want: &gormdb.NameVerification{
				RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusPending,
				Error: "transient: transport down", NextAttemptAt: at(10 * time.Minute),
			},
			wantKind: outcomeTransient,
		},
		{
			name:     "row pending for a day becomes failed until a daily retry",
			existing: pendingSinceRow(-pendingBudget, false, 6),
			result:   transientResult(dnsTimeoutText),
			want: func() *gormdb.NameVerification {
				row := *unavailable
				row.ConsecutiveFailures = 7
				row.NextAttemptAt = at(maxRetryDelay)

				return &row
			}(),
			wantKind: outcomeFailed,
		},
		{
			name:     "row pending for less than a day stays pending",
			existing: pendingSinceRow(-pendingBudget+time.Hour, false, 6),
			result:   transientResult(dnsTimeoutText),
			want:     pending(7, at(maxRetryDelay)),
			wantKind: outcomeTransient,
		},
		{
			name:     "row demoted from verified is pending for a day after its ttl before failing",
			existing: pendingSinceRow(-pendingBudget, true, 2),
			result:   transientResult(dnsTimeoutText),
			want: func() *gormdb.NameVerification {
				row := *unavailable
				row.ConsecutiveFailures = 3
				row.NextAttemptAt = at(maxRetryDelay)

				return &row
			}(),
			wantKind: outcomeFailed,
		},
		{
			name:     "row demoted from verified stays pending within a day of its ttl however old the row",
			existing: pendingSinceRow(-pendingBudget+time.Hour, true, 2),
			result:   transientResult(dnsTimeoutText),
			want: func() *gormdb.NameVerification {
				row := demoted(3, at(2*taskTestInterval))
				verifiedAt := fixedNow.Add(-pendingBudget + time.Hour - taskTestTTL)
				row.VerifiedAt = &verifiedAt

				return row
			}(),
			wantKind: outcomeTransient,
		},
		{
			name:     "retry-after does not extend the pending budget",
			existing: pendingSinceRow(-pendingBudget-6*time.Hour, false, 4),
			result:   retryAfter,
			want: &gormdb.NameVerification{
				RecordCID: taskTestCID, Method: string(naming.MethodANS), Status: gormdb.VerificationStatusFailed,
				Error: "verification unavailable for 24h; last: transport down", ConsecutiveFailures: 4, NextAttemptAt: at(maxRetryDelay),
			},
			wantKind: outcomeFailed,
		},
		{
			name: "row with an unknown status is treated as pending",
			existing: func() *gormdb.NameVerification {
				row := existingRow(gormdb.VerificationStatusPending, 0)
				row.Status = "weird"

				return row
			}(),
			result:   transientResult(dnsTimeoutText),
			want:     pending(1, at(taskTestInterval/2)),
			wantKind: outcomeTransient,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var existing types.NameVerificationObject
			if tc.existing != nil {
				existing = tc.existing
			}

			got := transition(taskTestCID, existing, tc.result, fixedNow, p)

			assert.Equal(t, tc.wantKind, got.kind)
			assert.Equal(t, tc.want, got.row)
		})
	}
}

// A verified row's retry never lands after its TTL, so the first run past the
// TTL demotes it instead of leaving it served for the rest of a long backoff.
func TestTransitionSchedulesVerifiedRowNoLaterThanTTL(t *testing.T) {
	p := policy{ttl: taskTestTTL, interval: taskTestInterval}
	verifiedAt := fixedNow.Add(time.Hour - taskTestTTL)

	tests := []struct {
		name   string
		result *naming.Result
	}{
		{name: "doubling backoff", result: transientResult(dnsTimeoutText)},
		{name: "retry-after from the breaker", result: retryAfterResult(errLookupDown.Error(), fixedNow.Add(2*time.Hour))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := existingRow(gormdb.VerificationStatusVerified, 6)
			existing.VerifiedAt = &verifiedAt

			got := transition(taskTestCID, existing, tt.result, fixedNow, p)

			assert.Equal(t, outcomeTransient, got.kind)
			assert.Equal(t, gormdb.VerificationStatusVerified, got.row.Status)
			require.NotNil(t, got.row.NextAttemptAt)
			assert.Equal(t, fixedNow.Add(time.Hour), *got.row.NextAttemptAt)
		})
	}
}

// Run loads the row once, calls Verify once and writes the transition once:
// a create when there is no row, an update otherwise.
func TestTask_Run_WritesTheTransitionOnce(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)

	tests := []struct {
		name       string
		existing   *gormdb.NameVerification
		lookupErr  error
		wantCreate bool
		wantStatus string
	}{
		{name: "transient with no row is created pending", lookupErr: errDNSTimeout, wantCreate: true, wantStatus: gormdb.VerificationStatusPending},
		{name: "transient on a verified row is updated in place", existing: existingRow(gormdb.VerificationStatusVerified, 0), lookupErr: errDNSTimeout, wantStatus: gormdb.VerificationStatusVerified},
		{name: "verified result on a pending row is updated", existing: existingRow(gormdb.VerificationStatusPending, 5), wantStatus: gormdb.VerificationStatusVerified},
		{name: "terminal result with no row is created failed", lookupErr: errAgentRevoke, wantCreate: true, wantStatus: gormdb.VerificationStatusFailed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &fakeLookup{err: tc.lookupErr, details: json.RawMessage(taskTestDetails)}
			if tc.lookupErr == nil {
				lookup.keys = []naming.PublicKey{publishedKey(t, victim)}
			}

			db := &fakeDB{records: ansRecords(), existing: tc.existing}
			fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}

			task := newTestTask(t, Config{Enabled: true, Interval: taskTestInterval}, db, fetcher, ansProvider(lookup))
			require.NoError(t, task.Run(t.Context()))

			require.Equal(t, 1, db.writes(), "exactly one write per record")
			assert.Equal(t, 1, lookup.calls, "exactly one Verify per record")
			assert.Equal(t, 1, fetcher.sigCalls)

			rows := db.updated
			if tc.wantCreate {
				rows = db.created
			}

			require.Len(t, rows, 1)
			assert.Equal(t, taskTestCID, rows[0].GetRecordCID())
			assert.Equal(t, tc.wantStatus, rows[0].GetStatus())
		})
	}
}

func TestTask_VerifyRecord_PersistFailures(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	writeErr := errors.New("disk full")

	tests := []struct {
		name string
		db   *fakeDB
	}{
		{name: "row cannot be loaded", db: &fakeDB{getErr: errors.New("db down")}},
		{name: "row cannot be created", db: &fakeDB{createErr: writeErr}},
		{name: "row cannot be updated", db: &fakeDB{existing: existingRow(gormdb.VerificationStatusPending, 1), updateErr: writeErr}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}}
			fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}

			task := newTestTask(t, Config{Enabled: true}, tc.db, fetcher, ansProvider(lookup))

			got := task.verifyRecord(t.Context(), taskTestCID, taskTestANSName)

			assert.Equal(t, outcomePersistFailed, got.kind)
			assert.Equal(t, string(naming.MethodANS), got.method)
			assert.Equal(t, 1, lookup.calls)
		})
	}
}

func TestTask_Run_StopsBeforeEachRecordOnceCanceled(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}}
	fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}
	db := &fakeDB{records: []coretypes.Record{
		&fakeRecord{cid: taskTestCID, name: taskTestANSName},
		&fakeRecord{cid: taskTestOtherCID, name: taskTestANSName},
	}}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(lookup))

	err := task.Run(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "stopped after 0 of 2 records")
	assert.Equal(t, 0, db.writes())
	assert.Equal(t, 0, lookup.calls)
	assert.Equal(t, 0, fetcher.sigCalls)
}

// A failure observed after the run was canceled may be the cancellation's own
// doing, so nothing is written for it and the batch stops.
func TestTask_Run_CancellationDuringARecordWritesNothing(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	lookup := &fakeLookup{err: errDNSTimeout, onLookup: cancel}
	fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}
	db := &fakeDB{records: []coretypes.Record{
		&fakeRecord{cid: taskTestCID, name: taskTestANSName},
		&fakeRecord{cid: taskTestOtherCID, name: taskTestANSName},
	}}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(lookup))

	err := task.Run(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "stopped after 1 of 2 records")
	assert.Equal(t, 0, db.writes())
	assert.Equal(t, 1, lookup.calls)
}

// A run canceled while the record's signatures are being read reports the
// interruption, not the record.
func TestTask_VerifyRecord_CancellationWhileCollectingSignersWritesNothing(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	db := &fakeDB{}
	lookup := &fakeLookup{}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}, ansProvider(lookup))

	got := task.verifyRecord(ctx, taskTestCID, taskTestANSName)

	assert.Equal(t, outcomeAborted, got.kind)
	assert.Equal(t, 0, db.writes())
	assert.Equal(t, 0, lookup.calls)
}

func TestTask_VerifyRecord_SuccessAfterCancellationIsStored(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}, onLookup: cancel}
	db := &fakeDB{}

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}, ansProvider(lookup))

	got := task.verifyRecord(ctx, taskTestCID, taskTestANSName)

	assert.Equal(t, outcomeVerified, got.kind)
	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusVerified, db.created[0].GetStatus())
}

func TestRunSummary(t *testing.T) {
	summary := newRunSummary()

	summary.add(outcome{kind: outcomeVerified, method: "ans"})
	summary.add(outcome{kind: outcomeVerified, method: "wellknown"})
	summary.add(outcome{kind: outcomeFailed, method: "ans"})
	summary.add(outcome{kind: outcomeTransient, method: "ans"})
	summary.add(outcome{kind: outcomeSkipped, protocol: ansProtocol})
	summary.add(outcome{kind: outcomeSkipped, protocol: ansProtocol})
	summary.add(outcome{kind: outcomeAborted, method: "ans"})
	summary.add(outcome{kind: outcomePersistFailed, method: "ans"})

	assert.Equal(t, 2, summary.verified)
	assert.Equal(t, 1, summary.failed)
	assert.Equal(t, 1, summary.transient)
	assert.Equal(t, 2, summary.skipped)
	assert.Equal(t, 1, summary.aborted)
	assert.Equal(t, 1, summary.persistFailed)
	assert.Equal(t, map[string]int{"ans": 1, "wellknown": 1}, summary.verifiedByMethod)
	assert.Equal(t, map[string]int{"ans": 1}, summary.failedByMethod)
	assert.Equal(t, map[string]int{ansProtocol: 2}, summary.skippedByProtocol)

	summary.log(time.Second)
}

// The record's signed payload is exactly the CID string: the reconciler's
// binding check must accept what the client produces for it.
func TestCertificateSigners_MatchesClientPayloadShape(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	sig := signedBy(t, victim)

	raw, err := base64.StdEncoding.DecodeString(sig.GetSignature())
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	signers, err := certificateSigners(t.Context(), taskTestCID, []*signv1.Signature{sig})
	require.NoError(t, err)
	require.Len(t, signers, 1)

	parsed, err := x509.ParsePKIXPublicKey(signers[0].Key)
	require.NoError(t, err)
	assert.Equal(t, victim.key.Public(), parsed)
}

func TestFailedRow_DefaultMessage(t *testing.T) {
	row := failedRow(taskTestCID, string(naming.MethodANS), "")

	assert.Equal(t, gormdb.VerificationStatusFailed, row.Status)
	assert.Equal(t, "verification failed", row.Error)
}
