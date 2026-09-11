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
	taskTestCID     = signersTestCID
	taskTestANSName = "ans://v1.0.0.agent.example.com/assistant"
	taskTestHTTPS   = "https://example.com/agent"
	taskTestDetails = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentId":"agent-1"}`
	victimKeyID     = "SHA256:victim"
)

var (
	fixedNow       = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	errLookupDown  = errors.New("transport down")
	errAgentRevoke = errors.New("ans status-token: agent revoked")
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

type scheduleCall struct {
	cid           string
	status        string
	failures      int
	nextAttemptAt *time.Time
	errMsg        string
}

type fakeDB struct {
	types.DatabaseAPI

	records    []coretypes.Record
	recordsErr error
	existing   *gormdb.NameVerification
	getErr     error

	createErr   error
	updateErr   error
	scheduleErr error

	created   []types.NameVerificationObject
	updated   []types.NameVerificationObject
	scheduled []scheduleCall
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

func (f *fakeDB) UpdateNameVerificationSchedule(cid string, status string, failures int, nextAttemptAt *time.Time, errMsg string) error {
	f.scheduled = append(f.scheduled, scheduleCall{cid: cid, status: status, failures: failures, nextAttemptAt: nextAttemptAt, errMsg: errMsg})

	return f.scheduleErr
}

func (f *fakeDB) writes() int {
	return len(f.created) + len(f.updated) + len(f.scheduled)
}

// fakeLookup is the ans:// method: it records the evidence it was given and
// answers with configured keys or an error.
type fakeLookup struct {
	keys    []naming.PublicKey
	details json.RawMessage
	err     error

	calls    int
	evidence naming.Evidence
	name     *naming.ParsedName
}

func (l *fakeLookup) Method() naming.VerificationMethod { return naming.MethodANS }

func (l *fakeLookup) LookupKeys(_ context.Context, name *naming.ParsedName, evidence naming.Evidence) (*naming.LookupResult, error) {
	l.calls++
	l.evidence = evidence
	l.name = name

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
	return naming.NewProvider(naming.WithLookup(naming.ANSProtocol, lookup))
}

func publishedKey(t *testing.T, id testIdentity) naming.PublicKey {
	t.Helper()

	return naming.PublicKey{ID: victimKeyID, Type: "ecdsa-p256", Key: mustMarshalKey(t, &id.key.PublicKey)}
}

func ansRecords() []coretypes.Record {
	return []coretypes.Record{&fakeRecord{cid: taskTestCID, name: taskTestANSName}}
}

func at(offset time.Duration) *time.Time {
	when := fixedNow.Add(offset)

	return &when
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
	assert.Empty(t, db.scheduled)

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
	assert.Equal(t, 0, fetcher.keyCalls, "the ans lane never consults public-key referrers")
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
	assert.Equal(t, "no certificate attached to the record's signatures; sign with --certificate", row.GetError())
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
	assert.Equal(t, [][]byte{victim.cert.Raw, other.cert.Raw}, lookup.evidence.Certificates, "the certificate naming the host is offered first")
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
	assert.Equal(t, "could not parse record name", db.created[0].GetError())
	assert.Equal(t, 0, fetcher.sigCalls+fetcher.keyCalls)
}

func TestTask_Run_FetcherErrorIsTerminal(t *testing.T) {
	db := &fakeDB{records: ansRecords()}
	fetcher := &fakeFetcher{sigErr: errors.New("registry unavailable")}

	task := newTestTask(t, Config{Enabled: true}, db, fetcher, ansProvider(&fakeLookup{}))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusFailed, db.created[0].GetStatus())
	assert.Equal(t, string(naming.MethodANS), db.created[0].GetMethod())
	assert.Equal(t, "signers: pull signatures: registry unavailable", db.created[0].GetError())
}

func TestTask_Run_DatabaseReadErrorSkipsWrite(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	lookup := &fakeLookup{keys: []naming.PublicKey{publishedKey(t, victim)}}
	db := &fakeDB{records: ansRecords(), getErr: errors.New("db down")}

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}, ansProvider(lookup))
	require.NoError(t, task.Run(t.Context()))

	assert.Equal(t, 0, db.writes())
}

// --- jwks lane ---

func TestTask_Run_HTTPSUsesPublicKeys(t *testing.T) {
	pemIdentity := newTestIdentity(t, "")
	derIdentity := newTestIdentity(t, "")

	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(&pemIdentity.key.PublicKey)
	require.NoError(t, err)

	derKey := mustMarshalKey(t, &derIdentity.key.PublicKey)

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
	assert.Equal(t, 0, fetcher.sigCalls, "the jwks lane never pulls signatures")
}

func TestTask_Run_HTTPSWithoutPublicKeysIsTerminal(t *testing.T) {
	wellKnown := &fakeKeyLookup{}
	db := &fakeDB{records: []coretypes.Record{&fakeRecord{cid: taskTestCID, name: taskTestHTTPS}}}

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{}, naming.NewProvider(naming.WithWellKnownLookup(wellKnown)))
	require.NoError(t, task.Run(t.Context()))

	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusFailed, db.created[0].GetStatus())
	assert.Equal(t, string(naming.MethodWellKnown), db.created[0].GetMethod())
	assert.Equal(t, "no public keys found for record", db.created[0].GetError())
	assert.Equal(t, 0, wellKnown.calls)
}

func TestPublicKeyDER(t *testing.T) {
	id := newTestIdentity(t, "")
	der := mustMarshalKey(t, &id.key.PublicKey)

	pemKey, err := cryptoutils.MarshalPublicKeyToPEM(&id.key.PublicKey)
	require.NoError(t, err)

	tests := []struct {
		name    string
		key     string
		want    []byte
		wantErr bool
	}{
		{name: "pem", key: string(pemKey), want: der},
		{name: "base64 der", key: base64.StdEncoding.EncodeToString(der), want: der},
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

// --- persistence state machine ---

type writeKind int

const (
	writeCreate writeKind = iota
	writeUpdate
	writeSchedule
)

func existingRow(status string, failures int) *gormdb.NameVerification {
	verifiedAt := fixedNow.Add(-2 * time.Hour)

	row := &gormdb.NameVerification{
		RecordCID:           taskTestCID,
		Method:              string(naming.MethodANS),
		Status:              status,
		ConsecutiveFailures: failures,
		UpdatedAt:           fixedNow.Add(-time.Hour),
	}

	switch status {
	case gormdb.VerificationStatusVerified:
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

func TestTask_Run_PersistenceStateMachine(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	transientErr := errors.Join(errors.New("ans dns: lookup timed out"), naming.ErrTransient)

	tests := []struct {
		name          string
		interval      time.Duration
		existing      *gormdb.NameVerification
		lookupErr     error
		lookupDetails json.RawMessage

		want            writeKind
		wantStatus      string
		wantFailures    int
		wantNext        *time.Time
		wantErrContains string
		wantErrEquals   string
		wantKeyID       string
		wantVerifiedAt  *time.Time
		wantDetails     string
	}{
		{
			name:            "transient with no row creates a pending row scheduled after one interval",
			interval:        time.Hour,
			lookupErr:       transientErr,
			want:            writeCreate,
			wantStatus:      gormdb.VerificationStatusPending,
			wantFailures:    1,
			wantNext:        at(time.Hour),
			wantErrContains: "transient: ans dns: lookup timed out",
		},
		{
			name:            "transient on a verified row only reschedules and keeps the verdict",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusVerified, 0),
			lookupErr:       transientErr,
			want:            writeSchedule,
			wantStatus:      gormdb.VerificationStatusVerified,
			wantFailures:    1,
			wantNext:        at(time.Hour),
			wantErrContains: "transient: ans dns: lookup timed out",
		},
		{
			name:            "third strike doubles twice",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusPending, 2),
			lookupErr:       transientErr,
			want:            writeSchedule,
			wantStatus:      gormdb.VerificationStatusPending,
			wantFailures:    3,
			wantNext:        at(4 * time.Hour),
			wantErrContains: "transient: ans dns",
		},
		{
			name:            "backoff is capped at a day",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusPending, 6),
			lookupErr:       transientErr,
			want:            writeSchedule,
			wantStatus:      gormdb.VerificationStatusPending,
			wantFailures:    7,
			wantNext:        at(24 * time.Hour),
			wantErrContains: "transient: ans dns",
		},
		{
			name:            "eighth strike becomes a failed verdict retried daily",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusPending, 7),
			lookupErr:       transientErr,
			want:            writeUpdate,
			wantStatus:      gormdb.VerificationStatusFailed,
			wantFailures:    8,
			wantNext:        at(24 * time.Hour),
			wantErrContains: "verification unavailable after 8 consecutive transient failures; last: ans dns: lookup timed out",
		},
		{
			name:            "later strikes on an unavailable row renew the daily verdict",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusFailed, 8),
			lookupErr:       transientErr,
			want:            writeUpdate,
			wantStatus:      gormdb.VerificationStatusFailed,
			wantFailures:    9,
			wantNext:        at(24 * time.Hour),
			wantErrContains: "verification unavailable after 8 consecutive transient failures",
		},
		{
			name:            "retry-after from the method sets the schedule without counting a strike",
			interval:        time.Hour,
			existing:        existingRow(gormdb.VerificationStatusPending, 3),
			lookupErr:       &naming.RetryAfterError{Until: fixedNow.Add(10 * time.Minute), Err: errLookupDown},
			want:            writeSchedule,
			wantStatus:      gormdb.VerificationStatusPending,
			wantFailures:    3,
			wantNext:        at(10 * time.Minute),
			wantErrContains: "transient: transport down",
		},
		{
			name:            "retry-after with no row creates a pending row without a strike",
			interval:        time.Hour,
			lookupErr:       &naming.RetryAfterError{Until: fixedNow.Add(10 * time.Minute), Err: errLookupDown},
			want:            writeCreate,
			wantStatus:      gormdb.VerificationStatusPending,
			wantFailures:    0,
			wantNext:        at(10 * time.Minute),
			wantErrContains: "transient: transport down",
		},
		{
			name:          "transient on a failed row keeps failed and its own error",
			interval:      time.Hour,
			existing:      existingRow(gormdb.VerificationStatusFailed, 0),
			lookupErr:     transientErr,
			want:          writeSchedule,
			wantStatus:    gormdb.VerificationStatusFailed,
			wantFailures:  1,
			wantNext:      at(time.Hour),
			wantErrEquals: errAgentRevoke.Error(),
		},
		{
			name:          "terminal after transient strikes clears the schedule",
			interval:      time.Hour,
			existing:      existingRow(gormdb.VerificationStatusPending, 3),
			lookupErr:     errAgentRevoke,
			want:          writeUpdate,
			wantStatus:    gormdb.VerificationStatusFailed,
			wantFailures:  0,
			wantErrEquals: errAgentRevoke.Error(),
		},
		{
			name:           "success after transient strikes resets the counters",
			interval:       time.Hour,
			existing:       existingRow(gormdb.VerificationStatusPending, 5),
			lookupDetails:  json.RawMessage(taskTestDetails),
			want:           writeUpdate,
			wantStatus:     gormdb.VerificationStatusVerified,
			wantFailures:   0,
			wantKeyID:      victimKeyID,
			wantVerifiedAt: &fixedNow,
			wantDetails:    taskTestDetails,
		},
		{
			name:           "success without details stores an empty string, not null",
			interval:       time.Hour,
			want:           writeCreate,
			wantStatus:     gormdb.VerificationStatusVerified,
			wantKeyID:      victimKeyID,
			wantVerifiedAt: &fixedNow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &fakeLookup{err: tc.lookupErr, details: tc.lookupDetails}
			if tc.lookupErr == nil {
				lookup.keys = []naming.PublicKey{publishedKey(t, victim)}
			}

			db := &fakeDB{records: ansRecords(), existing: tc.existing}
			fetcher := &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}

			task := newTestTask(t, Config{Enabled: true, Interval: tc.interval}, db, fetcher, ansProvider(lookup))
			require.NoError(t, task.Run(t.Context()))

			require.Equal(t, 1, db.writes(), "exactly one write per record")

			switch tc.want {
			case writeCreate, writeUpdate:
				rows := db.created
				if tc.want == writeUpdate {
					rows = db.updated
				}

				require.Len(t, rows, 1)

				row := rows[0]
				assert.Equal(t, taskTestCID, row.GetRecordCID())
				assert.Equal(t, string(naming.MethodANS), row.GetMethod())
				assert.Equal(t, tc.wantStatus, row.GetStatus())
				assert.Equal(t, tc.wantFailures, row.GetConsecutiveFailures())
				assert.Equal(t, tc.wantNext, row.GetNextAttemptAt())
				assert.Equal(t, tc.wantKeyID, row.GetKeyID())
				assert.Equal(t, tc.wantDetails, row.GetDetails())
				assert.Equal(t, tc.wantVerifiedAt, row.GetVerifiedAt())

				if tc.wantErrEquals != "" {
					assert.Equal(t, tc.wantErrEquals, row.GetError())
				}

				if tc.wantErrContains != "" {
					assert.Contains(t, row.GetError(), tc.wantErrContains)
				}
			case writeSchedule:
				require.Len(t, db.scheduled, 1)

				call := db.scheduled[0]
				assert.Equal(t, taskTestCID, call.cid)
				assert.Equal(t, tc.wantStatus, call.status)
				assert.Equal(t, tc.wantFailures, call.failures)
				assert.Equal(t, tc.wantNext, call.nextAttemptAt)

				if tc.wantErrEquals != "" {
					assert.Equal(t, tc.wantErrEquals, call.errMsg)
				}

				if tc.wantErrContains != "" {
					assert.Contains(t, call.errMsg, tc.wantErrContains)
				}
			}
		})
	}
}

func TestScheduleStatus(t *testing.T) {
	tests := []struct {
		name       string
		existing   *gormdb.NameVerification
		wantStatus string
		wantErr    string
	}{
		{name: "verified stays verified with the transient error", existing: existingRow(gormdb.VerificationStatusVerified, 0), wantStatus: gormdb.VerificationStatusVerified, wantErr: "transient: now"},
		{name: "failed stays failed with its own error", existing: existingRow(gormdb.VerificationStatusFailed, 0), wantStatus: gormdb.VerificationStatusFailed, wantErr: errAgentRevoke.Error()},
		{name: "pending stays pending with the transient error", existing: existingRow(gormdb.VerificationStatusPending, 1), wantStatus: gormdb.VerificationStatusPending, wantErr: "transient: now"},
		{name: "unknown status becomes pending", existing: &gormdb.NameVerification{Status: "weird"}, wantStatus: gormdb.VerificationStatusPending, wantErr: "transient: now"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, errMsg := scheduleStatus(tc.existing, "transient: now")
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantErr, errMsg)
		})
	}
}

func TestRunSummary(t *testing.T) {
	summary := newRunSummary()

	summary.add(outcome{kind: outcomeVerified, method: "ans"})
	summary.add(outcome{kind: outcomeVerified, method: "wellknown"})
	summary.add(outcome{kind: outcomeFailed, method: "ans"})
	summary.add(outcome{kind: outcomeTransient, method: "ans"})
	summary.add(outcome{kind: outcomeSkipped, protocol: naming.ANSProtocol})
	summary.add(outcome{kind: outcomeSkipped, protocol: naming.ANSProtocol})

	assert.Equal(t, 2, summary.verified)
	assert.Equal(t, 1, summary.failed)
	assert.Equal(t, 1, summary.transient)
	assert.Equal(t, 2, summary.skipped)
	assert.Equal(t, map[string]int{"ans": 1, "wellknown": 1}, summary.verifiedByMethod)
	assert.Equal(t, map[string]int{"ans": 1}, summary.failedByMethod)
	assert.Equal(t, map[string]int{naming.ANSProtocol: 2}, summary.skippedByProtocol)

	summary.log()
}

// The record's signed payload is exactly the CID string: the reconciler's
// binding check must accept what the client produces for it.
func TestCertificateSigners_MatchesClientPayloadShape(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	sig := signedBy(t, victim)

	raw, err := base64.StdEncoding.DecodeString(sig.GetSignature())
	require.NoError(t, err)
	assert.NotEmpty(t, raw)

	signers, err := certificateSigners(t.Context(), taskTestCID, "agent.example.com", []*signv1.Signature{sig})
	require.NoError(t, err)
	require.Len(t, signers, 1)

	parsed, err := x509.ParsePKIXPublicKey(signers[0].Key)
	require.NoError(t, err)
	assert.Equal(t, &victim.key.PublicKey, parsed)
}

// Write failures are logged and must not abort the run or panic.
func TestTask_Run_WriteFailuresAreTolerated(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	transientErr := errors.Join(errors.New("ans dns: lookup timed out"), naming.ErrTransient)
	writeErr := errors.New("disk full")

	tests := []struct {
		name      string
		existing  *gormdb.NameVerification
		lookupErr error
		db        func() *fakeDB
	}{
		{name: "create verdict fails", db: func() *fakeDB { return &fakeDB{createErr: writeErr} }},
		{name: "update verdict fails", existing: existingRow(gormdb.VerificationStatusPending, 1), db: func() *fakeDB { return &fakeDB{updateErr: writeErr} }},
		{name: "create pending fails", lookupErr: transientErr, db: func() *fakeDB { return &fakeDB{createErr: writeErr} }},
		{name: "schedule write fails", existing: existingRow(gormdb.VerificationStatusVerified, 0), lookupErr: transientErr, db: func() *fakeDB { return &fakeDB{scheduleErr: writeErr} }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lookup := &fakeLookup{err: tc.lookupErr}
			if tc.lookupErr == nil {
				lookup.keys = []naming.PublicKey{publishedKey(t, victim)}
			}

			db := tc.db()
			db.records = ansRecords()
			db.existing = tc.existing

			task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}, ansProvider(lookup))
			require.NoError(t, task.Run(t.Context()))
			assert.Equal(t, 1, db.writes())
		})
	}
}

func TestTask_Run_CanceledContextIsTerminal(t *testing.T) {
	victim := newTestIdentity(t, signersTestSAN)
	db := &fakeDB{records: ansRecords()}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	task := newTestTask(t, Config{Enabled: true}, db, &fakeFetcher{signatures: []*signv1.Signature{signedBy(t, victim)}}, ansProvider(&fakeLookup{}))
	require.NoError(t, task.Run(ctx))

	require.Len(t, db.created, 1)
	assert.Equal(t, gormdb.VerificationStatusFailed, db.created[0].GetStatus())
	assert.Contains(t, db.created[0].GetError(), "signers: certificate signers: context canceled")
}

func TestFailedRow_DefaultMessage(t *testing.T) {
	row := failedRow(taskTestCID, string(naming.MethodANS), "")

	assert.Equal(t, gormdb.VerificationStatusFailed, row.Status)
	assert.Equal(t, "verification failed", row.Error)
}
