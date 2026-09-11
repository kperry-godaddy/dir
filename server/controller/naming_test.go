// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	oasfv1alpha1 "buf.build/gen/go/agntcy/oasf/protocolbuffers/go/agntcy/oasf/types/v1alpha1"
	coretypes "github.com/agntcy/dir/api/core/types"
	corev1 "github.com/agntcy/dir/api/core/v1"
	namingv1 "github.com/agntcy/dir/api/naming/v1"
	gormdb "github.com/agntcy/dir/server/database/gorm"
	"github.com/agntcy/dir/server/naming"
	"github.com/agntcy/dir/server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	namingTestCID     = "baeareitestnaming0000000000000000000000000000000000000000000000"
	namingTestDetails = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentHost":"agent.example.com","agentId":"agent-1",` +
		`"logUrl":"https://log.example.com","receiptUrl":"https://log.example.com/v1/agents/agent-1/receipt",` +
		`"agentStatus":"ACTIVE"}`
)

type fakeNamingDB struct {
	types.DatabaseAPI

	verification types.NameVerificationObject
	err          error
	records      []coretypes.Record
	recordsErr   error
}

func (f *fakeNamingDB) GetVerificationByCID(string) (types.NameVerificationObject, error) {
	return f.verification, f.err
}

func (f *fakeNamingDB) GetRecords(...types.FilterOption) ([]coretypes.Record, error) {
	return f.records, f.recordsErr
}

type fakeNamingStore struct {
	types.StoreAPI

	record *corev1.Record
	err    error
}

func (f *fakeNamingStore) Pull(context.Context, *corev1.RecordRef) (*corev1.Record, error) {
	return f.record, f.err
}

type fakeNamedRecord struct {
	coretypes.Record

	cid, name, version string
}

func (r *fakeNamedRecord) GetCid() string     { return r.cid }
func (r *fakeNamedRecord) GetName() string    { return r.name }
func (r *fakeNamedRecord) GetVersion() string { return r.version }

func newNamingController(db types.DatabaseAPI, store types.StoreAPI, ttl time.Duration) namingv1.NamingServiceServer {
	return NewNamingController(store, db, nil, WithVerificationTTL(ttl))
}

func verifiedRow(method, keyID, details string, verifiedAt *time.Time) *gormdb.NameVerification {
	return &gormdb.NameVerification{
		RecordCID:  namingTestCID,
		Method:     method,
		KeyID:      keyID,
		Status:     gormdb.VerificationStatusVerified,
		Details:    details,
		VerifiedAt: verifiedAt,
		UpdatedAt:  time.Now(),
	}
}

func TestGetVerificationInfo_AnsRowMapsDetails(t *testing.T) {
	verifiedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	db := &fakeNamingDB{verification: verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, &verifiedAt)}
	ctrl := newNamingController(db, &fakeNamingStore{err: errors.New("store must not be consulted")}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())

	ans := resp.GetVerification().GetAns()
	require.NotNil(t, ans, "an ans row must be reported through the ans arm")
	assert.Nil(t, resp.GetVerification().GetDomain())
	assert.Equal(t, "ans://v1.0.0.agent.example.com", ans.GetAnsName())
	assert.Equal(t, "agent-1", ans.GetAgentId())
	assert.Equal(t, "agent.example.com", ans.GetAgentHost())
	assert.Equal(t, "https://log.example.com", ans.GetLogUrl())
	assert.Equal(t, "https://log.example.com/v1/agents/agent-1/receipt", ans.GetReceiptUrl())
	assert.Equal(t, "SHA256:abc", ans.GetCertFingerprint())
	assert.Equal(t, "ACTIVE", ans.GetAgentStatus())
	assert.Equal(t, verifiedAt.Unix(), resp.GetVerification().GetVerifiedAt().AsTime().Unix())
}

func TestGetVerificationInfo_AnsRowWithUnusableDetails(t *testing.T) {
	tests := []struct {
		name    string
		details string
	}{
		{name: "empty details", details: ""},
		{name: "malformed json", details: `{"v":1,`},
		{name: "newer version", details: `{"v":99,"ansName":"ans://v1.0.0.agent.example.com"}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifiedAt := time.Now().Add(-time.Minute)
			db := &fakeNamingDB{verification: verifiedRow(string(naming.MethodANS), "SHA256:abc", tc.details, &verifiedAt)}
			ctrl := newNamingController(db, &fakeNamingStore{}, time.Hour)

			resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
			require.Error(t, err, "a verified row whose details cannot be read must not be served")
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

func TestGetVerificationInfo_UnknownMethodIsAnError(t *testing.T) {
	verifiedAt := time.Now().Add(-time.Minute)
	db := &fakeNamingDB{verification: verifiedRow("did", "kid-9", "", &verifiedAt)}
	ctrl := newNamingController(db, &fakeNamingStore{}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Nil(t, resp)
}

func TestGetVerificationInfo_WellKnownRowMapsDomain(t *testing.T) {
	verifiedAt := time.Now().Add(-time.Minute)
	db := &fakeNamingDB{verification: verifiedRow(string(naming.MethodWellKnown), "kid-1", "", &verifiedAt)}
	store := &fakeNamingStore{record: corev1.New(&oasfv1alpha1.Record{
		Name:          "https://agent.example.com/agent",
		SchemaVersion: "0.7.0",
		Version:       "1.0.0",
	})}
	ctrl := newNamingController(db, store, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())

	domain := resp.GetVerification().GetDomain()
	require.NotNil(t, domain)
	assert.Nil(t, resp.GetVerification().GetAns())
	assert.Equal(t, "agent.example.com", domain.GetDomain())
	assert.Equal(t, string(naming.MethodWellKnown), domain.GetMethod())
	assert.Equal(t, "kid-1", domain.GetKeyId())
	assert.Equal(t, verifiedAt.Unix(), domain.GetVerifiedAt().AsTime().Unix())
	assert.Equal(t, verifiedAt.Unix(), resp.GetVerification().GetVerifiedAt().AsTime().Unix())
}

func TestGetVerificationInfo_WellKnownRowWithoutRecordLeavesDomainEmpty(t *testing.T) {
	db := &fakeNamingDB{verification: verifiedRow(string(naming.MethodWellKnown), "kid-1", "", nil)}
	ctrl := newNamingController(db, &fakeNamingStore{err: errors.New("gone")}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())
	assert.Empty(t, resp.GetVerification().GetDomain().GetDomain())
}

// Rows written before the verified_at column existed report updated_at, which
// for a verified row is when that verdict was reached.
func TestGetVerificationInfo_VerifiedAtFallsBackToUpdatedAt(t *testing.T) {
	row := verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, nil)
	row.UpdatedAt = time.Now().Add(-10 * time.Minute).Truncate(time.Second)

	ctrl := newNamingController(&fakeNamingDB{verification: row}, &fakeNamingStore{}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.Equal(t, row.UpdatedAt.Unix(), resp.GetVerification().GetVerifiedAt().AsTime().Unix())
}

func TestGetVerificationInfo_NotVerifiedRows(t *testing.T) {
	tests := []struct {
		name        string
		row         *gormdb.NameVerification
		ttl         time.Duration
		wantMessage string
	}{
		{
			name: "pending row reports the transient error",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusPending, Error: "transient: ans dns: lookup timed out",
				ConsecutiveFailures: 2, UpdatedAt: time.Now(),
			},
			ttl:         time.Hour,
			wantMessage: "transient: ans dns: lookup timed out",
		},
		{
			name: "failed row reports its error",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusFailed, Error: "ans status-token: agent revoked",
				UpdatedAt: time.Now(),
			},
			ttl:         time.Hour,
			wantMessage: "ans status-token: agent revoked",
		},
		{
			name: "failed row without an error text gets the generic message",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodWellKnown),
				Status: gormdb.VerificationStatusFailed, UpdatedAt: time.Now(),
			},
			ttl:         time.Hour,
			wantMessage: "verification invalid or expired",
		},
		{
			name: "verified row past the ttl is expired",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusVerified, Details: namingTestDetails,
				UpdatedAt: time.Now().Add(-2 * time.Hour),
			},
			ttl:         time.Hour,
			wantMessage: "verification invalid or expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newNamingController(&fakeNamingDB{verification: tc.row}, &fakeNamingStore{}, tc.ttl)

			resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
			require.NoError(t, err)
			assert.False(t, resp.GetVerified())
			assert.Nil(t, resp.GetVerification())
			assert.Equal(t, tc.wantMessage, resp.GetErrorMessage())
		})
	}
}

func TestGetVerificationInfo_NoVerificationRow(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{err: gormdb.ErrVerificationNotFound}, &fakeNamingStore{}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.False(t, resp.GetVerified())
	assert.Equal(t, "no verification found", resp.GetErrorMessage())
}

func TestGetVerificationInfo_DatabaseError(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{err: errors.New("db down")}, &fakeNamingStore{}, time.Hour)

	_, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetVerificationInfo_RequiresCidOrName(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{}, &fakeNamingStore{}, time.Hour)

	_, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetVerificationInfo_ResolvesAnsNameToCid(t *testing.T) {
	db := &fakeNamingDB{
		verification: verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, nil),
		records: []coretypes.Record{
			&fakeNamedRecord{cid: namingTestCID, name: "ans://v1.0.0.agent.example.com", version: "1.0.0"},
		},
	}
	ctrl := newNamingController(db, &fakeNamingStore{}, time.Hour)

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Name: new("ans://v1.0.0.agent.example.com")})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())
	assert.Equal(t, "ans://v1.0.0.agent.example.com", resp.GetVerification().GetAns().GetAnsName())
}

func TestGetVerificationInfo_NameWithoutRecord(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{}, &fakeNamingStore{}, time.Hour)

	_, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Name: new("ans://v1.0.0.missing.example.com")})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestExpandNameWithProtocols(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "ans name is already prefixed", in: "ans://v1.0.0.agent.example.com/agent", want: []string{"ans://v1.0.0.agent.example.com/agent"}},
		{name: "https name is already prefixed", in: "https://example.com/agent", want: []string{"https://example.com/agent"}},
		{name: "http name is already prefixed", in: "http://localhost:8080/agent", want: []string{"http://localhost:8080/agent"}},
		{name: "bare name expands to the jwks schemes", in: "example.com/agent", want: []string{"example.com/agent", "http://example.com/agent", "https://example.com/agent"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, expandNameWithProtocols(tc.in))
		})
	}
}
