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
	namingTestTTL     = time.Hour
	namingTestDetails = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentHost":"agent.example.com","agentId":"agent-1",` +
		`"logUrl":"https://log.example.com","receiptUrl":"https://log.example.com/v1/agents/agent-1/receipt",` +
		`"agentStatus":"ACTIVE"}`
)

type fakeNamingDB struct {
	types.DatabaseAPI

	verification types.NameVerificationObject
	err          error
	records      []coretypes.Record
}

func (f *fakeNamingDB) GetVerificationByCID(string) (types.NameVerificationObject, error) {
	return f.verification, f.err
}

func (f *fakeNamingDB) GetRecords(...types.FilterOption) ([]coretypes.Record, error) {
	return f.records, nil
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

func newNamingController(db types.DatabaseAPI, store types.StoreAPI) namingv1.NamingServiceServer {
	return NewNamingController(store, db, nil, WithVerificationTTL(namingTestTTL))
}

func verifiedRow(method, keyID, details string, verifiedAt time.Time) *gormdb.NameVerification {
	return &gormdb.NameVerification{
		RecordCID:  namingTestCID,
		Method:     method,
		KeyID:      keyID,
		Status:     gormdb.VerificationStatusVerified,
		Details:    details,
		VerifiedAt: &verifiedAt,
		UpdatedAt:  time.Now(),
	}
}

func TestGetVerificationInfo_VerifiedRows(t *testing.T) {
	verifiedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	record := corev1.New(&oasfv1alpha1.Record{
		Name:          "https://agent.example.com/agent",
		SchemaVersion: "0.7.0",
		Version:       "1.0.0",
	})

	tests := []struct {
		name  string
		row   *gormdb.NameVerification
		store *fakeNamingStore
		check func(t *testing.T, v *namingv1.Verification)
	}{
		{
			name:  "ans row maps its details without consulting the store",
			row:   verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, verifiedAt),
			store: &fakeNamingStore{err: errors.New("store must not be consulted")},
			check: func(t *testing.T, v *namingv1.Verification) {
				t.Helper()

				ans := v.GetAns()
				require.NotNil(t, ans, "an ans row must be reported through the ans arm")
				assert.Nil(t, v.GetDomain())
				assert.Equal(t, "ans://v1.0.0.agent.example.com", ans.GetAnsName())
				assert.Equal(t, "agent-1", ans.GetAgentId())
				assert.Equal(t, "agent.example.com", ans.GetAgentHost())
				assert.Equal(t, "https://log.example.com", ans.GetLogUrl())
				assert.Equal(t, "https://log.example.com/v1/agents/agent-1/receipt", ans.GetReceiptUrl())
				assert.Equal(t, "SHA256:abc", ans.GetCertFingerprint())
				assert.Equal(t, "ACTIVE", ans.GetAgentStatus())
			},
		},
		{
			name:  "wellknown row maps the record's domain",
			row:   verifiedRow(string(naming.MethodWellKnown), "kid-1", "", verifiedAt),
			store: &fakeNamingStore{record: record},
			check: func(t *testing.T, v *namingv1.Verification) {
				t.Helper()

				domain := v.GetDomain()
				require.NotNil(t, domain)
				assert.Nil(t, v.GetAns())
				assert.Equal(t, "agent.example.com", domain.GetDomain())
				assert.Equal(t, string(naming.MethodWellKnown), domain.GetMethod())
				assert.Equal(t, "kid-1", domain.GetKeyId())
				assert.Equal(t, verifiedAt.Unix(), domain.GetVerifiedAt().AsTime().Unix())
			},
		},
		{
			name:  "wellknown row without a readable record leaves the domain empty",
			row:   verifiedRow(string(naming.MethodWellKnown), "kid-1", "", verifiedAt),
			store: &fakeNamingStore{err: errors.New("gone")},
			check: func(t *testing.T, v *namingv1.Verification) {
				t.Helper()

				assert.Empty(t, v.GetDomain().GetDomain())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newNamingController(&fakeNamingDB{verification: tc.row}, tc.store)

			resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
			require.NoError(t, err)
			assert.True(t, resp.GetVerified())
			assert.Equal(t, verifiedAt.Unix(), resp.GetVerification().GetVerifiedAt().AsTime().Unix())

			tc.check(t, resp.GetVerification())
		})
	}
}

func TestGetVerificationInfo_NotVerifiedRows(t *testing.T) {
	expired := time.Now().Add(-2 * namingTestTTL)

	tests := []struct {
		name        string
		row         *gormdb.NameVerification
		wantMessage string
	}{
		{
			name: "pending row reports the transient error",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusPending, Error: "transient: ans dns: lookup timed out",
				ConsecutiveFailures: 2, UpdatedAt: time.Now(),
			},
			wantMessage: "transient: ans dns: lookup timed out",
		},
		{
			name: "failed row reports its error",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusFailed, Error: "ans status-token: agent revoked",
				UpdatedAt: time.Now(),
			},
			wantMessage: "ans status-token: agent revoked",
		},
		{
			name: "failed row without an error text gets the generic message",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodWellKnown),
				Status: gormdb.VerificationStatusFailed, UpdatedAt: time.Now(),
			},
			wantMessage: "verification invalid or expired",
		},
		{
			name:        "verified row past the ttl is expired",
			row:         verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, expired),
			wantMessage: "verification invalid or expired",
		},
		{
			name: "verified row past the ttl carrying a transient error reports it",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusVerified, KeyID: "SHA256:abc", Details: namingTestDetails,
				Error: "transient: ans receipt: log unreachable", ConsecutiveFailures: 3,
				VerifiedAt: &expired, UpdatedAt: time.Now(),
			},
			wantMessage: "transient: ans receipt: log unreachable",
		},
		{
			name: "verified row without a verification time is not served",
			row: &gormdb.NameVerification{
				RecordCID: namingTestCID, Method: string(naming.MethodANS),
				Status: gormdb.VerificationStatusVerified, KeyID: "SHA256:abc", Details: namingTestDetails,
				UpdatedAt: time.Now(),
			},
			wantMessage: "verification invalid or expired",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newNamingController(&fakeNamingDB{verification: tc.row}, &fakeNamingStore{})

			resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
			require.NoError(t, err)
			assert.False(t, resp.GetVerified())
			assert.Nil(t, resp.GetVerification())
			assert.Equal(t, tc.wantMessage, resp.GetErrorMessage())
		})
	}
}

func TestGetVerificationInfo_UnservableVerifiedRows(t *testing.T) {
	verifiedAt := time.Now().Add(-time.Minute)

	tests := []struct {
		name string
		row  *gormdb.NameVerification
	}{
		{name: "ans row with empty details", row: verifiedRow(string(naming.MethodANS), "SHA256:abc", "", verifiedAt)},
		{name: "ans row with malformed details", row: verifiedRow(string(naming.MethodANS), "SHA256:abc", `{"v":1,`, verifiedAt)},
		{name: "ans row with details of a newer version", row: verifiedRow(string(naming.MethodANS), "SHA256:abc", `{"v":99,"ansName":"ans://v1.0.0.agent.example.com"}`, verifiedAt)},
		{name: "row with an unknown method", row: verifiedRow("did", "kid-9", "", verifiedAt)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := newNamingController(&fakeNamingDB{verification: tc.row}, &fakeNamingStore{})

			resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
			require.Error(t, err, "a verified row this server cannot vouch for must not be served")
			assert.Equal(t, codes.Internal, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

func TestGetVerificationInfo_NoVerificationRow(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{err: gormdb.ErrVerificationNotFound}, &fakeNamingStore{})

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.NoError(t, err)
	assert.False(t, resp.GetVerified())
	assert.Equal(t, "no verification found", resp.GetErrorMessage())
}

func TestGetVerificationInfo_DatabaseError(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{err: errors.New("db down")}, &fakeNamingStore{})

	_, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Cid: new(namingTestCID)})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetVerificationInfo_RequiresCidOrName(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{}, &fakeNamingStore{})

	_, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetVerificationInfo_ResolvesAnsNameToCid(t *testing.T) {
	db := &fakeNamingDB{
		verification: verifiedRow(string(naming.MethodANS), "SHA256:abc", namingTestDetails, time.Now()),
		records: []coretypes.Record{
			&fakeNamedRecord{cid: namingTestCID, name: "ans://v1.0.0.agent.example.com", version: "1.0.0"},
		},
	}
	ctrl := newNamingController(db, &fakeNamingStore{})

	resp, err := ctrl.GetVerificationInfo(t.Context(), &namingv1.GetVerificationInfoRequest{Name: new("ans://v1.0.0.agent.example.com")})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())
	assert.Equal(t, "ans://v1.0.0.agent.example.com", resp.GetVerification().GetAns().GetAnsName())
}

func TestGetVerificationInfo_NameWithoutRecord(t *testing.T) {
	ctrl := newNamingController(&fakeNamingDB{}, &fakeNamingStore{})

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
