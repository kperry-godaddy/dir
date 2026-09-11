// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package gorm

import (
	"testing"
	"time"

	"github.com/agntcy/dir/server/naming"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	namingTestCID     = "baeareitestnaming0000000000000000000000000000000000000000000000"
	namingTestDetails = `{"v":1,"ansName":"ans://v1.0.0.agent.example.com","agentId":"a1"}`
)

func setupNamingDB(t *testing.T) *DB {
	t.Helper()

	gdb, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	require.NoError(t, err)

	db, err := New(gdb)
	require.NoError(t, err)

	return db
}

func loadNameVerification(t *testing.T, db *DB, cid string) *NameVerification {
	t.Helper()

	var row NameVerification
	require.NoError(t, db.gormDB.Where("record_cid = ?", cid).Take(&row).Error)

	return &row
}

// setNameVerificationUpdatedAt backdates updated_at directly: GORM refreshes
// the column on every Updates call, so a test cannot set it through the API.
func setNameVerificationUpdatedAt(t *testing.T, db *DB, cid string, at time.Time) {
	t.Helper()

	require.NoError(t, db.gormDB.Model(&NameVerification{}).
		Where("record_cid = ?", cid).
		UpdateColumn("updated_at", at).Error)
}

func seedSignedRecord(t *testing.T, db *DB, cid, name string, signed bool) {
	t.Helper()

	require.NoError(t, db.gormDB.Create(&Record{
		RecordCID:     cid,
		Name:          name,
		Version:       "1.0.0",
		SchemaVersion: "0.8.0",
		Signed:        signed,
	}).Error)
}

func needsVerificationCIDs(t *testing.T, db *DB, ttl time.Duration) []string {
	t.Helper()

	records, err := db.GetRecordsNeedingVerification(ttl)
	require.NoError(t, err)

	cids := make([]string, 0, len(records))
	for _, r := range records {
		cids = append(cids, r.GetCid())
	}

	return cids
}

// --- Create / Update / Get ---

func TestNameVerification_RoundTripsEveryColumn(t *testing.T) {
	t.Parallel()

	db := setupNamingDB(t)

	verifiedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	nextAttemptAt := time.Now().Add(time.Hour).Truncate(time.Second)

	require.NoError(t, db.CreateNameVerification(&NameVerification{
		RecordCID:           namingTestCID,
		Method:              string(naming.MethodANS),
		KeyID:               "SHA256:abc",
		Status:              VerificationStatusVerified,
		Details:             namingTestDetails,
		VerifiedAt:          &verifiedAt,
		ConsecutiveFailures: 2,
		NextAttemptAt:       &nextAttemptAt,
	}))

	got, err := db.GetVerificationByCID(namingTestCID)
	require.NoError(t, err)

	assert.Equal(t, namingTestCID, got.GetRecordCID())
	assert.Equal(t, string(naming.MethodANS), got.GetMethod())
	assert.Equal(t, "SHA256:abc", got.GetKeyID())
	assert.Equal(t, VerificationStatusVerified, got.GetStatus())
	assert.Empty(t, got.GetError())
	assert.JSONEq(t, namingTestDetails, got.GetDetails())
	require.NotNil(t, got.GetVerifiedAt())
	assert.WithinDuration(t, verifiedAt, *got.GetVerifiedAt(), time.Second)
	assert.Equal(t, 2, got.GetConsecutiveFailures())
	require.NotNil(t, got.GetNextAttemptAt())
	assert.WithinDuration(t, nextAttemptAt, *got.GetNextAttemptAt(), time.Second)
	assert.False(t, got.GetCreatedAt().IsZero())
	assert.False(t, got.GetUpdatedAt().IsZero())
}

func TestUpdateNameVerification_WritesEveryColumnAndClearsNilOnes(t *testing.T) {
	t.Parallel()

	db := setupNamingDB(t)

	verifiedAt := time.Now()
	nextAttemptAt := time.Now().Add(time.Hour)

	require.NoError(t, db.CreateNameVerification(&NameVerification{
		RecordCID:           namingTestCID,
		Method:              string(naming.MethodANS),
		KeyID:               "SHA256:abc",
		Status:              VerificationStatusVerified,
		Details:             namingTestDetails,
		VerifiedAt:          &verifiedAt,
		ConsecutiveFailures: 3,
		NextAttemptAt:       &nextAttemptAt,
	}))

	past := time.Now().Add(-2 * time.Hour)
	setNameVerificationUpdatedAt(t, db, namingTestCID, past)

	require.NoError(t, db.UpdateNameVerification(&NameVerification{
		RecordCID: namingTestCID,
		Method:    string(naming.MethodANS),
		Status:    VerificationStatusFailed,
		Error:     "ans status-token: agent revoked",
	}))

	row := loadNameVerification(t, db, namingTestCID)

	assert.Equal(t, VerificationStatusFailed, row.Status)
	assert.Equal(t, "ans status-token: agent revoked", row.Error)
	assert.Empty(t, row.KeyID)
	assert.Empty(t, row.Details)
	assert.Nil(t, row.VerifiedAt)
	assert.Equal(t, 0, row.ConsecutiveFailures)
	assert.Nil(t, row.NextAttemptAt)
	assert.True(t, row.UpdatedAt.After(past), "an update moves updated_at")
}

func TestUpdateNameVerification_MissingRow(t *testing.T) {
	t.Parallel()

	db := setupNamingDB(t)

	err := db.UpdateNameVerification(&NameVerification{RecordCID: namingTestCID, Method: "wellknown", Status: VerificationStatusFailed})
	require.ErrorIs(t, err, ErrVerificationNotFound)
}

func TestGetVerificationByCID_MissingRow(t *testing.T) {
	t.Parallel()

	db := setupNamingDB(t)

	_, err := db.GetVerificationByCID(namingTestCID)
	require.ErrorIs(t, err, ErrVerificationNotFound)
}

// --- GetRecordsNeedingVerification ---

func TestGetRecordsNeedingVerification_SelectsSignedPrefixedNames(t *testing.T) {
	t.Parallel()

	db := setupNamingDB(t)

	const (
		ansCID      = "baeareinamingans000000000000000000000000000000000000000000000000"
		httpsCID    = "baeareinaminghttps0000000000000000000000000000000000000000000000"
		httpCID     = "baeareinaminghttp00000000000000000000000000000000000000000000000"
		bareCID     = "baeareinamingbare00000000000000000000000000000000000000000000000"
		unsignedCID = "baeareinamingunsigned000000000000000000000000000000000000000000"
	)

	seedSignedRecord(t, db, ansCID, "ans://v1.0.0.agent.example.com/agent", true)
	seedSignedRecord(t, db, httpsCID, "https://example.com/agent", true)
	seedSignedRecord(t, db, httpCID, "http://localhost:8080/agent", true)
	seedSignedRecord(t, db, bareCID, "example.com/agent", true)
	seedSignedRecord(t, db, unsignedCID, "https://example.com/unsigned", false)

	cids := needsVerificationCIDs(t, db, time.Hour)

	assert.ElementsMatch(t, []string{ansCID, httpsCID, httpCID}, cids)
}

func TestGetRecordsNeedingVerification_ScheduleAndTTL(t *testing.T) {
	t.Parallel()

	const ttl = time.Hour

	future := time.Now().Add(30 * time.Minute)
	due := time.Now().Add(-time.Minute)

	tests := []struct {
		name     string
		row      *NameVerification
		ageAfter time.Duration // how far back updated_at is set; zero keeps it fresh
		want     bool
	}{
		{
			name:     "verified row older than the ttl with a future retry is not selected",
			row:      &NameVerification{Status: VerificationStatusVerified, NextAttemptAt: &future},
			ageAfter: 2 * ttl,
			want:     false,
		},
		{
			name: "pending row with a due retry is selected while fresh",
			row:  &NameVerification{Status: VerificationStatusPending, NextAttemptAt: &due},
			want: true,
		},
		{
			name: "pending row with a future retry is not selected while fresh",
			row:  &NameVerification{Status: VerificationStatusPending, NextAttemptAt: &future},
			want: false,
		},
		{
			name:     "pending row older than the ttl with a future retry is not selected",
			row:      &NameVerification{Status: VerificationStatusPending, NextAttemptAt: &future},
			ageAfter: 2 * ttl,
			want:     false,
		},
		{
			name:     "failed row older than the ttl with a future retry is not selected",
			row:      &NameVerification{Status: VerificationStatusFailed, Error: "verification unavailable for 24h; last: boom", NextAttemptAt: &future},
			ageAfter: 2 * ttl,
			want:     false,
		},
		{
			name: "failed row with a due retry is selected while fresh",
			row:  &NameVerification{Status: VerificationStatusFailed, Error: "boom", NextAttemptAt: &due},
			want: true,
		},
		{
			name: "failed row without a schedule is not selected before the ttl",
			row:  &NameVerification{Status: VerificationStatusFailed, Error: "boom"},
			want: false,
		},
		{
			name:     "failed row without a schedule is selected after the ttl",
			row:      &NameVerification{Status: VerificationStatusFailed, Error: "boom"},
			ageAfter: 2 * ttl,
			want:     true,
		},
		{
			name: "verified row without a schedule is not selected before the ttl",
			row:  &NameVerification{Status: VerificationStatusVerified},
			want: false,
		},
		{
			name:     "verified row without a schedule is selected after the ttl",
			row:      &NameVerification{Status: VerificationStatusVerified},
			ageAfter: 2 * ttl,
			want:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := setupNamingDB(t)
			seedSignedRecord(t, db, namingTestCID, "ans://v1.0.0.agent.example.com", true)

			tc.row.RecordCID = namingTestCID
			tc.row.Method = string(naming.MethodANS)
			require.NoError(t, db.CreateNameVerification(tc.row))

			if tc.ageAfter > 0 {
				setNameVerificationUpdatedAt(t, db, namingTestCID, time.Now().Add(-tc.ageAfter))
			}

			cids := needsVerificationCIDs(t, db, ttl)

			if tc.want {
				assert.Contains(t, cids, namingTestCID)
			} else {
				assert.NotContains(t, cids, namingTestCID)
			}
		})
	}
}
