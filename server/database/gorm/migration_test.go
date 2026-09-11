// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package gorm

import (
	"testing"
	"time"

	"github.com/agntcy/dir/server/database/gorm/migrations"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	migrationVerifiedCID  = "baeareimigrationverified000000000000000000000000000000000000000"
	migrationFailedCID    = "baeareimigrationfailed00000000000000000000000000000000000000000"
	migrationKeptCID      = "baeareimigrationkept000000000000000000000000000000000000000000"
	nameVerifiedAtMigrate = "005_name_verification_verified_at"
)

// legacyNameVerification is the name_verifications shape before verified_at
// existed.
type legacyNameVerification struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
	RecordCID string         `gorm:"column:record_cid;not null;uniqueIndex"`
	Method    string         `gorm:"not null"`
	KeyID     string
	Status    string `gorm:"not null;index"`
	Error     string
}

func (legacyNameVerification) TableName() string { return "name_verifications" }

// markEarlierMigrationsApplied records every migration but 005 as applied, the
// history of a database upgraded from a release that predates the column.
func markEarlierMigrationsApplied(t *testing.T, gdb *gorm.DB) {
	t.Helper()

	require.NoError(t, gdb.AutoMigrate(&Migration{}))

	for _, m := range migrations.GetMigrations() {
		if m.ID == nameVerifiedAtMigrate {
			continue
		}

		require.NoError(t, gdb.Create(&Migration{ID: m.ID, Details: m.Details}).Error)
	}
}

func TestMigrate_NameVerificationVerifiedAt(t *testing.T) {
	t.Parallel()

	verdictAt := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
	keptAt := time.Now().Add(-30 * time.Minute).Truncate(time.Second)

	tests := []struct {
		name  string
		seed  func(t *testing.T, gdb *gorm.DB)
		check func(t *testing.T, db *DB)
	}{
		{
			name: "fresh database has nothing to backfill",
			seed: func(*testing.T, *gorm.DB) {},
			check: func(t *testing.T, db *DB) {
				t.Helper()

				var count int64
				require.NoError(t, db.gormDB.Model(&NameVerification{}).Count(&count).Error)
				assert.Zero(t, count)
			},
		},
		{
			name: "table without the column gets it and verified rows take updated_at",
			seed: func(t *testing.T, gdb *gorm.DB) {
				t.Helper()

				markEarlierMigrationsApplied(t, gdb)
				require.NoError(t, gdb.AutoMigrate(&legacyNameVerification{}))
				require.NoError(t, gdb.Create(&[]legacyNameVerification{
					{RecordCID: migrationVerifiedCID, Method: "wellknown", KeyID: "kid-1", Status: VerificationStatusVerified},
					{RecordCID: migrationFailedCID, Method: "wellknown", Status: VerificationStatusFailed, Error: "boom"},
				}).Error)
				require.NoError(t, gdb.Model(&legacyNameVerification{}).
					Where("record_cid = ?", migrationVerifiedCID).
					UpdateColumn("updated_at", verdictAt).Error)
			},
			check: func(t *testing.T, db *DB) {
				t.Helper()

				verified := loadNameVerification(t, db, migrationVerifiedCID)
				require.NotNil(t, verified.VerifiedAt)
				assert.WithinDuration(t, verdictAt, *verified.VerifiedAt, time.Second)
				assert.WithinDuration(t, verdictAt, verified.UpdatedAt, time.Second, "the backfill leaves updated_at alone")

				assert.Nil(t, loadNameVerification(t, db, migrationFailedCID).VerifiedAt)
			},
		},
		{
			name: "table with the column keeps values already set",
			seed: func(t *testing.T, gdb *gorm.DB) {
				t.Helper()

				markEarlierMigrationsApplied(t, gdb)
				require.NoError(t, gdb.AutoMigrate(&NameVerification{}))
				require.NoError(t, gdb.Create(&[]NameVerification{
					{RecordCID: migrationVerifiedCID, Method: "ans", Status: VerificationStatusVerified},
					{RecordCID: migrationKeptCID, Method: "ans", Status: VerificationStatusVerified, VerifiedAt: &keptAt},
				}).Error)
				require.NoError(t, gdb.Model(&NameVerification{}).
					Where("record_cid = ?", migrationVerifiedCID).
					UpdateColumn("updated_at", verdictAt).Error)
			},
			check: func(t *testing.T, db *DB) {
				t.Helper()

				backfilled := loadNameVerification(t, db, migrationVerifiedCID)
				require.NotNil(t, backfilled.VerifiedAt)
				assert.WithinDuration(t, verdictAt, *backfilled.VerifiedAt, time.Second)

				kept := loadNameVerification(t, db, migrationKeptCID)
				require.NotNil(t, kept.VerifiedAt)
				assert.WithinDuration(t, keptAt, *kept.VerifiedAt, time.Second)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gdb, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
			require.NoError(t, err)

			tc.seed(t, gdb)

			db, err := New(gdb)
			require.NoError(t, err)

			applied, err := db.HasMigration(nameVerifiedAtMigrate)
			require.NoError(t, err)
			assert.True(t, applied)

			tc.check(t, db)
		})
	}
}
