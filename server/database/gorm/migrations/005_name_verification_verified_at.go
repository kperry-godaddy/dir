// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

const nameVerificationsTable = "name_verifications"

// nameVerificationVerifiedAtRow is a minimal name_verifications projection for
// migration 005.
type nameVerificationVerifiedAtRow struct {
	RecordCID  string     `gorm:"column:record_cid;primaryKey"`
	Status     string     `gorm:"column:status"`
	VerifiedAt *time.Time `gorm:"column:verified_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at"`
}

func (nameVerificationVerifiedAtRow) TableName() string { return nameVerificationsTable }

func init() {
	register(Migration{
		ID:      "005_name_verification_verified_at",
		Details: "Add name_verifications.verified_at and backfill it from updated_at for verified rows.",
		Run:     runNameVerificationVerifiedAt,
	})
}

// runNameVerificationVerifiedAt adds verified_at to name_verifications and
// fills it for rows verified before the column existed.
//
// It adds the column itself rather than leaving it to AutoMigrate because
// custom migrations run first (see migrate in ../migration.go).
func runNameVerificationVerifiedAt(db *gorm.DB) error {
	if !db.Migrator().HasTable(nameVerificationsTable) {
		return nil
	}

	if !db.Migrator().HasColumn(&nameVerificationVerifiedAtRow{}, "VerifiedAt") {
		if err := db.Migrator().AddColumn(&nameVerificationVerifiedAtRow{}, "VerifiedAt"); err != nil {
			return fmt.Errorf("add name_verifications.verified_at column: %w", err)
		}
	}

	err := db.Model(&nameVerificationVerifiedAtRow{}).
		Where("status = ? AND verified_at IS NULL", "verified").
		UpdateColumn("verified_at", gorm.Expr("updated_at")).Error
	if err != nil {
		return fmt.Errorf("backfill name_verifications.verified_at: %w", err)
	}

	return nil
}
