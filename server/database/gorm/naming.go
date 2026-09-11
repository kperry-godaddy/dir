// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package gorm

import (
	"errors"
	"fmt"
	"strings"
	"time"

	coretypes "github.com/agntcy/dir/api/core/types"
	"github.com/agntcy/dir/server/naming"
	"github.com/agntcy/dir/server/types"
	"gorm.io/gorm"
)

// NameVerification status constants.
const (
	VerificationStatusVerified = "verified"
	VerificationStatusFailed   = "failed"

	// VerificationStatusPending marks a record that has never reached a
	// verdict because every attempt so far failed transiently.
	VerificationStatusPending = "pending"
)

// ErrVerificationNotFound is returned when no verification is found for a record.
var ErrVerificationNotFound = errors.New("verification not found")

// NameVerification stores name verification result for a record (one per CID).
//
// updated_at moves only on a verdict (verified or failed). Transient failures
// are recorded through UpdateNameVerificationSchedule, which changes the
// status, the failure counter, the retry time and the error alone.
type NameVerification struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`                                  // soft delete support
	RecordCID string         `gorm:"column:record_cid;not null;uniqueIndex"` // one verification per record
	Method    string         `gorm:"not null"`                               // "wellknown" or "ans"
	KeyID     string         // matched key ID (if successful)
	Status    string         `gorm:"not null;index"` // "verified", "failed" or "pending"
	Error     string         // error message (if failed or pending)

	Details    string     `gorm:"type:text"` // method-specific JSON recorded with a verified result
	VerifiedAt *time.Time // last successful verification

	ConsecutiveFailures int        `gorm:"not null;default:0"` // transient failures since the last verdict
	NextAttemptAt       *time.Time `gorm:"index"`              // scheduled retry; NULL leaves the row to the TTL
}

// Implement types.NameVerificationObject interface.

func (nv *NameVerification) GetRecordCID() string {
	return nv.RecordCID
}

func (nv *NameVerification) GetMethod() string {
	return nv.Method
}

func (nv *NameVerification) GetKeyID() string {
	return nv.KeyID
}

func (nv *NameVerification) GetStatus() string {
	return nv.Status
}

func (nv *NameVerification) GetError() string {
	return nv.Error
}

func (nv *NameVerification) GetDetails() string {
	return nv.Details
}

func (nv *NameVerification) GetVerifiedAt() *time.Time {
	return nv.VerifiedAt
}

func (nv *NameVerification) GetConsecutiveFailures() int {
	return nv.ConsecutiveFailures
}

func (nv *NameVerification) GetNextAttemptAt() *time.Time {
	return nv.NextAttemptAt
}

func (nv *NameVerification) GetCreatedAt() time.Time {
	return nv.CreatedAt
}

func (nv *NameVerification) GetUpdatedAt() time.Time {
	return nv.UpdatedAt
}

// CreateNameVerification creates a new name verification for a record.
func (d *DB) CreateNameVerification(verification types.NameVerificationObject) error {
	nv := &NameVerification{
		RecordCID:           verification.GetRecordCID(),
		Method:              verification.GetMethod(),
		KeyID:               verification.GetKeyID(),
		Status:              verification.GetStatus(),
		Error:               verification.GetError(),
		Details:             verification.GetDetails(),
		VerifiedAt:          verification.GetVerifiedAt(),
		ConsecutiveFailures: verification.GetConsecutiveFailures(),
		NextAttemptAt:       verification.GetNextAttemptAt(),
	}

	if err := d.gormDB.Create(nv).Error; err != nil {
		return fmt.Errorf("failed to create name verification: %w", err)
	}

	logger.Debug("Created name verification", "record_cid", nv.RecordCID, "status", nv.Status)

	return nil
}

// UpdateNameVerification replaces the verdict of an existing name verification
// for a record. Every verdict column is written, so a nil verified_at or
// next_attempt_at clears the stored value; updated_at moves.
func (d *DB) UpdateNameVerification(verification types.NameVerificationObject) error {
	result := d.gormDB.Model(&NameVerification{}).
		Where("record_cid = ?", verification.GetRecordCID()).
		Updates(map[string]any{
			"method":               verification.GetMethod(),
			"key_id":               verification.GetKeyID(),
			"status":               verification.GetStatus(),
			"error":                verification.GetError(),
			"details":              verification.GetDetails(),
			"verified_at":          verification.GetVerifiedAt(),
			"consecutive_failures": verification.GetConsecutiveFailures(),
			"next_attempt_at":      verification.GetNextAttemptAt(),
		})

	if result.Error != nil {
		return fmt.Errorf("failed to update name verification: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrVerificationNotFound
	}

	logger.Debug("Updated name verification", "record_cid", verification.GetRecordCID(), "status", verification.GetStatus())

	return nil
}

// UpdateNameVerificationSchedule records the retry state of a transient
// failure. Only status, consecutive_failures, next_attempt_at and error are
// written; updated_at, key_id, details and verified_at keep their values.
func (d *DB) UpdateNameVerificationSchedule(cid string, status string, consecutiveFailures int, nextAttemptAt *time.Time, errMsg string) error {
	result := d.gormDB.Model(&NameVerification{}).
		Where("record_cid = ?", cid).
		UpdateColumns(map[string]any{
			"status":               status,
			"consecutive_failures": consecutiveFailures,
			"next_attempt_at":      nextAttemptAt,
			"error":                errMsg,
		})

	if result.Error != nil {
		return fmt.Errorf("failed to update name verification schedule: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrVerificationNotFound
	}

	logger.Debug("Updated name verification schedule",
		"record_cid", cid,
		"status", status,
		"consecutive_failures", consecutiveFailures,
		"next_attempt_at", nextAttemptAt)

	return nil
}

// GetVerificationByCID retrieves the verification for a record.
// Returns ErrVerificationNotFound if no verification exists.
func (d *DB) GetVerificationByCID(cid string) (types.NameVerificationObject, error) {
	var nv NameVerification
	if err := d.gormDB.Where("record_cid = ?", cid).First(&nv).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationNotFound
		}

		return nil, fmt.Errorf("failed to get name verification: %w", err)
	}

	return &nv, nil
}

// GetRecordsNeedingVerification retrieves signed records with verifiable names
// that have no verification, an expired verification, or a scheduled retry
// that is due.
//
// A scheduled retry wins over the TTL: a row with a next_attempt_at is
// selected exactly when that time has passed, however old its updated_at is.
// Otherwise a previously verified row in the transient state, whose
// updated_at no longer moves, would be re-selected on every run and the
// backoff would never apply.
func (d *DB) GetRecordsNeedingVerification(ttl time.Duration) ([]coretypes.Record, error) {
	now := time.Now()
	expiredBefore := now.Add(-ttl)

	prefixes := naming.VerifiablePrefixes()
	nameClauses := make([]string, 0, len(prefixes))
	nameArgs := make([]any, 0, len(prefixes))

	for _, prefix := range prefixes {
		nameClauses = append(nameClauses, "records.name LIKE ?")
		nameArgs = append(nameArgs, prefix+"%")
	}

	var records []Record

	err := d.gormDB.Table("records").
		Joins("LEFT JOIN name_verifications nv ON records.record_cid = nv.record_cid").
		Where("records.signed = ?", true).
		Where("("+strings.Join(nameClauses, " OR ")+")", nameArgs...).
		Where(`(nv.record_cid IS NULL
			OR (nv.next_attempt_at IS NULL AND nv.updated_at < ?)
			OR (nv.next_attempt_at IS NOT NULL AND nv.next_attempt_at <= ?))`, expiredBefore, now).
		Find(&records).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get records needing verification: %w", err)
	}

	result := make([]coretypes.Record, len(records))
	for i := range records {
		result[i] = &records[i]
	}

	return result, nil
}
