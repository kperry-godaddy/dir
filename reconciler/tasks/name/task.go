// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package name implements the name reconciler task: name ownership verification.
// It periodically re-verifies ownership of named records through the method the
// name's protocol prefix selects and stores results in the database.
// Distinct from the signature task (see reconciler/tasks/signature for that).
package name

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	"github.com/agntcy/dir/client/utils/verify"
	gormdb "github.com/agntcy/dir/server/database/gorm"
	"github.com/agntcy/dir/server/naming"
	"github.com/agntcy/dir/server/types"
	"github.com/agntcy/dir/utils/logging"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

var logger = logging.Logger("reconciler/name")

const (
	// maxRetryDelay caps the doubling backoff between transient retries and is
	// how long a record recorded as unavailable waits before its next attempt.
	maxRetryDelay = 24 * time.Hour

	// pendingBudget is how long a record may stay pending before it is
	// recorded as failed.
	pendingBudget = 24 * time.Hour

	// unreadableSignaturesMessage is stored when the record's signatures could
	// not be pulled. The cause is logged, never stored.
	unreadableSignaturesMessage = "could not read the record's signatures"
)

// Task implements the name reconciler task (name ownership verification).
type Task struct {
	config   Config
	db       types.DatabaseAPI
	fetcher  verify.Fetcher
	provider *naming.Provider
	now      func() time.Time
}

// NewTask creates a new name reconciliation task.
// fetcher supplies the record's signatures and public keys (e.g. the store
// fetcher from the signature task).
func NewTask(config Config, db types.DatabaseAPI, fetcher verify.Fetcher, provider *naming.Provider) (*Task, error) {
	return &Task{
		config:   config,
		db:       db,
		fetcher:  fetcher,
		provider: provider,
		now:      time.Now,
	}, nil
}

// Name returns the task name: name verification (distinct from signature task).
func (t *Task) Name() string {
	return "name"
}

// Interval returns how often this task should run.
func (t *Task) Interval() time.Duration {
	return t.config.GetInterval()
}

// IsEnabled returns whether this task is enabled.
func (t *Task) IsEnabled() bool {
	return t.config.Enabled
}

// Run executes name verification: fetch records needing verification, then
// verify each. It stops at the first record for which ctx is done.
func (t *Task) Run(ctx context.Context) error {
	started := t.now()

	logger.Debug("Running name verification")

	records, err := t.db.GetRecordsNeedingVerification(t.config.GetTTL())
	if err != nil {
		return fmt.Errorf("get records needing name verification: %w", err)
	}

	if len(records) == 0 {
		logger.Info("No records need name verification")

		return nil
	}

	logger.Info("Processing records for name verification", "count", len(records))

	summary := newRunSummary()

	for i, r := range records {
		if err := ctx.Err(); err != nil {
			summary.log(t.now().Sub(started))

			return fmt.Errorf("name verification stopped after %d of %d records: %w", i, len(records), err)
		}

		summary.add(t.verifyRecord(ctx, r.GetCid(), r.GetName()))
	}

	summary.log(t.now().Sub(started))

	return nil
}

// verifyRecord verifies ownership of one record's name within the record
// timeout and records the result.
func (t *Task) verifyRecord(ctx context.Context, cid, recordName string) outcome {
	started := t.now()

	parsed := naming.ParseName(recordName)
	if parsed == nil {
		return t.recordResult(ctx, cid, recordName, &naming.Result{Method: string(naming.MethodNone), Error: "could not parse record name"}, started)
	}

	method := t.provider.Method(parsed.Protocol)
	if method == naming.MethodNone {
		logger.Debug("Skipping record: no verification method for its protocol", "cid", cid, "protocol", parsed.Protocol)

		return outcome{kind: outcomeSkipped, protocol: parsed.Protocol}
	}

	recordCtx, cancel := context.WithTimeout(ctx, t.config.GetRecordTimeout())
	defer cancel()

	signers, err := t.collectSigners(recordCtx, cid)
	if err != nil {
		logger.Warn("Could not read the record's signatures", "cid", cid, "recordName", recordName, "error", err)

		result := &naming.Result{Domain: parsed.Domain, Method: string(method), Error: unreadableSignaturesMessage, Transient: true}

		return t.recordResult(ctx, cid, recordName, result, started)
	}

	return t.recordResult(ctx, cid, recordName, t.provider.Verify(recordCtx, recordName, signers), started)
}

// collectSigners gathers the parties that signed the record: the certificates
// bound to its signatures, then the public keys attached to it.
func (t *Task) collectSigners(ctx context.Context, cid string) ([]naming.Signer, error) {
	ref := &corev1.RecordRef{Cid: cid}

	sigs, err := t.fetcher.PullSignatures(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull signatures: %w", err)
	}

	signers, err := certificateSigners(ctx, cid, sigs)
	if err != nil {
		return nil, err
	}

	keys, err := t.fetcher.PullPublicKeys(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull public keys: %w", err)
	}

	return append(signers, publicKeySigners(cid, keys)...), nil
}

// publicKeySigners decodes the record's public keys, PEM or base64 DER, into
// signers. Keys that decode as neither are skipped.
func publicKeySigners(cid string, keys []string) []naming.Signer {
	signers := make([]naming.Signer, 0, len(keys))

	for _, key := range keys {
		der, err := publicKeyDER(key)
		if err != nil {
			logger.Debug("Skipping unreadable public key", "cid", cid, "error", err)

			continue
		}

		signers = append(signers, naming.Signer{Key: der})
	}

	return signers
}

// publicKeyDER returns the DER SubjectPublicKeyInfo of a PEM or base64-DER key.
func publicKeyDER(key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("empty public key")
	}

	parsed, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(key))
	if err != nil {
		der, decodeErr := base64.StdEncoding.DecodeString(key)
		if decodeErr != nil {
			return nil, fmt.Errorf("public key is neither PEM nor base64 DER: %w", err)
		}

		if _, parseErr := x509.ParsePKIXPublicKey(der); parseErr != nil {
			return nil, fmt.Errorf("public key is not DER SubjectPublicKeyInfo: %w", parseErr)
		}

		return der, nil
	}

	der, err := cryptoutils.MarshalPublicKeyToDER(parsed)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to DER: %w", err)
	}

	return der, nil
}

// recordResult folds the result into the record's row and logs the attempt. A
// failure is not persisted once ctx is done, because it may be the
// cancellation's own doing.
func (t *Task) recordResult(ctx context.Context, cid, recordName string, result *naming.Result, started time.Time) outcome {
	if !result.Verified && ctx.Err() != nil {
		logger.Warn("Name verification aborted", "cid", cid, "recordName", recordName, "method", result.Method, "error", result.Error)

		return outcome{kind: outcomeAborted, method: result.Method}
	}

	existing, err := t.db.GetVerificationByCID(cid)
	if err != nil && !errors.Is(err, gormdb.ErrVerificationNotFound) {
		logger.Error("Failed to load name verification", "cid", cid, "error", err)

		return outcome{kind: outcomePersistFailed, method: result.Method}
	}

	next := transition(cid, existing, result, t.now(), policy{ttl: t.config.GetTTL(), interval: t.config.GetInterval()})

	if err := t.write(existing != nil, next.row); err != nil {
		logger.Error("Failed to store name verification", "cid", cid, "status", next.row.Status, "error", err)

		return outcome{kind: outcomePersistFailed, method: result.Method}
	}

	t.logAttempt(cid, recordName, result, next.row, t.now().Sub(started))

	return outcome{kind: next.kind, method: next.row.Method}
}

// write creates the record's row or replaces the existing one.
func (t *Task) write(exists bool, row *gormdb.NameVerification) error {
	if exists {
		return t.db.UpdateNameVerification(row) //nolint:wrapcheck // logged with its context by the caller
	}

	return t.db.CreateNameVerification(row) //nolint:wrapcheck // logged with its context by the caller
}

// logAttempt reports one persisted attempt with the row it produced.
func (t *Task) logAttempt(cid, recordName string, result *naming.Result, row *gormdb.NameVerification, elapsed time.Duration) {
	if result.Verified {
		logger.Info("Name verification succeeded",
			"cid", cid,
			"recordName", recordName,
			"domain", result.Domain,
			"method", row.Method,
			"keyID", row.KeyID,
			"elapsedMs", elapsed.Milliseconds())

		return
	}

	attrs := []any{
		"cid", cid,
		"recordName", recordName,
		"domain", result.Domain,
		"method", row.Method,
		"error", row.Error,
		"transient", result.Transient,
		"status", row.Status,
		"elapsedMs", elapsed.Milliseconds(),
	}

	if row.NextAttemptAt != nil {
		attrs = append(attrs, "consecutiveFailures", row.ConsecutiveFailures, "nextAttemptAt", *row.NextAttemptAt)
	}

	logger.Warn("Name verification did not verify", attrs...)
}

// policy is the timing the state machine applies.
type policy struct {
	// ttl is how long a verified verdict is served.
	ttl time.Duration

	// interval is the task interval; the first retry lands on the next run.
	interval time.Duration
}

// step is the row one attempt produces and how the run counts it.
type step struct {
	row  *gormdb.NameVerification
	kind outcomeKind
}

// transition folds the result of one attempt into the record's row. A verdict
// replaces the row. A transient failure advances the retry schedule and keeps
// the verdict columns: a verified row stays verified until its TTL and is
// pending after it, a failed row stays failed with its own error, and a row
// pending for pendingBudget becomes failed until its daily retry.
func transition(cid string, existing types.NameVerificationObject, result *naming.Result, now time.Time, p policy) step {
	switch {
	case result.Verified:
		return step{row: verifiedRow(cid, result, now), kind: outcomeVerified}
	case result.Transient:
		return transientStep(cid, existing, result, now, p)
	default:
		return step{row: failedRow(cid, result.Method, result.Error), kind: outcomeFailed}
	}
}

func transientStep(cid string, existing types.NameVerificationObject, result *naming.Result, now time.Time, p policy) step {
	failures, nextAttemptAt := retrySchedule(existing, result, now, p.interval)
	transientErr := "transient: " + result.Error

	if existing == nil {
		row := &gormdb.NameVerification{
			RecordCID:           cid,
			Method:              result.Method,
			Status:              gormdb.VerificationStatusPending,
			Error:               transientErr,
			ConsecutiveFailures: failures,
			NextAttemptAt:       &nextAttemptAt,
		}

		return step{row: row, kind: outcomeTransient}
	}

	row := carriedRow(cid, existing, failures, nextAttemptAt)

	switch existing.GetStatus() {
	case gormdb.VerificationStatusVerified:
		row.Error = transientErr
		row.Status = gormdb.VerificationStatusPending

		if at := existing.GetVerifiedAt(); at != nil && now.Before(at.Add(p.ttl)) {
			row.Status = gormdb.VerificationStatusVerified
		}
	case gormdb.VerificationStatusFailed:
		row.Error = existing.GetError()
		row.Status = gormdb.VerificationStatusFailed
	default:
		if !now.Before(pendingSince(existing, p.ttl).Add(pendingBudget)) {
			row = failedRow(cid, result.Method, "verification unavailable for 24h; last: "+result.Error)
			row.ConsecutiveFailures = failures
			retryAt := now.Add(maxRetryDelay)
			row.NextAttemptAt = &retryAt

			return step{row: row, kind: outcomeFailed}
		}

		row.Error = transientErr
		row.Status = gormdb.VerificationStatusPending
	}

	return step{row: row, kind: outcomeTransient}
}

// retrySchedule advances the failure counter and picks the next attempt. A
// retry time named by the method (its circuit breaker is open) is used as is
// and does not count as a strike. Otherwise the delay starts at half the task
// interval, so the first retry lands on the next run, and doubles up to
// maxRetryDelay.
func retrySchedule(existing types.NameVerificationObject, result *naming.Result, now time.Time, interval time.Duration) (int, time.Time) {
	failures := 0
	if existing != nil {
		failures = existing.GetConsecutiveFailures()
	}

	if !result.RetryAfter.IsZero() {
		return failures, result.RetryAfter
	}

	failures++

	schedule := types.ScanSchedule{RetryBase: interval / 2, RetryMax: maxRetryDelay} //nolint:mnd // half: the first retry lands on the next run

	return failures, schedule.NextAttempt(now, failures)
}

// pendingSince is when a pending row stopped being served: the end of its
// verified verdict's TTL when it has one, otherwise its creation.
func pendingSince(existing types.NameVerificationObject, ttl time.Duration) time.Time {
	if at := existing.GetVerifiedAt(); at != nil {
		return at.Add(ttl)
	}

	return existing.GetCreatedAt()
}

// carriedRow starts a row from the columns a transient failure never changes.
func carriedRow(cid string, existing types.NameVerificationObject, failures int, nextAttemptAt time.Time) *gormdb.NameVerification {
	return &gormdb.NameVerification{
		RecordCID:           cid,
		Method:              existing.GetMethod(),
		KeyID:               existing.GetKeyID(),
		Details:             existing.GetDetails(),
		VerifiedAt:          existing.GetVerifiedAt(),
		ConsecutiveFailures: failures,
		NextAttemptAt:       &nextAttemptAt,
	}
}

// verifiedRow is the verdict row for a verified result.
func verifiedRow(cid string, result *naming.Result, now time.Time) *gormdb.NameVerification {
	return &gormdb.NameVerification{
		RecordCID:  cid,
		Method:     result.Method,
		KeyID:      result.MatchedKeyID,
		Status:     gormdb.VerificationStatusVerified,
		Details:    string(result.Details),
		VerifiedAt: &now,
	}
}

// failedRow is the verdict row for a terminal failure.
func failedRow(cid, method, errMsg string) *gormdb.NameVerification {
	if errMsg == "" {
		errMsg = "verification failed"
	}

	return &gormdb.NameVerification{
		RecordCID: cid,
		Method:    method,
		Status:    gormdb.VerificationStatusFailed,
		Error:     errMsg,
	}
}

// outcomeKind classifies one record's attempt for the run summary.
type outcomeKind int

const (
	outcomeVerified outcomeKind = iota
	outcomeFailed
	outcomeTransient
	outcomeSkipped
	outcomeAborted
	outcomePersistFailed
)

// outcome is what one record contributed to the run.
type outcome struct {
	kind     outcomeKind
	method   string
	protocol string
}

// runSummary aggregates the outcomes of one run for the completion log line.
type runSummary struct {
	verified, failed, transient, skipped, aborted, persistFailed int

	verifiedByMethod  map[string]int
	failedByMethod    map[string]int
	skippedByProtocol map[string]int
}

func newRunSummary() *runSummary {
	return &runSummary{
		verifiedByMethod:  make(map[string]int),
		failedByMethod:    make(map[string]int),
		skippedByProtocol: make(map[string]int),
	}
}

func (s *runSummary) add(o outcome) {
	switch o.kind {
	case outcomeVerified:
		s.verified++
		s.verifiedByMethod[o.method]++
	case outcomeFailed:
		s.failed++
		s.failedByMethod[o.method]++
	case outcomeTransient:
		s.transient++
	case outcomeSkipped:
		s.skipped++
		s.skippedByProtocol[o.protocol]++
	case outcomeAborted:
		s.aborted++
	case outcomePersistFailed:
		s.persistFailed++
	}
}

func (s *runSummary) log(duration time.Duration) {
	logger.Info("Name verification complete",
		"durationMs", duration.Milliseconds(),
		"verified", s.verified,
		"failed", s.failed,
		"transient", s.transient,
		"skipped", s.skipped,
		"aborted", s.aborted,
		"persistFailed", s.persistFailed,
		"verifiedByMethod", s.verifiedByMethod,
		"failedByMethod", s.failedByMethod,
		"skippedByProtocol", s.skippedByProtocol)
}
