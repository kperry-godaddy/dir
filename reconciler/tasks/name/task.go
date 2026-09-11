// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package name implements the name reconciler task: name ownership verification.
// It periodically re-verifies ownership of named records through the method the
// name's protocol prefix selects and stores results in the database.
// Distinct from the signature task (see reconciler/tasks/signature for that).
package name

import (
	"context"
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
	// maxConsecutiveTransients is the number of transient failures in a row
	// after which a record is recorded as failed instead of pending, so a
	// dependency that stays down does not leave the record undecided forever.
	maxConsecutiveTransients = 8

	// maxRetryDelay caps the doubling backoff between transient retries.
	maxRetryDelay = 24 * time.Hour

	// unavailableRetryDelay is how long a record recorded as failed after
	// maxConsecutiveTransients waits before its next attempt.
	unavailableRetryDelay = 24 * time.Hour
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

// Run executes name verification: fetch records needing verification, then verify each.
func (t *Task) Run(ctx context.Context) error {
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

	for _, r := range records {
		recordCtx, cancel := context.WithTimeout(ctx, t.config.GetRecordTimeout())
		summary.add(t.verifyRecord(recordCtx, r.GetCid(), r.GetName()))
		cancel()
	}

	summary.log()

	return nil
}

// verifyRecord verifies ownership of one record's name and records the result.
func (t *Task) verifyRecord(ctx context.Context, cid, recordName string) outcome {
	started := t.now()

	parsed := naming.ParseName(recordName)
	if parsed == nil {
		return t.recordResult(cid, recordName, &naming.Result{Error: "could not parse record name"}, started)
	}

	if t.provider.Method(parsed.Protocol) == naming.MethodNone {
		logger.Debug("Skipping record: no verification method for its protocol", "cid", cid, "protocol", parsed.Protocol)

		return outcome{kind: outcomeSkipped, protocol: parsed.Protocol}
	}

	method := methodFor(parsed.Protocol)

	signers, err := t.collectSigners(ctx, cid, parsed)
	if err != nil {
		return t.recordResult(cid, recordName, &naming.Result{Domain: parsed.Domain, Method: method, Error: "signers: " + err.Error()}, started)
	}

	if len(signers) == 0 {
		return t.recordResult(cid, recordName, &naming.Result{Domain: parsed.Domain, Method: method, Error: noSignersMessage(parsed.Protocol)}, started)
	}

	return t.recordResult(cid, recordName, t.provider.Verify(ctx, recordName, signers), started)
}

// collectSigners gathers the parties that signed the record. For ans:// names
// a signer is a certificate whose key verifiably produced a signature over the
// CID; for other names it is a public key attached to the record.
func (t *Task) collectSigners(ctx context.Context, cid string, parsed *naming.ParsedName) ([]naming.Signer, error) {
	ref := &corev1.RecordRef{Cid: cid}

	if parsed.Protocol == naming.ANSProtocol {
		sigs, err := t.fetcher.PullSignatures(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("pull signatures: %w", err)
		}

		return certificateSigners(ctx, cid, parsed.Domain, sigs)
	}

	keys, err := t.fetcher.PullPublicKeys(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull public keys: %w", err)
	}

	return publicKeySigners(cid, keys), nil
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

		return der, nil
	}

	der, err := cryptoutils.MarshalPublicKeyToDER(parsed)
	if err != nil {
		return nil, fmt.Errorf("marshal public key to DER: %w", err)
	}

	return der, nil
}

// methodFor names the verification method the provider runs for a supported
// protocol, for results recorded before Verify is reached.
func methodFor(protocol string) string {
	if protocol == naming.ANSProtocol {
		return string(naming.MethodANS)
	}

	return string(naming.MethodWellKnown)
}

// noSignersMessage explains a record without signers in the terms of its method.
func noSignersMessage(protocol string) string {
	if protocol == naming.ANSProtocol {
		return "no certificate attached to the record's signatures; sign with --certificate"
	}

	return "no public keys found for record"
}

// recordResult persists and logs the result of one attempt.
func (t *Task) recordResult(cid, recordName string, result *naming.Result, started time.Time) outcome {
	t.persist(cid, result)

	elapsedMs := t.now().Sub(started).Milliseconds()

	if result.Verified {
		logger.Info("Name verification succeeded",
			"cid", cid,
			"recordName", recordName,
			"domain", result.Domain,
			"method", result.Method,
			"keyID", result.MatchedKeyID,
			"elapsedMs", elapsedMs)

		return outcome{kind: outcomeVerified, method: result.Method}
	}

	logger.Warn("Name verification did not verify",
		"cid", cid,
		"recordName", recordName,
		"domain", result.Domain,
		"method", result.Method,
		"error", result.Error,
		"transient", result.Transient,
		"elapsedMs", elapsedMs)

	if result.Transient {
		return outcome{kind: outcomeTransient, method: result.Method}
	}

	return outcome{kind: outcomeFailed, method: result.Method}
}

// persist writes the result to the record's row. A verdict (verified or
// terminal failure) replaces the row; a transient failure only advances the
// retry state, so the previous verdict stays readable.
func (t *Task) persist(cid string, result *naming.Result) {
	existing, err := t.db.GetVerificationByCID(cid)
	if err != nil && !errors.Is(err, gormdb.ErrVerificationNotFound) {
		logger.Warn("Failed to load existing name verification", "cid", cid, "error", err)

		return
	}

	now := t.now()

	switch {
	case result.Verified:
		t.writeVerdict(cid, existing, verifiedRow(cid, result, now))
	case result.Transient:
		t.recordTransient(cid, existing, result, now)
	default:
		t.writeVerdict(cid, existing, failedRow(cid, result.Method, result.Error))
	}
}

// recordTransient advances the retry state after a transient failure. Each
// strike doubles the delay from the task interval up to maxRetryDelay. A retry
// time named by the method (its circuit breaker is open) is used as is and does
// not count as a strike. At maxConsecutiveTransients the row becomes a failed
// verdict that retries once a day; the counter keeps climbing across those
// daily attempts so its value shows how long the dependency has been down.
func (t *Task) recordTransient(cid string, existing types.NameVerificationObject, result *naming.Result, now time.Time) {
	failures := 0
	if existing != nil {
		failures = existing.GetConsecutiveFailures()
	}

	if !result.RetryAfter.IsZero() {
		t.writeSchedule(cid, existing, result, failures, result.RetryAfter)

		return
	}

	failures++

	if failures >= maxConsecutiveTransients {
		nextAttemptAt := now.Add(unavailableRetryDelay)
		row := failedRow(cid, result.Method,
			fmt.Sprintf("verification unavailable after %d consecutive transient failures; last: %s", maxConsecutiveTransients, result.Error))
		row.ConsecutiveFailures = failures
		row.NextAttemptAt = &nextAttemptAt

		t.writeVerdict(cid, existing, row)

		return
	}

	schedule := types.ScanSchedule{RetryBase: t.config.GetInterval(), RetryMax: maxRetryDelay}

	t.writeSchedule(cid, existing, result, failures, schedule.NextAttempt(now, failures))
}

// writeVerdict creates or replaces the record's row with a verdict.
func (t *Task) writeVerdict(cid string, existing types.NameVerificationObject, row *gormdb.NameVerification) {
	if existing == nil {
		if err := t.db.CreateNameVerification(row); err != nil {
			logger.Warn("Failed to create name verification", "cid", cid, "error", err)
		}

		return
	}

	if err := t.db.UpdateNameVerification(row); err != nil {
		logger.Warn("Failed to update name verification", "cid", cid, "error", err)
	}
}

// writeSchedule records the retry state of a transient failure. A record
// without a row gets a pending one; an existing row keeps its verdict.
func (t *Task) writeSchedule(cid string, existing types.NameVerificationObject, result *naming.Result, failures int, nextAttemptAt time.Time) {
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

		if err := t.db.CreateNameVerification(row); err != nil {
			logger.Warn("Failed to create pending name verification", "cid", cid, "error", err)
		}

		return
	}

	status, errMsg := scheduleStatus(existing, transientErr)

	row := &gormdb.NameVerification{
		RecordCID:           cid,
		Method:              existing.GetMethod(),
		KeyID:               existing.GetKeyID(),
		Status:              status,
		Error:               errMsg,
		Details:             existing.GetDetails(),
		VerifiedAt:          existing.GetVerifiedAt(),
		ConsecutiveFailures: failures,
		NextAttemptAt:       &nextAttemptAt,
	}

	if err := t.db.UpdateNameVerification(row); err != nil {
		logger.Warn("Failed to update name verification schedule", "cid", cid, "error", err)
	}
}

// scheduleStatus keeps a verdict through a transient failure: a verified row
// stays verified, a failed row stays failed with its own error, and any other
// row is pending. Returns the status and the error to store.
func scheduleStatus(existing types.NameVerificationObject, transientErr string) (string, string) {
	switch existing.GetStatus() {
	case gormdb.VerificationStatusVerified:
		return gormdb.VerificationStatusVerified, transientErr
	case gormdb.VerificationStatusFailed:
		return gormdb.VerificationStatusFailed, existing.GetError()
	default:
		return gormdb.VerificationStatusPending, transientErr
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
)

// outcome is what one record contributed to the run.
type outcome struct {
	kind     outcomeKind
	method   string
	protocol string
}

// runSummary aggregates the outcomes of one run for the completion log line.
type runSummary struct {
	verified, failed, transient, skipped int

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
	}
}

func (s *runSummary) log() {
	for protocol, count := range s.skippedByProtocol {
		logger.Warn("Skipped records whose name protocol has no verification method configured",
			"protocol", protocol,
			"count", count)
	}

	logger.Info("Name verification complete",
		"verified", s.verified,
		"failed", s.failed,
		"transient", s.transient,
		"skipped", s.skipped,
		"verifiedByMethod", s.verifiedByMethod,
		"failedByMethod", s.failedByMethod)
}
