// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package types

import "time"

// NameVerificationRetryState is the retry bookkeeping of a name verification.
// It is written on transient failures without touching the verdict columns.
type NameVerificationRetryState interface {
	// GetConsecutiveFailures counts transient failures since the last verdict.
	GetConsecutiveFailures() int

	// GetNextAttemptAt is the scheduled retry after a transient failure, nil
	// when the row is governed by the TTL alone.
	GetNextAttemptAt() *time.Time
}

// NameVerificationObject represents a name verification result.
type NameVerificationObject interface {
	NameVerificationRetryState

	GetRecordCID() string
	GetMethod() string
	GetKeyID() string
	GetStatus() string
	GetError() string

	// GetDetails is method-specific JSON recorded with a verified result,
	// empty when the method records none.
	GetDetails() string

	// GetVerifiedAt is when the record last verified successfully, nil when
	// it never has.
	GetVerifiedAt() *time.Time

	GetCreatedAt() time.Time
	GetUpdatedAt() time.Time
}
