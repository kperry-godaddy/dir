// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"fmt"
	"time"

	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	namingconfig "github.com/agntcy/dir/server/naming/config"
)

const (
	// DefaultInterval is the default reconciliation interval for name verification.
	DefaultInterval = 1 * time.Hour

	// DefaultRecordTimeout is the default timeout for each name verification operation.
	DefaultRecordTimeout = 30 * time.Second
)

// Config holds the configuration for the name reconciliation task.
// Distinct from the signature task (signature verification).
type Config struct {
	// Enabled determines if the name task should run.
	Enabled bool `json:"enabled,omitempty" mapstructure:"enabled"`

	// Interval is how often to run name verification.
	Interval time.Duration `json:"interval,omitempty" mapstructure:"interval"`

	// TTL is the time-to-live for name verification results; records are re-verified after expiry.
	TTL time.Duration `json:"ttl,omitempty" mapstructure:"ttl"`

	// RecordTimeout is the timeout for each individual name verification operation.
	RecordTimeout time.Duration `json:"record_timeout,omitempty" mapstructure:"record_timeout"`

	// ANS configures Agent Name Service verification for ans:// names.
	ANS ansconfig.Config `json:"ans" mapstructure:"ans"`
}

// GetInterval returns the interval with default fallback.
func (c *Config) GetInterval() time.Duration {
	if c.Interval == 0 {
		return DefaultInterval
	}

	return c.Interval
}

// GetTTL returns the TTL with default fallback.
// The default is shared with the API server (server/naming.DefaultTTL) so both services use the same expiry.
func (c *Config) GetTTL() time.Duration {
	if c.TTL == 0 {
		return namingconfig.DefaultTTL
	}

	return c.TTL
}

// GetRecordTimeout returns the per-record timeout with default fallback.
func (c *Config) GetRecordTimeout() time.Duration {
	if c.RecordTimeout == 0 {
		return DefaultRecordTimeout
	}

	return c.RecordTimeout
}

// Validate checks the task configuration, including the ANS method's, and
// normalizes the ANS settings in place. One ANS lookup must fit inside the
// per-record budget, otherwise the record deadline would cut every lookup
// short and report it as a transient failure.
func (c *Config) Validate() error {
	if err := c.ANS.Validate(); err != nil {
		return fmt.Errorf("name task: %w", err)
	}

	if c.ANS.Enabled && c.ANS.GetTimeout() >= c.GetRecordTimeout() {
		return fmt.Errorf("name task: ans.timeout (%s) must be shorter than record_timeout (%s)", c.ANS.GetTimeout(), c.GetRecordTimeout())
	}

	return nil
}
