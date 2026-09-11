// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package name

import (
	"testing"
	"time"

	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	naming "github.com/agntcy/dir/server/naming/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_GetInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{"zero uses default", 0, DefaultInterval},
		{"custom interval", 15 * time.Minute, 15 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{Interval: tt.interval}
			assert.Equal(t, tt.want, c.GetInterval())
		})
	}
}

func TestConfig_GetTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"zero uses default", 0, naming.DefaultTTL},
		{"custom TTL", 24 * time.Hour, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{TTL: tt.ttl}
			assert.Equal(t, tt.want, c.GetTTL())
		})
	}
}

func TestConfig_GetRecordTimeout(t *testing.T) {
	tests := []struct {
		name          string
		recordTimeout time.Duration
		want          time.Duration
	}{
		{"zero uses default", 0, DefaultRecordTimeout},
		{"custom timeout", 10 * time.Second, 10 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{RecordTimeout: tt.recordTimeout}
			assert.Equal(t, tt.want, c.GetRecordTimeout())
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:   "ans disabled needs nothing",
			config: Config{},
		},
		{
			name: "ans enabled with a lookup budget inside the record budget",
			config: Config{
				RecordTimeout: 30 * time.Second,
				ANS:           ansconfig.Config{Enabled: true, TrustedLogHosts: []string{"log.example.com"}, RootKeys: []string{"log.example.com+01234567+AAAA"}, Timeout: 10 * time.Second},
			},
		},
		{
			name: "ans enabled with default budgets",
			config: Config{
				ANS: ansconfig.Config{Enabled: true, TrustedLogHosts: []string{"log.example.com"}, RootKeys: []string{"log.example.com+01234567+AAAA"}},
			},
		},
		{
			name: "ans timeout equal to the record timeout is rejected",
			config: Config{
				RecordTimeout: 10 * time.Second,
				ANS:           ansconfig.Config{Enabled: true, TrustedLogHosts: []string{"log.example.com"}, RootKeys: []string{"log.example.com+01234567+AAAA"}, Timeout: 10 * time.Second},
			},
			wantErr: "ans.timeout (10s) must be shorter than record_timeout (10s)",
		},
		{
			name: "ans timeout above the record timeout is rejected",
			config: Config{
				RecordTimeout: 5 * time.Second,
				ANS:           ansconfig.Config{Enabled: true, TrustedLogHosts: []string{"log.example.com"}, RootKeys: []string{"log.example.com+01234567+AAAA"}},
			},
			wantErr: "ans.timeout (10s) must be shorter than record_timeout (5s)",
		},
		{
			name: "ans configuration errors are reported",
			config: Config{
				ANS: ansconfig.Config{Enabled: true},
			},
			wantErr: "trusted_log_hosts must list at least one transparency-log host",
		},
		{
			name: "ans timeout is not checked while ans is disabled",
			config: Config{
				RecordTimeout: time.Second,
				ANS:           ansconfig.Config{Timeout: time.Minute},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.wantErr == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
