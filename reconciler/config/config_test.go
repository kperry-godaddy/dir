// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"

	dbconfig "github.com/agntcy/dir/server/database/config"
	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_NoFile_ReturnsDefaults(t *testing.T) {
	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Database defaults
	assert.Equal(t, dbconfig.DefaultType, cfg.Database.Type)
	assert.Equal(t, dbconfig.DefaultPostgresHost, cfg.Database.Postgres.Host)
	assert.Equal(t, dbconfig.DefaultPostgresPort, cfg.Database.Postgres.Port)
	assert.Equal(t, dbconfig.DefaultPostgresDatabase, cfg.Database.Postgres.Database)
	assert.Equal(t, dbconfig.DefaultPostgresSSLMode, cfg.Database.Postgres.SSLMode)

	// Task defaults
	assert.True(t, cfg.Regsync.Enabled)
	assert.True(t, cfg.Indexer.Enabled)
	assert.False(t, cfg.Name.Enabled)
	assert.False(t, cfg.Name.ANS.Enabled)
	assert.False(t, cfg.Name.ANS.AllowUnpinnedRootKeys)
	assert.Equal(t, ansconfig.DefaultTimeout, cfg.Name.ANS.Timeout)
	assert.Empty(t, cfg.Name.ANS.TrustedLogHosts)
	assert.Empty(t, cfg.Name.ANS.RootKeys)
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	t.Setenv("RECONCILER_REGSYNC_ENABLED", "false")
	t.Setenv("RECONCILER_INDEXER_ENABLED", "false")
	t.Setenv("RECONCILER_NAME_ENABLED", "true")
	t.Setenv("RECONCILER_INDEXER_INTERVAL", "2h")
	t.Setenv("RECONCILER_NAME_INTERVAL", "30m")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.False(t, cfg.Regsync.Enabled)
	assert.False(t, cfg.Indexer.Enabled)
	assert.True(t, cfg.Name.Enabled)
	assert.Equal(t, 2*time.Hour, cfg.Indexer.Interval)
	assert.Equal(t, 30*time.Minute, cfg.Name.Interval)
}

func TestLoadConfig_NameANSEnvOverrides(t *testing.T) {
	t.Setenv("RECONCILER_NAME_ANS_ENABLED", "true")
	t.Setenv("RECONCILER_NAME_ANS_TRUSTED_LOG_HOSTS", "a:443,b")
	t.Setenv("RECONCILER_NAME_ANS_ROOT_KEYS", "log.example.com+01234567+AAAA,other.example.com+89abcdef+BBBB")
	t.Setenv("RECONCILER_NAME_ANS_ALLOW_UNPINNED_ROOT_KEYS", "true")
	t.Setenv("RECONCILER_NAME_ANS_TIMEOUT", "5s")
	t.Setenv("RECONCILER_NAME_ANS_DNS_SERVER", "127.0.0.1:15353")
	t.Setenv("RECONCILER_NAME_ANS_CA_FILE", "/etc/agntcy/reconciler/ans-ca.pem")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.True(t, cfg.Name.ANS.Enabled)
	assert.Equal(t, []string{"a:443", "b"}, cfg.Name.ANS.TrustedLogHosts)
	assert.Equal(t, []string{"log.example.com+01234567+AAAA", "other.example.com+89abcdef+BBBB"}, cfg.Name.ANS.RootKeys)
	assert.True(t, cfg.Name.ANS.AllowUnpinnedRootKeys)
	assert.Equal(t, 5*time.Second, cfg.Name.ANS.Timeout)
	assert.Equal(t, "127.0.0.1:15353", cfg.Name.ANS.DNSServer)
	assert.Equal(t, "/etc/agntcy/reconciler/ans-ca.pem", cfg.Name.ANS.CAFile)
}
