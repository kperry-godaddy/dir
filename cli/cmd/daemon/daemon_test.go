// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	storeconfig "github.com/agntcy/dir/server/store/oci/config"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigUsesMacOSFriendlyLocalRegistryPort(t *testing.T) {
	originalOpts := opts
	opts = &Options{DataDir: t.TempDir()}
	t.Cleanup(func() {
		opts = originalOpts
	})

	cfg, err := loadConfig()

	require.NoError(t, err)
	require.Equal(t, "localhost:5555", cfg.Server.Store.OCI.RegistryAddress)
	require.Equal(t, "localhost:5555", cfg.Reconciler.LocalRegistry.RegistryAddress)
}

// TestLoadConfigRepublishIntervalEnvOverride asserts that the routing republish
// interval can be overridden by environment alone. AutomaticEnv only resolves
// keys viper already knows, so this depends on the key being declared in the
// embedded daemon.config.yaml.
func TestLoadConfigRepublishIntervalEnvOverride(t *testing.T) {
	originalOpts := opts
	opts = &Options{DataDir: t.TempDir()}
	t.Cleanup(func() {
		opts = originalOpts
	})

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.Equal(t, 36*time.Hour, cfg.Server.Routing.RepublishInterval)

	t.Setenv("DIRECTORY_DAEMON_SERVER_ROUTING_REPUBLISH_INTERVAL", "10m")

	cfg, err = loadConfig()
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, cfg.Server.Routing.RepublishInterval)
}

// TestLoadConfigRoutingAddressEnvOverride asserts that the advertised routing
// endpoints can be set by environment alone. They have no default and are absent
// from the embedded daemon.config.yaml, so this depends on them being registered
// in registerServerDefaults.
func TestLoadConfigRoutingAddressEnvOverride(t *testing.T) {
	originalOpts := opts
	opts = &Options{DataDir: t.TempDir()}
	t.Cleanup(func() {
		opts = originalOpts
	})

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.Server.Routing.DirectoryAPIAddress)
	require.Empty(t, cfg.Server.Routing.DirectoryOCIAddress)

	t.Setenv("DIRECTORY_DAEMON_SERVER_ROUTING_DIRECTORY_API_ADDRESS", "dir.example.com:8888")
	t.Setenv("DIRECTORY_DAEMON_SERVER_ROUTING_DIRECTORY_OCI_ADDRESS", "ghcr.io/org/agents")

	cfg, err = loadConfig()
	require.NoError(t, err)
	require.Equal(t, "dir.example.com:8888", cfg.Server.Routing.DirectoryAPIAddress)
	require.Equal(t, "ghcr.io/org/agents", cfg.Server.Routing.DirectoryOCIAddress)
}

// TestLoadConfigRoutingAddressEnvOverrideWithUserConfig asserts the same holds
// for a user-supplied config file that does not declare the keys, since --config
// is read as-is without merging the embedded defaults.
func TestLoadConfigRoutingAddressEnvOverrideWithUserConfig(t *testing.T) {
	originalOpts := opts
	dataDir := t.TempDir()

	configPath := filepath.Join(dataDir, DefaultConfigFile)
	require.NoError(t, os.WriteFile(configPath, []byte(defaultConfigYAML), 0o600))

	opts = &Options{DataDir: dataDir, ConfigFile: configPath}

	t.Cleanup(func() {
		opts = originalOpts
	})

	t.Setenv("DIRECTORY_DAEMON_SERVER_ROUTING_DIRECTORY_OCI_ADDRESS", "ghcr.io/org/agents")

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.Equal(t, "ghcr.io/org/agents", cfg.Server.Routing.DirectoryOCIAddress)
}

// TestLoadConfigExtractorEnvOverride asserts the extractor settings can be set
// by environment alone. They have no defaults and are absent from the embedded
// daemon.config.yaml, so this depends on them being registered in
// registerServerDefaults — AutomaticEnv cannot discover keys Viper has never
// seen.
func TestLoadConfigExtractorEnvOverride(t *testing.T) {
	originalOpts := opts
	opts = &Options{DataDir: t.TempDir()}
	t.Cleanup(func() {
		opts = originalOpts
	})

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.Server.Extractor.RemoteAddr)
	require.Empty(t, cfg.Server.Extractor.AssetDir)
	require.Empty(t, cfg.Server.Extractor.OASFURL)

	t.Setenv("DIRECTORY_DAEMON_SERVER_EXTRACTOR_REMOTE_ADDR", "localhost:31234")
	t.Setenv("DIRECTORY_DAEMON_SERVER_EXTRACTOR_ASSET_DIR", "/tmp/assets")
	t.Setenv("DIRECTORY_DAEMON_SERVER_EXTRACTOR_OASF_URL", "https://schema.example.com")

	cfg, err = loadConfig()
	require.NoError(t, err)
	require.Equal(t, "localhost:31234", cfg.Server.Extractor.RemoteAddr)
	require.Equal(t, "/tmp/assets", cfg.Server.Extractor.AssetDir)
	require.Equal(t, "https://schema.example.com", cfg.Server.Extractor.OASFURL)
}

// TestLoadConfigExtractorEnvOverrideWithUserConfig asserts the same holds for a
// user-supplied config file that does not declare the keys, since --config is
// read as-is without merging the embedded defaults.
func TestLoadConfigExtractorEnvOverrideWithUserConfig(t *testing.T) {
	originalOpts := opts
	dataDir := t.TempDir()

	configPath := filepath.Join(dataDir, DefaultConfigFile)
	require.NoError(t, os.WriteFile(configPath, []byte(defaultConfigYAML), 0o600))

	opts = &Options{DataDir: dataDir, ConfigFile: configPath}

	t.Cleanup(func() {
		opts = originalOpts
	})

	t.Setenv("DIRECTORY_DAEMON_SERVER_EXTRACTOR_REMOTE_ADDR", "oasf-sdk:31234")

	cfg, err := loadConfig()
	require.NoError(t, err)
	require.Equal(t, "oasf-sdk:31234", cfg.Server.Extractor.RemoteAddr)
}

// TestLoadConfigLocalRegistryCredentialEnvOverride asserts that the reconciler
// local registry credentials can be set by environment alone, including for a
// user-supplied config file that does not declare them, so a token never has to
// be written into the config.
func TestLoadConfigLocalRegistryCredentialEnvOverride(t *testing.T) {
	dataDir := t.TempDir()

	configPath := filepath.Join(dataDir, DefaultConfigFile)
	require.NoError(t, os.WriteFile(configPath, []byte(defaultConfigYAML), 0o600))

	for name, configFile := range map[string]string{
		"embedded config":    "",
		"user-supplied file": configPath,
	} {
		t.Run(name, func(t *testing.T) {
			originalOpts := opts
			opts = &Options{DataDir: dataDir, ConfigFile: configFile}

			t.Cleanup(func() {
				opts = originalOpts
			})

			cfg, err := loadConfig()
			require.NoError(t, err)
			require.Empty(t, cfg.Reconciler.LocalRegistry.Username)
			require.Empty(t, cfg.Reconciler.LocalRegistry.Password)

			t.Setenv("DIRECTORY_DAEMON_RECONCILER_LOCAL_REGISTRY_AUTH_CONFIG_USERNAME", "registry-user")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_LOCAL_REGISTRY_AUTH_CONFIG_PASSWORD", "registry-token")

			cfg, err = loadConfig()
			require.NoError(t, err)
			require.Equal(t, "registry-user", cfg.Reconciler.LocalRegistry.Username)
			require.Equal(t, "registry-token", cfg.Reconciler.LocalRegistry.Password)
		})
	}
}

// TestEmbeddedZot tests the embedded Zot server.
func TestEmbeddedZot(t *testing.T) {
	address := storeconfig.DefaultRegistryAddress
	rootDirectory := "/tmp/agntcy/dir/oci/"

	go func() {
		ctx := runEmbeddedZot(context.Background(), address, rootDirectory)

		defer ctx.Done()
	}()

	var (
		zotIsReady bool
		err        error
	)

	for range 10 {
		zotIsReady, err = isZotReady(address)
		if err == nil && zotIsReady {
			break
		}

		time.Sleep(1 * time.Second)
	}

	require.NoError(t, err)
	require.True(t, zotIsReady)
}

// TestLoadConfigReconcilerNameANSEnvOverride asserts every ANS name-verification
// key can be set by environment alone, for the embedded defaults and for a
// user-supplied config file that does not declare the ans block.
func TestLoadConfigReconcilerNameANSEnvOverride(t *testing.T) {
	dataDir := t.TempDir()

	configPath := filepath.Join(dataDir, DefaultConfigFile)
	require.NoError(t, os.WriteFile(configPath, []byte(defaultConfigYAML), 0o600))

	for name, configFile := range map[string]string{
		"embedded config":    "",
		"user-supplied file": configPath,
	} {
		t.Run(name, func(t *testing.T) {
			originalOpts := opts
			opts = &Options{DataDir: dataDir, ConfigFile: configFile}

			t.Cleanup(func() {
				opts = originalOpts
			})

			cfg, err := loadConfig()
			require.NoError(t, err)
			require.False(t, cfg.Reconciler.Name.ANS.Enabled)
			require.Empty(t, cfg.Reconciler.Name.ANS.TrustedLogHosts)
			require.Empty(t, cfg.Reconciler.Name.ANS.RootKeys)
			require.False(t, cfg.Reconciler.Name.ANS.AllowUnpinnedRootKeys)
			require.Equal(t, ansconfig.DefaultTimeout, cfg.Reconciler.Name.ANS.Timeout)
			require.Empty(t, cfg.Reconciler.Name.ANS.DNSServer)
			require.Empty(t, cfg.Reconciler.Name.ANS.CAFile)

			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_ENABLED", "true")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_TRUSTED_LOG_HOSTS", "a:443,b:443")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_ROOT_KEYS", "origin+abcd1234+AAAA,origin+ef012345+BBBB")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_ALLOW_UNPINNED_ROOT_KEYS", "true")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_TIMEOUT", "30s")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_DNS_SERVER", "127.0.0.1:15353")
			t.Setenv("DIRECTORY_DAEMON_RECONCILER_NAME_ANS_CA_FILE", "ans/ca.pem")

			cfg, err = loadConfig()
			require.NoError(t, err)
			require.True(t, cfg.Reconciler.Name.ANS.Enabled)
			require.Equal(t, []string{"a:443", "b:443"}, cfg.Reconciler.Name.ANS.TrustedLogHosts)
			require.Equal(t, []string{"origin+abcd1234+AAAA", "origin+ef012345+BBBB"}, cfg.Reconciler.Name.ANS.RootKeys)
			require.True(t, cfg.Reconciler.Name.ANS.AllowUnpinnedRootKeys)
			require.Equal(t, 30*time.Second, cfg.Reconciler.Name.ANS.Timeout)
			require.Equal(t, "127.0.0.1:15353", cfg.Reconciler.Name.ANS.DNSServer)
			require.Equal(t, filepath.Join(dataDir, "ans/ca.pem"), cfg.Reconciler.Name.ANS.CAFile)
		})
	}
}

// TestResolveRelativePaths asserts every path setting is resolved against the
// data directory when relative and left alone when absolute or empty.
func TestResolveRelativePaths(t *testing.T) {
	dataDir := t.TempDir()

	originalOpts := opts
	opts = &Options{DataDir: dataDir}

	t.Cleanup(func() {
		opts = originalOpts
	})

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "relative path joins the data dir",
			path: filepath.Join("ans", "ca.pem"),
			want: filepath.Join(dataDir, "ans", "ca.pem"),
		},
		{
			name: "absolute path is kept",
			path: filepath.Join(string(filepath.Separator), "etc", "ans", "ca.pem"),
			want: filepath.Join(string(filepath.Separator), "etc", "ans", "ca.pem"),
		},
		{
			name: "empty path is left for the service default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &DaemonConfig{}
			cfg.Server.Store.OCI.LocalDir = tt.path
			cfg.Server.Routing.KeyPath = tt.path
			cfg.Server.Routing.DatastoreDir = tt.path
			cfg.Server.Database.SQLite.Path = tt.path
			cfg.Reconciler.Name.ANS.CAFile = tt.path

			resolveRelativePaths(cfg)

			for key, got := range map[string]string{
				"server.store.oci.local_dir":   cfg.Server.Store.OCI.LocalDir,
				"server.routing.key_path":      cfg.Server.Routing.KeyPath,
				"server.routing.datastore_dir": cfg.Server.Routing.DatastoreDir,
				"server.database.sqlite.path":  cfg.Server.Database.SQLite.Path,
				"reconciler.name.ans.ca_file":  cfg.Reconciler.Name.ANS.CAFile,
			} {
				require.Equal(t, tt.want, got, key)
			}
		})
	}
}
