package catalog_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	commoncatalog "github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/server/catalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	for _, tt := range []struct {
		desc          string
		prepareConfig func(dir string, config *catalog.Config)
		expectErr     string
		expectLogs    []spiretest.LogEntry
	}{
		{
			desc: "join_token node attestor cannot be overridden",
			prepareConfig: func(dir string, config *catalog.Config) {
				for i, pluginConfig := range config.PluginConfigs {
					if pluginConfig.Type == "NodeAttestor" && pluginConfig.Name == "join_token" {
						config.PluginConfigs[i].Path = filepath.Join(dir, "does-not-exist")
					}
				}
			},
			expectErr: "the built-in join_token node attestor cannot be overridden by an external plugin",
		},
		{
			desc: "datastore cannot be overridden",
			prepareConfig: func(dir string, config *catalog.Config) {
				for i, pluginConfig := range config.PluginConfigs {
					if pluginConfig.Type == "DataStore" {
						config.PluginConfigs[i].Path = filepath.Join(dir, "does-not-exist")
					}
				}
			},
			expectErr: `pluggability for the DataStore is deprecated; only the built-in "sql" plugin is supported`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			dir := t.TempDir()
			log, hook := test.NewNullLogger()

			config := catalog.Config{
				Log:           log,
				HealthChecker: fakeHealthChecker{},
				PluginConfigs: catalog.PluginConfigs{
					{
						Type: "DataStore",
						Name: "sql",
						DataSource: commoncatalog.FixedData(fmt.Sprintf(`
						database_type = "sqlite3"
						connection_string = %q
					`, filepath.Join(dir, "test.sql"))),
					},
					{
						Type: "KeyManager",
						Name: "memory",
					},
					{
						Type: "NodeAttestor",
						Name: "join_token",
					},
				},
			}
			if tt.prepareConfig != nil {
				tt.prepareConfig(dir, &config)
			}
			repo, err := catalog.Load(context.Background(), config)
			if repo != nil {
				repo.Close()
			}
			spiretest.AssertLogsContainEntries(t, hook.AllEntries(), tt.expectLogs)
			if tt.expectErr != "" {
				require.EqualError(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestExternalIssuerPluginExclusion(t *testing.T) {
	for _, tt := range []struct {
		name             string
		issuerDisabled   bool
		upstreamDisabled bool
		conflict         bool
	}{
		{name: "both enabled", conflict: true},
		{name: "issuer disabled", issuerDisabled: true},
		{name: "upstream disabled", upstreamDisabled: true},
		{name: "both disabled", issuerDisabled: true, upstreamDisabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := catalog.Config{PluginConfigs: catalog.PluginConfigs{
				{Type: "X509SVIDIssuer", Name: "any-issuer", Disabled: tt.issuerDisabled},
				{Type: "UpstreamAuthority", Name: "any-upstream", Disabled: tt.upstreamDisabled},
			}}
			// A conflict must be rejected even before the missing datastore
			// and host services can cause configuration side effects.
			_, err := catalog.Load(t.Context(), config)
			if tt.conflict {
				require.EqualError(t, err, "X509SVIDIssuer and UpstreamAuthority cannot both be enabled")
				_, err = catalog.ValidateConfig(t.Context(), config)
				require.EqualError(t, err, "X509SVIDIssuer and UpstreamAuthority cannot both be enabled")
			} else {
				require.EqualError(t, err, "expecting a DataStore plugin")
			}
		})
	}
}

type fakeHealthChecker struct{}

func (fakeHealthChecker) AddCheck(string, health.Checkable) error { return nil }
