package externalstate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/require"
)

func TestOwnershipRejectsStateLossAndConcurrentOwners(t *testing.T) {
	control, data, configs := provisionFixture(t)
	first, err := Open(control, data, "example.org", configs)
	require.NoError(t, err)
	require.True(t, first.IsFresh())
	_, err = Open(control, data, "example.org", configs)
	require.ErrorContains(t, err, "already owned")
	require.NoError(t, first.Close())

	second, err := Open(control, data, "example.org", configs)
	require.NoError(t, err)
	require.False(t, second.IsFresh())
	require.NoError(t, second.Close())

	require.NoError(t, os.Remove(filepath.Join(data, "external-x509", "owner.json")))
	_, err = Open(control, data, "example.org", configs)
	require.ErrorContains(t, err, "metadata is missing")
}

func TestProvisioningRejectsNamespaceAndIdentityChanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(string, string, catalog.PluginConfigs) (string, string, catalog.PluginConfigs)
	}{
		{name: "nested control", change: func(_, data string, configs catalog.PluginConfigs) (string, string, catalog.PluginConfigs) {
			return filepath.Join(data, "control"), data, configs
		}},
		{name: "issuer", change: func(control, data string, configs catalog.PluginConfigs) (string, string, catalog.PluginConfigs) {
			configs[0].Name = "another"
			return control, data, configs
		}},
		{name: "namespace", change: func(control, data string, configs catalog.PluginConfigs) (string, string, catalog.PluginConfigs) {
			configs[1].DataSource = catalog.FixedData("changed=true")
			return control, data, configs
		}},
		{name: "legacy data", change: func(control, data string, configs catalog.PluginConfigs) (string, string, catalog.PluginConfigs) {
			require.NoError(t, os.MkdirAll(data, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(data, "legacy"), nil, 0600))
			return control, data, configs
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control, data, configs := provisionFixture(t)
			control, data, configs = tc.change(control, data, configs)
			_, err := Open(control, data, "example.org", configs)
			require.Error(t, err)
		})
	}
}

func TestReadJSONRejectsAmbiguousAndUnsafeFiles(t *testing.T) {
	control := t.TempDir()
	path := filepath.Join(control, "state.json")
	require.NoError(t, WriteJSON(path, map[string]string{"value": "one"}))
	var out map[string]string
	require.NoError(t, ReadJSON(path, &out))
	require.NoError(t, os.WriteFile(path+".tmp", []byte(`{"value":"two"}`), 0600))
	require.ErrorContains(t, ReadJSON(path, &out), "ambiguous")
	require.ErrorContains(t, WriteJSON(path, out), "ambiguous")
	require.NoError(t, os.Remove(path+".tmp"))
	if runtime.GOOS != "windows" {
		require.NoError(t, os.Chmod(path, 0666))
		require.ErrorContains(t, ReadJSON(path, &out), "unsafe")
	}
}

func TestActivationBindsTheProvisioningIdentity(t *testing.T) {
	control, data, configs := provisionFixture(t)
	owner, err := Open(control, data, "example.org", configs)
	require.NoError(t, err)
	defer owner.Close()
	path := filepath.Join(control, "activate.json")
	require.NoError(t, WriteJSON(path, map[string]any{
		"version": 1, "binding": "another-instance", "authority_version": "v1",
	}))
	_, err = owner.ActivationVersion()
	require.ErrorContains(t, err, "mismatched")
	require.NoError(t, WriteJSON(path, map[string]any{
		"version": 1, "binding": owner.Binding(), "authority_version": "v1",
	}))
	version, err := owner.ActivationVersion()
	require.NoError(t, err)
	require.Equal(t, "v1", version)
}

func TestRetainedRootsCannotMutateProvisionedTrust(t *testing.T) {
	o := &owner{assertion: Assertion{RetainedRoots: [][]byte{{1, 2}, {3, 4}}}}
	roots := o.RetainedRoots()
	roots[0][0] = 9
	roots[1] = nil
	require.Equal(t, [][]byte{{1, 2}, {3, 4}}, o.RetainedRoots())
}

func provisionFixture(t *testing.T) (string, string, catalog.PluginConfigs) {
	t.Helper()
	control := t.TempDir()
	data := filepath.Join(t.TempDir(), "data")
	configs := catalog.PluginConfigs{
		{Type: "X509SVIDIssuer", Name: "issuer", Path: "/operator/issuer", Checksum: "checksum"},
		{Type: "KeyManager", Name: "memory", DataSource: catalog.FixedData("")},
	}
	digest, _, err := KeyManagerDigest(configs[1])
	require.NoError(t, err)
	require.NoError(t, WriteJSON(filepath.Join(control, "provision.json"), Assertion{
		Version: 1, TrustDomain: "example.org", Instance: "server-one",
		Issuer: "issuer", IssuerChecksum: "checksum", KeyManagerDigest: digest,
	}))
	return control, data, configs
}
