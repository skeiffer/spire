package workloadkey_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompanionProtocolIsProviderNeutral(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "proto", "private")
	neutral := filepath.Join(root, "spire", "agent", "workloadkey", "v1", "x509_key_backed_workload.proto")
	contents, err := os.ReadFile(neutral)
	require.NoError(t, err)

	contract := strings.ToLower(string(contents))
	for _, forbidden := range []string{
		"hse",
		"keyguard",
		"ncrypt",
		"software ksp",
		"servicetree",
		"local_cng",
		"agent_sign_rpc",
		"private_key",
		"x509_svid_key",
		"pkcs8",
		"pfx",
	} {
		require.NotContains(t, contract, forbidden)
	}
	require.Contains(t, contract, "key_operation_mode_local_reference")
	require.Contains(t, contract, "key_operation_mode_remote_sign")
	require.NoFileExists(t, filepath.Join(root, "hse", "workloadkey", "v1", "x509_key_backed_workload.proto"))
}
