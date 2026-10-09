package workloadkey

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	workloadkeyv1 "github.com/spiffe/spire/proto/private/spire/agent/workloadkey/v1"
	"github.com/stretchr/testify/require"
)

func TestBuildCapabilityForwardsLocalReferenceWithoutRemoteSignCapability(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	reference := []byte("cng-v1:run-owned-key")
	key := workloadkeyprovider.NewKeyWithMode(
		privateKey,
		reference,
		4,
		workloadkeyprovider.LocalReferenceMode,
	)
	handler := New(Config{})

	capability, err := handler.buildCapability(
		Binding{WorkloadID: "spiffe://example.org/workload", ProcessID: 101},
		key,
		time.Now().Add(time.Minute),
	)

	require.NoError(t, err)
	require.Equal(t, reference, capability.Id)
	require.Equal(t, uint64(4), capability.Generation)
	require.Equal(t, workloadkeyv1.KeyOperationMode_KEY_OPERATION_MODE_LOCAL_REFERENCE, capability.Mode)
	require.Empty(t, handler.store.capabilities)
}

func TestBuildCapabilityKeepsRemoteSignReferencesMemoryOnly(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key := workloadkeyprovider.NewKey(privateKey, []byte("provider-reference"), 5)
	handler := New(Config{})

	capability, err := handler.buildCapability(
		Binding{WorkloadID: "spiffe://example.org/workload", ProcessID: 101},
		key,
		time.Now().Add(time.Minute),
	)

	require.NoError(t, err)
	require.Len(t, capability.Id, 32)
	require.NotEqual(t, key.Reference(), capability.Id)
	require.Equal(t, workloadkeyv1.KeyOperationMode_KEY_OPERATION_MODE_REMOTE_SIGN, capability.Mode)
	require.Len(t, handler.store.capabilities, 1)
}
