package manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/stretchr/testify/require"
)

func TestNewCSRDispatchesOpaqueRequiredEntryBeforeCSRCreation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var requests []workloadkeyprovider.GenerateRequest
	m := &manager{
		c: &Config{
			WorkloadKeyProvider: workloadkeyprovider.ProviderFunc(func(_ context.Context, request workloadkeyprovider.GenerateRequest) (workloadkeyprovider.Key, error) {
				requests = append(requests, request)
				return workloadkeyprovider.NewKey(key, []byte("provider-reference"), request.Generation), nil
			}),
		},
		keyGenerations: make(map[string]uint64),
	}
	id := spiffeid.RequireFromString("spiffe://example.org/workload")

	signer, csr, err := m.newCSR(context.Background(), "entry-id", id, true)
	require.NoError(t, err)
	require.True(t, workloadkeyprovider.IsOpaque(signer))
	require.NotEmpty(t, csr)
	require.Equal(t, []workloadkeyprovider.GenerateRequest{{
		WorkloadID: id.String(),
		Generation: 1,
	}}, requests)

	_, _, err = m.newCSR(context.Background(), "entry-id", id, true)
	require.NoError(t, err)
	require.Equal(t, uint64(2), requests[1].Generation)
}

func TestNewCSRPersistsOpaqueGenerationAcrossManagerRestart(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sto, err := storage.Open(t.TempDir())
	require.NoError(t, err)
	var requests []workloadkeyprovider.GenerateRequest
	provider := workloadkeyprovider.ProviderFunc(func(_ context.Context, request workloadkeyprovider.GenerateRequest) (workloadkeyprovider.Key, error) {
		requests = append(requests, request)
		return workloadkeyprovider.NewKey(key, []byte("provider-reference"), request.Generation), nil
	})
	id := spiffeid.RequireFromString("spiffe://example.org/workload")

	first := &manager{
		c:              &Config{Storage: sto, WorkloadKeyProvider: provider},
		keyGenerations: make(map[string]uint64),
	}
	_, _, err = first.newCSR(context.Background(), "entry-id", id, true)
	require.NoError(t, err)

	second := &manager{
		c:              &Config{Storage: sto, WorkloadKeyProvider: provider},
		keyGenerations: make(map[string]uint64),
	}
	_, _, err = second.newCSR(context.Background(), "entry-id", id, true)
	require.NoError(t, err)
	require.Equal(t, []uint64{1, 2}, []uint64{
		requests[0].Generation,
		requests[1].Generation,
	})
}

func TestNewCSRRequiredOpaqueFailsClosedWithoutProvider(t *testing.T) {
	m := &manager{c: &Config{}, keyGenerations: make(map[string]uint64)}
	_, _, err := m.newCSR(
		context.Background(),
		"entry-id",
		spiffeid.RequireFromString("spiffe://example.org/workload"),
		true)
	require.EqualError(t, err, "opaque workload key is required but no WorkloadKeyProvider is configured")
}
