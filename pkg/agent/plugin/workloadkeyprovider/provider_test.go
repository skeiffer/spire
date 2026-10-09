package workloadkeyprovider_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/stretchr/testify/require"
)

func TestProviderKeyCreatesCSRWithoutPrivateKeySerialization(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	provider := workloadkeyprovider.ProviderFunc(func(context.Context, workloadkeyprovider.GenerateRequest) (workloadkeyprovider.Key, error) {
		return workloadkeyprovider.NewKey(key, []byte("opaque-reference"), 7), nil
	})

	opaque, err := provider.GenerateKey(context.Background(), workloadkeyprovider.GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 7,
	})
	require.NoError(t, err)
	require.Equal(t, uint64(7), opaque.Generation())
	require.True(t, workloadkeyprovider.IsOpaque(opaque))

	digest := sha256.Sum256([]byte("provider-dispatch"))
	signature, err := opaque.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
	require.Equal(t, []byte("opaque-reference"), opaque.Reference())
}
