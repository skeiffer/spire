package catalog_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/stretchr/testify/require"
)

func TestExternalWorkloadKeyProviderLifecycle(t *testing.T) {
	path := os.Getenv("SPIRE_TEST_WORKLOAD_KEY_PROVIDER")
	identity := os.Getenv("SPIRE_TEST_WORKLOAD_KEY_IDENTITY")
	prefix := os.Getenv("SPIRE_TEST_WORKLOAD_KEY_PREFIX")
	if path == "" || identity == "" {
		t.Skip("external WorkloadKeyProvider test inputs are not configured")
	}
	if prefix == "" {
		t.Fatal("external WorkloadKeyProvider key prefix is not configured")
	}

	log, _ := test.NewNullLogger()
	repo, err := catalog.Load(context.Background(), catalog.Config{
		Log:         log,
		TrustDomain: spiffeid.RequireTrustDomainFromString("example.org"),
		Metrics:     fakemetrics.New(),
		PluginConfigs: catalog.PluginConfigs{
			{Type: "KeyManager", Name: "memory"},
			{Type: "NodeAttestor", Name: "join_token"},
			{Type: "WorkloadAttestor", Name: "windows"},
			{
				Type: "WorkloadKeyProvider",
				Name: "external",
				Path: path,
				Args: []string{"-identity", identity, "-key-prefix", prefix},
			},
		},
	})
	require.NoError(t, err)
	t.Cleanup(repo.Close)

	provider := repo.GetWorkloadKeyProvider()
	require.NotNil(t, provider)
	key, err := provider.GenerateKey(context.Background(), workloadkeyprovider.GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 1,
	})
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("external-provider"))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	publicKey, ok := key.Public().(*rsa.PublicKey)
	require.True(t, ok)
	require.NoError(t, rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature))

	replacement, err := provider.GenerateKey(context.Background(), workloadkeyprovider.GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 2,
	})
	require.NoError(t, err)

	releaser, ok := provider.(interface {
		ReleaseKey(context.Context, []byte, uint64) error
	})
	require.True(t, ok)
	require.NoError(t, releaser.ReleaseKey(context.Background(), key.Reference(), key.Generation()))
	require.NoError(t, releaser.ReleaseKey(context.Background(), replacement.Reference(), replacement.Generation()))
	_, err = key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.Error(t, err)
}
