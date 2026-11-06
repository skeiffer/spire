package x509svidissuer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuthorityStoreStagesSuccessorUntilExplicitActivation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldRoot := newTestRoot(t, now, "old", now.Add(time.Hour))
	newRoot := newTestRoot(t, now, "new", now.Add(2*time.Hour))
	store := NewAuthorityStore(24*time.Hour, 8)

	require.NoError(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{oldRoot}, Chains: [][]*x509.Certificate{{oldRoot}}}))
	require.NoError(t, store.Activate("v1", now))
	require.NoError(t, store.Publish(Snapshot{Version: "v2", Roots: []*x509.Certificate{newRoot}, Chains: [][]*x509.Certificate{{newRoot}}}))
	require.Equal(t, "v1", store.ActiveVersion())
	require.ElementsMatch(t, []*x509.Certificate{oldRoot, newRoot}, store.BundleRoots(now))

	require.NoError(t, store.Activate("v2", now))
	require.Equal(t, "v2", store.ActiveVersion())
	require.ElementsMatch(t, []*x509.Certificate{oldRoot, newRoot}, store.BundleRoots(now))
	require.ElementsMatch(t, []*x509.Certificate{newRoot}, store.BundleRoots(oldRoot.NotAfter.Add(24*time.Hour)))
}

func TestAuthorityStoreRejectsVersionReuseAndHistoryOverflow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := NewAuthorityStore(24*time.Hour, 1)
	require.NoError(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{newTestRoot(t, now, "one", now.Add(time.Hour))}}))
	require.ErrorIs(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{newTestRoot(t, now, "two", now.Add(time.Hour))}}), ErrVersionReused)
	require.ErrorIs(t, store.Publish(Snapshot{Version: "v2", Roots: []*x509.Certificate{newTestRoot(t, now, "three", now.Add(time.Hour))}}), ErrHistoryLimit)
}

func newTestRoot(t *testing.T, now time.Time, name string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key := newTestKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	return createTestCertificate(t, template, template, key.Public(), key)
}
