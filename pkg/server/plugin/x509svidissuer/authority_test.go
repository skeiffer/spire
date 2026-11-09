package x509svidissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
)

func TestAuthorityPreparationAndDisjointRollover(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root1 := makeRoot(t, "root-1", now.Add(-time.Hour), now.Add(time.Hour))
	root2 := makeRoot(t, "root-2", now.Add(-time.Hour), now.Add(2*time.Hour))
	store := NewAuthorityStore()
	observed := map[string]bool{"v1": true, "v2": true}
	first, err := SnapshotFromProto(authoritySnapshot("v1", root1, now))
	require.NoError(t, err)
	next, err := SnapshotFromProto(authoritySnapshot("v2", root2, now))
	require.NoError(t, err)
	require.NoError(t, store.publish(first, now))
	store.selectActive(now, observed)
	require.Empty(t, store.active, "uncommitted authority must not activate")
	store.records["v1"].committed = true
	store.selectActive(now, observed)
	require.Equal(t, "v1", store.active)
	require.NoError(t, store.publish(next, now))
	store.records["v2"].committed = true
	store.selectActive(now.Add(50*time.Minute-time.Nanosecond), observed)
	require.Equal(t, "v1", store.active)
	store.selectActive(now.Add(50*time.Minute), observed)
	require.Equal(t, "v2", store.active)
	require.True(t, store.records["v1"].retired)
	require.Len(t, store.records, 2, "immutable version history must be retained")
	require.ErrorIs(t, store.publish(Snapshot{Version: "v1", Paths: next.Paths}, now), ErrVersionReused)
}

func TestAuthorityPathsAndBounds(t *testing.T) {
	f := newIssuanceFixture(t)
	key := newECDSAKey(t)
	intermediate := f.signingCA(t, "issuer", f.root, f.rootKey, key)
	for _, tt := range []struct {
		name string
		in   *issuerv1.AuthoritySnapshot
		want string
	}{
		{name: "ordered path", in: &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1", AuthorityChains: []*issuerv1.AuthorityChain{{Root: f.root.Raw, Intermediates: [][]byte{intermediate.Raw}}}}},
		{name: "non-self-signed trust anchor", in: authoritySnapshot("v1", intermediate, time.Now())},
		{name: "empty snapshot", in: &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1"}, want: "number of paths"},
		{name: "blank version", in: authoritySnapshot(" ", f.root, time.Now()), want: "authority version"},
		{name: "duplicate root", in: &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1", AuthorityChains: []*issuerv1.AuthorityChain{{Root: f.root.Raw, Intermediates: [][]byte{f.root.Raw}}}}, want: "duplicate"},
		{name: "wrong parent", in: &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1", AuthorityChains: []*issuerv1.AuthorityChain{{Root: makeRoot(t, "other", time.Now().Add(-time.Hour), time.Now().Add(time.Hour)).Raw, Intermediates: [][]byte{intermediate.Raw}}}}, want: "unordered"},
		{name: "oversized certificate", in: &issuerv1.AuthoritySnapshot{AuthorityVersion: "v1", AuthorityChains: []*issuerv1.AuthorityChain{{Root: make([]byte, maxCertificateSize+1)}}}, want: "size limit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SnapshotFromProto(tt.in)
			if tt.want != "" {
				require.ErrorContains(t, err, tt.want)
				return
			}
			require.NoError(t, err)
			require.Len(t, got.Paths, 1)
			before := append([]byte(nil), got.Paths[0].Root.Raw...)
			tt.in.AuthorityChains[0].Root[0] ^= 0xff
			require.Equal(t, before, got.Paths[0].Root.Raw)
			tt.in.AuthorityChains[0].Root[0] ^= 0xff
		})
	}
}

func TestAuthorityUsesAllPathExpirations(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// The lifetime calculation is independent of root expiration and selects
	// the best currently usable path, not the latest unconditionally.
	snapshot := Snapshot{Paths: []AuthorityPath{
		{Root: &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(3 * time.Hour)}, Intermediates: []*x509.Certificate{{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}}},
		{Root: &x509.Certificate{NotBefore: now.Add(time.Hour), NotAfter: now.Add(4 * time.Hour)}},
	}}
	require.Equal(t, now.Add(time.Hour), snapshot.effectiveExpiry(now))
	require.True(t, snapshot.effectiveExpiry(now.Add(5*time.Hour)).IsZero())
}

func TestExpiredAuthorityDoesNotPreferFuturePaths(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	old := makeRoot(t, "old", now.Add(-time.Hour), now.Add(time.Hour))
	future := makeRoot(t, "future", now.Add(2*time.Hour), now.Add(4*time.Hour))
	successor := makeRoot(t, "successor", now, now.Add(3*time.Hour))
	current, err := SnapshotFromProto(&issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v1",
		AuthorityChains:  []*issuerv1.AuthorityChain{{Root: old.Raw}, {Root: future.Raw}},
	})
	require.NoError(t, err)
	next, err := SnapshotFromProto(authoritySnapshot("v2", successor, now))
	require.NoError(t, err)
	store := NewAuthorityStore()
	require.NoError(t, store.publish(current, now))
	store.records["v1"].committed = true
	observed := map[string]bool{"v1": true, "v2": true}
	store.selectActive(now, observed)
	require.Equal(t, "v1", store.active)
	require.NoError(t, store.publish(next, now.Add(61*time.Minute)))
	store.records["v2"].committed = true
	store.selectActive(now.Add(61*time.Minute), observed)
	require.Equal(t, "v2", store.active, "a not-yet-valid path must not prevent recovery after current paths expire")
}

func makeRoot(t *testing.T, cn string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err)
}
