package x509svidissuer

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIssuanceValidatesCapturedProfileNotMutableComposerStorage(t *testing.T) {
	profile, proof, key := newProfileFixture(t)
	now := profile.NotBefore.Add(time.Minute)
	rootKey := newTestKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := createTestCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	leafTemplate := *profile
	leafTemplate.SerialNumber = big.NewInt(2)
	leaf := createTestCertificate(t, &leafTemplate, root, key.Public(), rootKey)
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
	stream.responses <- snapshotResult{snapshot: &issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
		AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
	}}
	host := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{stream: stream, issue: func(_ context.Context, request *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
			require.Equal(t, "workload.example", request.Profile.DnsNames[0])
			profile.Subject.CommonName = "changed after authorization"
			profile.DNSNames[0] = "changed.example"
			request.Profile.DnsNames[0] = "also changed by plugin"
			return &issuerv1.IssueX509SVIDResponse{LeafCertificate: leaf.Raw, AuthorityVersion: "v1"}, nil
		}},
		Now:                func() time.Time { return now },
		PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
	})
	require.NoError(t, host.Initialize(t.Context()))
	defer host.Close()
	chain, err := host.Issue(t.Context(), profile, proof, WorkloadSVID)
	require.NoError(t, err)
	require.Equal(t, "workload.example", chain[0].DNSNames[0])
}

func TestPublishedRootsDoNotExposeMutableAuthorityStorage(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Hour))
	store := NewAuthorityStore(24*time.Hour, 8)
	require.NoError(t, store.Publish(Snapshot{Version: "v1", Roots: []*x509.Certificate{root}, Chains: [][]*x509.Certificate{{root}}}))
	published := store.BundleRoots(now)
	published[0].Raw[0] ^= 1
	published[0].NotAfter = now.Add(-time.Hour)
	require.NoError(t, store.Activate("v1", now))
	active, err := store.Active()
	require.NoError(t, err)
	require.Equal(t, root.Raw, active.Roots[0].Raw)
	require.Equal(t, root.NotAfter, active.Roots[0].NotAfter)
}
