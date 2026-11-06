package x509svidissuer

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRootPublicationBudgetPreservesPreviousCommittedVersion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := newTestKey(t)
	padding, err := asn1.Marshal(make([]byte, 50000))
	require.NoError(t, err)
	makeSnapshot := func(version string) *issuerv1.AuthoritySnapshot {
		snapshot := &issuerv1.AuthoritySnapshot{AuthorityVersion: version, PublishedAt: timestamppb.New(now)}
		for i := range 16 {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: fmt.Sprintf("%s-%d", version, i)},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: padding}},
			}
			cert := createTestCertificate(t, template, template, key.Public(), key)
			snapshot.AuthorityChains = append(snapshot.AuthorityChains, &issuerv1.AuthorityChain{Root: cert.Raw})
		}
		return snapshot
	}
	var published []int
	host := NewHost(HostConfig{
		ActivationVersion: "v1", Now: func() time.Time { return now },
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			published = append(published, len(roots))
			return nil
		},
	})
	first := makeSnapshot("v1")
	require.NoError(t, host.applySnapshot(t.Context(), first, true))
	require.NoError(t, host.applySnapshot(t.Context(), makeSnapshot("v2"), false))
	require.ErrorContains(t, host.applySnapshot(t.Context(), makeSnapshot("v3"), false), "bundle budget")
	require.Equal(t, []int{16, 32}, published)
	require.NoError(t, host.applySnapshot(t.Context(), first, false))
	require.Equal(t, []int{16, 32, 32}, published)
	require.Equal(t, "v1", host.store.ActiveVersion())
}
