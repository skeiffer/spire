package credtemplate_test

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

func TestExternalProfilesPreservePolicyWithoutLocalSigningFields(t *testing.T) {
	clk := clock.NewMockAt(t, now)
	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain: td, Clock: clk, X509SVIDTTL: 42 * time.Minute, AgentSVIDTTL: 20 * time.Minute,
		NewSerialNumber: func() (*big.Int, error) {
			t.Fatal("external profiles must not allocate a local serial")
			return nil, nil
		},
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		name  string
		ttl   time.Duration
		id    string
		build func(context.Context) (*x509.Certificate, error)
	}{
		{name: "server", ttl: 42 * time.Minute, id: serverID.String(), build: func(ctx context.Context) (*x509.Certificate, error) {
			return builder.BuildServerX509SVIDTemplate(ctx, credtemplate.ServerX509SVIDParams{PublicKey: publicKey, ParentIndependent: true})
		}},
		{name: "agent", ttl: 20 * time.Minute, id: agentID.String(), build: func(ctx context.Context) (*x509.Certificate, error) {
			return builder.BuildAgentX509SVIDTemplate(ctx, credtemplate.AgentX509SVIDParams{PublicKey: publicKey, SPIFFEID: agentID, ParentIndependent: true})
		}},
		{name: "workload", ttl: 2 * time.Minute, id: workloadID.String(), build: func(ctx context.Context) (*x509.Certificate, error) {
			return builder.BuildWorkloadX509SVIDTemplate(ctx, credtemplate.WorkloadX509SVIDParams{
				PublicKey: publicKey, SPIFFEID: workloadID, DNSNames: []string{"authorized.example"}, TTL: 2 * time.Minute, ParentIndependent: true,
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := tc.build(t.Context())
			require.NoError(t, err)
			require.Nil(t, profile.SerialNumber)
			require.Empty(t, profile.SubjectKeyId)
			require.Empty(t, profile.AuthorityKeyId)
			require.Equal(t, now.Add(-credtemplate.NotBeforeCushion), profile.NotBefore)
			require.Equal(t, now.Add(tc.ttl), profile.NotAfter)
			require.Equal(t, tc.id, profile.URIs[0].String())
			if tc.name == "workload" {
				require.Equal(t, "authorized.example", profile.Subject.CommonName)
				require.Equal(t, []string{"authorized.example"}, profile.DNSNames)
			}
		})
	}
}
