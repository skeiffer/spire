package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/externalstate"
	host "github.com/spiffe/spire/pkg/server/plugin/x509svidissuer"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFixtureReportsMissingHostServiceRegistration(t *testing.T) {
	require.Equal(t, codes.FailedPrecondition, status.Code(new(issuer).BrokerHostServices(missingBroker{})))
}

type missingBroker struct{}

func (missingBroker) BrokerClient(pluginsdk.ServiceClient) bool { return false }

func TestFixtureRetainsRootsAndHonorsStagedOldVersion(t *testing.T) {
	p, profile, request, now := issuerFixture(t)
	require.NoError(t, externalstate.WriteJSON(filepath.Join(p.dir, "controls.json"), controls{Version: "v2"}))
	response, err := p.IssueX509SVID(t.Context(), request)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(p.roots["v1"].Root)
	require.NoError(t, err)
	_, err = host.ParseAndValidateResponse(profile, response, host.Snapshot{Version: "v1", Roots: []*x509.Certificate{root}}, now)
	require.NoError(t, err)
	reloaded, err := loadMaterial(p.dir)
	require.NoError(t, err)
	require.Equal(t, p.roots, reloaded)
}

func TestFixtureRejectsUnboundProofAndCanShortenValidity(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  bool
	}{
		{name: "unbound proof", bad: true},
		{name: "shorter valid leaf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, profile, request, now := issuerFixture(t)
			if tc.bad {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				request.ProofCsr, err = x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
				require.NoError(t, err)
				_, err = p.IssueX509SVID(t.Context(), request)
				require.Equal(t, codes.InvalidArgument, status.Code(err))
				return
			}
			require.NoError(t, externalstate.WriteJSON(filepath.Join(p.dir, "controls.json"), controls{Version: "v1", ShortTTL: 1}))
			response, err := p.IssueX509SVID(t.Context(), request)
			require.NoError(t, err)
			root, err := x509.ParseCertificate(p.roots["v1"].Root)
			require.NoError(t, err)
			chain, err := host.ParseAndValidateResponse(profile, response, host.Snapshot{Version: "v1", Roots: []*x509.Certificate{root}}, now)
			require.NoError(t, err)
			require.True(t, chain[0].NotAfter.Before(profile.NotAfter))
		})
	}
}

func issuerFixture(t *testing.T) (*issuer, *x509.Certificate, *issuerv1.IssueX509SVIDRequest, time.Time) {
	t.Helper()
	dir := t.TempDir()
	material, err := loadMaterial(dir)
	require.NoError(t, err)
	require.NoError(t, externalstate.WriteJSON(filepath.Join(dir, "controls.json"), controls{Version: "v1"}))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().Truncate(time.Second)
	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain: spiffeid.RequireTrustDomainFromString("domain.test"), Clock: clock.NewMockAt(t, now),
	})
	require.NoError(t, err)
	profile, err := builder.BuildWorkloadX509SVIDTemplate(t.Context(), credtemplate.WorkloadX509SVIDParams{
		PublicKey: key.Public(), SPIFFEID: spiffeid.RequireFromString("spiffe://domain.test/workload"),
		ParentIndependent: true,
	})
	require.NoError(t, err)
	proof, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
	require.NoError(t, err)
	request, err := host.BuildIssueRequest(profile, proof, host.WorkloadSVID, "v1")
	require.NoError(t, err)
	return &issuer{dir: dir, roots: material, now: func() time.Time { return now }}, profile, request, now
}
