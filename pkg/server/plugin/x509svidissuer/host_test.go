package x509svidissuer

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostInitializesPublishesAndIssues(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootKey := newECDSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "external-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	stream := &testAuthorityStream{snapshots: make(chan *issuerv1.AuthoritySnapshot, 1)}
	stream.snapshots <- authoritySnapshot("v1", root, now)
	plugin := &testPlugin{stream: stream}
	var published []*x509.Certificate
	host := NewHost(HostConfig{
		Plugin: plugin,
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			published = append([]*x509.Certificate(nil), roots...)
			return nil
		},
		Now: func() time.Time { return now },
	})
	ctx := t.Context()
	requireNoError(t, host.Initialize(ctx))
	if len(published) != 1 || !published[0].Equal(root) {
		t.Fatal("initial external root was not published")
	}

	key := newECDSAKey(t)
	id, err := url.Parse("spiffe://example.org/workload")
	requireNoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(30 * time.Minute),
		URIs:                  []*url.URL{id},
		PublicKey:             key.Public(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	proof, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
	requireNoError(t, err)
	leaf := createCertificate(t, template, root, key.Public(), rootKey)
	plugin.issue = func(req *issuerv1.IssueX509SVIDRequest) *issuerv1.IssueX509SVIDResponse {
		return &issuerv1.IssueX509SVIDResponse{
			LeafCertificate:  leaf.Raw,
			AuthorityVersion: req.GetAuthorityVersion(),
		}
	}

	chain, err := host.Issue(ctx, template, proof, WorkloadSVID)
	requireNoError(t, err)
	if len(chain) != 1 || !chain[0].Equal(leaf) {
		t.Fatal("host did not return the validated external chain")
	}
}

func TestHostRejectsUnauthorizedResponse(t *testing.T) {
	f := newIssuanceFixture(t)
	stream := &testAuthorityStream{snapshots: make(chan *issuerv1.AuthoritySnapshot, 1)}
	stream.snapshots <- authoritySnapshot("v1", f.root, time.Now())
	host := NewHost(HostConfig{
		Plugin: &testPlugin{
			stream: stream,
			issue: func(*issuerv1.IssueX509SVIDRequest) *issuerv1.IssueX509SVIDResponse {
				return f.response(t, func(c *x509.Certificate) {
					c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
				})
			},
		},
		PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
	})
	ctx := t.Context()
	require.NoError(t, host.Initialize(ctx))
	chain, err := host.Issue(ctx, f.template, f.proof, WorkloadSVID)
	require.ErrorContains(t, err, "unsupported subject alternative name")
	require.Nil(t, chain)
}

func TestHostActivatesOverlappingRolloverAndFailsClosedOnStreamError(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root1 := makeRoot(t, "root-1", now.Add(-time.Hour), now.Add(2*time.Hour))
	root2 := makeRoot(t, "root-2", now.Add(-time.Hour), now.Add(2*time.Hour))
	stream := &testAuthorityStream{
		snapshots: make(chan *issuerv1.AuthoritySnapshot, 2),
		errs:      make(chan error, 1),
	}
	stream.snapshots <- authoritySnapshot("v1", root1, now)
	published := make(chan []*x509.Certificate, 2)
	failed := make(chan error, 1)
	host := NewHost(HostConfig{
		Plugin: &testPlugin{stream: stream},
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			published <- roots
			return nil
		},
		Now:       func() time.Time { return now },
		ClockSkew: time.Minute,
		OnError:   func(err error) { failed <- err },
	})
	ctx := t.Context()
	requireNoError(t, host.Initialize(ctx))
	<-published

	stream.snapshots <- &issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v2",
		AuthorityChains:  []*issuerv1.AuthorityChain{{Root: root1.Raw}, {Root: root2.Raw}},
		PublishedAt:      timestamppb.New(now),
	}
	select {
	case roots := <-published:
		if len(roots) != 2 {
			t.Fatalf("published roots = %d, want 2", len(roots))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for rollover publication")
	}

	stream.errs <- errors.New("stream failed")
	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		t.Fatal("host did not report stream failure")
	}
	if _, err := host.active(); !errors.Is(err, ErrAuthorityTainted) {
		t.Fatalf("host did not fail closed after stream error: %v", err)
	}
	if state := host.CheckHealth(); !state.Live || state.Ready {
		t.Fatalf("unexpected health after stream failure: %+v", state)
	}
}

func authoritySnapshot(version string, root *x509.Certificate, now time.Time) *issuerv1.AuthoritySnapshot {
	return &issuerv1.AuthoritySnapshot{
		AuthorityVersion: version,
		AuthorityChains:  []*issuerv1.AuthorityChain{{Root: root.Raw}},
		PublishedAt:      timestamppb.New(now),
	}
}

type testPlugin struct {
	stream *testAuthorityStream
	issue  func(*issuerv1.IssueX509SVIDRequest) *issuerv1.IssueX509SVIDResponse
}

func (*testPlugin) Name() string     { return "test" }
func (*testPlugin) Type() string     { return "X509SVIDIssuer" }
func (*testPlugin) Version() string  { return "v1" }
func (*testPlugin) IsExternal() bool { return false }

func (p *testPlugin) IssueX509SVID(_ context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	if p.issue == nil {
		return nil, errors.New("unexpected issuance")
	}
	return p.issue(req), nil
}

func (p *testPlugin) SubscribeAuthoritySnapshots(ctx context.Context) (AuthoritySnapshotStream, error) {
	p.stream.ctx = ctx
	return p.stream, nil
}

type testAuthorityStream struct {
	ctx       context.Context
	snapshots chan *issuerv1.AuthoritySnapshot
	errs      chan error
}

func (s *testAuthorityStream) Recv() (*issuerv1.AuthoritySnapshot, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case snapshot := <-s.snapshots:
		return snapshot, nil
	case err := <-s.errs:
		return nil, err
	}
}
