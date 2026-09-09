package x509svidissuer

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	host := NewHost(HostConfig{
		Plugin: &testPlugin{stream: stream},
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			published <- roots
			return nil
		},
		Now:       func() time.Time { return now },
		ClockSkew: time.Minute,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := host.active()
		if errors.Is(err, ErrAuthorityTainted) {
			if state := host.CheckHealth(); !state.Live || state.Ready {
				t.Fatalf("unexpected health after stream failure: %+v", state)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host did not fail closed after stream error: %v", err)
		}
		time.Sleep(time.Millisecond)
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

func (p *testPlugin) SubscribeAuthoritySnapshots(context.Context) (AuthoritySnapshotStream, error) {
	return p.stream, nil
}

type testAuthorityStream struct {
	mu        sync.Mutex
	snapshots chan *issuerv1.AuthoritySnapshot
	errs      chan error
}

func (s *testAuthorityStream) Recv() (*issuerv1.AuthoritySnapshot, error) {
	select {
	case snapshot := <-s.snapshots:
		return snapshot, nil
	case err := <-s.errs:
		return nil, err
	}
}
