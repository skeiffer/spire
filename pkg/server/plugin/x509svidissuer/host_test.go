package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostRejectsLateResponseAfterSessionFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Hour))
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 2)}
	stream.responses <- snapshotResult{snapshot: &issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v1",
		PublishedAt:      timestamppb.New(now),
		AuthorityChains:  []*issuerv1.AuthorityChain{{Root: root.Raw}},
	}}
	issueStarted := make(chan struct{})
	issueRelease := make(chan struct{})
	plugin := &fakeIssuerPlugin{
		stream: stream,
		issue: func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
			close(issueStarted)
			<-issueRelease
			return nil, errors.New("issuer stopped")
		},
	}
	host := NewHost(HostConfig{
		Plugin: plugin,
		PublishAuthorities: func(context.Context, []*x509.Certificate) error {
			return nil
		},
		Now:              func() time.Time { return now },
		BootstrapTimeout: time.Second,
		ReconnectMin:     time.Hour,
	})
	ctx := t.Context()
	require.NoError(t, host.Initialize(ctx))
	defer host.Close()

	template, proof, _ := newProfileFixture(t)
	errCh := make(chan error, 1)
	go func() {
		_, err := host.Issue(ctx, template, proof, WorkloadSVID)
		errCh <- err
	}()
	<-issueStarted
	stream.responses <- snapshotResult{err: io.EOF}
	require.Eventually(t, func() bool { return !host.CheckHealth().Ready }, time.Second, time.Millisecond)
	close(issueRelease)
	require.ErrorContains(t, <-errCh, "session changed")
}

type fakeIssuerPlugin struct {
	stream AuthoritySnapshotStream
	issue  func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error)
}

func (*fakeIssuerPlugin) Name() string { return "fake" }
func (*fakeIssuerPlugin) Type() string { return "X509SVIDIssuer" }
func (p *fakeIssuerPlugin) IssueX509SVID(ctx context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	return p.issue(ctx, req)
}
func (p *fakeIssuerPlugin) SubscribeAuthoritySnapshots(ctx context.Context) (AuthoritySnapshotStream, error) {
	if stream, ok := p.stream.(*fakeSnapshotStream); ok {
		return &fakeSnapshotStream{responses: stream.responses, ctx: ctx}, nil
	}
	return p.stream, nil
}

type snapshotResult struct {
	snapshot *issuerv1.AuthoritySnapshot
	err      error
}

type fakeSnapshotStream struct {
	responses chan snapshotResult
	ctx       context.Context
}

func (s *fakeSnapshotStream) Recv() (*issuerv1.AuthoritySnapshot, error) {
	select {
	case result := <-s.responses:
		return result.snapshot, result.err
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
