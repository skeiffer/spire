package endpoints

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestPeerTrackerAttestor(t *testing.T) {
	attestor := PeerTrackerAttestor{Attestor: FakeAttestor{}}
	t.Run("requires peertracker watcher on context", func(t *testing.T) {
		selectors, err := attestor.Attest(context.Background())
		spiretest.AssertGRPCStatus(t, err, codes.Internal, "peer tracker watcher missing from context")
		assert.Empty(t, selectors)
	})

	t.Run("fails if peer is not alive", func(t *testing.T) {
		selectors, err := attestor.Attest(WithFakeWatcher(false))
		spiretest.AssertGRPCStatus(t, err, codes.Unauthenticated, "could not verify existence of the original caller: dead")
		assert.Empty(t, selectors)
	})

	t.Run("succeeds if peer is alive", func(t *testing.T) {
		selectors, err := attestor.Attest(WithFakeWatcher(true))
		assert.NoError(t, err)
		assert.Equal(t, []*common.Selector{{Type: "Type", Value: "Value"}}, selectors)
	})
}

func TestPeerTrackerAttestorPreservesVerifiedClientPID(t *testing.T) {
	underlying := &recordingAttestor{}
	attestor := PeerTrackerAttestor{Attestor: underlying}
	ctx := contextWithWatcher(recordingWatcher{pid: 42048, alive: true})

	for range 2 {
		selectors, err := attestor.Attest(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, selectors)
	}
	require.Equal(t, []int{42048, 42048}, underlying.pids)

	_, err := attestor.Attest(context.Background())
	spiretest.AssertGRPCStatus(t, err, codes.Internal, "peer tracker watcher missing from context")
	require.Equal(t, []int{42048, 42048}, underlying.pids,
		"unverified callers must fail before workload attestation")
}

type FakeAttestor struct{}

func (a FakeAttestor) Attest(_ context.Context, pid int) ([]*common.Selector, error) {
	if pid == os.Getpid() {
		return []*common.Selector{{Type: "Type", Value: "Value"}}, nil
	}
	return nil, nil
}

func (a FakeAttestor) AttestReference(_ context.Context, _ *anypb.Any) ([]*common.Selector, error) {
	return nil, status.Error(codes.Unimplemented, "AttestReference not implemented")
}

func WithFakeWatcher(alive bool) context.Context {
	return contextWithWatcher(FakeWatcher(alive))
}

func contextWithWatcher(watcher peertracker.Watcher) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: peertracker.AuthInfo{
			Watcher: watcher,
		},
	})
}

type FakeWatcher bool

func (w FakeWatcher) Close() {}

func (w FakeWatcher) IsAlive() error {
	if !w {
		return errors.New("dead")
	}
	return nil
}

func (w FakeWatcher) PID() int32 { return int32(os.Getpid()) }

type recordingWatcher struct {
	pid   int32
	alive bool
}

func (w recordingWatcher) Close() {}
func (w recordingWatcher) IsAlive() error {
	if !w.alive {
		return errors.New("dead")
	}
	return nil
}
func (w recordingWatcher) PID() int32 { return w.pid }

type recordingAttestor struct {
	pids []int
}

func (a *recordingAttestor) Attest(_ context.Context, pid int) ([]*common.Selector, error) {
	a.pids = append(a.pids, pid)
	return []*common.Selector{{Type: "Type", Value: "Value"}}, nil
}

func (*recordingAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return nil, status.Error(codes.Unimplemented, "AttestReference not implemented")
}
