package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/server/externalstate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthorityCrashBoundariesPreserveAttributionAndCommitBarrier(t *testing.T) {
	for _, boundary := range []int{2, 3, 4} {
		for _, uncertain := range []bool{false, true} {
			t.Run(fmt.Sprintf("write-%d-uncertain-%t", boundary, uncertain), func(t *testing.T) {
				now := time.Now().UTC().Truncate(time.Second)
				root := newTestRoot(t, now, "root", now.Add(time.Hour))
				snapshot := &issuerv1.AuthoritySnapshot{
					AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
					AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
				}
				newStream := func() *fakeSnapshotStream {
					stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
					stream.responses <- snapshotResult{snapshot: snapshot}
					return stream
				}
				ctx, cancel := context.WithCancel(t.Context())
				var publications atomic.Int32
				publish := func(context.Context, []*x509.Certificate) error {
					publications.Add(1)
					return nil
				}
				config := HostConfig{
					Plugin:   &fakeIssuerPlugin{stream: newStream()},
					StateDir: t.TempDir(), Binding: "instance-one", Fresh: true,
					ActivationVersion: "v1", Now: func() time.Time { return now },
					PublishAuthorities: publish, OnError: func(error) { cancel() },
				}
				host := NewHost(config)
				writes := 0
				host.writeState = func(path string, value any) error {
					writes++
					if writes == boundary {
						if uncertain {
							if err := externalstate.WriteJSON(path, value); err != nil {
								return err
							}
						}
						return errors.New("injected authority commit failure")
					}
					return externalstate.WriteJSON(path, value)
				}
				require.Error(t, host.Initialize(ctx))
				require.False(t, host.CheckHealth().Ready)
				if boundary >= 3 {
					require.Positive(t, publications.Load())
				}
				var state authorityState
				require.NoError(t, externalstate.ReadJSON(host.statePath(), &state))
				if publications.Load() != 0 {
					require.Len(t, state.Records, 1)
					require.Equal(t, root.Raw, state.Records[0].AuthorityChains[0].Root)
				}
				config.Fresh, config.OnError = false, nil
				config.Plugin = &fakeIssuerPlugin{stream: newStream()}
				restarted := NewHost(config)
				require.NoError(t, restarted.Initialize(t.Context()))
				defer restarted.Close()
				require.True(t, restarted.CheckHealth().Ready)
				require.Equal(t, "v1", restarted.store.ActiveVersion())
			})
		}
	}
}

func TestSilentStreamExpiryDisablesIssuanceWithoutHealthMinting(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Minute))
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
	stream.responses <- snapshotResult{snapshot: &issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
		AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
	}}
	var seconds atomic.Int64
	seconds.Store(now.Unix())
	var issues atomic.Int32
	host := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{stream: stream, issue: func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
			issues.Add(1)
			return nil, errors.New("unexpected issuance")
		}},
		ActivationVersion: "v1", Now: func() time.Time { return time.Unix(seconds.Load(), 0) },
		PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
	})
	require.NoError(t, host.Initialize(t.Context()))
	defer host.Close()
	require.True(t, host.CheckHealth().Ready)
	seconds.Store(now.Add(2 * time.Minute).Unix())
	require.False(t, host.CheckHealth().Ready)
	require.True(t, host.CheckHealth().Live)
	profile, proof, _ := newProfileFixture(t)
	_, err := host.Issue(t.Context(), profile, proof, WorkloadSVID)
	require.Error(t, err)
	require.Zero(t, issues.Load())
}
