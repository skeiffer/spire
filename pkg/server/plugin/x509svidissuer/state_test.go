package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/server/externalstate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAuthorityIntentSurvivesPublicationFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Hour))
	snapshot := &issuerv1.AuthoritySnapshot{
		AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
		AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
	}
	dir := t.TempDir()
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
	stream.responses <- snapshotResult{snapshot: snapshot}
	ctx, cancel := context.WithCancel(t.Context())
	first := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{stream: stream}, StateDir: dir, Binding: "instance-one", Fresh: true,
		ActivationVersion: "v1", Now: func() time.Time { return now },
		PublishAuthorities: func(context.Context, []*x509.Certificate) error {
			cancel()
			return errors.New("datastore unavailable")
		},
	})
	require.ErrorIs(t, first.Initialize(ctx), context.Canceled)
	var pending authorityState
	require.NoError(t, externalstate.ReadJSON(filepath.Join(dir, "authorities.json"), &pending))
	require.Len(t, pending.Records, 1)
	require.False(t, pending.Committed["v1"])
	require.Empty(t, pending.Active)

	restartedStream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
	restartedStream.responses <- snapshotResult{snapshot: snapshot}
	restarted := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{stream: restartedStream}, StateDir: dir, Binding: "instance-one",
		ActivationVersion: "v1", Now: func() time.Time { return now },
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			require.Len(t, roots, 1)
			return nil
		},
	})
	require.NoError(t, restarted.Initialize(t.Context()))
	defer restarted.Close()
	require.True(t, restarted.CheckHealth().Ready)
	var committed authorityState
	require.NoError(t, externalstate.ReadJSON(filepath.Join(dir, "authorities.json"), &committed))
	require.True(t, committed.Committed["v1"])
	require.Equal(t, "v1", committed.Active)
}

func TestPersistedAuthorityDoesNotAuthorizeOfflineStartup(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Hour))
	require.NoError(t, externalstate.WriteJSON(filepath.Join(dir, "authorities.json"), authorityState{
		Version: 1, Binding: "instance-one", Active: "v1", Committed: map[string]bool{"v1": true},
		Records: []*issuerv1.AuthoritySnapshot{{
			AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
			AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
		}},
	}))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	host := NewHost(HostConfig{
		Plugin:   &fakeIssuerPlugin{stream: &fakeSnapshotStream{responses: make(chan snapshotResult)}},
		StateDir: dir, Binding: "instance-one", ActivationVersion: "v1",
		PublishAuthorities: func(context.Context, []*x509.Certificate) error {
			t.Error("offline startup must not publish")
			return nil
		},
	})
	require.ErrorIs(t, host.Initialize(ctx), context.Canceled)
	require.False(t, host.CheckHealth().Ready)
}

func TestNormalStagingDoesNotInvalidateInflightGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	makeSnapshot := func(version string) *issuerv1.AuthoritySnapshot {
		root := newTestRoot(t, now, version, now.Add(time.Hour))
		return &issuerv1.AuthoritySnapshot{
			AuthorityVersion: version, PublishedAt: timestamppb.New(now),
			AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
		}
	}
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 2)}
	stream.responses <- snapshotResult{snapshot: makeSnapshot("v1")}
	started, release, staged := make(chan struct{}), make(chan struct{}), make(chan struct{})
	host := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{
			stream: stream,
			issue: func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
				close(started)
				<-release
				return nil, errors.New("normal issuer response")
			},
		},
		ActivationVersion: "v1", Now: func() time.Time { return now },
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			if len(roots) == 2 {
				close(staged)
			}
			return nil
		},
	})
	require.NoError(t, host.Initialize(t.Context()))
	defer host.Close()
	template, proof, _ := newProfileFixture(t)
	result := make(chan error, 1)
	go func() {
		_, err := host.Issue(t.Context(), template, proof, WorkloadSVID)
		result <- err
	}()
	<-started
	stream.responses <- snapshotResult{snapshot: makeSnapshot("v2")}
	<-staged
	close(release)
	require.ErrorContains(t, <-result, "normal issuer response")
	require.Equal(t, "v1", host.store.ActiveVersion())
}
