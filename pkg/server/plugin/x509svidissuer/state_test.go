package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	testclock "github.com/spiffe/spire/test/clock"
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
		Plugin: &fakeIssuerPlugin{stream: stream}, StateDir: dir,
		Now: func() time.Time { return now },
		PublishAuthorities: func(context.Context, []*x509.Certificate) error {
			cancel()
			return errors.New("datastore unavailable")
		},
	})
	require.ErrorIs(t, first.Initialize(ctx), context.Canceled)
	var pending authorityState
	require.NoError(t, readAuthorityState(filepath.Join(dir, "authorities.json"), &pending))
	require.Len(t, pending.Records, 1)
	require.False(t, pending.Committed["v1"])
	require.Empty(t, pending.Active)

	restartedStream := &fakeSnapshotStream{responses: make(chan snapshotResult, 1)}
	restartedStream.responses <- snapshotResult{snapshot: snapshot}
	restarted := NewHost(HostConfig{
		Plugin: &fakeIssuerPlugin{stream: restartedStream}, StateDir: dir,
		Now: func() time.Time { return now },
		PublishAuthorities: func(_ context.Context, roots []*x509.Certificate) error {
			require.Len(t, roots, 1)
			return nil
		},
	})
	require.NoError(t, restarted.Initialize(t.Context()))
	defer restarted.Close()
	require.True(t, restarted.CheckHealth().Ready)
	var committed authorityState
	require.NoError(t, readAuthorityState(filepath.Join(dir, "authorities.json"), &committed))
	require.True(t, committed.Committed["v1"])
	require.Equal(t, "v1", committed.Active)
}

func TestPersistedAuthorityDoesNotAuthorizeOfflineStartup(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestRoot(t, now, "root", now.Add(time.Hour))
	require.NoError(t, writeAuthorityState(filepath.Join(dir, "authorities.json"), authorityState{
		Version: 1, Active: "v1", Committed: map[string]bool{"v1": true},
		Records: []*issuerv1.AuthoritySnapshot{{
			AuthorityVersion: "v1", PublishedAt: timestamppb.New(now),
			AuthorityChains: []*issuerv1.AuthorityChain{{Root: root.Raw}},
		}},
	}))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	host := NewHost(HostConfig{
		Plugin:   &fakeIssuerPlugin{stream: &fakeSnapshotStream{responses: make(chan snapshotResult)}},
		StateDir: dir,
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
		Now: func() time.Time { return now },
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

func TestAuthorityActivatesSuccessorOnNativeThreshold(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	mockClock := testclock.NewMockAt(t, now)
	makeSnapshot := func(version string, lifetime time.Duration) *issuerv1.AuthoritySnapshot {
		root := newTestRoot(t, now, version, now.Add(lifetime))
		return &issuerv1.AuthoritySnapshot{
			AuthorityVersion: version,
			PublishedAt:      timestamppb.New(now),
			AuthorityChains:  []*issuerv1.AuthorityChain{{Root: root.Raw}},
		}
	}
	stream := &fakeSnapshotStream{responses: make(chan snapshotResult, 2)}
	stream.responses <- snapshotResult{snapshot: makeSnapshot("v1", time.Hour)}
	host := NewHost(HostConfig{
		Plugin:             &fakeIssuerPlugin{stream: stream},
		Clock:              mockClock,
		PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
	})
	require.NoError(t, host.Initialize(t.Context()))
	defer host.Close()
	mockClock.WaitForTicker(time.Second, "lifecycle ticker was not created")
	require.Equal(t, "v1", host.store.ActiveVersion())

	stream.responses <- snapshotResult{snapshot: makeSnapshot("v2", 2*time.Hour)}
	require.Eventually(t, func() bool {
		host.mu.RLock()
		defer host.mu.RUnlock()
		return host.state.Prepared == "v2"
	}, time.Second, time.Millisecond)

	mockClock.Add(50 * time.Minute)
	require.Equal(t, "v1", host.store.ActiveVersion())
	mockClock.Add(lifecycleInterval)
	require.Eventually(t, func() bool {
		return host.store.ActiveVersion() == "v2"
	}, time.Second, time.Millisecond)
}

func TestAuthorityDoesNotActivateNonImprovingSuccessor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	makeSnapshot := func(version string, lifetime time.Duration) *issuerv1.AuthoritySnapshot {
		root := newTestRoot(t, now, version, now.Add(lifetime))
		return &issuerv1.AuthoritySnapshot{
			AuthorityVersion: version,
			PublishedAt:      timestamppb.New(now),
			AuthorityChains:  []*issuerv1.AuthorityChain{{Root: root.Raw}},
		}
	}
	host := NewHost(HostConfig{
		Now:                func() time.Time { return now.Add(55 * time.Minute) },
		PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
	})
	host.state = authorityState{
		Version: 1, Active: "v1", Prepared: "v2",
		Committed: map[string]bool{"v1": true, "v2": true},
	}
	require.NoError(t, host.store.Publish(mustSnapshot(t, makeSnapshot("v1", time.Hour))))
	require.NoError(t, host.store.Publish(mustSnapshot(t, makeSnapshot("v2", 45*time.Minute))))
	require.NoError(t, host.store.Activate("v1", now))
	require.ErrorContains(t, host.activatePrepared(t.Context()), "prepared external authority is unusable")
	require.Equal(t, "v1", host.store.ActiveVersion())
}

func TestAuthorityStateRejectsCorruptUnknownAndUnsupportedMetadata(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		err     string
	}{
		{name: "corrupt", content: `{`, err: "restore external authority state"},
		{name: "unknown field", content: `{"version":1,"records":[],"committed":{},"active":"","extra":true}`, err: `unknown field "extra"`},
		{name: "unsupported version", content: `{"version":2,"records":[],"committed":{},"active":""}`, err: "invalid external authority state"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "authorities.json"), []byte(tt.content), 0600))
			host := NewHost(HostConfig{
				Plugin:             &fakeIssuerPlugin{stream: &fakeSnapshotStream{responses: make(chan snapshotResult)}},
				StateDir:           dir,
				PublishAuthorities: func(context.Context, []*x509.Certificate) error { return nil },
			})
			err := host.Initialize(t.Context())
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func mustSnapshot(t *testing.T, snapshot *issuerv1.AuthoritySnapshot) Snapshot {
	t.Helper()
	parsed, err := SnapshotFromProto(snapshot)
	require.NoError(t, err)
	return parsed
}
