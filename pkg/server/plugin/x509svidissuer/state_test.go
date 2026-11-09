package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

func TestHostPublicationBarrierAndRecovery(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	entered, release := make(chan struct{}), make(chan struct{})
	host, _ := testHost(t, f, mock, func(ctx context.Context, _ []*x509.Certificate) error {
		close(entered)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	done := make(chan error, 1)
	go func() { done <- host.Initialize(t.Context()) }()
	<-entered
	require.False(t, host.CheckHealth().Ready)
	_, err := host.Issue(t.Context(), f.template, f.proof, WorkloadSVID)
	require.Error(t, err)
	close(release)
	require.NoError(t, <-done)
	require.True(t, host.CheckHealth().Ready)
}

func TestHostRetainedStateReobservesAndPreservesPreparationAge(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	host, _ := testHost(t, f, mock, successfulPublication)
	require.NoError(t, host.Initialize(t.Context()))
	firstPrepared := host.store.records["v1"].preparedAt
	root2 := makeRoot(t, "successor", mock.Now().Add(-time.Hour), mock.Now().Add(4*time.Hour))
	require.NoError(t, host.applySnapshot(t.Context(), authoritySnapshot("v2", root2, mock.Now())))
	require.Equal(t, "v1", host.store.active)
	secondPrepared := host.store.records["v2"].preparedAt
	host.Close()
	mock.Add(time.Minute)

	restarted, _ := testHost(t, f, mock, successfulPublication)
	restarted.c.DataDir = host.c.DataDir
	require.False(t, restarted.CheckHealth().Ready)
	require.NoError(t, restarted.Initialize(t.Context()))
	require.True(t, firstPrepared.Equal(restarted.store.records["v1"].preparedAt))
	require.True(t, secondPrepared.Equal(restarted.store.records["v2"].preparedAt))
	require.Equal(t, "v1", restarted.store.active)
	// A persisted successor is not live until reobserved in this session.
	require.NoError(t, restarted.applySnapshot(t.Context(), authoritySnapshot("v2", root2, mock.Now())))
	restarted.mu.Lock()
	expiry := restarted.store.records["v1"].snapshot.effectiveExpiry(mock.Now())
	threshold := expiry.Add(-min(expiry.Sub(firstPrepared)/6, 7*24*time.Hour))
	restarted.mu.Unlock()
	mock.Set(threshold)
	restarted.mu.Lock()
	require.NoError(t, restarted.activateLocked())
	require.Equal(t, "v2", restarted.store.active)
	restarted.mu.Unlock()
	require.True(t, restarted.CheckHealth().Ready)
	// Retired content remains immutable even after activation.
	require.ErrorIs(t, restarted.applySnapshot(t.Context(), authoritySnapshot("v1", root2, mock.Now())), ErrVersionReused)
}

func TestHostFailedCommitNeverActivates(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	var host *Host
	host, _ = testHost(t, f, mock, func(context.Context, []*x509.Certificate) error {
		// Fail the atomic replacement after successful publication.
		return os.Mkdir(host.statePath()+".tmp", 0700)
	})
	err := host.Initialize(t.Context())
	require.ErrorContains(t, err, "persist external authority metadata")
	require.False(t, host.CheckHealth().Ready)
	restarted, _ := testHost(t, f, mock, successfulPublication)
	restarted.c.DataDir = host.c.DataDir
	require.NoError(t, restarted.load())
	require.Empty(t, restarted.store.active)
	require.False(t, restarted.store.records["v1"].committed)
}

func TestHostRecoversPendingPublication(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	host, _ := testHost(t, f, mock, func(context.Context, []*x509.Certificate) error {
		return errors.New("publication interrupted")
	})
	require.NoError(t, host.load())
	require.ErrorContains(t, host.applySnapshot(t.Context(), authoritySnapshot("v1", f.root, mock.Now())), "publication interrupted")
	require.Empty(t, host.store.active)
	require.False(t, host.store.records["v1"].committed)
	restarted, _ := testHost(t, f, mock, successfulPublication)
	restarted.c.DataDir = host.c.DataDir
	require.NoError(t, restarted.Initialize(t.Context()))
	require.True(t, restarted.CheckHealth().Ready)
	require.Equal(t, "v1", restarted.store.active)
	require.True(t, restarted.store.records["v1"].preparedAt.Equal(host.store.records["v1"].preparedAt))
}

func TestHostSessionGenerationAndNoReplay(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	host, plugin := testHost(t, f, mock, successfulPublication)
	entered, release := make(chan struct{}), make(chan struct{})
	failed := make(chan error, 1)
	host.c.OnError = func(err error) { failed <- err }
	response := f.response(t, nil)
	var calls atomic.Int32
	plugin.issueContext = func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
		calls.Add(1)
		close(entered)
		<-release
		return response, nil
	}
	require.NoError(t, host.Initialize(t.Context()))
	done := make(chan error, 1)
	go func() {
		_, err := host.Issue(t.Context(), f.template, f.proof, WorkloadSVID)
		done <- err
	}()
	<-entered
	plugin.stream.errs <- errors.New("lost stream")
	<-failed
	require.False(t, host.CheckHealth().Ready)
	close(release)
	require.ErrorContains(t, <-done, "session changed")
	require.EqualValues(t, 1, calls.Load())
	// Recover the same immutable version in a fresh subscription.
	plugin.stream.snapshots <- authoritySnapshot("v1", f.root, mock.Now())
	mock.Add(2 * time.Second)
	require.Eventually(t, func() bool { return host.CheckHealth().Ready }, 5*time.Second, time.Millisecond)
}

func TestStreamFailureInterruptsBlockedPublication(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	publishing := make(chan struct{})
	failed := make(chan error, 1)
	var publications atomic.Int32
	host, plugin := testHost(t, f, mock, func(ctx context.Context, _ []*x509.Certificate) error {
		if publications.Add(1) == 1 {
			return nil
		}
		close(publishing)
		<-ctx.Done()
		return ctx.Err()
	})
	host.c.OnError = func(err error) { failed <- err }
	require.NoError(t, host.Initialize(t.Context()))
	next := makeRoot(t, "successor", mock.Now().Add(-time.Hour), mock.Now().Add(4*time.Hour))
	plugin.stream.snapshots <- authoritySnapshot("v2", next, mock.Now())
	<-publishing
	plugin.stream.errs <- errors.New("stream failed while publishing")
	select {
	case err := <-failed:
		require.ErrorContains(t, err, "stream failed while publishing")
	case <-time.After(5 * time.Second):
		t.Fatal("stream failure did not interrupt publication")
	}
	require.False(t, host.CheckHealth().Ready)
	host.mu.Lock()
	committed := host.store.records["v2"].committed
	host.mu.Unlock()
	require.False(t, committed)
}

func TestHostCapturesProfileAndRejectsPluginMutation(t *testing.T) {
	f := newIssuanceFixture(t)
	host, plugin := testHost(t, f, clock.NewMock(t), successfulPublication)
	wrong := f.response(t, func(cert *x509.Certificate) { cert.DNSNames = []string{"unauthorized.test"} })
	plugin.issue = func(req *issuerv1.IssueX509SVIDRequest) *issuerv1.IssueX509SVIDResponse {
		req.Profile.DnsNames = []string{"unauthorized.test"}
		return wrong
	}
	require.NoError(t, host.Initialize(t.Context()))
	_, err := host.Issue(t.Context(), f.template, f.proof, WorkloadSVID)
	require.ErrorContains(t, err, "DNS SAN mismatch")
}

func TestHostHealthReevaluatesExpiryWithoutEnrollment(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	host, plugin := testHost(t, f, mock, successfulPublication)
	var calls atomic.Int32
	plugin.issueContext = func(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
		calls.Add(1)
		return nil, errors.New("unexpected health enrollment")
	}
	require.NoError(t, host.Initialize(t.Context()))
	require.True(t, host.CheckHealth().Ready)
	mock.Set(f.root.NotAfter)
	require.False(t, host.CheckHealth().Ready)
	require.Zero(t, calls.Load())
}

func TestHostIssueTimeoutAndClose(t *testing.T) {
	for _, tt := range []struct {
		name  string
		close bool
	}{
		{name: "timeout"},
		{name: "close", close: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			mock := clock.NewMock(t)
			host, plugin := testHost(t, f, mock, successfulPublication)
			entered := make(chan struct{})
			var calls atomic.Int32
			plugin.issueContext = func(ctx context.Context, _ *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
				calls.Add(1)
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			require.NoError(t, host.Initialize(t.Context()))
			done := make(chan error, 1)
			go func() {
				_, err := host.Issue(t.Context(), f.template, f.proof, WorkloadSVID)
				done <- err
			}()
			<-entered
			if tt.close {
				host.Close()
			} else {
				mock.Add(issueTimeout)
			}
			require.Error(t, <-done)
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

func TestHostBootstrapDeadline(t *testing.T) {
	f := newIssuanceFixture(t)
	mock := clock.NewMock(t)
	host, plugin := testHost(t, f, mock, successfulPublication)
	<-plugin.stream.snapshots
	subscribed := make(chan struct{})
	plugin.subscribe = func(ctx context.Context) (AuthoritySnapshotStream, error) {
		plugin.stream.ctx = ctx
		close(subscribed)
		return plugin.stream, nil
	}
	done := make(chan error, 1)
	go func() { done <- host.Initialize(t.Context()) }()
	<-subscribed
	mock.Add(bootstrapTimeout)
	require.ErrorContains(t, <-done, "bootstrap timed out")
	require.False(t, host.CheckHealth().Ready)
}

func TestMetadataStrictDecoding(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
	}{
		{name: "truncated", data: `{"format":1`},
		{name: "unsupported", data: `{"format":2,"active":"","records":[]}`},
		{name: "missing history", data: `{"format":1}`},
		{name: "unknown field", data: `{"format":1,"private_key":"unexpected"}`},
		{name: "trailing", data: `{"format":1,"active":"","records":[]} {}`},
		{name: "invalid active", data: `{"format":1,"active":"missing","records":[]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			host := NewHost(HostConfig{DataDir: t.TempDir()})
			require.NoError(t, os.MkdirAll(filepath.Dir(host.statePath()), 0700))
			require.NoError(t, os.WriteFile(host.statePath(), []byte(tt.data), 0600))
			require.Error(t, host.load())
		})
	}
}

func successfulPublication(context.Context, []*x509.Certificate) error { return nil }

func testHost(t *testing.T, f *issuanceFixture, mock *clock.Mock, publish PublishAuthoritiesFunc) (*Host, *testPlugin) {
	t.Helper()
	stream := &testAuthorityStream{snapshots: make(chan *issuerv1.AuthoritySnapshot, 8), errs: make(chan error, 1)}
	stream.snapshots <- authoritySnapshot("v1", f.root, mock.Now())
	plugin := &testPlugin{stream: stream}
	host := NewHost(HostConfig{Plugin: plugin, DataDir: t.TempDir(), Clock: mock, PublishAuthorities: publish})
	t.Cleanup(host.Close)
	return host, plugin
}
