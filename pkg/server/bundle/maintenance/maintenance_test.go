package maintenance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakenotifier"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLoadedNotificationWithoutNotifiersDoesNotFetchBundle(t *testing.T) {
	ds := &memoryBundle{fetchError: errors.New("bundle fetch must not be needed")}
	manager := New(Config{DataStore: ds, TrustDomain: "spiffe://example.org", Log: logrus.New()})
	require.NoError(t, manager.Initialize(t.Context()))
}

func TestLoadedNotificationsUseConcurrentFanout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	called := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	handler := func(*common.Bundle) error {
		called <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	manager := New(Config{
		DataStore:   &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org"}},
		TrustDomain: "spiffe://example.org", Log: logrus.New(),
		GetNotifiers: func() []notifier.Notifier {
			return []notifier.Notifier{
				fakenotifier.New(t, fakenotifier.Config{OnNotifyAndAdviseBundleLoaded: handler}),
				fakenotifier.New(t, fakenotifier.Config{OnNotifyAndAdviseBundleLoaded: handler}),
			}
		},
	})
	done := make(chan error, 1)
	go func() { done <- manager.Initialize(ctx) }()
	for range 2 {
		select {
		case <-called:
		case <-ctx.Done():
			t.Fatal("notifier fan-out did not start concurrently")
		}
	}
	unblock()
	require.NoError(t, <-done)
}

func TestPruneBundleUsesNativeSafetyMarginAndUpdateSignal(t *testing.T) {
	failure := errors.New("prune unavailable")
	for _, tc := range []struct {
		name    string
		changed bool
		err     error
	}{
		{name: "unchanged"},
		{name: "changed", changed: true},
		{name: "error", err: failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := clock.NewMock(t)
			ds := &memoryBundle{pruneChanged: tc.changed, pruneError: tc.err}
			manager := New(Config{
				DataStore: ds, TrustDomain: "spiffe://example.org",
				Log: logrus.New(), Clock: clk, Metrics: fakemetrics.New(),
			})
			err := manager.PruneBundle(t.Context())
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.ErrorContains(t, err, "unable to prune bundle")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, clk.Now().Add(-24*time.Hour), ds.prunedBefore)
			select {
			case <-manager.Updates():
				require.True(t, tc.changed)
			default:
				require.False(t, tc.changed)
			}
		})
	}
}

func TestBundleNotificationsDoNotRequireACAManager(t *testing.T) {
	ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org", RootCas: []*common.Certificate{{DerBytes: []byte{1}}}}}
	plugin := &recordingNotifier{loaded: make(chan *common.Bundle, 1), updated: make(chan *common.Bundle, 1)}
	clk := clock.NewMock(t)
	manager := New(Config{
		DataStore: ds, TrustDomain: "spiffe://example.org",
		GetNotifiers: func() []notifier.Notifier { return []notifier.Notifier{plugin} },
		Log:          logrus.New(), Clock: clk,
	})
	require.NoError(t, manager.Initialize(t.Context()))
	loaded := <-plugin.loaded
	require.Len(t, loaded.RootCas, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	clk.WaitForTickerMulti(time.Second, 1, "bundle maintenance did not start")
	ds.mu.Lock()
	ds.bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "independent-token-key"}}
	ds.mu.Unlock()
	manager.BundleUpdated()
	updated := <-plugin.updated
	require.Len(t, updated.RootCas, 1)
	require.Equal(t, "independent-token-key", updated.JwtSigningKeys[0].Kid)
	cancel()
	require.NoError(t, <-done)
}

func TestLoadedNotificationFailureIsAnInitializationError(t *testing.T) {
	ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org"}}
	failure := errors.New("notifier unavailable")
	plugin := &recordingNotifier{loadedError: failure}
	log, hook := logtest.NewNullLogger()
	manager := New(Config{
		DataStore: ds, TrustDomain: "spiffe://example.org",
		GetNotifiers: func() []notifier.Notifier { return []notifier.Notifier{plugin} },
		Log:          log,
	})
	require.ErrorIs(t, manager.Initialize(t.Context()), failure)
	entry := hook.LastEntry()
	require.NotNil(t, entry)
	require.Equal(t, failure, entry.Data[logrus.ErrorKey])
	require.Equal(t, "fixture", entry.Data[telemetry.Notifier])
	require.Equal(t, "bundle loaded", entry.Data[telemetry.Event])
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.ErrorIs(t, manager.Run(ctx), failure)
}

func TestBundleFetchFailuresHaveDistinctDiagnostics(t *testing.T) {
	failure := errors.New("datastore unavailable")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "datastore error", err: failure},
		{name: "missing bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org"}}
			log, hook := logtest.NewNullLogger()
			clk := clock.NewMock(t)
			plugin := &recordingNotifier{loaded: make(chan *common.Bundle, 1)}
			manager := New(Config{
				DataStore: ds, TrustDomain: "spiffe://example.org", Log: log, Clock: clk,
				GetNotifiers: func() []notifier.Notifier { return []notifier.Notifier{plugin} },
			})
			require.NoError(t, manager.Initialize(t.Context()))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- manager.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				require.NoError(t, <-done)
			})
			clk.WaitForTickerMulti(time.Second, 1, "bundle maintenance did not start")
			ds.mu.Lock()
			ds.bundle, ds.fetchError = nil, tc.err
			ds.mu.Unlock()
			manager.BundleUpdated()
			require.Eventually(t, func() bool { return hook.LastEntry() != nil }, time.Second, time.Millisecond)
			entry := hook.LastEntry()
			require.Equal(t, logrus.WarnLevel, entry.Level)
			require.Equal(t, "Failed to notify on bundle update", entry.Message)
			if tc.err != nil {
				require.Equal(t, tc.err, entry.Data[logrus.ErrorKey])
			} else {
				require.EqualError(t, entry.Data[logrus.ErrorKey].(error), "trust domain bundle is missing")
			}
		})
	}
}

func TestBundleUpdateFailureIncludesNotifierContext(t *testing.T) {
	ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org"}}
	failure := errors.New("notifier unavailable")
	plugin := &recordingNotifier{loaded: make(chan *common.Bundle, 1), updatedError: failure}
	log, hook := logtest.NewNullLogger()
	clk := clock.NewMock(t)
	manager := New(Config{
		DataStore: ds, TrustDomain: "spiffe://example.org",
		GetNotifiers: func() []notifier.Notifier { return []notifier.Notifier{plugin} },
		Log:          log, Clock: clk,
	})
	require.NoError(t, manager.Initialize(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	clk.WaitForTickerMulti(time.Second, 1, "bundle maintenance did not start")
	ds.mu.Lock()
	ds.bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "new-key"}}
	ds.mu.Unlock()
	manager.BundleUpdated()
	var entry *logrus.Entry
	require.Eventually(t, func() bool {
		for _, candidate := range hook.AllEntries() {
			if candidate.Data[telemetry.Notifier] == "fixture" && candidate.Data[telemetry.Event] == "bundle updated" {
				entry = candidate
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	require.Equal(t, logrus.WarnLevel, entry.Level)
	require.Equal(t, failure, entry.Data[logrus.ErrorKey])
	require.Equal(t, "fixture", entry.Data[telemetry.Notifier])
	require.Equal(t, "bundle updated", entry.Data[telemetry.Event])
}

type memoryBundle struct {
	datastore.DataStore
	mu           sync.Mutex
	bundle       *common.Bundle
	fetchError   error
	pruneChanged bool
	pruneError   error
	prunedBefore time.Time
}

func (d *memoryBundle) FetchBundle(context.Context, string) (*common.Bundle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fetchError != nil || d.bundle == nil {
		return nil, d.fetchError
	}
	return proto.Clone(d.bundle).(*common.Bundle), nil
}

func (d *memoryBundle) PruneBundle(_ context.Context, _ string, before time.Time) (bool, error) {
	d.prunedBefore = before
	return d.pruneChanged, d.pruneError
}

type recordingNotifier struct {
	loadedError  error
	updatedError error
	loaded       chan *common.Bundle
	updated      chan *common.Bundle
}

func (*recordingNotifier) Name() string { return "fixture" }
func (*recordingNotifier) Type() string { return "Notifier" }
func (n *recordingNotifier) NotifyAndAdviseBundleLoaded(_ context.Context, bundle *common.Bundle) error {
	if n.loadedError != nil {
		return n.loadedError
	}
	n.loaded <- bundle
	return nil
}
func (n *recordingNotifier) NotifyBundleUpdated(_ context.Context, bundle *common.Bundle) error {
	if n.updatedError != nil {
		return n.updatedError
	}
	n.updated <- bundle
	return nil
}
