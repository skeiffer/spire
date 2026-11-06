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
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBundleNotificationsDoNotRequireACAManager(t *testing.T) {
	ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org", RootCas: []*common.Certificate{{DerBytes: []byte{1}}}}}
	plugin := &recordingNotifier{loaded: make(chan *common.Bundle, 1), updated: make(chan *common.Bundle, 1)}
	clk := clock.NewMock(t)
	manager := New(Config{
		DataStore: ds, TrustDomain: "spiffe://example.org",
		Notifiers: []notifier.Notifier{plugin}, Log: logrus.New(), Clock: clk,
	})
	require.NoError(t, manager.Initialize(t.Context()))
	loaded := <-plugin.loaded
	require.Len(t, loaded.RootCas, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	clk.WaitForTickerMulti(time.Second, 2, "bundle maintenance did not start")
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
		Notifiers: []notifier.Notifier{plugin}, Log: log,
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
		name    string
		err     error
		message string
	}{
		{name: "datastore error", err: failure, message: "Failed to load local bundle for notification"},
		{name: "missing bundle", message: "Local bundle is missing for notification"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ds := &memoryBundle{bundle: &common.Bundle{TrustDomainId: "spiffe://example.org"}}
			log, hook := logtest.NewNullLogger()
			clk := clock.NewMock(t)
			manager := New(Config{DataStore: ds, TrustDomain: "spiffe://example.org", Log: log, Clock: clk})
			require.NoError(t, manager.Initialize(t.Context()))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- manager.Run(ctx) }()
			t.Cleanup(func() {
				cancel()
				require.NoError(t, <-done)
			})
			clk.WaitForTickerMulti(time.Second, 2, "bundle maintenance did not start")
			ds.mu.Lock()
			ds.bundle, ds.fetchError = nil, tc.err
			ds.mu.Unlock()
			manager.BundleUpdated()
			require.Eventually(t, func() bool { return hook.LastEntry() != nil }, time.Second, time.Millisecond)
			entry := hook.LastEntry()
			require.Equal(t, logrus.WarnLevel, entry.Level)
			require.Equal(t, tc.message, entry.Message)
			if tc.err != nil {
				require.Equal(t, tc.err, entry.Data[logrus.ErrorKey])
			} else {
				require.NotContains(t, entry.Data, logrus.ErrorKey)
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
		Notifiers: []notifier.Notifier{plugin}, Log: log, Clock: clk,
	})
	require.NoError(t, manager.Initialize(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- manager.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	clk.WaitForTickerMulti(time.Second, 2, "bundle maintenance did not start")
	ds.mu.Lock()
	ds.bundle.JwtSigningKeys = []*common.PublicKey{{Kid: "new-key"}}
	ds.mu.Unlock()
	manager.BundleUpdated()
	require.Eventually(t, func() bool { return hook.LastEntry() != nil }, time.Second, time.Millisecond)
	entry := hook.LastEntry()
	require.Equal(t, logrus.WarnLevel, entry.Level)
	require.Equal(t, failure, entry.Data[logrus.ErrorKey])
	require.Equal(t, "fixture", entry.Data[telemetry.Notifier])
	require.Equal(t, "bundle updated", entry.Data[telemetry.Event])
}

type memoryBundle struct {
	datastore.DataStore
	mu         sync.Mutex
	bundle     *common.Bundle
	fetchError error
}

func (d *memoryBundle) FetchBundle(context.Context, string) (*common.Bundle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fetchError != nil || d.bundle == nil {
		return nil, d.fetchError
	}
	return proto.Clone(d.bundle).(*common.Bundle), nil
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
