package maintenance

import (
	"context"
	"errors"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/protobuf/proto"
)

type Config struct {
	DataStore   datastore.DataStore
	TrustDomain string
	Notifiers   []notifier.Notifier
	Log         logrus.FieldLogger
	Clock       clock.Clock
}

type manager struct {
	c           Config
	updates     chan struct{}
	last        *common.Bundle
	initialized bool
}

func New(c Config) Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	return &manager{c: c, updates: make(chan struct{}, 1)}
}

func (m *manager) BundleUpdated() {
	select {
	case m.updates <- struct{}{}:
	default:
	}
}

func (m *manager) Initialize(ctx context.Context) error {
	last, err := m.c.DataStore.FetchBundle(ctx, m.c.TrustDomain)
	if err != nil {
		return err
	}
	if last == nil {
		return errors.New("local bundle is unavailable for bundle maintenance")
	}
	for _, plugin := range m.c.Notifiers {
		if err := plugin.NotifyAndAdviseBundleLoaded(ctx, proto.Clone(last).(*common.Bundle)); err != nil {
			m.c.Log.WithError(err).WithFields(logrus.Fields{
				telemetry.Notifier: plugin.Name(),
				telemetry.Event:    "bundle loaded",
			}).Error("Notifier failed to handle event")
			return err
		}
	}
	m.last, m.initialized = last, true
	return nil
}

func (m *manager) Run(ctx context.Context) error {
	if !m.initialized {
		if err := m.Initialize(ctx); err != nil {
			return err
		}
	}
	last := m.last
	prune := m.c.Clock.Ticker(6 * time.Hour)
	poll := m.c.Clock.Ticker(5 * time.Second)
	defer prune.Stop()
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-prune.C:
			if changed, err := m.c.DataStore.PruneBundle(ctx, m.c.TrustDomain, m.c.Clock.Now().Add(-24*time.Hour)); err != nil {
				m.c.Log.WithError(err).Warn("Failed to prune expired bundle verification material")
			} else if changed {
				m.BundleUpdated()
			}
			continue
		case <-poll.C:
		case <-m.updates:
		}
		bundle, err := m.c.DataStore.FetchBundle(ctx, m.c.TrustDomain)
		if err != nil {
			m.c.Log.WithError(err).Warn("Failed to load local bundle for notification")
			continue
		}
		if bundle == nil {
			m.c.Log.Warn("Local bundle is missing for notification")
			continue
		}
		if proto.Equal(last, bundle) {
			continue
		}
		complete := true
		for _, plugin := range m.c.Notifiers {
			if err := plugin.NotifyBundleUpdated(ctx, proto.Clone(bundle).(*common.Bundle)); err != nil {
				m.c.Log.WithError(err).WithFields(logrus.Fields{
					telemetry.Notifier: plugin.Name(),
					telemetry.Event:    "bundle updated",
				}).Warn("Notifier failed to handle event")
				complete = false
			}
		}
		if complete {
			last = bundle
		}
	}
}
