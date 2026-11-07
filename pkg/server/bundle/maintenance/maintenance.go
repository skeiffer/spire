package maintenance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetryserver "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/notifier"
	"github.com/spiffe/spire/proto/spire/common"
)

const (
	PruneInterval = 6 * time.Hour
	SafetyMargin  = 24 * time.Hour
)

type Config struct {
	DataStore    datastore.DataStore
	TrustDomain  string
	GetNotifiers func() []notifier.Notifier
	Log          logrus.FieldLogger
	Clock        clock.Clock
	Metrics      telemetry.Metrics
}

type manager struct {
	c           Config
	updates     chan struct{}
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

func (m *manager) Updates() <-chan struct{} { return m.updates }

func (m *manager) Initialize(ctx context.Context) error {
	select {
	case <-m.updates:
	default:
	}
	if err := m.notify(ctx, "bundle loaded", true, func(ctx context.Context, n notifier.Notifier, bundle *common.Bundle) error {
		return n.NotifyAndAdviseBundleLoaded(ctx, bundle)
	}); err != nil {
		return err
	}
	m.initialized = true
	return nil
}

func (m *manager) NotifyBundleUpdated(ctx context.Context) error {
	return m.notify(ctx, "bundle updated", false, func(ctx context.Context, n notifier.Notifier, bundle *common.Bundle) error {
		return n.NotifyBundleUpdated(ctx, bundle)
	})
}

func (m *manager) notify(ctx context.Context, event string, advise bool, do func(context.Context, notifier.Notifier, *common.Bundle) error) error {
	var notifiers []notifier.Notifier
	if m.c.GetNotifiers != nil {
		notifiers = m.c.GetNotifiers()
	}
	if len(notifiers) == 0 {
		return nil
	}
	bundle, err := m.c.DataStore.FetchBundle(ctx, m.c.TrustDomain)
	if err != nil {
		return err
	}
	if bundle == nil {
		return errors.New("trust domain bundle is missing")
	}
	errsCh := make(chan error, len(notifiers))
	for _, n := range notifiers {
		go func(n notifier.Notifier) {
			err := do(ctx, n, bundle)
			log := m.c.Log.WithFields(logrus.Fields{
				telemetry.Notifier: n.Name(),
				telemetry.Event:    event,
			})
			if err == nil {
				log.Debug("Notifier handled event")
			} else {
				log = log.WithError(err)
				if advise {
					log.Error("Notifier failed to handle event")
				} else {
					log.Warn("Notifier failed to handle event")
				}
			}
			errsCh <- err
		}(n)
	}
	var allErrs error
	for range notifiers {
		allErrs = errors.Join(allErrs, <-errsCh)
	}
	if allErrs != nil {
		return fmt.Errorf("one or more notifiers returned an error: %w", allErrs)
	}
	return nil
}

func (m *manager) PruneBundle(ctx context.Context) (err error) {
	counter := telemetryserver.StartCAManagerPruneBundleCall(m.c.Metrics)
	defer counter.Done(&err)
	changed, err := m.c.DataStore.PruneBundle(ctx, m.c.TrustDomain, m.c.Clock.Now().Add(-SafetyMargin))
	if err != nil {
		return fmt.Errorf("unable to prune bundle: %w", err)
	}
	if changed {
		telemetryserver.IncrManagerPrunedBundleCounter(m.c.Metrics)
		m.c.Log.Debug("Expired certificates were successfully pruned from bundle")
		m.BundleUpdated()
	}
	return nil
}

func (m *manager) Run(ctx context.Context) error {
	if !m.initialized {
		if err := m.Initialize(ctx); err != nil {
			return err
		}
	}
	prune := m.c.Clock.Ticker(PruneInterval)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-prune.C:
			if err := m.PruneBundle(ctx); err != nil {
				m.c.Log.WithError(err).Error("Could not prune CA certificates")
			}
		case <-m.updates:
			if err := m.NotifyBundleUpdated(ctx); err != nil {
				m.c.Log.WithError(err).Warn("Failed to notify on bundle update")
			}
		}
	}
}
