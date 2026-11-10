package x509svidissuer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/health"
	"google.golang.org/protobuf/proto"
)

type SVIDType = issuerv1.X509SVIDType

const (
	ServerSVID   = issuerv1.X509SVIDType_X509_SVID_TYPE_SERVER
	AgentSVID    = issuerv1.X509SVIDType_X509_SVID_TYPE_AGENT
	WorkloadSVID = issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD

	bootstrapTimeout   = time.Minute
	issueTimeout       = 30 * time.Second
	publicationTimeout = 30 * time.Second
	activationInterval = 10 * time.Second
)

type PublishAuthoritiesFunc func(context.Context, []*x509.Certificate) error

type HostConfig struct {
	Plugin             X509SVIDIssuer
	PublishAuthorities PublishAuthoritiesFunc
	DataDir            string
	Clock              clock.Clock
	OnError            func(error)
	HealthChecker      health.Checker
}

type Host struct {
	c HostConfig

	mu         sync.Mutex
	store      *AuthorityStore
	observed   map[string]bool
	live       bool
	generation uint64
	fatal      error
	ctx        context.Context
	session    context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	closed     bool
	issues     sync.WaitGroup
}

func NewHost(config HostConfig) *Host {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	return &Host{c: config, store: NewAuthorityStore(), observed: make(map[string]bool)}
}

func (h *Host) Initialize(ctx context.Context) error {
	if h.c.Plugin == nil || h.c.PublishAuthorities == nil || h.c.DataDir == "" {
		return errors.New("external X509-SVID issuer requires a plugin, authority publisher and data directory")
	}
	h.mu.Lock()
	if h.ctx != nil || h.closed {
		h.mu.Unlock()
		return errors.New("external X509-SVID issuer host has already been initialized or closed")
	}
	if err := h.load(); err != nil {
		h.mu.Unlock()
		return err
	}
	h.ctx, h.cancel = context.WithCancel(ctx)
	h.done = make(chan struct{})
	h.mu.Unlock()

	ready := make(chan struct{}, 1)
	go h.run(ready)
	timer := h.c.Clock.Timer(bootstrapTimeout)
	defer timer.Stop()
	var err error
	select {
	case <-ready:
		if h.c.HealthChecker != nil {
			err = h.c.HealthChecker.AddCheck("server.x509svidissuer", h)
		}
	case <-timer.C:
		err = errors.New("external X509-SVID issuer bootstrap timed out waiting for a usable committed authority")
	case <-h.done:
		h.mu.Lock()
		err = h.fatal
		h.mu.Unlock()
		if err == nil {
			err = errors.New("external X509-SVID issuer stopped during bootstrap")
		}
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		h.Close()
	}
	return err
}

func (h *Host) Close() {
	h.mu.Lock()
	h.closed = true
	h.live = false
	h.generation++
	if h.cancel != nil {
		h.cancel()
	}
	done := h.done
	h.mu.Unlock()
	if done != nil {
		<-done
	}
	h.issues.Wait()
}

func (h *Host) CheckHealth() health.State {
	h.mu.Lock()
	_, err := h.activeLocked()
	h.mu.Unlock()
	var details any
	if err != nil {
		details = err.Error()
	}
	return health.State{Live: true, Ready: err == nil, ReadyDetails: details}
}

func (h *Host) activeLocked() (Snapshot, error) {
	if h.fatal != nil {
		return Snapshot{}, h.fatal
	}
	if h.closed || !h.live || h.ctx == nil || h.ctx.Err() != nil || h.session == nil || h.session.Err() != nil {
		return Snapshot{}, ErrAuthorityTainted
	}
	record := h.store.records[h.store.active]
	if record == nil || !record.committed || !h.observed[h.store.active] {
		return Snapshot{}, ErrUnknownAuthority
	}
	if record.snapshot.effectiveExpiry(h.c.Clock.Now()).IsZero() {
		return Snapshot{}, errors.New("external authority has no currently usable path")
	}
	return record.snapshot, nil
}

func (h *Host) Issue(ctx context.Context, template *x509.Certificate, csr []byte, svidType SVIDType) ([]*x509.Certificate, error) {
	h.mu.Lock()
	snapshot, err := h.activeLocked()
	generation := h.generation
	session := h.session
	if err == nil {
		h.issues.Add(1)
	}
	h.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("external authority is not ready: %w", err)
	}
	defer h.issues.Done()

	authorized, err := cloneProfile(template)
	if err != nil {
		return nil, err
	}
	req, err := BuildIssueRequest(authorized, csr, svidType, snapshot.Version)
	if err != nil {
		return nil, err
	}
	ctx, cancel := h.timedContext(ctx, issueTimeout)
	stop := context.AfterFunc(session, cancel)
	defer stop()
	defer cancel()
	// The plugin may mutate its request; validation uses a separate capture.
	resp, err := h.c.Plugin.IssueX509SVID(ctx, proto.Clone(req).(*issuerv1.IssueX509SVIDRequest))
	if err != nil {
		return nil, fmt.Errorf("external X509-SVID issuance failed: %w", err)
	}
	chain, err := parseAndValidateResponse(authorized, resp, snapshot, h.c.Clock.Now())
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil || !h.live || h.closed || h.fatal != nil ||
		h.ctx.Err() != nil || session.Err() != nil || generation != h.generation ||
		snapshot.effectiveExpiry(h.c.Clock.Now()).IsZero() {
		return nil, errors.New("external issuer session changed or expired during issuance; response discarded")
	}
	return chain, nil
}

func (h *Host) run(ready chan<- struct{}) {
	defer close(h.done)
	backoff := time.Second
	for h.ctx.Err() == nil {
		err := h.consumeSession(ready)
		h.mu.Lock()
		h.live = false
		h.generation++
		h.observed = make(map[string]bool)
		fatal := h.fatal != nil
		h.mu.Unlock()
		if h.ctx.Err() != nil || fatal {
			return
		}
		if h.c.OnError != nil {
			h.c.OnError(err)
		}
		jitter, err := rand.Int(rand.Reader, big.NewInt(int64(backoff/4)))
		if err != nil {
			h.mu.Lock()
			h.fatal = fmt.Errorf("generate external issuer reconnect jitter: %w", err)
			h.mu.Unlock()
			return
		}
		timer := h.c.Clock.Timer(backoff + time.Duration(jitter.Int64()))
		select {
		case <-h.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (h *Host) consumeSession(ready chan<- struct{}) error {
	ctx, cancelCause := context.WithCancelCause(h.ctx)
	cancel := func() { cancelCause(context.Canceled) }
	defer cancel()
	h.mu.Lock()
	h.session = ctx
	h.mu.Unlock()
	// Stop the bootstrap timer without canceling the long-lived subscription
	// once the first snapshot is received.
	timer := h.c.Clock.Timer(bootstrapTimeout)
	established := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancelCause(context.DeadlineExceeded)
		case <-established:
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-watched }()
	stream, err := h.c.Plugin.SubscribeAuthoritySnapshots(ctx)
	if err != nil {
		return fmt.Errorf("subscribe external issuer authorities: %w", err)
	}
	results := make(chan *issuerv1.AuthoritySnapshot)
	received := make(chan struct{})
	go func() {
		defer close(received)
		for {
			snapshot, err := stream.Recv()
			if err != nil {
				cancelCause(fmt.Errorf("receive external issuer authority: %w", err))
				h.mu.Lock()
				h.live = false
				h.generation++
				h.mu.Unlock()
				return
			}
			select {
			case results <- snapshot:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); <-received }()
	ticker := h.c.Clock.Ticker(activationInterval)
	defer ticker.Stop()
	first := true
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
			h.mu.Lock()
			err = h.activateLocked()
			h.mu.Unlock()
		case next := <-results:
			err = h.applySnapshot(ctx, next)
			if err == nil && first {
				close(established)
				first = false
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			return err
		}
		if h.CheckHealth().Ready {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
}

func (h *Host) applySnapshot(ctx context.Context, in *issuerv1.AuthoritySnapshot) error {
	snapshot, err := SnapshotFromProto(in)
	if err != nil {
		return fmt.Errorf("validate external issuer authority: %w", err)
	}
	if snapshot.effectiveExpiry(h.c.Clock.Now()).IsZero() {
		return errors.New("external issuer snapshot has no currently usable authority path")
	}
	h.mu.Lock()
	err = h.store.publish(snapshot, h.c.Clock.Now())
	if err == nil {
		err = h.saveLocked()
	}
	h.mu.Unlock()
	if err != nil {
		return err
	}
	ctx, cancel := h.timedContext(ctx, publicationTimeout)
	defer cancel()
	roots := make([]*x509.Certificate, 0, len(snapshot.Roots))
	for _, root := range snapshot.Roots {
		cert, err := x509.ParseCertificate(bytes.Clone(root.Raw))
		if err != nil {
			return err
		}
		roots = append(roots, cert)
	}
	if err := h.c.PublishAuthorities(ctx, roots); err != nil {
		return fmt.Errorf("publish external issuer authorities: %w", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	h.store.records[snapshot.Version].committed = true
	if err := h.saveLocked(); err != nil {
		return err
	}
	h.observed[snapshot.Version] = true
	h.live = true
	return h.activateLocked()
}

func (h *Host) activateLocked() error {
	previous := h.store.active
	h.store.selectActive(h.c.Clock.Now(), h.observed)
	if previous != h.store.active {
		return h.saveLocked()
	}
	return nil
}

func (h *Host) statePath() string {
	return filepath.Join(h.c.DataDir, "x509svidissuer", "authorities.json")
}

func (h *Host) timedContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	timer := h.c.Clock.Timer(timeout)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(); <-done }
}
