package x509svidissuer

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/health"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	defaultBootstrapTimeout    = 30 * time.Second
	defaultIssueTimeout        = 30 * time.Second
	defaultReconnectMin        = time.Second
	defaultReconnectMax        = 30 * time.Second
	defaultHistoryLimit        = 64
	lifecycleInterval          = 10 * time.Second
	rootRetentionMargin        = 24 * time.Hour
	maxRootBundleBytes         = 2 << 20
	maxAuthorityStateBytes     = 2 << 20
	activationThresholdCap     = 7 * 24 * time.Hour
	activationThresholdDivisor = 6
)

type PublishAuthoritiesFunc func(context.Context, []*x509.Certificate) error

type HostConfig struct {
	Plugin             X509SVIDIssuer
	PublishAuthorities PublishAuthoritiesFunc
	StateDir           string
	WriteState         func(string, any) error
	Clock              clock.Clock
	Now                func() time.Time
	OnError            func(error)
	HealthChecker      health.Checker
	BootstrapTimeout   time.Duration
	IssueTimeout       time.Duration
	ReconnectMin       time.Duration
	ReconnectMax       time.Duration
	HistoryLimit       int
}

type authorityState struct {
	Version   int                           `json:"version"`
	Records   []*issuerv1.AuthoritySnapshot `json:"records"`
	Committed map[string]bool               `json:"committed"`
	Active    string                        `json:"active"`
	Prepared  string                        `json:"prepared,omitempty"`
}

type Host struct {
	c          HostConfig
	store      *AuthorityStore
	mu         sync.RWMutex
	transition sync.Mutex
	state      authorityState
	seen       map[string]bool
	generation uint64
	ready      bool
	lastErr    error
	fatalState bool
	readyCh    chan struct{}
	readyOnce  sync.Once
	limit      chan struct{}
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	writeState func(string, any) error
}

func NewHost(config HostConfig) *Host {
	if config.Clock == nil {
		config.Clock = clock.New()
	}
	if config.Now == nil {
		config.Now = config.Clock.Now
	}
	if config.BootstrapTimeout == 0 {
		config.BootstrapTimeout = defaultBootstrapTimeout
	}
	if config.IssueTimeout == 0 {
		config.IssueTimeout = defaultIssueTimeout
	}
	if config.ReconnectMin == 0 {
		config.ReconnectMin = defaultReconnectMin
	}
	if config.ReconnectMax == 0 {
		config.ReconnectMax = defaultReconnectMax
	}
	if config.HistoryLimit == 0 {
		config.HistoryLimit = defaultHistoryLimit
	}
	if config.WriteState == nil {
		config.WriteState = writeAuthorityState
	}
	return &Host{
		c: config, store: NewAuthorityStore(rootRetentionMargin, config.HistoryLimit),
		seen: make(map[string]bool), readyCh: make(chan struct{}), limit: make(chan struct{}, 64),
		writeState: config.WriteState,
	}
}

func (h *Host) Initialize(ctx context.Context) error {
	if h.c.Plugin == nil || h.c.PublishAuthorities == nil {
		return errors.New("external X509-SVID issuer plugin and authority publisher are required")
	}
	h.state = authorityState{Version: 1, Committed: make(map[string]bool)}
	if h.c.StateDir != "" {
		err := readAuthorityState(h.statePath(), &h.state)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := h.persist(h.state); err != nil {
				return err
			}
		case err != nil:
			return fmt.Errorf("restore external authority state: %w", err)
		}
		if h.state.Version != 1 || h.state.Committed == nil || len(h.state.Records) > h.c.HistoryLimit {
			return errors.New("invalid external authority state")
		}
		for _, record := range h.state.Records {
			snapshot, err := SnapshotFromProto(record)
			if err != nil {
				return err
			}
			if err := h.store.Publish(snapshot); err != nil {
				return err
			}
		}
		if h.state.Active != "" && !h.state.Committed[h.state.Active] {
			return errors.New("active external authority has no committed publication")
		}
		if h.state.Prepared != "" && !h.state.Committed[h.state.Prepared] {
			return errors.New("prepared external authority has no committed publication")
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	h.cancel = cancel
	h.wg.Go(func() { h.consume(runCtx) })
	h.wg.Go(func() { h.runLifecycle(runCtx) })
	timer := time.NewTimer(h.c.BootstrapTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		h.Close()
		return ctx.Err()
	case <-timer.C:
		h.Close()
		h.mu.RLock()
		defer h.mu.RUnlock()
		cause := h.lastErr
		if cause == nil {
			cause = errors.New("no usable external authority was observed")
		}
		return fmt.Errorf("timed out waiting for selected external authority: %w", cause)
	case <-h.readyCh:
	}
	if h.c.HealthChecker != nil {
		if err := h.c.HealthChecker.AddCheck("server.x509svidissuer", h); err != nil {
			h.Close()
			return fmt.Errorf("register external issuer health check: %w", err)
		}
	}
	return nil
}

func (h *Host) Close() {
	if h.cancel != nil {
		h.cancel()
		h.wg.Wait()
	}
}

func (h *Host) CheckHealth() health.State {
	h.mu.RLock()
	ready, lastErr := h.ready, h.lastErr
	h.mu.RUnlock()
	if ready {
		snapshot, err := h.store.Active()
		if err == nil {
			err = usableSnapshot(snapshot, h.c.Now())
		}
		if err != nil {
			ready, lastErr = false, err
		}
	}
	var details any
	if lastErr != nil {
		details = "external authority is unavailable; inspect the issuer session and authority state"
	}
	return health.State{Live: true, Ready: ready, ReadyDetails: details}
}

func (h *Host) Issue(ctx context.Context, template *x509.Certificate, proofCSR []byte, svidType SVIDType) ([]*x509.Certificate, error) {
	issueCtx, cancel := context.WithTimeout(ctx, h.c.IssueTimeout)
	defer cancel()
	select {
	case h.limit <- struct{}{}:
		defer func() { <-h.limit }()
	case <-issueCtx.Done():
		return nil, issueCtx.Err()
	}
	h.mu.RLock()
	generation, ready := h.generation, h.ready
	h.mu.RUnlock()
	if !ready {
		return nil, errors.New("external authority is not ready")
	}
	snapshot, err := h.store.Active()
	if err != nil {
		return nil, err
	}
	if err := usableSnapshot(snapshot, h.c.Now()); err != nil {
		return nil, err
	}
	req, err := BuildIssueRequest(template, proofCSR, svidType, snapshot.Version)
	if err != nil {
		return nil, err
	}
	prepared, err := capturedProfile(req.Profile)
	if err != nil {
		return nil, err
	}
	resp, issueErr := h.c.Plugin.IssueX509SVID(issueCtx, req)
	var chain []*x509.Certificate
	if issueErr == nil {
		if resp != nil {
			resp = proto.Clone(resp).(*issuerv1.IssueX509SVIDResponse)
		}
		chain, issueErr = ParseAndValidateResponse(prepared, resp, snapshot, h.c.Now())
	}
	h.mu.RLock()
	sameSession := h.ready && h.generation == generation
	h.mu.RUnlock()
	if !sameSession {
		return nil, errors.New("external issuer session changed while issuance was in flight")
	}
	if issueErr != nil {
		return nil, fmt.Errorf("external X509-SVID issuance failed: %w", boundedFailure(issueErr))
	}
	return chain, nil
}

func (h *Host) Activate(ctx context.Context, version string) error {
	h.transition.Lock()
	defer h.transition.Unlock()
	h.mu.RLock()
	seen, fatal, generation := h.seen[version], h.fatalState, h.generation
	h.mu.RUnlock()
	if fatal {
		return errors.New("external authority persistence failed; restart with reconciled durable state")
	}
	if !seen || !h.state.Committed[version] {
		return errors.New("selected authority has not been validated and committed in the current session")
	}
	snapshot, err := h.store.Snapshot(version)
	if err != nil {
		return err
	}
	if err := usableSnapshot(snapshot, h.c.Now()); err != nil {
		return err
	}
	h.mu.RLock()
	alreadyActive := h.ready && h.state.Active == version
	h.mu.RUnlock()
	if alreadyActive {
		return nil
	}
	next := h.state
	next.Active = version
	if next.Prepared == version {
		next.Prepared = ""
	}
	if err := h.persist(next); err != nil {
		h.invalidate(err)
		return err
	}
	h.mu.Lock()
	h.state = next
	h.mu.Unlock()
	if err := h.store.Activate(version, h.c.Now()); err != nil {
		h.invalidate(err)
		return err
	}
	h.mu.Lock()
	if h.generation != generation || !h.seen[version] {
		h.mu.Unlock()
		return errors.New("external authority session failed during activation")
	}
	h.ready, h.lastErr = true, nil
	h.mu.Unlock()
	h.readyOnce.Do(func() { close(h.readyCh) })
	return nil
}

func (h *Host) consume(ctx context.Context) {
	backoff := h.c.ReconnectMin
	for ctx.Err() == nil {
		streamCtx, cancel := context.WithCancel(ctx)
		stream, err := h.c.Plugin.SubscribeAuthoritySnapshots(streamCtx)
		if err == nil {
			for ctx.Err() == nil {
				snapshot, receiveErr := stream.Recv()
				if receiveErr != nil {
					err = receiveErr
					break
				}
				if err = h.applySnapshot(ctx, snapshot, false); err != nil {
					break
				}
				backoff = h.c.ReconnectMin
			}
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		h.invalidate(err)
		timer := time.NewTimer(backoff + reconnectJitter(backoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(backoff*2, h.c.ReconnectMax)
	}
}

func (h *Host) runLifecycle(ctx context.Context) {
	ticker := h.c.Clock.Ticker(lifecycleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.activatePrepared(ctx); err != nil {
				h.report(err)
			}
		}
	}
}

func (h *Host) activatePrepared(ctx context.Context) error {
	h.mu.RLock()
	active, prepared := h.state.Active, h.state.Prepared
	h.mu.RUnlock()
	if prepared == "" {
		return nil
	}
	if active == "" {
		return h.Activate(ctx, prepared)
	}
	current, err := h.store.Snapshot(active)
	if err != nil {
		return err
	}
	next, err := h.store.Snapshot(prepared)
	if err != nil {
		return err
	}
	now := h.c.Now()
	currentExpiry, currentErr := effectiveSnapshotExpiry(current, now)
	nextExpiry, nextErr := effectiveSnapshotExpiry(next, now)
	if nextErr != nil {
		return fmt.Errorf("prepared external authority is unusable: %w", nextErr)
	}
	if !nextExpiry.After(currentExpiry) {
		return nil
	}
	if currentErr != nil || now.After(authorityActivationThreshold(current.PublishedAt, currentExpiry)) {
		return h.Activate(ctx, prepared)
	}
	return nil
}

func reconnectJitter(backoff time.Duration) time.Duration {
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(max(int64(backoff/2), 1)))
	if err != nil {
		return 0
	}
	return time.Duration(value.Int64())
}

func (h *Host) applySnapshot(ctx context.Context, in *issuerv1.AuthoritySnapshot, _ bool) error {
	h.mu.RLock()
	fatal := h.fatalState
	h.mu.RUnlock()
	if fatal {
		return errors.New("external authority persistence failed; restart with reconciled durable state")
	}
	snapshot, err := SnapshotFromProto(in)
	if err != nil {
		return fmt.Errorf("validate external issuer authority: %w", err)
	}
	if err := usableSnapshot(snapshot, h.c.Now()); err != nil {
		return err
	}
	h.transition.Lock()
	previous, foundErr := h.store.Snapshot(snapshot.Version)
	if foundErr == nil {
		left, _ := snapshotDigest(previous)
		right, _ := snapshotDigest(snapshot)
		if left != right {
			h.transition.Unlock()
			return ErrVersionReused
		}
	} else {
		if len(h.state.Records) >= h.c.HistoryLimit {
			h.transition.Unlock()
			return ErrHistoryLimit
		}
		next := h.state
		next.Records = append(append([]*issuerv1.AuthoritySnapshot(nil), h.state.Records...), proto.Clone(in).(*issuerv1.AuthoritySnapshot))
		if err := h.persist(next); err != nil {
			h.transition.Unlock()
			return err
		}
		h.mu.Lock()
		h.state = next
		h.mu.Unlock()
	}
	if err := h.store.Publish(snapshot); err != nil {
		h.transition.Unlock()
		return err
	}
	roots, err := h.publicationRoots(snapshot.Version)
	if err != nil {
		h.transition.Unlock()
		return err
	}
	rootBytes := 0
	for _, root := range roots {
		rootBytes += len(root.Raw)
	}
	if rootBytes > maxRootBundleBytes {
		h.transition.Unlock()
		return errors.New("retained external root publication exceeds the host bundle budget; an approved archival policy is required")
	}
	if err := h.c.PublishAuthorities(ctx, roots); err != nil {
		h.transition.Unlock()
		return fmt.Errorf("publish external issuer authorities: %w", err)
	}
	next := h.state
	next.Committed = make(map[string]bool, len(h.state.Committed)+1)
	maps.Copy(next.Committed, h.state.Committed)
	next.Committed[snapshot.Version] = true
	if err := h.persist(next); err != nil {
		h.transition.Unlock()
		return err
	}
	h.mu.Lock()
	h.state = next
	h.seen[snapshot.Version] = true
	h.mu.Unlock()
	h.transition.Unlock()
	h.mu.RLock()
	active := h.state.Active
	h.mu.RUnlock()
	if active == "" || active == snapshot.Version {
		return h.Activate(ctx, snapshot.Version)
	}
	h.transition.Lock()
	next = h.state
	next.Prepared = snapshot.Version
	if err := h.persist(next); err != nil {
		h.transition.Unlock()
		return err
	}
	h.mu.Lock()
	h.state = next
	h.mu.Unlock()
	h.transition.Unlock()
	return h.activatePrepared(ctx)
}

func (h *Host) invalidate(err error) {
	h.mu.Lock()
	h.generation++
	h.ready, h.lastErr = false, boundedFailure(err)
	h.seen = make(map[string]bool)
	h.mu.Unlock()
	h.report(err)
}

func boundedFailure(err error) error {
	if err == nil {
		return nil
	}
	return status.Errorf(status.Code(err), "%.256s", err.Error())
}

func (h *Host) report(err error) {
	if h.c.OnError != nil && err != nil {
		h.c.OnError(fmt.Errorf("external issuer session: %.256s", err.Error()))
	}
}

func (h *Host) AuthorizesRoot(raw []byte) bool { return h.store.ContainsRoot(raw) }

func (h *Host) publicationRoots(candidate string) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	seen := make(map[string]bool)
	for _, record := range h.state.Records {
		version := record.GetAuthorityVersion()
		if !h.state.Committed[version] && version != candidate {
			continue
		}
		snapshot, err := h.store.Snapshot(version)
		if err != nil {
			return nil, err
		}
		for _, root := range snapshot.Roots {
			key := string(root.Raw)
			if seen[key] || !h.c.Now().Before(root.NotAfter.Add(rootRetentionMargin)) {
				continue
			}
			seen[key] = true
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func (h *Host) statePath() string { return filepath.Join(h.c.StateDir, "authorities.json") }

func (h *Host) persist(state authorityState) error {
	if h.c.StateDir == "" {
		return nil
	}
	if err := h.writeState(h.statePath(), state); err != nil {
		h.mu.Lock()
		h.fatalState = true
		h.generation++
		h.ready = false
		h.mu.Unlock()
		return err
	}
	return nil
}

func usableSnapshot(snapshot Snapshot, now time.Time) error {
	_, err := effectiveSnapshotExpiry(snapshot, now)
	return err
}

func effectiveSnapshotExpiry(snapshot Snapshot, now time.Time) (time.Time, error) {
	var best time.Time
	for _, chain := range snapshot.Chains {
		if len(chain) == 0 {
			continue
		}
		roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(chain[0])
		valid := true
		for i, cert := range chain {
			if cert.MaxPathLen >= 0 && len(chain)-i-1 > cert.MaxPathLen {
				valid = false
				break
			}
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				valid = false
				break
			}
			if i > 0 && cert.CheckSignatureFrom(chain[i-1]) != nil {
				valid = false
				break
			}
			if i > 0 && i < len(chain)-1 {
				intermediates.AddCert(cert)
			}
		}
		if valid {
			if _, err := chain[len(chain)-1].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates, CurrentTime: now,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}); err == nil {
				expiry := chain[0].NotAfter
				for _, cert := range chain[1:] {
					expiry = minTime(expiry, cert.NotAfter)
				}
				if expiry.After(best) {
					best = expiry
				}
			}
		}
	}
	if best.IsZero() {
		return time.Time{}, errors.New("external authority snapshot has no currently usable signing path")
	}
	return best, nil
}

func authorityActivationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	return notAfter.Add(-min(lifetime/activationThresholdDivisor, activationThresholdCap))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func readAuthorityState(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("external authority state is not a regular file")
	}
	if info.Size() > maxAuthorityStateBytes {
		return fmt.Errorf("external authority state exceeds %d bytes", maxAuthorityStateBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxAuthorityStateBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("external authority state contains trailing data")
		}
		return err
	}
	return nil
}

func writeAuthorityState(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxAuthorityStateBytes {
		return fmt.Errorf("external authority state exceeds %d bytes", maxAuthorityStateBytes)
	}
	return diskutil.AtomicWritePrivateFile(path, data)
}
