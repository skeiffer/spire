package tokenauthority

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/credentialissuer"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	rotationInterval            = 10 * time.Second
	preparationThresholdCap     = 30 * 24 * time.Hour
	preparationThresholdDivisor = 2
	activationThresholdCap      = 7 * 24 * time.Hour
	activationThresholdDivisor  = 6
	randomIdentityBytes         = 24
)

type Config struct {
	KeyManager      keymanager.KeyManager
	DataStore       datastore.DataStore
	Builder         *credtemplate.Builder
	Validator       *credvalidator.Validator
	Metrics         telemetry.Metrics
	TrustDomain     spiffeid.TrustDomain
	StateDir        string
	Binding         string
	Fresh           bool
	JWTKeyType      keymanager.KeyType
	WITKeyType      keymanager.KeyType
	DisableJWTSVIDs bool
	DisableWITSVIDs bool
	Clock           clock.Clock
	Log             logrus.FieldLogger
	WriteFile       func(string, []byte) error
}

type Manager struct {
	mu sync.RWMutex

	c            Config
	state        *stateFile
	metadataPath string
	keyPrefix    string
	keyTTL       time.Duration
	writeFile    func(string, []byte) error
	stateErr     error
}

var _ credentialissuer.AuthorityAdmin = (*Manager)(nil)

func NewManager(ctx context.Context, c Config) (*Manager, error) {
	if err := validateConfig(&c); err != nil {
		return nil, err
	}
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	if c.WriteFile == nil {
		c.WriteFile = diskutil.AtomicWritePrivateFile
	}

	m := &Manager{
		c:            c,
		metadataPath: filepath.Join(c.StateDir, metadataFileName),
		keyPrefix:    makeKeyPrefix(c.Binding, c.TrustDomain),
		keyTTL:       c.Builder.Config().X509CATTL,
		writeFile:    c.WriteFile,
	}

	state, err := loadState(m.metadataPath)
	switch {
	case err == nil:
		m.state = state
	case errors.Is(err, os.ErrNotExist) && c.Fresh:
		m.state = &stateFile{
			Version:     metadataVersion,
			Binding:     c.Binding,
			TrustDomain: c.TrustDomain.IDString(),
			JWT: authorityState{
				Enabled: !c.DisableJWTSVIDs,
				KeyType: c.JWTKeyType,
			},
			WIT: authorityState{
				Enabled: !c.DisableWITSVIDs,
				KeyType: c.WITKeyType,
			},
		}
		if err := m.persist("create token authority metadata", m.state); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		return nil, errors.New("token authority metadata is missing")
	default:
		return nil, err
	}

	if err := m.state.validate(m.c, m.keyPrefix); err != nil {
		return nil, err
	}
	if err := m.applyConfig(); err != nil {
		return nil, err
	}
	if err := m.recover(ctx); err != nil {
		return nil, err
	}
	if err := m.ensureInitialAuthorities(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) applyConfig() error {
	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	changed := false
	for _, update := range []struct {
		authority *authorityState
		enabled   bool
		keyType   keymanager.KeyType
	}{
		{authority: &next.JWT, enabled: !m.c.DisableJWTSVIDs, keyType: m.c.JWTKeyType},
		{authority: &next.WIT, enabled: !m.c.DisableWITSVIDs, keyType: m.c.WITKeyType},
	} {
		if update.authority.Enabled != update.enabled {
			update.authority.Enabled = update.enabled
			changed = true
		}
		if update.keyType != keymanager.KeyTypeUnset && update.authority.KeyType != update.keyType {
			update.authority.KeyType = update.keyType
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return m.persist("update token authority configuration", next)
}

func validateConfig(c *Config) error {
	switch {
	case c.KeyManager == nil:
		return errors.New("key manager is required")
	case c.DataStore == nil:
		return errors.New("data store is required")
	case c.Builder == nil:
		return errors.New("credential builder is required")
	case c.Validator == nil:
		return errors.New("credential validator is required")
	case c.Metrics == nil:
		return errors.New("metrics is required")
	case c.TrustDomain.IsZero():
		return errors.New("trust domain is required")
	case c.StateDir == "":
		return errors.New("state directory is required")
	case c.Binding == "":
		return errors.New("binding is required")
	case c.Log == nil:
		return errors.New("logger is required")
	case !c.DisableJWTSVIDs && c.JWTKeyType == keymanager.KeyTypeUnset:
		return errors.New("jwt key type is required")
	case !c.DisableWITSVIDs && c.WITKeyType == keymanager.KeyTypeUnset:
		return errors.New("wit key type is required")
	case c.Builder.Config().X509CATTL <= 0:
		return errors.New("token key lifetime must be positive")
	default:
		return nil
	}
}

func (m *Manager) IsJWTSVIDsDisabled() bool {
	return m.c.DisableJWTSVIDs
}

func (m *Manager) IsWITSVIDsDisabled() bool {
	return m.c.DisableWITSVIDs
}

func (m *Manager) IsUpstreamAuthority() bool {
	return false
}

func (m *Manager) CheckHealth() health.State {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.stateErr != nil {
		return health.State{
			Live:         false,
			Ready:        false,
			LiveDetails:  "token authority metadata state is uncertain; restart after reconciling persistent state",
			ReadyDetails: "token authority metadata state is uncertain; restart after reconciling persistent state",
		}
	}
	now := m.c.Clock.Now()
	for _, authority := range []*authorityState{&m.state.JWT, &m.state.WIT} {
		if !authority.Enabled {
			continue
		}
		current := authority.find(authority.Current)
		if current == nil || current.Status != statusActive || !current.NotAfter.After(now) {
			return health.State{
				Live:         true,
				Ready:        false,
				ReadyDetails: "an enabled token authority has no unexpired active key",
			}
		}
	}
	return health.State{Live: true, Ready: true}
}

func (m *Manager) GetCurrentJWTKeySlot() credentialissuer.AuthorityState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.JWT.view(m.state.JWT.Current)
}

func (m *Manager) GetNextJWTKeySlot() credentialissuer.AuthorityState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.JWT.view(m.state.JWT.Next)
}

func (m *Manager) GetCurrentX509CASlot() credentialissuer.AuthorityState {
	return credentialissuer.AuthorityView{}
}

func (m *Manager) GetNextX509CASlot() credentialissuer.AuthorityState {
	return credentialissuer.AuthorityView{}
}

func (m *Manager) PrepareX509CA(context.Context) error {
	return status.Error(codes.Unimplemented, "external x509 authority administration is not supported")
}

func (m *Manager) RotateX509CA(context.Context) error {
	return status.Error(codes.Unimplemented, "external x509 authority administration is not supported")
}

func (m *Manager) NotifyTaintedX509Authority(context.Context, string) error {
	return status.Error(codes.Unimplemented, "external x509 authority administration is not supported")
}

func (m *Manager) PrepareJWTKey(ctx context.Context) (err error) {
	if m.IsJWTSVIDsDisabled() {
		return nil
	}
	counter := telemetry_server.StartServerCAManagerPrepareJWTKeyCall(m.c.Metrics)
	defer counter.Done(&err)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkState(); err != nil {
		return err
	}
	return m.prepare(ctx, authorityJWT, false)
}

func (m *Manager) RotateJWTKey(ctx context.Context) error {
	if m.IsJWTSVIDsDisabled() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkState(); err != nil {
		return err
	}
	return m.activateNext(ctx, authorityJWT)
}

func (m *Manager) currentWITView() credentialissuer.AuthorityState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state.WIT.view(m.state.WIT.Current)
}

func (m *Manager) Run(ctx context.Context) error {
	ticker := m.c.Clock.Ticker(rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := m.rotate(ctx); err != nil {
				m.c.Log.WithError(err).Error("Unable to rotate token authorities")
			}
		}
	}
}

func (m *Manager) rotate(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs error
	if !m.c.DisableJWTSVIDs {
		errs = errors.Join(errs, m.rotateAuthority(ctx, authorityJWT))
	}
	if !m.c.DisableWITSVIDs {
		errs = errors.Join(errs, m.rotateAuthority(ctx, authorityWIT))
	}
	return errs
}

func (m *Manager) rotateAuthority(ctx context.Context, kind authorityKind) error {
	if err := m.checkState(); err != nil {
		return err
	}
	if err := m.reconcileAuthority(ctx, kind); err != nil {
		return err
	}
	authority := m.authority(kind)
	current := authority.find(authority.Current)
	if current == nil {
		return m.prepare(ctx, kind, true)
	}
	now := m.c.Clock.Now()
	if authority.Next == "" && now.After(preparationThreshold(current.IssuedAt, current.NotAfter)) {
		if err := m.prepare(ctx, kind, false); err != nil {
			return err
		}
		authority = m.authority(kind)
	}
	if authority.Next != "" && now.After(activationThreshold(current.IssuedAt, current.NotAfter)) {
		return m.activateNext(ctx, kind)
	}
	return nil
}

func preparationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	return notAfter.Add(-min(lifetime/preparationThresholdDivisor, preparationThresholdCap))
}

func activationThreshold(issuedAt, notAfter time.Time) time.Time {
	lifetime := notAfter.Sub(issuedAt)
	return notAfter.Add(-min(lifetime/activationThresholdDivisor, activationThresholdCap))
}

func (m *Manager) ensureInitialAuthorities(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.c.DisableJWTSVIDs && m.state.JWT.Current == "" {
		if err := m.prepare(ctx, authorityJWT, true); err != nil {
			return fmt.Errorf("initialize JWT authority: %w", err)
		}
	}
	if !m.c.DisableWITSVIDs && m.state.WIT.Current == "" {
		if err := m.prepare(ctx, authorityWIT, true); err != nil {
			return fmt.Errorf("initialize WIT authority: %w", err)
		}
	}
	return nil
}

func (m *Manager) recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validateKnownKeys(ctx); err != nil {
		return err
	}
	for _, kind := range []authorityKind{authorityJWT, authorityWIT} {
		if !m.authority(kind).Enabled {
			continue
		}
		if err := m.recoverPending(ctx, kind); err != nil {
			return err
		}
		if err := m.reconcileAuthority(ctx, kind); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) recoverPending(ctx context.Context, kind authorityKind) error {
	pending := m.authority(kind).Pending
	if pending == nil {
		return nil
	}
	switch pending.Type {
	case operationPrepare:
		return m.finishPrepare(ctx, kind)
	case operationActivate:
		return m.finishActivation(ctx, kind)
	default:
		return fmt.Errorf("%s authority has unknown pending operation %q", kind, pending.Type)
	}
}

func (m *Manager) reconcileAuthority(ctx context.Context, kind authorityKind) error {
	authority := m.authority(kind)
	if authority.Pending != nil {
		return fmt.Errorf("%s authority has unresolved pending operation", kind)
	}

	if authority.Current != "" {
		record := authority.find(authority.Current)
		healthy, err := m.recordHealthy(ctx, kind, record)
		if err != nil {
			return err
		}
		if !healthy {
			if err := m.retire(ctx, kind, authority.Current); err != nil {
				return err
			}
			authority = m.authority(kind)
			if authority.Next != "" {
				next := authority.find(authority.Next)
				nextHealthy, err := m.recordHealthy(ctx, kind, next)
				if err != nil {
					return err
				}
				if nextHealthy {
					return m.activateNext(ctx, kind)
				}
				if err := m.retire(ctx, kind, authority.Next); err != nil {
					return err
				}
			}
			return m.prepare(ctx, kind, true)
		}
	}

	authority = m.authority(kind)
	if authority.Next != "" {
		record := authority.find(authority.Next)
		healthy, err := m.recordHealthy(ctx, kind, record)
		if err != nil {
			return err
		}
		if !healthy {
			return m.retire(ctx, kind, authority.Next)
		}
	}
	return nil
}

func (m *Manager) prepare(ctx context.Context, kind authorityKind, activate bool) error {
	authority := m.authority(kind)
	if !authority.Enabled {
		return nil
	}
	if authority.Pending != nil {
		return fmt.Errorf("%s authority already has a pending operation", kind)
	}
	if !activate && authority.Next != "" {
		return fmt.Errorf("%s authority already has a prepared key", kind)
	}
	if len(authority.History) >= maxAuthorityKeys {
		return fmt.Errorf("%s authority history limit of %d reached", kind, maxAuthorityKeys)
	}

	operationID, err := newIdentity()
	if err != nil {
		return fmt.Errorf("generate %s operation identity: %w", kind, err)
	}
	keyIdentity, err := newIdentity()
	if err != nil {
		return fmt.Errorf("generate %s key identity: %w", kind, err)
	}
	kid, err := newIdentity()
	if err != nil {
		return fmt.Errorf("generate %s kid: %w", kind, err)
	}
	now := m.c.Clock.Now().UTC()
	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	target := authorityFor(next, kind)
	target.Pending = &pendingOperation{
		ID:       operationID,
		Type:     operationPrepare,
		Stage:    stageIntent,
		KeyID:    m.keyPrefix + string(kind) + "-" + keyIdentity,
		KID:      kid,
		IssuedAt: now,
		NotAfter: now.Add(m.keyTTL),
		Activate: activate,
	}
	if err := m.persist(fmt.Sprintf("persist %s prepare intent", kind), next); err != nil {
		return err
	}
	return m.finishPrepare(ctx, kind)
}

func (m *Manager) finishPrepare(ctx context.Context, kind authorityKind) error {
	pending := m.authority(kind).Pending
	if pending == nil || pending.Type != operationPrepare {
		return fmt.Errorf("%s authority prepare intent is missing", kind)
	}

	if pending.Stage == stageIntent {
		key, err := m.c.KeyManager.GetKey(ctx, pending.KeyID)
		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			key, err = m.c.KeyManager.GenerateKey(ctx, pending.KeyID, m.keyType(kind))
			if err != nil {
				return fmt.Errorf("generate %s key: %w", kind, err)
			}
		default:
			return fmt.Errorf("load pending %s key: %w", kind, err)
		}
		publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return fmt.Errorf("marshal %s public key: %w", kind, err)
		}
		next, err := cloneState(m.state)
		if err != nil {
			return err
		}
		target := authorityFor(next, kind)
		target.Pending.PublicKey = publicKey
		target.Pending.Stage = stageBound
		if err := m.persist(fmt.Sprintf("persist %s public key binding", kind), next); err != nil {
			return err
		}
		pending = m.authority(kind).Pending
	}

	if pending.Stage == stageBound {
		published, err := m.bundleKey(ctx, kind, pending.KID)
		if err != nil {
			return err
		}
		switch {
		case published != nil && published.TaintedKey:
			return m.abandonPending(kind, fmt.Errorf("%s pending key %q is tainted", kind, pending.KID))
		case published != nil && !bytes.Equal(published.PkixBytes, pending.PublicKey):
			return fmt.Errorf("%s pending key %q has mismatched published key", kind, pending.KID)
		case published == nil:
			if _, err := m.c.DataStore.AppendBundle(ctx, m.bundleFor(kind, pending)); err != nil {
				return fmt.Errorf("publish %s key: %w", kind, err)
			}
		}
		if err := m.requirePublished(ctx, kind, pending.KID, pending.PublicKey, pending.NotAfter); err != nil {
			return err
		}
		next, err := cloneState(m.state)
		if err != nil {
			return err
		}
		authorityFor(next, kind).Pending.Stage = stagePublished
		if err := m.persist(fmt.Sprintf("persist %s publication", kind), next); err != nil {
			return err
		}
		pending = m.authority(kind).Pending
	}

	if pending.Stage != stagePublished {
		return fmt.Errorf("%s authority has unsafe pending stage %q", kind, pending.Stage)
	}
	if err := m.requirePublished(ctx, kind, pending.KID, pending.PublicKey, pending.NotAfter); err != nil {
		if errors.Is(err, errKeyUnavailable) {
			return m.abandonPending(kind, err)
		}
		return err
	}
	key, err := m.c.KeyManager.GetKey(ctx, pending.KeyID)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return m.abandonPending(kind, fmt.Errorf("%w: pending %s private key is missing", errKeyUnavailable, kind))
		}
		return fmt.Errorf("load pending %s key: %w", kind, err)
	}
	if err := requirePublicKeyBinding(key, pending.PublicKey); err != nil {
		return fmt.Errorf("%s pending key binding mismatch: %w", kind, err)
	}

	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	target := authorityFor(next, kind)
	pending = target.Pending
	recordStatus := statusPrepared
	if pending.Activate {
		recordStatus = statusActive
		if target.Current != "" {
			target.find(target.Current).Status = statusRetired
		}
		target.Current = pending.KID
	} else {
		target.Next = pending.KID
	}
	target.History = append(target.History, keyRecord{
		KeyID:     pending.KeyID,
		KID:       pending.KID,
		PublicKey: append([]byte(nil), pending.PublicKey...),
		IssuedAt:  pending.IssuedAt,
		NotAfter:  pending.NotAfter,
		Status:    recordStatus,
	})
	target.Pending = nil
	if err := m.persist(fmt.Sprintf("commit %s key", kind), next); err != nil {
		return err
	}
	if pending.Activate {
		m.incrementActivation(kind)
	}
	return nil
}

func (m *Manager) activateNext(ctx context.Context, kind authorityKind) error {
	authority := m.authority(kind)
	if !authority.Enabled {
		return nil
	}
	if authority.Pending != nil {
		return fmt.Errorf("%s authority already has a pending operation", kind)
	}
	if authority.Next == "" {
		return fmt.Errorf("%s authority has no prepared key", kind)
	}
	record := authority.find(authority.Next)
	healthy, err := m.recordHealthy(ctx, kind, record)
	if err != nil {
		return err
	}
	if !healthy {
		return fmt.Errorf("%s prepared key is unavailable", kind)
	}

	operationID, err := newIdentity()
	if err != nil {
		return fmt.Errorf("generate %s activation identity: %w", kind, err)
	}
	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	target := authorityFor(next, kind)
	target.Pending = &pendingOperation{
		ID:        operationID,
		Type:      operationActivate,
		Stage:     stageIntent,
		KeyID:     record.KeyID,
		KID:       record.KID,
		PublicKey: append([]byte(nil), record.PublicKey...),
		IssuedAt:  record.IssuedAt,
		NotAfter:  record.NotAfter,
	}
	if err := m.persist(fmt.Sprintf("persist %s activation intent", kind), next); err != nil {
		return err
	}
	return m.finishActivation(ctx, kind)
}

func (m *Manager) finishActivation(ctx context.Context, kind authorityKind) error {
	authority := m.authority(kind)
	pending := authority.Pending
	if pending == nil || pending.Type != operationActivate || pending.Stage != stageIntent {
		return fmt.Errorf("%s authority activation intent is unsafe", kind)
	}
	record := authority.find(pending.KID)
	if record == nil || authority.Next != pending.KID || record.Status != statusPrepared {
		return fmt.Errorf("%s authority activation target is not prepared", kind)
	}
	healthy, err := m.recordHealthy(ctx, kind, record)
	if err != nil {
		return err
	}
	if !healthy {
		return fmt.Errorf("%s activation target is unavailable", kind)
	}

	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	target := authorityFor(next, kind)
	if target.Current != "" {
		target.find(target.Current).Status = statusRetired
	}
	target.find(pending.KID).Status = statusActive
	target.Current = pending.KID
	target.Next = ""
	target.Pending = nil
	if err := m.persist(fmt.Sprintf("commit %s activation", kind), next); err != nil {
		return err
	}
	m.incrementActivation(kind)
	return nil
}

func (m *Manager) retire(_ context.Context, kind authorityKind, kid string) error {
	next, err := cloneState(m.state)
	if err != nil {
		return err
	}
	target := authorityFor(next, kind)
	record := target.find(kid)
	if record == nil {
		return fmt.Errorf("%s authority cannot retire unknown kid %q", kind, kid)
	}
	record.Status = statusRetired
	if target.Current == kid {
		target.Current = ""
	}
	if target.Next == kid {
		target.Next = ""
	}
	return m.persist(fmt.Sprintf("retire %s key", kind), next)
}

func (m *Manager) abandonPending(kind authorityKind, cause error) error {
	next, err := cloneState(m.state)
	if err != nil {
		return errors.Join(cause, err)
	}
	authorityFor(next, kind).Pending = nil
	if err := m.persist(fmt.Sprintf("abandon %s pending operation", kind), next); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (m *Manager) recordHealthy(ctx context.Context, kind authorityKind, record *keyRecord) (bool, error) {
	if record == nil {
		return false, nil
	}
	if !record.NotAfter.After(m.c.Clock.Now()) {
		return false, nil
	}
	published, err := m.bundleKey(ctx, kind, record.KID)
	if err != nil {
		return false, err
	}
	if published == nil || published.TaintedKey {
		return false, nil
	}
	if !bytes.Equal(published.PkixBytes, record.PublicKey) {
		return false, fmt.Errorf("%s key %q has mismatched published key", kind, record.KID)
	}
	key, err := m.c.KeyManager.GetKey(ctx, record.KeyID)
	switch status.Code(err) {
	case codes.OK:
	case codes.NotFound:
		return false, nil
	default:
		return false, fmt.Errorf("load %s key %q: %w", kind, record.KeyID, err)
	}
	if err := requirePublicKeyBinding(key, record.PublicKey); err != nil {
		return false, fmt.Errorf("%s key %q has mismatched key binding: %w", kind, record.KeyID, err)
	}
	return true, nil
}

func (m *Manager) validateKnownKeys(ctx context.Context) error {
	known := make(map[string][]byte)
	for _, authority := range []*authorityState{&m.state.JWT, &m.state.WIT} {
		for i := range authority.History {
			known[authority.History[i].KeyID] = authority.History[i].PublicKey
		}
		if authority.Pending != nil {
			known[authority.Pending.KeyID] = authority.Pending.PublicKey
		}
	}

	keys, err := m.c.KeyManager.GetKeys(ctx)
	if err != nil {
		return fmt.Errorf("list key manager keys: %w", err)
	}
	for _, key := range keys {
		expected, ok := known[key.ID()]
		if !ok {
			return fmt.Errorf("unprovable unknown token authority key %q", key.ID())
		}
		if ok && len(expected) > 0 {
			if err := requirePublicKeyBinding(key, expected); err != nil {
				return fmt.Errorf("token authority key %q has mismatched key binding: %w", key.ID(), err)
			}
		}
	}
	return nil
}

func requirePublicKeyBinding(key keymanager.Key, expected []byte) error {
	publicKey, err := x509.ParsePKIXPublicKey(expected)
	if err != nil {
		return fmt.Errorf("parse public key binding: %w", err)
	}
	equal, err := cryptoutil.PublicKeyEqual(key.Public(), publicKey)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New("public keys do not match")
	}
	return nil
}

func (m *Manager) requirePublished(ctx context.Context, kind authorityKind, kid string, publicKey []byte, notAfter time.Time) error {
	key, err := m.bundleKey(ctx, kind, kid)
	if err != nil {
		return err
	}
	switch {
	case key == nil:
		return fmt.Errorf("%w: %s key %q is not published", errKeyUnavailable, kind, kid)
	case key.TaintedKey:
		return fmt.Errorf("%w: %s key %q is tainted", errKeyUnavailable, kind, kid)
	case !bytes.Equal(key.PkixBytes, publicKey):
		return fmt.Errorf("%s key %q has mismatched published key", kind, kid)
	case key.NotAfter != notAfter.Unix():
		return fmt.Errorf("%s key %q has mismatched expiration", kind, kid)
	default:
		return nil
	}
}

func (m *Manager) bundleKey(ctx context.Context, kind authorityKind, kid string) (*common.PublicKey, error) {
	bundle, err := m.c.DataStore.FetchBundle(ctx, m.c.TrustDomain.IDString())
	if err != nil {
		return nil, fmt.Errorf("fetch trust domain bundle: %w", err)
	}
	if bundle == nil {
		return nil, errors.New("trust domain bundle is missing")
	}
	var keys []*common.PublicKey
	switch kind {
	case authorityJWT:
		keys = bundle.JwtSigningKeys
	case authorityWIT:
		keys = bundle.WitSigningKeys
	}
	var found *common.PublicKey
	for _, key := range keys {
		if key.Kid != kid {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%s bundle contains duplicate kid %q", kind, kid)
		}
		found = key
	}
	return found, nil
}

func (m *Manager) bundleFor(kind authorityKind, pending *pendingOperation) *common.Bundle {
	key := &common.PublicKey{
		PkixBytes: append([]byte(nil), pending.PublicKey...),
		Kid:       pending.KID,
		NotAfter:  pending.NotAfter.Unix(),
	}
	bundle := &common.Bundle{TrustDomainId: m.c.TrustDomain.IDString()}
	switch kind {
	case authorityJWT:
		bundle.JwtSigningKeys = []*common.PublicKey{key}
	case authorityWIT:
		bundle.WitSigningKeys = []*common.PublicKey{key}
	}
	return bundle
}

func (m *Manager) persist(action string, next *stateFile) error {
	if err := next.validate(m.c, m.keyPrefix); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	data, err := marshalState(next)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := ensureNoPendingStateWrite(m.metadataPath); err != nil {
		m.stateErr = fmt.Errorf("token authority metadata state is uncertain: %w", err)
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := m.writeFile(m.metadataPath, data); err != nil {
		m.stateErr = fmt.Errorf("token authority metadata state is uncertain: %w", err)
		return fmt.Errorf("%s: %w", action, err)
	}
	m.state = next
	return nil
}

func (m *Manager) checkState() error {
	return m.stateErr
}

func ensureNoPendingStateWrite(path string) error {
	if _, err := os.Lstat(path + ".tmp"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("ambiguous pending state write")
	}
	return nil
}

func (m *Manager) authority(kind authorityKind) *authorityState {
	return authorityFor(m.state, kind)
}

func authorityFor(state *stateFile, kind authorityKind) *authorityState {
	switch kind {
	case authorityJWT:
		return &state.JWT
	case authorityWIT:
		return &state.WIT
	default:
		panic("unknown token authority kind")
	}
}

func (m *Manager) keyType(kind authorityKind) keymanager.KeyType {
	return m.authority(kind).KeyType
}

func (m *Manager) incrementActivation(kind authorityKind) {
	switch kind {
	case authorityJWT:
		telemetry_server.IncrActivateJWTKeyManagerCounter(m.c.Metrics)
	case authorityWIT:
		telemetry_server.IncrActivateWITKeyManagerCounter(m.c.Metrics)
	}
}

func makeKeyPrefix(binding string, trustDomain spiffeid.TrustDomain) string {
	sum := sha256.Sum256([]byte(binding + "\x00" + trustDomain.IDString()))
	return "token-authority-" + base64.RawURLEncoding.EncodeToString(sum[:12]) + "-"
}

func newIdentity() (string, error) {
	value := make([]byte, randomIdentityBytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type authorityKind string

const (
	authorityJWT authorityKind = "jwt"
	authorityWIT authorityKind = "wit"
)

var errKeyUnavailable = errors.New("token authority key is unavailable")
