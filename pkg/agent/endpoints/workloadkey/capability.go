package workloadkey

import (
	"crypto"
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
)

var (
	ErrInvalidCapability      = errors.New("capability is invalid")
	ErrUnauthorizedCapability = errors.New("capability is not authorized for this workload process")
	ErrExpiredCapability      = errors.New("capability is expired")
	ErrGenerationMismatch     = errors.New("capability generation mismatch")
)

type Binding struct {
	WorkloadID string
	ProcessID  int32
}

type Capability struct {
	ID         [32]byte
	Generation uint64
	PublicKey  crypto.PublicKey
	ExpiresAt  time.Time
}

type capabilityState struct {
	binding Binding
	key     workloadkeyprovider.Key
	expires time.Time
}

type CapabilityStore struct {
	mu           sync.Mutex
	capabilities map[[32]byte]capabilityState
	active       map[Binding][32]byte
}

func NewCapabilityStore() *CapabilityStore {
	return &CapabilityStore{
		capabilities: make(map[[32]byte]capabilityState),
		active:       make(map[Binding][32]byte),
	}
}

func (s *CapabilityStore) Issue(binding Binding, key workloadkeyprovider.Key, expires time.Time) (Capability, error) {
	if binding.WorkloadID == "" || binding.ProcessID <= 0 || key == nil || !expires.After(time.Now()) {
		return Capability{}, errors.New("invalid capability input")
	}
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Capability{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.active[binding]; ok {
		delete(s.capabilities, previous)
	}
	s.capabilities[id] = capabilityState{binding: binding, key: key, expires: expires}
	s.active[binding] = id
	return Capability{
		ID:         id,
		Generation: key.Generation(),
		PublicKey:  key.Public(),
		ExpiresAt:  expires,
	}, nil
}

func (s *CapabilityStore) Sign(id [32]byte, binding Binding, generation uint64, digest []byte, now time.Time) ([]byte, error) {
	s.mu.Lock()
	state, ok := s.capabilities[id]
	s.mu.Unlock()
	switch {
	case !ok:
		return nil, ErrInvalidCapability
	case state.binding != binding:
		return nil, ErrUnauthorizedCapability
	case state.key.Generation() != generation:
		return nil, ErrGenerationMismatch
	case !now.Before(state.expires):
		return nil, ErrExpiredCapability
	case len(digest) != crypto.SHA256.Size():
		return nil, errors.New("only SHA-256 digests are accepted")
	}
	return state.key.Sign(rand.Reader, digest, crypto.SHA256)
}

func (s *CapabilityStore) Revoke(binding Binding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.active[binding]; ok {
		delete(s.capabilities, id)
		delete(s.active, binding)
	}
}
