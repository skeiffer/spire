package tokenauthority

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/spire/pkg/server/externalstate"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
)

const (
	metadataFileName  = "token-authorities.json"
	metadataVersion   = 1
	maxMetadataSize   = 1 << 20
	maxAuthorityKeys  = 128
	statusPrepared    = "prepared"
	statusActive      = "active"
	statusRetired     = "retired"
	operationPrepare  = "prepare"
	operationActivate = "activate"
	stageIntent       = "intent"
	stageBound        = "bound"
	stagePublished    = "published"
)

type stateFile struct {
	Version     int            `json:"version"`
	Binding     string         `json:"binding"`
	TrustDomain string         `json:"trust_domain"`
	JWT         authorityState `json:"jwt"`
	WIT         authorityState `json:"wit"`
}

type authorityState struct {
	Enabled bool               `json:"enabled"`
	KeyType keymanager.KeyType `json:"key_type"`
	Current string             `json:"current,omitempty"`
	Next    string             `json:"next,omitempty"`
	History []keyRecord        `json:"history,omitempty"`
	Pending *pendingOperation  `json:"pending,omitempty"`
}

type keyRecord struct {
	KeyID     string    `json:"key_id"`
	KID       string    `json:"kid"`
	PublicKey []byte    `json:"public_key"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
	Status    string    `json:"status"`
}

type pendingOperation struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Stage     string    `json:"stage"`
	KeyID     string    `json:"key_id"`
	KID       string    `json:"kid"`
	PublicKey []byte    `json:"public_key,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	NotAfter  time.Time `json:"not_after"`
	Activate  bool      `json:"activate,omitempty"`
}

func loadState(path string) (*stateFile, error) {
	var state stateFile
	if err := externalstate.ReadJSON(path, &state); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if isStatePathSafetyError(err) {
			return nil, fmt.Errorf("load token authority metadata: %w", err)
		}
		return nil, fmt.Errorf("decode token authority metadata: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat token authority metadata: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("token authority metadata is not a regular file")
	}
	if info.Size() > maxMetadataSize {
		return nil, fmt.Errorf("token authority metadata exceeds %d bytes", maxMetadataSize)
	}
	return &state, nil
}

func isStatePathSafetyError(err error) bool {
	message := err.Error()
	for _, marker := range []string{
		"ambiguous pending state write",
		"missing protected DACL",
		"symlink",
		"unsafe permissions",
		"untrusted owner",
		"untrusted write access",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func marshalState(state *stateFile) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode token authority metadata: %w", err)
	}
	data = append(data, '\n')
	if len(data) > maxMetadataSize {
		return nil, fmt.Errorf("token authority metadata exceeds %d bytes", maxMetadataSize)
	}
	return data, nil
}

func cloneState(state *stateFile) (*stateFile, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var cloned stateFile
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, err
	}
	return &cloned, nil
}

func (s *stateFile) validate(c Config, keyPrefix string) error {
	if s.Version != metadataVersion {
		return fmt.Errorf("unsupported token authority metadata version %d", s.Version)
	}
	if s.Binding != c.Binding {
		return fmt.Errorf("token authority binding mismatch: metadata is bound to %q", s.Binding)
	}
	if s.TrustDomain != c.TrustDomain.IDString() {
		return fmt.Errorf("token authority trust domain mismatch: metadata is bound to %q", s.TrustDomain)
	}
	if err := s.JWT.validate("jwt", keyPrefix+"jwt-"); err != nil {
		return err
	}
	return s.WIT.validate("wit", keyPrefix+"wit-")
}

func (s *authorityState) validate(name, keyPrefix string) error {
	switch s.KeyType {
	case keymanager.KeyTypeUnset, keymanager.ECP256, keymanager.ECP384, keymanager.RSA2048, keymanager.RSA4096:
	default:
		return fmt.Errorf("%s authority has unknown key type %d", name, s.KeyType)
	}
	if s.KeyType == keymanager.KeyTypeUnset && (s.Enabled || s.Current != "" || s.Next != "" || len(s.History) != 0 || s.Pending != nil) {
		return fmt.Errorf("%s authority key type is required", name)
	}
	if len(s.History) > maxAuthorityKeys {
		return fmt.Errorf("%s authority history exceeds %d entries", name, maxAuthorityKeys)
	}

	kids := make(map[string]struct{}, len(s.History))
	keyIDs := make(map[string]struct{}, len(s.History))
	var activeCount, preparedCount int
	for i := range s.History {
		record := &s.History[i]
		switch {
		case record.KeyID == "":
			return fmt.Errorf("%s authority history entry %d has no key id", name, i)
		case !strings.HasPrefix(record.KeyID, keyPrefix):
			return fmt.Errorf("%s authority history entry %d has invalid key id", name, i)
		case record.KID == "":
			return fmt.Errorf("%s authority history entry %d has no kid", name, i)
		case len(record.PublicKey) == 0:
			return fmt.Errorf("%s authority history entry %d has no public key", name, i)
		case record.IssuedAt.IsZero() || record.NotAfter.IsZero() || !record.NotAfter.After(record.IssuedAt):
			return fmt.Errorf("%s authority history entry %d has invalid lifetime", name, i)
		}
		if _, err := x509.ParsePKIXPublicKey(record.PublicKey); err != nil {
			return fmt.Errorf("%s authority history entry %d has invalid public key: %w", name, i, err)
		}
		if _, ok := kids[record.KID]; ok {
			return fmt.Errorf("%s authority contains duplicate kid %q", name, record.KID)
		}
		kids[record.KID] = struct{}{}
		if _, ok := keyIDs[record.KeyID]; ok {
			return fmt.Errorf("%s authority contains duplicate key id %q", name, record.KeyID)
		}
		keyIDs[record.KeyID] = struct{}{}
		switch record.Status {
		case statusActive:
			activeCount++
		case statusPrepared:
			preparedCount++
		case statusRetired:
		default:
			return fmt.Errorf("%s authority history entry %d has unknown status %q", name, i, record.Status)
		}
	}
	if activeCount > 1 {
		return fmt.Errorf("%s authority contains multiple active keys", name)
	}
	if preparedCount > 1 {
		return fmt.Errorf("%s authority contains multiple prepared keys", name)
	}
	if activeCount == 1 && s.Current == "" {
		return fmt.Errorf("%s authority contains an unreferenced active key", name)
	}
	if preparedCount == 1 && s.Next == "" {
		return fmt.Errorf("%s authority contains an unreferenced prepared key", name)
	}
	if err := s.validateSlot(name, s.Current, statusActive); err != nil {
		return err
	}
	if err := s.validateSlot(name, s.Next, statusPrepared); err != nil {
		return err
	}
	if s.Pending != nil {
		if err := s.Pending.validate(name, keyPrefix); err != nil {
			return err
		}
		if _, ok := keyIDs[s.Pending.KeyID]; ok && s.Pending.Type == operationPrepare {
			return fmt.Errorf("%s authority pending prepare reuses key id %q", name, s.Pending.KeyID)
		}
		if _, ok := kids[s.Pending.KID]; ok && s.Pending.Type == operationPrepare {
			return fmt.Errorf("%s authority pending prepare reuses kid %q", name, s.Pending.KID)
		}
		if s.Pending.Type == operationActivate {
			record := s.find(s.Pending.KID)
			if record == nil || s.Next != s.Pending.KID || record.Status != statusPrepared {
				return fmt.Errorf("%s authority activation target is not prepared", name)
			}
		}
	}
	return nil
}

func (s *authorityState) validateSlot(name, kid, expectedStatus string) error {
	if kid == "" {
		return nil
	}
	record := s.find(kid)
	if record == nil {
		return fmt.Errorf("%s authority slot references unknown kid %q", name, kid)
	}
	if record.Status != expectedStatus {
		return fmt.Errorf("%s authority slot %q has status %q", name, kid, record.Status)
	}
	return nil
}

func (p *pendingOperation) validate(name, keyPrefix string) error {
	switch {
	case p.ID == "":
		return fmt.Errorf("%s authority pending operation has no id", name)
	case p.Type != operationPrepare && p.Type != operationActivate:
		return fmt.Errorf("%s authority pending operation has unknown type %q", name, p.Type)
	case p.Stage != stageIntent && p.Stage != stageBound && p.Stage != stagePublished:
		return fmt.Errorf("%s authority pending operation has unknown stage %q", name, p.Stage)
	case p.KeyID == "" || !strings.HasPrefix(p.KeyID, keyPrefix):
		return fmt.Errorf("%s authority pending operation has invalid key id", name)
	case p.KID == "":
		return fmt.Errorf("%s authority pending operation has no kid", name)
	case p.IssuedAt.IsZero() || p.NotAfter.IsZero() || !p.NotAfter.After(p.IssuedAt):
		return fmt.Errorf("%s authority pending operation has invalid lifetime", name)
	case (p.Stage == stageBound || p.Stage == stagePublished) && len(p.PublicKey) == 0:
		return fmt.Errorf("%s authority pending operation has no public key binding", name)
	case p.Type == operationActivate && p.Stage != stageIntent:
		return fmt.Errorf("%s authority activation has unsafe stage %q", name, p.Stage)
	}
	if len(p.PublicKey) > 0 {
		if _, err := x509.ParsePKIXPublicKey(p.PublicKey); err != nil {
			return fmt.Errorf("%s authority pending operation has invalid public key: %w", name, err)
		}
	}
	return nil
}

func (s *authorityState) find(kid string) *keyRecord {
	for i := range s.History {
		if s.History[i].KID == kid {
			return &s.History[i]
		}
	}
	return nil
}

func (s *authorityState) view(kid string) authorityView {
	record := s.find(kid)
	if record == nil {
		return authorityView{}
	}
	return authorityView{
		id:       record.KID,
		notAfter: record.NotAfter,
		status:   journalStatus(record.Status),
	}
}

func journalStatus(status string) journal.Status {
	switch status {
	case statusPrepared:
		return journal.Status_PREPARED
	case statusActive:
		return journal.Status_ACTIVE
	case statusRetired:
		return journal.Status_OLD
	default:
		return journal.Status_UNKNOWN
	}
}

type authorityView struct {
	id       string
	notAfter time.Time
	status   journal.Status
}

func (v authorityView) AuthorityID() string         { return v.id }
func (v authorityView) UpstreamAuthorityID() string { return "" }
func (v authorityView) NotAfter() time.Time         { return v.notAfter }
func (v authorityView) Status() journal.Status      { return v.status }
