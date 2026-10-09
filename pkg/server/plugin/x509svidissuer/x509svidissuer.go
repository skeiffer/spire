package x509svidissuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
)

var (
	ErrVersionReused      = errors.New("authority version reused with different content")
	ErrUnknownAuthority   = errors.New("unknown authority version")
	ErrNoAuthorityOverlap = errors.New("authority activation has no trust-root overlap")
	ErrRetentionWindow    = errors.New("authority retention window has not elapsed")
	ErrAuthorityTainted   = errors.New("active authority is tainted")
)

type X509SVIDIssuer interface {
	catalog.PluginInfo
	IssueX509SVID(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error)
	SubscribeAuthoritySnapshots(context.Context) (AuthoritySnapshotStream, error)
}

type AuthoritySnapshotStream interface {
	Recv() (*issuerv1.AuthoritySnapshot, error)
}

type Snapshot struct {
	Version       string
	Roots         []*x509.Certificate
	Intermediates []*x509.Certificate
	PublishedAt   time.Time
}

type authorityRecord struct {
	snapshot   Snapshot
	digest     [32]byte
	retainTill time.Time
	taint      error
}

type AuthorityStore struct {
	mu        sync.RWMutex
	clockSkew time.Duration
	active    string
	records   map[string]*authorityRecord
}

func NewAuthorityStore(clockSkew time.Duration) *AuthorityStore {
	return &AuthorityStore{clockSkew: clockSkew, records: make(map[string]*authorityRecord)}
}

func (s *AuthorityStore) Publish(snapshot Snapshot) error {
	if snapshot.Version == "" || len(snapshot.Roots) == 0 {
		return errors.New("authority version and roots are required")
	}
	h := sha256.New()
	for _, cert := range append(append([]*x509.Certificate{}, snapshot.Roots...), snapshot.Intermediates...) {
		if cert == nil {
			return errors.New("authority snapshot contains nil certificate")
		}
		_, _ = h.Write(cert.Raw)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))

	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.records[snapshot.Version]; ok {
		if previous.digest != digest {
			return ErrVersionReused
		}
		return nil
	}
	s.records[snapshot.Version] = &authorityRecord{snapshot: cloneSnapshot(snapshot), digest: digest}
	return nil
}

func (s *AuthorityStore) Activate(version string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, ok := s.records[version]
	if !ok {
		return ErrUnknownAuthority
	}
	if next.taint != nil {
		return fmt.Errorf("%w: %v", ErrAuthorityTainted, next.taint)
	}
	for _, root := range next.snapshot.Roots {
		if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
			return errors.New("authority root is outside its validity window")
		}
	}
	if s.active != "" && s.active != version {
		current := s.records[s.active]
		if !hasRootOverlap(current.snapshot.Roots, next.snapshot.Roots) {
			return ErrNoAuthorityOverlap
		}
		if current.retainTill.Before(now.Add(s.clockSkew)) {
			current.retainTill = now.Add(s.clockSkew)
		}
	}
	s.active = version
	return nil
}

func (s *AuthorityStore) MarkIssued(version string, notAfter time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record := s.records[version]; record != nil {
		retainTill := notAfter.Add(s.clockSkew)
		if record.retainTill.Before(retainTill) {
			record.retainTill = retainTill
		}
	}
}

func (s *AuthorityStore) Remove(version string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[version]
	if !ok {
		return ErrUnknownAuthority
	}
	if version == s.active {
		return errors.New("cannot remove active authority")
	}
	if now.Before(record.retainTill) {
		return ErrRetentionWindow
	}
	delete(s.records, version)
	return nil
}

func (s *AuthorityStore) Taint(version string, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record := s.records[version]; record != nil {
		record.taint = cause
	}
}

func (s *AuthorityStore) Active() (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record := s.records[s.active]
	if record == nil {
		return Snapshot{}, ErrUnknownAuthority
	}
	if record.taint != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrAuthorityTainted, record.taint)
	}
	return cloneSnapshot(record.snapshot), nil
}

func (s *AuthorityStore) ActiveVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *AuthorityStore) BundleRoots(now time.Time) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var roots []*x509.Certificate
	seen := make(map[string]struct{})
	for version, record := range s.records {
		if version != s.active && !now.Before(record.retainTill) {
			continue
		}
		for _, root := range record.snapshot.Roots {
			key := string(root.Raw)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			roots = append(roots, root)
		}
	}
	return roots
}

func SnapshotFromProto(in *issuerv1.AuthoritySnapshot) (Snapshot, error) {
	if in == nil {
		return Snapshot{}, errors.New("authority snapshot is nil")
	}
	out := Snapshot{Version: in.GetAuthorityVersion()}
	if in.GetPublishedAt() != nil {
		if err := in.GetPublishedAt().CheckValid(); err != nil {
			return Snapshot{}, fmt.Errorf("invalid published_at: %w", err)
		}
		out.PublishedAt = in.GetPublishedAt().AsTime()
	}
	for _, chain := range in.GetAuthorityChains() {
		root, err := x509.ParseCertificate(chain.GetRoot())
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse authority root: %w", err)
		}
		if !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return Snapshot{}, errors.New("authority root is not a signing CA")
		}
		out.Roots = append(out.Roots, root)
		for _, raw := range chain.GetIntermediates() {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse authority intermediate: %w", err)
			}
			out.Intermediates = append(out.Intermediates, cert)
		}
	}
	return out, nil
}

func cloneSnapshot(in Snapshot) Snapshot {
	in.Roots = append([]*x509.Certificate(nil), in.Roots...)
	in.Intermediates = append([]*x509.Certificate(nil), in.Intermediates...)
	return in
}

func hasRootOverlap(a, b []*x509.Certificate) bool {
	for _, left := range a {
		for _, right := range b {
			if bytes.Equal(left.Raw, right.Raw) {
				return true
			}
		}
	}
	return false
}
