package x509svidissuer

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/util"
	"google.golang.org/protobuf/proto"
)

var (
	ErrVersionReused    = errors.New("authority version reused with different content")
	ErrUnknownAuthority = errors.New("unknown authority version")
	ErrHistoryLimit     = errors.New("authority version history limit reached")
	ErrAuthorityTainted = errors.New("authority version is tainted")
)

type Snapshot struct {
	Version     string
	Chains      [][]*x509.Certificate
	Roots       []*x509.Certificate
	PublishedAt time.Time
}

type authorityRecord struct {
	snapshot Snapshot
	digest   [32]byte
	taint    error
}

type AuthorityStore struct {
	mu              sync.RWMutex
	retentionMargin time.Duration
	historyLimit    int
	active          string
	records         map[string]*authorityRecord
}

func NewAuthorityStore(retentionMargin time.Duration, historyLimit int) *AuthorityStore {
	return &AuthorityStore{
		retentionMargin: retentionMargin,
		historyLimit:    historyLimit,
		records:         make(map[string]*authorityRecord),
	}
}

func (s *AuthorityStore) Publish(snapshot Snapshot) error {
	if strings.TrimSpace(snapshot.Version) == "" || len(snapshot.Roots) == 0 {
		return errors.New("authority version and roots are required")
	}
	digest, err := snapshotDigest(snapshot)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous := s.records[snapshot.Version]; previous != nil {
		if previous.digest != digest {
			return ErrVersionReused
		}
		return nil
	}
	if s.historyLimit > 0 && len(s.records) >= s.historyLimit {
		return ErrHistoryLimit
	}
	s.records[snapshot.Version] = &authorityRecord{
		snapshot: cloneSnapshot(snapshot),
		digest:   digest,
	}
	return nil
}

func (s *AuthorityStore) Activate(version string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[version]
	if record == nil {
		return ErrUnknownAuthority
	}
	if record.taint != nil {
		return fmt.Errorf("%w: %w", ErrAuthorityTainted, record.taint)
	}
	if err := usableSnapshot(record.snapshot, now); err != nil {
		return err
	}
	s.active = version
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
		return Snapshot{}, fmt.Errorf("%w: %w", ErrAuthorityTainted, record.taint)
	}
	return cloneSnapshot(record.snapshot), nil
}

func (s *AuthorityStore) ActiveVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *AuthorityStore) Snapshot(version string) (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record := s.records[version]
	if record == nil {
		return Snapshot{}, ErrUnknownAuthority
	}
	return cloneSnapshot(record.snapshot), nil
}

func (s *AuthorityStore) BundleRoots(now time.Time) []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var roots []*x509.Certificate
	for _, record := range s.records {
		for _, root := range record.snapshot.Roots {
			if !now.Before(root.NotAfter.Add(s.retentionMargin)) {
				continue
			}
			if !slices.ContainsFunc(roots, root.Equal) {
				roots = append(roots, cloneCertificate(root))
			}
		}
	}
	return roots
}

func (s *AuthorityStore) ContainsRoot(raw []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, record := range s.records {
		for _, root := range record.snapshot.Roots {
			if bytes.Equal(raw, root.Raw) {
				return true
			}
		}
	}
	return false
}

func SnapshotFromProto(in *issuerv1.AuthoritySnapshot) (Snapshot, error) {
	if in == nil {
		return Snapshot{}, errors.New("authority snapshot is nil")
	}
	out := Snapshot{Version: in.GetAuthorityVersion()}
	if out.Version == "" || strings.TrimSpace(out.Version) != out.Version || len(out.Version) > 256 {
		return Snapshot{}, errors.New("authority version is required")
	}
	if proto.Size(in) > 1<<20 || len(in.GetAuthorityChains()) > 16 {
		return Snapshot{}, errors.New("authority snapshot exceeds host resource limits")
	}
	if in.GetPublishedAt() == nil || in.GetPublishedAt().CheckValid() != nil {
		return Snapshot{}, errors.New("authority published_at is invalid")
	}
	out.PublishedAt = in.GetPublishedAt().AsTime()
	for _, chain := range in.GetAuthorityChains() {
		if chain == nil {
			return Snapshot{}, errors.New("authority chain is nil")
		}
		if len(chain.GetRoot()) > 64<<10 || len(chain.GetIntermediates()) > 8 {
			return Snapshot{}, errors.New("authority chain exceeds host resource limits")
		}
		root, err := x509.ParseCertificate(chain.GetRoot())
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse authority root: %w", err)
		}
		if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
			return Snapshot{}, errors.New("authority root is not a signing CA")
		}
		parsed := []*x509.Certificate{root}
		for _, raw := range chain.GetIntermediates() {
			if len(raw) > 64<<10 {
				return Snapshot{}, errors.New("authority certificate exceeds host resource limits")
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse authority intermediate: %w", err)
			}
			if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				return Snapshot{}, errors.New("authority intermediate is not a signing CA")
			}
			parsed = append(parsed, cert)
		}
		out.Chains = append(out.Chains, parsed)
		out.Roots = append(out.Roots, root)
	}
	if len(out.Roots) == 0 {
		return Snapshot{}, errors.New("authority snapshot has no chains")
	}
	return out, nil
}

func snapshotDigest(snapshot Snapshot) ([32]byte, error) {
	h := sha256.New()
	writeLength := func(n int) {
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], util.MustCast[uint64](n))
		_, _ = h.Write(raw[:])
	}
	writeLength(len(snapshot.Roots))
	for _, root := range snapshot.Roots {
		if root == nil {
			return [32]byte{}, errors.New("authority snapshot contains nil root")
		}
		writeLength(len(root.Raw))
		_, _ = h.Write(root.Raw)
	}
	writeLength(len(snapshot.Chains))
	for _, chain := range snapshot.Chains {
		writeLength(len(chain))
		for _, cert := range chain {
			if cert == nil {
				return [32]byte{}, errors.New("authority snapshot contains nil certificate")
			}
			writeLength(len(cert.Raw))
			_, _ = h.Write(cert.Raw)
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func cloneSnapshot(in Snapshot) Snapshot {
	out := in
	out.Roots = make([]*x509.Certificate, len(in.Roots))
	for i, root := range in.Roots {
		out.Roots[i] = cloneCertificate(root)
	}
	out.Chains = make([][]*x509.Certificate, len(in.Chains))
	for i, chain := range in.Chains {
		out.Chains[i] = make([]*x509.Certificate, len(chain))
		for j, cert := range chain {
			out.Chains[i][j] = cloneCertificate(cert)
		}
	}
	return out
}

func cloneCertificate(cert *x509.Certificate) *x509.Certificate {
	parsed, err := x509.ParseCertificate(bytes.Clone(cert.Raw))
	if err != nil {
		return nil
	}
	return parsed
}

func sameCertificate(left, right *x509.Certificate) bool {
	return left != nil && right != nil && bytes.Equal(left.Raw, right.Raw)
}
