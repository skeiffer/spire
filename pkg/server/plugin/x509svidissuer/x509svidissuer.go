package x509svidissuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/protobuf/proto"
)

const (
	maxCertificateSize = 16 << 10
	maxSnapshotSize    = 64 << 10
	maxResponseSize    = 256 << 10
	maxCSRSize         = 32 << 10
	maxPaths           = 8
	maxPathDepth       = 8
	maxHistory         = 64
)

var (
	ErrVersionReused    = errors.New("authority version reused with different content")
	ErrUnknownAuthority = errors.New("unknown authority version")
	ErrAuthorityTainted = errors.New("authority session is unavailable")
)

type X509SVIDIssuer interface {
	catalog.PluginInfo
	IssueX509SVID(context.Context, *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error)
	SubscribeAuthoritySnapshots(context.Context) (AuthoritySnapshotStream, error)
}

// AuthorityPath is ordered from the trust root to the issuing CA.
type AuthorityPath struct {
	Root          *x509.Certificate
	Intermediates []*x509.Certificate
}

type Snapshot struct {
	Version     string
	Roots       []*x509.Certificate
	Paths       []AuthorityPath
	PublishedAt time.Time
}

type authorityRecord struct {
	snapshot   Snapshot
	digest     [32]byte
	preparedAt time.Time
	committed  bool
	retired    bool
}

// AuthorityStore is serialized by its owning Host.
type AuthorityStore struct {
	active  string
	records map[string]*authorityRecord
}

func NewAuthorityStore() *AuthorityStore {
	return &AuthorityStore{records: make(map[string]*authorityRecord)}
}

func (s *AuthorityStore) publish(snapshot Snapshot, now time.Time) error {
	digest := snapshotDigest(snapshot)
	if previous := s.records[snapshot.Version]; previous != nil {
		if previous.digest != digest {
			return ErrVersionReused
		}
		return nil
	}
	if len(s.records) >= maxHistory {
		return errors.New("external authority history is full; provision a new server data directory and review retained trust before restarting")
	}
	s.records[snapshot.Version] = &authorityRecord{snapshot: snapshot, digest: digest, preparedAt: now}
	return nil
}

func (s *AuthorityStore) selectActive(now time.Time, observed map[string]bool) {
	current := s.records[s.active]
	var expiry time.Time
	if current != nil {
		expiry = current.snapshot.effectiveExpiry(now)
		if !expiry.IsZero() {
			lifetime := expiry.Sub(current.preparedAt)
			if now.Before(expiry.Add(-min(lifetime/6, 7*24*time.Hour))) {
				return
			}
		}
	}
	best := s.active
	for version, record := range s.records {
		if !record.committed || record.retired || !observed[version] {
			continue
		}
		nextExpiry := record.snapshot.effectiveExpiry(now)
		// Expired current paths must not permit expiration regression.
		floor := expiry
		if current != nil && expiry.IsZero() {
			floor = current.snapshot.latestExpiry(now)
		}
		if !nextExpiry.IsZero() && (current == nil || nextExpiry.After(floor)) &&
			(best == s.active || nextExpiry.After(s.records[best].snapshot.effectiveExpiry(now)) ||
				nextExpiry.Equal(s.records[best].snapshot.effectiveExpiry(now)) && version < best) {
			best = version
		}
	}
	if best != s.active {
		if current != nil {
			current.retired = true
		}
		s.active = best
	}
}

func (s Snapshot) effectiveExpiry(now time.Time) time.Time {
	var best time.Time
	for _, path := range s.Paths {
		expiry := path.Root.NotAfter
		usable := true
		for _, cert := range append([]*x509.Certificate{path.Root}, path.Intermediates...) {
			if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
				usable = false
				break
			}
			if cert.NotAfter.Before(expiry) {
				expiry = cert.NotAfter
			}
		}
		if usable && expiry.After(best) {
			best = expiry
		}
	}
	return best
}

func (s Snapshot) latestExpiry(now time.Time) time.Time {
	var best time.Time
	for _, path := range s.Paths {
		expiry := path.Root.NotAfter
		notBefore := path.Root.NotBefore
		for _, cert := range path.Intermediates {
			if cert.NotAfter.Before(expiry) {
				expiry = cert.NotAfter
			}
			if cert.NotBefore.After(notBefore) {
				notBefore = cert.NotBefore
			}
		}
		// Future paths must not prevent recovery from an expired active path.
		if !now.Before(notBefore) && notBefore.Before(expiry) && expiry.After(best) {
			best = expiry
		}
	}
	return best
}

func SnapshotFromProto(in *issuerv1.AuthoritySnapshot) (Snapshot, error) {
	if in == nil || proto.Size(in) > maxSnapshotSize {
		return Snapshot{}, errors.New("authority snapshot is missing or exceeds size limit")
	}
	version := in.GetAuthorityVersion()
	if strings.TrimSpace(version) == "" || len(version) > 256 {
		return Snapshot{}, errors.New("authority version must contain between 1 and 256 bytes")
	}
	if len(in.GetAuthorityChains()) == 0 || len(in.GetAuthorityChains()) > maxPaths {
		return Snapshot{}, errors.New("authority snapshot has an invalid number of paths")
	}
	out := Snapshot{Version: version}
	if in.GetPublishedAt() != nil {
		if err := in.GetPublishedAt().CheckValid(); err != nil {
			return Snapshot{}, fmt.Errorf("invalid published_at: %w", err)
		}
		out.PublishedAt = in.GetPublishedAt().AsTime()
	}
	for _, chain := range in.GetAuthorityChains() {
		if chain == nil || len(chain.GetIntermediates()) >= maxPathDepth {
			return Snapshot{}, errors.New("authority path exceeds depth limit")
		}
		root, err := parseAuthorityCertificate(chain.GetRoot())
		if err != nil {
			return Snapshot{}, fmt.Errorf("parse authority root: %w", err)
		}
		path := AuthorityPath{Root: root}
		parent := root
		seen := map[string]bool{string(root.Raw): true}
		for i, raw := range chain.GetIntermediates() {
			cert, err := parseAuthorityCertificate(raw)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse authority intermediate: %w", err)
			}
			if seen[string(cert.Raw)] || !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
				return Snapshot{}, errors.New("authority path contains duplicate or unordered certificates")
			}
			if err := cert.CheckSignatureFrom(parent); err != nil {
				return Snapshot{}, fmt.Errorf("invalid authority path signature: %w", err)
			}
			for j, ancestor := range append([]*x509.Certificate{root}, path.Intermediates...) {
				if (ancestor.MaxPathLenZero || ancestor.MaxPathLen > 0) && i-j+1 > ancestor.MaxPathLen {
					return Snapshot{}, errors.New("authority path exceeds CA path length constraint")
				}
			}
			seen[string(cert.Raw)] = true
			path.Intermediates = append(path.Intermediates, cert)
			parent = cert
		}
		out.Roots = append(out.Roots, root)
		out.Paths = append(out.Paths, path)
	}
	return out, nil
}

func parseAuthorityCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > maxCertificateSize {
		return nil, errors.New("authority certificate exceeds size limit or is empty")
	}
	cert, err := x509.ParseCertificate(bytes.Clone(raw))
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!cert.NotAfter.After(cert.NotBefore) || len(cert.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("authority certificate is not a valid signing CA")
	}
	return cert, nil
}

func snapshotDigest(snapshot Snapshot) [32]byte {
	h := sha256.New()
	for _, path := range snapshot.Paths {
		_ = binary.Write(h, binary.BigEndian, int64(len(path.Intermediates)+1))
		for _, cert := range append([]*x509.Certificate{path.Root}, path.Intermediates...) {
			_ = binary.Write(h, binary.BigEndian, int64(len(cert.Raw)))
			_, _ = h.Write(cert.Raw)
		}
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
