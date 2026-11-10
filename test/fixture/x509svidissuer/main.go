package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const authorityVersion = "local-ephemeral-v1"
const successorVersion = "local-ephemeral-v2"

type plugin struct {
	issuerv1.UnimplementedX509SVIDIssuerServer
	authorities map[string]fixtureAuthority
}

type fixtureAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

type fixtureRecord struct {
	Version     string `json:"version"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
}

func newAuthority(ttl time.Duration, name string) (fixtureAuthority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fixtureAuthority{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, rootKey.Public(), rootKey)
	if err != nil {
		return fixtureAuthority{}, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return fixtureAuthority{}, err
	}
	return fixtureAuthority{cert: root, key: rootKey}, nil
}

func loadAuthorities(dir string, ttl time.Duration) (map[string]fixtureAuthority, error) {
	var records []fixtureRecord
	if dir != "" {
		data, err := os.ReadFile(filepath.Join(dir, "provider.json"))
		if err == nil {
			if err := json.Unmarshal(data, &records); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	out := make(map[string]fixtureAuthority)
	if records == nil {
		for _, version := range []string{authorityVersion, successorVersion} {
			lifetime, name := ttl, "SPIRE external issuer test root"
			if version == successorVersion {
				lifetime, name = max(ttl*2, time.Hour), name+" v2"
			}
			authority, err := newAuthority(lifetime, name)
			if err != nil {
				return nil, err
			}
			key, err := x509.MarshalECPrivateKey(authority.key)
			if err != nil {
				return nil, err
			}
			records = append(records, fixtureRecord{Version: version, Certificate: authority.cert.Raw, PrivateKey: key})
		}
		if dir != "" {
			if err := diskutil.CreateDataDirectory(dir); err != nil {
				return nil, err
			}
			// #nosec G117 -- The test provider privately persists its own keys, separately from host metadata.
			data, err := json.Marshal(records)
			if err != nil {
				return nil, err
			}
			if err := diskutil.AtomicWritePrivateFile(filepath.Join(dir, "provider.json"), data); err != nil {
				return nil, err
			}
		}
	}
	if len(records) != 2 {
		return nil, errors.New("fixture provider state must contain both authorities")
	}
	for _, record := range records {
		cert, err := x509.ParseCertificate(record.Certificate)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(record.PrivateKey)
		publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if err != nil || !ok || !publicKey.Equal(key.Public()) {
			return nil, errors.New("fixture provider key does not match certificate")
		}
		if record.Version != authorityVersion && record.Version != successorVersion {
			return nil, errors.New("unknown fixture authority version")
		}
		out[record.Version] = fixtureAuthority{cert: cert, key: key}
	}
	if len(out) != 2 {
		return nil, errors.New("duplicate fixture authority version")
	}
	return out, nil
}

func main() {
	ttl := time.Hour
	if value := os.Getenv("SPIRE_TEST_ISSUER_ROOT_TTL"); value != "" {
		var err error
		ttl, err = time.ParseDuration(value)
		if err != nil {
			panic(err)
		}
	}
	authorities, err := loadAuthorities(os.Getenv("SPIRE_TEST_ISSUER_STATE_DIR"), ttl)
	if err != nil {
		panic(err)
	}
	pluginmain.Serve(issuerv1.X509SVIDIssuerPluginServer(&plugin{authorities: authorities}))
}

func (p *plugin) IssueX509SVID(_ context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	if failureFile := os.Getenv("SPIRE_TEST_ISSUER_FAILURE_FILE"); failureFile != "" {
		if _, err := os.Stat(failureFile); !errors.Is(err, os.ErrNotExist) {
			return nil, status.Error(codes.Unavailable, "fixture issuance disabled")
		}
	}
	authority, ok := p.authorities[req.GetAuthorityVersion()]
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "authority version is not active")
	}
	profile := req.GetProfile()
	if profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil || csr.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "proof CSR is invalid")
	}
	proofKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(proofKey, profile.GetPublicKey()) {
		return nil, status.Error(codes.InvalidArgument, "proof CSR key does not match profile")
	}
	leaf, err := certificateFromProfile(profile, csr.PublicKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if leaf.NotAfter.After(authority.cert.NotAfter) {
		leaf.NotAfter = authority.cert.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, authority.cert, csr.PublicKey, authority.key)
	if err != nil {
		return nil, status.Error(codes.Internal, "sign certificate")
	}
	return &issuerv1.IssueX509SVIDResponse{
		LeafCertificate:  der,
		AuthorityVersion: req.GetAuthorityVersion(),
	}, nil
}

func (p *plugin) SubscribeAuthoritySnapshots(_ *issuerv1.SubscribeAuthoritySnapshotsRequest, stream issuerv1.X509SVIDIssuer_SubscribeAuthoritySnapshotsServer) error {
	send := func(version string) error {
		return stream.Send(&issuerv1.AuthoritySnapshot{
			AuthorityVersion: version,
			AuthorityChains:  []*issuerv1.AuthorityChain{{Root: p.authorities[version].cert.Raw}},
			PublishedAt:      timestamppb.Now(),
		})
	}
	if time.Now().Before(p.authorities[authorityVersion].cert.NotAfter) {
		if err := send(authorityVersion); err != nil {
			return err
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	prepared := false
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ticker.C:
			if controlExists("SPIRE_TEST_ISSUER_STREAM_FAILURE_FILE") {
				return status.Error(codes.Unavailable, "fixture snapshot stream disabled")
			}
			if !prepared && controlExists("SPIRE_TEST_ISSUER_ROLLOVER_FILE") {
				if err := send(successorVersion); err != nil {
					return err
				}
				prepared = true
			}
		}
	}
}

func controlExists(variable string) bool {
	path := os.Getenv(variable)
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return !errors.Is(err, os.ErrNotExist)
}

func certificateFromProfile(profile *issuerv1.X509SVIDProfile, publicKey any) (*x509.Certificate, error) {
	if profile.GetNotBefore() == nil || profile.GetNotAfter() == nil {
		return nil, errors.New("profile validity is required")
	}
	if err := profile.GetNotBefore().CheckValid(); err != nil {
		return nil, errors.New("profile not_before is invalid")
	}
	if err := profile.GetNotAfter().CheckValid(); err != nil {
		return nil, errors.New("profile not_after is invalid")
	}
	id, err := url.Parse(profile.GetSpiffeId())
	if err != nil {
		return nil, errors.New("profile SPIFFE ID is invalid")
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(profile.GetSubject(), &subject); err != nil {
		return nil, errors.New("profile subject is invalid")
	}
	var subjectName pkix.Name
	subjectName.FillFromRDNSequence(&subject)
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subjectName,
		NotBefore:             profile.GetNotBefore().AsTime(),
		NotAfter:              profile.GetNotAfter().AsTime(),
		URIs:                  []*url.URL{id},
		DNSNames:              append([]string(nil), profile.GetDnsNames()...),
		PublicKey:             publicKey,
		KeyUsage:              keyUsages(profile.GetKeyUsages()),
		ExtKeyUsage:           extendedKeyUsages(profile.GetExtendedKeyUsages()),
		BasicConstraintsValid: true,
	}
	for _, extension := range profile.GetExtraExtensions() {
		oid, err := parseOID(extension.GetOid())
		if err != nil {
			return nil, err
		}
		leaf.ExtraExtensions = append(leaf.ExtraExtensions, pkix.Extension{
			Id: oid, Critical: extension.GetCritical(), Value: append([]byte(nil), extension.GetValue()...),
		})
	}
	return leaf, nil
}

func keyUsages(in []issuerv1.X509KeyUsage) x509.KeyUsage {
	var out x509.KeyUsage
	for _, usage := range in {
		switch usage {
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_DIGITAL_SIGNATURE:
			out |= x509.KeyUsageDigitalSignature
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_ENCIPHERMENT:
			out |= x509.KeyUsageKeyEncipherment
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_AGREEMENT:
			out |= x509.KeyUsageKeyAgreement
		}
	}
	return out
}

func extendedKeyUsages(in []issuerv1.X509ExtendedKeyUsage) []x509.ExtKeyUsage {
	var out []x509.ExtKeyUsage
	for _, usage := range in {
		switch usage {
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH:
			out = append(out, x509.ExtKeyUsageClientAuth)
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH:
			out = append(out, x509.ExtKeyUsageServerAuth)
		}
	}
	return out
}

func parseOID(value string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return nil, errors.New("profile extension OID is invalid")
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return nil, errors.New("profile extension OID is invalid")
		}
		oid[i] = value
	}
	return oid, nil
}
