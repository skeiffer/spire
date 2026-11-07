package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	identityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type material struct {
	Root []byte `json:"root"`
	Key  []byte `json:"key"`
}

type controls struct {
	Version            string `json:"version"`
	StreamError        bool   `json:"stream_error"`
	RejectIssue        bool   `json:"reject_issue"`
	ShortTTL           int64  `json:"short_ttl"`
	BootstrapDependent bool   `json:"bootstrap_dependent"`
	PublishedAgo       int64  `json:"published_ago,omitempty"`
}

type issuer struct {
	issuerv1.UnimplementedX509SVIDIssuerServer
	configv1.UnimplementedConfigServer
	dir              string
	roots            map[string]material
	identityProvider identityv1.IdentityProviderServiceClient
	now              func() time.Time
}

func main() {
	if len(os.Args) > 1 {
		if err := command(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	p := new(issuer)
	pluginmain.Serve(issuerv1.X509SVIDIssuerPluginServer(p), configv1.ConfigServiceServer(p))
}

func (p *issuer) BrokerHostServices(broker pluginsdk.ServiceBroker) error {
	if !broker.BrokerClient(&p.identityProvider) {
		return status.Error(codes.FailedPrecondition, "fixture IdentityProvider host service is not registered")
	}
	return nil
}

func (p *issuer) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	var config struct {
		Dir string `hcl:"dir"`
	}
	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.Dir) {
		return nil, status.Error(codes.InvalidArgument, "fixture dir must be absolute")
	}
	roots, err := loadMaterial(config.Dir)
	if err != nil {
		return nil, err
	}
	p.dir, p.roots = config.Dir, roots
	return new(configv1.ConfigureResponse), nil
}

func (p *issuer) SubscribeAuthoritySnapshots(_ *issuerv1.SubscribeAuthoritySnapshotsRequest, stream grpc.ServerStreamingServer[issuerv1.AuthoritySnapshot]) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var previous string
	for {
		state, err := p.controls()
		if err != nil {
			return err
		}
		if state.StreamError {
			return status.Error(codes.Unavailable, "fixture authority stream interrupted")
		}
		if previous == "" && state.BootstrapDependent {
			if !p.identityProvider.IsInitialized() {
				return status.Error(codes.FailedPrecondition, "fixture needs IdentityProvider before bootstrap")
			}
			if _, err := p.identityProvider.FetchX509Identity(stream.Context(), new(identityv1.FetchX509IdentityRequest)); err != nil {
				return err
			}
		}
		if state.Version != previous {
			authority, ok := p.roots[state.Version]
			if !ok {
				return status.Error(codes.InvalidArgument, "fixture authority version is unknown")
			}
			publishedAt := time.Now().Add(-time.Duration(state.PublishedAgo) * time.Second)
			if err := stream.Send(&issuerv1.AuthoritySnapshot{
				AuthorityVersion: state.Version, PublishedAt: timestamppb.New(publishedAt),
				AuthorityChains: []*issuerv1.AuthorityChain{{Root: authority.Root}},
			}); err != nil {
				return err
			}
			previous = state.Version
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
		}
	}
}

func (p *issuer) IssueX509SVID(_ context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	state, err := p.controls()
	if err != nil {
		return nil, err
	}
	if state.RejectIssue {
		return nil, status.Error(codes.Unavailable, "fixture issuance is disabled")
	}
	m, ok := p.roots[req.GetAuthorityVersion()]
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "unknown fixture authority version")
	}
	profile := req.GetProfile()
	if profile == nil || profile.NotBefore == nil || profile.NotAfter == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}
	proof, err := x509.ParseCertificateRequest(req.GetProofCsr())
	if err != nil || proof.CheckSignature() != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid proof")
	}
	proofKey, err := x509.MarshalPKIXPublicKey(proof.PublicKey)
	if err != nil || !bytes.Equal(proofKey, profile.PublicKey) {
		return nil, status.Error(codes.InvalidArgument, "proof key mismatch")
	}
	publicKey, err := x509.ParsePKIXPublicKey(profile.PublicKey)
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(profile.SpiffeId)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, PublicKey: publicKey, RawSubject: bytes.Clone(profile.Subject),
		URIs: []*url.URL{uri}, DNSNames: append([]string(nil), profile.DnsNames...),
		NotBefore: profile.NotBefore.AsTime(), NotAfter: profile.NotAfter.AsTime(),
		BasicConstraintsValid: true,
	}
	for _, usage := range profile.KeyUsages {
		switch usage {
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_DIGITAL_SIGNATURE:
			template.KeyUsage |= x509.KeyUsageDigitalSignature
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_ENCIPHERMENT:
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_AGREEMENT:
			template.KeyUsage |= x509.KeyUsageKeyAgreement
		default:
			return nil, status.Error(codes.InvalidArgument, "unsupported key usage")
		}
	}
	for _, usage := range profile.ExtendedKeyUsages {
		switch usage {
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH:
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH:
			template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		default:
			return nil, status.Error(codes.InvalidArgument, "unsupported extended key usage")
		}
	}
	for _, extension := range profile.ExtraExtensions {
		var oid asn1.ObjectIdentifier
		for part := range strings.SplitSeq(extension.Oid, ".") {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			oid = append(oid, n)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id: oid, Value: bytes.Clone(extension.Value), Critical: extension.Critical,
		})
	}
	if state.ShortTTL > 0 {
		now := time.Now()
		if p.now != nil {
			now = p.now()
		}
		template.NotAfter = minTime(template.NotAfter, now.Add(time.Duration(state.ShortTTL)*time.Second).Truncate(time.Second))
	}
	root, err := x509.ParseCertificate(m.Root)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(m.Key)
	if err != nil {
		return nil, err
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, root, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return &issuerv1.IssueX509SVIDResponse{LeafCertificate: raw, AuthorityVersion: req.AuthorityVersion}, nil
}

func (p *issuer) controls() (controls, error) {
	var state controls
	err := readJSON(filepath.Join(p.dir, "controls.json"), &state)
	return state, err
}

func loadMaterial(dir string) (map[string]material, error) {
	roots := make(map[string]material)
	path := filepath.Join(dir, "provider.json")
	if err := readJSON(path, &roots); err == nil {
		return roots, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for _, version := range []string{"v1", "v2"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		lifetime := 24 * time.Hour
		if version == "v2" {
			lifetime = 48 * time.Hour
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(len(roots) + 1)), Subject: pkix.Name{CommonName: "external fixture " + version},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(lifetime),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		raw, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(crypto.Signer(key))
		if err != nil {
			return nil, err
		}
		roots[version] = material{Root: raw, Key: keyDER}
	}
	if err := writeJSON(path, roots); err != nil {
		return nil, err
	}
	return roots, nil
}

func readJSON(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains trailing data")
		}
		return err
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
