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
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const authorityVersion = "local-ephemeral-v1"

type plugin struct {
	issuerv1.UnimplementedX509SVIDIssuerServer
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func main() {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "SPIRE external issuer test root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, rootKey.Public(), rootKey)
	if err != nil {
		panic(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pluginmain.Serve(issuerv1.X509SVIDIssuerPluginServer(&plugin{root: root, rootKey: rootKey}))
}

func (p *plugin) IssueX509SVID(_ context.Context, req *issuerv1.IssueX509SVIDRequest) (*issuerv1.IssueX509SVIDResponse, error) {
	if req.GetAuthorityVersion() != authorityVersion {
		return nil, status.Error(codes.FailedPrecondition, "authority version is not active")
	}
	profile := req.GetProfile()
	if profile == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}
	csr, err := x509.ParseCertificateRequest(req.GetProofCsr())
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
	der, err := x509.CreateCertificate(rand.Reader, leaf, p.root, csr.PublicKey, p.rootKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "sign certificate")
	}
	return &issuerv1.IssueX509SVIDResponse{
		LeafCertificate:  der,
		AuthorityVersion: authorityVersion,
	}, nil
}

func (p *plugin) SubscribeAuthoritySnapshots(_ *issuerv1.SubscribeAuthoritySnapshotsRequest, stream issuerv1.X509SVIDIssuer_SubscribeAuthoritySnapshotsServer) error {
	if err := stream.Send(&issuerv1.AuthoritySnapshot{
		AuthorityVersion: authorityVersion,
		AuthorityChains:  []*issuerv1.AuthorityChain{{Root: p.root.Raw}},
		PublishedAt:      timestamppb.Now(),
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
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
