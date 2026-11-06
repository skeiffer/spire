package x509svidissuer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
)

func TestPreparedProfileRejectsUnexpressedAndMalformedInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate, *[]byte)
	}{
		{name: "malformed proof", change: func(_ *x509.Certificate, p *[]byte) { *p = []byte("not DER") }},
		{name: "bad proof signature", change: func(_ *x509.Certificate, p *[]byte) { (*p)[len(*p)-1] ^= 1 }},
		{name: "extra URI", change: func(p *x509.Certificate, _ *[]byte) { p.URIs = append(p.URIs, p.URIs[0]) }},
		{name: "IP SAN", change: func(p *x509.Certificate, _ *[]byte) { p.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} }},
		{name: "email SAN", change: func(p *x509.Certificate, _ *[]byte) { p.EmailAddresses = []string{"name@example.org"} }},
		{name: "CA path length", change: func(p *x509.Certificate, _ *[]byte) { p.MaxPathLenZero = true }},
		{name: "cert signing usage", change: func(p *x509.Certificate, _ *[]byte) { p.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "unknown extended usage", change: func(p *x509.Certificate, _ *[]byte) { p.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning} }},
		{name: "duplicate extended usage", change: func(p *x509.Certificate, _ *[]byte) { p.ExtKeyUsage = append(p.ExtKeyUsage, p.ExtKeyUsage[0]) }},
		{name: "unknown usage OID", change: func(p *x509.Certificate, _ *[]byte) { p.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3}} }},
		{name: "locally allocated serial", change: func(p *x509.Certificate, _ *[]byte) { p.SerialNumber = big.NewInt(1) }},
		{name: "issuer key identity", change: func(p *x509.Certificate, _ *[]byte) { p.AuthorityKeyId = []byte{1} }},
		{name: "issuer name", change: func(p *x509.Certificate, _ *[]byte) { p.Issuer.CommonName = "local CA" }},
		{name: "invalid raw subject", change: func(p *x509.Certificate, _ *[]byte) { p.RawSubject = []byte("invalid") }},
		{name: "invalid OID", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{4, 1}, Value: []byte{5, 0}}}
		}},
		{name: "duplicate OID", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3}}, {Id: asn1.ObjectIdentifier{1, 2, 3}}}
		}},
		{name: "SAN override", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}}}
		}},
		{name: "KU override", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}}}
		}},
		{name: "basic constraints override", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}}}
		}},
		{name: "EKU override", change: func(p *x509.Certificate, _ *[]byte) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}}}
		}},
		{name: "zero validity", change: func(p *x509.Certificate, _ *[]byte) { p.NotBefore = time.Time{} }},
		{name: "empty second precision", change: func(p *x509.Certificate, _ *[]byte) { p.NotAfter = p.NotBefore.Add(time.Millisecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, proof, _ := newProfileFixture(t)
			tc.change(profile, &proof)
			_, err := BuildIssueRequest(profile, proof, WorkloadSVID, "v1")
			require.Error(t, err)
		})
	}
	for _, tc := range []struct {
		name    string
		role    SVIDType
		version string
	}{
		{name: "missing role", role: 0, version: "v1"},
		{name: "unknown role", role: 99, version: "v1"},
		{name: "missing version", role: WorkloadSVID},
		{name: "normalized version", role: WorkloadSVID, version: " v1 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, proof, _ := newProfileFixture(t)
			_, err := BuildIssueRequest(profile, proof, tc.role, tc.version)
			require.Error(t, err)
		})
	}
}

func TestReturnedLeafMustMatchAuthorizedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{name: "changed subject", change: func(p *x509.Certificate) { p.Subject.CommonName = "other" }},
		{name: "missing DNS", change: func(p *x509.Certificate) { p.DNSNames = nil }},
		{name: "extra DNS", change: func(p *x509.Certificate) { p.DNSNames = append(p.DNSNames, "other.example") }},
		{name: "duplicate DNS", change: func(p *x509.Certificate) { p.DNSNames = append(p.DNSNames, p.DNSNames[0]) }},
		{name: "zero URI", change: func(p *x509.Certificate) { p.URIs = nil }},
		{name: "two URIs", change: func(p *x509.Certificate) { p.URIs = append(p.URIs, p.URIs[0]) }},
		{name: "changed URI", change: func(p *x509.Certificate) {
			p.URIs = []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/other"}}
		}},
		{name: "IP SAN", change: func(p *x509.Certificate) { p.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)} }},
		{name: "email SAN", change: func(p *x509.Certificate) { p.EmailAddresses = []string{"name@example.org"} }},
		{name: "CA leaf", change: func(p *x509.Certificate) { p.IsCA = true }},
		{name: "missing key usage", change: func(p *x509.Certificate) { p.KeyUsage = 0 }},
		{name: "extra key usage", change: func(p *x509.Certificate) { p.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "missing EKU", change: func(p *x509.Certificate) { p.ExtKeyUsage = nil }},
		{name: "duplicate EKU", change: func(p *x509.Certificate) { p.ExtKeyUsage = append(p.ExtKeyUsage, p.ExtKeyUsage[0]) }},
		{name: "extra EKU", change: func(p *x509.Certificate) { p.ExtKeyUsage = append(p.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) }},
		{name: "expired", change: func(p *x509.Certificate) { p.NotAfter = p.NotBefore.Add(time.Second) }},
		{name: "not yet valid", change: func(p *x509.Certificate) { p.NotBefore = p.NotAfter.Add(-time.Second) }},
		{name: "upper validity bound", change: func(p *x509.Certificate) { p.NotAfter = p.NotAfter.Add(time.Second) }},
		{name: "lower validity bound", change: func(p *x509.Certificate) { p.NotBefore = p.NotBefore.Add(-time.Second) }},
		{name: "noncritical key usage", change: func(p *x509.Certificate) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{3, 2, 7, 128}}}
		}},
		{name: "noncritical SAN with empty subject", change: func(p *x509.Certificate) {
			value, err := asn1.Marshal([]asn1.RawValue{
				{Class: 2, Tag: 2, Bytes: []byte(p.DNSNames[0])},
				{Class: 2, Tag: 6, Bytes: []byte(p.URIs[0].String())},
			})
			require.NoError(t, err)
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}}
		}},
		{name: "unauthorized extension", change: func(p *x509.Certificate) {
			p.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile, _, key := newProfileFixture(t)
			now := profile.NotBefore.Add(time.Minute)
			rootKey := newTestKey(t)
			rootTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			}
			root := createTestCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
			leaf := *profile
			leaf.SerialNumber = big.NewInt(2)
			tc.change(&leaf)
			signed := createTestCertificate(t, &leaf, root, key.Public(), rootKey)
			_, err := ParseAndValidateResponse(profile, &issuerv1.IssueX509SVIDResponse{
				LeafCertificate: signed.Raw, AuthorityVersion: "v1",
			}, Snapshot{Version: "v1", Roots: []*x509.Certificate{root}}, now)
			require.Error(t, err)
		})
	}
}

func TestLeafValidityUsesAUsableActualAnchorNotShortestAlternate(t *testing.T) {
	profile, _, leafKey := newProfileFixture(t)
	now := profile.NotBefore.Add(time.Minute)
	key := newTestKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "same root key"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Second),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	short := createTestCertificate(t, rootTemplate, rootTemplate, key.Public(), key)
	rootTemplate.SerialNumber = big.NewInt(2)
	rootTemplate.NotAfter = now.Add(2 * time.Hour)
	long := createTestCertificate(t, rootTemplate, rootTemplate, key.Public(), key)
	for _, tc := range []struct {
		name string
		ttl  time.Duration
	}{
		{name: "requested validity", ttl: time.Hour},
		{name: "shorter validity", ttl: 30 * time.Second},
		{name: "already half lived and below renewal interval", ttl: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := *profile
			leaf.SerialNumber = big.NewInt(3)
			leaf.NotAfter = now.Add(tc.ttl)
			signed := createTestCertificate(t, &leaf, long, leafKey.Public(), key)
			_, err := ParseAndValidateResponse(profile, &issuerv1.IssueX509SVIDResponse{
				LeafCertificate: signed.Raw, AuthorityVersion: "v1",
			}, Snapshot{Version: "v1", Roots: []*x509.Certificate{short, long}}, now)
			require.NoError(t, err)
		})
	}
}

func TestProofBytesAreNotSharedWithThePlugin(t *testing.T) {
	profile, proof, _ := newProfileFixture(t)
	request, err := BuildIssueRequest(profile, proof, WorkloadSVID, "v1")
	require.NoError(t, err)
	request.ProofCsr[0] ^= 1
	_, err = x509.ParseCertificateRequest(proof)
	require.NoError(t, err)
	request.Profile.DnsNames[0] = "changed"
	require.Equal(t, "workload.example", profile.DNSNames[0])
}
