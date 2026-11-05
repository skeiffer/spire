package x509svidissuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/stretchr/testify/require"
)

func TestBuildIssueRequestAndValidateResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rootKey := newECDSAKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := createCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	key := newECDSAKey(t)
	id, err := url.Parse("spiffe://example.org/workload")
	requireNoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		URIs: []*url.URL{id}, PublicKey: key.Public(),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	proof, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "untrusted subject"},
		DNSNames: []string{"untrusted.example"},
		URIs:     []*url.URL{{Scheme: "spiffe", Host: "untrusted.example", Path: "/other"}},
	}, key)
	requireNoError(t, err)
	request, err := BuildIssueRequest(template, proof, issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD, "v1")
	requireNoError(t, err)
	if request.GetProfile().GetSpiffeId() != id.String() {
		t.Fatalf("profile SPIFFE ID = %q", request.GetProfile().GetSpiffeId())
	}
	expectedSubject, err := asn1.Marshal(template.Subject.ToRDNSequence())
	requireNoError(t, err)
	if !bytes.Equal(request.GetProfile().GetSubject(), expectedSubject) || len(request.GetProfile().GetDnsNames()) != 0 {
		t.Fatal("proof CSR subject or SANs replaced the authoritative profile")
	}
	if got := request.GetProfile().GetExtendedKeyUsages(); len(got) != 2 ||
		got[0] != issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH ||
		got[1] != issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH {
		t.Fatalf("extended key usages were not canonicalized: %v", got)
	}

	leafTemplate := *template
	leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	leaf := createCertificate(t, &leafTemplate, root, key.Public(), rootKey)
	chain, err := ParseAndValidateResponse(template, &issuerv1.IssueX509SVIDResponse{
		LeafCertificate: leaf.Raw, AuthorityVersion: "v1",
	}, Snapshot{Version: "v1", Roots: []*x509.Certificate{root}})
	requireNoError(t, err)
	if len(chain) != 1 {
		t.Fatalf("chain length = %d", len(chain))
	}

	response := &issuerv1.IssueX509SVIDResponse{LeafCertificate: leaf.Raw, AuthorityVersion: "wrong"}
	if _, err := ParseAndValidateResponse(template, response, Snapshot{Version: "v1", Roots: []*x509.Certificate{root}}); err == nil {
		t.Fatal("expected authority version mismatch")
	}
}

func TestBuildIssueRequestRejectsProofKeyMismatch(t *testing.T) {
	templateKey := newECDSAKey(t)
	proofKey := newECDSAKey(t)
	proof, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), proofKey)
	requireNoError(t, err)
	id, err := url.Parse("spiffe://example.org/workload")
	requireNoError(t, err)
	template := &x509.Certificate{
		PublicKey: templateKey.Public(), URIs: []*url.URL{id},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}

	_, err = BuildIssueRequest(template, proof, issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD, "v1")
	require.ErrorContains(t, err, "proof CSR public key does not match profile")
}

func TestExtendedKeyUsageComparisonRejectsDuplicateSubstitution(t *testing.T) {
	if sameExtendedKeyUsages(
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	) {
		t.Fatal("duplicate usage substituted for a required usage")
	}
}

func TestResponseRejectsProfileViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
		want   string
	}{
		{"wrong key", func(c *x509.Certificate) { c.PublicKey = newECDSAKey(t).Public() }, "public key mismatch"},
		{"CA leaf", func(c *x509.Certificate) { c.IsCA = true }, "leaf CA constraints"},
		{"missing basic constraints", func(c *x509.Certificate) { c.BasicConstraintsValid = false }, "leaf CA constraints"},
		{"leaf path length", func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
				Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 2, 1, 0},
			})
		}, "leaf CA constraints"},
		{"wrong subject", func(c *x509.Certificate) { c.Subject.CommonName = "unauthorized" }, "subject mismatch"},
		{"wrong identity", func(c *x509.Certificate) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "other.example", Path: "/workload"}}
		}, "SPIFFE ID mismatch"},
		{"extra URI", func(c *x509.Certificate) {
			c.URIs = append(c.URIs, &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/other"})
		}, "SPIFFE ID mismatch"},
		{"missing URI", func(c *x509.Certificate) { c.URIs = nil }, "SPIFFE ID mismatch"},
		{"extra DNS", func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example") }, "DNS SAN mismatch"},
		{"missing DNS", func(c *x509.Certificate) { c.DNSNames = nil }, "DNS SAN mismatch"},
		{"extra IP", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }, "unsupported subject alternative name"},
		{"extra email", func(c *x509.Certificate) { c.EmailAddresses = []string{"workload@example.org"} }, "unsupported subject alternative name"},
		{"extra registered ID", func(c *x509.Certificate) {
			raw, err := asn1.Marshal([]asn1.RawValue{
				{Class: 2, Tag: 2, Bytes: []byte("workload.example")},
				{Class: 2, Tag: 6, Bytes: []byte("spiffe://example.org/workload")},
				{Class: 2, Tag: 8, Bytes: []byte{42, 3, 4}},
			})
			require.NoError(t, err)
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: raw})
		}, "unsupported subject alternative name"},
		{"missing digital signature", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, "usage mismatch"},
		{"additional key usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCRLSign }, "usage mismatch"},
		{"missing EKU", func(c *x509.Certificate) { c.ExtKeyUsage = nil }, "usage mismatch"},
		{"additional EKU", func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) }, "usage mismatch"},
		{"unknown EKU", func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 99}} }, "usage mismatch"},
		{"noncritical key usage", func(c *x509.Certificate) {
			usage, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})
			require.NoError(t, err)
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: usage})
		}, "key usage extension must be critical"},
		{"noncritical SAN with empty subject", func(c *x509.Certificate) {
			raw, err := asn1.Marshal([]asn1.RawValue{
				{Class: 2, Tag: 2, Bytes: []byte("workload.example")},
				{Class: 2, Tag: 6, Bytes: []byte("spiffe://example.org/workload")},
			})
			require.NoError(t, err)
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: raw})
		}, "subject alternative name extension must be critical"},
		{"missing custom extension", func(c *x509.Certificate) { c.ExtraExtensions = nil }, "extension 1.2.3.4 mismatch"},
		{"changed custom extension", func(c *x509.Certificate) { c.ExtraExtensions[0].Value = []byte{5, 0} }, "extension 1.2.3.4 mismatch"},
		{"changed extension criticality", func(c *x509.Certificate) { c.ExtraExtensions[0].Critical = true }, "extension 1.2.3.4 mismatch"},
		{"unauthorized extension", func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 99}, Value: []byte{5, 0}})
		}, "unauthorized certificate extension"},
		{"extra backdating", func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(-time.Second) }, "validity exceeds authoritative profile"},
		{"extra lifetime", func(c *x509.Certificate) { c.NotAfter = c.NotAfter.Add(time.Second) }, "validity exceeds authoritative profile"},
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-10 * time.Second) }, "chain validation failed"},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }, "chain validation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			response := f.response(t, tt.mutate)
			chain, err := ParseAndValidateResponse(f.template, response, f.snapshot())
			require.ErrorContains(t, err, tt.want)
			require.Nil(t, chain)
		})
	}
}

func TestResponseAllowsIssuerMetadataAndShorterValidity(t *testing.T) {
	policy, err := x509.ParseOID("1.2.3.5")
	require.NoError(t, err)
	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"key identifier", func(c *x509.Certificate) { c.SubjectKeyId = []byte{1, 2, 3} }},
		{"authority information access", func(c *x509.Certificate) {
			c.OCSPServer = []string{"https://ocsp.example.org"}
			c.IssuingCertificateURL = []string{"https://ca.example.org/issuer"}
		}},
		{"CRL distribution", func(c *x509.Certificate) { c.CRLDistributionPoints = []string{"https://ca.example.org/issuer.crl"} }},
		{"certificate policies", func(c *x509.Certificate) { c.Policies = []x509.OID{policy} }},
		{"shorter validity", func(c *x509.Certificate) {
			c.NotBefore = c.NotBefore.Add(10 * time.Second)
			c.NotAfter = c.NotAfter.Add(-time.Minute)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			chain, err := ParseAndValidateResponse(f.template, f.response(t, tt.mutate), f.snapshot())
			require.NoError(t, err)
			require.Len(t, chain, 1)
		})
	}
	t.Run("absent optional EKU", func(t *testing.T) {
		f := newIssuanceFixture(t)
		f.template.ExtKeyUsage = nil
		request, err := BuildIssueRequest(f.template, f.proof, WorkloadSVID, "v1")
		require.NoError(t, err)
		require.Empty(t, request.Profile.ExtendedKeyUsages)
		_, err = ParseAndValidateResponse(f.template, f.response(t, nil), f.snapshot())
		require.NoError(t, err)
	})
	t.Run("empty EKU extension", func(t *testing.T) {
		f := newIssuanceFixture(t)
		f.template.ExtKeyUsage = nil
		response := f.response(t, func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions,
				pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: []byte{0x30, 0}})
		})
		_, err := ParseAndValidateResponse(f.template, response, f.snapshot())
		require.ErrorContains(t, err, "usage mismatch")
	})
	t.Run("explicit metadata remains authoritative", func(t *testing.T) {
		f := newIssuanceFixture(t)
		f.template.ExtraExtensions = append(f.template.ExtraExtensions,
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{4, 1, 1}})
		response := f.response(t, func(c *x509.Certificate) {
			c.ExtraExtensions[1].Value = []byte{4, 1, 2}
		})
		_, err := ParseAndValidateResponse(f.template, response, f.snapshot())
		require.ErrorContains(t, err, "extension 2.5.29.14 mismatch")
	})
}

func TestRequestRejectsInvalidProfilesAndProofs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*x509.Certificate)
		proof   func([]byte) []byte
		kind    SVIDType
		version string
		want    string
	}{
		{name: "missing URI", mutate: func(c *x509.Certificate) { c.URIs = nil }, want: "exactly one SPIFFE URI"},
		{name: "nil URI", mutate: func(c *x509.Certificate) { c.URIs[0] = nil }, want: "exactly one SPIFFE URI"},
		{name: "non-SPIFFE URI", mutate: func(c *x509.Certificate) { c.URIs[0].Scheme = "https" }, want: "valid leaf SPIFFE ID"},
		{name: "trust domain ID", mutate: func(c *x509.Certificate) { c.URIs[0].Path = "" }, want: "valid leaf SPIFFE ID"},
		{name: "CA profile", mutate: func(c *x509.Certificate) { c.IsCA = true }, want: "leaf CA constraints"},
		{name: "missing basic constraints", mutate: func(c *x509.Certificate) { c.BasicConstraintsValid = false }, want: "leaf CA constraints"},
		{name: "leaf path length", mutate: func(c *x509.Certificate) { c.MaxPathLenZero = true }, want: "leaf CA constraints"},
		{name: "missing digital signature", mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, want: "key usage"},
		{name: "unsupported key usage", mutate: func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }, want: "key usage"},
		{name: "unsupported EKU", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) }, want: "extended key usage"},
		{name: "duplicate EKU", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) }, want: "extended key usage"},
		{name: "unknown EKU", mutate: func(c *x509.Certificate) { c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 99}} }, want: "extended key usage"},
		{name: "unrepresentable IP", mutate: func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable email", mutate: func(c *x509.Certificate) { c.EmailAddresses = []string{"workload@example.org"} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable AIA", mutate: func(c *x509.Certificate) { c.OCSPServer = []string{"https://ocsp.example.org"} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable CRL", mutate: func(c *x509.Certificate) { c.CRLDistributionPoints = []string{"https://ca.example.org/issuer.crl"} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable policy", mutate: func(c *x509.Certificate) { c.PolicyIdentifiers = []asn1.ObjectIdentifier{{1, 2, 3, 5}} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable name constraint", mutate: func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"example.org"} }, want: "unsupported certificate profile fields"},
		{name: "unrepresentable policy constraint", mutate: func(c *x509.Certificate) { c.RequireExplicitPolicyZero = true }, want: "unsupported certificate profile fields"},
		{name: "SAN override", mutate: func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: []byte{5, 0}})
		}, want: "overrides a profile field"},
		{name: "duplicate extension", mutate: func(c *x509.Certificate) { c.ExtraExtensions = append(c.ExtraExtensions, c.ExtraExtensions[0]) }, want: "duplicate profile extension"},
		{name: "invalid extension OID", mutate: func(c *x509.Certificate) { c.ExtraExtensions[0].Id = nil }, want: "invalid profile extension OID"},
		{name: "malformed raw subject", mutate: func(c *x509.Certificate) { c.RawSubject = []byte("invalid") }, want: "invalid authoritative raw subject"},
		{name: "trailing raw subject data", mutate: func(c *x509.Certificate) { c.RawSubject = []byte{0x30, 0, 0} }, want: "invalid authoritative raw subject"},
		{name: "invalid validity", mutate: func(c *x509.Certificate) { c.NotAfter = c.NotBefore }, want: "profile validity"},
		{name: "empty second-precision validity", mutate: func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(time.Millisecond) }, want: "profile validity"},
		{name: "missing validity", mutate: func(c *x509.Certificate) { c.NotBefore = time.Time{} }, want: "profile validity"},
		{name: "invalid timestamp", mutate: func(c *x509.Certificate) { c.NotAfter = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, want: "profile validity"},
		{name: "missing proof", proof: func([]byte) []byte { return nil }, want: "proof CSR is required"},
		{name: "malformed proof", proof: func([]byte) []byte { return []byte("invalid") }, want: "proof CSR is invalid"},
		{name: "invalid signature", proof: func(p []byte) []byte { p[len(p)-1] ^= 0xff; return p }, want: "proof CSR is invalid"},
		{name: "invalid SVID type", kind: SVIDType(99), want: "SVID type"},
		{name: "missing authority version", version: " ", want: "authority version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			if tt.mutate != nil {
				tt.mutate(f.template)
			}
			if tt.proof != nil {
				f.proof = tt.proof(f.proof)
			}
			kind, version := WorkloadSVID, "v1"
			if tt.kind != 0 {
				kind = tt.kind
			}
			if tt.version != "" {
				version = strings.TrimSpace(tt.version)
			}
			var request *issuerv1.IssueX509SVIDRequest
			var err error
			require.NotPanics(t, func() {
				request, err = BuildIssueRequest(f.template, f.proof, kind, version)
			})
			require.ErrorContains(t, err, tt.want)
			require.Nil(t, request)
		})
	}
	t.Run("nil profile", func(t *testing.T) {
		f := newIssuanceFixture(t)
		require.NotPanics(t, func() {
			_, err := BuildIssueRequest(nil, f.proof, WorkloadSVID, "v1")
			require.ErrorContains(t, err, "profile is required")
		})
	})
}

func TestProfileUsesX509SecondPrecision(t *testing.T) {
	f := newIssuanceFixture(t)
	f.template.NotBefore = f.template.NotBefore.Add(900 * time.Millisecond)
	f.template.NotAfter = f.template.NotAfter.Add(900 * time.Millisecond)
	request, err := BuildIssueRequest(f.template, f.proof, WorkloadSVID, "v1")
	require.NoError(t, err)
	require.Equal(t, f.template.NotBefore.Truncate(time.Second), request.Profile.NotBefore.AsTime())
	require.Equal(t, f.template.NotAfter.Truncate(time.Second), request.Profile.NotAfter.AsTime())
	_, err = ParseAndValidateResponse(f.template, f.response(t, nil), f.snapshot())
	require.NoError(t, err)
}

func TestProfilePreservesRawSubject(t *testing.T) {
	f := newIssuanceFixture(t)
	raw, err := asn1.Marshal(pkix.Name{CommonName: "authorized raw subject"}.ToRDNSequence())
	require.NoError(t, err)
	f.template.RawSubject = raw
	request, err := BuildIssueRequest(f.template, f.proof, WorkloadSVID, "v1")
	require.NoError(t, err)
	require.Equal(t, raw, request.Profile.Subject)
	_, err = ParseAndValidateResponse(f.template, f.response(t, nil), f.snapshot())
	require.NoError(t, err)
}

func TestResponseChainAndMalformedData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*issuerv1.IssueX509SVIDResponse, []*x509.Certificate) *issuerv1.IssueX509SVIDResponse
		want   string
	}{
		{"valid ordered chain", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			return r
		}, ""},
		{"nil response", func(*issuerv1.IssueX509SVIDResponse, []*x509.Certificate) *issuerv1.IssueX509SVIDResponse { return nil }, "no response"},
		{"malformed leaf", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.LeafCertificate = []byte("invalid")
			return r
		}, "malformed leaf"},
		{"invalid leaf signature", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.LeafCertificate[len(r.LeafCertificate)-1] ^= 0xff
			return r
		}, "chain validation failed"},
		{"malformed intermediate", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates[0] = []byte("invalid")
			return r
		}, "malformed intermediate"},
		{"authority version", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.AuthorityVersion = "v2"
			return r
		}, "mismatched authority version"},
		{"missing intermediate", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates = r.Intermediates[:1]
			return r
		}, "chain validation failed"},
		{"reversed intermediates", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates[0], r.Intermediates[1] = r.Intermediates[1], r.Intermediates[0]
			return r
		}, "ordered chain"},
		{"duplicate intermediate", func(r *issuerv1.IssueX509SVIDResponse, _ []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates = append(r.Intermediates, r.Intermediates[1])
			return r
		}, "ordered chain"},
		{"root in response", func(r *issuerv1.IssueX509SVIDResponse, c []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates = append(r.Intermediates, c[0].Raw)
			return r
		}, "ordered chain"},
		{"unused intermediate", func(r *issuerv1.IssueX509SVIDResponse, c []*x509.Certificate) *issuerv1.IssueX509SVIDResponse {
			r.Intermediates = append(r.Intermediates, c[3].Raw)
			return r
		}, "ordered chain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newIssuanceFixture(t)
			firstKey, secondKey := newECDSAKey(t), newECDSAKey(t)
			first := f.signingCA(t, "first", f.root, f.rootKey, firstKey)
			second := f.signingCA(t, "second", first, firstKey, secondKey)
			unused := f.signingCA(t, "unused", f.root, f.rootKey, newECDSAKey(t))
			leaf := createCertificate(t, f.template, second, f.template.PublicKey, secondKey)
			response := &issuerv1.IssueX509SVIDResponse{
				LeafCertificate: leaf.Raw, Intermediates: [][]byte{second.Raw, first.Raw}, AuthorityVersion: "v1",
			}
			response = tt.mutate(response, []*x509.Certificate{f.root, first, second, unused})
			chain, err := ParseAndValidateResponse(f.template, response, f.snapshot())
			if tt.want == "" {
				require.NoError(t, err)
				require.Len(t, chain, 3)
			} else {
				require.ErrorContains(t, err, tt.want)
				require.Nil(t, chain)
			}
		})
	}
	t.Run("untrusted root", func(t *testing.T) {
		f := newIssuanceFixture(t)
		other := newIssuanceFixture(t)
		_, err := ParseAndValidateResponse(f.template, f.response(t, nil), other.snapshot())
		require.ErrorContains(t, err, "chain validation failed")
	})
}

type issuanceFixture struct {
	template *x509.Certificate
	proof    []byte
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
}

func newIssuanceFixture(t *testing.T) *issuanceFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := newECDSAKey(t)
	f := &issuanceFixture{rootKey: newECDSAKey(t)}
	f.root = f.signingCA(t, "root", nil, f.rootKey, f.rootKey)
	f.template = &x509.Certificate{
		SerialNumber: big.NewInt(42),
		PublicKey:    key.Public(),
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		URIs:     []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/workload"}},
		DNSNames: []string{"workload.example"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{4, 1, 1}}},
	}
	var err error
	f.proof, err = x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
	require.NoError(t, err)
	return f
}

func (f *issuanceFixture) signingCA(t *testing.T, name string, parent *x509.Certificate, signer, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	if parent == nil {
		parent = template
	}
	return createCertificate(t, template, parent, key.Public(), signer)
}

func (f *issuanceFixture) response(t *testing.T, mutate func(*x509.Certificate)) *issuerv1.IssueX509SVIDResponse {
	t.Helper()
	template := *f.template
	template.ExtraExtensions = append([]pkix.Extension(nil), template.ExtraExtensions...)
	if mutate != nil {
		mutate(&template)
	}
	leaf := createCertificate(t, &template, f.root, template.PublicKey, f.rootKey)
	return &issuerv1.IssueX509SVIDResponse{LeafCertificate: leaf.Raw, AuthorityVersion: "v1"}
}

func (f *issuanceFixture) snapshot() Snapshot {
	return Snapshot{Version: "v1", Roots: []*x509.Certificate{f.root}}
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireNoError(t, err)
	return key
}

func createCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	requireNoError(t, err)
	cert, err := x509.ParseCertificate(der)
	requireNoError(t, err)
	return cert
}
