package x509svidissuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
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
	proof, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
	requireNoError(t, err)
	request, err := BuildIssueRequest(template, proof, issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD, "v1")
	requireNoError(t, err)
	if request.GetProfile().GetSpiffeId() != id.String() {
		t.Fatalf("profile SPIFFE ID = %q", request.GetProfile().GetSpiffeId())
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
	}

	if _, err := BuildIssueRequest(template, proof, issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD, "v1"); err == nil {
		t.Fatal("expected proof key mismatch")
	}
}

func TestExtendedKeyUsageComparisonRejectsDuplicateSubstitution(t *testing.T) {
	if sameExtendedKeyUsages(
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	) {
		t.Fatal("duplicate usage substituted for a required usage")
	}
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
