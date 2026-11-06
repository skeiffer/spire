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
	"github.com/stretchr/testify/require"
)

func TestIssueRequestUsesAuthorizedProfileNotProofContents(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := newTestKey(t)
	id := &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/workload"}
	template := &x509.Certificate{
		PublicKey:             key.Public(),
		Subject:               pkix.Name{CommonName: "authorized.example"},
		URIs:                  []*url.URL{id},
		DNSNames:              []string{"authorized.example"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
	}
	proof, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "untrusted.example"},
		DNSNames: []string{"untrusted.example"},
		URIs:     []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/other"}},
	}, key)
	require.NoError(t, err)

	req, err := BuildIssueRequest(template, proof, WorkloadSVID, "v1")
	require.NoError(t, err)
	require.Equal(t, id.String(), req.Profile.SpiffeId)
	require.Equal(t, []string{"authorized.example"}, req.Profile.DnsNames)
	require.Equal(t, now.Add(-time.Minute), req.Profile.NotBefore.AsTime())
	require.Equal(t, now.Add(time.Hour), req.Profile.NotAfter.AsTime())
}

func TestIssueRequestRejectsInvalidProofAndProfile(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*x509.Certificate, *[]byte)
		want   string
	}{
		{
			name: "missing proof",
			mutate: func(_ *x509.Certificate, proof *[]byte) {
				*proof = nil
			},
			want: "proof CSR is required",
		},
		{
			name: "wrong proof key",
			mutate: func(_ *x509.Certificate, proof *[]byte) {
				var err error
				*proof, err = x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), newTestKey(t))
				require.NoError(t, err)
			},
			want: "proof CSR public key does not match profile",
		},
		{
			name: "root identity",
			mutate: func(template *x509.Certificate, _ *[]byte) {
				template.URIs[0].Path = ""
			},
			want: "valid leaf SPIFFE ID",
		},
		{
			name: "CA leaf",
			mutate: func(template *x509.Certificate, _ *[]byte) {
				template.IsCA = true
			},
			want: "leaf CA constraints",
		},
		{
			name: "invalid second precision",
			mutate: func(template *x509.Certificate, _ *[]byte) {
				template.NotAfter = template.NotBefore.Add(time.Millisecond)
			},
			want: "profile validity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template, proof, _ := newProfileFixture(t)
			tt.mutate(template, &proof)
			_, err := BuildIssueRequest(template, proof, WorkloadSVID, "v1")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestResponseValidationUsesCapturedPathAndTime(t *testing.T) {
	template, _, leafKey := newProfileFixture(t)
	now := template.NotBefore.Add(time.Minute)
	rootKey := newTestKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              template.NotAfter.Add(-time.Minute),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root := createTestCertificate(t, rootTemplate, rootTemplate, rootKey.Public(), rootKey)

	short := *template
	short.SerialNumber = big.NewInt(2)
	short.NotBefore = now.Add(-time.Second)
	short.NotAfter = root.NotAfter.Add(-time.Second)
	leaf := createTestCertificate(t, &short, root, leafKey.Public(), rootKey)
	response := &issuerv1.IssueX509SVIDResponse{LeafCertificate: leaf.Raw, AuthorityVersion: "v1"}
	snapshot := Snapshot{Version: "v1", Roots: []*x509.Certificate{root}}

	chain, err := ParseAndValidateResponse(template, response, snapshot, now)
	require.NoError(t, err)
	require.Len(t, chain, 1)

	tooLong := short
	tooLong.NotAfter = root.NotAfter.Add(time.Second)
	response.LeafCertificate = createTestCertificate(t, &tooLong, root, leafKey.Public(), rootKey).Raw
	_, err = ParseAndValidateResponse(template, response, snapshot, now)
	require.ErrorContains(t, err, "selected authority path")

	response.LeafCertificate = leaf.Raw
	_, err = ParseAndValidateResponse(template, response, snapshot, leaf.NotAfter)
	require.ErrorContains(t, err, "currently usable")
}

func newProfileFixture(t *testing.T) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := newTestKey(t)
	template := &x509.Certificate{
		PublicKey:             key.Public(),
		Subject:               pkix.Name{},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/workload"}},
		DNSNames:              []string{"workload.example"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
	}
	proof, err := x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), key)
	require.NoError(t, err)
	return template, proof, key
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func createTestCertificate(t *testing.T, template, parent *x509.Certificate, publicKey any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return cert
}
