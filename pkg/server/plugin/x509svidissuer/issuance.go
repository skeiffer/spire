package x509svidissuer

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func BuildIssueRequest(template *x509.Certificate, proofCSR []byte, svidType issuerv1.X509SVIDType, authorityVersion string) (*issuerv1.IssueX509SVIDRequest, error) {
	if len(proofCSR) == 0 {
		return nil, errors.New("proof CSR is required by configured external X509-SVID issuer")
	}
	csr, err := x509.ParseCertificateRequest(proofCSR)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("proof CSR is invalid")
	}
	profileKey, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal profile public key: %w", err)
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(profileKey, csrKey) {
		return nil, errors.New("proof CSR public key does not match profile")
	}
	if len(template.URIs) != 1 {
		return nil, errors.New("authoritative profile must contain exactly one SPIFFE URI")
	}
	subject, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal profile subject: %w", err)
	}
	return &issuerv1.IssueX509SVIDRequest{
		ProofCsr: proofCSR,
		Profile: &issuerv1.X509SVIDProfile{
			Type:              svidType,
			SpiffeId:          template.URIs[0].String(),
			PublicKey:         profileKey,
			Subject:           subject,
			DnsNames:          append([]string(nil), template.DNSNames...),
			KeyUsages:         toPluginKeyUsages(template.KeyUsage),
			ExtendedKeyUsages: toPluginExtendedKeyUsages(template.ExtKeyUsage),
			ExtraExtensions:   toPluginExtensions(template.ExtraExtensions),
			NotBefore:         timestamppb.New(template.NotBefore),
			NotAfter:          timestamppb.New(template.NotAfter),
		},
		AuthorityVersion: authorityVersion,
	}, nil
}

func ParseAndValidateResponse(template *x509.Certificate, response *issuerv1.IssueX509SVIDResponse, snapshot Snapshot) ([]*x509.Certificate, error) {
	if response == nil {
		return nil, errors.New("external issuer returned no response")
	}
	if response.GetAuthorityVersion() != snapshot.Version {
		return nil, errors.New("external issuer returned mismatched authority version")
	}
	leaf, err := x509.ParseCertificate(response.GetLeafCertificate())
	if err != nil {
		return nil, errors.New("external issuer returned malformed leaf certificate")
	}
	chain := []*x509.Certificate{leaf}
	for _, raw := range response.GetIntermediates() {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("external issuer returned malformed intermediate certificate")
		}
		chain = append(chain, cert)
	}
	if err := validateLeaf(template, leaf, chain[1:], snapshot.Roots); err != nil {
		return nil, fmt.Errorf("external issuer returned invalid X509-SVID: %w", err)
	}
	return chain, nil
}

func toPluginKeyUsages(usage x509.KeyUsage) []issuerv1.X509KeyUsage {
	var out []issuerv1.X509KeyUsage
	if usage&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, issuerv1.X509KeyUsage_X509_KEY_USAGE_DIGITAL_SIGNATURE)
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_ENCIPHERMENT)
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_AGREEMENT)
	}
	return out
}

func toPluginExtendedKeyUsages(usages []x509.ExtKeyUsage) []issuerv1.X509ExtendedKeyUsage {
	var out []issuerv1.X509ExtendedKeyUsage
	if slices.Contains(usages, x509.ExtKeyUsageClientAuth) {
		out = append(out, issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH)
	}
	if slices.Contains(usages, x509.ExtKeyUsageServerAuth) {
		out = append(out, issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH)
	}
	return out
}

func toPluginExtensions(extensions []pkix.Extension) []*issuerv1.X509Extension {
	out := make([]*issuerv1.X509Extension, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, &issuerv1.X509Extension{
			Oid: extension.Id.String(), Value: append([]byte(nil), extension.Value...), Critical: extension.Critical,
		})
	}
	return out
}

func validateLeaf(template, leaf *x509.Certificate, intermediates, roots []*x509.Certificate) error {
	templateKey, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return err
	}
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(templateKey, leafKey) {
		return errors.New("public key mismatch")
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid {
		return errors.New("leaf CA constraints are invalid")
	}
	expectedSubject, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil || !bytes.Equal(expectedSubject, leaf.RawSubject) {
		return errors.New("certificate subject mismatch")
	}
	if len(leaf.URIs) != 1 || len(template.URIs) != 1 || leaf.URIs[0].String() != template.URIs[0].String() {
		return errors.New("SPIFFE ID mismatch")
	}
	if !slices.Equal(leaf.DNSNames, template.DNSNames) {
		return errors.New("DNS SAN mismatch")
	}
	if leaf.KeyUsage != template.KeyUsage || !sameExtendedKeyUsages(leaf.ExtKeyUsage, template.ExtKeyUsage) {
		return errors.New("certificate usage mismatch")
	}
	for _, expected := range template.ExtraExtensions {
		if !slices.ContainsFunc(leaf.Extensions, func(actual pkix.Extension) bool {
			return actual.Id.Equal(expected.Id) && actual.Critical == expected.Critical && bytes.Equal(actual.Value, expected.Value)
		}) {
			return fmt.Errorf("certificate extension %s mismatch", expected.Id)
		}
	}
	if leaf.NotBefore.Before(template.NotBefore.Add(-time.Minute)) || leaf.NotAfter.After(template.NotAfter.Add(time.Second)) {
		return errors.New("certificate validity exceeds authoritative profile")
	}
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}
	return nil
}

func sameExtendedKeyUsages(left, right []x509.ExtKeyUsage) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[x509.ExtKeyUsage]int, len(left))
	for _, usage := range left {
		counts[usage]++
	}
	for _, usage := range right {
		counts[usage]--
		if counts[usage] < 0 {
			return false
		}
	}
	return true
}
