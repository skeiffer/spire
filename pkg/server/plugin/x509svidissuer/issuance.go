package x509svidissuer

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SVIDType = issuerv1.X509SVIDType

const (
	ServerSVID   = issuerv1.X509SVIDType_X509_SVID_TYPE_SERVER
	AgentSVID    = issuerv1.X509SVIDType_X509_SVID_TYPE_AGENT
	WorkloadSVID = issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD
)

func BuildIssueRequest(template *x509.Certificate, proofCSR []byte, svidType SVIDType, authorityVersion string) (*issuerv1.IssueX509SVIDRequest, error) {
	if err := validateProfile(template); err != nil {
		return nil, err
	}
	switch svidType {
	case ServerSVID, AgentSVID, WorkloadSVID:
	default:
		return nil, errors.New("authoritative profile has invalid SVID type")
	}
	if strings.TrimSpace(authorityVersion) == "" || strings.TrimSpace(authorityVersion) != authorityVersion || len(authorityVersion) > 256 {
		return nil, errors.New("authority version is required")
	}
	if len(proofCSR) == 0 || len(proofCSR) > 64<<10 {
		return nil, errors.New("proof CSR is required by configured external X509-SVID issuer")
	}
	csr, err := x509.ParseCertificateRequest(proofCSR)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("proof CSR is invalid")
	}
	publicKey, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal profile public key: %w", err)
	}
	proofKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(publicKey, proofKey) {
		return nil, errors.New("proof CSR public key does not match profile")
	}
	subject, err := profileSubject(template)
	if err != nil {
		return nil, err
	}
	return &issuerv1.IssueX509SVIDRequest{
		ProofCsr: bytes.Clone(proofCSR),
		Profile: &issuerv1.X509SVIDProfile{
			Type:              svidType,
			SpiffeId:          template.URIs[0].String(),
			PublicKey:         publicKey,
			Subject:           subject,
			DnsNames:          append([]string(nil), template.DNSNames...),
			KeyUsages:         toPluginKeyUsages(template.KeyUsage),
			ExtendedKeyUsages: toPluginExtendedKeyUsages(template.ExtKeyUsage),
			ExtraExtensions:   toPluginExtensions(template.ExtraExtensions),
			NotBefore:         timestamppb.New(template.NotBefore.Truncate(time.Second)),
			NotAfter:          timestamppb.New(template.NotAfter.Truncate(time.Second)),
		},
		AuthorityVersion: authorityVersion,
	}, nil
}

func ParseAndValidateResponse(template *x509.Certificate, response *issuerv1.IssueX509SVIDResponse, snapshot Snapshot, now time.Time) ([]*x509.Certificate, error) {
	if err := validateProfile(template); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("external issuer returned no response")
	}
	if response.GetAuthorityVersion() != snapshot.Version {
		return nil, errors.New("external issuer returned mismatched authority version")
	}
	if len(response.GetLeafCertificate()) > 64<<10 || len(response.GetIntermediates()) > 8 {
		return nil, errors.New("external issuer response exceeds host resource limits")
	}
	leaf, err := x509.ParseCertificate(response.GetLeafCertificate())
	if err != nil {
		return nil, errors.New("external issuer returned malformed leaf certificate")
	}
	intermediates := make([]*x509.Certificate, 0, len(response.GetIntermediates()))
	for _, raw := range response.GetIntermediates() {
		if len(raw) > 64<<10 {
			return nil, errors.New("external issuer certificate exceeds host resource limits")
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("external issuer returned malformed intermediate certificate")
		}
		intermediates = append(intermediates, cert)
	}
	if err := validateLeaf(template, leaf, intermediates, snapshot, now); err != nil {
		return nil, fmt.Errorf("external issuer returned invalid X509-SVID: %w", err)
	}
	return append([]*x509.Certificate{leaf}, intermediates...), nil
}

func validateProfile(template *x509.Certificate) error {
	if template == nil {
		return errors.New("authoritative profile is required")
	}
	if len(template.URIs) != 1 || template.URIs[0] == nil {
		return errors.New("authoritative profile must contain exactly one SPIFFE URI")
	}
	id, err := spiffeid.FromURI(template.URIs[0])
	if err != nil || id.Path() == "" || id.Path() == "/" {
		return errors.New("authoritative profile must contain a valid leaf SPIFFE ID")
	}
	if template.IsCA || !template.BasicConstraintsValid || template.MaxPathLen > 0 || template.MaxPathLen < -1 || template.MaxPathLenZero {
		return errors.New("authoritative profile leaf CA constraints are invalid")
	}
	allowed := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 || template.KeyUsage&^allowed != 0 {
		return errors.New("authoritative profile has unsupported key usage")
	}
	if len(template.UnknownExtKeyUsage) != 0 ||
		len(template.ExtKeyUsage) != 0 && !sameExtendedKeyUsages(template.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}) {
		return errors.New("authoritative profile has unsupported extended key usage")
	}
	if len(template.IPAddresses) != 0 || len(template.EmailAddresses) != 0 ||
		len(template.OCSPServer) != 0 || len(template.IssuingCertificateURL) != 0 ||
		len(template.CRLDistributionPoints) != 0 || len(template.Policies) != 0 ||
		len(template.PolicyIdentifiers) != 0 || len(template.PermittedDNSDomains) != 0 ||
		len(template.ExcludedDNSDomains) != 0 || len(template.PermittedIPRanges) != 0 ||
		len(template.ExcludedIPRanges) != 0 || len(template.PermittedEmailAddresses) != 0 ||
		len(template.ExcludedEmailAddresses) != 0 || len(template.PermittedURIDomains) != 0 ||
		len(template.ExcludedURIDomains) != 0 || len(template.PolicyMappings) != 0 {
		return errors.New("authoritative profile contains unsupported certificate profile fields")
	}
	if template.SerialNumber != nil || len(template.SubjectKeyId) != 0 || len(template.AuthorityKeyId) != 0 ||
		len(template.Raw) != 0 || len(template.RawTBSCertificate) != 0 || len(template.RawSubjectPublicKeyInfo) != 0 ||
		len(template.RawIssuer) != 0 || len(template.Signature) != 0 || len(template.Extensions) != 0 ||
		len(template.UnhandledCriticalExtensions) != 0 || template.SignatureAlgorithm != x509.UnknownSignatureAlgorithm ||
		template.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm || template.Version != 0 || template.Issuer.String() != "" ||
		template.PermittedDNSDomainsCritical || template.RequireExplicitPolicy != 0 || template.RequireExplicitPolicyZero ||
		template.InhibitAnyPolicy != 0 || template.InhibitAnyPolicyZero || template.InhibitPolicyMapping != 0 || template.InhibitPolicyMappingZero {
		return errors.New("authoritative profile contains unexpressed signing or constraint fields")
	}
	notBefore := template.NotBefore.Truncate(time.Second)
	notAfter := template.NotAfter.Truncate(time.Second)
	if notBefore.IsZero() || !notAfter.After(notBefore) ||
		timestamppb.New(notBefore).CheckValid() != nil || timestamppb.New(notAfter).CheckValid() != nil {
		return errors.New("authoritative profile validity is invalid")
	}
	seen := make(map[string]struct{}, len(template.ExtraExtensions))
	for _, extension := range template.ExtraExtensions {
		if _, err := asn1.Marshal(extension.Id); err != nil {
			return errors.New("invalid profile extension OID")
		}
		oid := extension.Id.String()
		if _, ok := seen[oid]; ok {
			return fmt.Errorf("duplicate profile extension %s", oid)
		}
		seen[oid] = struct{}{}
		switch oid {
		case "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.37":
			return fmt.Errorf("profile extension %s overrides a profile field", oid)
		}
	}
	_, err = profileSubject(template)
	return err
}

func profileSubject(template *x509.Certificate) ([]byte, error) {
	if len(template.RawSubject) == 0 {
		return asn1.Marshal(template.Subject.ToRDNSequence())
	}
	var subject pkix.RDNSequence
	rest, err := asn1.Unmarshal(template.RawSubject, &subject)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("invalid authoritative raw subject")
	}
	return bytes.Clone(template.RawSubject), nil
}

func validateLeaf(template, leaf *x509.Certificate, intermediates []*x509.Certificate, snapshot Snapshot, now time.Time) error {
	templateKey, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return err
	}
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(templateKey, leafKey) {
		return errors.New("public key mismatch")
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.MaxPathLen > 0 || leaf.MaxPathLenZero {
		return errors.New("leaf CA constraints are invalid")
	}
	subject, err := profileSubject(template)
	if err != nil || !bytes.Equal(subject, leaf.RawSubject) {
		return errors.New("certificate subject mismatch")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != template.URIs[0].String() {
		return errors.New("SPIFFE ID mismatch")
	}
	if !slices.Equal(leaf.DNSNames, template.DNSNames) {
		return errors.New("DNS SAN mismatch")
	}
	if leaf.KeyUsage != template.KeyUsage || len(leaf.UnknownExtKeyUsage) != 0 || !sameExtendedKeyUsages(leaf.ExtKeyUsage, template.ExtKeyUsage) {
		return errors.New("certificate usage mismatch")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("certificate is not currently usable")
	}
	if leaf.NotBefore.Before(template.NotBefore.Truncate(time.Second)) ||
		leaf.NotAfter.After(template.NotAfter.Truncate(time.Second)) || !leaf.NotAfter.After(leaf.NotBefore) {
		return errors.New("certificate validity exceeds authoritative profile")
	}
	for _, expected := range template.ExtraExtensions {
		if !slices.ContainsFunc(leaf.Extensions, func(actual pkix.Extension) bool {
			return actual.Id.Equal(expected.Id) && actual.Critical == expected.Critical && bytes.Equal(actual.Value, expected.Value)
		}) {
			return fmt.Errorf("certificate extension %s mismatch", expected.Id)
		}
	}
	if err := validateLeafExtensions(template, leaf); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	for _, root := range snapshot.Roots {
		roots.AddCert(root)
	}
	pool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		pool.AddCert(intermediate)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}
	orderedPathFound := false
	for _, path := range verified {
		if len(path) != len(intermediates)+2 ||
			!slices.EqualFunc(intermediates, path[1:len(path)-1], sameCertificate) {
			continue
		}
		orderedPathFound = true
		validLifetime := true
		for _, issuer := range path[1:] {
			if leaf.NotAfter.After(issuer.NotAfter) {
				validLifetime = false
				break
			}
		}
		if validLifetime {
			return nil
		}
	}
	if orderedPathFound {
		return errors.New("certificate outlives selected authority path")
	}
	return errors.New("response must contain an ordered chain without trust roots or unused certificates")
}

func validateLeafExtensions(template, leaf *x509.Certificate) error {
	for _, extension := range leaf.Extensions {
		switch extension.Id.String() {
		case "2.5.29.15":
			if !extension.Critical {
				return errors.New("key usage extension must be critical")
			}
		case "2.5.29.17":
			if len(leaf.Subject.Names) == 0 && !extension.Critical {
				return errors.New("subject alternative name extension must be critical for an empty subject")
			}
			var names []asn1.RawValue
			rest, err := asn1.Unmarshal(extension.Value, &names)
			if err != nil || len(rest) != 0 {
				return errors.New("invalid subject alternative name extension")
			}
			for _, name := range names {
				if name.Class != 2 || name.IsCompound || name.Tag != 2 && name.Tag != 6 {
					return errors.New("unsupported subject alternative name")
				}
			}
		case "2.5.29.14", "2.5.29.19", "2.5.29.35", "2.5.29.37",
			"1.3.6.1.5.5.7.1.1", "2.5.29.31", "2.5.29.32":
		default:
			if !slices.ContainsFunc(template.ExtraExtensions, func(expected pkix.Extension) bool {
				return expected.Id.Equal(extension.Id)
			}) {
				return fmt.Errorf("unauthorized certificate extension %s", extension.Id)
			}
		}
	}
	return nil
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
			Oid: extension.Id.String(), Value: bytes.Clone(extension.Value), Critical: extension.Critical,
		})
	}
	return out
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
