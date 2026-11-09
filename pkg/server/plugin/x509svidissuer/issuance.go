package x509svidissuer

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func BuildIssueRequest(template *x509.Certificate, proofCSR []byte, svidType issuerv1.X509SVIDType, authorityVersion string) (*issuerv1.IssueX509SVIDRequest, error) {
	if err := validateProfile(template); err != nil {
		return nil, err
	}
	switch svidType {
	case ServerSVID, AgentSVID, WorkloadSVID:
	default:
		return nil, errors.New("authoritative profile has invalid SVID type")
	}
	if strings.TrimSpace(authorityVersion) == "" {
		return nil, errors.New("authority version is required")
	}
	if len(proofCSR) > maxCSRSize {
		return nil, errors.New("proof CSR exceeds size limit")
	}
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
	subject, err := profileSubject(template)
	if err != nil {
		return nil, fmt.Errorf("marshal profile subject: %w", err)
	}
	return &issuerv1.IssueX509SVIDRequest{
		ProofCsr: bytes.Clone(proofCSR),
		Profile: &issuerv1.X509SVIDProfile{
			Type:              svidType,
			SpiffeId:          template.URIs[0].String(),
			PublicKey:         profileKey,
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

func ParseAndValidateResponse(template *x509.Certificate, response *issuerv1.IssueX509SVIDResponse, snapshot Snapshot) ([]*x509.Certificate, error) {
	return parseAndValidateResponse(template, response, snapshot, time.Now())
}

func parseAndValidateResponse(template *x509.Certificate, response *issuerv1.IssueX509SVIDResponse, snapshot Snapshot, now time.Time) ([]*x509.Certificate, error) {
	if err := validateProfile(template); err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("external issuer returned no response")
	}
	if proto.Size(response) > maxResponseSize || len(response.GetIntermediates()) >= maxPathDepth {
		return nil, errors.New("external issuer response exceeds size or chain depth limit")
	}
	if response.GetAuthorityVersion() != snapshot.Version {
		return nil, errors.New("external issuer returned mismatched authority version")
	}
	if strings.TrimSpace(snapshot.Version) == "" || len(snapshot.Roots) == 0 {
		return nil, errors.New("authority snapshot requires a version and trust roots")
	}
	if len(response.GetLeafCertificate()) > maxCertificateSize {
		return nil, errors.New("external issuer leaf certificate exceeds size limit")
	}
	leaf, err := x509.ParseCertificate(bytes.Clone(response.GetLeafCertificate()))
	if err != nil {
		return nil, errors.New("external issuer returned malformed leaf certificate")
	}
	chain := []*x509.Certificate{leaf}
	for _, raw := range response.GetIntermediates() {
		if len(raw) > maxCertificateSize {
			return nil, errors.New("external issuer intermediate certificate exceeds size limit")
		}
		cert, err := x509.ParseCertificate(bytes.Clone(raw))
		if err != nil {
			return nil, errors.New("external issuer returned malformed intermediate certificate")
		}
		chain = append(chain, cert)
	}
	if err := validateLeaf(template, leaf, chain[1:], snapshot.Roots, now); err != nil {
		return nil, fmt.Errorf("external issuer returned invalid X509-SVID: %w", err)
	}
	paths := snapshot.Paths
	if len(paths) == 0 {
		for _, root := range snapshot.Roots {
			paths = append(paths, AuthorityPath{Root: root})
		}
	}
	authorized := false
	for _, path := range paths {
		if len(path.Intermediates) != len(chain)-1 {
			continue
		}
		match := true
		for i, cert := range path.Intermediates {
			if !cert.Equal(chain[len(chain)-1-i]) {
				match = false
				break
			}
		}
		if match && verifyChain(leaf, chain[1:], []*x509.Certificate{path.Root}, now) == nil {
			authorized = true
			break
		}
	}
	if !authorized {
		return nil, errors.New("external issuer returned a chain outside the authorized authority paths")
	}
	return chain, nil
}

func cloneProfile(template *x509.Certificate) (*x509.Certificate, error) {
	if err := validateProfile(template); err != nil {
		return nil, err
	}
	out := *template
	key, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return nil, err
	}
	out.PublicKey, err = x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	out.RawSubject, err = profileSubject(template)
	if err != nil {
		return nil, err
	}
	id := *template.URIs[0]
	out.URIs = []*url.URL{&id}
	out.DNSNames = slices.Clone(template.DNSNames)
	out.ExtKeyUsage = slices.Clone(template.ExtKeyUsage)
	out.ExtraExtensions = slices.Clone(template.ExtraExtensions)
	for i := range out.ExtraExtensions {
		out.ExtraExtensions[i].Id = slices.Clone(out.ExtraExtensions[i].Id)
		out.ExtraExtensions[i].Value = bytes.Clone(out.ExtraExtensions[i].Value)
	}
	return &out, nil
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
	if template.IsCA || !template.BasicConstraintsValid || template.MaxPathLen > 0 || template.MaxPathLenZero {
		return errors.New("authoritative profile leaf CA constraints are invalid")
	}
	allowedUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	if template.KeyUsage&x509.KeyUsageDigitalSignature == 0 || template.KeyUsage&^allowedUsage != 0 {
		return errors.New("authoritative profile has unsupported key usage")
	}
	if len(template.UnknownExtKeyUsage) != 0 ||
		len(template.ExtKeyUsage) != 0 && !sameExtendedKeyUsages(template.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}) {
		return errors.New("authoritative profile has unsupported extended key usage")
	}
	if len(template.IPAddresses) != 0 || len(template.EmailAddresses) != 0 ||
		len(template.OCSPServer) != 0 || len(template.IssuingCertificateURL) != 0 ||
		len(template.CRLDistributionPoints) != 0 || len(template.Policies) != 0 || len(template.PolicyIdentifiers) != 0 ||
		template.PermittedDNSDomainsCritical || len(template.PermittedDNSDomains) != 0 || len(template.ExcludedDNSDomains) != 0 ||
		len(template.PermittedIPRanges) != 0 || len(template.ExcludedIPRanges) != 0 ||
		len(template.PermittedEmailAddresses) != 0 || len(template.ExcludedEmailAddresses) != 0 ||
		len(template.PermittedURIDomains) != 0 || len(template.ExcludedURIDomains) != 0 ||
		template.InhibitAnyPolicy > 0 || template.InhibitAnyPolicyZero ||
		template.InhibitPolicyMapping > 0 || template.InhibitPolicyMappingZero ||
		template.RequireExplicitPolicy > 0 || template.RequireExplicitPolicyZero || len(template.PolicyMappings) != 0 {
		return errors.New("authoritative profile contains unsupported certificate profile fields")
	}
	if template.NotBefore.IsZero() || template.NotAfter.IsZero() ||
		!template.NotAfter.Truncate(time.Second).After(template.NotBefore.Truncate(time.Second)) ||
		timestamppb.New(template.NotBefore).CheckValid() != nil || timestamppb.New(template.NotAfter).CheckValid() != nil {
		return errors.New("authoritative profile validity is invalid")
	}
	seen := make(map[string]bool, len(template.ExtraExtensions))
	for _, extension := range template.ExtraExtensions {
		oid := extension.Id.String()
		if _, err := asn1.Marshal(extension.Id); err != nil {
			return fmt.Errorf("invalid profile extension OID: %w", err)
		}
		if seen[oid] {
			return fmt.Errorf("duplicate profile extension %s", oid)
		}
		seen[oid] = true
		switch oid {
		case "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.37":
			return fmt.Errorf("profile extension %s overrides a profile field", oid)
		}
	}
	return nil
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

func validateLeaf(template, leaf *x509.Certificate, intermediates, roots []*x509.Certificate, now time.Time) error {
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
	expectedSubject, err := profileSubject(template)
	if err != nil || !bytes.Equal(expectedSubject, leaf.RawSubject) {
		return errors.New("certificate subject mismatch")
	}
	if len(leaf.URIs) != 1 || len(template.URIs) != 1 || leaf.URIs[0].String() != template.URIs[0].String() {
		return errors.New("SPIFFE ID mismatch")
	}
	if !slices.Equal(leaf.DNSNames, template.DNSNames) {
		return errors.New("DNS SAN mismatch")
	}
	if leaf.KeyUsage != template.KeyUsage || len(leaf.UnknownExtKeyUsage) != 0 || !sameExtendedKeyUsages(leaf.ExtKeyUsage, template.ExtKeyUsage) {
		return errors.New("certificate usage mismatch")
	}
	for _, expected := range template.ExtraExtensions {
		if !slices.ContainsFunc(leaf.Extensions, func(actual pkix.Extension) bool {
			return actual.Id.Equal(expected.Id) && actual.Critical == expected.Critical && bytes.Equal(actual.Value, expected.Value)
		}) {
			return fmt.Errorf("certificate extension %s mismatch", expected.Id)
		}
	}
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
		case "2.5.29.37":
			if len(leaf.ExtKeyUsage) == 0 {
				return errors.New("certificate usage mismatch")
			}
		case "2.5.29.14", "2.5.29.19", "2.5.29.35",
			"1.3.6.1.5.5.7.1.1", "2.5.29.31", "2.5.29.32":
			// Issuers may supply key identifiers and certificate-discovery metadata.
		default:
			if !slices.ContainsFunc(template.ExtraExtensions, func(expected pkix.Extension) bool {
				return expected.Id.Equal(extension.Id)
			}) {
				return fmt.Errorf("unauthorized certificate extension %s", extension.Id)
			}
		}
	}
	if leaf.NotBefore.Before(template.NotBefore.Truncate(time.Second)) ||
		leaf.NotAfter.After(template.NotAfter.Truncate(time.Second)) || !leaf.NotAfter.After(leaf.NotBefore) {
		return errors.New("certificate validity exceeds authoritative profile")
	}
	return verifyChain(leaf, intermediates, roots, now)
}

func verifyChain(leaf *x509.Certificate, intermediates, roots []*x509.Certificate, now time.Time) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		if root == nil {
			return errors.New("authority snapshot contains a nil root")
		}
		rootPool.AddCert(root)
	}
	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}
	verified, err := leaf.Verify(x509.VerifyOptions{
		Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: now,
	})
	if err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}
	for _, chain := range verified {
		if len(chain) == len(intermediates)+2 &&
			slices.EqualFunc(intermediates, chain[1:len(chain)-1], (*x509.Certificate).Equal) {
			return nil
		}
	}
	return errors.New("response must contain an ordered chain without trust roots or unused certificates")
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
