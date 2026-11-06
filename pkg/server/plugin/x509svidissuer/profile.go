package x509svidissuer

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
)

func capturedProfile(profile *issuerv1.X509SVIDProfile) (*x509.Certificate, error) {
	key, err := x509.ParsePKIXPublicKey(bytes.Clone(profile.PublicKey))
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(profile.SpiffeId)
	if err != nil {
		return nil, err
	}
	out := &x509.Certificate{
		PublicKey: key, RawSubject: bytes.Clone(profile.Subject),
		URIs: []*url.URL{uri}, DNSNames: slices.Clone(profile.DnsNames),
		NotBefore: profile.NotBefore.AsTime(), NotAfter: profile.NotAfter.AsTime(),
		BasicConstraintsValid: true,
	}
	for _, usage := range profile.KeyUsages {
		switch usage {
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_DIGITAL_SIGNATURE:
			out.KeyUsage |= x509.KeyUsageDigitalSignature
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_ENCIPHERMENT:
			out.KeyUsage |= x509.KeyUsageKeyEncipherment
		case issuerv1.X509KeyUsage_X509_KEY_USAGE_KEY_AGREEMENT:
			out.KeyUsage |= x509.KeyUsageKeyAgreement
		default:
			return nil, fmt.Errorf("unsupported captured key usage %d", usage)
		}
	}
	for _, usage := range profile.ExtendedKeyUsages {
		switch usage {
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH:
			out.ExtKeyUsage = append(out.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		case issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH:
			out.ExtKeyUsage = append(out.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
		default:
			return nil, fmt.Errorf("unsupported captured extended key usage %d", usage)
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
		out.ExtraExtensions = append(out.ExtraExtensions, pkix.Extension{
			Id: oid, Value: bytes.Clone(extension.Value), Critical: extension.Critical,
		})
	}
	return out, nil
}
