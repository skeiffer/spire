package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	"github.com/spiffe/spire/pkg/common/health"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/plugin/x509svidissuer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	backdate = 10 * time.Second
)

// ServerCA is an interface for Server CAs
type ServerCA interface {
	SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error)
	SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error)
	SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error)
	SignWorkloadWITSVID(ctx context.Context, params WorkloadWITSVIDParams) (string, error)
	TaintedAuthorities() <-chan []*x509.Certificate
	IsJWTSVIDsDisabled() bool
	IsWITSVIDsDisabled() bool
}

// DownstreamX509CAParams are parameters relevant to downstream X.509 CA creation
type DownstreamX509CAParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration
}

// ServerX509SVIDParams are parameters relevant to server X509-SVID creation
type ServerX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// ProofCSR is the original DER-encoded PKCS#10 proof CSR. The built-in
	// issuer ignores this field to preserve existing behavior.
	ProofCSR []byte
}

// AgentX509SVIDParams are parameters relevant to agent X509-SVID creation
type AgentX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the agent
	SPIFFEID spiffeid.ID

	// ProofCSR is the original DER-encoded PKCS#10 proof CSR. The built-in
	// issuer ignores this field to preserve existing behavior.
	ProofCSR []byte
}

// WorkloadX509SVIDParams are parameters relevant to workload X509-SVID creation
type WorkloadX509SVIDParams struct {
	// Public Key
	PublicKey crypto.PublicKey

	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// DNSNames is used to add DNS SAN's to the X509 SVID. The first entry
	// is also added as the CN.
	DNSNames []string

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the certificate will be capped to that of the signing cert.
	TTL time.Duration

	// Subject of the SVID. Default subject is used if it is empty.
	Subject pkix.Name

	// ProofCSR is the original DER-encoded PKCS#10 proof CSR. The built-in
	// issuer ignores this field to preserve existing behavior.
	ProofCSR []byte
}

// WorkloadJWTSVIDParams are parameters relevant to workload JWT-SVID creation
type WorkloadJWTSVIDParams struct {
	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the token will be capped to that of the signing key.
	TTL time.Duration

	// Audience is used for audience claims
	Audience []string

	// IncludeJTI, when true, instructs the CA to include a unique "jti" (JWT ID)
	// claim in the issued token.
	IncludeJTI bool
}

// WorkloadWITSVIDParams are parameters relevant to workload WIT-SVID creation
type WorkloadWITSVIDParams struct {
	// SPIFFE ID of the SVID
	SPIFFEID spiffeid.ID

	// TTL is the desired time-to-live of the SVID. Regardless of the TTL, the
	// lifetime of the token will be capped to that of the signing key.
	TTL time.Duration

	// PublicKey is used for the cnf claim
	PublicKey jose.JSONWebKey
}

type X509CA struct {
	// Signer is used to sign child certificates.
	Signer crypto.Signer

	// Certificate is the CA certificate.
	Certificate *x509.Certificate

	// UpstreamChain contains the CA certificate and intermediates necessary to
	// chain back to the upstream trust bundle. It is only set if the CA is
	// signed by an UpstreamCA.
	UpstreamChain []*x509.Certificate
}

type JWTKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the JWT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the JWT key.
	NotAfter time.Time
}

type WITKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the WIT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the WIT key.
	NotAfter time.Time
}

type Config struct {
	Log             logrus.FieldLogger
	Clock           clock.Clock
	Metrics         telemetry.Metrics
	TrustDomain     spiffeid.TrustDomain
	CredBuilder     *credtemplate.Builder
	CredValidator   *credvalidator.Validator
	HealthChecker   health.Checker
	DisableJWTSVIDs bool
	DisableWITSVIDs bool
	ExternalIssuer  x509svidissuer.X509SVIDIssuer
}

type CA struct {
	c Config

	mu                   sync.RWMutex
	x509CA               *X509CA
	x509CAChain          []*x509.Certificate
	jwtKey               *JWTKey
	witKey               *WITKey
	taintedAuthoritiesCh chan []*x509.Certificate
	externalAuthorities  *x509svidissuer.AuthorityStore
}

func NewCA(config Config) *CA {
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	ca := &CA{
		c: config,

		// Notify caller about any tainted authority
		taintedAuthoritiesCh: make(chan []*x509.Certificate, 1),
		externalAuthorities:  x509svidissuer.NewAuthorityStore(time.Minute),
	}

	_ = config.HealthChecker.AddCheck("server.ca", &caHealth{
		ca: ca,
		td: config.TrustDomain,
	})

	return ca
}

func (ca *CA) InitializeExternalIssuer(ctx context.Context) error {
	if ca.c.ExternalIssuer == nil {
		return nil
	}
	stream, err := ca.c.ExternalIssuer.SubscribeAuthoritySnapshots(ctx)
	if err != nil {
		return fmt.Errorf("subscribe external issuer authorities: %w", err)
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive external issuer authority: %w", err)
	}
	snapshot, err := x509svidissuer.SnapshotFromProto(first)
	if err != nil {
		return fmt.Errorf("validate external issuer authority: %w", err)
	}
	if err := ca.externalAuthorities.Publish(snapshot); err != nil {
		return err
	}
	if err := ca.externalAuthorities.Activate(snapshot.Version, ca.c.Clock.Now()); err != nil {
		return err
	}
	go ca.consumeAuthoritySnapshots(ctx, stream)
	return nil
}

func (ca *CA) consumeAuthoritySnapshots(ctx context.Context, stream x509svidissuer.AuthoritySnapshotStream) {
	for {
		next, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				version := ca.externalAuthorities.ActiveVersion()
				ca.externalAuthorities.Taint(version, err)
				ca.c.Log.WithError(err).Error("External X509-SVID issuer authority stream closed")
			}
			return
		}
		snapshot, err := x509svidissuer.SnapshotFromProto(next)
		if err != nil {
			ca.externalAuthorities.Taint(ca.externalAuthorities.ActiveVersion(), err)
			ca.c.Log.WithError(err).Error("Rejected external X509-SVID issuer authority snapshot")
			continue
		}
		if err := ca.externalAuthorities.Publish(snapshot); err != nil {
			ca.externalAuthorities.Taint(ca.externalAuthorities.ActiveVersion(), err)
			ca.c.Log.WithError(err).Error("Rejected external X509-SVID issuer authority version")
		}
	}
}

func (ca *CA) X509CA() *X509CA {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.x509CA
}

func (ca *CA) SetX509CA(x509CA *X509CA) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.x509CA = x509CA
	switch {
	case x509CA == nil:
		ca.x509CAChain = nil
	case len(x509CA.UpstreamChain) > 0:
		ca.x509CAChain = x509CA.UpstreamChain
	default:
		ca.x509CAChain = []*x509.Certificate{x509CA.Certificate}
	}
}

func (ca *CA) JWTKey() *JWTKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.jwtKey
}

func (ca *CA) SetJWTKey(jwtKey *JWTKey) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.jwtKey = jwtKey
}

func (ca *CA) WITKey() *WITKey {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.witKey
}

func (ca *CA) SetWITKey(witKey *WITKey) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.witKey = witKey
}

func (ca *CA) NotifyTaintedX509Authorities(taintedAuthorities []*x509.Certificate) {
	select {
	case ca.taintedAuthoritiesCh <- taintedAuthorities:
	default:
	}
}

func (ca *CA) TaintedAuthorities() <-chan []*x509.Certificate {
	return ca.taintedAuthoritiesCh
}

func (ca *CA) SignDownstreamX509CA(ctx context.Context, params DownstreamX509CAParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildDownstreamX509CATemplate(ctx, credtemplate.DownstreamX509CAParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		TTL:         params.TTL,
	})
	if err != nil {
		return nil, err
	}

	downstreamCA, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("unable to create downstream X509 CA: %w", err)
	}

	if err := ca.c.CredValidator.ValidateX509CA(downstreamCA); err != nil {
		return nil, fmt.Errorf("invalid downstream X509 CA: %w", err)
	}

	telemetry_server.IncrServerCASignX509CACounter(ca.c.Metrics)

	return makeCertChain(x509CA, downstreamCA), nil
}

func (ca *CA) SignServerX509SVID(ctx context.Context, params ServerX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildServerX509SVIDTemplate(ctx, credtemplate.ServerX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(ctx, x509CA, template, params.ProofCSR, issuerv1.X509SVIDType_X509_SVID_TYPE_SERVER)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateServerX509SVID(svidChain[0]); err != nil {
		return nil, fmt.Errorf("invalid server X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignAgentX509SVID(ctx context.Context, params AgentX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildAgentX509SVIDTemplate(ctx, credtemplate.AgentX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(ctx, x509CA, template, params.ProofCSR, issuerv1.X509SVIDType_X509_SVID_TYPE_AGENT)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid agent X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadX509SVID(ctx context.Context, params WorkloadX509SVIDParams) ([]*x509.Certificate, error) {
	x509CA, caChain, err := ca.getX509CA()
	if err != nil {
		return nil, err
	}

	template, err := ca.c.CredBuilder.BuildWorkloadX509SVIDTemplate(ctx, credtemplate.WorkloadX509SVIDParams{
		ParentChain: caChain,
		PublicKey:   params.PublicKey,
		SPIFFEID:    params.SPIFFEID,
		DNSNames:    params.DNSNames,
		TTL:         params.TTL,
		Subject:     params.Subject,
	})
	if err != nil {
		return nil, err
	}

	svidChain, err := ca.signX509SVID(ctx, x509CA, template, params.ProofCSR, issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD)
	if err != nil {
		return nil, err
	}

	if err := ca.c.CredValidator.ValidateX509SVID(svidChain[0], params.SPIFFEID); err != nil {
		return nil, fmt.Errorf("invalid workload X509-SVID: %w", err)
	}

	return svidChain, nil
}

func (ca *CA) SignWorkloadJWTSVID(ctx context.Context, params WorkloadJWTSVIDParams) (string, error) {
	jwtKey := ca.JWTKey()
	if jwtKey == nil {
		return "", errors.New("JWT key is not available for signing")
	}

	claims, err := ca.c.CredBuilder.BuildWorkloadJWTSVIDClaims(ctx, credtemplate.WorkloadJWTSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		Audience:      params.Audience,
		TTL:           params.TTL,
		ExpirationCap: jwtKey.NotAfter,
		IncludeJTI:    params.IncludeJTI,
	})
	if err != nil {
		return "", err
	}

	token, err := ca.signJWTSVID(jwtKey, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT SVID: %w", err)
	}

	if err := ca.c.CredValidator.ValidateWorkloadJWTSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}

	telemetry_server.IncrServerCASignJWTSVIDCounter(ca.c.Metrics)
	return token, nil
}

func (ca *CA) SignWorkloadWITSVID(ctx context.Context, params WorkloadWITSVIDParams) (string, error) {
	witKey := ca.WITKey()
	if witKey == nil {
		return "", errors.New("WIT key is not available for signing")
	}

	// We already validate in other places that a valid algorithm is given
	if params.PublicKey.Algorithm == "" {
		return "", errors.New("public key must have algorithm set")
	}

	claims, err := ca.c.CredBuilder.BuildWorkloadWITSVIDClaims(ctx, credtemplate.WorkloadWITSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		PublicKey:     params.PublicKey,
		TTL:           params.TTL,
		ExpirationCap: witKey.NotAfter,
	})
	if err != nil {
		return "", err
	}

	token, err := ca.signWITSVID(witKey, claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT SVID: %w", err)
	}

	if err := ca.c.CredValidator.ValidateWorkloadWITSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}

	return token, nil
}

func (ca *CA) getX509CA() (*X509CA, []*x509.Certificate, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.x509CA == nil {
		return nil, nil, errors.New("X509 CA is not available for signing")
	}
	return ca.x509CA, ca.x509CAChain, nil
}

func (ca *CA) signX509SVID(ctx context.Context, x509CA *X509CA, template *x509.Certificate, proofCSR []byte, svidType issuerv1.X509SVIDType) ([]*x509.Certificate, error) {
	if ca.c.ExternalIssuer != nil {
		return ca.signExternalX509SVID(ctx, template, proofCSR, svidType)
	}
	x509SVID, err := x509util.CreateCertificate(template, x509CA.Certificate, template.PublicKey, x509CA.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to sign X509 SVID: %w", err)
	}
	telemetry_server.IncrServerCASignX509Counter(ca.c.Metrics)
	return makeCertChain(x509CA, x509SVID), nil
}

func (ca *CA) signExternalX509SVID(ctx context.Context, template *x509.Certificate, proofCSR []byte, svidType issuerv1.X509SVIDType) ([]*x509.Certificate, error) {
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
	snapshot, err := ca.externalAuthorities.Active()
	if err != nil {
		return nil, fmt.Errorf("external authority is not ready: %w", err)
	}
	subject, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("marshal profile subject: %w", err)
	}
	req := &issuerv1.IssueX509SVIDRequest{
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
		AuthorityVersion: snapshot.Version,
	}
	resp, err := ca.c.ExternalIssuer.IssueX509SVID(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("external X509-SVID issuance failed: %w", err)
	}
	if resp.GetAuthorityVersion() != snapshot.Version {
		return nil, errors.New("external issuer returned mismatched authority version")
	}
	leaf, err := x509.ParseCertificate(resp.GetLeafCertificate())
	if err != nil {
		return nil, errors.New("external issuer returned malformed leaf certificate")
	}
	chain := []*x509.Certificate{leaf}
	for _, raw := range resp.GetIntermediates() {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, errors.New("external issuer returned malformed intermediate certificate")
		}
		chain = append(chain, cert)
	}
	if err := validateExternalLeaf(template, leaf, chain[1:], snapshot.Roots); err != nil {
		return nil, fmt.Errorf("external issuer returned invalid X509-SVID: %w", err)
	}
	ca.externalAuthorities.MarkIssued(snapshot.Version, leaf.NotAfter)
	telemetry_server.IncrServerCASignX509Counter(ca.c.Metrics)
	return chain, nil
}

func (ca *CA) signJWTSVID(jwtKey *JWTKey, claims map[string]any) (string, error) {
	alg, err := cryptoutil.JoseAlgFromPublicKey(jwtKey.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine JWT key algorithm: %w", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(jwtKey.Signer),
				KeyID: jwtKey.Kid,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure JWT signer: %w", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT SVID: %w", err)
	}

	return signedToken, nil
}

func (ca *CA) IsJWTSVIDsDisabled() bool {
	return ca.c.DisableJWTSVIDs
}

func (ca *CA) IsWITSVIDsDisabled() bool {
	return ca.c.DisableWITSVIDs
}

func (ca *CA) signWITSVID(witKey *WITKey, claims map[string]any) (string, error) {
	alg, err := cryptoutil.JoseAlgFromPublicKey(witKey.Signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to determine WIT key algorithm: %w", err)
	}

	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(witKey.Signer),
				KeyID: witKey.Kid,
			},
		},
		new(jose.SignerOptions).WithType("wit+jwt"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to configure WIT signer: %w", err)
	}

	signedToken, err := jwt.Signed(jwtSigner).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign WIT SVID: %w", err)
	}

	return signedToken, nil
}

func makeCertChain(x509CA *X509CA, leaf *x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate{leaf}, x509CA.UpstreamChain...)
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
	for _, usage := range usages {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_SERVER_AUTH)
		case x509.ExtKeyUsageClientAuth:
			out = append(out, issuerv1.X509ExtendedKeyUsage_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH)
		}
	}
	return out
}

func toPluginExtensions(extensions []pkix.Extension) []*issuerv1.X509Extension {
	out := make([]*issuerv1.X509Extension, 0, len(extensions))
	for _, extension := range extensions {
		out = append(out, &issuerv1.X509Extension{
			Oid:      extension.Id.String(),
			Value:    append([]byte(nil), extension.Value...),
			Critical: extension.Critical,
		})
	}
	return out
}

func validateExternalLeaf(template, leaf *x509.Certificate, intermediates, roots []*x509.Certificate) error {
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
	if len(leaf.URIs) != len(template.URIs) || len(leaf.URIs) != 1 || leaf.URIs[0].String() != template.URIs[0].String() {
		return errors.New("SPIFFE ID mismatch")
	}
	if !slices.Equal(leaf.DNSNames, template.DNSNames) {
		return errors.New("DNS SAN mismatch")
	}
	if leaf.KeyUsage != template.KeyUsage || !slices.Equal(leaf.ExtKeyUsage, template.ExtKeyUsage) {
		return errors.New("certificate usage mismatch")
	}
	for _, expected := range template.ExtraExtensions {
		found := false
		for _, actual := range leaf.Extensions {
			if actual.Id.Equal(expected.Id) && actual.Critical == expected.Critical && bytes.Equal(actual.Value, expected.Value) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate extension %s mismatch", expected.Id)
		}
	}
	if leaf.NotBefore.Before(template.NotBefore.Add(-time.Second)) || leaf.NotAfter.After(template.NotAfter.Add(time.Second)) {
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
		Roots: rootPool, Intermediates: intermediatePool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("chain validation failed: %w", err)
	}
	return nil
}
