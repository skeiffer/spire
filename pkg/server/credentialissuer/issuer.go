package credentialissuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type Issuer interface {
	SignDownstreamX509CA(context.Context, DownstreamX509CAParams) ([]*x509.Certificate, error)
	SignServerX509SVID(context.Context, ServerX509SVIDParams) ([]*x509.Certificate, error)
	SignAgentX509SVID(context.Context, AgentX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadX509SVID(context.Context, WorkloadX509SVIDParams) ([]*x509.Certificate, error)
	SignWorkloadJWTSVID(context.Context, WorkloadJWTSVIDParams) (string, error)
	SignWorkloadWITSVID(context.Context, WorkloadWITSVIDParams) (string, error)
	TaintedAuthorities() <-chan []*x509.Certificate
	IsJWTSVIDsDisabled() bool
	IsWITSVIDsDisabled() bool
}

type DownstreamX509CAParams struct {
	PublicKey crypto.PublicKey
	TTL       time.Duration
}

type ServerX509SVIDParams struct {
	PublicKey crypto.PublicKey
	ProofCSR  []byte
}

type AgentX509SVIDParams struct {
	PublicKey crypto.PublicKey
	SPIFFEID  spiffeid.ID
	ProofCSR  []byte
}

type WorkloadX509SVIDParams struct {
	PublicKey crypto.PublicKey
	SPIFFEID  spiffeid.ID
	DNSNames  []string
	TTL       time.Duration
	Subject   pkix.Name
	ProofCSR  []byte
}

type WorkloadJWTSVIDParams struct {
	SPIFFEID   spiffeid.ID
	TTL        time.Duration
	Audience   []string
	IncludeJTI bool
}

type WorkloadWITSVIDParams struct {
	SPIFFEID  spiffeid.ID
	TTL       time.Duration
	PublicKey jose.JSONWebKey
}
