package credentialissuer

import (
	"context"
	"crypto/x509"
	"slices"

	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetryserver "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/plugin/x509svidissuer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type External struct {
	TokenIssuer
	Builder   *credtemplate.Builder
	Validator *credvalidator.Validator
	Leaf      x509svidissuer.Issuer
	Metrics   telemetry.Metrics
}

func (*External) RequiresProofCSR() bool { return true }

func (*External) TaintedAuthorities() <-chan []*x509.Certificate { return nil }

func (*External) SignDownstreamX509CA(context.Context, DownstreamX509CAParams) ([]*x509.Certificate, error) {
	return nil, status.Error(codes.Unimplemented, "downstream X509 CA issuance is unavailable with X509SVIDIssuer")
}

func (e *External) SignServerX509SVID(ctx context.Context, p ServerX509SVIDParams) ([]*x509.Certificate, error) {
	template, err := e.Builder.BuildServerX509SVIDTemplate(ctx, credtemplate.ServerX509SVIDParams{
		PublicKey: p.PublicKey, ParentIndependent: true,
	})
	if err != nil {
		return nil, err
	}
	chain, err := e.Leaf.Issue(ctx, template, slices.Clone(p.ProofCSR), x509svidissuer.ServerSVID)
	if err != nil {
		return nil, err
	}
	if err := e.Validator.ValidateServerX509SVID(chain[0]); err != nil {
		return nil, err
	}
	telemetryserver.IncrServerCASignX509Counter(e.Metrics)
	return chain, nil
}

func (e *External) SignAgentX509SVID(ctx context.Context, p AgentX509SVIDParams) ([]*x509.Certificate, error) {
	template, err := e.Builder.BuildAgentX509SVIDTemplate(ctx, credtemplate.AgentX509SVIDParams{
		PublicKey: p.PublicKey, SPIFFEID: p.SPIFFEID, ParentIndependent: true,
	})
	if err != nil {
		return nil, err
	}
	chain, err := e.Leaf.Issue(ctx, template, slices.Clone(p.ProofCSR), x509svidissuer.AgentSVID)
	if err != nil {
		return nil, err
	}
	if err := e.Validator.ValidateX509SVID(chain[0], p.SPIFFEID); err != nil {
		return nil, err
	}
	telemetryserver.IncrServerCASignX509Counter(e.Metrics)
	return chain, nil
}

func (e *External) SignWorkloadX509SVID(ctx context.Context, p WorkloadX509SVIDParams) ([]*x509.Certificate, error) {
	template, err := e.Builder.BuildWorkloadX509SVIDTemplate(ctx, credtemplate.WorkloadX509SVIDParams{
		PublicKey: p.PublicKey, SPIFFEID: p.SPIFFEID, DNSNames: slices.Clone(p.DNSNames),
		TTL: p.TTL, Subject: p.Subject, ParentIndependent: true,
	})
	if err != nil {
		return nil, err
	}
	chain, err := e.Leaf.Issue(ctx, template, slices.Clone(p.ProofCSR), x509svidissuer.WorkloadSVID)
	if err != nil {
		return nil, err
	}
	if err := e.Validator.ValidateX509SVID(chain[0], p.SPIFFEID); err != nil {
		return nil, err
	}
	telemetryserver.IncrServerCASignX509Counter(e.Metrics)
	return chain, nil
}
