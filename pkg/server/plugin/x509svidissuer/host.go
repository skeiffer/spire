package x509svidissuer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	issuerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/x509svidissuer/v1"
	"github.com/spiffe/spire/pkg/common/health"
)

type SVIDType = issuerv1.X509SVIDType

const (
	ServerSVID   = issuerv1.X509SVIDType_X509_SVID_TYPE_SERVER
	AgentSVID    = issuerv1.X509SVIDType_X509_SVID_TYPE_AGENT
	WorkloadSVID = issuerv1.X509SVIDType_X509_SVID_TYPE_WORKLOAD
)

type Issuer interface {
	Issue(context.Context, *x509.Certificate, []byte, SVIDType) ([]*x509.Certificate, error)
}

type PublishAuthoritiesFunc func(context.Context, []*x509.Certificate) error

type HostConfig struct {
	Plugin             X509SVIDIssuer
	PublishAuthorities PublishAuthoritiesFunc
	ClockSkew          time.Duration
	Now                func() time.Time
	OnError            func(error)
	HealthChecker      health.Checker
}

type Host struct {
	c     HostConfig
	store *AuthorityStore
}

func NewHost(config HostConfig) *Host {
	if config.ClockSkew == 0 {
		config.ClockSkew = time.Minute
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Host{
		c:     config,
		store: NewAuthorityStore(config.ClockSkew),
	}
}

func (h *Host) Initialize(ctx context.Context) error {
	if h.c.Plugin == nil {
		return errors.New("external X509-SVID issuer plugin is required")
	}
	if h.c.PublishAuthorities == nil {
		return errors.New("external X509-SVID authority publisher is required")
	}
	stream, err := h.c.Plugin.SubscribeAuthoritySnapshots(ctx)
	if err != nil {
		return fmt.Errorf("subscribe external issuer authorities: %w", err)
	}
	first, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive external issuer authority: %w", err)
	}
	if err := h.applySnapshot(ctx, first); err != nil {
		return err
	}
	if h.c.HealthChecker != nil {
		if err := h.c.HealthChecker.AddCheck("server.x509svidissuer", h); err != nil {
			return fmt.Errorf("register external issuer health check: %w", err)
		}
	}
	go h.consume(ctx, stream)
	return nil
}

func (h *Host) CheckHealth() health.State {
	_, err := h.active()
	var details any
	if err != nil {
		details = err.Error()
	}
	return health.State{
		Live:         true,
		Ready:        err == nil,
		ReadyDetails: details,
	}
}

func (h *Host) Issue(ctx context.Context, template *x509.Certificate, proofCSR []byte, svidType SVIDType) ([]*x509.Certificate, error) {
	snapshot, err := h.active()
	if err != nil {
		return nil, fmt.Errorf("external authority is not ready: %w", err)
	}
	req, err := BuildIssueRequest(template, proofCSR, svidType, snapshot.Version)
	if err != nil {
		return nil, err
	}
	resp, err := h.c.Plugin.IssueX509SVID(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("external X509-SVID issuance failed: %w", err)
	}
	chain, err := ParseAndValidateResponse(template, resp, snapshot)
	if err != nil {
		return nil, err
	}
	h.store.MarkIssued(snapshot.Version, chain[0].NotAfter)
	return chain, nil
}

func (h *Host) active() (Snapshot, error) {
	return h.store.Active()
}

func (h *Host) consume(ctx context.Context, stream AuthoritySnapshotStream) {
	for {
		next, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				h.taintActive(err)
			}
			return
		}
		if err := h.applySnapshot(ctx, next); err != nil {
			h.taintActive(err)
			return
		}
	}
}

func (h *Host) applySnapshot(ctx context.Context, in *issuerv1.AuthoritySnapshot) error {
	snapshot, err := SnapshotFromProto(in)
	if err != nil {
		return fmt.Errorf("validate external issuer authority: %w", err)
	}
	if err := h.store.Publish(snapshot); err != nil {
		return err
	}
	if err := h.store.Activate(snapshot.Version, h.c.Now()); err != nil {
		return err
	}
	if err := h.c.PublishAuthorities(ctx, h.store.BundleRoots(h.c.Now())); err != nil {
		h.store.Taint(snapshot.Version, err)
		return fmt.Errorf("publish external issuer authorities: %w", err)
	}
	return nil
}

func (h *Host) taintActive(err error) {
	h.store.Taint(h.store.ActiveVersion(), err)
	if h.c.OnError != nil {
		h.c.OnError(err)
	}
}
