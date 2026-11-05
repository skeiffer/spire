package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/health"
)

type caHealth struct {
	ca ServerCA
	td spiffeid.TrustDomain
}

func (h *caHealth) CheckHealth() health.State {
	// Prevent a problem with signing the SVID from blocking the health check
	// indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	ctx = health.CheckContext(ctx)

	spiffeID, err := spiffeid.FromPath(h.td, "/for/health/check/only")
	if err == nil {
		var signer *ecdsa.PrivateKey
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			var proofCSR []byte
			proofCSR, err = x509.CreateCertificateRequest(rand.Reader, new(x509.CertificateRequest), signer)
			if err == nil {
				_, err = h.ca.SignWorkloadX509SVID(ctx, WorkloadX509SVIDParams{
					SPIFFEID:  spiffeID,
					PublicKey: signer.Public(),
					ProofCSR:  proofCSR,
				})
			}
		}
	}

	// Both liveness and readiness are determined by whether the
	// x509 CA was successfully signed.
	ready := err == nil
	live := err == nil

	return health.State{
		Live:  live,
		Ready: ready,
		ReadyDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
		LiveDetails: caHealthDetails{
			SignX509SVIDErr: errString(err),
		},
	}
}

type caHealthDetails struct {
	SignX509SVIDErr string `json:"sign_x509_svid_err,omitempty"`
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
