package x509svidissuer

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/common/health"
)

type Issuer interface {
	health.Checkable
	Issue(context.Context, *x509.Certificate, []byte, SVIDType) ([]*x509.Certificate, error)
}
