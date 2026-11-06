package x509svidissuer

import (
	"context"
	"crypto/x509"
)

type Issuer interface {
	Issue(context.Context, *x509.Certificate, []byte, SVIDType) ([]*x509.Certificate, error)
}
