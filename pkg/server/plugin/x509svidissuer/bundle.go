package x509svidissuer

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

func NewBundlePublisher(ds datastore.DataStore, trustDomainID string) PublishAuthoritiesFunc {
	return func(ctx context.Context, roots []*x509.Certificate) error {
		bundle := &common.Bundle{
			TrustDomainId: trustDomainID,
			RootCas:       make([]*common.Certificate, 0, len(roots)),
		}
		for _, root := range roots {
			bundle.RootCas = append(bundle.RootCas, &common.Certificate{DerBytes: root.Raw})
		}
		_, err := ds.AppendBundle(ctx, bundle)
		return err
	}
}
