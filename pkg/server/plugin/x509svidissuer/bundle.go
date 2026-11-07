package x509svidissuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"

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
		if _, err := ds.AppendBundle(ctx, bundle); err != nil {
			return err
		}
		published, err := ds.FetchBundle(ctx, trustDomainID)
		if err != nil {
			return err
		}
		if published == nil {
			return errors.New("external issuer bundle publication was not readable")
		}
		for _, root := range roots {
			found := false
			for _, actual := range published.RootCas {
				if bytes.Equal(root.Raw, actual.DerBytes) {
					found = true
					break
				}
			}
			if !found {
				return errors.New("external issuer bundle publication read-back was incomplete")
			}
		}
		return nil
	}
}
