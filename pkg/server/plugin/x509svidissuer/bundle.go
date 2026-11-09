package x509svidissuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
)

func NewBundlePublisher(ds datastore.DataStore, trustDomainID string, publish PublishAuthoritiesFunc) PublishAuthoritiesFunc {
	return func(ctx context.Context, roots []*x509.Certificate) error {
		if err := publish(ctx, roots); err != nil {
			return err
		}
		bundle, err := ds.FetchBundle(ctx, trustDomainID)
		if err != nil {
			return err
		}
		if bundle == nil {
			return errors.New("external authority publication read-back returned no bundle")
		}
		for _, root := range roots {
			if !slices.ContainsFunc(bundle.RootCas, func(cert *common.Certificate) bool {
				return cert != nil && bytes.Equal(cert.DerBytes, root.Raw)
			}) {
				return errors.New("external authority publication read-back is missing a root")
			}
		}
		return nil
	}
}
