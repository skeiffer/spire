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

func NewAuthorizedBundlePublisher(ds datastore.DataStore, trustDomainID string, retainedRoots [][]byte, knownRoot func([]byte) bool) PublishAuthoritiesFunc {
	publish := NewBundlePublisher(ds, trustDomainID)
	return func(ctx context.Context, roots []*x509.Certificate) error {
		current, err := ds.FetchBundle(ctx, trustDomainID)
		if err != nil {
			return err
		}
		if current != nil {
			for _, existing := range current.RootCas {
				authorized := knownRoot != nil && knownRoot(existing.DerBytes)
				for _, root := range roots {
					authorized = authorized || bytes.Equal(existing.DerBytes, root.Raw)
				}
				for _, raw := range retainedRoots {
					authorized = authorized || bytes.Equal(existing.DerBytes, raw)
				}
				if !authorized {
					return errors.New("shared bundle contains unexplained X509 trust; provision retained trust authorization or restore its ledger")
				}
			}
		}
		return publish(ctx, roots)
	}
}
