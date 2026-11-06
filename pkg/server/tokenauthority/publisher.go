package tokenauthority

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/spire/proto/spire/common"
)

func (m *Manager) PublishJWTKey(ctx context.Context, key *common.PublicKey) ([]*common.PublicKey, error) {
	return m.publishKey(ctx, authorityJWT, key)
}

func (m *Manager) PublishWITKey(ctx context.Context, key *common.PublicKey) ([]*common.PublicKey, error) {
	return m.publishKey(ctx, authorityWIT, key)
}

func (m *Manager) publishKey(ctx context.Context, kind authorityKind, key *common.PublicKey) ([]*common.PublicKey, error) {
	if err := validatePublishedKey(kind, key); err != nil {
		return nil, err
	}
	key = &common.PublicKey{
		PkixBytes:  append([]byte(nil), key.PkixBytes...),
		Kid:        key.Kid,
		NotAfter:   key.NotAfter,
		TaintedKey: key.TaintedKey,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.bundleKey(ctx, kind, key.Kid)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if err := validateExistingPublishedKey(kind, existing, key); err != nil {
			return nil, err
		}
		return m.bundleKeys(ctx, kind)
	}

	bundle := &common.Bundle{TrustDomainId: m.c.TrustDomain.IDString()}
	switch kind {
	case authorityJWT:
		bundle.JwtSigningKeys = []*common.PublicKey{key}
	case authorityWIT:
		bundle.WitSigningKeys = []*common.PublicKey{key}
	}
	if _, err := m.c.DataStore.AppendBundle(ctx, bundle); err != nil {
		return nil, fmt.Errorf("publish %s key: %w", kind, err)
	}

	published, err := m.bundleKey(ctx, kind, key.Kid)
	if err != nil {
		return nil, err
	}
	if published == nil {
		return nil, fmt.Errorf("%s key %q is missing after publication", kind, key.Kid)
	}
	if err := validateExistingPublishedKey(kind, published, key); err != nil {
		return nil, err
	}
	return m.bundleKeys(ctx, kind)
}

func (m *Manager) bundleKeys(ctx context.Context, kind authorityKind) ([]*common.PublicKey, error) {
	bundle, err := m.c.DataStore.FetchBundle(ctx, m.c.TrustDomain.IDString())
	if err != nil {
		return nil, fmt.Errorf("fetch trust domain bundle: %w", err)
	}
	if bundle == nil {
		return nil, errors.New("trust domain bundle is missing")
	}
	switch kind {
	case authorityJWT:
		return bundle.JwtSigningKeys, nil
	case authorityWIT:
		return bundle.WitSigningKeys, nil
	default:
		return nil, errors.New("unknown token authority kind")
	}
}

func validatePublishedKey(kind authorityKind, key *common.PublicKey) error {
	switch {
	case key == nil:
		return fmt.Errorf("%s key is required", kind)
	case key.Kid == "":
		return fmt.Errorf("%s key kid is required", kind)
	case len(key.PkixBytes) == 0:
		return fmt.Errorf("%s key public key is required", kind)
	case key.TaintedKey:
		return fmt.Errorf("%s key %q is tainted", kind, key.Kid)
	}
	if _, err := x509.ParsePKIXPublicKey(key.PkixBytes); err != nil {
		return fmt.Errorf("parse %s public key: %w", kind, err)
	}
	return nil
}

func validateExistingPublishedKey(kind authorityKind, existing, requested *common.PublicKey) error {
	switch {
	case existing.TaintedKey:
		return fmt.Errorf("%s key %q is already tainted", kind, existing.Kid)
	case !bytes.Equal(existing.PkixBytes, requested.PkixBytes):
		return fmt.Errorf("%s key %q has mismatched published key", kind, existing.Kid)
	case existing.NotAfter != requested.NotAfter:
		return fmt.Errorf("%s key %q has mismatched expiration", kind, existing.Kid)
	default:
		return nil
	}
}
