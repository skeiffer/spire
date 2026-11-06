package tokenauthority

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/spire/pkg/common/cryptoutil"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/credentialissuer"
	"github.com/spiffe/spire/pkg/server/credtemplate"
)

func (m *Manager) SignWorkloadJWTSVID(ctx context.Context, params credentialissuer.WorkloadJWTSVIDParams) (string, error) {
	if m.IsJWTSVIDsDisabled() {
		return "", errors.New("jwt-svids are disabled")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkState(); err != nil {
		return "", err
	}
	record, signer, err := m.signer(ctx, authorityJWT)
	if err != nil {
		return "", err
	}
	claims, err := m.c.Builder.BuildWorkloadJWTSVIDClaims(ctx, credtemplate.WorkloadJWTSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		Audience:      params.Audience,
		TTL:           params.TTL,
		ExpirationCap: record.NotAfter,
		IncludeJTI:    params.IncludeJTI,
	})
	if err != nil {
		return "", err
	}
	token, err := signToken(signer, record.KID, "JWT", claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign JWT-SVID: %w", err)
	}
	if err := m.c.Validator.ValidateWorkloadJWTSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}
	telemetry_server.IncrServerCASignJWTSVIDCounter(m.c.Metrics)
	return token, nil
}

func (m *Manager) SignWorkloadWITSVID(ctx context.Context, params credentialissuer.WorkloadWITSVIDParams) (string, error) {
	if m.IsWITSVIDsDisabled() {
		return "", errors.New("wit-svids are disabled")
	}
	if params.PublicKey.Algorithm == "" {
		return "", errors.New("public key must have algorithm set")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkState(); err != nil {
		return "", err
	}
	record, signer, err := m.signer(ctx, authorityWIT)
	if err != nil {
		return "", err
	}
	claims, err := m.c.Builder.BuildWorkloadWITSVIDClaims(ctx, credtemplate.WorkloadWITSVIDParams{
		SPIFFEID:      params.SPIFFEID,
		PublicKey:     params.PublicKey,
		TTL:           params.TTL,
		ExpirationCap: record.NotAfter,
	})
	if err != nil {
		return "", err
	}
	token, err := signToken(signer, record.KID, "wit+jwt", claims)
	if err != nil {
		return "", fmt.Errorf("unable to sign WIT-SVID: %w", err)
	}
	if err := m.c.Validator.ValidateWorkloadWITSVID(token, params.SPIFFEID); err != nil {
		return "", err
	}
	return token, nil
}

func (m *Manager) signer(ctx context.Context, kind authorityKind) (*keyRecord, crypto.Signer, error) {
	if err := m.reconcileAuthority(ctx, kind); err != nil {
		return nil, nil, err
	}
	authority := m.authority(kind)
	record := authority.find(authority.Current)
	if record == nil {
		return nil, nil, fmt.Errorf("%s key is not available for signing", kind)
	}
	key, err := m.c.KeyManager.GetKey(ctx, record.KeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("load active %s key: %w", kind, err)
	}
	if err := requirePublicKeyBinding(key, record.PublicKey); err != nil {
		return nil, nil, fmt.Errorf("active %s key binding mismatch: %w", kind, err)
	}
	return record, key, nil
}

func signToken(signer crypto.Signer, kid, tokenType string, claims map[string]any) (string, error) {
	algorithm, err := cryptoutil.JoseAlgFromPublicKey(signer.Public())
	if err != nil {
		return "", fmt.Errorf("determine signing algorithm: %w", err)
	}
	joseSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: algorithm,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(signer),
				KeyID: kid,
			},
		},
		new(jose.SignerOptions).WithType(jose.ContentType(tokenType)),
	)
	if err != nil {
		return "", fmt.Errorf("configure signer: %w", err)
	}
	token, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("serialize token: %w", err)
	}
	return token, nil
}
