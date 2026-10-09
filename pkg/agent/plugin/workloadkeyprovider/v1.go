package workloadkeyprovider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"

	workloadkeyproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadkeyprovider/v1"
	"github.com/spiffe/spire/pkg/common/plugin"
)

type V1 struct {
	plugin.Facade
	workloadkeyproviderv1.WorkloadKeyProviderPluginClient
}

func (v *V1) GenerateKey(ctx context.Context, request GenerateRequest) (Key, error) {
	response, err := v.WorkloadKeyProviderPluginClient.GenerateKey(ctx, &workloadkeyproviderv1.GenerateKeyRequest{
		WorkloadId: request.WorkloadID,
		Generation: request.Generation,
		Algorithm:  workloadkeyproviderv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
	})
	if err != nil {
		return nil, v.WrapErr(err)
	}
	if response == nil || len(response.KeyReference) == 0 || len(response.PublicKey) == 0 ||
		response.Generation != request.Generation ||
		response.Algorithm != workloadkeyproviderv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048 ||
		response.OperationMode == workloadkeyproviderv1.KeyOperationMode_KEY_OPERATION_MODE_UNSPECIFIED {
		return nil, errors.New("WorkloadKeyProvider returned invalid key metadata")
	}
	mode, err := operationMode(response.OperationMode)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		return nil, errors.New("WorkloadKeyProvider returned an invalid public key")
	}
	if _, ok := publicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("WorkloadKeyProvider returned an unexpected public key type")
	}
	return NewKeyWithMode(&rpcSigner{
		ctx:        ctx,
		provider:   v,
		publicKey:  publicKey,
		reference:  append([]byte(nil), response.KeyReference...),
		generation: response.Generation,
	}, response.KeyReference, response.Generation, mode), nil
}

func operationMode(mode workloadkeyproviderv1.KeyOperationMode) (OperationMode, error) {
	switch mode {
	case workloadkeyproviderv1.KeyOperationMode_KEY_OPERATION_MODE_LOCAL_REFERENCE:
		return LocalReferenceMode, nil
	case workloadkeyproviderv1.KeyOperationMode_KEY_OPERATION_MODE_REMOTE_SIGN:
		return RemoteSignMode, nil
	default:
		return 0, errors.New("WorkloadKeyProvider returned an unsupported operation mode")
	}
}

func (v *V1) ReleaseKey(ctx context.Context, reference []byte, generation uint64) error {
	if len(reference) == 0 || generation == 0 {
		return errors.New("invalid workload key release")
	}
	_, err := v.WorkloadKeyProviderPluginClient.ReleaseKey(ctx, &workloadkeyproviderv1.ReleaseKeyRequest{
		KeyReference: append([]byte(nil), reference...),
		Generation:   generation,
	})
	if err != nil {
		return v.WrapErr(err)
	}
	return nil
}

type rpcSigner struct {
	ctx        context.Context
	provider   *V1
	publicKey  crypto.PublicKey
	reference  []byte
	generation uint64
}

func (s *rpcSigner) Public() crypto.PublicKey {
	return s.publicKey
}

func (s *rpcSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("only SHA-256 digests are accepted")
	}
	response, err := s.provider.WorkloadKeyProviderPluginClient.Sign(s.ctx, &workloadkeyproviderv1.SignRequest{
		KeyReference:    append([]byte(nil), s.reference...),
		Generation:      s.generation,
		Digest:          append([]byte(nil), digest...),
		HashAlgorithm:   workloadkeyproviderv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		SignatureScheme: workloadkeyproviderv1.SignatureScheme_SIGNATURE_SCHEME_RSA_PKCS1V15,
	})
	if err != nil {
		return nil, s.provider.WrapErr(err)
	}
	if response == nil || len(response.Signature) == 0 {
		return nil, errors.New("WorkloadKeyProvider returned an empty signature")
	}
	return append([]byte(nil), response.Signature...), nil
}

var _ crypto.Signer = (*rpcSigner)(nil)
