package workloadkeyprovider

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	workloadkeyproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadkeyprovider/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestV1GenerateSignAndRelease(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	client := &fakePluginClient{
		generateResponse: &workloadkeyproviderv1.GenerateKeyResponse{
			KeyReference:  []byte("reference"),
			PublicKey:     publicKey,
			Generation:    7,
			Algorithm:     workloadkeyproviderv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
			OperationMode: workloadkeyproviderv1.KeyOperationMode_KEY_OPERATION_MODE_LOCAL_REFERENCE,
		},
		privateKey: privateKey,
	}
	facade := &V1{}
	facade.WorkloadKeyProviderPluginClient.WorkloadKeyProviderClient = client

	key, err := facade.GenerateKey(context.Background(), GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 7,
	})
	require.NoError(t, err)
	require.Equal(t, LocalReferenceMode, key.OperationMode())
	digest := sha256.Sum256([]byte("facade"))
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature))
	require.NoError(t, facade.ReleaseKey(context.Background(), key.Reference(), key.Generation()))
	require.Equal(t, 1, client.releaseCalls)
}

func TestV1RejectsUnspecifiedOperationMode(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	facade := &V1{}
	facade.WorkloadKeyProviderPluginClient.WorkloadKeyProviderClient = &fakePluginClient{
		generateResponse: &workloadkeyproviderv1.GenerateKeyResponse{
			KeyReference: []byte("reference"),
			PublicKey:    publicKey,
			Generation:   1,
			Algorithm:    workloadkeyproviderv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		},
	}

	_, err = facade.GenerateKey(context.Background(), GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 1,
	})
	require.Error(t, err)
}

func TestV1RejectsMalformedGenerateResponse(t *testing.T) {
	facade := &V1{}
	facade.WorkloadKeyProviderPluginClient.WorkloadKeyProviderClient = &fakePluginClient{
		generateResponse: &workloadkeyproviderv1.GenerateKeyResponse{Generation: 1},
	}
	_, err := facade.GenerateKey(context.Background(), GenerateRequest{
		WorkloadID: "spiffe://example.org/workload",
		Generation: 1,
	})
	require.Error(t, err)
}

type fakePluginClient struct {
	generateResponse *workloadkeyproviderv1.GenerateKeyResponse
	privateKey       *rsa.PrivateKey
	releaseCalls     int
}

func (c *fakePluginClient) GenerateKey(context.Context, *workloadkeyproviderv1.GenerateKeyRequest, ...grpc.CallOption) (*workloadkeyproviderv1.GenerateKeyResponse, error) {
	return c.generateResponse, nil
}

func (c *fakePluginClient) Sign(_ context.Context, request *workloadkeyproviderv1.SignRequest, _ ...grpc.CallOption) (*workloadkeyproviderv1.SignResponse, error) {
	signature, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, request.Digest)
	return &workloadkeyproviderv1.SignResponse{Signature: signature}, err
}

func (c *fakePluginClient) ReleaseKey(context.Context, *workloadkeyproviderv1.ReleaseKeyRequest, ...grpc.CallOption) (*workloadkeyproviderv1.ReleaseKeyResponse, error) {
	c.releaseCalls++
	return new(workloadkeyproviderv1.ReleaseKeyResponse), nil
}
