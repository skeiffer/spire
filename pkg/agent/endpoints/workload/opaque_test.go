package workload

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/stretchr/testify/require"
)

func TestMarshalWorkloadPrivateKeyDeniesOpaqueRequiredSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opaque := workloadkeyprovider.NewKey(key, []byte("provider-reference"), 1)

	keyBytes, err := marshalWorkloadPrivateKey(opaque)
	require.EqualError(t, err, "opaque-required entry is unavailable through the standard Workload API")
	require.Nil(t, keyBytes)
}

func TestMarshalWorkloadPrivateKeyPreservesSoftwareKeyBehavior(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes, err := marshalWorkloadPrivateKey(key)
	require.NoError(t, err)
	require.NotEmpty(t, keyBytes)
}
