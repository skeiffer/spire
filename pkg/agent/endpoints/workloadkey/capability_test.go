package workloadkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/stretchr/testify/require"
)

func TestCapabilityRequiresReauthorizationAndDiesOnRestart(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opaque := workloadkeyprovider.NewKey(key, []byte("provider-reference"), 3)
	now := time.Now()
	store := NewCapabilityStore()
	capability, err := store.Issue(Binding{
		WorkloadID: "spiffe://example.org/workload",
		ProcessID:  101,
	}, opaque, now.Add(time.Minute))
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("reauthorized-sign"))
	signature, err := store.Sign(capability.ID, Binding{
		WorkloadID: "spiffe://example.org/workload",
		ProcessID:  101,
	}, 3, digest[:], now)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))

	_, err = store.Sign(capability.ID, Binding{
		WorkloadID: "spiffe://example.org/workload",
		ProcessID:  202,
	}, 3, digest[:], now)
	require.ErrorIs(t, err, ErrUnauthorizedCapability)

	restarted := NewCapabilityStore()
	_, err = restarted.Sign(capability.ID, Binding{
		WorkloadID: "spiffe://example.org/workload",
		ProcessID:  101,
	}, 3, digest[:], now)
	require.ErrorIs(t, err, ErrInvalidCapability)
}

func TestRotationInvalidatesPreviousGeneration(t *testing.T) {
	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	nextKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	binding := Binding{WorkloadID: "spiffe://example.org/workload", ProcessID: 101}
	store := NewCapabilityStore()
	first, err := store.Issue(binding, workloadkeyprovider.NewKey(firstKey, []byte("one"), 1), time.Now().Add(time.Minute))
	require.NoError(t, err)
	next, err := store.Issue(binding, workloadkeyprovider.NewKey(nextKey, []byte("two"), 2), time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.NotEqual(t, first.ID, next.ID)

	digest := sha256.Sum256([]byte("rotation"))
	_, err = store.Sign(first.ID, binding, 1, digest[:], time.Now())
	require.ErrorIs(t, err, ErrInvalidCapability)
	_, err = store.Sign(next.ID, binding, 2, digest[:], time.Now())
	require.NoError(t, err)
}
