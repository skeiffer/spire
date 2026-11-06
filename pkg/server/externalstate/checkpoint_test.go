package externalstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/stretchr/testify/require"
)

func TestIndependentCheckpointRejectsMetadataRollbackAndLoss(t *testing.T) {
	for _, name := range []string{"rollback", "loss"} {
		t.Run(name, func(t *testing.T) {
			control, data, configs := provisionFixture(t)
			owner, err := Open(control, data, "example.org", configs)
			require.NoError(t, err)
			path := filepath.Join(owner.StateDir(), "authorities.json")
			require.NoError(t, owner.WriteJSON(path, map[string]int{"history": 1}))
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, owner.WriteJSON(path, map[string]int{"history": 2}))
			require.NoError(t, owner.Close())
			if name == "rollback" {
				require.NoError(t, diskutil.AtomicWritePrivateFile(path, before))
			} else {
				require.NoError(t, os.Remove(path))
			}
			_, err = Open(control, data, "example.org", configs)
			require.ErrorContains(t, err, "rollback or unprovable restore")
		})
	}
}

func TestIndependentCheckpointReconcilesPendingAtomicReplacement(t *testing.T) {
	for _, committed := range []bool{false, true} {
		name := "before-data-write"
		if committed {
			name = "after-data-write"
		}
		t.Run(name, func(t *testing.T) {
			control, data, configs := provisionFixture(t)
			owner, err := Open(control, data, "example.org", configs)
			require.NoError(t, err)
			path := filepath.Join(owner.StateDir(), "authorities.json")
			require.NoError(t, owner.WriteJSON(path, map[string]int{"history": 1}))
			var pending checkpoint
			require.NoError(t, ReadJSON(filepath.Join(control, "checkpoint.json"), &pending))
			record := pending.Files["authorities.json"]
			oldDigest := record.Digest
			next, err := json.Marshal(map[string]int{"history": 2})
			require.NoError(t, err)
			sum := sha256.Sum256(next)
			record.Pending = hex.EncodeToString(sum[:])
			pending.Files["authorities.json"] = record
			require.NoError(t, WriteJSON(filepath.Join(control, "checkpoint.json"), pending))
			if committed {
				require.NoError(t, diskutil.AtomicWritePrivateFile(path, next))
			}
			require.NoError(t, owner.Close())
			restarted, err := Open(control, data, "example.org", configs)
			require.NoError(t, err)
			defer restarted.Close()
			var recovered checkpoint
			require.NoError(t, ReadJSON(filepath.Join(control, "checkpoint.json"), &recovered))
			got := recovered.Files["authorities.json"]
			require.Empty(t, got.Pending)
			if committed {
				require.Equal(t, hex.EncodeToString(sum[:]), got.Digest)
			} else {
				require.Equal(t, oldDigest, got.Digest)
			}
		})
	}
}

func TestMissingMarkerCannotEraseSurvivingIndependentEvidence(t *testing.T) {
	control, data, configs := provisionFixture(t)
	owner, err := Open(control, data, "example.org", configs)
	require.NoError(t, err)
	path := filepath.Join(owner.StateDir(), "authorities.json")
	require.NoError(t, owner.WriteJSON(path, map[string]int{"history": 1}))
	checkpointPath := filepath.Join(control, "checkpoint.json")
	before, err := os.ReadFile(checkpointPath)
	require.NoError(t, err)
	require.NoError(t, owner.Close())
	require.NoError(t, os.Remove(filepath.Join(control, "established.json")))
	require.NoError(t, os.Remove(filepath.Join(owner.StateDir(), "owner.json")))
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Remove(owner.StateDir()))
	_, err = Open(control, data, "example.org", configs)
	require.ErrorContains(t, err, "independent checkpoint exists")
	after, err := os.ReadFile(checkpointPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestOwnerRejectsWritesOutsidePublicMetadata(t *testing.T) {
	control, data, configs := provisionFixture(t)
	owner, err := Open(control, data, "example.org", configs)
	require.NoError(t, err)
	defer owner.Close()
	require.Error(t, owner.WriteJSON(filepath.Join(owner.StateDir(), "private-key.json"), map[string]int{"x": 1}))
	require.Error(t, owner.WriteJSON(filepath.Join(control, "authorities.json"), map[string]int{"x": 1}))
}
