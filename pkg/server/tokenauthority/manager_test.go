package tokenauthority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/jwtsvid"
	"github.com/spiffe/spire/pkg/server/credentialissuer"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testKeyTTL = time.Hour

var (
	testTrustDomain = spiffeid.RequireTrustDomainFromString("example.org")
	testWorkloadID  = spiffeid.RequireFromPath(testTrustDomain, "/workload")
)

func TestManagerCreatesIndependentAuthoritiesAndSigns(t *testing.T) {
	test := newManagerTest(t, false, false)
	manager := test.newManager(true)

	jwtState := manager.GetCurrentJWTKeySlot()
	witState := manager.currentWITView()
	require.Equal(t, journal.Status_ACTIVE, jwtState.Status())
	require.Equal(t, journal.Status_ACTIVE, witState.Status())
	require.NotEqual(t, jwtState.AuthorityID(), witState.AuthorityID())

	jwtRecord := manager.state.JWT.find(jwtState.AuthorityID())
	witRecord := manager.state.WIT.find(witState.AuthorityID())
	require.NotNil(t, jwtRecord)
	require.NotNil(t, witRecord)
	require.NotEqual(t, jwtRecord.KeyID, witRecord.KeyID)
	require.NotEqual(t, jwtRecord.PublicKey, witRecord.PublicKey)

	jwtToken, err := manager.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
		SPIFFEID:   testWorkloadID,
		TTL:        10 * time.Minute,
		Audience:   []string{"audience"},
		IncludeJTI: true,
	})
	require.NoError(t, err)
	jwtClaims := parseClaims(t, jwtToken)
	require.Equal(t, testWorkloadID.String(), jwtClaims["sub"])
	require.Equal(t, []any{"audience"}, jwtClaims["aud"])
	require.NotEmpty(t, jwtClaims["jti"])
	require.Equal(t, jwtState.AuthorityID(), parseKID(t, jwtToken))

	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	witToken, err := manager.SignWorkloadWITSVID(context.Background(), credentialissuer.WorkloadWITSVIDParams{
		SPIFFEID: testWorkloadID,
		TTL:      10 * time.Minute,
		PublicKey: jose.JSONWebKey{
			Key:       workloadKey.Public(),
			KeyID:     "workload-key",
			Algorithm: string(jose.ES256),
		},
	})
	require.NoError(t, err)
	require.Equal(t, witState.AuthorityID(), parseKID(t, witToken))
	require.Equal(t, "wit+jwt", parseType(t, witToken))
}

func TestManagerDisabledModesCreateNoKeys(t *testing.T) {
	for _, tt := range []struct {
		name        string
		disableJWT  bool
		disableWIT  bool
		expectKeys  int
		jwtDisabled bool
		witDisabled bool
	}{
		{name: "jwt disabled", disableJWT: true, expectKeys: 1, jwtDisabled: true},
		{name: "wit disabled", disableWIT: true, expectKeys: 1, witDisabled: true},
		{name: "both disabled", disableJWT: true, disableWIT: true, expectKeys: 0, jwtDisabled: true, witDisabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := newManagerTest(t, tt.disableJWT, tt.disableWIT)
			manager := test.newManager(true)
			keys, err := test.keyManager.GetKeys(context.Background())
			require.NoError(t, err)
			require.Len(t, keys, tt.expectKeys)
			require.Equal(t, tt.jwtDisabled, manager.IsJWTSVIDsDisabled())
			require.Equal(t, tt.witDisabled, manager.IsWITSVIDsDisabled())
		})
	}
}

func TestManagerRestartEnablementChanges(t *testing.T) {
	t.Run("JWT off and on reuses healthy key", func(t *testing.T) {
		test := newManagerTest(t, false, true)
		enabled := test.newManager(true)
		kid := enabled.GetCurrentJWTKeySlot().AuthorityID()

		test.config.DisableJWTSVIDs = true
		disabled := test.newManager(false)
		require.True(t, disabled.IsJWTSVIDsDisabled())
		_, err := disabled.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
			SPIFFEID: testWorkloadID,
			Audience: []string{"audience"},
		})
		require.EqualError(t, err, "jwt-svids are disabled")

		test.config.DisableJWTSVIDs = false
		reEnabled := test.newManager(false)
		require.Equal(t, kid, reEnabled.GetCurrentJWTKeySlot().AuthorityID())
		require.Contains(t, keyIDs(test.fetchBundle().JwtSigningKeys), kid)
	})

	t.Run("WIT off and on reuses healthy key", func(t *testing.T) {
		test := newManagerTest(t, true, false)
		enabled := test.newManager(true)
		kid := enabled.currentWITView().AuthorityID()

		test.config.DisableWITSVIDs = true
		disabled := test.newManager(false)
		require.True(t, disabled.IsWITSVIDsDisabled())
		_, err := disabled.SignWorkloadWITSVID(context.Background(), credentialissuer.WorkloadWITSVIDParams{})
		require.EqualError(t, err, "wit-svids are disabled")

		test.config.DisableWITSVIDs = false
		reEnabled := test.newManager(false)
		require.Equal(t, kid, reEnabled.currentWITView().AuthorityID())
		require.Contains(t, keyIDs(test.fetchBundle().WitSigningKeys), kid)
	})

	t.Run("revoked JWT is replaced when re-enabled", func(t *testing.T) {
		test := newManagerTest(t, false, true)
		enabled := test.newManager(true)
		kid := enabled.GetCurrentJWTKeySlot().AuthorityID()

		test.config.DisableJWTSVIDs = true
		test.newManager(false)
		_, err := test.dataStore.TaintJWTKey(context.Background(), testTrustDomain.IDString(), kid)
		require.NoError(t, err)
		_, err = test.dataStore.RevokeJWTKey(context.Background(), testTrustDomain.IDString(), kid)
		require.NoError(t, err)

		test.config.DisableJWTSVIDs = false
		reEnabled := test.newManager(false)
		require.NotEqual(t, kid, reEnabled.GetCurrentJWTKeySlot().AuthorityID())
		require.NotContains(t, keyIDs(test.fetchBundle().JwtSigningKeys), kid)
	})
}

func TestManagerDisabledRestartDoesNotReplaceMissingPrivateKey(t *testing.T) {
	test := newManagerTest(t, false, true)
	enabled := test.newManager(true)
	old := enabled.state.JWT.find(enabled.GetCurrentJWTKeySlot().AuthorityID())
	require.NotNil(t, old)
	keysBefore, err := test.keyManager.GetKeys(context.Background())
	require.NoError(t, err)

	test.config.DisableJWTSVIDs = true
	test.config.KeyManager = &missingKeyManager{
		KeyManager: test.keyManager,
		missingID:  old.KeyID,
	}
	disabled := test.newManager(false)
	require.True(t, disabled.IsJWTSVIDsDisabled())
	keysAfter, err := test.keyManager.GetKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keysAfter, len(keysBefore))

	test.config.DisableJWTSVIDs = false
	reEnabled := test.newManager(false)
	require.NotEqual(t, old.KID, reEnabled.GetCurrentJWTKeySlot().AuthorityID())
	require.Contains(t, keyIDs(test.fetchBundle().JwtSigningKeys), old.KID)
}

func TestManagerKeyTypeChangeAppliesToFutureKeys(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	current := manager.state.JWT.find(manager.GetCurrentJWTKeySlot().AuthorityID())
	require.NotNil(t, current)
	currentPublic, err := x509.ParsePKIXPublicKey(current.PublicKey)
	require.NoError(t, err)
	require.Equal(t, elliptic.P256(), currentPublic.(*ecdsa.PublicKey).Curve)

	test.config.JWTKeyType = keymanager.ECP384
	restarted := test.newManager(false)
	require.Equal(t, current.KID, restarted.GetCurrentJWTKeySlot().AuthorityID())
	require.NoError(t, restarted.PrepareJWTKey(context.Background()))
	next := restarted.state.JWT.find(restarted.GetNextJWTKeySlot().AuthorityID())
	require.NotNil(t, next)
	nextPublic, err := x509.ParsePKIXPublicKey(next.PublicKey)
	require.NoError(t, err)
	require.Equal(t, elliptic.P384(), nextPublic.(*ecdsa.PublicKey).Curve)
	require.Contains(t, keyIDs(test.fetchBundle().JwtSigningKeys), current.KID)
}

func TestManagerCapsTokenExpiryAtAuthorityExpiry(t *testing.T) {
	test := newManagerTest(t, false, false)
	manager := test.newManager(true)

	token, err := manager.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
		SPIFFEID: testWorkloadID,
		TTL:      2 * testKeyTTL,
		Audience: []string{"audience"},
	})
	require.NoError(t, err)

	claims := parseClaims(t, token)
	require.Equal(t, float64(test.clock.Now().Add(testKeyTTL).Unix()), claims["exp"])
}

func TestManagerRestartPreservesAuthorities(t *testing.T) {
	test := newManagerTest(t, false, false)
	first := test.newManager(true)
	firstJWT := first.GetCurrentJWTKeySlot().AuthorityID()
	firstWIT := first.currentWITView().AuthorityID()

	restarted := test.newManager(false)
	require.Equal(t, firstJWT, restarted.GetCurrentJWTKeySlot().AuthorityID())
	require.Equal(t, firstWIT, restarted.currentWITView().AuthorityID())

	_, err := restarted.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
		SPIFFEID: testWorkloadID,
		Audience: []string{"audience"},
	})
	require.NoError(t, err)
}

func TestManagerAutomaticallyStagesAndRotatesJWTAndWIT(t *testing.T) {
	test := newManagerTest(t, false, false)
	manager := test.newManager(true)
	issuedAt := test.clock.Now()
	oldJWT := manager.GetCurrentJWTKeySlot().AuthorityID()
	oldWIT := manager.currentWITView().AuthorityID()

	test.clock.Set(issuedAt.Add(testKeyTTL/2 + time.Second))
	require.NoError(t, manager.rotate(context.Background()))
	require.Equal(t, journal.Status_PREPARED, manager.GetNextJWTKeySlot().Status())
	manager.mu.RLock()
	require.Equal(t, journal.Status_PREPARED, manager.state.WIT.view(manager.state.WIT.Next).Status())
	manager.mu.RUnlock()

	test.clock.Set(issuedAt.Add(testKeyTTL - testKeyTTL/6 + time.Second))
	require.NoError(t, manager.rotate(context.Background()))
	require.NotEqual(t, oldJWT, manager.GetCurrentJWTKeySlot().AuthorityID())
	require.NotEqual(t, oldWIT, manager.currentWITView().AuthorityID())
}

func TestManagerRecoversPendingIntent(t *testing.T) {
	test := newManagerTest(t, false, true)
	failingKM := &controllableKeyManager{KeyManager: test.keyManager}
	test.config.KeyManager = failingKM
	manager := test.newManager(true)

	failingKM.failNextGenerate(errors.New("generate failed"))
	require.EqualError(t, manager.PrepareJWTKey(context.Background()), "generate jwt key: generate failed")
	require.Empty(t, manager.GetNextJWTKeySlot().AuthorityID())

	restarted := test.newManager(false)
	require.Equal(t, journal.Status_PREPARED, restarted.GetNextJWTKeySlot().Status())
	require.NotEmpty(t, restarted.GetNextJWTKeySlot().AuthorityID())
}

func TestManagerRejectsRevokedKeyOnRestart(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	oldKID := manager.GetCurrentJWTKeySlot().AuthorityID()

	_, err := test.dataStore.TaintJWTKey(context.Background(), testTrustDomain.IDString(), oldKID)
	require.NoError(t, err)
	_, err = test.dataStore.RevokeJWTKey(context.Background(), testTrustDomain.IDString(), oldKID)
	require.NoError(t, err)

	restarted := test.newManager(false)
	require.NotEqual(t, oldKID, restarted.GetCurrentJWTKeySlot().AuthorityID())
	bundle := test.fetchBundle()
	require.NotContains(t, keyIDs(bundle.JwtSigningKeys), oldKID)
}

func TestManagerDoesNotSignWithTaintedKey(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	oldKID := manager.GetCurrentJWTKeySlot().AuthorityID()

	_, err := test.dataStore.TaintJWTKey(context.Background(), testTrustDomain.IDString(), oldKID)
	require.NoError(t, err)
	token, err := manager.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
		SPIFFEID: testWorkloadID,
		Audience: []string{"audience"},
	})
	require.NoError(t, err)
	require.NotEqual(t, oldKID, parseKID(t, token))

	bundle := test.fetchBundle()
	require.Contains(t, keyIDs(bundle.JwtSigningKeys), oldKID)
	for _, key := range bundle.JwtSigningKeys {
		if key.Kid == oldKID {
			require.True(t, key.TaintedKey)
		}
	}
}

func TestManagerReplacesMissingPrivateKey(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	old := manager.state.JWT.find(manager.GetCurrentJWTKeySlot().AuthorityID())
	require.NotNil(t, old)

	test.config.KeyManager = &missingKeyManager{
		KeyManager: test.keyManager,
		missingID:  old.KeyID,
	}
	restarted := test.newManager(false)
	require.NotEqual(t, old.KID, restarted.GetCurrentJWTKeySlot().AuthorityID())
	require.Contains(t, keyIDs(test.fetchBundle().JwtSigningKeys), old.KID)
}

func TestManagerRejectsUnattributableDedicatedNamespaceKeys(t *testing.T) {
	for _, tt := range []struct {
		name  string
		keyID string
	}{
		{name: "unknown CA role key", keyID: "x509-CA-A"},
		{name: "foreign token prefix", keyID: "token-authority-foreign-jwt-key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := newManagerTest(t, true, true)
			_, err := test.keyManager.GenerateKey(context.Background(), tt.keyID, keymanager.ECP256)
			require.NoError(t, err)

			_, err = NewManager(context.Background(), test.config)
			require.EqualError(t, err, `unprovable unknown token authority key "`+tt.keyID+`"`)
		})
	}
}

func TestManagerJWTAdminFailurePropagation(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	manager.writeFile = func(string, []byte) error {
		return errors.New("disk failed")
	}

	require.EqualError(t, manager.PrepareJWTKey(context.Background()), "persist jwt prepare intent: disk failed")
	require.Empty(t, manager.GetNextJWTKeySlot().AuthorityID())
}

func TestManagerFailedFinalCommitDoesNotExposeSigner(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	require.NoError(t, manager.PrepareJWTKey(context.Background()))
	oldKID := manager.GetCurrentJWTKeySlot().AuthorityID()
	nextKID := manager.GetNextJWTKeySlot().AuthorityID()

	var writes int
	manager.writeFile = func(path string, data []byte) error {
		writes++
		if err := diskutil.AtomicWritePrivateFile(path, data); err != nil {
			return err
		}
		if writes == 2 {
			return errors.New("uncertain rename")
		}
		return nil
	}
	require.EqualError(t, manager.RotateJWTKey(context.Background()), "commit jwt activation: uncertain rename")
	require.Equal(t, oldKID, manager.GetCurrentJWTKeySlot().AuthorityID())
	_, err := manager.SignWorkloadJWTSVID(context.Background(), credentialissuer.WorkloadJWTSVIDParams{
		SPIFFEID: testWorkloadID,
		Audience: []string{"audience"},
	})
	require.EqualError(t, err, "token authority metadata state is uncertain: uncertain rename")

	restarted := test.newManager(false)
	require.Equal(t, nextKID, restarted.GetCurrentJWTKeySlot().AuthorityID())
}

func TestManagerMetadataValidation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		content string
		fresh   bool
		err     string
	}{
		{name: "missing established metadata", err: "token authority metadata is missing"},
		{name: "unknown version", content: `{"version":99}`, fresh: true, err: "unsupported token authority metadata version 99"},
		{name: "corrupt", content: `{`, fresh: true, err: "decode token authority metadata:"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			test := newManagerTest(t, true, true)
			if tt.content != "" {
				require.NoError(t, os.WriteFile(filepath.Join(test.config.StateDir, metadataFileName), []byte(tt.content), 0o600))
			}
			_, err := NewManager(context.Background(), test.configWithFresh(tt.fresh))
			require.ErrorContains(t, err, tt.err)
		})
	}
}

func TestManagerRejectsUnsafeMetadataBeforeParsing(t *testing.T) {
	t.Run("ambiguous temporary file", func(t *testing.T) {
		test := newManagerTest(t, true, true)
		require.NoError(t, os.WriteFile(test.config.StateDir+string(filepath.Separator)+metadataFileName+".tmp", []byte(`{`), 0o600))

		_, err := NewManager(context.Background(), test.config)
		require.ErrorContains(t, err, "ambiguous pending state write")
		require.NotContains(t, err.Error(), "decode token authority metadata")
	})

	t.Run("symlink", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation requires additional privileges on windows")
		}
		test := newManagerTest(t, true, true)
		target := filepath.Join(test.config.StateDir, "target.json")
		require.NoError(t, os.WriteFile(target, []byte(`{`), 0o600))
		require.NoError(t, os.Symlink(target, filepath.Join(test.config.StateDir, metadataFileName)))

		_, err := NewManager(context.Background(), test.config)
		require.ErrorContains(t, err, "symlink")
		require.NotContains(t, err.Error(), "decode token authority metadata")
	})

	t.Run("unsafe permissions", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("posix permissions are not available on windows")
		}
		test := newManagerTest(t, true, true)
		test.newManager(true)
		path := filepath.Join(test.config.StateDir, metadataFileName)
		require.NoError(t, os.Chmod(path, 0o666))

		_, err := NewManager(context.Background(), test.configWithFresh(false))
		require.ErrorContains(t, err, "unsafe permissions")
		require.NotContains(t, err.Error(), "decode token authority metadata")
	})
}

func TestManagerRejectsAmbiguousWriteAndRemainsFailed(t *testing.T) {
	test := newManagerTest(t, false, true)
	manager := test.newManager(true)
	tmpPath := filepath.Join(test.config.StateDir, metadataFileName+".tmp")
	require.NoError(t, os.WriteFile(tmpPath, []byte(`{}`), 0o600))

	err := manager.PrepareJWTKey(context.Background())
	require.ErrorContains(t, err, "ambiguous pending state write")
	require.NoError(t, os.Remove(tmpPath))
	require.EqualError(t, manager.PrepareJWTKey(context.Background()), "token authority metadata state is uncertain: ambiguous pending state write")
}

func TestManagerCheckHealth(t *testing.T) {
	t.Run("enabled authorities ready", func(t *testing.T) {
		test := newManagerTest(t, false, false)
		manager := test.newManager(true)
		state := manager.CheckHealth()
		require.True(t, state.Live)
		require.True(t, state.Ready)
		require.Nil(t, state.ReadyDetails)
	})

	t.Run("disabled authorities ready", func(t *testing.T) {
		test := newManagerTest(t, true, true)
		manager := test.newManager(true)
		state := manager.CheckHealth()
		require.True(t, state.Live)
		require.True(t, state.Ready)
	})

	t.Run("expired authority not ready without mutation", func(t *testing.T) {
		test := newManagerTest(t, false, true)
		manager := test.newManager(true)
		before, err := marshalState(manager.state)
		require.NoError(t, err)
		keysBefore, err := test.keyManager.GetKeys(context.Background())
		require.NoError(t, err)
		bundleBefore := test.fetchBundle()

		test.clock.Add(testKeyTTL + time.Second)
		state := manager.CheckHealth()
		require.True(t, state.Live)
		require.False(t, state.Ready)
		require.NotNil(t, state.ReadyDetails)

		after, err := marshalState(manager.state)
		require.NoError(t, err)
		keysAfter, err := test.keyManager.GetKeys(context.Background())
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.Len(t, keysAfter, len(keysBefore))
		require.Equal(t, bundleBefore.SequenceNumber, test.fetchBundle().SequenceNumber)
	})

	t.Run("uncertain state not live or ready", func(t *testing.T) {
		test := newManagerTest(t, false, true)
		manager := test.newManager(true)
		manager.mu.Lock()
		manager.stateErr = errors.New("uncertain")
		manager.mu.Unlock()

		state := manager.CheckHealth()
		require.False(t, state.Live)
		require.False(t, state.Ready)
		require.NotNil(t, state.ReadyDetails)
	})
}

func TestManagerExternalX509AdminIsUnimplemented(t *testing.T) {
	test := newManagerTest(t, true, true)
	manager := test.newManager(true)
	ctx := context.Background()

	require.Equal(t, codes.Unimplemented, status.Code(manager.PrepareX509CA(ctx)))
	require.Equal(t, codes.Unimplemented, status.Code(manager.RotateX509CA(ctx)))
	require.Equal(t, codes.Unimplemented, status.Code(manager.NotifyTaintedX509Authority(ctx, "authority")))
	require.Empty(t, manager.GetCurrentX509CASlot().AuthorityID())
	require.Empty(t, manager.GetNextX509CASlot().AuthorityID())
	require.False(t, manager.IsUpstreamAuthority())
}

func TestManagerPublishesExternalTokenKeysAdditively(t *testing.T) {
	test := newManagerTest(t, true, true)
	manager := test.newManager(true)
	jwtExisting := newPublicKey(t, "jwt-existing")
	witExisting := newPublicKey(t, "wit-existing")
	_, err := test.dataStore.AppendBundle(context.Background(), &common.Bundle{
		TrustDomainId:  testTrustDomain.IDString(),
		RootCas:        []*common.Certificate{{DerBytes: []byte("root")}},
		JwtSigningKeys: []*common.PublicKey{jwtExisting},
		WitSigningKeys: []*common.PublicKey{witExisting},
	})
	require.NoError(t, err)
	_, err = test.dataStore.TaintJWTKey(context.Background(), testTrustDomain.IDString(), jwtExisting.Kid)
	require.NoError(t, err)

	jwtNew := newPublicKey(t, "jwt-new")
	jwtKeys, err := manager.PublishJWTKey(context.Background(), jwtNew)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"jwt-existing", "jwt-new"}, keyIDs(jwtKeys))

	witNew := newPublicKey(t, "wit-new")
	witKeys, err := manager.PublishWITKey(context.Background(), witNew)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"wit-existing", "wit-new"}, keyIDs(witKeys))

	bundle := test.fetchBundle()
	require.Equal(t, []byte("root"), bundle.RootCas[0].DerBytes)
	require.ElementsMatch(t, []string{"jwt-existing", "jwt-new"}, keyIDs(bundle.JwtSigningKeys))
	require.ElementsMatch(t, []string{"wit-existing", "wit-new"}, keyIDs(bundle.WitSigningKeys))
	for _, key := range bundle.JwtSigningKeys {
		if key.Kid == jwtExisting.Kid {
			require.True(t, key.TaintedKey)
		}
	}
}

func TestManagerPublisherDoesNotClearTaint(t *testing.T) {
	test := newManagerTest(t, true, true)
	manager := test.newManager(true)
	key := newPublicKey(t, "tainted")
	_, err := test.dataStore.AppendBundle(context.Background(), &common.Bundle{
		TrustDomainId:  testTrustDomain.IDString(),
		JwtSigningKeys: []*common.PublicKey{key},
	})
	require.NoError(t, err)
	_, err = test.dataStore.TaintJWTKey(context.Background(), testTrustDomain.IDString(), key.Kid)
	require.NoError(t, err)

	_, err = manager.PublishJWTKey(context.Background(), key)
	require.EqualError(t, err, `jwt key "tainted" is already tainted`)
	published, err := test.dataStore.FetchBundle(context.Background(), testTrustDomain.IDString())
	require.NoError(t, err)
	require.True(t, published.JwtSigningKeys[0].TaintedKey)
}

func TestManagerRunStopsOnCancellation(t *testing.T) {
	test := newManagerTest(t, false, false)
	manager := test.newManager(true)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- manager.Run(ctx)
	}()
	cancel()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.FailNow(t, "manager did not stop after cancellation")
	}
}

type managerTest struct {
	t          *testing.T
	clock      *clock.Mock
	dataStore  *fakedatastore.DataStore
	keyManager keymanager.KeyManager
	config     Config
}

func newManagerTest(t *testing.T, disableJWT, disableWIT bool) *managerTest {
	t.Helper()
	testClock := clock.NewMock(t)
	dataStore := fakedatastore.New(t)
	_, err := dataStore.CreateBundle(context.Background(), &common.Bundle{
		TrustDomainId: testTrustDomain.IDString(),
	})
	require.NoError(t, err)
	keyManager := fakeserverkeymanager.New(t)
	builder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain: testTrustDomain,
		Clock:       testClock,
		X509CATTL:   testKeyTTL,
		JWTSVIDTTL:  15 * time.Minute,
		WITSVIDTTL:  15 * time.Minute,
	})
	require.NoError(t, err)
	validator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: testTrustDomain,
		Clock:       testClock,
	})
	require.NoError(t, err)
	log, _ := test.NewNullLogger()
	return &managerTest{
		t:          t,
		clock:      testClock,
		dataStore:  dataStore,
		keyManager: keyManager,
		config: Config{
			KeyManager:      keyManager,
			DataStore:       dataStore,
			Builder:         builder,
			Validator:       validator,
			Metrics:         fakemetrics.New(),
			TrustDomain:     testTrustDomain,
			StateDir:        t.TempDir(),
			Binding:         "server-one",
			Fresh:           true,
			JWTKeyType:      keymanager.ECP256,
			WITKeyType:      keymanager.ECP256,
			DisableJWTSVIDs: disableJWT,
			DisableWITSVIDs: disableWIT,
			Clock:           testClock,
			Log:             log,
		},
	}
}

func (t *managerTest) newManager(fresh bool) *Manager {
	t.t.Helper()
	manager, err := NewManager(context.Background(), t.configWithFresh(fresh))
	require.NoError(t.t, err)
	return manager
}

func (t *managerTest) configWithFresh(fresh bool) Config {
	config := t.config
	config.Fresh = fresh
	return config
}

func (t *managerTest) fetchBundle() *common.Bundle {
	t.t.Helper()
	bundle, err := t.dataStore.FetchBundle(context.Background(), testTrustDomain.IDString())
	require.NoError(t.t, err)
	return bundle
}

func parseClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, jwtsvid.AllowedSignatureAlgorithms)
	require.NoError(t, err)
	claims := make(map[string]any)
	require.NoError(t, parsed.UnsafeClaimsWithoutVerification(&claims))
	return claims
}

func parseKID(t *testing.T, token string) string {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, jwtsvid.AllowedSignatureAlgorithms)
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)
	return parsed.Headers[0].KeyID
}

func parseType(t *testing.T, token string) string {
	t.Helper()
	parsed, err := jwt.ParseSigned(token, jwtsvid.AllowedSignatureAlgorithms)
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)
	return parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
}

func keyIDs(keys []*common.PublicKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.Kid)
	}
	return ids
}

func newPublicKey(t *testing.T, kid string) *common.PublicKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pkixBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	require.NoError(t, err)
	return &common.PublicKey{
		PkixBytes: pkixBytes,
		Kid:       kid,
		NotAfter:  time.Unix(2_000_000_000, 0).Unix(),
	}
}

type controllableKeyManager struct {
	keymanager.KeyManager

	mu              sync.Mutex
	nextGenerateErr error
}

func (m *controllableKeyManager) failNextGenerate(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextGenerateErr = err
}

func (m *controllableKeyManager) GenerateKey(ctx context.Context, id string, keyType keymanager.KeyType) (keymanager.Key, error) {
	m.mu.Lock()
	err := m.nextGenerateErr
	m.nextGenerateErr = nil
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return m.KeyManager.GenerateKey(ctx, id, keyType)
}

type missingKeyManager struct {
	keymanager.KeyManager
	missingID string
}

func (m *missingKeyManager) GetKey(ctx context.Context, id string) (keymanager.Key, error) {
	if id == m.missingID {
		return nil, status.Error(codes.NotFound, "key not found")
	}
	return m.KeyManager.GetKey(ctx, id)
}

func (m *missingKeyManager) GetKeys(ctx context.Context) ([]keymanager.Key, error) {
	keys, err := m.KeyManager.GetKeys(ctx)
	if err != nil {
		return nil, err
	}
	filtered := keys[:0]
	for _, key := range keys {
		if key.ID() != m.missingID {
			filtered = append(filtered, key)
		}
	}
	return filtered, nil
}
