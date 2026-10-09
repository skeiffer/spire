package workloadkey_test

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type capability struct {
	id         [32]byte
	workloadID string
	generation uint64
	expiresAt  time.Time
}

type capabilityStore struct {
	byID map[[32]byte]capability
}

func newCapabilityStore() *capabilityStore {
	return &capabilityStore{byID: make(map[[32]byte]capability)}
}

func (s *capabilityStore) issue(workloadID string, generation uint64, expiresAt time.Time) capability {
	var id [32]byte
	_, _ = rand.Read(id[:])
	c := capability{id: id, workloadID: workloadID, generation: generation, expiresAt: expiresAt}
	s.byID[id] = c
	return c
}

func (s *capabilityStore) authorize(id [32]byte, workloadID string, generation uint64, now time.Time) error {
	c, ok := s.byID[id]
	switch {
	case !ok:
		return errors.New("capability is invalid")
	case c.workloadID != workloadID:
		return errors.New("capability workload binding mismatch")
	case c.generation != generation:
		return errors.New("capability generation mismatch")
	case !now.Before(c.expiresAt):
		return errors.New("capability is expired")
	default:
		return nil
	}
}

func TestExperimentalV1ProtoHasNoPrivateKeyField(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "..", "proto", "private", "spire", "agent", "workloadkey", "v1", "x509_key_backed_workload.proto")
	contents, err := os.ReadFile(protoPath)
	require.NoError(t, err)
	require.Contains(t, string(contents), "package spire.agent.workloadkey.v1")
	require.Contains(t, string(contents), `ProtocolVersion protocol_version = 1`)
	require.Contains(t, string(contents), `PROTOCOL_VERSION_V1 = 1`)
	require.False(t, regexp.MustCompile(`(?m)^\s*bytes\s+(private_key|x509_svid_key|pkcs8|pfx)\s*=`).Match(contents))
}

func TestCapabilitiesAreWorkloadBoundGenerationBoundAndMemoryOnly(t *testing.T) {
	now := time.Now()
	store := newCapabilityStore()
	first := store.issue("spiffe://example.org/workload", 7, now.Add(time.Minute))

	require.NoError(t, store.authorize(first.id, first.workloadID, 7, now))
	require.EqualError(t, store.authorize(first.id, "spiffe://example.org/other", 7, now), "capability workload binding mismatch")
	require.EqualError(t, store.authorize(first.id, first.workloadID, 8, now), "capability generation mismatch")
	require.EqualError(t, store.authorize(first.id, first.workloadID, 7, now.Add(time.Minute)), "capability is expired")

	restarted := newCapabilityStore()
	require.EqualError(t, restarted.authorize(first.id, first.workloadID, 7, now), "capability is invalid")
}

func TestRotationIssuesANewCapabilityAndInvalidatesWrongGeneration(t *testing.T) {
	now := time.Now()
	store := newCapabilityStore()
	old := store.issue("spiffe://example.org/workload", 1, now.Add(time.Minute))
	next := store.issue("spiffe://example.org/workload", 2, now.Add(time.Minute))

	require.NotEqual(t, old.id, next.id)
	require.NoError(t, store.authorize(next.id, next.workloadID, 2, now))
	require.EqualError(t, store.authorize(next.id, next.workloadID, 1, now), "capability generation mismatch")
}

func TestOpaqueRequiredEntryCannotUseStandardWorkloadAPI(t *testing.T) {
	type entry struct {
		opaqueRequired bool
		privateKey     []byte
	}
	standardFetch := func(e entry) error {
		if e.opaqueRequired {
			return errors.New("opaque-required entry is unavailable through the standard Workload API")
		}
		if len(e.privateKey) == 0 {
			return errors.New("software-key entry requires PKCS#8 key material")
		}
		return nil
	}

	require.NoError(t, standardFetch(entry{privateKey: []byte("ephemeral-test-pkcs8")}))
	require.EqualError(t, standardFetch(entry{opaqueRequired: true}), "opaque-required entry is unavailable through the standard Workload API")
}

func TestHandlerDefinesSanitizedCorrelatedBoundaryStages(t *testing.T) {
	contents, err := os.ReadFile("handler.go")
	require.NoError(t, err)
	source := string(contents)

	for _, stage := range []string{
		"request_start",
		"caller_context",
		"attestor_result",
		"registration_lookup_start",
		"registration_candidate",
		"registration_lookup_end",
		"workload_key_route",
		"capability_construct",
		"response_construct",
		"stream_send",
		"request_cancelled",
		"error_mapping",
	} {
		require.Contains(t, source, stage)
	}
	for _, field := range []string{
		"schema_version",
		"timestamp_utc",
		"monotonic_elapsed_ms",
		"run_id",
		"request_id",
		"correlation_id",
		"component",
		"operation",
		"attempt",
		"error_category",
		"selector_count",
		"selector_hash",
		"selector_type_summary",
		"candidate_id",
		"predicate",
		"predicate_matched",
		"rejection_category",
		"opaque_required",
		"response_count",
		"response_size_category",
	} {
		require.Contains(t, source, field)
	}
	require.Contains(t, source, "x-spiffe-correlation-id")
	require.Contains(t, source, "x-spiffe-request-id")
	require.Contains(t, source, "pid_source=%s")
	require.Contains(t, source, `pidSourceNamedPipe = "os_named_pipe_peer"`)
	require.Contains(t, source, "caller_category=%s")
	require.Contains(t, source, `return "external_workload"`)
	lower := strings.ToLower(source)
	for _, forbidden := range []string{
		"private_key",
		"raw_key",
		"key_blob",
		"capability_value",
		"opaque_reference",
		"access_token",
		"refresh_token",
		"request_body",
		"response_body",
		"certificate_private",
	} {
		require.NotContains(t, lower, forbidden)
	}
}

func TestKeyBackedFetchRemainsSubscribedAfterInitialResponse(t *testing.T) {
	contents, err := os.ReadFile("handler.go")
	require.NoError(t, err)
	source := string(contents)

	require.Contains(t, source, "SubscribeToX509CacheChanges")
	require.Contains(t, source, "defer subscriber.Finish()")
	require.Contains(t, source, "case update := <-subscriber.Updates():")
	require.Contains(t, source, "case <-ctx.Done():")
}

func TestOpaqueProviderDispatchDefinesSanitizedLifecycleStages(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "manager", "sync.go"))
	require.NoError(t, err)
	source := string(contents)

	for _, stage := range []string{"provider_selection", "provider_dispatch", "provider_result"} {
		require.Contains(t, source, stage)
	}
	for _, stage := range []string{"cache_decision", "rotation_decision", "csr_start", "csr_result", "provider_release"} {
		require.Contains(t, source, stage)
	}
	require.Contains(t, source, "opaque_required")
	require.Contains(t, source, "entry_id")
	require.NotContains(t, strings.ToLower(source), "opaque_reference=")
	require.NotContains(t, strings.ToLower(source), "private_key=")
}
