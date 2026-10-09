package workloadkey

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/spiffe/spire/pkg/common/x509util"
	workloadkeyv1 "github.com/spiffe/spire/proto/private/spire/agent/workloadkey/v1"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Manager interface {
	SubscribeToX509CacheChanges(context.Context, cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error)
	FetchWorkloadUpdate([]*common.Selector) *cache.X509WorkloadUpdate
}

type diagnosticRegistrationManager interface {
	RegistrationEntriesDiagnostic() []*common.RegistrationEntry
}

type Attestor interface {
	Attest(context.Context) ([]*common.Selector, error)
}

type Config struct {
	Manager  Manager
	Attestor Attestor
	Log      logrus.FieldLogger
	Now      func() time.Time
}

type Handler struct {
	workloadkeyv1.UnimplementedX509KeyBackedWorkloadAPIServer

	c     Config
	store *CapabilityStore
}

var requestSequence atomic.Uint64

const (
	pidSourceNamedPipe = "os_named_pipe_peer"
	pidSourceUDS       = "os_uds_peer"
	pidSourceUnknown   = "unavailable"
)

func New(c Config) *Handler {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = logrus.New()
	}
	return &Handler{c: c, store: NewCapabilityStore()}
}

func (h *Handler) FetchX509SVIDs(_ *emptypb.Empty, stream workloadkeyv1.X509KeyBackedWorkloadAPI_FetchX509SVIDsServer) error {
	ctx := stream.Context()
	started := h.c.Now()
	requestID, correlationID := diagnosticRequestIdentifiers(ctx)
	processID := rpccontext.CallerPID(ctx)
	h.report(requestID, correlationID, "request_start", "started", "fetch_x509_svids",
		processID, nil, "", "", "", false, "", "", false, 0, "none", false, started)
	h.report(requestID, correlationID, "caller_context", "observed", "caller_pid",
		processID, nil, "", "", "", processID > 0, "", "", false, 0, "none", false, started)
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		h.report(requestID, correlationID, "attestor_result", "deny", "workload_attestation_failed",
			processID, nil, "", "", "", false, "attestation_error", "", false, 0, "none", false, started)
		h.report(requestID, correlationID, "error_mapping", "deny", "permission_denied",
			processID, nil, "", "", "", false, "workload_attestation_failed", "", false, 0, "none", false, started)
		return status.Error(codes.PermissionDenied, "workload attestation failed")
	}
	selectorHash, selectorTypes := selectorSummary(selectors)
	h.report(requestID, correlationID, "attestor_result", "success", "selectors_returned",
		processID, selectors, selectorHash, selectorTypes, "", true, "", "", false, 0, "none", false, started)

	h.report(requestID, correlationID, "registration_lookup_start", "started", "cache_scan",
		processID, selectors, selectorHash, selectorTypes, "", false, "", "", false, 0, "none", false, started)
	if manager, ok := h.c.Manager.(diagnosticRegistrationManager); ok {
		for _, entry := range manager.RegistrationEntriesDiagnostic() {
			matched := selectorsContainEntry(selectors, entry)
			rejection := ""
			if !matched {
				rejection = "selector_subset_mismatch"
			}
			h.report(requestID, correlationID, "registration_candidate", mapDiagnosticResult(matched),
				"selector_subset", processID, selectors, selectorHash, selectorTypes,
				entry.EntryId, matched, rejection, "", entryRequiresOpaqueKey(entry),
				0, "none", false, started)
		}
	}
	update := h.c.Manager.FetchWorkloadUpdate(selectors)
	if update == nil || len(update.Identities) == 0 || update.Bundle == nil {
		h.report(requestID, correlationID, "registration_lookup_end", "deny", "no_identity_issued",
			processID, selectors, selectorHash, selectorTypes, "", false, "no_matching_identity",
			"", false, 0, "none", false, started)
		return status.Error(codes.PermissionDenied, "no identity issued")
	}
	selectedRegistration := update.Identities[0].Entry.EntryId
	h.report(requestID, correlationID, "registration_lookup_end", "success", "identity_selected",
		processID, selectors, selectorHash, selectorTypes, selectedRegistration, true, "",
		selectedRegistration, entryRequiresOpaqueKey(update.Identities[0].Entry),
		0, "none", false, started)
	if processID <= 0 || processID > math.MaxInt32 {
		h.report(requestID, correlationID, "workload_key_route", "deny", "caller_pid_unavailable",
			processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
			"caller_pid_unavailable", selectedRegistration, true, 0, "none", false, started)
		return status.Error(codes.PermissionDenied, "workload process identity is unavailable")
	}

	subscriber, err := h.c.Manager.SubscribeToX509CacheChanges(ctx, selectors)
	if err != nil {
		h.report(requestID, correlationID, "error_mapping", "failed", "subscription_failed",
			processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
			"subscription_failed", selectedRegistration, true, 0, "none", false, started)
		return status.Error(codes.Unavailable, "workload identity subscription failed")
	}
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if update == nil || len(update.Identities) == 0 || update.Bundle == nil {
				h.report(requestID, correlationID, "response_construct", "deny", "no_identity_issued",
					processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
					"no_matching_identity", selectedRegistration, true, 0, "empty", true, started)
				return status.Error(codes.PermissionDenied, "no identity issued")
			}
			selectedRegistration = update.Identities[0].Entry.EntryId
			response := &workloadkeyv1.X509KeyBackedSVIDResponse{
				ProtocolVersion: workloadkeyv1.ProtocolVersion_PROTOCOL_VERSION_V1,
			}
			bundle := x509util.DERFromCertificates(update.Bundle.X509Authorities())
			for _, identity := range update.Identities {
				key, ok := identity.PrivateKey.(workloadkeyprovider.Key)
				h.report(requestID, correlationID, "workload_key_route", mapDiagnosticResult(ok),
					mapDiagnosticCategory(ok, "opaque_provider_key", "software_key_not_eligible"),
					processID, selectors, selectorHash, selectorTypes, identity.Entry.EntryId, ok,
					mapDiagnosticCategory(ok, "", "opaque_key_not_available"), identity.Entry.EntryId,
					entryRequiresOpaqueKey(identity.Entry), len(response.Svids), "none", true, started)
				if !ok {
					continue
				}
				h.report(requestID, correlationID, "capability_construct", "started", "opaque_metadata_only",
					processID, selectors, selectorHash, selectorTypes, identity.Entry.EntryId, true,
					"", identity.Entry.EntryId, entryRequiresOpaqueKey(identity.Entry),
					len(response.Svids), "none", true, started)
				capability, err := h.buildCapability(Binding{
					WorkloadID: identity.Entry.SpiffeId,
					ProcessID:  int32(processID),
				}, key, identity.SVID[0].NotAfter)
				if err != nil {
					return status.Error(codes.Internal, "failed to issue key capability")
				}
				response.Svids = append(response.Svids, &workloadkeyv1.X509KeyBackedSVID{
					SpiffeId: identity.Entry.SpiffeId,
					X509Svid: x509util.DERFromCertificates(identity.SVID),
					Bundle:   bundle,
					Hint:     identity.Entry.Hint,
					Key:      capability,
				})
			}
			if len(response.Svids) == 0 {
				h.report(requestID, correlationID, "response_construct", "deny", "no_key_backed_identity",
					processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
					"opaque_key_not_available", selectedRegistration, true, 0, "empty", true, started)
				return status.Error(codes.PermissionDenied, "no key-backed identity issued")
			}
			responseSizeCategory := sizeCategory(proto.Size(response))
			h.report(requestID, correlationID, "response_construct", "success", "key_backed_response",
				processID, selectors, selectorHash, selectorTypes, selectedRegistration, true, "",
				selectedRegistration, true, len(response.Svids), responseSizeCategory, true, started)
			if err := stream.Send(response); err != nil {
				if errors.Is(err, context.Canceled) {
					h.report(requestID, correlationID, "request_cancelled", "cancelled", "caller_cancelled",
						processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
						"cancelled", selectedRegistration, true, len(response.Svids),
						responseSizeCategory, true, started)
				}
				h.report(requestID, correlationID, "stream_send", "failed", "send_error",
					processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
					"stream_send_failed", selectedRegistration, true, len(response.Svids),
					responseSizeCategory, true, started)
				return err
			}
			h.report(requestID, correlationID, "stream_send", "success", "sent",
				processID, selectors, selectorHash, selectorTypes, selectedRegistration, true, "",
				selectedRegistration, true, len(response.Svids), responseSizeCategory, true, started)
		case <-ctx.Done():
			h.report(requestID, correlationID, "request_cancelled", "cancelled", "caller_cancelled",
				processID, selectors, selectorHash, selectorTypes, selectedRegistration, true,
				"cancelled", selectedRegistration, true, 0, "none", true, started)
			return nil
		}
	}
}

func (h *Handler) report(
	requestID, correlationID, stage, result, category string,
	callerPID int,
	selectors []*common.Selector,
	selectorHash, selectorTypeSummary, candidateID string,
	predicateMatched bool,
	rejectionCategory, selectedRegistration string,
	opaqueRequired bool,
	responseCount int,
	responseSizeCategory string,
	protocolVersionValid bool,
	started time.Time,
) {
	if strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_DEBUG")) != "1" {
		return
	}
	h.c.Log.Infof(
		"schema_version=spire.workloadkey.watch.v1 timestamp_utc=%s monotonic_elapsed_ms=%d classification=LOCAL-DEBUG-NOT-PUBLISHABLE run_id=%s correlation_id=%s request_id=%s component=spire-agent-workload-key stage=%s operation=fetch_x509_svids result=%s duration_ms=%d attempt=1 error_category=%s metadata=bounded caller_pid=%d pid_source=%s caller_category=%s selector_count=%d selector_hash=%s selector_type_summary=%s candidate_id=%s predicate=selector_subset predicate_matched=%t rejection_category=%s selected_registration=%s opaque_required=%t response_count=%d response_size_category=%s protocol_version_valid=%t",
		h.c.Now().UTC().Format(time.RFC3339Nano), h.c.Now().Sub(started).Milliseconds(),
		diagnosticRunID(), correlationID, requestID, stage, result,
		h.c.Now().Sub(started).Milliseconds(), diagnosticErrorCategory(result, category),
		callerPID, callerPIDSource(callerPID), callerPIDCategory(callerPID), len(selectors),
		emptyDiagnosticValue(selectorHash), emptyDiagnosticValue(selectorTypeSummary),
		emptyDiagnosticValue(candidateID), predicateMatched, emptyDiagnosticValue(rejectionCategory),
		emptyDiagnosticValue(selectedRegistration), opaqueRequired, responseCount,
		responseSizeCategory, protocolVersionValid,
	)
}

func callerPIDSource(pid int) string {
	if pid <= 0 {
		return pidSourceUnknown
	}
	if runtime.GOOS == "windows" {
		return pidSourceNamedPipe
	}
	return pidSourceUDS
}

func callerPIDCategory(pid int) string {
	switch {
	case pid <= 0:
		return "unverified"
	case pid == os.Getpid():
		return "agent_internal"
	default:
		return "external_workload"
	}
}

func selectorSummary(selectors []*common.Selector) (string, string) {
	canonical := make([]string, 0, len(selectors))
	typeCounts := make(map[string]int)
	for _, selector := range selectors {
		canonical = append(canonical, selector.Type+"\x00"+selector.Value)
		typeCounts[selector.Type]++
	}
	sort.Strings(canonical)
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	types := make([]string, 0, len(typeCounts))
	for selectorType, count := range typeCounts {
		types = append(types, selectorType+":"+strconv.Itoa(count))
	}
	sort.Strings(types)
	return hex.EncodeToString(sum[:]), strings.Join(types, ",")
}

func selectorsContainEntry(selectors []*common.Selector, entry *common.RegistrationEntry) bool {
	observed := make(map[string]struct{}, len(selectors))
	for _, selector := range selectors {
		observed[selector.Type+"\x00"+selector.Value] = struct{}{}
	}
	for _, required := range entry.Selectors {
		if _, ok := observed[required.Type+"\x00"+required.Value]; !ok {
			return false
		}
	}
	return true
}

func entryRequiresOpaqueKey(entry *common.RegistrationEntry) bool {
	return entry != nil && entry.Hint == "workload-key-provider-required"
}

func diagnosticCorrelationID() string {
	value := strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_CORRELATION_ID"))
	if value != "" && len(value) <= 96 {
		for _, character := range value {
			if !((character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') ||
				character == '-' || character == '_') {
				return "invalid"
			}
		}
		return value
	}
	return "unspecified"
}

func diagnosticRequestIdentifiers(ctx context.Context) (string, string) {
	requestID := "workload-key-" + strconv.FormatUint(requestSequence.Add(1), 10)
	correlationID := diagnosticCorrelationID()
	if strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_DEBUG")) != "1" {
		return requestID, correlationID
	}
	if incoming, ok := metadata.FromIncomingContext(ctx); ok {
		if values := incoming.Get("x-spiffe-request-id"); len(values) == 1 {
			requestID = diagnosticIdentifier(values[0], requestID)
		}
		if values := incoming.Get("x-spiffe-correlation-id"); len(values) == 1 {
			correlationID = diagnosticIdentifier(values[0], correlationID)
		}
	}
	return requestID, correlationID
}

func diagnosticIdentifier(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 96 {
		return fallback
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_') {
			return fallback
		}
	}
	return value
}

func diagnosticRunID() string {
	value := strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_DEBUG_RUN_ID"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_CORRELATION_ID"))
	}
	if value == "" {
		return "unspecified"
	}
	return emptyDiagnosticValue(value)
}

func diagnosticErrorCategory(result, category string) string {
	if result == "deny" || result == "failed" || result == "cancelled" {
		return category
	}
	return "none"
}

func sizeCategory(size int) string {
	switch {
	case size <= 0:
		return "empty"
	case size <= 16*1024:
		return "small"
	case size <= 64*1024:
		return "medium"
	default:
		return "large"
	}
}

func mapDiagnosticResult(ok bool) string {
	if ok {
		return "success"
	}
	return "deny"
}

func mapDiagnosticCategory(ok bool, success, failure string) string {
	if ok {
		return success
	}
	return failure
}

func emptyDiagnosticValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func (h *Handler) buildCapability(binding Binding, key workloadkeyprovider.Key, expires time.Time) (*workloadkeyv1.KeyCapability, error) {
	publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	capability := &workloadkeyv1.KeyCapability{
		Generation: key.Generation(),
		PublicKey:  publicKey,
		Algorithm:  workloadkeyv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		ExpiresAt:  timestamppb.New(expires),
	}
	switch key.OperationMode() {
	case workloadkeyprovider.LocalReferenceMode:
		reference := key.Reference()
		if len(reference) == 0 || len(reference) > 1024 {
			return nil, errors.New("invalid local key reference")
		}
		capability.Id = reference
		capability.Mode = workloadkeyv1.KeyOperationMode_KEY_OPERATION_MODE_LOCAL_REFERENCE
	case workloadkeyprovider.RemoteSignMode:
		issued, err := h.store.Issue(binding, key, expires)
		if err != nil {
			return nil, err
		}
		capability.Id = append([]byte(nil), issued.ID[:]...)
		capability.Mode = workloadkeyv1.KeyOperationMode_KEY_OPERATION_MODE_REMOTE_SIGN
	default:
		return nil, errors.New("unsupported workload key operation mode")
	}
	return capability, nil
}

func (h *Handler) Sign(ctx context.Context, request *workloadkeyv1.SignRequest) (*workloadkeyv1.SignResponse, error) {
	if request == nil || len(request.CapabilityId) != 32 || request.Generation == 0 ||
		request.HashAlgorithm != workloadkeyv1.HashAlgorithm_HASH_ALGORITHM_SHA256 ||
		request.SignatureScheme != workloadkeyv1.SignatureScheme_SIGNATURE_SCHEME_RSA_PKCS1V15 ||
		len(request.Digest) != 32 {
		return nil, status.Error(codes.InvalidArgument, "invalid sign request")
	}
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "workload attestation failed")
	}
	update := h.c.Manager.FetchWorkloadUpdate(selectors)
	if update == nil {
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}
	processID := rpccontext.CallerPID(ctx)
	if processID <= 0 || processID > math.MaxInt32 {
		return nil, status.Error(codes.PermissionDenied, "workload process identity is unavailable")
	}
	var id [32]byte
	copy(id[:], request.CapabilityId)
	for _, identity := range update.Identities {
		signature, err := h.store.Sign(id, Binding{
			WorkloadID: identity.Entry.SpiffeId,
			ProcessID:  int32(processID),
		}, request.Generation, request.Digest, h.c.Now())
		if err == nil {
			return &workloadkeyv1.SignResponse{Signature: signature}, nil
		}
		if !errors.Is(err, ErrUnauthorizedCapability) && !errors.Is(err, ErrInvalidCapability) {
			return nil, status.Error(codes.PermissionDenied, "key capability is not authorized")
		}
	}
	return nil, status.Error(codes.PermissionDenied, "key capability is not authorized")
}
