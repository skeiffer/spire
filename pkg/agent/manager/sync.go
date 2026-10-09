package manager

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadkeyprovider"
	"github.com/spiffe/spire/pkg/agent/storage"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/bundleutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_agent "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
)

type csrRequest struct {
	EntryID              string
	SpiffeID             string
	CurrentSVIDExpiresAt time.Time
	OpaqueRequired       bool
}

var providerDiagnosticSequence atomic.Uint64

// taintedAuthorities carries the tainted authority key IDs reported by the
// server. They drive SVID rotation but are not part of the cache's entry
// state, so they are kept out of cache.UpdateEntries.
type taintedAuthorities struct {
	X509 []string
	JWT  map[string]struct{}
}

// Implemented by both the LRU cache and the store cache as the common
// interface for updating cached X509-SVIDs.
type x509SVIDCache interface {
	// UpdateEntries updates entries on cache
	UpdateEntries(update *cache.UpdateEntries, checkSVID func(*common.RegistrationEntry, *common.RegistrationEntry, *cache.X509SVID) bool)

	// UpdateX509SVIDs updates SVIDs on provided records
	UpdateX509SVIDs(update map[string]*cache.X509SVID)

	// GetStaleEntries gets a list of records that need update SVIDs
	GetStaleEntries() []*cache.StaleEntry
}

func (m *manager) syncX509SVIDs(ctx context.Context) error {
	m.x509Cache.SyncSVIDsWithSubscribers()
	return m.updateX509SVIDs(ctx, m.c.Log.WithField(telemetry.CacheType, telemetry_agent.CacheTypeWorkload), m.x509Cache)
}

func (m *manager) syncWITSVIDs(ctx context.Context) error {
	if m.witCache == nil {
		return ErrWITSVIDsDisabled
	}
	m.witCache.SyncSVIDsWithSubscribers()
	return m.updateWITSVIDs(ctx, m.c.Log.WithField(telemetry.CacheType, telemetry_agent.CacheTypeWorkload).WithField(telemetry.SVIDType, telemetry_agent.SVIDTypeWIT))
}

// processTaintedAuthorities verifies if a new authority is tainted and forces rotation in all caches if required.
func (m *manager) processTaintedAuthorities(ctx context.Context, bundle *spiffebundle.Bundle, tainted *taintedAuthorities) error {
	newTaintedX509Authorities := getNewItemsFromSlice(m.processedTaintedX509Authorities, tainted.X509)
	if len(newTaintedX509Authorities) > 0 {
		m.c.Log.WithField(telemetry.SubjectKeyIDs, strings.Join(newTaintedX509Authorities, ",")).
			Debug("New tainted X.509 authorities found")

		taintedX509Authorities, err := bundleutil.FindX509Authorities(bundle, newTaintedX509Authorities)
		if err != nil {
			return fmt.Errorf("failed to search X.509 authorities: %w", err)
		}

		// Taint all regular X.509 SVIDs
		m.x509Cache.TaintX509SVIDs(ctx, taintedX509Authorities)

		// Taint all SVIDStore SVIDs
		m.svidStoreCache.TaintX509SVIDs(ctx, taintedX509Authorities)

		// Notify rotator about new tainted authorities
		if err := m.svid.NotifyTaintedAuthorities(taintedX509Authorities); err != nil {
			return err
		}

		for _, subjectKeyID := range newTaintedX509Authorities {
			m.processedTaintedX509Authorities[subjectKeyID] = struct{}{}
		}
	}

	newTaintedJWTAuthorities := getNewItemsFromMap(m.processedTaintedJWTAuthorities, tainted.JWT)
	if len(newTaintedJWTAuthorities) > 0 {
		m.c.Log.WithField(telemetry.JWTAuthorityKeyIDs, strings.Join(newTaintedJWTAuthorities, ",")).
			Debug("New tainted JWT authorities found")

		// Taint JWT-SVIDs in the cache
		m.jwtCache.TaintJWTSVIDs(ctx, tainted.JWT)

		for _, subjectKeyID := range newTaintedJWTAuthorities {
			m.processedTaintedJWTAuthorities[subjectKeyID] = struct{}{}
		}
	}

	return nil
}

// synchronize fetches the authorized entries from the server, updates the
// caches, and fetches missing/expiring X509-SVIDs.
func (m *manager) synchronize(ctx context.Context) (err error) {
	cacheUpdate, storeUpdate, tainted, err := m.fetchEntries(ctx)
	if err != nil {
		return err
	}

	// Update the shared bundle cache as soon as the latest bundles are
	// available. This keeps bundle consumers (rotator, broker, bundle
	// observer) in sync even if a later step (e.g. SVID fetching) fails, and
	// avoids a stale bundle view relative to the workload cache, which is
	// updated by updateX509SVIDCache below.
	m.bundleCache.Update(cacheUpdate.Bundles)

	// Process all tainted authorities. The bundle is shared between both caches using regular cache data.
	var errs []error
	errs = append(errs, m.processTaintedAuthorities(ctx, cacheUpdate.Bundles[m.c.TrustDomain], tainted))
	errs = append(errs, m.updateX509SVIDCache(ctx, cacheUpdate, m.c.Log.WithField(telemetry.CacheType, telemetry_agent.CacheTypeWorkload), "", m.x509Cache))
	errs = append(errs, m.updateX509SVIDCache(ctx, storeUpdate, m.c.Log.WithField(telemetry.CacheType, telemetry_agent.CacheTypeSVIDStore), telemetry_agent.CacheTypeSVIDStore, m.svidStoreCache))
	if m.witCache != nil {
		m.updateWITSVIDCacheEntries(cacheUpdate, m.c.Log.WithField(telemetry.CacheType, telemetry_agent.CacheTypeWorkload).WithField(telemetry.SVIDType, telemetry_agent.SVIDTypeWIT))
	}

	if err := errors.Join(errs...); err != nil {
		return err
	}

	// Set last success sync
	m.setLastSync()
	return nil
}

func (m *manager) updateX509SVIDCache(ctx context.Context, update *cache.UpdateEntries, log logrus.FieldLogger, cacheType string, c x509SVIDCache) error {
	// update the cache and build a list of CSRs that need to be processed
	// in this interval.
	//
	// the values in `update` now belong to the cache. DO NOT MODIFY.
	var expiring int
	var outdated int
	c.UpdateEntries(update, func(existingEntry, newEntry *common.RegistrationEntry, svid *cache.X509SVID) bool {
		switch {
		case svid == nil:
			// no SVID
		case len(svid.Chain) == 0:
			// SVID has an empty chain. this is not expected to happen.
			log.WithFields(logrus.Fields{
				telemetry.RegistrationID: newEntry.EntryId,
				telemetry.SPIFFEID:       newEntry.SpiffeId,
			}).Warn("cached X509 SVID is empty")
		case m.c.RotationStrategy.ShouldRotateX509(m.c.Clk.Now(), svid.Chain[0]):
			expiring++
		case existingEntry != nil && existingEntry.RevisionNumber != newEntry.RevisionNumber:
			// Registration entry has been updated
			outdated++
		default:
			// SVID is good
			return false
		}

		return true
	})

	// TODO: this values are not real, we may remove
	if expiring > 0 {
		telemetry_agent.AddCacheManagerExpiredSVIDsSample(m.c.Metrics, cacheType, telemetry_agent.SVIDTypeX509, float32(expiring))
		log.WithField(telemetry.ExpiringSVIDs, expiring).Debug("Updating expiring SVIDs in cache")
	}
	if outdated > 0 {
		telemetry_agent.AddCacheManagerOutdatedSVIDsSample(m.c.Metrics, cacheType, telemetry_agent.SVIDTypeX509, float32(outdated))
		log.WithField(telemetry.OutdatedSVIDs, outdated).Debug("Updating SVIDs with outdated attributes in cache")
	}

	return m.updateX509SVIDs(ctx, log, c)
}

func (m *manager) updateX509SVIDs(ctx context.Context, log logrus.FieldLogger, c x509SVIDCache) error {
	m.updateSVIDMu.Lock()
	defer m.updateSVIDMu.Unlock()

	staleEntries := c.GetStaleEntries()
	if len(staleEntries) > 0 {
		var csrs []csrRequest
		sizeLimit := m.csrSizeLimitedBackoff.NextBackOff()
		log.WithFields(logrus.Fields{
			telemetry.Count: len(staleEntries),
			telemetry.Limit: sizeLimit,
		}).Debug("Renewing stale entries")

		for _, entry := range staleEntries {
			// we've exceeded the CSR limit, don't make any more CSRs
			if len(csrs) >= sizeLimit {
				break
			}

			csrs = append(csrs, csrRequest{
				EntryID:              entry.Entry.EntryId,
				SpiffeID:             entry.Entry.SpiffeId,
				CurrentSVIDExpiresAt: entry.SVIDExpiresAt,
				OpaqueRequired:       m.c.RequireOpaqueKey != nil && m.c.RequireOpaqueKey(entry.Entry),
			})
			m.reportProviderDiagnostic("cache-"+entry.Entry.EntryId, managerDiagnosticCorrelationID(),
				"cache_decision", "rotate", "stale_entry", entry.Entry.EntryId,
				m.c.RequireOpaqueKey != nil && m.c.RequireOpaqueKey(entry.Entry), time.Now())
			m.reportProviderDiagnostic("rotation-"+entry.Entry.EntryId, managerDiagnosticCorrelationID(),
				"rotation_decision", "rotate", "renewal_required", entry.Entry.EntryId,
				m.c.RequireOpaqueKey != nil && m.c.RequireOpaqueKey(entry.Entry), time.Now())
		}

		svids, err := m.fetchX509SVIDs(ctx, csrs)
		if err != nil {
			return err
		}
		// the values in `update` now belong to the cache. DO NOT MODIFY.
		c.UpdateX509SVIDs(svids)
	}
	return nil
}

func (m *manager) updateWITSVIDCacheEntries(update *cache.UpdateEntries, log logrus.FieldLogger) {
	// the values in `update` now belong to the cache. DO NOT MODIFY.
	var expiring int
	m.witCache.UpdateEntries(update, func(_, newEntry *common.RegistrationEntry, svid *cache.WITSVID) bool {
		switch {
		case svid == nil:
			// no SVID
		case rotationutil.WITSVIDExpiresSoon(svid.IssuedAt, svid.ExpiresOn, m.c.Clk.Now()):
			expiring++
		default:
			// SVID is good
			return false
		}

		return true
	})

	if expiring > 0 {
		telemetry_agent.AddCacheManagerExpiredSVIDsSample(m.c.Metrics, telemetry_agent.CacheTypeWorkload, telemetry_agent.SVIDTypeWIT, float32(expiring))
		log.WithField(telemetry.ExpiringSVIDs, expiring).Debug("Updating expiring SVIDs in cache")
	}
}

func (m *manager) updateWITSVIDs(ctx context.Context, log logrus.FieldLogger) error {
	m.updateSVIDMu.Lock()
	defer m.updateSVIDMu.Unlock()

	staleEntries := m.witCache.GetStaleEntries()
	if len(staleEntries) == 0 {
		return nil
	}

	sizeLimit := m.witSizeLimitedBackoff.NextBackOff()
	log.WithFields(logrus.Fields{
		telemetry.Count: len(staleEntries),
		telemetry.Limit: sizeLimit,
	}).Debug("Renewing stale entries")

	if len(staleEntries) > sizeLimit {
		staleEntries = staleEntries[:sizeLimit]
	}

	svids, err := m.fetchWITSVIDs(ctx, staleEntries)
	if err != nil {
		return err
	}
	// the values in `svids` now belong to the cache. DO NOT MODIFY.
	m.witCache.UpdateWITSVIDs(svids)
	return nil
}

func (m *manager) fetchWITSVIDs(ctx context.Context, staleEntries []*cache.StaleEntry) (_ map[string]*cache.WITSVID, err error) {
	counter := telemetry_agent.StartManagerFetchSVIDsUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	signingAlgorithm, err := m.c.WorkloadKeyType.SigningAlgorithm()
	if err != nil {
		return nil, err
	}

	privateKeys := make(map[string]crypto.Signer, len(staleEntries))
	publicKeys := make(map[string]crypto.PublicKey, len(staleEntries))
	for _, staleEntry := range staleEntries {
		entry := staleEntry.Entry
		log := m.c.Log.WithFields(logrus.Fields{
			telemetry.SPIFFEID:       entry.SpiffeId,
			telemetry.RegistrationID: entry.EntryId,
		})
		if staleEntry.SVIDExpiresAt.IsZero() {
			log.Info("Creating WIT-SVID")
		} else {
			log.WithField(telemetry.ExpiresAt, staleEntry.SVIDExpiresAt.Format(time.RFC3339)).Info("Renewing WIT-SVID")
		}

		privateKey, err := m.c.WorkloadKeyType.GenerateSigner()
		if err != nil {
			return nil, err
		}
		privateKeys[entry.EntryId] = privateKey
		publicKeys[entry.EntryId] = privateKey.Public()
	}

	svidsOut, err := m.client.NewWITSVIDs(ctx, publicKeys, signingAlgorithm)
	if err != nil {
		// Reduce the batch size for the next invocation
		m.witSizeLimitedBackoff.Failure()
		return nil, err
	}
	m.witSizeLimitedBackoff.Success()

	byEntryID := make(map[string]*cache.WITSVID, len(svidsOut))
	for entryID, svid := range svidsOut {
		privateKey, ok := privateKeys[entryID]
		if !ok {
			continue
		}

		byEntryID[entryID] = &cache.WITSVID{
			Token:      svid.Token,
			PrivateKey: privateKey,
			IssuedAt:   svid.IssuedAt,
			ExpiresOn:  svid.ExpiresAt,
		}
	}

	return byEntryID, nil
}

func (m *manager) fetchX509SVIDs(ctx context.Context, csrs []csrRequest) (_ map[string]*cache.X509SVID, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchSVIDsUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)
	defer func() {
		if err == nil {
			m.csrSizeLimitedBackoff.Success()
		}
	}()

	csrsIn := make(map[string][]byte)

	privateKeys := make(map[string]crypto.Signer, len(csrs))
	for _, csr := range csrs {
		log := m.c.Log.WithFields(logrus.Fields{
			"spiffe_id": csr.SpiffeID,
			"entry_id":  csr.EntryID,
		})
		if !csr.CurrentSVIDExpiresAt.IsZero() {
			log = log.WithField("expires_at", csr.CurrentSVIDExpiresAt.Format(time.RFC3339))
		}

		// Since entryIDs are unique, this shouldn't happen. Log just in case
		if _, ok := privateKeys[csr.EntryID]; ok {
			log.Warnf("Ignoring duplicate X509-SVID renewal for entry ID: %q", csr.EntryID)
			continue
		}

		if csr.CurrentSVIDExpiresAt.IsZero() {
			log.Info("Creating X509-SVID")
		} else {
			log.Info("Renewing X509-SVID")
		}

		spiffeID, err := spiffeid.FromString(csr.SpiffeID)
		if err != nil {
			return nil, err
		}
		privateKey, csrBytes, err := m.newCSR(ctx, csr.EntryID, spiffeID, csr.OpaqueRequired)
		if err != nil {
			return nil, err
		}
		privateKeys[csr.EntryID] = privateKey
		csrsIn[csr.EntryID] = csrBytes
	}

	svidsOut, err := m.client.NewX509SVIDs(ctx, csrsIn)
	if err != nil {
		// Reduce csr size for next invocation
		m.csrSizeLimitedBackoff.Failure()
		return nil, err
	}

	byEntryID := make(map[string]*cache.X509SVID, len(svidsOut))
	for entryID, svid := range svidsOut {
		privateKey, ok := privateKeys[entryID]
		if !ok {
			continue
		}
		chain, err := x509.ParseCertificates(svid.CertChain)
		if err != nil {
			return nil, err
		}

		svidLifetime := chain[0].NotAfter.Sub(chain[0].NotBefore)
		if m.c.RotationStrategy.ShouldFallbackX509DefaultRotation(svidLifetime) {
			log := m.c.Log.WithFields(logrus.Fields{
				"spiffe_id": chain[0].URIs[0].String(),
				"entry_id":  entryID,
			})
			log.Warn("X509 SVID lifetime isn't long enough to guarantee the availability_target, falling back to the default rotation strategy")
		}

		byEntryID[entryID] = &cache.X509SVID{
			Chain:      chain,
			PrivateKey: privateKey,
		}
		if key, ok := privateKey.(workloadkeyprovider.Key); ok {
			if previous := m.activeOpaqueKeys[entryID]; previous != nil {
				if err := m.releaseOpaqueKey(ctx, previous); err != nil {
					return nil, err
				}
			}
			m.activeOpaqueKeys[entryID] = key
		}
		delete(privateKeys, entryID)
	}
	for _, privateKey := range privateKeys {
		if key, ok := privateKey.(workloadkeyprovider.Key); ok {
			if err := m.releaseOpaqueKey(ctx, key); err != nil {
				return nil, err
			}
		}
	}

	return byEntryID, nil
}

func (m *manager) releaseOpaqueKey(ctx context.Context, key workloadkeyprovider.Key) error {
	started := time.Now()
	requestID := "release-" + strconv.FormatUint(providerDiagnosticSequence.Add(1), 10)
	m.reportProviderDiagnostic(requestID, managerDiagnosticCorrelationID(), "provider_release",
		"started", "release_key", "", true, started)
	releaser, ok := m.c.WorkloadKeyProvider.(interface {
		ReleaseKey(context.Context, []byte, uint64) error
	})
	if !ok {
		m.reportProviderDiagnostic(requestID, managerDiagnosticCorrelationID(), "provider_release",
			"skipped", "release_unsupported", "", true, started)
		return nil
	}
	if err := releaser.ReleaseKey(ctx, key.Reference(), key.Generation()); err != nil {
		m.reportProviderDiagnostic(requestID, managerDiagnosticCorrelationID(), "provider_release",
			"failed", "release_failed", "", true, started)
		return fmt.Errorf("release opaque workload key: %w", err)
	}
	m.reportProviderDiagnostic(requestID, managerDiagnosticCorrelationID(), "provider_release",
		"success", "released", "", true, started)
	return nil
}

// fetchEntries fetches entries that the agent is entitled to, divided in lists, one for regular entries and
// another one for storable entries
func (m *manager) fetchEntries(ctx context.Context) (_ *cache.UpdateEntries, _ *cache.UpdateEntries, _ *taintedAuthorities, err error) {
	// Put all the CSRs in an array to make just one call with all the CSRs.
	counter := telemetry_agent.StartManagerFetchEntriesUpdatesCall(m.c.Metrics)
	defer counter.Done(&err)

	stats, err := m.client.SyncUpdates(ctx, m.syncedEntries, m.syncedBundles)
	if err != nil {
		return nil, nil, nil, err
	}
	telemetry_agent.SetSyncStats(m.c.Metrics, stats)
	update := &client.Update{
		Entries: m.syncedEntries,
		Bundles: m.syncedBundles,
	}

	bundles, err := parseBundles(update.Bundles)
	if err != nil {
		return nil, nil, nil, err
	}

	// Get all Subject Key IDs and KeyIDs of tainted authorities
	var taintedX509Authorities []string
	taintedJWTAuthorities := make(map[string]struct{})
	if b, ok := update.Bundles[m.c.TrustDomain.IDString()]; ok {
		for _, rootCA := range b.RootCas {
			if rootCA.TaintedKey {
				cert, err := x509.ParseCertificate(rootCA.DerBytes)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("failed to parse tainted x509 authority: %w", err)
				}
				subjectKeyID := x509util.SubjectKeyIDToString(cert.SubjectKeyId)
				taintedX509Authorities = append(taintedX509Authorities, subjectKeyID)
			}
		}
		for _, jwtKey := range b.JwtSigningKeys {
			if jwtKey.TaintedKey {
				taintedJWTAuthorities[jwtKey.Kid] = struct{}{}
			}
		}
	}

	cacheEntries := make(map[string]*common.RegistrationEntry)
	storeEntries := make(map[string]*common.RegistrationEntry)

	for entryID, entry := range update.Entries {
		switch {
		case entry.StoreSvid:
			storeEntries[entryID] = entry
		default:
			cacheEntries[entryID] = entry
		}
	}

	return &cache.UpdateEntries{
		Bundles:             bundles,
		RegistrationEntries: cacheEntries,
	}, &cache.UpdateEntries{
		Bundles:             bundles,
		RegistrationEntries: storeEntries,
	}, &taintedAuthorities{
		X509: taintedX509Authorities,
		JWT:  taintedJWTAuthorities,
	}, nil
}

func newCSR(spiffeID spiffeid.ID, keyType workloadkey.KeyType) (crypto.Signer, []byte, error) {
	pk, err := keyType.GenerateSigner()
	if err != nil {
		return nil, nil, err
	}

	csr, err := util.MakeCSR(pk, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return pk, csr, nil
}

func (m *manager) newCSR(ctx context.Context, entryID string, spiffeID spiffeid.ID, opaqueRequired bool) (crypto.Signer, []byte, error) {
	started := time.Now()
	requestID := "provider-" + strconv.FormatUint(providerDiagnosticSequence.Add(1), 10)
	correlationID := managerDiagnosticCorrelationID()
	m.reportProviderDiagnostic(requestID, correlationID, "provider_selection",
		mapProviderResult(!opaqueRequired || m.c.WorkloadKeyProvider != nil),
		mapProviderCategory(!opaqueRequired, "software_key_route", "external_provider_route"),
		entryID, opaqueRequired, started)
	m.reportProviderDiagnostic(requestID, correlationID, "csr_start", "started",
		"safe_metadata_only", entryID, opaqueRequired, started)
	if !opaqueRequired {
		return newCSR(spiffeID, m.c.WorkloadKeyType)
	}
	if m.c.WorkloadKeyProvider == nil {
		m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
			"provider_missing", entryID, true, started)
		return nil, nil, errors.New("opaque workload key is required but no WorkloadKeyProvider is configured")
	}
	m.keyGenerationsLoadOnce.Do(func() {
		if m.storage == nil {
			m.storage = m.c.Storage
		}
		if m.storage == nil {
			return
		}
		persisted, err := m.storage.LoadWorkloadKeyGenerations()
		if err != nil {
			if !errors.Is(err, storage.ErrNotCached) {
				m.keyGenerationsLoadErr = fmt.Errorf("load opaque workload key generations: %w", err)
			}
			return
		}
		for persistedEntryID, persistedGeneration := range persisted {
			m.keyGenerations[persistedEntryID] = persistedGeneration
		}
	})
	if m.keyGenerationsLoadErr != nil {
		m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
			"generation_load_failed", entryID, true, started)
		return nil, nil, m.keyGenerationsLoadErr
	}
	previousGeneration := m.keyGenerations[entryID]
	generation := previousGeneration + 1
	m.reportProviderDiagnostic(requestID, correlationID, "provider_dispatch", "started",
		"generate_key", entryID, true, started)
	key, err := m.c.WorkloadKeyProvider.GenerateKey(ctx, workloadkeyprovider.GenerateRequest{
		WorkloadID: spiffeID.String(),
		Generation: generation,
	})
	if err != nil {
		m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
			"generate_failed", entryID, true, started)
		return nil, nil, fmt.Errorf("generate opaque workload key: %w", err)
	}
	if key == nil || key.Generation() != generation || len(key.Reference()) == 0 {
		m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
			"invalid_metadata", entryID, true, started)
		return nil, nil, errors.New("WorkloadKeyProvider returned an invalid opaque key")
	}
	csr, err := util.MakeCSR(key, spiffeID)
	if err != nil {
		m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
			"csr_failed", entryID, true, started)
		return nil, nil, fmt.Errorf("create CSR with opaque workload key: %w", err)
	}
	m.reportProviderDiagnostic(requestID, correlationID, "csr_result", "success",
		"csr_created_not_logged", entryID, true, started)
	m.keyGenerations[entryID] = generation
	if m.storage != nil {
		if err := m.storage.StoreWorkloadKeyGenerations(m.keyGenerations); err != nil {
			if previousGeneration == 0 {
				delete(m.keyGenerations, entryID)
			} else {
				m.keyGenerations[entryID] = previousGeneration
			}
			m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "deny",
				"generation_store_failed", entryID, true, started)
			return nil, nil, fmt.Errorf("store opaque workload key generation: %w", err)
		}
	}
	m.reportProviderDiagnostic(requestID, correlationID, "provider_result", "success",
		"opaque_signer_ready", entryID, true, started)
	return key, csr, nil
}

func (m *manager) reportProviderDiagnostic(
	requestID, correlationID, stage, result, category, entryID string,
	opaqueRequired bool,
	started time.Time,
) {
	if m.c.Log == nil || strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_DEBUG")) != "1" {
		return
	}
	m.c.Log.Infof(
		"schema_version=spire.workloadkey.watch.v1 timestamp_utc=%s monotonic_elapsed_ms=%d classification=LOCAL-DEBUG-NOT-PUBLISHABLE run_id=%s correlation_id=%s request_id=%s component=spire-agent-manager stage=%s operation=workload_key_provider result=%s duration_ms=%d attempt=1 error_category=%s metadata=bounded entry_id=%s opaque_required=%t",
		time.Now().UTC().Format(time.RFC3339Nano), time.Since(started).Milliseconds(),
		managerDiagnosticRunID(), correlationID, requestID, stage, result,
		time.Since(started).Milliseconds(), managerErrorCategory(result, category),
		diagnosticValue(entryID),
		opaqueRequired,
	)
}

func managerDiagnosticRunID() string {
	value := strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_DEBUG_RUN_ID"))
	if value == "" {
		value = strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_CORRELATION_ID"))
	}
	return diagnosticValue(value)
}

func managerErrorCategory(result, category string) string {
	if result == "deny" || result == "failed" {
		return category
	}
	return "none"
}

func managerDiagnosticCorrelationID() string {
	value := strings.TrimSpace(os.Getenv("SPIRE_WORKLOAD_KEY_CORRELATION_ID"))
	if value == "" || len(value) > 96 {
		return "unspecified"
	}
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

func mapProviderResult(ok bool) string {
	if ok {
		return "success"
	}
	return "deny"
}

func mapProviderCategory(condition bool, whenTrue, whenFalse string) string {
	if condition {
		return whenTrue
	}
	return whenFalse
}

func diagnosticValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func parseBundles(bundles map[string]*common.Bundle) (map[spiffeid.TrustDomain]*cache.Bundle, error) {
	out := make(map[spiffeid.TrustDomain]*cache.Bundle, len(bundles))
	for _, bundle := range bundles {
		bundle, err := bundleutil.SPIFFEBundleFromProto(bundle)
		if err != nil {
			return nil, err
		}
		td, err := spiffeid.TrustDomainFromString(bundle.TrustDomain().IDString())
		if err != nil {
			return nil, err
		}
		out[td] = bundle
	}
	return out, nil
}

func getNewItemsFromSlice(current map[string]struct{}, items []string) []string {
	var newItems []string
	for _, subjectKeyID := range items {
		if _, ok := current[subjectKeyID]; !ok {
			newItems = append(newItems, subjectKeyID)
		}
	}

	return newItems
}

func getNewItemsFromMap(current map[string]struct{}, items map[string]struct{}) []string {
	var newItems []string
	for subjectKeyID := range items {
		if _, ok := current[subjectKeyID]; !ok {
			newItems = append(newItems, subjectKeyID)
		}
	}

	return newItems
}
