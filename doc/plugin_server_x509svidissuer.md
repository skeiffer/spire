# Server plugin: X509SVIDIssuer

This development extension delegates **leaf X.509-SVID issuance** to an external
plugin. SPIRE still authorizes the identity and certificate profile, verifies
the proof CSR, validates the returned certificate and chain, and distributes
the issuer's public authorities through its bundle.

This is not an `UpstreamAuthority` plugin: that category supplies an intermediate
CA to SPIRE, whereas `X509SVIDIssuer` signs the actual leaf certificates.

## Configuration and behavior

At most one issuer may be configured. Without an issuer, SPIRE uses its existing
local signer. Configuring an issuer routes server, Agent, and workload leaf
issuance through it. JWT-SVIDs and WIT-SVIDs retain the native key manager,
rotation, signing and journal. Normal JWT/WIT enable/disable settings still
apply; configuring an issuer does not enable a disabled token profile.
Enabled `X509SVIDIssuer` and `UpstreamAuthority`
plugins cannot be combined, regardless of their names. Disabled entries do not
conflict. External mode rejects downstream CA signing before local key use
(`FailedPrecondition` at the CA boundary; the existing SVID API maps signing
failures to `Internal`). Native and upstream-only downstream issuance is unchanged.

**The native CA and its root are intentionally retained.** SPIRE still creates,
rotates and publishes its own CA alongside the external trust roots. This mode
delegates leaf issuance; it does not eliminate native CA keys or make the external
root the only trusted root. External leaf profiles do not borrow the native
parent's expiration, issuer identity, AKI or signing key.

```hcl
plugins {
    X509SVIDIssuer "example" {
        plugin_cmd = "/path/to/issuer"
        plugin_data {
            # Provider-specific configuration belongs to the external plugin.
        }
    }
}
```

The external executable implements the v1 `X509SVIDIssuer` service in
`spire-plugin-sdk`. The host supplies a typed authorized profile and a
proof-of-possession CSR. The CSR's subject, SANs, and extensions are not
authorization inputs.

The plugin streams versioned authority snapshots and returns a DER leaf,
intermediates, and matching authority version for each issuance request. SPIRE
validates the response before serving it. Plugin errors, invalid responses, and
unavailable authority state fail issuance; they do not enable local fallback.
Initialization requires a usable committed authority within one minute.
A broken snapshot stream invalidates readiness and in-flight responses.
Only the subscription is retried, with bounded exponential backoff and jitter;
issuance is never automatically replayed. Each issuance has a thirty-second
timeout. A fresh validated session can recover an unchanged authority version.
Health checks inspect current session/path validity without enrolling a leaf or
generating a key. The reconnecting process remains live but not ready.

Operators must deploy a trusted plugin and configuration: the plugin supplies
trust roots for the trust domain, not merely untrusted certificate data.

## Profile validation

The v1 wire contract is unchanged. Profiles must describe a non-CA leaf with one
valid, non-root-path SPIFFE ID and digital-signature key usage. Key encipherment
and key agreement are also supported. Extended key usage may be absent; when
present it must contain exactly client authentication and server authentication.
Unsupported typed profile fields fail issuance instead of being silently dropped.
These include IP/email SANs, other usages, and typed discovery, policy, or
name-constraint fields not represented by v1.

The returned leaf must match the authorized public key, subject DER (including an
explicit raw subject), URI/DNS SANs, usages, and every requested extra extension's
value and criticality. Additional SAN types and unknown usages are rejected.
Key usage must be critical; SAN must be critical when the subject is empty.
Raw extra extensions cannot override the profile's SAN, key usage, extended key
usage, or basic constraints.

Issuers may add subject/authority key identifiers, authority information access,
CRL distribution points, and certificate policies. Other additions require an
explicit profile extra extension. Required extra extensions still have to match
when their OID is in this issuer-metadata allowlist.

Validity bounds are truncated to X.509 whole-second precision in both the request
and response checks. Shorter, currently valid certificates are accepted; no
additional backdating or lifetime slack is permitted. Normal X.509 verification
must succeed against the snapshot's trust roots, and supplied intermediates must
match a verified, advertised authority path in leaf-to-root order, without roots,
duplicates, or unused certificates. Snapshot paths are ordered root-to-issuer.
The host bounds CSR, certificate, response, path, snapshot and history sizes
before accepting or mutating authority state.

## Development checkout

This branch pins an immutable issuer-contract SDK fork revision in `go.mod`.
A standalone SPIRE checkout does not require a sibling SDK checkout or a Go
workspace:

```shell
GOWORK=off make build
```

The fork replacement can be removed once the interface is available upstream.
For simultaneous SPIRE and SDK development, an optional workspace can override
the pin with the matching SDK checkout:

```shell
go work init /path/to/spire /path/to/spire-plugin-sdk
export GOWORK=/absolute/path/to/go.work
```

Use the Go version from SPIRE's `.go-version`. Confirm `go list -m` resolves the
SDK to the intended checkout. Do not copy machine-specific replacement paths
into the tracked module manifests. Generate SDK bindings with `GOWORK=off` and
the SDK's own pinned Go version to avoid workspace-selected generator drift.

The process-level smoke test is documented in
[`external-x509-issuer`](../test/integration/suites/external-x509-issuer/README.md).
It uses an ordinary Agent and the standard Workload API, without workload-key
extensions or a provider-specific adapter.

## Publication, rollover and restart

An authority is recorded as pending, its roots are appended through the native
CA manager, and datastore read-back must confirm every root. Only after atomic
persistence of committed preparation state can the host activate it. A blocked or
failed publication cannot expose the candidate. A persistence failure stops
issuance until the operator restores writable, intact state and restarts.
Datastore read-back is not acknowledgement that every verifier has received trust.

The first usable committed authority activates immediately. Successors are
published and prepared while the current authority remains active. Every ten
seconds the host checks the current path's effective expiration, considering all
certificates. Activation begins at expiration minus the lesser of one sixth of
its preparation-to-expiration lifetime and seven days. Only a usable, committed,
reobserved successor with improved expiration may replace it. Preparation age
survives reconnect and restart. Retired versions cannot be reactivated.

Disjoint-root rollover publishes trust additively. Native bundle notifications,
publication and pruning remain shared; old roots are not deleted to force a
rollover. Expiration without a usable successor makes external issuance not ready.

Public metadata is stored in `data_dir/x509svidissuer/authorities.json`, using
SPIRE's private-file atomic-write helper. It contains public certificates,
immutable version history and selection/preparation attribution, not signing keys
or token data. Back up this file together with the normal server datastore and
CA journal. Back up provider private material separately under the provider's
own procedures. Missing metadata is first start; corrupt, unsupported or
trailing metadata fails startup. Restart still requires a live provider session,
validation, additive publication and read-back. Reusing a version with different
certificate content is rejected.

History is limited to 64 versions and metadata to 8 MiB. Exhaustion fails with
an actionable error rather than silently deleting version evidence. There is no
automatic old-state migration, concurrent-writer coordination, rollback or
lost-state attribution guarantee, or atomic transaction across disk and the
datastore. This isolated development feature is not a production qualification;
supported-skew and real-provider validation must be reported separately.
