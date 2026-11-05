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
issuance through it. JWT-SVIDs, WIT-SVIDs, and downstream CA issuance are unchanged.

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
Initialization requires an initial authority snapshot. A broken snapshot stream
taints the active authority and makes the issuer readiness check fail.

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
match a verified path in leaf-to-root order, without roots, duplicates, or unused
certificates.

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

## Current POC limitations

This is an isolated development POC, not a production-ready issuer integration:

- The local CA manager still initializes. Leaf profile construction requires its
  parent chain and caps lifetime against it, even for an external issuer.
- Health checks perform real leaf issuance. Health and server rotation construct
  proof CSRs even when the external issuer is not configured.
- The authority store is in memory. Publication appends roots to the datastore;
  its retention tracking alone does not establish durable rollover or retirement.
- Authority activation precedes bundle publication. Concurrent issuance and
  publication failures need additional lifecycle characterization.
- Snapshot stream failure taints authority state; automatic stream recovery is
  not implemented.
- The synthetic fixture has an ephemeral root and a fixed version label. It is
  not a production plugin or a restart/rollover implementation.

Lifecycle recovery, compatibility across supported version skew, real-provider
qualification, and removal of residual local-CA coupling remain separate work.
Do not infer full feature acceptance from the extraction smoke.
