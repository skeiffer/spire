# Server plugin: X509SVIDIssuer

The `X509SVIDIssuer` plugin delegates leaf X.509-SVID signing to an external
issuer while SPIRE remains responsible for authorization, certificate profiles,
response validation, and trust-bundle publication.

The interface is opt-in. Servers without an `X509SVIDIssuer` configuration keep
the existing local and UpstreamAuthority behavior.

## Configuration

```hcl
server {
    data_dir = "/var/lib/spire/server-one"
    external_x509_control_dir = "/var/lib/spire-external/server-one"
}
plugins {
    X509SVIDIssuer "external_issuer" {
        plugin_cmd = "/opt/spire/plugin/external-issuer"
        plugin_checksum = "REPLACE_WITH_PLUGIN_CHECKSUM"
        plugin_data {
            # Provider-specific configuration.
        }
    }
}
```

Only one issuer may be configured. `X509SVIDIssuer` and `UpstreamAuthority`
cannot be enabled together.

External selection composes a leaf host, independent token authorities, and
generic bundle maintenance. It does not construct an internal CA or CA
manager/rotator, provision CA-role keys, or route leaves through the local CA.
JWT/OIDC behavior and separately enabled experimental WIT remain available
with independent KeyManager keys. `disable_jwt_svids` and the existing WIT
enablement keep their meanings; disabled token modes generate no signing keys.
The existing `ca_ttl` remains the token-key lifetime in this mode. X.509 local,
upstream and downstream authority administration is unavailable after normal
API authorization. WIT administration remains Unimplemented.

## Provisioning and protected state

The operator must provision the control directory independently of `data_dir`.
They must not contain one another. On POSIX, the assertion and state paths must
be owned by the process user or root, without group/other write access or
symlinks. Windows checks trusted ownership and write ACLs and uses the existing
owner-private atomic-write protections. Both the control directory and
`data_dir` are exclusively locked for the server process lifetime.

Before any catalog configuration, SPIRE reads `provision.json`:

```json
{
  "version": 1,
  "trust_domain": "example.org",
  "instance": "unique-server-instance",
  "issuer": "external_issuer",
  "issuer_checksum": "SHA256_OF_THE_ISSUER_EXECUTABLE",
  "key_manager_digest": "SHA256_OF_THE_CANONICAL_KEYMANAGER_CONFIGURATION",
  "retained_roots": []
}
```

The issuer name and nonempty executable checksum must match the plugin
configuration. Compute `key_manager_digest` with
`externalstate.KeyManagerDigest` from the configuration returned by
`catalog.PluginConfigsFromHCLNode`, using the same HCL loader as the server.
It hashes the canonical JSON fields `Name`, `Path`, `Checksum`, `Data`, and
`Args`, including the exact catalog-rendered plugin data. Do not hash the
original HCL text instead. Dynamic KeyManager plugin data is frozen after this
comparison so later reconfiguration cannot switch namespaces.

This assertion is a trusted local operator statement, not a remotely signed
credential. It must identify dedicated KeyManager storage. For disk
KeyManager, `keys_path` must be absolute and absent at first provisioning; an
existing file is rejected before Configure can parse private keys. On restart,
restore only the matching dedicated key storage. Namespace isolation for
opaque remote KeyManagers is an operator provisioning invariant; all returned
keys must subsequently match token metadata or a durable pending intent.
Reusing a legacy CA namespace or copying arbitrary key files is not supported.

`retained_roots` contains base64-encoded public DER CA certificates explicitly
authorized for a new node's retained trust. The shared bundle may contain only
roots justified by that assertion or the server's validated authority ledger.
Unexplained roots cause a closed failure, not deletion or origin guessing.
An assertion does not prove that other servers are configured in external
mode; uniform cluster configuration is a separate deployment invariant.

First provisioning requires an empty `data_dir`. SPIRE consumes this permission
by recording ownership in `data_dir/external-x509/owner.json` and the separate
control directory's `established.json` before catalog side effects. Token and
authority metadata contain only public DER/keys, stable key references,
lifetimes and transition status. Private authority signing keys remain in
KeyManager; server and client leaf-key ownership is unchanged.

The independent `checkpoint.json` binds each public metadata file to its latest
committed digest. Its pending digest is written before replacing that metadata
file; restart reconciles either the preceding committed file or the intended
replacement. A rollback, deletion or unprovable restore of `data_dir` is rejected
before configuring KeyManager. Preserve this independent evidence separately;
rolling it back together with all runtime and key state defeats that evidence.
Do not manually reformat metadata files.

An established instance with missing, corrupt, copied, mismatched or
unknown-version state fails closed. Ambiguous `.tmp` files also require
reconciliation; they are not silently overwritten. A failed initialization may
need a verified restore rather than a new first-provision assertion. Never
delete the ownership record to make an established node initialize again.
If both independent evidence stores are lost, SPIRE cannot infer whether this
is a new instance; automatic complete-state-loss recovery is not provided.

Durable intent precedes key generation or root/key publication. Public bindings
precede additive publication and read-back; final durable commit precedes
signer or authority activation. Recovery reconciles pending operations and
existing bundle taints/revocations rather than resurrecting revoked keys.
Missing private keys with valid public history are replaced under new
identities while previously published verification material is retained.

The integration fixture's `prepare` command generates complete isolated
assertions and configurations for a runnable example. That fixture is a test
issuer, not a production provisioning or CA service.

## Bootstrap contract

The issuer must authenticate its initial authority subscription and the request
for the SPIRE server's first X.509-SVID without using that server X.509-SVID.
Depending on the deployment, this can use a locally provisioned workload
identity, a platform identity, or another independently managed credential.

SPIRE waits for a valid authority snapshot, publishes its roots additively to
the local trust-domain bundle, reads the bundle back, and only then permits
issuance. BundlePublisher delivery and peer or Agent cache refresh remain
asynchronous and are not acknowledged by the plugin protocol.

## Certificate profile

The proof CSR proves control of the authorized public key only. Its subject,
SANs, and extensions do not authorize certificate contents. SPIRE sends an
immutable profile prepared after normal API authorization and validates the
returned leaf and exact ordered path against the captured authority version.

Returned leaves:

- contain exactly one non-root SPIFFE URI;
- are non-CA certificates;
- have a critical digital-signature key usage;
- have both client and server authentication EKUs when EKUs are present;
- use a critical SAN extension when the subject is empty;
- stay within the requested second-precision validity bounds; and
- do not outlive any certificate in the selected path.

An issuer may return a shorter certificate that is currently usable and remains
within those bounds. Very short or already-half-lived certificates can renew on
the next five-second server rotation check and may cause frequent issuance.
There is no additional minimum lifetime or scheduler change in this feature.
The process suite exercises 30-second server, Agent and workload lifetimes;
focused validation also accepts a one-second, already-half-lived leaf. Such a
leaf may expire before an existing renewal scheduler's next check. Acceptance
does not guarantee uninterrupted operation for sub-renewal-interval lifetimes.

## Rollover and failure behavior

Authority versions are immutable. Reusing a version with different certificate
bytes is rejected. Successor roots are published while the current version
continues to issue. Selecting the successor requires an explicit host-side
activation after operators confirm propagation; publication alone is not global
delivery confirmation.

To select an initial or already-staged successor, atomically replace
`activate.json` in the protected control directory:

```json
{
  "version": 1,
  "binding": "SHA256_OF_THE_CANONICAL_PROVISIONING_ASSERTION_JSON",
  "authority_version": "issuer-version-to-select"
}
```

`binding` is SHA-256 of `json.Marshal(externalstate.Assertion)` for the
provisioned assertion; it also appears in the established ownership record.
The file is checked once per second. It must name an exact version observed
and revalidated in the current healthy subscription session and committed
after datastore publication. Changing this file asserts that the operator
confirmed propagation to the relevant verifiers; SPIRE cannot infer delivery
from the file or a timer. The issuer must keep honoring the previous selected
version during staging and re-advertise it when reconnecting if it is still
selected. A multi-root version does not let the host select a root within it.

Published old roots remain through their certificate expiry plus at least
the existing 24-hour pruning margin. Additive updates preserve token keys,
taints and federated bundles. Bundle loaded/updated notifications and ordinary
asynchronous BundlePublisher delivery continue without a CA manager.

An observed stream or protocol failure invalidates the session generation.
Leaf issuance fails closed, including responses from requests that were in
flight before the failure. SPIRE reconnects with bounded backoff. Published
trust is retained; a transport failure does not revoke an authority.

The frozen v1 protocol has no heartbeat, lease, ordering sequence, or revocation
RPC. Health can therefore report certificate expiry and observed stream
failures, but cannot infer provider freshness from silence.
Restored metadata is recovery evidence, never offline issuance permission.
An issuer outage does not disable independently healthy JWT/WIT signing, but
existing server/client X.509 transport credentials still limit remote API
reachability as they expire.

## Operational limits

External mode is intended for uniformly configured clusters. Mixed
internal/external operation, migration from an existing internal hierarchy,
automatic emergency root revocation, provider-specific adapters, and complete
state-loss recovery are outside this iteration.

Bootstrap and issuance waits are bounded to 30 seconds; concurrent issuance
is bounded to 64 requests. A snapshot is limited to 1 MiB, 16 advertised chains,
eight intermediates per chain and 64 KiB per certificate. At most 64 immutable
versions are retained, and retained roots selected for publication are limited
to 2 MiB to leave room within existing transport limits. The host rejects activation beyond those bounds
rather than evicting version/content bindings. An archival/migration policy
requires separate approval. Metadata files are limited to 8 MiB.

Rollback must retain compatible external-mode code and matching state. The
frozen v1 plugin interface, Agent protocol and datastore APIs/schema are
unchanged. This fork extension is not a maintainer-approved production release.
