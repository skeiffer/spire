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

## State and recovery

External mode uses the ordinary server `data_dir` and configured KeyManager.
Public issuer metadata is stored below `data_dir/external-x509/issuer`, and
public token-key attribution is stored below `data_dir/external-x509/tokens`.
The files are bounded, strictly decoded JSON and are replaced with SPIRE's
standard private atomic-file helper. Missing metadata is an ordinary first
start. Corrupt metadata, unsupported versions, or referenced token private
keys whose public keys do not match still fail startup.

Private token signing keys remain in KeyManager. New JWT and WIT key IDs are
randomly unique and role-specific. Unrelated pre-existing KeyManager keys are
not deleted, overwritten, or required to belong to this server.

There is no independent provisioning assertion, owner marker, checkpoint,
lock, or rollback detector. Back up `data_dir`, the matching KeyManager, and
the datastore consistently using the same operational practices as other
SPIRE server state. Loss of public metadata is treated as a fresh state and
cannot be distinguished from intentional first startup. Atomic replacement
does not provide a transaction across KeyManager, the filesystem, and the
datastore.

Durable intent precedes key generation or root/key publication. Public bindings
precede additive publication and read-back; final durable commit precedes
signer or authority activation. Recovery reconciles pending operations and
existing bundle taints/revocations rather than resurrecting revoked keys.
Missing or mismatched private keys referenced by token metadata fail startup;
unreferenced KeyManager keys are ignored. Previously published verification
material is retained additively.

The integration fixture's `prepare` command generates isolated configurations
for a runnable example. That fixture is a test issuer, not a production
provisioning or CA service.

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
bytes is rejected. The first valid authority is published, read back, persisted,
and activated immediately, matching native first-start behavior. A successor
is published and retained as prepared while the current authority remains in
use. The host checks the lifecycle every ten seconds and activates the prepared
successor after the native activation threshold: the smaller of one sixth of
the current effective signing-path lifetime and seven days before the current
effective expiry. Every certificate in each usable path constrains that
effective expiry; the best usable advertised path is used.

A successor that does not improve the current effective expiry is not
activated. An unusable successor is rejected. If the current path expires, a
usable improving prepared successor can be activated on the lifecycle check.
Publication and datastore read-back still precede use, but do not prove global
delivery to every verifier.

The issuer must keep honoring the current version during staging and
re-advertise it after reconnect so the host can re-establish current-session
observations. The v1 protocol cannot request a historical version or acknowledge
global propagation. A multi-root version does not let the host select a root
within it.

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
eight intermediates per chain and 64 KiB per certificate. At most 64 immutable versions are retained, and retained roots selected for
publication are limited to 2 MiB to leave room within existing transport
limits. The host rejects snapshots beyond those bounds rather than evicting
version/content bindings. An archival/migration policy requires separate
approval. Metadata files are limited to 2 MiB.

Rollback must retain compatible external-mode code and matching state. The
frozen v1 plugin interface, Agent protocol and datastore APIs/schema are
unchanged. This fork extension is not a maintainer-approved production release.
