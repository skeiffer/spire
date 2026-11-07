# Decoupled external X.509 issuance

This suite builds a generic restartable issuer fixture and two SPIRE servers
with independent ordinary data directories and disk KeyManagers, sharing a SQLite
datastore. Two Agents exercise attestation, workload issuance and renewal.

The fixture bootstraps independently of IdentityProvider. Roots are retained
across fixture restarts. The suite stages a successor, checks propagation to
warm Agent caches, observes automatic native-threshold activation, interrupts and recovers authority
streams, checks independent JWT/WIT signatures and published verification keys,
and restarts both servers. It verifies JWTs through OIDC discovery/JWKS before
and after concurrent token rotations and restart. A supported one-minor-older
Agent (1.15.3) exercises the unchanged Agent protocol and trust rollover. A
bootstrap-dependent issuer is bounded and fails rather than creating a local
CA. The suite rejects internal X.509 administration and checks
that KeyManager contains only token-role keys.

Run using the existing Linux integration runner:

```shell
GOWORK=off make integration SUITES=suites/external-x509-issuer-decoupled
```

Docker must be available. The fixture image uses the repository-built binaries
on Ubuntu, rather than a sibling SDK or an old feature branch.
