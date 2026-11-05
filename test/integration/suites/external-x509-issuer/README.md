# External X.509-SVID issuer

Runs an ordinary Agent and workload against both the default signer and the
optional external leaf issuer. The check verifies the identity, private-key/public-key
match, chain against the delivered bundle, issuer, and workload renewal.
Successful Agent admission and server startup also exercise their leaf paths.

The external server launches the generic `test/fixture/x509svidissuer` plugin.
After successful issuance, a fixture-only file control makes a fresh admin mint
fail. This is a new CSR/RPC, not a cached workload credential.

Prerequisites: the pinned issuer SDK dependency, Linux Docker Compose, the normal
`spire-server:latest-local` and `spire-agent:latest-local` test images, and Go
on the host. The Agent image must support a root workload using the unix
attestor, as in the other integration suites.

From the SPIRE root, run:

```shell
make integration SUITES=suites/external-x509-issuer
```

The first step builds the two generic fixture executables using the current Go
module configuration. A sibling SDK checkout and Go workspace are optional.
No provider, opaque-key endpoint, cloud service, or live environment is used.
The framework always tears down this suite's containers.
