FROM ubuntu:24.04 AS fixture
WORKDIR /opt/spire
COPY bin/spire-server bin/spire-agent bin/oidc-discovery-provider bin/x509svidissuer-fixture /opt/spire/bin/
RUN mkdir -p /tmp/spire-server/private /tmp/spire-agent/public /opt/spire/data/server /opt/spire/data/agent

FROM fixture AS spire-server
ENTRYPOINT ["/opt/spire/bin/spire-server", "run"]

FROM fixture AS spire-agent
ENTRYPOINT ["/opt/spire/bin/spire-agent", "run"]

FROM fixture AS oidc-discovery-provider
ENTRYPOINT ["/opt/spire/bin/oidc-discovery-provider"]
