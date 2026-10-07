# The OBI image of the k3s payloads: the final stage of the repository's Dockerfile, around an obi
# binary built on the host (CGO_ENABLED=0), as the cloud lab built obi:disk-v2-23410d280.
# Context (build-payload.sh prepares it): obi, LICENSE, NOTICE, NOTICES/ from the repository and
# certs/ca-certificates.crt from the host.
FROM scratch

ARG OBI_REVISION=unknown
ARG OBI_VERSION=lab

LABEL maintainer="The OpenTelemetry Authors"
LABEL org.opencontainers.image.source="https://github.com/TheDwingMAN/opentelemetry-ebpf-instrumentation"
LABEL org.opencontainers.image.revision="${OBI_REVISION}"
LABEL org.opencontainers.image.version="${OBI_VERSION}"

WORKDIR /

COPY obi .
COPY LICENSE NOTICE ./
COPY NOTICES ./NOTICES

COPY certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/obi" ]
