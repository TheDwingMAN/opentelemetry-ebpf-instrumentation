#!/bin/bash
# Runs the kind disk_stats suite on this host, with the lab docker shim (see lab/bin/docker).
# Needs kind and a Docker daemon (moby-engine). OBI_REPO: the OBI checkout.
set -u
LAB="$(cd "$(dirname "$0")" && pwd)"
REPO="${OBI_REPO:-$HOME/obi-work/opentelemetry-ebpf-instrumentation}"
cd "$REPO" || exit 1
export PATH=$LAB/bin:$HOME/go/bin:$PATH
export LAB_PREBUILT="${LAB_PREBUILT-obi:dev,go-disk-io:dev}"
export LAB_KIND_EXTRA_IMAGES="${LAB_KIND_EXTRA_IMAGES-quay.io/prometheus/prometheus:v2.55.1,otel/opentelemetry-collector-contrib:0.104.0,otel/opentelemetry-collector-contrib:0.155.0}"
go test -v -count=1 -timeout 60m ./internal/test/integration/k8s/disk_stats/ 2>&1
