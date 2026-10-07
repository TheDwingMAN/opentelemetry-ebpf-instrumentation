#!/usr/bin/env bash
# Build what a lab payload needs, from the OBI checkout and pinned public downloads.
#
#   build-payload.sh <payload-name|payload-dir>
#
# Reads the payload's run.sh (and main.sh) and builds only what they use, into the payload dir:
#   obi             CGO_ENABLED=0 go build ./cmd/obi
#   stats.test      CGO_ENABLED=0 go test -c -tags privileged_tests ./pkg/internal/statsolly/stats
#   verifier.test   CGO_ENABLED=0 go test -c -tags bpf_verifier_tests ./pkg/internal/ebpf/verifier
#   bpfmaps bpfstats kprobecost   go build of lab/<tool>/
#   k3s-root.tar    docker export of rancher/k3s:$K3S_TAG (cached in cache/k3s/)
#   images*.tar     docker save of the images the payload's yaml files use: obi:<tag> built from the
#                   repo with docker/obi-image.Dockerfile, go-disk-io:dev from the repo's component
#                   with docker/go-disk-io.Dockerfile, otel/opentelemetry-collector-contrib:lab
#                   (busybox: the collector binary comes from the payload), any other image pulled;
#                   plus k3s's pause image, and coredns unless run.sh disables it
#   otelcol-contrib GitHub release v$OTELCOL_VERSION (cached in cache/downloads/)
#   prometheus      GitHub release v$PROMETHEUS_VERSION (cached in cache/downloads/)
# and writes COMMIT (the repo HEAD). The guest userland (Ubuntu 24.04) has an older glibc than the
# host, so every Go binary is static (CGO_ENABLED=0).
#
# Environment:
#   OBI_REPO        the OBI checkout (default ~/obi-work/opentelemetry-ebpf-instrumentation)
#   DOCKER          the container CLI (default docker; podman-docker and "sudo docker" work too)
#   OBI_GENERATE    make (default: make generate, incremental) | docker (make docker-generate) | 0
#   OBI_DOCKERFILE  the obi image Dockerfile (default docker/obi-image.Dockerfile)
#   K3S_TAG=v1.30.14-k3s2 OTELCOL_VERSION=0.161.0 PROMETHEUS_VERSION=3.15.0 (what the cloud lab ran)
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"
REPO="${OBI_REPO:-$HOME/obi-work/opentelemetry-ebpf-instrumentation}"
read -ra DOCKER <<< "${DOCKER:-docker}"
OBI_DOCKERFILE="${OBI_DOCKERFILE:-$LAB/docker/obi-image.Dockerfile}"

DEFAULT_K3S_TAG=v1.30.14-k3s2
DEFAULT_OTELCOL_VERSION=0.161.0
DEFAULT_PROMETHEUS_VERSION=3.15.0
K3S_TAG="${K3S_TAG:-$DEFAULT_K3S_TAG}"
OTELCOL_VERSION="${OTELCOL_VERSION:-$DEFAULT_OTELCOL_VERSION}"
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-$DEFAULT_PROMETHEUS_VERSION}"
# sha256 of the binaries the cloud lab ran, compared when the versions are the defaults
CLOUD_SHA256_K3S=ebaa7fa510f389cc8a9569bc2a7de53cffd83a15b1d3694893ad60f5c556c372
CLOUD_SHA256_OTELCOL=1e6629a05c0d3084b2bc090307ea16166af4a2d24452785d076736adbcb13be7
CLOUD_SHA256_PROMETHEUS=dac83d1d1007961de3b9ba624942c9af0c192ee3df262ac47ef390bcade71c65

# the k3s system images of v1.30.14+k3s2 (the VM has no network, so they ship in images.tar)
PAUSE_IMAGE=docker.io/rancher/mirrored-pause:3.6
PAUSE_DIGEST=sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893
COREDNS_IMAGE=docker.io/rancher/mirrored-coredns-coredns:1.12.1
# the collector pods of the k3s-volumes family run the payload's otelcol-contrib from a hostPath
# in a busybox image tagged as the collector image
COLLECTOR_LAB_IMAGE=docker.io/otel/opentelemetry-collector-contrib:lab
COLLECTOR_STANDIN=docker.io/library/busybox:1.37

die() { echo "build-payload: $*" >&2; exit 1; }
note() { echo "[build-payload] $*" >&2; }

[ $# -eq 1 ] || { sed -n '2,27p' "$0" >&2; exit 2; }
case "$1" in
    */*) P="$(realpath "$1")" ;;
    *) P="$LAB/payloads/$1" ;;
esac
[ -f "$P/run.sh" ] || die "$P/run.sh not found"
[ -e "$REPO/.git" ] || die "OBI_REPO=$REPO is not a git checkout"

SCRIPTS=("$P/run.sh")
[ -f "$P/main.sh" ] && SCRIPTS+=("$P/main.sh")

# uses <name>: the payload runs ./<name>
uses() { grep -qE "(^|[^A-Za-z0-9_.-])\\./$1([^A-Za-z0-9_.-]|\$)" "${SCRIPTS[@]}"; }
# mentions <file>: run.sh refers to <file> (the k3s tars)
mentions() { grep -qF "$1" "$P/run.sh"; }
is_podman() { "${DOCKER[@]}" --version 2>/dev/null | grep -qi podman; }

# link_or_copy <src> <dst>: the caches and payloads share a filesystem, so a hard link saves space
link_or_copy() { ln -f "$1" "$2" 2>/dev/null || cp -f "$1" "$2"; }

check_sha() { # file expected label
    local got
    got="$(sha256sum "$1" | cut -d' ' -f1)"
    if [ "$got" = "$2" ]; then note "$3: same binary as the cloud lab"; else note "WARNING: $3 differs from the cloud lab's ($got)"; fi
}

# ---- what to build

if [ -d "$P/bundle" ]; then
    die "$(basename "$P"): its images come from bundle/kustomization.yaml (obi:bundle-test, obi-k8s-cache:bundle-test); not supported, use k3s-final"
fi
for b in blkprobe fsyncargs v2probe obi-dynsel; do
    if uses "$b"; then
        die "$(basename "$P") runs ./$b, whose source is not part of the kit: put the binary in $P by hand"
    fi
done

K3S=0; mentions k3s-root.tar && K3S=1
GO_TARGETS=()
for t in obi stats.test verifier.test bpfmaps bpfstats kprobecost; do
    uses "$t" && GO_TARGETS+=("$t")
done
if [ "$K3S" = 0 ] && [ "${#GO_TARGETS[@]}" -eq 0 ]; then
    note "$(basename "$P") needs no build"
    exit 0
fi
command -v go >/dev/null || die "go is not installed"
if [ "$K3S" = 1 ]; then
    command -v curl >/dev/null || die "curl is not installed"
    "${DOCKER[@]}" info >/dev/null 2>&1 ||
        die "'${DOCKER[*]}' does not work for $(id -un): join the docker group (moby) or use podman-docker, or set DOCKER='sudo docker'"
fi

# ---- Go builds from the repo

generate() {
    case "${OBI_GENERATE:-make}" in
        0|no|false) ;;
        docker)
            local oci="${DOCKER[*]}"
            is_podman && oci=podman
            (cd "$REPO" && make docker-generate OCI_BIN="$oci") ;;
        *) (cd "$REPO" && make generate) ;;
    esac
}

HEAD="$(git -C "$REPO" rev-parse --short HEAD)"
DIRTY=""
[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ] || DIRTY=" (with uncommitted changes)"
note "building $(basename "$P") from $REPO @ $HEAD$DIRTY"
generate

WORK="$(mktemp -d "$LAB/cache/build-payload.XXXXXX" 2>/dev/null || { mkdir -p "$LAB/cache" && mktemp -d "$LAB/cache/build-payload.XXXXXX"; })"
trap 'rm -rf "$WORK"' EXIT

OBI_BIN=""
build_obi() {
    [ -z "$OBI_BIN" ] || return 0
    OBI_BIN="$WORK/obi"
    (cd "$REPO" && CGO_ENABLED=0 go build -o "$OBI_BIN" ./cmd/obi) || die "obi build failed"
}

for t in "${GO_TARGETS[@]}"; do
    note "building $t"
    case "$t" in
        obi) build_obi; cp -f "$OBI_BIN" "$P/obi" ;;
        stats.test)
            (cd "$REPO" && CGO_ENABLED=0 go test -c -tags privileged_tests -o "$P/stats.test" ./pkg/internal/statsolly/stats) ||
                die "stats.test build failed" ;;
        verifier.test)
            (cd "$REPO" && CGO_ENABLED=0 go test -c -tags bpf_verifier_tests -o "$P/verifier.test" ./pkg/internal/ebpf/verifier/) ||
                die "verifier.test build failed" ;;
        *) (cd "$LAB/$t" && CGO_ENABLED=0 go build -o "$P/$t" .) || die "$t build failed" ;;
    esac
done

# ---- k3s payloads

k3s_root() {
    local cache="$LAB/cache/k3s/k3s-root-$K3S_TAG.tar" image="docker.io/rancher/k3s:$K3S_TAG" cid
    if [ ! -s "$cache" ]; then
        note "exporting $image"
        mkdir -p "$(dirname "$cache")"
        "${DOCKER[@]}" pull "$image" >&2
        cid="$("${DOCKER[@]}" create "$image")"
        "${DOCKER[@]}" export "$cid" > "$cache.tmp"
        "${DOCKER[@]}" rm "$cid" >/dev/null
        mv "$cache.tmp" "$cache"
    fi
    if [ "$K3S_TAG" = "$DEFAULT_K3S_TAG" ]; then
        tar -xOf "$cache" bin/k3s > "$WORK/k3s"
        check_sha "$WORK/k3s" "$CLOUD_SHA256_K3S" "k3s $K3S_TAG"
    fi
    link_or_copy "$cache" "$P/k3s-root.tar"
}

release_binary() { # name version url member cloud-sha default-version
    local name=$1 version=$2 url=$3 member=$4 cloud_sha=$5 default_version=$6
    local bin="$LAB/cache/downloads/$name-$version"
    if [ ! -s "$bin" ]; then
        note "downloading $url"
        mkdir -p "$(dirname "$bin")"
        curl -fL --retry 3 --max-time 1800 -o "$WORK/$name.tar.gz" "$url"
        tar -xzf "$WORK/$name.tar.gz" -O "$member" > "$bin.tmp"
        chmod 0755 "$bin.tmp"
        mv "$bin.tmp" "$bin"
        rm -f "$WORK/$name.tar.gz"
    fi
    [ "$version" != "$default_version" ] || check_sha "$bin" "$cloud_sha" "$name $version"
    link_or_copy "$bin" "$P/$name"
}

# qualify <image>: the full name containerd gives an image reference (docker.io/library/ for a bare
# name), so the saved archives import under the names the manifests use with docker and podman alike
qualify() {
    local ref=$1 first=${1%%/*}
    case "$ref" in *:*|*@*) ;; *) ref="$ref:latest" ;; esac
    if [[ $1 != */* ]]; then
        echo "docker.io/library/$ref"
    elif [[ $first == *.* || $first == *:* || $first == localhost ]]; then
        echo "$ref"
    else
        echo "docker.io/$ref"
    fi
}

build_obi_image() { # version-label, then the image names
    local version=$1 ca="" c args=()
    shift
    for c in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-bundle.crt; do
        [ -s "$c" ] && { ca=$c; break; }
    done
    [ -n "$ca" ] || die "no CA bundle found on this host"
    [ -d "$REPO/NOTICES" ] || die "$REPO/NOTICES missing"
    build_obi
    local ctx="$WORK/obi-image"
    mkdir -p "$ctx/certs"
    cp "$OBI_BIN" "$ctx/obi"
    grep -q obi-stripped "$OBI_DOCKERFILE" && cp "$OBI_BIN" "$ctx/obi-stripped"
    cp "$REPO/LICENSE" "$REPO/NOTICE" "$ctx/"
    cp -r "$REPO/NOTICES" "$ctx/NOTICES"
    cp "$ca" "$ctx/certs/ca-certificates.crt"
    for c in "$@"; do args+=(-t "$c"); done
    note "building the obi image: $*"
    "${DOCKER[@]}" build -f "$OBI_DOCKERFILE" --build-arg "OBI_REVISION=$(git -C "$REPO" rev-parse HEAD)" \
        --build-arg "OBI_VERSION=$version" "${args[@]}" "$ctx" >&2
    rm -rf "$ctx"
}

build_go_disk_io() { # image name
    local ctx="$WORK/go-disk-io"
    mkdir -p "$ctx"
    (cd "$REPO/internal/test/integration/components/go-disk-io" && CGO_ENABLED=0 go build -o "$ctx/go-disk-io" main.go) ||
        die "go-disk-io build failed"
    note "building $1"
    "${DOCKER[@]}" build -f "$LAB/docker/go-disk-io.Dockerfile" -t "$1" "$ctx" >&2
}

save_images() { # tar, then the image names
    local out=$1 flags=()
    shift
    is_podman && flags=(--multi-image-archive)
    note "saving $(basename "$out"): $*"
    "${DOCKER[@]}" save "${flags[@]}" "$@" > "$out.tmp"
    mv "$out.tmp" "$out"
}

k3s_images() {
    local yaml=() f ref name obi_images=() collector_images=() other_images=()
    for f in "$P"/*.yaml "$P"/*.yml "$P"/manifests/*.yaml "$P"/manifests/*.yml; do
        [ -f "$f" ] && yaml+=("$f")
    done
    local refs=()
    if [ "${#yaml[@]}" -gt 0 ]; then
        mapfile -t refs < <(grep -hE '^[[:space:]]*(-[[:space:]]*)?image:' "${yaml[@]}" |
            sed -E "s/^[^:]*image:[[:space:]]*//; s/[\"']//g; s/[[:space:]].*\$//" | sort -u)
    fi

    for ref in "${refs[@]}"; do
        name="$(qualify "$ref")"
        case "${name%%[:@]*}" in
            docker.io/library/obi) obi_images+=("$name") ;;
            docker.io/library/go-disk-io)
                build_go_disk_io "$name"; other_images+=("$name") ;;
            docker.io/otel/opentelemetry-collector-contrib)
                if [ "$name" = "$COLLECTOR_LAB_IMAGE" ]; then
                    "${DOCKER[@]}" pull "$COLLECTOR_STANDIN" >&2
                    "${DOCKER[@]}" tag "$COLLECTOR_STANDIN" "$name"
                else
                    "${DOCKER[@]}" pull "$name" >&2
                fi
                collector_images+=("$name") ;;
            docker.io/library/obi-k8s-cache) die "$ref: the k8s-cache image is not built by this script" ;;
            *) "${DOCKER[@]}" pull "$name" >&2; other_images+=("$name") ;;
        esac
    done
    if [ "${#obi_images[@]}" -gt 0 ]; then
        build_obi_image "${obi_images[0]##*:}" "${obi_images[@]}"
        note "the manifests run ${obi_images[*]}: that tag now holds $HEAD$DIRTY"
    fi

    "${DOCKER[@]}" pull "docker.io/rancher/mirrored-pause@$PAUSE_DIGEST" >&2
    "${DOCKER[@]}" tag "docker.io/rancher/mirrored-pause@$PAUSE_DIGEST" "$PAUSE_IMAGE"
    other_images+=("$PAUSE_IMAGE")
    if ! grep -E '^[[:space:]]*k3s server' "$P/run.sh" | grep -q coredns; then
        "${DOCKER[@]}" pull "$COREDNS_IMAGE" >&2
        other_images+=("$COREDNS_IMAGE")
    fi

    if mentions images-obi.tar; then
        [ "${#obi_images[@]}" -gt 0 ] || die "run.sh loads images-obi.tar but no yaml file uses an obi image"
        save_images "$P/images-obi.tar" "${obi_images[@]}"
    else
        other_images+=("${obi_images[@]}")
    fi
    if mentions images-collector.tar; then
        [ "${#collector_images[@]}" -gt 0 ] || die "run.sh loads images-collector.tar but no yaml file uses a collector image"
        save_images "$P/images-collector.tar" "${collector_images[@]}"
    else
        other_images+=("${collector_images[@]}")
    fi
    save_images "$P/images.tar" "${other_images[@]}"
}

if [ "$K3S" = 1 ]; then
    k3s_root
    mentions images.tar && k3s_images
    # run.sh starts it, or the in-cluster collector of the k3s-volumes family runs it from /work
    if uses otelcol-contrib || grep -qs otelcol-contrib "$P"/*.yaml; then
        release_binary otelcol-contrib "$OTELCOL_VERSION" \
            "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v$OTELCOL_VERSION/otelcol-contrib_${OTELCOL_VERSION}_linux_amd64.tar.gz" \
            otelcol-contrib "$CLOUD_SHA256_OTELCOL" "$DEFAULT_OTELCOL_VERSION"
    fi
    if uses prometheus; then
        release_binary prometheus "$PROMETHEUS_VERSION" \
            "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/prometheus-$PROMETHEUS_VERSION.linux-amd64.tar.gz" \
            "prometheus-$PROMETHEUS_VERSION.linux-amd64/prometheus" "$CLOUD_SHA256_PROMETHEUS" "$DEFAULT_PROMETHEUS_VERSION"
    fi
fi

echo "$HEAD$DIRTY" > "$P/COMMIT"
ls -la "$P" >&2
