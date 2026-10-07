#!/bin/bash
# Per-program run time of OBI's block probes with the I/O on one CPU versus spread over all CPUs:
# the completion probe adds to the same accumulator entry from every CPU that completes I/O.
set -u
LAB="$(cd "$(dirname "$0")/.." && pwd)"
OBI=${OBI:-$LAB/bench/obi}
OUT=${OUT:-$LAB/bench/contention}
mkdir -p "$OUT"
img=/dev/shm/obi-contention.img
truncate -s 1G $img
dev=$(losetup -f --show $img)
dd if=/dev/urandom of="$dev" bs=1M count=1024 oflag=direct status=none
trap 'losetup -d $dev; rm -f $img; sysctl -qw kernel.bpf_stats_enabled=0' EXIT

run() { # name, fio args...
  local name=$1; shift
  OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=9414 "$OBI" > "$OUT/obi-$name.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 60); do curl -sf localhost:9414/metrics > /dev/null && break; sleep 1; done
  sleep 2
  sysctl -qw kernel.bpf_stats_enabled=1
  fio --name="$name" --filename="$dev" --direct=1 --ioengine=libaio --rw=randread --bs=4k --iodepth=32 \
    --time_based --runtime=20 --group_reporting --minimal "$@" | awk -F';' -v n="$name" '{ printf "%s: %s IOPS\n", n, $8 }'
  "$LAB/bpfstats/bpfstats" obi_stats_raw_tp_block_rq | sed "s/^/  /"
  sysctl -qw kernel.bpf_stats_enabled=0
  kill $pid; wait $pid 2>/dev/null
}

run one-cpu --numjobs=1 --cpus_allowed=0
run all-cpus --numjobs=4 --cpus_allowed=0-3
run one-cpu-again --numjobs=1 --cpus_allowed=0
