#!/bin/bash
# Measures the average run time of OBI's disk and fsync eBPF programs on this host (kernel stats),
# and the wall time of a direct I/O workload on a loop device with and without OBI.
set -u
LAB="$(cd "$(dirname "$0")/.." && pwd)"
OBI=$LAB/payloads/disk/obi
N=${N:-20000}
img=$(mktemp -p "$LAB/bpfstats" disk.XXXX); truncate -s 256M "$img"
dev=$(losetup -f --show "$img")
trap 'kill $obi_pid 2>/dev/null; wait $obi_pid 2>/dev/null; losetup -d $dev; rm -f $img; sysctl -qw kernel.bpf_stats_enabled=0' EXIT

workload() {
  local start end
  start=$(date +%s.%N)
  dd if=/dev/zero of=$dev bs=4k count=$N oflag=direct status=none
  dd if=$dev of=/dev/null bs=4k count=$N iflag=direct status=none
  end=$(date +%s.%N)
  awk -v a=$start -v b=$end -v n=$((2 * N)) 'BEGIN { printf "%.1f us per request (%d requests, %.2fs)\n", (b-a)*1e6/n, n, b-a }'
}

echo "without OBI: $(workload)"
echo "without OBI: $(workload)"
sysctl -qw kernel.bpf_stats_enabled=1
OTEL_EBPF_METRICS_FEATURES=${FEATURES:-stats_disk} OTEL_EBPF_PROMETHEUS_PORT=9411 OTEL_EBPF_STATS_AGENT_IP=10.0.0.1 \
  OTEL_EBPF_LOG_LEVEL=info $OBI > "$LAB/bpfstats/obi.log" 2>&1 &
obi_pid=$!
for _ in $(seq 1 60); do curl -sf localhost:9411/metrics >/dev/null && break; sleep 1; done
sleep 2
echo "with OBI:    $(workload)"
echo "with OBI:    $(workload)"
"$LAB/bpfstats/bpfstats" obi_stats_raw_t
"$LAB/bpfstats/bpfstats" obi_stats_kpro
"$LAB/bpfstats/bpfstats" obi_stats_kret
