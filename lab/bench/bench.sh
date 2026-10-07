#!/bin/bash
# Overhead of OBI's storage stats on this host.
#
# Configurations, interleaved over ROUNDS rounds:
#   none     no OBI
#   disk     OBI with stats_disk (every block I/O metric, stacked volumes included)
# The file sync probes are kprobes; hosts whose kernel has no kprobe events can't run them.
#
# Workloads: 4 KiB random read/write with direct I/O on a loop device backed by tmpfs
# (block request probes), and 4 KiB writes with an fsync after each on ext4 (file sync probes).
# Reports IOPS, latency percentiles, host CPU, and OBI CPU and RSS. A last pass with
# kernel.bpf_stats_enabled=1 gives the run time of each eBPF program.
set -u
LAB="$(cd "$(dirname "$0")/.." && pwd)"
OUT=${OUT:-$LAB/bench/results-$(date +%Y%m%d-%H%M%S)}
OBI=${OBI:-$LAB/bench/obi}
ROUNDS=${ROUNDS:-3}
RUNTIME=${RUNTIME:-30}
PORT=9412
mkdir -p "$OUT"

declare -A FEATURES=(
  [disk]=stats_disk
)

img=/dev/shm/obi-bench-raw.img
fsimg=/dev/shm/obi-bench-fs.img
mnt=/mnt/obi-bench
truncate -s 2G "$img"
truncate -s 1G "$fsimg"
raw=$(losetup -f --show "$img")
fsdev=$(losetup -f --show "$fsimg")
mkfs.ext4 -q -F "$fsdev"
mkdir -p "$mnt"
mount "$fsdev" "$mnt"
# Fill the raw device so reads are served from tmpfs pages, not zero pages.
dd if=/dev/urandom of="$raw" bs=1M count=2048 oflag=direct status=none

obi_pid=
cleanup() {
  [ -n "$obi_pid" ] && kill "$obi_pid" 2>/dev/null && wait "$obi_pid" 2>/dev/null
  sysctl -qw kernel.bpf_stats_enabled=0
  umount "$mnt" 2>/dev/null
  losetup -d "$raw" "$fsdev" 2>/dev/null
  rm -f "$img" "$fsimg"
}
trap cleanup EXIT

start_obi() {
  local cfg=$1
  OTEL_EBPF_METRICS_FEATURES=${FEATURES[$cfg]} OTEL_EBPF_PROMETHEUS_PORT=$PORT \
    OTEL_EBPF_STATS_AGENT_IP=10.0.0.1 OTEL_EBPF_LOG_LEVEL=info \
    "$OBI" > "$OUT/obi-$cfg.log" 2>&1 &
  obi_pid=$!
  for _ in $(seq 1 90); do curl -sf "localhost:$PORT/metrics" > /dev/null && break; sleep 1; done
  if ! kill -0 "$obi_pid" 2> /dev/null; then
    echo "OBI ($cfg) exited:"; tail -5 "$OUT/obi-$cfg.log"
    exit 1
  fi
  sleep 3
}

stop_obi() {
  kill "$obi_pid" 2>/dev/null
  wait "$obi_pid" 2>/dev/null
  obi_pid=
}

cpu_busy() { awk '/^cpu / { print $2+$3+$4+$7+$8+$9, $2+$3+$4+$5+$6+$7+$8+$9 }' /proc/stat; }
proc_ticks() { [ -n "$obi_pid" ] && awk '{ print $14+$15 }' "/proc/$obi_pid/stat" || echo 0; }
proc_rss_kb() { [ -n "$obi_pid" ] && awk '/^VmRSS/ { print $2 }' "/proc/$obi_pid/status" || echo 0; }

# run_fio <name> <cfg> <round> <fio args...>: one fio run, one line in results.tsv.
run_fio() {
  local name=$1 cfg=$2 round=$3
  shift 3
  local json=$OUT/fio-$name-$cfg-$round.json
  read -r b0 t0 < <(cpu_busy)
  local p0; p0=$(proc_ticks)
  fio --output-format=json --output="$json" --group_reporting --time_based --runtime="$RUNTIME" "$@" > /dev/null
  read -r b1 t1 < <(cpu_busy)
  local p1; p1=$(proc_ticks)
  local rss; rss=$(proc_rss_kb)
  local hz; hz=$(getconf CLK_TCK)
  python3 - "$json" "$name" "$cfg" "$round" "$b0" "$t0" "$b1" "$t1" "$p0" "$p1" "$hz" "$RUNTIME" "$rss" >> "$OUT/results.tsv" << 'EOF'
import json, sys
path, name, cfg, rnd = sys.argv[1:5]
b0, t0, b1, t1, p0, p1, hz, runtime, rss = map(float, sys.argv[5:14])
job = json.load(open(path))["jobs"][0]
iops = job["read"]["iops"] + job["write"]["iops"]
lat = job["write"] if job["read"]["iops"] == 0 else job["read"]
pct = lat["clat_ns"]["percentile"]
sync = job.get("sync", {}).get("lat_ns", {}).get("percentile", {})
host_cpu = 100.0 * (b1 - b0) / (t1 - t0)
obi_cpu = 100.0 * (p1 - p0) / hz / runtime
print(f"{name}\t{cfg}\t{rnd}\t{iops:.0f}\t{pct['50.000000']/1e3:.1f}\t{pct['99.000000']/1e3:.1f}"
      f"\t{sync.get('50.000000', 0)/1e3:.1f}\t{sync.get('99.000000', 0)/1e3:.1f}"
      f"\t{host_cpu:.1f}\t{obi_cpu:.2f}\t{rss/1024:.0f}")
EOF
}

workloads() {
  local cfg=$1 round=$2
  run_fio randrw "$cfg" "$round" --name=randrw --filename="$raw" --direct=1 --ioengine=libaio \
    --rw=randrw --rwmixread=70 --bs=4k --iodepth=32 --numjobs=2
  run_fio fsync "$cfg" "$round" --name=fsync --directory="$mnt" --size=256M --ioengine=sync \
    --rw=randwrite --bs=4k --fsync=1 --numjobs=2
}

printf 'workload\tconfig\tround\tiops\tp50_us\tp99_us\tsync_p50_us\tsync_p99_us\thost_cpu_pct\tobi_cpu_pct\tobi_rss_mb\n' > "$OUT/results.tsv"
for round in $(seq 1 "$ROUNDS"); do
  for cfg in none disk; do
    echo "round $round: $cfg"
    [ "$cfg" != none ] && start_obi "$cfg"
    workloads "$cfg" "$round"
    [ "$cfg" != none ] && stop_obi
  done
done

# Per-program run time, with the kernel's BPF stats on.
start_obi disk
sysctl -qw kernel.bpf_stats_enabled=1
workloads disk stats
"$LAB/bpfstats/bpfstats" obi_ > "$OUT/bpf-prog-stats.txt"
sysctl -qw kernel.bpf_stats_enabled=0
curl -s "localhost:$PORT/metrics" > "$OUT/metrics-disk.txt"
stop_obi

cat "$OUT/results.tsv"
echo "results: $OUT"
