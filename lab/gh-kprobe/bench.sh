#!/bin/bash
# Cost of OBI's file sync kprobes (and block tracepoints) on a GitHub runner's real kernel.
#   sudo bench.sh <obi> <kprobecost> <bpfstats>
# Times system calls with and without OBI (stats_disk + stats_fs_sync_duration): fsync,
# fdatasync, syncfs of a tmpfs file (the probes are most of the cost), a 4 KiB write + fsync on
# ext4, 4 KiB direct reads of a block device, and getppid (no probe: the noise floor). Then the
# run time of each eBPF program from bpf_stats.
set -u
OBI=$1; COST=$2; STATS=$3
N=${N:-50000}; NW=${NW:-3000}; ROUNDS=${ROUNDS:-5}
out=${OUT:-/tmp/kprobe-bench}; mkdir -p $out
echo "kernel: $(uname -r)  arch: $(uname -m)  cpus: $(nproc)"

mkdir -p /mnt/t && mount -t tmpfs tmpfs /mnt/t && : > /mnt/t/f
truncate -s 512M /var/tmp/fs.img && mkfs.ext4 -q -F /var/tmp/fs.img
mkdir -p /mnt/e && mount -o loop /var/tmp/fs.img /mnt/e && : > /mnt/e/f
if modprobe null_blk nr_devices=1 2>/dev/null && [ -b /dev/nullb0 ]; then
  blk=/dev/nullb0
else
  truncate -s 256M /var/tmp/blk.img; blk=$(losetup -f --show /var/tmp/blk.img)
fi
echo "block device: $blk"

bench() { # label
  for r in $(seq 1 $ROUNDS); do
    for spec in getppid:/mnt/t/f:$N fsync:/mnt/t/f:$N fdatasync:/mnt/t/f:$N syncfs:/mnt/t/f:$N \
                read:$blk:$N writefsync:/mnt/e/f:$NW; do
      IFS=: read -r op path n <<< "$spec"
      printf '%s\t%s\t' "$1" "$r"; taskset -c 1 $COST $op $path $n
    done
  done
}

bench without | tee $out/without-1.txt
OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration OTEL_EBPF_PROMETHEUS_PORT=9400 \
  OTEL_EBPF_STATS_AGENT_IP_IFACE=local OTEL_EBPF_LOG_LEVEL=info taskset -c 0 $OBI > $out/obi.log 2>&1 &
obi_pid=$!
for _ in $(seq 1 120); do
  curl -sf localhost:9400/metrics > /dev/null 2>&1 && break
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
curl -sf localhost:9400/metrics > /dev/null || { echo "obi did not start"; tail -30 $out/obi.log; exit 1; }
sleep 5
bench with | tee $out/with.txt

sysctl -qw kernel.bpf_stats_enabled=1
ROUNDS=1 bench stats > $out/stats-pass.txt
sysctl -qw kernel.bpf_stats_enabled=0
$STATS obi_stats | tee $out/bpfstats.txt
curl -sf localhost:9400/metrics > $out/metrics.txt
kill $obi_pid; wait $obi_pid 2>/dev/null
bench without | tee $out/without-2.txt

median() { # label op
  cat $out/*.txt | awk -F'\t' -v label="$1" -v op="$2:" '{ split($3, a, " ") } $1 == label && a[1] == op { print a[2] }' |
    sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'
}
{
  echo "### $(uname -r) ($(uname -m), $(nproc) CPUs), block device $blk"
  echo
  echo "| op | without OBI (ns/call) | with OBI | delta |"
  echo "|---|---|---|---|"
  for op in getppid fsync fdatasync syncfs read writefsync; do
    wo=$(median without $op); w=$(median with $op)
    echo "| $op | $wo | $w | $((w - wo)) |"
  done
  echo
  echo "eBPF program run time (bpf_stats, one pass):"
  echo '```'
  cat $out/bpfstats.txt
  echo '```'
  echo "file sync series: $(grep -c '^obi_stat_fs_sync_duration_seconds_count' $out/metrics.txt)"
} | tee $out/summary.md
