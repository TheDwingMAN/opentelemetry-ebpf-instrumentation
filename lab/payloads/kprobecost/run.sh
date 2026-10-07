#!/bin/bash
# Cost of OBI's file sync kprobes, next to the block tracepoints, on a kernel that has kprobes.
#
# Times system calls with and without OBI (stats_disk + stats_fs_sync_duration), the bench on
# CPU 1 and OBI on CPU 0: fsync, fdatasync and syncfs of a tmpfs file (the file system does
# nothing, so the probes are most of the cost), 4 KiB direct reads of a null_blk device (block
# tracepoints) and getppid (no probe, the noise floor). Then the run time of each eBPF program
# from the kernel's bpf_stats. Under TCG, absolute numbers are inflated: compare the ratios.
set -u
echo "uname -r: $(uname -r)  cpus: $(nproc)"
N=${N:-20000}
ROUNDS=${ROUNDS:-3}
OPS="getppid fsync fdatasync syncfs read"

modprobe null_blk nr_devices=0 || { echo "no null_blk"; exit 1; }
mkdir -p /sys/kernel/config/nullb/fast
echo 64 > /sys/kernel/config/nullb/fast/size
before=$(ls /sys/block); echo 1 > /sys/kernel/config/nullb/fast/power
dev=$(comm -13 <(echo "$before") <(ls /sys/block) | head -1)
mkdir -p /mnt/t && mount -t tmpfs tmpfs /mnt/t && : > /mnt/t/f
echo "block device: $dev, scheduler: $(cat /sys/block/$dev/queue/scheduler)"

bench() { # label
  for op in $OPS; do
    path=/mnt/t/f; [ $op = read ] && path=/dev/$dev
    for r in $(seq 1 $ROUNDS); do
      printf '%s\t%s\t' "$1" "$r"; taskset -c 1 ./kprobecost $op $path $N
    done
  done
}

bench without | tee "$LAB_RESULTS/without-1.txt"

OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration OTEL_EBPF_PROMETHEUS_PORT=9400 \
  OTEL_EBPF_LOG_LEVEL=info OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  taskset -c 0 ./obi > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
for _ in $(seq 1 600); do curl -sf localhost:9400/metrics > /dev/null 2>&1 && break; sleep 1; done
curl -sf localhost:9400/metrics > /dev/null || { echo "obi did not start"; tail -20 "$LAB_RESULTS/obi.log"; exit 1; }
sleep 5

bench with | tee "$LAB_RESULTS/with.txt"

echo "##### eBPF program run time (bpf_stats)"
sysctl -qw kernel.bpf_stats_enabled=1
ROUNDS=1 bench stats > /dev/null
sysctl -qw kernel.bpf_stats_enabled=0
./bpfstats obi_stats | tee "$LAB_RESULTS/bpfstats.txt"
echo "(each op ran $N times in that pass)"
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

bench without | tee "$LAB_RESULTS/without-2.txt"

echo "##### summary: median ns per call"
median() { # label op, from the bench outputs
  cat "$LAB_RESULTS"/*.txt | awk -F'\t' -v label="$1" -v op="$2:" '{ split($3, a, " ") } $1 == label && a[1] == op { print a[2] }' |
    sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'
}
for op in $OPS; do
  wo=$(median without $op); w=$(median with $op)
  echo "$op: without=${wo} ns with=${w} ns delta=$((w - wo)) ns"
done
grep -c '^obi_stat_fs_sync_duration_seconds_count' "$LAB_RESULTS/metrics.txt" | sed 's/^/fs sync series: /'
