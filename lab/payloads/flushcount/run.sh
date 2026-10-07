#!/bin/bash
# OBI (with the flush sequence fix) on ext4 over a loop device, compared with /proc/diskstats:
#   1. direct writes, no flush
#   2. fsyncs of a file that didn't change: empty flushes, which the device never sees
#   3. small writes, each followed by fsync: journal writes with a cache flush before or after them
# Writes and flushes must be counted as the kernel counts them, and no write may take 5 s or more.
set -u
echo "uname -r: $(uname -r)"
fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }
PORT=9411
ip link set lo up
truncate -s 256M /tmp/disk.img
dev=$(losetup -f --show /tmp/disk.img); d=$(basename $dev)
mkfs.ext4 -q -E lazy_itable_init=0,lazy_journal_init=0 $dev && mkdir -p /mnt/fs && mount $dev /mnt/fs
echo "device $d: write cache $(cat /sys/block/$d/queue/write_cache 2>/dev/null), wbt $(cat /sys/block/$d/queue/wbt_lat_usec 2>/dev/null)"

OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=$PORT OTEL_EBPF_STATS_AGENT_IP=127.0.0.1 \
  OTEL_EBPF_KUBE_METADATA_ENABLE=false OTEL_EBPF_BPF_BATCH_TIMEOUT=1s ./obi > "$LAB_RESULTS/obi.log" 2>&1 &
obi=$!
for _ in $(seq 1 300); do curl -sf localhost:$PORT/metrics > /dev/null && break; sleep 1; done
grep -q 'starting OBI in Stat metrics mode' "$LAB_RESULTS/obi.log"; result obi-started $?

metrics() { curl -sf localhost:$PORT/metrics | grep "system_device=\"$d\""; }
obi_sum() { metrics | grep "^$1{" | grep -F "$2" | awk '{ s += $2 } END { printf "%d", s + 0.5 }'; }
obi_slow() {
  metrics | grep '^obi_stat_disk_operation_duration_seconds_bucket{' | grep 'disk_io_direction="write"' |
    awk '/le="\+Inf"/ { inf += $2 } /le="5"/ { five += $2 } END { printf "%d", inf - five }'
}
has_flushes=$(awk -v d=$d '$3 == d { print (NF >= 20) }' /proc/diskstats)
snapshot() {
  read -r kw kf < <(awk -v d=$d '$3 == d { print $8, (NF >= 20 ? $19 : 0) }' /proc/diskstats)
  ow=$(obi_sum obi_stat_disk_operations_total 'disk_io_direction="write"')
  of=$(obi_sum obi_stat_disk_flush_duration_seconds_count '')
  slow=$(obi_slow)
}
phase() { # name command...
  local name=$1; shift
  snapshot; local k0w=$kw k0f=$kf o0w=$ow o0f=$of s0=$slow
  "$@"
  sleep 6
  snapshot
  echo "$name: kernel writes $((kw - k0w)) flushes $((kf - k0f)) | obi writes $((ow - o0w)) flushes $((of - o0f)) | writes of 5s or more $((slow - s0))"
  [ $((kw - k0w)) -eq $((ow - o0w)) ]; result "$name-writes" $?
  if [ "$has_flushes" = 1 ]; then [ $((kf - k0f)) -eq $((of - o0f)) ]; result "$name-flushes" $?; fi
  [ $((slow - s0)) -eq 0 ]; result "$name-no-outliers" $?
}
direct() { for _ in $(seq 1 20); do dd if=/dev/zero of=$dev bs=4k count=25 seek=50000 oflag=direct status=none; done; }
echo data > /mnt/fs/f; sync; sleep 8
empty_fsyncs() { for _ in $(seq 1 100); do sync /mnt/fs/f; done; }
write_fsyncs() { for _ in $(seq 1 100); do dd if=/dev/zero of=/mnt/fs/g bs=4k count=1 conv=fsync,notrunc status=none; done; }
phase direct direct
phase empty-fsyncs empty_fsyncs
phase write-fsyncs write_fsyncs
phase direct-again direct
grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -8
kill $obi; wait $obi 2>/dev/null
exit $fail
