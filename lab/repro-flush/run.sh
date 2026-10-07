#!/bin/bash
# Reproduces the block request timing outliers of the dashboard run: OBI (built from the branch head)
# on an ext4 filesystem over a loop device, in three phases, each compared with /proc/diskstats:
#   1. direct writes, no flush
#   2. fsyncs of a file that didn't change: empty flushes
#   3. small writes, each followed by fsync: writes with a flush (journal commits)
# usage: run.sh <obi binary>
set -u
OBI=$1
PORT=9411
W=$(mktemp -d /var/tmp/repro-flush.XXXX)
truncate -s 256M $W/disk.img
dev=$(losetup -f --show $W/disk.img); d=$(basename $dev)
mkfs.ext4 -q $dev && mkdir -p $W/mnt && mount $dev $W/mnt
echo "device $d: scheduler $(cat /sys/block/$d/queue/scheduler), write cache: $(cat /sys/block/$d/queue/write_cache), wbt: $(cat /sys/block/$d/queue/wbt_lat_usec 2>/dev/null)"

OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=$PORT OTEL_EBPF_STATS_AGENT_IP=127.0.0.1 \
  OTEL_EBPF_KUBE_METADATA_ENABLE=false OTEL_EBPF_BPF_BATCH_TIMEOUT=1s "$OBI" > $W/obi.log 2>&1 &
obi=$!
for _ in $(seq 1 120); do curl -sf localhost:$PORT/metrics > /dev/null && break; sleep 1; done
sleep 5

metrics() { curl -sf localhost:$PORT/metrics | grep "system_device=\"$d\""; }
# kernel: writes completed, flushes completed
kernel() { awk -v d=$d '$3 == d { print $8, $19 }' /proc/diskstats; }
obi_sum() { metrics | grep "^$1{" | grep -F "$2" | awk '{ s += $2 } END { printf "%.6f", s }'; }
snapshot() {
  read -r kw kf < <(kernel)
  ow=$(obi_sum obi_stat_disk_operations_total 'disk_io_direction="write"')
  of=$(obi_sum obi_stat_disk_flush_duration_seconds_count '')
  ot=$(obi_sum obi_stat_disk_operation_time_seconds_total 'disk_io_direction="write"')
  slow=$(metrics | grep '^obi_stat_disk_operation_duration_seconds_bucket{' | grep 'disk_io_direction="write"' |
    awk '/le="\+Inf"/ { inf += $2 } /le="5"/ { five += $2 } END { printf "%d", inf - five }')
  wmax=$(metrics | grep '^obi_stat_disk_operation_duration_seconds_sum{' | grep 'disk_io_direction="write"' | awk '{ s += $2 } END { printf "%.3f", s }')
}
phase() { # name command...
  local name=$1; shift
  snapshot; k0w=$kw; k0f=$kf; o0w=$ow; o0f=$of; o0t=$ot; s0=$slow; l0=$wmax
  "$@"
  sleep 6
  snapshot
  printf '%-22s kernel writes %5d flushes %4d | obi writes %5d flushes %4d | obi write time %8.3fs, latency sum %8.3fs, writes over 5s %d\n' \
    "$name" $((kw - k0w)) $((kf - k0f)) $(printf '%.0f' "$(echo "$ow - $o0w" | bc)") $(printf '%.0f' "$(echo "$of - $o0f" | bc)") \
    "$(echo "$ot - $o0t" | bc)" "$(echo "$wmax - $l0" | bc)" $((slow - s0))
}
direct() { for _ in $(seq 1 20); do dd if=/dev/zero of=$dev bs=4k count=25 seek=50000 oflag=direct status=none; done; }
echo data > $W/mnt/f; sync
empty_fsyncs() { for _ in $(seq 1 200); do python3 -c "import os; f=os.open('$W/mnt/f', os.O_RDONLY); os.fsync(f)"; done; }
write_fsyncs() { for i in $(seq 1 200); do python3 -c "import os; f=os.open('$W/mnt/g', os.O_WRONLY|os.O_CREAT); os.write(f, b'x' * 4096); os.fsync(f)"; done; }
phase "1 direct writes" direct
phase "2 empty fsyncs" empty_fsyncs
phase "3 write+fsync" write_fsyncs
phase "1 direct writes again" direct

kill $obi; wait $obi 2>/dev/null
umount $W/mnt; losetup -d $dev; rm -rf $W
