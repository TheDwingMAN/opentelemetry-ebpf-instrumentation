#!/bin/bash
# fsyncs on ext4 (over a loop device) and on tmpfs: system.filesystem.type must be ext4 on the first
# and absent on the second, which semantic conventions don't list
set -u
echo "uname -r: $(uname -r)"
fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }
PORT=9412
ip link set lo up
truncate -s 64M /tmp/disk.img
dev=$(losetup -f --show /tmp/disk.img)
mkfs.ext4 -q $dev && mkdir -p /mnt/ext4 /mnt/tmpfs && mount $dev /mnt/ext4 && mount -t tmpfs tmpfs /mnt/tmpfs
OTEL_EBPF_METRICS_FEATURES=stats_fs_sync_duration OTEL_EBPF_PROMETHEUS_PORT=$PORT OTEL_EBPF_STATS_AGENT_IP=127.0.0.1 \
  OTEL_EBPF_KUBE_METADATA_ENABLE=false OTEL_EBPF_BPF_BATCH_TIMEOUT=1s ./obi -config obi.yaml > "$LAB_RESULTS/obi.log" 2>&1 &
obi=$!
for _ in $(seq 1 300); do curl -sf localhost:$PORT/metrics > /dev/null && break; sleep 1; done
sleep 3
for _ in $(seq 1 5); do
  dd if=/dev/zero of=/mnt/ext4/f bs=4k count=1 conv=fsync,notrunc status=none
  dd if=/dev/zero of=/mnt/tmpfs/f bs=4k count=1 conv=fsync,notrunc status=none
done
sleep 6
series=$(curl -sf localhost:$PORT/metrics | grep '^obi_stat_fs_sync_duration_seconds_count')
echo "$series" | grep -F '/mnt/'
ext4=$(echo "$series" | grep -F 'system_filesystem_mountpoint="/mnt/ext4"')
tmpfs=$(echo "$series" | grep -F 'system_filesystem_mountpoint="/mnt/tmpfs"')
echo "$ext4" | grep -q 'system_filesystem_type="ext4"'; result ext4-type-reported $?
[ -n "$tmpfs" ]; result tmpfs-synced $?
# Prometheus exposes an attribute without a value as an empty label, which a scrape drops
! echo "$tmpfs" | grep -q 'system_filesystem_type="[^"]'; result tmpfs-type-omitted $?
kill $obi; wait $obi 2>/dev/null
exit $fail
