#!/bin/bash
# Soak test of OBI's storage stats on this host.
#
# OBI runs with $FEATURES (default stats_disk: this host has no kprobes), with every opt-in attribute
# selected (container.id, partition, mountpoint...), for SOAK_SECONDS. Meanwhile:
#   - a steady fio load on one loop device, whose counts OBI must match with /proc/diskstats;
#   - churn: loop devices (some partitioned) created, formatted, mounted, fsynced and removed,
#     so device numbers are reused; short-lived docker containers doing direct I/O and syncs.
# Every minute: OBI RSS, CPU, goroutines, heap, fds, series count, BPF map fill, warnings,
# and the accuracy of the steady device.
set -u
LAB="$(cd "$(dirname "$0")/.." && pwd)"
OUT=${OUT:-$LAB/soak/run-$(date +%Y%m%d-%H%M%S)}
OBI=${OBI:-$LAB/bench/obi}
SOAK_SECONDS=${SOAK_SECONDS:-10800}
PORT=9413
PPROF=6061
mkdir -p "$OUT"

if ! docker info > /dev/null 2>&1; then
  nohup dockerd > "$OUT/dockerd.log" 2>&1 &
  for _ in $(seq 1 60); do docker info > /dev/null 2>&1 && break; sleep 1; done
fi

acc_img=/dev/shm/soak-acc.img
truncate -s 512M $acc_img
acc=$(losetup -f --show $acc_img)
acc_dev=$(basename "$acc")
dd if=/dev/urandom of="$acc" bs=1M count=512 oflag=direct status=none

cat > "$OUT/obi.yml" << 'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
    obi.stat.disk.io:
      include: ["*"]
    obi.stat.disk.operation.duration:
      include: ["*"]
    obi.stat.disk.operation.time:
      include: ["*"]
    obi.stat.fs.sync.duration:
      include: ["*"]
YML
OTEL_EBPF_METRICS_FEATURES=${FEATURES:-stats_disk} OTEL_EBPF_PROMETHEUS_PORT=$PORT \
  OTEL_EBPF_PROFILE_PORT=$PPROF OTEL_EBPF_STATS_AGENT_IP=10.0.0.1 OTEL_EBPF_LOG_LEVEL=info \
  "$OBI" -config "$OUT/obi.yml" > "$OUT/obi.log" 2>&1 &
obi_pid=$!
for _ in $(seq 1 90); do curl -sf "localhost:$PORT/metrics" > /dev/null && break; sleep 1; done
sleep 5

churn_pid=
fio_pid=
cleanup() {
  [ -n "$churn_pid" ] && kill "$churn_pid" 2>/dev/null
  [ -n "$fio_pid" ] && kill "$fio_pid" 2>/dev/null
  wait 2>/dev/null
  kill "$obi_pid" 2>/dev/null
  umount /mnt/soak-churn 2>/dev/null
  losetup -d "$acc" 2>/dev/null
  rm -f $acc_img /dev/shm/soak-churn.img
}
trap cleanup EXIT

metrics() { curl -sf "localhost:$PORT/metrics"; }
obi_sum() { # metric direction
  metrics | grep "^$1{" | grep -F "system_device=\"$acc_dev\"" | grep -F "disk_io_direction=\"$2\"" |
    awk '{ s += $2 } END { printf "%.0f", s }'
}
# reads, read bytes, writes, written bytes
kernel_counts() { awk -v d="$acc_dev" '$3 == d { printf "%d %d %d %d", $4, $6 * 512, $8, $10 * 512 }' /proc/diskstats; }
obi_counts() {
  printf '%s %s %s %s' "$(obi_sum obi_stat_disk_operations_total read)" "$(obi_sum obi_stat_disk_io_bytes_total read)" \
    "$(obi_sum obi_stat_disk_operations_total write)" "$(obi_sum obi_stat_disk_io_bytes_total write)"
}

read -r k0r k0rb k0w k0wb < <(kernel_counts)
read -r o0r o0rb o0w o0wb < <(obi_counts)

fio --name=steady --filename="$acc" --direct=1 --ioengine=libaio --rw=randrw --rwmixread=70 \
  --bs=4k --iodepth=8 --rate_iops=1400,600 --time_based --runtime="$SOAK_SECONDS" > "$OUT/fio-steady.log" 2>&1 &
fio_pid=$!

churn() {
  local i=0 img=/dev/shm/soak-churn.img mnt=/mnt/soak-churn dev part
  mkdir -p $mnt
  while true; do
    i=$((i + 1))
    truncate -s 64M $img
    if [ $((i % 3)) -eq 0 ]; then
      printf 'label: dos\n2048,,83\n' | sfdisk -q $img
      dev=$(losetup -f --show -P $img)
      part=${dev}p1
      for _ in $(seq 1 20); do [ -e "/sys/class/block/$(basename "$part")/dev" ] && break; sleep 0.1; done
      # without devtmpfs or udev, make the partition's node from its numbers in sysfs
      [ -b "$part" ] || mknod "$part" b $(tr ':' ' ' < "/sys/class/block/$(basename "$part")/dev")
    else
      dev=$(losetup -f --show $img)
      part=$dev
    fi
    mkfs.ext4 -q -F "$part" && mount "$part" $mnt &&
      fio --name=churn --directory=$mnt --size=16M --ioengine=sync --rw=randwrite --bs=4k \
        --fsync=1 --time_based --runtime=5 > /dev/null 2>&1
    sync -f $mnt/churn.0.0 2> /dev/null
    [ $((i % 10)) -eq 0 ] && sync
    umount $mnt
    losetup -d "$dev"
    rm -f $img
    docker run --rm docker.io/library/busybox:1.37 sh -c 'dd if=/dev/zero of=/tmp/f bs=4k count=2000 oflag=direct 2>/dev/null; sync' > /dev/null 2>&1
    echo "$i" > "$OUT/churn-iterations"
    sleep 2
  done
}
churn &
churn_pid=$!

hz=$(getconf CLK_TCK)
printf 'min\trss_mb\tcpu_s\tgoroutines\theap_inuse_mb\tfds\tseries\twarnings\tmaps\tacc_kernel_r_w\tacc_obi_r_w\tacc_err_pct\n' > "$OUT/soak.tsv"
start=$(date +%s)
while [ $(($(date +%s) - start)) -lt "$SOAK_SECONDS" ]; do
  sleep 60
  kill -0 "$obi_pid" 2> /dev/null || { echo "OBI exited" >> "$OUT/soak.tsv"; break; }
  min=$((($(date +%s) - start) / 60))
  rss=$(awk '/^VmRSS/ { printf "%.0f", $2 / 1024 }' "/proc/$obi_pid/status")
  cpu=$(awk -v hz="$hz" '{ printf "%.0f", ($14 + $15) / hz }' "/proc/$obi_pid/stat")
  gor=$(curl -sf "localhost:$PPROF/debug/pprof/goroutine?debug=1" | head -1 | awk '{ print $NF }')
  heap=$(curl -sf "localhost:$PPROF/debug/pprof/heap?debug=1" | awk '/^# HeapInuse = / { printf "%.0f", $4 / 1048576 }')
  fds=$(ls "/proc/$obi_pid/fd" | wc -l)
  series=$(metrics | grep -c '^obi_stat')
  warns=$(grep -c 'level=WARN\|level=ERROR' "$OUT/obi.log")
  maps=$("$LAB/bpfmaps/bpfmaps" disk_ fs_sync nfs_ | awk '{ printf "%s=%s/%s,", $1, $2, $3 }')
  read -r k1r k1rb k1w k1wb < <(kernel_counts)
  read -r o1r o1rb o1w o1wb < <(obi_counts)
  kr=$((k1r - k0r)); kw=$((k1w - k0w)); orr=$((o1r - o0r)); ow=$((o1w - o0w))
  err=$(awk -v k=$((kr + kw)) -v o=$((orr + ow)) 'BEGIN { printf "%.3f", k ? 100 * (o - k) / k : 0 }')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\t%s/%s\t%s\n' "$min" "$rss" "$cpu" "$gor" "$heap" "$fds" \
    "$series" "$warns" "$maps" "$kr" "$kw" "$orr" "$ow" "$err" >> "$OUT/soak.tsv"
done

# Exact comparison once the steady load stopped.
kill "$fio_pid" 2>/dev/null; wait "$fio_pid" 2>/dev/null; fio_pid=
sleep 5
read -r k1r k1rb k1w k1wb < <(kernel_counts)
read -r o1r o1rb o1w o1wb < <(obi_counts)
{
  echo "final: kernel reads=$((k1r - k0r)) bytes=$((k1rb - k0rb)) writes=$((k1w - k0w)) bytes=$((k1wb - k0wb))"
  echo "final: obi    reads=$((o1r - o0r)) bytes=$((o1rb - o0rb)) writes=$((o1w - o0w)) bytes=$((o1wb - o0wb))"
  echo "churn iterations: $(cat "$OUT/churn-iterations" 2>/dev/null)"
  grep 'level=WARN\|level=ERROR' "$OUT/obi.log" | sed 's/time=[^ ]* //' | sort | uniq -c | sort -rn | head -20
} > "$OUT/summary.txt"
metrics > "$OUT/metrics-final.txt"
curl -sf "localhost:$PPROF/debug/pprof/heap" > "$OUT/heap.pprof"
cat "$OUT/summary.txt"
