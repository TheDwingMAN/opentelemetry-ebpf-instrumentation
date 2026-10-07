#!/bin/bash
# VM soak of every storage feature: stats_disk, stats_fs_sync_duration and stats_nfs, with all
# opt-in attributes, for SOAK_MIN minutes, while LVM volumes and md arrays are created and
# removed, files are written and synced on ext4 and NFS, and NFS lookups fail with ENOENT.
# A steady direct-I/O load on null_blk is checked against /proc/diskstats.
# Before the soak, the cost of the file sync probes is measured with fio (relative only: TCG).
set -u
SOAK_MIN=${SOAK_MIN:-90}
echo "uname -r: $(uname -r)  cpus: $(nproc)  soak: ${SOAK_MIN} min"
export DM_DISABLE_UDEV=1

modprobe null_blk nr_devices=0
cfg=/sys/kernel/config/nullb/steady
mkdir -p $cfg; echo 256 > $cfg/size
before=$(ls /sys/block); echo 1 > $cfg/power
dev=$(comm -13 <(echo "$before") <(ls /sys/block) | head -1)

truncate -s 256M /tmp/lvm.img /tmp/fs.img
lvm_pv=$(losetup -f --show /tmp/lvm.img)
pvcreate -qq "$lvm_pv" && vgcreate -qq obivg "$lvm_pv"
mkfs.ext4 -q -F /tmp/fs.img; mkdir -p /mnt/obifs; mount -o loop /tmp/fs.img /mnt/obifs

modprobe nfs; modprobe nfsd
ip link set lo up; mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs || echo "can't mount NFS"

fsync_iops() {
  fio --name=fsync --directory=/mnt/obifs --size=32M --ioengine=sync --rw=randwrite --bs=4k --fsync=1 \
    --time_based --runtime=30 --output-format=json 2>/dev/null |
    python3 -c 'import json,sys; j=json.load(sys.stdin)["jobs"][0]; print(round(j["write"]["iops"]))' 2>/dev/null ||
    fio --name=fsync --directory=/mnt/obifs --size=32M --ioengine=sync --rw=randwrite --bs=4k --fsync=1 \
      --time_based --runtime=30 --minimal 2>/dev/null | awk -F';' '{ print $49 }'
}
f0=$(fsync_iops); f1=$(fsync_iops)

cat > /tmp/obi.yml << 'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
    obi.stat.disk.io:
      include: ["*"]
    obi.stat.disk.operation.duration:
      include: ["*"]
    obi.stat.fs.sync.duration:
      include: ["*"]
    obi.stat.nfs.client.procedure.duration:
      include: ["*"]
    obi.stat.nfs.client.io:
      include: ["*"]
    obi.stat.disk.operation.time:
      include: ["*"]
    obi.stat.disk.queue.duration:
      include: ["*"]
    obi.stat.disk.flush.duration:
      include: ["*"]
    obi.stat.disk.discard.duration:
      include: ["*"]
    obi.stat.disk.discard.io:
      include: ["*"]
    obi.stat.disk.pending_operations:
      include: ["*"]
YML
OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration,stats_nfs OTEL_EBPF_PROMETHEUS_PORT=9400 \
  OTEL_EBPF_PROFILE_PORT=6060 OTEL_EBPF_LOG_LEVEL=info OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi -config /tmp/obi.yml > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
for _ in $(seq 1 300); do curl -sf localhost:9400/metrics > /dev/null 2>&1 && break; sleep 1; done
curl -sf localhost:9400/metrics > /dev/null || { echo "obi did not start"; tail -20 "$LAB_RESULTS/obi.log"; exit 1; }
sleep 5

f2=$(fsync_iops); f3=$(fsync_iops)
echo "fsync IOPS without OBI: $f0 $f1   with OBI: $f2 $f3"

metrics() { curl -sf localhost:9400/metrics; }
obi_sum() { # metric direction
  metrics | grep "^$1{" | grep -F "system_device=\"$dev\"" | grep -F "disk_io_direction=\"$2\"" |
    awk '{ s += $2 } END { printf "%.0f", s }'
}
kernel_counts() { awk -v d="$dev" '$3 == d { printf "%d %d", $4, $8 }' /proc/diskstats; }
obi_counts() { printf '%s %s' "$(obi_sum obi_stat_disk_operations_total read)" "$(obi_sum obi_stat_disk_operations_total write)"; }
read -r k0r k0w < <(kernel_counts)
read -r o0r o0w < <(obi_counts)

fio --name=steady --filename=/dev/$dev --direct=1 --ioengine=libaio --rw=randrw --bs=4k --iodepth=4 \
  --rate_iops=150,50 --time_based --runtime=$((SOAK_MIN * 60)) > /dev/null 2>&1 &
fio_pid=$!

churn() {
  local i=0 a b
  while true; do
    i=$((i + 1))
    lvcreate -qq -y -n "lv$i" -L 8M obivg 2>/dev/null &&
      dd if=/dev/zero of="/dev/obivg/lv$i" bs=64k count=32 oflag=direct status=none 2>/dev/null
    lvremove -qq -y "obivg/lv$i" 2>/dev/null
    truncate -s 32M /tmp/md-a.img /tmp/md-b.img
    a=$(losetup -f --show /tmp/md-a.img); b=$(losetup -f --show /tmp/md-b.img)
    mdadm --create /dev/md1 --level=1 --raid-devices=2 --run --quiet --metadata=1.2 "$a" "$b" 2>/dev/null &&
      dd if=/dev/zero of=/dev/md1 bs=64k count=32 oflag=direct status=none
    mdadm --stop /dev/md1 --quiet 2>/dev/null
    losetup -d "$a" "$b"
    fio --name=churn --directory=/mnt/obifs --size=4M --ioengine=sync --rw=randwrite --bs=4k --fdatasync=1 \
      --time_based --runtime=3 > /dev/null 2>&1
    sync -f /mnt/obifs 2>/dev/null
    [ $((i % 5)) -eq 0 ] && sync
    dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 conv=fsync status=none 2>/dev/null
    dd if=/mnt/nfs/f of=/dev/null bs=64k iflag=direct status=none 2>/dev/null
    stat /mnt/nfs/missing-$i > /dev/null 2>&1
    rm -f /mnt/nfs/f
    echo "$i" > /tmp/churn-iterations
    sleep 1
  done
}
churn &
churn_pid=$!

printf 'min\trss_mb\tcpu_s\tgoroutines\theap_inuse_mb\tseries\twarnings\tmaps\tsteady_kernel_r/w\tsteady_obi_r/w\n' > "$LAB_RESULTS/soak.tsv"
hz=$(getconf CLK_TCK)
for min in $(seq 1 "$SOAK_MIN"); do
  sleep 60
  kill -0 $obi_pid 2>/dev/null || { echo "OBI exited" | tee -a "$LAB_RESULTS/soak.tsv"; break; }
  rss=$(awk '/^VmRSS/ { printf "%.0f", $2 / 1024 }' /proc/$obi_pid/status)
  cpu=$(awk -v hz="$hz" '{ printf "%.0f", ($14 + $15) / hz }' /proc/$obi_pid/stat)
  gor=$(curl -sf "localhost:6060/debug/pprof/goroutine?debug=1" | head -1 | awk '{ print $NF }')
  heap=$(curl -sf "localhost:6060/debug/pprof/heap?debug=1" | awk '/^# HeapInuse = / { printf "%.0f", $4 / 1048576 }')
  series=$(metrics | grep -c '^obi_stat')
  warns=$(grep -c 'level=WARN\|level=ERROR' "$LAB_RESULTS/obi.log")
  maps=$(./bpfmaps disk_ fs_sync nfs_ | awk '{ printf "%s=%s/%s,", $1, $2, $3 }')
  read -r k1r k1w < <(kernel_counts)
  read -r o1r o1w < <(obi_counts)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\t%s/%s\n' "$min" "$rss" "$cpu" "$gor" "$heap" "$series" "$warns" \
    "$maps" $((k1r - k0r)) $((k1w - k0w)) $((o1r - o0r)) $((o1w - o0w)) >> "$LAB_RESULTS/soak.tsv"
  [ $((min % 10)) -eq 0 ] && tail -1 "$LAB_RESULTS/soak.tsv"
done

kill $churn_pid $fio_pid 2>/dev/null; wait $churn_pid $fio_pid 2>/dev/null
sleep 5
read -r k1r k1w < <(kernel_counts)
read -r o1r o1w < <(obi_counts)
echo "churn iterations: $(cat /tmp/churn-iterations)"
echo "steady device: kernel reads=$((k1r - k0r)) writes=$((k1w - k0w)); obi reads=$((o1r - o0r)) writes=$((o1w - o0w))"
metrics > "$LAB_RESULTS/metrics-final.txt"
echo "series by metric:"; grep -o '^obi_stat_[a-z_]*' "$LAB_RESULTS/metrics-final.txt" | sort | uniq -c
echo "warnings:"; grep 'level=WARN\|level=ERROR' "$LAB_RESULTS/obi.log" | sed 's/time=[^ ]* //' | sort | uniq -c | sort -rn | head -10
head -2 "$LAB_RESULTS/soak.tsv" | tail -1; tail -1 "$LAB_RESULTS/soak.tsv"
kill $obi_pid
[ $((k1r - k0r)) -eq $((o1r - o0r)) ] && [ $((k1w - k0w)) -eq $((o1w - o0w)) ]
