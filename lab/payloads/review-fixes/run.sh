#!/bin/bash
# review fixes payload: privileged tests, obi end to end (queue, flush, discard,
# pending, partitions) on null_blk and loop devices.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { # name rc
  if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi
}


step "privileged tests"
./stats.test -test.v -test.run 'TestDisk|TestFsSync|TestNFS' -test.timeout 10m > "$LAB_RESULTS/privileged.log" 2>&1
rc=$?; grep -E '^(--- |ok|FAIL|PASS)|Error:|Messages|tracer_disk' "$LAB_RESULTS/privileged.log" | grep -v 'TestDiskReader\|TestDiskErrorType\|TestDiskIOWriterProcess\|TestFsSyncReader\|TestFsSyncerProcess' | head -30
result privileged $rc

step "obi end to end"
modprobe -r null_blk 2>/dev/null
modprobe null_blk nr_devices=0 || { echo "no null_blk"; result e2e 1; exit 1; }
mkdir -p /sys/kernel/config/nullb/ok
echo 64 > /sys/kernel/config/nullb/ok/size
before=$(ls /sys/block); echo 1 > /sys/kernel/config/nullb/ok/power
ok_dev=$(comm -13 <(echo "$before") <(ls /sys/block) | head -1)
# a loop device with a partition, for flushes, discards and partitions
truncate -s 64M /tmp/disk.img
printf 'label: dos\n2048,65536,83\n' | sfdisk -q /tmp/disk.img
loop=$(losetup -f --show -P /tmp/disk.img); loop_dev=$(basename $loop)
# losetup -P (LOOP_CONFIGURE) doesn't scan partitions on Linux 5.8: ask the kernel to read them
[ -e /sys/class/block/${loop_dev}p1 ] || blockdev --rereadpt $loop
for _ in $(seq 1 50); do [ -e /sys/class/block/${loop_dev}p1/dev ] && break; sleep 0.1; done
# /dev may not have the partition node yet: create it from its numbers in sysfs
part_node=/tmp/${loop_dev}p1
mknod $part_node b $(tr ':' ' ' < /sys/class/block/${loop_dev}p1/dev) || echo "no partition on $loop_dev"
# an LVM volume and an md RAID volume on other loop devices, for stacked volumes
export DM_DISABLE_UDEV=1
truncate -s 64M /tmp/lvm.img /tmp/md1.img /tmp/md2.img
lvm_pv=$(losetup -f --show /tmp/lvm.img)
pvcreate -qq $lvm_pv && vgcreate -qq obivg $lvm_pv && lvcreate -qq -y -n lv -L 32M obivg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname obivg-lv)
[ -b /dev/$lv_dev ] || mknod /dev/$lv_dev b $(tr ':' ' ' < /sys/class/block/$lv_dev/dev)
md1=$(losetup -f --show /tmp/md1.img); md2=$(losetup -f --show /tmp/md2.img)
mdadm --create /dev/md0 --level=0 --raid-devices=2 --run --quiet $md1 $md2 2>&1 | tail -1
echo "stacked volumes: LVM $lv_dev on $(basename $lvm_pv), md0 on $(basename $md1) $(basename $md2)"
# an ext4 filesystem, for the file syncs
truncate -s 64M /tmp/fs.img; mkfs.ext4 -q -F /tmp/fs.img
mkdir -p /mnt/obifs; mount -o loop /tmp/fs.img /mnt/obifs || echo "can't mount ext4"
# a loopback NFSv4.2 mount, before OBI starts so that the sunrpc and nfs modules are loaded
modprobe nfs; modprobe nfsd
ip link set lo up; mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs && nfs_ok=1 || { nfs_ok=0; echo "can't mount NFS"; }
cat > /tmp/obi.yml <<'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
    obi.stat.fs.sync.duration:
      include: ["*"]
YML
OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration,stats_nfs OTEL_EBPF_PROMETHEUS_PORT=9400 \
OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms OTEL_EBPF_LOG_LEVEL=debug OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
  ./obi -config /tmp/obi.yml > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 180); do
  if curl -sf localhost:9400/metrics >/dev/null 2>&1; then up=1; break; fi
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
[ $up -eq 1 ] || { echo "obi did not start"; tail -30 "$LAB_RESULTS/obi.log"; result e2e 1; exit 1; }
sleep 3 # let the probes attach

dd if=/dev/zero of=/dev/$ok_dev bs=4k count=200 oflag=direct status=none
dd if=/dev/$ok_dev of=/dev/null bs=4k count=300 iflag=direct status=none
dd if=/dev/zero of=$part_node bs=64k count=16 oflag=direct status=none
blkdiscard -f -o 0 -l 1048576 $loop 2>&1 && discard_ok=1 || discard_ok=0
dd if=/dev/zero of=$loop bs=4k count=1 seek=12000 conv=fsync status=none
dd if=/dev/zero of=/dev/$lv_dev bs=64k count=32 oflag=direct status=none
dd if=/dev/zero of=/dev/md0 bs=64k count=16 oflag=direct status=none
echo data > /mnt/obifs/f
sync /mnt/obifs/f; sync -d /mnt/obifs/f; sync -f /mnt/obifs/f; sync
if [ $nfs_ok = 1 ]; then
  dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
  dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
  ls /mnt/nfs/nonexistent 2>/dev/null
fi
sleep 3
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

sum() { # metric, then label filters (key="value")
  local metric=$1; shift
  local lines; lines=$(grep "^${metric}{" "$LAB_RESULTS/metrics.txt")
  for f in "$@"; do lines=$(echo "$lines" | grep -F "$f"); done
  echo "$lines" | awk 'NF {s+=$2} END {printf "%d", s}'
}
qw=$(sum obi_stat_disk_queue_duration_seconds_count "system_device=\"$ok_dev\"" 'disk_io_direction="write"')
qr=$(sum obi_stat_disk_queue_duration_seconds_count "system_device=\"$ok_dev\"" 'disk_io_direction="read"')
echo "queue: writes=$qw (want 200) reads=$qr (want 300)"
[ "$qw" = 200 ] && [ "$qr" = 300 ]; result e2e-queue $?

if [ -b $part_node ]; then
  part=$(sum obi_stat_disk_operations_total "system_device=\"$loop_dev\"" "obi_disk_partition=\"${loop_dev}p1\"" 'disk_io_direction="write"')
  echo "partition: writes on ${loop_dev}p1=$part (want 16)"
  [ "$part" = 16 ]; result e2e-partition $?
else
  echo "partition: losetup can't enable partitions on this kernel (TestDiskPartitions covers them)"
fi

flushes=$(sum obi_stat_disk_flush_duration_seconds_count "system_device=\"$loop_dev\"")
echo "flush: $flushes (want >=1)"
[ "$flushes" -ge 1 ]; result e2e-flush $?

if [ $discard_ok = 1 ]; then
  dbytes=$(sum obi_stat_disk_discard_io_bytes_total "system_device=\"$loop_dev\"")
  dops=$(sum obi_stat_disk_discard_duration_seconds_count "system_device=\"$loop_dev\"")
  echo "discard: bytes=$dbytes (want 1048576) requests=$dops (want >=1)"
  [ "$dbytes" = 1048576 ] && [ "$dops" -ge 1 ]; result e2e-discard $?
else
  echo "discard: not supported by the loop device on this kernel"
fi

pending=$(grep -c "^obi_stat_disk_pending_operations{.*system_device=\"$ok_dev\"" "$LAB_RESULTS/metrics.txt")
echo "pending: series of $ok_dev=$pending (want 2: read and write, now 0)"
[ "$pending" = 2 ] && [ "$(sum obi_stat_disk_pending_operations "system_device=\"$ok_dev\"")" = 0 ]; result e2e-pending $?

lvw=$(sum obi_stat_disk_operations_total "system_device=\"$lv_dev\"" 'obi_disk_stacked="true"' 'disk_io_direction="write"')
lvb=$(sum obi_stat_disk_io_bytes_total "system_device=\"$lv_dev\"" 'obi_disk_stacked="true"' 'disk_io_direction="write"')
echo "LVM volume: writes=$lvw (want 32) bytes=$lvb (want 2097152)"
[ "$lvw" = 32 ] && [ "$lvb" = 2097152 ]; result e2e-lvm $?
mdw=$(sum obi_stat_disk_operations_total 'system_device="md0"' 'obi_disk_stacked="true"' 'disk_io_direction="write"')
kmaj=$(uname -r | cut -d. -f1); kmin=$(uname -r | cut -d. -f2)
if [ "$kmaj" -gt 5 ] || { [ "$kmaj" = 5 ] && [ "$kmin" -ge 15 ]; }; then
  echo "md volume: writes=$mdw (want >=16)"
  [ "$mdw" -ge 16 ]; result e2e-md $?
else
  echo "md volume: writes=$mdw (md needs Linux 5.15+)"
fi
stacked_loop=$(grep -c "^obi_stat_disk_operations_total{.*obi_disk_stacked=\"true\".*system_device=\"$loop_dev\"" "$LAB_RESULTS/metrics.txt")
plain_null=$(grep -c "^obi_stat_disk_operations_total{.*obi_disk_stacked=\"false\".*system_device=\"$ok_dev\"" "$LAB_RESULTS/metrics.txt")
echo "stacked label: loop series stacked=$stacked_loop (want >=1), null_blk series not stacked=$plain_null (want >=1)"
[ "$stacked_loop" -ge 1 ] && [ "$plain_null" -ge 1 ]; result e2e-stacked-label $?
for t in fsync fdatasync syncfs; do
  n=$(sum obi_stat_fs_sync_duration_seconds_count "obi_fs_sync_type=\"$t\"" 'system_filesystem_mountpoint="/mnt/obifs"' 'system_filesystem_type="ext4"')
  echo "file sync: $t on /mnt/obifs=$n (want 1)"
  [ "$n" = 1 ]; result e2e-fs-sync-$t $?
done
n=$(grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | grep 'obi_fs_sync_type="sync"' | grep -v 'system_filesystem_mountpoint="/' | awk '{s+=$2} END {printf "%d", s}')
echo "file sync: sync=$n without mountpoint (want >=1)"
[ "$n" -ge 1 ]; result e2e-fs-sync-sync $?
nfs_btf=1
if grep -q "doesn't describe the sunrpc types" "$LAB_RESULTS/obi.log"; then
  nfs_btf=0; echo "NFS: the kernel has no BTF for the sunrpc types, so the NFS metrics are disabled (expected before 5.11 with sunrpc as a module)"
elif grep -q "can't tell the arguments of rpc_" "$LAB_RESULTS/obi.log"; then
  nfs_btf=0; echo "NFS: no module BTF to check the tracepoint arguments on a kernel older than 5.8, so the NFS metrics are disabled (expected on RHEL 8)"
fi
if [ $nfs_ok = 1 ] && [ $nfs_btf = 1 ]; then
  nfs_tx=$(sum obi_stat_nfs_client_io_bytes_total 'server_address="127.0.0.1"' 'network_io_direction="transmit"')
  nfs_rx=$(sum obi_stat_nfs_client_io_bytes_total 'server_address="127.0.0.1"' 'network_io_direction="receive"')
  echo "NFS io: written=$nfs_tx read=$nfs_rx (want 1048576 each)"
  [ "$nfs_tx" = 1048576 ] && [ "$nfs_rx" = 1048576 ]; result e2e-nfs-io $?
  nfs_writes=$(sum obi_stat_nfs_client_procedure_duration_seconds_count 'onc_rpc_procedure_name="WRITE"' 'onc_rpc_version="4"' 'server_address="127.0.0.1"')
  nfs_reads=$(sum obi_stat_nfs_client_procedure_duration_seconds_count 'onc_rpc_procedure_name="READ"' 'onc_rpc_version="4"' 'server_address="127.0.0.1"')
  nfs_lookup_errors=$(grep '^obi_stat_nfs_client_procedure_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | grep -c 'error_type="ENOENT"')
  echo "NFS procedures: WRITE=$nfs_writes READ=$nfs_reads (want >=16 each), ENOENT series=$nfs_lookup_errors (want >=1)"
  grep '^obi_stat_nfs_client_procedure_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | head -20
  [ "$nfs_writes" -ge 16 ] && [ "$nfs_reads" -ge 16 ] && [ "$nfs_lookup_errors" -ge 1 ]; result e2e-nfs-procedures $?
fi
rw=$(sum obi_stat_disk_operations_total "system_device=\"$loop_dev\"")
echo "loop read/write operations=$rw (flushes and discards not included)"
grep -iE 'level=(WARN|ERROR)' "$LAB_RESULTS/obi.log" | grep -iv 'imds\|kube\|cloud' | head -10
umount /mnt/obifs; umount /mnt/nfs; losetup -d $loop
mdadm --stop /dev/md0 >/dev/null 2>&1; lvchange -an obivg/lv >/dev/null 2>&1
exit $fail
