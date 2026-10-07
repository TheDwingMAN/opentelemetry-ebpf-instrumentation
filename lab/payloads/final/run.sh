#!/bin/bash
# final payload (G1-G4): privileged tests, obi end to end (queue, flush, discard,
# pending, partitions) on null_blk and loop devices. Also: NFS error names, zone append op, NFS late
# attach, 12 s stalls, kernel filesystem type names, sync_file_range waits only, write-zeroes.
set -u
echo "uname -r: $(uname -r)"
fail=0
step() { echo; echo "##### $*"; }
result() { # name rc
  if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL (rc=$2)"; fail=1; fi
}
sum() { # metric, then label filters (key="value"); reads $METRICS when set
  local metric=$1; shift
  local lines; lines=$(grep "^${metric}{" "${METRICS:-$LAB_RESULTS/metrics.txt}")
  for f in "$@"; do lines=$(echo "$lines" | grep -F "$f"); done
  echo "$lines" | awk 'NF {s+=$2} END {printf "%d", s}'
}
cat > /tmp/obi.yml <<'YML'
attributes:
  select:
    obi.stat.disk.operations:
      include: ["*"]
    obi.stat.fs.sync.duration:
      include: ["*"]
    obi.stat.fs.sync.operations:
      include: ["*"]
YML
setup_nfs() { # a loopback NFSv4.2 mount; idempotent
  modprobe nfs; modprobe nfsd
  ip link set lo up; mkdir -p /srv/nfs /mnt/nfs
  mountpoint -q /srv/nfs || mount -t tmpfs tmpfs /srv/nfs
  mountpoint -q /proc/fs/nfsd || mount -t nfsd nfsd /proc/fs/nfsd
  pgrep -x rpcbind >/dev/null || rpcbind -w 2>/dev/null || rpcbind
  exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs
  pgrep -x rpc.mountd >/dev/null || rpc.mountd
  rpc.nfsd 2
  mountpoint -q /mnt/nfs || mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs
}
teardown_nfs() { umount /mnt/nfs; exportfs -ua; rpc.nfsd 0; umount /proc/fs/nfsd; pkill -x rpc.mountd; modprobe -r nfsv4 nfsv3; }
nfs_traffic() {
  dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
  dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
  ls /mnt/nfs/nonexistent 2>/dev/null
}

step "privileged tests"
./stats.test -test.v -test.run 'TestDisk|TestFsSync|TestNFS' -test.timeout 10m > "$LAB_RESULTS/privileged.log" 2>&1
rc=$?; grep -E '^(--- |ok|FAIL|PASS)|Error:|Messages|tracer_disk' "$LAB_RESULTS/privileged.log" | grep -v 'TestDiskReader\|TestDiskErrorType\|TestDiskIOWriterProcess\|TestFsSyncReader\|TestFsSyncerProcess' | head -30
result privileged $rc
# the NFS error name table (TestNFSErrorType runs in the step above)
grep -q -- '--- PASS: TestNFSErrorType' "$LAB_RESULTS/privileged.log" \
  && ! grep -q -- '--- FAIL: TestNFSErrorType' "$LAB_RESULTS/privileged.log"
result nfs-error-names $?

step "zone append op"
if [ -x ./ebpf.test ]; then
  ./ebpf.test -test.v -test.run 'TestKernelBlockTracepointLayoutZoneAppendOp' > "$LAB_RESULTS/zone-append.log" 2>&1
  rc=$?; grep -E '^(--- |ok|FAIL|PASS)|Error:|Messages' "$LAB_RESULTS/zone-append.log" | head -10
  result zone-append-op $rc
else
  echo "SKIP zone-append-op no ebpf.test in the payload (build-payload.sh builds it)"
fi

step "nfs late attach"
modprobe -r nfs 2>/dev/null   # the privileged test loaded it and left it unused
[ ! -e /sys/module/sunrpc/initstate ]; rc=$?
[ $rc = 0 ] || echo "sunrpc still loaded, holders: $(ls /sys/module/sunrpc/holders)"
result nfs-late-setup $rc
if [ $rc = 0 ]; then
  late_log=$LAB_RESULTS/obi-late.log; late_metrics=$LAB_RESULTS/metrics-late.txt
  OTEL_EBPF_METRICS_FEATURES=stats_nfs OTEL_EBPF_PROMETHEUS_PORT=9401 OTEL_EBPF_BPF_BATCH_TIMEOUT=100ms \
  OTEL_EBPF_LOG_LEVEL=debug OTEL_EBPF_HOSTNAME=lab OTEL_EBPF_STATS_AGENT_IP=10.0.2.15 \
    ./obi -config /tmp/obi.yml > "$late_log" 2>&1 &
  late_pid=$!
  for _ in $(seq 1 180); do curl -sf localhost:9401/metrics >/dev/null 2>&1 && break; kill -0 $late_pid 2>/dev/null || break; sleep 1; done
  if grep -q 'waiting for the tracepoints of the sunrpc kernel module' "$late_log"; then
    result nfs-waiting-warn 0
    setup_nfs; attached=0
    # the refresh ticker is a fixed 30 s: wait for two ticks, as sunrpc and nfs can attach on different ones
    for _ in $(seq 1 90); do
      a=$(grep 'NFS client probes attached' "$late_log")
      echo "$a" | grep -q stats_nfs_client_procedure && echo "$a" | grep -q stats_nfs_client_io && { attached=1; break; }
      sleep 1
    done
    grep 'NFS client probes attached' "$late_log"
    mountpoint -q /mnt/nfs && [ $attached = 1 ]; result nfs-late-attach $?
    nfs_traffic; sleep 3; curl -sf localhost:9401/metrics > "$late_metrics"
    lsum() { METRICS=$late_metrics sum "$@"; }
    tx=$(lsum obi_stat_nfs_client_io_bytes_total 'server_address="127.0.0.1"' 'network_io_direction="transmit"')
    rx=$(lsum obi_stat_nfs_client_io_bytes_total 'server_address="127.0.0.1"' 'network_io_direction="receive"')
    w=$(lsum obi_stat_nfs_client_procedure_duration_seconds_count 'onc_rpc_procedure_name="WRITE"' 'onc_rpc_version="4"' 'server_address="127.0.0.1"')
    r=$(lsum obi_stat_nfs_client_procedure_duration_seconds_count 'onc_rpc_procedure_name="READ"' 'onc_rpc_version="4"' 'server_address="127.0.0.1"')
    e=$(grep '^obi_stat_nfs_client_procedure_duration_seconds_count{' "$late_metrics" | grep -c 'error_type="ENOENT"')
    echo "late NFS: written=$tx read=$rx (want 1048576 each), WRITE=$w READ=$r (want >=16), ENOENT series=$e (want >=1)"
    [ "$tx" = 1048576 ] && [ "$rx" = 1048576 ] && [ "$w" -ge 16 ] && [ "$r" -ge 16 ] && [ "$e" -ge 1 ]; result e2e-nfs-late-io $?
    teardown_nfs
    holders=$(ls /sys/module/nfs/holders 2>/dev/null); ref_on=$(cat /sys/module/nfs/refcnt 2>/dev/null || echo 0)
    kill $late_pid; wait $late_pid 2>/dev/null
    ref_off=$(cat /sys/module/nfs/refcnt 2>/dev/null || echo 0)
    echo "nfs module: holders='$holders' refcnt with OBI=$ref_on, without=$ref_off (want '', >=1, 0)"
    [ -z "$holders" ] && [ "$ref_on" -ge 1 ] && [ "$ref_off" = 0 ]; result nfs-modules-pinned $?
  elif grep -qE "doesn't describe the sunrpc types|can't tell the arguments of rpc_" "$late_log"; then
    setup_nfs; sleep 15; nfs_traffic; sleep 3; curl -sf localhost:9401/metrics > "$late_metrics"
    ! grep -q 'NFS client probes attached' "$late_log" && ! grep -q '^obi_stat_nfs_client' "$late_metrics"; result nfs-stays-off $?
    teardown_nfs; kill $late_pid; wait $late_pid 2>/dev/null
  else
    grep -i nfs "$late_log" | head -5; result nfs-late-attach 1   # sunrpc is absent, so no skip
    kill $late_pid; wait $late_pid 2>/dev/null
  fi
  modprobe -r nfsd nfs 2>/dev/null
fi

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
# a 12 s stall: a dm-delay device on its own loop device (bio-based, tp_bio.c), with a direct-io
# loop device on top (request-based, tp_blk.c). Neither has a request timeout below 12 s: dm is
# bio-based, and the loop queue keeps the 30 s blk-mq default. Before OBI starts, so that the bio
# device refresh lists the dm device. Not on $ok_dev (e2e-queue wants exactly 200 writes there).
modprobe dm_delay 2>/dev/null
truncate -s 64M /tmp/slow.img
slow_pv=$(losetup -f --show /tmp/slow.img)
dmsetup create slowdm --table "0 $(blockdev --getsz $slow_pv) delay $slow_pv 0 12000"
slowdm=$(dmsetup info -c --noheadings -o blkdevname slowdm)
[ -b /dev/$slowdm ] || mknod /dev/$slowdm b $(tr ':' ' ' < /sys/class/block/$slowdm/dev)
slow_loop=$(losetup -f --show --direct-io=on /dev/$slowdm 2>/dev/null) || slow_loop=
slow_dev=$(basename "${slow_loop:-none}")
slow_dio=$(cat /sys/block/$slow_dev/loop/dio 2>/dev/null || echo 0)
echo "stall: dm-delay $slowdm on $(basename $slow_pv), loop on top: ${slow_loop:-none} (dio=$slow_dio)"
# an ext4 filesystem, for the file syncs
truncate -s 64M /tmp/fs.img; mkfs.ext4 -q -F /tmp/fs.img
mkdir -p /mnt/obifs; mount -o loop /tmp/fs.img /mnt/obifs || echo "can't mount ext4"
# other filesystem types, for system.filesystem.type: tmpfs, and overlay over the ext4 root
mkdir -p /mnt/obitmpfs /mnt/obiovl /var/tmp/ovl/lower /var/tmp/ovl/upper /var/tmp/ovl/work
mount -t tmpfs tmpfs /mnt/obitmpfs
mount -t overlay overlay -o lowerdir=/var/tmp/ovl/lower,upperdir=/var/tmp/ovl/upper,workdir=/var/tmp/ovl/work /mnt/obiovl || echo "can't mount overlay"
# a loopback NFSv4.2 mount, before OBI starts so that the sunrpc and nfs modules are loaded
setup_nfs && nfs_ok=1 || { nfs_ok=0; echo "can't mount NFS"; }
# a zram disk, whose driver handles bios itself like the PowerFlex SDC
zram_ok=0
modprobe zram num_devices=0 2>/dev/null
if zid=$(cat /sys/class/zram-control/hot_add 2>/dev/null) && echo 32M > /sys/block/zram$zid/disksize; then
  zdev=zram$zid
  [ -b /dev/$zdev ] || mknod /dev/$zdev b $(tr ':' ' ' < /sys/class/block/$zdev/dev)
  zram_ok=1; echo "$zdev: scheduler '$(cat /sys/block/$zdev/queue/scheduler 2>/dev/null || echo absent)'"
else
  echo "no zram on this kernel"
fi
# write-zeroes: a dedicated loop device (request path) and a second LV on obivg (bio path), so
# that the e2e-discard and e2e-lvm checks keep their exact counts
truncate -s 64M /tmp/zero.img
zloop=$(losetup -f --show /tmp/zero.img); zloop_dev=$(basename $zloop)
zlv_ok=0
if lvcreate -qq -y -n lv2 -L 16M obivg; then
  zlv_dev=$(dmsetup info -c --noheadings -o blkdevname obivg-lv2)
  [ -b /dev/$zlv_dev ] || mknod /dev/$zlv_dev b $(tr ':' ' ' < /sys/class/block/$zlv_dev/dev)
  zlv_ok=1
fi
echo "write-zeroes: loop $zloop_dev, LVM volume ${zlv_dev:-none}"
OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync,stats_nfs OTEL_EBPF_PROMETHEUS_PORT=9400 \
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
# without dio the loop write is buffered and returns at once, so write to the dm device directly
if [ "$slow_dio" = 1 ]; then slow_target=$slow_loop; else slow_target=/dev/$slowdm; fi
dd if=/dev/zero of=$slow_target bs=4k count=1 oflag=direct status=none &
slow_pid=$!

dd if=/dev/zero of=/dev/$ok_dev bs=4k count=200 oflag=direct status=none
dd if=/dev/$ok_dev of=/dev/null bs=4k count=300 iflag=direct status=none
dd if=/dev/zero of=$part_node bs=64k count=16 oflag=direct status=none
blkdiscard -f -o 0 -l 1048576 $loop 2>&1 && discard_ok=1 || discard_ok=0
# write-zeroes: fio's falloc engine punches a hole in the device (one fallocate, no fsync)
# diskstats fields 8 and 10: writes completed and sectors written
zstat() { awk -v d=$1 '$3==d {print $8, $10}' /proc/diskstats; }
zd0=$(zstat $zloop_dev)
zero() { fio --name=zero --filename=$1 --ioengine=falloc --rw=trim --bs=1M --size=1M --invalidate=0 --output=/dev/null; }
zero $zloop 2>&1 && zero_ok=1 || zero_ok=0
zd1=$(zstat $zloop_dev)
zlv_zero_ok=0
if [ $zlv_ok = 1 ]; then
  zl0=$(zstat $zlv_dev)
  zero /dev/$zlv_dev 2>&1 && zlv_zero_ok=1
  zl1=$(zstat $zlv_dev)
fi
dd if=/dev/zero of=$loop bs=4k count=1 seek=12000 conv=fsync status=none
dd if=/dev/zero of=/dev/$lv_dev bs=64k count=32 oflag=direct status=none
[ $zram_ok = 1 ] && dd if=/dev/zero of=/dev/$zdev bs=4k count=32 oflag=direct status=none
dd if=/dev/zero of=/dev/md0 bs=64k count=16 oflag=direct status=none
echo data > /mnt/obifs/f
sync /mnt/obifs/f; sync -d /mnt/obifs/f; sync -f /mnt/obifs/f; sync
for mp in /mnt/obitmpfs /mnt/obiovl; do
  mountpoint -q $mp && { echo data > $mp/f; sync $mp/f; }
done
# sync_file_range: 7 WRITE-only hints (not syncs) and 5 waiting calls, from one call site
sfr_ok=0
if [ -x ./sfr ]; then
  ./sfr /mnt/obifs/sfr 7 5 && sfr_ok=1 || echo "sfr failed"
else
  echo "SKIP e2e-fs-sync-sync_file_range no sfr helper in the payload (build-payload.sh builds it)"
fi
# sync FILE is fsync(2) and writes nothing: the exact byte counts of e2e-nfs-io stay
if [ $nfs_ok = 1 ]; then nfs_traffic; sync /mnt/nfs/f; fi
wait $slow_pid; slow_rc=$?
sleep 3
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

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

if [ $zero_ok = 1 ]; then
  read -r zw0 zs0 <<< "$zd0"; read -r zw1 zs1 <<< "$zd1"
  kw=$((zw1 - zw0)); kb=$(( (zs1 - zs0) * 512 ))
  zops=$(sum obi_stat_disk_operations_total "system_device=\"$zloop_dev\"" 'disk_io_direction="write"')
  zbytes=$(sum obi_stat_disk_io_bytes_total "system_device=\"$zloop_dev\"" 'disk_io_direction="write"')
  zdisc=$(sum obi_stat_disk_discard_duration_seconds_count "system_device=\"$zloop_dev\"")
  echo "write-zeroes (loop): obi writes=$zops bytes=$zbytes discards=$zdisc, diskstats writes=$kw bytes=$kb (want 1, 1048576 and 0 discards)"
  # exactly one write in diskstats: a zero-page fallback would show many
  [ "$kw" = 1 ] && [ "$kb" = 1048576 ] && [ "$zops" = "$kw" ] && [ "$zbytes" = "$kb" ] && [ "$zdisc" = 0 ]
  result e2e-write-zeroes $?
else
  echo "SKIP e2e-write-zeroes the loop device has no write-zeroes on this kernel"
fi
if [ $zlv_zero_ok = 1 ]; then
  read -r lw0 ls0 <<< "$zl0"; read -r lw1 ls1 <<< "$zl1"
  klw=$((lw1 - lw0)); klb=$(( (ls1 - ls0) * 512 ))
  zlops=$(sum obi_stat_disk_operations_total "system_device=\"$zlv_dev\"" 'obi_disk_stacked="true"' 'disk_io_direction="write"')
  zlbytes=$(sum obi_stat_disk_io_bytes_total "system_device=\"$zlv_dev\"" 'obi_disk_stacked="true"' 'disk_io_direction="write"')
  echo "write-zeroes (LVM bio): obi writes=$zlops bytes=$zlbytes, diskstats writes=$klw bytes=$klb (want equal, 1048576 bytes)"
  [ "$klw" -ge 1 ] && [ "$klb" = 1048576 ] && [ "$zlops" = "$klw" ] && [ "$zlbytes" = "$klb" ]
  result e2e-write-zeroes-lvm $?
elif [ $zlv_ok = 1 ]; then
  echo "SKIP e2e-write-zeroes-lvm the LVM volume has no write-zeroes on this kernel"
else
  echo "SKIP e2e-write-zeroes-lvm lvcreate of obivg/lv2 failed"
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
  c=$(sum obi_stat_fs_sync_operations_total "obi_fs_sync_type=\"$t\"" 'system_filesystem_mountpoint="/mnt/obifs"' 'system_filesystem_type="ext4"')
  echo "file sync counter: $t on /mnt/obifs=$c (want 1)"
  [ "$c" = 1 ]; result e2e-fs-sync-counter-$t $?
done
# nfs4 is gated on nfs_ok only, not on nfs_btf: the fsync probes and the mount table don't need
# module BTF, so RHEL 8 must report it too
fs_type_checks="/mnt/obifs:ext4 /mnt/obitmpfs:tmpfs"
[ $nfs_ok = 1 ] && fs_type_checks="$fs_type_checks /mnt/nfs:nfs4"
for check in $fs_type_checks; do
  mp=${check%%:*}; fstype=${check##*:}
  n=$(sum obi_stat_fs_sync_duration_seconds_count 'obi_fs_sync_type="fsync"' "system_filesystem_mountpoint=\"$mp\"" "system_filesystem_type=\"$fstype\"")
  echo "file sync type: fsync on $mp reported as $fstype=$n (want >=1)"
  [ "$n" -ge 1 ]; result e2e-fs-type-$fstype $?
done
# overlay: printed only, until a dry run on rhel8.9 and on one 6.x kernel both show n>=1 (then it
# becomes RESULT e2e-fs-type-overlay); an old kernel may report the lower filesystem instead
if mountpoint -q /mnt/obiovl; then
  n=$(sum obi_stat_fs_sync_duration_seconds_count 'obi_fs_sync_type="fsync"' 'system_filesystem_mountpoint="/mnt/obiovl"' 'system_filesystem_type="overlay"')
  echo "file sync type: fsync on /mnt/obiovl reported as overlay=$n (want >=1, not yet a RESULT)"
  grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | grep 'system_filesystem_mountpoint="/mnt/obiovl"'
else
  echo "SKIP e2e-fs-type-overlay the overlay didn't mount"
fi
untyped=$(grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt" | grep 'system_filesystem_mountpoint="/' | grep -vc 'system_filesystem_type="[^"]')
echo "file sync series with a mountpoint and no type=$untyped (want 0)"
[ "$untyped" = 0 ]; result e2e-fs-type-always-set $?
if [ $sfr_ok = 1 ]; then
  sfr_n=$(sum obi_stat_fs_sync_duration_seconds_count 'obi_fs_sync_type="sync_file_range"' 'system_filesystem_mountpoint="/mnt/obifs"' 'system_filesystem_type="ext4"')
  sfr_c=$(sum obi_stat_fs_sync_operations_total 'obi_fs_sync_type="sync_file_range"' 'system_filesystem_mountpoint="/mnt/obifs"' 'system_filesystem_type="ext4"')
  echo "file sync: sync_file_range on /mnt/obifs=$sfr_n counter=$sfr_c (want 5: the 7 WRITE-only hints are not syncs; 12 means the fix is missing, 0 or 12 with the fix means a wrong register)"
  [ "$sfr_n" = 5 ]; result e2e-fs-sync-sync_file_range $?
  [ "$sfr_c" = 5 ]; result e2e-fs-sync-counter-sync_file_range $?
fi
hist_all=$(sum obi_stat_fs_sync_duration_seconds_count)
ops_all=$(sum obi_stat_fs_sync_operations_total)
time_all=$(grep '^obi_stat_fs_sync_operation_time_seconds_total' "$LAB_RESULTS/metrics.txt" | awk '{s+=$2} END {printf "%.6f", s}')
hist_sum=$(grep '^obi_stat_fs_sync_duration_seconds_sum' "$LAB_RESULTS/metrics.txt" | awk '{s+=$2} END {printf "%.6f", s}')
echo "file syncs: histogram count=$hist_all operations=$ops_all, histogram sum=$hist_sum operation time=$time_all (want equal)"
[ "$hist_all" = "$ops_all" ] && awk -v a="$hist_sum" -v b="$time_all" 'BEGIN {d=a-b; if (d<0) d=-d; exit !(d < 0.000001 + a*1e-9)}'; result e2e-fs-sync-counters-match $?
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
  nfs_hist=$(sum obi_stat_nfs_client_procedure_duration_seconds_count)
  nfs_count=$(sum obi_stat_nfs_client_procedure_count_total)
  nfs_count_writes=$(sum obi_stat_nfs_client_procedure_count_total 'onc_rpc_procedure_name="WRITE"' 'server_address="127.0.0.1"')
  echo "NFS counters: count=$nfs_count (histogram $nfs_hist), WRITE=$nfs_count_writes (histogram $nfs_writes)"
  [ "$nfs_count" = "$nfs_hist" ] && [ "$nfs_count_writes" = "$nfs_writes" ] && grep -q '^obi_stat_nfs_client_procedure_time_seconds_total{' "$LAB_RESULTS/metrics.txt"; result e2e-nfs-counters $?
fi
bk() { sum obi_stat_disk_operation_duration_seconds_bucket "system_device=\"$1\"" 'disk_io_direction="write"' "le=\"$2\""; }
stall() { # device: one successful write between 10 s and 30 s
  # error_type="" is on every successful series: only a non-empty value is an error
  [ "$(bk $1 10)" = 0 ] && [ "$(bk $1 30)" = 1 ] && [ "$(bk $1 60)" = 1 ] && [ "$(bk $1 +Inf)" = 1 ] &&
    ! grep "^obi_stat_disk_operation_duration_seconds_count{.*system_device=\"$1\"" "$LAB_RESULTS/metrics.txt" | grep -q 'error_type="[^"]'
}
echo "stall: dd exit=$slow_rc (want 0) on $slow_target"
[ "$slow_rc" = 0 ]; result e2e-stall-write $?
grep "^obi_stat_disk_operation_duration_seconds_bucket{.*system_device=\"$slowdm\"" "$LAB_RESULTS/metrics.txt" | grep -E 'le="(5|10|30|60|\+Inf)"'
slow_sum=$(sum obi_stat_disk_operation_duration_seconds_sum "system_device=\"$slowdm\"" 'disk_io_direction="write"')
echo "stall: $slowdm write time sum=${slow_sum}s (want 12..29)"
stall $slowdm && [ "$slow_sum" -ge 12 ] && [ "$slow_sum" -lt 30 ]; result e2e-stall-bucket-bio $?
if [ "$slow_dio" = 1 ]; then
  grep "^obi_stat_disk_operation_duration_seconds_bucket{.*system_device=\"$slow_dev\"" "$LAB_RESULTS/metrics.txt" | grep -E 'le="(5|10|30|60|\+Inf)"'
  stall $slow_dev; result e2e-stall-bucket $?
else
  echo "SKIP e2e-stall-bucket losetup --direct-io over the dm device didn't take, only the bio path is checked"
fi
stall_bounds=0
for h in disk_operation disk_queue disk_flush fs_sync $([ $discard_ok = 1 ] && echo disk_discard); do
  grep -q "^obi_stat_${h}_duration_seconds_bucket{.*le=\"60\"" "$LAB_RESULTS/metrics.txt" || { echo "stall: no le=\"60\" on $h"; stall_bounds=1; }
done
[ $stall_bounds = 0 ]; result e2e-stall-bounds $?
if [ $nfs_ok = 1 ] && [ $nfs_btf = 1 ]; then
  nfs_stall_bounds=0
  for le in 10 30 60; do
    grep -q "^obi_stat_nfs_client_procedure_duration_seconds_bucket{.*le=\"$le\"" "$LAB_RESULTS/metrics.txt" || { echo "stall: no NFS le=\"$le\""; nfs_stall_bounds=1; }
  done
  [ $nfs_stall_bounds = 0 ]; result e2e-stall-bounds-nfs $?
fi
! grep -q 'more histogram buckets than the kernel can keep' "$LAB_RESULTS/obi.log"; result e2e-stall-no-approximation $?
if [ $zram_ok = 1 ]; then
  zw=$(sum obi_stat_disk_operations_total "system_device=\"$zdev\"" 'obi_disk_stacked="false"' 'disk_io_direction="write"')
  zb=$(sum obi_stat_disk_io_bytes_total "system_device=\"$zdev\"" 'obi_disk_stacked="false"' 'disk_io_direction="write"')
  echo "zram (bio-based disk): writes=$zw (want 32) bytes=$zb (want 131072)"
  [ "$zw" = 32 ] && [ "$zb" = 131072 ]; result e2e-bio-based-disk $?
fi
rw=$(sum obi_stat_disk_operations_total "system_device=\"$loop_dev\"")
echo "loop read/write operations=$rw (flushes and discards not included)"
grep -iE 'level=(WARN|ERROR)' "$LAB_RESULTS/obi.log" | grep -iv 'imds\|kube\|cloud' | head -10
step "optional storage features"
grep -E 'probes of the enabled storage metrics are loaded|storage metrics disabled on this node' "$LAB_RESULTS/obi.log" | head -5
if [ $nfs_btf = 1 ]; then
  grep -q 'the probes of the enabled storage metrics are loaded' "$LAB_RESULTS/obi.log"; result storage-all-loaded $?
else
  grep 'storage metrics disabled on this node' "$LAB_RESULTS/obi.log" | grep -q 'NFS client'; result storage-nfs-disabled-warn $?
fi
[ -n "$slow_loop" ] && losetup -d $slow_loop
dmsetup remove slowdm; losetup -d $slow_pv
umount /mnt/obifs; umount /mnt/nfs; losetup -d $loop
lvchange -an obivg/lv2 >/dev/null 2>&1; losetup -d $zloop
mdadm --stop /dev/md0 >/dev/null 2>&1; lvchange -an obivg/lv >/dev/null 2>&1
exit $fail
