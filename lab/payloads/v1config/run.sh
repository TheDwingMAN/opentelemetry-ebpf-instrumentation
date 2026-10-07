#!/bin/bash
# Runs OBI with the v1 storage config (obi-storage-v1.yaml, unchanged) and checks the metrics
# of a disk, a partition, flushes, discards, file syncs on ext4 and NFS I/O.
set -u
echo "uname -r: $(uname -r)"
fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }

truncate -s 64M /tmp/disk.img
printf 'label: dos\n2048,65536,83\n' | sfdisk -q /tmp/disk.img
loop=$(losetup -f --show -P /tmp/disk.img); dev=$(basename $loop)
[ -e /sys/class/block/${dev}p1 ] || blockdev --rereadpt $loop
for _ in $(seq 1 50); do [ -e /sys/class/block/${dev}p1/dev ] && break; sleep 0.1; done
part=/tmp/${dev}p1; mknod $part b $(tr ':' ' ' < /sys/class/block/${dev}p1/dev) || echo "no partition"
truncate -s 64M /tmp/fs.img; mkfs.ext4 -q -F /tmp/fs.img
mkdir -p /mnt/obifs; mount -o loop /tmp/fs.img /mnt/obifs
modprobe nfs; modprobe nfsd
ip link set lo up; mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs && nfs_ok=1 || nfs_ok=0

# a host-like network address: the lab VM has only loopback, and OBI reports the host IP
modprobe dummy 2>/dev/null; ip link add obi0 type dummy 2>/dev/null && ip link set obi0 up && nic=obi0 || nic=lo
ip addr add 10.0.2.15/24 dev $nic
./obi -config obi-storage-v1.yaml > "$LAB_RESULTS/obi.log" 2>&1 &
obi_pid=$!
up=0
for _ in $(seq 1 300); do
  curl -sf localhost:9400/metrics > /dev/null 2>&1 && { up=1; break; }
  kill -0 $obi_pid 2>/dev/null || break
  sleep 1
done
grep -E 'configuration loaded|level=(WARN|ERROR)' "$LAB_RESULTS/obi.log" | cut -c1-220
[ $up = 1 ]; result obi-started $?
[ $up = 1 ] || exit 1
sleep 5

dd if=/dev/zero of=$loop bs=4k count=200 oflag=direct status=none
dd if=$loop of=/dev/null bs=4k count=300 iflag=direct status=none
[ -b $part ] && dd if=/dev/zero of=$part bs=64k count=16 oflag=direct status=none
dd if=/dev/zero of=$loop bs=4k count=1 seek=12000 conv=fsync status=none
blkdiscard -f -o 0 -l 1048576 $loop 2>/dev/null && discard_ok=1 || discard_ok=0
echo data > /mnt/obifs/f
sync /mnt/obifs/f; sync -d /mnt/obifs/f; sync -f /mnt/obifs/f
if [ $nfs_ok = 1 ]; then
  dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
  dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
fi
sleep 5
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
kill $obi_pid; wait $obi_pid 2>/dev/null

sum() { # metric, then label filters
  local metric=$1; shift
  local lines; lines=$(grep "^${metric}{" "$LAB_RESULTS/metrics.txt")
  for f in "$@"; do lines=$(echo "$lines" | grep -F "$f"); done
  echo "$lines" | awk 'NF {s+=$2} END {printf "%d", s}'
}
w=$(sum obi_stat_disk_operations_total "system_device=\"$dev\"" 'disk_io_direction="write"')
r=$(sum obi_stat_disk_operations_total "system_device=\"$dev\"" 'disk_io_direction="read"')
echo "disk $dev: writes=$w (want 217: 200 + 16 on the partition + 1) reads=$r (want >=300)"
[ "$w" = 217 ] && [ "$r" -ge 300 ]; result disk-operations $?
f=$(sum obi_stat_disk_flush_duration_seconds_count "system_device=\"$dev\"")
echo "flushes: $f (want >=1)"; [ "$f" -ge 1 ]; result disk-flush $?
if [ $discard_ok = 1 ]; then
  d=$(sum obi_stat_disk_discard_io_bytes_total "system_device=\"$dev\"")
  echo "discarded bytes: $d (want 1048576)"; [ "$d" = 1048576 ]; result disk-discard $?
fi
p=$(grep -c "^obi_stat_disk_pending_operations{.*system_device=\"$dev\"" "$LAB_RESULTS/metrics.txt")
echo "pending series: $p (want 2)"; [ "$p" = 2 ]; result disk-pending $?
q=$(sum obi_stat_disk_queue_duration_seconds_count "system_device=\"$dev\"")
echo "queue duration count: $q (want >=500)"; [ "$q" -ge 500 ]; result disk-queue $?
for t in fsync fdatasync syncfs; do
  n=$(sum obi_stat_fs_sync_duration_seconds_count "obi_fs_sync_type=\"$t\"" 'system_filesystem_mountpoint="/mnt/obifs"' 'system_filesystem_type="ext4"')
  echo "file sync $t on /mnt/obifs (ext4): $n (want 1)"; [ "$n" = 1 ]; result fs-sync-$t $?
done
if grep -q 'NFS client .* stats are disabled' "$LAB_RESULTS/obi.log"; then
  echo "NFS: disabled on this kernel (see the warning above)"
elif [ $nfs_ok = 1 ]; then
  tx=$(sum obi_stat_nfs_client_io_bytes_total 'network_io_direction="transmit"')
  rx=$(sum obi_stat_nfs_client_io_bytes_total 'network_io_direction="receive"')
  echo "NFS bytes: written=$tx read=$rx (want 1048576 each)"
  [ "$tx" = 1048576 ] && [ "$rx" = 1048576 ]; result nfs-io $?
fi
echo "metric names:"; grep -o '^obi_stat_[a-z_]*' "$LAB_RESULTS/metrics.txt" | sed 's/_bucket$\|_sum$\|_count$//' | sort -u | tr '\n' ' '; echo
umount /mnt/obifs; umount /mnt/nfs; losetup -d $loop
exit $fail
