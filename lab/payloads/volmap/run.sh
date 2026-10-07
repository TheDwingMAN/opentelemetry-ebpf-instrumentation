#!/bin/bash
# OBI as a process (stats_disk, Prometheus export) on stacked volumes, to check obi_stat_disk_volume_device:
#   extra-1          LVM (labvg) over the whole disk, with two LVs: lv0 and lv1
#   extra-2          one partition, LVM (labvg2) over it with lv0, and a dm-linear volume (lab-linear,
#                    dmsetup) over that LV
#   extra-3, extra-4 md RAID1 (md0) over both whole disks
#   a loop device on a file of the root disk, and a loop device on a file of tmpfs (no series)
# It asserts the exact set of (volume, device mapper name, disk) series, then removes labvg/lv1 and
# asserts that its series goes to 0 and then disappears (Prometheus TTL 75 s).
# Needs four extra disks: LAB_EXTRA_DISKS="256M 256M 256M 256M" ./run-vm.sh v6.12.111 payloads/volmap 1800
set -u
echo "uname -r: $(uname -r)"
fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }
wait_for() { # description timeout-seconds command...
  local what=$1 timeout=$2; shift 2
  local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then echo "timed out waiting for $what"; return 1; fi
    sleep 3
  done
  echo "$what after $(($(date +%s) - start))s"
}
# the device node of a block device, which LVM and dmsetup may not create without udev
devnode() { [ -b /dev/$1 ] || mknod /dev/$1 b $(tr ':' ' ' < /sys/class/block/$1/dev); }
extra() { for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = lab-extra-$1 ] && echo ${d##*/}; done; }
dm_of() { dmsetup info -c --noheadings -o blkdevname "$1" 2>/dev/null | tr -d ' '; }

PORT=9413
ip link set lo up
export DM_DISABLE_UDEV=1
for m in dm_mod raid1 loop; do modprobe $m 2>/dev/null; done

e1=$(extra 1); e2=$(extra 2); e3=$(extra 3); e4=$(extra 4)
echo "extra disks: $e1 $e2 $e3 $e4"
[ -n "$e1" ] && [ -n "$e2" ] && [ -n "$e3" ] && [ -n "$e4" ]; result extra-disks-found $?
mkdir -p /var/lib/obi-lab
root_disk=$(basename "$(readlink -f /sys/dev/block/$(findmnt -no MAJ:MIN -T /var/lib/obi-lab | tr -d ' '))")
echo "root disk: $root_disk"

# LVM over a whole disk, with two LVs
pvcreate -qq /dev/$e1 && vgcreate -qq labvg /dev/$e1 && lvcreate -qq -y -n lv0 -L 64M labvg &&
  lvcreate -qq -y -n lv1 -L 64M labvg
result lvm-whole-disk-setup $?
# LVM over a partition, and a dm-linear volume over its LV
printf 'label: dos\n,\n' | sfdisk -q /dev/$e2; sleep 1
p2=$(ls /sys/block/$e2 | grep "^${e2}p\?1$")
devnode "$p2"
pvcreate -qq /dev/$p2 && vgcreate -qq labvg2 /dev/$p2 && lvcreate -qq -y -n lv0 -L 64M labvg2
result lvm-partition-setup $?
lv20=$(dm_of labvg2-lv0); devnode "$lv20"
dmsetup create lab-linear --table "0 $(blockdev --getsz /dev/$lv20) linear $(cat /sys/block/$lv20/dev) 0"
result dm-linear-setup $?
# md RAID1 over two whole disks, without the initial resync
mdadm --create /dev/md0 --run --assume-clean --level=1 --raid-devices=2 --metadata=1.2 /dev/$e3 /dev/$e4 > /dev/null 2>&1
[ -d /sys/block/md0/md ] && [ "$(ls /sys/block/md0/slaves | sort | tr '\n' ' ')" = "$(printf '%s\n' $e3 $e4 | sort | tr '\n' ' ')" ]
result md-raid1-setup $?
# a loop device on a file of the root disk, and one on a file of tmpfs
truncate -s 16M /var/lib/obi-lab/root.img; root_loop=$(basename "$(losetup -f --show /var/lib/obi-lab/root.img)")
truncate -s 16M /tmp/tmpfs.img; tmpfs_loop=$(basename "$(losetup -f --show /tmp/tmpfs.img)")
echo "loop devices: $root_loop on $(findmnt -no SOURCE -T /var/lib/obi-lab/root.img), $tmpfs_loop on $(findmnt -no FSTYPE -T /tmp/tmpfs.img)"
lv0=$(dm_of labvg-lv0); lv1=$(dm_of labvg-lv1); linear=$(dm_of lab-linear)
echo "device mapper volumes: labvg-lv0=$lv0 labvg-lv1=$lv1 labvg2-lv0=$lv20 lab-linear=$linear"
for d in /sys/block/*; do
  n=${d##*/}; s=""
  [ -d $d/slaves ] && s=$(ls $d/slaves | tr '\n' ' ')
  [ -n "$s" ] || [ -d $d/loop ] && echo "  $n slaves: ${s:-none} $(cat $d/dm/name 2>/dev/null) $(cat $d/loop/backing_file 2>/dev/null)"
done

OTEL_EBPF_METRICS_FEATURES=stats_disk OTEL_EBPF_PROMETHEUS_PORT=$PORT OTEL_EBPF_PROMETHEUS_TTL=75s \
  OTEL_EBPF_STATS_AGENT_IP=127.0.0.1 OTEL_EBPF_KUBE_METADATA_ENABLE=false OTEL_EBPF_BPF_BATCH_TIMEOUT=1s \
  ./obi > "$LAB_RESULTS/obi.log" 2>&1 &
obi=$!
wait_for "metrics endpoint" 600 curl -sf localhost:$PORT/metrics; result obi-started $?
grep -o '"msg":"OpenTelemetry eBPF Instrumentation"[^}]*' "$LAB_RESULTS/obi.log" | head -1

metrics() { curl -sf localhost:$PORT/metrics; }
label() { echo "$1" | grep -o "$2=\"[^\"]*\"" | cut -d'"' -f2; }
# volume|name|disk value, one line per series
volumes() {
  local line
  metrics | grep '^obi_stat_disk_volume_device{' | while IFS= read -r line; do
    echo "$(label "$line" obi_disk_volume_device)|$(label "$line" obi_disk_volume_name)|$(label "$line" system_device) ${line##* }"
  done | sort
}
expected=$(printf '%s\n' "$lv0|labvg-lv0|$e1 1" "$lv1|labvg-lv1|$e1 1" "$lv20|labvg2-lv0|$e2 1" \
  "$linear|lab-linear|$e2 1" "md0||$e3 1" "md0||$e4 1" "$root_loop||$root_disk 1" | sort)
echo "expected series:"; echo "$expected"
exact() { [ "$(volumes)" = "$expected" ]; }
wait_for "the volume series" 120 exact; result volume-series-exact $?
echo "series:"; volumes
metrics | grep -E '^# (HELP|TYPE) obi_stat_disk_volume_device'
metrics | grep '^obi_stat_disk_volume_device{' | head -3
! volumes | grep -q "^$tmpfs_loop|"; result loop-on-tmpfs-no-series $?

# the disk metrics, with the renamed operation time counter
dd if=/dev/zero of=/dev/$lv0 bs=4k count=256 oflag=direct status=none
dd if=/dev/zero of=/dev/md0 bs=4k count=256 oflag=direct status=none
op_time() { metrics | grep '^obi_stat_disk_operation_time_seconds_total{' | grep -q "system_device=\"$e1\""; }
wait_for "operation time of $e1" 60 op_time; result operation-time-seconds-total $?
metrics | grep '^obi_stat_disk_operation_time_seconds_total{' | grep -E "system_device=\"($e1|$lv0)\"" | head -4
! metrics | grep -q '^obi_stat_disk_operation_time_seconds_total_'; result no-other-operation-time-name $?

# a removed LV: 0 once, then gone
lvremove -qq -y labvg/lv1; result lvremove $?
removed_zero() { volumes | grep -qx "$lv1|labvg-lv1|$e1 0"; }
wait_for "labvg-lv1 at 0" 120 removed_zero; result removed-lv-reported-0 $?
others=$(echo "$expected" | grep -v "^$lv1|")
removed_gone() { [ "$(volumes)" = "$others" ]; }
wait_for "labvg-lv1 gone" 240 removed_gone; result removed-lv-gone $?
echo "series:"; volumes

grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -8
metrics > "$LAB_RESULTS/metrics.prom"
kill $obi; wait $obi 2>/dev/null
exit $fail
