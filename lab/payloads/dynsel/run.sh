#!/bin/bash
# OBI with a dynamic selector on cgroup v2, and two "containers": cgroups named like those of
# container runtimes, A systemd style (cri-containerd-<id>.scope) and B cgroupfs style (<id>).
# Both write to the same disk and sync a file on it. The disk and file sync metrics must count only
# the containers of the selected PIDs: nothing while nothing is selected, then A, then B.
set -u
echo "uname -r: $(uname -r)"
fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }
PORT=9415
ip link set lo up
CG=/sys/fs/cgroup
grep -q cgroup2 /proc/mounts || mount -t cgroup2 none $CG
echo +io > $CG/cgroup.subtree_control
id_a=$(printf 'a%.0s' $(seq 1 64)); id_b=$(printf 'b%.0s' $(seq 1 64))
cg_a=$CG/cri-containerd-$id_a.scope; cg_b=$CG/$id_b
mkdir -p $cg_a $cg_b

# the direct writes go to one disk, and the synced files are on another one
truncate -s 64M /tmp/disk.img /tmp/fs.img
dev=$(losetup -f --show /tmp/disk.img); d=$(basename $dev)
fsdev=$(losetup -f --show /tmp/fs.img)
mkfs.ext4 -q $fsdev && mkdir -p /mnt/fs && mount $fsdev /mnt/fs
# the init process of each container, whose PID is selected
sh -c "echo \$\$ > $cg_a/cgroup.procs; exec sleep 3600" & init_a=$!
sh -c "echo \$\$ > $cg_b/cgroup.procs; exec sleep 3600" & init_b=$!
sleep 1
echo "device $d, init PIDs: A $init_a ($(cat /proc/$init_a/cgroup)), B $init_b ($(cat /proc/$init_b/cgroup))"

mkfifo /tmp/ctl
OTEL_EBPF_METRICS_FEATURES=stats_disk,stats_fs_sync_duration OTEL_EBPF_PROMETHEUS_PORT=$PORT \
  OTEL_EBPF_STATS_AGENT_IP=127.0.0.1 OTEL_EBPF_NETWORK_AGENT_IP=127.0.0.1 \
  OTEL_EBPF_KUBE_METADATA_ENABLE=false OTEL_EBPF_BPF_BATCH_TIMEOUT=1s \
  ./obi-dynsel < /tmp/ctl > "$LAB_RESULTS/obi.log" 2>&1 &
obi=$!
exec 3> /tmp/ctl
for _ in $(seq 1 300); do curl -sf localhost:$PORT/metrics > /dev/null && break; sleep 1; done
sleep 3
running() { kill -0 $obi 2> /dev/null || { echo "OBI exited:"; tail -5 "$LAB_RESULTS/obi.log"; exit 1; }; }

sum() { curl -sf localhost:$PORT/metrics | grep "^$1{" | grep -F "$2" | awk '{ s += $2 } END { printf "%d", s + 0.5 }'; }
obi_writes() { sum obi_stat_disk_operations_total "system_device=\"$d\"" ; }
obi_syncs() { sum obi_stat_fs_sync_duration_seconds_count '' ; }
kernel_writes() { awk -v d=$d '$3 == d { print $8 }' /proc/diskstats; }
# a process of the container: joins its cgroup, then writes directly to the disk, and syncs a file
in_container() { sh -c "echo \$\$ > $1/cgroup.procs; $2"; }
work() {
  in_container $cg_a "dd if=/dev/zero of=$dev bs=4k count=40 seek=1000 oflag=direct status=none; for i in 1 2 3; do dd if=/dev/zero of=/mnt/fs/a bs=4k count=1 conv=fsync,notrunc status=none; done"
  in_container $cg_b "dd if=/dev/zero of=$dev bs=4k count=20 seek=2000 oflag=direct status=none; dd if=/dev/zero of=/mnt/fs/b bs=4k count=1 conv=fsync,notrunc status=none"
}
phase() { # name expected-writes expected-syncs
  running
  local o0 s0 k0; o0=$(obi_writes); s0=$(obi_syncs); k0=$(kernel_writes)
  work; sleep 6
  local o s k; o=$(( $(obi_writes) - o0 )); s=$(( $(obi_syncs) - s0 )); k=$(( $(kernel_writes) - k0 ))
  echo "$1: kernel writes $k (A 40, B 20) | obi writes $o (expected $2), file syncs $s (expected $3)"
  [ "$o" -eq "$2" ]; result "$1-disk" $?
  [ "$s" -eq "$3" ]; result "$1-fs-sync" $?
}

phase nothing-selected 0 0
running; echo "add $init_a" >&3; sleep 3
phase a-selected 40 3
running; echo "remove $init_a" >&3; echo "add $init_b" >&3; sleep 3
phase b-selected 20 1
[ "$(curl -sf localhost:$PORT/metrics | grep -c '^obi_stat_disk_pending_operations{')" -eq 0 ]; result no-device-stats $?
grep -E 'DYNSEL|level=(ERROR|WARN)' "$LAB_RESULTS/obi.log" | head -10

exec 3>&-
kill $obi $init_a $init_b; wait 2> /dev/null
exit $fail
