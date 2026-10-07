#!/bin/bash
# PID 1 inside the lab guest (kernel cmdline: init=/lab-init.sh).
# Mounts the usual pseudo filesystems (cgroup v2 only), loads optional modules,
# runs /payload/run.sh from a tmpfs copy and powers the VM off.
#
# Console protocol parsed by run-vm.sh on the host:
#   ===LAB_BOOTED=== <uptime>          init reached, before payload
#   ===LAB_PAYLOAD_BEGIN===            payload output follows
#   ===LAB_PAYLOAD_END===
#   LAB_EXIT=<code>                     payload exit code
#   LAB_ERROR=<text>                    infrastructure failure inside the guest

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export TERM=dumb

log() { echo "[lab-init] $*"; }

mnt() { # mnt <type> <source> <target> [opts]
    local type=$1 src=$2 dst=$3 opts=${4:-}
    mkdir -p "$dst"
    mountpoint -q "$dst" && return 0
    mount -t "$type" ${opts:+-o "$opts"} "$src" "$dst" || log "WARN: mount $type on $dst failed"
}

finish() {
    # without 9p, the host reads the results from a tar written over the whole results disk
    [ "${transport:-9p}" = disk ] && tar -C /results -cf /dev/vdc . 2>/dev/null
    sync
    echo s > /proc/sysrq-trigger 2>/dev/null
    echo o > /proc/sysrq-trigger 2>/dev/null
    # Should not be reached; PID 1 exiting panics the kernel, and panic=-1 plus
    # qemu -no-reboot turns that into a VM exit as well.
    sleep 5
    exit 1
}

cmdline_arg() { # value of key=value on the kernel cmdline
    local kv
    for kv in $(cat /proc/cmdline); do
        case "$kv" in "$1="*) echo "${kv#*=}"; return 0 ;; esac
    done
    return 1
}

mnt proc proc /proc
mnt sysfs sysfs /sys
mnt devtmpfs devtmpfs /dev
mnt devpts devpts /dev/pts gid=5,mode=620
mnt tmpfs tmpfs /dev/shm mode=1777
mnt tmpfs tmpfs /run mode=755
mnt tmpfs tmpfs /tmp mode=1777
mount -o remount,rw / 2>/dev/null
mnt debugfs debugfs /sys/kernel/debug
mnt tracefs tracefs /sys/kernel/tracing
mnt bpf bpffs /sys/fs/bpf
mnt configfs configfs /sys/kernel/config
mnt cgroup2 cgroup2 /sys/fs/cgroup nsdelegate
[ -e /dev/fd ] || ln -s /proc/self/fd /dev/fd
hostname lab 2>/dev/null
ip link set lo up 2>/dev/null

# Make every available controller usable by child cgroups (io is needed for
# per-cgroup blkg attribution). The root cgroup is exempt from the
# no-internal-process rule, so this is safe.
for c in $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null); do
    echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
done

KREL=$(uname -r)
MODULES=$(cmdline_arg lab.modules || echo "9pnet_virtio,9p,null_blk,dm_mod,dm_delay,dm_flakey,loop,overlay")
loaded="" failed=""
for m in ${MODULES//,/ }; do
    if modprobe "$m" 2>/dev/null; then loaded="$loaded $m"; else failed="$failed $m"; fi
done
log "kernel $KREL; modprobe ok:${loaded:- none}; failed:${failed:- none}"

transport=$(cmdline_arg lab.transport || echo 9p)
if [ "$transport" = disk ]; then
    # kernels without 9p (RHEL): the payload is a tar on /dev/vdb, the results go to /dev/vdc
    mkdir -p /payload /results
    tar -xf /dev/vdb -C /payload || log "WARN: extracting the payload from /dev/vdb failed"
else
    mnt 9p payload /payload ro,trans=virtio,version=9p2000.L,msize=512000,cache=loose
    mnt 9p results /results rw,trans=virtio,version=9p2000.L,msize=512000
fi
if [ ! -f /payload/run.sh ]; then
    echo "LAB_ERROR=no /payload/run.sh (payload mount failed?)"
    echo "LAB_EXIT=254"
    finish
fi

read -r up _ < /proc/uptime
echo "===LAB_BOOTED=== $up"

# Run from a writable tmpfs copy so payloads can write next to their binaries.
mkdir -p /work
cp -a /payload/. /work/ || { echo "LAB_ERROR=copying payload failed"; echo "LAB_EXIT=254"; finish; }

# Keep kernel messages off the console while the payload runs; they are saved
# to /results/dmesg.log afterwards.
dmesg -n 1 2>/dev/null
export LAB_RESULTS=/results LAB_KREL=$KREL
echo "===LAB_PAYLOAD_BEGIN==="
cd /work
set -o pipefail
bash ./run.sh 2>&1 | tee /results/output.log
rc=$?
set +o pipefail
echo "===LAB_PAYLOAD_END==="
read -r up _ < /proc/uptime
echo "LAB_UPTIME=$up"
dmesg > /results/dmesg.log 2>/dev/null
echo "$rc" > /results/exit_code
sync
echo "LAB_EXIT=$rc"
finish
