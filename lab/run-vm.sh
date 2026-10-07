#!/usr/bin/env bash
# Boot a lab kernel under QEMU (KVM when /dev/kvm is usable, else TCG) and run <payload-dir>/run.sh inside it.
#
#   run-vm.sh <kernel-version> <payload-dir> [timeout-seconds]
#
# stdout: the payload's output (streamed live). stderr: a one-line summary.
# Exit code: the payload's exit code; 124 on timeout; 125 on boot/infra failure.
#
# Environment knobs:
#   LAB_VERBOSE=1     also stream the whole guest console to stderr
#   LAB_SMP=2 LAB_MEM=4096
#   LAB_ACCEL=kvm|tcg,thread=multi  default: kvm when /dev/kvm is readable and writable, else tcg
#   LAB_CPU=host|max  default: host under KVM, max under TCG
#   LAB_TIMEOUT_SCALE=1  multiplies the timeout (the payload timeouts were sized for TCG)
#   LAB_TRANSPORT=9p|disk  default: 9p when the kernel has 9p, else disk (also for a QEMU without 9p)
#   LAB_APPEND="..."  extra kernel cmdline (e.g. "loglevel=7", "lab.modules=loop,9p,9pnet_virtio")
#   LAB_KEEP=1        keep the qcow2 overlay (and extra disks) after the run (runs/<ver>-<ts>/)
#   LAB_EXTRA_DISKS="1G 1G"  attach one empty raw virtio disk per size (sparse files in the run dir,
#                     deleted afterwards); the guest finds them by serial: /sys/block/vd*/serial is
#                     lab-extra-1, lab-extra-2, ...
#   LAB_NVME_MPATH=256M  attach one shared NVMe namespace of that size behind two controllers of one
#                     subsystem (both with serial lab-nvme, as one subsystem requires), as dual-port SSDs and NVMe-oF show it:
#                     with native NVMe multipath the guest gets a bio-based head over two hidden paths
#
# The payload dir is shared read-only over 9p and copied to /work (tmpfs) in the
# guest; run.sh is started there with cwd=/work. Files written to $LAB_RESULTS
# (/results in the guest) land in runs/<ver>-<ts>/results/ on the host, next to
# output.log, dmesg.log and exit_code.
set -euo pipefail
LAB="$(cd "$(dirname "$0")" && pwd)"

if [ $# -lt 2 ]; then
    sed -n '2,25p' "$0" >&2
    exit 2
fi
VER="$1"
PAYLOAD="$(realpath "$2")"
TIMEOUT="${3:-900}"
TIMEOUT="$(awk -v t="$TIMEOUT" -v s="${LAB_TIMEOUT_SCALE:-1}" 'BEGIN { printf "%d", t * s }')"
[ -f "$PAYLOAD/run.sh" ] || { echo "run-vm: $PAYLOAD/run.sh not found" >&2; exit 2; }
if [ ! -d "$LAB/cache/kernels/$VER" ]; then
    case "$VER" in
        rhel*) "$LAB/fetch-rhel-kernel.sh" "$VER" >&2 ;;
        *) "$LAB/fetch-kernel.sh" "$VER" >&2 ;;
    esac
fi
eval "$("$LAB/kernel-info.sh" "$VER")"
[ -f "$LAB/cache/base.raw" ] || { echo "run-vm: cache/base.raw missing, run build-rootfs.sh" >&2; exit 2; }
INITRD="$("$LAB/build-initramfs.sh" "$VER")"

TS="$(date +%Y%m%d-%H%M%S)"
RUNDIR="$LAB/runs/$VER-$TS"
LOG="$LAB/logs/$VER-$TS.log"
mkdir -p "$RUNDIR/results" "$LAB/logs"
: > "$LOG"

# One VM at a time: the host is shared with other heavy work.
exec 9>"$LAB/cache/vm.lock"
flock 9

qemu-img create -q -f qcow2 -b "$LAB/cache/base.raw" -F raw "$RUNDIR/overlay.qcow2"

APPEND="console=ttyS0,115200 root=/dev/vda rw rootfstype=ext4 init=/lab-init.sh panic=-1"
APPEND+=" cgroup_no_v1=all mitigations=off loglevel=4 rcupdate.rcu_cpu_stall_timeout=120"
APPEND+=" ${LAB_APPEND:-}"

# Kernels without 9p (RHEL-family) get the payload as a tar on a second disk and write their
# results as a tar over a third one.
TRANSPORT="${LAB_TRANSPORT:-}"
if [ -z "$TRANSPORT" ]; then
    TRANSPORT=9p
    grep -q '^CONFIG_NET_9P_VIRTIO=[ym]' "$CONFIG" || TRANSPORT=disk
fi
if [ "$TRANSPORT" = disk ]; then
    tar -C "$PAYLOAD" -cf "$RUNDIR/payload.tar" .
    truncate -s 4G "$RUNDIR/results.img"
    APPEND+=" lab.transport=disk"
fi

# KVM when this user can open /dev/kvm (Fedora: mode 0666, or the kvm group), else TCG
ACCEL="${LAB_ACCEL:-}"
if [ -z "$ACCEL" ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg,thread=multi; fi
fi
CPU="${LAB_CPU:-}"
if [ -z "$CPU" ]; then
    case "$ACCEL" in kvm*) CPU=host ;; *) CPU=max ;; esac
fi

QEMU_ARGS=(
    -accel "$ACCEL" -cpu "$CPU"
    -smp "${LAB_SMP:-2}" -m "${LAB_MEM:-4096}"
    -nodefaults -no-reboot -display none
    -kernel "$VMLINUZ" -append "$APPEND"
    -drive "file=$RUNDIR/overlay.qcow2,format=qcow2,if=virtio,cache=unsafe"
    -chardev stdio,id=con0,signal=off -serial chardev:con0
)
if [ "$TRANSPORT" = disk ]; then
    QEMU_ARGS+=(
        -drive "file=$RUNDIR/payload.tar,format=raw,if=virtio,readonly=on"
        -drive "file=$RUNDIR/results.img,format=raw,if=virtio,cache=unsafe"
    )
else
    QEMU_ARGS+=(
        -virtfs "local,path=$PAYLOAD,mount_tag=payload,security_model=none,readonly=on,multidevs=remap"
        -virtfs "local,path=$RUNDIR/results,mount_tag=results,security_model=none"
    )
fi
[ -n "$INITRD" ] && QEMU_ARGS+=(-initrd "$INITRD")
# Extra empty disks, after the payload and results disks: the guest finds them by their serial,
# as their names depend on the transport. They sit in PCI slots 0x10+, after the slots QEMU gives
# the if=virtio drives, so that the root disk stays vda.
n=0
for size in ${LAB_EXTRA_DISKS:-}; do
    n=$((n + 1))
    truncate -s "$size" "$RUNDIR/extra-$n.raw"
    QEMU_ARGS+=(
        -drive "file=$RUNDIR/extra-$n.raw,format=raw,if=none,id=extra$n,cache=unsafe"
        -device "virtio-blk-pci,drive=extra$n,serial=lab-extra-$n,addr=$(printf '0x%x' $((0x10 + n - 1)))"
    )
done

if [ -n "${LAB_NVME_MPATH:-}" ]; then
    truncate -s "$LAB_NVME_MPATH" "$RUNDIR/extra-nvme.raw"
    QEMU_ARGS+=(
        -device "nvme-subsys,id=labsubsys,nqn=lab-subsys"
        -device "nvme,serial=lab-nvme,subsys=labsubsys,id=labnvme0,addr=0x18"
        -device "nvme,serial=lab-nvme,subsys=labsubsys,id=labnvme1,addr=0x19"
        -drive "file=$RUNDIR/extra-nvme.raw,format=raw,if=none,id=labnvmens,cache=unsafe"
        -device "nvme-ns,drive=labnvmens,bus=labnvme0,nsid=1,shared=on"
    )
fi

# Reads the console, saves it to $LOG, streams payload lines to stdout and
# records the host time at which the guest init came up.
console_reader() {
    local line in_payload=0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        printf '%s\n' "$line" >> "$LOG"
        [ -n "${LAB_VERBOSE:-}" ] && printf '%s\n' "$line" >&2
        case "$line" in
            *===LAB_BOOTED===*) date +%s.%N > "$RUNDIR/booted_at" ;;
            *===LAB_PAYLOAD_BEGIN===*) in_payload=1; continue ;;
            *===LAB_PAYLOAD_END===*) in_payload=0; date +%s.%N > "$RUNDIR/payload_done_at" ;;
        esac
        [ "$in_payload" = 1 ] && printf '%s\n' "$line"
    done
    return 0
}

start="$(date +%s.%N)"
set +e
timeout -k 10 "$TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" </dev/null 2>"$RUNDIR/qemu.stderr" | console_reader
qrc="${PIPESTATUS[0]}"
set -e
end="$(date +%s.%N)"
[ -n "${LAB_KEEP:-}" ] || rm -f "$RUNDIR/overlay.qcow2" "$RUNDIR"/extra-*.raw
if [ "$TRANSPORT" = disk ]; then
    tar -xf "$RUNDIR/results.img" -C "$RUNDIR/results" 2>/dev/null || echo "[run-vm] no results tar" >&2
    rm -f "$RUNDIR/payload.tar" "$RUNDIR/results.img"
fi
flock -u 9

secs() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'; }
boot="n/a"; payload="n/a"
[ -f "$RUNDIR/booted_at" ] && boot="$(secs "$start" "$(cat "$RUNDIR/booted_at")")s"
[ -f "$RUNDIR/booted_at" ] && [ -f "$RUNDIR/payload_done_at" ] &&
    payload="$(secs "$(cat "$RUNDIR/booted_at")" "$(cat "$RUNDIR/payload_done_at")")s"
total="$(secs "$start" "$end")s"

guest_rc="$(grep -a -o 'LAB_EXIT=[0-9]*' "$LOG" | tail -1 | cut -d= -f2 || true)"
summary="kernel=$VER ($KREL) accel=${ACCEL%%,*} boot=$boot payload=$payload total=$total log=$LOG results=$RUNDIR/results"

if [ -n "$guest_rc" ]; then
    grep -a 'LAB_ERROR=' "$LOG" >&2 || true
    echo "[run-vm] exit=$guest_rc $summary" >&2
    exit "$guest_rc"
fi
if [ "$qrc" = 124 ] || [ "$qrc" = 137 ]; then
    echo "[run-vm] TIMEOUT after ${TIMEOUT}s; $summary" >&2
    exit 124
fi
echo "[run-vm] BOOT/INFRA FAILURE (qemu rc=$qrc, no LAB_EXIT); $summary" >&2
echo "---- last console lines ----" >&2
tail -40 "$LOG" >&2
cat "$RUNDIR/qemu.stderr" >&2
exit 125
