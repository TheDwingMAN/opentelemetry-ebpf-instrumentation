#!/bin/bash
# The k3s-openshift-ccb payload (the OpenShift manifest on single-node k3s, OTLP to a collector in the
# cluster) with the OBI image obi:disk-v2-8d3d6d35c of feat/disk-loop-backing, and more pod volumes,
# to check the disks that their pod -> PVC -> PV -> disk series end on:
#   lab-local       ext4 on LVM (labvg/pv) over a loop device whose file is on the root disk: the
#                   disk is the root disk (vda), not the loop device
#   lab-tmpfs-loop  ext4 on a loop device whose file is on tmpfs, on no block device: the loop device
#                   stays the disk
#   lab-lvm         ext4 on LVM (labvg2/pv) over a whole extra virtio disk, written with O_DIRECT and
#                   fsync by the disk-io-lvm Deployment: the disk is the extra disk, and the I/O of the
#                   extra disk carries the pod of that Deployment
#   lab-hostpath    a hostPath PV on the root disk, as before
# Needs one extra disk: LAB_MEM=6144 LAB_SMP=4 LAB_EXTRA_DISKS=1G ./run-vm.sh v6.12.111 payloads/k3s-volumes 2400
set -u
echo "uname -r: $(uname -r)"
grep -q localhost /etc/hosts 2>/dev/null || echo "127.0.0.1 localhost" >> /etc/hosts
K=/work/k3s-root
mkdir -p $K && tar -xf k3s-root.tar -C $K && rm -f k3s-root.tar
for m in br_netfilter overlay nf_conntrack nf_nat iptable_nat iptable_filter iptable_mangle ip_tables x_tables \
  xt_conntrack xt_MASQUERADE xt_comment xt_mark xt_addrtype xt_nat xt_multiport veth bridge dummy nf_tables nft_compat \
  loop dm_mod; do
  modprobe $m 2>/dev/null
done
sysctl -qw net.ipv4.ip_forward=1
ip link set lo up
ip link add lab0 type dummy && ip addr add 10.0.2.15/24 dev lab0 && ip link set lab0 up
ip route add default via 10.0.2.2 dev lab0 onlink
mount --make-rshared /

fail=0
result() { if [ "$2" -eq 0 ]; then echo "RESULT $1 PASS"; else echo "RESULT $1 FAIL"; fail=1; fi; }
wait_for() { # description timeout-seconds command...
  local what=$1 timeout=$2; shift 2
  local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then echo "timed out waiting for $what"; return 1; fi
    sleep 5
  done
  echo "$what after $(($(date +%s) - start))s"
}
# the device node of a block device, which LVM may not create without udev
devnode() { [ -b /dev/$1 ] || mknod /dev/$1 b $(tr ':' ' ' < /sys/class/block/$1/dev); }

export DM_DISABLE_UDEV=1
mkdir -p /var/lib/obi-lab/hostpath
root_disk=$(basename "$(readlink -f /sys/dev/block/$(findmnt -no MAJ:MIN -T /var/lib/obi-lab | tr -d ' '))")
echo "root disk: $root_disk"

# lab-local: LVM over a loop device whose file is on the root disk
truncate -s 64M /var/lib/obi-lab/pv.img; pv_loop=$(basename "$(losetup -f --show /var/lib/obi-lab/pv.img)")
pvcreate -qq /dev/$pv_loop && vgcreate -qq labvg /dev/$pv_loop && lvcreate -qq -y -n pv -L 32M labvg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname labvg-pv)
devnode $lv_dev
mkfs.ext4 -q /dev/$lv_dev && mkdir -p /mnt/lab-local && mount /dev/$lv_dev /mnt/lab-local
echo "lab-local on $lv_dev over $pv_loop, whose file $(cat /sys/block/$pv_loop/loop/backing_file) is on" \
  "$(findmnt -no SOURCE -T /var/lib/obi-lab/pv.img)"

# lab-tmpfs-loop: a loop device whose file is on tmpfs
truncate -s 32M /tmp/tmpfs-pv.img; tmpfs_loop=$(basename "$(losetup -f --show /tmp/tmpfs-pv.img)")
mkfs.ext4 -q /dev/$tmpfs_loop && mkdir -p /mnt/lab-tmpfs-loop && mount /dev/$tmpfs_loop /mnt/lab-tmpfs-loop
echo "lab-tmpfs-loop on $tmpfs_loop, whose file $(cat /sys/block/$tmpfs_loop/loop/backing_file) is on" \
  "$(findmnt -no SOURCE,FSTYPE -T /tmp/tmpfs-pv.img)"

# lab-lvm: LVM over the extra disk itself, found by its virtio serial
extra_disk=""
for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = lab-extra-1 ] && extra_disk=${d##*/}; done
echo "extra disk: ${extra_disk:-none} ($(cat /sys/block/${extra_disk:-none}/size 2>/dev/null) sectors)"
[ -n "$extra_disk" ]; result extra-disk-found $?
lvm_dev=""
if [ -n "$extra_disk" ]; then
  pvcreate -qq /dev/$extra_disk && vgcreate -qq labvg2 /dev/$extra_disk && lvcreate -qq -y -n pv -L 64M labvg2
  lvm_dev=$(dmsetup info -c --noheadings -o blkdevname labvg2-pv)
  devnode $lvm_dev
  mkfs.ext4 -q /dev/$lvm_dev && mkdir -p /mnt/lab-lvm && mount /dev/$lvm_dev /mnt/lab-lvm
  echo "lab-lvm on $lvm_dev over $(ls /sys/block/$lvm_dev/slaves)"
fi
[ -n "$lvm_dev" ] && [ "$(ls /sys/block/$lvm_dev/slaves)" = "$extra_disk" ] && mountpoint -q /mnt/lab-lvm
result lvm-on-extra-disk-setup $?

mkdir -p /var/lib/rancher/k3s/agent/images /work/collector-out
mv images.tar images-collector.tar images-obi.tar /var/lib/rancher/k3s/agent/images/
export PATH=$PATH:$K/bin/aux:$K/bin
k3s server --disable traefik,servicelb,metrics-server,local-storage --disable-helm-controller \
  --disable-network-policy --flannel-backend=host-gw --node-ip 10.0.2.15 --write-kubeconfig-mode 644 \
  > "$LAB_RESULTS/k3s.log" 2>&1 &
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

metrics() { curl -sf 10.0.2.15:9400/metrics; }

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || exit 1
kubectl apply -f collector.yaml > /dev/null; result collector-apply $?
kubectl apply -f obi-openshift.yaml; result manifest-apply $?
kubectl apply -f manifests/ > /dev/null
wait_for "coredns running" 900 sh -c 'kubectl -n kube-system get pods -l k8s-app=kube-dns | grep -q "1/1"'
wait_for "collector running" 900 sh -c 'kubectl -n otel get pods | grep -q "1/1"'; result collector-running $?
wait_for "obi running" 900 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi | grep -q "1/1"'; result obi-running $?
kubectl -n obi get pods -o wide
image=$(kubectl -n obi get pod -l app.kubernetes.io/name=obi -o jsonpath='{.items[0].spec.containers[0].image}')
echo "$image"; [ "$image" = docker.io/library/obi:disk-v2-8d3d6d35c ]; result obi-image $?
wait_for "disk-io running" 600 sh -c 'kubectl get pods -l app=disk-io | grep -q Running'
wait_for "disk-io-pvc running" 600 sh -c 'kubectl get pods -l app=disk-io-pvc | grep -q Running'; result pvc-workload-running $?
wait_for "disk-io-lvm running" 600 sh -c 'kubectl get pods -l app=disk-io-lvm | grep -q Running'; result lvm-workload-running $?
kubectl get pods -o wide

# disk and file sync activity on the node, besides the disk-io pods'
for _ in $(seq 1 30); do echo data > /var/tmp/f; sync /var/tmp/f; sleep 2; done

obi_log() { kubectl -n obi logs -l app.kubernetes.io/name=obi --tail=-1 2>/dev/null; }
obi_log > "$LAB_RESULTS/obi.log"
grep -q 'starting OBI in Stat metrics mode' "$LAB_RESULTS/obi.log"; result obi-stats-agent $?
grep -o '"msg":"OpenTelemetry eBPF Instrumentation"[^}]*' "$LAB_RESULTS/obi.log" | head -1
grep -q '"Version":"disk-v2-8d3d6d35c","Revision":"8d3d6d35c"' "$LAB_RESULTS/obi.log"; result obi-version $?
awk '/^metrics:/ {m=1; print; next} m && /^[^ ]/ {m=0} m' "$LAB_RESULTS/obi.log" | head -8
! grep -qi 'forbidden' "$LAB_RESULTS/obi.log"; result obi-no-forbidden $?

m=$(metrics)
echo "$m" | grep -o '^obi_stat_[a-z_]*' | sed -E 's/_(bucket|sum|count)$//' | sort -u | tr '\n' ' '; echo
echo "$m" | grep '^obi_stat_disk_operations_total{' | grep -q 'k8s_owner_name="disk-io"'; result node-disk-metrics-with-workload $?
echo "$m" | grep '^obi_stat_disk_io_bytes_total{' | grep 'k8s_owner_name="disk-io"' | grep -q 'k8s_pod_name="disk-io-'
result disk-io-with-pod-name $?
echo "$m" | grep '^obi_stat_disk_operations_total{' | grep 'disk-io' | head -2 | cut -c1-400
echo "$m" | grep '^obi_stat_fs_sync_duration_seconds_count{' | grep -q 'obi_fs_sync_type="'; result fs-sync-type $?

vol() { metrics | grep '^obi_stat_k8s_pod_volume_device{' | grep 'k8s_owner_name="disk-io-pvc"'; }
has_volumes() {
  vol | grep 'k8s_persistentvolume_name="lab-local"' | grep 'k8s_persistentvolumeclaim_name="lab-local-claim"' |
    grep -q "obi_disk_volume_device=\"$lv_dev\"" &&
  vol | grep -q 'k8s_persistentvolume_name="lab-hostpath"'
}
wait_for "pod volume devices of disk-io-pvc" 300 has_volumes; result pod-volume-devices $?
vol | cut -c1-500

# a: the loop device of lab-local resolves to the disk that holds its file, and only to it
local_series() { vol | grep 'k8s_persistentvolume_name="lab-local"' | grep ' 1$'; }
local_on_root_disk() {
  [ "$(local_series | wc -l)" -eq 1 ] &&
    local_series | grep "obi_disk_volume_device=\"$lv_dev\"" | grep -q "system_device=\"$root_disk\""
}
wait_for "lab-local on $root_disk" 120 local_on_root_disk; result pod-volume-loop-file-on-disk $?
[ "$root_disk" = vda ]; result pod-volume-loop-root-disk-is-vda $?
# the fallback: a loop device whose file is on tmpfs stays the disk
tmpfs_loop_is_disk() {
  vol | grep 'k8s_persistentvolume_name="lab-tmpfs-loop"' | grep "obi_disk_volume_device=\"$tmpfs_loop\"" |
    grep -q "system_device=\"$tmpfs_loop\""
}
wait_for "lab-tmpfs-loop on $tmpfs_loop" 120 tmpfs_loop_is_disk; result pod-volume-loop-file-on-tmpfs $?

# b: LVM over the extra disk: the volume series, and the pod on the I/O of the physical disk
lvm_vol() { metrics | grep '^obi_stat_k8s_pod_volume_device{' | grep 'k8s_owner_name="disk-io-lvm"'; }
lvm_on_extra_disk() {
  lvm_vol | grep 'k8s_persistentvolume_name="lab-lvm"' | grep 'k8s_persistentvolumeclaim_name="lab-lvm-claim"' |
    grep "obi_disk_volume_device=\"$lvm_dev\"" | grep -q "system_device=\"$extra_disk\""
}
wait_for "lab-lvm on $lvm_dev over $extra_disk" 300 lvm_on_extra_disk; result pod-volume-lvm-on-extra-disk $?
lvm_vol | cut -c1-500
io_of() { metrics | grep '^obi_stat_disk_io_bytes_total{' | grep "system_device=\"$1\""; }
extra_disk_io_of_pod() {
  io_of "$extra_disk" | grep 'obi_disk_stacked="false"' | grep 'k8s_owner_name="disk-io-lvm"' |
    grep -q 'k8s_pod_name="disk-io-lvm-'
}
wait_for "I/O of disk-io-lvm on $extra_disk" 300 extra_disk_io_of_pod; result extra-disk-io-charged-to-pod $?
lvm_volume_io_of_pod() {
  io_of "$lvm_dev" | grep 'obi_disk_stacked="true"' | grep 'k8s_owner_name="disk-io-lvm"' |
    grep -q 'k8s_pod_name="disk-io-lvm-'
}
wait_for "I/O of disk-io-lvm on $lvm_dev" 120 lvm_volume_io_of_pod; result lvm-volume-io-charged-to-pod $?
labels() { # the given labels and the value of each metric line on stdin
  local line l out
  while IFS= read -r line; do
    out=""
    for l in "$@"; do out="$out $(echo "$line" | grep -o "$l=\"[^\"]*\"")"; done
    echo "$out ${line##* }"
  done
}
for dev in "$extra_disk" "$lvm_dev"; do
  echo "obi_stat_disk_io_bytes_total series of $dev:"
  io_of "$dev" | labels system_device obi_disk_stacked disk_io_direction k8s_owner_name k8s_pod_name
done

wait_for "OTLP metrics in the collector" 300 grep -q 'obi.stat.disk.operations' /work/collector-out/metrics.json
result collector-got-disk-metrics $?
wait_for "OTLP pod volume metric in the collector" 300 grep -q '"obi.stat.k8s.pod.volume.device"' /work/collector-out/metrics.json
for name in obi.stat.disk.operations obi.stat.disk.io obi.stat.disk.operation.duration obi.stat.fs.sync.duration \
  obi.stat.k8s.pod.volume.device; do
  grep -q "\"$name\"" /work/collector-out/metrics.json; result "collector-$name" $?
done
grep -o '"k8s.owner.name","value":{"stringValue":"disk-io"}' /work/collector-out/metrics.json | head -1
grep -o '"k8s.persistentvolume.name","value":{"stringValue":"lab-local"}' /work/collector-out/metrics.json | head -1

grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | grep -v 'Cloud metadata' | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -10
metrics > "$LAB_RESULTS/metrics.prom"
cp /work/collector-out/metrics.json "$LAB_RESULTS/" 2>/dev/null
exit $fail
