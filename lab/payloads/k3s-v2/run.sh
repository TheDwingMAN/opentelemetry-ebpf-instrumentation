#!/bin/bash
# Single-node k3s in the guest (no network: images are preloaded), OBI as a DaemonSet with the disk,
# file sync and pod volume stats. Checks the pod -> PVC -> PV -> disk series of a Deployment with a
# local PV (on LVM over a loop device) and a hostPath PV, and that the I/O is charged to it.
set -u
echo "uname -r: $(uname -r)"
K=/work/k3s-root
mkdir -p $K && tar -xf k3s-root.tar -C $K

for m in br_netfilter overlay nf_conntrack nf_nat iptable_nat iptable_filter iptable_mangle ip_tables x_tables \
  xt_conntrack xt_MASQUERADE xt_comment xt_mark xt_addrtype xt_nat xt_multiport veth bridge dummy nf_tables nft_compat; do
  modprobe $m 2>/dev/null
done
sysctl -qw net.ipv4.ip_forward=1
# the guest has no NIC: k3s needs one with a default route
# (loading the dummy module may already create dummy0: use a name of our own)
ip link add lab0 type dummy && ip addr add 10.0.2.15/24 dev lab0 && ip link set lab0 up
ip route add default via 10.0.2.2 dev lab0 onlink
ip route
mount --make-rshared /
# the local PV: ext4 on an LVM volume over a loop device; the hostPath PV: a directory of the root disk
export DM_DISABLE_UDEV=1
truncate -s 64M /tmp/pv.img; pv_loop=$(losetup -f --show /tmp/pv.img)
pvcreate -qq $pv_loop && vgcreate -qq labvg $pv_loop && lvcreate -qq -y -n pv -L 32M labvg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname labvg-pv)
[ -b /dev/$lv_dev ] || mknod /dev/$lv_dev b $(tr ':' ' ' < /sys/class/block/$lv_dev/dev)
mkfs.ext4 -q /dev/$lv_dev && mkdir -p /mnt/lab-local && mount /dev/$lv_dev /mnt/lab-local
mkdir -p /var/lib/obi-lab/hostpath
root_dev=$(findmnt -no MAJ:MIN -T /var/lib/obi-lab/hostpath)
echo "local PV on $lv_dev over $(basename $pv_loop); hostPath PV on $root_dev"
mkdir -p /var/lib/rancher/k3s/agent/images /var/lib/rancher/k3s/server/manifests
mv images.tar /var/lib/rancher/k3s/agent/images/
cp manifests/*.yaml /var/lib/rancher/k3s/server/manifests/

export PATH=$PATH:$K/bin/aux:$K/bin
k3s server --disable traefik,servicelb,metrics-server,local-storage,coredns --disable-helm-controller \
  --disable-network-policy --flannel-backend=host-gw --node-ip 10.0.2.15 --write-kubeconfig-mode 644 \
  > "$LAB_RESULTS/k3s.log" 2>&1 &
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

wait_for() { # description timeout-seconds command...
  local what=$1 timeout=$2; shift 2
  local start; start=$(date +%s)
  until "$@" >/dev/null 2>&1; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then echo "timed out waiting for $what"; return 1; fi
    sleep 5
  done
  echo "$what after $(($(date +%s) - start))s"
}
fail() {
  echo "RESULT k3s FAIL: $*"; kubectl get pods -A -o wide 2>&1 | head -20
  curl -sf localhost:9400/metrics | grep -E '^obi_stat_(fs_sync_duration_seconds_count|disk_operations)' | head -20
  kubectl logs -l app=obi --tail 400 > "$LAB_RESULTS/obi.log" 2>&1
  grep -iE 'kprobe|fsync|error|warn' "$LAB_RESULTS/obi.log" | head -20
  exit 1
}

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || fail "node not ready"
wait_for "obi running" 900 sh -c 'kubectl get pods -l app=obi | grep -q Running' || fail "obi not running"
wait_for "disk-io running" 600 sh -c 'kubectl get pods -l app=disk-io | grep -q Running' || fail "disk-io not running"
kubectl get pods -A -o wide
pid=$(pgrep -f go-disk-io | head -1)
echo "go-disk-io pid $pid cgroup: $(cat /proc/$pid/cgroup)"
cg=/sys/fs/cgroup$(sed 's/^0:://' /proc/$pid/cgroup)
while [ "$cg" != /sys/fs ]; do echo "$cg: controllers=[$(cat $cg/cgroup.controllers 2>/dev/null)] subtree=[$(cat $cg/cgroup.subtree_control 2>/dev/null)]"; cg=$(dirname $cg); done
wait_for "disk metrics of the disk-io workload" 600 sh -c \
  'curl -sf localhost:9400/metrics | grep "^obi_stat_disk_operations_total{" | grep "k8s_owner_name=\"disk-io\"" | grep -q "k8s_namespace_name=\"default\""' \
  || { curl -sf localhost:9400/metrics | grep '^obi_stat_disk' | head -20; kubectl logs -l app=obi --tail 30; fail "no disk metrics for disk-io"; }
for _ in $(seq 1 10); do dd if=/dev/zero of=/tmp/synced bs=4k count=1 conv=fsync status=none; done
wait_for "file sync metrics of the disk-io workload" 300 sh -c \
  'curl -sf localhost:9400/metrics | grep "^obi_stat_fs_sync_duration_seconds_count{" | grep -q "k8s_owner_name=\"disk-io\""' \
  || fail "no file sync metrics for disk-io"
wait_for "disk-io-pvc running" 600 sh -c 'kubectl get pods -l app=disk-io-pvc | grep -q Running' || fail "disk-io-pvc not running"
vol() { curl -sf localhost:9400/metrics | grep '^obi_stat_k8s_pod_volume_device{' | grep 'k8s_owner_name="disk-io-pvc"'; }
has_hostpath_volume() { vol | grep -q 'k8s_persistentvolume_name="lab-hostpath"'; }
lvm_io() { curl -sf localhost:9400/metrics | grep '^obi_stat_disk_io_bytes_total{' | grep 'k8s_owner_name="disk-io-pvc"' | grep "system_device=\"$lv_dev\""; }
volumes_gone() { vol | grep -q ' 0$' && ! vol | grep -q ' 1$'; }

wait_for "pod volume devices of disk-io-pvc" 300 has_hostpath_volume || { vol; fail "no pod volume devices"; }
vol
local_ok=$(vol | grep 'k8s_persistentvolume_name="lab-local"' | grep 'k8s_persistentvolumeclaim_name="lab-local-claim"' \
  | grep 'k8s_volume_name="data"' | grep 'k8s_volume_type="persistentVolumeClaim"' | grep "obi_disk_volume_device=\"$lv_dev\"" \
  | grep "system_device=\"$(basename $pv_loop)\"" | grep 'k8s_namespace_name="default"' | grep -c ' 1$')
echo "local PV series (want 1): $local_ok"
[ "$local_ok" = 1 ] || fail "wrong local PV series"
host_disk=$(vol | grep 'k8s_persistentvolume_name="lab-hostpath"' | grep -o 'system_device="[^"]*"')
echo "hostPath PV on $host_disk (root filesystem $root_dev)"
[ -n "$host_disk" ] || fail "no hostPath PV series"
wait_for "block I/O of disk-io-pvc on its LVM volume" 300 lvm_io || fail "no I/O of disk-io-pvc on $lv_dev"
lvm_io
kubectl delete deployment disk-io-pvc --wait=true
wait_for "pod volume devices of disk-io-pvc back to 0" 300 volumes_gone || { vol; fail "the volumes of the deleted pod are still reported"; }
vol
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt"
kubectl logs -l app=obi --tail 200 > "$LAB_RESULTS/obi.log" 2>&1
grep '^obi_stat_disk_operations_total{' "$LAB_RESULTS/metrics.txt" | grep 'disk-io'
grep '^obi_stat_disk_operations_total{' "$LAB_RESULTS/metrics.txt" | grep 'k8s_owner_name="disk-io"' | grep -q 'k8s_cluster_name="lab-k3s"' \
  || fail "missing cluster name"
echo "RESULT k3s PASS"
