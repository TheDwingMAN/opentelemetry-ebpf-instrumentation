#!/bin/bash
# The OpenShift manifest (configs/openshift/obi-openshift.yaml, placeholders filled) with the OBI image
# obi:disk-v2-ccb2404e6 on single-node k3s: OBI runs from the image with the user's config, talks to
# the Kubernetes API itself, and sends OTLP to a collector in the cluster that writes the metrics to a
# file. k3s has no SecurityContextConstraints: the SCC grant is applied but not enforced here.
# Besides the disk and file sync metrics, checks the pod -> PVC -> PV -> disk series of a Deployment
# with a local PV (ext4 on LVM over a loop device) and a hostPath PV.
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

# the local PV: ext4 on an LVM volume over a loop device; the hostPath PV: a directory of the root disk
export DM_DISABLE_UDEV=1
truncate -s 64M /tmp/pv.img; pv_loop=$(losetup -f --show /tmp/pv.img)
pvcreate -qq $pv_loop && vgcreate -qq labvg $pv_loop && lvcreate -qq -y -n pv -L 32M labvg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname labvg-pv)
[ -b /dev/$lv_dev ] || mknod /dev/$lv_dev b $(tr ':' ' ' < /sys/class/block/$lv_dev/dev)
mkfs.ext4 -q /dev/$lv_dev && mkdir -p /mnt/lab-local && mount /dev/$lv_dev /mnt/lab-local
mkdir -p /var/lib/obi-lab/hostpath
echo "local PV on $lv_dev over $(basename $pv_loop); hostPath PV on $(findmnt -no SOURCE -T /var/lib/obi-lab/hostpath)"

mkdir -p /var/lib/rancher/k3s/agent/images /work/collector-out
mv images.tar images-collector.tar images-obi.tar /var/lib/rancher/k3s/agent/images/
export PATH=$PATH:$K/bin/aux:$K/bin
k3s server --disable traefik,servicelb,metrics-server,local-storage --disable-helm-controller \
  --disable-network-policy --flannel-backend=host-gw --node-ip 10.0.2.15 --write-kubeconfig-mode 644 \
  > "$LAB_RESULTS/k3s.log" 2>&1 &
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

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
echo "$image"; [ "$image" = docker.io/library/obi:disk-v2-ccb2404e6 ]; result obi-image $?
wait_for "disk-io running" 600 sh -c 'kubectl get pods -l app=disk-io | grep -q Running'
wait_for "disk-io-pvc running" 600 sh -c 'kubectl get pods -l app=disk-io-pvc | grep -q Running'; result pvc-workload-running $?

# disk and file sync activity on the node, besides the disk-io pods'
for _ in $(seq 1 30); do echo data > /var/tmp/f; sync /var/tmp/f; sleep 2; done

obi_log() { kubectl -n obi logs -l app.kubernetes.io/name=obi --tail=-1 2>/dev/null; }
obi_log > "$LAB_RESULTS/obi.log"
grep -q 'starting OBI in Stat metrics mode' "$LAB_RESULTS/obi.log"; result obi-stats-agent $?
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
cp /work/collector-out/metrics.json "$LAB_RESULTS/" 2>/dev/null
exit $fail
