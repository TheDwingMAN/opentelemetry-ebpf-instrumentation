#!/bin/bash
# Single-node k3s in the guest (no network: images are preloaded), OBI as a DaemonSet with the disk
# and file sync stats, and a Deployment doing direct I/O. Checks that the I/O is charged to the
# Deployment, with its Kubernetes metadata.
set -u
echo "uname -r: $(uname -r)"
K=/work/k3s-root
mkdir -p $K && tar -xf k3s-root.tar -C $K && rm -f k3s-root.tar

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
curl -sf localhost:9400/metrics > "$LAB_RESULTS/metrics.txt"
grep '^obi_stat_fs_sync_duration_seconds_count{' "$LAB_RESULTS/metrics.txt"
kubectl logs -l app=obi --tail 200 > "$LAB_RESULTS/obi.log" 2>&1
grep '^obi_stat_disk_operations_total{' "$LAB_RESULTS/metrics.txt" | grep 'disk-io'
grep '^obi_stat_disk_operations_total{' "$LAB_RESULTS/metrics.txt" | grep 'k8s_owner_name="disk-io"' | grep -q 'k8s_cluster_name="lab-k3s"' \
  || fail "missing cluster name"
echo "RESULT k3s PASS"
