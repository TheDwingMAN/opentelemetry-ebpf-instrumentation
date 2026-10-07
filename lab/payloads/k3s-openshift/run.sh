#!/bin/bash
# The OpenShift manifest (configs/openshift/obi-openshift.yaml, placeholders filled) with the OBI image
# obi:disk-v2-29a3da1d8 on single-node k3s: OBI runs from the image with the user's config, talks to
# the Kubernetes API itself, and sends OTLP to a collector in the cluster that writes the metrics to a
# file. k3s has no SecurityContextConstraints: the SCC grant is applied but not enforced here.
set -u
echo "uname -r: $(uname -r)"
grep -q localhost /etc/hosts 2>/dev/null || echo "127.0.0.1 localhost" >> /etc/hosts
K=/work/k3s-root
mkdir -p $K && tar -xf k3s-root.tar -C $K && rm -f k3s-root.tar
for m in br_netfilter overlay nf_conntrack nf_nat iptable_nat iptable_filter iptable_mangle ip_tables x_tables \
  xt_conntrack xt_MASQUERADE xt_comment xt_mark xt_addrtype xt_nat xt_multiport veth bridge dummy nf_tables nft_compat; do
  modprobe $m 2>/dev/null
done
sysctl -qw net.ipv4.ip_forward=1
ip link set lo up
ip link add lab0 type dummy && ip addr add 10.0.2.15/24 dev lab0 && ip link set lab0 up
ip route add default via 10.0.2.2 dev lab0 onlink
mount --make-rshared /

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

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || exit 1
kubectl apply -f collector.yaml > /dev/null; result collector-apply $?
kubectl apply -f obi-openshift.yaml; result manifest-apply $?
kubectl apply -f manifests/ > /dev/null
wait_for "coredns running" 900 sh -c 'kubectl -n kube-system get pods -l k8s-app=kube-dns | grep -q "1/1"'
wait_for "collector running" 900 sh -c 'kubectl -n otel get pods | grep -q "1/1"'; result collector-running $?
wait_for "obi running" 900 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi | grep -q "1/1"'; result obi-running $?
kubectl -n obi get pods -o wide
kubectl -n obi get pod -l app.kubernetes.io/name=obi -o jsonpath='{.items[0].spec.containers[0].image}{"\n"}'
wait_for "disk-io running" 600 sh -c 'kubectl get pods -l app=disk-io | grep -q Running'

# disk and file sync activity on the node, besides the disk-io pod's
for _ in $(seq 1 30); do echo data > /var/tmp/f; sync /var/tmp/f; sleep 2; done

obi_log() { kubectl -n obi logs -l app.kubernetes.io/name=obi --tail=-1 2>/dev/null; }
obi_log > "$LAB_RESULTS/obi.log"
grep -q 'starting OBI in Stat metrics mode' "$LAB_RESULTS/obi.log"; result obi-stats-agent $?
awk '/^metrics:/ {m=1; print; next} m && /^[^ ]/ {m=0} m' "$LAB_RESULTS/obi.log" | head -8
! grep -qi 'forbidden' "$LAB_RESULTS/obi.log"; result obi-no-forbidden $?

m=$(curl -sf 10.0.2.15:9400/metrics)
echo "$m" | grep -o '^obi_stat_[a-z_]*' | sed -E 's/_(bucket|sum|count)$//' | sort -u | tr '\n' ' '; echo
echo "$m" | grep '^obi_stat_disk_operations_total{' | grep -q 'k8s_owner_name="disk-io"'; result node-disk-metrics-with-workload $?
echo "$m" | grep '^obi_stat_disk_operations_total{' | grep 'disk-io' | head -2 | cut -c1-300

wait_for "OTLP metrics in the collector" 300 grep -q 'obi.stat.disk.operations' /work/collector-out/metrics.json
result collector-got-disk-metrics $?
for name in obi.stat.disk.operations obi.stat.disk.io obi.stat.disk.operation.duration obi.stat.fs.sync.duration; do
  grep -q "\"$name\"" /work/collector-out/metrics.json; result "collector-$name" $?
done
grep -o '"k8s.owner.name","value":{"stringValue":"disk-io"}' /work/collector-out/metrics.json | head -1

grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | grep -v 'Cloud metadata' | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -10
cp /work/collector-out/metrics.json "$LAB_RESULTS/" 2>/dev/null
exit $fail
