#!/bin/bash
# The bundle's debug script (bundle/debug/obi-debug.sh) on single-node k3s, with OBI and the
# k8s-cache from the bundle and an OpenTelemetry Collector 0.161.0 in the cluster. Each scenario
# breaks the path in one place and checks that the script names that place:
#   1. the bundle as is: otel_metrics_export commented out, OBI sends no OTLP
#   2. OTLP to the collector, OBI's internal metrics on: nothing broken
#   3. a collector exporter that fails without a sending queue: the collector refuses the data
#   4. OTEL_EXPORTER_OTLP_METRICS_ENDPOINT without /v1/metrics: 404 from the collector
#   5. the wrong port in otel_metrics_export: connection refused
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

mkdir -p /var/lib/rancher/k3s/agent/images
mv images.tar images-collector.tar /var/lib/rancher/k3s/agent/images/
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
# some disk I/O to measure between the scenarios
io() { for _ in $(seq 1 20); do dd if=/dev/zero of=/var/tmp/io bs=64k count=16 oflag=direct status=none; sleep 1; done; }
rollout_obi() {
  kubectl -n obi rollout status ds/obi --timeout=600s >/dev/null 2>&1
  wait_for "obi running" 600 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi | grep -q "1/1"'
}
# debug <scenario> <expected text in the result> [variables...]
debug() {
  local name=$1 want=$2; shift 2
  io
  echo "##### scenario $name"
  (cd bundle/debug && env "$@" ./obi-debug.sh) > "$LAB_RESULTS/debug-$name.txt" 2>&1
  cat "$LAB_RESULTS/debug-$name.txt"
  sed -n '/^== Result/,$p' "$LAB_RESULTS/debug-$name.txt" | grep -qF "$want"
  result "debug-$name" $?
}

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || exit 1
kubectl apply -f collector/collector.yaml -f collector/config-healthy.yaml >/dev/null; result collector-apply $?
kubectl apply -k bundle >/dev/null; result apply-k $?
wait_for "coredns running" 900 sh -c 'kubectl -n kube-system get pods -l k8s-app=kube-dns | grep -q "1/1"'
wait_for "collector running" 900 sh -c 'kubectl -n otel get pods | grep -q "1/1"'; result collector-running $?
wait_for "k8s-cache ready" 900 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi-k8s-cache | grep -q "1/1"'
rollout_obi; result obi-running $?
sleep 30

debug 1-no-otlp "OBI doesn't send OTLP to the collector"

sed -i -e 's|^# otel_metrics_export:|otel_metrics_export:|' \
  -e 's|^#   endpoint: http://otel-collector:4318|  endpoint: http://otel-collector.otel.svc:4318|' \
  -e 's|^#   protocol: http/protobuf|  protocol: http/protobuf|' bundle/obi-config.yaml
grep -A2 '^otel_metrics_export:' bundle/obi-config.yaml
kubectl apply -k bundle >/dev/null
kubectl -n obi set env ds/obi OTEL_EBPF_INTERNAL_METRICS_EXPORTER=prometheus \
  OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT=9400 OTEL_EBPF_METRICS_INTERVAL=15s >/dev/null
rollout_obi
sleep 45
debug 2-healthy "No break found along the way"
grep -q 'OBI delivers its metrics to the collector' "$LAB_RESULTS/debug-2-healthy.txt"; result debug-2-obi-delivers $?
grep -q 'accepted otlp' "$LAB_RESULTS/debug-2-healthy.txt"; result debug-2-collector-accepts $?

kubectl apply -f collector/config-failing-exporter.yaml >/dev/null
kubectl -n otel rollout restart deploy/otel-collector >/dev/null
kubectl -n otel rollout status deploy/otel-collector --timeout=600s >/dev/null
sleep 45
debug 3-failing-exporter "the collector can't write to otlphttp/backend and so refuses the metrics"
grep -q 'fails to send metrics to: otlphttp/backend' "$LAB_RESULTS/debug-3-failing-exporter.txt"; result debug-3-names-exporter $?

kubectl apply -f collector/config-healthy.yaml >/dev/null
kubectl -n otel rollout restart deploy/otel-collector >/dev/null
kubectl -n otel rollout status deploy/otel-collector --timeout=600s >/dev/null
kubectl -n obi set env ds/obi OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otel-collector.otel.svc:4318 >/dev/null
rollout_obi
sleep 45
debug 4-metrics-endpoint-no-path "the collector answers 404"
grep -q '404 Not Found' "$LAB_RESULTS/debug-4-metrics-endpoint-no-path.txt"; result debug-4-logs-404 $?

kubectl -n obi set env ds/obi OTEL_EXPORTER_OTLP_METRICS_ENDPOINT- >/dev/null
sed -i 's|endpoint: http://otel-collector.otel.svc:4318|endpoint: http://otel-collector.otel.svc:4319|' bundle/obi-config.yaml
kubectl apply -k bundle >/dev/null
rollout_obi
sleep 45
debug 5-wrong-port "OBI can't deliver to the collector"

kubectl get pods -A -o wide
exit $fail
