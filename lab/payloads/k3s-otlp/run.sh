#!/bin/bash
# The disk dashboard through the OpenTelemetry Collector: single-node k3s in the guest, OBI as a
# DaemonSet with every disk, file sync, NFS and pod volume feature, exporting OTLP to a real
# otelcol-contrib. Two Prometheus servers scrape the collector's Prometheus exporters, one with the
# default settings and one with resource_to_telemetry_conversion, and their TSDBs are saved to the
# results for the dashboard checks on the host.
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

# storage: the local PV on LVM over a loop device, the hostPath PV on the root disk
export DM_DISABLE_UDEV=1
truncate -s 64M /tmp/pv.img; pv_loop=$(losetup -f --show /tmp/pv.img)
pvcreate -qq $pv_loop && vgcreate -qq labvg $pv_loop && lvcreate -qq -y -n pv -L 32M labvg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname labvg-pv)
[ -b /dev/$lv_dev ] || mknod /dev/$lv_dev b $(tr ':' ' ' < /sys/class/block/$lv_dev/dev)
mkfs.ext4 -q /dev/$lv_dev && mkdir -p /mnt/lab-local && mount /dev/$lv_dev /mnt/lab-local
mkdir -p /var/lib/obi-lab/hostpath
echo "local PV on $lv_dev over $(basename $pv_loop)"

# a loopback NFSv4.2 mount, before OBI starts so that the sunrpc and nfs modules are loaded
modprobe nfs; modprobe nfsd
mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs && echo "NFS mounted" || echo "can't mount NFS"

cat > otelcol.yml <<'CFG'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  prometheus/default:
    endpoint: 127.0.0.1:9464
  prometheus/resource:
    endpoint: 127.0.0.1:9465
    resource_to_telemetry_conversion:
      enabled: true
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus/default, prometheus/resource]
CFG
./otelcol-contrib --config=otelcol.yml > "$LAB_RESULTS/otelcol.log" 2>&1 &
for exporter in default:9464 resource:9465; do
  name=${exporter%%:*} port=${exporter##*:}
  mkdir -p /tmp/prom-$name
  # the default setup keeps Prometheus' defaults: the collector's address as instance
  honor=false; [ $name = resource ] && honor=true
  cat > prom-$name.yml <<CFG
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: otelcol
    honor_labels: $honor
    static_configs:
      - targets: ["127.0.0.1:$port"]
CFG
  ./prometheus --config.file=prom-$name.yml --storage.tsdb.path=/tmp/prom-$name \
    --web.listen-address=127.0.0.1:$((9090 + ${#name})) > "$LAB_RESULTS/prom-$name.log" 2>&1 &
done
echo "collector and prometheus started"

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
metrics() { curl -sf 127.0.0.1:9464/metrics; }
fail() {
  echo "RESULT k3s-otlp FAIL: $*"; kubectl get pods -A -o wide 2>&1 | head -20
  kubectl logs -l app=obi --tail 400 > "$LAB_RESULTS/obi.log" 2>&1
  grep -iE 'error|warn' "$LAB_RESULTS/obi.log" | head -20
  tail -5 "$LAB_RESULTS/otelcol.log"
  exit 1
}
has() { metrics | grep "^$1{" | grep -q "$2"; }

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || fail "node not ready"
wait_for "obi running" 900 sh -c 'kubectl get pods -l app=obi | grep -q Running' || fail "obi not running"
wait_for "disk-io-pvc running" 600 sh -c 'kubectl get pods -l app=disk-io-pvc | grep -q Running' || fail "disk-io-pvc not running"
kubectl get pods -A -o wide

# load: syncs of each kind, NFS I/O, discards and flushes, for 3 minutes
end=$(($(date +%s) + 180))
while [ "$(date +%s)" -lt $end ]; do
  echo data > /mnt/lab-local/host-file
  sync /mnt/lab-local/host-file; sync -d /mnt/lab-local/host-file; sync -f /mnt/lab-local/host-file
  dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
  dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
  ls /mnt/nfs/missing 2>/dev/null
  fstrim /mnt/lab-local 2>/dev/null
  sleep 5
done

wait_for "disk metrics through the collector" 120 has obi_stat_disk_operations_total 'k8s_owner_name="disk-io-pvc"' || fail "no disk metrics"
wait_for "file sync metrics through the collector" 120 has obi_stat_fs_sync_duration_seconds_count 'obi_fs_sync_type="syncfs"' || fail "no file sync metrics"
wait_for "NFS metrics through the collector" 120 has obi_stat_nfs_client_procedure_duration_seconds_count 'onc_rpc_procedure_name="WRITE"' || fail "no NFS metrics"
wait_for "pod volume metrics through the collector" 120 has obi_stat_k8s_pod_volume_device 'k8s_persistentvolume_name="lab-local"' || fail "no pod volume metrics"
metrics > "$LAB_RESULTS/collector-default.txt"
curl -sf 127.0.0.1:9465/metrics > "$LAB_RESULTS/collector-resource.txt"
echo "series at the default exporter: $(grep -c '^obi_stat' "$LAB_RESULTS/collector-default.txt")"
grep '^obi_stat_k8s_pod_volume_device{' "$LAB_RESULTS/collector-default.txt"
grep '^obi_stat_k8s_pod_volume_device{' "$LAB_RESULTS/collector-resource.txt" | head -1
grep '^target_info' "$LAB_RESULTS/collector-default.txt" | head -2

sleep 20 # the last scrapes
for p in $(pgrep -f 'prometheus --config'); do kill $p; done
sleep 5
date -u +%s > "$LAB_RESULTS/end-epoch"
tar -czf "$LAB_RESULTS/prom-default.tgz" -C /tmp prom-default
tar -czf "$LAB_RESULTS/prom-resource.tgz" -C /tmp prom-resource
kubectl logs -l app=obi --tail 200 > "$LAB_RESULTS/obi.log" 2>&1
grep -iE 'level=(warn|error)' "$LAB_RESULTS/obi.log" | head -10
echo "RESULT k3s-otlp PASS"
