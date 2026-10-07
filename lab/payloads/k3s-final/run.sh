#!/bin/bash
# Final verification of disk-v2-23410d280 on Kubernetes, from the payload that validated disk-v2-3d1a67934: the OpenShift manifest (configs/openshift/obi-openshift.yaml,
# placeholders filled) with OBI built from 4a3b33f31 on single-node k3s, with workloads in two namespaces,
# a pod with a local PV on LVM and a hostPath PV, a partitioned disk with fstrim, file syncs of every
# kind and a loopback NFS mount. OBI sends OTLP to a collector on the node, which writes it to a file,
# and a Prometheus on the node scrapes OBI's port 9400. Both go to $LAB_RESULTS for the dashboards.
set -u
echo "uname -r: $(uname -r)"
DURATION=${DURATION:-960}
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

# the local PV: ext4 on an LVM volume over a loop device; the hostPath PV: a directory of the root disk
export DM_DISABLE_UDEV=1
mkdir -p /var/lib/obi-lab; truncate -s 64M /var/lib/obi-lab/pv.img; pv_loop=$(losetup -f --show /var/lib/obi-lab/pv.img)
pvcreate -qq $pv_loop && vgcreate -qq labvg $pv_loop && lvcreate -qq -y -n pv -L 32M labvg
lv_dev=$(dmsetup info -c --noheadings -o blkdevname labvg-pv)
[ -b /dev/$lv_dev ] || mknod /dev/$lv_dev b $(tr ':' ' ' < /sys/class/block/$lv_dev/dev)
mkfs.ext4 -q /dev/$lv_dev && mkdir -p /mnt/lab-local && mount /dev/$lv_dev /mnt/lab-local
mkdir -p /var/lib/obi-lab/hostpath
# a partitioned disk: ext4 on its first partition, trimmed every minute
truncate -s 96M /tmp/part.img; part_loop=$(losetup -fP --show /tmp/part.img)
printf 'label: dos\n,48M,L\n,,L\n' | sfdisk -q $part_loop && partx -u $part_loop 2>/dev/null
p1=${part_loop}p1
for _ in 1 2 3 4 5; do [ -b $p1 ] && break; sleep 1; done
[ -b $p1 ] || mknod $p1 b $(tr ':' ' ' < /sys/class/block/$(basename $p1)/dev)
mkfs.ext4 -q $p1 && mkdir -p /mnt/part && mount $p1 /mnt/part
echo "local PV on $lv_dev over $(basename $pv_loop); partitioned disk $(basename $part_loop)"
# a loopback NFSv4.2 mount, before OBI starts so that the sunrpc and nfs modules are loaded
modprobe nfs; modprobe nfsd
mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs && nfs_ok=1 || { nfs_ok=0; echo "can't mount NFS"; }

# a zram disk, whose driver handles bios itself like the PowerFlex SDC
zram_ok=0
modprobe zram num_devices=0 2>/dev/null
if zid=$(cat /sys/class/zram-control/hot_add 2>/dev/null) && echo 32M > /sys/block/zram$zid/disksize; then
  zdev=zram$zid
  [ -b /dev/$zdev ] || mknod /dev/$zdev b $(tr ':' ' ' < /sys/class/block/$zdev/dev)
  zram_ok=1; echo "$zdev: scheduler '$(cat /sys/block/$zdev/queue/scheduler 2>/dev/null || echo absent)'"
else
  echo "no zram on this kernel"
fi

# the collector and Prometheus on the node
mkdir -p /work/collector-out /work/prom-data
cat > /work/collector.yaml <<'EOF'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: /work/collector-out/metrics.json
  debug:
    verbosity: basic
service:
  telemetry:
    metrics:
      level: none
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [file]
    traces:
      receivers: [otlp]
      exporters: [debug]
EOF
./otelcol-contrib --config=/work/collector.yaml > "$LAB_RESULTS/collector.log" 2>&1 &
cat > /work/prometheus.yml <<'EOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: obi
    static_configs:
      - targets: ['10.0.2.15:9400']
EOF
./prometheus --config.file=/work/prometheus.yml --storage.tsdb.path=/work/prom-data \
  --web.listen-address=127.0.0.1:9091 > "$LAB_RESULTS/prometheus.log" 2>&1 &
prom_pid=$!

mkdir -p /var/lib/rancher/k3s/agent/images /var/lib/rancher/k3s/server/manifests
mv images.tar /var/lib/rancher/k3s/agent/images/
cp manifests/*.yaml /var/lib/rancher/k3s/server/manifests/
export PATH=$PATH:$K/bin/aux:$K/bin
k3s server --disable traefik,servicelb,metrics-server,local-storage,coredns --disable-helm-controller \
  --disable-network-policy --flannel-backend=host-gw --node-ip 10.0.2.15 --write-kubeconfig-mode 644 \
  > "$LAB_RESULTS/k3s.log" 2>&1 &
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || exit 1
node=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
echo "node name: $node"
wait_for "obi running" 900 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi | grep -q "1/1"'; result obi-running $?
wait_for "workloads running" 900 sh -c '[ $(kubectl get pods -A -l role=writer --no-headers 2>/dev/null | grep -c Running) -ge 4 ]'
kubectl get pods -A -o wide

# node activity for DURATION seconds: file syncs of every kind and partition I/O, trims, NFS, and pods
# coming and going in the batch namespace
echo "##### activity for ${DURATION}s from $(date -u +%FT%TZ)"
start=$(date +%s); i=0
while [ $(($(date +%s) - start)) -lt $DURATION ]; do
  i=$((i + 1))
  dd if=/dev/urandom of=/mnt/part/f bs=64k count=32 status=none
  sync /mnt/part/f; sync -d /mnt/part/f; sync -f /mnt/part/f
  dd if=/dev/zero of=/var/tmp/synced bs=4k count=4 conv=fsync status=none
  rm -f /mnt/part/f
  if [ $nfs_ok = 1 ]; then
    dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
    dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
    ls /mnt/nfs/nonexistent 2>/dev/null
  fi
  [ $zram_ok = 1 ] && dd if=/dev/zero of=/dev/$zdev bs=4k count=8 oflag=direct status=none
  [ $((i % 6)) = 0 ] && fstrim /mnt/part
  [ $i = 30 ] && kubectl -n batch scale deployment report-writer --replicas=3 > /dev/null
  [ $i = 90 ] && kubectl -n batch scale deployment report-writer --replicas=1 > /dev/null
  sleep 10
done
echo "##### activity done at $(date -u +%FT%TZ)"
sleep 70 # the last OTLP export

curl -sf 10.0.2.15:9400/metrics > "$LAB_RESULTS/metrics.txt"
kubectl -n obi logs ds/obi --tail=-1 > "$LAB_RESULTS/obi.log" 2>&1
kubectl get pods -A -o wide > "$LAB_RESULTS/pods.txt"
grep -q 'starting OBI in Stat metrics mode' "$LAB_RESULTS/obi.log"; result obi-stats-agent $?
m="$LAB_RESULTS/metrics.txt"
grep '^obi_stat_disk_io_bytes_total{' $m | grep -q 'k8s_pod_name="report-writer-'; result pod-names $?
grep '^obi_stat_disk_io_bytes_total{' $m | grep -q 'obi_disk_partition="'"$(basename $p1)"'"'; result partition $?
grep '^obi_stat_k8s_pod_volume_device{' $m | grep 'k8s_persistentvolume_name="lab-local"' | grep -q ' 1$'; result pod-volumes $?
grep -q '^obi_stat_disk_discard_io_bytes_total{' $m; result discards $?
grep '^obi_stat_disk_volume_device{' $m
grep '^obi_stat_disk_volume_device{' $m | grep "obi_disk_volume_device=\"$lv_dev\"" | grep 'obi_disk_volume_name="labvg-pv"' | grep -q 'system_device="vda"'; result volume-device-lvm-to-vda $?
grep '^obi_stat_disk_operation_time_seconds_total{' $m | grep -q 'k8s_pod_name="report-writer-'; result operation-time-select-new-key $?
grep -qF '"obi.stat.disk.operation_time"' /work/collector-out/metrics.json; result otlp-operation-time-new-name $?
! grep -qF '{"value":{}}' /work/collector-out/metrics.json; result otlp-no-empty-attribute-key $?
grep -q '^obi_stat_disk_flush_duration_seconds_count{' $m; result flushes $?
grep '^obi_stat_fs_sync_duration_seconds_count{' $m | grep -q 'obi_fs_sync_type="syncfs"'; result fs-sync-types $?
[ $nfs_ok = 0 ] || { grep -q '^obi_stat_nfs_client_procedure_duration_seconds_count{' $m; result nfs $?; }
# G2: the file sync and NFS counters, per workload on Kubernetes
grep '^obi_stat_fs_sync_operations_total{' $m | grep -q 'k8s_owner_name="disk-io"'; result fs-sync-operations-per-workload $?
grep '^obi_stat_fs_sync_operation_time_seconds_total{' $m | grep -q 'k8s_owner_name="disk-io"'; result fs-sync-operation-time-per-workload $?
[ $nfs_ok = 0 ] || { grep -q '^obi_stat_nfs_client_procedure_count_total{' $m && grep -q '^obi_stat_nfs_client_procedure_time_seconds_total{' $m; result nfs-counters $?; }
grep -qF '"obi.stat.fs.sync.operations"' /work/collector-out/metrics.json && grep -qF '"obi.stat.nfs.client.procedure.count"' /work/collector-out/metrics.json; result otlp-new-counters $?
# G2: no storage histogram is configured per pod, so no warning about it
! grep -q 'reported per pod or container' "$LAB_RESULTS/obi.log"; result no-per-pod-histogram-warning $?
# G4: the bio-based zram disk of the node
if [ $zram_ok = 1 ]; then
  grep '^obi_stat_disk_operations_total{' $m | grep "system_device=\"$zdev\"" | grep -q 'obi_disk_stacked="false"'; result bio-based-disk $?
fi
grep -o '"host.id","value":{"stringValue":"[^"]*"' /work/collector-out/metrics.json | sort -u | head -3
grep -q '"host.id","value":{"stringValue":"'"$node"'"' /work/collector-out/metrics.json; result host-id-is-node-name $?
grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | grep -v 'Cloud metadata' | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -10

kill -TERM $prom_pid; wait $prom_pid 2>/dev/null
cp -r /work/prom-data "$LAB_RESULTS/prom-data"
cp /work/collector-out/metrics.json "$LAB_RESULTS/otlp.json"
du -sh "$LAB_RESULTS/prom-data" "$LAB_RESULTS/otlp.json"
exit $fail
