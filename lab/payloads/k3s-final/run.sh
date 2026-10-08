#!/bin/bash
# Final verification on Kubernetes (the image is built from the OBI checkout by build-payload.sh, under the
# tag of manifests/10-obi.yaml; COMMIT says which commit), from the payload that validated disk-v2-3d1a67934
# and disk-v2-23410d280: the OpenShift manifest (configs/openshift/obi-openshift.yaml,
# placeholders filled) on single-node k3s, with workloads in two namespaces,
# a pod with a local PV on LVM and a hostPath PV, a partitioned disk with fstrim, file syncs of every
# kind and a loopback NFS mount. OBI sends OTLP to a collector on the node, which writes it to a file,
# and a Prometheus on the node scrapes OBI's port 9400. Both go to $LAB_RESULTS for the dashboards.
# k3s runs in a mount namespace of its own pinned at /run/kubens/mnt (OpenShift's kubens), the NFS
# mount comes after OBI starts (late attach), and the checks cover the stall buckets, the kernel
# filesystem type names, the omitted empty k8s attributes, and the labels that the bundle's include
# lists must keep: error.type on the time counters, obi.disk.volume.name and k8s.kind.
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
# the PV that only the kubelet's mount namespace has: ext4 on a loop device of a file on vda, mounted in
# that namespace only (at the k3s start), so that the LocalPath fallback (a path on the host) can't hide it
truncate -s 32M /var/lib/obi-lab/kubens.img; kubens_loop=$(losetup -f --show /var/lib/obi-lab/kubens.img)
mkfs.ext4 -q $kubens_loop
mkdir -p /mnt/kubens-only
# the pin, as kubens.service does it: a namespace file can't be bind-mounted on a shared mount (/ is
# rshared above), so /run/kubens is first made an unbindable bind mount of itself
mkdir -p /run/kubens && mount --make-unbindable --bind /run/kubens /run/kubens && touch /run/kubens/mnt
# a partitioned disk: ext4 on its first partition, trimmed every minute
truncate -s 96M /tmp/part.img; part_loop=$(losetup -fP --show /tmp/part.img)
printf 'label: dos\n,48M,L\n,,L\n' | sfdisk -q $part_loop && partx -u $part_loop 2>/dev/null
p1=${part_loop}p1
for _ in 1 2 3 4 5; do [ -b $p1 ] && break; sleep 1; done
[ -b $p1 ] || mknod $p1 b $(tr ':' ' ' < /sys/class/block/$(basename $p1)/dev)
mkfs.ext4 -q $p1 && mkdir -p /mnt/part && mount $p1 /mnt/part
echo "local PV on $lv_dev over $(basename $pv_loop); partitioned disk $(basename $part_loop)"

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
cat > /var/lib/rancher/k3s/server/manifests/25-kubens.yaml <<'EOF'
# a local PersistentVolume whose path only the kubelet's mount namespace has
apiVersion: v1
kind: PersistentVolume
metadata:
  name: lab-kubens
spec:
  storageClassName: manual
  capacity:
    storage: 16Mi
  accessModes: [ReadWriteOnce]
  local:
    path: /mnt/kubens-only/pv
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/os
              operator: In
              values: [linux]
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lab-kubens-claim
  namespace: default
spec:
  storageClassName: manual
  volumeName: lab-kubens
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 16Mi
---
# no role: writer label, so the -ge 4 writers wait below is unchanged
apiVersion: apps/v1
kind: Deployment
metadata:
  name: disk-io-kubens
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: disk-io-kubens
  template:
    metadata:
      labels:
        app: disk-io-kubens
    spec:
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: lab-kubens-claim
      containers:
        - name: writer
          image: go-disk-io:dev
          imagePullPolicy: Never
          volumeMounts:
            - mountPath: /data
              name: data
EOF
# k3s (kubelet and containerd) in a mount namespace of its own, a slave of the host's, pinned at /run/kubens/mnt.
# The kubelet gives its runtime calls 15 min instead of 2: under emulation on a busy host, creating a container
# (and unpacking its image) took longer than 2 min, and the kubelet restarted every creation from scratch
KUBENS_LOOP=$kubens_loop unshare --mount=/run/kubens/mnt --propagation slave sh -c '
  mount --make-rshared /
  mount -t tmpfs tmpfs /mnt/kubens-only && mkdir /mnt/kubens-only/pv && mount "$KUBENS_LOOP" /mnt/kubens-only/pv
  exec k3s server --disable traefik,servicelb,metrics-server,local-storage,coredns --disable-helm-controller \
    --disable-network-policy --flannel-backend=host-gw --node-ip 10.0.2.15 --write-kubeconfig-mode 644 \
    --kubelet-arg=runtime-request-timeout=15m' \
  > "$LAB_RESULTS/k3s.log" 2>&1 &
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

wait_for "node ready" 900 sh -c 'kubectl get nodes | grep -qw Ready' || exit 1
node=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
echo "node name: $node"
wait_for "obi running" 900 sh -c 'kubectl -n obi get pods -l app.kubernetes.io/name=obi | grep -q "1/1"'; result obi-running $?
wait_for "workloads running" 900 sh -c '[ $(kubectl get pods -A -l role=writer --no-headers 2>/dev/null | grep -c Running) -ge 4 ]'
kubectl get pods -A -o wide
wait_for "the kubens pod" 300 sh -c '[ $(kubectl get pods -l app=disk-io-kubens --no-headers | grep -c Running) -ge 1 ]'
! grep -q '/pods/[^/]*/volumes/' /proc/1/mountinfo && nsenter --mount=/run/kubens/mnt grep -q '/pods/[^/]*/volumes/' /proc/self/mountinfo
result kubens-hides-the-mounts $?

kubectl -n obi logs ds/obi | grep -q 'waiting for the tracepoints of the sunrpc kernel module'; result nfs-waiting-warn $?
# a loopback NFSv4.2 mount, after OBI starts: the NFS probes attach when the modules are loaded
modprobe nfs; modprobe nfsd
mkdir -p /srv/nfs /mnt/nfs; mount -t tmpfs tmpfs /srv/nfs; mount -t nfsd nfsd /proc/fs/nfsd
rpcbind -w 2>/dev/null || rpcbind
exportfs -o rw,no_root_squash,fsid=0,insecure 127.0.0.1:/srv/nfs; rpc.mountd; rpc.nfsd 2
mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/nfs && nfs_ok=1 || { nfs_ok=0; echo "can't mount NFS"; }
# both families (procedures and I/O) log one INFO each; the 30 s ticker fits twice in 120 s
[ $nfs_ok = 0 ] || {
  wait_for "NFS probes attached" 120 sh -c "kubectl -n obi logs ds/obi | grep 'NFS client probes attached' | grep -q stats_nfs_client_procedure && kubectl -n obi logs ds/obi | grep 'NFS client probes attached' | grep -q stats_nfs_client_io"
  result nfs-late-attach $?
}

# node activity for DURATION seconds: file syncs of every kind and partition I/O, trims, NFS, and pods
# coming and going in the batch namespace
echo "##### activity for ${DURATION}s from $(date -u +%FT%TZ)"
start=$(date +%s); i=0
while [ $(($(date +%s) - start)) -lt $DURATION ]; do
  i=$((i + 1))
  dd if=/dev/urandom of=/mnt/part/f bs=64k count=32 status=none
  sync /mnt/part/f; sync -d /mnt/part/f; sync -f /mnt/part/f
  dd if=/dev/zero of=/var/tmp/synced bs=4k count=4 conv=fsync status=none
  dd if=/dev/zero of=/dev/shm/synced bs=4k count=1 conv=fsync status=none
  rm -f /mnt/part/f
  if [ $nfs_ok = 1 ]; then
    dd if=/dev/zero of=/mnt/nfs/f bs=64k count=16 oflag=direct status=none
    dd if=/mnt/nfs/f of=/dev/null bs=64k count=16 iflag=direct status=none
    ls /mnt/nfs/nonexistent 2>/dev/null
    sync /mnt/nfs/f
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
grep '^obi_stat_k8s_pod_volume_info{' $m | grep 'k8s_persistentvolume_name="lab-local"' | grep -q ' 1$'; result pod-volumes $?
grep '^obi_stat_k8s_pod_volume_info{' $m | grep 'k8s_persistentvolume_name="lab-kubens"' \
  | grep "obi_disk_volume_device=\"$(basename $kubens_loop)\"" | grep 'system_device="vda"' | grep -q ' 1$'
result pod-volumes-in-kubens-namespace $?
! grep -q 'no volume mount of the kubelet is visible' "$LAB_RESULTS/obi.log"; result no-mounts-warning-when-visible $?
grep -q '^obi_stat_disk_discard_io_bytes_total{' $m; result discards $?
grep '^obi_stat_disk_volume_info{' $m
grep '^obi_stat_disk_volume_info{' $m | grep "obi_disk_volume_device=\"$lv_dev\"" | grep 'obi_disk_volume_name="labvg-pv"' | grep -q 'system_device="vda"'; result volume-info-lvm-to-vda $?
grep '^obi_stat_disk_service_time_seconds_total{' $m | grep -q 'k8s_pod_name="report-writer-'; result service-time-select-new-key $?
grep -qF '"obi.stat.disk.service_time"' /work/collector-out/metrics.json; result otlp-service-time-new-name $?
# the four block counters keep the default labels in the bundle's include lists. Every one of them has
# series of the LVM volume, all named as /dev/mapper names it (obi.disk.volume.name)
lv_io=$(grep -E '^obi_stat_disk_(io_bytes|operations|service_time_seconds|queue_time_seconds)_total\{' $m | grep "system_device=\"$lv_dev\"")
echo "$lv_io" | head -4
[ "$(echo "$lv_io" | grep 'obi_disk_volume_name="labvg-pv"' | sed 's/{.*//' | sort -u | wc -l)" = 4 ] &&
  ! echo "$lv_io" | grep -vq 'obi_disk_volume_name="labvg-pv"'
result volume-name-on-lvm-io $?
# the kind of the pods' owner (k8s.kind), on the four block counters
[ "$(grep -E '^obi_stat_disk_(io_bytes|operations|service_time_seconds|queue_time_seconds)_total\{' $m |
  grep 'k8s_pod_name="report-writer-' | grep 'k8s_kind="Deployment"' | sed 's/{.*//' | sort -u | wc -l)" = 4 ]
result k8s-kind-on-pod-counters $?
# error.type on the time counters, as on the operations: OBI's endpoint shows it empty for the successful I/O
grep '^obi_stat_disk_service_time_seconds_total{' $m | grep -q 'error_type="'; result error-type-on-service-time $?
! grep -qF '{"value":{}}' /work/collector-out/metrics.json; result otlp-no-empty-attribute-key $?
# no storage data point carries an empty k8s.* attribute over OTLP
! grep -qE '"key":"k8s\.(namespace|owner|pod|container)\.name","value":\{"stringValue":""\}|"key":"k8s\.(kind|cluster\.name)","value":\{"stringValue":""\}' /work/collector-out/metrics.json; result otlp-no-empty-k8s-attribute $?
# the I/O of pods keeps its workload over OTLP (guards against omitting too much)
grep -qE '"key":"k8s\.namespace\.name","value":\{"stringValue":"default"\}' /work/collector-out/metrics.json && grep -qE '"key":"k8s\.owner\.name","value":\{"stringValue":"disk-io"\}' /work/collector-out/metrics.json; result otlp-pod-keeps-k8s-attributes $?
# OBI's Prometheus endpoint still exposes the pod-less I/O with empty workload labels
grep '^obi_stat_disk_io_bytes_total{' $m | grep -q 'k8s_namespace_name=""'; result prometheus-keeps-empty-workload-label $?
# the pod-less series are still exported over OTLP, without the attribute (zram I/O is issued from the host)
if [ $zram_ok = 1 ]; then
  grep -qF '"key":"system.device","value":{"stringValue":"'"$zdev"'"}' /work/collector-out/metrics.json; result otlp-pod-less-series-exported $?
fi
grep -q '^obi_stat_disk_flush_duration_seconds_count{' $m; result flushes $?
grep '^obi_stat_fs_sync_duration_seconds_count{' $m | grep -q 'obi_fs_sync_type="syncfs"'; result fs-sync-types $?
[ $nfs_ok = 0 ] || { grep -q '^obi_stat_nfs_client_procedure_duration_seconds_count{' $m; result nfs $?; }
# stall buckets at the defaults: OBI runs both exporters, so these cover the OTel and Prometheus union
for h in disk_operation disk_flush fs_sync; do
  grep -q "^obi_stat_${h}_duration_seconds_bucket{.*le=\"60\"" $m; result stall-bounds-$h $?
done
# the queue time has no histogram: it is a counter, which carries the pod like the other block counters
grep '^obi_stat_disk_queue_time_seconds_total{' $m | grep -q 'k8s_pod_name="report-writer-'; result queue-time-counter $?
[ $nfs_ok = 0 ] || { grep -q '^obi_stat_nfs_client_procedure_duration_seconds_bucket{.*le="60"' $m; result stall-bounds-nfs $?; }
# the 16 default bounds of the storage histograms end with 0.5, 1, 5, 30 and 60 s
grep -q '"explicitBounds":\[[^]]*,0\.5,1,5,30,60\]' /work/collector-out/metrics.json; result otlp-stall-bounds $?
! grep -q 'more histogram buckets than the kernel can keep' "$LAB_RESULTS/obi.log"; result no-approximated-buckets $?
# the kernel names of the filesystem types, on the file sync counter: the bundle keeps the mountpoint off
# the histogram, and the manifest selects it with the type on the counters, as the bundle's guide says
fs_sync_series=$(grep '^obi_stat_fs_sync_operations_total{' $m)
echo "$fs_sync_series" | grep 'system_filesystem_mountpoint="/mnt/part"' | grep -q 'system_filesystem_type="ext4"'; result fs-type-ext4 $?
echo "$fs_sync_series" | grep 'system_filesystem_mountpoint="/dev/shm"' | grep -q 'system_filesystem_type="tmpfs"'; result fs-type-tmpfs $?
[ $nfs_ok = 0 ] || { echo "$fs_sync_series" | grep 'system_filesystem_mountpoint="/mnt/nfs"' | grep -q 'system_filesystem_type="nfs4"'; result fs-type-nfs4 $?; }
[ "$(echo "$fs_sync_series" | grep 'system_filesystem_mountpoint="/' | grep -vc 'system_filesystem_type="[^"]')" = 0 ]; result fs-type-always-set $?
# tmpfs, not ext4: ext4 was already reported before this change, tmpfs was filtered out
grep -qF '"system.filesystem.type","value":{"stringValue":"tmpfs"}' /work/collector-out/metrics.json; result otlp-fs-type-string $?
# G2: the file sync and NFS counters, per workload on Kubernetes
grep '^obi_stat_fs_sync_operations_total{' $m | grep -q 'k8s_owner_name="disk-io"'; result fs-sync-operations-per-workload $?
grep '^obi_stat_fs_sync_operation_time_seconds_total{' $m | grep -q 'k8s_owner_name="disk-io"'; result fs-sync-operation-time-per-workload $?
[ $nfs_ok = 0 ] || { grep -q '^obi_stat_nfs_client_procedure_count_total{' $m && grep -q '^obi_stat_nfs_client_procedure_time_seconds_total{' $m; result nfs-counters $?; }
grep -qF '"obi.stat.fs.sync.operations"' /work/collector-out/metrics.json && grep -qF '"obi.stat.nfs.client.procedure.count"' /work/collector-out/metrics.json; result otlp-new-counters $?
# no storage histogram is configured per pod, container or volume, so no cardinality warning at startup
! grep -q 'storage latency histogram is reported per pod' "$LAB_RESULTS/obi.log"; result no-cardinality-warning $?
# G4: the bio-based zram disk of the node
if [ $zram_ok = 1 ]; then
  grep '^obi_stat_disk_operations_total{' $m | grep "system_device=\"$zdev\"" | grep -q 'obi_disk_stacked="false"'; result bio-based-disk $?
fi
grep -o '"host.id","value":{"stringValue":"[^"]*"' /work/collector-out/metrics.json | sort -u | head -3
grep -q '"host.id","value":{"stringValue":"'"$node"'"' /work/collector-out/metrics.json; result host-id-is-node-name $?
grep -E '"level":"(WARN|ERROR)"' "$LAB_RESULTS/obi.log" | grep -v 'Cloud metadata' | sed 's/.*"msg":"\([^"]*\)".*/\1/' | sort | uniq -c | head -10

# the kubelet's mount namespace unpinned: its mounts are hidden from OBI, which warns once
umount /run/kubens/mnt
sleep 100 # three resolutions of the pod volumes
kubectl -n obi logs ds/obi --tail=-1 > "$LAB_RESULTS/obi-hidden.log" 2>&1
[ "$(grep -c 'no volume mount of the kubelet is visible' "$LAB_RESULTS/obi-hidden.log")" = 1 ]
result mounts-hidden-warns-once $?

kill -TERM $prom_pid; wait $prom_pid 2>/dev/null
cp -r /work/prom-data "$LAB_RESULTS/prom-data"
cp /work/collector-out/metrics.json "$LAB_RESULTS/otlp.json"
du -sh "$LAB_RESULTS/prom-data" "$LAB_RESULTS/otlp.json"
exit $fail
