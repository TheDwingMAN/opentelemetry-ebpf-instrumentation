#!/usr/bin/env bash
# Print the pod -> PVC -> PV -> mount -> device chain exactly as the resolver
# will have to reconstruct it. Run this after up.sh to confirm the environment
# is exercising the real code path.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

echo "### Kubernetes objects"
kubectl -n storage-test get pvc,pv -o custom-columns=\
'KIND:.kind,NAME:.metadata.name,CLAIM:.spec.claimRef.name,VOLUME:.spec.volumeName,SC:.spec.storageClassName' 2>/dev/null

echo
echo "### pod -> PVC (from pod.spec.volumes)"
kubectl -n storage-test get pods -l workload=storage-io \
  -o jsonpath='{range .items[*]}{.metadata.name}{"  uid="}{.metadata.uid}{"  pvc="}{.spec.volumes[?(@.persistentVolumeClaim)].persistentVolumeClaim.claimName}{"\n"}{end}'

echo
echo "### kubelet mount table (what the resolver parses)"
for node in $(kubectl get nodes -o name | sed 's|node/||'); do
  echo "--- node: $node"
  docker exec "$node" sh -c \
    'grep " /var/lib/kubelet/pods/" /proc/self/mountinfo | grep -vE "kubernetes.io~projected|kubernetes.io~configmap|secret" |
     while read -r _ _ majmin _ mp _ rest; do
       fstype=$(echo "$rest" | awk -F" - " "{print \$2}" | awk "{print \$1}")
       src=$(echo "$rest" | awk -F" - " "{print \$2}" | awk "{print \$2}")
       printf "  s_dev=%-8s fstype=%-8s\n    mount=%s\n    src=%s\n" "$majmin" "$fstype" "$mp" "$src"
     done' 2>/dev/null
done

echo
echo "### NFS kprobe targets available on this kernel"
node=$(kubectl get nodes -o name | head -1 | sed 's|node/||')
docker exec "$node" sh -c \
  'grep -E "^(nfs_file_read|nfs_file_write|nfs_file_open|nfs_getattr|nfs4_file_open) " /sys/kernel/tracing/available_filter_functions' \
  2>/dev/null | sed 's/^/  /' || echo "  (none - is nfs.ko loaded?)"
