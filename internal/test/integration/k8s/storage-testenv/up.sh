#!/usr/bin/env bash
# Bring up the OBI storage test cluster. Idempotent.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"
REPO_ROOT=$(cd ../../../../.. && pwd)

if ! kind get clusters 2>/dev/null | grep -qx obi-storage; then
  echo "==> creating kind cluster"
  kind create cluster --config kind-storage.yml --wait 120s
else
  echo "==> cluster obi-storage already exists"
fi

echo "==> NFS server + storage classes"
kubectl apply -f 01-nfs-server.yml
kubectl -n storage-test wait --for=condition=available deploy/nfs-provisioner --timeout=180s

echo "==> PVCs + I/O workloads"
kubectl apply -f 02-workloads.yml
kubectl -n storage-test wait --for=condition=available deploy/nfs-io deploy/local-io --timeout=240s

if docker image inspect obi:dev >/dev/null 2>&1; then
  echo "==> loading obi:dev into the cluster"
  kind load docker-image obi:dev --name obi-storage
  kubectl apply -f 03-obi-daemonset.yml
  kubectl -n storage-test rollout status ds/obi --timeout=180s
else
  echo "==> SKIPPING OBI DaemonSet: image obi:dev not found."
  echo "    Build it first:  (cd $REPO_ROOT && make image-build)"
  echo "    Then re-run this script."
fi

echo
echo "==> ready. Verify the attribution chain with:  ./verify.sh"
