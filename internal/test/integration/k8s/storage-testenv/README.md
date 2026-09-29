# OBI storage-metrics test cluster

A kind cluster for developing and validating OBI's storage metrics, with real
Kubernetes storage objects and a real NFS client path.

```bash
./up.sh        # create cluster + NFS server + PVCs + workloads (+ OBI if obi:dev exists)
./verify.sh    # print the pod -> PVC -> PV -> mount -> device chain
./down.sh      # delete the cluster
```

To include the OBI DaemonSet, build the image first, then re-run `up.sh`:

```bash
(cd ../../../../.. && make image-build)
```

## What this environment gives you

Verified working, not assumed:

- **Real dynamically-provisioned PV/PVC objects**, with `pvc-<uuid>` names
  exactly as a production cluster produces. This matters because the mount-path
  resolver has to parse those names.
- **The real kernel NFS client path.** The server is nfs-ganesha (userspace, so
  it needs no `nfsd` module and works inside a network namespace), but the
  client side uses the kernel's `nfs.ko`/`nfsv4.ko` -- which is what OBI
  instruments.
- **Real kubelet mount paths**, which is the join key the whole PV/PVC
  attribution design rests on:

  ```
  s_dev  = 0:574
  fstype = nfs4
  mount  = /var/lib/kubelet/pods/<pod-uid>/volumes/kubernetes.io~nfs/<pv-name>
  src    = 10.96.84.126:/export/<pv-name>
  ```

  Note `s_dev` has major 0: NFS superblocks get an *anonymous* dev_t from
  `get_anon_bdev()`. It joins exactly to `mountinfo.MajorMinorVer`, but it can
  never be walked down to a physical device. Reaching a block device requires
  bridging through the mount `src`.

- **All five kprobe targets confirmed attachable** on this kernel:
  `nfs_file_read`, `nfs_file_write`, `nfs_file_open`, `nfs_getattr` (in `nfs`),
  and `nfs4_file_open` (in `nfsv4`).

- **A DaemonSet with the mount-propagation prerequisite.** `03-obi-daemonset.yml`
  mounts `/var/lib/kubelet` with `mountPropagation: HostToContainer`. The
  existing `06-obi-daemonset.yml` does not, and without it `procfs.GetMounts()`
  sees only the agent's own mount namespace and the whole PV/PVC join resolves
  nothing.

## What this environment does NOT give you

Stated plainly, because these gaps decide what still needs real VMs:

- **No kernel isolation.** kind nodes are containers sharing the *host* kernel.
  This host runs 7.0.12, where every NFS/FUSE/Ceph tracepoint and all module BTF
  happens to be present. Validating OBI's stated floor -- 5.8 with BTF, and
  RHEL8-family 4.18 -- requires real VMs. A kprobe-based design is the more
  portable choice precisely because it does not depend on module BTF, but that
  claim is untested here.

- **No realistic block-device path.** kind nodes run on `overlay` (itself an
  anonymous dev), and the `standard` local-path PVC is a bind into that
  overlay rather than a distinct mount. So the `local-io` workload exercises
  the *workload* side but produces nothing meaningful for block-layer
  attribution. Testing LVM, MD RAID, or dm-crypt attribution needs VMs with
  real virtual disks.

- **LOCALIO may short-circuit the wire.** `nfs_localio` is loaded and the server
  shares the client's kernel, so NFS can bypass the network path. The
  `nfs_file_*` probes still fire correctly -- the instrumentation path is fully
  exercised -- but measured latency will be unrealistically low. Do not use this
  environment to validate latency *distributions*.

## Files

| file | purpose |
|---|---|
| `kind-storage.yml` | 2-node cluster; mounts `/lib/modules` and `/sys/kernel/tracing` |
| `01-nfs-server.yml` | nfs-ganesha provisioner, RBAC, `obi-nfs` StorageClass |
| `02-workloads.yml` | NFS + local-path PVCs and one I/O workload each |
| `03-obi-daemonset.yml` | OBI with `hostPID`, `privileged`, and the kubelet mount |
| `up.sh` / `down.sh` / `verify.sh` | lifecycle and chain verification |
