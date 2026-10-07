# Lab kernels

Ubuntu mainline builds (generic flavour, amd64) from https://kernel.ubuntu.com/mainline/<ver>/amd64/.
All eight requested versions had amd64 debs, so no substitutions were needed.
Extracted with `dpkg-deb -x` into `cache/kernels/<ver>/`; `./kernel-info.sh <ver>` prints the paths below.
Paths are relative to `lab/cache/kernels/<ver>/`. `setup.sh` compares each vmlinuz with the cloud lab's
(`KERNELS.sha256`).

| Version | Release (uname -r) | vmlinuz | Modules dir | Module compression | Package build |
|---|---|---|---|---|---|
| v5.8.18 | 5.8.18-050818-generic | `boot/vmlinuz-5.8.18-050818-generic` | `lib/modules/5.8.18-050818-generic` | none | 5.8.18-050818.202011011237 |
| v5.10.270 | 5.10.270-0510270-generic | `boot/vmlinuz-5.10.270-0510270-generic` | `lib/modules/5.10.270-0510270-generic` | none | 5.10.270-0510270.202609141137 |
| v5.15.221 | 5.15.221-0515221-generic | `boot/vmlinuz-5.15.221-0515221-generic` | `lib/modules/5.15.221-0515221-generic` | none | 5.15.221-0515221.202609141134 |
| v6.1.188 | 6.1.188-0601188-generic | `boot/vmlinuz-6.1.188-0601188-generic` | `lib/modules/6.1.188-0601188-generic` | none | 6.1.188-0601188.202609141410 |
| v6.6.157 | 6.6.157-0606157-generic | `boot/vmlinuz-6.6.157-0606157-generic` | `lib/modules/6.6.157-0606157-generic` | zstd | 6.6.157-0606157.202609141304 |
| v6.12.111 | 6.12.111-0612111-generic | `boot/vmlinuz-6.12.111-0612111-generic` | `lib/modules/6.12.111-0612111-generic` | zstd | 6.12.111-0612111.202609211340 |
| v6.18.54 | 6.18.54-061854-generic | `boot/vmlinuz-6.18.54-061854-generic` | `usr/lib/modules/6.18.54-061854-generic` | zstd | 6.18.54-061854.202609251533 |
| v7.2.6 | 7.2.6-070206-generic | `boot/vmlinuz-7.2.6-070206-generic` | `usr/lib/modules/7.2.6-070206-generic` | zstd | 7.2.6-070206.202609141300 |

## Kernel config (from `boot/config-*`)

| CONFIG_ | v5.8.18 | v5.10.270 | v5.15.221 | v6.1.188 | v6.6.157 | v6.12.111 | v6.18.54 | v7.2.6 |
|---|---|---|---|---|---|---|---|---|
| DEBUG_INFO_BTF | y | y | y | y | y | y | y | y |
| KPROBES | y | y | y | y | y | y | y | y |
| BPF_EVENTS | y | y | y | y | y | y | y | y |
| 9P_FS | m | m | m | m | m | m | m | m |
| NET_9P_VIRTIO | m | m | m | m | m | m | m | m |
| VIRTIO_PCI | y | y | y | y | y | y | y | y |
| VIRTIO_BLK | m | m | m | m | y | y | y | y |
| EXT4_FS | y | y | y | y | y | y | y | y |
| BLK_DEV_NULL_BLK | m | m | m | m | m | m | m | m |
| DM_DELAY | m | m | m | m | m | m | m | m |
| DM_FLAKEY | m | m | m | m | m | m | m | m |
| BLK_DEV_DM | y | y | y | y | y | y | y | y |
| BLK_CGROUP | y | y | y | y | y | y | y | y |
| CGROUP_WRITEBACK | y | y | y | y | y | y | y | y |
| FUSE_FS | y | y | y | y | y | y | y | y |
| OVERLAY_FS | m | m | m | m | m | m | m | m |
| BLK_DEV_LOOP | y | y | y | y | y | y | y | y |

`n` = not set. Notes:

- `VIRTIO_BLK=m` on 5.8–6.1, so those boots use a tiny busybox initramfs (`build-initramfs.sh`) that insmods virtio_blk and switch_roots. 6.6+ boot the disk directly.
- 9p (`9P_FS`, `NET_9P_VIRTIO`), `null_blk`, `dm_delay`, `dm_flakey` and `overlay` are modules everywhere; `lab-init.sh` modprobes them from the rootfs. `BLK_DEV_DM`, `BLK_DEV_LOOP`, `FUSE_FS` and `EXT4_FS` are built in everywhere.
- BTF, kprobes, BPF events, blk-cgroup and cgroup writeback are enabled on every kernel.

## RHEL-family kernels (added 2026-09-28)

quay.io (where the repo's CI gets its RHEL kernel images) was blocked from the cloud sandbox, so the
RHEL kernels come from Oracle Linux's Red Hat Compatible Kernel (RHCK) on yum.oracle.com: the RHEL
kernel rebuilt from Red Hat's sources. `fetch-rhel-kernel.sh <id>` downloads them and
`rpm-extract.py` unpacks `kernel-core` + `kernel-modules` (+ `kernel-modules-core` on 9.x) into
`cache/kernels/<id>/`.

| Id | Release (uname -r) | RHEL minor | Notes |
|---|---|---|---|
| rhel8.9 | 4.18.0-513.24.1.el8_9.x86_64 | 8.9 | vmlinux BTF only, no module BTF |
| rhel8.10 | 4.18.0-553.146.1.el8_10.x86_64 | 8.10 | vmlinux BTF only, no module BTF |
| rhel9.6 | 5.14.0-570.62.1.0.1.el9_6.x86_64 | 9.6 | vmlinux + module BTF |

They have no 9p (`CONFIG_NET_9P` unset) and virtio_blk and ext4 are modules, so:
- `build-initramfs.sh` loads virtio_blk, ext4 and their dependencies (from a host `depmod`);
- `run-vm.sh` passes the payload as a tar on /dev/vdb and reads the results back from a tar that
  the guest writes over /dev/vdc (`lab.transport=disk` on the cmdline, handled in `lab-init.sh`).

## Download URLs

Ubuntu mainline (`fetch-kernel.sh <ver>` reads the listing and picks the two generic amd64 debs):

```
https://kernel.ubuntu.com/mainline/<ver>/amd64/linux-image-unsigned-<release>_<package build>_amd64.deb
https://kernel.ubuntu.com/mainline/<ver>/amd64/linux-modules-<release>_<package build>_amd64.deb
```

with `<release>` and `<package build>` from the first table, e.g.
`https://kernel.ubuntu.com/mainline/v6.12.111/amd64/linux-image-unsigned-6.12.111-0612111-generic_6.12.111-0612111.202609211340_amd64.deb`.

Oracle Linux RHCK (`fetch-rhel-kernel.sh <id>`, the exact packages the cloud lab unpacked):

```
https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-core-4.18.0-513.24.1.el8_9.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-modules-4.18.0-513.24.1.el8_9.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-core-4.18.0-553.146.1.el8_10.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/getPackage/kernel-modules-4.18.0-553.146.1.el8_10.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/getPackage/kernel-core-5.14.0-570.62.1.0.1.el9_6.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/getPackage/kernel-modules-core-5.14.0-570.62.1.0.1.el9_6.x86_64.rpm
https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/getPackage/kernel-modules-5.14.0-570.62.1.0.1.el9_6.x86_64.rpm
```
