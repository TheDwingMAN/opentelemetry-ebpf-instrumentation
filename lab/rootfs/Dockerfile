FROM docker.io/library/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils findutils util-linux mount e2fsprogs kmod fio iproute2 procps \
        curl ca-certificates strace dmsetup less xz-utils zstd \
        fdisk lvm2 mdadm nfs-kernel-server nfs-common rpcbind \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN echo lab > /etc/hostname && mkdir -p /payload /results /lib/modules
