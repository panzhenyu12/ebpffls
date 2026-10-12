FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash build-essential python3 rsync iproute2 util-linux kmod \
       busybox-static e2fsprogs qemu-system-x86 qemu-utils bpftool \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY tests/kernel_vm_init.sh /kernel-vm-init
RUN chmod 0755 /kernel-vm-init

WORKDIR /workspace
