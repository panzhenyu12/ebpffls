#!/bin/bash
set -eu

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /run /tmp /workspace /results
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t securityfs securityfs /sys/kernel/security
mount -t tracefs tracefs /sys/kernel/tracing
mount -t bpf bpf /sys/fs/bpf
mount -t 9p -o trans=virtio,version=9p2000.L,ro artifacts /workspace
mount -t 9p -o trans=virtio,version=9p2000.L results /results
ip link set lo up
ulimit -l unlimited

finish() {
  local status="$?"
  trap - EXIT
  printf '\nKERNEL_VM_EXIT=%d\n' "${status}"
  printf '%d\n' "${status}" >/results/guest-exit-code
  sync
  /bin/busybox poweroff -f
}
trap finish EXIT

read -r expected_sha _ </workspace/binary.sha256
read -r expected_kernel </results/kernel-series
export EBPFFLS_TEST_TIMEOUT_SCALE=8
bash /workspace/tests/kernel_guest.sh \
  --binary /workspace/bin/ebpffls \
  --expected-sha256 "${expected_sha}" \
  --kernel-series "${expected_kernel}" \
  --output-dir /results \
  --lsm-chain-helper /workspace/bin/lsm-chain-test \
  --lsm-guard-object /workspace/bpf/test_lsm_chain.bpf.o
