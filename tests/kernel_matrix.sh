#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" == Darwin ]]; then
  CACHE_ROOT="${EBPFFLS_KERNEL_CACHE:-${HOME}/Library/Caches/ebpffls-kernel-matrix}"
else
  CACHE_ROOT="${EBPFFLS_KERNEL_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/ebpffls-kernel-matrix}"
fi
VM_IMAGE="${EBPFFLS_VM_IMAGE:-ebpffls-kernel-vm:bookworm}"
BUILD_IMAGE="${EBPFFLS_TEST_IMAGE:-ebpffls-test:bookworm}"
SOURCE_CONTAINER=""
VM_CONTAINER=""

cleanup() {
  if [[ -n "${VM_CONTAINER}" ]]; then
    docker stop --time 2 "${VM_CONTAINER}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${SOURCE_CONTAINER}" ]]; then
    docker rm "${SOURCE_CONTAINER}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

usage() {
  echo "usage: kernel_matrix.sh prepare | freeze | run ARTIFACT_DIR KERNEL_DIR KERNEL_SERIES [LSM_LIST]"
  echo "Caches and reports: ${CACHE_ROOT}"
}

prepare() {
  docker build -f "${ROOT_DIR}/tests/kernel_vm.Dockerfile" -t "${VM_IMAGE}" "${ROOT_DIR}"
  mkdir -p "${CACHE_ROOT}/rootfs"
  local image_id
  image_id="$(docker image inspect --format '{{.Id}}' "${VM_IMAGE}")"
  image_id="${image_id#sha256:}"
  local raw_image="${CACHE_ROOT}/rootfs/${image_id}.raw"
  if [[ ! -f "${raw_image}" ]]; then
    local staging
    staging="$(mktemp -d "${CACHE_ROOT}/rootfs/staging.XXXXXX")"
    SOURCE_CONTAINER="$(docker create "${VM_IMAGE}" /bin/true)"
    docker export "${SOURCE_CONTAINER}" | docker run --rm -i \
      --mount "type=bind,src=${staging},dst=/staging" "${VM_IMAGE}" \
      tar -xf - -C /staging
    docker rm "${SOURCE_CONTAINER}" >/dev/null
    SOURCE_CONTAINER=""
    docker run --rm \
      --mount "type=bind,src=${staging},dst=/staging,readonly" \
      --mount "type=bind,src=${CACHE_ROOT}/rootfs,dst=/images" \
      "${VM_IMAGE}" mke2fs -q -t ext4 -d /staging "/images/${image_id}.raw" 2097152
  fi
  printf '%s\n' "${raw_image}" >"${CACHE_ROOT}/rootfs/current"
  echo "[kernel-matrix] rootfs=${raw_image}"
}

freeze() {
  mkdir -p "${CACHE_ROOT}/artifacts"
  local snapshot
  snapshot="$(mktemp -d "${CACHE_ROOT}/artifacts/build.XXXXXX")"
  docker build -f "${ROOT_DIR}/tests/Dockerfile" -t "${BUILD_IMAGE}" "${ROOT_DIR}"
  docker run --rm \
    --mount "type=bind,src=${ROOT_DIR},dst=/workspace" \
    --mount "type=bind,src=${snapshot},dst=/snapshot" \
    --mount type=volume,src=ebpffls-go-build,dst=/root/.cache/go-build \
    --mount type=volume,src=ebpffls-go-mod,dst=/go/pkg/mod \
    --workdir /workspace "${BUILD_IMAGE}" bash -eu -c '
      make generate
      mkdir -p /snapshot/bin /snapshot/bpf
      CGO_ENABLED=0 go build -trimpath -o /snapshot/bin/ebpffls ./cmd/ebpffls
      CGO_ENABLED=0 go build -trimpath -o /snapshot/bin/lsm-chain-test ./tests/lsm_chain
      clang -O2 -g -Wall -Werror -target bpf -I bpf -c bpf/test_lsm_chain.bpf.c -o /snapshot/bpf/test_lsm_chain.bpf.o
      cp -R tests /snapshot/tests
      cd /snapshot
      sha256sum bin/ebpffls > binary.sha256
      sha256sum bin/ebpffls bin/lsm-chain-test bpf/test_lsm_chain.bpf.o > artifacts.sha256
      go version > build-toolchain.txt
    '
  docker image inspect --format '{{.Id}}' "${BUILD_IMAGE}" >"${snapshot}/build-image.txt"
  printf '%s\n' "${snapshot}" >"${CACHE_ROOT}/artifacts/current"
  echo "[kernel-matrix] frozen_artifacts=${snapshot}"
}

run_kernel() {
  [[ "$#" -ge 3 && "$#" -le 4 ]] || { usage >&2; exit 2; }
  local artifacts kernel_dir series lsm_list raw_image
  artifacts="$(cd "$1" && pwd)"
  kernel_dir="$(cd "$2" && pwd)"
  series="$3"
  lsm_list="${4:-capability,bpf}"
  [[ "${series}" =~ ^[0-9]+\.[0-9]+$ ]] || { echo "invalid kernel series" >&2; exit 2; }
  [[ "${lsm_list}" =~ ^[a-z,]+$ ]] || { echo "invalid LSM list" >&2; exit 2; }
  read -r raw_image <"${CACHE_ROOT}/rootfs/current"
  [[ -f "${raw_image}" && -f "${artifacts}/binary.sha256" ]] || { echo "run prepare and freeze first" >&2; exit 2; }
  local kernels=("${kernel_dir}"/boot/vmlinuz-*)
  [[ "${#kernels[@]}" == 1 && -f "${kernels[0]}" ]] || { echo "expected exactly one vmlinuz artifact" >&2; exit 2; }
  mkdir -p "${CACHE_ROOT}/results"
  local result_dir
  result_dir="$(mktemp -d "${CACHE_ROOT}/results/${series}.XXXXXX")"
  printf '%s\n' "${series}" >"${result_dir}/kernel-series"
  printf '%s\n' "${artifacts}" >"${result_dir}/artifact-directory"
  printf '%s\n' "${lsm_list}" >"${result_dir}/lsm-request"
  cp "${kernel_dir}"/boot/config-* "${result_dir}/kernel.config"
  cp "${artifacts}/binary.sha256" "${result_dir}/binary.sha256"
  docker run --rm \
    --mount "type=bind,src=${raw_image},dst=/base.raw,readonly" \
    --mount "type=bind,src=${result_dir},dst=/results" \
    "${VM_IMAGE}" qemu-img create -f qcow2 -F raw -b /base.raw /results/guest.qcow2 >/dev/null
  VM_CONTAINER="ebpffls-kernel-${series//./-}-${result_dir##*.}"
  echo "[kernel-matrix] kernel=${series} artifacts=${artifacts} results=${result_dir}"
  set +e
  docker run --rm --name "${VM_CONTAINER}" \
    --mount "type=bind,src=${raw_image},dst=/base.raw,readonly" \
    --mount "type=bind,src=${artifacts},dst=/artifacts,readonly" \
    --mount "type=bind,src=${kernel_dir}/boot,dst=/kernel,readonly" \
    --mount "type=bind,src=${result_dir},dst=/results" \
    "${VM_IMAGE}" timeout "${EBPFFLS_VM_TIMEOUT:-3600}" \
    qemu-system-x86_64 -accel tcg,thread=multi -cpu max -smp 2 -m 2048 \
      -nodefaults -display none -no-reboot -serial stdio -nic none \
      -kernel "/kernel/${kernels[0]##*/}" \
      -append "root=/dev/vda rw console=ttyS0 init=/kernel-vm-init panic=-1 lsm=${lsm_list}" \
      -drive file=/results/guest.qcow2,if=virtio,format=qcow2 \
      -fsdev local,id=artifacts,path=/artifacts,security_model=none,readonly=on \
      -device virtio-9p-pci,fsdev=artifacts,mount_tag=artifacts \
      -fsdev local,id=results,path=/results,security_model=none \
      -device virtio-9p-pci,fsdev=results,mount_tag=results \
      2>&1 | tee "${result_dir}/console.log"
  local vm_status="${PIPESTATUS[0]}"
  set -e
  VM_CONTAINER=""
  [[ "${vm_status}" == 0 && -f "${result_dir}/guest-exit-code" ]] || { echo "VM failed; see ${result_dir}/console.log" >&2; return 1; }
  local guest_status
  read -r guest_status <"${result_dir}/guest-exit-code"
  [[ "${guest_status}" == 0 ]] || { echo "Guest tests failed; see ${result_dir}" >&2; return 1; }
  echo "[kernel-matrix] PASS kernel=${series} results=${result_dir}"
}

case "${1:-}" in
  prepare) prepare ;;
  freeze) freeze ;;
  run) shift; run_kernel "$@" ;;
  *) usage >&2; exit 2 ;;
esac
