#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_IMAGE="${EBPFFLS_TEST_IMAGE:-ebpffls-test:bookworm}"

docker build -f "${ROOT_DIR}/tests/Dockerfile" -t "${TEST_IMAGE}" "${ROOT_DIR}"
docker run --rm --privileged --pid=host --ulimit memlock=-1:-1 \
  --mount "type=bind,src=${ROOT_DIR},dst=/workspace" \
  --mount type=volume,src=ebpffls-go-build,dst=/root/.cache/go-build \
  --mount type=volume,src=ebpffls-go-mod,dst=/go/pkg/mod \
  --workdir /workspace \
  "${TEST_IMAGE}" sh -eu -c '
    mount -t tracefs tracefs /sys/kernel/tracing
    mount -t securityfs securityfs /sys/kernel/security
    uname -r
    cat /sys/kernel/security/lsm
    make generate
    make integration-test
  '
