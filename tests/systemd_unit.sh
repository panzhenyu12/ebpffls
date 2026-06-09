#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT="${ROOT_DIR}/deploy/systemd/ebpffls.service"

fail() {
  echo "[systemd-unit] FAIL: $*" >&2
  exit 1
}

grep -q '^ExecStart=/usr/local/bin/ebpffls monitor --config /etc/ebpffls/ransomware.yaml --dry-run=false$' "${UNIT}" ||
  fail "service must run monitor with enforcement enabled"
grep -q '^Restart=always$' "${UNIT}" ||
  fail "service must restart automatically"
grep -q '^ProtectSystem=strict$' "${UNIT}" ||
  fail "service must enable strict filesystem protection"
grep -q '^ReadWritePaths=/run /var/log /var/lib/ebpffls$' "${UNIT}" ||
  fail "service must keep writes scoped"
grep -q '^CapabilityBoundingSet=.*CAP_BPF' "${UNIT}" ||
  fail "service must include CAP_BPF"
grep -q '^CapabilityBoundingSet=.*CAP_KILL' "${UNIT}" ||
  fail "service must include CAP_KILL for userspace enforcement"

echo "[systemd-unit] ok"
