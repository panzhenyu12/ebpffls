#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/ebpffls"
TMP_DIR="$(mktemp -d /tmp/ebpffls-it.XXXXXX)"
AGENT_PID=""
BADLOOP=""
SPOOF=""

if [[ "${EUID}" -ne 0 ]]; then
  echo "integration tests must run as root" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${AGENT_PID}" ]]; then
    kill "${AGENT_PID}" 2>/dev/null || true
    wait "${AGENT_PID}" 2>/dev/null || true
  fi
  if [[ -n "${BADLOOP}" ]]; then
    pkill -f "${BADLOOP}" 2>/dev/null || true
  fi
  if [[ -n "${SPOOF}" ]]; then
    pkill -f "${SPOOF}" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

log() {
  printf '[integration] %s\n' "$*"
}

fail() {
  echo "[integration] FAIL: $*" >&2
  exit 1
}

stop_agent() {
  if [[ -n "${AGENT_PID}" ]]; then
    kill "${AGENT_PID}" 2>/dev/null || true
    wait "${AGENT_PID}" 2>/dev/null || true
    AGENT_PID=""
  fi
}

write_policy() {
  local path="$1"
  local name="$2"
  local threshold="$3"
  local action="$4"
  local protected_dir="$5"
  local blacklist_file="$6"
  local scan="${7:-30s}"

  cat >"${path}" <<YAML
name: ${name}
window: 10s
threshold: ${threshold}
action: ${action}
block_ttl: 1m
protected_dirs:
  - ${protected_dir}
backup_dirs:
  - ${protected_dir}/backup
trusted_processes:
  - ebpffls
blacklist_scan: ${scan}
blacklist_hashes: []
blacklist_hash_files:
  - ${blacklist_file}
suspicious_extensions:
  - .locked
  - .encrypted
  - .crypt
  - .crypto
  - .enc
ransom_note_names:
  - README_FOR_DECRYPT.txt
  - README_TO_DECRYPT.txt
  - DECRYPT_INSTRUCTIONS.txt
  - RECOVER_FILES.txt
  - RECOVER_FILES.html
  - HOW_TO_DECRYPT.txt
scores:
  write: 1
  truncate: 6
  rename: 8
  unlink: 8
  suspicious_extension: 10
  ransom_note: 20
  backup_destroy: 20
  high_rate_bonus: 15
  exec_after_blocked: 10
YAML
}

start_agent() {
  local policy="$1"
  local logfile="$2"
  local mode="${3:-enforce}"

  stop_agent
  if [[ "${mode}" == "dry-run" ]]; then
    "${BIN}" monitor --config "${policy}" >"${logfile}" 2>&1 &
  else
    "${BIN}" monitor --config "${policy}" --dry-run=false >"${logfile}" 2>&1 &
  fi
  AGENT_PID="$!"
  sleep 1
  kill -0 "${AGENT_PID}" 2>/dev/null || {
    cat "${logfile}" >&2 || true
    fail "agent failed to start"
  }
}

expect_killed() {
  local name="$1"
  shift
  set +e
  timeout 8s "$@"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 137 ]]; then
    fail "${name}: expected SIGKILL exit 137, got ${rc}"
  fi
}

expect_survives() {
  local name="$1"
  shift
  set +e
  timeout 8s "$@"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    fail "${name}: expected success exit 0, got ${rc}"
  fi
}

wait_for_log() {
  local logfile="$1"
  local pattern="$2"
  local name="$3"

  for _ in $(seq 1 30); do
    if grep -q "${pattern}" "${logfile}"; then
      return
    fi
    sleep 0.1
  done
  fail "${name}: expected log pattern ${pattern}"
}

write_py() {
  local path="$1"
  shift
  cat >"${path}" <<'PY'
PY
  cat >>"${path}"
}

build_badloop() {
  local src="${TMP_DIR}/badloop.c"
  BADLOOP="${TMP_DIR}/badloop"
  cat >"${src}" <<'C'
#include <signal.h>
#include <unistd.h>
int main(void) {
  signal(SIGTERM, SIG_IGN);
  for (;;) {
    sleep(1);
  }
}
C
  cc "${src}" -o "${BADLOOP}"
}

build_spoof() {
  local src="${TMP_DIR}/spoof.c"
  SPOOF="${TMP_DIR}/spoof"
  cat >"${src}" <<'C'
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    return 2;
  }
  prctl(PR_SET_NAME, "ebpffls", 0, 0, 0);
  for (int i = 0; i < 64; i++) {
    char path[512];
    snprintf(path, sizeof(path), "%s/spoof-%d.txt", argv[1], i);
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
      return 3;
    }
    write(fd, "data", 4);
    close(fd);
    usleep(20000);
  }
  return 0;
}
C
  cc "${src}" -o "${SPOOF}"
}

test_dry_run_survives() {
  log "dry-run alerts but does not kill"
  local dir="${TMP_DIR}/dry"
  local bl="${TMP_DIR}/dry-blacklist.txt"
  local policy="${TMP_DIR}/dry.yaml"
  local agent_log="${TMP_DIR}/dry-agent.log"
  local sim="${TMP_DIR}/dry.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" dry-run-test 3 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}" dry-run
  cat >"${sim}" <<PY
import os
base = "${dir}"
for i in range(6):
    with open(f"{base}/f{i}.txt", "w") as f:
        f.write("data")
print("survived")
PY
  expect_survives "dry-run" python3 "${sim}"
  wait_for_log "${agent_log}" '"dry_run":true' "dry-run"
  stop_agent
}

test_behavior_threshold_kills() {
  log "behavior threshold kills bulk protected writes"
  local dir="${TMP_DIR}/behavior"
  local bl="${TMP_DIR}/behavior-blacklist.txt"
  local policy="${TMP_DIR}/behavior.yaml"
  local agent_log="${TMP_DIR}/behavior-agent.log"
  local sim="${TMP_DIR}/behavior.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" behavior-test 5 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}"
  cat >"${sim}" <<PY
import time
base = "${dir}"
for i in range(100):
    with open(f"{base}/bulk{i}.txt", "w") as f:
        f.write("data")
    time.sleep(0.02)
print("survived")
PY
  expect_killed "behavior threshold" python3 "${sim}"
  wait_for_log "${agent_log}" 'behavior threshold' "behavior threshold"
  stop_agent
}

test_fd_write_path_scoring_kills() {
  log "fd write path scoring kills repeated writes to protected fd"
  local dir="${TMP_DIR}/fd-write"
  local bl="${TMP_DIR}/fd-write-blacklist.txt"
  local policy="${TMP_DIR}/fd-write.yaml"
  local agent_log="${TMP_DIR}/fd-write-agent.log"
  local sim="${TMP_DIR}/fd-write.py"
  local pwrite_sim="${TMP_DIR}/fd-pwrite.py"
  local writev_sim="${TMP_DIR}/fd-writev.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" fd-write-test 5 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}"
  cat >"${sim}" <<PY
import time
p = "${dir}/single-fd.txt"
f = open(p, "w")
for i in range(100):
    f.write("x" * 4096)
    f.flush()
    time.sleep(0.02)
print("survived")
PY
  expect_killed "fd write path scoring" python3 "${sim}"
  wait_for_log "${agent_log}" 'write syscall on protected fd' "fd write"
  stop_agent

  start_agent "${policy}" "${agent_log}"
  cat >"${pwrite_sim}" <<PY
import os, time
p = "${dir}/single-fd-pwrite.txt"
fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o600)
for i in range(100):
    os.pwrite(fd, b"x" * 4096, i * 4096)
    time.sleep(0.02)
print("survived")
PY
  expect_killed "fd pwrite path scoring" python3 "${pwrite_sim}"
  wait_for_log "${agent_log}" 'write syscall on protected fd' "fd pwrite"
  stop_agent

  start_agent "${policy}" "${agent_log}"
  cat >"${writev_sim}" <<PY
import os, time
p = "${dir}/single-fd-writev.txt"
fd = os.open(p, os.O_CREAT | os.O_WRONLY, 0o600)
for i in range(100):
    os.writev(fd, [b"x" * 2048, b"y" * 2048])
    time.sleep(0.02)
print("survived")
PY
  expect_killed "fd writev path scoring" python3 "${writev_sim}"
  wait_for_log "${agent_log}" 'write syscall on protected fd' "fd writev"
  stop_agent
}

test_trusted_comm_spoof_not_bypassed() {
  log "strict trust rejects comm spoof without trusted exe path"
  local dir="${TMP_DIR}/trust-spoof"
  local bl="${TMP_DIR}/trust-spoof-blacklist.txt"
  local policy="${TMP_DIR}/trust-spoof.yaml"
  local agent_log="${TMP_DIR}/trust-spoof-agent.log"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" trust-spoof-test 3 kill "${dir}" "${bl}"
  cat >>"${policy}" <<'YAML'
trusted_exe_paths:
  - /usr/bin
trusted_uids:
  - 0
YAML
  start_agent "${policy}" "${agent_log}"
  expect_killed "trusted comm spoof" "${SPOOF}" "${dir}"
  wait_for_log "${agent_log}" 'behavior threshold' "trusted comm spoof"
  stop_agent
}

test_immediate_rename_ioc_kills() {
  log "protected suspicious rename kills immediately"
  local dir="${TMP_DIR}/rename-ioc"
  local bl="${TMP_DIR}/rename-blacklist.txt"
  local policy="${TMP_DIR}/rename.yaml"
  local agent_log="${TMP_DIR}/rename-agent.log"
  local sim="${TMP_DIR}/rename.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" rename-ioc-test 45 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}"
  cat >"${sim}" <<PY
import os, time
p = "${dir}/doc.txt"
with open(p, "w") as f:
    f.write("data")
os.rename(p, p + ".locked")
time.sleep(5)
print("survived")
PY
  expect_killed "rename IOC" python3 "${sim}"
  wait_for_log "${agent_log}" 'protected rename to suspicious extension' "rename IOC"
  stop_agent
}

test_ransom_note_kills() {
  log "protected ransom note creation kills immediately"
  local dir="${TMP_DIR}/note-ioc"
  local bl="${TMP_DIR}/note-blacklist.txt"
  local policy="${TMP_DIR}/note.yaml"
  local agent_log="${TMP_DIR}/note-agent.log"
  local sim="${TMP_DIR}/note.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" note-ioc-test 45 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}"
  cat >"${sim}" <<PY
import time
with open("${dir}/README_FOR_DECRYPT.txt", "w") as f:
    f.write("pay")
time.sleep(5)
print("survived")
PY
  expect_killed "ransom note IOC" python3 "${sim}"
  wait_for_log "${agent_log}" 'protected ransom note creation' "ransom note IOC"
  stop_agent
}

test_unlink_and_truncate_kill() {
  log "legacy unlink and truncate events score and kill"
  local dir="${TMP_DIR}/destructive"
  local bl="${TMP_DIR}/destructive-blacklist.txt"
  local policy="${TMP_DIR}/destructive.yaml"
  local agent_log="${TMP_DIR}/destructive-agent.log"
  local unlink_sim="${TMP_DIR}/unlink.py"
  local trunc_sim="${TMP_DIR}/truncate.py"
  local ftrunc_sim="${TMP_DIR}/ftruncate.py"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" destructive-test 6 kill "${dir}" "${bl}"

  start_agent "${policy}" "${agent_log}"
  cat >"${unlink_sim}" <<PY
import os, time
p = "${dir}/delete-me.txt"
with open(p, "w") as f:
    f.write("data")
os.unlink(p)
time.sleep(5)
print("survived")
PY
  expect_killed "unlink scoring" python3 "${unlink_sim}"
  stop_agent

  start_agent "${policy}" "${agent_log}"
  cat >"${trunc_sim}" <<PY
import os, time
p = "${dir}/truncate-me.txt"
with open(p, "w") as f:
    f.write("data")
os.truncate(p, 0)
time.sleep(5)
print("survived")
PY
  expect_killed "truncate scoring" python3 "${trunc_sim}"
  stop_agent

  write_policy "${policy}" destructive-test 7 kill "${dir}" "${bl}"
  start_agent "${policy}" "${agent_log}"
  cat >"${ftrunc_sim}" <<PY
import os, time
p = "${dir}/ftruncate-me.txt"
fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o600)
os.write(fd, b"data")
os.ftruncate(fd, 0)
time.sleep(5)
print("survived")
PY
  expect_killed "ftruncate fd scoring" python3 "${ftrunc_sim}"
  wait_for_log "${agent_log}" 'ftruncate on protected fd' "ftruncate fd"
  stop_agent
}

test_hash_blacklist_exec_kills() {
  log "hash blacklist kills blacklisted exec"
  local dir="${TMP_DIR}/hash-exec"
  local bl="${TMP_DIR}/hash-exec-blacklist.txt"
  local policy="${TMP_DIR}/hash-exec.yaml"
  local agent_log="${TMP_DIR}/hash-exec-agent.log"
  mkdir -p "${dir}"
  sha256sum "${BADLOOP}" | cut -d' ' -f1 >"${bl}"
  write_policy "${policy}" hash-exec-test 45 kill "${dir}" "${bl}" 30s
  start_agent "${policy}" "${agent_log}"
  expect_killed "hash exec" "${BADLOOP}"
  wait_for_log "${agent_log}" 'blacklisted exec' "hash exec"
  stop_agent
}

test_hash_blacklist_hot_scan_kills() {
  log "hash blacklist hot reload kills already running process"
  local dir="${TMP_DIR}/hash-scan"
  local bl="${TMP_DIR}/hash-scan-blacklist.txt"
  local policy="${TMP_DIR}/hash-scan.yaml"
  local agent_log="${TMP_DIR}/hash-scan-agent.log"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" hash-scan-test 45 kill "${dir}" "${bl}" 1s
  start_agent "${policy}" "${agent_log}"
  "${BADLOOP}" &
  local pid="$!"
  sleep 1
  sha256sum "${BADLOOP}" | cut -d' ' -f1 >"${bl}"
  for _ in $(seq 1 8); do
    if ! kill -0 "${pid}" 2>/dev/null; then
      wait "${pid}" 2>/dev/null || true
      wait_for_log "${agent_log}" 'blacklisted running process' "hash scan"
      stop_agent
      return
    fi
    sleep 1
  done
  kill "${pid}" 2>/dev/null || true
  fail "hash scan: process survived hot blacklist"
}

test_blocked_lineage_exec_kills_child() {
  log "blocked lineage exec kills child process"
  local dir="${TMP_DIR}/lineage"
  local bl="${TMP_DIR}/lineage-blacklist.txt"
  local policy="${TMP_DIR}/lineage.yaml"
  local agent_log="${TMP_DIR}/lineage-agent.log"
  local sim="${TMP_DIR}/lineage.py"
  local status_file="${TMP_DIR}/lineage.status"
  mkdir -p "${dir}"
  : >"${bl}"
  write_policy "${policy}" lineage-test 1 deny "${dir}" "${bl}" 30s
  start_agent "${policy}" "${agent_log}"
  cat >"${sim}" <<PY
import os, time
with open("${dir}/mark-parent.txt", "w") as f:
    f.write("data")
time.sleep(1.0)
pid = os.fork()
if pid == 0:
    os.execv("${BADLOOP}", ["${BADLOOP}"])
_, status = os.waitpid(pid, 0)
with open("${status_file}", "w") as f:
    f.write(str(status))
PY
  expect_survives "lineage parent" python3 "${sim}"
  local status
  status="$(cat "${status_file}")"
  python3 - <<PY
import os, sys
status = int("${status}")
sys.exit(0 if os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9 else 1)
PY
  wait_for_log "${agent_log}" 'exec by blocked lineage' "lineage"
  stop_agent
}

main() {
  command -v cc >/dev/null || fail "cc is required for integration tests"
  [[ -x "${BIN}" ]] || fail "missing binary ${BIN}; run make build first"
  build_badloop
  build_spoof
  test_dry_run_survives
  test_behavior_threshold_kills
  test_fd_write_path_scoring_kills
  test_trusted_comm_spoof_not_bypassed
  test_immediate_rename_ioc_kills
  test_ransom_note_kills
  test_unlink_and_truncate_kill
  test_hash_blacklist_exec_kills
  test_hash_blacklist_hot_scan_kills
  test_blocked_lineage_exec_kills_child
  log "all integration tests passed"
}

main "$@"
