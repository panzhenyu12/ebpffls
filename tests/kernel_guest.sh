#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary=""
expected_sha=""
expected_kernel=""
output_dir=""
chain_helper=""
guard_object=""
suite_args=()

usage() {
  echo "usage: kernel_guest.sh --binary PATH --expected-sha256 SHA --output-dir DIR [--kernel-series 5.15] [--only TEST] [--lsm-chain-helper PATH --lsm-guard-object PATH]"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --binary|--expected-sha256|--output-dir|--kernel-series|--only|--lsm-chain-helper|--lsm-guard-object)
      [[ "$#" -ge 2 ]] || { usage >&2; exit 2; }
      case "$1" in
        --binary) binary="$2" ;;
        --expected-sha256) expected_sha="$2" ;;
        --output-dir) output_dir="$2" ;;
        --kernel-series) expected_kernel="$2" ;;
        --only) suite_args+=(--only "$2") ;;
        --lsm-chain-helper) chain_helper="$2" ;;
        --lsm-guard-object) guard_object="$2" ;;
      esac
      shift 2
      ;;
    --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

[[ "${EUID}" -eq 0 && "$(uname -s)" == Linux ]] || { echo "guest tests require root on Linux" >&2; exit 1; }
[[ -x "${binary}" && "${expected_sha}" =~ ^[a-fA-F0-9]{64}$ && "${output_dir}" == /* ]] || { usage >&2; exit 2; }
for tool in sha256sum python3 cc timeout tee; do
  command -v "${tool}" >/dev/null || { echo "missing guest dependency: ${tool}" >&2; exit 1; }
done
binary="$(readlink -f "${binary}")"
actual_sha="$(sha256sum "${binary}" | awk '{print $1}')"
[[ "${actual_sha}" == "${expected_sha,,}" ]] || { echo "binary SHA-256 differs from frozen artifact" >&2; exit 1; }
kernel_release="$(uname -r)"
if [[ -n "${expected_kernel}" && "${kernel_release}" != "${expected_kernel}."* ]]; then
  echo "expected kernel series ${expected_kernel}, got ${kernel_release}" >&2
  exit 1
fi
mkdir -p "${output_dir}"
output_dir="$(readlink -f "${output_dir}")"
[[ ! -e "${output_dir}/result.json" && ! -e "${output_dir}/suite.tsv" ]] || { echo "choose a fresh guest output directory" >&2; exit 1; }
timeout_scale="${EBPFFLS_TEST_TIMEOUT_SCALE:-4}"
[[ "${timeout_scale}" =~ ^[1-9][0-9]*$ ]] || { echo "timeout scale must be a positive integer" >&2; exit 2; }

# Mount only the kernel interfaces needed by the in-guest load/attach tests.
mkdir -p /sys/kernel/tracing /sys/kernel/security
if [[ ! -d /sys/kernel/tracing/events ]]; then
  mount -t tracefs tracefs /sys/kernel/tracing >"${output_dir}/tracefs-mount.log" 2>&1 || true
fi
if [[ ! -r /sys/kernel/security/lsm ]]; then
  mount -t securityfs securityfs /sys/kernel/security >"${output_dir}/securityfs-mount.log" 2>&1 || true
fi
ulimit -l unlimited 2>/dev/null || true

python3 - "${binary}" "${actual_sha}" "${expected_kernel}" "${output_dir}" "${timeout_scale}" "${chain_helper}" "${guard_object}" "${ROOT_DIR}" <<'PY'
import gzip
import hashlib
import json
import pathlib
import platform
import subprocess
import sys

binary, digest, expected_kernel, output, scale, chain_helper, guard, root = sys.argv[1:]
def read(path):
    try:
        return pathlib.Path(path).read_text().strip()
    except OSError:
        return None

def sha(path):
    if not path or not pathlib.Path(path).is_file():
        return None
    value = hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()

config_text, config_source = None, None
for candidate in ('/proc/config.gz', '/boot/config-' + platform.release()):
    try:
        if candidate.endswith('.gz'):
            with gzip.open(candidate, 'rt') as stream:
                config_text = stream.read()
        else:
            config_text = pathlib.Path(candidate).read_text()
        config_source = candidate
        break
    except OSError:
        pass
keys = ('BPF', 'BPF_SYSCALL', 'BPF_JIT', 'DEBUG_INFO_BTF', 'BPF_LSM', 'LSM', 'BPF_KPROBE_OVERRIDE',
        'FUNCTION_ERROR_INJECTION', 'KPROBES', 'KPROBE_EVENTS', 'TRACEPOINTS', 'FTRACE_SYSCALLS', 'SECURITY')
config = {key: 'unknown' for key in keys}
if config_text is not None:
    for line in config_text.splitlines():
        for key in keys:
            if line.startswith('CONFIG_' + key + '='):
                config[key] = line.split('=', 1)[1]
            elif line == '# CONFIG_' + key + ' is not set':
                config[key] = 'n'
data = {
    'schema_version': 'kernel-guest/v1', 'binary': binary, 'binary_sha256': digest,
    'expected_kernel_series': expected_kernel or None, 'uname': platform.uname()._asdict(),
    'cmdline': read('/proc/cmdline'), 'active_lsm': read('/sys/kernel/security/lsm'),
    'btf_present': pathlib.Path('/sys/kernel/btf/vmlinux').is_file(),
    'tracefs_events_present': pathlib.Path('/sys/kernel/tracing/events').is_dir(),
    'kernel_config_source': config_source, 'kernel_config': config,
    'compiler': subprocess.run(['cc', '--version'], capture_output=True, text=True).stdout.splitlines()[0],
    'timeout_scale': int(scale), 'build_main_in_guest': False,
    'test_artifacts_sha256': {
        'integration.sh': sha(root + '/tests/integration.sh'),
        'event_semantics.c': sha(root + '/tests/event_semantics.c'),
        'lsm_chain_helper': sha(chain_helper), 'lsm_guard_object': sha(guard),
    },
}
pathlib.Path(output, 'environment.json').write_text(json.dumps(data, indent=2) + '\n')
print(json.dumps(data, separators=(',', ':')))
PY

echo "[kernel-guest] frozen_binary_sha256=${actual_sha} kernel=${kernel_release}"
suite_rc=0
set +e
EBPFFLS_BIN="${binary}" EBPFFLS_TEST_TIMEOUT_SCALE="${timeout_scale}" \
  EBPFFLS_INTEGRATION_KEEP_TMP=1 EBPFFLS_INTEGRATION_TMP_PARENT=/tmp \
  EBPFFLS_INTEGRATION_ARTIFACTS_DIR="${output_dir}/suite-artifacts" \
  EBPFFLS_INTEGRATION_RESULTS_FILE="${output_dir}/suite.tsv" \
  bash "${ROOT_DIR}/tests/integration.sh" "${suite_args[@]}" 2>&1 | tee "${output_dir}/suite.log"
suite_rc="${PIPESTATUS[0]}"
set -e

chain_rc=0
chain_status=passed
if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
  chain_status=unsupported
  echo "[kernel-guest] UNSUPPORTED lsm_chain: active BPF LSM is required; no chain claim" | tee "${output_dir}/lsm-chain.log"
elif [[ ! -x "${chain_helper}" || ! -r "${guard_object}" ]]; then
  chain_rc=1
  chain_status=failed
  echo "[kernel-guest] FAIL lsm_chain: active LSM requires the frozen helper and guard object" | tee "${output_dir}/lsm-chain.log"
else
  "${chain_helper}" --binary "${binary}" --guard "${guard_object}" \
    --artifacts "${output_dir}/lsm-chain" --timeout "$((30 * timeout_scale))s" \
    >"${output_dir}/lsm-chain.log" 2>&1 || chain_rc=$?
  if [[ "${chain_rc}" -ne 0 ]]; then chain_status=failed; fi
  cat "${output_dir}/lsm-chain.log"
fi

final_sha="$(sha256sum "${binary}" | awk '{print $1}')"
binary_unchanged=true
if [[ "${final_sha}" != "${actual_sha}" ]]; then binary_unchanged=false; fi
python3 - "${output_dir}" "${suite_rc}" "${chain_rc}" "${chain_status}" "${binary_unchanged}" "${final_sha}" <<'PY'
import csv
import json
import pathlib
import sys

output, suite_rc, chain_rc, chain_status, unchanged, final_sha = sys.argv[1:]
directory = pathlib.Path(output)
rows = []
if directory.joinpath('suite.tsv').is_file():
    with directory.joinpath('suite.tsv').open() as stream:
        rows = list(csv.DictReader(stream, delimiter='\t'))
unsupported = [row for row in rows if row['status'] == 'UNSUPPORTED']
failed = int(suite_rc) != 0 or int(chain_rc) != 0 or unchanged != 'true'
status = 'failed' if failed else ('passed_with_unsupported' if unsupported or chain_status == 'unsupported' else 'passed')
result = {
    'schema_version': 'kernel-guest/v1', 'status': status,
    'suite_exit_code': int(suite_rc), 'lsm_chain_status': chain_status, 'lsm_chain_exit_code': int(chain_rc),
    'binary_unchanged': unchanged == 'true', 'binary_sha256_after': final_sha,
    'tests': [row for row in rows if row['status'] != 'RUNNING'], 'unsupported_checks': unsupported,
    'limits': ['unsupported checks are not passes', 'guest kernel result does not establish cross-kernel coverage without the other kernel reports'],
}
directory.joinpath('result.json').write_text(json.dumps(result, indent=2) + '\n')
print('[kernel-guest] RESULT ' + json.dumps(result, separators=(',', ':')))
PY
[[ "${suite_rc}" -eq 0 && "${chain_rc}" -eq 0 && "${binary_unchanged}" == true ]]
