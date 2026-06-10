# Kernel Compatibility Plan

目标：`ebpffls` 的发布物只构建一次，内置多套 BPF object，部署到不同 Linux 内核分支时由 Go loader 自动选择可运行路径，不要求在目标机器重新生成 `vmlinux.h` 或重新编译 BPF 程序。

## Runtime 分层

| Runtime mode | 目标内核 | BPF object | 事件通道 | 观测方式 | 主要降级 |
|--------------|----------|------------|----------|----------|----------|
| `core` | 5.8+ 优先；有可用 kernel BTF 的现代内核 | `ransomware` | ringbuf | CO-RE tracepoint + optional BPF LSM + kprobe override | BPF LSM、部分 syscall kprobe 仍按 attach 结果 optional |
| `legacy_perf` | 4.4+ | `ransomwareLegacy` | perf event array | no-CO-RE tracepoint；部分 syscall optional | 无 BPF LSM、无 ringbuf、无内核态 kill |
| `ultra_legacy_map` | 4.1-4.3 | `ransomwareUltraLegacy` | BPF array map polling | no-CO-RE kprobe-only 核心事件 | 无 perf/ringbuf、无 tracepoint、无 override deny、无 BPF LSM |

`EBPFFLS_BPF_MODE` 支持：

- `auto` 或空值：按 `core -> legacy_perf -> ultra_legacy_map` 尝试。
- `core`：只加载 CO-RE object，失败即退出。
- `legacy_perf`：只加载 perf legacy object，失败即退出。
- `legacy`：兼容旧名称，等价于 `legacy_perf`。
- `ultra_legacy_map`：只加载 map polling ultra legacy object，失败即退出。

能力选择以实际 load/attach/probe 结果为准，不只依赖版本字符串。版本号只用于日志、测试矩阵和解释能力边界。

## 已核实的版本边界

| 能力 | 上游版本 | 约束 | ebpffls 策略 |
|------|----------|------|--------------|
| `BPF_PROG_TYPE_KPROBE` | 4.1 | 依赖 kprobe/ftrace 和 syscall 符号可见性 | 4.1+ 基线，ultra legacy 用它采集核心事件 |
| `BPF_MAP_TYPE_HASH` / `ARRAY` / `PERCPU_ARRAY` | 早于 4.1 | 仍受 verifier 和 memlock 约束 | ultra legacy 的事件槽、scratch buffer、策略 map 基线 |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 4.3 | 还需要 perf event 用户态 reader | `legacy_perf` 的 map 基础；真正输出依赖下一项 |
| `bpf_perf_event_output` | 4.4 | 只能向当前 CPU 对应 perf event 输出 | `legacy_perf` 事件通道基线 |
| `BPF_PROG_TYPE_TRACEPOINT` | 4.7 | tracepoint 名称必须在目标内核存在 | `core` / `legacy_perf` 优先使用；4.1-4.6 不依赖 |
| `bpf_probe_read_str` | 4.11 | 旧 helper；5.5 后拆分 user/kernel helper | legacy object 使用旧 helper；ultra legacy 只在 4.1-4.3 能力范围内做核心路径 |
| `bpf_override_return` | 4.16 | 需 `CONFIG_BPF_KPROBE_OVERRIDE` 且目标函数允许 error injection | `core` / `legacy_perf` optional deny；失败回退用户态 kill |
| `bpf_get_current_cgroup_id` | 4.18 | program type 可用性受内核影响 | legacy 不依赖；Go agent 保留 `/proc/<pid>/cgroup` 过滤 |
| bounded loops | 5.3 | 5.3 前 verifier 不接受普通 bounded loop | legacy/ultra legacy 禁止运行时 bounded loop |
| `bpf_send_signal` | 5.3 | helper 可能返回忙或权限错误 | 只作为现代增强；4.x 基线是 Go agent `SIGKILL` |
| `bpf_probe_read_user*` | 5.5 | user/kernel read helper 拆分后的新 helper | core 可用；legacy/ultra legacy 禁止依赖 |
| `BPF_PROG_TYPE_LSM` / BPF LSM attach | 5.7 | 还需 config 和 active LSM 列表包含 `bpf` | 始终 optional hard-deny |
| `bpf_get_current_ancestor_cgroup_id` | 5.7 | program type/backport 差异较多 | core 可用时启用；legacy 不依赖 |
| `BPF_MAP_TYPE_RINGBUF` / ringbuf helpers | 5.8 | map 类型和 helper 都必须存在 | core 事件通道；低版本 fallback |

结论：

- **4.1-4.3**：可以承诺核心勒索 syscall 可观测、可评分、可用户态 kill；不承诺 perf/ringbuf 高吞吐、BPF LSM hard-deny、`bpf_override_return` 或内核态 kill。
- **4.4-4.6**：可以使用 perf event 输出，但不依赖 tracepoint；实际覆盖以 kprobe/tracepoint attach 结果为准。
- **4.7+**：tracepoint object 成为主要 legacy 观测路径。
- **5.7+**：BPF LSM 才可能启用，但仍必须 active LSM 包含 `bpf`。
- **5.8+**：优先使用 CO-RE/ringbuf 现代路径。

## 参考 Tetragon / Tracee

Tetragon 当前主线以 CO-RE/BTF 为核心路径，BTF discovery 有明确优先级：用户指定路径或环境变量、`/sys/kernel/btf/vmlinux`、随包 metadata、lib 目录中的 BTF 文件。它还对 kernel version 解析和 capability attach 做 feature-specific 处理，而不是只按版本字符串判断。

Tracee 当前偏向 CO-RE + BTFHub，安装文档明确列出 BTF、kconfig、kallsyms、LSM 条件；kconfig 缺失时 warning 并继续；LSM 检测区分 active LSM、kernel config 和 boot parameter。历史文档中也保留过 non-CO-RE fallback 经验，说明 no-CO-RE object 应收窄能力面。

ebpffls 的落地取舍：

- 学 Tetragon：提供显式 `EBPFFLS_BTF`，记录 BTF source 和 fallback 原因。
- 学 Tracee：缺 BTF/kconfig/LSM 不让 `auto` 失败，只影响能力选择。
- 为满足 4.1+，额外维护 `ultra_legacy_map`，只覆盖防勒索核心 syscall。

## CO-RE 与一次编译

`make build` 只构建 Go binary，不读取目标机 `/sys/kernel/btf/vmlinux`。BPF object 由构建机通过 `make generate` 生成，并由 bpf2go embed 到 Go package 中。

发布要求：

- 生成的 `internal/sensor/*_bpf*.go` 和 `.o` 必须进入发布产物或被显式 `git add -f`。
- `bpf/vmlinux.h` 是构建输入，不是目标机运行依赖。
- 目标机运行时如果 core CO-RE 因 BTF/ringbuf/verifier 失败，`auto` 必须记录原因并 fallback。

BTF discovery 顺序：

1. `EBPFFLS_BTF`
2. `/sys/kernel/btf/vmlinux`
3. 随包 metadata/BTFHub 目录
4. fallback 到 `legacy_perf` 或 `ultra_legacy_map`

## 能力覆盖

所有 runtime 都应尽量覆盖这些核心语义：

- `execve`：用户态 hash blacklist。
- `open` / `openat`：写意图与 fd->path 缓存。
- `write` / `pwrite64` / `writev`：通过 fd->path 评分 protected/backup/self-protect。
- `rename`、`link`、`symlink`、`unlink`、`truncate`、`ftruncate`：路径变异评分。
- 命中策略后：Go agent 发送 `SIGKILL`，并写入 blocked TGID map。

可降级能力：

- BPF LSM IOC hard-deny。
- `bpf_override_return(-EPERM)` deny。
- ringbuf drop counter；legacy 使用 perf lost sample 或 map polling lost event 日志。
- cgroup BPF 预过滤；保留 Go agent 用户态 cgroup 过滤。
- `openat2`、`renameat2`、`copy_file_range`、`io_uring`、`connect` 等非 4.1 基线 syscall。

## 测试验收

- 单元测试：mode selection、core fallback 到 `legacy_perf`、`legacy_perf` fallback 到 `ultra_legacy_map`。
- 单元测试：ringbuf/perf/map polling reader 都能 decode 同一 `sensor.Event`。
- 单元测试：BPF LSM 和 kprobe override attach 失败只计 skip，不 fatal。
- 集成测试：强制 `EBPFFLS_BPF_MODE=legacy_perf` 跑 protected write、rename、link/symlink、truncate、blacklist kill。
- 集成测试：强制 `EBPFFLS_BPF_MODE=ultra_legacy_map` 验证 map polling 事件触发评分和 kill。
- 远程参考服务器：`PATH=/usr/local/go/bin:$PATH make integration-test`。
- 低内核矩阵：4.1、4.4、4.7、4.16、5.3、5.7、5.8；每档缺失能力必须有明确 skip 日志。

## 资料来源

- [`BPF_PROG_TYPE_KPROBE` v4.1](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)
- [`BPF_PROG_TYPE_TRACEPOINT` v4.7](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/)
- [`BPF_MAP_TYPE_PERF_EVENT_ARRAY` v4.3](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/)
- [`bpf_perf_event_output` v4.4](https://docs.ebpf.io/linux/helper-function/bpf_perf_event_output/)
- [`bpf_probe_read_str` v4.11](https://docs.ebpf.io/linux/helper-function/bpf_probe_read_str/)
- [`bpf_override_return` v4.16](https://docs.ebpf.io/linux/helper-function/bpf_override_return/)
- [`bpf_send_signal` v5.3](https://docs.ebpf.io/linux/helper-function/bpf_send_signal/)
- [`bpf_probe_read_user_str` v5.5](https://docs.ebpf.io/linux/helper-function/bpf_probe_read_user_str/)
- [`BPF_PROG_TYPE_LSM` v5.7](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/)
- [`BPF_MAP_TYPE_RINGBUF` v5.8](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/)
- [BPF CO-RE concept](https://docs.ebpf.io/concepts/core/)
- [Tetragon BTF discovery](https://github.com/cilium/tetragon/blob/main/pkg/btf/btf.go)
- [Tracee OS requirements](https://aquasecurity.github.io/tracee/latest/docs/install/os-requirements/)
