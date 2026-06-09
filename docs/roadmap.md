# 开发路线图

> 更新：2026-06-09  
> 基于当前四轨架构与 [调用抽象](./ransomware-call-abstraction.md)

---

## 当前基线（v0.x）

### 已有能力

- **轨1** BPF LSM 文件名硬阻断（可疑扩展名、赎金信；要求 active BPF LSM）
- **轨2** 用户态滑动窗口评分（保护域 open/write/rename/unlink/truncate）
- **轨3** SHA256 黑名单（exec 事件 + `/proc` 周期扫描）
- **轨4** 对已标记 TGID：kprobe SIGKILL 或 `bpf_override_return(-EPERM)` deny；active BPF LSM 时提供 IOC hard-deny

### 已知缺口

- 文档曾与代码不一致（已在本次更新中对齐）
- `write` 已基于 agent fd→path 缓存计分；close/dup 与相对 dirfd 已跟踪
- `procState`、fd→path 与 blocked lineage 缓存已按空闲 TTL 定期淘汰；ringbuf reserve 失败已有内核计数和用户态增量日志
- BPF IOC 已从 yaml 同步到 map；path-based LSM IOC 已受 `protected_dirs` inode 作用域约束
- blocked lineage exec 已做 kill 传播；dry-run/评分路径输出 `exec_after_blocked`
- kprobe attach 已按架构选择候选符号；deny 动作已用 `bpf_override_return(-EPERM)` 同步拒绝
- io_uring 已有基础 `io_uring_enter` 观测；不解析 SQE 内容，仍属于弱覆盖

---

## Phase 1 — 闭环修复（建议 1–2 周）

**目标：** 文档、策略、执法一致；堵住最危险的 syscall 缝。

| ID | 任务 | 产出 | 优先级 |
|----|------|------|--------|
| 1.1 | 统一 IOC 策略源：启动时将 yaml `suspicious_extensions`、`ransom_note_names` 写入 BPF map | 已完成：Go 启动同步 IOC hash map | P0 |
| 1.2 | LSM 硬规则增加 `protected_dirs` 前缀 map，IOC 仅在保护域生效 | 已完成：path-based LSM IOC 使用 protected dir inode 作用域 | P0 |
| 1.3 | kprobe 增加 `__x64_sys_write/pwrite64/writev`；修复黑名单扫描读 `/proc/pid/status` Tgid | 已完成 | P0 |
| 1.4 | 恢复 `EventWrite` 路径感知评分（fd→path 缓存或 BPF 带 path） | 已完成：open/openat/openat2 fd→path 缓存 | P0 |
| 1.5 | 高置信语义规则即时 `BlockTGID`：保护域 +（赎金信 \| 可疑后缀 rename） | 已完成 | P0 |
| 1.6 | 实现 blocked lineage exec 传播：blocked TGID/父 TGID 再 exec → 新 TGID 入 map | 已完成 kill 传播 | P1 |
| 1.7 | `procState` 定期淘汰；ringbuf 丢事件计数日志 | 已完成：空闲状态淘汰 + BPF drop counter + Go 增量日志 | P1 |

### Phase 1 验收标准

- [x] 修改 yaml 扩展名/赎金信名后，BPF IOC map 同步生效
- [x] path-based BPF LSM IOC 使用 protected dir inode 作用域；active BPF LSM 环境下覆盖保护域内外硬拒绝验收
- [x] 标记 TGID 后 `write` 触发 SIGKILL 或 LSM 拒绝
- [x] 原地加密模拟（open+write 扇出）能在阈值内告警/阻断
- [x] 单 fd 重复 `write` 可通过 fd→path 评分触发阻断
- [x] 单 fd 重复 `pwrite64`/`writev` 可通过 fd→path 评分触发阻断
- [x] fd→path 缓存跟踪 close 与 dup/fcntl 复制，避免 fd 复用误杀并覆盖 dup 后写入
- [x] openat/openat2 相对 dirfd 可解析到保护域路径并触发评分
- [x] copy_file_range 写入保护域目标 fd 可通过 fd→path 评分触发阻断
- [x] 父进程 blocked 后 exec 子进程，子进程被 kill 传播阻断
- [x] `procState`、fd→path、blocked lineage 用户态状态按 TTL 淘汰，避免长期运行内存无界增长
- [x] ringbuf reserve 失败在 BPF map 中计数，Go agent 周期读取并打印增量日志
- [x] 集成测试覆盖 dry-run、行为阈值、即时 IOC、unlink/truncate、hash 黑名单、热更新扫描、blocked lineage exec

---

## Phase 2 — 特征抽象层（建议 2–4 周）

**目标：** 从「积分表」升级为「特征 + 规则」。

| ID | 任务 | 产出 |
|----|------|------|
| 2.1 | `procFeatures`：`distinct_paths`、`open_write_pairs`、`rename_suffix_count` | 已完成：alert JSON 输出 L2 特征向量 |
| 2.2 | yaml 支持 `rules[]`（when 组合 + action） | 已完成：基于特征阈值的 rules[] DSL |
| 2.3 | 加密状态机：`SCAN`→`STAGE`→`FINALIZE`（先实现 STAGE/FINALIZE） | 已完成：STAGE/FINALIZE 输出到特征向量 |
| 2.4 | trust 模型升级：comm + exe 路径 + uid；备份破坏不减分 | 已完成 |
| 2.5 | ftruncate fd→path 解析 | 已完成：复用 open/openat/openat2 fd→path 缓存 |
| 2.6 | 结构化 metrics：alert/block/blacklist 计数导出 | 已完成：周期性 `metrics={...}` 结构化日志 |

### Phase 2 验收标准

- [x] 可用 yaml 定义一条「distinct_paths > N → block」规则（`block` 规范化为 `deny`）
- [x] 告警输出 `distinct_paths`、`open_write_pairs`、`rename_suffix_count` 特征向量
- [x] 可用 yaml 定义一条「distinct_paths >= N → block/kill」规则
- [x] 不改名加密可通过扇出规则触发
- [x] 伪装 comm 但 exe 路径不在 trust 列表仍计分
- [x] trusted 进程破坏 backup_dirs 仍计分并阻断

---

## Phase 3 — 调用面扩展（建议 4–8 周）

**目标：** 覆盖高级 I/O 绕过与架构无关执法。

| ID | 任务 | 产出 |
|----|------|------|
| 3.1 | `mmap` LSM `file_mmap` 或等效 trace | 已完成：writable shared mmap fd→path 评分与 kprobe kill |
| 3.2 | `copy_file_range` tracepoint | 已完成：目标 fd→path 评分与 kprobe kill |
| 3.3 | kprobe 符号多架构（arm64 `__arm64_sys_*`）或 fentry 迁移 | 已完成：按 GOARCH 选择 `__x64_sys_*`/`__arm64_sys_*` 并 fallback `__se_sys_*` |
| 3.4 | `bpf_override_return(-EPERM)` deny 路径与 kill 路径分离 | 已完成：deny 同步返回 `-EPERM`，kill 保持 `SIGKILL` |
| 3.5 | `getdents64` 采样（可选阈值） | 已完成：目录 fd→path 评分与 kprobe kill |
| 3.6 | io_uring 基础观测 | 已完成：`io_uring_enter` 采样，保护域活动后的 io_uring 行为计分；不解析 SQE |

---

## Phase 4 — 产品化（持续）

| ID | 任务 |
|----|------|
| 4.1 | Agent 自保护：systemd 看门狗、只读部署、保护自身路径 | 已完成：`self_protect_paths` 篡改评分、trusted 不豁免回归、systemd notify watchdog 与 read-only hardening unit |
| 4.2 | 集成测试套件：勒索模拟脚本 + 误报场景（make -j、rsync backup） | 已完成：`tests/ransomware_sim.py` 勒索模拟器；trusted rsync、make -j、trusted tar 解包误报回归 |
| 4.3 | 多策略 / cgroup 绑定 | 已完成：重复 `--config` 合并多策略文件；`cgroup_paths` 用户态前缀 scope + BPF cgroup id map 预过滤 |
| 4.4 | SIEM 出口（alert JSON schema 稳定化） | 已完成：alert/metrics 增加 `schema_version:"v1"` 与 `kind` |
| 4.5 | 网络 egress 子模块（双重勒索），可选 | 已完成：IPv4/IPv6 `connect` 观测，文件活动后非 allowlist 外联评分 |

---

## 里程碑建议

```
v0.2  Phase 1 完成 — 策略统一、write 闭环、fork 传播
v0.3  Phase 2 完成 — 特征向量 + rules DSL
v0.4  Phase 3 前半 — mmap/copy_file_range/io_uring + 多 arch
v0.5  Phase 3 后半 — deny override + scan 预警
v1.0  Phase 4 核心 — 测试套件 + 自保护 + 文档稳定
```

---

## 非目标（当前阶段不做）

- 完整 EDR / 横向移动检测
- 文件内容熵变分析
- 内核模块级 rootkit 对抗
- Windows 支持

---

## 相关文档

- [strategy.md](./strategy.md) — 架构与响应级别
- [ransomware-call-abstraction.md](./ransomware-call-abstraction.md) — 调用抽象
- [review-consolidated.md](./review-consolidated.md) — 合并 review
