# 开发路线图

> 更新：2026-06-08  
> 基于当前四轨架构与 [调用抽象](./ransomware-call-abstraction.md)

---

## 当前基线（v0.x）

### 已有能力

- **轨1** BPF LSM 文件名硬阻断（可疑扩展名、赎金信；要求 active BPF LSM）
- **轨2** 用户态滑动窗口评分（保护域 open/rename/unlink/truncate）
- **轨3** SHA256 黑名单（exec 事件 + `/proc` 周期扫描）
- **轨4** 对已标记 TGID：x86_64 kprobe SIGKILL；active BPF LSM 时提供 deny/kill

### 已知缺口

- 文档曾与代码不一致（已在本次更新中对齐）
- `write` 不计分；已标记 TGID 的 write/pwrite64/writev 已有 kprobe kill
- BPF IOC 与 yaml 不同步；硬规则无 `protected_dirs` 作用域
- blocked lineage exec 已做 kill 传播；`exec_after_blocked` 作为评分规则未实现
- 仅 x86_64 kprobe；无 `bpf_override_return` 真 deny
- 无 mmap/io_uring/scan 类观测

---

## Phase 1 — 闭环修复（建议 1–2 周）

**目标：** 文档、策略、执法一致；堵住最危险的 syscall 缝。

| ID | 任务 | 产出 | 优先级 |
|----|------|------|--------|
| 1.1 | 统一 IOC 策略源：启动时将 yaml `suspicious_extensions`、`ransom_note_names` 写入 BPF map | 删/减 BPF 硬编码 | P0 |
| 1.2 | LSM 硬规则增加 `protected_dirs` 前缀 map，IOC 仅在保护域生效 | 降误杀 | P0 |
| 1.3 | kprobe 增加 `__x64_sys_write/pwrite64/writev`；修复黑名单扫描读 `/proc/pid/status` Tgid | 已完成 | P0 |
| 1.4 | 恢复 `EventWrite` 路径感知评分（fd→path 缓存或 BPF 带 path） | `SO_ENCRYPT_WRITE` | P0 |
| 1.5 | 高置信语义规则即时 `BlockTGID`：保护域 +（赎金信 \| 可疑后缀 rename） | 已完成 | P0 |
| 1.6 | 实现 blocked lineage exec 传播：blocked TGID/父 TGID 再 exec → 新 TGID 入 map | 已完成 kill 传播 | P1 |
| 1.7 | `procState` 定期淘汰；ringbuf 丢事件计数日志 | 稳定性 | P1 |

### Phase 1 验收标准

- [ ] 修改 yaml 扩展名后，BPF 硬规则同步生效
- [ ] `/tmp/test.locked` 不写保护域时不被拦；`/home/u/f.locked` 被拦
- [x] 标记 TGID 后 `write` 触发 SIGKILL 或 LSM 拒绝
- [x] 原地加密模拟（open+write 扇出）能在阈值内告警/阻断
- [ ] 父进程 blocked 后 exec 子进程，子进程写保护域被拒

---

## Phase 2 — 特征抽象层（建议 2–4 周）

**目标：** 从「积分表」升级为「特征 + 规则」。

| ID | 任务 | 产出 |
|----|------|------|
| 2.1 | `procFeatures`：`distinct_paths`、`open_write_pairs`、`rename_suffix_count` | L2 特征向量 |
| 2.2 | yaml 支持 `rules[]`（when 组合 + action） | L3 可组合策略 |
| 2.3 | 加密状态机：`SCAN`→`STAGE`→`FINALIZE`（先实现 STAGE/FINALIZE） | 模式识别 |
| 2.4 | trust 模型升级：comm + exe 路径 + uid；备份破坏不减分 | 降绕过 |
| 2.5 | ftruncate fd→path 解析 | 补齐 `SO_TRUNCATE` |
| 2.6 | 结构化 metrics：alert/block/blacklist 计数导出 | 可运营 |

### Phase 2 验收标准

- [ ] 可用 yaml 定义一条「distinct_paths > N → block」规则
- [ ] 不改名加密可通过扇出规则触发
- [ ] 伪装 comm 但 exe 路径不在 trust 列表仍计分

---

## Phase 3 — 调用面扩展（建议 4–8 周）

**目标：** 覆盖高级 I/O 绕过与架构无关执法。

| ID | 任务 | 产出 |
|----|------|------|
| 3.1 | `mmap` LSM `file_mmap` 或等效 trace | `SO_ENCRYPT_WRITE` 补洞 |
| 3.2 | `copy_file_range` tracepoint | 模式 C |
| 3.3 | kprobe 符号多架构（arm64 `__arm64_sys_*`）或 fentry 迁移 | 可移植 |
| 3.4 | `bpf_override_return(-EPERM)` deny 路径与 kill 路径分离 | 真同步 deny |
| 3.5 | `getdents64` 采样（可选阈值） | `SO_SCAN` 早期预警 |
| 3.6 | io_uring 基础观测 | 新样本规避 |

---

## Phase 4 — 产品化（持续）

| ID | 任务 |
|----|------|
| 4.1 | Agent 自保护：systemd 看门狗、只读部署、保护自身路径 |
| 4.2 | 集成测试套件：勒索模拟脚本 + 误报场景（make -j、rsync backup） |
| 4.3 | 多策略 / cgroup 绑定 |
| 4.4 | SIEM 出口（alert JSON schema 稳定化） |
| 4.5 | 网络 egress 子模块（双重勒索），可选 |

---

## 里程碑建议

```
v0.2  Phase 1 完成 — 策略统一、write 闭环、fork 传播
v0.3  Phase 2 完成 — 特征向量 + rules DSL
v0.4  Phase 3 前半 — mmap/copy_file_range + 多 arch
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
