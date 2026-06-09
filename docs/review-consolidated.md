# ebpffls 合并 Review（代码 + 文档）

> 版本：2026-06-09（文档已对齐更新）  
> 详见：[strategy.md](./strategy.md)、[ransomware-call-abstraction.md](./ransomware-call-abstraction.md)、[roadmap.md](./roadmap.md)

---

## 1. 项目现状

ebpffls 是 **四轨混合防勒索** 运行时守卫：

1. **IOC 快轨** — BPF LSM 可疑名即时 `-EPERM`（要求 active BPF LSM）
2. **行为慢轨** — 保护域 syscall 滑动窗口评分
3. **哈希轨** — SHA256 黑名单（exec + `/proc` 扫描）
4. **执法轨** — 已标记 TGID：kprobe SIGKILL 或 `bpf_override_return(-EPERM)` deny；LSM 在 active 时补充 IOC hard-deny

定位：**主机文件系统层**，非完整 EDR。

---

## 2. 文档状态

| 文档 | 用途 |
|------|------|
| `README.md` | 快速上手、默认行为、限制 |
| `docs/strategy.md` | 架构、四轨、响应级别 |
| `docs/ransomware-call-abstraction.md` | 勒索调用抽象与映射表 |
| `docs/roadmap.md` | 分阶段开发计划 |
| `docs/review-consolidated.md` | 本文件：review 摘要 |

**已对齐：** 默认 `action: kill` + CLI `--dry-run=true`；write fd→path 评分、BPF LSM 依赖等限制已在 README/strategy 标明。

---

## 3. 勒索调用抽象（摘要）

完整内容见 [ransomware-call-abstraction.md](./ransomware-call-abstraction.md)。

```
语义操作 (SO_ENCRYPT_WRITE, SO_RENAME_SUFFIX, ...)
    ↓
调用面 (openat, write, renameat2, ...)
    ↓
归一化事件 (struct event → agent.Event)
```

**覆盖评估：** 核心文件变异调用约 86–93%；`write`/`pwrite64`/`writev`/`mmap`/`copy_file_range`/`getdents64` 已做 fd→path 评分，io_uring 已有基础行为观测但不解析 SQE，仍是弱覆盖点。

---

## 4. 手段覆盖矩阵

| 勒索手段 | 有效性 | 依赖轨 |
|----------|--------|--------|
| rename → 可疑后缀 / 赎金信 | 高 | 轨1 |
| 已知 hash 样本 | 高 | 轨3 |
| 保护域批量 open 改写 | 中 | 轨2→4 |
| 零日原地 write 加密 | 中高 | 轨2 fd→path 评分覆盖 write/pwrite64/writev/copy_file_range；已标记后 kprobe 可补杀 |
| fork 子进程逃逸 | 中 | blocked lineage exec kill 传播；dry-run/评分路径输出 exec_after_blocked |
| comm 伪装 trusted | 中 | 可配置 comm + exe 路径 + uid；默认策略已启用严格身份；backup_dirs 高危操作不被 trust 豁免 |
| mmap | 中 | writable shared mmap fd→path 评分 |
| io_uring | 低 | `io_uring_enter` 基础观测；保护域活动后计分，不解析 SQE |
| 目录扫描 | 中 | getdents64 fd→path 评分 |

---

## 5. 已知代码缺口

1. BPF IOC 已从 yaml 同步到 map，path-based LSM 硬规则已加 `protected_dirs` inode 作用域；硬拒绝仍依赖 active BPF LSM
2. `EventWrite` 已基于 agent fd→path 缓存计分，且跟踪 close/dup/fcntl 复制、相对 dirfd 与空闲淘汰；mmap 已做 fd→path 评分，io_uring 当前仅做上下文关联计分
3. deny 动作已用 kprobe `bpf_override_return(-EPERM)`；仍依赖内核 error injection allowlist
4. kprobe 符号仅 x86_64
5. blocked lineage 已支持 kill 传播与 `exec_after_blocked` 评分输出
6. Agent 无自保护

---

## 6. 下一步开发计划（摘要）

完整路线图见 [roadmap.md](./roadmap.md)。

| 阶段 | 目标 | 关键任务 |
|------|------|----------|
| **Phase 1** | 闭环修复 | yaml→BPF IOC 同步；write 评分；保护域 scoped IOC；exec 传播 |
| **Phase 2** | 特征抽象 | 特征向量、rules DSL、状态机、trust 升级 |
| **Phase 3** | 调用面扩展 | mmap、copy_file_range、多架构、真 deny |
| **Phase 4** | 产品化 | 自保护、扩展集成测试、SIEM |

**建议里程碑：** v0.2 = Phase 1 完成。

---

## 7. 代码索引

| 主题 | 路径 |
|------|------|
| 行为评分/阻断 | `internal/agent/agent.go` |
| 黑名单 | `internal/agent/blacklist.go` |
| BPF | `bpf/ransomware.bpf.c` |
| 传感器 | `internal/sensor/sensor.go` |
| 策略 | `configs/ransomware.yaml` |

---

## 8. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-06-08 | 初版合并 review |
| 2026-06-08 | 文档对齐；新增调用抽象与 roadmap 引用 |
| 2026-06-09 | 完成 Phase 1.7：用户态状态空闲淘汰与 ringbuf drop 增量日志 |
| 2026-06-09 | 完成 Phase 1.1/1.2：yaml IOC 同步 BPF map，path-based LSM IOC 增加 protected dir 作用域 |
| 2026-06-09 | 完成 Phase 2.1：alert JSON 输出 procFeatures 特征向量 |
| 2026-06-09 | 完成 Phase 2.2：yaml rules[] 支持特征阈值规则并覆盖不改名扇出阻断 |
| 2026-06-09 | 完成 Phase 2.3：加密状态机输出 STAGE/FINALIZE |
| 2026-06-09 | 完成 Phase 2.6：结构化 metrics 日志导出 alert/block/blacklist/drop 计数 |
| 2026-06-09 | 完成 Phase 3.5：getdents64 目录扫描采样与阻断回归 |
| 2026-06-09 | 完成 Phase 3.1：writable shared mmap 采样与阻断回归 |
| 2026-06-09 | 完成 Phase 3.6：io_uring_enter 基础观测与集成回归 |
| 2026-06-09 | 完成 Phase 3.3/3.4：多架构 kprobe 符号候选与 deny override 回归 |
| 2026-06-09 | 完成 Phase 4.2/4.4：trusted rsync、make -j 误报回归与 alert/metrics schema v1 |
