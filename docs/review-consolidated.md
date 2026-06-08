# ebpffls 合并 Review（代码 + 文档）

> 版本：2026-06-08（文档已对齐更新）  
> 详见：[strategy.md](./strategy.md)、[ransomware-call-abstraction.md](./ransomware-call-abstraction.md)、[roadmap.md](./roadmap.md)

---

## 1. 项目现状

ebpffls 是 **四轨混合防勒索** 运行时守卫：

1. **IOC 快轨** — BPF LSM 可疑名即时 `-EPERM`（要求 active BPF LSM）
2. **行为慢轨** — 保护域 syscall 滑动窗口评分
3. **哈希轨** — SHA256 黑名单（exec + `/proc` 扫描）
4. **执法轨** — 已标记 TGID：x86_64 kprobe SIGKILL；LSM 在 active 时补充 deny/kill

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

**已对齐：** 默认 `action: kill` + CLI `--dry-run=true`；`write` 未计分等限制已在 README/strategy 标明。

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

**覆盖评估：** 核心文件变异调用约 60–70%；**最弱环节是 `write` 原地加密链**。

---

## 4. 手段覆盖矩阵

| 勒索手段 | 有效性 | 依赖轨 |
|----------|--------|--------|
| rename → 可疑后缀 / 赎金信 | 高 | 轨1 |
| 已知 hash 样本 | 高 | 轨3 |
| 保护域批量 open 改写 | 中 | 轨2→4 |
| 零日原地 write 加密 | 中低 | 轨2 仍弱；已标记后 write kprobe 可补杀 |
| fork 子进程逃逸 | 低 | exec_after_blocked 未实现 |
| comm 伪装 trusted | 低 | 完全豁免 |
| mmap / io_uring | 无 | 未观测 |

---

## 5. 已知代码缺口

1. BPF IOC 硬编码，与 yaml 不同步；硬规则无 `protected_dirs` 作用域；且依赖 active BPF LSM
2. `EventWrite` 不计分；write 已有 kprobe kill 但缺少路径感知评分
3. kprobe 仅 `bpf_send_signal`，不 `bpf_override_return`
4. kprobe 符号仅 x86_64
5. `exec_after_blocked` 作为评分规则未实现；kill 传播已实现
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
