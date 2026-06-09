# 勒索软件调用抽象

本文档将勒索软件在 Linux 上的典型行为，抽象为可观测的**调用面（Call Surface）**与**语义操作（Semantic Ops）**，并映射到 ebpffls 当前的观测与执法能力。

---

## 1. 为什么做调用抽象

勒索家族千差万别，但在主机上要完成「加密落地」，必须通过有限的内核接口修改文件。防御侧不应绑定某个家族名，而应绑定：

1. **调用了什么**（syscall / LSM 钩子点）
2. **对谁调用**（路径作用域、文件类型）
3. **以什么模式调用**（读改写、重命名、截断、创建）
4. **调用有多猛**（速率、扇出、持续时间）

ebpffls 的演进方向是：**L1 归一化调用事实 → L2 关联成语义特征 → L3 策略判定 → L4 执法**。

---

## 2. 三层调用模型

```
┌──────────────────────────────────────────────────────────────┐
│ L3 语义操作（Semantic Op）— 勒索意图的可组合描述                │
│   ENCRYPT_INPLACE | RENAME_SUFFIX | DROP_ORIGINAL | ...       │
├──────────────────────────────────────────────────────────────┤
│ L2 内核调用面（Call Surface）— syscall + VFS/LSM 钩子         │
│   openat(O_RDWR) | write | renameat2 | unlinkat | ...         │
├──────────────────────────────────────────────────────────────┤
│ L1 归一化事件（Normalized Event）— ebpffls struct event       │
│   {tgid, comm, type, path, path2, flags, size, ts}            │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. 语义操作目录（勒索通用）

| 语义 ID | 含义 | 典型调用序列 | 检测价值 |
|---------|------|--------------|----------|
| `SO_SPAWN` | 投放/执行载荷 | `execve` | 身份、黑名单 |
| `SO_SCAN` | 侦察目录 | `getdents64`*, `stat`*, `openat(O_DIRECTORY)` | 早期预警 |
| `SO_STAGE_OPEN` | 打开目标写 | `openat(O_RDWR\|O_WRONLY\|O_TRUNC)` | 核心 |
| `SO_ENCRYPT_WRITE` | 原地覆写 | `write` / `pwrite` | 核心（最常见） |
| `SO_RENAME_SUFFIX` | 改后缀 | `renameat` / `renameat2` | 高置信 IOC |
| `SO_TRUNCATE` | 截断破坏 | `truncate` / `ftruncate` | 中高 |
| `SO_DELETE` | 删除原文件/影子 | `unlinkat` | 中高 |
| `SO_CREATE_NOTE` | 留赎金信 | `openat(O_CREAT\|O_WRONLY)` + `write` | 高置信 IOC |
| `SO_BACKUP_STRIKE` | 破坏备份 | `unlinkat`/`truncate` on backup_dirs | 高 |
| `SO_PERSIST` | 持久化/横向 | `execve`, `fork`* | 逃逸面 |

\* 尚未观测。

### 3.1 常见加密模式 → 调用链

**模式 A：原地加密（最常见）**

```
openat(path, O_RDWR) → write* → [可选 unlink]
```

**模式 B：扩展名替换**

```
openat(old, O_RDWR) → write* → renameat(old → old.locked)
或：renameat(old → old.locked) 直接
```

**模式 C：写新删旧**

```
openat(new) → write* → unlinkat(old)
或：copy_file_range* → unlinkat(old)
```

**模式 D：截断破坏**

```
truncate(path, 0) 或 ftruncate(fd, 0)
```

---

## 4. 调用面 ↔ ebpffls 映射表

### 4.1 观测（Tracepoint → Normalized Event）

| 内核入口 | Event 类型 | 携带字段 | Agent 用途 |
|----------|------------|----------|------------|
| `sys_enter_execve` | `EVENT_EXEC` | path=filename | 黑名单哈希 |
| `sys_exit_openat` / `sys_exit_openat2` | `EVENT_OPEN` | path, arg0=flags, arg1=fd, size=dirfd | 写意图、赎金信、扩展名；建立 fd→path 缓存并解析相对 dirfd |
| `sys_enter_write` / `sys_enter_pwrite64` / `sys_enter_writev` | `EVENT_WRITE` | arg0=fd, size | 使用 agent fd→path 缓存做保护域/备份域评分 |
| `sys_enter_copy_file_range` | `EVENT_WRITE` | arg0=fd_out, size | 使用目标 fd→path 缓存覆盖写新删旧模式 |
| `sys_enter_close` | `EVENT_CLOSE` | arg0=fd | 删除 fd→path 缓存，避免 fd 复用误杀 |
| `dup` / `dup2` / `dup3` / `fcntl(F_DUPFD*)` exit | `EVENT_DUP` | arg0=oldfd, arg1=newfd | 复制 fd→path 缓存，覆盖 dup 后写入 |
| `sys_enter_rename` | `EVENT_RENAME` | path, path2 | 后缀替换 |
| `sys_enter_renameat` | `EVENT_RENAME` | path, path2 | 后缀替换 |
| `sys_enter_renameat2` | `EVENT_RENAME` | path, path2, arg0=flags | 后缀替换 |
| `sys_enter_unlink` | `EVENT_UNLINK` | path | 删除/清痕 |
| `sys_enter_unlinkat` | `EVENT_UNLINK` | path | 删除/清痕 |
| `sys_enter_truncate` | `EVENT_TRUNCATE` | path, size | 截断 |
| `sys_enter_ftruncate` | `EVENT_TRUNCATE` | arg0=fd, size | 通过 agent fd→path 缓存解析保护域/备份域 |

### 4.2 快轨执法（BPF LSM，无需先标记 TGID）

> 该能力要求运行时 active LSM 列表包含 `bpf`。若 `/sys/kernel/security/lsm`
> 中没有 `bpf`，这些 BPF LSM 程序即使加载成功，也不能作为可靠执法路径。

| LSM 钩子 | 触发条件 | 语义操作 |
|----------|----------|----------|
| `file_open` | 写打开 + 可疑 dentry 名 | `SO_CREATE_NOTE`, `SO_RENAME_SUFFIX` |
| `path_rename` / `inode_rename` | new dentry 可疑名 | `SO_RENAME_SUFFIX` |
| `path_mknod` / `inode_create` | 创建可疑名 | `SO_CREATE_NOTE` |
| `path_unlink` | 可疑名 | `SO_DELETE` |

> 当前硬规则**全局生效**，且 IOC 列表在 BPF 内硬编码，与 yaml 未完全同步。

### 4.3 执法轨（需先 BlockTGID）

| 机制 | 覆盖调用 | 行为 |
|------|----------|------|
| LSM `file_open` | 写打开 | `-EPERM` / SIGKILL（需 active BPF LSM） |
| LSM `file_permission` | `MAY_WRITE` | `-EPERM` / SIGKILL（需 active BPF LSM） |
| LSM `path_truncate` | truncate | `-EPERM` / SIGKILL（需 active BPF LSM） |
| LSM `path_rename` / `inode_rename` | rename | `-EPERM` / SIGKILL（需 active BPF LSM） |
| LSM `path_unlink` | unlink | `-EPERM` / SIGKILL（需 active BPF LSM） |
| LSM `bprm_check_security` | execve | `-EPERM` / SIGKILL（需 active BPF LSM） |
| kprobe `__x64_sys_*` | openat/rename/unlink/truncate/ftruncate/execve/write/pwrite64/writev/copy_file_range | SIGKILL |

### 4.4 未覆盖调用面（缺口）

| 调用面 | 语义操作 | 优先级 |
|--------|----------|--------|
| `getdents64` / `stat` | `SO_SCAN` | P2 |
| `mmap` + 写 | `SO_ENCRYPT_WRITE` | P1 |
| `io_uring` 异步 I/O | 多种 | P2；当前已有 `io_uring_enter` 基础观测，不解析 SQE |
| `link` / `symlink` | 逃避/替换 | P2 |
| socket 系列 | 外传/C2 | P3（新子系统） |

---

## 5. 四维特征（与调用抽象正交）

在调用面之上，用四个维度组合判定「像勒索」：

| 维度 | 从调用中抽取的特征 | 示例规则 |
|------|-------------------|----------|
| **Scope** | path ∈ protected_dirs；distinct_paths/窗口 | 扇出 > 50 |
| **Pattern** | open→write 比；rename 后缀比 | rename_suffix_rate > 0.3 |
| **Rate** | events/s；write bytes/s | open_write > 30/10s |
| **Lineage** | ppid；blocked 祖先；exe hash | parent_blocked → block child |

当前实现已有 Scope（路径前缀）+ 部分 Pattern（扩展名/赎金信）+ 弱 Rate（open/write 计数），并对 blocked lineage 的 exec 做 kill 传播和 `exec_after_blocked` 评分；更完整的跨会话/跨 cgroup Lineage 仍待演进。

---

## 6. 目标策略形态（演进方向）

```yaml
# 未来形态示意，当前 yaml 尚未支持
semantic_rules:
  - name: instant-suffix-rename
    when: [SO_RENAME_SUFFIX, scope.protected]
    action: block_immediate

  - name: bulk-encrypt
    when: [SO_STAGE_OPEN, rate.distinct_paths > 50, scope.protected]
    action: block

  - name: fork-after-block
    when: [SO_SPAWN, lineage.parent_blocked]
    action: block
```

---

## 7. 小结

| 问题 | 答案 |
|------|------|
| 勒索调用能否抽象？ | **能**，分为语义操作 → 调用面 → 归一化事件 |
| 当前版覆盖多少？ | 核心文件变异调用约 **86–93%**；write/pwrite64/writev/copy_file_range/mmap/getdents64 已覆盖普通 fd 路径评分，close/dup 和相对 dirfd 生命周期已跟踪；io_uring 已有基础观测但不解析 SQE |
| 下一步抽象重点？ | 扩展 `SO_ENCRYPT_WRITE` 调用面；统一 IOC 策略源；引入特征向量 |

相关文档：[strategy.md](./strategy.md)、[roadmap.md](./roadmap.md)
