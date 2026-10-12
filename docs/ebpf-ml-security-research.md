# eBPF + ML runtime security research

> 初次调研：2026-09-04；复核：2026-09-07。区分论文主张、公开实现和本项目建议。本次是论文与源码审查，未运行竞品或真实恶意样本；固定版本以文末来源为准。

## Review 结论

方向保留，但四项研究不能直接视为成熟的自适应检测引擎。最值得融合的是上下文归属、速率与短序列特征、分层采集和响应前证据验证。具体实施见 [自适应检测开发计划](./adaptive-detection-plan.md)。

| 优先级 | 旧报告的问题 | 修正与开发影响 |
|--------|--------------|----------------|
| P1 | 性能口径不完整，容易低估全量采集成本 | CryptoGuard 的 0.06 是监控端 CPU 使用率增量百分点；同文另报告良性应用 CPU 平均增加 10.97%。Tetragon 的 1.52x/2.98x 是应用请求延迟比。必须分别测采集、推理和业务影响。 |
| P1 | 把 Tetragon + ML 一并归为秒级至分钟级检测 | 该文未报告在线端到端检测时延；40-gram 是事件数，不是秒数，不能据此承诺勒索阻断时延。 |
| P1 | PATROL 的自适应、LSM 与同步阻断容易过度解读 | Adaptive Policy Learning 是 future work；本次未核验到对应实现或具体 LSM hook。异步 verdict map 不等于保证阻止产生该事件的同一次 syscall。 |
| P2 | CryptoGuard 写成 CNN + LSTM，sketch 参数写成唯一配置 | CNN/LSTM 是比较的候选分类器，不是已证明串联的混合网络；论文与不同源码实验使用不同 sketch 配置。 |
| P2 | ebpfangel 遗漏了最有用的特征组合 | 离线模型还融合每秒峰值、累计数量和长度 3 的行为序列频次，比照搬两个固定 pattern 更适合本项目。 |
| P2 | 样本数和 accuracy 的泛化边界不够明确 | 123 个样本高度偏向 Sysrv；Tetragon 只做两类矿工与四类正常服务六分类。都不足以承诺未知攻击检测效果。 |

## 策略对比

| 项目 | 采集与特征 | 检测与响应 | 应吸收的点 | 不应直接照搬 |
|------|------------|------------|------------|--------------|
| [eBPF-PATROL][patrol] | syscall 参数、进程及容器上下文；tracepoint、kprobe、cgroup hook | 用户态 signature、behavior profile、YAML policy；论文描述 deny、kill、capability revoke、isolation | 工作负载身份、事件关联、策略与执行分离 | 把命令名黑名单当通用行为识别；把 future work 当已有自学习 |
| [CryptoGuard][crypto] | host/VM 分布 sketch，process/container 滑动 syscall 序列 | 两阶段分类；CNN/LSTM 候选；响应前验证持久化等迹象 | 低成本筛查后定向深入、触发前历史、证据交叉验证 | 固定照抄 sketch/LSTM、按 comm 关联和终止、认为仓库已完整闭环 |
| [ebpfangel][angel] | open/create/delete/encrypt 计数、峰值、短序列及序列频次 | 内核静态匹配，用户态 CSV，离线 RBF-SVM | 多种弱特征组合、短语义序列 | “DT + MLP 在 eBPF 内运行”；将 OpenSSL 调用等同文件已加密 |
| [Tetragon + ML][tetragon] | Tetragon syscall number 序列、Kubernetes metadata、n-gram | 离线六分类，比较 SVM/KNN/DT/MLP/LSTM | 序列顺序、轻重模型对照、容器归属 | 将 99.75% 当阻断率或未知攻击召回率；默认全 syscall 采集低开销 |

## eBPF-PATROL

论文架构由 Probe Manager、Policy Engine、Event Analyzer、Enforcement Module 组成。用户态结合 syscall 参数与进程/容器 profile 产生 verdict，通过 map 和运行时响应。可借鉴职责划分，但不是已验证的学习算法。[架构与实现][patrol-architecture]

- 第 VIII 节将 Adaptive Policy Learning 明确列为未来工作，不能写成已有自动学习与策略收敛。[Future Work][patrol-future]
- 部分示例依据 `bash`、`nc`、`python`、`sh` 及参数匹配，不足以证明适应 AI 训练、推理等正常高负载。
- 论文描述异步用户态策略评估，又描述拒绝操作，但未充分解释同一次 syscall 的同步保证。必须区分预置内核规则的即时拒绝和用户态判定后的后续操作限制。
- 本次核验的 v1 正文没有明确 LSM 实现说明，也未核验到对应可复现代码，不将“eBPF-LSM 代理”作为已证实实现事实。
- 平均响应 23 us、p99 41 us、性能开销低于 2.5% 仅作为该论文场景内主张，不作为本项目实测或独立复现结果。[评估][patrol-evaluation]

取舍：学习 workload identity 和策略/执行分离；自行验证行为证据与内核执行能力，不照搬高层响应保证。

## CryptoGuard

### 检测策略

第一阶段在 host/VM 范围聚合 syscall 分布，使用 Count-Min Sketch 和分类器筛查；第二阶段用 process/container 近期滑动序列定位可疑对象。CNN 和 LSTM 是实验比较的候选模型，不应写成固定串联网络。第二阶段依赖近期历史，不能理解成触发后才记录就能还原触发前行为。[方法第 3.4-3.5 节][crypto-method]

Remediator 验证可疑持久化入口等迹象后采取响应。可迁移的是“分类结果 + 独立行为证据”，不是模型报可疑就终止进程。论文用进程名追踪 PID 变化的做法不可直接采用：名称可重复、可修改，动作必须绑定进程实例。[响应第 3.6 节][crypto-response]

### 评估边界

- 123 个可运行样本来自 Sysrv 100、XMRig 15、TeamTNT 5、WatchDog 3，按行为归为两个恶意类别，不是 123 个独立家族。另有 Mirai 扩展评估，也不等于通用恶意行为检测。[数据集][crypto-dataset]
- 每样本采集 300 秒，按 0-168 秒训练、169-210 秒验证、211-300 秒测试；是时间划分，但不是未见运行实例或家族验证。第二阶段比较 30/60/90 秒窗口。[切分][crypto-split]
- 两阶段平均 F1 报告为 96.12%、92.26%。端到端约 85 秒来自 55x5 sketch、30 秒滑窗配置下 100 次测试均值，包含两次约 35 秒采集及 2.68/11.87 秒推理，不适合作为勒索快速阻断路径。[开销与时延][crypto-overhead]
- 监控端 CPU 从 0.29% 到 0.35%，是增加 0.06 个百分点，不是整体系统相对开销 0.06%；同节另报告良性应用 CPU 平均增加 10.97%。中央推理与业务影响须另计。

### 公开实现

复核固定快照 `a65f65986a192cfe1a11b15660503ae5d4a49faf`，不声称覆盖后续提交。

- 有 Phase 1/2 训练 notebook、CMS 特征实验及离线滑窗。顶层仍主要是 30 秒采集、CSV、调用 `judge.py`、输出可疑进程名；未核验到第一阶段 verdict 自动驱动第二阶段采集及响应的完整编排。[训练实验][crypto-phase1]、[顶层流程][crypto-main]
- `Model/CMS` 示例有 width 272、depth 3、seed 1934；其他生成器支持宽深参数，`cms4` notebook 使用 1x165 输入。272x3 不能写成整个系统唯一配置。[生成器][crypto-cms]
- 存在 XDP、按进程名找 PID、CronGuard 等独立响应试验，但未集成上述主流程；XDP 示例硬编码 PID 1234，不能证明按真实进程归属隔离网络。[XDP 示例][crypto-xdp]
- 顶层按 comm 分流，`judge.py` 固定取前 1024 个 syscall，类别编码超过 255 却存入 `uint8`；代表性 Phase 2 notebook 又逐文件拟合编码。必须统一身份、词表、类型宽度和训练/推理预处理契约。[推理][crypto-judge]、[Phase 2][crypto-phase2]
- 部分 CMS 实验混合 149 个良性文件和 1 个恶意文件，再随机划分合成 sketch；尚未排除同一源运行进入多个集合的风险，不表述为已经证实的数据泄漏。[合成数据][crypto-mix]

取舍：分层成本控制、触发前摘要、响应前独立证据验证。少量语义事件先用精确计数；高基数序列特征确有需要时再评估 sketch。

## ebpfangel

复核固定快照 `d5e7d3cdebf19474722a97a6238b8f737d16b7d0`。公开代码没有在 eBPF 内运行决策树或 MLP，离线分类实际为 RBF-SVM。[模型][angel-model]

- 内核按 `bpf_get_current_pid_tgid()` 低 32 位维护状态，实际为线程 TID；记录四类行为计数及最多 8 个事件的 4-bit 序列，匹配两个短 pattern。[内核实现][angel-bpf]
- 离线 `dataprep.py` 按 CSV 的 PID 字段组织数据，融合每秒峰值、累计数量、pattern 和长度 3 的行为序列频次，再送入 SVM。这是旧报告遗漏的重要思路。[特征工程][angel-features]
- 时间分布与操作顺序补充总次数，但原型没有同文件关联和跨线程聚合，不能将进程内相邻事件解释成同一文件的加密链。
- OpenSSL uprobes 只覆盖动态 `libcrypto.so.1.1/.3` 的三个 EVP 初始化函数，看不到所有静态链接/自带实现；`EVP_CipherInit_ex` 未区分加解密。因此 crypto hook 只能作可选弱证据。[探针][angel-probes]
- 源码有不宜照搬的问题：`last_reset_ts` 零初始化而非零才更新，周期重置无法正常开始；Python `reset_period_ns` 为 `c_uint32`，C 侧为 `u64`；模型代码未使用 `scaler.transform(...)` 返回值。应借鉴特征思路并重建在线状态和测试。[重置][angel-reset]、[Python 配置][angel-config]、[C 配置][angel-config-c]、[标准化][angel-model]

在线 detector 输出 CSV，不含在线模型闭环及 deny/kill。训练/测试 CSV 约 1448/1338 行不代表独立攻击运行数，不足以证明跨家族泛化。浅克隆的本地提交数量不用于判断成熟度。

## Tetragon + ML cryptojacking

论文用 Tetragon `raw_syscalls/sys_enter` 采集 syscall number，结合 Pod 等 Kubernetes metadata 归属，生成 n=5..50 的 overlapping/non-overlapping frame。不是文件语义模型，也未使用 syscall 返回值。[方法第 3.1 节][tetragon]

- 最佳 99.75% accuracy/F1 来自 overlapping 40-gram、两层 LSTM 六分类；non-overlapping 最佳为 5-gram 决策树，99.24%。轻量模型值得作对照，但不能据不同窗口的成绩断言模型等效。
- 六类为 XMRig、xmr-stak-cpu、Media-Streaming、Data-Caching、Web-Serving、MariaDB。表 1 的 `Number of Samples` 为矿工 115,611/125,432、良性合计 241,734，但未充分说明是原始记录还是转换后 frame，不能当作独立恶意样本数。
- 先生成 frame，再分层采样做 70/30 切分，训练集另取 20% 验证。未说明按运行实例、家族或时间分组；重叠 frame 可能跨集合，论文也承认重复 frame 会过拟合。结论是有风险，非已证实泄漏。
- 表 6 是开启监控/无监控的应用平均请求延迟比，每类重复 10 次：MariaDB 19.263 -> 29.24 ms，即 1.52x；Data-Caching 3.783 -> 11.29 ms，即 2.98x；Web-Serving 为 1.07x/1.08x/1.18x。不是 agent CPU 或在线检测时延。
- 未报告在线端到端检测/阻断时延；第 5.1 节明确把模型与 Tetragon enforcement 集成留作 future study。这不等于上游 Tetragon 没有 enforcement 能力。
- 第 5.2 节用另一个工具 bpfFlowMon 观察网络 bytes/packets，未报告融合后模型增益，不能称为已验证的 syscall + network 联合检测器。

取舍：借鉴序列与容器上下文，保留简单模型对照，先分组再切窗；根据业务开销决定升级采集。原始 syscall 数字跨架构不可直接混训，先归一化为稳定语义事件。

## 对 ebpffls 的决定

1. 保留受策略约束的确定性快路径，不让统计模型阻塞同步 IOC，也不扩大现有 IOC 的置信含义。
2. 先统一事件成功/尝试语义、进程实例、文件对象与 workload 归属，再做顺序、速率和多进程关联。
3. 规则、序列、基线、模型汇入可解释证据层；相关证据去重，低置信异常不能覆盖确定性判定，也不能单独触发 kill。
4. 常态维护精确计数和有界触发前摘要，可疑时按 workload 升级采集；有迟滞、TTL、预算与丢失标记，不将抽样后的相邻事件当真实连续 syscall。
5. 先做用户态短序列、统计基线及轻量模型 shadow，证实增量价值后再考虑 LSTM。勒索与挖矿采用不同时间尺度。
6. 不直接移植竞品代码和模型权重；确需复用先审许可证及数据来源。文件熵、诱饵文件是可另行评估的扩展，不归功于这四项已核验策略，第一阶段不纳入。

[patrol]: https://arxiv.org/html/2511.18155v1
[patrol-architecture]: https://arxiv.org/html/2511.18155v1#S4
[patrol-future]: https://arxiv.org/html/2511.18155v1#S8
[patrol-evaluation]: https://arxiv.org/html/2511.18155v1#S6
[crypto]: https://arxiv.org/html/2510.18324v1
[crypto-method]: https://arxiv.org/html/2510.18324v1#S3.SS4
[crypto-response]: https://arxiv.org/html/2510.18324v1#S3.SS6
[crypto-dataset]: https://arxiv.org/html/2510.18324v1#S4.SS1
[crypto-split]: https://arxiv.org/html/2510.18324v1#S4.SS3
[crypto-overhead]: https://arxiv.org/html/2510.18324v1#S4.SS6
[crypto-phase1]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/Model/phase1/4digits_cms4_CNN_1D.ipynb
[crypto-phase2]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/Model/phase2/30sec_multi_LSTM.ipynb
[crypto-main]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/CryptoGuard/cryptoguard.c#L123
[crypto-cms]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/dataset/cms/gen3.c#L189
[crypto-xdp]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/CryptoGuard/eBPF_module/test/drop_tcp.bpf.c#L18
[crypto-judge]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/CryptoGuard/judge.py#L309
[crypto-mix]: https://github.com/PGHOON/CryptoGuard/blob/a65f65986a192cfe1a11b15660503ae5d4a49faf/Model/CMS/parallel_cms_malware.c#L120
[angel]: https://github.com/TomasPhilippart/ebpfangel
[angel-model]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/machinelearning/model.py#L86
[angel-features]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/machinelearning/dataprep.py#L33
[angel-bpf]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/detector/bpf.c#L132
[angel-probes]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/detector/detector.py#L138
[angel-reset]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/detector/bpf.c#L37
[angel-config]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/detector/detector.py#L21
[angel-config-c]: https://github.com/TomasPhilippart/ebpfangel/blob/d5e7d3cdebf19474722a97a6238b8f737d16b7d0/detector/bpf.h#L83
[tetragon]: https://www.mdpi.com/2079-9292/14/6/1208
