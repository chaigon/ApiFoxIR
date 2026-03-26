# ApiFoxIR

ApiFoxIR 是一个面向 2026-03 Apifox 供应链事件的本地应急排查 CLI，目标很收敛：优先回答"这台机器现在有没有明显中招迹象，以及哪些凭证已经被窃取"。

- 在 Apifox / Electron 用户数据目录里搜索已公开的 IOC 字符串。
- **直接解析 Apifox LevelDB（`Local Storage/leveldb/*.ldb/.log`），匹配 `_rl_headers`/`_rl_mc` 等恶意 localStorage 键的残留字节流。**
- 盘点被恶意脚本明确尝试窃取的敏感路径，并对 `.npmrc`、`.git-credentials`、`.zshrc` 等凭证文件做内容分析（不输出明文，仅说明存在何种敏感内容）。
- 扫描 shell / PowerShell 命令历史，查找 IOC、可疑下载执行命令和解释器调用。
- 补扫 Startup / LaunchAgents / systemd / 计划任务等持久化位置，给"是否已经落第二阶段后门"做快速分诊。
- 在 Windows 上补扫 `Run/RunOnce` 注册表启动项和 `Prefetch` 执行痕迹。
- **综合所有扫描结果，自动推断已泄露凭证类型并生成带处置动作的"泄露内容推断"章节。**

它不是杀毒软件，也不能证明主机"绝对干净"。它的定位是快速分诊和留证，不追求一次性覆盖所有深度取证源。

## 事件背景

攻击活跃期：**2026-03-04 至 2026-03-22**（18 天）。

攻击者向 Apifox 官方 CDN 的 JS 文件植入约 42KB 的严重混淆恶意代码（7 层混淆 + 反调试），利用 Electron `nodeIntegration` 获取完整 Node.js 权限。

**攻击链：**

| 阶段 | 行为 | 窃取内容 |
|---|---|---|
| Stage-1 | 采集机器指纹；读取 Apifox `common.accessToken`；调用官方 API 获取账户邮箱/姓名 | MAC 地址、CPU、主机名、Apifox 账户信息 |
| Stage-2 v1 | `collectPreInformations()` | `~/.ssh/*`（全部密钥）、`~/.zsh_history`、`~/.bash_history`、`~/.git-credentials`、`ps aux` / `tasklist` |
| Stage-2 v2 | `collectAddInformations()` | `~/.kube/*`、`~/.zshrc`、`~/.npmrc`、`~/.subversion/*`、主目录/桌面/文档目录树 |
| 持续轮询 | `eval(rsaDecrypt(C2响应))`，每次可下发不同指令 | 任意后续载荷（横向移动、后门植入等） |

数据外泄全程加密（RSA-2048 OAEP 头部 + AES-256-GCM 正文 + Gzip），AES 密钥 `apifox`，盐值 `foxapi`。

参考资料：[Apifox 供应链投毒攻击 - 完整技术分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)

## 工具内置的威胁结论

- 公开样本已确认有信息窃取和主机侦察行为。
- 公开样本同样显示恶意代码会从 C2 拉取加密 JavaScript 并 `eval()` 执行，所以不能只按"凭证窃取器"处理。
- 因此本工具会额外扫描常见持久化位置，帮助发现可能已经从 Apifox 进程外独立运行的第二阶段。

## 已覆盖的 IOC

**网络 / C2：**
- `apifox.it.com`
- `/event/0/log`（Stage-2 v1 上报接口）
- `/event/2/log`（Stage-2 v2 上报接口）

**恶意载荷特征：**
- `/public/apifox-event.js`
- `apifox-app-event-tracking`（投毒 CDN 文件名特征）
- `collectpreinformations`（Stage-2 函数名）
- `collectaddinformations`（Stage-2 函数名）
- `scryptsync`（AES-256-GCM 密钥派生函数调用特征）

**LevelDB / localStorage 键：**
- `_rl_headers`
- `_rl_mc`
- `common.accessToken`

**注入请求头：**
- `af_uuid` / `af_os` / `af_user` / `af_name`
- `af_apifox_user` / `af_apifox_name`

**加密参数：**
- `foxapi`（AES 盐值）
- `miiEvqIBADANBgk`（攻击者嵌入的 RSA-2048 私钥 PKCS#8 Base64 特征前缀）

## 已盘点的敏感路径及内容分析

| 路径 | 分析方式 |
|---|---|
| `~/.ssh` | 元数据 + 文件数量 + 总大小 |
| `~/.kube` | 元数据 + 文件数量 |
| `~/.git-credentials` | 内容分析：检测含 token 的 HTTPS URL 格式 |
| `~/.npmrc` | 内容分析：检测 `_authToken` / `_auth` / 私有 registry 凭证 |
| `~/.zsh_history` | 元数据 + IOC 命中 |
| `~/.bash_history` | 元数据 + IOC 命中 |
| `~/.zshrc` | 内容分析：检测 9 类内联环境变量凭证（AWS Key、Vault Token 等） |
| `~/.subversion` | 元数据 + 文件数量 |

## 构建

排查工具：

```bash
go build -o ApiFoxIR ./cmd/ApiFoxIR
```

为 Windows 主机交叉编译：

```bash
GOOS=windows GOARCH=amd64 go build -o ApiFoxIR.exe ./cmd/ApiFoxIR
```

清理工具：

```bash
go build -o ApiFoxIR-clean ./cmd/ApiFoxIR-clean
```

为 Windows 主机交叉编译：

```bash
GOOS=windows GOARCH=amd64 go build -o ApiFoxIR-clean.exe ./cmd/ApiFoxIR-clean
```

## 使用

默认扫描本机可见用户目录，并把结果写到 `./out/report.json` 与 `./out/report.md`：

```bash
./ApiFoxIR
```

如需切回纯文本摘要输出：

```bash
./ApiFoxIR -format text
```

附加扫描一个便携安装目录或挂载出来的用户数据目录：

```bash
./ApiFoxIR -extra-root "D:\\PortableApps\\Apifox"
```

默认情况下，`-extra-root` 会按“外部证据目录”处理：

- 适合扫描挂载出来的其他主机用户数据目录。
- 命中会展示在“额外扫描目录”里，但不会默认并入当前分析机的中招结论，也不会把当前分析机本地的 `~/.ssh`、`.npmrc`、`.zshrc` 误算为已泄露。
- 这类目录的命中会保留在 `report.extra_root_findings`，同时 `report.extra_root_mode` 会标记为 `external`。

如果这个目录其实就是**当前主机**的便携版或非标准安装路径，请显式切到本机模式：

```bash
./ApiFoxIR -extra-root "D:\\PortableApps\\Apifox" -extra-root-mode local
```

`-extra-root-mode local` 的含义：

- 把 `-extra-root` 当作**当前主机**的附加 Apifox 数据目录。
- 其中命中的 IOC、LevelDB 和 `Network/` 缓存会并入当前主机的中招判断、C2 通信证据和“泄露内容推断”。
- 只应在你确认该目录确实属于当前被分析主机时使用。

如需把命中 IOC 的 Apifox 文件复制到输出目录留证：

```bash
./ApiFoxIR -copy-apifox-evidence
```

## 清理工具使用

`ApiFoxIR-clean` 用于在保留最小安全控制的前提下，删除已命中的恶意残留。默认只删除 LevelDB 中命中 IOC 的 `.ldb/.log` 文件，不会直接清空整个 Apifox 数据目录。

预演全量清理：

```bash
./ApiFoxIR-clean -all
```

实际执行全量清理：

```bash
./ApiFoxIR-clean -all -dry-run=false
```

只清理 LevelDB 命中 IOC 的文件：

```bash
./ApiFoxIR-clean -dry-run=false
```

如果你只想删除持久化位置里的可疑条目，可单独开启：

```bash
./ApiFoxIR-clean -remove-persistence -dry-run=false
```

## 输出解释

### 泄露内容推断章节

报告中的 **"泄露内容推断"** 章节由 `BuildLeakageAnalysis()` 自动生成，综合所有扫描结果推断已暴露的凭证类型，并给出每类凭证的：

- **证据说明**：支撑推断的具体依据（文件存在 + 攻击窗口活动 + LevelDB IOC）
- **风险等级**：高 / 中 / 低
- **必要处置**：具体的轮换/审查动作

触发推断的条件：
1. `ActivityDuringIncident` — Apifox 数据目录在攻击窗口（2026-03-04 至 2026-03-22）内有文件被修改
2. `LevelDBIOCFound` — 在 `Local Storage/leveldb/` 中直接发现 `_rl_headers`/`_rl_mc` 字节
3. `-extra-root-mode local` 下，`-extra-root` 目录中发现的 LevelDB / IOC / `Network/` 缓存也会计入本机推断

默认 `-extra-root-mode external` 下，额外目录只作为外部证据展示，不会驱动当前分析机的：

- `assessment`
- `c2_contact_evidence`
- `leakage_analysis`

### 综合评估状态

`assessment.compromise_status` 给出最终判定：

- `evidence-of-compromise`: 已发现中招迹象。
- `review-required`: 存在可疑迹象，需人工复审。
- `exposure-risk`: 更像暴露风险，建议继续跟进。
- `no-clear-compromise-evidence`: 当前未发现明确中招迹象。

标记说明：

- `host-ioc-found`: 在扫描目录里直接发现已知 IOC 字符串，按已受害主机处理。
- `likely-exposed-host`: 没有残留 IOC，但 Apifox 目录在已知攻击窗口内有活动，同时用户配置里存在高价值凭证路径。
- `possible-post-exploitation`: 在启动项/持久化位置发现了可疑条目，或者这些位置里直接命中了本次事件 IOC，需要按"可能已落二阶段"处理。
- `manual-review-required`: 没有足够的硬 IOC，但命令历史、注册表或持久化位置存在启发式可疑项，需要人工复审。
- `apifox-active-during-window`: 说明该用户在攻击窗口内使用过 Apifox，需要进一步核实。
- `no-apifox-artifacts-found`: 没找到标准 Apifox 数据目录；不等于绝对安全。

### 额外扫描目录模式

`report.json` 中新增：

- `extra_root_mode`: `external` 或 `local`

解释如下：

- `external`: 额外目录按外部证据处理，适合离线挂载目录、便携包样本目录、其他主机导出的用户数据目录。
- `local`: 额外目录按当前主机附加目录处理，适合本机便携版 Apifox、非标准安装路径、手工迁移过的用户数据目录。

## 人工复审标准

JSON 报告里的启发式结果都会带 `review` 字段：

- `direct_ioc`: 高置信度。表示直接命中了公开 IOC 或直接引用了 Apifox 恶意加载链相关内容。包括 LevelDB 中发现的恶意 localStorage 键。
- `behavioral_correlation`: 中置信度。表示命中了"解释器/下载器 + 网络/可写路径 + 持久化/命令历史"等组合特征。
- `execution_artifact`: 中置信度。表示只证明在攻击窗口执行过某个程序，需要结合更多证据判断。

建议复审方法：

- 对 `direct_ioc`：打开原文件或注册表值确认 IOC 是否真实存在，再结合 EDR / 进程创建日志 / DNS / 代理日志做时间线。LevelDB 命中时可用十六进制编辑器确认字节内容。
- 对 `behavioral_correlation`：检查完整命令、文件签名、安装来源、父目录权限，以及是否属于正常 IT 自动化或开发脚本。
- 对 `execution_artifact`：把它当作时间线 pivot，继续核对 Prefetch 邻近项、Jump List、命令历史上下文和进程创建日志。

## 局限

- 不解析内存，也不覆盖未知后门或内存态负载。
- 不会默认复制 `~/.ssh`、`~/.kube` 等敏感内容，只记录元数据和哈希。
- LevelDB 扫描采用字节流字符串匹配，不做完整 LevelDB 协议解析，极小概率漏掉只存在于压缩块内部的 key。
- 对 Windows 事件日志、`Amcache`、EDR 命中、浏览器代理日志等更深层证据，目前未做采集；这些不属于当前"首轮中招排查"范围。
- C2 采用 DOM 自清理机制，内存态执行的后续载荷不会留下文件痕迹，本工具无法检测。
