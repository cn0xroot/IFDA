# IFDA — IoT 固件深度分析（IoT Firmware Deep Analysis）

> [English](README.md) | 简体中文

面向 IoT 固件二进制的自动化逆向工程与漏洞发现工具。本仓库实现了
[`firmware-analysis-requirements.md`](firmware-analysis-requirements.md) 中描述的**分析核心**。

> **仅限防御性/授权用途。** 只分析你拥有所有权或已获得授权评估的固件。详见需求文档 §1.3。

## 第一迭代范围

按照既定计划，第一迭代交付**二进制逆向工程（FR-RE）**和**漏洞发现（FR-VUL）**。默认摄取与解包
（FR-ING / FR-EXT）已经把文件产出到磁盘上——直接指向单个 ELF 文件或已解包的固件目录树即可。

各引擎封装了现有工具：**capstone**（多架构反汇编，无论宿主机架构如何都能处理 MIPS/ARM）、
**pyelftools** + **binutils**（ELF 解析、缓解措施检测）。更重的污点分析引擎（angr）作为未来
可选项，可在同一接口后面替换接入。

## 架构

```
        ┌───────────────────────────── Python 分析核心（本仓库） ──────┐
 解包    │ loader/      re/            vuln/           inventory/ scripts/ fs/  │
 产物 ──┼► load_elf ─► disassemble ─► dangerous_funcs ► secrets  shell    加固│─► JSON /
 (FR-   │ (架构、      缓解措施       污点分析(源→汇)   + 规则/ (命令    检查  │  Markdown
  EXT)  │  导入表、    调用图         CVE 关联          签名     注入)         │  + SBOM
        │  字符串)     交叉引用       跨二进制 +        + 熵值检测              │  (CycloneDX)
        │                             优先级/分诊                             │
        └─────────────────────────────────────────────────────────────────────┘
                         ▲
                         │ 每个任务执行一次 `ifda.cli analyze --progress`
            Go 服务/编排层（service/）  ← 队列、worker、
            REST API（FR-INT-1）、去重缓存、带实时进度的 Web UI
```

Python 核心是一个库 + CLI。项目选择的**混合架构**把批量/大规模语料的编排、REST API
（FR-INT-1）、排队（FR-ING-4）和 Web UI 放到独立的 **Go 服务层**（`service/`，已实现），
由它通过 CLI 一次驱动一个分析任务。JSON 模型（`ifda/model.py`）是两者之间的契约；核心
以 `@@IFDA@@<json>` 格式流式输出进度事件，供服务层展示实时任务进度。构建和运行方法见
[`service/README.md`](service/README.md)。

## 技术栈

**分析核心（Python 3.10+）**
- [`capstone`](https://www.capstone-engine.org/) —— 多架构反汇编（x86/x86_64、ARM、ARM Thumb-2、AArch64、MIPS 大端/小端）
- [`pyelftools`](https://github.com/eliben/pyelftools) —— ELF 解析与缓解措施检测（NX/canary/RELRO/PIE/FORTIFY），不依赖外部 `binutils` 进程
- [`cve-bin-tool`](https://github.com/intel/cve-bin-tool) —— FR-VUL-1 广域 CVE 关联的必需依赖（NVD/OSV/RedHat/GitLab Advisory/Curl，350+ 组件）
- [`yara-python`](https://github.com/VirusTotal/yara-python)（可选）—— 外部化 YARA 签名规则桥接
- [`angr`](https://angr.io/)（可选，未来计划）—— 更重的污点/符号执行引擎，计划在现有污点分析接口后面替换接入

**服务层（Go 1.22+）**
- 只用标准库，零第三方 Go 依赖——增强版 `net/http` 的 `ServeMux`（方法 + 路径参数路由）、
  手写实现的 PBKDF2（`crypto/hmac` + `crypto/sha256`）用于密码哈希、`image`/`image/png`
  用于登录验证码
- 用 Server-Sent Events（无需轮询、不依赖 WebSocket）推送实时任务进度

**Web UI**
- [Alpine.js](https://alpinejs.dev/) 3.14.1（本地内嵌，无需构建步骤，可离线使用）
- 纯 CSS，基于 CSS 自定义属性做主题化（内置 7 套主题，自适应深浅色）

**可选增强能力**
- [Ghidra](https://ghidra-sre.org/)（headless 模式）—— 为发现结果提供反编译伪代码增强

## 参考与致谢

- [**EMBA**](https://github.com/e-m-b-a/emba) —— 一个开源 IoT 固件分析工具，它在 CVE 关联
  和敏感信息挖掘上的思路影响了本项目的多处设计决策。IFDA 效仿 EMBA 的做法，把广域 CVE
  关联委托给 `cve-bin-tool` 而不是自己维护一份人工整理的 CVE 列表；它的 `config/` 签名文件
  （`deep_key_search.cfg`、`password_regex.cfg`、各类 `*_files.cfg` 敏感路径列表）也为本项目
  的敏感字符串关键词字典建设、以及修复一处 PEM 私钥检测遗漏提供了参考。感谢 EMBA 团队的
  这些前期工作。
- [**cve-bin-tool**](https://github.com/intel/cve-bin-tool)（OpenSSF 旗下项目）—— FR-VUL-1
  广域 CVE 覆盖背后的实际引擎，也是 EMBA 自己用来做 CVE 关联的同一个工具。

## 安装

> 完整的分步环境搭建（Go 升级、交叉编译器、Ghidra + JDK 的坑、验证方法）见
> [`ENVIRONMENT.md`](ENVIRONMENT.md)。

```bash
# Python 分析核心
apt-get install -y python3-capstone python3-pyelftools   # 或: pip install -e .
pip install cve-bin-tool   # 必需: FR-VUL-1 广域 CVE 覆盖（NVD/OSV/RedHat/GitLab/Curl）
pip install yara-python    # 可选: 存在 data/yara/*.yar 时启用 YARA 阶段

# Go 服务层（可选——仅在需要 REST API + Web UI 时安装）
cd service && go build -o ifda-service .                # Go 1.22+
```

`cve-bin-tool` 会维护自己的本地 CVE 数据库（NVD + OSV + RedHat + GitLab Advisory + Curl，
约 1GB+）；某台机器上首次扫描时会下载/更新该数据库，所以第一次运行会较慢且需要联网。
没有它的话 `analyze()` 仍能运行，只是 CVE 关联会退化为使用内置的小型精选数据库
`data/vuln_db.json`，报告里会带上一条关于该依赖缺失的明显警告（NFR-USE-1——
某个组件缺失时功能降级，而不是让整个任务崩溃）。

## 用法

运行 ifda 有两种方式：**CLI**（单次运行，便于脚本化）和**服务**（队列 + REST API +
带实时进度的 Web UI）。

### A. CLI ——一次性分析

```bash
# 分析一个二进制文件或已解包的目录树；默认把 JSON 输出到 stdout。
python3 -m ifda.cli analyze /path/to/extracted_rootfs --json report.json --md report.md

# 同时生成 CycloneDX 格式的 SBOM。
python3 -m ifda.cli analyze ./rootfs --json report.json --sbom sbom.json

# 在 stderr 上输出机器可读的进度事件（供服务层使用）。
python3 -m ifda.cli analyze ./rootfs --json report.json --progress

# 用 Ghidra 反编译的伪代码丰富发现结果（可选启用；需要 Ghidra，
# 设置 GHIDRA_HOME 或安装到 /opt/ghidra）。较慢；缺失时优雅降级为空操作。
python3 -m ifda.cli analyze ./rootfs --md report.md --decompile

# 对某个发现做分诊；跨重新扫描持久保存（FR-VUL-8）。
python3 -m ifda.cli triage triage.json <finding_id> false_positive
python3 -m ifda.cli analyze ./rootfs --triage triage.json   # 已静音的发现会被剔除
```

`analyze` 接受单个 ELF 文件或一个目录（已解包的固件目录树）。它会遍历目录树一次，
并运行每一个阶段：逐二进制的逆向工程/漏洞检测、跨二进制污点分析、敏感信息 +
签名规则 + 熵值检测、shell 和 PHP/Python/Lua 脚本注入检测、文件系统加固检查。

### B. 服务——队列、REST API 和 Web UI

```bash
cd service
go build -o ifda-service .                 # Go 1.22+，仅首次需要
./ifda-service -addr :8080 -core ..        # -core = 仓库目录（省略时自动探测）
# 打开 http://localhost:8080
```

参数：`-addr`、`-core`、`-workers`（默认 2）、`-queue`、`-data`（分诊状态 + 上传目录；
默认 `$TMPDIR/ifda-service`）、`-auth`（默认 `true`）、`-user`/`-pass`（仅在账号首次创建时
播种密码——不会覆盖已经通过 Web UI 修改过的密码；加 `-reset-pass` 可强制覆盖）。
完整说明见 [`service/README.md`](service/README.md)。

**Web UI**（Alpine.js，内嵌——无需构建步骤，可离线使用）：提交一个服务器路径
*或*上传一个文件，然后查看实时 SSE 进度并浏览：

- **仪表盘** —— 发现数/严重/高危/二进制数/CVE 卡片、严重度与漏洞类别分布条形图、
  组件数/配置文件数/证书数统计（可点击跳转）、BusyBox 情况概览卡片区、网络服务/
  开放端口数卡片。
- **发现列表** —— 按严重度开关、漏洞类别、分诊状态、置信度阈值筛选，支持全文搜索；
  按严重度/置信度排序；展开查看证据、污点路径、Ghidra 伪代码；**内联分诊**
  （确认/误报/接受风险/重置）。
- **二进制列表** —— 每个二进制的架构、libc、缓解措施标签（NX/Canary/RELRO/PIE/
  FORTIFY，按颜色区分）、函数数量、CVE（服务端真分页）。
- **文件列表** —— 完整非 ELF 文件清单，按类型筛选（binary/script/**config**/
  symlink/other）；点击某行在其下方展开语法高亮的源码预览。
- **BusyBox** —— 已编译指令 vs. 参考列表得出的"被阉割"指令、任意层级 bin/sbin
  目录下的额外可执行文件、`/etc/init.d` 脚本源码。
- **服务识别** —— 纯静态分析识别出的网络服务（服务名/类别/版本号/端口/端口来源/
  二进制路径），支持按类别筛选+关键字搜索。
- **CVE 漏洞库** —— 独立于任何扫描，浏览工具实际能匹配到的 CVE 覆盖范围
  （cve-bin-tool 的广域覆盖 + 内置精选回退库）；全站 CVE 编号均可点击跳转 NVD。
- **敏感字符串字典** —— 独立管理页面，增删/重置用于匹配敏感字符串的关键词字典，
  不需要先跑一次扫描。
- **对比扫描** —— 对比两次扫描的发现差异（新增/消失/共有）。
- **导出** —— 下载 JSON / Markdown / SBOM。
- **用户中心** —— 修改密码、退出登录。

REST 接口（完整表格见 [`service/README.md`](service/README.md)）：

```bash
# 提交一个任务（返回 {"id": ...}）；去重缓存对未变化的目标直接返回缓存结果
curl -XPOST localhost:8080/api/jobs -H 'Content-Type: application/json' \
     -d '{"target":"/path/to/extracted_rootfs"}'

curl -N  localhost:8080/api/jobs/<id>/events             # 实时进度（SSE，无需轮询）
curl     localhost:8080/api/jobs/<id>/report             # 发现结果 JSON（叠加了分诊状态）
curl     "localhost:8080/api/jobs/<id>/report?format=md" # 或 format=sbom；加 &download=1 下载

# 对某个发现做分诊——按指纹持久化，跨重启和重新扫描依然有效（FR-VUL-8）
curl -XPOST localhost:8080/api/jobs/<id>/triage -H 'Content-Type: application/json' \
     -d '{"finding_id":"<finding_id>","state":"false_positive"}'

# 把文件上传到服务器端，再把返回的路径当作 target 提交
curl -F "file=@firmware.bin" localhost:8080/api/upload   # -> {"target": "...", "name": ...}
```

分诊状态：`new | confirmed | false_positive | accepted_risk`。重复提交一个未变化的
目标会直接返回缓存结果。

### 输出

| 格式 | 方式 | 内容 |
|---|---|---|
| JSON | `--json` / `GET …/report` | 完整结构化报告（集成契约） |
| Markdown | `--md` | 执行摘要 + 每条发现的详情 |
| CycloneDX SBOM | `--sbom` | 组件清单 + 检测到的 CVE（可直接导入 Dependency-Track） |

## 已实现内容

| 需求项 | 状态 | 位置 |
|---|---|---|
| FR-RE-1 反汇编（多架构） | ✅ | `re/disasm.py`（capstone） |
| FR-RE-3 CFG / 调用图 / 函数边界 | ✅（符号表 + 线性扫描兜底） | `re/disasm.py` |
| 导入调用解析 | ✅ x86/x86_64 + ARM/AArch64（PLT）+ MIPS（GOT/`jalr $t9`） | `re/disasm.py` |
| ARM/Thumb-2 + 交互跳板（veneer） | ✅（映射符号模式切换、跳板跟踪） | `re/disasm.py` |
| FR-INV-4 嵌入式敏感信息/凭据 | ✅（密钥、哈希、硬编码凭据/令牌、熵值兜底） | `inventory/secrets.py` |
| FR-INT-3 外部化签名规则（YARA 风格） | ✅（可更新的 JSON 规则库；可选 yara-python 桥接） | `rules/engine.py`, `data/secret_rules.json` |
| FR-INV-3 脚本分析（shell/CGI 命令注入） | ✅（分级污点分析） | `scripts/shell.py` |
| FR-INV-3 脚本分析（PHP/Python/Lua 注入） | ✅（命令/代码/文件包含/反序列化） | `scripts/langs.py` |
| 文件系统加固（setuid、全局可写、弱权限、init 脚本） | ✅ | `fs/hardening.py` |
| FR-RE-5 缓解措施（NX/canary/RELRO/PIE/fortify） | ✅ | `re/mitigations.py` |
| FR-RE-6 交叉引用（调用点、字符串） | ✅（调用/导入交叉引用） | `re/disasm.py` |
| FR-RE-7 可脚本化 API | ✅（库 + CLI） | `pipeline.py`, `cli.py` |
| FR-RE-2 反编译伪代码 | ✅（可选启用 Ghidra headless；丰富发现结果） | `re/decompile.py` |
| FR-VUL-1 已知 CVE 关联 | ✅ 内置精选离线库 + 必需的 `cve-bin-tool`（NVD/OSV/RedHat/GitLab/Curl，350+ 组件） | `vuln/cve.py`, `vuln/cve_bin_tool.py`, `data/vuln_db.json` |
| FR-VUL-2 危险函数检测 | ✅ | `vuln/dangerous_funcs.py` |
| FR-VUL-3 污点分析/可达性 | ✅（调用图启发式） | `vuln/taint.py` |
| FR-VUL-4 漏洞类别覆盖 | ◑ 溢出/命令注入/代码注入/文件包含/反序列化/格式化字符串/弱加密 | `vuln/catalog.py`, `scripts/langs.py` |
| FR-VUL-5 跨二进制分析 | ✅（全局调用图，CGI→库） | `vuln/crossbinary.py` |
| FR-VUL-7 优先级排序 + 证据 | ✅ | `vuln/findings.py`, `model.py` |
| FR-VUL-8 分诊状态持久化 | ✅ | `vuln/findings.py` |
| FR-VUL-6 模拟/动态验证 | ⬜ 计划中（可选，沙箱化） | — |
| FR-REP-1 JSON + Markdown 输出 | ✅ | `report/` |
| FR-REP-2 SBOM（CycloneDX 1.5） | ✅（SPDX 待办） | `report/sbom.py` |
| FR-INT-1 REST API + 队列 + Web UI（仪表盘、筛选、分诊、SSE） | ✅（Go 服务层，Alpine.js） | `service/` |
| FR-ING-4 批量提交 + 去重缓存 | ✅（worker + 路径-mtime 缓存） | `service/job.go` |
| 配置文件分类 + 内容安全加固审计 | ✅（类型分类；内容规则覆盖 telnet/匿名FTP/debug/SNMP默认团体名/TLS校验关闭/WPS/UPnP） | `inventory/firmware_meta.py`, `vuln/config_audit.py` |
| BusyBox 指令审计 | ✅（已编译 vs. 参考列表对比、额外 bin/sbin 可执行文件、init.d 脚本导出） | `inventory/busybox_audit.py` |
| 证书检测 | ✅（用 `cryptography` 逐张判断 RSA/非 RSA，支持证书链/bundle） | `inventory/secrets.py` |
| 网络服务识别 | ✅（纯静态分析；版本号取自内嵌 banner，端口按 UCI/inetd/init.d 参数/默认值推断） | `inventory/service_id.py` |
| 剥离二进制函数边界恢复 | ✅（直接调用发现 + prologue 识别，ARM/Thumb 自动判定） | `re/disasm.py` |

图例：✅ 已完成 · ◑ 部分完成 · ⬜ 未开始

## 准确性定位

不做反编译的静态分析本质上是启发式的（需求文档 §5）。每条发现都带有**置信度**分数；
精确的调用点检测（0.8）排在导入存在性检测（0.4）和调用图污点可达性检测（0.5）之前。
污点分析类发现明确只是候选路径，供分析人员验证，而非已证实的可利用漏洞。

## 测试

```bash
python3 -m pytest tests/ -q
```

装了交叉编译器 + Ghidra 时：25 passed, 2 skipped（跳过的是两个 opt-in 的实机测试——
见 `ENVIRONMENT.md`）。测试会构建真实的跨架构样本（x86_64、MIPS 大端/小端、ARM、
ARM Thumb-2、AArch64），覆盖：预置的命令注入验收用例（源→汇路径到 `system()`）、
各架构的导入调用解析和跨二进制 RCE、缓解措施检测、CVE 关联（内置精选离线库，
包括不误报已修补版本；以及 `cve-bin-tool` 的结果解析）、嵌入式敏感信息（外部化
签名规则 + 熵值兜底，含脱敏）、shell/CGI 命令注入、PHP/Python/Lua 注入（命令/代码/
文件包含/反序列化）、文件系统加固、CycloneDX SBOM、优先级排序、分诊状态持久化。

## 更新日志

完整技术细节（根因分析、修复前后对比数据、测试数量）见
[`PROGRESS.md`](PROGRESS.md) 的"变更记录"章节。以下是功能层面的摘要：

- **v3.9** —— AI 分析运行期的动态反馈:常驻状态条(呼吸脉冲点、分阶段文案、秒表、
  发丝扫光)、流式文本末尾的打字光标、自动跟随尾部但让位于手动滚动、以及
  `prefers-reduced-motion` 支持。修复了进度指示器在首个 token 到达时就消失的问题——
  此前长时间停顿与"分析已完成"在视觉上完全无法区分。
- **v3.8** —— AI 分析扫描结果 + 工具调用 agent。每服务商独立配置(自定义 Host URL、
  Key、模型、OpenAI 兼容或 Anthropic 协议、max_tokens),API Key 加密落盘并支持轮换。
  NDJSON 流式输出,分析中周期性持久化部分内容。模型可**按需主动取数**——finding 详情
  (含证据链和伪代码)、init.d 启动脚本、BusyBox 审计、网络服务——而不是只能接受固定
  样本;网关不支持 tool calling 时自动降级。finding 选择会把近似重复的簇折叠,并按漏洞
  类别轮询分配,避免一次 CVE 洪水挤掉其它所有类别。
- **v3.7** —— 内核版本 CVE 关联,用自研的内核探测结果(cve-bin-tool 自带 checker 在
  Ubuntu 系编译器字符串上会失配)。修复 8MB 扫描上限——真实 35MB 内核镜像的 banner 在
  17.1MB 处,此前被静默截断。Dirty Pipe 按三个分支各自的 backport 修复点精确表达,
  已修复的分支不再误报。
- **v3.6** —— FR-VUL-4 扩类:路径遍历(复用现有污点引擎,新增 fopen/open/unlink/remove
  作为 sink)与认证逻辑弱点(鉴权类函数内使用非常量时间比较凭据)。整数溢出喂分配函数
  刻意搁置——缺少参数级分析时噪音过大。
- **v3.5** —— 新增纯静态网络服务识别（WEB/SSH/FTP/Telnet/gSOAP/DNS/SNMP/UPnP/
  WiFi 管理类守护进程）；版本号一律从二进制内嵌的版本 banner 字符串提取，绝不
  猜测；端口按 UCI 配置 → inetd.conf → init.d 启动参数 → 已知默认端口的优先级
  推断。新增"服务识别"标签页 + 仪表盘服务数/端口数卡片。修复了同名配置/init.d
  脚本文件与真实 ELF 二进制被重复计为多个服务的问题。
- **v3.4** —— 新增真实证书检测（用 `cryptography` 库逐张判断 RSA/非 RSA，支持
  证书链/bundle，而非从 PEM 头猜测）。仪表盘新增组件数/配置文件数/证书数统计
  以及 BusyBox 情况概览卡片区。
- **v3.3** —— 修复 v3.2 引入的回归：配置文件曾静默丢失点击预览能力。Binaries/
  Scripts 标签页从 `?all=1` 一次性全量加载改为真正的服务端分页。
- **v3.2** —— 新增 `config` 文件类型分类（扩展名/文件名/UCI 路径/内容嗅探），
  Files 标签页新增服务端 Kind 筛选。新增 `config_audit.py` 内容安全加固规则
  （检测 telnet、匿名 FTP、debug 模式、SNMP 默认团体名、TLS 校验关闭、WPS、
  UPnP 等遗留开启项）。全站 CVE 编号改为可点击跳转 NVD。为文件/BusyBox 预览
  加入零依赖语法高亮。修复对比扫描在报告拉取失败时静默呈现"0 新增/全部消失"
  这类误导性结果的问题。
- **v3.0** —— 剥离（stripped）ELF 的函数边界恢复（直接调用发现 + prologue
  识别，ARM/Thumb 自动判定）。CVE 同步可靠性修复（上游 `cve-bin-tool` bug
  补丁、NVD GitHub 镜像引导脚本）。findings/binaries/scripts/components 从
  单个 JSON 大 blob 迁移到 SQLite 并改为服务端分页，修复了大型扫描下的 UI
  卡死问题及一个隐藏的导出截断 bug。新增 BusyBox 指令审计标签页（已编译 vs.
  参考列表对比）。修复了因绝对路径指纹匹配导致的严重对比扫描准确性 bug。
  修复了分析器升级后去重缓存仍静默复用旧版本报告的问题。
- **v2.0** —— 新增中文文档（`README.zh-CN.md`）、技术栈章节，以及参考与致谢
  章节（感谢 EMBA 与 cve-bin-tool）。
- **v1.0** —— 首个版本：多架构反汇编与导入调用解析（x86/x86_64、ARM、
  ARM Thumb-2、AArch64、MIPS 大端/小端），漏洞发现（危险函数、污点/可达性
  分析、跨二进制污点分析、CVE 关联、CycloneDX SBOM、优先级排序 + 分诊状态
  持久化），嵌入式敏感信息与脚本注入检测，文件系统加固检查，可选 Ghidra
  反编译增强，以及 Go 服务层 + Alpine.js Web UI。

## 后续迭代计划

- 在现有的 `detect_taint_paths` / `detect_cross_binary_taint` 接口后面，用 angr
  替换启发式污点分析。
- FR-VUL-6：可选的沙箱化模拟执行，用于确认可达性。
- FR-REP-2：除 CycloneDX 外增加 SPDX 输出格式。
- 服务层加固：持久化任务存储、上传/解包前端（FR-ING/FR-EXT）。队列 + REST API +
  Web UI 已经实现（`service/`）。

x86/x86_64、ARM、ARM Thumb-2、AArch64 和 MIPS 大端/小端的调用解析均已就绪。
