# 开发进度 — IFDA(IoT Firmware Deep Analysis)

> 配套需求文档:[`firmware-analysis-requirements.md`](firmware-analysis-requirements.md)
> 最近更新:2026-06-10

## 0. 变更记录

- **2026-06-10 — 项目更名 `fwana` → `IFDA`(IoT Firmware Deep Analysis)。**
  Python 包 `fwana/`→`ifda/`(全部 `import`、`python -m ifda.cli`、pyproject `name`/入口);
  Go 模块 `github.com/ifda/service`、二进制 `ifda-service`;进度标记 `@@FWANA@@`→`@@IFDA@@`
  (Python 发、Go 解析已对齐);环境变量 `FWANA_GHIDRA_TEST`→`IFDA_GHIDRA_TEST`;
  Ghidra 脚本 `fwana_decompile.py`→`ifda_decompile.py`;Web 品牌与 `localStorage` 键、全部文档同步。
  仓库目录仍为 `/root/IDA`(文件系统位置未动)。验证:`import ifda` OK、pytest 23 通过/1 跳过、
  `go build`+`go vet` 干净、起服务端到端正常。

## 1. 总体定位

按既定方案实施:**Python 分析核心 + Go 服务层(已落地)、封装现有工具、首版聚焦逆向(FR-RE)与漏洞挖掘(FR-VUL)**。假定接收/提取(FR-ING/FR-EXT)已在磁盘产出制品,本核心分析其中的二进制。

引擎封装:**capstone**(跨架构反汇编)、**pyelftools** + **binutils**(ELF 解析、缓解措施)。服务层用 **Go 1.22**(队列 + worker + REST API + 内嵌 Web UI)。

- 代码量:约 3350 行 Python(32 个模块)+ ~710 行 Go + ~460 行内嵌 Web UI(`service/`,Alpine.js)
- 测试:**23 通过 / 1 跳过**(`tests/test_core.py`;跳过的是按可用性 gate 的 live Ghidra 测试);Go 服务端到端实测(提交→进度→报告→去重缓存)
- 已安装 Ghidra 11.1.2 + JDK 17,反编译已用真实 ELF 验证
- 架构:浏览器 → Go 服务(队列/worker/REST)→ `exec python3 -m ifda.cli analyze --progress` → 核心吐 `@@IFDA@@<json>` 进度行,服务实时更新任务进度
- 已安装工具链:gcc(x86)、mips/mipsel、arm/arm-thumb、aarch64 交叉编译器,用于造样本验证

## 2. 需求覆盖矩阵

图例:✅ 完成 · ◑ 部分 · ⬜ 未开始

| 需求 | 状态 | 实现位置 |
|------|------|----------|
| FR-RE-1 反汇编(跨架构) | ✅ | `re/disasm.py`(capstone) |
| FR-RE-3 CFG / 调用图 / 函数边界 | ✅(符号 + 线性兜底) | `re/disasm.py` |
| 导入调用解析 | ✅ x86/x86_64 + ARM/AArch64(PLT)+ MIPS(GOT/`jalr $t9`) | `re/disasm.py` |
| ARM/Thumb-2 + interworking veneer | ✅(mapping symbol 切模式、veneer 透明跟随) | `re/disasm.py` |
| FR-INV-4 内嵌密钥/凭据检测 | ✅(私钥、口令哈希、硬编码凭据/令牌、**熵值兜底**) | `inventory/secrets.py` |
| FR-INT-3 可外置签名规则(YARA 风格) | ✅(JSON 规则库,可独立更新;yara-python 可选桥) | `rules/engine.py`, `data/secret_rules.json` |
| FR-INV-3 脚本分析(shell/CGI 命令注入) | ✅(按 shell 语义分级) | `scripts/shell.py` |
| FR-INV-3 脚本分析(PHP/Python/Lua 注入) | ✅(命令/代码/文件包含/反序列化) | `scripts/langs.py` |
| 文件系统加固(setuid、世界可写、弱权限、init) | ✅ | `fs/hardening.py` |
| FR-RE-5 缓解措施(NX/canary/RELRO/PIE/fortify) | ✅ | `re/mitigations.py` |
| FR-RE-6 交叉引用(调用点、字符串) | ✅(调用/导入 xref) | `re/disasm.py` |
| FR-RE-7 可脚本化接口 | ✅(库 + CLI) | `pipeline.py`, `cli.py` |
| FR-INT-1 REST API + 队列 + Web UI(仪表盘/过滤/分诊/SSE) | ✅(Go 服务层 + Alpine.js) | `service/` |
| FR-ING-4 批量提交 + 去重缓存 | ✅(worker 池 + path/mtime 缓存) | `service/job.go` |
| FR-RE-2 反编译伪代码 | ✅(可选,封装 Ghidra headless,富化发现) | `re/decompile.py`, `re/ghidra_scripts/` |
| FR-VUL-1 已知 CVE 关联 | ✅(离线 DB) | `vuln/cve.py`, `data/vuln_db.json` |
| FR-VUL-2 危险函数检测 | ✅ | `vuln/dangerous_funcs.py` |
| FR-VUL-3 污点 / 可达性 | ✅(调用图启发式) | `vuln/taint.py` |
| FR-VUL-4 漏洞类别覆盖 | ◑ 溢出/命令注入/代码注入/文件包含/反序列化/格式化串/弱加密 | `vuln/catalog.py`, `scripts/langs.py` |
| FR-VUL-5 跨二进制分析 | ✅(全局调用图,CGI→库) | `vuln/crossbinary.py` |
| FR-VUL-7 优先级 + 证据 | ✅ | `vuln/findings.py`, `model.py` |
| FR-VUL-8 分诊状态持久化 | ✅ | `vuln/findings.py` |
| FR-VUL-6 仿真 / 动态验证 | ⬜ 计划(可选、沙箱) | — |
| FR-REP-1 JSON + Markdown 输出 | ✅ | `report/` |
| FR-REP-2 SBOM(CycloneDX 1.5) | ✅(SPDX 待补) | `report/sbom.py` |
| FR-REP-4 执行摘要 + 逐条详情 | ✅ | `report/markdown_report.py` |
| NFR-ARCH-1 架构覆盖(ARM 32/64、MIPS LE/BE、x86/64) | ✅ 全部精确解析 | `re/disasm.py` |
| NFR-USE-1 优雅降级 | ✅(各阶段异常隔离) | `pipeline.py` |
| NFR-USE-2 DB/签名可独立更新 | ✅ | `data/vuln_db.json` |

## 3. 已验证能力

所有验证均以交叉编译的植入漏洞样本实测,而非假设。

### 跨架构检测质量一致(六种 ABI,含 ARM Thumb-2)

| 架构 | 精确调用点 | 污点路径 | 警告 |
|------|-----------|---------|------|
| x86_64 | 4 | 2 | 无 |
| mips-be / mipsel | 4 | 2 | 无 |
| arm | 4 | 2 | 无 |
| arm-thumb | 4 | 2 | 无 |
| aarch64 | 4 | 2 | 无 |

各架构调用解析的技术要点:
- **x86/x86_64**:`.plt`(含 `.plt.sec`/CET),保留 PLT0,按 `.rela.plt` 顺序映射
- **ARM**:条目大小不定(Thumb interworking veneer),改为**反汇编每个 stub 的 `add ip,pc; ldr pc,[ip]` 算出 GOT 地址**,再用 `.rel.plt` 的 `r_offset`→符号(与条目大小/顺序无关)
- **ARM Thumb-2**:用 mapping symbol(`$a`/`$t`/`$d`)在函数内切换 ARM/Thumb 反汇编、跳过字面量池;函数符号 LSB 定模式;轻量寄存器跟踪把 `bx`/`b.w` interworking veneer 解析为调用边(污点能穿过 veneer 到达真实 Thumb 函数体)
- **AArch64**:PLT0=32 + 每条 16
- **MIPS**:无 PLT,外部调用走 `lw $t9, off($gp); jalr $t9`;用 MIPS 专属动态标签建 GOT→符号映射 + 寄存器跟踪;含 PIC 共享库 `addu gp,gp,t9` 的 gp 计算

### 内嵌密钥/凭据(FR-INV-4)

合成 rootfs 实测,扫描整个解包树(非仅 ELF),证据中密钥值脱敏:
- 私钥(PEM)→ CRITICAL;GitHub/AWS 令牌 → HIGH
- 口令哈希按强度分级:`$1$` MD5 / 13 字符 DES → HIGH,`$6$` SHA-512 → MEDIUM
- 硬编码凭据(`db_password=...`)→ HIGH;占位符 `changeme`、变量引用 `${FTP_PW}` 正确跳过
- **外置签名规则**(`data/secret_rules.json`,可独立更新 NFR-USE-2):AWS/GitHub/OpenAI/Google/JWT/Slack/Stripe/Twilio 等令牌按形状匹配,值脱敏;装上 yara-python + 放 `data/yara/*.yar` 即自动启用 YARA 阶段(FR-INT-3 / EMBA S110)
- **熵值兜底**(Shannon):抓无前缀的随机密钥/口令(≥32 字符 hex、混合字符 base64);近 `token=`/`secret=` 等键名 → MEDIUM,孤立超高熵 → LOW,普通词/路径不误报;每文件封顶 25 条

### Shell/CGI 脚本命令注入(FR-INV-3)

合成 CGI/init 脚本实测,**按真实 shell 语义分级**(再解析上下文才是高危,纯参数位不会重解析 `;`/`|`):
- `eval`、`sh -c "...$tainted"`、`下载 | sh`、命令名为污点变量 → HIGH
- 命令替换 `$(... $QUERY_STRING ...)` 含污点 → MEDIUM
- 污点变量做命令参数(未加引号)→ LOW(可能进 `system()` 包装)
- 已加引号的 `nvram set last="$host"` **不误报**;`echo safe`、shebang 不产生噪声
- 轻量两遍污点:从 `QUERY_STRING`/`nvram get`/`read`/位置参数传播变量污点

**PHP / Python / Lua 注入**(`scripts/langs.py`,EMBA S22-S28):同一套两遍污点 + 分级,按语言识别(扩展名/shebang/`<?php`):
- PHP:`system/exec/shell_exec/passthru/popen` 命令注入、反引号、`eval/assert` 代码注入、`include/require` 动态路径文件包含(LFI/RFI),源 `$_GET/$_POST/$_REQUEST/$_SERVER/getenv`
- Python:`os.system/os.popen`、`subprocess(... shell=True)` 命令注入、`eval/exec` 代码注入、`pickle.loads`/`yaml.load` 反序列化,源 `request.args/form`、`os.environ`、`sys.argv`、`input()`
- Lua:`os.execute/io.popen` 命令注入、`loadstring/load/dofile` 代码加载,源 `http.formvalue`、`os.getenv`、`ngx.var`
- 污点参数 → HIGH(0.7),仅动态拼接(未证污点)→ MEDIUM(0.4),纯静态字面量**跳过**;实测 `system("uptime")`、`subprocess.call(["ls","-l"])`、`os.execute("reboot")` 均不误报

### 文件系统加固/配置(EMBA S40-S55)

基于 mode 位(解包工具会保留,即使 owner 丢失)实测:
- setuid 二进制:shell 可逃逸者(busybox/sh/perl…)→ HIGH,普通 → MEDIUM,叠加世界可写 → CRITICAL
- 世界可写可执行文件 → HIGH;普通世界可写文件 → LOW;无 sticky 的世界可写目录 → MEDIUM
- 世界可读的 `shadow`/私钥文件 → HIGH
- init/服务脚本(`/etc/init.d`、`inittab`、`xinetd.d`…)→ INFO 攻击面清点(FR-INV-3)

### 验收标准(需求 §6)实测

- 植入的命令注入,源到汇可追溯路径:`getenv() → handle_request → system()` ✅
- 危险函数带反汇编证据(如 `bl #0x... <strcpy>`、`jalr $t9 <system>`)✅
- 加固二进制 `/bin/ls`:NX/canary/full RELRO/PIE/fortify 全部正确识别 ✅
- CVE 关联:OpenSSL 1.0.1f → Heartbleed(critical);1.0.2h 已修复版本不误报 ✅
- 分诊持久化:标记 false_positive 后重扫自动剔除 ✅

### 跨二进制 RCE(FR-VUL-5)

四种架构(x86_64/MIPS/ARM/AArch64)均命中经典路由器模式,跨 `-fPIC` 共享库边界:

```
getenv() → main @ cgi → run_ping @ libcmd.so (cross) → system()
```

### 反编译伪代码(FR-RE-2,Ghidra)

可选、重量级富化(默认关闭,`--decompile` / `analyze(decompile=True)` 开启):
- `re/ghidra_scripts/ifda_decompile.py`:headless 后置脚本,用 `DecompInterface` 反编译**仅发现所在的函数**(按名过滤,控制开销),输出 JSON(name/address/signature/pseudocode)
- `re/decompile.py`:探测 Ghidra(`$GHIDRA_HOME`/`/opt/ghidra`/PATH)、跑 headless、解析、把伪代码挂到对应 `Finding.pseudocode`;**缺 Ghidra 时优雅降级为 no-op + warning**(NFR-USE-1)
- Markdown 报告以 `<details>` 折叠块展示伪代码
- **真实验证**:对植入样本反编译 `handle()`,伪代码清楚还原漏洞 `strcpy(local_58,param_1); system(local_58);`——正是分析人员定位所需的制品
- 解析器/富化/降级三条路径有单测(用真实 Ghidra 输出夹具,不绑定 1GB 依赖);live 测试按 `IFDA_GHIDRA_TEST=1` opt-in
- 注:本环境资源受限,Ghidra 单次运行较慢(冷启动/分析数分钟,曾被 OOM kill),故设为可选 + 充裕超时 + 默认跳过 live 测试

### 服务层(Go)端到端实测(FR-INT-1 / FR-ING-4)

`go build` 通过,起服务后实测全链路:
- `POST /api/jobs` 提交目标 → 队列 → worker `exec` 核心 → 进度从 0% 走到 100%(stage:disassemble→secrets→scripts→filesystem→done)
- `GET /api/jobs/{id}` 实时看到 `status/progress/stage/detail`;`GET /api/jobs/{id}/report` 取完整发现 JSON
- 合成 rootfs 经服务跑出 16 条发现(private_key/命令注入/凭据/setuid/init/熵值等),与直接 CLI 结果一致
- **去重缓存**:同一未变目标重复提交 → `cache_hit=true` 秒回
- 错误处理:不存在的 target → 400;非法 triage 状态 → 400

### Web UI 增强(Alpine.js,内嵌无构建、可离线)

把原先简陋单页升级为分析师工作台,后端配套新增端点,全部端到端实测:
- **SSE 进度**(`GET /api/jobs/{id}/events`)替代客户端轮询,实测推送 `status/progress/stage`
- **页面分诊**(`POST /api/jobs/{id}/triage`):Go 端 `TriageStore` 按 finding 指纹落盘 `triage.json`,服务报告时 overlay;实测**重启服务后仍生效、且对重新发现同一问题的新任务自动套用**(FR-VUL-8 跨重扫语义)
- **导出**(`/report?format=json|md|sbom&download=1`):worker 完成时一并产出 MD/SBOM,实测三种格式可下载
- **上传**(`POST /api/upload`):存盘返回 target 路径,再下任务
- 前端:严重度仪表盘、任务列表(SSE 进度条)、发现表(严重度/类/分诊/置信度过滤 + 全文搜索 + 排序)、逐条展开看证据/污点路径/反编译伪代码、行内分诊按钮、二进制详情(arch/缓解措施彩色 chip/CVE/SBOM)
- Alpine.js 离线内嵌(`web/vendor/alpine.min.js`),无 Node 构建链,仍是单 Go 二进制;`go vet` 干净

## 4. 准确性设计

静态分析为启发式(需求 §5)。各发现携带置信度:精确调用点(0.8)> 调用图污点可达(0.5)> 跨二进制(0.45)> 仅导入存在(0.4);凭据类:私钥(0.95)、令牌(0.85)、口令哈希(0.5–0.7)、硬编码赋值(0.6)。污点结果显式标注为"候选路径,需分析人员验证",非已证明的可利用漏洞。凭据证据一律脱敏,不输出原文。

## 5. 对标 EMBA(借鉴方向)

参考 [EMBA](https://github.com/e-m-b-a/emba)(模块化固件分析,P 提取 / S 静态 / L 仿真 / F 报告)梳理可借鉴功能及我们的状态:

| EMBA 能力 | 对应模块 | 对应需求 | 我们的状态 |
|-----------|----------|----------|-----------|
| 二进制加固/checksec | S12/S13 | FR-RE-5 | ✅ 已做 |
| 危险/弱函数 | S13/S14 | FR-VUL-2 | ✅ 已做 |
| 已知 CVE/版本、SBOM | S09/F15/F17 | FR-VUL-1/FR-REP-2 | ✅ 已做(CycloneDX,天然对接 Dependency-Track) |
| 硬编码凭据/私钥/口令哈希 | S85/S106-S108 | FR-INV-4 | ✅ **本轮借鉴落地** |
| 命令注入溯源(CGI→sink) | S100 | FR-VUL-3/5 | ✅ 已做(跨二进制污点,较 EMBA 的 grep 更深) |
| 脚本静态分析(shell/PHP/Python/Lua 注入) | S20-S28 | FR-INV-3 | ✅ shell + PHP/Python/Lua(命令/代码/文件包含/反序列化) |
| 文件系统配置/加固(setuid、世界可写、init) | S40-S55 | 攻击面/FR-INV | ✅ **本轮借鉴落地** |
| 可外置签名规则(YARA 风格) | S110 | FR-INT-3 | ✅ **本轮落地**(原生 JSON 规则库 + yara-python 可选桥;熵值兜底补无前缀密钥) |
| 内核识别/加固 | S24-S26 | FR-INV/FR-VUL | ⬜ 未做 |
| 系统仿真 + 网络服务探测 | L10-L35 | FR-VUL-6 | ⬜ 未做(重) |

## 6. 待办(按优先级)

1. **FR-VUL-6 沙箱仿真(借鉴 EMBA L 系列)** — 可选,验证可达性、降低误报。
2. **FR-VUL-4 扩类** — 整数溢出喂分配/拷贝、路径遍历、认证逻辑弱点(二进制侧)。
3. **签名规则面扩展** — 把命令注入/弱函数等也纳入外置 YARA/规则文件,并补一组 `data/yara/*.yar` 实样。
4. **服务层加固** — 持久化任务存储(Postgres/Redis)、前置上传/提取(FR-ING/FR-EXT)、认证授权;当前队列/REST/Web UI 已建(`service/`)。
5. **反编译增强** — 在伪代码上叠加数据流(如把 `--decompile` 结果喂二次污点),或加 radare2 作为轻量备选后端。

## 7. 运行方式

两种用法:**CLI**(单次、可脚本化)与**服务**(队列 + REST API + Web UI 实时进度)。

```bash
# --- A. CLI:一次性分析 ---
# 分析单个二进制或解包后的目录树(JSON / Markdown / CycloneDX SBOM)
python3 -m ifda.cli analyze ./rootfs --json report.json --md report.md --sbom sbom.json

# 分诊一个发现(跨重扫持久化)
python3 -m ifda.cli triage triage.json <finding_id> false_positive
python3 -m ifda.cli analyze ./rootfs --triage triage.json   # 已静默项重扫剔除

# 测试
python3 -m pytest tests/ -q

# --- B. 服务:队列 + REST API + Web UI ---
cd service && go build -o ifda-service .         # 需 Go 1.22+
./ifda-service -addr :8080 -core ..              # -core 仓库目录(省略自动探测);-data 分诊/上传目录
# 浏览器打开 http://localhost:8080:仪表盘 / 发现(过滤·搜索·分诊)/ 二进制详情 / 导出

# REST(详见 service/README.md)
curl -XPOST localhost:8080/api/jobs -H 'Content-Type: application/json' \
     -d '{"target":"./rootfs"}'                   # 入队 -> {"id": ...}
curl -N  localhost:8080/api/jobs/<id>/events      # SSE 实时进度(免轮询)
curl     localhost:8080/api/jobs/<id>/report      # 完整发现 JSON(已叠加分诊)
curl     "localhost:8080/api/jobs/<id>/report?format=md"   # 导出 MD(或 format=sbom)
curl -XPOST localhost:8080/api/jobs/<id>/triage -H 'Content-Type: application/json' \
     -d '{"finding_id":"<id>","state":"false_positive"}'   # 分诊(按指纹持久化)
curl -F "file=@firmware.bin" localhost:8080/api/upload     # 上传 -> 返回 target 再下任务
```
