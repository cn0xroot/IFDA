# 开发进度 — IFDA(IoT Firmware Deep Analysis)

> 配套需求文档:[`firmware-analysis-requirements.md`](firmware-analysis-requirements.md)
> 最近更新:2026-07-11

## 0. 变更记录

- **2026-07-11 — v3.7(`ifda.__version__` 2.5.0 → 2.6.0):内核版本 CVE 关联 + 一个真实的扫描上限 bug。**

  用户问"内核漏洞关联是不是已经做了",查代码过程中发现两个独立的坑,而不是单纯的"没做":

  - **bug 1(`inventory/firmware_meta.py`)**:`detect_kernel_version()` 里注释写"内核版本 banner 通常出现在
    文件早期",所以只读文件头 8MB(`_SCAN_CAP`)。拿真实的 Starlink Dishy aarch64 内核镜像
    (`qemu-emulator/kernel/Image`,35MB)实测,banner 实际在第 17.1MB 处——这个假设在现代内核上是错的,
    8MB 上限直接把 banner 截没了,`report.kernel_version` 静默返回空。已把 `_SCAN_CAP` 提到 64MB(与同文件
    `_HASH_SIZE_CAP` 对齐),改完实测该文件正确识别出 `5.15.55`。
  - **bug 2(第三方,`cve-bin-tool`)**:cve-bin-tool 自带的 `linux_kernel` checker 存在但**在同一个真实文件上
    也没识别出版本**——它的版本正则要求版本号后紧跟的编译器字符串只能是 `[a-zA-Z0-9 ,+@\-\.\(\)]`,而这台设备
    的 banner 里编译器版本号是 `13.3.0-6ubuntu2~24.04`,`~` 直接把匹配断掉。这是第三方 checker 自身的局限
    (常见于 Ubuntu 系工具链编译的内核),没有去改 cve-bin-tool 本身。
  - **新增关联路径**:既然不能依赖 cve-bin-tool 的内核检测,新增 `vuln/cve.py` 的
    `correlate_kernel_cve(kernel_version)`,复用 `report.kernel_version`(我们自己更可靠的探测结果)去匹配
    `data/vuln_db.json` 新增的 `linux_kernel` 条目——目前收录 Dirty COW(CVE-2016-5195,< 4.8.3)和
    Dirty Pipe(CVE-2022-0847)。Dirty Pipe 的可复现范围本身跨三个发布分支且各自有不同的 backport 修复点
    (5.10.102 / 5.15.25 / 5.16.11),用单一 `version_lt` 会把已经 backport 修复的分支(比如这台设备实际跑
    的 5.15.55,早过 5.15.25 修复点)也误判为易受攻击——为此把 `_vulnerable()` 的 schema 扩成
    `version_ge`+`version_lt` 可组合的区间,Dirty Pipe 拆成三条按分支精确表达的记录。用真实的 5.15.55 验证:
    改之前(单区间写法)会误报,改之后正确不误报;用构造的旧内核(4.4.60)验证 Dirty COW 正确命中
    (CRITICAL,confidence 0.6)。内核也接入了 `report.components`(SBOM/组件清单),`cve_ids` 复用现有的
    按 `name@version` 匹配逻辑,零改动自动生效。
  - 单测新增 5 条(scan-cap 回归、Dirty COW/Dirty Pipe 命中、patched 不误报、5.15.55/5.10.150 backport 不误报),
    全量 `pytest tests/ -q`:62 passed, 2 skipped,零回归。
  - EMBA 对照表"内核识别/加固"行由 ⬜ 改为 ◑(CVE 关联已做,CONFIG_* 编译选项/grsecurity 等加固检查仍未做)。

- **2026-07-11 — v3.6(`ifda.__version__` 2.4.0 → 2.5.0):FR-VUL-4 扩类——路径遍历 + 认证逻辑弱点(二进制侧)。**

  - **路径遍历**:复用已有的调用图污点可达性引擎(`vuln/taint.py`),把 `fopen`/`open`/`unlink`/
    `remove` 加进 `catalog.py` 的 `SINKS`,新增 `path_traversal` 漏洞类别(HIGH)。同一套"污点源
    (`getenv`/`recv`/CGI 取值函数等)→ 调用图可达 sink"机制,不新增检测逻辑,只扩数据表。典型
    场景:CGI 配置导出/文件下载接口直接用请求参数拼文件名传给 `fopen()`。
  - **认证逻辑弱点**:新增 `vuln/auth_weak.py`(`detect_auth_weaknesses`,rule
    `auth-logic-weak`)。启发式:函数名含 auth/login/passwd/password/credential/verify/
    checkpw 等关键词、且函数体内调用了非常量时间比较函数(`strcmp`/`strncmp`/`memcmp`/
    `strcasecmp`/`strncasecmp`)——路由器/摄像头固件里常见的"明文 `strcmp` 比对密码/令牌"反模式,
    存在按响应时间逐字节泄露密码的理论风险(即使不考虑时序攻击,这类比对也常与硬编码后门凭据同现)。
    新漏洞类别 `auth_logic_weakness`(MEDIUM,置信度 0.45,与污点类发现同档)。
  - **有意搁置**:整数溢出喂 `malloc`/`realloc` 未做——若照搬"污点可达 sink"套路,几乎每个读网络
    输入又要分配内存的二进制都会命中(malloc 太常见),噪音远大于其余 sink;需要真正识别"喂给
    size 参数的乘法/加法运算"这类参数级分析才值得做,留在待办里。
  - 单测:`tests/test_core.py` 新增 `test_path_traversal_taint`(真实编译 getenv→fopen 样本,
    验证污点路径含 `path_traversal` 类别)、`test_auth_logic_weakness`(真实编译
    `check_password()` 内 `strcmp` 样本)、`test_auth_logic_weakness_ignores_non_auth_named_function`
    (函数名不含关键词时不误报,构造 `CallSite` 单测)。全量 `pytest tests/ -q`:59 passed, 2
    skipped(较 v3.5 时 +3 条新测试,原有用例零回归)。
  - 文档修复:README「Next iterations」一节此前仍写"authn/z 未做",但登录认证
    (`service/auth.go` pbkdf2 + 按账号锁定 + `service/captcha.go` 验证码)和报告持久化
    (`service/reportdb.go` SQLite)其实早就落地了——已更正,并把"服务层加固"待办项收窄到真正
    还没做的部分(任务队列存储与报告存储统一到 SQLite)。EMBA 对照表也把"网络服务识别"拆成了
    v3.5 已做的静态特征匹配和仍未做的动态仿真探测两行,避免混淆。

- **2026-07-08 — v3.5:新增网络服务识别功能(WEB/SSH/FTP/Telnet/gSOAP/DNS/SNMP/UPnP/WiFi 等),独立标签页 + 仪表盘服务数/端口展示。**
  自 v3.4 以来的改动。

  - 新增 `ifda/inventory/service_id.py`:纯静态分析,不做任何实时端口扫描——"端口"指配置/脚本中
    体现出该服务被配置监听的端口,而非实际观测到的流量。签名库覆盖 WEB(nginx/GoAhead/Boa/
    lighttpd/thttpd/mini_httpd/Apache/Mongoose/uhttpd/BusyBox httpd)、SSH(OpenSSH/Dropbear)、
    FTP(vsftpd/ProFTPD/Pure-FTPd/BusyBox ftpd/tftpd)、Telnet(BusyBox telnetd/utelnetd)、
    gSOAP、DNS(dnsmasq)、SNMP(Net-SNMP)、UPnP(MiniUPnPd)、WiFi 管理(hostapd/wpa_supplicant)。
    版本号一律从二进制内嵌的版本 banner 字符串中提取(如 `nginx/1.18.0`、
    `SSH-2.0-dropbear_2019.78`),绝不猜测;命中但读不到版本号的严格签名不计入结果,避免误报。
  - 端口推断优先级(由高到低):UCI 配置文件 `option Port` → inetd.conf 风格条目(含 init.d
    脚本里 `echo -e "...\t..."` 硬编码生成的 inetd.conf,兼容脚本源码里字面 `\t` 转义序列而非
    真实 tab 字节的情况)→ 服务自身 init.d 脚本里的 `-p`/`--port` 启动参数 → 已知默认端口。
  - BusyBox 多用途二进制(`httpd`/`ftpd`/`tftpd`/`telnetd` 等符号链接指向 busybox)按对应
    applet 识别。gSOAP 因无固定二进制名(代码生成工具库,链接进任意厂商命名的守护进程),改为
    单独一趟"按二进制内容匹配版本 banner"的兜底扫描,而非按名称匹配。
  - 修复:同名的配置文件/init.d 脚本与真实二进制(如 `/etc/config/dropbear`、
    `/etc/init.d/dropbear` 与 `/usr/sbin/dropbear` 同名)此前会被重复计为多个服务——现在要求
    候选路径必须是真实 ELF(`is_elf()`)才算一次命中,同名的配置/脚本文件仅用于端口推断。
  - Go 侧沿用 `busybox_audit` 的落库方式:`report_meta` 新增 `services` 单列 JSON blob(非分页
    表),`GetServices`/`ExportFull`/`GetSummary` 均已接入;新增 `GET /api/jobs/{id}/services`
    接口。`Summary` 新增 `service_count`/`open_port_count` 两个仪表盘聚合字段。
  - 前端新增独立"服务识别"标签页(服务名/类别/版本/端口/端口来源/二进制路径表格,支持按类别
    筛选+关键字搜索),仪表盘新增"网络服务"卡片区(已识别服务数、开放端口数,可点击跳转)及
    端口号 chip 列表。
  - `ifda.__version__` 同步升到 2.4.0。

  验证:Python 56 通过/2 跳过(`tests/test_core.py` 新增 9 个:banner 版本提取、同名文件去重、
  UCI/inetd/init.d flag 端口推断优先级、BusyBox 符号链接识别、无二进制时不误报、gSOAP 按内容
  匹配、pipeline 集成);Go 全量通过(`reportdb_test.go` 新增 services 落库/查询/Summary 聚合/
  ExportFull 往返测试)。真实固件样本(bank_B 分区)端到端验证:修复前误报 11 个服务(重复计
  dropbear/dnsmasq/miniupnpd),修复后正确识别 7 个唯一服务;inetd 端口推断此前完全不生效(脚本
  里的 `\t` 是字面反斜杠+t,不是真实 tab 字节;正则又误加了行首锚点),修复后 BusyBox ftpd 端口
  正确标注来源为 inetd 而非 default。telnetd 因该分区确实没有对应二进制/符号链接,正确地不予
  识别(脚本提到不等于二进制存在),写成专门的回归测试而非当作缺陷处理。

- **2026-07-08 — v3.4:仪表盘新增组件/配置文件/证书统计、BusyBox 情况概览、真实证书检测。**
  自 v3.3 以来的改动。

  - 新增证书检测能力(`inventory/secrets.py` 的 `count_certificates()`):此前代码里有个匹配
    `-----BEGIN CERTIFICATE-----` 的正则从未真正接上,现在补全并用 `cryptography` 库真正解析
    每一张证书判断公钥算法,而不是从 PEM 头猜——证书本身不像私钥那样把算法写在头部里。一个文件
    内多张证书(CA bundle/证书链)按张数分别计数,不会只算"这个文件有没有证书"而漏计。属于纯
    库存类统计(不产生 Finding,不会像私钥检测那样刷屏 Findings 列表)。`cryptography` 正式列入
    `pyproject.toml` 依赖(此前只是运行环境里恰好装了,并非项目显式声明)。
  - 仪表盘内核信息下方新增一行:组件数(点击展开可看全部组件名+版本)、配置文件数(点击直接跳转
    Files 页并按 config 类型筛选)、证书数(含其中 RSA 证书数量)。组件数/配置文件数复用已有数据
    (`componentsPage`/`filesStringsAll`),证书数据经上述新字段(`cert_count`/`rsa_cert_count`)
    随 report_meta 一起落库、经 Summary 接口下发。
  - 仪表盘新增"BusyBox 情况"卡片区(已编译指令数、被移除/阉割指令数、自有指令数、init.d 脚本数),
    直接复用 BusyBox 标签页已经在用的 `busyboxAudit` 数据,未新增后端接口;四张卡片均可点击跳转
    BusyBox 标签页。
  - `ifda.__version__` 同步升到 2.3.0。

  验证:Python 47 通过/2 跳过(`tests/test_core.py` 新增 7 个:证书检测 RSA/非 RSA 区分、
  bundle 多证书计数、管道集成);Go 全量通过(`reportdb_test.go` 新增 2 个:cert 计数往返、
  旧任务/缺省字段兜底为 0)。真实固件样本端到端验证(bank_B 分区:169 个证书、其中 152 个 RSA、
  27 个组件、51 个配置文件、BusyBox 164 已编译/231 缺失/265 额外指令/38 个 init.d 脚本,
  仪表盘数字与截图逐一核对一致)。

- **2026-07-08 — v3.3:修复 config 文件预览回归、二进制/脚本标签页改为服务端真分页。**
  自 v3.2 以来的改动。

  - 修复回归 bug:v3.2 给文件新增了 `config` 类型分类后,`previewableKind()` 的判断条件忘了同步
    更新(还是只认 `script`/`other`),导致原本能点开预览的文件一旦被分类成 `config` 反而点不开了。
    改为按"非二进制"判断(`kind !== "binary" && kind !== "symlink"`),script/config/other 均可
    点击预览+语法高亮,binary/symlink 保持不可点(符合预期:二进制内容应看反汇编/字符串,符号
    链接本身没有内容)。
  - Binaries、Scripts 标签页从"一次性 `?all=1` 全量加载"改为服务端真分页(100 条/页),翻页控件
    与"跳转到指定页"和 Findings/Files 页保持一致。后端接口本来就支持 offset/limit 分页,这次
    改动只涉及前端。
  - 处理了分页引入的一个隐藏依赖:Strings 标签页的字符串搜索需要"全部二进制"的字符串数据,
    不能只依赖 Binaries 表格当前那一页,因此新增单独一路 `?all=1` 拉取(`binariesStringsAll`),
    专门供 Strings 标签页使用,不受 Binaries 页翻页影响。Components 标签页条目数量级远小于
    binaries/scripts(通常几十条),保持原来的一次性加载不变。

  验证:Python 43 通过/2 跳过、Go 全量通过(均无改动,回归验证);真实固件样本(bank_A 分区,
  537 个二进制、246 个脚本)端到端验证——config 文件预览恢复正常、二进制分页翻页与跳页正确、
  Strings 标签页字符串来源数量不受分页影响(仍为全部 537 个二进制 + 非二进制文件)。

- **2026-07-08 — v3.2:配置文件分类+内容安全审计、CVE 编号跳转 NVD、预览语法高亮、对比扫描报错修复。**
  自 v3.0(`b314e2d`)以来的改动(3.1 版本号跳过,直接到 3.2)。

  配置文件(新):
  - 新增 `config` 文件类型分类(`inventory/firmware_meta.py` 的 `is_config_file()`):按扩展名
    (`.conf/.cfg/.ini/.xml` 等)、已知文件名(`passwd/hosts/sshd_config` 等)、UCI 路径标记
    (`/config/` 目录)、以及内容嗅探(`[section]`/`config xxx`)兜底判定,不再混在笼统的"other"里。
    Files 标签页新增"类型"筛选下拉(全部/binary/script/**config**/symlink/other),`files` 表新增
    `kind` 列做服务端过滤(不是前端假过滤),含一条数据库升级路径的回归测试(旧库缺 `kind` 列时
    `ALTER TABLE` 必须先于依赖该列的索引创建执行)。
  - 新增 `vuln/config_audit.py`(`config-hardening` 规则):检测配置文件**内容**里遗留的不安全
    设置——telnet 开启、匿名 FTP 开启、debug/verbose 模式开启、SNMP 默认团体名(public/private)、
    TLS 证书校验被关闭、WPS 开启、UPnP 开启。这是此前完全没覆盖的盲区(`fs/hardening.py` 只查
    文件权限位,`inventory/secrets.py` 只查硬编码密码/密钥值,都不查"服务开关"类设置)。真实固件
    验证发现 2 条真实命中(`/etc/config/upnpd` 的 `enable_upnp=1`、`wifi.cfg` 的 `WPS_ACTIVE_IF=1`)。
    修复了规则本身一个真实的正则回溯 bug:`telnet_enable=0`(明确关闭)最初会被错误地把 key 名
    里的"enable"当成开启值而误判,已加强制分隔符修正并补了回归测试。
  - `ifda.__version__` 同步升到 2.2.0,让去重缓存对已缓存过的目标重新提交时能取到新分类/新
    finding,而不是复用升级前的旧报告。

  可视化 / 交互:
  - CVE 编号(Findings/Components/Binaries 标签页 + CVE 数据库弹窗)全部改成可点击链接,跳转到
    `https://nvd.nist.gov/vuln/detail/<CVE编号>`(新标签页打开)。Components/Binaries 原本点击
    CVE 列表是跳到内部"按此组件/二进制过滤 findings",现统一改为跳 NVD。
  - Files/BusyBox 标签页的文件预览新增语法高亮(纯前端正则 tokenizer,零依赖):按内容/路径自动
    识别 shell/XML/JSON/通用 config(含 ini 风格和 OpenWrt/UCI 风格),配色跟随所选主题的强调色/
    静音色变量,不是写死的固定颜色。同时修复了 BusyBox 页 `/etc/init.d` 脚本列表遗漏接入这套
    高亮的疏漏(它是独立于"点击预览"的另一条展示路径)。
  - 预览展开位置从页面/整个列表的最底部改为直接展开在被点击的那一行下方(HTML 表格改为
    "每行一个 tbody"的写法实现行内展开),不再需要为了看预览内容滚到很远的地方。
  - 修复对比扫描(Compare)返回"0 新增/全部消失/0 未变化"这类误导性结果的 bug:`runCompare()`
    两个 `/report` 请求此前完全没检查 HTTP 状态码,鉴权过期/任务出错时返回的 `{"error":...}`
    对象被当成"这一侧没有任何 finding"处理;现在检查 `r.ok` 并在失败时给出明确报错。

  验证:Python 43 通过/2 跳过(`tests/test_core.py` 新增 5 个);Go 全量通过(`reportdb_test.go`
  新增 3 个,含 `kind` 列过滤 + 数据库升级路径两个回归测试)。真实固件端到端验证
  (真实固件样本 bank_B 分区:51 个文件被正确分类为 config,新增 2 条 config-hardening finding,
  Files 标签页 Kind 筛选、CVE 链接、预览高亮均截图确认)。

- **2026-07-08 — v3.0:剥离二进制函数恢复、CVE 同步可靠性、SQLite 分页迁移、BusyBox 指令对比、对比扫描/去重缓存修复。**
  自 v2.0(`ac32f3f`)以来积累的全部功能改动,一次性记录、提交、打 tag。

  逆向引擎:
  - 剥离(stripped)ELF 的函数边界恢复(`re/disasm.py`):此前符号表为空时整段 `.text` 会退化成一个巨大伪函数;
    现改为同一次线性扫描里做**直接调用目标发现** + **prologue 识别**(`push {…, lr}` / `stmfd sp!, {…, lr}`,
    覆盖只被回调/跳转表引用、从未被直接 `call` 到的函数),并用已知符号体(`_symbol_bodies`)防止函数体内的
    数据字/中间指令被误判为函数入口。
  - 剥离 ARM 二进制新增 **ARM/Thumb 模式自动判定**(`_detect_arm_default_thumb`):无 `$a`/`$t` mapping symbol 时,
    两种模式各解一遍取有效指令覆盖字节数更多的一侧,避免 Thumb-heavy armhf 固件被误判成 ARModel 产出乱码。
  - `_robust_disasm`:线性扫描跳过反汇编不了的字面量池/数据字,不再因为中途一个坏字就把后续代码全部截断。
  - ELF entry point 现在总会被纳入函数起点集合(只要落在可执行区间内)。

  CVE 覆盖可靠性:
  - `cve_bin_tool.py` 改为 `-u daily -n api2`(此前默认走不可靠的 `json-mirror`),并通过运行时补丁
    `vuln/_nvd_patch.py` 修掉上游 cve-bin-tool 3.4 的两个 bug:① `NVD_API.nvd_count_metadata()` 请求的
    仅用于估算进度的计数接口被 Cloudflare 403 时会让**整个同步直接失败**,现改为兜底估算值继续跑;
    ② `NVD_Source.format_data_api2()` 有三处独立 bug(不存在的 `self.logger`、大小写不一致的 dict key、
    `baseMetricV4`/`baseMetricV2` 复制粘贴错位),对普通 CVE(尤其无 CVSS 分数或纯 CVSSv2 的旧 CVE)必现崩溃,
    现替换为修复后的版本。
  - 新增独立运维脚本 `scripts/bootstrap_nvd_cache.py`:从 GitHub 镜像(fkie-cad/nvd-json-data-feeds)拉取
    预格式化的 NVD 快照灌入 cve-bin-tool 本地库,作为直连 NVD 慢/限流时的快速替代(手动运行,未接入服务)。

  存储架构:
  - findings/binaries/scripts/components 从单个 JSON 大 blob 迁移到 SQLite(`service/reportdb.go`),
    交互式标签页改为服务端分页 + 过滤,不再一次性把整份报告(含全部 strings)扔给浏览器渲染
    ——这正是此前大扫描把 Findings 标签页卡死的根因。Triage 决策改为 ingest 时直接以 overlay 方式落库
    (`TriageStore.Snapshot()`),不再在读时对 JSON 做二次改写。
  - 发现并修复此前分页/导出的隐藏截断 bug:`ListFindings`/`paginateRaw` 对超出常规页大小的请求会静默砍到
    100/500 条,导致大报告(3000+ findings)的 JSON/MD/SBOM 导出以及 Compare 的 `/report` 拉取实际上从未
    完整过。新增 `NoLimit`/`listAllRaw`/前端 `?all=1` 约定,保证"导出"必须是名副其实的全部数据。

  固件级元数据(`inventory/firmware_meta.py`, 新增 Files 标签页):
  - 内核版本识别加两层兜底:loadable module 的 `vermagic` 字符串、`lib/modules/<version>/` 目录名——
    覆盖内核镜像和 rootfs 分属不同 flash 分区、rootfs 里没有 `Linux version` 横幅的常见情况。
  - MD5 此前在 UI 里被截断成前 8 位,现全部改为完整 32 位。
  - 新增完整文件清单(不再局限于 ELF 二进制和能识别的脚本类型),正确跳过设备节点/FIFO/socket(此前
    `open()` 一个真实的 `/dev/console` 字符设备会导致整个分析卡死,现与仓库里其它遍历器一致地先
    `os.path.isfile()` 判断再打开)。

  BusyBox 指令对比(新标签页,`inventory/busybox_audit.py`):
  - 对比该固件 busybox 实际编译进的 applet 与内置参考列表(~380 个),给出"已编译"/"被阉割(缺失)"两组;
    检测基于 busybox 二进制里的精确字符串 token(而非子串搜索),避免误判。
  - 扫描树中**任意层级**的 bin/sbin 目录(不止顶层 /bin /sbin),列出busybox 之外的额外可执行文件
    (标准二进制/脚本/非 busybox 符号链接),按目录筛选 + 文本搜索。
  - 展示 `/etc/init.d`(含各厂商等价目录)下每个脚本的文件名与完整源码。

  对比扫描(Compare)准确性:
  - 修复严重 bug:finding 匹配此前用含**绝对路径**的 `Finding.fingerprint()`,导致两次独立提取
    (不同绝对根目录,如 bank_A/bank_B)之间几乎所有 finding 都被误判成"新增+移除",`common` 恒为 0;
    改为按各自 target 相对化路径重建匹配 key。用真实数据验证:修复前 512 common/2494 新增/2494 移除,
    修复后 3006 common/0/0(两份固件内容其实一致)。
  - 文件对比此前只比较二进制+脚本,现改用完整文件清单(含配置文件等);字符串/敏感字符串对比同样
    从"只看二进制"扩展到覆盖非二进制文件的提取字符串。
  - 修复报告拉取失败(鉴权过期/任务被删等)时被静默当作"这一侧没有任何 finding"处理、从而产出
    "0 新增/全部消失/0 未变化"这类误导性结果的 bug——现在会检查 HTTP 状态并明确报错。

  分页与预览体验:
  - 敏感字符串结果加分页(客户端,200/页)+ 文本过滤框。
  - findings/files/敏感字符串三处分页统一加"跳转到指定页"输入框。
  - Files 与 BusyBox 标签页里的非二进制文件(配置文件、脚本)支持点击预览源码;新增
    `/api/jobs/{id}/file-content` 接口(先校验路径确实属于该任务扫描记录里的文件,再从磁盘按需读取,
    256KB 上限+截断提示);预览展开在被点击的那一行下方,不是页面/整段列表的最底部。
  - 报告加载、对比扫描均从无进度指示的转圈动画改为带百分比的进度条。

  任务去重缓存修复:
  - 去重缓存此前只按"目标路径 + 大小 + mtime"算 key,与分析器代码版本无关——分析器升级后重新提交
    同一固件会静默复用旧版本产出的报告(缺少新字段,如 busybox_audit),这正是 busybox 对比功能
    "看似没生效"的真实原因。现纳入 `ifda.__version__`(启动时探测),并给每个任务记录实际产出报告的
    分析器版本,只信任版本匹配当前运行版本的历史任务作为缓存来源(`ifda/__init__.py` 同步升到 2.1.0)。

  其它:
  - 静态前端资源(`service/main.go`)加 `Cache-Control: no-cache`——Go `embed.FS` 内嵌文件的 mtime
    恒为零值,`http.FileServer` 因此从不下发 `Last-Modified`,部分浏览器可能长期复用旧版页面而感知
    不到任何一次重新部署。
  - 清理仓库里残留的旧版 Go 二进制 `service/fws`。

  验证:Python 38 通过/2 跳过(`tests/test_core.py`);Go 全量通过,新增
  `job_test.go`(去重缓存版本失效)/`reportdb_test.go`(busybox 审计往返、导出不截断、finding 去重)/
  `api_test.go`(文件预览截断与非常规文件拒绝)。真实固件端到端验证
  (真实固件样本 bank_A/bank_B 分区:3006 findings、2578 files、537 binaries;62062-finding 大型固件验证导出/分页不截断)。

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
| FR-VUL-4 漏洞类别覆盖 | ◑ 溢出/命令注入/代码注入/文件包含/反序列化/格式化串/弱加密/路径遍历/认证逻辑弱点 | `vuln/catalog.py`, `vuln/auth_weak.py`, `scripts/langs.py` |
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
| 内核识别/加固 | S24-S26 | FR-INV/FR-VUL | ◑ **v3.7 落地内核版本 CVE 关联**(`vuln/cve.py` correlate_kernel_cve);加固检查(CONFIG_* 编译选项、grsecurity 标记等)仍未做 |
| 网络服务识别(静态特征库) | S ~06 | — | ✅ **v3.5 落地**(`inventory/service_id.py`,纯签名匹配,非实测流量) |
| 系统仿真 + 动态网络服务探测 | L10-L35 | FR-VUL-6 | ⬜ 未做(重;与上面的静态识别是两回事) |

## 6. 待办(按优先级)

1. **FR-VUL-6 沙箱仿真(借鉴 EMBA L 系列)** — 可选,验证可达性、降低误报。
2. **FR-VUL-4 扩类:整数溢出喂分配/拷贝** — 路径遍历、认证逻辑弱点(二进制侧)已在 v3.6 落地(见变更记录);整数溢出因"污点可达 malloc/realloc"噪音太大(几乎所有网络输入型二进制都会命中)故意搁置,需要真正的参数级分析(识别喂给 size 参数的乘法运算)才值得做。
3. **签名规则面扩展** — 把命令注入/弱函数等也纳入外置 YARA/规则文件,并补一组 `data/yara/*.yar` 实样。
4. **服务层加固** — 统一任务队列存储(`service/job.go` 目前逐个 JSON 文件)到报告层已用的 SQLite(`service/reportdb.go`);认证授权(pbkdf2 + 按账号锁定 + 登录验证码)已落地,`service/auth.go`/`service/captcha.go`。
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
