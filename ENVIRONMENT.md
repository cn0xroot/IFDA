# 本地运行环境搭建

> 记录把一台"干净"机器配到能跑 IFDA 全部功能(含可选的 Ghidra 反编译富化)所需的步骤,
> 以及过程中踩的坑和排查方法。配套:[`README.md`](README.md)(用法)、
> [`PROGRESS.md`](PROGRESS.md)(功能进度)。

## 1. 需要什么

| 组件 | 用途 | 是否必需 |
|------|------|----------|
| Python ≥ 3.10 + `capstone`、`pyelftools` | 分析核心(`ifda/`) | **必需** |
| `cve-bin-tool` ≥ 3.4 | FR-VUL-1 广域 CVE 关联(NVD/OSV/RedHat/GitLab Advisory/Curl,350+ 组件) | **必需**(缺失时该阶段降级为仅用内置小型 `vuln_db.json`,并在报告里留下明显警告) |
| Go ≥ 1.22 | 服务层(`service/`,REST API + 队列 + Web UI) | 仅用服务层时需要 |
| `yara-python` | FR-INT-3 YARA 规则桥(无 `data/yara/*.yar` 时该阶段自动跳过) | 可选 |
| mips/arm/aarch64 交叉编译器 | 造跨架构测试样本(`tests/test_core.py`) | 可选(缺失时相关用例自动 skip) |
| Ghidra(+ 一个真正的 **JDK**,不是 JRE) | FR-RE-2 反编译伪代码富化(`--decompile`) | 可选(缺失时优雅降级为 no-op) |

除 Go 版本外,其余组件缺失都不会导致功能报错——只会跳过/降级对应能力(NFR-USE-1 优雅降级)。
`cve-bin-tool` 是唯一一个"必需但仍会优雅降级"的组件:它是官方推荐的默认路径,但一次网络故障
不应该让整个分析任务失败,所以缺失/失败时只留警告,不中断 `analyze()`。

## 2. Python 分析核心

```bash
pip install -e .                     # 或: pip install capstone pyelftools
pip install cve-bin-tool             # 必需:FR-VUL-1 广域 CVE 关联(见下方说明)
pip install yara-python              # 可选:啟用 YARA 规则桥
python3 -m pytest tests/ -q          # 全绿是: 25 passed, 2 skipped(跳过项是 live Ghidra + live cve-bin-tool 测试)
```

`cve-bin-tool` 首次在一台机器上运行会下载/更新本地 CVE 数据库
(NVD + OSV + RedHat + GitLab Advisory + Curl,压缩后 1GB+),需要联网,耗时可能
到几分钟甚至更久,视网络状况而定;之后每次分析只查询本地缓存
(`~/.cache/cve-bin-tool`),很快。可以提前手动预热:

```bash
cve-bin-tool -u now -n json --disable-version-check /bin/true   # 触发一次数据库同步
```

单元测试默认不会调用真正的 `cve-bin-tool`(`tests/conftest.py` 设置了
`IFDA_DISABLE_CVE_BIN_TOOL=1`,解析逻辑由一个 fixture 驱动的单测覆盖),这样测试
套件不需要联网或那个数据库也能保持秒级。要跑一次真实的端到端冒烟测试:

```bash
IFDA_CVE_BIN_TOOL_TEST=1 python3 -m pytest tests/ -q -k cve_bin_tool
```

## 3. Go 服务层

`service/go.mod` 要求 `go 1.22`(`net/http` 的 `r.PathValue` 是 1.22 才引入的 API)。
如果 `go version` 低于 1.22,`go build` 会直接报 `r.PathValue undefined`。

```bash
# 卸掉旧版本,装最新稳定版(示例为 1.26.4,请以 https://go.dev/dl/ 当前版本为准)
GO_VER=$(curl -s "https://go.dev/VERSION?m=text" | head -1)   # 如 go1.26.4
curl -sL -o /tmp/go.tar.gz "https://go.dev/dl/${GO_VER}.linux-amd64.tar.gz"
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz

# 让 go 在新 shell 里自动可用
cat > /etc/profile.d/go.sh << 'EOF'
export PATH="/usr/local/go/bin:$PATH"
EOF
# 当前 shell 立即可用(不重开 shell 时)
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

go version                            # 确认 >= 1.22
cd service && go build -o ifda-service . && go vet ./...
```

### 鉴权:`-user`/`-pass`/`-reset-pass` 与网页端改密码的关系

`-auth` 默认开启(需要登录)。首次启动、且数据目录里还没有 `users.json` 时:

- 给了 `-user`/`-pass`:用这对账号密码播种第一个账号
- 没给:自动生成一个随机密码给 `admin`,打印在启动日志里(只打印这一次,记得当场记下来)

**账号已存在之后**,`-user`/`-pass` 不会再生效——不会覆盖网页端"用户中心 → 修改密码"改过的密码。这是有意为之:如果启动命令(比如写死在 systemd unit / docker-compose 里的那种)每次重启都带着同一对 `-user`/`-pass`,而它一旦被当成"每次都要设置"来处理,就会把网页上改过的密码悄悄改回去,而且没有任何提示——这正是曾经的真实 bug。现在遇到这种情况,日志会打印:

```
-user/-pass ignored: "admin" already has a password (possibly changed via the web UI) — pass -reset-pass to force it back to -pass
```

真要强制找回/重置密码(比如忘记了网页上改成了什么),加 `-reset-pass`:

```bash
./ifda-service -addr :8080 -core .. -user admin -pass 新密码 -reset-pass
```

`-reset-pass` 只在同时给了 `-user`/`-pass` 时才生效,且每次都会真的覆盖,用完记得从启动命令里去掉,否则又变成每次重启都被强制改回同一个密码。

## 4. 交叉编译器(造测试样本用)

```bash
apt-get install -y gcc-mips-linux-gnu gcc-arm-linux-gnueabi
# aarch64 通常已随 gcc-aarch64-linux-gnu 提供;x86_64 用系统自带 gcc
```

装完后 `python3 -m pytest tests/ -q` 应从 `21 passed, 6 skipped` 变为 `25 passed, 2 skipped`
(剩下的 skip 是 live Ghidra 测试和 live cve-bin-tool 测试,分别见下节和 §2)。

## 5. Ghidra(反编译富化,可选)

```bash
curl -sL -o /tmp/ghidra.zip \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip"
unzip -q /tmp/ghidra.zip -d /opt/
ln -s /opt/ghidra_11.1.2_PUBLIC /opt/ghidra
chmod +x /opt/ghidra/ghidraRun /opt/ghidra/support/analyzeHeadless

cat > /etc/profile.d/ghidra.sh << 'EOF'
export GHIDRA_HOME=/opt/ghidra
EOF
```

`ifda/re/decompile.py` 会按 `$GHIDRA_HOME` → `/opt/ghidra` → `PATH` 顺序自动探测,装到
`/opt/ghidra` 时甚至不需要设置环境变量。

### 坑 1:无 TTY 环境下 headless 无法选 JDK

容器 / CI / 无交互 shell 里直接跑 `analyzeHeadless` 会报:

```
Unable to prompt user for JDK path, no TTY detected.
```

Ghidra 正常是弹交互式选择器让你选 JDK,没有 TTY 就没法问。解法是在
`support/launch.properties` 里显式写死路径,跳过交互:

```bash
# /opt/ghidra/support/launch.properties
JAVA_HOME_OVERRIDE=/usr/lib/jvm/java-21-openjdk-amd64   # 改成你机器上的实际路径
```

### 坑 2:装的是 JRE,不是 JDK

即使设了 `JAVA_HOME_OVERRIDE`,如果指向的目录下没有 `javac`(只是
`openjdk-*-jre-headless`),Ghidra 会静默判定"不支持"并退出(`isSupportedJavaHomeDir`
返回 false,不报详细原因)。确认方法:

```bash
ls $JAVA_HOME/bin/javac   # 不存在就是 JRE,需要装完整 JDK
apt-get install -y openjdk-21-jdk-headless
```

Ghidra 11.1.2 要求 JDK ≥ 17(`Ghidra/application.properties` 里的
`application.java.min=17`);装 21 系列 LTS 即可。

### 验证

```bash
# 手动跑一次 headless,确认能正常反编译
java -cp /opt/ghidra/support/LaunchSupport.jar LaunchSupport /opt/ghidra -jdk_home -save
# 应输出 JDK 路径且 exit 0;若 exit 1 无输出,回到坑 1/坑 2 排查

# 跑 opt-in 的 live 反编译测试(默认因为慢而跳过)
IFDA_GHIDRA_TEST=1 python3 -m pytest tests/ -q   # 应为 24 passed(不再有 skip)
```

## 6. 端到端冒烟测试

```bash
mkdir -p /tmp/smoke/rootfs/bin && cd /tmp/smoke
cat > vuln.c << 'EOF'
#include <string.h>
#include <stdlib.h>
void handle(char*i){char b[64];strcpy(b,i);system(b);}
int main(int c,char**v){if(c>1)handle(getenv("QUERY_STRING"));return 0;}
EOF
gcc -o rootfs/bin/vulnbin vuln.c

cd /home/init3/Tools/IDA/service && go build -o /tmp/ifda-service .
/tmp/ifda-service -addr :18099 -core /home/init3/Tools/IDA -data /tmp/smoke/data &

curl -s -XPOST localhost:18099/api/jobs -H 'Content-Type: application/json' \
     -d '{"target":"/tmp/smoke/rootfs"}'          # -> {"id": "job-...", ...}
curl -s localhost:18099/api/jobs/<id>              # status 应变为 completed,findings > 0
```

## 7. 一次性检查清单

```bash
go version                                    # >= 1.22
python3 -m pytest tests/ -q                   # 23 passed, 1 skipped(无交叉编译器则更少)
cd service && go build -o ifda-service . && go vet ./...
IFDA_GHIDRA_TEST=1 python3 -m pytest tests/ -q -k decompile   # 有 Ghidra 时应通过
```
