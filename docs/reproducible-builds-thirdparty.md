# 第三方确定性重建指南

> 任何第三方可在一台非集群 Linux 机器上，从 hub 公开配方重建 RPM，并与配方锚点做逐 RPM sha256 比对。

## 1 前置与安装

### 1.1 系统要求

- Linux x86_64。构建在产品的 base OS 用户态内进行，宿主发行版不限。
- 宿主需具备 `dnf`（用于装配 base OS）、`git`、Rust 工具链；nspawn 后端另需 `systemd-container`。
- `rpmbuild` 由 base OS 提供（产品 `base_packages` 含 `rpm-build`），宿主无需预装。
- 构建引擎经 `crbs-priv-helper`（setuid root，owner `root:crbs`，mode `4750`）执行特权操作；运行 crbs 的用户必须属于 `crbs` 组。
- 磁盘不少于 5 GB（base OS、dnf 缓存与产物）。

### 1.2 安装

```bash
git clone <crbs 仓库> && cd crbs
cargo build --release -p crbs -p crbs-priv-helper
sudo install -o root -g crbs -m 0750 target/release/crbs /usr/bin/crbs
sudo install -o root -g crbs -m 4750 target/release/crbs-priv-helper \
    /usr/libexec/crbs/crbs-priv-helper
sudo usermod -aG crbs "$(id -un)"   # 重新登录生效
crbs --version
```

以 root 运行时，root 也须加入 `crbs` 组：

```bash
sudo usermod -aG crbs root
```

组身份是硬要求：引擎把构建目录 chown 到 `builder:crbs` 后调用 helper `chmod 2770`。helper 保留 `CAP_FOWNER` / `CAP_DAC_OVERRIDE`，但不保留 `CAP_FSETID`；调用者不在文件属组时，内核会静默剥离 setgid 位，导致 RPM 内目录模式记录为 `0755` 而非 `02755`，产物字节漂移。

### 1.3 全局配置

`/etc/crbs/crbs.toml` 最小内容：

```toml
crbs_root = "/var/lib/crbs"
```

`crbs_root` 必须在 helper 配置的根白名单内（由 `/etc/crbs/crbs.toml` 或 `/etc/crbs/server.toml` 声明），否则 helper 报 `--crbs-root ... is not one of the configured crbs roots`。

## 2 配方、配置与输入

一次可重建的构建由三部分组成：任务配方 `recipe.json`、产品 resolved 配置、源 SRPM。

令牌仅经环境变量注入，不落盘：

```bash
read -rs HUB_TOKEN
HUB="https://hub.example.com:18443"
```

### 2.1 任务配方 `GET /api/v1/tasks/{id}/recipe`

```bash
curl -s --cacert ca.crt -H "Authorization: Bearer $HUB_TOKEN" \
    "$HUB/api/v1/tasks/<task_id>/recipe" | jq . > recipe.json
```

配方字段（`schema_version=1`）：

| 字段 | 语义 |
|---|---|
| `srpm_sha256` | 血缘锚：源 SRPM 原始字节的 sha256；下载后必须相等 |
| `macros` | 提交时的 `--define` 集（`source` 标注来源）；实际宏组另叠加产品 `rpm_macros`、`--dist` 与确定性宏组 |
| `env` | 引擎注入的环境基线：`LC_ALL=C` 恒在；`TZ=UTC`、`PYTHONHASHSEED=0`、`PERL_HASH_SEED=0`、`PERL_PERTURB_KEYS=0` 仅确定性构建注入 |
| `ccache` | ccache 状态（`enabled` / `compiler_check` / `sloppy`） |
| `instrumentation_disclosure` | spec 插桩披露（见 §5.1） |
| `repos[]` | 产品启用仓的 `name` / `baseurl` 原值 + 生成时点 `repomd_sha256`（仅记录；抓取失败记 `repomd_fetch_error`，不阻塞配方） |
| `per_arch[]` | 每架构一项：`arch`、`build_id`、`base_os_digest`、`build_packages_sha256`、`unsigned_artifacts[]`（比对锚：签名前产物的 `name` 与 `sha256`） |

子构建未全部 `succeeded` 时返回 409（不落盘）；任务不存在或无 `result_dir` 返回 404。首次请求生成 `recipe.json`（mode 0660），之后回读同一文件。

### 2.2 产品 resolved 配置 `GET /api/v1/products/{name}/resolved`

配方不含 `base_packages`、`nocheck`、`build_target` 等产品级开关，需从 resolved TOML 获取：

```bash
curl -s --cacert ca.crt -H "Authorization: Bearer $HUB_TOKEN" \
    "$HUB/api/v1/products/<product>/resolved" -o product.toml
```

### 2.3 环境快照 `build_packages.json`

`GET /api/v1/builds/{id}/build-packages`（`id` 取 `per_arch[].build_id`）返回锁定环境包清单（`nevra` / `sha256` / `repo` / `url` 数组）：

```bash
curl -s --cacert ca.crt -H "Authorization: Bearer $HUB_TOKEN" \
    "$HUB/api/v1/builds/<build_id>/build-packages" | jq . > build-packages.json
```

重放节点按 `url` 重新下载并逐包校验 `sha256`；该清单也用于 §4.2 的环境等价性比对。

### 2.4 源 SRPM

通过 `GET /api/v1/builds/{id}/srpm-download` 获取，先验证锚点：

```bash
sha256sum <srpm>
# 输出必须等于 recipe.json 的 srpm_sha256
```

## 3 重建

### 3.1 产品配置

将 resolved TOML 存为 `/etc/crbs/products/<local-product>.toml`，`repos` 与配方 `repos[].name` / `baseurl` 逐条一致。确定性产品示例：

```toml
base_packages = ["bash", "rpm-build", "gcc", "make", "glibc-devel", "dnf"]
arches = ["x86_64"]
dnf_cache_enabled = true   # deterministic 前置条件
build_target = "bb"        # deterministic 不允许 ba
nocheck = true
deterministic = true

[[repos]]
name = "base"
baseurl = "https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS-SP1/OS/$basearch"
gpgcheck = false
```

### 3.2 重放命令

```bash
sudo crbs build --offline --local \
    --product <local-product> --backend chroot --stage bb \
    /path/to/<srpm>
```

- `--offline`：产品配置从本盘读取（第三方机器不连 hub），仓库网络照常。
- `--local`：当前进程内执行，不经 daemon 或远程 hub。
- `--backend`：`chroot` 与 `nspawn` 均支持。

首次构建包含 base OS 初始化与冷 dnf 缓存下载（数百个包，通常 1–4 分钟）。产物位于 `{crbs_root}/results/<product>/<pkg>/<ts>-<build_id>/RPMS/`，`latest` 指向末次构建；`build.log` 与 `build_packages.json` 同目录。

## 4 比对

### 4.1 逐 RPM sha256

```bash
RESULT=/var/lib/crbs/results/<product>/<pkg>/latest

jq -r '.per_arch[] | .unsigned_artifacts[] | "\(.sha256)  \(.name)"' \
    recipe.json | sort -k2 > /tmp/expected.sha

(cd "$RESULT/RPMS" && find . -name '*.rpm' -exec sha256sum {} \;) \
    | awk '{n=split($2,a,"/"); print $1"  "a[n]}' | sort -k2 > /tmp/actual.sha

diff -u /tmp/expected.sha /tmp/actual.sha && echo "VERDICT: SAME"
```

纯 noarch SRPM 存在 1 字节差异（见 §6.6）：CLI 路径产物 lead archnum 为 noarch=255，hub/worker 路径为 x86_64=1；header 与 payload 一致。差异应定位确认后归因，不得静默放行：

```bash
cmp -l <anchor-rpm> "$RESULT/RPMS/<rpm>" | head
```

### 4.2 环境等价性

```bash
python3 - <<'EOF'
import json
old = {p["nevra"]: p["sha256"] for p in json.load(open("build-packages-hub.json"))}
new = {p["nevra"]: p["sha256"] for p in json.load(open("build-packages-rebuilt.json"))}
print("sha drift:", sum(1 for k in old.keys() & new.keys() if old[k] != new[k]))
print("only in hub:", len(old.keys() - new.keys()))
print("only in rebuild:", len(new.keys() - old.keys()))
EOF
```

`sha drift` 非零表示上游仓滚动导致环境包版本漂移；`only in hub` 通常只是 hub 侧 base OS 历史更厚。双方共同集合的 sha256 全等即环境一致。

## 5 机制披露

### 5.1 spec 插桩

构建环境内对 spec 插桩：`%prep`–`%check` 各节头部插入幂等的阶段标记（echo 到 stdout）。`RPMBUILD_SUBPHASE_FILTER` 只过滤 rpmbuild 输出，不修改 spec 与产物。`-bb` 下二进制 RPM 字节不受影响；环境内 spec 与上游存在 stdout 标记差异；`-bs` / `-ba` 会把插桩 spec 嵌入重造的 SRPM，因此确定性模式禁用 `ba`。

### 5.2 `_buildhost=crbs`

确定性构建固定 `_buildhost=crbs`，消除宿主机名变量；产物 BUILDHOST 为常量 `crbs`。

### 5.3 ccache

配方 `ccache` 块披露 ccache 状态。启用 ccache 的确定性产品强制 `CCACHE_COMPILERCHECK=content` 并剔除时间类 sloppiness；重放以冷 ccache 起步，缓存内容不属于配方。

### 5.4 SOURCE_DATE_EPOCH

SDE 由 rpm 从 SRPM changelog 推导，crbs 不注入数值；构建日志中的 `setting SOURCE_DATE_EPOCH=<n>` 可审计。无 changelog 的包不满足 SDE 推导前置条件。

### 5.5 构建期网络

`dnf builddep` 按配方仓库拉包；spec 若在构建期主动联网，产生的差异属已接受的残余风险。

### 5.6 签名口径

比对锚是 unsigned sha256（`build_artifacts.unsigned_sha256`）。未签名产品的重建产物即最终字节；启用签名后应以同配方重放构建的 unsigned 哈希为锚。

## 6 已知限制

1. **CAP_SETFCAP 缺口**：沙箱缺该 capability，安装带 file capability 的 RPM 会失败（如 tar → policycoreutils）；可通过 `builddep_install_weak_deps = false` 绕开弱依赖链。
2. **Java 组件层非确定性**：部分旧版 maven/bnd 插件在 MANIFEST 与 maven-metadata 中引入时间戳或随机 UUID，SDE 无法覆盖 jar 内部；此类包按不可复现公示。
3. **ar 归档 mtime**：静态库 `.a` 成员头 mtime 泄漏构建时间，字节差集中于该字段；需确定性归档选项或平台级 `--enable-deterministic-archives` 修复。
4. **上游仓滚动**：`repos[].repomd_sha256` 仅为记录，无锁仓服务；上游修剪后重新解析的依赖 NEVRA 可能前移。跨时间重放以 §4.2 环境比对为准。
5. **首次构建确定性**：仓库状态尚未纳入锁定输入，两次全新首建不承诺字节一致。
6. **纯 noarch SRPM 的 lead archnum**：CLI 本地路径注入 `rpmbuild --target noarch`，lead archnum 为 255；hub/worker 路径默认平台为 x86_64，archnum 为 1。差异仅 1 字节（lead 为 rpm 遗留字段，header/payload 相同），按 §4.1 例外流程归因。
7. **运行者组上下文**：见 §1.2。运行者不在 `crbs` 组时 setgid 位被静默剥离，目录模式漂移，导致产物不一致。
