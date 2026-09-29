# CRBS 构建手册

> 本文适用于 0.1.0。版本号以 `Cargo.toml` workspace 与 `crbs.spec` 为准；
> RPM 打包细节（spec 结构、mock）见
> [`packaging/PACKAGING.md`](../../packaging/PACKAGING.md)。

## 1. 工具链要求

### 1.1 Rust

源码构建要求 **Rust ≥ 1.82**。`Cargo.lock` 已将传递依赖钉在 MSRV ≤ 1.82
的版本，`crbs.spec` 的 `BuildRequires: rust >= 1.82` 与此一致；编译器低于
1.82 会在编译期失败。

```bash
# Fedora 官方包
sudo dnf install -y rust cargo gcc

# 或 rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 1.2 RPM 构建依赖

仅生成 SRPM 的机器：

```bash
sudo dnf install -y rpm-build
```

执行 `rpmbuild --rebuild` 的目标机（与 spec 的 `BuildRequires` 对应）：

```bash
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
```

| 依赖 | 用途 |
|------|------|
| `rpm-build` | `rpmbuild -bs` / `--rebuild` |
| `rust` / `cargo` | `%build` 拉取依赖并编译 |
| `gcc` | 依赖 crate（如 `ring`）的 C 代码编译 |
| `systemd-rpm-macros` | `%systemd_post` 等 scriptlet 宏 |
| `pkgconfig(sqlite3)` | `libsqlite3-sys` 动态链接系统 sqlite |

SRPM 不含 vendored 依赖。rebuild 时 `%build` 按 `Cargo.lock` 拉取依赖并
编译（需访问 crates.io 或配置 cargo 源镜像）。

### 1.3 平台说明

`crbs` 运行时依赖 Linux（OverlayFS、chroot/nspawn）。源码层已封装
Linux-only 系统调用，macOS 上可执行 `cargo check` / `clippy` / `test`
辅助开发，但无法执行真实构建。平台相关 import 与调用必须位于
`#[cfg(target_os = "linux")]` 边界内，否则会破坏 macOS 编译。

## 2. 构建路径总览

| # | 路径 | 入口 | 适用场景 |
|---|------|------|----------|
| 1 | cargo 源码构建 | `cargo build --release` | 开发验证、提交门禁 |
| 2 | SRPM 生成 | `bash scripts/build-srpm.sh` | 产出 `.src.rpm`，供目标机 rebuild |
| 3 | 目标机原生 rpmbuild | `rpmbuild --rebuild <srpm>` | 目标机用系统 Rust 构建（glibc 动态链接） |

产物目录约定：

```text
<项目根>/rpmbuild/SRPMS/           # build-srpm.sh 产出的 SRPM
~/rpmbuild/RPMS/<arch>/            # --rebuild 产出的二进制 RPM
~/rpmbuild/BUILD/crbs-0.1.0-src/   # rebuild 解包的源码树（含 target/）
```

## 3. 路径一：cargo 源码构建

```bash
git clone https://gitcode.com/jiachao2130/crbs.git
cd crbs

cargo build            # debug
cargo build --release  # target/release/{crbs,crbs-server,crbs-worker,crbs-priv-helper}
```

提交前门禁：

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`tests/*.sh` 为集成测试脚本，依赖真实 Linux 环境与 root 权限，需在
Fedora 等 Linux 主机上执行，不在上述门禁范围内。

## 4. 路径二：SRPM 生成

### 4.1 一键脚本（推荐）

源码包只含源码，不含 vendored 依赖；脚本组装打包树并执行
`rpmbuild -bs`。

```bash
bash scripts/build-srpm.sh
# 输出（stdout 最后一行为 SRPM 路径，dist 置空、各架构通用）：
# rpmbuild/SRPMS/crbs-0.1.0-1.src.rpm

# 生成后送至目标机执行 rpmbuild --rebuild 验证
bash scripts/build-srpm.sh --remote user@host

# 保留中间目录并输出详细过程
bash scripts/build-srpm.sh -v
```

脚本行为：

- 版本号从 `crbs.spec` 的 `Version:` 解析，spec 是版本的唯一事实源。
- 打包树位于仓库 `target/crbs-srpm.*`，成功自动清理，失败保留并打印
  路径；`-v` 始终保留。
- 产物固定输出到项目根的 `rpmbuild/SRPMS/`。

### 4.2 从 SRPM 构建

rebuild 主机需能访问 crates.io，或已配置可用的 cargo 源镜像：

```bash
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
rpmbuild --rebuild rpmbuild/SRPMS/crbs-0.1.0-1*.src.rpm
```

`%build` 按 `Cargo.lock` 拉取依赖并编译，构建期间需保持网络可达（或已
预填充 cargo 缓存）。

### 4.3 手动准备源码包

不使用脚本时的等价流程（适合需要定制排除项的场景）：

```bash
VERSION=0.1.0
SRC_DIR="$HOME/crbs-${VERSION}-src"
rm -rf "$SRC_DIR" && mkdir -p "$SRC_DIR"

git archive --prefix="crbs-${VERSION}-src/" --format=tar HEAD | tar -C "$HOME" -xf -
cd "$HOME"
tar --exclude='.git' --exclude='target' --exclude='rpmbuild' \
    -czf "crbs-${VERSION}.tar.gz" "crbs-${VERSION}-src"

mkdir -p ~/rpmbuild/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
cp "$HOME/crbs-${VERSION}.tar.gz" ~/rpmbuild/SOURCES/
cp crbs.spec ~/rpmbuild/SPECS/
rpmbuild -ba ~/rpmbuild/SPECS/crbs.spec    # 同时产出 SRPM 与二进制 RPM
```

生成的 SRPM 可交给路径三在目标机 rebuild，或用 `mock` 在干净 chroot 中
构建（CI 建议）。

## 5. 路径三：目标机原生 rpmbuild

在目标机上用系统 Rust 构建 glibc 动态链接版本：

```bash
cd crbs
bash scripts/build-srpm.sh
# → rpmbuild/SRPMS/crbs-0.1.0-1.src.rpm

rpmbuild --rebuild rpmbuild/SRPMS/crbs-0.1.0-1.src.rpm
```

产物位于 `~/rpmbuild/RPMS/<arch>/`（`<arch>` 为 `uname -m` 输出）：

```text
crbs-0.1.0-1.<dist>.<arch>.rpm
crbs-server-0.1.0-1.<dist>.<arch>.rpm
crbs-worker-0.1.0-1.<dist>.<arch>.rpm
crbs-priv-helper-0.1.0-1.<dist>.<arch>.rpm
```

首次构建需完整编译依赖，耗时约 15 分钟；`~/.cargo` 依赖缓存就绪后约
3 分钟。rpmbuild 的 `%build` 在独立 BUILD 目录执行，没有增量语义，速度
取决于依赖缓存。

构建后自检：

```bash
# 四个子包齐全
ls ~/rpmbuild/RPMS/$(uname -m)/

# setuid 位随包携带（应见 -rwsr-x--- root crbs）
rpm -qpl --dump ~/rpmbuild/RPMS/$(uname -m)/crbs-priv-helper-*.rpm | grep priv-helper
```

安装与升级命令见 [`deploy.md`](deploy.md) §2、§8。

## 6. 构建产物说明

四个子包及内容（来源：`crbs.spec` 的 `%files`）：

| 子包 | 安装内容 | 关键权限 | 依赖 |
|------|----------|----------|------|
| `crbs` | `/usr/bin/crbs`、`/etc/crbs/crbs.toml.example`、`/etc/crbs/products/`、`/var/lib/crbs`（2770 setgid）、sysusers、bash/zsh/fish 补全 | `0750 root:crbs` | `sqlite-libs` `dnf` `rpm` `createrepo_c` `systemd-nspawn`；`Recommends: rpm-build` |
| `crbs-server` | `/usr/bin/crbs-server`、`crbs-server.service`、`server.toml.example` | `0750 root:crbs` | `crbs`、`crbs-priv-helper`（同 NEVRA） |
| `crbs-worker` | `/usr/bin/crbs-worker`、`crbs-worker.service`、`worker.toml.example` | `0750 root:crbs` | `crbs`、`crbs-priv-helper`（同 NEVRA） |
| `crbs-priv-helper` | `/usr/libexec/crbs/crbs-priv-helper`、`/etc/crbs/priv-helper.toml` | setuid `4750 root:crbs`；配置 `0640` | `crbs`（同 NEVRA） |

- 最小安装为 `crbs` + `crbs-priv-helper`（本地构建）；需要 HTTP API 与
  Web UI 时加装 `crbs-server`；作为分布式节点时加装 `crbs-worker`。
- `crbs` 主包的 `%pre` 创建 `crbs` 系统组；sysusers 创建 `crbs-server` 与
  `crbs-worker` 系统用户并加入 `crbs` 组。
- 二进制经 release profile strip，不生成 debuginfo 子包。
- spec 在 `%install` 阶段调用二进制生成补全。
- `%post` 在 SELinux enforcing 系统上对 setuid 二进制、配置与状态目录
  执行 `restorecon`。

## 7. 与 setup.sh 直装的关系

源码直装（`sudo bash scripts/setup.sh <username>`）将二进制安装到
`/usr/local/bin`（helper 在 `/usr/libexec/crbs`），不安装 systemd unit、
不创建 sysusers、无 RPM 升级语义。该方式仅建议用于开发机；服务器部署
使用 RPM，对比见 [`deploy.md`](deploy.md) §2.4。

## 8. 常见构建问题

| 现象 | 原因 | 处置 |
|------|------|------|
| 语法报错（如 `if-let chains` 不可用） | rustc < 1.82，或 `cargo update` 后依赖漂移出 lock 钉定的 MSRV | 升级工具链 |
| `cargo build --locked` 报 Cargo.lock 不一致 | 依赖变更后未提交 lock | 提交更新后的 `Cargo.lock` |
| rpmbuild 中 rustc 报非 UTF-8 输入错误 | rpmbuild 把 spec 脚本内容作为 stdin 传给 cargo | spec 已内建 `exec < /dev/null`；自写构建脚本时需重定向 stdin |
| 磁盘占用快速增长 | `target/` 与 `~/rpmbuild/BUILD` 各保留一份构建产物 | 构建收尾后执行 `cargo clean` 并清理 BUILD 目录 |
| macOS `cargo check` 报平台符号缺失 | Linux-only 导入位于 cfg 边界之外 | 将平台相关 import 与调用收进 `#[cfg(target_os = "linux")]` |
| rebuild 总是全量编译 | rpmbuild 在独立 BUILD 目录构建，无增量语义 | 属预期行为，依赖 `~/.cargo` 缓存缩短耗时 |
| 离线机器构建失败 | rebuild 时 cargo 需拉取依赖 | 配置 cargo 源镜像，或预先填充 registry 缓存 |
| RPM 产物落在意外目录 | 未显式指定 `_topdir` | rebuild 时显式传入 `--define "_topdir ..."` |

## 9. 确定性构建模式

产品 TOML 设置 `deterministic = true` 后，构建自动携带确定性宏组
（SOURCE_DATE_EPOCH 族与 `_buildhost = "crbs"`）、环境基线
（`TZ` / `LC_ALL` / `PYTHONHASHSEED` 等）并固定 hostname，同时强制输出
溯源文件 `build_packages.json`（sha256 与 url 均为非空硬性要求，不受
`reproduce_enabled` 影响）。同一机器重复构建的 RPM 字节一致是该模式的
产品级保证。

前置条件（缺失时配置加载报错）：

- 全局或产品配置 `dnf_cache_enabled = true`；
- `build_target` 不得为 `ba`（逐架构重建 SRPM 与确定性冲突）。

配套开关与核验方式：

- `auto_replay`（默认 `true`）：构建成功后由 hub 自动在锁定环境中重放一次，
  逐 RPM 比对 sha256；后台优先级执行，不发布产物，冷 ccache。设为 `false`
  关闭。
- `replay_sampling`（默认 `100`，即全量；`0` 关闭自动重放）：自动重放的
  抽样上限。
- `crbs verify <TASK_A> [TASK_B]`：逐包比对两个任务的 RPM 产物；省略第二
  个任务时，对同一任务内的各构建做两两比对。
- 复现率观测：Web UI `/ui/reproducibility` 与
  `GET /api/v1/reproducibility/stats`。

第三方按公开配方重放的核验方法见
[`../reproducible-builds-thirdparty.md`](../reproducible-builds-thirdparty.md)。

## 10. repro-from-srpm 模式

只有 SRPM、没有原 hub 构建记录时，可用 `crbs build --repro-from-srpm`
（网页提交表单勾选，或 API 字段 `repro_from_srpm`）从 SRPM 头读取
`BUILDHOST` 与 `BUILDTIME` 并注入本次构建。产物头字段与源码同源；
构建环境不做还原，payload 字节不保证一致，比对由使用方自行完成。

三种复现手段的分工：

| 手中物料 | 使用方式 | 结果 |
|---|---|---|
| SRPM + 原 hub 记录 | `--reproduce <TASK_ID>` | 还原依赖清单，做环境级一致性校验 |
| 产品级长期保证 | 产品 `deterministic = true`（§9） | 字节级可复现、溯源、硬门、自动比对 |
| 仅 SRPM | `--repro-from-srpm` | 头字段与源码同源；payload 不保证一致 |

注入内容：`_buildhost`（SRPM 头的 `BUILDHOST` 原值）、
`use_source_date_epoch_as_buildtime` 与
`clamp_mtime_to_source_date_epoch` 两个时间宏、容器内
`SOURCE_DATE_EPOCH`（SRPM 头的 `BUILDTIME`），容器 hostname 固定为
`crbs-build`。在 deterministic 产品上叠加此旗标时，回放值覆盖确定性宏组
（crbs 自产 SRPM 的头值与该宏组值相同，覆盖为等值操作）；CLI `--define`
仍具有最终优先级。

该模式与 `--reproduce`、`--chain` 互斥。按历史任务 rebuild 时会继承该
旗标并重新探测 SRPM 头。

跨环境一致性核对：

- noarch / 解释型 / 纯数据包：解释器与宏的版本通常不写入产物字节，跨环境
  一般可保持字节一致。
- 编译型包：比对构建环境中的 gcc\*、binutils、glibc（以及 make、
  rpm-build）版本即可预判。repro-from-srpm 构建完成后，引擎会把共享层中
  实际命中的工具链 NVRA 写入构建 note，可经 `crbs status` 或任务详情查看。

边界与限制：

- SRPM 头不等于原 RPM 头：SRPM 若曾被重打包，回放值只对当前 SRPM 负责。
- 头一致不等于字节一致：payload 是否一致取决于上述工具链版本。
- SRPM 头 `BUILDTIME` 为 0 时照原值注入，会把构建期文件 mtime 钳到 1970，
  可能导致构建失败，属该模式的边界行为。
- 提交时 `rpm -qp` 探测失败视为 SRPM 损坏，按坏输入拒绝（HTTP 400 或 CLI
  报错），不做降级。
- 该模式不记录 provenance、不产生重放锚、不设置 `builds.deterministic`
  标记、不触发自动重放；deterministic 产品的既有语义不受影响。

## 11. 构建溯源

### 11.1 任务标签

`crbs build --label KEY=VALUE` 为任务附加通用键值元数据，可重复；远程提交
（JSON `labels` 数组 / multipart 重复 `label` 字段）与本地直接构建同样落库。
标签是任务级的不透明元数据，键名无系统保留约定——`git-repo` / `git-commit`
只是常见用法示例（仓库地址与提交号），可自由定义其他键：

```bash
crbs build foo.src.rpm -p fedora --remote prod \
  --label git-repo=https://example.com/foo.git \
  --label git-commit=3f2a1c9
```

校验与用量：至多 16 条；key ≤ 64 字符、限 `[A-Za-z0-9_.-]`；value ≤ 256
字符、不含控制字符；总量 ≤ 4096 字符；同一任务重复键拒绝（400 / CLI 报错）。

查询：

- `crbs status --label KEY=VALUE`（本地与远程同语义）与
  `GET /api/v1/tasks?label=KEY=VALUE` 按 (key, value) 精确过滤任务；
- 任务详情（`crbs status <TASK>` / `GET /api/v1/tasks/{id}`）回显全部标签，
  按 key 排序。

Web 界面（`/ui/`）同样可用：

- 新建任务页提供多行 `KEY=VALUE` 输入，可添加/删除行；空白行提交时忽略，
  校验规则与 CLI/API 一致，校验失败重渲染时保留已填行。行增删依赖页面脚本，
  无 JavaScript 时仍可提交表单已渲染的行（新表单为一行）。
- 任务列表页的 `Labels` 输入框按 `KEY=VALUE` 精确过滤，激活时显示可一键移除
  的过滤 chip，切换产品/阶段视图时保留该过滤条件。
- 任务详情页把标签渲染为徽章，点击即跳转到按该标签过滤的任务列表。

限制：标签声明在任务级，一次提交含多个 SRPM 时全部子构建共享同一组标签，
没有 per-SRPM 结构；需要区分来源时按包拆分为多次提交。

### 11.2 按输入 SRPM 内容检索

hub 对每个新构建计算输入 SRPM 原样字节的 sha256，写入
`builds.canonical_srpm_sha256`（任务内各架构子构建共享同一值）。据此可用
`GET /api/v1/builds?srpm_sha256=<hex>` 反查同一输入的全部历史构建。历史行
与 worker 镜像行为 NULL，不参与过滤。该哈希是配方导出（锁定输入快照）的
地基，不参与复现比对（产物比对锚是 `build_artifacts.unsigned_sha256`）。

### 11.3 构建时的产品配置快照

CLI 直接本地构建在创建构建行时锚定当时的合并产品配置 TOML
（`builds.product_config_toml`）；hub 在 claim 派发时同样把实际下发的配置
写入构建行，供审计与重投递复用（重投递优先读快照，缺失才重新解析，不会
无条件覆盖）。`crbs debug` 使用该快照还原环境，不受 hub 当前产品配置或
磁盘 TOML 后续变更影响；无快照的历史构建回落当前配置并告警。

## 12. 相关文档

- [`deploy.md`](deploy.md)：部署手册
- [`operations.md`](operations.md)：运维手册
- [`../../packaging/PACKAGING.md`](../../packaging/PACKAGING.md)：RPM 打包指南
