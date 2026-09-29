# crbs CLI 参考

`crbs` 命令行接口参考：子命令、常用选项、退出码与 JSON 输出格式。选项
定义以 `crates/crbs/src/cli/mod.rs` 为准，完整参数可用
`crbs <cmd> --help` 查看。配置文件参考见
[`configuration.md`](configuration.md)。

## 全局旗标

所有子命令可用：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-v, --verbose` | flag | — | debug 级日志（与 `--quiet` 互斥） |
| `-q, --quiet` | flag | — | 只输出 warning/error |
| `--offline` | flag | 关 | 从本地磁盘而非 hub 读取产品配置；作用于 build / reproduce / sign / init / clean / shell / debug。与 `--local` 正交：`--local` 决定构建在哪跑，`--offline` 决定产品配置从哪读 |

## `crbs init` — 初始化构建环境

安装 base packages、配置仓库、创建构建用户。

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<product>` | 位置参数 | 必填 | 产品名 |
| `--force` | flag | 关 | 覆盖已存在的 base_os |
| `--remote <URL\|NAME>` | string | — | 产品配置的 hub 来源（URL 或 profile 名，回退 profile / `remote.default`） |
| `--token <TOKEN>` | string | — | hub API token（回退 profile → `CRBS_TOKEN`） |
| `--ca-cert <PATH>` | path | — | hub TLS 的 PEM CA 证书（回退 profile → `CRBS_CA_CERT`） |
| `--format` | enum | `text` | `text` / `json` |

```bash
crbs init fedora --offline    # 无 hub 机器首跑生成配置模板
crbs init fedora              # 默认从 hub 读取 chain-resolved 配置
```

## `crbs build` — 构建一个或多个 SRPM

选项按功能分组如下。

输入：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<srpm>...` | 位置参数 | — | SRPM 路径或目录（目录自动扫描 `*.src.rpm`）；与 `--list` 至少一个 |
| `-p, --product <NAME>` | string | — | 产品名（`--attach`/`--reproduce`/`--rebuild` 模式可从构建记录推断） |
| `-l, --list <FILE>` | path | — | 从文件读 SRPM 列表（每行一个路径，程序内做 glob 展开） |
| `--rebuild <TASK_ID>` | string | — | 按 server 上的历史任务 ID 重放构建（复用原任务的 SRPM 与构建选项；与 srpm/list/attach/reproduce 互斥） |

构建行为：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-j, --jobs <N>` | usize | num_cpus | 并发构建数 |
| `-s, --shared-layer` | flag | 关 | 启用共享依赖层缓存（反复构建同一包时收益大） |
| `--tmpfs` | flag | 关 | tmpfs 加速：shared_layer=false 时全内存构建，true 时仅 BUILD 目录 |
| `--ccache` | flag | 关 | 启用 C/C++ 编译缓存 |
| `--fail-fast` | flag | 关 | 任一包失败即停止其余构建 |
| `--timeout <SECS>` | u64 | 0（无限） | 单包构建超时 |
| `--stage <bb\|bs\|ba>` | enum | 配置 `build_target` | rpmbuild 阶段：二进制包 / 源码包 / 两者 |
| `-D, --define KEY=VALUE` | 可重复 | — | RPM 宏定义；`_topdir` 保留不可覆盖，空值/非法键提交期即拒（远程提交 HTTP 400） |
| `--with FEATURE` / `--without FEATURE` | 可重复 | — | 条件构建开关 |
| `--nocheck` | flag | 关 | 跳过 `%check` 阶段 |
| `--noclean` | flag | 关 | 跳过 rpmbuild 收尾清理段（spec `%clean` 与 rpm 4.18 内建 `rmbuild`；BUILD 树回收由引擎 teardown 负责） |
| `--nodebuginfo` | flag | 关 | 不生成 debuginfo 包 |
| `--no-publish` | flag | 关 | 不把本次构建的 RPM 发布到产品 repo（Koji `--scratch` 风格；仅远程/daemon 提交） |
| `--no-consume` | flag | 关 | 本次构建不消费产品 repo（不注入 crbs-product.repo；只许收紧——私有产品或产品配置 `repo-consume = false` 关闭后无重新打开的旗标；仅远程/daemon 提交） |
| `--target <ARCH>` | string | — | 固定单一目标架构，按字面精确匹配；与 `--arches` 互斥。target 必须在产品构建架构集合内，否则整个提交被拒（远程 400 / 本地 exit 4）。spec 的 `ExclusiveArch` / `ExcludeArch` 同样按字面比对（如 `x86_64_v3` 不满足 `ExclusiveArch: x86_64`） |
| `--arches <ARCH>`（别名 `--arch`） | 列表 | 产品 `arches` | 多架构构建，逗号分隔或可重复；仅 `--remote` 支持 fan-out。纯 noarch 源码包默认只构建一次（`noarch_per_arch = true` 可恢复每架构构建）。显式架构与 spec 架构约束冲突时默认拒绝整单，`--skip-unsupported-arches` 改为跳过冲突架构 |
| `--skip-unsupported-arches` | flag | 关 | 显式 `--arches` 与 spec 架构约束冲突时跳过冲突架构，而非拒绝整个提交。产品默认 fan-out 与批次构建本就跳过；本地显式冲突固定 exit 4 |
| `--dist <TAG>` | string | — | 设置 `%dist` 宏（如 `.fc44`），字符限 `[a-zA-Z0-9._-]`，缺前导点自动补 |
| `--retry <N>` | u32 | 配置 `build_max_retries` | 覆盖 transient 失败重试次数 |
| `--priority <0\|1\|2>` | enum | `0` | 构建优先级（0=default, 1=high, 2=critical）；2=critical 仅 operator 及以上角色可设；排队语义仅远程/daemon 生效 |
| `--assume-independent` | flag | 关 | 跳过批量 SRPM 之间的 BuildRequires 检查 |
| `--label KEY=VALUE` | 可重复 | — | 任务级通用键值标签（如 `--label git-repo=... --label git-commit=...`），随任务落库，可用 `crbs status --label` / `GET /api/v1/tasks?label=` 过滤。至多 16 条；key ≤ 64 字符、限 `[A-Za-z0-9_.-]`；value ≤ 256 字符；重复键拒绝。键名无系统保留，上述键仅为示例 |

链式构建（`--chain`）：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-C, --chain` | flag | 关 | 依赖链构建：拓扑排序 + 分轮 + 本地仓库 + 增量 |
| `-o, --order-only` | flag | 关 | 与 `--chain` 配合，只输出构建顺序不构建 |
| `--repo <PATH>` | path | `{crbs_root}/repo/{product}/` | 指定 local repo 路径（覆盖配置） |
| `--result-repo` / `--no-result-repo` | flag | 注入开 | `--chain` 模式的本地 result repo 注入开关（仅注入被其他包依赖的 RPM）；两 flag 互斥，后出现者生效 |
| `--summary-limit <N>` | usize | `20` | chain 摘要每分类显示的包数（0 = 不截断） |
| `--list-failed` / `--list-succeeded` | flag | 关 | 摘要末尾附全量失败/成功包名（不截断） |
| `--concise` | flag | 关 | 仅输出一行 `Total/Succeeded/Failed/Skipped/Wall` 摘要 |
| `--verbose-summary` | flag | 关 | 摘要中每行列出全量包名，不截断 |
| `-f, --force` | flag | 关 | 忽略增量缓存强制重建 |

容器与资源（build / shell / debug 共用）：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `--backend <chroot\|nspawn>` | enum | 配置 `backend`（默认 nspawn） | 容器后端 |
| `-n, --no-network` | flag | 关 | 禁用构建容器网络 |
| `--memory-max <SIZE>` | string | — | 硬内存上限（仅 nspawn，如 `4G`） |
| `--cpu-quota <QUOTA>` | string | — | CPU 配额（仅 nspawn，`200%` = 2 核） |

运行模式：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `--remote <URL\|NAME>` | string | — | 提交到远程 crbs-server（URL 或 profile 名；配置了 `remote.default` 可省略） |
| `--token <TOKEN>` | string | — | 远程 API token（解析顺序：`--token` > profile 的 token/token_env/token_file > `CRBS_TOKEN`） |
| `--ca-cert <PATH>` | path | — | 远程 server CA 证书（解析顺序：profile `ca_cert` > `CRBS_CA_CERT` > 系统信任库） |
| `--local` | flag | — | 强制本地直接构建，忽略配置的 `remote.default`（与 `--remote`/`--daemon` 互斥） |
| `--daemon` | flag | — | 使用本地 daemon（未运行时自动拉起，失败回退本地直连） |
| `--detach` | flag | 关 | 提交后立即返回任务 ID（本地派生后台 worker，远程走 server；与 `--attach`/`--follow-logs`/`--chain` 互斥） |
| `--attach <ID>` | string | — | 接入已存在的本地/远程任务，等待完成并返回语义化退出码 |
| `--download` | flag | 关 | 远程构建成功后自动把产物下载到本地 result_dir（默认留在 server） |

复现（reproduce）：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `--reproduce <TASK_ID>` | string | — | 复现指定任务的锁定依赖快照并重建（环境级一致性校验） |
| `--reproduce-keep-tmp-on-failure` | flag | 关 | 复现失败时保留临时 repo 和 base_os 供调试 |
| `--no-reproduce` | flag | 关 | 本次构建不记录 provenance（之后无法 reproduce；与 `--reproduce` 互斥） |
| `--repro-from-srpm` | flag | 关 | 从 SRPM 头回放 BUILDHOST/BUILDTIME（头字段同源；环境不还原、payload 不保证一致；与 `--reproduce`/`--chain` 互斥） |

输出：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `--format <text\|json>` | enum | `text` | json 仅输出最终摘要，适合 CI/脚本 |
| `--follow-logs` | flag | 关 | 实时显示/拉取构建日志（本地单包、远程 wait/attach 模式） |

```bash
crbs build hello.src.rpm -p fedora
crbs build *.src.rpm -p fedora -C                 # 链式批量构建
crbs build pkg.src.rpm -p fedora --format json | jq -r '.packages[].result_dir'
crbs build pkg.src.rpm -p fedora --remote prod --detach
crbs build --attach 42 --follow-logs
crbs build -p fedora --reproduce 42
crbs build pkg.src.rpm -p fedora --backend nspawn --memory-max 4G --cpu-quota 200%
```

远程构建注意事项：多 SRPM 批量提交时 client 流式构造 multipart（不整读内存）；`--chain` 目前只支持本地路径与 `--daemon`，不支持 `--remote`；`--chain` 与 `--detach` 暂不支持组合。

## `crbs shell` — 进入产品环境

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<product>` | 位置参数 | 必填 | 产品名 |
| `-c <CMD>` | string | — | 非交互式执行命令（非零退出按失败处理，exit 2） |
| `--bind host[:container[:ro\|rw]]` | 可重复 | — | 挂载宿主目录到容器 `/mnt/`（省略容器路径时用 `/mnt/<basename>`，默认只读） |
| 容器参数 | — | — | `--backend` / `--no-network` / `--memory-max` / `--cpu-quota`，同 `build` |
| `--format` | enum | `text` | `text` / `json` |

```bash
crbs shell fedora
crbs shell fedora -c "sudo dnf install -y vim"
crbs shell fedora --bind /home/user/patches:/mnt/patches:rw
```

## `crbs clean` — 清理产品环境

卸载挂载点、删除产品目录。选项：`--remote`/`--token`/`--ca-cert`（产品配置的 hub 来源，语义同 `init`）、`--yes` 跳过确认、`--format`。

```bash
crbs clean fedora
crbs clean fedora --yes    # 脚本/非交互场景
```

## `crbs debug` — 复现某次构建的环境

进入指定任务构建时的环境，并自动完成 rpmbuild 之前的编包准备：留档的 `result_dir/crbs-build.sh` 同时加载到容器 `/crbs-build.sh`，其截断版（ccache-init → install-srpm → install-deps）自动执行——进 shell 时 SRPM 已解包到 `/builddir`、依赖已装齐，可直接手动 `rpmbuild -ba`。准备阶段任一步失败（含 builddep 失败）不阻断，落入 shell 手动排查；SRPM 或留档脚本缺失时跳过准备，退化为纯环境复现。位置参数 `<task>` 为构建 ID（本地执行域的增量整数，`crbs status` 第一列），其余参数（`-c`、`--bind`、容器参数、`--format`）同 `crbs shell`。必须使用构建时的 backend，否则报错；仅支持本地环境。

debug 使用构建记录中锚定的产品配置快照，环境与构建时同源，不受 hub 当前产品配置或磁盘 TOML 后续变更影响。旧构建无快照（或快照不可解析）时回落到当前产品配置并输出告警。

```bash
crbs debug 42
crbs debug 42 --bind /tmp/repro:/mnt/repro:rw
```

## `crbs status` — 查看构建历史

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `[TASK]` / `--task <ID>` | string | — | 查看单任务详情及其子构建（两种形态互斥） |
| `-p, --product <NAME>` | string | — | 按产品过滤 |
| `-l, --limit <N>` | usize | `20` | 显示条数（0 = 全部） |
| `--all` | flag | 关 | 显示所有用户（默认只显示自己的） |
| `--filter <phase>` | 列表 | — | 按状态过滤，逗号分隔：succeeded,failed,building,pending,timeout,cancelled |
| `--label KEY=VALUE` | string | — | 按任务标签精确过滤（本地与远程同语义；缺 `=` 报错）。单任务详情回显该任务的全部标签（按 key 排序） |
| `--watch` | flag | 关 | 每 2 秒实时刷新（与 `--format`/`--profile` 互斥） |
| `--profile` | flag | 关 | 查看单个子构建的性能档案（此模式 ID 为 build ID） |
| `--repair` | flag | 关 | 修复残留的活跃构建记录（phase=building/pending 但进程已退出），并清理超过 24 小时的本地 detach 请求临时文件 |
| `--remote` / `--token` / `--local` | — | — | 查询远程 server（见「远程通用三元组」） |
| `--format` | enum | `text` | `text` / `json`（输出完整构建记录） |

表格额外显示 `ELAPSED`（已运行/耗时）与 `PROGRESS`（pending 队列位置、building 运行中）。单任务详情的子构建表含 `Worker` 列（执行节点名，纯归档排障信息；本地构建为 `-`）。

`--format json` 的输出约定：单任务详情的 `builds` 为按 arch 索引的字典，
键值恒为数组（`.builds["x86_64"][0].phase`），同 arch 的多个 SRPM 不会
丢失，缺少 arch 的遗留构建归入 `unknown`；每项包含 `duration_seconds` 与
可选 `worker`。`lineage` 为命名字段（`replay_source` 与 `replays`）。
时间统一为 RFC3339 UTC。

```bash
crbs status -p fedora -l 50
crbs status 42
crbs status --remote prod --format json
```

## `crbs logs` — 查看构建日志

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<task>` | 位置参数 | 必填 | 完整数字 task id |
| `-f, --follow` | flag | 关 | 实时跟踪（类似 tail -f；与 `--format` 互斥） |
| `-n, --lines <N>` | usize | 50 | 最后 N 行（0 = 全部；远程 `--follow` 拒绝显式 `-n`） |
| `-g, --grep <PAT>` | 可重复 | — | 过滤包含指定串的行（OR 关系） |
| `-e, --editor` | flag | 关 | 编辑器只读打开（`$CRBS_LOG_VIEWER` > `$EDITOR` > `vim -R` > `vi -R`；与 `--format` 互斥） |
| `-a, --arch <ARCH>` | string | — | 多架构任务选择对应子构建日志 |
| `--remote` / `--token` / `--local` | — | — | 拉取远程 server 日志 |
| `--format` | enum | `text` | `text` / `json` |

```bash
crbs logs 42 -f
crbs logs 42 -n 20 -g error
crbs logs 42 -f --remote workstation
```

## `crbs cancel` — 取消构建

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<task>` | 位置参数 | 必填 | 完整数字 task id；本地发送 SIGTERM，远程/daemon 走 HTTP cancel，级联取消子构建 |
| `--remote` / `--token` / `--local` | — | — | 远程通用三元组 |
| `--format` | enum | `text` | `text` / `json` |

非 root 用户只能取消自己的任务（权属校验）；构建过程中按一次 `Ctrl+C` 等价取消，清理收尾阶段的重复信号被忽略（避免留下孤儿挂载）。

```bash
crbs cancel 42
crbs cancel 42 --remote https://crbs.example.com --token <API_TOKEN>
```

### 远程通用三元组

`status` / `logs` / `cancel` / `sign` / `download` / `builds` 六命令共享 `RemoteCommonArgs`：`--remote <URL|NAME>`（远程目标）、`--token <TOKEN>`、`--local`（强制本地，忽略 `remote.default`；与 `--remote` 互斥）。未指定 `--remote` 且无 `remote.default` 时为本地。

## `crbs verify` — 产物字节级比对

本地双任务 RPM 产物逐包 sha256 比对；省略第二个任务 = 同任务内各构建两两互比（内部一致性）。参数：`<task_a>`、`[task_b]`、`--format`。

```bash
crbs verify 42 43
```

## `crbs diff` — 构建差异对比

比较两个构建的产物与 profile 差异，输出结构化差异报告。参数：`<left>`、`<right>`（构建 ID）、`--format`。

```bash
crbs diff 42 43
```

## `crbs sign` — GPG 签名

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<task>` | 位置参数 | 必填 | 任务 ID |
| `-k, --key-id <ID>` | string | 全局配置 | 指定密钥 |
| `--gpg-home <PATH>` | string | 当前用户 keyring | 指定 GPG home |
| `--remote` / `--token` / `--local` | — | — | 远程签名（hub 集中签名，operator+） |
| `--ca-cert <PATH>` | path | — | hub TLS CA 证书 |
| `--format` | enum | `text` | `text` / `json` |

```bash
crbs sign 42
crbs sign <task_id> --remote hub --token <operator-token>
```

## `crbs download` — 下载构建产物

profile 未配置 token 时自动走匿名受限端点（`/api/v1/public/*`）：仅公开产品可下，`public_access.download` 关闭时匿名被 401 拒绝；SRPM 默认不下载，需 `--src` 显式开启（仍受 `allow_srpm_download` 角色门约束，失败仅警告一次并跳过）。带 token 则走常规认证链路，行为不变。

`--logs` 同时覆盖构建期自定义日志约定目录：构建脚本放入 `/builddir/result/crbs-logs/` 的普通文件（不限扩展名、可嵌套子目录）随产物登记为日志，`--logs` 下载时按相对子目录结构落盘（`{arch}/crbs-logs/...`）；目录本身不上传，缺失或为空时不可见。

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `<task>` | 位置参数 | 必填 | 任务 ID |
| `-o, --output-dir <DIR>` | path | 当前目录 | 输出目录 |
| `--src` | flag | 关 | 含源码包 SRPM（默认跳过；下载时仍受 `allow_srpm_download` 角色门约束，失败仅警告一次） |
| `--arches <ARCH>`（别名 `--arch`） | 列表 | 全部 | 只下载这些架构的子构建产物（逗号分隔或可重复；任务里不存在的架构静默忽略） |
| `--debuginfo` | flag | 关 | 含 debuginfo/debugsource/debug 包（默认跳过） |
| `--logs` | flag | 关 | 含 build.log 与 crbs-logs/ 约定目录全部文件（默认跳过；保留子目录结构落盘） |
| `--force` | flag | 关 | 覆盖输出目录已存在文件（默认冲突即失败） |
| `--remote` / `--token` / `--local` | — | — | 远程通用三元组 |
| `--format` | enum | `text` | `text` / `json` |

```bash
crbs download 42 --output-dir ./rpms
```

## `crbs builds` — 构建产物管理

| 子命令 | 说明 |
|--------|------|
| `show <id>` | 查看产物列表（文件 + 元数据） |
| `publish <id>` | 把产物发布进产品 repo（远程；admin/operator/提交者） |
| `unpublish <id>` | 从产品 repo 移除（可逆，旧版本可能重新浮现） |

父命令级选项：`--remote` / `--token` / `--local`（须置于子命令之前）、子命令 `--format`。

```bash
crbs builds show 42 --remote prod
crbs builds publish 42 --remote prod
```

## `crbs rebuild` — 服务端整仓重建批次

按源仓库批量重建产品存量包（operator/admin，仅远程；批次内按依赖拓扑分轮、按包名增量跳过）。父命令级选项：`--remote` / `--token` / `--local`（global，置于子命令前后均可）。

`rebuild submit`：

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-p, --product <NAME>` | string | 必填 | 产品名 |
| `--repo <URL>` | string | 必填 | 源仓库 URL（http/https/file），必须指到含 `repodata/` 的仓库层 |
| `--dist <TAG>` | string | — | 重建包的 `%dist` 宏 |
| `--arch <ARCH>` | 列表 | 产品 arches | 目标架构，逗号分隔或可重复 |
| `--force` | flag | 关 | 忽略增量缓存全量重建 |
| `--on-failure <continue\|abort>` | enum | `continue` | 包失败时的批次行为 |
| `--allow-dist-mismatch` | flag | 关 | 显式允许与源仓 tag 的 dist 不匹配（否则 fail-closed） |
| `--dry-run` | flag | 关 | 只做枚举 + 增量预览，不落库不下载 |

`rebuild status`：`--id <ID>`（与 `--latest` 互斥）、`--latest`（最近批次）、`-f, --follow`（每 5s 刷新直到终态）。`rebuild cancel`：`--id <ID>`（级联取消在飞构建）。

```bash
crbs rebuild submit -p demo --repo <url> --dry-run --remote hub
crbs rebuild submit -p demo --repo <url> --force --remote hub
crbs rebuild status --id <id> --follow --remote hub
crbs rebuild cancel --id <id> --remote hub
```

三个子命令（submit / status / cancel）均支持 `--format <text|json>`：status 的 JSON 为 `{command, batch, rounds[], failures[]}`（batch 计数键不带 `n_` 前缀、时间 RFC3339 UTC）；`--format json` 与 `--follow` 互斥。

## `crbs products` — 产品管理

不带子命令时列出产品。父命令级选项（global）：`--remote` / `--token` / `--local` / `--format`。

| 子命令 | 说明 |
|--------|------|
| `show <product>` | 查看产品详细配置（base packages、repos、macros 等） |
| `create <product> --config-file <PATH>` | 创建产品（仅远程）；body 配置读自 TOML 文件；可选 `--display-name` / `--parent-id` / `--reason` |
| `update <product> --config-file <PATH> --expected-revision <N>` | 更新配置（仅远程）；乐观锁 revision 不匹配报 HTTP 409；re-parent 用 `--parent-id <ID>` 或 `--detach-parent`（互斥，都不传则不动） |
| `fork <parent> <new_name>` | 派生产品：默认 activelink（空配置 + 继承父链），`--detached` 快照父链解析结果为独立配置 |
| `delete <product>` | 删除 DB 产品行（仅远程；不触碰磁盘产物——那是 `clean` 的事）；`--yes` 跳过确认 |
| `clean <product>` | 清理 hub 上的发布仓库与磁盘产物（admin 角色，异步任务，有活跃构建时拒绝）；`--yes` 跳过确认 |
| `history <product>` | 配置 revision 历史；`--revision <N>` 查特定版本 |
| `export <product>` | 导出 chain-resolved 配置为 TOML（`--file <PATH>` 写文件，缺省 stdout） |
| `publish <product>` / `unpublish <product>` | 公开 / 私有切换（仅远程）；可选 `--reason` |
| `transfer <product> <new_owner>` | 所有权转让（转让时自动取消相关构建任务）；可选 `--reason` |
| `acl <sub>` | ACL 管理：`list <product>`、`grant <product> <user> [--role viewer\|builder\|admin]`（默认 viewer）、`revoke <product> <user>` |

```bash
crbs products
crbs products show fedora --remote workstation
crbs products publish foo
crbs products transfer foo alice
crbs products acl grant foo bob builder
```

## `crbs gc` — 清理

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-r, --results` | flag | 关 | 清理过期结果目录 |
| `-p, --product <NAME>` | string | — | 限定产品（需配合 `-r`/`--policy`） |
| `-d, --dry-run` | flag | 关 | 预览不删除 |
| `-o, --orphan-mounts` | flag | 关 | 扫描并清理所有产品的孤儿挂载点（含 shared_layers_dir） |
| `--cache` | flag | 关 | 清理无引用包缓存 |
| `--all` | flag | 关 | 跳过引用检查删除所有包缓存（需配合 `--cache`；非交互必须 `--yes`） |
| `--policy` | flag | 关 | 执行已配置的策略 GC（result 条数/保留天数 + package_cache 容量） |
| `--yes` | flag | 关 | 跳过确认提示 |
| `--format` | enum | `text` | `text` / `json` |

`gc` 需要完整特权（跨用户回收）。注意 `--cache --all` 会破坏所有历史构建的 `--reproduce`。

```bash
crbs gc
crbs gc -rd
crbs gc --policy -d
```

## `crbs ping` / `crbs whoami`

连通性与身份探测，选项一致：`--remote` / `--token` / `--ca-cert` /
`--daemon` / `--format`。

- `ping`：探活与认证检查。
- `whoami`：显示当前身份与角色。

```bash
crbs ping --daemon
crbs whoami --remote prod
```

## `crbs admin` — 管理员操作

`admin init <product>`：远程（重新）初始化 worker 上的 base_os。

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `-w, --worker <ID>` | 可重复 | — | 目标 worker 数字 ID（如 `-w 1 -w 2`；与 `--all` 互斥） |
| `--all` | flag | — | 派发到所有在线 worker（与 `-w` 互斥；都不指定则报错） |
| `-y, --yes` | flag | — | 跳过交互确认 |
| `--remote` / `--token` / `--ca-cert` / `--format` | — | — | 远程连接与输出 |

`admin rebuild-repo <product>`：从当前 DB 状态重建产品发布仓库（admin only）；选项同上。

```bash
crbs admin init fedora -w 1 -w 2 --remote prod
crbs admin rebuild-repo fedora --remote prod
```

## `crbs remote` — 远程 profile 管理

读写本地配置（list/test 读系统 + 用户级合并视图；add 只写用户级 `~/.config/crbs/crbs.toml`，注释保留式编辑）。

| 子命令 | 说明 |
|--------|------|
| `list` | 列出已配置 profile（name / URL / 鉴权方式，token 值不回显） |
| `test <profile>` | 用 ping 端点做连通 + 鉴权自检（回报 URL 与认证身份） |
| `add <name> --url <URL>` | 添加 profile；`--token-env <VAR>` / `--token-file <PATH>` / `--token <TOKEN>` 三选一（互斥，都不给则匿名访问并告警）；`--ca-cert <PATH>`；`--use-default` 写入 `remote.default`（之后 `--remote` 可省略）。已存在同名 profile 报错（无 `--force`）；删除/编辑直接改配置文件 |

```bash
crbs remote add prod --url https://hub.example.com --token-env CRBS_PROD_TOKEN --use-default
crbs remote list
crbs remote test prod
```

三个子命令（list / test / add）均支持 `--format <text|json>`；任何形态不回显 token 值。

## `crbs config` — 配置 schema

`crbs config schema`：导出配置文件 JSON Schema（draft-07）到 stdout，零副作用不读配置；覆盖 crbs.toml、server.toml、产品配置与 worker 配置。

```bash
crbs config schema > crbs-config.schema.json
```

## `crbs completions` — Shell 补全

`crbs completions <bash|zsh|fish|powershell>` 生成补全脚本。zsh / Oh My Zsh 安装步骤、补全覆盖范围与排障见 [`../operations/zsh-completion-guide.md`](../operations/zsh-completion-guide.md)。

```bash
crbs completions bash > /etc/bash_completion.d/crbs
crbs completions zsh > /usr/share/zsh/site-functions/_crbs
crbs completions fish > ~/.config/fish/completions/crbs.fish
```

## `crbs-server` 命令

独立二进制 `crbs-server`（hub）。全局选项：`--config-dir <DIR>`（默认 `/etc/crbs`，也可用 `CRBS_CONFIG_DIR` 环境变量，必须是非空绝对路径）。

| 命令 | 说明 | 常用选项 |
|------|------|----------|
| `run` | 启动 HTTP API server | `-l, --listen`（默认 127.0.0.1:9090）、`--allow-product-management` 启用产品 init/clean 端点、`--shutdown-timeout` 优雅退出超时、`--web-ui-enabled {true,false}` |
| `local start\|stop\|status` | 管理本地 daemon | `--run-dir` pid/port 文件目录 |
| `user add <name>` | 创建 DB 用户 | `--role {viewer,builder,operator,admin}`（默认 builder） |
| `user list` | 列出 DB 用户 | — |
| `user set-role <name> <role>` | 修改用户角色 | — |
| `user disable <name>` | 禁用用户 | — |
| `user set-password <name>` | 设置密码（stdin 读入，长度 10–1024） | `--must-change` 下次登录必须改密 |
| `token create <name>` | 发行 DB token（只显示一次） | `--name` 备注、`--expires` 过期天数（上限 3650） |
| `token list <name>` | 列出用户 token | — |
| `token revoke <name> --id <N>` | 撤销 token | `--id` token ID |
| `worker add <name>` | 注册 worker 并生成密钥（仅显示一次） | `--arch`、`--capacity`（默认 1）、`--output-config <PATH>` 直接产出可部署 worker.toml（需 `--hub-url`，可选 `--hub-ca-cert` / `--build-dir` / `--crbs-root` 覆盖默认路径） |
| `worker list` | 列出 worker（密钥脱敏） | — |
| `worker rotate-secret <name>` | 轮换密钥（旧密钥立即失效） | `--output-config` 同上 |
| `worker revoke-secret <name>` | 撤销密钥（worker 无法再认证） | — |
| `worker remove <name>` | 删除 worker 节点 | — |
| `product acl grant <product> <user>` | 授予产品权限（admin/owner） | `--role {viewer,builder,admin}` |
| `product acl revoke <product> <user>` | 撤销产品权限 | — |
| `product acl list <product>` | 列出产品授权用户 | — |
| `gpg import` | 导入 GPG 私钥到 server keyring | `--key-file <PATH>` |
| `gpg list` | 列出 server keyring 密钥 | — |
| `gpg export` | 导出 GPG 公钥 | `--armor` |
| `audit list` | 查询审计日志 | `--limit <N>`、`--user`、`--action` |

```bash
sudo -u crbs-server crbs-server user add alice --role builder
sudo -u crbs-server crbs-server token create alice --name laptop --expires 30
sudo -u crbs-server crbs-server worker add worker-01 --arch x86_64 \
    --output-config /etc/crbs/worker.toml --hub-url https://<hub>:18443
crbs-server run
crbs-server local start
crbs-server audit list --user alice
```

本地 daemon（可选）：`crbs build --daemon` 使用；配置见 [`configuration.md`](configuration.md) 的 server.toml `[local]` 段。

## 退出码

crbs 用细分退出码区分错误类别，便于 CI 脚本做不同策略：

| 码 | 含义 | 典型场景 |
|----|------|----------|
| 0 | 成功 | 构建成功完成 |
| 1 | 未分类内部错误 | 不应发生，需排查 |
| 2 | 构建失败 | depsolve 失败、容器执行失败、签名失败、层创建失败 |
| 3 | 中断 | 超时、取消（Ctrl+C / `crbs cancel`） |
| 4 | 配置 / 参数错误 | 产品名为空、SRPM 不存在、仓库配置错误、乐观锁 revision 不匹配、资源冲突（409 族）、spec 架构约束与目标架构冲突（`ExclusiveArch`/`ExcludeArch`，构建前预检与构建期 rpmbuild 裁决命中同归类）、`--target` 不在产品构建架构集合内 / 与本地宿主架构不符 |
| 5 | 权限错误 | 非 root 且不在 crbs 组、跨用户操作 |
| 6 | 环境错误 | IO 错误、数据库错误、cgroup 设置失败 |

## JSON 输出格式

`--format json` 抑制所有进度输出，仅在完成后输出一个 JSON 对象（stdout；`RUST_LOG`/`-v` 的日志走 stderr，不影响解析）。text 模式默认只显示简洁状态行，实时日志用 `--follow-logs`。

```json
{
  "command": "build",
  "product": "fedora",
  "outcome": "succeeded",
  "summary": { "total": 1, "succeeded": 1, "failed": 0, "cancelled": 0, "timeout": 0 },
  "packages": [
    { "srpm": "tmux-3.6b-1.fc44.src.rpm", "build_id": 42, "outcome": "succeeded",
      "duration_seconds": 42, "retries": 0,
      "result_dir": "/var/lib/crbs/results/fedora/tmux/20260617-011212-a7329818" }
  ]
}
```

- `--chain` 模式下 `summary` 额外包含 `cached`/`dep_skipped`/`cycle_failed` 计数；`--chain --order-only` 输出 `mode: "chain-plan"` 对象。
- `--reproduce --format json` 额外输出 `verification` 三计数：`environment_packages`（原始构建的环境包总数）、`restored_packages`（从 package cache 按 SHA256 恢复的包数）、`produced_rpms`（本次产出 RPM 数）。
- 成功信封统一：所有 `--format json` 的成功输出都是含 `command` 键的顶层 JSON 对象——裸数组输出会包一层复数键（如 `{"command":"status","tasks":[...]}`），透传服务端响应只平铺加 `command`。
- 错误时输出信封而非人类文本（`outcome` 恒为 `"error"`；main 早期失败——参数解析、配置加载——不在此口径内）：

```json
{ "command": "build", "outcome": "error", "error": { "code": "sign_failed", "message": "..." } }
```

- 可空字段缺省的双轨口径：透传服务端 schema / 显式构造的固定键输出恒显式 `null`（键集稳定）；CLI 手写 struct 统一省键（键在即有值），脚本对手写体需容忍键缺省。
