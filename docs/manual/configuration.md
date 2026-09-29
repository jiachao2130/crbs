# CRBS 配置参考

配置文件默认位于 `/etc/crbs`，可用 `CRBS_CONFIG_DIR` 重定位：

| 文件 | 读取者 | 职责 |
|------|--------|------|
| `crbs.toml` | `crbs` CLI / BuildEngine | 引擎全局配置与客户端远程 profile |
| `server.toml` | `crbs-server` | 监听、认证、TLS、调度、DB 保留策略 |
| `worker.toml` | `crbs-worker` | worker 连接信息与本地资源 |
| `products/<product>.toml` | 引擎 / hub seed | 产品配置 |

逐键注释的样例见 [`../../examples/config/`](../../examples/config/)。
`crbs config schema` 可导出 JSON Schema（draft-07）。

## 1. 合并优先级

引擎侧配置分三层，优先级由低到高：

1. 硬编码默认值；
2. `CrbsConfig`（`/etc/crbs/crbs.toml`，所有产品共享）；
3. `ProductConfig`（`products/<product>.toml`，按产品覆盖）；
4. CLI 旗标（最高，如 `--backend`、`--jobs`）。

产品 TOML 省略字段表示继承全局值；`rpm_macros` 与 hooks 按产品优先合并。
`crbs_root` 是机器级配置，产品 TOML 中设置会被忽略并告警。

引擎世界与 server 世界使用不同的 root：引擎 root 由 `crbs.toml` 的
`crbs_root` 决定（默认 `/var/lib/crbs-engine`），server root 由
`server.toml` 的 `crbs_root` 决定（默认 `/var/lib/crbs`）。`result_dir`
与 `shared_layers_dir` 未配置时各随所属 root 派生。

## 2. crbs.toml

### 2.1 路径与数据库

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `crbs_root` | string | `/var/lib/crbs-engine` | 引擎数据根目录；机器级配置 |
| `result_dir` | string | `{crbs_root}/results` | 构建结果目录，按 `{product}/{pkg}/{timestamp-uuid}/` 存放 |
| `shared_layers_dir` | string | `{crbs_root}/shared_layers` | 共享层目录，按 BuildRequires 指纹（blake3）组织 |
| `database_url` | string | — | 状态库连接 URL；未配置时使用 SQLite `{crbs_root}/crbs.db` |
| `product_root` | string | `{crbs_root}/{product}` | 产品根目录 |
| `base_os_path` | string | `{product_root}/base` | base OS 层路径 |
| `dnf_cache_path` | string | `{product_root}/dnf-cache` | DNF 缓存目录，`dnf_cache_enabled = true` 时生效 |
| `package_cache_path` | string | `{crbs_root}/cache/packages` | 包缓存目录，供复现与 deterministic 构建使用 |

### 2.2 构建用户

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `builder_user` / `builder_uid` | string / int | `ccbuilder` / `10010` | 构建用户在 init 时创建，chroot 内执行 rpmbuild |
| `builder_group` / `builder_gid` | string / int | `ccbuilder` / `10010` | 构建组 |

### 2.3 构建行为

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `shared_layer` | bool / 列表 | `false` | 依赖缓存：`false` 关闭，`true` 全局启用，列表仅对指定包启用 |
| `build_tmpfs` | bool | `false` | 使用 tmpfs 加速构建目录；shared_layer 关闭时整个构建目录在 tmpfs，开启时仅 BUILD 目录。单实例默认上限为宿主内存的 50%，并发构建时应配置 `memory_max` 或预留足够内存 |
| `ccache_enabled` | bool / 列表 | `false` | 编译缓存，启用后自动把 ccache 加入 base_packages |
| `ccache_dir` | string | `{crbs_root}/ccache/{product}` | ccache 目录；全局值不参与合并，按产品派生 |
| `ccache_max_size` | string | `4G` | ccache 容量上限 |
| `dnf_cache_enabled` | bool | `false` | 绑定宿主 `/var/cache/dnf` 与 `/var/cache/libdnf5` |
| `build_target` | string | `bb` | rpmbuild 阶段（bb / bs / ba），CLI `--stage` 优先 |
| `backend` | string | `nspawn` | 容器后端（nspawn / chroot），CLI `--backend` 优先 |
| `memory_max` / `cpu_quota` | string | — | nspawn 资源限制；chroot 后端忽略 |
| `max_concurrent_builds` | int | `0`（CPU 核数） | 本地并发数，CLI `--jobs` 优先 |
| `build_max_retries` | int | `1` | transient 失败的最大额外重试次数，`0` 不重试 |
| `build_retry_backoff_ms` | int | `1000` | 重试基础退避毫秒数 |
| `releasever` | string | 宿主 `/etc/os-release` | dnf `--releasever` 值 |
| `shared_layer_max_retries` | int | `2` | 共享层创建失败重试次数 |
| `shared_layer_staleness` | string | — | 共享层陈旧时长（如 `7d` / `720h`），超期重建；未配置不判陈旧 |
| `rpm_macros` | table | `{}` | 全局 RPM 宏；`_topdir` 固定为 `/builddir`，不可覆盖 |

### 2.4 GC 与保留

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `shared_layer_gc_grace_hours` | int | `168` | 共享层引用归零后的保留时长 |
| `result_gc_grace_hours` | int | `720` | result 目录 GC 宽限期，清理时保留 builds 表记录 |
| `result_max_count_per_pkg` | int | — | 单包保留的 result 目录上限 |
| `result_retention_days` | int | — | result 目录最长保留天数 |
| `package_cache_max_size_gb` | int | — | 包缓存容量上限，按 0.9 倍 LRU 淘汰 |
| `package_cache_evict_referenced` | bool | `false` | 容量不足时是否淘汰仍被引用的缓存 |
| `package_url_cache_ttl_days` | int | `90` | 包 URL 缓存保留天数，`0` 不清理 |
| `base_snapshot_keep_generations` | int | `0`（不清理） | base 快照保留代数 |

### 2.5 运行时与复现

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `shared_layer_poll_interval_ms` | int | `100` | 共享层 flock 轮询间隔 |
| `shared_layer_timeout_secs` | int | `60` | 共享层 flock 超时 |
| `resource_sample_interval_secs` | int | `15`（`0` 关闭） | proc 口径资源采样间隔 |
| `resource_sample_interval_cgroup_secs` | int | `5`（`0` 关闭） | cgroup 口径资源采样间隔，与 proc 口径独立 |
| `reproduce_enabled` | bool / 列表 | `false` | 记录 provenance（URL、SHA256、build_packages.json） |
| `gpg_signing_key_id` | string | — | GPG 签名密钥 ID（邮箱或指纹） |
| `gpg_signing_enabled` | bool | — | 显式签名开关；缺省以是否配置 key id 为准 |
| `gpg_home` | string | 当前用户 keyring | GPG keyring 路径 |
| `use_privileged_helper` | string | `auto` | 特权 helper 探测（auto / on / off） |
| `privileged_helper_path` | string | — | 显式指定 helper 路径 |

### 2.6 Hooks

`[hooks.pre]` 与 `[hooks.post]` 按 step 注入脚本，可用 step：`ccache-init`、
`install-srpm`、`install-deps`、`build`、`ccache-summary`。
`[hooks.spec.pre]` / `[hooks.spec.post]` 以 rpmbuild spec 阶段名为 key：

```toml
[hooks.pre]
install-srpm = "echo 'installing srpm'"

[hooks.post]
build = "echo 'build finished'"

[hooks.spec.pre]
prep = "echo 'enter %prep'"
```

### 2.7 远程 profile

仅在客户端执行远程操作时读取，推荐放在用户级 `~/.config/crbs/crbs.toml`：

```toml
[remote]
default = "hub"

[[remote.profiles]]
name = "hub"
url = "https://hub.example.com:18443"
token_env = "CRBS_TOKEN"

[[remote.profiles]]
name = "lab"
url = "https://lab.example.com:18443"
token_file = "~/.crbs/lab.token"
ca_cert = "/etc/crbs/certs/ca.crt"
```

`[remote]` 表必须位于 `[[remote.profiles]]` 之前。该段可用
`crbs remote add` 生成，删除与就地编辑直接修改文件。

## 3. 产品配置

产品配置位于 `products/<product>.toml`，`base_packages` 与 `repos` 必填，
其余字段省略时继承全局值。`crbs init <product> --offline` 可生成模板，
完整样例见 [`../../examples/config/fedora.toml`](../../examples/config/fedora.toml)。

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `base_packages` | 列表 | 必填 | 基础包；CRBS 自动注入 bash、coreutils、shadow、sudo、dnf、gawk 等 |
| `[[repos]]` | 数组 | 必填 | 仓库配置，init 时写入 base_os。支持 dnf 原生键：`priority`、`cost`、`module_hotfixes`、`exclude`、`includepkgs` 与 `extra` |
| `arches` | 列表 | — | 产品支持的架构；省略为单架构模式 |
| `overlay_dir` | string | — | 覆盖层目录，必须位于 `/etc/crbs/overlays/` 下 |
| `[[post_init]]` | 数组 | — | init 后执行的命令；`ignore_failure = true` 时失败仅告警 |
| `+base_packages` / `+repos` / `+arches` / `+post_init` | 列表 | — | 子产品追加语法，追加到父链合并值之后 |
| `builder_user` / `builder_uid` / `builder_group` / `builder_gid` | — | 继承 | 构建用户与组 |
| `result_dir` / `shared_layers_dir` | — | 继承 | 路径 |
| `shared_layer_gc_grace_hours` / `result_gc_grace_hours` | — | 继承 | GC 宽限期 |
| `shared_layer` / `build_tmpfs` | — | 继承 | 缓存开关 |
| `ccache_enabled` / `ccache_dir` / `ccache_max_size` | — | 继承 | ccache |
| `dnf_cache_enabled` | — | 继承 | DNF 缓存 |
| `build_target` / `backend` / `memory_max` / `cpu_quota` | — | 继承 | 构建目标与资源限制 |
| `network` | bool | `true` | `true` 共享宿主网络，`false` 使用隔离网络 |
| `local_repo` | string | — | chain 构建的本地 repo 路径 |
| `chain_parallelism` | int | — | chain 同轮并行包数 |
| `chain_max_recovery_rounds` | int | — | chain 依赖解析最大恢复轮数 |
| `build_max_retries` / `build_retry_backoff_ms` | — | 继承 | 重试策略 |
| `releasever` / `product_root` / `base_os_path` / `dnf_cache_path` | — | 继承 | 路径与发行版 |
| `shared_layer_staleness` / `shared_layer_max_retries` | — | 继承 | 共享层策略 |
| `resource_sample_interval_secs` / `resource_sample_interval_cgroup_secs` | — | 继承 | 资源采样 |
| `[resource_overrides.<pkg>]` | table | — | 按包覆盖 `mem_gb` / `cpu_cores`，优先于全局限制 |
| `package_cache_max_size_gb` / `package_cache_evict_referenced` | — | 继承 | 包缓存策略 |
| `result_max_count_per_pkg` / `result_retention_days` | — | 继承 | 结果保留 |
| `package_url_cache_ttl_days` | — | 继承 | URL 缓存 TTL |
| `reproduce_enabled` | — | 继承 | provenance 开关 |
| `gpg_signing_key_id` / `gpg_home` / `gpg_signing_enabled` | — | 继承 | GPG 配置 |
| `nocheck` / `noclean` / `nodebuginfo` | bool | 继承 | 跳过 `%check`、跳过清理段、不生成 debuginfo |
| `[rpm_macros]` | table | — | RPM 宏，与全局合并且产品优先 |
| `[hooks.*]` | table | — | 钩子，与全局合并且产品优先 |
| `deterministic` | bool | `false` | 确定性构建：注入确定性宏组、环境基线与 hostname，强制溯源与完整性硬门；要求 `dnf_cache_enabled = true` 且 `build_target != ba` |
| `repo-publish` | bool | `true` | 发布轴：成功构建的产物是否进入产品 repo；逐构建 `--no-publish` 可进一步收紧 |
| `repo-consume` | bool | `true` | 消费轴：后续构建的 builddep 是否注入本产品 repo；私有产品强制关闭，逐构建 `--no-consume` 可进一步收紧 |
| `allow_srpm_download` | bool | 继承 | 本产品 SRPM 下载权限覆盖；`false` 时仅 operator/admin 可下载 |
| `_buildhost` | string | `"crbs"` | RPM 包头 BUILDHOST 固定值 |
| `auto_replay` | bool | `true` | deterministic 构建成功后自动执行一次锁定环境重放 |
| `replay_sampling` | int | `100` | 自动重放抽样百分比，`0` 关闭，超过 100 按 100 处理 |
| `recipe_retention_days` | int | `90` | recipe 引用 sha256 免于 package cache GC 的钉住天数 |
| `builddep_install_weak_deps` | bool | dnf 默认 | builddep 是否安装 weak deps |
| `noarch_per_arch` | bool | `false` | 纯 noarch SRPM 默认只构建一个子构建；`true` 恢复每架构构建 |
| `noarch_preferred_arches` | string[] | 空 | noarch 构建的宿主架构偏好集；省略表示不限制 |

子产品继承与 `+field` 追加语法的完整说明见
[`../operations/product-management.md`](../operations/product-management.md)。

## 4. server.toml

### 4.1 基础

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `listen` | string | `127.0.0.1:9090` | 监听地址，CLI `run --listen` 优先 |
| `crbs_root` | string | `/var/lib/crbs` | server 数据根（状态库、uploads、artifacts、run_dir） |
| `max_local_builds` | int | `0`（CPU 核数） | hub 本地构建并发，不影响 worker |
| `build_timeout_secs` | int | `86400` | 本地构建超时兜底，`0` 关闭；请求指定 timeout 时不生效 |
| `scheduler_mode` | string | `auto` | `auto` 为 worker 优先加本地兜底；另可选 `local_only` / `distributed_only` |
| `min_free_disk_gb` | int | `1` | 接受构建所需的最小剩余磁盘，不足返回 422；`0` 禁用 |
| `allow_product_management` | bool | `false` | 是否开放产品 init/clean 端点 |
| `auth_enabled` | bool | `true` | Bearer token 认证；关闭仅允许 loopback |
| `shutdown_timeout_secs` | int | `60` | 优雅退出等待时长，必须 ≥ 1 |
| `upload_max_size_mb` | int | `500` | multipart 上传上限，反向代理需对齐 |
| `db_retention_days` | int | `90` | DB 历史行保留天数，`0` 禁用 |
| `db_max_connections` | int | `8` | 连接池上限；环境变量 `CRBS_DB_MAX_CONNECTIONS` 优先 |
| `gc_result_retention` | int | `100` | 内存中保留的 GC 任务结果条数 |
| `product_result_retention` | int | 复用上一个键 | 内存中保留的产品管理任务结果条数 |
| `low_priority_reserve_ratio` | float | `0.25` | Default 优先级预留的并发槽比例，下限为 1 槽 |
| `force_secure_cookies` | bool | `false` | 反向代理终止 TLS 时必须为 `true`；内置 TLS 时自动生效 |
| `allow_srpm_download` | bool | `true` | `false` 时仅 operator/admin 可下载 SRPM |
| `cors_allowed_origins` | 列表 | 空 | 允许的跨域 Origin |
| `result_dir` / `upload_dir` / `artifact_dir` / `state_db_path` | string | 随 `crbs_root` 派生 | 路径覆盖 |
| `resource_profile_min_peak_rss_kb` | int | `1048576` | 低于该峰值内存的构建不写资源画像，`0` 关闭门槛 |
| `resource_censor_headroom` | float | `1.25` | OOM 删失样本的峰值抬升系数，必须 ≥ 1.0 |
| `resource_requirements_enabled` | bool | `false` | 按构建声明的最小资源过滤可放置节点 |
| `resource_profile_weights_enabled` | bool | `true` | 使用画像学习权重计算节点负载 |
| `resource_local_watermark_enabled` | bool | `false` | hub 本地构建水位门 |
| `resource_dispatch_watermark_enabled` | bool | `true` | 分布式派发水位门 |
| `resource_mem_watermark` | float | `0.90` | 内存水位系数，`used + Σmem` 超过 `total × 系数` 时拒绝 |
| `resource_cpu_watermark` | float | `1.00` | CPU 水位系数，`load1 + Σcpu` 超过 `ncpu × 系数` 时拒绝 |
| `resource_hard_req_stall_secs` | int | `3600` | 硬下限持续拒绝该时长后追加构建 note，`0` 关闭 |
| `resource_steering_enabled` | bool | `false` | 重型构建按资源余量评分选择节点 |
| `resource_heavy_srpm_bytes` | int | `104857600` | heavy 判定的 SRPM 体积阈值，`0` 禁用该判定臂 |
| `resource_learned_gates_enabled` | bool | `false` | 学习门影子记录，仅写决策日志，不改变派发 |
| `resource_tmpfs_gate_enforced` | bool | `false` | 将学习 tmpfs 门升级为真实拒绝 |
| `strict_ownership` | bool | — | 已废弃，仅用于兼容旧配置文件，不参与判定 |

### 4.2 段配置

| 段 | 键 | 默认 | 说明 |
|----|----|------|------|
| `[public_access]` | `view` / `logs` / `download` | 全 `true` | 未认证访客的查看、日志与下载权限；写操作始终需认证 |
| — | `web_ui_enabled` | `true` | Web UI 与 `/` 仪表盘路由开关 |
| `[log_sanitization]` | `redact_tokens` / `redact_urls` / `redact_paths` | `true` / `false` / `false` | 访问日志脱敏 |
| `[tls]` | `cert` / `key` | — | 内置 TLS 证书；不配置则需反向代理终止 TLS |
| `[submit_rate_limit]` | `enabled` / `requests` / `per_secs` | 关闭 | 按用户提交限流 |
| `[local]` | `enable` / `daemon_auto` / `run_dir` / `idle_timeout_secs` | `true` / `false` / `/run/crbs` / `300` | 本地 daemon 配置 |

`[local].run_dir` 默认值：root 为 `/run/crbs`，普通用户为
`{crbs_root}/run`。daemon 在该目录写入 `crbs-server.pid` 与
`crbs-server.port`。

## 5. worker.toml

安装路径 `/etc/crbs/worker.toml`，可由
`crbs-server worker add --output-config` 生成。样例见
[`../../examples/config/worker.toml`](../../examples/config/worker.toml)。

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `name` | string | 必填 | worker 显示名称，建议在 hub 内唯一 |
| `hub_url` | string | 必填 | hub 地址；生产必须为 `https://` |
| `arch` | string | 运行时探测 | 本机架构 |
| `capacity` | int | `1` | 最大并发构建数，范围 1..=1024 |
| `token` | string | 必填 | worker 注册 token（`crbs_wkr_...`），文件权限应设为 `0640 root:crbs` |
| `hub_ca_cert` | string | 系统信任库 | hub CA 证书 |
| `heartbeat_interval_secs` | int | `30` | 心跳间隔，小于 5 加载报错；hub 超过 120s 无心跳标记 offline |
| `poll_timeout_secs` | int | `60` | 任务长轮询超时 |
| `build_dir` | string | `/var/lib/crbs/worker/builds` | 构建工作目录 |
| `result_retention_days` | int | `3` | 本地结果保留天数，`0` 永久保留 |
| `crbs_root` | string | `/var/lib/crbs` | 引擎世界 root |
| `tmp_dir` | string | `/var/tmp` | 构建临时目录，须与 crbs.toml 的 `tmp_dir` 一致 |
| `tmpfs_dir` | string | `/dev/shm` | 历史 tmpfs 目录，须与 crbs.toml 的 `tmpfs_dir` 一致 |
| `startup_mount_gc` | string | `auto` | 启动期孤儿挂载 GC：`auto` / `always` / `never` |
| `build_timeout_secs` | int | `86400` | 构建超时兜底，`0` 关闭 |
| `min_free_disk_gb` | int | `1` | 领任务前磁盘水位门，`0` 关闭 |
| `min_free_mem_mb` | int | `512` | 领任务前内存水位门，`0` 关闭；读取失败放行 |

## 6. 环境变量

| 变量 | 消费者 | 说明 |
|------|--------|------|
| `CRBS_CONFIG_DIR` | crbs-server | 配置目录，默认 `/etc/crbs`，必须为非空绝对路径 |
| `CRBS_TOKEN` | crbs CLI | 远程 token 兜底；优先级低于 `--token` 与 profile |
| `CRBS_CA_CERT` | crbs CLI | CA 证书兜底；优先级低于 profile `ca_cert` |
| `CRBS_DB_MAX_CONNECTIONS` | server / worker / CLI | DB 连接池上限 |
| `CRBS_ALLOW_PLAINTEXT_TOKEN` | crbs CLI | `=1` 时允许向非 loopback HTTP 主机发送 token，仅限开发 |
| `CRBS_LOG_VIEWER` | crbs CLI | `crbs logs -e` 的编辑器首选 |

## 7. SQLite 与 PostgreSQL

状态库支持双后端：

- **SQLite（默认）**：未配置 `database_url` 时使用
  `{crbs_root}/crbs.db`（WAL 模式）；也可显式写
  `sqlite:///path/to/crbs.db`。server 侧可用 `state_db_path` 单独指定。
- **PostgreSQL**：在 `crbs.toml` 配置
  `database_url = "postgres://user:pass@host/dbname"`。该键不属于
  server.toml，写入会被 `deny_unknown_fields` 拒绝。连接池上限由
  `CRBS_DB_MAX_CONNECTIONS` 控制。

方言实现说明见
[`../../crates/crbs-core/src/state/DIALECT.md`](../../crates/crbs-core/src/state/DIALECT.md)。
