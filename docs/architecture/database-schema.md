# CRBS 数据库 Schema 参考

hub 状态库与 engine/worker 本地库共用同一份 baseline。状态库支持双后端：
[`schema.sql`](../../crates/crbs-core/src/state/schema.sql)（SQLite，默认）与
[`schema.pg.sql`](../../crates/crbs-core/src/state/schema.pg.sql)（PostgreSQL）结构等价、
逐表逐索引对齐（等价性由 migrate.rs 的 baseline_equivalence 守卫按表名/索引名比对）。
方言差异（时间列统一 TEXT UTC 墙钟、`AUTOINCREMENT` → `BIGSERIAL`、布尔保持
INTEGER 0/1 不转 BOOLEAN 等）见
[`DIALECT.md`](../../crates/crbs-core/src/state/DIALECT.md)。本文以 schema.sql 为准；
列注释与设计背景的原文见 schema.sql 各列行内注释。

**版本机制（单 baseline + 版本闩）**：无增量迁移。权威实现
[`migrate.rs`](../../crates/crbs-core/src/state/migrate.rs)——`SCHEMA_VERSION = 1`、
`SCHEMA_EPOCH = 1`：空库首启自动建 baseline 并 stamp (1, 1)；库戳恰为 (1, 1) 时
no-op；其余一切（版本更高/更低、epoch 不符、有业务表但无版本表）**拒绝启动**并给
re-init 指引（fail-closed，绝不静默清库）。升级/回滚操作语义见
[`deploy.md`](../manual/deploy.md) §8.2。库戳本身存于 `schema_version` 表
（`version` / `applied_at` / `epoch` 三列）——该表由 migrate.rs 自举创建，
不在 schema.sql 内；实库中数表时会比下文清单多出这一张。

## 表清单（22 张）

`builds`、`tasks`、`task_labels`、`workers`、`worker_tasks`、`users`、`user_tokens`、
`sessions`、`product_acl`、`audit_logs`、`layer_packages`、`package_urls`、`layers`、
`products`、`product_config_history`、`app_meta`、`build_artifacts`、
`build_reproducibility`、`build_batches`、`batch_items`、`worker_telemetry_samples`、
`package_resource_profiles`。

## 构建域

### builds — 单次构建（任务 × 架构的子构建，每行一个产物集）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `product` / `pkg_name` | TEXT NOT NULL | 产品名 / 包名 |
| `phase` | TEXT NOT NULL | 状态机（见下） |
| `result_dir` | TEXT | 产物目录（result GC 后置 NULL） |
| `started_at` / `completed_at` | TEXT | 执行起点 / 终点 |
| `layer_digest` / `base_os_digest` | TEXT | 共享层 / base_os 指纹 |
| `backend` | TEXT | 构建后端 |
| `duration` | INTEGER | 耗时秒 |
| `user` | TEXT NOT NULL DEFAULT '' | 提交者用户名快照 |
| `crbs_pid` | INTEGER | 构建进程 PID（崩溃回收判定） |
| `srpm_path` / `request_json` | TEXT | 输入 SRPM / 请求 JSON |
| `attempt` | INTEGER NOT NULL DEFAULT 0 | 系统回收重排计数（毒丸封顶：reclaimer 失败重入每轮 +1，达上限拒绝重排并转终态 failed） |
| `signed` / `repo_publish` / `repo_consume` / `deterministic` | INTEGER 0/1 | 已签名 / 发布轴：允许进产品 repo（`--no-publish` 置 0）/ 消费轴：builddep 注入产品 repo（提交时合流快照，私有产品与 `--no-consume` 置 0）/ deterministic 模式 |
| `priority` | INTEGER NOT NULL DEFAULT 0 | |
| `arch` | TEXT DEFAULT '' | 架构（默认 ''；纯 noarch 收敛行记语义值 `noarch`） |
| `host_arches` | TEXT | 调度宿主约束：仅 `arch='noarch'` 行有值——逗号分隔可领取架构集（提交时由显式点名集或产品 `noarch_preferred_arches` 物化；复现行钉源构建实际宿主单架构）。NULL = 不限制；领取谓词按集合成员放行，非成员架构不可见（无队头阻塞）。token 白名单排除逗号，无注入面 |
| `task_id` | INTEGER NOT NULL → tasks(id) | 每条构建必须挂任务（杜绝 standalone 行） |
| `user_id` | INTEGER → users(id) | |
| `product_id` | INTEGER → products(id) ON DELETE SET NULL | |
| `name` / `version` / `release` | TEXT NOT NULL DEFAULT '' | NVR 快照 |
| `error_summary` | TEXT | 失败原因摘要（UI 详情页展示） |
| `product_config_toml` | TEXT | 构建时产品配置快照（合并后 TOML 原文）：CLI 本地构建创建行时写入，是 `crbs debug` 的配置锚；hub claim 时写入供审计与重派复用。NULL = 未采集（历史行） |
| `canonical_srpm_sha256` | TEXT | 输入 SRPM 原样字节的 sha256（任务内各架构共享；hub 新构建统一计算，`?srpm_sha256=` 内容检索的索引键；历史行 / worker 镜像行 NULL） |
| `batch_id` | INTEGER → build_batches(id) ON DELETE SET NULL | 批次归属（NULL = 常规提交） |
| `created_at` | TEXT | 入队时刻（插入时写入；历史回灌/镜像行可空）。排队时长以最新 build 型 `worker_tasks.assigned_at` 为准 |
| `peak_rss_kb` / `cpu_secs` / `cpu_p90_cores` / `peak_tmpfs_kb` | INTEGER / REAL | 构建资源采集：匿名内存峰值 / CPU 累计秒 / CPU p90 核数 / 构建自身 tmpfs 峰值；均可空（未采集 / `build_tmpfs` 关闭即 NULL） |
| `peak_total_kb` / `disk_wbytes` | INTEGER | 采集包络：总内存峰值（含 file cache）/ 磁盘写字节；能力不可用即 NULL |
| `oom_killed` / `sample_backend` / `sample_ncpu` | INTEGER / TEXT / INTEGER | OOM 检出（0/1，NULL = 口径不可用）/ 采样口径（`cgroup` / `proc`）/ 执行节点核数 |
| `req_min_mem_kb` / `req_min_ncpu` / `req_min_disk_kb` | INTEGER | 任务级放置下限（提交时物化、扇出继承；可空） |
| `srpm_size_bytes` | INTEGER | 输入 SRPM 大小（heavy steering 判定输入；可空） |

`phase` 状态机（7 值，与 tasks 同一全集）：`pending`（INSERT 恒为此值）→
`assigned` / `building`（worker 上报中间态）→ 终态 `succeeded` / `failed` /
`cancelled` / `timeout`。

### tasks — 构建任务（一次提交，含一或多个架构子构建）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | server task id（远程 CLI 用的 ID 空间） |
| `product` / `pkg_name` / `user` | TEXT NOT NULL | |
| `phase` | TEXT NOT NULL DEFAULT 'pending' | 同 builds 的 7 值全集（聚合写路径不产 `assigned`，读守卫显式承认该中间态） |
| `priority` | INTEGER NOT NULL DEFAULT 0 | |
| `srpm_path` / `result_dir` | TEXT | |
| `submitted_at` | TEXT NOT NULL DEFAULT now | 提交时刻 |
| `completed_at` / `duration` | TEXT / INTEGER | |
| `user_id` | INTEGER → users(id) | |
| `name` / `version` / `release` | TEXT NOT NULL DEFAULT '' | |
| `request_json` / `pkg_names` | TEXT | 构建选项快照（回灌留 NULL 的任务不可 `--rebuild`） |
| `product_id` | INTEGER → products(id) ON DELETE SET NULL | |

### task_labels — 任务级通用键值标签

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `task_id` | INTEGER NOT NULL → tasks(id) ON DELETE CASCADE | PK (task_id, key)：任务内按键唯一，随任务删除级联清理 |
| `key` / `value` | TEXT NOT NULL | 不透明元数据（如 `git-repo` / `git-commit` 仅为用户示例，无系统保留键）；同一 (key, value) 可被多个任务共享 |

与任务行同事务写入；`?label=KEY=VALUE` 按 (key, value) 等值过滤任务列表，
详情回显按 key 排序。

### build_batches — 整仓重建批次（一次 `crbs rebuild submit` 的实体与进度聚合）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `product_id` | INTEGER → products(id) ON DELETE SET NULL | |
| `created_by` | INTEGER → users(id) ON DELETE SET NULL | |
| `status` | TEXT NOT NULL | 状态机（见下） |
| `source_repo_url` | TEXT NOT NULL | 源仓库 URL |
| `source_fingerprint` | TEXT | repodata 指纹（防规划期源仓漂移） |
| `dist` | TEXT | NULL = 产品默认 dist；非默认值触发硬预检 |
| `arch_targets` | TEXT | 序列化架构列表 |
| `on_failure` | TEXT NOT NULL DEFAULT 'continue' | `continue` / `abort` |
| `force_all` | INTEGER NOT NULL DEFAULT 0 | |
| `total_items` / `n_succeeded` / `n_failed` / `n_skipped` / `n_cancelled` | INTEGER NOT NULL DEFAULT 0 | 进度计数 |
| `request_json` / `notes` | TEXT | |
| `created_at` / `started_at` / `finished_at` | TEXT | |

`status` 状态机：在途 `preparing` / `planning` / `running`；终态 `completed` /
`partial` / `failed` / `cancelled`（DB retention 仅删终态且 `finished_at` 超期的行）。
仅 hub 侧写批次行；worker 本地库同 baseline 但不产批次行。

### batch_items — 批次项（持久化的重建计划，崩溃恢复的事实源）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `batch_id` | INTEGER NOT NULL → build_batches(id) ON DELETE CASCADE | 批次删除带走全部批次项 |
| `pkg_name` | TEXT NOT NULL | UNIQUE (batch_id, pkg_name)：一批内每包至多一项 |
| `srpm_nevra` / `srpm_staging_path` | TEXT | 源 SRPM 定位 |
| `round` | INTEGER NOT NULL | 拓扑轮次；0 = 环/未解析（先试构建） |
| `state` | TEXT NOT NULL | 枚举：`pending` / `released` / `succeeded` / `failed` / `dep_skipped` / `skipped_conflict` / `arch_skipped` / `cancelled` |
| `attempt` | INTEGER NOT NULL DEFAULT 0 | |
| `task_id` | INTEGER → tasks(id) ON DELETE SET NULL | retention 删 task 不被批次项阻塞 |
| `error_code` / `error_message` | TEXT | |
| `updated_at` | TEXT NOT NULL DEFAULT now | |

## Worker 域

### workers — 注册的 worker 节点

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | admin init 的 `-w` 用此数字 ID |
| `name` | TEXT NOT NULL UNIQUE | |
| `arch` | TEXT NOT NULL | |
| `capacity` | INTEGER NOT NULL DEFAULT 1 | 并发上限 |
| `status` | TEXT DEFAULT 'offline' | 状态机（见下） |
| `last_heartbeat` | TEXT | hub 超 120s 无心跳标 offline |
| `version` | TEXT DEFAULT '' | |
| `created_at` | TEXT NOT NULL DEFAULT now | |
| `secret_hash` / `secret_expires_at` | TEXT | 认证密钥哈希 |
| `load1` / `ncpu` / `cpu_util_pct` / `mem_used_pct` | REAL / INTEGER / REAL / REAL | 心跳负载遥测（CPU 利用率 0-100、内存已用百分比） |
| `mem_total_kb` | INTEGER | 内存准入门换算基准（未上报可空） |
| `disk_free_kb` | INTEGER | 工件卷可用磁盘 KB（心跳随载上报；磁盘硬下限基准；未上报可空） |
| `resource_caps` | INTEGER | 采集能力位图（bit0 cgroup_v2 … bit4 psi；未上报可空） |

`status` 状态机：生产写入仅 `online` / `offline`（注册/离线/恢复收口）；
`draining` / `suspended` 是状态机守卫显式保护的管理员保留态。

### worker_tasks — worker 侧任务分配行（构建与管理型 init 两族）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `build_id` | INTEGER → builds(id) ON DELETE SET NULL | |
| `worker_id` | INTEGER NOT NULL → workers(id) ON DELETE CASCADE | |
| `task_id` | INTEGER → tasks(id) ON DELETE SET NULL | |
| `status` | TEXT DEFAULT 'assigned' | 状态机：`assigned`（INSERT 恒此值）→ `running` → 终态 `completed` / `failed` / `cancelled` |
| `assigned_at` | TEXT NOT NULL DEFAULT now | |
| `started_at` / `completed_at` | TEXT | |
| `result_json` | TEXT | |
| `kind` | TEXT NOT NULL DEFAULT 'build' | 枚举：`build` / `init`（管理型 init assignment，`crbs admin init` 走此通道） |
| `init_product` | TEXT | kind=init 时的产品名 |
| `init_product_id` | INTEGER → products(id) ON DELETE SET NULL | |

### worker_telemetry_samples — Worker 心跳遥测历史（趋势图数据源）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `worker_id` | INTEGER NOT NULL → workers(id) ON DELETE CASCADE | worker 删除连带采样 |
| `sampled_at` | TEXT NOT NULL | 与 `workers.last_heartbeat` 同源同帧（UTC 墙钟） |
| `cpu_util_pct` / `mem_used_pct` / `load1` | REAL | 心跳负载快照（浮点列写入走 `Dialect::float_param_cast`） |
| `ncpu` / `mem_total_kb` | INTEGER | 节点核数 / 内存总量 |
| `disk_free_kb` | INTEGER | 节点可用磁盘 KB（磁盘折线数据源） |

心跳路径 best-effort 追加写：只 INSERT 不 UPDATE、无业务删除点；清理仅走
retention 按 `sampled_at` 删除（不进业务表 prune 序列之外的例外）。
详情页趋势图按 `(worker_id, sampled_at)` 窗口查询（见索引清单）。

## 资源画像域

### package_resource_profiles — 包资源画像（声明 + 学习）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `product` / `source_name` / `arch` | TEXT NOT NULL | 复合 PK；无 FK（retention 删 builds 不连带画像）；`source_name` = `builds.name` 源码包基础名（同包多版本共享画像，版本维只留 builds 历史）；`arch='any'` 仅声明面哨兵 |
| `declared_min_mem_kb` / `declared_min_ncpu` / `declared_min_disk_kb` / `declared_updated_at` | INTEGER / TEXT | 声明面放置契约（hub admin 写入；NULL = 未声明）；DELETE 只清本组 |
| `learned_ema_mem_kb` / `learned_max_mem_kb` | INTEGER | 成功样本内存 EMA / 删失只抬不降的最大值 |
| `learned_ema_tmpfs_kb` / `learned_max_tmpfs_kb` | INTEGER | tmpfs 峰值 EMA / 最大（同折叠语义；口径升级重置不清） |
| `learned_ema_ncpu` / `learned_max_ncpu` | REAL | CPU p90 核数 EMA / 最大（浮点写入走 `float_param_cast`） |
| `learned_samples` | INTEGER NOT NULL DEFAULT 0 | 累计样本数（含删失样本） |
| `learned_sample_ncpu` | INTEGER | 末次样本执行节点核数（@nC 上下文） |
| `learned_backend` | TEXT | 采样主口径 `cgroup` / `proc`（sticky；NULL = 回填播种行） |
| `learned_censored` | INTEGER NOT NULL DEFAULT 0 | node-OOM 删失标记；任意 succeeded 解锁 |
| `learned_updated_at` / `created_at` / `updated_at` | TEXT | 学习更新时间 / 行时间戳 |

写入语义：终态学习 upsert 只写 learned 列组，admin PUT 只写 declared 列组；
本表不进 retention 删除序列（画像寿命 = 集群寿命）。

## 用户与认证域

### users — 账号（token / 密码两种登录方式）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `name` | TEXT NOT NULL UNIQUE | |
| `role` | TEXT NOT NULL | 枚举：`admin` / `operator` / `builder` / `viewer`（高层级包含低层级） |
| `status` | TEXT NOT NULL DEFAULT 'active' | 枚举：`active` / `disabled` |
| `created_at` | TEXT NOT NULL DEFAULT now | |
| `password_hash` | TEXT NULL | NULL = 未设密码（仅 token 认证） |
| `must_change_password` | INTEGER 0/1 NOT NULL DEFAULT 0 | |

### user_tokens — API token（`crbs_tok_...`）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user_id` | INTEGER NOT NULL → users(id) ON DELETE CASCADE | |
| `name` | TEXT | 每用户内唯一（partial UNIQUE 索引强制） |
| `hash` | TEXT NOT NULL UNIQUE | 明文不落库，只显示一次 |
| `expires_at` | TEXT | RFC3339 |
| `created_at` | TEXT NOT NULL DEFAULT now | |
| `revoked_at` | TEXT | 置位即吊销 |

### sessions — Web UI 密码登录会话

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user_id` | INTEGER NOT NULL → users(id) ON DELETE CASCADE | |
| `hash` | TEXT NOT NULL UNIQUE | `crbs_sess_` 明文的 SHA-256 |
| `created_at` | TEXT NOT NULL DEFAULT now | |
| `expires_at` | TEXT NOT NULL | RFC3339，TEXT 字典序比较过期 |
| `revoked_at` / `agent` | TEXT | 吊销标记 / UA |

## 产品域

### products — 产品配置（DB 权威，替代磁盘 products/*.toml）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `name` | TEXT NOT NULL | **全局唯一**（UNIQUE 索引 idx_products_name；slug `^[a-z0-9_-]+$`） |
| `display_name` | TEXT | |
| `owner_id` | INTEGER → users(id) ON DELETE RESTRICT | NULL = 官方产品；RESTRICT：删用户前须先转移/删除其产品 |
| `parent_id` | INTEGER → products(id) ON DELETE RESTRICT | 继承父产品（NULL = 根） |
| `visibility` | TEXT NOT NULL DEFAULT 'private' | 枚举：`public` / `private`；CHECK：官方产品（owner_id IS NULL）强制 public |
| `config_json` | TEXT NOT NULL | ProductConfig 的 serde_json（唯一权威；下发 worker 时反序列化→to_toml） |
| `revision` | INTEGER NOT NULL DEFAULT 1 | 每次 update 单调递增（乐观锁 / history / 缓存失效） |
| `base_os_revision` | INTEGER NOT NULL DEFAULT 1 | 触发 base_os 重建的字段被改时 = 当前 revision（reinit gate 判旧依据） |
| `created_at` / `updated_at` | TEXT NOT NULL DEFAULT now | |

### product_config_history — 产品配置历史（每次 update 追加一条快照）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `product_id` | INTEGER NOT NULL → products(id) ON DELETE CASCADE | 随产品删除 |
| `revision` | INTEGER NOT NULL | PK (product_id, revision)，从 1 起 |
| `config_json` | TEXT NOT NULL | 该 revision 的完整快照（不存 diff） |
| `parent_id` | INTEGER | 该 revision 时的父产品 |
| `base_os_revision` | INTEGER NOT NULL | |
| `changed_by_user_id` | INTEGER → users(id) ON DELETE SET NULL | |
| `changed_at` | TEXT NOT NULL DEFAULT now | |
| `reason` | TEXT | 变更说明 |

### product_acl — 产品级授权（与 products 表解耦）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `product_id` | INTEGER NOT NULL → products(id) ON DELETE CASCADE | PK (product_id, user_id) |
| `user_id` | INTEGER NOT NULL → users(id) ON DELETE CASCADE | |
| `role` | TEXT NOT NULL DEFAULT 'viewer' | 枚举：`viewer` / `builder` / `admin` |
| `created_at` | TEXT NOT NULL DEFAULT now | |

## 层与缓存域

### layers — 共享依赖层

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `digest` | TEXT PK | blake3 指纹 |
| `path` / `product` | TEXT NOT NULL | |
| `status` | TEXT NOT NULL | CHECK 恒 'complete'（唯一写入点 upsert_layer） |
| `ref_count` | INTEGER DEFAULT 0 | CHECK ≥ 0；归零后进入 GC 宽限 |
| `created_at` / `scheduled_gc_at` | TEXT | |
| `product_id` | INTEGER → products(id) ON DELETE SET NULL | |

### layer_packages — 层内包清单

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `digest` | TEXT PK | 对应 layers.digest |
| `product` / `packages` | TEXT NOT NULL | 包列表序列化 |
| `created_at` | TEXT NOT NULL DEFAULT now | |
| `product_id` | INTEGER → products(id) ON DELETE SET NULL | |

### package_urls — `dnf repoquery --location` 的 URL 缓存

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `repo_baseurl` / `nevra` / `url` | TEXT NOT NULL | PK (repo_baseurl, nevra) |
| `created_at` / `last_used_at` | INTEGER NOT NULL DEFAULT epoch 秒 | 全库唯一 epoch 秒时间列（其余为 TEXT 墙钟） |

## 产物与复现域

### build_artifacts — 构建产物元数据（每 build N 行）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `build_id` | INTEGER NOT NULL → builds(id) ON DELETE CASCADE | UNIQUE (build_id, relative_path) |
| `relative_path` | TEXT NOT NULL | |
| `kind` | TEXT NOT NULL | 枚举：`rpm` / `srpm` / `log` / `metadata` / `script` / `other` |
| `size_bytes` / `sha256` | INTEGER / TEXT NOT NULL | 签名后哈希（签名刷新会更新） |
| `unsigned_sha256` | TEXT | **签名前**字节哈希——复现比对锚（签名时序不影响比对）；NULL = 未记录 |
| `arch` / `name` / `version` / `release` / `epoch` | TEXT / INTEGER | NEVRA |
| `signed` / `on_disk` | INTEGER 0/1 NOT NULL | |
| `metadata_json` | TEXT | |
| `created_at` | TEXT NOT NULL | |

### build_reproducibility — 重放比对结果

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `kind` | TEXT NOT NULL DEFAULT 'replay' | 枚举：`replay`（自动/手动重放比对）/ `cross_arch_noarch`（同 task 跨架构 noarch 互比） |
| `source_build_id` | INTEGER NOT NULL → builds(id) ON DELETE CASCADE | 比对行随 source 构建行级联删除 |
| `replay_build_id` | INTEGER → builds(id) ON DELETE SET NULL | 重放构建行被删仅置空，比对行保留 |
| `verdict` | TEXT NOT NULL | 枚举：`same` / `diff` / `build_failed` / `dep_unavailable` / `infra_error`（复现率分母只计前三；后两类是基础设施问题单列） |
| `detail_json` | TEXT | |
| `compared_at` | TEXT NOT NULL DEFAULT now | |

同 task 的 cross_arch_noarch 比对仅记一行（partial UNIQUE 索引去重）。

## 审计与元数据域

### audit_logs — 管理操作审计

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `user` / `role` | TEXT NOT NULL DEFAULT '' | 操作者快照 |
| `action` | TEXT NOT NULL | 如 sign_triggered、产品变更 |
| `target` / `detail` | TEXT | |
| `created_at` | TEXT NOT NULL DEFAULT now | |

### app_meta — 应用级元数据 KV（seed 门闩等启动一次性状态）

| 列 | 类型 | 约束 / 说明 |
|----|------|------|
| `key` | TEXT PK | 如 `products_seeded_at`（产品 seed 门闩） |
| `value` | TEXT NOT NULL | |
| `updated_at` | TEXT NOT NULL DEFAULT now | |

## 索引清单

名称两侧同名等价（个别方向差异无查询面影响，如 idx_audit_logs_created_at
SQLite 缺省 ASC / PG 为 DESC）；partial 索引的 WHERE 谓词已注明。

| 表 | 索引 | 列 / 说明 |
|----|------|------|
| builds | idx_builds_user_id | (user, id DESC) |
| builds | idx_builds_phase_id | (phase, id DESC) |
| builds | idx_builds_product_id | (product, id DESC) |
| builds | idx_builds_phase_pid | (phase, crbs_pid) |
| builds | idx_builds_task_arch | (task_id, arch) |
| builds | idx_builds_product_pkg_active | (product, pkg_name) WHERE phase IN ('pending','assigned','building')——提交去重查 |
| builds | uq_active_builds_identity | UNIQUE (product, pkg_name, COALESCE(arch,'')) WHERE phase 活跃——并发双插数据库级兜底 |
| builds | idx_builds_product_pkg_phase | (product, pkg_name, phase) 全历史行（聚合查询面） |
| builds | idx_builds_pending_pick | (priority DESC, started_at) WHERE phase='pending' AND srpm_path IS NOT NULL AND request_json IS NOT NULL——派发 pick 的缓解索引（权重表达式允许低优先级靠等待反超，索引序只覆盖前缀段） |
| builds | idx_builds_completed | (completed_at DESC) WHERE completed_at IS NOT NULL——仪表盘时长图 / retention cutoff 的排序键 |
| builds | idx_builds_srpm_sha256 | (canonical_srpm_sha256) WHERE canonical_srpm_sha256 IS NOT NULL——`?srpm_sha256=` 内容检索 |
| task_labels | idx_task_labels_key_value | (key, value)——`?label=` 过滤 |
| tasks | idx_tasks_phase_id / idx_tasks_product_id / idx_tasks_user_id | (列, id DESC) |
| tasks | idx_tasks_submitted_id | (submitted_at DESC, id DESC) |
| workers | idx_workers_arch / idx_workers_status | 单列 |
| workers | idx_workers_secret_hash | (secret_hash) WHERE secret_hash IS NOT NULL |
| worker_tasks | idx_worker_tasks_build / _worker / _status | 单列 |
| worker_tasks | uq_worker_tasks_active_init | UNIQUE (worker_id, init_product) WHERE kind='init' AND status IN ('assigned','running')——同 worker 同产品活跃 init 的 DB 级兜底（PG TOCTOU） |
| worker_telemetry_samples | idx_telemetry_samples_worker_time | (worker_id, sampled_at)——详情页趋势图窗口查询 |
| worker_telemetry_samples | idx_telemetry_samples_sampled_at | (sampled_at, id)——14 天遥测 retention 的批次删除路径 |
| audit_logs | idx_audit_logs_user / _action / _created_at | 单列 |
| user_tokens | idx_user_tokens_user | (user_id) |
| user_tokens | idx_user_tokens_user_name | UNIQUE (user_id, name) WHERE name IS NOT NULL——token 名每用户唯一 |
| product_acl | idx_product_acl_user | (user_id) |
| package_urls | idx_package_urls_last_used | (last_used_at)——LRU 清理 |
| layers | idx_layers_product | 单列 |
| layers | idx_layers_gc | (scheduled_gc_at) WHERE status='complete' AND ref_count=0 |
| products | idx_products_owner / idx_products_parent | 单列（FK 查找面） |
| products | idx_products_name | UNIQUE (name)——产品名全局唯一 |
| build_artifacts | idx_artifacts_sha256 / idx_artifacts_pkg | (sha256) / (name, arch) |
| build_reproducibility | idx_build_repro_source / _replay | 单列 |
| build_reproducibility | idx_build_repro_compared | (compared_at DESC)——复现率看板 cutoff |
| build_reproducibility | idx_build_repro_cross_arch | UNIQUE (source_build_id) WHERE kind='cross_arch_noarch' |
| build_batches | idx_batches_active | (product_id, id DESC) WHERE status IN ('preparing','planning','running')——批次驱动 5s tick 的活跃批次扫 |
| build_batches | uq_batches_active_product | UNIQUE (product_id) WHERE status IN ('preparing','planning','running')——每产品单活批次的 DB 级兜底 |
| batch_items | idx_batch_items_batch_round | (batch_id, round) |
| batch_items | idx_batch_items_batch_state | (batch_id, state)——批次对账/摘要的状态过滤 |
| package_resource_profiles | idx_profiles_product_mem | (product, learned_ema_mem_kb)——产品内 top-N 资源大户 |

约束级索引（不单列）：PK / UNIQUE 自带索引——product_acl (product_id, user_id)、
product_config_history (product_id, revision)、package_urls (repo_baseurl, nevra)、
batch_items (batch_id, pkg_name)、build_artifacts (build_id, relative_path)、
users.name / workers.name / user_tokens.hash / sessions.hash 的 UNIQUE。
