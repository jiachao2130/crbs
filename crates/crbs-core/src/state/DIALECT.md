# SQL 方言双后端：已完成实现与设计说明

> ✅ **状态：已实现并验证** — 本文档原是「迁移前映射表」，现已更新为「实现完成台账」。
> 双后端支持已落地：`cargo test` 默认跑 SQLite，`--features postgres` + `CRBS_TEST_DATABASE_URL` 跑 PostgreSQL。

---

## 架构总览

### 设计选择

1. **AnyPool 抽象**：`StateStore` 内部持有 `sqlx::AnyPool`，通过 `Dialect` 枚举分发 SQL。
   业务代码完全无感知。

2. **TEXT 时间统一策略**（与原迁移建议相反的最终决策）：
   - 所有时间列类型在两后端均保持 `TEXT`，格式 `YYYY-MM-DD HH24:MI:SS`
   - PostgreSQL 写入用 `to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')`；
     比较用 `col::timestamp` naive 解析、与 `(NOW() AT TIME ZONE 'UTC')` 同帧运算；
     **禁用** `to_timestamp(text, fmt)`（按会话时区解释文本，见 `db/mod.rs::sql_seconds_since` 注释）
   - **理由**：避免大规模 schema 迁移 + 类型映射风险 + 已验证测试全量通过

3. **方言枚举集中分发**：`db/mod.rs::Dialect` 提供：
   - `sql_now()` / `sql_days_ago(n)` / `sql_minutes_ago(n)` / `sql_seconds_since(col)`
   - `sql_priority_wait_weight()` / `sql_is_distinct_from(lhs, rhs)` / `float_param_cast(n)`
   - `begin_write()`
   - 自由函数：`pagination_clause()` / `push_filter()` / `push_common_filters()` /
     `escape_like()` / `in_placeholders()`
   所有 SQL 方言点通过这些 helper 统一生成，无分散的硬编码。

4. **编译条件门控**：`#[cfg(feature = "postgres")]` 包裹所有 PG 特有代码，
   无 `postgres` feature 时可编译且零成本。

---

## 实现台账：逐项映射完成状态

### 1. 时间函数（全量完成）

| SQLite 写法 | PostgreSQL 实现 | 状态 |
|------------|----------------|------|
| `datetime('now')` | `to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')`（`sql_now`） | ✅ |
| `datetime('now', '-N days')` | `to_char((NOW() AT TIME ZONE 'UTC') - INTERVAL 'N days', 'YYYY-MM-DD HH24:MI:SS')`（`sql_days_ago`） | ✅ |
| `datetime('now', '-N minutes')` | `to_char((NOW() AT TIME ZONE 'UTC') - INTERVAL 'N minutes', 'YYYY-MM-DD HH24:MI:SS')`（`sql_minutes_ago`） | ✅ |
| `datetime('now', '+' \|\| $1 \|\| ' hours')` | `to_char((NOW() AT TIME ZONE 'UTC') + ($1::INTEGER \|\| ' hours')::INTERVAL, 'YYYY-MM-DD HH24:MI:SS')`（layers.rs 层 GC schedule 绑定现场；无 minutes 绑定现场） | ✅ |
| `datetime(col, '+' \|\| $1 \|\| ' minutes') <= datetime('now')` | `col::timestamp + INTERVAL '1 minute' * $1 <= (NOW() AT TIME ZONE 'UTC')`（gc.rs 僵尸判定） | ✅ |
| `ROUND((julianday(datetime('now')) - julianday(x)) * 86400)` | `ROUND(EXTRACT(EPOCH FROM ((NOW() AT TIME ZONE 'UTC') - x::timestamp)))`（`sql_seconds_since`） | ✅ |
| `strftime('%s','now')` | `EXTRACT(EPOCH FROM NOW())::bigint` | ✅ |

**总纲**：PG 分支一律 `AT TIME ZONE 'UTC'` / `::timestamp` naive，写入与比较必须同帧；
epoch BIGINT 列（package_urls）除外——EPOCH 是绝对秒无需时区；`$N` 一律名值绑定，
SQL 文本出现序不限（改 `?` 顺序占位符必须按绑定序重排）。

**TEXT 时间格式台账**（存储层唯一权威清单；新增时间列一律用核心格式）：

| 格式 | 形态 | 使用范围 |
|------|------|---------|
| **核心格式**（默认，新列一律同款） | `YYYY-MM-DD HH:MM:SS`（UTC 墙钟 TEXT） | 全部 baseline 时间列及其 DEFAULT（SQLite `datetime('now')` / PG `to_char(NOW() AT TIME ZONE 'UTC', …)`，如 tasks.submitted_at、users.created_at、build_batches.created_at、batch_items.updated_at）；Dialect helper（`sql_now`/`sql_days_ago`/…）产出与 `sql_seconds_since` 消费的同一格式；retention/GC 的 cutoff 比较 |
| RFC3339 特例（不扩散） | `chrono::to_rfc3339()` 输出（UTC，含 `+00:00`） | `sessions.expires_at`、`user_tokens.expires_at`（应用端写入，按 TEXT 字典序比较过期）；seed 门闩写入的 `app_meta.value`（通用 KV 值列，非专门时间列） |
| epoch 秒特例 | INTEGER/BIGINT Unix 秒 | `package_urls.created_at/last_used_at`（`strftime('%s','now')` / `EXTRACT(EPOCH FROM NOW())::bigint`） |

补充边界：`audit` 的时间过滤**入参**接受 RFC3339 / `YYYY-MM-DD` 等形态，但
`audit.rs` 在入 SQL 前统一归一化为核心格式（存储层不出现第三种格式）。
新表/新列建列纪律：TEXT 时间列 + 核心 DEFAULT（PG 侧照抄 build_reproducibility
的 `to_char(NOW() AT TIME ZONE 'UTC', …)` 先例），**禁 TIMESTAMPTZ**（会破坏
双侧 TEXT 对称）；应用端写入走 Dialect 收口的 helper，不得手拼格式。

**已覆盖文件**：`builds.rs`, `tasks.rs`, `workers.rs`, `layers.rs`, `gc.rs`, `gc_queries.rs`, `retention.rs`, `audit.rs`, `users.rs`

> 本清单非穷举（`sessions.rs`、`migrate.rs` 等亦有方言分支未列全；
> `reproducibility*.rs` 为方言中性 SQL）。方言分发的权威核对方式：
> `grep -rn "Dialect" crates/crbs-core/src/`，以代码为准。

---

### 2. Upsert / 冲突处理（全量完成）

| SQLite 写法 | PostgreSQL 实现 | 状态 |
|------------|----------------|------|
| `INSERT OR REPLACE INTO t (...)` | `INSERT INTO t (...) ON CONFLICT (pk) DO UPDATE SET ...` | ✅ |
| `INSERT ... ON CONFLICT(col) DO UPDATE SET ...` | **相同，直接复用** | ✅ |
| `ON CONFLICT DO NOTHING` | **相同，直接复用** | ✅ |
| `RETURNING id, ...` | **相同，直接复用** | ✅ |

**已覆盖文件**：`layers.rs`, `layer_packages.rs`, `workers.rs`

---

### 3. 自增主键与 RETURNING（全量完成）

| SQLite 写法 | PostgreSQL 实现 | 状态 |
|------------|----------------|------|
| `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` | ✅ (`schema.pg.sql`) |
| `.last_insert_rowid()` | `INSERT ... RETURNING id` + `fetch_one` | ✅ 全部替换完成 |

---

### 4. Row 类型泄漏（全量完成）

所有 `SqliteRow` 引用 → `sqlx::any::AnyRow`，无类型泄漏，双后端通用。

---

### 5. 事务 BEGIN（全量完成）

- SQLite：`BEGIN IMMEDIATE`（避免升级死锁）
- PostgreSQL：`BEGIN`（MVCC 原生支持）
- 统一入口：`Dialect::begin_write()`

注：begin_write 在 PG 上不锁行——"SELECT 守卫 + 写"序列的写语句须自带谓词
（CAS 家族：`DELETE_WORKER_IF_OFFLINE`、`complete_task` 的 NOT EXISTS 活跃
子构建、`UPDATE_BUILD_INFO_GUARDED`、`UPDATE_BUILD_PHASE` /
`UPDATE_BUILD_PHASE_GUARDED` / `UPDATE_TASK_PHASE` /
`mark_task_failed` / `pick_and_lock_pending` 的 phase 谓词）。

全局计数守卫（无单行可锁，如批次总量上限）：PG 在写事务内先取事务级
`pg_advisory_xact_lock`（键见 `batches::PG_BATCH_QUOTA_LOCK_SQL`，随
COMMIT/ROLLBACK 自动释放）；SQLite 由 `BEGIN IMMEDIATE` 串行化写者。新增
同类"全表计数 + 插入"守卫时照此办理，勿退回 check-then-insert。

---

### 6. NULL 安全比较（全量完成）

- SQLite：`x IS NOT y`
- PostgreSQL：`x IS DISTINCT FROM y`
- 统一入口：`Dialect::sql_is_distinct_from(x, y)`

---

### 7. 保留字处理（全量完成）

`user` 列在 PostgreSQL 是保留字，采用：
- **SELECT**：`"user" AS user`（引号 + 别名，保证 `row.get("user")` 双后端通用）
- **INSERT**：`"user"` 列名加引号
- **WHERE**：`"user"` 列名加引号

---

## 测试基础设施

### 本地 PostgreSQL 测试

```bash
# 启动测试数据库
docker-compose -f docker-compose.pg.yml up -d

# 运行 core 测试
CRBS_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/crbs_test \
  cargo test --features postgres -p crbs-core -- --test-threads=1
```

### 注意事项

- PostgreSQL 测试使用共享数据库，必须单线程执行（`--test-threads=1`）
- SQLite 测试使用每个测试独立的临时数据库，可并行

---

## Feature 透传

| crate | feature | 说明 |
|-------|---------|------|
| `crbs-core` | `postgres` | 启用 PostgreSQL driver + 方言分支 |
| `crbs-server` | `postgres` | 透传 `crbs-core/postgres` + `sqlx/postgres` |
| `crbs` (root) | 无 | CLI 暂不直接依赖，通过 server 启用 |

---

## D2 设计决策落实

### 产品名全局唯一约束（已完成）

**原 D2 设计结论**：产品名是全局命名空间，私人产品不得与官方产品重名，不同用户间私人产品也不得重名。

**实现**：
- SQLite (`schema.sql`)：删除两个 partial 索引，改为 `CREATE UNIQUE INDEX idx_products_name ON products(name)`
- PostgreSQL (`schema.pg.sql`)：同上

**意义**：
1. 为 PostgreSQL READ COMMITTED 隔离级别提供并发竞态数据库级兜底
2. 两个不同用户并发创建同名私人产品 → 恰好一个成功，一个约束冲突（正确语义）
3. 用户创建与官方产品重名的私人产品 → 直接冲突（符合全局命名空间设计）

---

## 原文档 §8 未来工作完成情况

| 条目 | 状态 |
|------|------|
| `BASELINE_DDL` 拆到 `schema.sql` 用 `include_str!` | ✅ 已完成 |
| PostgreSQL 版 `schema.pg.sql` | ✅ 已完成 |
| 引入 `trait StateStore` 抽象后端 | ❌ 未做（按原决策暂不引入过早抽象） |

---

## 验证结果

| 测试矩阵 | 结果 |
|---------|------|
| `cargo test -p crbs-core` (SQLite) | ✅ 406/406 passed |
| `cargo test --features postgres -p crbs-core` (PG) | ✅ 406/406 passed |
| `cargo clippy --workspace` | ✅ exit 0 |
| `cargo fmt --all` | ✅ 无变更 |

---

## 已知限制与后续方向

1. **Server 集成测试**：当前 8 个 server 集成测试文件仅跑 SQLite。
   可通过 `CRBS_TEST_DATABASE_URL` 环境变量扩展支持 PG（非阻塞）。

2. **并发竞态测试**：产品创建/更新的竞态正确性目前依赖数据库约束 + 事务隔离保证，
   可补充显式并发测试用例（非阻塞）。

3. **文档更新**：设计文档 D3/P0-6 修正案、CHANGELOG、部署文档双后端章节（非阻塞）。
