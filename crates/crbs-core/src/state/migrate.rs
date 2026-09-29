// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Schema 版本闩（单 baseline + (version, epoch) 戳判等）。
//!
//! schema 结构唯一事实源是 baseline 文件（`schema.sql` / `schema.pg.sql`，
//! 编译期内联）：新建库单事务建全量 baseline 并落戳，不做增量迁移。版本闩
//! fail-closed：戳与预期 `(SCHEMA_VERSION, SCHEMA_EPOCH)` 不完全相等即拒绝
//! 启动，绝不静默重建（静默 DROP 全部业务表是数据丢失）：
//!
//! | 库状态 | 动作 |
//! |---|---|
//! | schema_version 为空（含全新库）且无业务表 | fresh init：建 baseline，落戳 |
//! | 戳恰为 `(SCHEMA_VERSION, SCHEMA_EPOCH)` | 已就绪，no-op（附升级对象探测，见下） |
//! | 其余一切（旧世代戳、更高版本、多行戳、epoch-less 残留表、业务表存在而无版本行） | 拒绝启动 + 重建指引 |
//!
//! 戳判等只比 `(version, epoch)`，不覆盖列结构：存量库缺新增库对象
//! （builds / workers / worker_telemetry_samples 新列、package_resource_
//! profiles / task_labels 表）时由 `probe_upgrade_schema_*` fail-closed 拒启，
//! 指引桥接脚本 `deploy/upgrade-resource-schema-{sqlite,pg,worker}.sh` 补齐
//! （纯加法 DDL，逐字对齐 baseline）。

use crate::error::{CrbsError, DbResultExt};

/// 当前 schema 版本（与 [`SCHEMA_EPOCH`] 组成库戳判等对）。
///
/// 结构变更只同步两个 baseline，版本闩恒 `(1, 1)`——无兼容迁移史，
/// fail-closed 仅拦戳不等的形态；版本闩无 DDL 哈希，存量库列结构漂移
/// （如缺新增列）不被闩拒绝——升级对象由 `probe_upgrade_schema_*`
/// 启动探测兜底（缺则拒启），其余漂移仍在首次相关 UPDATE 才爆。后续版本
/// 递增需两侧纯手工同步，等价性由 `baseline_equivalence` 守卫校验。
pub const SCHEMA_VERSION: i64 = 1;

/// 版本编号空间世代：与 [`SCHEMA_VERSION`] 构成库形态判等对，缺一不可——
/// 其余一切形态（更高/更低版本、缺 epoch 列残留表、业务表存在而无版本行）
/// 启动即拒。落戳/自举 SQL 的 epoch 值由本常量编译期注入（[`sql`] 模块
/// 注记），无第二处字面量可漂移。
pub const SCHEMA_EPOCH: i64 = 1;

/// Baseline schema DDL (SQLite)。编译期内联；结构变更时同步修改此文件并
/// 前移版本闩（见 [`SCHEMA_VERSION`]），不得只改一侧。
const BASELINE_DDL_SQLITE: &str = include_str!("schema.sql");

/// Baseline schema DDL (PostgreSQL)。编译期内联。
#[cfg(feature = "postgres")]
const BASELINE_DDL_PG: &str = include_str!("schema.pg.sql");

/// 按 `;` 切分 DDL 文本，剔除空白与纯注释语句。前提：`schema.sql` 不含
/// 带 `;` 的字符串字面量（表默认值都是不带 `;` 的函数调用）；未来引入须
/// 改成引号感知解析器。
fn split_ddl_statements(sql: &str) -> impl Iterator<Item = &str> {
    sql.split(';').filter_map(|stmt| {
        let trimmed = stmt.trim();
        // 剔除空段与整段都是行注释的段（保守：只要有非注释行就保留）
        let has_code = trimmed
            .lines()
            .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with("--"));
        if has_code {
            Some(trimmed)
        } else {
            None
        }
    })
}

mod sql {
    use super::SCHEMA_EPOCH;

    // schema_version：唯一在两侧 baseline 之外的自举表（业务表 DDL 全在
    // BASELINE_DDL_SQLITE / BASELINE_DDL_PG）；单行 (version, epoch) 戳。
    // 落戳 INSERT 点名 epoch——缺列的旧世代残留表在探测 SELECT 处即报错，
    // 不会走到落戳。epoch 值一律由 [`SCHEMA_EPOCH`] 编译期注入（format!
    // 常量拼接），四处生成函数是全库仅有的 epoch 出现点；注入形态由
    // `stamp_sql_epoch_binds_schema_epoch_constant` 单测钉住。
    pub(super) fn create_schema_version_table_sqlite() -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS schema_version ( \
                 version INTEGER PRIMARY KEY, \
                 applied_at INTEGER NOT NULL, \
                 epoch INTEGER NOT NULL DEFAULT {SCHEMA_EPOCH} \
             )"
        )
    }

    pub(super) const SELECT_SCHEMA_STAMP: &str = "SELECT version, epoch FROM schema_version";

    pub(super) fn insert_schema_version_sqlite() -> String {
        format!(
            "INSERT INTO schema_version (version, applied_at, epoch) \
             VALUES ($1, strftime('%s','now'), {SCHEMA_EPOCH})"
        )
    }

    // 非 postgres 构建下仅测试引用，压 dead_code。
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(super) fn create_schema_version_table_pg() -> String {
        format!(
            "CREATE TABLE IF NOT EXISTS schema_version ( \
                 version BIGINT PRIMARY KEY, \
                 applied_at BIGINT NOT NULL, \
                 epoch BIGINT NOT NULL DEFAULT {SCHEMA_EPOCH} \
             )"
        )
    }

    /// applied_at 由应用端传入而非 `EXTRACT(EPOCH...)`：sqlx Any 驱动对
    /// "参数 + 表达式"混合 VALUES 发不完整 Bind 报文（PG "insufficient data left in message"）。
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(super) fn insert_schema_version_pg() -> String {
        format!(
            "INSERT INTO schema_version (version, applied_at, epoch) VALUES ($1, $2, {SCHEMA_EPOCH})"
        )
    }

    #[cfg(feature = "postgres")]
    pub(super) fn unix_epoch_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    // ===== PG 探测 SQL 锚 =====
    //
    // 探测一律锚定 current_schema()（跟随 search_path），不得回退硬编码
    // 'public'：baseline 建表不带 schema 限定、落 search_path 首位 schema，
    // 按 'public' 探测会把已建表库误判为可重建空库（首启撞 42P07 或更糟）。
    // 文本回归见 `pg_probe_sql_anchors_pin_current_schema`。
    //
    // current_schema()（首个**存在的** schema）与非限定名逐名解析的语义差
    // 不可达：建表全程非限定名，锚与落点恒同 schema；残余面仅在 init 后改
    // search_path 的契约外拓扑，该面探测层无法自愈，维持现状。
    //
    // 非 postgres 构建下仅测试引用，压 dead_code。

    /// 业务表存在性守卫模板；`{names}` 由调用点以 `BUSINESS_TABLES` 引号清单替换（编译期常量，无注入面）。
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(super) const PROBE_NO_BUSINESS_TABLES_SQL_TEMPLATE: &str =
        "SELECT COUNT(*) FROM information_schema.tables \
     WHERE table_schema = current_schema() AND table_name IN ({names})";

    // ===== PG schema 变更 advisory lock 语句对 =====
    //
    // baseline DDL 非幂等（CREATE TABLE 无 IF NOT EXISTS），并发首启输家的
    // 裸 DDL 撞 42P07/42707；语句对成 const（回归测试
    // `pg_migration_lock_sql_pins_advisory_xact_lock`）。显式 READ COMMITTED
    // 根除 repeatable-read 部署"锁等待结束后快照冻结看不见赢家提交"陷阱
    //（推导见 create_fresh_baseline_pg_any 注释）。
    //
    // 非 postgres 构建下仅测试引用，压 dead_code。
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(super) const PG_MIGRATION_ISOLATION_SQL: &str =
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED";
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(super) const PG_MIGRATION_ADVISORY_LOCK_SQL: &str =
        "SELECT pg_advisory_xact_lock(524372339)";
}

/// 全部业务表名。fresh init 前的存在性守卫用：这些表出现而版本记录缺失时
/// 必须拒建，绝不静默 DROP（数据丢失红线）。
const BUSINESS_TABLES: &[&str] = &[
    "product_config_history",
    "products",
    "app_meta",
    "batch_items",
    "build_artifacts",
    "build_batches",
    "build_reproducibility",
    "worker_tasks",
    "worker_telemetry_samples",
    "builds",
    "tasks",
    "workers",
    "user_tokens",
    "sessions",
    "product_acl",
    "users",
    "audit_logs",
    "layer_packages",
    "package_urls",
    "layers",
    "package_resource_profiles",
    "task_labels",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SchemaStamp {
    version: i64,
    epoch: i64,
}

enum ProbeOutcome {
    Unstamped,
    Stamped(SchemaStamp),
}

/// 读取 schema_version 戳（调用方先 `CREATE TABLE IF NOT EXISTS`，无表
/// 不可达）。多行戳与畸形行解码失败（NULL / 类型不符）fail-closed 拒；缺
/// epoch 列的残留表由 [`unrecognized_probe_error`] 包装成重建指引。
async fn probe_schema_stamp<'e, E>(executor: E, reinit: &str) -> crate::Result<ProbeOutcome>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    use sqlx::Row;
    let rows = sqlx::query(sql::SELECT_SCHEMA_STAMP)
        .fetch_all(executor)
        .await
        .db_ctx("read schema stamp")
        .map_err(|e| unrecognized_probe_error(e, reinit))?;
    let mut it = rows.iter();
    match (it.next(), it.next()) {
        (None, _) => Ok(ProbeOutcome::Unstamped),
        (Some(row), None) => {
            let decode = |idx: usize| {
                row.try_get::<i64, _>(idx).map_err(|e| {
                    unrecognized_library_error(
                        &format!("schema_version stamp row is malformed ({e})"),
                        reinit,
                    )
                })
            };
            Ok(ProbeOutcome::Stamped(SchemaStamp {
                version: decode(0)?,
                epoch: decode(1)?,
            }))
        }
        _ => Err(unrecognized_library_error(
            "schema_version carries multiple stamp rows",
            reinit,
        )),
    }
}

/// 戳判等：恰为 `(SCHEMA_VERSION, SCHEMA_EPOCH)` 才放行，否则拒绝并报实际戳值。
fn verify_stamp(stamp: SchemaStamp, reinit: &str) -> crate::Result<()> {
    if stamp
        == (SchemaStamp {
            version: SCHEMA_VERSION,
            epoch: SCHEMA_EPOCH,
        })
    {
        return Ok(());
    }
    Err(unrecognized_library_error(
        &format!(
            "schema stamp is (version={}, epoch={})",
            stamp.version, stamp.epoch
        ),
        reinit,
    ))
}

/// 不认识的库形态统一拒绝：报实际状态 + 重建指引（fail-closed，库原样保留）。
fn unrecognized_library_error(found: &str, reinit: &str) -> CrbsError {
    CrbsError::ValidationFailed {
        message: format!(
            "state database schema is not recognized by this binary ({found}; expected \
             version={SCHEMA_VERSION} epoch={SCHEMA_EPOCH}): the database cannot be \
             migrated in place. Back up any data you need, then {reinit}."
        ),
    }
}

/// 探测 SQL 报错包装：错误文本含 "epoch"（缺列残留表在唯一点名 epoch 的
/// SELECT 处报列缺失）时包一层重建指引，其余报错原样透传。
fn unrecognized_probe_error(e: CrbsError, reinit: &str) -> CrbsError {
    let text = e.to_string();
    if !text.contains("epoch") {
        return e;
    }
    unrecognized_library_error(
        &format!("schema_version table predates the epoch column ({text})"),
        reinit,
    )
}

// ===== 存量库升级对象探测 =====
//
// 版本闩只判等 (version, epoch) 戳，不覆盖列结构：存量库（戳恰为预期对）可能
// 缺新增对象，首次相关 UPDATE 才爆列错。此处探测升级对象的表存在性与新增
// 列，任一缺失 fail-closed 拒启并指引桥接脚本（纯加法 DDL，逐字对齐
// baseline）。fresh init 落全量 baseline 必然全齐，只在戳判等路径探测。

/// 升级对象清单：(表名, 该表新增列)。探测先查表存在性，再逐列核对；
/// 列清单为空 = 只查表存在性。与两份 baseline 及
/// `deploy/upgrade-resource-schema-*.sh` 的补列清单三处同步——改这里必须
/// 同改另两处。
const UPGRADE_SCHEMA_PROBE: &[(&str, &[&str])] = &[
    (
        "builds",
        &[
            "req_min_mem_kb",
            "req_min_ncpu",
            "req_min_disk_kb",
            "peak_total_kb",
            "disk_wbytes",
            "oom_killed",
            "sample_backend",
            "sample_ncpu",
            "peak_tmpfs_kb",
            "product_config_toml",
        ],
    ),
    ("workers", &["disk_free_kb", "resource_caps"]),
    ("worker_telemetry_samples", &["disk_free_kb"]),
    (
        "package_resource_profiles",
        &[
            "source_name",
            "learned_ema_tmpfs_kb",
            "learned_max_tmpfs_kb",
        ],
    ),
    ("task_labels", &[]),
];

/// SQLite 方言的桥接脚本指引：SQLite 同时是 hub 默认库与 worker 本地库的方言，
/// 收口点不区分调用方，两个脚本并列给出。
const SQLITE_SCHEMA_BRIDGE_HINT: &str = "back up the database, then run \
     deploy/upgrade-resource-schema-sqlite.sh (hub SQLite database) or \
     deploy/upgrade-resource-schema-worker.sh (worker local database)";

/// PG 方言的桥接脚本指引。
#[cfg(feature = "postgres")]
const PG_SCHEMA_BRIDGE_HINT: &str =
    "back up the database, then run deploy/upgrade-resource-schema-pg.sh";

/// 探测缺失 → 结构化拒绝：缺失对象全集 + 桥接脚本指引（fail-closed，库原样）。
fn upgrade_probe_error(missing: &[String], bridge_hint: &str) -> CrbsError {
    CrbsError::ValidationFailed {
        message: format!(
            "state database schema is missing required objects ({}): \
             {bridge_hint} to add them, or re-initialize the state database.",
            missing.join(", ")
        ),
    }
}

/// 存量库（戳判等路径）的升级对象探测（SQLite）：整表缺失按 `表 (table)`、
/// 列缺失按 `表.列` 汇集为单条拒绝错误。
async fn probe_upgrade_schema_sqlite_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    use sqlx::Row;
    let mut missing: Vec<String> = Vec::new();
    for (table, columns) in UPGRADE_SCHEMA_PROBE {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = $1",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .db_ctx("probe upgrade table")?;
        if n == 0 {
            missing.push(format!("{table} (table)"));
            continue;
        }
        if columns.is_empty() {
            continue;
        }
        let rows = sqlx::query("SELECT name FROM pragma_table_info($1)")
            .bind(table)
            .fetch_all(pool)
            .await
            .db_ctx("probe upgrade columns")?;
        let present: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();
        for col in *columns {
            if !present.iter().any(|c| c == col) {
                missing.push(format!("{table}.{col}"));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(upgrade_probe_error(&missing, SQLITE_SCHEMA_BRIDGE_HINT))
    }
}

/// 存量库（戳判等路径）的升级对象探测（PostgreSQL）：同 SQLite 版语义，
/// 探测锚 current_schema()（同 [`sql::PROBE_NO_BUSINESS_TABLES_SQL_TEMPLATE`]
/// 注记，不回退硬编码 'public'）。
#[cfg(feature = "postgres")]
async fn probe_upgrade_schema_pg_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    use sqlx::Row;
    let mut missing: Vec<String> = Vec::new();
    for (table, columns) in UPGRADE_SCHEMA_PROBE {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_name = $1 AND table_schema = current_schema()",
        )
        .bind(table)
        .fetch_one(pool)
        .await
        .db_ctx("probe upgrade table")?;
        if n == 0 {
            missing.push(format!("{table} (table)"));
            continue;
        }
        if columns.is_empty() {
            continue;
        }
        // ::text：sqlx Any 驱动不支持 decode PG 的 Name 类型（pg_tests 同款）。
        let rows = sqlx::query(
            "SELECT column_name::text FROM information_schema.columns \
             WHERE table_name = $1 AND table_schema = current_schema()",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .db_ctx("probe upgrade columns")?;
        let present: Vec<String> = rows
            .iter()
            .map(|r| r.get::<String, _>("column_name"))
            .collect();
        for col in *columns {
            if !present.iter().any(|c| c == col) {
                missing.push(format!("{table}.{col}"));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(upgrade_probe_error(&missing, PG_SCHEMA_BRIDGE_HINT))
    }
}

/// SQLite 入口（AnyPool 签名）。三态判定（见模块文档）：空戳表 + 无业务表
/// → fresh init；戳判等 → 升级对象探测后 no-op；其余 → 拒启动 + 重建指引。
pub(crate) async fn ensure_schema_sqlite_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    sqlx::query(&sql::create_schema_version_table_sqlite())
        .execute(pool)
        .await
        .db_ctx("create schema_version")?;

    match probe_schema_stamp(pool, SQLITE_REINIT_HINT).await? {
        ProbeOutcome::Stamped(stamp) => {
            verify_stamp(stamp, SQLITE_REINIT_HINT)?;
            // fresh init 落全量 baseline 必然全齐，只对存量（戳判等）路径探测
            probe_upgrade_schema_sqlite_any(pool).await?;
            tracing::debug!("database schema already at the expected baseline");
            Ok(())
        }
        ProbeOutcome::Unstamped => create_fresh_baseline_sqlite_any(pool).await,
    }
}

/// fresh init：空戳表单事务建 baseline schema 并落戳 (SQLite, AnyPool 签名)。
/// `BEGIN IMMEDIATE` 而非 DEFERRED：立即取写锁（配合 per-connection
/// `busy_timeout`），避免 DEFERRED 先读后升级写触发不可重试的
/// SQLITE_BUSY_SNAPSHOT。
async fn create_fresh_baseline_sqlite_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    let mut conn = pool
        .acquire()
        .await
        .db_ctx("acquire baseline schema conn")?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .db_ctx("begin baseline schema")?;

    // 事务外探测与 BEGIN 间可能有并发进程（server 与 CLI 同时首启）完成
    // 建库：事务内重读，赢家已落戳则核对一致后放弃（空事务提交），不符仍拒。
    let outcome = async {
        match probe_schema_stamp(&mut *conn, SQLITE_REINIT_HINT).await? {
            ProbeOutcome::Unstamped => {
                // 防误覆盖守卫：业务表存在而版本记录缺失 = 版本行被清或库
                // 损坏——拒建、数据原样保留、人工介入。
                assert_no_business_tables_sqlite(&mut conn).await?;
                apply_baseline_ddl_sqlite(&mut conn).await
            }
            ProbeOutcome::Stamped(stamp) => verify_stamp(stamp, SQLITE_REINIT_HINT),
        }
    }
    .await;

    match outcome {
        Ok(()) => {
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit baseline schema")?;
            Ok(())
        }
        Err(e) => {
            // 尽力回滚；失败也返回原始错误(连接归还池后事务不会自动提交)。
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            Err(e)
        }
    }
}

/// fresh init 防误覆盖守卫（SQLite）：[`BUSINESS_TABLES`] 任一存在即拒绝。
async fn assert_no_business_tables_sqlite(conn: &mut sqlx::AnyConnection) -> crate::Result<()> {
    // 表名清单为编译期常量（无注入面），拼 IN 字面量。
    let names = BUSINESS_TABLES
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let n: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ({names})"
    ))
    .fetch_one(&mut *conn)
    .await
    .db_ctx("check for pre-existing business tables")?;
    if n > 0 {
        return Err(CrbsError::ValidationFailed {
            message: "state database already contains business tables but has no usable \
                      schema_version record: this looks like a damaged database. Refusing \
                      to create a baseline over it; back up what you need and \
                      re-initialize (remove/move aside the database file)."
                .to_string(),
        });
    }
    Ok(())
}

/// baseline schema 的 DDL 语句序列（调用方事务内执行）：建表建索引，最后落戳。
async fn apply_baseline_ddl_sqlite(conn: &mut sqlx::AnyConnection) -> crate::Result<()> {
    for stmt in split_ddl_statements(BASELINE_DDL_SQLITE) {
        sqlx::query(stmt)
            .execute(&mut *conn)
            .await
            .db_ctx("apply baseline schema")?;
    }

    sqlx::query(&sql::insert_schema_version_sqlite())
        .bind(SCHEMA_VERSION)
        .execute(&mut *conn)
        .await
        .db_ctx("stamp schema_version")?;
    Ok(())
}

/// SQLite 方言的"重建库"指引：单文件库，指引文件操作。
const SQLITE_REINIT_HINT: &str = "re-initialize the state database (remove/move aside \
     the database file and restart so a fresh baseline is created)";
/// PG 方言的"重建库"指引：无文件语义，只给中性措辞。
#[cfg(feature = "postgres")]
const PG_REINIT_HINT: &str = "re-initialize the state database (drop and re-create it, \
     then restart so a fresh baseline is created)";

/// PostgreSQL 入口（AnyPool 签名）。三态判定与 SQLite 版一致（见模块文档）。
#[cfg(feature = "postgres")]
pub(crate) async fn ensure_schema_pg_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    sqlx::query(&sql::create_schema_version_table_pg())
        .execute(pool)
        .await
        .db_ctx("create schema_version")?;

    match probe_schema_stamp(pool, PG_REINIT_HINT).await? {
        ProbeOutcome::Stamped(stamp) => {
            verify_stamp(stamp, PG_REINIT_HINT)?;
            // fresh init 落全量 baseline 必然全齐，只对存量（戳判等）路径探测
            probe_upgrade_schema_pg_any(pool).await?;
            tracing::debug!("database schema already at the expected baseline");
            Ok(())
        }
        ProbeOutcome::Unstamped => create_fresh_baseline_pg_any(pool).await,
    }
}

/// fresh init：空戳表单事务建 baseline schema 并落戳 (PostgreSQL)。
#[cfg(feature = "postgres")]
async fn create_fresh_baseline_pg_any(pool: &sqlx::AnyPool) -> crate::Result<()> {
    let mut tx = pool.begin().await.db_ctx("begin PG baseline schema")?;

    // PG 无 BEGIN IMMEDIATE 等价物：deferred 事务里并发首启输家看不到未提交
    // 赢家（重读仍空戳、守卫放行），裸 CREATE TABLE 阻塞到赢家提交后报
    // 42P07。事务级 advisory lock（锁 ID 524372339 专属此用途，随事务提交/
    // 回滚自动释放）在 BEGIN 后立刻串行化基线创建：输家等锁后重读见赢家
    // 已落戳，核对一致后放弃。显式 READ COMMITTED 防部署默认 repeatable
    // read——输家快照冻结于事务首读，锁等待结束后重读仍看不到赢家提交的
    // 戳，守卫放行复现 42P07；READ COMMITTED 每语句取新快照，锁后重读必
    // 见赢家戳行。
    sqlx::query(sql::PG_MIGRATION_ISOLATION_SQL)
        .execute(&mut *tx)
        .await
        .db_ctx("set PG baseline schema isolation level")?;
    sqlx::query(sql::PG_MIGRATION_ADVISORY_LOCK_SQL)
        .execute(&mut *tx)
        .await
        .db_ctx("acquire PG baseline schema advisory lock")?;

    // 事务外探测与 BEGIN 间可能有并发首启赢家：事务内重读，一致则放弃，不符仍拒。
    let outcome = async {
        match probe_schema_stamp(&mut *tx, PG_REINIT_HINT).await? {
            ProbeOutcome::Unstamped => {
                // 防误覆盖守卫（同 SQLite 版）：业务表存在而版本记录缺失 → 拒建。
                assert_no_business_tables_pg(&mut tx).await?;
                apply_baseline_ddl_pg(&mut tx).await
            }
            ProbeOutcome::Stamped(stamp) => verify_stamp(stamp, PG_REINIT_HINT),
        }
    }
    .await;

    match outcome {
        Ok(()) => tx.commit().await.db_ctx("commit PG baseline schema")?,
        Err(e) => {
            let _ = tx.rollback().await;
            return Err(e);
        }
    }

    Ok(())
}

/// fresh init 防误覆盖守卫（PostgreSQL）：[`BUSINESS_TABLES`] 任一存在即拒绝。
#[cfg(feature = "postgres")]
async fn assert_no_business_tables_pg(conn: &mut sqlx::AnyConnection) -> crate::Result<()> {
    // 表名清单为编译期常量（无注入面），替换模板占位符。
    let names = BUSINESS_TABLES
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(", ");
    // 探测锚跟随 current_schema()，不硬编码 'public'（见
    // sql::PROBE_NO_BUSINESS_TABLES_SQL_TEMPLATE 注记）。
    let probe_sql = sql::PROBE_NO_BUSINESS_TABLES_SQL_TEMPLATE.replace("{names}", &names);
    let n: i64 = sqlx::query_scalar(&probe_sql)
        .fetch_one(&mut *conn)
        .await
        .db_ctx("check for pre-existing business tables")?;
    if n > 0 {
        return Err(CrbsError::ValidationFailed {
            message: "state database already contains business tables but has no usable \
                      schema_version record: this looks like a damaged database. Refusing \
                      to create a baseline over it; back up what you need and \
                      re-initialize (drop the schema)."
                .to_string(),
        });
    }
    Ok(())
}

/// baseline schema 的 DDL 语句序列（调用方事务内执行）：建表建索引，最后落戳。
#[cfg(feature = "postgres")]
async fn apply_baseline_ddl_pg(conn: &mut sqlx::AnyConnection) -> crate::Result<()> {
    for stmt in split_ddl_statements(BASELINE_DDL_PG) {
        sqlx::query(stmt)
            .execute(&mut *conn)
            .await
            .db_ctx("apply PG baseline schema")?;
    }

    sqlx::query(&sql::insert_schema_version_pg())
        .bind(SCHEMA_VERSION)
        .bind(sql::unix_epoch_secs())
        .execute(&mut *conn)
        .await
        .db_ctx("stamp schema_version")?;

    Ok(())
}

/// tests / pg_tests 双测试模块共用的断言工具与批次列名清单。
#[cfg(test)]
mod test_util {
    use sqlx::Row;

    /// 读库戳：schema_version 恰一行 (version, epoch)。
    pub(super) async fn stamp_row(pool: &sqlx::AnyPool) -> (i64, i64) {
        let rows = sqlx::query(super::sql::SELECT_SCHEMA_STAMP)
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "schema_version must hold exactly one stamp row"
        );
        let row = &rows[0];
        (row.get::<i64, _>(0), row.get::<i64, _>(1))
    }

    /// 删除引用行为（与 PG FK 语义一致）：删 build/task → 引用 SET NULL；删 worker/user → 级联。
    pub(super) async fn assert_fk_delete_behavior(pool: &sqlx::AnyPool) {
        sqlx::query("DELETE FROM builds")
            .execute(pool)
            .await
            .unwrap();
        let build_id: Option<i64> =
            sqlx::query_scalar("SELECT build_id FROM worker_tasks WHERE id = 1")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            build_id, None,
            "deleting build must SET NULL worker_tasks.build_id"
        );

        sqlx::query("DELETE FROM tasks")
            .execute(pool)
            .await
            .unwrap();
        let task_id: Option<i64> =
            sqlx::query_scalar("SELECT task_id FROM worker_tasks WHERE id = 1")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            task_id, None,
            "deleting task must SET NULL worker_tasks.task_id"
        );

        sqlx::query("DELETE FROM workers WHERE id = 1")
            .execute(pool)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            count, 0,
            "deleting worker must CASCADE away worker_tasks rows"
        );

        sqlx::query("DELETE FROM users")
            .execute(pool)
            .await
            .unwrap();
        let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_tokens")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            tokens, 0,
            "deleting user must CASCADE away user_tokens rows"
        );
    }

    /// 批次结构断言的三组列名清单（SQLite / PG 双侧遍历共用，双侧漂移由遍历断言钉住）。
    pub(super) const BUILD_BATCHES_COLS: &[&str] = &[
        "id",
        "product_id",
        "created_by",
        "status",
        "source_repo_url",
        "source_fingerprint",
        "dist",
        "arch_targets",
        "on_failure",
        "force_all",
        "total_items",
        "n_succeeded",
        "n_failed",
        "n_skipped",
        "n_cancelled",
        "request_json",
        "notes",
        "created_at",
        "started_at",
        "finished_at",
    ];
    pub(super) const BATCH_ITEMS_COLS: &[&str] = &[
        "id",
        "batch_id",
        "pkg_name",
        "srpm_nevra",
        "srpm_staging_path",
        "round",
        "state",
        "attempt",
        "task_id",
        "error_code",
        "error_message",
        "updated_at",
    ];
    pub(super) const BUILDS_BATCH_COLS: &[&str] = &[
        "batch_id",
        "created_at",
        "peak_rss_kb",
        "cpu_secs",
        "cpu_p90_cores",
        "srpm_size_bytes",
    ];
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    /// AnyPool 连接 helper：先安装 Any 驱动（幂等），否则 connect 报
    /// "no driver installed"；Any 连接不创建文件，测试先建空文件。
    async fn connect_any(db: &std::path::Path) -> sqlx::AnyPool {
        crate::state::StateStore::install_any_drivers();
        std::fs::File::create(db).unwrap();
        sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap()
    }

    /// SQLite 测试夹具：临时目录 + state.db 连接池；TempDir 由返回值保活
    ///（绑定 `_tmp` 至测试结束，drop 即删库文件）。
    async fn fresh_sqlite_pool() -> (tempfile::TempDir, sqlx::AnyPool) {
        let tmp = tempfile::tempdir().unwrap();
        let pool = connect_any(&tmp.path().join("state.db")).await;
        (tmp, pool)
    }

    async fn assert_unrecognized_refusal(pool: &sqlx::AnyPool) {
        let err = super::ensure_schema_sqlite_any(pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("not recognized by this binary")
                        && message.contains("re-initialize the state database")
            ),
            "expected unrecognized-library refusal with re-init guidance, got: {err:?}"
        );
    }

    /// 拒启动断言：带重建指引、戳行原样保留（行集排序比对，SELECT 无 ORDER BY 不保证行序）。
    async fn assert_stamp_refused(pool: &sqlx::AnyPool, expected_rows: &[(i64, i64)]) {
        assert_unrecognized_refusal(pool).await;
        let mut got: Vec<(i64, i64)> = sqlx::query(super::sql::SELECT_SCHEMA_STAMP)
            .fetch_all(pool)
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get::<i64, _>(0), row.get::<i64, _>(1)))
            .collect();
        got.sort_unstable();
        let mut expected = expected_rows.to_vec();
        expected.sort_unstable();
        assert_eq!(got, expected, "refused gate must not touch schema_version");
    }

    /// 旧世代戳 (1, 2)：version 恰撞预期但 epoch 不同——判等必须双双相等。
    #[tokio::test]
    async fn previous_epoch_stamp_refused_despite_matching_version() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(&super::sql::create_schema_version_table_sqlite())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (1, 0, 2)")
            .execute(&pool)
            .await
            .unwrap();

        assert_stamp_refused(&pool, &[(1, 2)]).await;
    }

    /// 上一世代戳 (1, SCHEMA_EPOCH-1) 拒启：fail-closed 且戳行原样保留（PG 腿对应）。
    #[tokio::test]
    async fn previous_generation_stamp_refused() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(&super::sql::create_schema_version_table_sqlite())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(&format!(
            "INSERT INTO schema_version (version, applied_at, epoch) \
             VALUES (1, 0, {})",
            super::SCHEMA_EPOCH - 1
        ))
        .execute(&pool)
        .await
        .unwrap();

        assert_stamp_refused(&pool, &[(1, super::SCHEMA_EPOCH - 1)]).await;
    }

    /// 高版本戳 (2, 3)：版本高于预期 → 拒降级，戳行原样保留。
    #[tokio::test]
    async fn newer_version_stamp_refused() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(&super::sql::create_schema_version_table_sqlite())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (2, 0, 3)")
            .execute(&pool)
            .await
            .unwrap();

        assert_stamp_refused(&pool, &[(2, 3)]).await;
    }

    /// 零版本戳 (0, 3)：不在预期判等对内 → 拒（预期是精确判等，不是区间）。
    #[tokio::test]
    async fn zero_version_stamp_refused() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(&super::sql::create_schema_version_table_sqlite())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (0, 0, 3)")
            .execute(&pool)
            .await
            .unwrap();

        assert_stamp_refused(&pool, &[(0, 3)]).await;
    }

    /// 多行戳拒启动：version 是 PK 但允许多行并存，见多行即拒、原样保留。
    #[tokio::test]
    async fn multiple_stamp_rows_refused() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(&super::sql::create_schema_version_table_sqlite())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (1, 0, 3)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (2, 0, 3)")
            .execute(&pool)
            .await
            .unwrap();

        assert_stamp_refused(&pool, &[(1, 3), (2, 3)]).await;
    }

    /// 畸形戳行（epoch NULL，手工建可空列复现）解码失败 fail-closed 拒（不得 panic）。
    #[tokio::test]
    async fn malformed_stamp_row_refused() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        sqlx::query(
            "CREATE TABLE schema_version ( \
                 version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, epoch INTEGER \
             )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO schema_version (version, applied_at, epoch) VALUES (1, 0, NULL)")
            .execute(&pool)
            .await
            .unwrap();

        assert_unrecognized_refusal(&pool).await;
        let version: i64 = sqlx::query_scalar("SELECT version FROM schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, 1, "refused gate must not touch schema_version");
    }

    /// epoch-less 残留表：探测报列缺失 → 带重建指引的拒绝；重开仍同型、库内容原样。
    #[tokio::test]
    async fn epoch_less_table_refused_with_reinit_guidance() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        sqlx::query(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();

        for _ in 0..2 {
            let err = super::ensure_schema_sqlite_any(&pool).await.unwrap_err();
            assert!(
                matches!(
                    &err,
                    crate::error::CrbsError::ValidationFailed { message }
                        if message.contains("epoch column") && message.contains("re-initialize")
                ),
                "expected epoch-less refusal with re-init guidance, got: {err:?}"
            );
            let tables: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'tasks'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(tables, 0, "refused gate must not create business tables");
        }
    }

    #[tokio::test]
    async fn fresh_db_gets_baseline() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        assert_eq!(
            super::test_util::stamp_row(&pool).await,
            (super::SCHEMA_VERSION, super::SCHEMA_EPOCH),
            "fresh baseline must stamp the expected (version, epoch) pair"
        );
        let rows = sqlx::query("PRAGMA table_info(tasks)")
            .fetch_all(&pool)
            .await
            .unwrap();
        let cols: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();
        assert!(cols.contains(&"request_json".to_string()));
        assert!(cols.contains(&"pkg_names".to_string()));
    }

    /// 已就绪库重开：no-op（戳行不增不改，baseline 不重建）。
    #[tokio::test]
    async fn fresh_stamp_rerun_is_noop() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        assert_eq!(
            super::test_util::stamp_row(&pool).await,
            (super::SCHEMA_VERSION, super::SCHEMA_EPOCH),
            "already-stamped rerun must be a no-op"
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "stamp table must stay single-row");
    }

    /// 全新库落全量 baseline：资源感知四对象探测放行（fresh init 与重开的
    /// 戳判等路径都走一遍）。
    #[tokio::test]
    async fn upgrade_schema_probe_passes_on_fresh_db() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        super::ensure_schema_sqlite_any(&pool).await.unwrap();
    }

    /// 存量库缺新列（模拟旧库，SQLite 3.35+ DROP COLUMN）：戳判等通过但探测
    /// fail-closed，错误文本指明全部缺失对象并指引桥接脚本；戳行原样保留。
    #[tokio::test]
    async fn upgrade_columns_dropped_refused_with_bridge_guidance() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query("ALTER TABLE builds DROP COLUMN peak_total_kb")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE workers DROP COLUMN disk_free_kb")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP INDEX idx_builds_srpm_sha256")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE builds DROP COLUMN product_config_toml")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_sqlite_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("builds.peak_total_kb")
                        && message.contains("builds.product_config_toml")
                        && message.contains("workers.disk_free_kb")
                        && message.contains("upgrade-resource-schema-sqlite.sh")
                        && message.contains("upgrade-resource-schema-worker.sh")
                        && message.contains("re-initialize the state database")
            ),
            "expected upgrade-probe refusal with bridge guidance, got: {err:?}"
        );
        assert_eq!(
            super::test_util::stamp_row(&pool).await,
            (super::SCHEMA_VERSION, super::SCHEMA_EPOCH),
            "refused probe must not touch schema_version"
        );
    }

    /// 存量库缺新表：探测报 `表 (table)` 形态的缺失并指引桥接脚本。
    #[tokio::test]
    async fn upgrade_table_dropped_refused_with_bridge_guidance() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query("DROP TABLE package_resource_profiles")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DROP TABLE task_labels")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_sqlite_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("package_resource_profiles (table)")
                        && message.contains("task_labels (table)")
                        && message.contains("upgrade-resource-schema-sqlite.sh")
            ),
            "expected upgrade-probe refusal naming the missing tables, got: {err:?}"
        );
    }

    /// 存量库画像表缺 tmpfs 两列（18 列表）：探测 fail-closed 点名两列并指引
    /// 桥接脚本——空列清单只查表存在性曾让这一形态静默通过。
    #[tokio::test]
    async fn profile_tmpfs_columns_dropped_refused_with_bridge_guidance() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query("ALTER TABLE package_resource_profiles DROP COLUMN learned_ema_tmpfs_kb")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE package_resource_profiles DROP COLUMN learned_max_tmpfs_kb")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_sqlite_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("package_resource_profiles.learned_ema_tmpfs_kb")
                        && message.contains("package_resource_profiles.learned_max_tmpfs_kb")
                        && message.contains("upgrade-resource-schema-sqlite.sh")
            ),
            "expected upgrade-probe refusal naming the missing profile columns, got: {err:?}"
        );
    }

    /// 桥接脚本实测（SQLite 双脚本幂等）：含存量行的老形态库各跑两遍 worker /
    /// hub 脚本均成功；重开库启动探测放行（= 桥接后启动正常），存量行新列全
    /// NULL、画像空表与索引就位。依赖 bash + sqlite3 CLI（CI ubuntu 镜像与
    /// 开发机均预装；缺失即跳过——钉的是部署脚本行为，非状态层逻辑）。PG 脚
    /// 本同形状（IF NOT EXISTS），执行依赖本机 PG，随 CI 数据库腿覆盖。
    #[tokio::test]
    async fn bridge_scripts_idempotent_on_legacy_db_with_rows() {
        for prog in ["bash", "sqlite3"] {
            let spawned = std::process::Command::new(prog)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            match spawned {
                Ok(status) if status.success() => {}
                _ => {
                    eprintln!("skip: {prog} not available on this host");
                    return;
                }
            }
        }

        let (tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        // 存量数据行：桥接的保全对象（升级后新列必须全 NULL）。
        sqlx::query("INSERT INTO tasks (product, pkg_name, phase) VALUES ('mydist', 'testpkg', 'succeeded')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, task_id) \
             VALUES ('mydist', 'testpkg', 'succeeded', (SELECT MAX(id) FROM tasks))",
        )
        .execute(&pool)
        .await
        .unwrap();
        // 剥回老形态：资源列 + 画像表 + 快照列 + 标签表（索引随表）——
        // 同探测测试的旧库模拟法。DROP COLUMN 前先删该列的 partial 索引。
        for stmt in [
            "ALTER TABLE builds DROP COLUMN req_min_mem_kb",
            "ALTER TABLE builds DROP COLUMN req_min_ncpu",
            "ALTER TABLE builds DROP COLUMN req_min_disk_kb",
            "ALTER TABLE builds DROP COLUMN peak_total_kb",
            "ALTER TABLE builds DROP COLUMN disk_wbytes",
            "ALTER TABLE builds DROP COLUMN oom_killed",
            "ALTER TABLE builds DROP COLUMN sample_backend",
            "ALTER TABLE builds DROP COLUMN sample_ncpu",
            "ALTER TABLE workers DROP COLUMN disk_free_kb",
            "ALTER TABLE workers DROP COLUMN resource_caps",
            "ALTER TABLE worker_telemetry_samples DROP COLUMN disk_free_kb",
            "DROP TABLE package_resource_profiles",
            "DROP INDEX idx_builds_srpm_sha256",
            "ALTER TABLE builds DROP COLUMN product_config_toml",
            "DROP TABLE task_labels",
        ] {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        pool.close().await;

        let db = tmp.path().join("state.db");
        let manifest = env!("CARGO_MANIFEST_DIR");
        // 首遍落在老形态库，二遍验证幂等（已存在对象一律跳过）；两脚本目标
        // 对象同构，先后互不依赖。
        for script in [
            "upgrade-resource-schema-worker.sh",
            "upgrade-resource-schema-sqlite.sh",
            "upgrade-resource-schema-worker.sh",
            "upgrade-resource-schema-sqlite.sh",
        ] {
            let out = tokio::process::Command::new("bash")
                .arg(format!("{manifest}/../../deploy/{script}"))
                .arg("--db")
                .arg(&db)
                .output()
                .await
                .unwrap();
            assert!(
                out.status.success(),
                "bridge script must succeed on legacy db and re-run idempotently: {script}\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }

        // 桥接后启动：戳判等 + 资源对象探测放行（直连既有库文件，不新建）。
        crate::state::StateStore::install_any_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", db.display()))
            .await
            .unwrap();
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        // 新列存在性 + 存量行全 NULL 一把验证：任一列缺失（SQL 报错）或
        // 非 NULL（布尔和 > 0）都算失败。
        let dirty: i64 = sqlx::query_scalar(
            "SELECT (req_min_mem_kb IS NOT NULL) + (req_min_ncpu IS NOT NULL) \
             + (req_min_disk_kb IS NOT NULL) + (peak_total_kb IS NOT NULL) \
             + (disk_wbytes IS NOT NULL) + (oom_killed IS NOT NULL) \
             + (sample_backend IS NOT NULL) + (sample_ncpu IS NOT NULL) \
             + (product_config_toml IS NOT NULL) \
             FROM builds WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            dirty, 0,
            "legacy row must carry all-NULL new columns after bridging"
        );
        let profiles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM package_resource_profiles")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(profiles, 0, "bridged profiles table must start empty");
        let labels: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM task_labels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(labels, 0, "bridged task_labels table must start empty");
        let index: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND name IN \
             ('idx_profiles_product_mem', 'idx_task_labels_key_value', \
              'idx_builds_srpm_sha256')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(index, 3, "new indexes must exist after bridging");
    }

    /// 业务表存在而版本记录缺失：拒建、数据原样保留——绝不静默 DROP 清库。
    #[tokio::test]
    async fn tables_without_version_rows_refused_not_wiped() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) VALUES ('foo', 'public', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_version")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_sqlite_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("already contains business tables")
                        && message.contains("re-initialize")
            ),
            "expected overwrite refusal, got: {err:?}"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM products")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "guard must not drop existing data");
    }

    async fn index_exists_sqlite(pool: &sqlx::AnyPool, name: &str) -> bool {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = $1",
        )
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
        n > 0
    }

    /// builds.task_id 的 PRAGMA table_info notnull 标志（1 = NOT NULL）。
    async fn builds_task_id_notnull_sqlite(pool: &sqlx::AnyPool) -> i64 {
        let rows = sqlx::query("PRAGMA table_info(builds)")
            .fetch_all(pool)
            .await
            .unwrap();
        rows.iter()
            .find(|r| r.get::<String, _>("name") == "task_id")
            .map(|r| r.get::<i64, _>("notnull"))
            .expect("builds.task_id column must exist")
    }

    async fn table_cols_sqlite(pool: &sqlx::AnyPool, table: &str) -> Vec<String> {
        let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(pool)
            .await
            .unwrap();
        rows.iter().map(|r| r.get::<String, _>("name")).collect()
    }

    /// 全新库 baseline 必含列表复合索引（查询面只能来自 schema.sql baseline）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_list_indexes() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        for idx in [
            "idx_builds_user_id",
            "idx_builds_phase_id",
            "idx_builds_product_id",
            "idx_tasks_phase_id",
            "idx_tasks_product_id",
            "idx_tasks_user_id",
            "idx_tasks_submitted_id",
        ] {
            assert!(
                index_exists_sqlite(&pool, idx).await,
                "fresh install must have index {idx} from baseline"
            );
        }
    }

    /// 全新库 baseline 必含活跃去重 partial 索引（顺带验证 partial 语法可建）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_active_duplicate_index() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        assert!(
            index_exists_sqlite(&pool, "idx_builds_product_pkg_active").await,
            "fresh install must have idx_builds_product_pkg_active from baseline"
        );
    }

    /// 全新库 baseline 必含活跃去重 partial UNIQUE 表达式索引（验证表达式列语法可建）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_active_duplicate_unique_index() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        assert!(
            index_exists_sqlite(&pool, "uq_active_builds_identity").await,
            "fresh install must have uq_active_builds_identity from baseline"
        );
    }

    /// 全新库 baseline 必含密码登录结构（users 密码两列 + sessions 表）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_password_login_structures() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let user_cols = table_cols_sqlite(&pool, "users").await;
        assert!(
            user_cols.contains(&"password_hash".to_string()),
            "fresh install must have users.password_hash: {user_cols:?}"
        );
        assert!(
            user_cols.contains(&"must_change_password".to_string()),
            "fresh install must have users.must_change_password: {user_cols:?}"
        );

        let session_cols = table_cols_sqlite(&pool, "sessions").await;
        for col in [
            "id",
            "user_id",
            "hash",
            "created_at",
            "expires_at",
            "revoked_at",
            "agent",
        ] {
            assert!(
                session_cols.contains(&col.to_string()),
                "sessions table missing column {col}: {session_cols:?}"
            );
        }
    }

    /// 全新库 baseline 必含 workers 负载遥测列 + mem_total_kb 总量基准。
    #[tokio::test]
    async fn fresh_db_baseline_contains_worker_telemetry_columns() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let worker_cols = table_cols_sqlite(&pool, "workers").await;
        for col in [
            "load1",
            "ncpu",
            "cpu_util_pct",
            "mem_used_pct",
            "mem_total_kb",
        ] {
            assert!(
                worker_cols.contains(&col.to_string()),
                "fresh install must have workers.{col}: {worker_cols:?}"
            );
        }
    }

    /// 全新库 baseline 必带 builds.task_id NOT NULL（每构建必须挂任务，杜绝 standalone 行）。
    #[tokio::test]
    async fn fresh_db_baseline_task_id_not_null() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        assert_eq!(
            builds_task_id_notnull_sqlite(&pool).await,
            1,
            "fresh install must have builds.task_id NOT NULL from baseline"
        );
        let null_insert = sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, backend, user) \
             VALUES ('fedora', 'bar-1.0-1', 'pending', 'chroot', 'alice')",
        )
        .execute(&pool)
        .await;
        assert!(
            null_insert.is_err(),
            "baseline must refuse NULL task_id inserts"
        );
    }

    /// FK fixture：1 user/task/build/worker + worker_tasks、user_tokens 各 1 行。
    async fn seed_fk_fixture(pool: &sqlx::AnyPool) {
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, user, phase) \
             VALUES ('fedora', 'foo-1.0-1', 'alice', 'succeeded')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, backend, user, task_id) \
             VALUES ('fedora', 'foo-1.0-1', 'succeeded', 'chroot', 'alice', 1)",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO worker_tasks (build_id, worker_id, task_id) VALUES (1, 1, 1)")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, 'cli', 'hash-a')")
            .execute(pool)
            .await
            .unwrap();
    }

    /// 全新库 baseline 必含全套 FK 行为（worker_tasks 三 FK + user_tokens CASCADE）。
    #[tokio::test]
    async fn fresh_db_baseline_fk_delete_behavior() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        seed_fk_fixture(&pool).await;
        super::test_util::assert_fk_delete_behavior(&pool).await;
    }

    /// 批次 FK fixture：user/官方产品/task + 终态批次(1) 与在途批次(2)，各挂 1 项引用 task 1。
    async fn seed_batch_fixture(pool: &sqlx::AnyPool) {
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) \
             VALUES ('p1', 'public', '{}')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, phase) VALUES ('p1', 'foo-1.0-1', 'succeeded')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO build_batches (id, product_id, created_by, status, source_repo_url) \
             VALUES (1, 1, 1, 'completed', 'https://example.test/repo')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO build_batches (id, status, source_repo_url) \
             VALUES (2, 'running', 'https://example.test/repo')",
        )
        .execute(pool)
        .await
        .unwrap();
        for (item, batch, pkg) in [(1, 1, "foo-1.0-1"), (2, 2, "bar-1.0-1")] {
            sqlx::query(&format!(
                "INSERT INTO batch_items (id, batch_id, pkg_name, round, state, task_id) \
                 VALUES ({item}, {batch}, '{pkg}', 1, 'pending', 1)"
            ))
            .execute(pool)
            .await
            .unwrap();
        }
    }

    /// 全新库 baseline 必含批次两表列全集、builds 批次/资源列与新索引。
    #[tokio::test]
    async fn fresh_db_baseline_contains_batch_structures() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let batch_cols = table_cols_sqlite(&pool, "build_batches").await;
        for col in super::test_util::BUILD_BATCHES_COLS {
            assert!(
                batch_cols.contains(&col.to_string()),
                "build_batches missing column {col}: {batch_cols:?}"
            );
        }

        let item_cols = table_cols_sqlite(&pool, "batch_items").await;
        for col in super::test_util::BATCH_ITEMS_COLS {
            assert!(
                item_cols.contains(&col.to_string()),
                "batch_items missing column {col}: {item_cols:?}"
            );
        }

        let build_cols = table_cols_sqlite(&pool, "builds").await;
        for col in super::test_util::BUILDS_BATCH_COLS {
            assert!(
                build_cols.contains(&col.to_string()),
                "builds missing column {col}: {build_cols:?}"
            );
        }

        for idx in [
            "idx_builds_product_pkg_phase",
            "idx_batch_items_batch_round",
        ] {
            assert!(
                index_exists_sqlite(&pool, idx).await,
                "fresh install must have index {idx} from baseline"
            );
        }
    }

    /// 批次两表的 FK / UNIQUE 行为：同批同包拒；删 task → 批次项 task_id
    /// SET NULL（否则阻塞任务清理）；删批次 → 项级联、builds.batch_id SET NULL；删产品/用户 → 归属列 SET NULL。
    #[tokio::test]
    async fn fresh_db_baseline_batch_fk_and_unique_behavior() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        seed_batch_fixture(&pool).await;

        let dup = sqlx::query(
            "INSERT INTO batch_items (batch_id, pkg_name, round, state) \
             VALUES (1, 'foo-1.0-1', 1, 'pending')",
        )
        .execute(&pool)
        .await;
        assert!(
            dup.is_err(),
            "duplicate (batch_id, pkg_name) must be rejected"
        );

        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, task_id, batch_id) \
             VALUES ('p1', 'foo-1.0-1', 'succeeded', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // 删 build（解除引用）→ 删 task → 批次项 task_id SET NULL（在途项仍在）。
        sqlx::query("DELETE FROM builds")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM tasks")
            .execute(&pool)
            .await
            .unwrap();
        let task_id: Option<i64> =
            sqlx::query_scalar("SELECT task_id FROM batch_items WHERE id = 2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            task_id, None,
            "deleting task must SET NULL batch_items.task_id"
        );

        sqlx::query("DELETE FROM products")
            .execute(&pool)
            .await
            .unwrap();
        let product_id: Option<i64> =
            sqlx::query_scalar("SELECT product_id FROM build_batches WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            product_id, None,
            "deleting product must SET NULL build_batches.product_id"
        );
        sqlx::query("DELETE FROM users")
            .execute(&pool)
            .await
            .unwrap();
        let created_by: Option<i64> =
            sqlx::query_scalar("SELECT created_by FROM build_batches WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            created_by, None,
            "deleting user must SET NULL build_batches.created_by"
        );

        sqlx::query("DELETE FROM build_batches WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        let remaining: Vec<i64> = sqlx::query_scalar("SELECT id FROM batch_items ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec![2],
            "deleting batch must CASCADE its items and leave other batches intact"
        );
    }

    /// 批次 CHECK 域（status 7 / on_failure 2 / state 7 值）与默认值（on_failure='continue'、attempt=0、force_all=0）。
    #[tokio::test]
    async fn fresh_db_baseline_batch_check_domains() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO build_batches (id, status, source_repo_url) \
             VALUES (1, 'preparing', 'https://example.test/repo')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let rejected = [
            "INSERT INTO build_batches (id, status, source_repo_url) \
             VALUES (2, 'queued', 'https://example.test/repo')",
            "UPDATE build_batches SET status = 'paused' WHERE id = 1",
            "INSERT INTO build_batches (id, status, source_repo_url, on_failure) \
             VALUES (3, 'running', 'https://example.test/repo', 'retry')",
            "UPDATE build_batches SET on_failure = 'halt' WHERE id = 1",
            "INSERT INTO batch_items (batch_id, pkg_name, round, state) \
             VALUES (1, 'x-1.0-1', 0, 'queued')",
        ];
        for stmt in rejected {
            let res = sqlx::query(stmt).execute(&pool).await;
            assert!(res.is_err(), "batch CHECK must reject: {stmt}");
        }

        sqlx::query(
            "INSERT INTO batch_items (batch_id, pkg_name, round, state) \
             VALUES (1, 'x-1.0-1', 0, 'pending')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let (on_failure, force_all): (String, i64) =
            sqlx::query_as("SELECT on_failure, force_all FROM build_batches WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (on_failure.as_str(), force_all),
            ("continue", 0),
            "batch defaults must be on_failure='continue', force_all=0"
        );
        let attempt: i64 =
            sqlx::query_scalar("SELECT attempt FROM batch_items WHERE pkg_name = 'x-1.0-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(attempt, 0, "batch item attempt must default to 0");

        for state in [
            "released",
            "succeeded",
            "failed",
            "dep_skipped",
            "skipped_conflict",
            "arch_skipped",
            "cancelled",
        ] {
            let res = sqlx::query(&format!(
                "UPDATE batch_items SET state = '{state}' WHERE pkg_name = 'x-1.0-1'"
            ))
            .execute(&pool)
            .await;
            assert!(
                res.is_ok(),
                "state '{state}' must be in-domain, got {:?}",
                res.err()
            );
        }
    }

    /// 索引清理后形态：查询面索引在位、冗余不再建（覆盖关系见 schema.sql
    /// 注释）；token 名每用户唯一（同用户重名拒，跨用户/NULL 不限）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_index_cleanup_and_unique_token_names() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        for idx in [
            "idx_layers_product",
            "idx_user_tokens_user",
            "idx_user_tokens_user_name",
        ] {
            assert!(
                index_exists_sqlite(&pool, idx).await,
                "fresh install must have index {idx} from baseline"
            );
        }
        for idx in [
            "idx_user_tokens_hash",
            "idx_builds_phase",
            "idx_builds_product",
            "idx_tasks_phase",
            "idx_builds_task_id",
            "idx_artifacts_build",
            "idx_worker_tasks_task",
        ] {
            assert!(
                !index_exists_sqlite(&pool, idx).await,
                "redundant index {idx} must not exist in baseline"
            );
        }

        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, name, role) VALUES (2, 'bob', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, 'cli', 'h1')")
            .execute(&pool)
            .await
            .unwrap();
        let dup =
            sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, 'cli', 'h2')")
                .execute(&pool)
                .await;
        assert!(
            dup.is_err(),
            "same user duplicate token name must be rejected"
        );
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (2, 'cli', 'h3')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, NULL, 'h4')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, NULL, 'h5')")
            .execute(&pool)
            .await
            .unwrap();
    }

    /// 全新库 baseline 的 product_config_history.base_os_revision 不带 DEFAULT
    ///（唯一插入点 INSERT_HISTORY 恒显式供给该列，双方言一致）。
    #[tokio::test]
    async fn fresh_db_baseline_base_os_revision_has_no_default() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let rows = sqlx::query("PRAGMA table_info(product_config_history)")
            .fetch_all(&pool)
            .await
            .unwrap();
        let dflt = rows
            .iter()
            .find(|r| r.get::<String, _>("name") == "base_os_revision")
            .expect("base_os_revision column must exist")
            .get::<Option<String>, _>("dflt_value");
        assert_eq!(
            dflt, None,
            "base_os_revision must carry no DEFAULT in baseline"
        );
    }

    /// 全新库 baseline 必带表 CHECK 约束族：枚举列与布尔列在位；断言匹配
    /// sqlite_master 存档的 CREATE TABLE 文本。
    #[tokio::test]
    async fn fresh_db_baseline_m6_check_constraints() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let create_table_sql = |name: &'static str| {
            let pool = &pool;
            async move {
                let sql: String = sqlx::query_scalar(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = $1",
                )
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap();
                sql
            }
        };

        let phase_domain = concat!(
            "phase IN ('pending', 'assigned', 'building', ",
            "'succeeded', 'failed', 'cancelled', 'timeout')"
        );
        let builds = create_table_sql("builds").await;
        assert!(
            builds.contains(phase_domain),
            "builds.phase CHECK missing: {builds}"
        );
        assert!(
            builds.contains("signed IN (0, 1)")
                && builds.contains("repo_publish IN (0, 1)")
                && builds.contains("repo_consume IN (0, 1)"),
            "builds boolean CHECKs missing: {builds}"
        );
        assert!(
            builds.contains("oom_killed IN (0, 1)")
                && builds.contains("sample_backend IN ('cgroup', 'proc')"),
            "builds resource-sampling CHECKs missing: {builds}"
        );

        let tasks = create_table_sql("tasks").await;
        assert!(
            tasks.contains(phase_domain),
            "tasks.phase CHECK missing: {tasks}"
        );

        let workers = create_table_sql("workers").await;
        assert!(
            workers.contains("status IN ('online', 'offline', 'draining', 'suspended')"),
            "workers.status CHECK missing: {workers}"
        );

        let worker_tasks = create_table_sql("worker_tasks").await;
        assert!(
            worker_tasks
                .contains("status IN ('assigned', 'running', 'completed', 'failed', 'cancelled')"),
            "worker_tasks.status CHECK missing: {worker_tasks}"
        );
        assert!(
            worker_tasks.contains("kind IN ('build', 'init')"),
            "worker_tasks.kind CHECK missing: {worker_tasks}"
        );

        let users = create_table_sql("users").await;
        assert!(
            users.contains("role IN ('admin', 'operator', 'builder', 'viewer')"),
            "users.role CHECK missing: {users}"
        );
        assert!(
            users.contains("status IN ('active', 'disabled')"),
            "users.status CHECK missing: {users}"
        );
        assert!(
            users.contains("must_change_password IN (0, 1)"),
            "users.must_change_password CHECK missing: {users}"
        );

        let layers = create_table_sql("layers").await;
        assert!(
            layers.contains("status = 'complete'"),
            "layers.status CHECK missing: {layers}"
        );

        let products = create_table_sql("products").await;
        assert!(
            products.contains("visibility IN ('public', 'private')"),
            "products.visibility CHECK missing: {products}"
        );
        assert!(
            products.contains("owner_id IS NOT NULL OR visibility = 'public'"),
            "products official-product CHECK missing: {products}"
        );

        let product_acl = create_table_sql("product_acl").await;
        assert!(
            product_acl.contains("role IN ('viewer', 'builder', 'admin')"),
            "product_acl.role CHECK missing: {product_acl}"
        );

        let build_artifacts = create_table_sql("build_artifacts").await;
        assert!(
            build_artifacts
                .contains("kind IN ('rpm', 'srpm', 'log', 'metadata', 'script', 'other')"),
            "build_artifacts.kind CHECK missing: {build_artifacts}"
        );
        assert!(
            build_artifacts.contains("signed IN (0, 1)")
                && build_artifacts.contains("on_disk IN (0, 1)"),
            "build_artifacts boolean CHECKs missing: {build_artifacts}"
        );

        let profiles = create_table_sql("package_resource_profiles").await;
        assert!(
            profiles.contains("learned_backend IN ('cgroup', 'proc')")
                && profiles.contains("learned_censored IN (0, 1)"),
            "package_resource_profiles learned CHECKs missing: {profiles}"
        );
    }

    /// 表 CHECK 行为边界（代表性）：域外拒、域内放行；布尔列两侧均 INTEGER 0/1。
    #[tokio::test]
    async fn fresh_db_baseline_m6_check_rejects_out_of_domain_values() {
        let (_tmp, pool) = fresh_sqlite_pool().await;

        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        // fixture：task 1 / build 1 / worker 1 / user 1 / layer d1（全部合法值）。
        let seed = [
            "INSERT INTO tasks (product, pkg_name) VALUES ('fedora', 'foo-1.0-1')",
            "INSERT INTO builds (product, pkg_name, phase, user, task_id) \
             VALUES ('fedora', 'foo-1.0-1', 'pending', 'alice', 1)",
            "INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')",
            "INSERT INTO users (name, role) VALUES ('alice', 'viewer')",
            "INSERT INTO layers (digest, path, product, status) \
             VALUES ('d1', '/tmp/l1', 'fedora', 'complete')",
        ];
        for stmt in seed {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }

        // 域外值拒绝；worker_tasks 域外值走 INSERT——UPDATE 仅对已有行断言，避免 0 行假阳性。
        let rejected = [
            "INSERT INTO builds (product, pkg_name, phase, user, task_id) \
             VALUES ('fedora', 'rej-1.0-1', 'queued', 'alice', 1)",
            "UPDATE builds SET phase = 'running' WHERE id = 1",
            "UPDATE builds SET signed = 2 WHERE id = 1",
            "UPDATE builds SET repo_publish = 2 WHERE id = 1",
            "UPDATE builds SET repo_consume = 2 WHERE id = 1",
            "INSERT INTO tasks (product, pkg_name, phase) \
             VALUES ('fedora', 'rej-2.0-1', 'started')",
            "UPDATE tasks SET phase = 'unknown' WHERE id = 1",
            "INSERT INTO workers (name, arch, status) VALUES ('rej-w', 'x86_64', 'paused')",
            "UPDATE workers SET status = 'busy' WHERE id = 1",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'done', 'build')",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'running', 'gc')",
            "INSERT INTO users (name, role) VALUES ('rej-u', 'root')",
            "INSERT INTO users (name, role, status) VALUES ('rej-u', 'viewer', 'banned')",
            "INSERT INTO users (name, role, must_change_password) VALUES ('rej-u', 'viewer', 2)",
            "UPDATE users SET role = 'superuser' WHERE id = 1",
            "UPDATE users SET status = 'inactive' WHERE id = 1",
            "INSERT INTO layers (digest, path, product, status) \
             VALUES ('rej-d', '/tmp/l2', 'fedora', 'pending')",
            "UPDATE layers SET status = 'expired' WHERE digest = 'd1'",
            "UPDATE builds SET oom_killed = 2 WHERE id = 1",
            "UPDATE builds SET sample_backend = 'foo' WHERE id = 1",
            "INSERT INTO package_resource_profiles (product, source_name, arch, learned_backend) \
             VALUES ('fedora', 'rej', 'x86_64', 'perf')",
            "INSERT INTO package_resource_profiles (product, source_name, arch, learned_censored) \
             VALUES ('fedora', 'rej2', 'x86_64', 2)",
        ];
        for stmt in rejected {
            let res = sqlx::query(stmt).execute(&pool).await;
            assert!(res.is_err(), "M6 CHECK must reject: {stmt}");
        }

        let accepted = [
            "INSERT INTO tasks (product, pkg_name, phase) \
             VALUES ('fedora', 'ok-1.0-1', 'assigned')",
            "INSERT INTO builds (product, pkg_name, phase, user, task_id) \
             VALUES ('fedora', 'ok-2.0-1', 'assigned', 'alice', 1)",
            "UPDATE builds SET phase = 'succeeded', signed = 1, repo_publish = 0 WHERE id = 1",
            "UPDATE tasks SET phase = 'timeout' WHERE id = 1",
            "INSERT INTO workers (name, arch, status) VALUES ('ok-w', 'x86_64', 'online')",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'running', 'init')",
            "UPDATE worker_tasks SET status = 'completed' WHERE id = 1",
            "INSERT INTO users (name, role, status, must_change_password) \
             VALUES ('ok-u', 'operator', 'disabled', 1)",
            "UPDATE users SET must_change_password = 1 WHERE id = 1",
            "UPDATE builds SET oom_killed = 1, sample_backend = 'cgroup' WHERE id = 1",
            "INSERT INTO package_resource_profiles (product, source_name, arch, learned_backend, learned_censored) \
             VALUES ('fedora', 'ok', 'x86_64', 'proc', 1)",
        ];
        for stmt in accepted {
            let res = sqlx::query(stmt).execute(&pool).await;
            assert!(
                res.is_ok(),
                "M6 CHECK must accept in-domain value, got {:?}: {stmt}",
                res.err()
            );
        }
    }

    /// 全新库 baseline 必含 products / product_config_history / app_meta（PRAGMA 查列，严于 sqlite_master）。
    #[tokio::test]
    async fn fresh_db_baseline_contains_product_and_meta_tables() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        for (table, expected_col) in [
            ("products", "config_json"),
            ("product_config_history", "revision"),
            ("app_meta", "key"),
        ] {
            let rows = sqlx::query(&format!("PRAGMA table_info({})", table))
                .fetch_all(&pool)
                .await
                .unwrap();
            let cols: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();
            assert!(
                cols.contains(&expected_col.to_string()),
                "table {} missing column {}: got {:?}",
                table,
                expected_col,
                cols
            );
        }
    }

    #[tokio::test]
    async fn partial_unique_official_product_name() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) \
             VALUES ('foo', 'public', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let dup = sqlx::query(
            "INSERT INTO products (name, visibility, config_json) \
             VALUES ('foo', 'public', '{}')",
        )
        .execute(&pool)
        .await;
        assert!(
            dup.is_err(),
            "second official product with same name must fail"
        );
    }

    /// 产品名全局唯一——官方/私人/跨用户私人产品之间都不重名。
    #[tokio::test]
    async fn product_name_global_unique() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, name, role) VALUES (2, 'bob', 'builder')")
            .execute(&pool)
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO products (name, owner_id, visibility, config_json) \
             VALUES ('mine', 1, 'private', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let dup_diff_owner = sqlx::query(
            "INSERT INTO products (name, owner_id, visibility, config_json) \
             VALUES ('mine', 2, 'private', '{}')",
        )
        .execute(&pool)
        .await;
        assert!(
            dup_diff_owner.is_err(),
            "different owner same name must fail (global namespace)"
        );

        let dup_same_owner = sqlx::query(
            "INSERT INTO products (name, owner_id, visibility, config_json) \
             VALUES ('mine', 1, 'private', '{}')",
        )
        .execute(&pool)
        .await;
        assert!(dup_same_owner.is_err(), "same owner same name must fail");

        let dup_official = sqlx::query(
            "INSERT INTO products (name, owner_id, visibility, config_json) \
             VALUES ('mine', NULL, 'public', '{}')",
        )
        .execute(&pool)
        .await;
        assert!(
            dup_official.is_err(),
            "official product same name as private must fail"
        );
    }

    #[tokio::test]
    async fn official_product_forbids_private() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let bad = sqlx::query(
            "INSERT INTO products (name, visibility, config_json) \
             VALUES ('foo', 'private', '{}')",
        )
        .execute(&pool)
        .await;
        assert!(
            bad.is_err(),
            "official product cannot be private (CHECK constraint)"
        );
    }

    /// 私人产品省略 visibility 默认 'private'（安全默认；反例造出公开的私人产品，击穿隔离）。
    #[tokio::test]
    async fn private_product_defaults_visibility_to_private() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO products (name, owner_id, config_json) VALUES ('mine', 1, '{}')")
            .execute(&pool)
            .await
            .unwrap();
        let vis: String = sqlx::query_scalar("SELECT visibility FROM products WHERE name = 'mine'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(vis, "private", "default visibility must be 'private'");
    }

    /// 官方产品省略 visibility 被 CHECK 拒（DEFAULT 'private' + owner_id NULL 违反 `owner_id IS NOT NULL OR visibility = 'public'`）。
    #[tokio::test]
    async fn official_product_insert_without_visibility_rejected() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        let bad = sqlx::query("INSERT INTO products (name, config_json) VALUES ('foo', '{}')")
            .execute(&pool)
            .await;
        assert!(
            bad.is_err(),
            "official product without explicit visibility='public' must fail CHECK"
        );
    }

    /// owner_id → users 是 RESTRICT：须先 transfer/delete 产品才能删用户，避免 CASCADE 静默清光配置与历史。
    #[tokio::test]
    async fn owner_delete_restricted_when_products_exist() {
        let (_tmp, pool) = fresh_sqlite_pool().await;
        super::ensure_schema_sqlite_any(&pool).await.unwrap();

        // sqlx 0.8 已默认 PRAGMA foreign_keys=ON，此处只是显式表明依赖
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, owner_id, visibility, config_json) \
             VALUES ('mine', 1, 'private', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let del = sqlx::query("DELETE FROM users WHERE id = 1")
            .execute(&pool)
            .await;
        assert!(
            del.is_err(),
            "deleting user that owns products must fail (RESTRICT)"
        );
    }

    /// PG 探测 SQL 锚定 current_schema()，防回退硬编码 'public'（非 public search_path 部署探不到自己的表）。
    #[test]
    fn pg_probe_sql_anchors_pin_current_schema() {
        let sql = super::sql::PROBE_NO_BUSINESS_TABLES_SQL_TEMPLATE;
        assert!(
            sql.contains("current_schema()"),
            "probe must anchor on current_schema(), got: {sql}"
        );
        assert!(
            !sql.contains("'public'"),
            "probe must not hardcode the 'public' schema, got: {sql}"
        );
        assert!(
            sql.contains("{names}"),
            "business-tables probe must keep its names placeholder for the call site"
        );
    }

    /// 回归测试（无 DB）：advisory lock 语句对不回退——钉的是共享 const 文本
    /// 本身；入口若改抄内联字面量（脱离 const），本测试不再覆盖其运行时
    /// 行为（真 PG 并发行为由 CI/hub 腿覆盖）。
    #[test]
    fn pg_migration_lock_sql_pins_advisory_xact_lock() {
        assert_eq!(
            super::sql::PG_MIGRATION_ISOLATION_SQL,
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
            "PG migration lock pair must pin READ COMMITTED isolation"
        );
        assert!(
            super::sql::PG_MIGRATION_ADVISORY_LOCK_SQL.contains("pg_advisory_xact_lock(524372339)"),
            "PG migration lock pair must keep the shared advisory lock id 524372339, got: {}",
            super::sql::PG_MIGRATION_ADVISORY_LOCK_SQL
        );
    }

    /// 落戳/自举 SQL 的 epoch 值与 [`SCHEMA_EPOCH`] 常量绑定（SQLite + PG
    /// 双侧，无 DB）：四处生成文本必须各自嵌当前常量值（format! 注入）——
    /// 回退成裸字面量时常量前移此处必红；端到端由 fresh-init 断言覆盖。
    #[test]
    fn stamp_sql_epoch_binds_schema_epoch_constant() {
        let cases = [
            (
                "sqlite bootstrap CREATE",
                super::sql::create_schema_version_table_sqlite(),
                format!("epoch INTEGER NOT NULL DEFAULT {}", super::SCHEMA_EPOCH),
            ),
            (
                "sqlite stamp INSERT",
                super::sql::insert_schema_version_sqlite(),
                format!("strftime('%s','now'), {})", super::SCHEMA_EPOCH),
            ),
            (
                "pg bootstrap CREATE",
                super::sql::create_schema_version_table_pg(),
                format!("epoch BIGINT NOT NULL DEFAULT {}", super::SCHEMA_EPOCH),
            ),
            (
                "pg stamp INSERT",
                super::sql::insert_schema_version_pg(),
                format!("VALUES ($1, $2, {})", super::SCHEMA_EPOCH),
            ),
        ];
        for (label, sql, needle) in cases {
            assert!(
                sql.contains(&needle),
                "{label} must embed the current SCHEMA_EPOCH constant ({}), got: {sql}",
                super::SCHEMA_EPOCH
            );
            // 上一世代值不得再以同语法形态出现（防"旧行为残影"复制粘贴）。
            let stale = super::SCHEMA_EPOCH - 1;
            assert!(
                !sql.contains(&format!("DEFAULT {stale} "))
                    && !sql.contains(&format!(", {stale})")),
                "{label} must not embed the previous generation value {stale}: {sql}"
            );
        }
    }

    /// ===== 双 baseline 静态等价守卫（无 DB）=====
    ///
    /// 两侧 baseline 同步纯手工，默认（无 PG env）测试对 schema.pg.sql 零
    /// 验证：编译期 include_str! 两侧，按表解析后互相断言等价，比列（名+序
    /// +归一化定义文本）、CHECK 约束文本、表级约束、索引（名 → 表 + UNIQUE）。
    /// 归一化映射仅限双方言已核实规则（见 schema.pg.sql 头注）：`AUTOINCREMENT≡BIGSERIAL`、`INTEGER/BIGINT` 同型
    ///（sqlite INTEGER 本就 64 位语义）、`datetime('now')≡to_char(NOW()
    /// AT TIME ZONE 'UTC',…)`、`strftime('%s','now')≡EXTRACT(EPOCH FROM
    /// NOW())::bigint`、`REAL≡DOUBLE PRECISION`、DEFAULT 包裹括号差、
    /// `user` 保留字引号、显式 `NULL` 可空标记（PG 侧省略）、表建序差（PG
    /// 按 FK 依赖重排；按表名归组解析天然免疫）。解析不了的结构宁可显式
    /// 跳过；出现未覆盖漂移会红，停下核对，不要为绿而改 schema 或放宽
    /// 归一化。CHECK / 表级约束 / 列总数三维在等价之外各自钉死数值（等价
    /// 只保证互等，对称缩水靠总数钉变红）。
    mod baseline_equivalence {
        use std::collections::BTreeMap;

        /// 表级约束首词（非列定义；单独归位比对，不参与列序断言）。
        const TABLE_CONSTRAINT_KEYWORDS: [&str; 5] =
            ["PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT"];

        /// 方向豁免清单：两侧列集合相同、仅排序方向有意差的索引——豁免只
        /// 放行列条目的方向字段（压成裸列名比对），列集合、谓词、表、UNIQUE
        /// 仍逐项比。现仅 idx_audit_logs_created_at（audit 列表按 id DESC
        /// 排序，该索引仅服务 created_at 范围过滤，方向无查询面影响）；
        /// 改 audit 排序口径须重审本豁免。
        const DIRECTION_EXEMPT_INDEXES: [&str; 1] = ["idx_audit_logs_created_at"];

        /// 豁免索引的列条目压成列名（剥 ASC/DESC），其余原样返回。
        fn comparable_columns(name: &str, columns: &[String]) -> Vec<String> {
            if DIRECTION_EXEMPT_INDEXES.contains(&name) {
                columns
                    .iter()
                    .map(|c| c.split_whitespace().next().unwrap_or_default().to_string())
                    .collect()
            } else {
                columns.to_vec()
            }
        }

        #[derive(Debug, PartialEq, Eq)]
        struct TableDef {
            /// 列定义（归一化全文，CHECK 子句已剥离另比），按声明序。
            columns: Vec<String>,
            /// 表级约束（PRIMARY KEY / UNIQUE / …，CHECK 除外），归一化全文。
            table_constraints: Vec<String>,
            /// 全部 CHECK 约束文本（列级 + 表级），按出现序。
            checks: Vec<String>,
        }

        #[derive(Debug, PartialEq, Eq)]
        struct IndexDef {
            table: String,
            unique: bool,
            /// 列清单（归一化文本、含排序方向，按声明序）。
            columns: Vec<String>,
            /// partial 索引 WHERE 谓词（归一化文本）；全量索引为 None。
            predicate: Option<String>,
        }

        /// 逐行剥离 `--` 行注释：命中首个 `--` 立即截断、不回看引号态——
        /// 引号配平的合法 SQL 下引号感知不可达；未来引入"字符串内 `--`"
        /// 形态时字面量被拦腰截断、冲垮下游 `;` 切分，绝对数钉必红（保守
        /// 方向），届时再恢复引号感知。
        fn strip_line_comment(line: &str) -> &str {
            match line.find("--") {
                Some(i) => &line[..i],
                None => line,
            }
        }

        /// 双方言归一化（顺序敏感的映射链，规则清单见外层模块注释）。
        fn normalize(text: &str) -> String {
            let joined = text
                .lines()
                .map(strip_line_comment)
                .collect::<Vec<_>>()
                .join(" ");
            let s = joined
                // 先保护含 NULL 的复合词，防末尾按词剔除裸 NULL 时误伤。
                .replace("NOT NULL", "\u{1}NN\u{1}")
                .replace("SET NULL", "\u{1}SN\u{1}")
                .replace(
                    "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')",
                    "NOWF",
                )
                .replace("datetime('now')", "NOWF")
                .replace("EXTRACT(EPOCH FROM NOW())::bigint", "EPOCHF")
                .replace("strftime('%s','now')", "EPOCHF")
                .replace("DOUBLE PRECISION", "REAL")
                .replace("BIGSERIAL", "INT64 AUTOINC")
                .replace("BIGINT", "INT64")
                .replace("INTEGER", "INT64")
                // 子句词序差：sqlite `… PRIMARY KEY AUTOINCREMENT` vs pg `BIGSERIAL PRIMARY KEY`。
                .replace("PRIMARY KEY AUTOINCREMENT", "AUTOINC PRIMARY KEY")
                .replace("AUTOINCREMENT", "AUTOINC") // 兜底：对不上会红
                .replace("(NOWF)", "NOWF") // DEFAULT 包裹括号差
                .replace("(EPOCHF)", "EPOCHF")
                .replace('"', ""); // `user` 保留字：pg 侧引号包裹，统一剥掉
                                   // 剩余独立 NULL 词 = 显式可空标记（PG 侧省略），按词剔除后还原。
            s.split_whitespace()
                .filter(|t| *t != "NULL")
                .collect::<Vec<_>>()
                .join(" ")
                .replace("\u{1}NN\u{1}", "NOT NULL")
                .replace("\u{1}SN\u{1}", "SET NULL")
        }

        /// 顶层 `;` 切分（引号/括号感知）→ 归一化语句列表（每条单行文本）。
        fn normalized_statements(sql: &str) -> Vec<String> {
            let mut out = Vec::new();
            let mut cur = String::new();
            let mut depth = 0i32;
            let mut in_quote = false;
            for line in sql.lines() {
                for ch in strip_line_comment(line).chars() {
                    match ch {
                        '\'' => in_quote = !in_quote,
                        '(' if !in_quote => depth += 1,
                        ')' if !in_quote => depth -= 1,
                        ';' if !in_quote && depth == 0 => {
                            let s = normalize(&cur);
                            if !s.is_empty() {
                                out.push(s);
                            }
                            cur.clear();
                            continue;
                        }
                        _ => {}
                    }
                    cur.push(ch);
                }
                cur.push(' ');
            }
            let s = normalize(&cur);
            if !s.is_empty() {
                out.push(s);
            }
            out
        }

        /// 提取条目内全部 `CHECK(…)` 的字符区间（词边界 + 括号配平 + 引号感知，兼容 `CHECK(` 无空格）。
        fn check_spans(chars: &[char]) -> Vec<(usize, usize)> {
            let mut spans = Vec::new();
            let mut i = 0;
            while i + 5 <= chars.len() {
                let word: String = chars[i..i + 5].iter().collect();
                let before_ok =
                    i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
                if word == "CHECK" && before_ok {
                    let mut j = i + 5;
                    while j < chars.len() && chars[j].is_whitespace() {
                        j += 1;
                    }
                    if j < chars.len() && chars[j] == '(' {
                        let mut depth = 0i32;
                        let mut in_quote = false;
                        let mut end = None;
                        while j < chars.len() {
                            let c = chars[j];
                            if c == '\'' {
                                in_quote = !in_quote;
                            } else if !in_quote {
                                if c == '(' {
                                    depth += 1;
                                } else if c == ')' {
                                    depth -= 1;
                                    if depth == 0 {
                                        end = Some(j);
                                        break;
                                    }
                                }
                            }
                            j += 1;
                        }
                        if let Some(e) = end {
                            spans.push((i, e + 1));
                            i = e + 1;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            spans
        }

        /// 提取条目内全部 `CHECK(…)`，返回（剔除后的剩余文本、CHECK 文本
        /// 列表）——列条目与表级约束条目走同一切分。
        fn split_checks(item: &str) -> (String, Vec<String>) {
            let chars: Vec<char> = item.chars().collect();
            let spans = check_spans(&chars);
            let checks = spans
                .iter()
                .map(|&(s, e)| chars[s..e].iter().collect())
                .collect();
            let mut remainder: Vec<char> = Vec::new();
            let mut last = 0;
            for &(s, e) in &spans {
                remainder.extend(&chars[last..s]);
                last = e;
            }
            remainder.extend(&chars[last..]);
            let remainder: String = remainder
                .iter()
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            (remainder, checks)
        }

        /// 归位一个顶层条目：CHECK 统一进 checks；剩余按首词归入列定义或表级约束。
        fn push_item(seg: &mut String, def: &mut TableDef) {
            let item = seg.trim().to_string();
            seg.clear();
            if item.is_empty() {
                return;
            }
            let (remainder, checks) = split_checks(&item);
            def.checks.extend(checks);
            if remainder.is_empty() {
                return;
            }
            let first = remainder.split_whitespace().next().unwrap_or_default();
            if TABLE_CONSTRAINT_KEYWORDS.contains(&first) {
                def.table_constraints.push(remainder);
            } else {
                def.columns.push(remainder);
            }
        }

        /// 解析归一化的 CREATE TABLE 语句：表名 + 顶层逗号切分的条目。
        fn parse_table(stmt: &str) -> Option<(String, TableDef)> {
            let rest = stmt.strip_prefix("CREATE TABLE ")?;
            let name = rest.split_whitespace().next()?.to_string();
            let body = rest.split_once('(')?.1;
            let body = body.rsplit_once(')')?.0;
            let mut def = TableDef {
                columns: Vec::new(),
                table_constraints: Vec::new(),
                checks: Vec::new(),
            };
            let mut seg = String::new();
            let mut depth = 0i32;
            let mut in_quote = false;
            for ch in body.chars() {
                match ch {
                    '\'' => {
                        in_quote = !in_quote;
                        seg.push(ch);
                    }
                    '(' if !in_quote => {
                        depth += 1;
                        seg.push(ch);
                    }
                    ')' if !in_quote => {
                        depth -= 1;
                        seg.push(ch);
                    }
                    ',' if !in_quote && depth == 0 => push_item(&mut seg, &mut def),
                    _ => seg.push(ch),
                }
            }
            push_item(&mut seg, &mut def);
            Some((name, def))
        }

        /// 解析归一化的 CREATE [UNIQUE] INDEX 语句：名 → (表, UNIQUE, 列清单,
        /// WHERE 谓词)。列清单保留排序方向；谓词为归一化全文（None = 全量
        /// 索引），谓词漂移 / partial↔full 翻转 / 列集合改动逐项比对（方向差
        /// 走 [`DIRECTION_EXEMPT_INDEXES`]）。解析从简：表名后首个 `(`
        /// 括号配平切列清单、余文须 WHERE 开头或空；列条目顶层逗号盲切。
        fn parse_index(stmt: &str) -> Option<(String, IndexDef)> {
            let t: Vec<&str> = stmt.split_whitespace().collect();
            if t.first() != Some(&"CREATE") {
                return None;
            }
            let mut i = 1;
            let unique = if t.get(i) == Some(&"UNIQUE") {
                i += 1;
                true
            } else {
                false
            };
            if t.get(i) != Some(&"INDEX") {
                return None;
            }
            i += 1;
            if t.get(i) == Some(&"IF") {
                if t.get(i + 1) != Some(&"NOT") || t.get(i + 2) != Some(&"EXISTS") {
                    return None;
                }
                i += 3;
            }
            let name = (*t.get(i)?).to_string();
            if t.get(i + 1) != Some(&"ON") {
                return None;
            }
            let table = t.get(i + 2)?.split('(').next()?.to_string();
            if table.is_empty() {
                return None;
            }

            // 定位 `ON <table>(`：归一化文本单行单空格，无前文误命中面。
            let marker = format!("ON {table}(");
            let cols_start = stmt.find(&marker)? + marker.len();
            let mut depth = 1i32;
            let mut in_quote = false;
            let mut cols_end = None;
            for (pos, ch) in stmt[cols_start..].char_indices() {
                match ch {
                    '\'' => in_quote = !in_quote,
                    '(' if !in_quote => depth += 1,
                    ')' if !in_quote => {
                        depth -= 1;
                        if depth == 0 {
                            cols_end = Some(cols_start + pos);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let cols_end = cols_end?;
            let columns: Vec<String> = stmt[cols_start..cols_end]
                .split(',')
                .map(|c| c.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect();
            if columns.iter().any(String::is_empty) {
                return None;
            }
            // 余文：partial 为 `WHERE <谓词>`、全量为空；其余形态显式 None 让守卫红。
            let rest = stmt[cols_end + 1..].trim();
            let predicate = match rest.strip_prefix("WHERE ") {
                Some(p) if !p.is_empty() => Some(p.to_string()),
                None if rest.is_empty() => None,
                _ => return None,
            };
            Some((
                name,
                IndexDef {
                    table,
                    unique,
                    columns,
                    predicate,
                },
            ))
        }

        /// 主断言：表集合同集并钉死清单；逐表三维度全等；索引全等 + 总数钉死。
        #[test]
        fn sqlite_and_pg_baselines_are_structurally_equivalent() {
            let sqlite = include_str!("schema.sql");
            let pg = include_str!("schema.pg.sql");

            let sqlite_stmts = normalized_statements(sqlite);
            let pg_stmts = normalized_statements(pg);

            let mut sqlite_tables: BTreeMap<String, TableDef> = BTreeMap::new();
            let mut pg_tables: BTreeMap<String, TableDef> = BTreeMap::new();
            for (stmts, into) in [
                (&sqlite_stmts, &mut sqlite_tables),
                (&pg_stmts, &mut pg_tables),
            ] {
                for s in stmts {
                    if let Some((name, def)) = parse_table(s) {
                        assert!(
                            into.insert(name.clone(), def).is_none(),
                            "duplicate table: {name}"
                        );
                    }
                }
            }
            let mut sqlite_indexes: BTreeMap<String, IndexDef> = BTreeMap::new();
            let mut pg_indexes: BTreeMap<String, IndexDef> = BTreeMap::new();
            for (stmts, into) in [
                (&sqlite_stmts, &mut sqlite_indexes),
                (&pg_stmts, &mut pg_indexes),
            ] {
                for s in stmts {
                    if let Some((name, idx)) = parse_index(s) {
                        assert!(
                            into.insert(name.clone(), idx).is_none(),
                            "duplicate index: {name}"
                        );
                    }
                }
            }

            // 收集处 `if let Some` 会静默跳过解析失败——双侧对称新增不可
            // 解析形态时等价断言全绿；按前缀数原始语句数断言 == 解析产物数。
            let raw_stmt_count = |stmts: &[String], prefixes: &[&str]| {
                stmts
                    .iter()
                    .filter(|s| prefixes.iter().any(|p| s.starts_with(p)))
                    .count()
            };
            for (side, stmts, tables, indexes) in [
                ("sqlite", &sqlite_stmts, &sqlite_tables, &sqlite_indexes),
                ("pg", &pg_stmts, &pg_tables, &pg_indexes),
            ] {
                assert_eq!(
                    raw_stmt_count(stmts, &["CREATE INDEX ", "CREATE UNIQUE INDEX "]),
                    indexes.len(),
                    "{side} baseline: CREATE INDEX statement failed to parse \
                     (guard collection would silently skip it)"
                );
                assert_eq!(
                    raw_stmt_count(stmts, &["CREATE TABLE "]),
                    tables.len(),
                    "{side} baseline: CREATE TABLE statement failed to parse \
                     (guard collection would silently skip it)"
                );
            }

            // 表集合：两侧同集 + 钉死 22 表清单——增删表须双侧同步并有意识更新。
            const EXPECTED_TABLES: [&str; 22] = [
                "app_meta",
                "audit_logs",
                "batch_items",
                "build_artifacts",
                "build_batches",
                "build_reproducibility",
                "builds",
                "layer_packages",
                "layers",
                "package_resource_profiles",
                "package_urls",
                "product_acl",
                "product_config_history",
                "products",
                "sessions",
                "task_labels",
                "tasks",
                "user_tokens",
                "users",
                "worker_tasks",
                "worker_telemetry_samples",
                "workers",
            ];
            let expected: std::collections::BTreeSet<&str> = EXPECTED_TABLES.into_iter().collect();
            let sqlite_names: std::collections::BTreeSet<&str> =
                sqlite_tables.keys().map(String::as_str).collect();
            let pg_names: std::collections::BTreeSet<&str> =
                pg_tables.keys().map(String::as_str).collect();
            assert_eq!(sqlite_names, pg_names, "table set drift between baselines");
            assert_eq!(
                sqlite_names, expected,
                "table set changed: update BOTH baselines in lockstep and this pin"
            );

            // 逐表断言（取不到的表由上方集合等价排除，expect 只归因守卫自身）。
            for (name, sq) in &sqlite_tables {
                let pg = pg_tables.get(name).expect("table set equality asserted");
                let col_name =
                    |c: &String| c.split_whitespace().next().unwrap_or_default().to_string();
                let sq_cols: Vec<String> = sq.columns.iter().map(col_name).collect();
                let pg_cols: Vec<String> = pg.columns.iter().map(col_name).collect();
                assert_eq!(
                    sq_cols, pg_cols,
                    "table {name}: column names/order drift between baselines"
                );
                assert_eq!(
                    sq.columns, pg.columns,
                    "table {name}: normalized column defs drift (type/default/nullability/UNIQUE/REFERENCES)"
                );
                assert_eq!(
                    sq.table_constraints, pg.table_constraints,
                    "table {name}: table-level constraint drift between baselines"
                );
                assert_eq!(
                    sq.checks, pg.checks,
                    "table {name}: CHECK constraint text drift between baselines"
                );
            }

            // 三维总数钉（理由见模块头注）：结构变更须双侧同步并更新钉值
            //（当前钉值：CHECK 29 / 表级约束 7 / 列 253，含遥测采样表 9 列、
            // profiles 表 20 列、task_labels 表 3 列）。
            fn dimension_totals(tables: &BTreeMap<String, TableDef>) -> (usize, usize, usize) {
                (
                    tables.values().map(|d| d.checks.len()).sum(),
                    tables.values().map(|d| d.table_constraints.len()).sum(),
                    tables.values().map(|d| d.columns.len()).sum(),
                )
            }
            let (sq_checks, sq_table_cons, sq_cols) = dimension_totals(&sqlite_tables);
            let (pg_checks, pg_table_cons, pg_cols) = dimension_totals(&pg_tables);
            const EXPECTED_TOTAL_CHECKS: usize = 29;
            const EXPECTED_TOTAL_TABLE_CONSTRAINTS: usize = 7;
            const EXPECTED_TOTAL_COLUMNS: usize = 253;
            assert_eq!(
                sq_checks, EXPECTED_TOTAL_CHECKS,
                "total CHECK constraints (sqlite side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );
            assert_eq!(
                pg_checks, EXPECTED_TOTAL_CHECKS,
                "total CHECK constraints (pg side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );
            assert_eq!(
                sq_table_cons, EXPECTED_TOTAL_TABLE_CONSTRAINTS,
                "total table-level constraints (sqlite side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );
            assert_eq!(
                pg_table_cons, EXPECTED_TOTAL_TABLE_CONSTRAINTS,
                "total table-level constraints (pg side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );
            assert_eq!(
                sq_cols, EXPECTED_TOTAL_COLUMNS,
                "total column count (sqlite side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );
            assert_eq!(
                pg_cols, EXPECTED_TOTAL_COLUMNS,
                "total column count (pg side) changed: symmetric parser regression or real schema change; re-derive from both baselines and update this pin"
            );

            // 索引：名 → (表, UNIQUE, 列清单, WHERE 谓词) 全等；方向差只对豁免索引放行（剥方向比对）。
            let index_view = |m: &BTreeMap<String, IndexDef>| -> BTreeMap<
                String,
                (String, bool, Vec<String>, Option<String>),
            > {
                m.iter()
                    .map(|(n, d)| {
                        (
                            n.clone(),
                            (
                                d.table.clone(),
                                d.unique,
                                comparable_columns(n, &d.columns),
                                d.predicate.clone(),
                            ),
                        )
                    })
                    .collect()
            };
            assert_eq!(
                index_view(&sqlite_indexes),
                index_view(&pg_indexes),
                "index table/uniqueness/columns/predicate drift between baselines \
                 (intended direction differences must be listed in DIRECTION_EXEMPT_INDEXES)"
            );
            assert_eq!(
                sqlite_indexes.len(),
                48,
                "index count changed: keep both baselines in lockstep and update this pin"
            );

            // 同款对称缩水钉：谓词索引数与列条目总数两侧各自钉死。
            let predicates = |m: &BTreeMap<String, IndexDef>| {
                m.values().filter(|d| d.predicate.is_some()).count()
            };
            assert_eq!(
                predicates(&sqlite_indexes),
                12,
                "partial-index count (sqlite side) changed: re-derive from both baselines and update this pin"
            );
            assert_eq!(
                predicates(&pg_indexes),
                12,
                "partial-index count (pg side) changed: re-derive from both baselines and update this pin"
            );
            let col_entries =
                |m: &BTreeMap<String, IndexDef>| m.values().map(|d| d.columns.len()).sum::<usize>();
            // uq_active_builds_identity 的表达式列 COALESCE(arch, '') 顶层
            // 逗号盲切为 2 条（两侧对称），钉值已含此 +1。
            assert_eq!(
                col_entries(&sqlite_indexes),
                74,
                "total index column entries (sqlite side) changed: re-derive from both baselines and update this pin"
            );
            assert_eq!(
                col_entries(&pg_indexes),
                74,
                "total index column entries (pg side) changed: re-derive from both baselines and update this pin"
            );
        }

        /// [`BUSINESS_TABLES`](super::super::BUSINESS_TABLES) 与 baseline 表集合
        /// 互为镜像：漏登清单 = 守卫静默漏防；清单死名 = 误伤"只剩死名表"的库。
        #[test]
        fn business_tables_list_mirrors_baseline_table_set() {
            let sqlite = include_str!("schema.sql");
            let parsed: std::collections::BTreeSet<String> = normalized_statements(sqlite)
                .iter()
                .filter_map(|s| parse_table(s).map(|(name, _)| name))
                .collect();
            let listed: std::collections::BTreeSet<String> = super::super::BUSINESS_TABLES
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            assert_eq!(
                parsed, listed,
                "BUSINESS_TABLES must mirror the baseline table set exactly"
            );
        }

        /// schema_version 自举表双方言等价（不在 baseline 文件里，由方言
        /// 分叉的 CREATE 常量各自建）：类型/取值表达式差被归一化吸收，漂移即红。
        #[test]
        fn schema_version_bootstrap_table_is_dialect_equivalent() {
            assert_eq!(
                normalize(&super::super::sql::create_schema_version_table_sqlite()),
                normalize(&super::super::sql::create_schema_version_table_pg()),
                "schema_version bootstrap table drifts between dialects"
            );
        }

        /// 回归：`--` 剥离命中即截断（含字符串内 `--`，刻意简化；恢复条件
        /// 见 strip_line_comment 注释）。
        #[test]
        fn strip_line_comment_truncates_at_first_marker_regardless_of_quotes() {
            assert_eq!(strip_line_comment("-- don't forget the predicate"), "");
            assert_eq!(
                strip_line_comment("phase TEXT -- don't touch"),
                "phase TEXT "
            );
            assert_eq!(
                strip_line_comment("phase TEXT NOT NULL"),
                "phase TEXT NOT NULL"
            );
            // 刻意披露（ponytail: 上限 = baseline 出现 'a--b' 形态时本断言
            // 即失效提醒，升级路径 = 恢复引号感知）：引号内 `--` 同样截断。
            assert_eq!(
                strip_line_comment("x TEXT DEFAULT 'a--b'"),
                "x TEXT DEFAULT 'a"
            );
        }
    }
}

/// PG 侧迁移测试：`CRBS_TEST_DATABASE_URL` 未设置或非 postgres 时跳过。
/// 共享同一 PG 数据库，跑本组必须 `--test-threads=1`（与 test_state.rs 一致）。
// 两个相邻单 cfg 而非 `all(...)` 复合：clippy 测试豁免只识别 `#[cfg(test)]`
// 单属性，复合形式让本模块按生产代码参与 lint。
#[cfg(test)]
#[cfg(feature = "postgres")]
mod pg_tests {
    use sqlx::Row;

    /// `connect_pg` 跳过样板的单行等价：未配置测试库时打印跳过并早退。
    macro_rules! pg_pool {
        ($pool:ident) => {
            let Some($pool) = connect_pg().await else {
                eprintln!("skipped: CRBS_TEST_DATABASE_URL not set");
                return;
            };
        };
    }

    /// 连接测试 PG（无 URL 返回 None → 跳过）。libpq 两种 scheme 等价接受。
    /// 每个测试重置 schema：共享库不重置会互相毒化（如 future 测试留下的
    /// version=99 让后续全部 fail-closed）。
    async fn connect_pg() -> Option<sqlx::AnyPool> {
        let url = std::env::var("CRBS_TEST_DATABASE_URL").ok()?;
        if !url.starts_with("postgres:") && !url.starts_with("postgresql:") {
            return None;
        }
        crate::state::StateStore::install_any_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::query("DROP SCHEMA public CASCADE")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE SCHEMA public")
            .execute(&pool)
            .await
            .unwrap();
        Some(pool)
    }

    async fn table_columns(pool: &sqlx::AnyPool, table: &str) -> Vec<String> {
        let rows = sqlx::query(
            // ::text：sqlx Any 驱动不支持 decode PG 的 Name 类型；
            // table_schema 锚 current_schema()，防捞到其他 schema 的同名表列。
            "SELECT column_name::text FROM information_schema.columns \
             WHERE table_name = $1 AND table_schema = current_schema()",
        )
        .bind(table)
        .fetch_all(pool)
        .await
        .unwrap();
        rows.iter()
            .map(|r| r.get::<String, _>("column_name"))
            .collect()
    }

    async fn index_exists_pg(pool: &sqlx::AnyPool, name: &str) -> bool {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_indexes WHERE indexname = $1")
            .bind(name)
            .fetch_one(pool)
            .await
            .unwrap();
        n > 0
    }

    #[tokio::test]
    async fn pg_fresh_db_gets_baseline() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();
        assert_eq!(
            super::test_util::stamp_row(&pool).await,
            (super::SCHEMA_VERSION, super::SCHEMA_EPOCH),
            "fresh PG baseline must stamp the expected (version, epoch) pair"
        );
        let cols = table_columns(&pool, "tasks").await;
        assert!(cols.contains(&"request_json".to_string()));
        assert!(cols.contains(&"pkg_names".to_string()));
        // 密码列 + sessions 表 + workers 遥测列全部来自 baseline（fresh 库不跑增量 DDL）。
        let user_cols = table_columns(&pool, "users").await;
        assert!(user_cols.contains(&"password_hash".to_string()));
        assert!(user_cols.contains(&"must_change_password".to_string()));
        let session_cols = table_columns(&pool, "sessions").await;
        assert!(session_cols.contains(&"expires_at".to_string()));
        assert!(session_cols.contains(&"revoked_at".to_string()));
        let worker_cols = table_columns(&pool, "workers").await;
        assert!(worker_cols.contains(&"load1".to_string()));
        assert!(worker_cols.contains(&"ncpu".to_string()));
        assert!(worker_cols.contains(&"mem_used_pct".to_string()));

        // 重开走戳判等路径：附带的升级对象探测对全齐 baseline 放行。
        super::ensure_schema_pg_any(&pool).await.unwrap();
    }

    /// 存量 PG 库缺新列（模拟旧库）：戳判等通过但探测 fail-closed，指引 pg
    /// 桥接脚本（本机无 PG，待 CI 数据库腿执行）。
    #[tokio::test]
    async fn pg_upgrade_columns_dropped_refused_with_bridge_guidance() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        sqlx::query("ALTER TABLE builds DROP COLUMN peak_total_kb")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE builds DROP COLUMN product_config_toml")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_pg_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("builds.peak_total_kb")
                        && message.contains("builds.product_config_toml")
                        && message.contains("upgrade-resource-schema-pg.sh")
                        && message.contains("re-initialize the state database")
            ),
            "expected upgrade-probe refusal with bridge guidance, got: {err:?}"
        );
    }

    /// 紧邻上一世代戳 (1, epoch-1) 拒启（PG 腿，同 SQLite 侧）：fail-closed 且戳行原样保留。
    #[tokio::test]
    async fn pg_previous_generation_stamp_refused() {
        pg_pool!(pool);
        sqlx::query(&super::sql::create_schema_version_table_pg())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(&format!(
            "INSERT INTO schema_version (version, applied_at, epoch) VALUES (1, 0, {})",
            super::SCHEMA_EPOCH - 1
        ))
        .execute(&pool)
        .await
        .unwrap();

        let err = super::ensure_schema_pg_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("not recognized by this binary")
                        && message.contains("re-initialize")
            ),
            "expected unrecognized-library refusal with re-init guidance, got: {err:?}"
        );
        assert_eq!(
            super::test_util::stamp_row(&pool).await,
            (1, super::SCHEMA_EPOCH - 1),
            "refused gate must not touch schema_version"
        );
    }

    /// 多行戳拒启（PG 腿）：探测见多行即拒。
    #[tokio::test]
    async fn pg_multiple_stamp_rows_refused() {
        pg_pool!(pool);
        sqlx::query(&super::sql::create_schema_version_table_pg())
            .execute(&pool)
            .await
            .unwrap();
        for version in [1, 2] {
            sqlx::query(&format!(
                "INSERT INTO schema_version (version, applied_at, epoch) \
                 VALUES ({version}, 0, {})",
                super::SCHEMA_EPOCH
            ))
            .execute(&pool)
            .await
            .unwrap();
        }

        let err = super::ensure_schema_pg_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("multiple stamp rows")
            ),
            "expected multiple-stamp refusal, got: {err:?}"
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schema_version")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "refused gate must not touch schema_version");
    }

    /// 全新 PG 库 baseline 必含批次结构（与 SQLite 侧 fresh_db_baseline_contains_batch_structures 同款）。
    #[tokio::test]
    async fn pg_fresh_db_baseline_contains_batch_structures() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        let batch_cols = table_columns(&pool, "build_batches").await;
        for col in super::test_util::BUILD_BATCHES_COLS {
            assert!(
                batch_cols.contains(&col.to_string()),
                "build_batches missing column {col}: {batch_cols:?}"
            );
        }
        let item_cols = table_columns(&pool, "batch_items").await;
        for col in super::test_util::BATCH_ITEMS_COLS {
            assert!(
                item_cols.contains(&col.to_string()),
                "batch_items missing column {col}: {item_cols:?}"
            );
        }
        let build_cols = table_columns(&pool, "builds").await;
        for col in super::test_util::BUILDS_BATCH_COLS {
            assert!(
                build_cols.contains(&col.to_string()),
                "builds missing column {col}: {build_cols:?}"
            );
        }
        let worker_cols = table_columns(&pool, "workers").await;
        assert!(
            worker_cols.contains(&"mem_total_kb".to_string()),
            "workers.mem_total_kb missing: {worker_cols:?}"
        );

        for idx in [
            "idx_builds_product_pkg_phase",
            "idx_batch_items_batch_round",
        ] {
            assert!(
                index_exists_pg(&pool, idx).await,
                "fresh PG install must have index {idx} from baseline"
            );
        }

        sqlx::query("INSERT INTO users (name, role) VALUES ('alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO build_batches (id, status, source_repo_url) \
             VALUES (1, 'completed', 'https://example.test/repo')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO batch_items (id, batch_id, pkg_name, round, state) \
             VALUES (1, 1, 'foo-1.0-1', 1, 'pending')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let dup = sqlx::query(
            "INSERT INTO batch_items (batch_id, pkg_name, round, state) \
             VALUES (1, 'foo-1.0-1', 1, 'pending')",
        )
        .execute(&pool)
        .await;
        assert!(
            dup.is_err(),
            "duplicate (batch_id, pkg_name) must be rejected"
        );
        sqlx::query("DELETE FROM build_batches WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM batch_items")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "deleting batch must CASCADE its items");
    }

    /// 业务表存在而版本记录缺失（PG 版）：拒建 baseline、数据原样保留。
    #[tokio::test]
    async fn pg_tables_without_version_rows_refused_not_wiped() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) VALUES ('foo', 'public', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM schema_version")
            .execute(&pool)
            .await
            .unwrap();

        let err = super::ensure_schema_pg_any(&pool).await.unwrap_err();
        assert!(
            matches!(
                &err,
                crate::error::CrbsError::ValidationFailed { message }
                    if message.contains("already contains business tables")
            ),
            "expected overwrite refusal, got: {err:?}"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM products")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "guard must not drop existing data");
    }

    /// 全新 PG 库 baseline 必含列表复合索引（只能来自 schema.pg.sql baseline）。
    #[tokio::test]
    async fn pg_fresh_db_baseline_contains_list_indexes() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();
        for idx in [
            "idx_builds_user_id",
            "idx_builds_phase_id",
            "idx_builds_product_id",
            "idx_tasks_phase_id",
            "idx_tasks_product_id",
            "idx_tasks_user_id",
            "idx_tasks_submitted_id",
        ] {
            assert!(
                index_exists_pg(&pool, idx).await,
                "fresh PG install must have index {idx} from baseline"
            );
        }
    }

    #[tokio::test]
    async fn pg_fresh_db_baseline_task_id_not_null() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();
        let nullable: String = sqlx::query_scalar(
            "SELECT is_nullable::text FROM information_schema.columns \
             WHERE table_name = 'builds' AND column_name = 'task_id' \
             AND table_schema = current_schema()",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            nullable, "NO",
            "fresh PG install must have builds.task_id NOT NULL from baseline"
        );
    }

    /// 全新 PG baseline 的表 CHECK 族（与 SQLite 侧同语义）：枚举列与布尔列
    /// 在位 + 域外值拒绝；布尔列两侧均 INTEGER 0/1（见 schema.pg.sql 头注）。
    #[tokio::test]
    async fn pg_fresh_db_baseline_m6_check_constraints() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        // 每表 CHECK 计数：builds phase+signed+repo_publish+repo_consume+deterministic
        // +oom_killed+sample_backend；tasks phase；workers status；
        // worker_tasks status+kind；users role+status+must_change_password；
        // layers status+ref_count；products visibility+官方产品表级；
        // product_acl role；build_artifacts kind+signed+on_disk；
        // build_batches status+on_failure；batch_items state；
        // package_resource_profiles learned_backend+learned_censored。
        // 必须查 pg_constraint（contype='c'）：information_schema 的
        // table_constraints 会把每个 NOT NULL 列也合成一行 CHECK，计数虚高。
        for (table, expected) in [
            ("builds", 7),
            ("tasks", 1),
            ("workers", 1),
            ("worker_tasks", 2),
            ("users", 3),
            ("layers", 2),
            ("products", 2),
            ("product_acl", 1),
            ("build_artifacts", 3),
            ("build_batches", 2),
            ("batch_items", 1),
            ("package_resource_profiles", 2),
        ] {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM pg_constraint con \
                 JOIN pg_class rel ON rel.oid = con.conrelid \
                 JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace \
                 WHERE nsp.nspname = 'public' AND rel.relname = $1 AND con.contype = 'c'",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                n, expected,
                "table {table} must carry exactly {expected} CHECK constraints"
            );
        }

        // 行为边界（代表性）：域外拒、域内放行（"user" 是 PG 保留字需引号；
        // 被拒 INSERT 也消耗序列号，id 断言只锚先于拒绝播种的行）。
        sqlx::query("INSERT INTO tasks (product, pkg_name) VALUES ('fedora', 'foo-1.0-1')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (name, role) VALUES ('alice', 'viewer')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, \"user\", task_id) \
             VALUES ('fedora', 'foo-1.0-1', 'pending', 'alice', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO layers (digest, path, product, status) \
             VALUES ('d1', '/tmp/l1', 'fedora', 'complete')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let rejected = [
            "INSERT INTO builds (product, pkg_name, phase, \"user\", task_id) \
             VALUES ('fedora', 'rej-1.0-1', 'queued', 'alice', 1)",
            "UPDATE builds SET phase = 'running' WHERE task_id = 1",
            "INSERT INTO workers (name, arch, status) VALUES ('rej-w', 'x86_64', 'paused')",
            "UPDATE workers SET status = 'busy' WHERE name = 'w1'",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'done', 'build')",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'running', 'gc')",
            "INSERT INTO users (name, role) VALUES ('rej-u', 'root')",
            "INSERT INTO users (name, role, status) VALUES ('rej-u', 'viewer', 'banned')",
            "UPDATE users SET role = 'superuser' WHERE name = 'alice'",
            "UPDATE users SET status = 'inactive' WHERE name = 'alice'",
            "UPDATE layers SET status = 'expired' WHERE digest = 'd1'",
            "INSERT INTO layers (digest, path, product, status) \
             VALUES ('rej-d', '/tmp/l2', 'fedora', 'pending')",
        ];
        for stmt in rejected {
            let res = sqlx::query(stmt).execute(&pool).await;
            assert!(res.is_err(), "M6 CHECK must reject: {stmt}");
        }

        let accepted = [
            "INSERT INTO builds (product, pkg_name, phase, \"user\", task_id) \
             VALUES ('fedora', 'ok-1.0-1', 'pending', 'alice', 1)",
            "UPDATE builds SET signed = 1, repo_publish = 0",
            "UPDATE builds SET phase = 'succeeded'",
            "INSERT INTO workers (name, arch, status) VALUES ('ok-w', 'x86_64', 'online')",
            "INSERT INTO worker_tasks (worker_id, status, kind) VALUES (1, 'assigned', 'init')",
            "UPDATE worker_tasks SET status = 'completed'",
            "UPDATE users SET must_change_password = 1 WHERE name = 'alice'",
            "INSERT INTO users (name, role, status) VALUES ('ok-u', 'operator', 'disabled')",
        ];
        for stmt in accepted {
            let res = sqlx::query(stmt).execute(&pool).await;
            assert!(
                res.is_ok(),
                "M6 CHECK must accept in-domain value, got {:?}: {stmt}",
                res.err()
            );
        }
    }

    /// PG baseline 的 FK 删除行为（契约同 SQLite 侧；断言逐项对应）。
    #[tokio::test]
    async fn pg_baseline_fk_delete_behavior() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) \
             VALUES ('fedora', 'foo-1.0-1', 'alice', 'succeeded')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, backend, \"user\", task_id) \
             VALUES ('fedora', 'foo-1.0-1', 'succeeded', 'chroot', 'alice', 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO worker_tasks (build_id, worker_id, task_id) VALUES (1, 1, 1)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO user_tokens (user_id, name, hash) VALUES (1, 'cli', 'hash-a')")
            .execute(&pool)
            .await
            .unwrap();

        super::test_util::assert_fk_delete_behavior(&pool).await;
    }

    /// 全新 PG 库 baseline 必含索引清理后形态（查询面索引来自 schema.pg.sql，冗余不再建）。
    #[tokio::test]
    async fn pg_fresh_db_baseline_contains_index_cleanup() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        for idx in [
            "idx_workers_secret_hash",
            "idx_layers_gc",
            "idx_builds_phase_pid",
            "idx_builds_task_arch",
            "idx_audit_logs_action",
            "idx_audit_logs_created_at",
        ] {
            assert!(
                index_exists_pg(&pool, idx).await,
                "fresh PG install must have index {idx} from baseline"
            );
        }
        for idx in [
            "idx_builds_phase",
            "idx_builds_product",
            "idx_tasks_phase",
            "idx_tasks_product",
            "idx_builds_task_id",
            "idx_artifacts_build",
            "idx_products_name_owner",
            "idx_layers_ref_count",
            "idx_builds_phase_product",
        ] {
            assert!(
                !index_exists_pg(&pool, idx).await,
                "redundant index {idx} must not exist in baseline"
            );
        }
    }

    /// PG baseline 的 base_os_revision 不带 DEFAULT，省略该列的 INSERT 被 NOT NULL 拒（双方言一致）。
    #[tokio::test]
    async fn pg_fresh_db_baseline_base_os_revision_no_default() {
        pg_pool!(pool);
        super::ensure_schema_pg_any(&pool).await.unwrap();

        let dflt: Option<String> = sqlx::query_scalar(
            "SELECT column_default::text FROM information_schema.columns \
             WHERE table_name = 'product_config_history' \
             AND column_name = 'base_os_revision' \
             AND table_schema = current_schema()",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            dflt, None,
            "fresh PG baseline must carry no base_os_revision default"
        );

        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) \
             VALUES ('fedora', 'public', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let ins = sqlx::query(
            "INSERT INTO product_config_history (product_id, revision, config_json) \
             VALUES (1, 1, '{}')",
        )
        .execute(&pool)
        .await;
        assert!(
            ins.is_err(),
            "INSERT without base_os_revision must be rejected (NOT NULL, no default)"
        );
    }
}
