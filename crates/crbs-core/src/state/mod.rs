// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 状态存储：追踪构建记录，SQLite / PostgreSQL 双后端支持。

pub(crate) mod app_meta;
pub(crate) mod artifacts;
pub(crate) mod audit;
pub(crate) mod batches;
pub(crate) mod builds;
pub(crate) mod db;
pub(crate) mod dispatch;
pub(crate) mod gc;
pub(crate) mod gc_queries;
pub(crate) mod layer_packages;
pub(crate) mod layers;
pub(crate) mod migrate;
pub(crate) mod product_queries;
pub(crate) mod product_resolve;
pub(crate) mod products;
pub(crate) mod profiles;
pub(crate) mod reproducibility;
pub(crate) mod reproducibility_stats;
pub(crate) mod retention;
pub(crate) mod seed;
pub(crate) mod sessions;
pub(crate) mod tasks;
pub(crate) mod types;
pub(crate) mod users;
pub(crate) mod workers;
pub(crate) mod zombie;

#[cfg(test)]
pub(crate) mod test_state;

#[cfg(test)]
mod race_matrix;

mod sql {
    // SQLITE-ONLY: PRAGMA 是 SQLite 特有语法；Postgres 不需要 WAL（默认 MVCC）。
    pub(super) const ENABLE_WAL_MODE: &str = "PRAGMA journal_mode = WAL;";

    /// SQLITE-ONLY：WAL 日志收缩上限 64 MiB。WAL checkpoint 后不主动收缩，
    /// 长事务阻塞 checkpoint 期间 `-wal` 持续追加并常驻磁盘，设上限后每次
    /// checkpoint 截回该值。per-connection PRAGMA（连接级默认 -1），须随
    /// after_connect 每连接重申，非池级一次设置。
    pub(super) const JOURNAL_SIZE_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";

    /// SQLITE-ONLY：synchronous 降为 NORMAL，WAL 下 commit 只写 WAL 不逐次
    /// fsync，落盘收敛到 checkpoint 时点，单次 commit 不再承担 fsync 成本。
    /// OS 崩溃/断电可丢最近数秒 commit（进程崩溃不丢）；适用边界：worker 本地库
    /// = 可重建缓存与账面（任务事实源在 hub，崩掉的构建由 hub 重驱）。
    /// per-connection PRAGMA，须随 after_connect 每连接重申，非池级一次设置。
    // ponytail: 需要严格持久化的部署形态，移除本 pragma 即回编译默认 FULL。
    pub(super) const SYNCHRONOUS_NORMAL: &str = "PRAGMA synchronous = NORMAL";
}

pub(crate) use db::Dialect;

/// 事务体统一错误路径（state 层各写事务共用）：回滚后透出原错误，不得掩盖；
/// rollback 自身失败仅 debug 留痕（连接归还池，aborted-transaction 兜底暴露）。
macro_rules! rollback_and_return {
    ($conn:expr, $err:expr) => {{
        if let Err(rb) = sqlx::query("ROLLBACK").execute(&mut *$conn).await {
            tracing::debug!(error = %rb, "rollback failed after error (connection aborted)");
        }
        return Err($err);
    }};
}
pub(crate) use rollback_and_return;

pub use tasks::FinalizeOutcome;
pub(crate) use types::{
    build_record_from_row, layer_record_from_row, pending_build_info_from_row, BUILD_COLUMNS,
};
pub use types::{
    BuildInsert, BuildPackage, BuildRecord, LatestSourceBuild, LayerRecord, NvrGroupFilter,
    NvrGroupSummary, PendingBuildInfo, TaskInsert, TaskRebuildInfo, TaskRecord,
};
// 类型的公共 re-export（此行同时是 rustfmt use 分组边界，勿删）。
use crate::error::DbResultExt;
pub use batches::{
    BatchInsert, BatchItemRecord, BatchProgress, BatchRecord, FailedBatchItem, NewBatchItem,
    SkippedBatchItem,
};
pub use dispatch::{Assignment, DispatchCandidate, LearnedGateSnapshot};
pub use product_resolve::ResolvedProduct;
pub use products::{
    CreateProductInput, ProductConfigHistoryEntry, ProductRecord, ProductStub, ProductSummary,
    UpdateOutcome, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC,
};
pub use profiles::{
    DeclaredRequirements, LearnedWeightSnapshot, PackageResourceProfile, ProfileUpdateDecision,
    ResourceSampleOutcome, SampleBackend, DEFAULT_CENSOR_HEADROOM,
};
pub use reproducibility::{
    CompareDetail, NewReproducibility, ReplayVerdict, ReproducibilityRecord, RpmCompareEntry,
    ALL_VERDICTS, KIND_CROSS_ARCH_NOARCH, KIND_REPLAY,
};
pub use workers::{
    AssignedTaskInfo, BuildLifecycle, DeleteWorkerOutcome, InitConflict, TelemetrySamplePoint,
    WorkerActiveBuild, WorkerFilter, WorkerRecentBuild, WorkerRecentInit, WorkerStatus,
    WorkerTelemetry, HUB_LOCAL_WORKER_NAME, RESOURCE_CAP_CGROUP_V2, RESOURCE_CAP_IO_STAT,
    RESOURCE_CAP_MEMORY_EVENTS, RESOURCE_CAP_MEMORY_PEAK, RESOURCE_CAP_PSI,
    TELEMETRY_SAMPLE_QUERY_LIMIT,
};

/// 状态存储：追踪构建记录，AnyPool 统一抽象 SQLite / PostgreSQL。
#[derive(Clone)]
pub struct StateStore {
    pool: sqlx::AnyPool,
    dialect: Dialect,
    crbs_root: std::path::PathBuf,
    /// chain-resolve 结果缓存（key=product_id）。不变量：`products` 表写入必须
    /// 经 `StateStore` 方法并在事务提交后调 `invalidate_resolve`——命中即盲信，
    /// 无 DB 侧 revision 复核，裸 SQL 写产品表会破坏盲信（review 靠 grep 守护）。
    /// `Arc<RwLock<..>>` 使 `Clone` 共享；`std::sync::RwLock` 不跨 await。
    resolve_cache: std::sync::Arc<
        std::sync::RwLock<std::collections::HashMap<i64, product_resolve::CachedResolve>>,
    >,
    /// resolve 缓存代数：失效先 bump 再 remove；miss 回源前取代数、插入前复核，
    /// 防"读写交错"把失效前读到的旧快照回填进已清空的缓存（永久陈旧）。
    resolve_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// 状态变更通知（SSE 去轮询化）：关键写方法成功后群发唤醒，SSE 循环通知
    /// 驱动 + 兜底轮询；`Arc` 使 `Clone` 共享，`Notify` 无锁，`&self` 可直接
    /// 访问。进程内机制：hub 是唯一写入口，无遗漏源，无需 PG LISTEN/NOTIFY。
    /// ponytail: 多 hub / 跨进程写场景需换 NOTIFY 或逻辑复制，接口已隔离在
    /// `notify_state_changed`/`changed` 之后。
    change_notify: std::sync::Arc<tokio::sync::Notify>,
    /// 用户域代数计数器（认证缓存失效源）：影响认证判定的写方法成功后 bump，
    /// AuthCache 以填充时代数比对当前代数，失配即回源。`Arc` 使 `Clone` 共享；
    /// AtomicU64 读方无锁不睡眠（认证每请求都读，须零成本）。进程内、方言
    /// 无关，与 `change_notify` 同一 hub 单进程论证。
    user_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// 引擎本地库热路径写漏斗（[`Self::local_write_permit`] 的闸门）：SQLite
    /// 单写者锁上 N 个短写各自 busy_timeout 排队，不如进程内先串行。锁内只有
    /// 毫秒级短写语句，不跨网络 IO/长操作；读路径不取闸（WAL 读写并行保留）。
    /// `Arc` 使 `Clone` 共享（Clone = 同库多句柄，共闸才算同一漏斗）。
    local_write_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// 默认连接池大小（双方言一致）。SQLite WAL 读并发友好、写串行（busy_timeout
/// 兜底），池大小主要决定并发读吞吐，8 足够。
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 8;

/// 连接池 acquire 超时（秒）：池耗尽 / DB 不可达快速失败（→
/// `CrbsError::DatabaseUnavailable` → HTTP 503）而非挂起；10s 覆盖 SQLite
/// busy_timeout（5s）并留 PG 建连余量。
const DB_ACQUIRE_TIMEOUT_SECS: u64 = 10;

/// crbs-server 在其 root 下写入的归属标记文件名（marker 护栏）。server 启动
/// 时写 `{server_root}/.crbs-server-root`；引擎侧发现即拒绝开库并给分流
/// 指引，结构性防引擎写坏 server 库。
pub const SERVER_ROOT_MARKER: &str = ".crbs-server-root";

/// 连接池大小决议（纯函数便于单测）：env（`CRBS_DB_MAX_CONNECTIONS`）>
/// server.toml `db_max_connections` > 默认 8。非法值（非数字 / <1）warn 后
/// 回退下一级；CLI / worker / 测试路径 `configured` 传 `None`。
fn resolve_pool_max_connections(env_raw: Option<&str>, configured: Option<u32>) -> u32 {
    let from_env = env_raw
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|v| *v >= 1);
    let from_config = configured.filter(|v| *v >= 1);
    let resolved = from_env
        .or(from_config)
        .unwrap_or(DEFAULT_DB_MAX_CONNECTIONS);
    if from_env.is_none() {
        if let Some(v) = env_raw {
            tracing::warn!(value = %v, fallback = resolved, "Invalid CRBS_DB_MAX_CONNECTIONS, using fallback");
        }
    }
    if from_config.is_none() {
        if let Some(v) = configured {
            tracing::warn!(value = %v, fallback = resolved, "Invalid db_max_connections config, using fallback");
        }
    }
    resolved
}

/// 构建失败重入预算：reclaimer / zombie 把活跃构建重置回 pending 时
/// `attempt + 1`，达上限不再重排、转终态 failed——毒丸包（必 OOM / 断连）
/// 否则无限循环吃光槽位。
pub const MAX_BUILD_ATTEMPTS: i64 = 3;

impl StateStore {
    /// 打开或创建 SQLite 数据库（默认路径 `{crbs_root}/crbs.db`），启用 WAL，建表建索引。
    pub async fn new(crbs_root: &std::path::Path) -> crate::Result<Self> {
        Self::new_with_db_path(&crbs_root.join("crbs.db"), crbs_root).await
    }

    /// 引擎世界（crbs CLI / BuildEngine CLI 构造器）专用开库入口：root 含
    /// crbs-server 归属标记（[`SERVER_ROOT_MARKER`]）即拒绝，防引擎把本地
    /// 构建历史写进 server 库。server / worker 的 open 路径（`new` /
    /// `new_with_db_path` / `new_with_url`）不做此检查。
    pub async fn open_for_engine(crbs_root: &std::path::Path) -> crate::Result<Self> {
        let marker = crbs_root.join(SERVER_ROOT_MARKER);
        if tokio::fs::try_exists(&marker).await.unwrap_or_else(|e| {
            tracing::debug!(
                path = %marker.display(),
                error = %e,
                "stat server root marker failed; treating as absent"
            );
            false
        }) {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "refusing to open state store: '{}' is a crbs-server root \
                     (marker file '{}' present). The engine CLI must use its own \
                     engine root (crbs.toml 'crbs_root', default /var/lib/crbs-engine). \
                     Query submitted tasks via the web UI / API; query local builds \
                     with the engine CLI against its own root.",
                    crbs_root.display(),
                    SERVER_ROOT_MARKER,
                ),
            });
        }
        Self::new(crbs_root).await
    }

    /// 从指定数据库路径打开或创建 SQLite，启用 WAL，建表建索引。
    pub async fn new_with_db_path(
        db_path: &std::path::Path,
        crbs_root: &std::path::Path,
    ) -> crate::Result<Self> {
        Self::new_with_db_path_and_pool(db_path, crbs_root, None).await
    }

    /// 同 [`Self::new_with_db_path`]，但并入 server.toml `db_max_connections`
    ///（env > 配置 > 默认 8）；crbs-server run 专用，CLI / 测试走原入口。
    pub async fn new_with_db_path_and_pool(
        db_path: &std::path::Path,
        crbs_root: &std::path::Path,
        db_max_connections: Option<u32>,
    ) -> crate::Result<Self> {
        let db_url = format!("sqlite://{}", db_path.display());
        Self::new_with_url_and_pool(&db_url, crbs_root, db_max_connections).await
    }

    /// 从数据库 URL 打开连接（统一入口）：SQLite `sqlite:///path/to/file.db` /
    /// PostgreSQL `postgres://user:pass@host/dbname`。池大小只认
    /// `CRBS_DB_MAX_CONNECTIONS` env / 默认；要并入 server.toml
    /// `db_max_connections` 走 [`Self::new_with_url_and_pool`]。
    pub async fn new_with_url(db_url: &str, crbs_root: &std::path::Path) -> crate::Result<Self> {
        Self::new_with_url_and_pool(db_url, crbs_root, None).await
    }

    /// 同 [`Self::new_with_url`]，但把 server.toml `db_max_connections` 并入
    /// 连接池大小优先级（env > 配置 > 默认 8）。
    pub async fn new_with_url_and_pool(
        db_url: &str,
        crbs_root: &std::path::Path,
        db_max_connections: Option<u32>,
    ) -> crate::Result<Self> {
        Self::install_any_drivers();

        let dialect = Dialect::from_url(db_url)?;
        let crbs_root = crbs_root.to_path_buf();

        match dialect {
            Dialect::Sqlite => Self::connect_sqlite(db_url, crbs_root, db_max_connections).await,
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                Self::connect_postgres(db_url, crbs_root, db_max_connections).await
            }
        }
    }

    /// 安装所有编译启用的 AnyPool 驱动（幂等，可多次调用）。
    /// 必须在调用 `Dialect::from_url` 或 `AnyPoolOptions::connect` 之前调用。
    pub fn install_any_drivers() {
        #[cfg(feature = "postgres")]
        let drivers = &[sqlx::sqlite::any::DRIVER, sqlx::postgres::any::DRIVER];
        #[cfg(not(feature = "postgres"))]
        let drivers = &[sqlx::sqlite::any::DRIVER];

        // install_drivers 首次成功后再调用返回 Err（OnceCell），忽略即可
        let _ = sqlx::any::install_drivers(drivers);
    }

    /// SQLite 专用连接路径。
    async fn connect_sqlite(
        db_url: &str,
        crbs_root: std::path::PathBuf,
        db_max_connections: Option<u32>,
    ) -> crate::Result<Self> {
        let db_path = db_url
            .strip_prefix("sqlite://")
            .ok_or_else(|| crate::error::CrbsError::Database("invalid sqlite URL".to_string()))?;

        Self::prepare_sqlite_file(std::path::Path::new(db_path)).await?;

        let pool = Self::sqlite_pool(db_url, db_max_connections).await?;

        // ===== schema 版本闩 =====
        migrate::ensure_schema_sqlite_any(&pool).await?;

        Ok(Self {
            pool,
            dialect: Dialect::Sqlite,
            crbs_root,
            resolve_cache: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            change_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            user_generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            resolve_generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            local_write_gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// SQLite 库文件预创建 + 权限设置（非内存库）：父目录创建；空文件预创建
    ///（避免 "unable to open database file"）；mode 0660 + chown crbs 组——
    /// root 建的文件 group=root，组成员落 other 位 EACCES；chown 失败不阻断
    ///（非 root 预期路径，group rw 已够本进程访问）。
    async fn prepare_sqlite_file(path: &std::path::Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    crate::error::CrbsError::from_io_context("create db parent dir", e)
                })?;
            }
        }

        let skip = path.as_os_str().is_empty() || path == std::path::Path::new(":memory:");
        if skip {
            return Ok(());
        }

        tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .await
            .map_err(|e| crate::error::CrbsError::from_io_context("create database file", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // mode 已正确则跳过 chmod：非属主进程 chmod 必 EPERM，无谓 warn 污染启动日志。
            let need_fix = match tokio::fs::metadata(path).await {
                Ok(m) => m.permissions().mode() & 0o777 != 0o660,
                Err(_) => true,
            };
            if need_fix {
                if let Err(e) =
                    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await
                {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to set crbs.db mode 0660");
                }
            }
            crate::privilege::chown_to_crbs_group_async(path, false, "crbs.db").await;
        }
        Ok(())
    }

    /// AnyPoolOptions 统一构造（双方言；sqlite_pool / connect_postgres 两开库
    /// 路径共用防漂移）：池大小见 [`resolve_pool_max_connections`]，超时有界。
    fn any_pool_options(db_max_connections: Option<u32>) -> sqlx::any::AnyPoolOptions {
        sqlx::any::AnyPoolOptions::new()
            .max_connections(resolve_pool_max_connections(
                std::env::var("CRBS_DB_MAX_CONNECTIONS").ok().as_deref(),
                db_max_connections,
            ))
            .acquire_timeout(std::time::Duration::from_secs(DB_ACQUIRE_TIMEOUT_SECS))
    }

    /// SQLite 连接池建立（AnyPool + per-connection PRAGMA + WAL）。
    async fn sqlite_pool(
        db_url: &str,
        db_max_connections: Option<u32>,
    ) -> crate::Result<sqlx::AnyPool> {
        // per-connection `busy_timeout`：并发写者等待而非立即 SQLITE_BUSY（多
        // worker 并发初始化同一本地库时 DDL 撞写锁，默认 0 下后到者直接失败）。
        // `foreign_keys` 显式 ON：SQLite 本身默认 OFF，sqlx 驱动默认开启只是
        // 实现细节（驱动升级 / URL 参数可漂移）；FK 约束是完整性边界。
        let pool = Self::any_pool_options(db_max_connections)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    // 豁免 .db_ctx：sqlx 要求本闭包返回 Result<(), sqlx::Error>，
                    // 包成 CrbsError 会破坏签名；错误由外层 connect().db_ctx 兜底。
                    sqlx::query("PRAGMA busy_timeout = 5000")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(sql::JOURNAL_SIZE_LIMIT)
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(sql::SYNCHRONOUS_NORMAL)
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(db_url)
            .await
            .db_ctx("connect database")?;

        Self::enable_wal_with_retry(&pool).await?;
        Ok(pool)
    }

    /// 切换 SQLite 到 WAL（持久化设置，执行一次即可），"database is locked"
    /// 时有界自旋重试：切换需短暂独占锁且不触发 busy handler（busy_timeout
    /// 无效），重试等并发初始化方完成；WAL 生效后本 PRAGMA 为无锁 no-op。
    async fn enable_wal_with_retry(pool: &sqlx::AnyPool) -> crate::Result<()> {
        const MAX_ATTEMPTS: u32 = 50;
        const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
        let mut attempt = 0;
        loop {
            match sqlx::query(sql::ENABLE_WAL_MODE).execute(pool).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    attempt += 1;
                    if attempt < MAX_ATTEMPTS && e.to_string().contains("database is locked") {
                        tokio::time::sleep(RETRY_DELAY).await;
                        continue;
                    }
                    return Err(e).db_ctx("set wal mode");
                }
            }
        }
    }

    /// PostgreSQL 专用连接路径。
    #[cfg(feature = "postgres")]
    async fn connect_postgres(
        db_url: &str,
        crbs_root: std::path::PathBuf,
        db_max_connections: Option<u32>,
    ) -> crate::Result<Self> {
        let pool = Self::any_pool_options(db_max_connections)
            .connect(db_url)
            .await
            .db_ctx("connect postgres")?;

        // ===== schema 版本闩 =====
        migrate::ensure_schema_pg_any(&pool).await?;

        Ok(Self {
            pool,
            dialect: Dialect::Postgres,
            crbs_root,
            resolve_cache: std::sync::Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
            change_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            user_generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            resolve_generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            local_write_gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// 返回当前数据库方言。
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// 返回创建时传入的 crbs_root 路径。
    pub fn crbs_root(&self) -> &std::path::Path {
        &self.crbs_root
    }

    /// 返回内部 Any 连接池（裸 SQL 通道）。仅测试可见：生产代码一律走领域
    /// 方法；跨 crate 测试经各自 `[dev-dependencies]` 开 `expose-pool` feature
    /// 取直连通道。未开 feature 的构建可见性收窄 crate 私有，直连池编译期即拒。
    #[cfg(any(test, feature = "expose-pool"))]
    pub fn pool(&self) -> &sqlx::AnyPool {
        &self.pool
    }

    /// [`Self::pool`] 的生产构建形态：crate 私有，state 层内部使用。
    #[cfg(not(any(test, feature = "expose-pool")))]
    pub(crate) fn pool(&self) -> &sqlx::AnyPool {
        &self.pool
    }

    /// 广播一次状态变更（关键写方法成功路径收口）。`notify_waiters` 群发：
    /// N 个 SSE 连接各醒各查一次，空闲连接零查询；多通知只是无害唤醒。
    pub fn notify_state_changed(&self) {
        self.change_notify.notify_waiters();
    }

    /// 等待下一次状态变更。与 `notify_waiters` 配对：只唤醒已挂起等待方、
    /// 不记 permit；"查询完成"到"挂起等待"之间到达的变更由兜底轮询补上
    /// （错过只是延迟，不丢正确性）。
    pub async fn changed(&self) {
        self.change_notify.notified().await;
    }

    /// 当前用户域代数（认证缓存命中判据）。读方（AuthCache）回源前读、回填时
    /// 记录，写方在影响认证判定的写方法成功路径 bump——失配即回源，实现角色/
    /// ACL/禁用/会话变更即时失效；Relaxed 足够（只比对"代数是否变过"）。
    /// 进程内计数（非 DB 列）：即时失效依赖读写同进程（hub 单进程），多进程
    /// 共库时他进程变更不 bump 本进程，退化为 AuthCache 10s TTL 兜底。
    pub fn user_generation(&self) -> u64 {
        self.user_generation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// bump 用户域代数（影响认证判定的写方法成功路径收口）。宁多勿漏：多 bump
    /// 只是无害回源；覆盖用户 / 角色 / ACL / 会话 / 产品可见性 / worker
    /// secret→身份映射的写路径。裸 SQL 写用户域表会绕过收口（review 靠 grep
    /// 守护，与 `resolve_cache` 盲信不变量同论证）。
    pub(crate) fn bump_user_generation(&self) {
        self.user_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 引擎本地库热路径写漏斗许可：SQLite 方言返回闸门 guard——持有期间该库
    /// 的生命周期短写在进程内串行执行，写者排队微秒级而非各自撞 SQLITE_BUSY
    /// 再按秒重试；锁内只放毫秒级短写，不得跨网络 IO/长操作（否则串行退化
    /// 为队头阻塞）。PG 返回 `None`（MVCC 无单写者锁，无需进程内串行）；
    /// `postgres` feature 未编译时恒走 SQLite 臂。
    pub(crate) async fn local_write_permit(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if self.dialect.is_postgres() {
            None
        } else {
            Some(self.local_write_gate.lock().await)
        }
    }

    /// 开启写事务（方言感知），返回已持写锁的连接。SQLite 用 `BEGIN
    /// IMMEDIATE`（先拿写锁，避免 DEFERRED 升级死锁）；PG 用 `BEGIN`（行锁
    /// 即可）。调用方自管 COMMIT，错误路径 best-effort ROLLBACK。
    pub(crate) async fn begin_write(&self) -> crate::Result<sqlx::pool::PoolConnection<sqlx::Any>> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;

        sqlx::query(self.dialect.begin_write())
            .execute(&mut *conn)
            .await
            .db_ctx("begin write")?;

        Ok(conn)
    }

    /// 轻量存活探测（/health 深度检查）：取池连接执行跨方言恒真语句，只验证
    /// 连接可用，不做业务查询。
    pub async fn ping(&self) -> crate::Result<()> {
        let mut conn = self.pool.acquire().await.db_ctx("health ping acquire")?;
        // 双方言均接受无 FROM 的 SELECT 1，能执行即证明连接可用。
        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .db_ctx("health ping")?;
        Ok(())
    }

    // ---------- 方言感知 SQL 构造器（SQLite / Postgres 兼容）----------

    /// 返回 N 天前的时间 SQL。
    #[inline]
    pub(crate) fn sql_days_ago(&self, days: i64) -> String {
        self.dialect.sql_days_ago(days)
    }

    /// 解析构建 ID（数字，执行域，diff/debug/build attach 等用），并验证用户
    /// 权限；`user_filter` 为 Some 时只查该用户（非 root 隔离）。坑：build id
    /// 与 task id 自增序列独立、同数字两义——用户面命令应改用
    /// [`Self::resolve_task_id`]。
    pub async fn resolve_short_id(
        &self,
        task: &str,
        user_filter: Option<&str>,
    ) -> crate::Result<i64> {
        let id = task
            .parse::<i64>()
            .map_err(|_| crate::error::CrbsError::ValidationFailed {
                message: format!("Task ID must be a number, got '{}'", task),
            })?;
        let record = self.get_build(id).await?;
        match record {
            Some(r) => {
                if let Some(user) = user_filter {
                    if r.user != user && !r.user.is_empty() {
                        return Err(crate::error::CrbsError::NotFound {
                            message: format!(
                                "Build task '{}' not found. Run 'crbs status' to list builds.",
                                id
                            ),
                        });
                    }
                }
                Ok(r.id)
            }
            None => Err(crate::error::CrbsError::NotFound {
                message: format!(
                    "Build task '{}' not found. Run 'crbs status' to list builds.",
                    id
                ),
            }),
        }
    }

    /// 解析用户任务 ID（数字，提交域），并验证用户权限。按 `tasks.id` 解析，
    /// NotFound 消息与远程同形（`task {id} not found`），本地/远程同 ID 同
    /// 结果；`user_filter` 为 Some 时只查该用户，旧记录 user = '' 视为无主放行。
    pub async fn resolve_task_id(
        &self,
        task: &str,
        user_filter: Option<&str>,
    ) -> crate::Result<i64> {
        let id = task
            .parse::<i64>()
            .map_err(|_| crate::error::CrbsError::ValidationFailed {
                message: format!("Task ID must be a number, got '{}'", task),
            })?;
        match self.get_task(id).await? {
            Some(t) => {
                if let Some(user) = user_filter {
                    if t.user != user && !t.user.is_empty() {
                        return Err(crate::error::CrbsError::NotFound {
                            message: format!(
                                "task {id} not found. Run 'crbs status' to list tasks."
                            ),
                        });
                    }
                }
                Ok(t.id)
            }
            None => Err(crate::error::CrbsError::NotFound {
                message: format!("task {id} not found. Run 'crbs status' to list tasks."),
            }),
        }
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    /// root 含 server marker 时，引擎开库入口必须拒绝并给出分流指引。
    #[tokio::test]
    async fn open_for_engine_rejects_server_marker_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("server-root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(SERVER_ROOT_MARKER), "crbs-server root\n").unwrap();

        let err = match StateStore::open_for_engine(&root).await {
            Ok(_) => panic!("open_for_engine must reject a server marker root"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("crbs-server root"),
            "error should identify the server root, got: {msg}"
        );
        assert!(
            msg.contains(SERVER_ROOT_MARKER),
            "error should name the marker file, got: {msg}"
        );
        assert!(
            msg.contains("/var/lib/crbs-engine"),
            "error should point to the engine default root, got: {msg}"
        );
        // 库文件不得被创建（拒绝发生在打开之前）。
        assert!(
            !root.join("crbs.db").exists(),
            "marker check must happen before any db file is created"
        );
    }

    /// 无 marker 的 root 正常打开（引擎世界常规路径）。
    #[tokio::test]
    async fn open_for_engine_opens_clean_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("engine-root");
        std::fs::create_dir_all(&root).unwrap();

        let store = StateStore::open_for_engine(&root).await.unwrap();
        assert_eq!(store.crbs_root(), root);
    }
}

#[cfg(test)]
mod pragma_tests {
    use super::*;

    async fn journal_mode(pool: &sqlx::AnyPool) -> String {
        use sqlx::Row as _;
        let row = sqlx::query("PRAGMA journal_mode")
            .fetch_one(pool)
            .await
            .unwrap();
        row.get::<String, _>(0).to_lowercase()
    }

    /// 文件库连接启用 WAL（持久 PRAGMA，开库设置一次）：busy_timeout 之外的
    /// 并发加固前提——回归钉钉住 `sqlite_pool` 开库路径不得漂移回 journal
    /// 默认（delete）。WAL 下读不阻塞写：写事务持锁期间池内第二连接读立即
    /// 返回，不烧 busy_timeout。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_db_runs_wal_and_readers_do_not_block_on_writer() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        assert_eq!(
            journal_mode(store.pool()).await,
            "wal",
            "file-backed pool must run WAL (set once at open; persisted in the db file)"
        );

        let mut writer = store.pool().acquire().await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *writer)
            .await
            .unwrap();

        let mut reader = store.pool().acquire().await.unwrap();
        let started = std::time::Instant::now();
        let one: i64 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(one, 1);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "WAL reader must not wait on the write lock, got {elapsed:?}"
        );

        sqlx::query("COMMIT").execute(&mut *writer).await.unwrap();
    }

    /// WAL PRAGMA 对内存库是无害 no-op（SQLite 返回 memory、不报错）——
    /// PRAGMA 族在任何库形态上执行都不炸；仓库测试连接全部走临时文件库，
    /// StateStore 无 `:memory:` 开库路径（sqlx Any URL 解析不接受该形态），
    /// 本钉直接锁兼容性事实本身。
    #[tokio::test]
    async fn wal_pragma_is_harmless_noop_on_memory_db() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        use sqlx::Row as _;
        let mode: String = sqlx::query("PRAGMA journal_mode = WAL")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<String, _>(0);
        assert_eq!(
            mode.to_lowercase(),
            "memory",
            "in-memory db ignores the WAL switch without erroring"
        );
    }

    /// 连接级 synchronous 必须为 NORMAL：钉住 after_connect 的 per-connection
    /// PRAGMA 集不得漂移回编译默认。断言 1 即 NORMAL——SQLite synchronous
    /// 常量 0=OFF / 1=NORMAL / 2=FULL（编译默认）。
    #[tokio::test]
    async fn file_db_connections_run_synchronous_normal() {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();

        use sqlx::Row as _;
        let level: i64 = sqlx::query("PRAGMA synchronous")
            .fetch_one(store.pool())
            .await
            .unwrap()
            .get::<i64, _>(0);
        assert_eq!(
            level, 1,
            "pool connections must run synchronous=NORMAL (SQLite constants: 0=OFF 1=NORMAL 2=FULL)"
        );
    }
}
