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

    pub(super) const ENABLE_WAL_MODE: &str = "PRAGMA journal_mode = WAL;";

    pub(super) const JOURNAL_SIZE_LIMIT: &str = "PRAGMA journal_size_limit = 67108864";

    // ponytail: 需要严格持久化的部署形态，移除本 pragma 即回编译默认 FULL。
    pub(super) const SYNCHRONOUS_NORMAL: &str = "PRAGMA synchronous = NORMAL";
}

pub(crate) use db::Dialect;

/// 写事务的统一错误出口：先回滚再透出原错误，不替换、不掩盖；回滚自身失败
/// 仅记录 debug 日志，连接归还池后由 aborted-transaction 状态自然暴露。
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

/// 状态存储：追踪构建与任务记录，经 `AnyPool` 统一抽象 SQLite 与 PostgreSQL
/// 两种后端。
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

    /// resolve 缓存代数：失效先 bump 再 remove，防旧代数快照回填。
    resolve_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,

    /// ponytail: 多 hub / 跨进程写场景需换 NOTIFY 或逻辑复制，接口已隔离在
    /// `notify_state_changed`/`changed` 之后。
    change_notify: std::sync::Arc<tokio::sync::Notify>,

    user_generation: std::sync::Arc<std::sync::atomic::AtomicU64>,

    local_write_gate: std::sync::Arc<tokio::sync::Mutex<()>>,
}

/// 连接池默认大小，两种方言一致。SQLite 在 WAL 下读可并行而写仍串行，池容量
/// 主要决定并发读吞吐，8 满足常规负载。
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 8;

/// 连接池获取超时（秒）。池耗尽或数据库不可达时直接报错（映射为
/// `CrbsError::DatabaseUnavailable`，HTTP 503）而非挂起；10 秒覆盖 SQLite
/// busy_timeout（5 秒）并为 PostgreSQL 建连留出余量。
const DB_ACQUIRE_TIMEOUT_SECS: u64 = 10;

/// crbs-server 归属标记的文件名：server 启动时在自身 root 下创建该文件，
/// 引擎侧开库时发现标记即拒绝并提示改用引擎 root，从结构上阻止引擎把构建
/// 历史写入 server 数据库。
pub const SERVER_ROOT_MARKER: &str = ".crbs-server-root";

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

/// 单次构建允许的重排次数上限：构建被回收或判为僵尸后重置回 pending 时计数
/// 加一，达到上限即转入 failed 终态不再重排，防止必然失败的构建反复占用
/// 构建槽位。
pub const MAX_BUILD_ATTEMPTS: i64 = 3;

impl StateStore {
    /// 打开或创建 SQLite 数据库，默认路径为 `{crbs_root}/crbs.db`，开启 WAL
    /// 并完成建表建索引。
    pub async fn new(crbs_root: &std::path::Path) -> crate::Result<Self> {
        Self::new_with_db_path(&crbs_root.join("crbs.db"), crbs_root).await
    }

    /// 引擎侧专用开库入口：root 下存在 [`SERVER_ROOT_MARKER`] 时拒绝打开，
    /// 避免引擎把本地构建历史写入 server 数据库。server 与 worker 的开库路径
    /// （[`Self::new`] 等入口）不做该检查。
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

    /// 从指定数据库路径打开或创建 SQLite 数据库，开启 WAL 并完成建表建索引。
    pub async fn new_with_db_path(
        db_path: &std::path::Path,
        crbs_root: &std::path::Path,
    ) -> crate::Result<Self> {
        Self::new_with_db_path_and_pool(db_path, crbs_root, None).await
    }

    /// 行为同 [`Self::new_with_db_path`]，另将 server.toml 的
    /// `db_max_connections` 并入池大小优先级（env 优先、配置次之、默认 8）。
    /// 供 crbs-server run 使用，CLI 与测试走 [`Self::new_with_db_path`]。
    pub async fn new_with_db_path_and_pool(
        db_path: &std::path::Path,
        crbs_root: &std::path::Path,
        db_max_connections: Option<u32>,
    ) -> crate::Result<Self> {
        let db_url = format!("sqlite://{}", db_path.display());
        Self::new_with_url_and_pool(&db_url, crbs_root, db_max_connections).await
    }

    /// 从数据库 URL 打开连接的统一入口，接受 SQLite 与 PostgreSQL 两种 URL。
    /// 池大小仅由 `CRBS_DB_MAX_CONNECTIONS` 环境变量或默认值决定；需并入
    /// server.toml 配置时改用 [`Self::new_with_url_and_pool`]。
    pub async fn new_with_url(db_url: &str, crbs_root: &std::path::Path) -> crate::Result<Self> {
        Self::new_with_url_and_pool(db_url, crbs_root, None).await
    }

    /// 行为同 [`Self::new_with_url`]，另将 server.toml 的 `db_max_connections`
    /// 并入池大小优先级（env 优先、配置次之、默认 8）。
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

    /// 注册编译期启用的全部 `AnyPool` 驱动，幂等，可重复调用。必须在
    /// `Dialect::from_url` 与 `AnyPoolOptions::connect` 之前执行。
    pub fn install_any_drivers() {
        #[cfg(feature = "postgres")]
        let drivers = &[sqlx::sqlite::any::DRIVER, sqlx::postgres::any::DRIVER];
        #[cfg(not(feature = "postgres"))]
        let drivers = &[sqlx::sqlite::any::DRIVER];

        let _ = sqlx::any::install_drivers(drivers);
    }

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

    fn any_pool_options(db_max_connections: Option<u32>) -> sqlx::any::AnyPoolOptions {
        sqlx::any::AnyPoolOptions::new()
            .max_connections(resolve_pool_max_connections(
                std::env::var("CRBS_DB_MAX_CONNECTIONS").ok().as_deref(),
                db_max_connections,
            ))
            .acquire_timeout(std::time::Duration::from_secs(DB_ACQUIRE_TIMEOUT_SECS))
    }

    async fn sqlite_pool(
        db_url: &str,
        db_max_connections: Option<u32>,
    ) -> crate::Result<sqlx::AnyPool> {
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

    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    pub fn crbs_root(&self) -> &std::path::Path {
        &self.crbs_root
    }

    /// 返回内部连接池，供直接执行 SQL 的测试使用。仅测试与 `expose-pool`
    /// feature 构建可见：生产代码一律通过领域方法访问数据库；跨 crate 测试在
    /// 各自 `[dev-dependencies]` 中启用 `expose-pool` 后经此取连接池。
    #[cfg(any(test, feature = "expose-pool"))]
    pub fn pool(&self) -> &sqlx::AnyPool {
        &self.pool
    }

    /// 返回内部连接池的 crate 私有形态，供 state 层内部构造查询使用。
    #[cfg(not(any(test, feature = "expose-pool")))]
    pub(crate) fn pool(&self) -> &sqlx::AnyPool {
        &self.pool
    }

    /// 广播一次状态变更，供关键写方法在成功路径调用。内部使用
    /// `notify_waiters` 群发：每个 SSE 连接被唤醒后各自重新查询一次，空闲
    /// 连接不产生查询；多次通知只会造成无害唤醒。
    pub fn notify_state_changed(&self) {
        self.change_notify.notify_waiters();
    }

    /// 等待下一次状态变更，与 [`Self::notify_state_changed`] 配对使用。通知
    /// 只唤醒已挂起的等待方且不保留许可，"查询结束"与"进入等待"之间到达的
    /// 变更可能被错过，由消费方的兜底轮询保证最终一致。
    pub async fn changed(&self) {
        self.change_notify.notified().await;
    }

    /// 当前用户域代数，认证缓存的命中判据：缓存回源前读取并记录代数，回填
    /// 后比对，失配即重新认证，使角色、ACL、禁用与会话变更即时生效。计数为
    /// 进程内状态而非数据库列，即时失效依赖读写同进程；多进程共库时退化为
    /// 缓存自身的过期时间兜底。代数比较只关心是否变化，`Relaxed` 序即可。
    pub fn user_generation(&self) -> u64 {
        self.user_generation
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// 推进用户域代数，供影响认证判定的写方法在成功路径调用。多推无碍，只
    /// 会引发一次多余的缓存回源；调用面需覆盖用户、角色、ACL、会话、产品
    /// 可见性与 worker secret 映射的写路径，绕过本方法的裸 SQL 写入会破坏
    /// 即时失效（评审以 grep 检查调用完整性）。
    pub(crate) fn bump_user_generation(&self) {
        self.user_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// 获取本地库写串行许可：SQLite 方言返回互斥锁 guard，使该库的短写语句
    /// 在进程内排队执行，避免多个写者各自等待 SQLite 单写者锁；PostgreSQL
    /// 方言返回 `None`（MVCC 下无单写者锁，无需进程内串行）。约束：持锁期间
    /// 只做毫秒级短写，不得覆盖网络 IO 或长操作；读路径不取锁，保留 WAL 的
    /// 读写并行。
    pub(crate) async fn local_write_permit(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        if self.dialect.is_postgres() {
            None
        } else {
            Some(self.local_write_gate.lock().await)
        }
    }

    /// 开启写事务并返回持有该事务的连接，按方言选择 BEGIN 语句：SQLite 用
    /// `BEGIN IMMEDIATE` 预先取得写锁，避免 DEFERRED 事务升级时死锁；
    /// PostgreSQL 用普通 `BEGIN`，依赖行锁即可。提交由调用方负责，错误路径
    /// 经 `rollback_and_return` 回滚。
    pub(crate) async fn begin_write(&self) -> crate::Result<sqlx::pool::PoolConnection<sqlx::Any>> {
        let mut conn = self.pool.acquire().await.db_ctx("acquire conn")?;

        sqlx::query(self.dialect.begin_write())
            .execute(&mut *conn)
            .await
            .db_ctx("begin write")?;

        Ok(conn)
    }

    /// 轻量存活探测，供 /health 深度检查使用：从池中取连接执行一条跨方言
    /// 恒真语句，只验证连接可用性，不涉及业务表。
    pub async fn ping(&self) -> crate::Result<()> {
        let mut conn = self.pool.acquire().await.db_ctx("health ping acquire")?;

        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .db_ctx("health ping")?;
        Ok(())
    }

    /// 返回求值结果为 N 天前时间点的 SQL 表达式，按方言生成。
    #[inline]
    pub(crate) fn sql_days_ago(&self, days: i64) -> String {
        self.dialect.sql_days_ago(days)
    }

    /// 解析构建 ID（数字，执行域）并校验用户权限，供 diff、debug 与 build
    /// attach 等命令使用；`user_filter` 非 `None` 时仅接受属主为该用户的记录
    /// （属主为空视为公共可见）。build id 与 task id 各自独立自增，同一数字
    /// 在两个域中含义不同，面向用户的命令应改用 [`Self::resolve_task_id`]。
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

    /// 解析任务 ID（数字，提交域）并校验用户权限，按 `tasks.id` 查询。
    /// NotFound 消息文案与远程查询保持一致（`task {id} not found`），同一 ID
    /// 在本地与远程得到相同结果。`user_filter` 非 `None` 时仅接受属主匹配的
    /// 记录，属主为空字符串的记录视为无主、对所有人放行。
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

        assert!(
            !root.join("crbs.db").exists(),
            "marker check must happen before any db file is created"
        );
    }

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
