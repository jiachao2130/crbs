// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Server 共享状态。

use std::collections::HashMap;
use std::sync::Arc;

use crbs_core::types::GcSummary;
use crbs_core::StateStore;

/// Server 进程级共享状态（经 axum State 注入各 handler，生命周期与进程一致）。
pub struct AppState {
    pub state_store: Arc<StateStore>,

    pub build_semaphore: Arc<tokio::sync::Semaphore>,

    pub max_local_builds: usize,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub active_builds: Arc<tokio::sync::Mutex<HashMap<i64, tokio_util::sync::CancellationToken>>>,

    pub allow_product_management: bool,

    pub config_dir: Option<std::path::PathBuf>,

    pub server_config: crbs_core::config::ServerConfig,

    pub crbs_config: crbs_core::config::CrbsConfig,
    pub crbs_root: std::path::PathBuf,
    pub gc_tasks: Arc<tokio::sync::Mutex<HashMap<String, GcTask>>>,
    pub product_tasks: Arc<tokio::sync::Mutex<HashMap<String, ProductTask>>>,

    #[allow(dead_code)]
    pub(crate) server_lock: Option<crate::server::ServerLockGuard>,

    pub(crate) shutdown_cancel: tokio_util::sync::CancellationToken,
    #[allow(clippy::type_complexity)]
    pub(crate) worker_waiters:
        Arc<tokio::sync::Mutex<Vec<(i64, String, Arc<tokio::sync::Notify>)>>>,

    pub(crate) worker_notify: Arc<tokio::sync::Notify>,

    pub(crate) log_buffer: crate::server::log_buffer::LogBuffer,

    /// report_logs 落盘 build.log 已超上限、append 被拒的 build 集合（防认证 worker 灌盘，仅 warn 一次）。
    pub(crate) hub_log_cap_warned: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,

    /// report_logs 已完成 artifact 目录预备（create_dir_all + 递归 chown/chmod）的 build 集合。
    pub(crate) hub_log_dir_prepared: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,

    pub(crate) hub_log_chmod_warned: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,

    /// report_logs 幂等去重：assignment_id → 已接受的最大 chunk 序号。同一 chunk 的重试复用同一序号，重复投递直接确认不再追加（响应丢失零重复）。
    /// 容量封顶 4096 后清空，清空窗口内的重试可能重复一段，属可接受残余。
    pub(crate) hub_log_chunk_seq: Arc<std::sync::Mutex<std::collections::HashMap<i64, u64>>>,
    pub(crate) srpm_token_signer: crbs_core::srpm_token::SrpmTokenSigner,
    pub(crate) csrf_key: [u8; 32],

    pub(crate) login_limiter: Arc<crate::server::rate_limit::LoginRateLimiter>,

    pub(crate) gc_semaphore: Arc<tokio::sync::Semaphore>,

    /// 认证缓存：凭据派生值 → 用户快照，代数失效 + 10s TTL 兜底；不含凭据原文与密码哈希。
    pub(crate) auth_cache: crate::server::auth::AuthCache,

    pub(crate) repo_visibility_cache: crate::server::routes::repo::RepoVisibilityCache,

    pub(crate) resource_weight_cache: crate::server::scheduler::ResourceWeightCache,

    pub(crate) dispatch_attribution: crate::server::scheduler::planner::DispatchAttribution,

    pub(crate) metrics: crate::server::metrics::MetricsCounters,

    /// per-product repo regen 在途集合：spawn 前 insert 占位，收尾（含 panic）经 guard Drop remove。
    pub(crate) regen_inflight: std::sync::Mutex<std::collections::HashSet<String>>,

    /// per-product regen 脏标记：regen 在途期间到达的触发 claim 失败时 insert，在途轮收尾原子取走——有则补跑一轮完整 regen 收敛到最新。
    pub(crate) regen_dirty: std::sync::Mutex<std::collections::HashSet<String>>,

    /// auto replay 任务级在途集合：末两子构建近同时终态时，两个 spawn 钩子都读到 all-succeeded 快照会双开 reproduce_fan_out；入口（首个
    /// await 前）check-and-insert 源 task id 占位，收尾（含 Err/panic）guard Drop remove。
    pub(crate) auto_replay_inflight: std::sync::Mutex<std::collections::HashSet<i64>>,

    pub(crate) batch_barrier_passed: std::sync::Mutex<std::collections::HashSet<(i64, i64)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// /metrics 快照用的并发读数组。
pub(crate) struct ConcurrencySnapshot {
    pub local_active: usize,

    pub distributed_active: usize,

    pub local_slots: usize,

    pub worker_capacity_online: usize,

    pub total_active: usize,

    pub total_capacity: usize,
}

impl ConcurrencySnapshot {
    fn capacity_of(
        local_slots: usize,
        worker_capacity_online: usize,
        mode: &crbs_core::config::SchedulerMode,
    ) -> usize {
        match mode {
            crbs_core::config::SchedulerMode::Auto => local_slots + worker_capacity_online,
            crbs_core::config::SchedulerMode::DistributedOnly => worker_capacity_online,
            crbs_core::config::SchedulerMode::LocalOnly => local_slots,
        }
    }
}

/// spawn 收尾 guard：收尾（含 panic）经 Drop remove 在途标记。
pub(crate) struct CleanupGuard {
    pub active_builds: Arc<tokio::sync::Mutex<HashMap<i64, tokio_util::sync::CancellationToken>>>,
    pub build_id: i64,
    pub consumed: bool,
}

impl CleanupGuard {
    pub async fn remove(mut self, app: &AppState) {
        app.active_builds.lock().await.remove(&self.build_id);
        self.consumed = true;
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.consumed {
            return;
        }

        match self.active_builds.try_lock() {
            Ok(mut map) => {
                map.remove(&self.build_id);
            }
            Err(_) => {
                let map = self.active_builds.clone();
                let build_id = self.build_id;
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(async move {
                            map.lock().await.remove(&build_id);
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            build_id = %self.build_id,
                            error = %e,
                            "CleanupGuard dropped outside runtime; active_builds entry will vanish with process"
                        );
                    }
                }
            }
        }
    }
}

const TEST_SRPM_TOKEN_KEY: [u8; 32] = [0x42; 32];
const TEST_CSRF_KEY: [u8; 32] = [0x43; 32];

/// 读密钥文件；缺失/权限错误按调用方语义上抛。
async fn read_key_file(key_path: &std::path::Path, what: &str) -> crbs_core::Result<[u8; 32]> {
    let hex = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|e| crbs_core::error::CrbsError::from_io_context(format!("read {what}"), e))?;
    let bytes =
        hex::decode(hex.trim()).map_err(|e| crbs_core::error::CrbsError::ValidationFailed {
            message: format!("invalid {what} file: {}", e),
        })?;
    bytes
        .try_into()
        .map_err(|_| crbs_core::error::CrbsError::ValidationFailed {
            message: format!("{what} must be 32 bytes"),
        })
}

enum KeyFileCreate {
    Written,

    AlreadyExists,
}

async fn create_key_file(
    key_path: &std::path::Path,
    contents: &str,
) -> std::io::Result<KeyFileCreate> {
    use tokio::io::AsyncWriteExt;

    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = match options.open(key_path).await {
        Ok(file) => file,

        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(KeyFileCreate::AlreadyExists)
        }
        Err(e) => return Err(e),
    };
    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;
    Ok(KeyFileCreate::Written)
}

async fn load_or_generate_key(
    crbs_root: &std::path::Path,
    file_name: &'static str,
    what: &'static str,
) -> crbs_core::Result<[u8; 32]> {
    let key_path = crbs_root.join(file_name);
    if tokio::fs::try_exists(&key_path)
        .await
        .map_err(|e| crbs_core::error::CrbsError::from_io_context(format!("check {what}"), e))?
    {
        return read_key_file(&key_path, what).await;
    }

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| crbs_core::error::CrbsError::io_message(format!("generate {what}: {}", e)))?;
    let hex = hex::encode(key);

    match create_key_file(&key_path, &hex).await {
        Ok(KeyFileCreate::AlreadyExists) => {
            return match read_key_file(&key_path, what).await {
                Ok(existing) => Ok(existing),
                Err(first) => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    read_key_file(&key_path, what).await.map_err(|retry| {
                        tracing::warn!(
                            path = %key_path.display(),
                            first = %first,
                            retry = %retry,
                            "Concurrent first-start key file exists but is unreadable"
                        );
                        retry
                    })
                }
            };
        }
        Ok(KeyFileCreate::Written) => {
            #[cfg(unix)]
            {
                crbs_core::privilege::chown_to_crbs_group_async(&key_path, false, file_name).await;
            }
        }
        Err(e) => {
            return Err(crbs_core::error::CrbsError::from_io_context(
                format!("write {what}"),
                e,
            ))
        }
    }
    Ok(key)
}

/// 加载或生成 SRPM 下载 token 的签名密钥：持久化于
/// `crbs_root/srpm_token_key`，首次启动随机生成，文件 0o600，重启保持
/// 一致。
pub async fn load_or_generate_srpm_token_key(
    crbs_root: &std::path::Path,
) -> crbs_core::Result<[u8; 32]> {
    load_or_generate_key(crbs_root, "srpm_token_key", "srpm token key").await
}

/// 加载或生成 CSRF token 派生密钥：持久化于 `crbs_root/csrf_key`，首次
/// 启动随机生成，文件 0o600，重启保持一致。
pub async fn load_or_generate_csrf_key(crbs_root: &std::path::Path) -> crbs_core::Result<[u8; 32]> {
    load_or_generate_key(crbs_root, "csrf_key", "csrf key").await
}

impl AppState {
    /// 创建测试用 AppState：不创建 pidfile，也不启动恢复调度器。
    pub fn for_test(
        state_store: Arc<StateStore>,
        server_config: crbs_core::config::ServerConfig,
        crbs_root: std::path::PathBuf,
    ) -> Self {
        crate::test_support::pin_setuid_privilege_backend();
        let max_local = if server_config.max_local_builds > 0 {
            server_config.max_local_builds
        } else {
            crate::server::bootstrap::num_cpus()
        };
        let crbs_config = crbs_core::config::CrbsConfig {
            crbs_root: crbs_root.clone(),

            result_dir: None,
            shared_layers_dir: None,
            tmp_dir: Some(crbs_root.join("tmp")),
            tmpfs_dir: crbs_root.join("tmpfs"),
            ccache_dir: crbs_root.join("ccache"),
            ..Default::default()
        };
        Self {
            state_store,
            build_semaphore: Arc::new(tokio::sync::Semaphore::new(max_local)),
            max_local_builds: max_local,
            started_at: chrono::Utc::now(),
            active_builds: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            allow_product_management: server_config.allow_product_management,
            config_dir: Some(crbs_root.clone()),
            server_config,
            crbs_config,
            crbs_root,
            gc_tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            product_tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            server_lock: None,
            shutdown_cancel: tokio_util::sync::CancellationToken::new(),
            worker_waiters: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            worker_notify: Arc::new(tokio::sync::Notify::new()),
            log_buffer: crate::server::log_buffer::LogBuffer::new(),
            hub_log_cap_warned: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            hub_log_dir_prepared: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            hub_log_chmod_warned: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            hub_log_chunk_seq: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            srpm_token_signer: crbs_core::srpm_token::SrpmTokenSigner::new(TEST_SRPM_TOKEN_KEY),
            csrf_key: TEST_CSRF_KEY,
            login_limiter: crate::server::rate_limit::LoginRateLimiter::new(),
            gc_semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            auth_cache: crate::server::auth::AuthCache::new(),
            repo_visibility_cache: crate::server::routes::repo::RepoVisibilityCache::new(),
            resource_weight_cache: crate::server::scheduler::ResourceWeightCache::new(),
            dispatch_attribution: crate::server::scheduler::planner::DispatchAttribution::new(),
            metrics: crate::server::metrics::MetricsCounters::default(),
            regen_inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
            regen_dirty: std::sync::Mutex::new(std::collections::HashSet::new()),
            auto_replay_inflight: std::sync::Mutex::new(std::collections::HashSet::new()),
            batch_barrier_passed: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    #[doc(hidden)]
    /// 测试构造：注入登录限流时钟，供限流窗口恢复类测试手动推进时间，其余
    /// 行为同 [`AppState::for_test`]。
    pub fn for_test_with_login_clock(
        state_store: Arc<StateStore>,
        server_config: crbs_core::config::ServerConfig,
        crbs_root: std::path::PathBuf,
        login_clock: Arc<dyn Fn() -> std::time::Instant + Send + Sync>,
    ) -> Self {
        let mut app = Self::for_test(state_store, server_config, crbs_root);
        app.login_limiter = crate::server::rate_limit::LoginRateLimiter::with_clock(login_clock);
        app
    }

    /// 显式 result_dir 覆盖（server.toml 优先，crbs.toml 兜底），均未设置时
    /// 返回 None。供 GC 与 diff 在 `pinned_to_root` 清空显式配置后回填使用：
    /// 安全根必须与文件实际位置一致，否则 GC 会对全部候选给出 skipped_
    /// invalid 而静默零回收，diff 会拒绝所有合法 result_dir。
    pub fn explicit_result_dir(&self) -> Option<std::path::PathBuf> {
        self.server_config
            .result_dir
            .clone()
            .or_else(|| self.crbs_config.result_dir.clone())
    }

    fn global_result_root(&self) -> std::path::PathBuf {
        self.crbs_config
            .result_dir
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("results"))
    }

    pub(crate) fn default_task_result_root(&self) -> std::path::PathBuf {
        self.server_config
            .result_dir
            .clone()
            .unwrap_or_else(|| self.global_result_root())
    }

    /// 产品产物根目录（严格版）：优先级 server.toml result_dir 高于产品配置
    /// 高于全局根；产品未入库时回退全局根，数据库一致性错误向上传递。
    pub async fn result_dir_for(&self, product: &str) -> crbs_core::Result<std::path::PathBuf> {
        if let Some(ref server_result_dir) = self.server_config.result_dir {
            return Ok(server_result_dir.clone());
        }

        match self.state_store.resolve_any_product_by_name(product).await {
            Ok(resolved) => Ok(resolved
                .config
                .result_dir
                .clone()
                .unwrap_or_else(|| self.global_result_root())),
            Err(crbs_core::error::CrbsError::NotFound { .. }) => Ok(self.global_result_root()),
            Err(e) => Err(e),
        }
    }

    /// 产品产物根目录（回退版）：产品配置加载失败时回退全局 result_dir，
    /// 保证读取与执行端点不因产品配置临时损坏而不可用。
    pub async fn result_dir_for_or_default(&self, product: &str) -> std::path::PathBuf {
        match self.result_dir_for(product).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(product = %product, error = %e, "Failed to load product config for result_dir; falling back to global result_dir");
                self.global_result_root()
            }
        }
    }

    /// 把产品详情（UI 页与 API JSON）中的路径字段覆写为 server 世界的生效
    /// 值。merged config 的 crbs_root 属引擎世界（crbs.toml，服务 CLI 本地
    /// 构建语义）；hub 侧构建、产物与 GC 全部固定在 server root，直接透出
    /// 引擎 root 会指向不存在的路径。
    pub async fn apply_display_paths(
        &self,
        detail: &mut crbs_core::config::ProductDetail,
        product: &str,
    ) {
        detail.crbs_root = self.crbs_root.clone();
        detail.result_dir = self.result_dir_for_or_default(product).await;
    }

    /// 上传暂存目录（server root 下，按配置派生）。
    pub fn upload_dir(&self) -> std::path::PathBuf {
        self.server_config.upload_dir(&self.crbs_root)
    }

    /// 状态数据库路径（server root 下）。
    pub fn state_db_path(&self) -> std::path::PathBuf {
        self.server_config.state_db_path(&self.crbs_root)
    }

    /// 产物发布根目录（server root 下）。
    pub fn artifact_dir(&self) -> std::path::PathBuf {
        self.server_config.artifact_dir(&self.crbs_root)
    }

    pub(crate) async fn concurrency_snapshot(&self) -> crbs_core::Result<ConcurrencySnapshot> {
        let mode = &self.server_config.scheduler_mode;
        let local_active = self.active_builds.lock().await.len();
        let local_slots = self.max_local_builds;

        let (distributed_active, worker_capacity_online) = if *mode
            == crbs_core::config::SchedulerMode::LocalOnly
        {
            (0, 0)
        } else {
            let workers = self.state_store.list_online_workers(None).await?;
            let worker_capacity_online: usize = workers
                .iter()
                .map(|w| usize::try_from(w.capacity).unwrap_or(0))
                .sum();

            let online_ids: std::collections::HashSet<i64> = workers.iter().map(|w| w.id).collect();
            let distributed_active: usize = self
                .state_store
                .count_active_tasks_by_worker()
                .await?
                .into_iter()
                .filter(|(id, _)| online_ids.contains(id))
                .map(|(_, n)| usize::try_from(n).unwrap_or(0))
                .sum();
            (distributed_active, worker_capacity_online)
        };

        let total_active = local_active + distributed_active;
        Ok(ConcurrencySnapshot {
            local_active,
            distributed_active,
            local_slots,
            worker_capacity_online,
            total_active,
            total_capacity: ConcurrencySnapshot::capacity_of(
                local_slots,
                worker_capacity_online,
                mode,
            ),
        })
    }
}

/// 后台 GC 任务状态（内存态，重启即失）：执行中、成功并携带删除统计，或
/// 失败并携带原因。
#[derive(Debug, Clone)]
pub enum GcTaskStatus {
    Running,

    Succeeded(GcSummary),

    Failed(String),
}

/// 后台 GC 任务记录（内存态，重启即失）。
#[derive(Debug, Clone)]
pub struct GcTask {
    pub status: GcTaskStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// 终态时刻，执行中为 `None`。
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// 产品后台操作任务状态（内存态，重启即失）：执行中、成功，或失败并携带
/// 原因。
#[derive(Debug, Clone)]
pub enum ProductTaskStatus {
    Running,

    Succeeded,

    Failed(String),
}

/// 产品后台操作任务记录（内存态，重启即失）。
#[derive(Debug, Clone)]
pub struct ProductTask {
    pub status: ProductTaskStatus,
    pub product: String,
    pub op: &'static str,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crbs_core::config::SchedulerMode;

    #[test]
    fn cluster_capacity_auto_sums_local_and_worker() {
        assert_eq!(
            ConcurrencySnapshot::capacity_of(4, 6, &SchedulerMode::Auto),
            10
        );
    }

    #[test]
    fn cluster_capacity_distributed_only_excludes_local_slots() {
        assert_eq!(
            ConcurrencySnapshot::capacity_of(4, 6, &SchedulerMode::DistributedOnly),
            6
        );
        assert_eq!(
            ConcurrencySnapshot::capacity_of(4, 0, &SchedulerMode::DistributedOnly),
            0
        );
    }

    #[test]
    fn cluster_capacity_local_only_excludes_worker_capacity() {
        assert_eq!(
            ConcurrencySnapshot::capacity_of(4, 6, &SchedulerMode::LocalOnly),
            4
        );
    }

    async fn concurrency_test_app(
        mode: SchedulerMode,
        max_local_builds: usize,
    ) -> (AppState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = AppState::for_test(
            store,
            crbs_core::config::ServerConfig {
                scheduler_mode: mode,
                max_local_builds,
                ..Default::default()
            },
            tmp.path().to_path_buf(),
        );
        (app, tmp)
    }

    async fn seed_worker_assignment(app: &AppState, pkg: &str, worker_id: i64) {
        let task_id = crate::test_support::seed_task(&app.state_store, "mydist", pkg).await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product: "mydist",
                pkg_name: pkg,
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        app.state_store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn concurrency_snapshot_auto_counts_online_workers_only() {
        let (app, _tmp) = concurrency_test_app(SchedulerMode::Auto, 2).await;
        let w_online = app
            .state_store
            .upsert_worker("w-online", "x86_64", 3, "1.0", "online", None)
            .await
            .unwrap();
        let w_offline = app
            .state_store
            .upsert_worker("w-offline", "x86_64", 5, "1.0", "offline", None)
            .await
            .unwrap();
        seed_worker_assignment(&app, "pkg-a", w_online).await;
        seed_worker_assignment(&app, "pkg-b", w_online).await;
        seed_worker_assignment(&app, "pkg-c", w_offline).await;

        let snap = app.concurrency_snapshot().await.unwrap();
        assert_eq!(snap.local_slots, 2);
        assert_eq!(snap.worker_capacity_online, 3);
        assert_eq!(snap.distributed_active, 2);
        assert_eq!(snap.total_active, 2);
        assert_eq!(snap.total_capacity, 5);
    }

    #[tokio::test]
    async fn concurrency_snapshot_distributed_only_excludes_local_slots() {
        let (app, _tmp) = concurrency_test_app(SchedulerMode::DistributedOnly, 4).await;
        let w = app
            .state_store
            .upsert_worker("w-online", "x86_64", 3, "1.0", "online", None)
            .await
            .unwrap();
        seed_worker_assignment(&app, "pkg-a", w).await;
        app.active_builds
            .lock()
            .await
            .insert(999, tokio_util::sync::CancellationToken::new());

        let snap = app.concurrency_snapshot().await.unwrap();
        assert_eq!(snap.local_active, 1);
        assert_eq!(snap.distributed_active, 1);
        assert_eq!(snap.worker_capacity_online, 3);
        assert_eq!(snap.total_active, 2);
        assert_eq!(snap.total_capacity, 3);
    }

    #[tokio::test]
    async fn concurrency_snapshot_local_only_skips_workers() {
        let (app, _tmp) = concurrency_test_app(SchedulerMode::LocalOnly, 2).await;
        app.state_store
            .upsert_worker("w-online", "x86_64", 3, "1.0", "online", None)
            .await
            .unwrap();

        let snap = app.concurrency_snapshot().await.unwrap();
        assert_eq!(snap.local_slots, 2);
        assert_eq!(snap.worker_capacity_online, 0);
        assert_eq!(snap.distributed_active, 0);
        assert_eq!(snap.total_capacity, 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn generated_key_files_are_created_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let _csrf = load_or_generate_csrf_key(tmp.path()).await.unwrap();
        let _srpm = load_or_generate_srpm_token_key(tmp.path()).await.unwrap();

        for name in ["csrf_key", "srpm_token_key"] {
            let meta = std::fs::metadata(tmp.path().join(name)).unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o600,
                "{name} must be created with 0600 permissions"
            );
        }
    }

    #[tokio::test]
    async fn key_files_round_trip_across_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let a = load_or_generate_csrf_key(tmp.path()).await.unwrap();
        let b = load_or_generate_csrf_key(tmp.path()).await.unwrap();
        assert_eq!(a, b);

        let a = load_or_generate_srpm_token_key(tmp.path()).await.unwrap();
        let b = load_or_generate_srpm_token_key(tmp.path()).await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn corrupted_csrf_key_file_fails_closed_without_rewrite() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("csrf_key");

        tokio::fs::write(&path, "zzzz").await.unwrap();
        let err = load_or_generate_csrf_key(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("csrf key"),
            "unexpected error: {err}"
        );
        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            "zzzz",
            "corrupt key file must not be rewritten"
        );

        let short = "0123456789abcdef0123456789abcdef";
        tokio::fs::write(&path, short).await.unwrap();
        let err = load_or_generate_csrf_key(tmp.path()).await.unwrap_err();
        assert!(
            err.to_string().contains("csrf key"),
            "unexpected error: {err}"
        );
        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            short,
            "short key file must not be rewritten"
        );
    }
}
