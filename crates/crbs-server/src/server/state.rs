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
    /// 共享状态存储（与 CLI 共用 SQLite）。
    pub state_store: Arc<StateStore>,
    /// 本地构建并发限制信号量（仅约束 Hub 本机执行的构建）。
    pub build_semaphore: Arc<tokio::sync::Semaphore>,
    /// 本地构建并发上限（用于 /metrics，避免用 semaphore 反推）。
    pub max_local_builds: usize,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub active_builds: Arc<tokio::sync::Mutex<HashMap<i64, tokio_util::sync::CancellationToken>>>,
    /// 是否允许产品管理端点（init/clean）。
    pub allow_product_management: bool,
    /// 配置目录覆盖（None 表示使用默认 /etc/crbs）。
    pub config_dir: Option<std::path::PathBuf>,
    /// Server 配置（合并 CLI 覆盖后的最终值）。
    pub server_config: crbs_core::config::ServerConfig,
    /// 全局 CRBS 配置（用于解析产品级 result_dir 等）。
    pub crbs_config: crbs_core::config::CrbsConfig,
    pub crbs_root: std::path::PathBuf,
    pub gc_tasks: Arc<tokio::sync::Mutex<HashMap<String, GcTask>>>,
    pub product_tasks: Arc<tokio::sync::Mutex<HashMap<String, ProductTask>>>,
    /// 单活锁 guard：server 运行期间持有 pidfile，退出时自动删除。
    #[allow(dead_code)]
    pub(crate) server_lock: Option<crate::server::ServerLockGuard>,
    /// 停机取消 token：收到 shutdown 信号后第一时间触发，后台调度器与流式端点（SSE/日志流）监听以优雅收尾。
    pub(crate) shutdown_cancel: tokio_util::sync::CancellationToken,
    #[allow(clippy::type_complexity)]
    /// Worker 等待任务的通知列表（worker_id, arch, Notify）。
    pub(crate) worker_waiters:
        Arc<tokio::sync::Mutex<Vec<(i64, String, Arc<tokio::sync::Notify>)>>>,
    /// 全局 Worker 通知（调度器分配任务时触发）。
    pub(crate) worker_notify: Arc<tokio::sync::Notify>,
    /// 日志流缓冲（Worker chunked POST → LogBuffer → CLI 读取）。
    pub(crate) log_buffer: crate::server::log_buffer::LogBuffer,
    /// report_logs 落盘 build.log 已超上限、append 被拒的 build 集合（防认证 worker 灌盘，仅 warn 一次）。
    pub(crate) hub_log_cap_warned: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,
    /// report_logs 已完成 artifact 目录预备（create_dir_all + 递归 chown/chmod）的
    /// build 集合；build_id 自增不复用，标记无失效问题。
    pub(crate) hub_log_dir_prepared: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,
    /// report_logs 落盘 build.log 的 0660 set_permissions 已 warn 过的 build
    /// 集合（逐 chunk 幂等重设、失败逐 chunk 复现，仅 warn 一次；id 不复用无失效）。
    pub(crate) hub_log_chmod_warned: Arc<std::sync::Mutex<std::collections::HashSet<i64>>>,
    /// report_logs 幂等去重：assignment_id → 已接受的最大 chunk 序号。同一
    /// chunk 的重试复用同一序号，重复投递直接确认不再追加（响应丢失零重复）。
    /// 容量封顶 4096 后清空（与相邻集合同策略）：清空/重启窗口内重试可能重复
    /// 一段，属可接受残余。
    pub(crate) hub_log_chunk_seq: Arc<std::sync::Mutex<std::collections::HashMap<i64, u64>>>,
    pub(crate) srpm_token_signer: crbs_core::srpm_token::SrpmTokenSigner,
    pub(crate) csrf_key: [u8; 32],
    /// 登录/注册限流器（per-IP + per-username 固定窗口）。
    pub(crate) login_limiter: Arc<crate::server::rate_limit::LoginRateLimiter>,
    /// 限制同时只能运行一个 GC 任务。
    pub(crate) gc_semaphore: Arc<tokio::sync::Semaphore>,
    /// 认证缓存：凭据派生值 → 用户快照，代数失效 + 10s TTL 兜底；不含凭据原文与密码哈希，重启自然清空。
    pub(crate) auth_cache: crate::server::auth::AuthCache,
    /// repo 通道产品可见性短缓存：product name → is_public，代数失效 + TTL 兜底（防大 repo 逐文件查表）；重启自然清空。
    pub(crate) repo_visibility_cache: crate::server::routes::repo::RepoVisibilityCache,
    /// 包资源画像缓存：(product, pkg) → 调度准入门权重（历史 EMA + 静态覆盖回退），TTL 5min + 定容；包构建终态经 report_result 定点失效。
    pub(crate) resource_weight_cache: crate::server::scheduler::ResourceWeightCache,
    /// 排队归因内存态（planner 维护）：build_id → 最近拒绝原因
    /// + 首次水位全拒时刻（censored 兜底超龄判定输入）；诊断性质，重启清空。
    pub(crate) dispatch_attribution: crate::server::scheduler::planner::DispatchAttribution,
    /// 进程级 metrics 计数组（counter）：调度/学习路径自增，
    /// `/metrics` 抓取时并入快照渲染；重启清零由 Prometheus rate() 容忍。
    pub(crate) metrics: crate::server::metrics::MetricsCounters,
    /// per-product repo regen 在途集合：spawn 前 insert 占位，收尾（含 panic）
    /// 经 guard Drop remove；std::sync::Mutex 仅查插删，不跨 await。
    pub(crate) regen_inflight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// per-product regen 脏标记：regen 在途期间到达的触发 claim 失败时 insert，
    /// 在途轮收尾原子取走——有则补跑一轮完整 regen 收敛到最新；新 claim 成功即清除。
    /// std::sync::Mutex 仅 insert/remove，不跨 await。
    pub(crate) regen_dirty: std::sync::Mutex<std::collections::HashSet<String>>,
    /// auto replay 任务级在途集合：末两子构建近同时终态时，两个 spawn 钩子都读到
    /// all-succeeded 快照 → 双 `reproduce_fan_out`；入口（首个 await 前）
    /// check-and-insert 源 task id 占位，收尾（含 Err/panic）guard Drop remove；
    /// std::sync::Mutex 仅查插删，不跨 await。
    pub(crate) auto_replay_inflight: std::sync::Mutex<std::collections::HashSet<i64>>,
    /// 批次驱动器已放行轮间栅栏的轮次（batch_id, round）；内存标记，崩溃丢失后
    /// 多跑一次幂等 assemble 不丢正确性；std::sync::Mutex 仅查插删，不跨 await。
    pub(crate) batch_barrier_passed: std::sync::Mutex<std::collections::HashSet<(i64, i64)>>,
}

/// 集群并发快照：首页 footer 系统条与 `/api/v1/metrics` 共源的"并发"口径
///（见 [`AppState::concurrency_snapshot`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConcurrencySnapshot {
    /// Hub 本机活跃构建（active_builds 内存表）。
    pub local_active: usize,
    /// 在线 worker 活跃任务合计（worker_tasks assigned/running，只计在线 worker）。
    pub distributed_active: usize,
    /// Hub 本地槽（max_local_builds）。
    pub local_slots: usize,
    /// 在线 worker capacity 合计。
    pub worker_capacity_online: usize,
    /// 分子合计 = local_active + distributed_active。
    pub total_active: usize,
    /// 分母合计：分母只计启用车道（auto = 本地槽 + 在线容量；单车道只计对应项）。
    pub total_capacity: usize,
}

impl ConcurrencySnapshot {
    /// 分母规则（纯函数，单测钉死）：分母只计启用车道——LocalOnly 仅本地槽、
    /// DistributedOnly 仅在线 worker 容量、auto 两者合计。
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

/// 构建清理 guard：置于 spawn 闭包作用域，Drop 从 active_builds 移除条目，兜底
/// return/panic；正常路径应显式调 `remove` 异步清理。
pub(crate) struct CleanupGuard {
    pub active_builds: Arc<tokio::sync::Mutex<HashMap<i64, tokio_util::sync::CancellationToken>>>,
    pub build_id: i64,
    pub consumed: bool,
}

impl CleanupGuard {
    /// 显式异步移除条目；调用后 guard 已消费，Drop 不再重复清理。
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
        // try_lock 避免 runtime 关闭时死锁
        match self.active_builds.try_lock() {
            Ok(mut map) => {
                map.remove(&self.build_id);
            }
            Err(_) => {
                // 锁被占用（正常并发收尾）：交给运行时异步补删；runtime 已关闭
                // 则进程即将退出，条目随进程消失，仅留痕。
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

// for_test 专用固定密钥（无保密需求）；生产密钥一律走 load_or_generate_*（getrandom 失败即启动失败 fail-closed，无静默回退）。
const TEST_SRPM_TOKEN_KEY: [u8; 32] = [0x42; 32];
const TEST_CSRF_KEY: [u8; 32] = [0x43; 32];

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

/// 密钥文件创建结果：区分"本次调用写入"与"撞上并发首启的另一进程"。
enum KeyFileCreate {
    Written,
    /// `create_new` 撞 AlreadyExists：另一进程已创建（内容可能未写完），转读取分支。
    AlreadyExists,
}

/// 以 0o600 一次性创建密钥文件并写入：`create_new` + `mode(0o600)` 自诞生即 0600，
/// 无先写后 chmod 窗口（他用户可读走密钥）；AlreadyExists 可与真 IO 失败区分（并发首启）。
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
        // EEXIST：另一并发首启进程已创建。
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Ok(KeyFileCreate::AlreadyExists)
        }
        Err(e) => return Err(e),
    };
    file.write_all(contents.as_bytes()).await?;
    file.flush().await?;
    Ok(KeyFileCreate::Written)
}

/// 加载或生成持久化密钥的共享实现（`srpm_token_key` / `csrf_key` 共用）：落盘
/// `crbs_root/<file_name>`（0o600，重启一致），首启随机生成（getrandom 失败即
/// 启动失败 fail-closed，无静默回退）；并发首启（对端未写完）重试读取一次。
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
            // 并发首启复用他进程密钥：对端可能未写完，重试一次，仍失败报错而非覆盖（fail-closed）。
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
                // chown 到 crbs 组（mode 保持 0600，密钥不给组读）；非 root 必 EPERM，helper 内 debug。
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

/// 加载或生成 SRPM 下载 token 签名密钥：持久化 `crbs_root/srpm_token_key`，
/// 首启随机生成，0o600，重启一致。
pub async fn load_or_generate_srpm_token_key(
    crbs_root: &std::path::Path,
) -> crbs_core::Result<[u8; 32]> {
    load_or_generate_key(crbs_root, "srpm_token_key", "srpm token key").await
}

/// 加载或生成 CSRF token 派生密钥：持久化 `crbs_root/csrf_key`，
/// 首启随机生成，0o600，重启一致。
pub async fn load_or_generate_csrf_key(crbs_root: &std::path::Path) -> crbs_core::Result<[u8; 32]> {
    load_or_generate_key(crbs_root, "csrf_key", "csrf key").await
}

impl AppState {
    /// 创建测试用 AppState（不创建 pidfile，不启动恢复调度器）。
    pub fn for_test(
        state_store: Arc<StateStore>,
        server_config: crbs_core::config::ServerConfig,
        crbs_root: std::path::PathBuf,
    ) -> Self {
        // 特权后端钉死非 Helper 模式（进程级一次），防先于本测试加载 config 的路径钉歪全进程。
        crate::test_support::pin_setuid_privilege_backend();
        let max_local = if server_config.max_local_builds > 0 {
            server_config.max_local_builds
        } else {
            crate::server::bootstrap::num_cpus()
        };
        let crbs_config = crbs_core::config::CrbsConfig {
            crbs_root: crbs_root.clone(),
            // result_dir / shared_layers_dir Option 化：None = 按 crbs_root 派生。
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

    /// 测试构造（注入登录限流时钟，供窗口恢复类测试手动推进），余同 [`AppState::for_test`]。
    #[doc(hidden)]
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

    /// 显式 result_dir 覆盖（server.toml 优先，crbs.toml 兜底），均未设置返回 None。
    /// 供 GC / diff 在 `pinned_to_root` 清空显式配置后回填：安全根须与文件实际位置
    /// 一致，否则 GC 全候选 skipped_invalid 静默零回收、diff 对合法 result_dir 全拒 500。
    pub fn explicit_result_dir(&self) -> Option<std::path::PathBuf> {
        self.server_config
            .result_dir
            .clone()
            .or_else(|| self.crbs_config.result_dir.clone())
    }

    /// 全局 result root：显式 crbs.toml result_dir 优先，否则 `{crbs_root}/results`（随 server root 派生，不随 crbs.toml 引擎 root）。
    fn global_result_root(&self) -> std::path::PathBuf {
        self.crbs_config
            .result_dir
            .clone()
            .unwrap_or_else(|| self.crbs_root.join("results"))
    }

    /// task 目录对账清扫（`tasks_gc`）的扫描根：server.toml `result_dir` 显式时
    /// 全部 task 目录都在该根下，否则随全局根派生。
    /// 取舍：产品级 result_dir 覆盖目录不在清扫范围（worker 侧
    /// sweep_result_dirs 同款缺口）；升级 = 收集 tasks.result_dir 去重父目录逐根清扫。
    pub(crate) fn default_task_result_root(&self) -> std::path::PathBuf {
        self.server_config
            .result_dir
            .clone()
            .unwrap_or_else(|| self.global_result_root())
    }

    /// 产品产物根目录（严格版）：优先级 server.toml result_dir > 产品 > 全局；未 seed 到 DB 回退全局，内部一致性错误上抛。
    pub async fn result_dir_for(&self, product: &str) -> crbs_core::Result<std::path::PathBuf> {
        if let Some(ref server_result_dir) = self.server_config.result_dir {
            return Ok(server_result_dir.clone());
        }
        // 仅取产品层 result_dir，不做完整 Config 合并（CrbsConfig::load 会读全局
        // 配置文件、扩大失败面）；NotFound → 全局，其他错误上抛。
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

    /// 产品产物根目录（回退版）：配置加载失败回退全局 result_dir，读取/执行端点不因产品配置临时损坏而不可用。
    pub async fn result_dir_for_or_default(&self, product: &str) -> std::path::PathBuf {
        match self.result_dir_for(product).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(product = %product, error = %e, "Failed to load product config for result_dir; falling back to global result_dir");
                self.global_result_root()
            }
        }
    }

    /// 产品详情（UI 页 / API JSON）路径字段覆写为 server 世界生效值。
    /// merged config 的 crbs_root 属引擎世界（crbs.toml，CLI 本地构建语义）；
    /// hub 侧构建/产物/GC 全部 pin 在 server root，透出引擎 root 会指向不存在的路径。
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

    /// 集群并发快照：分子 = Hub 本地活跃 + 在线 worker 活跃，分母只计启用的
    /// 车道（scheduler_mode 三态）。在线判定复用调度器同款
    /// `list_online_workers`（status='online' 且心跳新鲜）；LocalOnly 跳过
    /// worker 查询——分布式车道未启用，容量与活跃不进口径。
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
            // 分布式活跃只计在线 worker：刚掉线 worker 的残留 assignment 不代表集群在跑的量。
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

/// 后台 GC 任务状态（内存态，重启即失）。
#[derive(Debug, Clone)]
pub enum GcTaskStatus {
    /// 执行中。
    Running,
    /// 完成并携带删除统计。
    Succeeded(GcSummary),
    /// 失败原因。
    Failed(String),
}

/// 后台 GC 任务记录（内存态，重启即失）。
#[derive(Debug, Clone)]
pub struct GcTask {
    pub status: GcTaskStatus,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// 终态打点（Running 为 None）；与整条记录同为内存态，重启即失。
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// 产品后台操作任务状态（内存态，重启即失）。
#[derive(Debug, Clone)]
pub enum ProductTaskStatus {
    /// 执行中。
    Running,
    /// 已完成。
    Succeeded,
    /// 失败原因。
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

    // ===== 集群并发快照 =====

    use crbs_core::config::SchedulerMode;

    /// 分母只计启用车道：auto = 本地槽 + 在线 worker 容量。
    #[test]
    fn cluster_capacity_auto_sums_local_and_worker() {
        assert_eq!(
            ConcurrencySnapshot::capacity_of(4, 6, &SchedulerMode::Auto),
            10
        );
    }

    /// DistributedOnly 分母不含本地槽（无在线 worker 时为 0）。
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

    /// LocalOnly 分母不含 worker 容量。
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

    /// seed 一条已派发的活跃 worker 任务（build pending + assign → assigned 行）。
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

    /// auto：分母 = 本地槽 + 在线 worker 容量；离线 worker 的容量与残留
    /// assignment 都不计入。
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

    /// DistributedOnly：分母不含本地槽，分子仍为本地 + 在线 worker 活跃合计。
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

    /// LocalOnly：不查 worker，容量与分布式活跃均为 0，分母仅本地槽。
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

    /// 密钥文件必须以 0o600 诞生（create_new + mode 一次到位，无先写后 chmod 窗口）；unix-gated。
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

    /// 密钥持久化：第二次加载复用同一密钥（重启一致性），不重新生成。
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

    /// 密钥文件损坏必须 fail-closed 且不得改写内容（重新生成 = CSRF 静默轮换、
    /// 会话全失效、多实例各持钥）；非法 hex 与长度不足两分支都钉住。
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
