// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 任务分发：调度器分配任务后通知等待的 Worker。

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::timeout;

use crate::server::state::AppState;

/// 任务类型：普通构建或远程重建 base_os。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AssignmentKind {
    #[serde(rename = "build")]
    Build,

    #[serde(rename = "init")]
    Init,
}

/// 分发给 Worker 的任务载荷。
#[derive(Debug, Clone)]
pub struct AssignedTask {
    pub assignment_id: i64,
    pub task_id: Option<i64>,
    pub build_id: i64,
    pub product: String,
    pub srpm_url: String,
    pub build_options: serde_json::Value,
    pub product_config: String,

    pub reproduce_packages_url: Option<String>,
    pub kind: AssignmentKind,

    pub init_product: Option<String>,

    pub product_repo_enabled: bool,
}

/// Worker 任务分发器。
pub struct WorkerDispatch {
    app: Arc<AppState>,

    redelivery_cursor: std::sync::Mutex<std::collections::HashMap<i64, usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HydrationErrorPolicy {
    Claim,

    Redelivery,
}

fn warn_redelivery_hydration_failure(assignment_id: i64, build_id: i64, reason: &str) {
    tracing::warn!(
        assignment_id = %assignment_id,
        build_id = %build_id,
        error = %reason,
        "Redelivery hydration failed; skipping this poll round, running assignment left untouched"
    );
}

impl WorkerDispatch {
    pub fn new(app: Arc<AppState>) -> Self {
        Self {
            app,
            redelivery_cursor: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Worker 等待任务：最多等 `wait_secs` 秒，期间有新任务分配时立即返回。
    /// 先检查是否已有分配给该 Worker 的任务；注册 waiter 后立刻复查，关闭
    /// "检查-注册"竞态窗口。Notify 不缓存通知，注册后二次检查与 notified()
    /// 首次 poll 之间到达的分配靠复查覆盖。
    pub async fn wait_for_task(
        &self,
        worker_id: i64,
        worker_arch: &str,
        wait_secs: u64,
    ) -> Option<AssignedTask> {
        match self.check_assigned_task(worker_id, worker_arch).await {
            Ok(Some(task)) => return Some(task),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(worker_id = %worker_id, error = %e, "poll: check assigned task failed")
            }
        }

        let notify = Arc::new(Notify::new());

        struct WaiterGuard {
            app: std::sync::Arc<crate::server::state::AppState>,
            worker_id: i64,
            notify: std::sync::Arc<tokio::sync::Notify>,
            armed: bool,
        }
        impl Drop for WaiterGuard {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                let app = self.app.clone();
                let worker_id = self.worker_id;
                let notify = self.notify.clone();

                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(async move {
                            let mut waiting = app.worker_waiters.lock().await;

                            waiting.retain(|(_, _, n)| !std::sync::Arc::ptr_eq(n, &notify));
                        });
                    }
                    Err(_) => {
                        tracing::warn!(
                            worker_id = %worker_id,
                            "WaiterGuard dropped outside a tokio runtime; leaked waiter entry \
                             will swallow task wakeups until the worker re-polls"
                        );
                    }
                }
            }
        }
        let mut waiter_guard = WaiterGuard {
            app: self.app.clone(),
            worker_id,
            notify: notify.clone(),
            armed: true,
        };

        {
            let mut waiting = self.app.worker_waiters.lock().await;
            waiting.push((worker_id, worker_arch.to_string(), notify.clone()));
        }

        if let Ok(Some(task)) = self.check_assigned_task(worker_id, worker_arch).await {
            {
                let mut waiting = self.app.worker_waiters.lock().await;
                waiting.retain(|(id, _, _)| *id != worker_id);
            }
            waiter_guard.armed = false;
            return Some(task);
        }

        let _ = timeout(Duration::from_secs(wait_secs), notify.notified()).await;

        {
            let mut waiting = self.app.worker_waiters.lock().await;
            waiting.retain(|(id, _, _)| *id != worker_id);
        }
        waiter_guard.armed = false;

        if let Ok(Some(task)) = self.check_assigned_task(worker_id, worker_arch).await {
            return Some(task);
        }

        None
    }

    async fn check_assigned_task(
        &self,
        worker_id: i64,
        worker_arch: &str,
    ) -> crbs_core::Result<Option<AssignedTask>> {
        let result = self.app.state_store.check_assigned_task(worker_id).await;

        match result {
            Ok(Some(info @ crbs_core::AssignedTaskInfo::Build { .. })) => {
                self.hydrate_build_assignment(
                    worker_id,
                    worker_arch,
                    info,
                    HydrationErrorPolicy::Claim,
                )
                .await
            }
            Ok(Some(crbs_core::AssignedTaskInfo::Init {
                assignment_id,
                product,
            })) => {
                let product_config = match self.read_product_config(&product).await {
                    Ok(cfg) => cfg,
                    Err(ProductConfigError::NotInDb) => {
                        tracing::error!(
                            product = %product,
                            assignment_id = %assignment_id,
                            worker_id = %worker_id,
                            "Refusing init dispatch: product not in DB (fail-closed)"
                        );
                        if let Err(err) = self
                            .app
                            .state_store
                            .complete_init_assignment(
                                assignment_id,
                                false,
                                Some("product not registered in database"),
                            )
                            .await
                        {
                            tracing::warn!(
                                assignment_id = %assignment_id,
                                error = %err,
                                "Failed to mark init assignment as failed after NotInDb"
                            );
                        }
                        return Ok(None);
                    }

                    Err(ProductConfigError::Permanent(err)) => {
                        tracing::error!(
                            product = %product,
                            assignment_id = %assignment_id,
                            worker_id = %worker_id,
                            error = %err,
                            "Refusing init dispatch: product chain config permanently invalid (fail-closed)"
                        );
                        if let Err(complete_err) = self
                            .app
                            .state_store
                            .complete_init_assignment(
                                assignment_id,
                                false,
                                Some(&format!("product chain config invalid: {err}")),
                            )
                            .await
                        {
                            tracing::warn!(
                                assignment_id = %assignment_id,
                                error = %complete_err,
                                "Failed to mark init assignment as failed after permanent config error"
                            );
                        }
                        return Ok(None);
                    }
                    Err(ProductConfigError::Transient(err)) => {
                        tracing::warn!(
                            product = %product,
                            assignment_id = %assignment_id,
                            worker_id = %worker_id,
                            error = %err,
                            "Transient error resolving product config for init; marking failed"
                        );
                        if let Err(complete_err) = self
                            .app
                            .state_store
                            .complete_init_assignment(
                                assignment_id,
                                false,
                                Some(&format!("resolve product config: {}", err)),
                            )
                            .await
                        {
                            tracing::warn!(
                                assignment_id = %assignment_id,
                                error = %complete_err,
                                "Failed to mark init assignment as failed after transient error"
                            );
                        }
                        return Ok(None);
                    }
                };

                tracing::info!(
                    assignment_id = %assignment_id,
                    worker_id = %worker_id,
                    product = %product,
                    "Dispatching init assignment to worker"
                );

                Ok(Some(AssignedTask {
                    assignment_id,
                    task_id: None,
                    build_id: 0,
                    product: product.clone(),
                    srpm_url: String::new(),
                    build_options: serde_json::Value::Null,
                    product_config,
                    reproduce_packages_url: None,
                    kind: AssignmentKind::Init,
                    init_product: Some(product),

                    product_repo_enabled: false,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// poll 响应丢失重投递：wait 到期且无新任务时，查询该 worker 名下
    /// running 且构建仍处 building 的 assignment，按正常领取相同的水合路径
    /// 重新下发；多个在跑任务之间按轮转游标逐个优先，避免每次都重发同一
    /// 条、其余丢失响应的任务持续收不到重发。
    ///
    /// 不把 running 重置回 pending（会复制双执行），也不做送达确认协议
    /// （worker 侧以取消注册表去重）。水合失败仅 warn 并跳过本轮：驱动查询
    /// 在任务执行期每个 poll 周期都会命中（属稳态而非异常），失败只说明本
    /// 轮响应无法构造——release 删行重派等于复制双执行，fail 会终结一次健
    /// 康执行；真正消失的 assignment 由 JOIN 条件自然排除，下一轮 poll 自然
    /// 重试。
    pub async fn redeliver_running_task(
        &self,
        worker_id: i64,
        worker_arch: &str,
    ) -> crbs_core::Result<Option<AssignedTask>> {
        let running = self
            .app
            .state_store
            .list_running_assignments_for_worker(worker_id)
            .await?;
        if running.is_empty() {
            return Ok(None);
        }

        let len = running.len();
        let index = {
            let mut cursors = self
                .redelivery_cursor
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let idx = cursors.entry(worker_id).or_insert(0);
            let current = *idx % len;
            *idx = idx.wrapping_add(1);
            drop(cursors);
            current
        };
        let Some(info) = running.into_iter().nth(index) else {
            return Ok(None);
        };
        let task = self
            .hydrate_build_assignment(
                worker_id,
                worker_arch,
                info,
                HydrationErrorPolicy::Redelivery,
            )
            .await?;
        if let Some(t) = task.as_ref() {
            tracing::debug!(
                worker_id = %worker_id,
                assignment_id = %t.assignment_id,
                build_id = %t.build_id,
                "worker still holds running assignment; redelivery payload sent (deduped by worker if already executing)"
            );
        }
        Ok(task)
    }

    async fn hydrate_build_assignment(
        &self,
        worker_id: i64,
        worker_arch: &str,
        info: crbs_core::AssignedTaskInfo,
        policy: HydrationErrorPolicy,
    ) -> crbs_core::Result<Option<AssignedTask>> {
        let crbs_core::AssignedTaskInfo::Build {
            assignment_id,
            task_id,
            build_id,
            product,
            srpm_path: _,
            request_json,
            repo_consume,
        } = info
        else {
            return Ok(None);
        };

        let build_options: serde_json::Value = match request_json.as_deref() {
            None => match policy {
                HydrationErrorPolicy::Redelivery => {
                    warn_redelivery_hydration_failure(
                        assignment_id,
                        build_id,
                        "request_json is NULL (build row not yet ready)",
                    );
                    return Ok(None);
                }
                HydrationErrorPolicy::Claim => {
                    tracing::warn!(
                        build_id = %build_id,
                        assignment_id = %assignment_id,
                        "request_json is NULL (build row not ready); releasing assignment back to queue"
                    );
                    if let Err(e) = self
                        .app
                        .state_store
                        .release_assignment(assignment_id, build_id)
                        .await
                    {
                        tracing::warn!(
                            assignment_id = %assignment_id,
                            build_id = %build_id,
                            error = %e,
                            "Failed to release assignment with missing request_json"
                        );
                    }
                    return Ok(None);
                }
            },
            Some(raw) => match serde_json::from_str(raw) {
                Ok(opts) => opts,
                Err(e) => {
                    if policy == HydrationErrorPolicy::Redelivery {
                        warn_redelivery_hydration_failure(
                            assignment_id,
                            build_id,
                            &format!("request_json corrupted: {e}"),
                        );
                        return Ok(None);
                    }
                    tracing::error!(
                        build_id = %build_id,
                        assignment_id = %assignment_id,
                        error = %e,
                        "request_json is corrupted; failing assignment"
                    );
                    if let Err(fail_err) = self
                        .app
                        .state_store
                        .fail_assignment(assignment_id, build_id)
                        .await
                    {
                        tracing::warn!(
                            assignment_id = %assignment_id,
                            build_id = %build_id,
                            error = %fail_err,
                            "Failed to mark corrupted assignment as failed"
                        );
                    }
                    return Ok(None);
                }
            },
        };

        let build_arch = build_options
            .get("arch")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !build_arch.is_empty() && build_arch != "noarch" && build_arch != worker_arch {
            if policy == HydrationErrorPolicy::Redelivery {
                warn_redelivery_hydration_failure(
                    assignment_id,
                    build_id,
                    &format!(
                        "arch mismatch: task arch {build_arch:?} vs worker arch {worker_arch:?}"
                    ),
                );
                return Ok(None);
            }
            tracing::warn!(
                worker_id = %worker_id,
                worker_arch = %worker_arch,
                build_id = %build_id,
                build_arch = %build_arch,
                "Assigned task arch does not match worker arch; releasing assignment"
            );
            if let Err(e) = self
                .app
                .state_store
                .release_assignment(assignment_id, build_id)
                .await
            {
                tracing::warn!(
                    assignment_id = %assignment_id,
                    build_id = %build_id,
                    error = %e,
                    "Failed to release mismatched assignment"
                );
            }
            return Ok(None);
        }

        let token = self.app.srpm_token_signer.generate(build_id);

        let srpm_url = format!("/api/v1/builds/{}/srpm-download?token={}", build_id, token);

        let reproduce_from_build_id = build_options
            .get("reproduce_from_build_id")
            .and_then(|v| v.as_i64());
        let reproduce_packages_url = reproduce_from_build_id.map(|src_id| {
            let pkg_token = self.app.srpm_token_signer.generate(src_id);
            format!(
                "/api/v1/builds/{}/build-packages?token={}",
                src_id, pkg_token
            )
        });

        let config_result = match self
            .app
            .state_store
            .get_build_product_config_toml(build_id)
            .await
        {
            Ok(Some(toml)) => Ok(toml),
            Ok(None) => {
                self.resolve_and_anchor_product_config(&product, build_id)
                    .await
            }
            Err(e) => Err(ProductConfigError::Transient(e.to_string())),
        };
        let product_config = match config_result {
            Ok(cfg) => cfg,
            Err(ProductConfigError::NotInDb) => {
                if policy == HydrationErrorPolicy::Redelivery {
                    warn_redelivery_hydration_failure(
                        assignment_id,
                        build_id,
                        &format!("product {product:?} not registered in database"),
                    );
                    return Ok(None);
                }
                tracing::error!(
                    product = %product,
                    build_id = %build_id,
                    assignment_id = %assignment_id,
                    "Refusing dispatch: product not in DB (fail-closed); marking build failed"
                );
                if let Err(fail_err) = self
                    .app
                    .state_store
                    .fail_assignment(assignment_id, build_id)
                    .await
                {
                    tracing::warn!(
                        assignment_id = %assignment_id,
                        build_id = %build_id,
                        error = %fail_err,
                        "Failed to mark assignment as failed after NotInDb"
                    );
                }
                return Ok(None);
            }

            Err(ProductConfigError::Permanent(err)) => {
                if policy == HydrationErrorPolicy::Redelivery {
                    warn_redelivery_hydration_failure(
                        assignment_id,
                        build_id,
                        &format!("product chain config invalid: {err}"),
                    );
                    return Ok(None);
                }
                tracing::error!(
                    product = %product,
                    build_id = %build_id,
                    assignment_id = %assignment_id,
                    error = %err,
                    "Refusing dispatch: product chain config permanently invalid; marking build failed"
                );
                if let Err(fail_err) = self
                    .app
                    .state_store
                    .fail_assignment(assignment_id, build_id)
                    .await
                {
                    tracing::warn!(
                        assignment_id = %assignment_id,
                        build_id = %build_id,
                        error = %fail_err,
                        "Failed to mark assignment as failed after permanent config error"
                    );
                }
                return Ok(None);
            }
            Err(ProductConfigError::Transient(err)) => {
                if policy == HydrationErrorPolicy::Redelivery {
                    warn_redelivery_hydration_failure(
                        assignment_id,
                        build_id,
                        &format!("transient error resolving product config: {err}"),
                    );
                    return Ok(None);
                }
                tracing::warn!(
                    product = %product,
                    build_id = %build_id,
                    assignment_id = %assignment_id,
                    error = %err,
                    "Transient error resolving product config; releasing assignment for retry"
                );
                if let Err(rel_err) = self
                    .app
                    .state_store
                    .release_assignment(assignment_id, build_id)
                    .await
                {
                    tracing::warn!(
                        assignment_id = %assignment_id,
                        build_id = %build_id,
                        error = %rel_err,
                        "Failed to release assignment after transient product-config error"
                    );
                }
                return Ok(None);
            }
        };

        let product_repo_enabled = repo_consume;

        Ok(Some(AssignedTask {
            assignment_id,
            task_id,
            build_id,
            product,
            srpm_url,
            build_options,
            product_config,
            reproduce_packages_url,
            kind: AssignmentKind::Build,
            init_product: None,
            product_repo_enabled,
        }))
    }

    async fn resolve_and_anchor_product_config(
        &self,
        product: &str,
        build_id: i64,
    ) -> Result<String, ProductConfigError> {
        let toml = self.read_product_config(product).await?;
        if let Err(e) = self
            .app
            .state_store
            .set_build_product_config_toml(build_id, &toml)
            .await
        {
            tracing::warn!(
                build_id,
                error = %e,
                "Failed to persist product config snapshot; debug will fall back to current config"
            );
        }
        Ok(toml)
    }

    async fn read_product_config(&self, product: &str) -> Result<String, ProductConfigError> {
        let record = match self.app.state_store.get_product_by_name(product).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ProductConfigError::NotInDb),
            Err(e) => return Err(ProductConfigError::Transient(e.to_string())),
        };

        let resolved = match self.app.state_store.chain_resolve(record.id).await {
            Ok(r) => r,
            Err(e) => return Err(classify_chain_error(e)),
        };
        log_path_overrides(product, &resolved.config);
        match self.app.state_store.chain_resolve_to_toml(record.id).await {
            Ok(toml) => Ok(toml.as_ref().clone()),
            Err(e) => Err(classify_chain_error(e)),
        }
    }
}

#[derive(Debug)]
enum ProductConfigError {
    NotInDb,
    Permanent(String),
    Transient(String),
}

fn classify_chain_error(e: crbs_core::error::CrbsError) -> ProductConfigError {
    match e {
        crbs_core::error::CrbsError::ProductChainInvalid { .. }
        | crbs_core::error::CrbsError::ProductChainCycle { .. }
        | crbs_core::error::CrbsError::ProductChainTooDeep { .. }
        | crbs_core::error::CrbsError::ValidationFailed { .. } => {
            ProductConfigError::Permanent(e.to_string())
        }
        other => ProductConfigError::Transient(other.to_string()),
    }
}

fn log_path_overrides(product: &str, cfg: &crbs_core::config::ProductConfig) {
    let overrides = crbs_core::config::product::path_overrides(cfg);
    if overrides.is_empty() {
        return;
    }
    let rendered = overrides
        .iter()
        .map(|(name, p)| format!("{name}={}", p.display()))
        .collect::<Vec<_>>()
        .join(",");
    tracing::debug!(
        product = %product,
        overrides = %rendered,
        "dispatching product config with machine-local path overrides; they reach the worker verbatim"
    );
}

/// 通知等待的 Worker 有新任务；锁内遍历调用 `notify_one()`（非阻塞），
/// 不移动/移除 waiter。指定 worker 只唤醒其自身 waiter，未指定则广播全部。
pub async fn notify_workers(app: &Arc<AppState>, worker_id: Option<i64>) {
    let waiters = app.worker_waiters.lock().await;

    match worker_id {
        Some(id) => {
            for (wid, _, notify) in waiters.iter() {
                if *wid == id {
                    notify.notify_one();
                }
            }
        }
        None => {
            for (_, _, notify) in waiters.iter() {
                notify.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crbs_core::config::ServerConfig;
    use crbs_core::StateStore;
    use tokio::time::timeout;

    use crate::server::state::AppState;

    use super::{notify_workers, WorkerDispatch};

    async fn setup_dispatch() -> (
        WorkerDispatch,
        Arc<AppState>,
        Arc<StateStore>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let dispatch = WorkerDispatch::new(app.clone());
        (dispatch, app, store, tmp)
    }

    async fn seed_assigned_build(
        store: &StateStore,
        product: &str,
        request_json: Option<&str>,
    ) -> (i64, i64, i64) {
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "", "online", None)
            .await
            .unwrap();
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product,
                pkg_name: "pkg",
                phase: "pending",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(crate::test_support::seed_task(store, product, "pkg").await),
                ..Default::default()
            })
            .await
            .unwrap();
        if let Some(json) = request_json {
            store
                .set_build_request_info(build_id, "/tmp/pkg.src.rpm", json)
                .await
                .unwrap();
        }
        let (assignment_id, _) = store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();
        (worker_id, build_id, assignment_id)
    }

    #[tokio::test]
    async fn check_assigned_task_rejects_invalid_request_json() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        let (worker_id, build_id, _assignment_id) =
            seed_assigned_build(&store, "fedora", Some("not valid json")).await;

        let result = dispatch.check_assigned_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "expected corrupted assignment to be dropped and returned as None"
        );

        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "failed");
    }

    #[tokio::test]
    async fn check_assigned_task_releases_assignment_when_request_json_null() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;

        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "fedora", None).await;

        let result = dispatch.check_assigned_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "NULL request_json assignment must be dropped (None)"
        );

        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "pending");
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
                .bind(assignment_id)
                .fetch_optional(store.pool())
                .await
                .unwrap();
        assert!(
            status.is_none(),
            "worker_task row must be deleted on release"
        );
    }

    #[tokio::test]
    async fn redelivery_skips_null_request_json_without_touching_running_assignment() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;

        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "fedora", None).await;
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
            .bind(assignment_id)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();

        let result = dispatch.redeliver_running_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "redelivery must skip this round (Ok(None)) on NULL request_json"
        );

        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "building");
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
                .bind(assignment_id)
                .fetch_optional(store.pool())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("running"));
    }

    #[tokio::test]
    async fn check_assigned_task_reads_repo_consume_column() {
        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        for (column, want_enabled) in [(1i64, true), (0, false)] {
            let (dispatch, _app, store, _tmp) = setup_dispatch().await;
            sqlx::query("INSERT INTO users (name, role) VALUES ('owner', 'admin')")
                .execute(store.pool())
                .await
                .unwrap();
            store
                .create_product(crbs_core::CreateProductInput {
                    name: "axis",
                    display_name: None,
                    owner_id: Some(1),
                    parent_id: None,
                    visibility: "private",
                    config: &cfg,
                    changed_by_user_id: None,
                    reason: None,
                })
                .await
                .unwrap();
            let (worker_id, build_id, _assignment_id) =
                seed_assigned_build(&store, "axis", Some(r#"{"arch":"x86_64"}"#)).await;
            sqlx::query("UPDATE builds SET repo_consume = $1 WHERE id = $2")
                .bind(column)
                .bind(build_id)
                .execute(store.pool())
                .await
                .unwrap();

            let task = dispatch
                .check_assigned_task(worker_id, "x86_64")
                .await
                .unwrap()
                .expect("hydrated assignment must dispatch");
            assert_eq!(
                task.product_repo_enabled, want_enabled,
                "repo_consume column {column} must drive product_repo_enabled"
            );
        }
    }

    #[tokio::test]
    async fn check_assigned_task_anchors_product_config_snapshot() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example.com/a".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        store
            .create_product(crbs_core::CreateProductInput {
                name: "anchor",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &cfg,
                changed_by_user_id: None,
                reason: Some("test seed"),
            })
            .await
            .unwrap();
        let (worker_id, build_id, _assignment_id) =
            seed_assigned_build(&store, "anchor", Some(r#"{"arch":"x86_64"}"#)).await;

        let task = dispatch
            .check_assigned_task(worker_id, "x86_64")
            .await
            .unwrap()
            .expect("hydrated assignment must dispatch");
        assert!(
            task.product_config.contains("http://example.com/a"),
            "dispatch payload must carry resolved config, got: {}",
            task.product_config
        );
        let anchored = store
            .get_build_product_config_toml(build_id)
            .await
            .unwrap()
            .expect("claim must anchor the product config snapshot");
        assert_eq!(anchored, task.product_config);
    }

    #[tokio::test]
    async fn redelivery_reuses_anchored_product_config_after_update() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example.com/a".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let product_id = store
            .create_product(crbs_core::CreateProductInput {
                name: "anchor-upd",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &cfg,
                changed_by_user_id: None,
                reason: Some("test seed"),
            })
            .await
            .unwrap();
        let (worker_id, build_id, _assignment_id) =
            seed_assigned_build(&store, "anchor-upd", Some(r#"{"arch":"x86_64"}"#)).await;

        let claimed = dispatch
            .check_assigned_task(worker_id, "x86_64")
            .await
            .unwrap()
            .expect("initial claim must dispatch");
        assert!(claimed.product_config.contains("http://example.com/a"));

        let mut updated = cfg;
        updated.repos[0].baseurl = "http://example.com/b".into();
        store
            .update_product_config(product_id, &updated, None, Some("test update"), None)
            .await
            .unwrap();

        let redelivered = dispatch
            .redeliver_running_task(worker_id, "x86_64")
            .await
            .unwrap()
            .expect("running assignment must be redelivered");
        assert!(
            redelivered.product_config.contains("http://example.com/a"),
            "redelivery must reuse the anchored snapshot, got: {}",
            redelivered.product_config
        );
        assert!(!redelivered.product_config.contains("http://example.com/b"));
        assert_eq!(
            store
                .get_build_product_config_toml(build_id)
                .await
                .unwrap()
                .as_deref(),
            Some(claimed.product_config.as_str())
        );
    }

    #[test]
    fn classify_chain_error_maps_config_semantics_to_permanent() {
        use super::{classify_chain_error, ProductConfigError};
        use crbs_core::error::CrbsError;

        let permanent = [
            CrbsError::ProductChainInvalid {
                product: "p".into(),
                reason: "r".into(),
            },
            CrbsError::ProductChainCycle { chain: vec![] },
            CrbsError::ProductChainTooDeep { max: 8 },
            CrbsError::ValidationFailed {
                message: "m".into(),
            },
        ];
        for e in permanent {
            assert!(
                matches!(classify_chain_error(e), ProductConfigError::Permanent(_)),
                "config-semantic error must classify as Permanent"
            );
        }

        let transient = [
            CrbsError::Database("db down".into()),
            CrbsError::Io {
                context: "io".into(),
                kind: std::io::ErrorKind::Other,
                detail: "d".into(),
            },
            CrbsError::Timeout,
            CrbsError::NotFound {
                message: "m".into(),
            },
        ];
        for e in transient {
            assert!(
                matches!(classify_chain_error(e), ProductConfigError::Transient(_)),
                "environment/ambiguous errors must classify as Transient"
            );
        }
    }

    #[tokio::test]
    async fn check_assigned_task_fails_assignment_on_permanently_invalid_chain() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;

        let cfg = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                enabled: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let product_id = store
            .create_product(crbs_core::CreateProductInput {
                name: "broken",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &cfg,
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
        let mut bad = cfg.clone();
        bad.base_packages.clear();
        let blob = serde_json::to_string(&bad).unwrap();
        sqlx::query("UPDATE products SET config_json = $1 WHERE id = $2")
            .bind(&blob)
            .bind(product_id)
            .execute(store.pool())
            .await
            .unwrap();

        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "broken", Some(r#"{"arch":"x86_64"}"#)).await;

        let result = dispatch.check_assigned_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "permanently invalid chain must terminate the assignment (None), not re-dispatch"
        );

        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "failed");
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
                .bind(assignment_id)
                .fetch_optional(store.pool())
                .await
                .unwrap();
        assert!(status.is_none(), "worker_task row must be deleted");
    }

    #[tokio::test]
    async fn redelivery_hydration_failure_leaves_running_assignment_untouched() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "fedora", Some("not valid json")).await;

        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE id = $1")
            .bind(assignment_id)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();

        let result = dispatch.redeliver_running_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "redelivery must skip this round (Ok(None)) on hydration failure"
        );

        let record = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "building");

        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM worker_tasks WHERE id = $1")
                .bind(assignment_id)
                .fetch_optional(store.pool())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("running"));
    }

    #[tokio::test]
    async fn notify_workers_notifies_target_and_keeps_others() {
        let (_dispatch, app, _store, _tmp) = setup_dispatch().await;

        let target_notify = Arc::new(tokio::sync::Notify::new());
        let other_notify = Arc::new(tokio::sync::Notify::new());
        {
            let mut waiters = app.worker_waiters.lock().await;
            waiters.push((1, "x86_64".into(), target_notify.clone()));
            waiters.push((2, "aarch64".into(), other_notify.clone()));
        }

        notify_workers(&app, Some(1)).await;

        timeout(Duration::from_millis(100), target_notify.notified())
            .await
            .expect("target waiter should be notified");

        {
            let waiters = app.worker_waiters.lock().await;
            assert!(
                waiters.iter().any(|(id, _, _)| *id == 2),
                "other waiter should remain in list"
            );
        }

        assert!(
            timeout(Duration::from_millis(100), other_notify.notified())
                .await
                .is_err(),
            "other waiter should not be notified"
        );
    }
}
