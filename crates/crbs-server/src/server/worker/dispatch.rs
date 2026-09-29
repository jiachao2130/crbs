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
    /// 远程重建 base_os（管理型 assignment）。
    #[serde(rename = "init")]
    Init,
}

/// 分发给 Worker 的任务。
#[derive(Debug, Clone)]
pub struct AssignedTask {
    pub assignment_id: i64,
    pub task_id: Option<i64>,
    pub build_id: i64,
    pub product: String,
    pub srpm_url: String,
    pub build_options: serde_json::Value,
    pub product_config: String,
    /// reproduce 模式下来源 build 的 build_packages.json 签名 URL；非 reproduce 为 `None`。
    pub reproduce_packages_url: Option<String>,
    pub kind: AssignmentKind,
    /// init 模式下要重建的产品名；build 模式为 None。
    pub init_product: Option<String>,
    /// 产品 repo 是否注入本次构建（消费轴生效值，读提交时快照的
    /// builds.repo_consume；与发布轴 repo_publish 脱钩）。true → worker 推导
    /// `{cfg.hub_url}/repo/{product}/{arch}` 注入 chroot；false → worker 不注入。
    /// 空 repo + `skip_if_unavailable=1` = 无害 no-op。
    pub product_repo_enabled: bool,
}

/// Worker 任务分发器。
pub struct WorkerDispatch {
    app: Arc<AppState>,
    /// 重投递轮转游标（worker_id → 下次优先的序号）：capacity>1 时逐个轮转，
    /// 避免每轮都重发最旧 assignment、其余丢失响应的 assignment 饿死。
    redelivery_cursor: std::sync::Mutex<std::collections::HashMap<i64, usize>>,
}

/// [`WorkerDispatch::hydrate_build_assignment`] 的错误处置策略（按调用路径分流）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HydrationErrorPolicy {
    /// 首次领取（`check_assigned_task`）：水合失败 = 不可执行成立，保持
    /// fail-closed（fail/release 交调度器收敛）。
    Claim,
    /// 响应丢失重投递（`redeliver_running_task`）：只 warn + 本轮跳过，绝不
    /// release/fail 在执行的 assignment（稳态命中是常态，理由见其文档注释）。
    Redelivery,
}

/// 重投递水合失败日志：带上下文 warn 一条，不做任何 DB 写（语义见 Redelivery）。
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
    pub async fn wait_for_task(
        &self,
        worker_id: i64,
        worker_arch: &str,
        wait_secs: u64,
    ) -> Option<AssignedTask> {
        // 先检查是否有已分配给该 Worker 的任务（DB 错误 warn 而非静默 204）
        match self.check_assigned_task(worker_id, worker_arch).await {
            Ok(Some(task)) => return Some(task),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(worker_id = %worker_id, error = %e, "poll: check assigned task failed")
            }
        }

        let notify = Arc::new(Notify::new());

        // Drop 守卫移除等待项：断连时 axum 丢弃 future 提前返回，泄漏的
        // (id, arch, notify) 会被 notify_workers 吞掉唤醒，活着的 waiter 退化
        // 等满超时。顺序必须先显式移除、再 disarm（守卫只兜恰落移除 await 点的取消/断连）。
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
                // Drop 可能在 runtime 之外（shutdown 卸载后丢弃 future）：裸
                // tokio::spawn 会 panic-in-drop 带崩进程。
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(async move {
                            let mut waiting = app.worker_waiters.lock().await;
                            // 只移除本请求自己的 waiter：同 worker 的新连接
                            // （旧请求断连后立即重连）不能被误删。
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

        // 注册后立刻复查，关闭"检查-注册"竞态窗口（此刻分配+notify 可直接取到）。
        if let Ok(Some(task)) = self.check_assigned_task(worker_id, worker_arch).await {
            {
                let mut waiting = self.app.worker_waiters.lock().await;
                waiting.retain(|(id, _, _)| *id != worker_id);
            }
            waiter_guard.armed = false;
            return Some(task);
        }

        // Notify 不缓存通知："注册后二次检查"与 `notified()` 首次 poll 之间
        // 到达的通知被静默丢弃，超时分支必须重查库兜底（否则拾取延迟到下轮轮询）。
        let _ = timeout(Duration::from_secs(wait_secs), notify.notified()).await;

        // 从等待列表移除（同步精确），移除完成后才 disarm（顺序见守卫注释）。
        {
            let mut waiting = self.app.worker_waiters.lock().await;
            waiting.retain(|(id, _, _)| *id != worker_id);
        }
        waiter_guard.armed = false;

        // 无论收到通知还是超时，都重查一次已分配任务，关闭通知丢失窗口。
        if let Ok(Some(task)) = self.check_assigned_task(worker_id, worker_arch).await {
            return Some(task);
        }

        None
    }

    /// 检查是否有已分配给该 Worker 的任务；arch 不匹配（非空）→ warn + `None`。
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
                // init：下发产品配置，worker 执行 init(force=true)。Fail-closed：
                // init 无 pending 队列可退回，解析错误一律标失败，管理端可见后重触发。
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
                            // 补偿失败仅 warn：不掩盖根因。
                            tracing::warn!(
                                assignment_id = %assignment_id,
                                error = %err,
                                "Failed to mark init assignment as failed after NotInDb"
                            );
                        }
                        return Ok(None);
                    }
                    // 坏链配置同 NotInDb 处置（init 无队列可退回）：标失败，管理端可见。
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
                            // 补偿失败仅 warn：不掩盖根因。
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
                            // 补偿失败仅 warn：不掩盖根因。
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
                    // init 不构建，不注入产品 repo。
                    product_repo_enabled: false,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// poll 响应丢失重投递：wait 到期且无新任务时，查该 worker 名下"running 且
    /// build building"的 assignment，按正常领取同款水合重新下发（见 [`Self::hydrate_build_assignment`]）。
    ///
    /// 不重置 running 回 pending（复刻双执行）、不做送达确认协议（worker 侧以取消注册表去重）。
    ///
    /// 水合失败只 warn + 本轮跳过（见 [`HydrationErrorPolicy::Redelivery`]）：
    /// 驱动查询在执行期每 poll 周期命中（稳态非异常），失败只代表本轮响应
    /// 无法构造——release 删行重派复刻双执行、fail 钉死健康执行；真正消失的
    /// assignment 由 JOIN 条件自然排除，下一轮 poll 自然重试。
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
        // capacity>1 轮转：每次 poll 从不同序号起步，worker 端按取消注册表
        // 去重已在执行的 assignment，下一轮即可收到其余丢失响应的任务。
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
            // debug 而非 info：稳态命中（执行期每 poll 一条）是常态，info 刷屏。
            tracing::debug!(
                worker_id = %worker_id,
                assignment_id = %t.assignment_id,
                build_id = %t.build_id,
                "worker still holds running assignment; redelivery payload sent (deduped by worker if already executing)"
            );
        }
        Ok(task)
    }

    /// 把一条 build assignment 的 DB 字段水合成可下发的 [`AssignedTask`]；正常
    /// 领取与重投递共用（字段集与语义零漂移），SRPM token 与 reproduce URL
    /// 在此签发。错误按 `policy` 分流：Claim fail-closed——request_json NULL
    /// （行未就绪）或 arch 不匹配 → release 回队列；解析失败 / NotInDb /
    /// 永久配置错误 → fail_assignment，瞬时错误 → release；Redelivery 一律 warn + 本轮跳过（不写 DB）。
    async fn hydrate_build_assignment(
        &self,
        worker_id: i64,
        worker_arch: &str,
        info: crbs_core::AssignedTaskInfo,
        policy: HydrationErrorPolicy,
    ) -> crbs_core::Result<Option<AssignedTask>> {
        // 两调用方只传 Build 变体（init 走独立臂、重投递查询排除 init）；
        // Init 到达属调用方错误，按无任务返回而非 panic。
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
        // 防御纵深：NULL 只来自绕过选点就绪谓词的老行。分流：NULL = 行未就绪
        // 临时态（start_build 到 set_build_request_info 落库的窗口），Claim 下
        // release 回 pending 即可重派；解析失败 = 永久数据损坏，Claim 下
        // fail_assignment。Redelivery 一致 warn + 跳过（绝不动 running 行）。
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
                        // 补偿失败仅 warn：不掩盖根因。
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
                    // 重投递稳态：只跳过本轮，绝不动 running 行（见 Redelivery）。
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
                        // 补偿失败仅 warn：不掩盖根因。
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

        // 防御性校验：调度器已按 arch 匹配，此处兜 DB/调度器异常，防执行错误
        // 架构；noarch 收敛构建任意 worker 可领（领取谓词放行），不参与比对。
        let build_arch = build_options
            .get("arch")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !build_arch.is_empty() && build_arch != "noarch" && build_arch != worker_arch {
            // 重投递稳态：只跳过本轮（如 worker 重注册换 arch，原执行仍在跑）。
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

        // 生成带签名的 SRPM 下载 token（10 分钟有效期，server 重启不失效）
        let token = self.app.srpm_token_signer.generate(build_id);

        let srpm_url = format!("/api/v1/builds/{}/srpm-download?token={}", build_id, token);

        // reproduce：build_options 带 reproduce_from_build_id 时额外签发来源
        // build 的 build_packages.json URL（token 必须绑来源 build_id，下载端点 id 即来源）。
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

        // 产品配置锚：构建行已有快照（本地车道建行时写入 / 首次 claim 写入）
        // 直接复用——重投递与构建时配置同源，链配置后续变更不漂移；缺失才
        // 解析链并补写（写失败 warn-only，不阻断派发）。DB 读错误按瞬时错误
        // 分流（claim release / redelivery 跳过本轮）。
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
                // 重投递：一律只跳过本轮——fail 钉死健康执行、release 复刻双执行。
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
                    // 补偿失败仅 warn：不掩盖根因。
                    tracing::warn!(
                        assignment_id = %assignment_id,
                        build_id = %build_id,
                        error = %fail_err,
                        "Failed to mark assignment as failed after NotInDb"
                    );
                }
                return Ok(None);
            }
            // 坏链同 NotInDb 处置：重试不可收敛，终结而非 release 无限空转。
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
                    // 补偿失败仅 warn：不掩盖根因。
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
                    // 补偿失败仅 warn：不掩盖根因。
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

        // 消费轴生效值直读提交时快照列（builds.repo_consume，合流谓词见
        // submit 侧 resolve_repo_axis_flags）：派发零计算，观测与注入同源。
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

    /// 解析产品链配置并把快照写回构建行：后续 claim / 重投递与 `crbs debug`
    /// 都读这份快照；写失败只降级（回落当前配置），不阻断派发。
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

    /// 读取产品配置 TOML（dispatch 热路径，命中缓存零 IO）。错误分类见
    /// [`ProductConfigError`]。恒不返回空串：空串 fallback 会让 Worker 静默
    /// 读磁盘 `products/*.toml`，Server/Worker 配置漂移。
    async fn read_product_config(&self, product: &str) -> Result<String, ProductConfigError> {
        let record = match self.app.state_store.get_product_by_name(product).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ProductConfigError::NotInDb),
            Err(e) => return Err(ProductConfigError::Transient(e.to_string())),
        };
        // 先 chain_resolve 建 cache entry（供 override 日志），再 chain_resolve_to_toml 命中同一 entry 免二次拉取。
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

/// `read_product_config` 的失败分类（调用方据此分流）：`NotInDb` 产品未注册 →
/// fail_assignment 终结；`Permanent` 链配置语义错误（变体见
/// [`classify_chain_error`]）重试不可收敛、只会无限空转 → 同 NotInDb 处置；
/// `Transient` DB/IO/超时/链中行消失（并发删除 vs 损坏含糊，保守）→ release 重试。
#[derive(Debug)]
enum ProductConfigError {
    NotInDb,
    Permanent(String),
    Transient(String),
}

/// 链解析错误分类：四个配置语义变体（坏链结构 / 出口校验失败）→ `Permanent`，
/// 其余一律 `Transient`——NotFound（链中行消失）含糊保守，不进 Permanent。
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

/// 路径 override 透传可见化：机器本地路径覆盖（result_dir 等 6 字段，见下方
/// `path_overrides` 调用）随 TOML 原样下发 worker 生效——同构 NFS 舰队合法，
/// 不剥离；非空时一条聚合 debug，防异构舰队误配时结果位置静默漂移。
/// debug 而非 info：本函数挂在重投递路径上，执行期每 poll 命中，info 刷屏。
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
/// 不移动/移除 waiter。
pub async fn notify_workers(app: &Arc<AppState>, worker_id: Option<i64>) {
    let waiters = app.worker_waiters.lock().await;

    match worker_id {
        Some(id) => {
            // 通知该 Worker 的全部等待者：重连窗口可能短暂并存新旧两个 poll，
            // 只唤醒第一个会让另一个空等到超时。
            for (wid, _, notify) in waiters.iter() {
                if *wid == id {
                    notify.notify_one();
                }
            }
        }
        None => {
            // 广播通知所有等待的 Worker
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

    /// 构造测试底座：临时 StateStore + AppState + WorkerDispatch，
    /// 返回 (dispatch, app, store, tmp)。
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

    /// 种一个已分配给 w1（x86_64）的 build：`request_json` 为 None 保持 NULL
    ///（绕过选点就绪谓词的老行形态），Some 则落库并指向固定 SRPM；
    /// 返回 (worker_id, build_id, assignment_id)。
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

    /// request_json NULL 的 Claim 水合 fail-closed：release 回 pending（行未
    /// 就绪临时态，request info 落库后可正常重派），非 fail_assignment（永久
    /// 损坏才 fail，对照 check_assigned_task_rejects_invalid_request_json）。
    #[tokio::test]
    async fn check_assigned_task_releases_assignment_when_request_json_null() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        // request_json 保持 NULL：绕过选点谓词的老行现场（assign 无就绪谓词可造 assigned 行）。
        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "fedora", None).await;

        let result = dispatch.check_assigned_task(worker_id, "x86_64").await;
        assert!(
            result.is_ok() && result.unwrap().is_none(),
            "NULL request_json assignment must be dropped (None)"
        );

        // release 语义：build 回 pending（非 failed，稍后就绪可重派），wt 行删除。
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

    /// request_json NULL 的重投递水合 fail-soft：本轮跳过（Ok(None)），wt 行
    /// 未被 release、build 未被 fail，与坏 JSON 的重投递处置一致（对照
    /// redelivery_hydration_failure_leaves_running_assignment_untouched）。
    #[tokio::test]
    async fn redelivery_skips_null_request_json_without_touching_running_assignment() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        // request_json 保持 NULL（老行执行期稳态的形态）。
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

    /// 消费轴派发直读列：product_repo_enabled 取提交时快照的 builds.repo_consume
    ///（private 产品 + 列值各组合按列下发布尔，dispatch 零再计算）。
    #[tokio::test]
    async fn check_assigned_task_reads_repo_consume_column() {
        // private 产品（owner_id 非空满足官方产品 CHECK）；config 形态过链出口校验。
        // 列值 1/0 各自独立 store 夹具（同 product+pkg+arch 活跃去重不允许二次领取）。
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

    /// claim 时把链解析结果锚定进 `builds.product_config_toml`：派发载荷与
    /// 落库快照同源，后续 `crbs debug` 读到的即构建时配置。
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

    /// 重投递复用已锚定快照：产品配置在 claim 之后变更，已领取构建的派发
    /// 载荷与快照均保持构建时值（快照只补缺，不覆盖）。
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

        // claim 已把 assignment 置 running、build 置 building，直接重投递。
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

    /// 分类单测：四个链配置语义变体 → Permanent；其余（NotFound 并发删除含糊保守）→ Transient。
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

    /// 坏链产品（root 空 base_packages，裸 SQL 构造）→ dispatch 终结分配而非
    /// release 重派：check_assigned_task 返回 None、build 翻 failed、wt 行删除。
    #[tokio::test]
    async fn check_assigned_task_fails_assignment_on_permanently_invalid_chain() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;

        // 合法 create 过入口校验，再裸 SQL 把 base_packages 抹空 →
        // chain_resolve 出口校验报 ProductChainInvalid（坏链不自愈）。
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

    /// 重投递水合失败 fail-soft：running/building 稳态行 + 坏 request_json →
    /// 本轮跳过（Ok(None)），wt 行仍 running、build 仍 building——重投递查询
    /// 执行期每 poll 命中，失败只说明本轮响应无法构造。claim 对照见
    /// `check_assigned_task_rejects_invalid_request_json`。
    #[tokio::test]
    async fn redelivery_hydration_failure_leaves_running_assignment_untouched() {
        let (dispatch, _app, store, _tmp) = setup_dispatch().await;
        let (worker_id, build_id, assignment_id) =
            seed_assigned_build(&store, "fedora", Some("not valid json")).await;

        // 推进到执行期稳态：running/building（重投递查询每 poll 命中的形态）。
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
        // 未 release：worker_task 行仍是 running（未删除、未回 assigned/pending）。
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
