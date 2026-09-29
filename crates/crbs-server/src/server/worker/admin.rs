// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker secret 管理 / 删除的共享核心：UI 表单与 REST API 两条路径共用，行为、
//! 审计与日志一致；成功操作统一在此写审计（fire-and-forget）与 info 日志，调用方勿重复记录。

use crbs_core::auth::secret::{Secret, SecretHash, SecretKind};
use crbs_core::StateStore;

use crate::server::error::ApiError;

/// Worker 管理操作错误（UI 侧映射 flash 消息，API 侧经 into_api_error 映射 `ApiError`）。
pub(crate) enum WorkerAdminError {
    /// 目标 worker 不存在（携带 worker id）。
    NotFound(i64),
    /// 删除在线 worker 的状态冲突（携带 worker 名）。最终文案由消费端组装：
    /// API 拼 JSON 原文案，UI 走双语模板，故用结构化变体不共用英文字面量。
    WorkerOnline(String),
    /// 存储层 / 随机数生成失败，message 带操作名上下文。
    Internal(String),
}

impl WorkerAdminError {
    /// 映射为 API 错误：Internal 详情只进日志，响应返回通用安全消息（不外泄 DB 细节）。
    pub(crate) fn into_api_error(self) -> ApiError {
        match self {
            Self::NotFound(id) => ApiError::not_found("worker", id),
            Self::WorkerOnline(name) => ApiError::Conflict(format!(
                "worker '{}' is online; revoke secret or wait for it to go offline before removing",
                name
            )),
            Self::Internal(msg) => ApiError::log_and_internal(msg),
        }
    }
}

/// init arch 门禁的冲突事实（API 拼 JSON 原文案，UI 走双语模板）。
pub(crate) struct InitArchMismatch {
    pub worker_arch: String,
    pub arches: Vec<String>,
}

/// Worker init 的 arch 门禁：worker arch 不在产品声明 arches 内时，init 只会
/// 产出无人可领取的任务。resolve 失败保持 fail-open（偏好是调度优化，不是
/// 安全裁决）；HTTP 与 UI 两个入口必须共用本函数。
pub(crate) async fn ensure_init_arch_compatible(
    app: &crate::server::state::AppState,
    worker_id: i64,
    worker_arch: &str,
    product: &str,
) -> Result<(), InitArchMismatch> {
    match app.state_store.resolve_any_product_by_name(product).await {
        Ok(resolved)
            if !resolved.config.arches.is_empty()
                && !resolved.config.arches.iter().any(|a| a == worker_arch) =>
        {
            Err(InitArchMismatch {
                worker_arch: worker_arch.to_string(),
                arches: resolved.config.arches.clone(),
            })
        }
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!(
                product,
                worker_id = %worker_id,
                error = %e,
                "Failed to resolve product config for init arch check; skipping arch gate"
            );
            Ok(())
        }
    }
}

/// 轮换 worker secret：生成新 secret 写入 hash，返回明文（仅此一次可见）。
pub(crate) async fn rotate_secret(
    store: &StateStore,
    actor: &str,
    role: &str,
    worker_id: i64,
) -> Result<String, WorkerAdminError> {
    let worker = store
        .get_worker(worker_id)
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("get worker: {e}")))?
        .ok_or(WorkerAdminError::NotFound(worker_id))?;
    let secret = Secret::generate(SecretKind::WorkerSecret)
        .map_err(|e| WorkerAdminError::Internal(format!("generate worker secret: {e}")))?;
    let hash = SecretHash::from_plain(secret.as_str());
    store
        .set_worker_secret(worker_id, hash.as_str())
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("set worker secret: {e}")))?;
    let _ = store
        .audit_log(
            actor,
            role,
            "rotate_worker_secret",
            Some(&worker_id.to_string()),
            None,
        )
        .await;
    tracing::info!(
        user = %actor,
        worker_id = %worker_id,
        worker_name = %worker.name,
        "Worker secret rotated"
    );
    Ok(secret.as_str().to_string())
}

/// 撤销 worker secret：清除后 worker 立即无法认证。
pub(crate) async fn revoke_secret(
    store: &StateStore,
    actor: &str,
    role: &str,
    worker_id: i64,
) -> Result<(), WorkerAdminError> {
    let worker = store
        .get_worker(worker_id)
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("get worker: {e}")))?
        .ok_or(WorkerAdminError::NotFound(worker_id))?;
    store
        .clear_worker_secret(worker_id)
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("clear worker secret: {e}")))?;
    let _ = store
        .audit_log(
            actor,
            role,
            "revoke_worker_secret",
            Some(&worker_id.to_string()),
            None,
        )
        .await;
    tracing::info!(
        user = %actor,
        worker_id = %worker_id,
        worker_name = %worker.name,
        "Worker secret revoked"
    );
    Ok(())
}

/// 删除 worker（在线时拒绝），返回 worker 名供调用方展示。
/// 不存在返回 `NotFound`，在线返回 `WorkerOnline`；状态检查与删除同一事务（`delete_worker_if_offline`）收口 TOCTOU。
pub(crate) async fn remove_worker(
    store: &StateStore,
    actor: &str,
    role: &str,
    worker_id: i64,
) -> Result<String, WorkerAdminError> {
    let worker = store
        .get_worker(worker_id)
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("get worker: {e}")))?
        .ok_or(WorkerAdminError::NotFound(worker_id))?;
    // 原子 status 检查 + 删除。
    use crbs_core::DeleteWorkerOutcome;
    match store
        .delete_worker_if_offline(worker_id)
        .await
        .map_err(|e| WorkerAdminError::Internal(format!("delete worker: {e}")))?
    {
        DeleteWorkerOutcome::NotFound => {
            // 与上面 get_worker 不一致说明并发删除，视同成功。
            Ok(worker.name)
        }
        DeleteWorkerOutcome::Online => Err(WorkerAdminError::WorkerOnline(worker.name)),
        DeleteWorkerOutcome::Deleted => {
            let _ = store
                .audit_log(
                    actor,
                    role,
                    "delete_worker",
                    Some(&worker_id.to_string()),
                    None,
                )
                .await;
            tracing::info!(
                user = %actor,
                worker_id = %worker_id,
                worker_name = %worker.name,
                "Worker removed"
            );
            Ok(worker.name)
        }
    }
}
