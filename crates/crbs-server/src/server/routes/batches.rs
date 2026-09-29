// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次 HTTP API（operator+）。
//! - `POST /api/v1/batches`：快速段（校验+建行）同步、慢段（枚举/下载/规划）
//!   后台执行，立即 202；`dry_run=true` 不落库不下载，同步返回增量判定预览。
//! - `GET /api/v1/batches`：分页列表；`GET .../{id}`：详情（UI 复用
//!   [`batch_detail`] 同一聚合）；`POST .../{id}/cancel`：取消。
//! - 失败语义：后台 prepare/plan 失败已由服务内收口为 failed 批次，202 只承诺
//!   “已受理”，终态经查询端点观察。

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{FromRequest, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::server::auth::AuthContext;
use crate::server::batches as service;
use crate::server::error::ApiError;
use crate::server::routes::builds::ensure_can_submit_to_product;
use crate::server::routes::warn_audit_log_failure;
use crate::server::state::AppState;

/// 提交端点 body 上限：请求体仅元数据，超限即客户端异常（dry-run 列表另有响应侧 200 条截断）。
const BATCH_BODY_LIMIT_BYTES: usize = 64 * 1024;

const LIST_MAX_LIMIT: usize = 200;
const LIST_DEFAULT_LIMIT: usize = 50;

/// dry-run 预览的包名列表截断上限（计数仍为全量，防巨响应）。
const DRY_RUN_LIST_CAP: usize = 200;

const FAILURE_BUCKET_CAP: usize = 10;
const FAILURE_SAMPLE_MAX_CHARS: usize = 200;

pub(crate) fn router() -> Router<Arc<AppState>> {
    // 提交端点 body 上限：子 router 挂 DefaultBodyLimit，超限在读 body 的 handler 内折 413。
    let submit = Router::new()
        .route("/api/v1/batches", post(create_batch))
        .layer(axum::extract::DefaultBodyLimit::max(BATCH_BODY_LIMIT_BYTES));
    Router::new()
        .route("/api/v1/batches", get(list_batches))
        .merge(submit)
        .route("/api/v1/batches/{id}", get(get_batch))
        .route("/api/v1/batches/{id}/cancel", post(cancel_batch))
}

#[derive(Debug, Deserialize)]
struct BatchCreateRequest {
    product: String,
    source_repo_url: String,
    #[serde(default)]
    dist: Option<String>,
    #[serde(default)]
    arch_targets: Vec<String>,
    #[serde(default)]
    on_failure: Option<String>,
    #[serde(default)]
    force_all: bool,
    #[serde(default)]
    allow_dist_mismatch: bool,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Serialize)]
struct BatchCreateResponse {
    batch_id: i64,
    status: &'static str,
}

/// dry-run 预览响应（200）：计数全量、列表截断。
#[derive(Serialize)]
struct BatchDryRunResponse {
    dry_run: bool,
    product: String,
    to_build_count: usize,
    to_build: Vec<String>,
    skipped_count: usize,
    skipped: Vec<String>,
    /// 列表截断说明（截断发生时才有意义，恒输出版本口径）。
    note: &'static str,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// 批次摘要行（列表与详情共用的批次面）。
#[derive(Serialize)]
pub(crate) struct BatchSummary {
    pub(crate) id: i64,
    /// 产品名（product_id 已解析；产品行被删时为 "unknown"）。
    pub(crate) product: String,
    pub(crate) status: String,
    pub(crate) total_items: i64,
    pub(crate) n_succeeded: i64,
    pub(crate) n_failed: i64,
    pub(crate) n_skipped: i64,
    pub(crate) n_cancelled: i64,
    pub(crate) created_at: String,
    pub(crate) finished_at: Option<String>,
}

#[derive(Serialize)]
struct BatchListResponse {
    batches: Vec<BatchSummary>,
}

#[derive(Serialize)]
pub(crate) struct RoundSummary {
    pub(crate) round: i64,
    pub(crate) total: usize,
    pub(crate) pending: usize,
    pub(crate) released: usize,
    pub(crate) succeeded: usize,
    pub(crate) failed: usize,
    /// dep_skipped + skipped_conflict + arch_skipped（三种跳过共用口径，与 n_skipped 对齐）。
    pub(crate) skipped: usize,
    pub(crate) cancelled: usize,
}

#[derive(Serialize)]
pub(crate) struct FailureBucket {
    pub(crate) error_code: String,
    pub(crate) count: usize,
    pub(crate) sample: String,
}

/// 项状态计数（响应面；core 的 `BatchProgress` 无 Serialize，逐字段镜像）。
#[derive(Serialize)]
pub(crate) struct ProgressSummary {
    pub(crate) pending: i64,
    pub(crate) released: i64,
    pub(crate) succeeded: i64,
    pub(crate) failed: i64,
    pub(crate) dep_skipped: i64,
    pub(crate) skipped_conflict: i64,
    pub(crate) arch_skipped: i64,
    pub(crate) cancelled: i64,
}

impl From<&crbs_core::BatchProgress> for ProgressSummary {
    fn from(p: &crbs_core::BatchProgress) -> Self {
        ProgressSummary {
            pending: p.pending,
            released: p.released,
            succeeded: p.succeeded,
            failed: p.failed,
            dep_skipped: p.dep_skipped,
            skipped_conflict: p.skipped_conflict,
            arch_skipped: p.arch_skipped,
            cancelled: p.cancelled,
        }
    }
}

/// 详情聚合（API 响应与 UI 详情页共用；summary 展平进响应顶层）。
#[derive(Serialize)]
pub(crate) struct BatchDetail {
    #[serde(flatten)]
    pub(crate) summary: BatchSummary,
    pub(crate) source_repo_url: String,
    pub(crate) dist: Option<String>,
    pub(crate) arch_targets: Option<Vec<String>>,
    pub(crate) on_failure: String,
    pub(crate) force_all: bool,
    pub(crate) notes: Option<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) progress: ProgressSummary,
    pub(crate) rounds: Vec<RoundSummary>,
    pub(crate) failures: Vec<FailureBucket>,
}

#[derive(Serialize)]
struct BatchCancelResponse {
    batch_id: i64,
    status: &'static str,
}

/// operator+ 门禁（GC 的 `can_gc` 同款口径）：匿名放行（auth 关闭的本地开发形态），非 operator/admin → 403。
fn ensure_operator(auth: Option<&AuthContext>) -> Result<(), ApiError> {
    if let Some(ctx) = auth {
        if !ctx.is_operator() {
            return Err(ApiError::PermissionDenied(
                "only operator and admin can manage rebuild batches".into(),
            ));
        }
    }
    Ok(())
}

/// 提交整仓重建批次：手工读 body 透传原始 JSON 落库（request_json 审计），超限折 413。
async fn create_batch(
    State(app): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let auth_ctx = req.extensions().get::<AuthContext>().cloned();
    ensure_operator(auth_ctx.as_ref())?;
    let app_state = app.clone();

    let bytes = match axum::body::Bytes::from_request(req, &app_state).await {
        Ok(b) => b,
        Err(rej) => return Err(map_body_rejection(rej)),
    };
    let body: BatchCreateRequest = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::Validation(format!("parse json: {e}")))?;
    let request_json = String::from_utf8_lossy(&bytes).into_owned();

    // 产品 ACL：与提交构建同口径（operator/匿名恒过，保持 gate 收紧时口径不漂）。
    ensure_can_submit_to_product(
        &app,
        &body.product,
        auth_ctx.as_ref(),
        auth_ctx.as_ref().and_then(|c| c.user_id),
    )
    .await?;

    if body.dry_run {
        return dry_run_response(&app, &body).await;
    }

    // 架构白名单在入口校验（信任边界输入必校验；plan/driver 侧另有复核）。
    for arch in &body.arch_targets {
        crbs_core::validation::validate_arch(arch)
            .map_err(|e| ApiError::Validation(format!("invalid arch in arch_targets: {e}")))?;
    }

    let prepare_req = service::PrepareBatchRequest {
        product: body.product.clone(),
        source_repo_url: body.source_repo_url.clone(),
        dist: body.dist.clone(),
        arch_targets: body.arch_targets.clone(),
        on_failure: body.on_failure.clone().unwrap_or_else(|| "continue".into()),
        force_all: body.force_all,
        allow_dist_mismatch: body.allow_dist_mismatch,
        request_json: Some(request_json),
    };

    // 快速段同步（校验+配额+建行），慢段后台串 prepare → plan；任一失败已由服务内收口为 failed 批次，这里只记日志。
    let (batch_id, dist) = service::validate_and_insert_batch(&app, &prepare_req).await?;
    audit(
        &app,
        auth_ctx.as_ref(),
        "batch_create",
        Some(&batch_id.to_string()),
        &serde_json::json!({
            "product": body.product,
            "source_repo_url": body.source_repo_url,
            "force_all": body.force_all,
            "on_failure": prepare_req.on_failure,
        }),
    )
    .await;

    let bg_app = app.clone();
    tokio::spawn(async move {
        match service::run_prepare_phase(&bg_app, prepare_req, dist, batch_id).await {
            Ok(outcome) => {
                if let Err(e) = service::plan_batch(&bg_app, outcome.batch_id).await {
                    warn!(
                        batch_id = outcome.batch_id,
                        error = ?e,
                        "Background batch plan failed (batch closed as failed)"
                    );
                }
            }
            Err(e) => warn!(
                batch_id = batch_id,
                error = ?e,
                "Background batch prepare failed (batch closed as failed)"
            ),
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!(BatchCreateResponse {
            batch_id,
            status: "preparing",
        })),
    ))
}

/// body 读取拒绝映射：超 64KB → 413；其余（IO 等）→ 400。
fn map_body_rejection(rej: axum::extract::rejection::BytesRejection) -> ApiError {
    use axum::extract::rejection::{BytesRejection, FailedToBufferBody};
    match rej {
        BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_)) => {
            ApiError::PayloadTooLarge(format!(
                "request body exceeds {BATCH_BODY_LIMIT_BYTES} bytes"
            ))
        }
        other => ApiError::Validation(format!("read request body: {other}")),
    }
}

async fn dry_run_response(
    app: &Arc<AppState>,
    body: &BatchCreateRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let (to_build, skipped) =
        service::dry_run_split(app, &body.product, &body.source_repo_url, body.force_all).await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!(BatchDryRunResponse {
            dry_run: true,
            product: body.product.clone(),
            to_build_count: to_build.len(),
            to_build: to_build.into_iter().take(DRY_RUN_LIST_CAP).collect(),
            skipped_count: skipped.len(),
            skipped: skipped.into_iter().take(DRY_RUN_LIST_CAP).collect(),
            note: "package-name level incremental preview; name lists are capped at 200 entries",
        })),
    ))
}

/// 批次列表（id DESC，limit ≤200，offset 窗口平移）。
async fn list_batches(
    State(app): State<Arc<AppState>>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<BatchListResponse>, ApiError> {
    ensure_operator(auth.as_ref().map(|ext| &ext.0))?;
    let limit = q
        .limit
        .unwrap_or(LIST_DEFAULT_LIMIT)
        .clamp(1, LIST_MAX_LIMIT);
    let offset = q.offset.unwrap_or(0).min(LIST_MAX_LIMIT);
    let batches = batch_summaries(&app, limit, offset).await?;
    Ok(Json(BatchListResponse { batches }))
}

/// 摘要页聚合（API 列表与 Web UI 列表页共用）：state 层只支持 limit，offset 用窗口+跳过（≤200 行，代价有界）；产品名逐 id 解析（页内去重）。
pub(crate) async fn batch_summaries(
    app: &Arc<AppState>,
    limit: usize,
    offset: usize,
) -> Result<Vec<BatchSummary>, ApiError> {
    let rows = app
        .state_store
        .list_batches((limit + offset) as i64)
        .await?;
    let page: Vec<crbs_core::BatchRecord> = rows.into_iter().skip(offset).take(limit).collect();
    let names = product_names(app, &page).await;
    Ok(page.iter().map(|b| summary_of(b, &names)).collect())
}

async fn get_batch(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<Json<BatchDetail>, ApiError> {
    ensure_operator(auth.as_ref().map(|ext| &ext.0))?;
    Ok(Json(batch_detail(&app, id).await?))
}

/// 取消在途批次（driver::cancel_batch 幂等：终态批次 409）。
async fn cancel_batch(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<(StatusCode, Json<BatchCancelResponse>), ApiError> {
    let ctx = auth.as_ref().map(|ext| &ext.0);
    ensure_operator(ctx)?;
    service::cancel_batch(&app, id, &ctx.map(|c| c.user.clone()).unwrap_or_default()).await?;
    audit(
        &app,
        ctx,
        "batch_cancel",
        Some(&id.to_string()),
        &serde_json::json!({}),
    )
    .await;
    Ok((
        StatusCode::OK,
        Json(BatchCancelResponse {
            batch_id: id,
            status: "cancelled",
        }),
    ))
}

/// 聚合批次详情（API 与 UI 详情页共用）。
pub(crate) async fn batch_detail(app: &Arc<AppState>, id: i64) -> Result<BatchDetail, ApiError> {
    let store = &app.state_store;
    let batch = store
        .get_batch(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("batch {id} not found")))?;

    let names = product_names(app, std::slice::from_ref(&batch)).await;
    let summary = summary_of(&batch, &names);
    let progress =
        ProgressSummary::from(&store.batch_item_summary(id).await.map_err(ApiError::from)?);

    // 轮次摘要：state 层无按轮聚合查询，整轮取行在 Rust 聚合（行字段小，万级项在详情端点预算内）。
    let mut rounds = Vec::new();
    for round in store.batch_rounds(id).await.map_err(ApiError::from)? {
        let items = store
            .items_in_round(id, round)
            .await
            .map_err(ApiError::from)?;
        let mut rs = RoundSummary {
            round,
            total: items.len(),
            pending: 0,
            released: 0,
            succeeded: 0,
            failed: 0,
            skipped: 0,
            cancelled: 0,
        };
        for item in &items {
            match item.state.as_str() {
                "pending" => rs.pending += 1,
                "released" => rs.released += 1,
                "succeeded" => rs.succeeded += 1,
                "failed" => rs.failed += 1,
                "dep_skipped" | "skipped_conflict" | "arch_skipped" => rs.skipped += 1,
                "cancelled" => rs.cancelled += 1,
                _ => {}
            }
        }
        rounds.push(rs);
    }

    let failed = store
        .items_in_state(id, "failed")
        .await
        .map_err(ApiError::from)?;
    let mut buckets: HashMap<String, (usize, String)> = HashMap::new();
    for item in &failed {
        let code = item.error_code.clone().unwrap_or_else(|| "unknown".into());
        let sample = item.error_message.clone().unwrap_or_default();
        let entry = buckets.entry(code).or_insert((0, sample));
        entry.0 += 1;
    }
    let mut failures: Vec<FailureBucket> = buckets
        .into_iter()
        .map(|(error_code, (count, sample))| FailureBucket {
            error_code,
            count,
            sample: truncate_chars(&sample, FAILURE_SAMPLE_MAX_CHARS),
        })
        .collect();
    failures.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.error_code.cmp(&b.error_code))
    });
    failures.truncate(FAILURE_BUCKET_CAP);

    let arch_targets = batch
        .arch_targets
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok());

    Ok(BatchDetail {
        summary,
        source_repo_url: batch.source_repo_url,
        dist: batch.dist,
        arch_targets,
        on_failure: batch.on_failure,
        force_all: batch.force_all,
        notes: batch.notes,
        started_at: batch.started_at,
        progress,
        rounds,
        failures,
    })
}

fn summary_of(batch: &crbs_core::BatchRecord, names: &HashMap<i64, String>) -> BatchSummary {
    BatchSummary {
        id: batch.id,
        product: batch
            .product_id
            .and_then(|id| names.get(&id).cloned())
            .unwrap_or_else(|| "unknown".into()),
        status: batch.status.clone(),
        total_items: batch.total_items,
        n_succeeded: batch.n_succeeded,
        n_failed: batch.n_failed,
        n_skipped: batch.n_skipped,
        n_cancelled: batch.n_cancelled,
        created_at: batch.created_at.clone(),
        finished_at: batch.finished_at.clone(),
    }
}

/// 批次集的产品名解析表（去重后逐 id 查询；产品行被删时缺席 → unknown）。
async fn product_names(
    app: &Arc<AppState>,
    batches: &[crbs_core::BatchRecord],
) -> HashMap<i64, String> {
    let mut names = HashMap::new();
    for id in batches.iter().filter_map(|b| b.product_id) {
        if names.contains_key(&id) {
            continue;
        }
        match app.state_store.get_product_by_id(id).await {
            Ok(Some(p)) => {
                names.insert(id, p.name);
            }
            Ok(None) => {}
            Err(e) => warn!(product_id = id, error = %e, "Resolve batch product name failed"),
        }
    }
    names
}

/// 审计写入（失败仅 warn，不逆转已生效的操作；匿名形态无审计主体，跳过）。
async fn audit(
    app: &Arc<AppState>,
    ctx: Option<&AuthContext>,
    action: &str,
    target: Option<&str>,
    detail: &serde_json::Value,
) {
    let Some(ctx) = ctx else { return };
    if let Err(e) = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            action,
            target,
            Some(&detail.to_string()),
        )
        .await
    {
        warn_audit_log_failure(&e, "audit_log");
    }
}

/// 按字符截断（UTF-8 边界安全）。
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_is_utf8_safe() {
        let long = "失".repeat(300);
        assert_eq!(truncate_chars(&long, 200).chars().count(), 200);
        assert_eq!(truncate_chars("short", 200), "short");
    }

    #[test]
    fn batch_create_request_defaults() {
        let req: BatchCreateRequest =
            serde_json::from_str(r#"{"product":"p","source_repo_url":"https://r"}"#).unwrap();
        assert_eq!(req.arch_targets, Vec::<String>::new());
        assert!(!req.force_all && !req.allow_dist_mismatch && !req.dry_run);
        assert_eq!(req.on_failure.as_deref(), None);
    }
}
