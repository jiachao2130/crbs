// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 页面 handler。

use super::{
    abs_time_or_dash, child_build_counts, format_duration_secs, package_link, rel_time_lang,
};
use crate::server::auth::visibility::{
    compute_visible_products, ensure_product_visible_for_record,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::tasks::{
    cancel_task_for_user, list_tasks_with_counts_for_user_with_visible, rebuild_task_for_user,
    reproduce_task_for_user, ListQuery as TaskListQuery,
};
use crate::server::routes::ui::components::{
    arch_matrix, artifact_table, artifact_tree_script, back_link, cancel_button,
    changelog_header_link, clickable_rows_script, count_chip, danger_row, detail_grid, empty_state,
    error_flash_location, filter_chips, filter_form, generate_nonce, id_link, list_page_head,
    notify_button, page_with_csp, pagination_links, phase_badge_with_class, phase_chips,
    phase_status, rebuild_button, reproduce_button, see_other_redirect, side_card, side_kv,
    status_message, task_sse_script, user_cell, FilterFormParams, PaginationParams, StatusQuery,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, matrix_summary_pattern, phase_option_label, t, t_fmt, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::page_size::page_size_from_headers;
use crate::server::routes::ui::service::{
    check_public_access, csrf_token_for_request, normalize_phase_filter, page_size_or_default,
    require_cancel_session, with_back_param, CancelForm, QueryParams,
};
use crate::server::state::AppState;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use crbs_core::types::build_phase_is_terminal;
use maud::{html, Markup};
use std::sync::Arc;

pub(crate) async fn cancel_task_submit(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let _session = require_cancel_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form,
        &app.csrf_key,
    )?;

    let result = cancel_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await;
    // flash 文案按页面语言本地化：服务层消息是 API 信封共用字面量（不动），映射只在 handler 侧。
    let lang = lang_from_headers(&headers);
    let location = match result {
        Ok(outcome) => {
            if outcome.cancelled_build_ids.is_empty() && !outcome.skipped_build_ids.is_empty() {
                // 源是拼好的字符串、无变体可 match，按 outcome 结构字段二分后直接取 key。
                let msg = if outcome.failed_build_ids.is_empty() {
                    t(lang, TextKey::FlashCancelNoCancellable).to_string()
                } else {
                    t_fmt(
                        lang,
                        FmtKey::FlashCancelPartial,
                        &[
                            &outcome.cancelled_build_ids.len().to_string(),
                            &outcome.failed_build_ids.len().to_string(),
                        ],
                    )
                };
                error_flash_location(&format!("/ui/tasks/{}", id), &msg, &app.csrf_key)
            } else {
                format!("/ui/tasks/{}?status=cancelled", id)
            }
        }
        Err(ref e) => error_flash_location(
            &format!("/ui/tasks/{}", id),
            &cancel_task_error_flash(e, id, lang),
            &app.csrf_key,
        ),
    };

    see_other_redirect(&location)
}

/// task 取消失败（[`cancel_task_for_user`] 的错误）→ 按页面语言本地化的
/// flash 文案（形态照 gc_error_flash）：稳定字面量精确匹配，其余回退英文
/// 原文；`database error` 族绝不映射（CLI remote.rs 精确匹配 exit 6）。
fn cancel_task_error_flash(e: &ApiError, task_id: i64, lang: Lang) -> String {
    match e {
        ApiError::NotFound(msg) if msg == &format!("task {task_id} not found") => {
            t_fmt(lang, FmtKey::FlashTaskNotFound, &[&task_id.to_string()])
        }
        ApiError::PermissionDenied(msg) => match msg.as_str() {
            "you do not have permission to cancel this task" => {
                t(lang, TextKey::FlashCancelTaskPermission).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::Conflict(msg) => match msg.as_str() {
            "task_already_terminal" => t(lang, TextKey::FlashCancelTaskTerminal).to_string(),
            "task state changed during cancel; retry" => {
                t(lang, TextKey::FlashCancelTaskStateChanged).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::Internal(msg) => match msg.as_str() {
            "failed to get child builds" => {
                t(lang, TextKey::FlashCancelGetChildrenFailed).to_string()
            }
            "failed to cancel task without child builds" => {
                t(lang, TextKey::FlashCancelEmptyTaskFailed).to_string()
            }
            _ => msg.clone(),
        },
        other => other.message().to_string(),
    }
}

/// Rebuild 表单提交：复用 cancel 的 session+CSRF 校验，成功后跳转新 task 详情页。
pub(crate) async fn rebuild_task_submit(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let _session = require_cancel_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form,
        &app.csrf_key,
    )?;

    let result = rebuild_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await;
    let lang = lang_from_headers(&headers);
    let location = match result {
        Ok(resp) => format!("/ui/tasks/{}?status=rebuilt", resp.task_id),
        Err(ref e) => error_flash_location(
            &format!("/ui/tasks/{}", id),
            &replay_task_error_flash(e, id, lang),
            &app.csrf_key,
        ),
    };

    see_other_redirect(&location)
}

/// Reproduce 表单提交：复用 cancel 的 session+CSRF 校验，成功后跳转新 task 详情页。
pub(crate) async fn reproduce_task_submit(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let _session = require_cancel_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form,
        &app.csrf_key,
    )?;

    let result = reproduce_task_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await;
    let lang = lang_from_headers(&headers);
    let location = match result {
        Ok(resp) => format!("/ui/tasks/{}?status=reproduced", resp.task_id),
        Err(ref e) => error_flash_location(
            &format!("/ui/tasks/{}", id),
            &replay_task_error_flash(e, id, lang),
            &app.csrf_key,
        ),
    };

    see_other_redirect(&location)
}

/// 重放失败（[`rebuild_task_for_user`] / [`reproduce_task_for_user`] 两路共用）
/// → 按页面语言本地化的 flash 文案（形态照 gc_error_flash）：只映射固定
/// 字面量族，带参族前缀 `task {id} ` 已知、尾部按固定锚点拆参，其余（动态
/// 拼接/自由文本消息、`database error` 族——CLI remote.rs 精确匹配 exit 6）
/// 回退英文原文；rebuild 与 reproduce 同族文案有措辞差异，逐条保真不合并。
fn replay_task_error_flash(e: &ApiError, task_id: i64, lang: Lang) -> String {
    let id_str = task_id.to_string();
    let task_prefix = format!("task {task_id} ");
    match e {
        ApiError::PermissionDenied(msg) => match msg.as_str() {
            "you do not have permission to rebuild this task" => {
                t(lang, TextKey::FlashRebuildPermission).to_string()
            }
            "you do not have permission to reproduce this task" => {
                t(lang, TextKey::FlashReproducePermission).to_string()
            }
            "only operator or admin can set priority=2 (critical)" => {
                t(lang, TextKey::FlashReplayPriorityOperatorOnly).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::Validation(msg) => match msg.as_str() {
            "priority must be 0 (default), 1 (high), or 2 (critical)" => {
                t(lang, TextKey::FlashReplayPriorityRange).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::NotFound(msg) => {
            if msg == &format!("task {task_id} not found") {
                t_fmt(lang, FmtKey::FlashTaskNotFound, &[&id_str])
            } else if msg == &format!("task rebuild info {task_id} not found") {
                t_fmt(lang, FmtKey::FlashReplayInfoNotFound, &[&id_str])
            } else if let Some(name) = msg
                .strip_prefix("product ")
                .and_then(|s| s.strip_suffix(" not found"))
            {
                t_fmt(lang, FmtKey::FlashProductNotFound, &[name])
            } else {
                msg.clone()
            }
        }
        ApiError::Conflict(msg) => match msg.as_str() {
            "source srpms no longer available (results may have been GC'd); cannot rebuild" => {
                t(lang, TextKey::FlashReplaySourceGcRebuild).to_string()
            }
            "source srpms no longer available (results may have been GC'd); cannot reproduce" => {
                t(lang, TextKey::FlashReplaySourceGcReproduce).to_string()
            }
            "task has no recorded build options; cannot rebuild" => {
                t(lang, TextKey::FlashReplayNoOptionsRebuild).to_string()
            }
            "task has no recorded build options; cannot reproduce" => {
                t(lang, TextKey::FlashReplayNoOptionsReproduce).to_string()
            }
            "no reproducible child builds (none recorded build_packages.json); enable reproduce_enabled and rebuild first" => {
                t(lang, TextKey::FlashReplayNoReproducibleChildren).to_string()
            }
            other => {
                // 带参族：尾部按固定锚点拆参，拆不中（动态拼接明细等）回退原文。
                if let Some(rest) = other.strip_prefix(&task_prefix) {
                    if rest == "has no child builds; cannot reproduce" {
                        return t_fmt(lang, FmtKey::FlashReplayNoChildBuilds, &[&id_str]);
                    }
                    if let Some(n) = rest
                        .strip_prefix("is still in progress (child build ")
                        .and_then(|s| s.strip_suffix(")"))
                    {
                        return t_fmt(lang, FmtKey::FlashReplayStillInProgress, &[&id_str, n]);
                    }
                    if let Some((n, tail)) = rest
                        .strip_prefix("child build ")
                        .and_then(|s| s.split_once(" has status '"))
                    {
                        if let Some(phase) =
                            tail.strip_suffix("' (only succeeded builds can be reproduced)")
                        {
                            return t_fmt(
                                lang,
                                FmtKey::FlashReplayChildNotSucceeded,
                                &[&id_str, n, phase],
                            );
                        }
                    }
                }
                other.to_string()
            }
        },
        other => other.message().to_string(),
    }
}

pub(crate) async fn list_tasks_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<TaskListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    // form 未填字段以空串传回（?phase=）→ 统一归 None：防 `phase = ''` 误过滤、
    // 保 All 选项回显；phase 另过白名单归一（未知值按未过滤）。
    let q = TaskListQuery {
        product: q.product.filter(|v| !v.is_empty()),
        name: q.name.filter(|v| !v.is_empty()),
        label: q.label.filter(|v| !v.is_empty()),
        phase: normalize_phase_filter(q.phase.as_deref()).map(str::to_string),
        ..q
    };
    // 标签过滤语法在入口收口（与 API 同源）：缺 `=` / 键非法按 400 错误页返回。
    let label_filter = match q.label.as_deref() {
        Some(raw) => Some(
            crbs_core::validation::parse_task_label_arg(raw)
                .map_err(|e| ApiError::Validation(e.to_string()))?,
        ),
        None => None,
    };
    // ?limit= query > crbs_page_size cookie > 默认 50。
    let limit = page_size_or_default(q.limit.or(page_size_from_headers(&headers)));
    let offset = q
        .offset
        .unwrap_or(0)
        .min(crate::server::validation::MAX_LIST_OFFSET);
    let filter = crbs_core::types::TaskListFilter {
        product: q.product.as_deref(),
        phase: q.phase.as_deref(),
        name: q.name.as_deref(),
        label: label_filter.clone(),
        limit: Some(limit),
        offset: Some(offset),
        order_by: q.sort.as_deref(),
        ..Default::default()
    };
    // 可见产品白名单只算一次：列表数据与 phase chips 共用。
    let visible = compute_visible_products(&app, auth.as_ref().map(|ext| &ext.0)).await?;
    let resp = list_tasks_with_counts_for_user_with_visible(&app, filter, visible.clone()).await?;
    let nonce = generate_nonce()?;
    // 样板页约定：可见文案走 t()/t_fmt()；表单 name/value 等机器面值不译。
    let lang = lang_from_headers(&headers);
    // 分页链接与详情链接 back 参数共用的过滤参数集；含当前 offset 即地址栏 URL。
    let page_query = QueryParams {
        product: q.product.as_deref(),
        name: q.name.as_deref(),
        label: q.label.as_deref(),
        phase: q.phase.as_deref(),
        sort: q.sort.as_deref(),
        ..Default::default()
    };
    let current_list = page_query.url("/ui/tasks", Some(offset));
    // 相位 chips 计数与列表同口径（product/name 一致、phase 除外），可见性共用上方 visible。
    let phase_counts = app
        .state_store
        .count_tasks_by_phase_scoped(
            visible.as_deref(),
            q.product.as_deref(),
            q.name.as_deref(),
            label_filter.as_ref().map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .await
        .map_err(ApiError::from)?;
    // All chip 计数 = 去 phase 过滤后 counts 求和，非含 phase 过滤的列表 total。
    let chips_total: i64 = phase_counts.iter().map(|&(_, c)| c).sum();
    // chip URL：以当前过滤集为基线替换/移除 phase、offset 归零。
    let chips_url = |phase: Option<&str>| -> String {
        QueryParams {
            phase,
            ..page_query.clone()
        }
        .url("/ui/tasks", None)
    };
    let chips = phase_chips(
        lang,
        q.phase.as_deref(),
        chips_total.max(0) as usize,
        &phase_counts,
        &chips_url,
    );
    // 激活过滤 chips（sort 不做 chip）：label 用表单字段标签同款文案，phase 走显示名。
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(product) = q.product.as_deref() {
        let remove = QueryParams {
            product: None,
            ..page_query.clone()
        }
        .url("/ui/tasks", None);
        active_chips.push((
            t(lang, TextKey::ThProduct).to_string(),
            product.to_string(),
            remove,
        ));
    }
    if let Some(name) = q.name.as_deref() {
        let remove = QueryParams {
            name: None,
            ..page_query.clone()
        }
        .url("/ui/tasks", None);
        active_chips.push((
            t(lang, TextKey::ThPackage).to_string(),
            name.to_string(),
            remove,
        ));
    }
    if let Some(raw) = q.label.as_deref() {
        let remove = QueryParams {
            label: None,
            ..page_query.clone()
        }
        .url("/ui/tasks", None);
        active_chips.push((
            t(lang, TextKey::LabelTaskLabels).to_string(),
            raw.to_string(),
            remove,
        ));
    }
    if let Some(phase) = q.phase.as_deref() {
        let remove = QueryParams {
            phase: None,
            ..page_query.clone()
        }
        .url("/ui/tasks", None);
        active_chips.push((
            t(lang, TextKey::ThPhase).to_string(),
            phase_option_label(lang, phase).to_string(),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    let toolbar = filter_form(FilterFormParams {
        base_path: "/ui/tasks",
        product: q.product.as_deref(),
        name: q.name.as_deref(),
        label: q.label.as_deref(),
        phase: q.phase.as_deref(),
        arch: None,
        priority: None,
        sort: Some(q.sort.as_deref().unwrap_or("id_desc")),
        chips: active_chips,
        lang,
    });
    // builder+ 显示提交入口（与 /ui/tasks/new 页门禁一致）。
    let can_submit = auth.as_ref().is_some_and(|ext| ext.0.can_submit());
    let head_actions = if can_submit {
        html! { a class="action-button" href="/ui/tasks/new" { (t(lang, TextKey::TaskNewAction)) } }
    } else {
        html! {}
    };
    let body = html! {
        // 页头：h1 = 导航名 + 总数 chip；meta 传空，主操作保留。
        (list_page_head(
            html! { (t(lang, TextKey::NavTasks)) " " (count_chip(resp.total)) },
            html! {},
            head_actions,
        ))
        (chips)
        @if resp.tasks.is_empty() {
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyTasksTitle), t(lang, TextKey::EmptyTasksHint)))
        } @else {
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    // 列宽：Package 吃剩余宽度并截断，Builds 列不截断。
                    colgroup {
                        col style="width:7%" {}
                        col style="width:11%" {}
                        col style="width:auto" {}
                        col style="width:11%" {}
                        col style="width:14%" {}
                        col style="width:12%" {}
                        col style="width:13%" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::ThProduct)) }
                            th { (t(lang, TextKey::ThPackage)) }
                            th { (t(lang, TextKey::ThPhase)) }
                            th { (t(lang, TextKey::NavBuilds)) }
                            th { (t(lang, TextKey::ThUser)) }
                            th class="num" { (t(lang, TextKey::ThSubmitted)) }
                        }
                    }
                    tbody {
                        @for t in &resp.tasks {
                            tr class="clickable-row" {
                                // #123 形态 mono 链接（row-target 契约保留）。
                                td { (id_link(with_back_param(&format!("/ui/tasks/{}", t.task.id), &current_list), t.task.id)) }
                                td { a href=(QueryParams { product: Some(&t.task.product), name: q.name.as_deref(), label: q.label.as_deref(), phase: q.phase.as_deref(), sort: q.sort.as_deref(), ..Default::default() }.url("/ui/tasks", None)) { (t.task.product) } }
                                td class="ellipsis" title=(t.task.pkg_label()) { (package_link(&t.task.pkg_label(), &t.task.name)) }
                                td { a href=(QueryParams { product: q.product.as_deref(), name: q.name.as_deref(), label: q.label.as_deref(), phase: Some(&t.task.phase), sort: q.sort.as_deref(), ..Default::default() }.url("/ui/tasks", None)) { (phase_status(&t.task.phase, lang)) } }
                                td { (child_build_counts(t.task.id, &t.build_counts, lang)) }
                                td { (user_cell(&t.task.user)) }
                                td class="num" { (rel_time_lang(t.task.submitted_at.as_deref(), lang)) }
                            }
                        }
                    }
                }
                (pagination_links(
                    &PaginationParams {
                        base_path: "/ui/tasks",
                        total: resp.total,
                        limit,
                        offset,
                        lang,
                        query: page_query,
                        raw_filter_qs: None,
                        csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),
                    },
                ))
            }
        }
        (clickable_rows_script(&nonce))
    };
    page_with_csp(
        t(lang, TextKey::NavTasks),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "tasks",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// task 详情页每个 arch 的产物行（来自 `build_artifacts` 表）。
type ArchArtifacts = (String, i64, Vec<crbs_core::Artifact>);

pub(crate) async fn task_detail_page(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let task = app
        .state_store
        .get_task(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("task", id))?;
    // 产品可见性与 API 同口径（防匿名凭 ID 查看 private 产品任务）；孤儿产品按公开处理。
    ensure_product_visible_for_record(&app, &task.product, auth.as_ref().map(|ext| &ext.0)).await?;
    let builds = app
        .state_store
        .get_child_build_summaries(id)
        .await
        .map_err(|e| {
            tracing::warn!(task_id = %id, error = %e, "Failed to get child build summaries for UI");
            ApiError::Internal("failed to get child build summaries".into())
        })?;
    let lineage = app.state_store.task_lineage(id).await.map_err(|e| {
        tracing::warn!(task_id = %id, error = %e, "Failed to get task lineage for UI");
        ApiError::Internal("failed to get task lineage".into())
    })?;
    let labels = app
        .state_store
        .get_task_labels(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("query task labels", e))?;
    // 批量查 build_artifacts 表（消除 N+1）。
    let build_ids: Vec<i64> = builds.iter().map(|b| b.id).collect();
    let all_artifacts = app
        .state_store
        .list_artifacts_for_builds(&build_ids)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(task_id = %id, error = %e, "Failed to batch-load artifacts from DB");
            Vec::new()
        });
    // 按 build_id 分组并过滤 Metadata/Script（与 load_artifacts_from_db 口径一致）。
    use crbs_core::ArtifactKind;
    let mut artifacts_map: std::collections::HashMap<i64, Vec<crbs_core::Artifact>> =
        std::collections::HashMap::new();
    for a in all_artifacts {
        if matches!(a.kind, ArtifactKind::Metadata | ArtifactKind::Script) {
            continue;
        }
        artifacts_map.entry(a.build_id).or_default().push(a);
    }
    let mut artifacts_by_arch: Vec<ArchArtifacts> = Vec::new();
    for b in &builds {
        if let Some(rows) = artifacts_map.remove(&b.id) {
            if !rows.is_empty() {
                artifacts_by_arch.push((b.arch.clone(), b.id, rows));
            }
        }
    }
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let is_terminal = build_phase_is_terminal(&task.phase);
    let show_cancel = auth
        .as_ref()
        .is_some_and(|ext| !is_terminal && ext.0.can_cancel(&task.user))
        && csrf_token.is_some();
    // Rebuild 权限与 cancel 对齐（原提交者或 operator/admin），不限 phase（终态任务也可重放）。
    let show_rebuild = auth
        .as_ref()
        .is_some_and(|ext| ext.0.can_cancel(&task.user))
        && csrf_token.is_some();
    // Reproduce 条件：有权限 + ≥1 个子构建在 hub 留有 build_packages.json（部分可复现
    // 即可），只查存在性不查 cache；布局 {task_id}/{arch}/{build_id}/。
    let show_reproduce = show_rebuild && {
        let result_root = app.result_dir_for_or_default(&task.product).await;
        let mut any = false;
        for b in &builds {
            let arch = b.arch.as_str();
            if !arch.is_empty() {
                let p = result_root
                    .join(id.to_string())
                    .join(arch)
                    .join(b.id.to_string())
                    .join("build_packages.json");
                if p.exists() {
                    any = true;
                    break;
                }
            }
        }
        any
    };
    let nonce = generate_nonce()?;
    // task 详情页自身 URL：作为子构建链接的 back 目标（task→build→back 回本页）。
    let task_url = format!("/ui/tasks/{id}");
    let lang = lang_from_headers(&headers);

    // 矩阵聚合摘要：「N 架构 · X 成功 · Y 失败」一行，矩阵本体仍全量。
    let arch_total = builds.len();
    let succeeded_count = builds.iter().filter(|b| b.phase == "succeeded").count();
    let failed_count = builds.iter().filter(|b| b.phase == "failed").count();

    let details_rows: Vec<(Markup, Markup)> = {
        let mut rows = Vec::new();
        if task.pkg_names.len() > 1 {
            let pkg_list: Vec<Markup> = task
                .pkg_names
                .iter()
                .map(|nvr| {
                    html! { li { (package_link(nvr, crbs_core::util::split_nvr(nvr).0)) } }
                })
                .collect();
            rows.push((
                html! { (t(lang, TextKey::LabelPackages)) },
                html! {
                    (t_fmt(lang, FmtKey::PackagesCount, &[&task.pkg_names.len().to_string()]))
                    ul { @for li_m in pkg_list { (li_m) } }
                },
            ));
        } else {
            rows.push((
                html! { (t(lang, TextKey::ThPackage)) },
                html! { (package_link(&task.pkg_name, &task.name)) },
            ));
        }
        // Duration 人类可读；Submitted/Completed 保持绝对时间（审计口径）。
        rows.push((
            html! { (t(lang, TextKey::ThSubmitted)) },
            html! { code { (abs_time_or_dash(task.submitted_at.as_deref())) } },
        ));
        rows.push((
            html! { (t(lang, TextKey::LabelDuration)) },
            html! {
                @match task.duration {
                    Some(secs) => (format_duration_secs(secs)),
                    None => "—",
                }
            },
        ));
        rows.push((
            html! { (t(lang, TextKey::LabelCompleted)) },
            html! { code { (abs_time_or_dash(task.completed_at.as_deref())) } },
        ));
        if let Some(src) = lineage.replay_source.as_ref() {
            rows.push((
                html! { (t(lang, TextKey::LabelReplaySource)) },
                html! {
                    a href=(format!("/ui/tasks/{}", src.task_id)) { (format!("task {}", src.task_id)) }
                    span class="sep" { "·" }
                    (format!("build {}", src.build_id))
                },
            ));
        }
        if !lineage.replays.is_empty() {
            rows.push((
                html! { (t(lang, TextKey::LabelReplays)) },
                html! {
                    @for (i, r) in lineage.replays.iter().enumerate() {
                        @if i > 0 { span class="sep" { "·" } }
                        a href=(format!("/ui/tasks/{}", r.task_id)) { (format!("task {}", r.task_id)) }
                        " "
                        (phase_badge_with_class(&r.phase, "phase-badge", lang))
                    }
                },
            ));
        }
        rows
    };

    let body = html! {
        // 页头条带（crumb + h1 + meta）；无 Rebuild/Reproduce 权限且终态时整个操作组省略。
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToTasks), "/ui/tasks", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 {
                    (t_fmt(lang, FmtKey::TaskTitle, &[&id.to_string()]))
                    // aria-live：SSE 脚本会改写徽章文本/类名，live region 让屏幕
                    // 阅读器播报 phase 变化（契约见 style.css 头注）。
                    span aria-live="polite" { (phase_badge_with_class(&task.phase, "phase-badge", lang)) }
                    // 终态页 SSE 只推一次终态即关流，脉冲灯会永久停留 → 终态不渲染。
                    @if !is_terminal {
                        span class="live-indicator" title=(t(lang, TextKey::LiveUpdatesEnabled)) { }
                    }
                }
                div class="page-meta" {
                    (task.product)
                    span class="sep" { "·" }
                    (task.user)
                    @if let Some(submitted) = task.submitted_at.as_deref() {
                        span class="sep" { "·" }
                        (rel_time_lang(Some(submitted), lang))
                    }
                    // 关键数字：该提交的构建数（与聚合摘要同口径）。
                    @if !builds.is_empty() {
                        span class="sep" { "·" }
                        (t_fmt(lang, FmtKey::MetaBuildsCount, &[&builds.len().to_string()]))
                    }
                    @if let Some(src) = lineage.replay_source.as_ref() {
                        span class="sep" { "·" }
                        a href=(format!("/ui/tasks/{}", src.task_id)) {
                            (t_fmt(lang, FmtKey::MetaReplayedFrom, &[&format!("{}", src.task_id)]))
                        }
                    }
                    @if !lineage.replays.is_empty() {
                        span class="sep" { "·" }
                        (t_fmt(lang, FmtKey::MetaReplayCount, &[&lineage.replays.len().to_string()]))
                    }
                }
                (task_label_pills(&labels))
            }
            // 通知按钮不门控（纯前端），匿名/无权限 live 页也有操作组；终态页省略整组。
            @if show_rebuild || show_reproduce || !is_terminal {
                div class="header-actions" {
                    @if show_rebuild {
                        (rebuild_button(
                            &format!("/ui/tasks/{}/rebuild", id),
                            csrf_token.as_deref(),
                            t(lang, TextKey::ConfirmRebuildTask),
                            lang,
                        ))
                    }
                    @if show_reproduce {
                        (reproduce_button(
                            &format!("/ui/tasks/{}/reproduce", id),
                            csrf_token.as_deref(),
                            t(lang, TextKey::ConfirmReproduceTask),
                            lang,
                        ))
                    }
                    @if !is_terminal {
                        (notify_button(&nonce, lang, &task.pkg_label()))
                    }
                }
            }
        }
        (status_message(&q, &app.csrf_key, lang))
        // 双栏：主列 = arch_matrix（cell 的 data-build-id / aria-live SSE 契约不动）
        // + artifacts；侧栏 = Details + Danger zone（红边卡沉底）。
        (detail_grid(
            html! {
                div class="admin-section" {
                    h2 { (t(lang, TextKey::ChildBuilds)) }
                    @if !builds.is_empty() {
                        // data-pattern = 带参模板原文（i18n/fmt.rs 单一真源）：
                        // sse_script.rs updateChildren 内联整句重算聚合行，
                        // 防矩阵实时翻转而聚合行停在 SSR 值（failed 仅计 failed）。
                        p class="matrix-summary" data-pattern=(matrix_summary_pattern(lang)) {
                            (t_fmt(
                                lang,
                                FmtKey::MatrixSummary,
                                &[
                                    &arch_total.to_string(),
                                    &succeeded_count.to_string(),
                                    &failed_count.to_string(),
                                ],
                            ))
                        }
                    }
                    (arch_matrix(&builds, Some(&task_url), lang))
                }
                @if !artifacts_by_arch.is_empty() {
                    div class="admin-section" {
                        h2 {
                            (t(lang, TextKey::ArtifactsTitle))
                            // task 作用域 changelog 入口：共享卡头恰一个链接（URL
                            // 任务作用域、不逐 arch 重复）；条件 = 任一 arch 产物行含 rpm/srpm。
                            @if artifacts_by_arch.iter().any(|(_, _, rows)| rows.iter().any(|a| matches!(a.kind, ArtifactKind::Rpm | ArtifactKind::Srpm))) {
                                (changelog_header_link(&format!("/ui/tasks/{id}/changelog"), lang))
                            }
                        }
                        @for (arch, build_id, rows) in &artifacts_by_arch {
                            h3 { (arch) }
                            (artifact_table(*build_id, rows, lang))
                        }
                    }
                }
            },
            html! {
                (side_card("", t(lang, TextKey::SideDetailsTitle), side_kv(&details_rows)))
                @if show_cancel {
                    (side_card(
                        "danger-zone",
                        t(lang, TextKey::DangerZoneTitle),
                        html! {
                            (danger_row(
                                t(lang, TextKey::ButtonCancel),
                                t(lang, TextKey::DangerCancelTaskDesc),
                                cancel_button(
                                    &task_url,
                                    csrf_token.as_deref(),
                                    t(lang, TextKey::ConfirmCancelTask),
                                    lang,
                                ),
                            ))
                        },
                    ))
                }
            },
        ))
        (task_sse_script(id, &nonce, lang))
        (artifact_tree_script(&nonce))
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::TaskTitle, &[&id.to_string()]),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "tasks",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 任务标签 pill 行（详情页标题区）：key（mono 主色）与 value 两段式；
/// 每个 pill 链到同标签过滤的任务列表。空列表不渲染容器。
fn task_label_pills(labels: &[(String, String)]) -> Markup {
    let items: Vec<(&str, &str, String)> = labels
        .iter()
        .map(|(key, value)| {
            let raw = format!("{key}={value}");
            let url = QueryParams {
                label: Some(&raw),
                ..Default::default()
            }
            .url("/ui/tasks", None);
            (key.as_str(), value.as_str(), url)
        })
        .collect();
    if items.is_empty() {
        return html! {};
    }
    html! {
        div class="task-labels" {
            @for (key, value, url) in &items {
                a class="task-label" href=(url) title=(format!("{key}={value}")) {
                    span class="task-label-key" { (key) }
                    span class="task-label-value" { (value) }
                }
            }
        }
    }
}
