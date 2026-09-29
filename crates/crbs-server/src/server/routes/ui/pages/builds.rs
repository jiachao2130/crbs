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

use super::{format_duration_secs, package_link, rel_time_lang, rel_time_text_lang};
use crate::server::auth::visibility::compute_visible_products;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::service as builds_service;
use crate::server::routes::builds::ListQuery as BuildListQuery;
use crate::server::routes::logs::build_phase_is_terminal;
use crate::server::routes::ui::components::{
    artifact_table, artifact_tree_script, attribution_badge, back_link, build_sse_script,
    cancel_button, changelog_header_link, clickable_rows_script, count_chip, danger_row,
    detail_grid, empty_state, error_flash_location, filter_chips, filter_form, format_local_time,
    generate_nonce, id_link, list_page_head, log_line_anchor_script, log_sse_script, notify_button,
    page_with_csp, pagination_links, parent_task_block, pending_log_sse_script,
    phase_badge_with_class, phase_chips, phase_status, phase_timeline, see_other_redirect,
    side_card, side_kv, srpm_download_href, status_message, user_cell, FilterFormParams,
    PaginationParams, StatusQuery,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, phase_option_label, priority_label, t, t_fmt, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::page_size::page_size_from_headers;
use crate::server::routes::ui::service::{
    check_public_access, csrf_token_for_request, load_artifacts_from_db, normalize_phase_filter,
    page_size_or_default, phase_timeline_spans, read_log_full_or_truncated, read_log_preview,
    require_cancel_session, with_back_param, CancelForm, QueryParams, UI_LOG_INLINE_MAX_BYTES,
};
use crate::server::state::AppState;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use crbs_core::types::{BuildPriority, PRIORITY_CRITICAL, PRIORITY_DEFAULT};
use maud::{html, Markup};
use std::sync::Arc;

/// Builds 列表页查询参数：API `ListQuery` 超集，额外含 `priority`（纯 UI 过滤，
/// API 契约不含）。`priority` 以字符串接收：GET 表单把未选中（"All"）的 select
/// 以空串回传，空串反序列化成数字会让 serde_urlencoded 拒绝整个 Query → 400。
#[derive(serde::Deserialize, Default)]
pub(crate) struct UiBuildListQuery {
    pub product: Option<String>,
    pub phase: Option<String>,
    pub name: Option<String>,
    pub arch: Option<String>,
    pub task_id: Option<i64>,
    pub sort: Option<String>,
    pub priority: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// 空串（"All" 选中）与非法值（非数字 / 越界 0..=2）一律视为未过滤，不 400——下拉只产生合法值。
fn parse_priority_filter(raw: Option<&str>) -> Option<BuildPriority> {
    let s = raw?.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<BuildPriority>()
        .ok()
        .filter(|p| (PRIORITY_DEFAULT..=PRIORITY_CRITICAL).contains(p))
}

pub(crate) async fn list_builds_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<UiBuildListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let q = UiBuildListQuery {
        product: q.product.filter(|v| !v.is_empty()),
        name: q.name.filter(|v| !v.is_empty()),
        phase: normalize_phase_filter(q.phase.as_deref()).map(str::to_string),
        arch: q.arch.filter(|v| !v.is_empty()),
        ..q
    };
    let priority_filter = parse_priority_filter(q.priority.as_deref());
    let limit = page_size_or_default(q.limit.or(page_size_from_headers(&headers)));
    let offset = q
        .offset
        .unwrap_or(0)
        .min(crate::server::validation::MAX_LIST_OFFSET);
    let api_q = BuildListQuery {
        product: q.product.clone(),
        phase: q.phase.clone(),
        name: q.name.clone(),
        arch: q.arch.clone(),
        task_id: q.task_id,
        srpm_sha256: None,
        sort: q.sort.clone(),
        limit: Some(limit),
        offset: Some(offset),
    };
    let visible = compute_visible_products(&app, auth.as_ref().map(|ext| &ext.0)).await?;
    let resp = builds_service::list_builds_for_user_with_visible(
        &app,
        &api_q,
        priority_filter,
        visible.clone(),
    )
    .await?;
    let nonce = generate_nonce()?;
    let priority_sel = priority_filter.map(|p| p.to_string());
    let page_query = QueryParams {
        product: q.product.as_deref(),
        name: q.name.as_deref(),
        label: None,
        nvr: None,
        phase: q.phase.as_deref(),
        arch: q.arch.as_deref(),
        priority: priority_sel.as_deref(),
        task_id: q.task_id,
        sort: q.sort.as_deref(),
    };
    let current_list = page_query.url("/ui/builds", Some(offset));
    let lang = lang_from_headers(&headers);
    let phase_counts = app
        .state_store
        .count_builds_by_phase_scoped(
            visible.as_deref(),
            q.product.as_deref(),
            q.name.as_deref(),
            q.arch.as_deref(),
        )
        .await
        .map_err(ApiError::from)?;
    let chips_total: i64 = phase_counts.iter().map(|&(_, c)| c).sum();
    let chips_url = |phase: Option<&str>| -> String {
        QueryParams {
            phase,
            ..page_query.clone()
        }
        .url("/ui/builds", None)
    };
    let chips = phase_chips(
        lang,
        q.phase.as_deref(),
        chips_total.max(0) as usize,
        &phase_counts,
        &chips_url,
    );
    let attributions: std::collections::HashMap<
        i64,
        crate::server::scheduler::planner::RejectAttribution,
    > = resp
        .builds
        .iter()
        .filter(|b| b.phase == "pending")
        .filter_map(|b| app.dispatch_attribution.get(b.id).map(|a| (b.id, a)))
        .collect();
    let watermarks = crate::server::scheduler::AdmitWatermarks::from_config(&app.server_config);
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(product) = q.product.as_deref() {
        let remove = QueryParams {
            product: None,
            ..page_query.clone()
        }
        .url("/ui/builds", None);
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
        .url("/ui/builds", None);
        active_chips.push((
            t(lang, TextKey::ThPackage).to_string(),
            name.to_string(),
            remove,
        ));
    }
    if let Some(phase) = q.phase.as_deref() {
        let remove = QueryParams {
            phase: None,
            ..page_query.clone()
        }
        .url("/ui/builds", None);
        active_chips.push((
            t(lang, TextKey::ThPhase).to_string(),
            phase_option_label(lang, phase).to_string(),
            remove,
        ));
    }
    if let Some(arch) = q.arch.as_deref() {
        let remove = QueryParams {
            arch: None,
            ..page_query.clone()
        }
        .url("/ui/builds", None);
        active_chips.push((
            t(lang, TextKey::FilterArch).to_string(),
            arch.to_string(),
            remove,
        ));
    }
    if let Some(priority) = priority_filter {
        let remove = QueryParams {
            priority: None,
            ..page_query.clone()
        }
        .url("/ui/builds", None);
        active_chips.push((
            t(lang, TextKey::FilterPriority).to_string(),
            priority_label(lang, priority),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    let toolbar = filter_form(FilterFormParams {
        base_path: "/ui/builds",
        product: q.product.as_deref(),
        name: q.name.as_deref(),
        label: None,
        phase: q.phase.as_deref(),
        arch: Some(q.arch.as_deref().unwrap_or("")),
        priority: priority_sel.as_deref(),
        sort: Some(q.sort.as_deref().unwrap_or("id_desc")),
        chips: active_chips,
        lang,
    });
    let body = html! {
        (list_page_head(
            html! { (t(lang, TextKey::NavBuilds)) " " (count_chip(resp.total)) },
            html! {},
            html! {},
        ))
        @if q.task_id.is_none() {
            (chips)
        }
        @if resp.builds.is_empty() {
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyBuildsTitle), t(lang, TextKey::EmptyBuildsHint)))
        } @else {
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    colgroup {
                        col style="width:7%" {}
                        col style="width:7%" {}
                        col style="width:10%" {}
                        col style="width:auto" {}
                        col style="width:10%" {}
                        col style="width:9%" {}
                        col style="width:8%" {}
                        col style="width:11%" {}
                        col style="width:11%" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::LabelTask)) }
                            th { (t(lang, TextKey::ThProduct)) }
                            th { (t(lang, TextKey::ThPackage)) }
                            th { (t(lang, TextKey::ThPhase)) }
                            th { (t(lang, TextKey::FilterPriority)) }
                            th { (t(lang, TextKey::FilterArch)) }
                            th { (t(lang, TextKey::ThUser)) }
                            th class="num" { (t(lang, TextKey::ThStarted)) }
                        }
                    }
                    tbody {
                        @for b in &resp.builds {
                            tr class="clickable-row" {
                                td { (id_link(with_back_param(&format!("/ui/builds/{}", b.id), &current_list), b.id)) }
                                td {
                                    @if let Some(task_id) = b.task_id {
                                        a class="id-link" href=(with_back_param(&format!("/ui/tasks/{}", task_id), &current_list)) { "#" (task_id) }
                                    } @else {
                                        "—"
                                    }
                                }
                                td { a href=(QueryParams { product: Some(&b.product), name: q.name.as_deref(), label: None, nvr: None, phase: q.phase.as_deref(), arch: q.arch.as_deref(), priority: priority_sel.as_deref(), task_id: q.task_id, sort: q.sort.as_deref() }.url("/ui/builds", None)) { (b.product) } }
                                td class="ellipsis" title=(b.pkg_name) { (package_link(&b.pkg_name, &b.name)) }
                                td {
                                    a href=(QueryParams { product: q.product.as_deref(), name: q.name.as_deref(), label: None, nvr: None, phase: Some(&b.phase), arch: q.arch.as_deref(), priority: priority_sel.as_deref(), task_id: q.task_id, sort: q.sort.as_deref() }.url("/ui/builds", None)) { (phase_status(&b.phase, lang)) }
                                    @if let Some(a) = attributions.get(&b.id) {
                                        (attribution_badge(a.reason, a.first_watermark_reject_at, a.watermark_effective_load, watermarks, lang))
                                    }
                                }
                                td { (priority_label(lang, b.priority)) }
                                td { (b.arch.as_deref().filter(|a| !a.is_empty()).unwrap_or("—")) }
                                td { (user_cell(&b.user)) }
                                td class="num" { (rel_time_lang(b.started_at.as_deref(), lang)) }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/builds",
                    lang,
                    total: resp.total,
                    limit,
                    offset,
                    query: page_query,
                    raw_filter_qs: None,

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),                }))
            }
        }
        (clickable_rows_script(&nonce))
    };
    page_with_csp(
        t(lang, TextKey::NavBuilds),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "builds",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// Lifecycle 认领段 warn 阈值（秒）：Dispatched→Claimed 超 60s 视为 worker
/// 认领迟滞（健康信号），值转 warn 色；排队段是容量现象，永不告警色。
const LIFECYCLE_PICKUP_WARN_SECS: i64 = 60;

/// 双轴生效值标注行（提交时快照）：publish = 产物进 repo 候选集、consume =
/// builddep 注入产品 repo；unpublish 只翻 publish 臂。
fn repo_axis_row(record: &crbs_core::BuildRecord, lang: Lang) -> (Markup, Markup) {
    let mark = |on: bool| if on { "✓" } else { "✗" };
    (
        html! { (t(lang, TextKey::LabelRepo)) },
        html! {
            span {
                "publish " (mark(record.repo_publish)) " · consume " (mark(record.repo_consume))
            }
        },
    )
}

/// KB 量 → 人类可读（二进制单位；规则惯例同 workers 页 mem_total_text——
/// 内存与磁盘 KB 同纲，req_min_disk 与 worker disk_free 可直读比较）。
/// None / 非正值 → None（整行不渲染）。
fn kb_text(kb: Option<i64>) -> Option<String> {
    kb.filter(|v| *v > 0)
        .map(|v| humansize::format_size(v as u64 * 1024, humansize::BINARY))
}

/// 字节 → 人类可读（十进制单位；口径惯例同产物表 size 列）。
/// None / 负值 → None（整行不渲染）。
fn bytes_text(bytes: Option<i64>) -> Option<String> {
    bytes
        .filter(|v| *v >= 0)
        .map(|v| humansize::format_size(v as u64, humansize::DECIMAL))
}

/// 资源卡渲染条件：任一资源字段非 NULL。老构建 / 未采集全 NULL 整卡不渲染，
/// 对既有页面零打扰；`oom_killed = Some(false)`（proc 口径显式无 OOM）也算
/// 有数据——采样口径 chip 仍有信息量。
fn has_resource_data(r: &crbs_core::BuildRecord) -> bool {
    r.peak_rss_kb.is_some()
        || r.peak_total_kb.is_some()
        || r.peak_tmpfs_kb.is_some()
        || r.cpu_secs.is_some()
        || r.cpu_p90_cores.is_some()
        || r.disk_wbytes.is_some()
        || r.oom_killed.is_some()
        || r.sample_backend.is_some()
        || r.sample_ncpu.is_some()
        || r.req_min_mem_kb.is_some()
        || r.req_min_ncpu.is_some()
        || r.req_min_disk_kb.is_some()
}

/// 放置需求声明值：只拼非 NULL 维（tokens "mem/ncpu/disk ≥" 语言中立，
/// 同 "{ratio:.1}×" 先例），维间 " · " 分隔。
fn req_min_value(r: &crbs_core::BuildRecord) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(v) = kb_text(r.req_min_mem_kb) {
        parts.push(format!("mem ≥ {v}"));
    }
    if let Some(v) = r.req_min_ncpu {
        parts.push(format!("ncpu ≥ {v}"));
    }
    if let Some(v) = kb_text(r.req_min_disk_kb) {
        parts.push(format!("disk ≥ {v}"));
    }
    (!parts.is_empty()).then_some(parts.join(" · "))
}

/// 资源卡主列标记：h2 = 标题 + OOM 警示徽章 + 采样口径 chip（backend 值 +
/// "@nC" 核数旁注），kv 行集 = 实测峰值 / 包络峰值 / tmpfs 峰值 / CPU 时间 /
/// CPU p90 / 磁盘写入 / 放置需求。`None` = 整卡不渲染（全 NULL，见
/// [`has_resource_data`]）。转义全部走 maud（值皆数字格式化或列 CHECK 收敛
/// 的枚举文本，无注入面）。
fn build_resource_section(r: &crbs_core::BuildRecord, lang: Lang) -> Option<Markup> {
    if !has_resource_data(r) {
        return None;
    }
    let mut rows: Vec<(Markup, Markup)> = Vec::new();
    if let Some(v) = kb_text(r.peak_rss_kb) {
        rows.push((html! { (t(lang, TextKey::ResPeakMem)) }, html! { (v) }));
    }
    if let Some(v) = kb_text(r.peak_total_kb) {
        rows.push((
            html! { (t(lang, TextKey::ResPeakTotal)) },
            html! {
                (v)
                span class="telemetry-extra" { (t(lang, TextKey::ResPeakTotalNote)) }
            },
        ));
    }
    if let Some(v) = kb_text(r.peak_tmpfs_kb) {
        rows.push((html! { (t(lang, TextKey::ResTmpfsPeak)) }, html! { (v) }));
    }
    if let Some(secs) = r.cpu_secs.map(|s| s.round() as i64) {
        rows.push((
            html! { (t(lang, TextKey::ResCpuTime)) },
            html! { (format_duration_secs(secs.max(0))) },
        ));
    }
    if let Some(v) = r.cpu_p90_cores {
        rows.push((
            html! { (t(lang, TextKey::ResCpuP90)) },
            html! { (format!("{v:.1}")) },
        ));
    }
    if let Some(v) = bytes_text(r.disk_wbytes) {
        rows.push((html! { (t(lang, TextKey::ResDiskWrite)) }, html! { (v) }));
    }
    if let Some(v) = req_min_value(r) {
        rows.push((html! { (t(lang, TextKey::ResReqLabel)) }, html! { (v) }));
    }
    let oom_badge = r.oom_killed.unwrap_or(false).then(|| {
        html! {
            span class="badge failure" title=(t(lang, TextKey::ResOomTitle)) { (t(lang, TextKey::ResOomBadge)) }
        }
    });
    let sampling_chip = r.sample_backend.as_deref().map(|backend| {
        html! {
            span class="badge" title=(t(lang, TextKey::ResSamplingLabel)) { (backend) }
            @if let Some(n) = r.sample_ncpu.filter(|n| *n > 0) {
                span class="telemetry-extra" { "@" (n) "C" }
            }
        }
    });
    Some(html! {
        div class="admin-section" {
            h2 {
                (t(lang, TextKey::BuildResourcesTitle))
                @if let Some(b) = oom_badge { (b) }
                @if let Some(c) = sampling_chip { (c) }
            }
            (side_kv(&rows))
        }
    })
}

/// 两 DB 时刻差（秒，end-start，负差按 0）；任一端缺失 / 不可解析 → None。
fn lc_gap_secs(start: Option<&str>, end: Option<&str>) -> Option<i64> {
    let s = start.and_then(crbs_core::util::parse_db_time)?;
    let e = end.and_then(crbs_core::util::parse_db_time)?;
    Some((e.and_utc() - s.and_utc()).num_seconds().max(0))
}

/// 两 DB 时刻差的定格时长文本；缺口不可计（端点缺失/坏帧）→ "—"。
fn lc_gap_text(start: Option<&str>, end: Option<&str>) -> String {
    lc_gap_secs(start, end)
        .map(format_duration_secs)
        .unwrap_or_else(|| "—".to_string())
}

/// Lifecycle"至今"活值 span：data-ts 承载起点（DB 原文）、data-tpl 承载 i18n
/// 模板原文（{0} 占位时长，同 task 页 .matrix-summary[data-pattern] 先例），
/// 初始文本服务端算好，build 页 SSE 脚本 10s ticker（lcWalk）走秒重渲。
fn lc_so_far(start: &str, tpl: FmtKey, lang: Lang) -> Markup {
    let secs = match crbs_core::util::parse_db_time(start) {
        Some(t) => (chrono::Utc::now() - t.and_utc()).num_seconds(),
        None => 0,
    };
    html! {
        span class="lc-so-far" data-ts=(start) data-tpl=(t_fmt(lang, tpl, &["{0}"])) {
            (t_fmt(lang, tpl, &[&format_duration_secs(secs.max(0))]))
        }
    }
}

/// Lifecycle 行集（并入 Details 卡，三段间隙语义，数据全来自
/// [`crbs_core::BuildLifecycle`]
/// 四时刻）：Queued = Submitted→Dispatched（排队等待，容量现象）、
/// Picked up = Dispatched→Claimed（认领耗时，worker 健康信号，超阈值
/// warn 色 + 附执行 worker 链接）、Ran = Claimed→Finished（构建本体时长），
/// Finished 行保留绝对+相对时间。缺阶段形态：
/// - 无 assigned_at（pending）：只渲染 Queued，值按"至今"走秒（活状态，
///   派发后 SSE/刷新接管后续阶段）；
/// - 有 assigned_at 无 started_at：Queued 定格时长 + 派发绝对时刻（code mono）
///   + Picked up 等待中；
/// - 有 started_at 无 completed_at（running）：Ran 按"至今"走秒；
/// - 全有：三段定格时长 + Finished。
fn lifecycle_rows(lc: &crbs_core::BuildLifecycle, lang: Lang) -> Vec<(Markup, Markup)> {
    let mut rows: Vec<(Markup, Markup)> = Vec::new();

    let queued: Markup = match lc.assigned_at.as_deref() {
        None => match lc
            .submitted_at
            .as_deref()
            .filter(|s| crbs_core::util::parse_db_time(s).is_some())
        {
            Some(s) => lc_so_far(s, FmtKey::LifecycleQueuedSoFar, lang),
            None => html! { "—" },
        },
        Some(assigned) => {
            html! {
                (lc_gap_text(lc.submitted_at.as_deref(), Some(assigned)))
                " · "
                code { (format_local_time(assigned)) }
            }
        }
    };
    rows.push((html! { (t(lang, TextKey::LifecycleQueued)) }, queued));

    if let Some(assigned) = lc.assigned_at.as_deref() {
        let started = lc.started_at.as_deref();
        let pickup: Markup = match started {
            None => html! { (t(lang, TextKey::LifecyclePickupWaiting)) },
            Some(started) => {
                let dur = match lc_gap_secs(Some(assigned), Some(started)) {
                    Some(v) => {
                        let text = t_fmt(
                            lang,
                            FmtKey::LifecyclePickupDur,
                            &[&format_duration_secs(v)],
                        );
                        if v > LIFECYCLE_PICKUP_WARN_SECS {
                            html! { span class="lc-warn" { (text) } }
                        } else {
                            html! { (text) }
                        }
                    }
                    None => html! { "—" },
                };
                match (
                    lc.worker_id,
                    lc.worker_name.as_deref().filter(|n| !n.is_empty()),
                ) {
                    (Some(wid), Some(name)) => html! {
                        (dur) " "
                        a class="id-link" href=(format!("/ui/workers/{wid}")) { (name) }
                    },
                    _ => dur,
                }
            }
        };
        rows.push((html! { (t(lang, TextKey::LifecyclePickedUp)) }, pickup));

        if let Some(s) = started.filter(|s| crbs_core::util::parse_db_time(s).is_some()) {
            let ran: Markup = match lc.completed_at.as_deref() {
                None => lc_so_far(s, FmtKey::LifecycleRanSoFar, lang),
                Some(done) => html! { (lc_gap_text(Some(s), Some(done))) },
            };
            rows.push((html! { (t(lang, TextKey::LifecycleRan)) }, ran));
        }
    }

    if let Some(done) = lc
        .completed_at
        .as_deref()
        .filter(|s| !s.is_empty() && *s != "-")
    {
        rows.push((
            html! { (t(lang, TextKey::LabelCompleted)) },
            html! {
                code { (format_local_time(done)) }
                " · "
                (rel_time_text_lang(Some(done), lang))
            },
        ));
    }
    rows
}

pub(crate) async fn build_detail_page(
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
    let record =
        builds_service::fetch_build_with_rpms(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let artifacts = load_artifacts_from_db(&app, id).await?;

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let is_terminal = build_phase_is_terminal(&record.phase);
    let attribution = if record.phase == "pending" {
        app.dispatch_attribution.get(record.id)
    } else {
        None
    };
    let watermarks = crate::server::scheduler::AdmitWatermarks::from_config(&app.server_config);
    let show_cancel = auth
        .as_ref()
        .is_some_and(|ext| !is_terminal && ext.0.can_cancel(&record.user))
        && csrf_token.is_some();

    let spans = phase_timeline_spans(&app, &record).await;

    let artifact_count = artifacts.len();

    let show_changelog_link = artifacts.iter().any(|a| {
        matches!(
            a.kind,
            crbs_core::ArtifactKind::Rpm | crbs_core::ArtifactKind::Srpm
        )
    });

    let sibling_builds = match record.task_id {
        Some(task_id) => app
            .state_store
            .get_child_build_summaries(task_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    task_id = %task_id,
                    error = %e,
                    "Failed to get sibling build summaries for build sidebar"
                );
                Vec::new()
            }),
        None => Vec::new(),
    };

    let lifecycle: Option<crbs_core::BuildLifecycle> = app
        .state_store
        .get_build_lifecycle(id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(
                build_id = %id,
                error = %e,
                "Failed to get build lifecycle for build sidebar"
            );
            None
        });

    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);

    let details_rows: Vec<(Markup, Markup)> = {
        let mut rows = Vec::new();
        rows.push((
            html! { (t(lang, TextKey::ThPackage)) },
            html! { (package_link(&record.pkg_name, &record.name)) },
        ));
        rows.push((
            html! { (t(lang, TextKey::LabelBackend)) },
            html! { (record.backend.as_deref().filter(|b| !b.is_empty()).unwrap_or("—")) },
        ));
        rows.push((
            html! { (t(lang, TextKey::ThSigned)) },
            html! { (if record.signed { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) },
        ));
        rows.push(repo_axis_row(&record, lang));
        match &lifecycle {
            Some(lc) => rows.extend(lifecycle_rows(lc, lang)),
            None => {
                if !is_terminal || record.started_at.is_some() {
                    let value = record
                        .started_at
                        .as_deref()
                        .map(|started| html! { code { (format_local_time(started)) } })
                        .unwrap_or_else(|| html! { "—" });
                    rows.push((html! { (t(lang, TextKey::ThStarted)) }, value));
                }
                if let Some(completed) = record.completed_at.as_deref() {
                    rows.push((
                        html! { (t(lang, TextKey::LabelCompleted)) },
                        html! { code { (format_local_time(completed)) } },
                    ));
                }
            }
        }
        if let Some(digest) = record.base_os_digest.as_deref().filter(|d| !d.is_empty()) {
            let short = digest.get(..12).unwrap_or(digest);
            rows.push((
                html! { (t(lang, TextKey::LabelBaseOs)) },
                html! { code title=(digest) { (short) } },
            ));
        }
        rows
    };

    let body = html! {
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToBuilds), "/ui/builds", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 {
                    (t_fmt(lang, FmtKey::BuildTitle, &[&id.to_string()]))
                    span aria-live="polite" { (phase_badge_with_class(&record.phase, "phase-badge", lang)) }
                    @if let Some(a) = attribution {
                        (attribution_badge(a.reason, a.first_watermark_reject_at, a.watermark_effective_load, watermarks, lang))
                    }
                    @if !is_terminal {
                        span class="live-indicator" title=(t(lang, TextKey::LiveUpdatesEnabled)) { }
                    }
                }
                div class="page-meta" {
                    @if let Some(task_id) = record.task_id {
                        a href=(format!("/ui/tasks/{}", task_id)) { (t_fmt(lang, FmtKey::TaskTitle, &[&task_id.to_string()])) }
                    }
                    span class="sep" { "·" }
                    (record.product)
                    span class="sep" { "·" }
                    (record.arch.as_deref().filter(|a| !a.is_empty()).unwrap_or("—"))
                    span class="sep" { "·" }
                    (record.user)
                    @if !is_terminal || record.started_at.is_some() {
                        span class="sep" { "·" }
                        (rel_time_lang(record.started_at.as_deref(), lang))
                    }
                    @if !is_terminal || record.duration.is_some() {
                        span class="sep" { "·" }
                        (record
                            .duration
                            .map(format_duration_secs)
                            .unwrap_or_else(|| "—".to_string()))
                    }
                }
            }
            div class="header-actions" {
                a class="action-button secondary" href=(format!("/ui/builds/{}/logs", id)) { (t(lang, TextKey::ViewLogs)) }
                @if !is_terminal {
                    (notify_button(&nonce, lang, &record.pkg_name))
                }
            }
        }
        (status_message(&q, &app.csrf_key, lang))
        (detail_grid(
            html! {
                @if record.phase == "failed" {
                    @if let Some(err) = record.error_summary.as_deref() {
                        @let failed_line = spans
                            .iter()
                            .rfind(|s| !s.skipped && s.exit_code != Some(0))
                            .map(|s| s.line);
                        @let logs_href = match failed_line {
                            Some(line) => format!("/ui/builds/{id}/logs?line={line}"),
                            None => format!("/ui/builds/{id}/logs"),
                        };
                        div class="message failure failure-box" {
                            (err)
                            br
                            a href=(logs_href) { small { (t(lang, TextKey::ViewLogs)) } }
                        }
                    }
                }
                @if record.phase != "failed" {
                    @if let Some(notes) = record.error_summary.as_deref() {
                        div class="message warning" role="note" {
                            strong { (t(lang, TextKey::BuildNotesTitle)) }
                            div { (notes) }
                        }
                    }
                }
                @if !spans.is_empty() || !is_terminal {
                    div class="admin-section" {
                        h2 { (t(lang, TextKey::PhaseTimelineTitle)) }
                        (phase_timeline(id, &spans, &record.phase, lang, false))
                    }
                }
                @if let Some(res) = build_resource_section(&record, lang) {
                    (res)
                }
                div class="admin-section" {
                    h2 {
                        (t(lang, TextKey::ArtifactsTitle))
                        (count_chip(artifact_count))
                        @if show_changelog_link {
                            (changelog_header_link(&format!("/ui/builds/{id}/changelog"), lang))
                        }
                    }
                    @if artifacts.is_empty() {
                        (empty_state(t(lang, TextKey::EmptyArtifactsTitle), t(lang, TextKey::EmptyArtifactsHint)))
                    } @else {
                        (artifact_table(id, &artifacts, lang))
                    }
                }
            },
            html! {
                (side_card("", t(lang, TextKey::SideDetailsTitle), html! {
                    (side_kv(&details_rows))
                    @if let Some(task_id) = record.task_id {
                        div class="side-divider" {}
                        (parent_task_block(task_id, id, &sibling_builds, lang))
                    }
                    @if let Some(href) = srpm_download_href(id, &artifacts) {
                        div class="side-divider" {}
                        a class="action-button" href=(href) {
                            (t(lang, TextKey::DownloadSrpm))
                        }
                    }
                }))
                @if show_cancel {
                    (side_card(
                        "danger-zone",
                        t(lang, TextKey::DangerZoneTitle),
                        html! {
                            (danger_row(
                                t(lang, TextKey::ButtonCancel),
                                t(lang, TextKey::DangerCancelBuildDesc),
                                cancel_button(
                                    &format!("/ui/builds/{}", id),
                                    csrf_token.as_deref(),
                                    t(lang, TextKey::ConfirmCancelBuild),
                                    lang,
                                ),
                            ))
                        },
                    ))
                }
            },
        ))
        (build_sse_script(id, &nonce, lang))
        (artifact_tree_script(&nonce))
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::BuildTitle, &[&id.to_string()]),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "builds",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn cancel_build_submit(
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

    let result =
        builds_service::cancel_build_for_user(&app, id, auth.as_ref().map(|ext| &ext.0)).await;
    let lang = lang_from_headers(&headers);
    let location = match result {
        Ok(_) => format!("/ui/builds/{}?status=cancelled", id),
        Err(ref e) => error_flash_location(
            &format!("/ui/builds/{}", id),
            &cancel_build_error_flash(e, id, lang),
            &app.csrf_key,
        ),
    };

    see_other_redirect(&location)
}

/// build 取消失败（[`builds_service::cancel_build_for_user`] 错误）→ 按页面语言
/// 本地化的 flash 文案（形态照 gc_error_flash）。可达错误全部可枚举（builds/
/// service.rs）：NotFound、PermissionDenied、Conflict 四字面量、mark_build_cancelled
/// 包装的 Internal；`database error` 族（CLI remote 匹配 exit 6）与新增文案回退英文原文。
fn cancel_build_error_flash(e: &ApiError, build_id: i64, lang: Lang) -> String {
    match e {
        ApiError::NotFound(msg) if msg == &format!("build {build_id} not found") => {
            t_fmt(lang, FmtKey::FlashBuildNotFound, &[&build_id.to_string()])
        }
        ApiError::PermissionDenied(msg) => match msg.as_str() {
            "you do not have permission to cancel this build" => {
                t(lang, TextKey::FlashCancelBuildPermission).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::Conflict(msg) => match msg.as_str() {
            "already_cancelled" => t(lang, TextKey::FlashBuildAlreadyCancelled).to_string(),
            "cannot_cancel_terminal_build" => {
                t(lang, TextKey::FlashBuildCancelTerminal).to_string()
            }
            "cannot_cancel_non_active_build" => {
                t(lang, TextKey::FlashBuildCancelNonActive).to_string()
            }
            _ => msg.clone(),
        },
        ApiError::Internal(msg) => match msg.as_str() {
            "failed to cancel build" => t(lang, TextKey::FlashBuildCancelFailed).to_string(),
            _ => msg.clone(),
        },
        other => other.message().to_string(),
    }
}

/// 日志页查询参数：`?line=N`（可选）为时间线失败子阶段跳转的行基准，N 超出
/// 渲染内容（截断 tail / 空日志）时定位脚本 no-op；axum Query 静默忽略未知参数。
#[derive(serde::Deserialize, Default)]
pub(crate) struct LogsPageQuery {
    pub line: Option<u64>,
}

pub(crate) async fn build_logs_page(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<LogsPageQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.logs,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let record =
        builds_service::fetch_build_with_rpms(&app, id, auth.as_ref().map(|ext| &ext.0)).await?;
    let is_terminal = build_phase_is_terminal(&record.phase);
    let download_url = format!("/api/v1/builds/{}/logs?offset=0", id);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    let body = if is_terminal {
        let content = read_log_full_or_truncated(&app, &record, UI_LOG_INLINE_MAX_BYTES).await;
        let mut spans = (*phase_timeline_spans(&app, &record).await).clone();
        for span in &mut spans {
            span.sub.clear();
        }
        html! {
            h1 { (t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()])) }
            p { a href=(format!("/ui/builds/{}", id)) { "← " (t(lang, TextKey::BackToBuild)) } }
            @if !spans.is_empty() {
                (phase_timeline(id, &spans, &record.phase, lang, !content.truncated))
            }
            @if content.truncated {
                p class="log-notice" {
                    (t_fmt(
                        lang,
                        FmtKey::LogTruncated,
                        &[
                            &humansize::format_size(UI_LOG_INLINE_MAX_BYTES as u64, humansize::DECIMAL),
                            &humansize::format_size(content.total_size, humansize::DECIMAL),
                        ],
                    ))
                    " "
                    a href=(download_url) { (t(lang, TextKey::DownloadFullLog)) }
                }
            }
            @if content.text.is_empty() {
                p { (t(lang, TextKey::NoLogs)) }
            } @else {
                pre id="log-output" role="log" { (content.text) }
            }
            @if let Some(line) = q.line {
                (log_line_anchor_script(line, &nonce))
            }
        }
    } else if record.phase == "building" {
        let (preview, preview_end) = read_log_preview(&app, &record, 64 * 1024).await;
        let mut spans = (*phase_timeline_spans(&app, &record).await).clone();
        for span in &mut spans {
            span.sub.clear();
        }
        html! {
            h1 { (t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()])) }
            p { a href=(format!("/ui/builds/{}", id)) { "← " (t(lang, TextKey::BackToBuild)) } }
            (phase_timeline(id, &spans, &record.phase, lang, false))
            div class="log-actions" {
                span class="live-indicator" title=(t(lang, TextKey::LiveLogStream)) { }
                label class="follow-toggle" for="follow-toggle" {
                    input #follow-toggle type="checkbox" name="follow" checked;
                    (t(lang, TextKey::FollowLabel))
                }
                button #jump-bottom type="button" class="action-button secondary" { (t(lang, TextKey::JumpToBottom)) }
                a class="log-download" href=(download_url) { (t(lang, TextKey::Download)) }
            }
            pre id="log-output" role="log" { (preview) }
            @if let Some(line) = q.line {
                (log_line_anchor_script(line, &nonce))
            }
            (log_sse_script(
                id,
                (!preview.is_empty()).then_some(preview_end),
                &nonce,
                lang,
            ))
        }
    } else {
        html! {
            h1 { (t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()])) }
            p { a href=(format!("/ui/builds/{}", id)) { "← " (t(lang, TextKey::BackToBuild)) } }
            p { (t(lang, TextKey::LogNotStarted)) }
            (pending_log_sse_script(id, &nonce, lang))
        }
    };
    page_with_csp(
        &t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()]),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "builds",
        &headers,
        &app.csrf_key,
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::util::DB_TIME_FMT;

    /// 固定基准（DB 帧、UTC 时间戳）：以"现在"回推偏移构造时刻串，gap 断言只看
    /// 时长文本（不受执行耗时影响的档位），活状态断言不固定具体数字。
    fn ts_ago(secs: i64) -> String {
        (chrono::Utc::now() - chrono::TimeDelta::seconds(secs))
            .format(DB_TIME_FMT)
            .to_string()
    }

    fn lc(
        submitted: Option<String>,
        assigned: Option<String>,
        started: Option<String>,
        completed: Option<String>,
    ) -> crbs_core::BuildLifecycle {
        crbs_core::BuildLifecycle {
            submitted_at: submitted,
            assigned_at: assigned,
            started_at: started,
            completed_at: completed,
            worker_id: Some(1),
            worker_name: Some("lc-worker".to_string()),
        }
    }

    fn rows_html(lc: &crbs_core::BuildLifecycle) -> String {
        side_kv(&lifecycle_rows(lc, Lang::En)).into_string()
    }

    /// 全字段默认的合成记录（测试就地改关心的字段）。
    fn base_record() -> crbs_core::BuildRecord {
        crbs_core::BuildRecord {
            id: 1,
            product: "fedora".into(),
            pkg_name: "hello".into(),
            name: "hello".into(),
            version: "1.0".into(),
            release: "1".into(),
            phase: "succeeded".into(),
            result_dir: None,
            srpm_path: None,
            started_at: None,
            completed_at: None,
            duration: None,
            layer_digest: None,
            base_os_digest: None,
            backend: Some("chroot".into()),
            user: "tester".into(),
            user_id: None,
            crbs_pid: None,
            rpms: Vec::new(),
            signed: false,
            priority: 0,
            arch: Some("x86_64".into()),
            task_id: Some(1),
            error_summary: None,
            deterministic: false,
            repo_publish: true,
            repo_consume: false,
            canonical_srpm_sha256: None,
            peak_rss_kb: None,
            peak_total_kb: None,
            cpu_secs: None,
            cpu_p90_cores: None,
            disk_wbytes: None,
            oom_killed: None,
            sample_backend: None,
            sample_ncpu: None,
            peak_tmpfs_kb: None,
            req_min_mem_kb: None,
            req_min_ncpu: None,
            req_min_disk_kb: None,
        }
    }

    /// 双轴标注行：publish/consume 生效值各以 ✓/✗ 渲染（提交时快照的观测面）。
    #[test]
    fn repo_axis_row_renders_publish_and_consume_marks() {
        let mut record = base_record();
        let s = side_kv(&[repo_axis_row(&record, Lang::En)]).into_string();
        assert!(s.contains("<dt>Repo</dt>"), "{s}");
        assert!(s.contains("publish ✓"), "{s}");
        assert!(s.contains("consume ✗"), "{s}");

        record.repo_publish = false;
        record.repo_consume = true;
        let s = side_kv(&[repo_axis_row(&record, Lang::Zh)]).into_string();
        assert!(s.contains("<dt>仓库</dt>"), "{s}");
        assert!(s.contains("publish ✗"), "{s}");
        assert!(s.contains("consume ✓"), "{s}");
    }

    /// 资源卡两态：全 NULL（老构建 / 未采集）不渲染整卡；字段齐备时行集、
    /// OOM 徽章、采样口径 chip、核数旁注与放置需求行齐出（双语各固定一处）。
    #[test]
    fn build_resource_section_two_states() {
        let record = base_record();
        assert!(build_resource_section(&record, Lang::En).is_none());

        let mut record = base_record();
        record.peak_rss_kb = Some(3_145_728); // 3 GiB
        record.peak_total_kb = Some(4_194_304); // 4 GiB
        record.cpu_secs = Some(100.4);
        record.cpu_p90_cores = Some(5.25);
        record.disk_wbytes = Some(1_500_000_000);
        record.oom_killed = Some(true);
        record.sample_backend = Some("cgroup".into());
        record.sample_ncpu = Some(8);
        record.req_min_mem_kb = Some(2_097_152); // 2 GiB
        record.req_min_ncpu = Some(4);
        record.req_min_disk_kb = Some(10_485_760); // 10 GiB

        let en = build_resource_section(&record, Lang::En)
            .expect("resource fields present → card renders")
            .into_string();
        assert!(en.contains("Resources"), "{en}");
        assert!(en.contains("3 GiB"), "{en}");
        assert!(en.contains("4 GiB"), "{en}");
        assert!(en.contains("incl. page cache"), "{en}");
        assert!(en.contains("1m 40s"), "{en}");
        assert!(en.contains("5.2"), "{en}");
        assert!(en.contains("1.50 GB"), "{en}");
        assert!(
            en.contains(r#"class="badge failure""#) && en.contains(">OOM<"),
            "{en}"
        );
        assert!(en.contains(r#"title="Sampling backend">cgroup<"#), "{en}");
        assert!(en.contains("@8C"), "{en}");
        assert!(
            en.contains("mem ≥ 2 GiB · ncpu ≥ 4 · disk ≥ 10 GiB"),
            "{en}"
        );
        assert!(en.contains(r#"class="side-kv""#), "{en}");

        let zh = build_resource_section(&record, Lang::Zh)
            .expect("resource fields present → card renders")
            .into_string();
        assert!(zh.contains("资源"), "{zh}");
        assert!(zh.contains("实测峰值内存"), "{zh}");
        assert!(zh.contains("含页缓存"), "{zh}");
        assert!(zh.contains("放置需求"), "{zh}");
        assert!(zh.contains(">OOM<"), "{zh}");

        let mut minimal = base_record();
        minimal.sample_backend = Some("proc".into());
        minimal.oom_killed = Some(false);
        let m = build_resource_section(&minimal, Lang::En)
            .expect("sampling-only data still renders")
            .into_string();
        assert!(m.contains(">proc<"), "{m}");
        assert!(!m.contains(">OOM<"), "{m}");
        assert!(!m.contains("Peak memory (RSS)"), "{m}");

        let mut req_only = base_record();
        req_only.req_min_ncpu = Some(2);
        let r = build_resource_section(&req_only, Lang::En)
            .expect("req-only data still renders")
            .into_string();
        assert!(r.contains("ncpu ≥ 2"), "{r}");
        assert!(!r.contains("mem ≥"), "{r}");
    }

    /// 缺派发只显示 Queued（活状态"至今"走秒）：无 Picked up/Ran/Completed 行，
    /// Queued 值是 lc-so-far span（data-ts 起点 + i18n 模板进 data-tpl）。
    #[test]
    fn lifecycle_pending_renders_live_queued_only() {
        let s = rows_html(&lc(Some(ts_ago(125)), None, None, None));
        assert!(s.contains("<dt>Queued</dt>"), "{s}");
        assert!(s.contains(r#"class="lc-so-far""#), "{s}");
        assert!(s.contains("data-ts="), "{s}");
        assert!(s.contains(r#"data-tpl="{0} so far""#), "{s}");
        assert!(s.contains("so far"), "{s}");
        assert!(!s.contains("<dt>Picked up</dt>"), "{s}");
        assert!(!s.contains("<dt>Ran</dt>"), "{s}");
        assert!(!s.contains("<dt>Completed</dt>"), "{s}");
    }

    /// 已派发未认领：Queued 定格时长 + 派发时刻（code）+ Picked up 等待中，
    /// 无走秒 span。
    #[test]
    fn lifecycle_dispatched_waiting_pickup() {
        let s = rows_html(&lc(Some(ts_ago(300)), Some(ts_ago(240)), None, None));
        assert!(s.contains("<dt>Queued</dt><dd>1m 0s · <code>"), "{s}");
        assert!(s.contains("<dt>Picked up</dt><dd>waiting</dd>"), "{s}");
        assert!(!s.contains("lc-so-far"), "{s}");
        assert!(!s.contains("<dt>Ran</dt>"), "{s}");
    }

    /// 认领耗时 >60s 转 warn 色；阈值内保持普通文本。
    #[test]
    fn lifecycle_pickup_warn_over_threshold() {
        let over = rows_html(&lc(
            Some(ts_ago(300)),
            Some(ts_ago(240)),
            Some(ts_ago(140)),
            None,
        ));
        assert!(
            over.contains(r#"<dd><span class="lc-warn">in 1m 40s</span>"#,),
            "{over}"
        );
        assert!(over.contains("<dt>Ran</dt>"), "{over}");
        assert!(over.contains("lc-so-far"), "{over}");

        let under = rows_html(&lc(
            Some(ts_ago(300)),
            Some(ts_ago(240)),
            Some(ts_ago(228)),
            None,
        ));
        assert!(under.contains("<dd>in 12s "), "{under}");
        assert!(!under.contains("lc-warn"), "{under}");
    }

    /// 全时刻齐：三段定格时长（Queued 附派发时刻 code）+ Completed 行
    /// （绝对 code + 相对词）+ worker 链接。
    #[test]
    fn lifecycle_terminal_three_segments_and_finished() {
        let done = ts_ago(300);
        let s = rows_html(&lc(
            Some(ts_ago(600)),
            Some(ts_ago(540)),
            Some(ts_ago(528)),
            Some(done.clone()),
        ));
        assert!(s.contains("<dt>Queued</dt><dd>1m 0s · <code>"), "{s}");
        assert!(s.contains("<dd>in 12s "), "{s}");
        assert!(s.contains("<dt>Ran</dt><dd>3m 48s</dd>"), "{s}");
        assert!(s.contains("<dt>Completed</dt><dd><code>"), "{s}");
        assert!(s.contains(" · "), "{s}");
        assert!(
            s.contains(r#"<a class="id-link" href="/ui/workers/1">lc-worker</a>"#),
            "{s}"
        );
        assert!(!s.contains("lc-so-far"), "{s}");
    }
}
