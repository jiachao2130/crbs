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
    // form 未填字段以空串传回（?phase=），统一视为 None：避免 `phase = ''`
    // 误过滤、保证 All 回显；phase 另过白名单归一，未知值按未过滤处理。
    let q = UiBuildListQuery {
        product: q.product.filter(|v| !v.is_empty()),
        name: q.name.filter(|v| !v.is_empty()),
        phase: normalize_phase_filter(q.phase.as_deref()).map(str::to_string),
        arch: q.arch.filter(|v| !v.is_empty()),
        ..q
    };
    let priority_filter = parse_priority_filter(q.priority.as_deref());
    // ?limit= query > crbs_page_size cookie > 默认 50。
    let limit = page_size_or_default(q.limit.or(page_size_from_headers(&headers)));
    // 与 API validate_list_pagination 同上限：usize::MAX 经 `offset as i64` 变
    // -1（SQLite 视作 0 / PG 直接 500），pagination_links 的 offset+limit 也会回绕。
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
    // 可见产品白名单只算一次：列表数据与 phase chips 共用同一 visible。
    let visible = compute_visible_products(&app, auth.as_ref().map(|ext| &ext.0)).await?;
    let resp = builds_service::list_builds_for_user_with_visible(
        &app,
        &api_q,
        priority_filter,
        visible.clone(),
    )
    .await?;
    let nonce = generate_nonce()?;
    // 过滤下拉/分页链接用的序列化值（与 DB 存储一致："0"/"1"/"2"）。
    let priority_sel = priority_filter.map(|p| p.to_string());
    // 分页与详情 back 参数共用的过滤参数集；带 offset 的 url 即地址栏（back 目标）。
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
    // 相位 chips 与列表同口径的分组计数（其余过滤一致，仅 phase 除外），共用 visible。
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
    // All chip 计数 = counts 求和（去 phase 过滤的总数），非含 phase 过滤的列表 total。
    let chips_total: i64 = phase_counts.iter().map(|&(_, c)| c).sum();
    // chip URL：以当前过滤集为基线替换/移除 phase、offset 归零。
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
    // 派发归因快照（内存态）：仅 pending 行有归因（派发成功即清除）。
    let attributions: std::collections::HashMap<
        i64,
        crate::server::scheduler::planner::RejectAttribution,
    > = resp
        .builds
        .iter()
        .filter(|b| b.phase == "pending")
        .filter_map(|b| app.dispatch_attribution.get(b.id).map(|a| (b.id, a)))
        .collect();
    // 归因徽章水位对照取运行期配置（百分比随 server.toml 水位数变化）。
    let watermarks = crate::server::scheduler::AdmitWatermarks::from_config(&app.server_config);
    // 激活过滤 chips（sort/task_id 不做 chip）：label 用表单标签文案，value
    // 展示化（phase/priority 走显示名），remove_url 去该参数、offset 归零。
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
        // task 下钻视图隐藏相位 chips：scoped 计数是全局口径，任务上下文有误导。
        @if q.task_id.is_none() {
            (chips)
        }
        @if resp.builds.is_empty() {
            // 空结果仍渲染过滤条（可调整/清除过滤），卡内只留卡头。
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyBuildsTitle), t(lang, TextKey::EmptyBuildsHint)))
        } @else {
            // 分页并入卡脚：total=0 时表格不渲染，pagination_links 也返回空标记。
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
                                // #task 链接只借 .id-link mono 视觉、不挂 row-target
                                //（脚本取行内首个 a.row-target = 上方构建 #N，整行点击须落
                                // 构建）；task_id 恒非空，None 仅作类型兜底。
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

// ===== 资源可观测：构建详情页"资源"卡 =====

/// KB 量 → 人类可读（二进制单位；口径惯例同 workers 页 mem_total_text——
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
    // tmpfs 峰值：build_tmpfs 关闭 / 缺观测不渲染该行（空值惯例同邻近字段）。
    if let Some(v) = kb_text(r.peak_tmpfs_kb) {
        rows.push((html! { (t(lang, TextKey::ResTmpfsPeak)) }, html! { (v) }));
    }
    // CPU 时间：秒取整走构建时长同款人类化（亚秒精度无观测价值）。
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
    // OOM 徽章：failed 构建的 failure-box 已有错误详情，徽章补充"因 OOM 而
    // 失败"维度；非 failed 构建（memory.events 事后检出）同样提示。
    let oom_badge = r.oom_killed.unwrap_or(false).then(|| {
        html! {
            span class="badge failure" title=(t(lang, TextKey::ResOomTitle)) { (t(lang, TextKey::ResOomBadge)) }
        }
    });
    // 采样口径 chip：backend 值（列 CHECK 收敛 cgroup/proc）+ "@nC" 核数旁注。
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
    // 调用方已过滤可解析起点；坏帧按 0 起算（初始文本失真可忽略，ticker 不改写）。
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

    // Queued 段：未派发按"至今"走秒（活），已派发定格 Submitted→Dispatched。
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

    // Picked up 段：有派发才渲染；未认领显示等待中，已认领渲染
    // Dispatched→Claimed（超阈值 warn 色）+ 执行 worker 链接（现状保留）。
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

        // Ran 段：有认领时刻才渲染（未完成按"至今"走秒，终态定格
        // Claimed→Finished）；等待认领阶段该段无信息量，不渲染。
        if let Some(s) = started.filter(|s| crbs_core::util::parse_db_time(s).is_some()) {
            let ran: Markup = match lc.completed_at.as_deref() {
                None => lc_so_far(s, FmtKey::LifecycleRanSoFar, lang),
                Some(done) => html! { (lc_gap_text(Some(s), Some(done))) },
            };
            rows.push((html! { (t(lang, TextKey::LifecycleRan)) }, ran));
        }
    }

    // Finished 行：绝对 + 相对时间（审计精确时刻 + 一眼新鲜度）。
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
    // 终态集合唯一真源（与 build SSE 循环共用）：crate::server::routes::logs。
    let is_terminal = build_phase_is_terminal(&record.phase);
    // 派发归因（内存态诊断）：pending 期存在，派发成功即清除。
    let attribution = if record.phase == "pending" {
        app.dispatch_attribution.get(record.id)
    } else {
        None
    };
    // 归因徽章水位对照取运行期配置（百分比随 server.toml 水位数变化）。
    let watermarks = crate::server::scheduler::AdmitWatermarks::from_config(&app.server_config);
    let show_cancel = auth
        .as_ref()
        .is_some_and(|ext| !is_terminal && ext.0.can_cancel(&record.user))
        && csrf_token.is_some();

    // 阶段时间线：全文件扫描 build.log 的 CRBS_PHASE 标记（LogBuffer 优先），无标记为空。
    let spans = phase_timeline_spans(&app, &record).await;

    let artifact_count = artifacts.len();

    // changelog 入口条件：DB 产物行含 rpm/srpm（解析链同依赖 DB 行）。
    let show_changelog_link = artifacts.iter().any(|a| {
        matches!(
            a.kind,
            crbs_core::ArtifactKind::Rpm | crbs_core::ArtifactKind::Srpm
        )
    });

    // 侧栏「所属任务」卡：同任务兄弟构建 mini 列表，复用 get_child_build_summaries
    // 现成查询；失败降级空列表不挡详情页，task_id None（迁移期残量）整卡不渲染。
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

    // 生命周期四时刻（Submitted/Dispatched/Claimed/Finished）：builds.created_at
    //（NULL 回退 tasks.submitted_at）+ 最新一条 build 型分配行的 assigned/
    // started + builds.completed_at；查询失败降级整块不渲染（页面不 500）。
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

    // 侧栏 Details 行集：基础信息 + 生命周期四行合并（时间值走 code mono，
    // .side-kv dd code 样式契约）。
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
        // 生命周期四行（Queued/Picked up/Ran/Completed）并入 Details；
        // 查询失败降级 Started/Completed 两行（页面不 500）。
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
        // 基础镜像摘要：base_os_digest 前 12 位 mono、title 悬停全值；无 digest 整行省略。
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
        // 页头条带：crumb 独立在条带外（全站统一，不受条带 flex 挤压）；操作组用 div
        //（form 是 flow content 不能进 h1）；主操作留页头，Cancel 在侧栏 Danger zone。
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToBuilds), "/ui/builds", q.back.as_deref()))
        }
        div class="page-head" {
            div class="title-block" {
                h1 {
                    (t_fmt(lang, FmtKey::BuildTitle, &[&id.to_string()]))
                    // aria-live：SSE 会改写徽章文本/类名（.phase-badge），live region
                    // 让屏幕阅读器播报 phase 变化（契约见 style.css 头注）；脚本按类名定位。
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
                    // live 页恒渲染（未就绪 "—" 占位，同侧栏 Details 行）；
                    // rel_time_lang 对 None/空值原生渲染 "—"。
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
                // 完成通知仅 live 页渲染（终态页无物可通知），匿名可用。
                @if !is_terminal {
                    (notify_button(&nonce, lang, &record.pkg_name))
                }
            }
        }
        (status_message(&q, &app.csrf_key, lang))
        (detail_grid(
            html! {
                // 失败原因摘要：worker / hub-local 失败路径落库的 error_summary；
                // maud 自动转义不 PreEscaped；failure-box 终端风 mono 防溢出。
                @if record.phase == "failed" {
                    @if let Some(err) = record.error_summary.as_deref() {
                        // 直达锚：取最后一个失败 span 的标记行做 ?line= 跳转，无标记
                        // 旧构建降级为不带 line 的原链接。失败判定对齐 phase_timeline
                        // 终态语义：exit 非零，或无 END 的未闭合 span（set -e 下失败步
                        // 不打 END，state() 此时是 running）；spans 全文件扫描，行号真实。
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
                // 软告警备注：非 failed 构建也携带 error_summary（worker notes /
                // hub-local warning），渲黄色卡（自动转义同上）；排除 failed 防双渲染。
                @if record.phase != "failed" {
                    @if let Some(notes) = record.error_summary.as_deref() {
                        div class="message warning" role="note" {
                            strong { (t(lang, TextKey::BuildNotesTitle)) }
                            div { (notes) }
                        }
                    }
                }
                // 阶段时间线：SSR 当前快照，live 增量由 build SSE timeline 事件驱动
                //（build_sse_script）。live 页 spans 尚空也渲染容器：JS applyTimeline
                // 容器缺位即 return（无日志页的就地补建），否则整场时间线静默丢失；
                // 空 spans 出 pending 骨架，终态无 spans（旧构建）不渲染。
                @if !spans.is_empty() || !is_terminal {
                    div class="admin-section" {
                        h2 { (t(lang, TextKey::PhaseTimelineTitle)) }
                        (phase_timeline(id, &spans, &record.phase, lang, false))
                    }
                }
                // 资源卡（可观测）：任一资源字段非 NULL 才渲染（老构建 /
                // 未采集零打扰），位于时间线与产物之间。
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
                    // SRPM 一键下载：有 SRPM 产物才渲染，无则整块不出现。
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
    // flash 本地化映射只在 handler 侧：服务层消息是 API JSON 信封共用字面量，一字不动。
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

/// 日志页查询参数：`?line=N`（可选）为时间线失败子阶段跳转的行锚，N 超出
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
    // 终态集合唯一真源（与 build SSE 循环共用）：crate::server::routes::logs。
    let is_terminal = build_phase_is_terminal(&record.phase);
    let download_url = format!("/api/v1/builds/{}/logs?offset=0", id);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    let body = if is_terminal {
        let content = read_log_full_or_truncated(&app, &record, UI_LOG_INLINE_MAX_BYTES).await;
        // spans 与详情页同源：phase_timeline_spans 全文件流式扫描（LogBuffer/落盘
        // 两驻留形态同覆盖，落盘解析含引擎时间戳目录回退），正文仍是 256KB tail 内联，
        // 头部标记不随 tail 窗口丢失。spans 返回 Arc：要原地清空 sub，取 owned 克隆改。
        let mut spans = (*phase_timeline_spans(&app, &record).await).clone();
        // 子阶段观测（chips + 失败面板）只在详情页输出：清空 sub 防展开面板。
        for span in &mut spans {
            span.sub.clear();
        }
        html! {
            h1 { (t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()])) }
            p { a href=(format!("/ui/builds/{}", id)) { "← " (t(lang, TextKey::BackToBuild)) } }
            @if !spans.is_empty() {
                // clickable ⟺ 行号与页内渲染文本自洽：未截断时全文件行号即页内行号，
                // 点击直达标记行；截断时行号超界渲为静态 span（不出死链，?line= 超界 no-op）。
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
                // role="log"：SSE 向 #log-output 追加日志 span（契约见 style.css
                // 头注），log role 让屏幕阅读器跟进流式输出。
                pre id="log-output" role="log" { (content.text) }
            }
            // ?line=N 行锚定位（终态页：全量或截断 tail——tail 时 N 超界 no-op）。
            @if let Some(line) = q.line {
                (log_line_anchor_script(line, &nonce))
            }
        }
    } else if record.phase == "building" {
        let (preview, preview_end) = read_log_preview(&app, &record, 64 * 1024).await;
        // spans 同终态分支走全量扫描：preview 只作正文首屏，64KB 窗口外头部标记
        // 不丢；LogBuffer 已淘汰早期内容（>10MB 构建中）时以"SSR 扫到多少渲多少
        // + SSE 实时补齐"为基线。spans 返回 Arc：要原地清空 sub，取 owned 克隆改。
        let mut spans = (*phase_timeline_spans(&app, &record).await).clone();
        for span in &mut spans {
            span.sub.clear();
        }
        html! {
            h1 { (t_fmt(lang, FmtKey::BuildLogsTitle, &[&id.to_string()])) }
            p { a href=(format!("/ui/builds/{}", id)) { "← " (t(lang, TextKey::BackToBuild)) } }
            // live 页恒渲染 .phase-timeline 容器：spans 空时补 pending 骨架，SSE 标记由
            // log_sse_script 就地推进（容器缺位脚本自建兜底，直接 return 吞掉全部标记）。
            // 不可点：正文是 preview tail 行号错位，且 SSE 整串改写 .phase-step className。
            (phase_timeline(id, &spans, &record.phase, lang, false))
            // log_sse_script 只按 id 挂事件（类名/id 契约由集成测试钉住）；
            // Download 常驻 live 页，终态分支保持截断提示。
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
            // ?line=N 行锚（building 页：未超 preview 窗口时行号才可靠，超界脚本 no-op）。
            @if let Some(line) = q.line {
                (log_line_anchor_script(line, &nonce))
            }
            // preview 非空时把末尾偏移交给 SSE 起播（?offset），预览与实时流无缝
            // 续接；为空时不带 offset，默认 tail 语义（无已渲染内容，tail 即起点）。
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
            // pending/assigned：phase 一旦离开排队态就整页 reload（见脚本注释）。
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

    /// 固定锚（DB 帧、UTC 墙钟）：以"现在"回推偏移构造时刻串，gap 断言只看
    /// 时长文本（不受执行耗时影响的档位），活状态断言不钉具体数字。
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

    /// 全字段缺省的合成记录（测试就地改关心的字段）。
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
    /// OOM 徽章、采样口径 chip、核数旁注与放置需求行齐出（双语各钉一处）。
    #[test]
    fn build_resource_section_two_states() {
        // 全 NULL：None（整卡不渲染的调用方契约）。
        let record = base_record();
        assert!(build_resource_section(&record, Lang::En).is_none());

        // 字段齐备：峰值/包络/CPU/磁盘/OOM/采样/需求全出。
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
        // CPU 时间 100.4s → 1m 40s（亚秒不进观测）。
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

        // zh：行标走中文表；OOM 徽章词两语同形。
        let zh = build_resource_section(&record, Lang::Zh)
            .expect("resource fields present → card renders")
            .into_string();
        assert!(zh.contains("资源"), "{zh}");
        assert!(zh.contains("实测峰值内存"), "{zh}");
        assert!(zh.contains("含页缓存"), "{zh}");
        assert!(zh.contains("放置需求"), "{zh}");
        assert!(zh.contains(">OOM<"), "{zh}");

        // 部分数据（仅采样口径 + 显式无 OOM）：仍有信息量，整卡渲染且无 OOM 徽章。
        let mut minimal = base_record();
        minimal.sample_backend = Some("proc".into());
        minimal.oom_killed = Some(false);
        let m = build_resource_section(&minimal, Lang::En)
            .expect("sampling-only data still renders")
            .into_string();
        assert!(m.contains(">proc<"), "{m}");
        assert!(!m.contains(">OOM<"), "{m}");
        assert!(!m.contains("Peak memory (RSS)"), "{m}");

        // 需求行只在任一 req 维非 NULL 时出现。
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
        // En 模板 "{0} so far"（data-tpl 承载原文，ticker 走秒用）。
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
        // Submitted→Dispatched = 60s；派发绝对时刻进 code（不钉具体墙钟）。
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
        // Dispatched→Claimed = 100s → warn + "in 1m 40s"；Ran 活状态走秒。
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
        // Dispatched→Claimed = 12s → 无 warn（worker 链接与值同 dd）。
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
        // Queued 定格时长后附派发绝对时刻（不钉具体墙钟）。
        assert!(s.contains("<dt>Queued</dt><dd>1m 0s · <code>"), "{s}");
        assert!(s.contains("<dd>in 12s "), "{s}");
        assert!(s.contains("<dt>Ran</dt><dd>3m 48s</dd>"), "{s}");
        // Finished 行绝对+相对：本地化绝对时间进 code，相对词同单元格。
        assert!(s.contains("<dt>Completed</dt><dd><code>"), "{s}");
        assert!(s.contains(" · "), "{s}");
        // 执行 worker 链接保留（认领段）。
        assert!(
            s.contains(r#"<a class="id-link" href="/ui/workers/1">lc-worker</a>"#),
            "{s}"
        );
        assert!(!s.contains("lc-so-far"), "{s}");
    }
}
