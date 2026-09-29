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

use super::{rel_time_lang, rel_time_text_lang};
use crate::server::auth::visibility::compute_product_visibility;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{
    admin_select, back_link, clickable_rows_script, confirm_button, count_chip, danger_row,
    detail_grid, detail_page_head, empty_state, filter_apply, filter_chips, format_local_time,
    generate_nonce, id_link, list_page_head, load_level, no_store, page_with_csp, pagination_links,
    phase_badge, resource_cap_bits, secret_reveal_box, see_other_error_redirect,
    see_other_redirect, side_card, side_kv, status_message, storage_error_flash, telemetry_chart,
    worker_heartbeat_older_than, worker_sse_script, worker_status_badge,
    worker_status_badge_with_class, ChartPoint, PaginationParams, StatusQuery, TelemetryRange,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, t, t_fmt, t_phase, worker_status_label, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::page_size::list_limit_offset;
use crate::server::routes::ui::service::{
    build_filter_qs, check_public_access, csrf_token_for_request, current_list_url,
    require_admin_session, with_back_param, CancelForm, QueryParams,
};
use crate::server::scheduler::WORKER_HEARTBEAT_TIMEOUT_SECS;
use crate::server::state::AppState;
use crate::server::worker::admin::{ensure_init_arch_compatible, WorkerAdminError};
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use crbs_core::{InitConflict, WorkerFilter};
use maud::{html, Markup};
use std::sync::Arc;

/// 共享核心（worker::admin）错误 → UI flash：NotFound / WorkerOnline 走双语业务文案，
/// Internal 可能带 DB 错误细节，只留日志、flash 固定文案（同 API `into_api_error` 脱敏口径）。
fn worker_admin_error_to_flash(e: WorkerAdminError, lang: Lang) -> String {
    match e {
        WorkerAdminError::NotFound(id) => {
            t_fmt(lang, FmtKey::FlashWorkerNotFound, &[&id.to_string()])
        }
        WorkerAdminError::WorkerOnline(name) => {
            t_fmt(lang, FmtKey::FlashWorkerOnlineConflict, &[&name])
        }
        WorkerAdminError::Internal(msg) => storage_error_flash("worker admin operation", &msg),
    }
}

/// 遥测 mini 水平条 + % 数字：色阶 <70 绿 / 70–90 琥珀 / >90 红（[`load_level`]
/// 统一阈值）；条宽 `min(pct,100)%`、数字超 100% 不封顶（load 超核数 = 排队，如实呈现）。
fn load_bar(pct: f64, title: Option<&str>) -> Markup {
    let width = pct.min(100.0).round() as u64;
    html! {
        span class=(format!("load-bar {}", load_level(pct))) title=[title] {
            i style=(format!("width:{width}%")) { }
        }
        " "
        span class="load-pct" { (format!("{}%", pct.round() as u64)) }
    }
}

/// CPU 遥测单元格（列表页）：主值 = cpu_util_pct 利用率条；load1/ncpu 齐备
/// 才挂 title（负载辅助口径），缺任一省略 title，避免模板拼出空洞段。缺
/// 利用率采样（首轮 / 非 Linux / 未上报）→ "—"。
fn cpu_telemetry_cell(
    cpu_util_pct: Option<f64>,
    load1: Option<f64>,
    ncpu: Option<i64>,
    lang: Lang,
) -> Markup {
    match cpu_util_pct {
        Some(util) => {
            let title = load1.zip(ncpu).map(|(l, n)| {
                t_fmt(
                    lang,
                    FmtKey::CpuUtilTitle,
                    &[
                        &format!("{}", util.round() as u64),
                        &format!("{l:.2}"),
                        &n.to_string(),
                    ],
                )
            });
            load_bar(util, title.as_deref())
        }
        None => html! { "—" },
    }
}

/// 内存遥测单元格（列表页）：mem_used_pct 已是百分比；缺采样 → "—"。
fn mem_telemetry_cell(mem_used_pct: Option<f64>) -> Markup {
    match mem_used_pct {
        Some(pct) => load_bar(pct, None),
        None => html! { "—" },
    }
}

/// 磁盘遥测单元格（列表 Disk 列）：disk_free_kb 绝对值文本（十进制 GB/MB，
/// 无分母不做条形）；缺采样（未上报 / 探测失败）→ "—"。
fn disk_telemetry_cell(disk_free_kb: Option<i64>) -> Markup {
    match disk_free_kb.filter(|kb| *kb > 0) {
        Some(kb) => html! { (humansize::format_size(kb as u64 * 1024, humansize::DECIMAL)) },
        None => html! { "—" },
    }
}

/// 采集能力 chips（详情页遥测卡）：resource_caps 置 1 位各渲染一枚中性
/// 徽章，词表见 [`resource_cap_bits`]（components 共享，SSE 注入同源）；
/// 值 0（在线 worker 上报了空能力）渲染 "—"，`None`（未上报）
/// 由调用方整组不渲染。
fn caps_chips(caps: i64) -> Markup {
    let bits = resource_cap_bits();
    // 全 0 位：徽章一个不出，落 "—" 占位（诚实呈现"上报了但无采集能力"）。
    if bits.iter().all(|(mask, _)| caps & mask == 0) {
        return html! { "—" };
    }
    html! {
        @for (mask, label) in &bits {
            @if caps & mask != 0 {
                span class="badge" { (label) }
            }
        }
    }
}

/// 详情遥测卡条形（带 SSE 定位 id：`worker_sse_script` 按 id 改写宽度/色阶/
/// title；`pct_id` 相邻 % 数字同步）。形态与列表页 [`load_bar`] 同款。
fn tel_bar(bar_id: &str, pct_id: &str, pct: f64, title: Option<&str>) -> Markup {
    let width = pct.min(100.0).round() as u64;
    html! {
        span id=(bar_id) class=(format!("load-bar {}", load_level(pct))) title=[title] {
            i style=(format!("width:{width}%")) { }
        }
        " "
        span id=(pct_id) class="load-pct" { (format!("{}%", pct.round() as u64)) }
    }
}

/// 无采样遥测的占位形态（条隐藏 + "—"），SSE 首个采样到达时由 JS 反隐藏——
/// id/结构与 [`tel_bar`] 逐字对应，DOM 契约见 worker_sse_script。
fn tel_bar_missing(bar_id: &str, pct_id: &str) -> Markup {
    html! {
        span id=(bar_id) class="load-bar success" hidden { i style="width:0%" { } }
        " "
        span id=(pct_id) class="load-pct" { "—" }
    }
}

/// SSE 可更新相对时间 span：`data-ts` 承载 DB 时间原文（JS ticker 10s 重渲
/// 相对词，title 落本地绝对时间）；阈值/降级与 [`rel_time_lang`] 同口径。
fn rel_time_span(id: &str, dt: Option<&str>, lang: Lang) -> Markup {
    match dt.filter(|s| !s.is_empty() && *s != "-") {
        None => html! { span id=(id) { "—" } },
        Some(s) if crbs_core::util::parse_db_time(s).is_none() => {
            html! { span id=(id) { (s) } }
        }
        Some(s) => html! {
            span id=(id) data-ts=(s) title=(format_local_time(s)) {
                (rel_time_text_lang(dt, lang))
            }
        },
    }
}

/// 耗时文本：started→completed 时长；无 completed 按"至今"实时（running 行，
/// SSE ticker 同口径重算）；无 started → "—"。
fn elapsed_text(started: Option<&str>, completed: Option<&str>) -> String {
    let Some(start) = started.and_then(crbs_core::util::parse_db_time) else {
        return "—".to_string();
    };
    let secs = match completed.and_then(crbs_core::util::parse_db_time) {
        Some(end) => (end.and_utc() - start.and_utc()).num_seconds(),
        None => (chrono::Utc::now() - start.and_utc()).num_seconds().max(0),
    };
    super::format_duration_secs(secs)
}

/// init 分配行成败徽章：worker_tasks.status（completed/failed/cancelled 终态
/// + assigned/running 活跃态）→ 徽章族色阶与显示名；终态复用 t_phase 同词表。
fn init_status_badge(status: &str, lang: Lang) -> Markup {
    let class = match status {
        "completed" => "badge success",
        "failed" => "badge failure",
        "cancelled" => "badge cancelled",
        "assigned" | "running" => "badge running",
        _ => "badge",
    };
    let text = match status {
        "completed" => t_phase(lang, "succeeded"),
        "failed" => t_phase(lang, "failed"),
        "cancelled" => t_phase(lang, "cancelled"),
        "assigned" | "running" => t(lang, TextKey::WorkerInitRunning),
        _ => status,
    };
    html! { span class=(class) { (text) } }
}

/// 节点内存总量 human 化（KB → 二进制单位 GiB/MiB；内存口径惯例用 1024 进
/// 制）；None/非正值 → None（整段不渲染）。
fn mem_total_text(mem_total_kb: Option<i64>) -> Option<String> {
    mem_total_kb
        .filter(|kb| *kb > 0)
        .map(|kb| humansize::format_size(kb as u64 * 1024, humansize::BINARY))
}

/// Worker 列表页查询参数；`status` 兼任 flash 消息通道（[`StatusQuery`]）——
/// 仅 `online` / `offline` 视为过滤器，`worker_removed` 等消息值不参与。
#[derive(serde::Deserialize, Default)]
pub(crate) struct WorkersListQuery {
    pub name: Option<String>,
    pub arch: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
    /// `error` 文本的 HMAC 签名（flash 通道，透传给 [`StatusQuery::es`]）。
    pub es: Option<String>,
    #[serde(default)]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

pub(crate) async fn list_workers_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<WorkersListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let name_filter = q.name.as_deref().filter(|v| !v.is_empty());
    let arch_filter = q.arch.as_deref().filter(|v| !v.is_empty());
    let status_filter = q
        .status
        .as_deref()
        .filter(|v| *v == "online" || *v == "offline");
    let (limit, offset) = list_limit_offset(q.limit, q.offset, &headers);
    let filter = WorkerFilter {
        name: name_filter,
        arch: arch_filter,
        status: status_filter,
        limit,
        offset,
    };
    let count_filter = WorkerFilter {
        name: filter.name,
        arch: filter.arch,
        status: filter.status,
        limit: 0,
        offset: 0,
    };
    let (total, workers) = tokio::try_join!(
        app.state_store.count_workers_filtered(&count_filter),
        app.state_store.list_workers_filtered(&filter)
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "Failed to list workers for UI");
        ApiError::Internal("failed to list workers".into())
    })?;
    // Load 列（active/capacity）批量统计；失败降级为空 map（按 0 显示），不挡页面。
    let load_by_worker = app
        .state_store
        .count_active_tasks_by_worker()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to count active tasks by worker for UI");
            std::collections::HashMap::new()
        });
    let nonce = generate_nonce()?;
    let flash = StatusQuery {
        status: q.status.clone(),
        error: q.error.clone(),
        es: q.es.clone(),
        back: None,
        range: None,
    };
    // 构建保留过滤器参数的查询后缀（用于分页链接），offset 由调用方覆盖。
    let filter_qs = build_filter_qs(&[
        ("name", name_filter),
        ("arch", arch_filter),
        ("status", status_filter),
    ]);
    let page_size = limit as usize;
    let offset_val = offset as usize;
    // 当前列表页 URL：详情链接 back 参数的目标（过滤参数 + 当前页码）。
    let current_list = current_list_url("/ui/workers", &filter_qs, offset_val);
    let lang = lang_from_headers(&headers);
    // 激活过滤 chips：name/arch 原值、status 走显示名；remove URL 去该参留其余、offset 归零。
    let mut active_chips: Vec<(String, String, String)> = Vec::new();
    if let Some(name) = name_filter {
        let remove = current_list_url(
            "/ui/workers",
            &build_filter_qs(&[
                ("name", None),
                ("arch", arch_filter),
                ("status", status_filter),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThName).to_string(),
            name.to_string(),
            remove,
        ));
    }
    if let Some(arch) = arch_filter {
        let remove = current_list_url(
            "/ui/workers",
            &build_filter_qs(&[
                ("name", name_filter),
                ("arch", None),
                ("status", status_filter),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::FilterArch).to_string(),
            arch.to_string(),
            remove,
        ));
    }
    if let Some(status) = status_filter {
        let remove = current_list_url(
            "/ui/workers",
            &build_filter_qs(&[
                ("name", name_filter),
                ("arch", arch_filter),
                ("status", None),
            ]),
            0,
        );
        active_chips.push((
            t(lang, TextKey::ThStatus).to_string(),
            worker_status_label(lang, status).to_string(),
            remove,
        ));
    }
    let active_chips = filter_chips(&active_chips, lang);
    // 过滤条并入卡头、chips 尾置其内；filter_form 组件无 status 字段，手写同构标记（同 products）。
    let toolbar = html! {
        form class="filter-bar" method="get" action="/ui/workers" {
            label {
                (t(lang, TextKey::ThName))
                input type="text" name="name" value=(q.name.as_deref().unwrap_or(""));
            }
            label {
                (t(lang, TextKey::FilterArch))
                input type="text" name="arch" value=(q.arch.as_deref().unwrap_or("")) placeholder=(t(lang, TextKey::PlaceholderArch));
            }
            label {
                (t(lang, TextKey::ThStatus))
                (admin_select("status", &[
                    ("", t(lang, TextKey::FilterAll)),
                    ("online", worker_status_label(lang, "online")),
                    ("offline", worker_status_label(lang, "offline")),
                ], status_filter))
            }
            (filter_apply("/ui/workers", lang))
            (active_chips)
        }
    };
    let body = html! {
        // 页头：h1 = 导航名 + 总数 chip；无主操作，meta/actions 传空。
        (list_page_head(
            html! { (t(lang, TextKey::NavWorkers)) " " (count_chip(total.max(0) as usize)) },
            html! {},
            html! {},
        ))
        (status_message(&flash, &app.csrf_key, lang))
        @if workers.is_empty() {
            // 过滤条仍需可操作（调整/清除过滤）：空结果时卡内只留卡头。
            div class="table-card" { (toolbar) }
            (empty_state(t(lang, TextKey::EmptyWorkersTitle), t(lang, TextKey::EmptyWorkersHint)))
        } @else {
            // 表格卡：高密度表 + 分页并入卡脚；CPU/内存遥测列与 Load 槽位并存（hub 权威口径），缺采样显示 "—"。
            div class="table-card" {
                (toolbar)
                table class="fixed" {
                    colgroup {
                        col style="width:6%" {}
                        col style="width:auto" {}
                        col style="width:9%" {}
                        col style="width:8%" {}
                        col style="width:8%" {}
                        col style="width:10%" {}
                        col style="width:10%" {}
                        col style="width:10%" {}
                        col style="width:9%" {}
                        col style="width:11%" {}
                        col style="width:9%" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::ThName)) }
                            th { (t(lang, TextKey::FilterArch)) }
                            th class="num" { (t(lang, TextKey::ThCapacity)) }
                            th class="num" { (t(lang, TextKey::ThLoad)) }
                            th class="num" { (t(lang, TextKey::ThCpu)) }
                            th class="num" { (t(lang, TextKey::ThMemory)) }
                            th class="num" { (t(lang, TextKey::ThDisk)) }
                            th { (t(lang, TextKey::ThStatus)) }
                            th class="num" { (t(lang, TextKey::ThLastHeartbeat)) }
                            th { (t(lang, TextKey::ThVersion)) }
                        }
                    }
                    tbody {
                        @for w in &workers {
                            tr class="clickable-row" {
                                td { (id_link(with_back_param(&format!("/ui/workers/{}", w.id), &current_list), w.id)) }
                                td class="ellipsis" title=(w.name) { (w.name) }
                                td class="mono" { (w.arch) }
                                td class="num" { (w.capacity) }
                                td class="num" {
                                    // Load 列 = 容量占用条（阈值色阶同遥测条）；
                                    // title 承载 active/capacity 原始数。capacity 0
                                    // 防除零按 0% 显绿条。
                                    @let active = load_by_worker.get(&w.id).copied().unwrap_or(0);
                                    @let cap = w.capacity.max(0);
                                    @let pct = if cap > 0 { active as f64 / cap as f64 * 100.0 } else { 0.0 };
                                    (load_bar(
                                        pct,
                                        Some(&t_fmt(lang, FmtKey::LoadCapacityTitle, &[&active.to_string(), &cap.to_string()])),
                                    ))
                                }
                                td class="num" { (cpu_telemetry_cell(w.cpu_util_pct, w.load1, w.ncpu, lang)) }
                                td class="num" { (mem_telemetry_cell(w.mem_used_pct)) }
                                td class="num" { (disk_telemetry_cell(w.disk_free_kb)) }
                                td { (worker_status_badge(&w.status, w.last_heartbeat.as_deref(), lang)) }
                                td class="num" { (rel_time_lang(w.last_heartbeat.as_deref(), lang)) }
                                td { (w.version) }
                            }
                        }
                    }
                }
                (pagination_links(&PaginationParams {
                    base_path: "/ui/workers",
                        lang,
                    total: total as usize,
                    limit: page_size,
                    offset: offset_val,
                    query: QueryParams::default(),
                    raw_filter_qs: Some(&filter_qs),

                    csrf_token: csrf_token_for_request(&headers, &app.csrf_key).as_deref(),                }))
            }
        }
        (clickable_rows_script(&nonce))
    };
    page_with_csp(
        t(lang, TextKey::NavWorkers),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "workers",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn worker_detail_page(
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
    // 活跃/历史构建与 init 卡按产品可见性过滤；Worker 自身的负载/遥测仍公开。
    // 孤儿产品（已删除）按 builds/tasks 列表同口径放行，见 ProductVisibility。
    let visibility = compute_product_visibility(&app, auth.as_ref().map(|ext| &ext.0)).await?;
    let worker = app
        .state_store
        .get_worker(id)
        .await
        .map_err(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to get worker for UI");
            ApiError::Internal("failed to get worker".into())
        })?
        .ok_or_else(|| ApiError::not_found("worker", id))?;
    // 当前 load（active/capacity 的分子）；失败降级 0，不挡详情页。
    let active_tasks = app
        .state_store
        .count_worker_active_tasks(id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to count active tasks for UI");
            0
        });
    // Active builds：当前非终态分配的 build 列表（与 load 计数同口径，init 任务不在此列）；失败降级空列表。
    let active_builds: Vec<crbs_core::WorkerActiveBuild> = app
        .state_store
        .list_worker_active_builds(id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to list active builds for UI");
            Vec::new()
        })
        .into_iter()
        .filter(|b| visibility.allows(&b.product))
        .collect();
    // Recent builds / 每产品最近 init：展示性区块，查询失败降级空列表不挡详情页。
    let recent_builds: Vec<crbs_core::WorkerRecentBuild> = app
        .state_store
        .list_worker_recent_builds(id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to list recent builds for UI");
            Vec::new()
        })
        .into_iter()
        .filter(|b| visibility.allows(&b.product))
        .collect();
    let recent_inits: Vec<crbs_core::WorkerRecentInit> = app
        .state_store
        .list_worker_recent_inits(id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to list recent inits for UI");
            Vec::new()
        })
        .into_iter()
        .filter(|it| visibility.allows(&it.product))
        .collect();
    // 产品下拉与 /ui/products 同一全量摘要 API（区块 admin-gated，私有产品也列出）；失败降级空下拉，POST 端仍校验。
    let product_options: Vec<(String, String)> = app
        .state_store
        .load_product_summaries()
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Failed to load product summaries for worker init form");
            Vec::new()
        })
        .into_iter()
        .map(|s| (s.name.clone(), s.name))
        .collect();
    let product_option_refs: Vec<(&str, &str)> = product_options
        .iter()
        .map(|(v, l)| (v.as_str(), l.as_str()))
        .collect();
    let nonce = generate_nonce()?;
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let lang = lang_from_headers(&headers);
    // 遥测趋势档位（?range=1h|24h|7d，非法/缺失回落 24h）与窗口内历史采样；
    // 查询失败降级空态文案（页面不 500），与现值条解耦（现值条来自 get_worker）。
    let range = TelemetryRange::from_query(q.range.as_deref());
    let samples: Vec<crbs_core::TelemetrySamplePoint> = app
        .state_store
        .list_telemetry_samples(
            id,
            range.window_minutes(),
            crbs_core::TELEMETRY_SAMPLE_QUERY_LIMIT,
        )
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(worker_id = %id, error = %e, "Failed to list telemetry samples for UI");
            Vec::new()
        });
    let chart_points: Vec<ChartPoint> = samples
        .iter()
        .filter_map(|s| {
            let ts = crbs_core::util::parse_db_time(&s.sampled_at)?
                .and_utc()
                .timestamp();
            Some(ChartPoint {
                ts,
                cpu: s.telemetry.cpu_util_pct,
                mem: s.telemetry.mem_used_pct,
                load: s.telemetry.load1,
            })
        })
        .collect();
    // 遥测随心跳过期：心跳超 WORKER_HEARTBEAT_TIMEOUT_SECS（同 scheduler 判离线阈值）即加 stale 标记。
    let telemetry_is_stale = worker_heartbeat_older_than(
        worker.last_heartbeat.as_deref(),
        WORKER_HEARTBEAT_TIMEOUT_SECS as i64,
    );
    let is_offline = worker.status == "offline";
    // 凭据存在性/过期时间是管理面元数据：仅 admin 可见，公开页不透出。
    let show_credentials = auth.as_ref().map(|ext| ext.0.is_admin()).unwrap_or(false);
    let mem_total = mem_total_text(worker.mem_total_kb);

    // 遥测卡 CPU 行：利用率条（title 带负载辅助口径），绝对负载归负载组
    // tooltip；id 由 worker_sse_script 就地改写（无采样时占位形态见
    // tel_bar_missing）。
    let cpu_title = worker
        .cpu_util_pct
        .zip(worker.load1)
        .zip(worker.ncpu.filter(|&n| n > 0))
        .map(|((util, l), n)| {
            t_fmt(
                lang,
                FmtKey::CpuUtilTitle,
                &[
                    &(util.round() as u64).to_string(),
                    &format!("{l:.2}"),
                    &n.to_string(),
                ],
            )
        });
    let cpu_value = if let Some(util) = worker.cpu_util_pct {
        html! { (tel_bar("w-cpu-bar", "w-cpu-pct", util, cpu_title.as_deref())) }
    } else {
        html! { (tel_bar_missing("w-cpu-bar", "w-cpu-pct")) }
    };
    // 遥测卡负载行：load1/ncpu 倍数（12.5px 继承自 .tel-now-item，无 bar 不加
    // 新样式）；超订如实显示（3.9× 不封顶）。缺任一采样 → 裸 "—" 省略 title。
    // ponytail: 刻意不做色阶告警——构建高峰合法超载，异常信号是"CPU 低 + 负
    // 载高"分叉，人眼并读 CPU 条与负载值；如需自动化再升级为分叉判据。
    let load_value = match worker.load1.zip(worker.ncpu.filter(|&n| n > 0)) {
        Some((load1, ncpu)) => {
            let ratio = load1 / ncpu as f64;
            html! {
                span id="w-load-val"
                    title=(t_fmt(lang, FmtKey::LoadAvgTitle, &[&format!("{load1:.2}"), &ncpu.to_string()]))
                { (format!("{ratio:.1}×")) }
            }
        }
        None => html! { span id="w-load-val" { "—" } },
    };
    // 遥测卡 Memory 行：已用条（title 已用 %）+ 节点内存总量 human 注记。
    let mem_value = if let Some(pct) = worker.mem_used_pct {
        html! {
            (tel_bar(
                "w-mem-bar",
                "w-mem-pct",
                pct,
                Some(&t_fmt(lang, FmtKey::MemUsedPct, &[&pct.round().to_string()])),
            ))
            @if let Some(total) = &mem_total {
                span class="telemetry-extra" title=(t(lang, TextKey::WorkerMemTotal)) { (total) }
            }
        }
    } else {
        html! {
            (tel_bar_missing("w-mem-bar", "w-mem-pct"))
            @if let Some(total) = &mem_total {
                span class="telemetry-extra" title=(t(lang, TextKey::WorkerMemTotal)) { (total) }
            }
        }
    };
    // 遥测卡磁盘行：disk_free_kb 绝对值文本（十进制 GB/MB，无分母不做条形，
    // 与列表 Disk 列同格式）；缺采样 → "—"。id 供 worker_sse_script 就地改写。
    let disk_value = html! {
        span id="w-disk-val" { (disk_telemetry_cell(worker.disk_free_kb)) }
    };
    // 采集能力组：resource_caps `None`（未上报）整组不渲染（零打
    // 扰），SSE 收到新值时 JS 只在容器已存在时重建（缺位即略过，同 DOM 契约）。
    let caps_group = worker.resource_caps.map(|caps| {
        html! {
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::WorkerCapsLabel)) }
                span id="w-caps-chips" { (caps_chips(caps)) }
            }
        }
    });
    // 现值条（遥测面板顶部横排）：CPU / 内存 / 负载 / 磁盘 / 遥测时间（+
    // 能力 chips）组原值。id 与 DOM 契约逐字保留（worker_sse_script 按 id
    // 就地改写）；stale 标记全页仅此遥测时间一处出现，其余行不带。
    let tel_now = html! {
        div class="tel-now" {
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::WorkerCpuLoad)) }
                (cpu_value)
            }
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::ThMemory)) }
                (mem_value)
            }
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::ThLoadAvg)) }
                (load_value)
            }
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::WorkerDiskFree)) }
                (disk_value)
            }
            @if let Some(caps) = caps_group {
                (caps)
            }
            span class="tel-now-item" {
                span class="tel-now-label" { (t(lang, TextKey::WorkerTelemetryTime)) }
                (rel_time_span("w-tel-time", worker.last_heartbeat.as_deref(), lang))
                span id="w-tel-stale" class="telemetry-stale" hidden[!telemetry_is_stale]
                    title=(t(lang, TextKey::TelemetryStaleNote)) {
                    "(" (t(lang, TextKey::WorkerStale)) ")"
                }
            }
        }
    };
    // 侧栏 Details 行集：身份/负载/凭据 + 注册与密钥过期（绝对时间）+ 内存总量。
    let details_rows: Vec<(Markup, Markup)> = {
        let mut rows: Vec<(Markup, Markup)> = vec![
            (
                html! { (t(lang, TextKey::ThCapacity)) },
                html! { (worker.capacity) },
            ),
            (
                html! { (t(lang, TextKey::ThLoad)) },
                html! { (active_tasks) "/" (worker.capacity) },
            ),
            (
                html! { (t(lang, TextKey::ThStatus)) },
                html! { (worker_status_badge(&worker.status, worker.last_heartbeat.as_deref(), lang)) },
            ),
            (
                html! { (t(lang, TextKey::ThLastHeartbeat)) },
                html! { (rel_time_span("w-hb", worker.last_heartbeat.as_deref(), lang)) },
            ),
            (
                html! { (t(lang, TextKey::ThVersion)) },
                html! { (worker.version) },
            ),
        ];
        if show_credentials {
            rows.push((
                html! { (t(lang, TextKey::LabelHasSecret)) },
                html! { (if worker.has_secret { t(lang, TextKey::Yes) } else { t(lang, TextKey::No) }) },
            ));
        }
        if let Some(created) = worker
            .created_at
            .as_deref()
            .filter(|s| !s.is_empty() && *s != "-")
        {
            rows.push((
                html! { (t(lang, TextKey::ThCreated)) },
                html! { code { (format_local_time(created)) } },
            ));
        }
        if show_credentials {
            if let Some(expires) = worker
                .secret_expires_at
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "-")
            {
                rows.push((
                    html! { (t(lang, TextKey::ThExpires)) },
                    html! { code { (format_local_time(expires)) } },
                ));
            }
        }
        if let Some(total) = &mem_total {
            rows.push((
                html! { (t(lang, TextKey::WorkerMemTotal)) },
                html! { (total) },
            ));
        }
        rows
    };
    // 页头（范式化 detail_page_head）：h1 = Worker #N + 状态徽章（SSE 定位类）
    // + live 指示灯（离线页无流不渲染）；meta = name · arch · v<version> ·
    // 注册 · 心跳。builds 列表尚无 worker 过滤参数，header-actions 保持空
    //（Recent builds 卡已承载导航，不为按钮新增过滤功能）。
    let head = detail_page_head(
        html! { (back_link(t(lang, TextKey::BackToWorkers), "/ui/workers", q.back.as_deref())) },
        html! {
            "Worker #" (id)
            span aria-live="polite" {
                (worker_status_badge_with_class(
                    &worker.status,
                    worker.last_heartbeat.as_deref(),
                    "worker-status-badge",
                    lang,
                ))
            }
            @if !is_offline {
                span class="live-indicator" title=(t(lang, TextKey::LiveUpdatesEnabled)) { }
            }
        },
        html! {
            (worker.name)
            span class="sep" { "·" }
            (worker.arch)
            @if !worker.version.is_empty() {
                span class="sep" { "·" }
                "v" (worker.version)
            }
            @if worker
                .created_at
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "-")
                .is_some()
            {
                span class="sep" { "·" }
                (t(lang, TextKey::ThCreated)) " "
                (rel_time_lang(worker.created_at.as_deref(), lang))
            }
            @if worker
                .last_heartbeat
                .as_deref()
                .filter(|s| !s.is_empty() && *s != "-")
                .is_some()
            {
                span class="sep" { "·" }
                (t(lang, TextKey::ThLastHeartbeat)) " "
                (rel_time_lang(worker.last_heartbeat.as_deref(), lang))
            }
        },
        html! {},
    );
    let body = html! {
        (head)
        (status_message(&q, &app.csrf_key, lang))
        // 双栏：主列 遥测 / Active builds / Recent builds / Base OS inits，
        // 侧栏 Details + Danger zone（admin，rotate/revoke/init/remove 四行，
        // Remove 视觉最重置底）。
        (detail_grid(
            html! {
                // 遥测面板（主列最前）：档位切换 + 现值条 + 趋势图（空窗口
                // 渲染弱色空态文案，新部署无历史属预期）。
                div class="admin-section" {
                    div class="telemetry-head" {
                        h2 { (t(lang, TextKey::TelemetryTitle)) }
                        nav class="range-picker" aria-label=(t(lang, TextKey::TelemetryTitle)) {
                            @for r in [TelemetryRange::H1, TelemetryRange::H24, TelemetryRange::D7] {
                                a href=(format!("/ui/workers/{}?range={}", id, r.query_value()))
                                    class=(if r == range { "active" } else { "" })
                                    aria-current=[(r == range).then_some("page")] {
                                    (r.label(lang))
                                }
                            }
                        }
                    }
                    (tel_now)
                    @if chart_points.is_empty() {
                        div class="tel-empty" { (t(lang, TextKey::TelemetryEmpty)) }
                    } @else {
                        (telemetry_chart(&chart_points, range, lang, &nonce))
                    }
                }
                div class="admin-section" {
                    h2 { (t(lang, TextKey::ActiveBuilds)) }
                    // 空态文案按 status 分支（离线给出恢复预期）；table/empty
                    // 二选一显示，SSE 收到活跃列表变化时按 id 切换 hidden。
                    div id="w-active-empty" hidden[!active_builds.is_empty()] {
                        @if is_offline {
                            (empty_state(
                                t(lang, TextKey::EmptyActiveOfflineTitle),
                                t(lang, TextKey::EmptyActiveOfflineHint),
                            ))
                        } @else {
                            (empty_state(
                                t(lang, TextKey::EmptyActiveBuildsTitle),
                                t(lang, TextKey::EmptyActiveBuildsHint),
                            ))
                        }
                    }
                    table id="w-active-table" class="fixed" hidden[active_builds.is_empty()] {
                        colgroup {
                            col style="width:10%" {}
                            col style="width:auto" {}
                            col style="width:14%" {}
                            col style="width:16%" {}
                        }
                        thead {
                            tr {
                                th class="num" { (t(lang, TextKey::ThId)) }
                                th { (t(lang, TextKey::ThPackage)) }
                                th { (t(lang, TextKey::ThPhase)) }
                                th class="num" { (t(lang, TextKey::ThStarted)) }
                            }
                        }
                        tbody id="w-active-tbody" {
                            @for b in &active_builds {
                                tr {
                                    td class="num" { a href=(format!("/ui/builds/{}", b.id)) { (b.id) } }
                                    td class="ellipsis" title=(b.pkg_name) { (b.pkg_name) }
                                    td { (phase_badge(&b.phase, lang)) }
                                    td class="num" { (rel_time_lang(b.started_at.as_deref(), lang)) }
                                }
                            }
                        }
                    }
                }
                div class="admin-section" {
                    // 卡头 id 供 SSE 定位 count-chip（行集随快照增减同步）。
                    h2 id="w-recent-head" {
                        (t(lang, TextKey::RecentBuildsTitle))
                        (count_chip(recent_builds.len()))
                    }
                    // 空态/table 恒双渲染、hidden 二选一（同 Active builds 卡）：
                    // SSE 快照行集清空时 JS 切回空态，无须重建 i18n 文案。
                    div id="w-recent-empty" hidden[!recent_builds.is_empty()] {
                        (empty_state(
                            t(lang, TextKey::EmptyRecentBuildsTitle),
                            t(lang, TextKey::EmptyRecentBuildsHint),
                        ))
                    }
                    table id="w-recent-table" class="fixed" hidden[recent_builds.is_empty()] {
                        colgroup {
                            col style="width:10%" {}
                            col style="width:auto" {}
                            col style="width:16%" {}
                            col style="width:18%" {}
                        }
                        thead {
                            tr {
                                th class="num" { (t(lang, TextKey::ThId)) }
                                th { (t(lang, TextKey::ThPackage)) }
                                th { (t(lang, TextKey::ThPhase)) }
                                th class="num" { (t(lang, TextKey::LabelDuration)) }
                            }
                        }
                        tbody id="w-recent-tbody" {
                            @for b in &recent_builds {
                                // data-recent-build 是 worker SSE 整表重建的行
                                // 定位键；耗时无 completed 按"至今"实时（SSE
                                // ticker 10s 重算），data-start/data-done 承载
                                // 口径供重建行同款回写。
                                tr data-recent-build=(b.id) {
                                    td class="num" { a href=(format!("/ui/builds/{}", b.id)) { (b.id) } }
                                    td class="ellipsis" title=(b.pkg_name) { (b.pkg_name) }
                                    td { (phase_badge(&b.phase, lang)) }
                                    td class="num" {
                                        span class="recent-dur"
                                            data-start=[b.started_at.as_deref()]
                                            data-done=[b.completed_at.as_deref()] {
                                            (elapsed_text(b.started_at.as_deref(), b.completed_at.as_deref()))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div class="admin-section" {
                    h2 {
                        (t(lang, TextKey::RecentInitsTitle))
                        (count_chip(recent_inits.len()))
                    }
                    @if recent_inits.is_empty() {
                        (empty_state(
                            t(lang, TextKey::EmptyRecentInitsTitle),
                            t(lang, TextKey::EmptyRecentInitsHint),
                        ))
                    } @else {
                        table class="fixed" {
                            colgroup {
                                col style="width:auto" {}
                                col style="width:30%" {}
                                col style="width:30%" {}
                            }
                            thead {
                                tr {
                                    th { (t(lang, TextKey::ThProduct)) }
                                    th { (t(lang, TextKey::ThStatus)) }
                                    th class="num" { (t(lang, TextKey::ThTime)) }
                                }
                            }
                            tbody {
                                @for it in &recent_inits {
                                    tr {
                                        td class="ellipsis" title=(it.product) { (it.product) }
                                        td { (init_status_badge(&it.status, lang)) }
                                        td class="num" {
                                            // 时间列 = 完成时刻，未完成回退派发时刻。
                                            @let shown = it.completed_at.as_deref().or(it.assigned_at.as_deref());
                                            (rel_time_lang(shown, lang))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            html! {
                (side_card("", t(lang, TextKey::SideDetailsTitle), side_kv(&details_rows)))
                @if auth.as_ref().is_some_and(|ext| ext.0.is_admin()) {
                    @if let Some(token) = csrf_token.as_ref() {
                        (side_card(
                            "danger-zone",
                            t(lang, TextKey::DangerZoneTitle),
                            html! {
                                (danger_row(
                                    t(lang, TextKey::ButtonRotateSecret),
                                    t(lang, TextKey::DangerRotateWorkerDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/workers/{}", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="action" value="rotate";
                                            (confirm_button(t(lang, TextKey::ButtonRotateSecret), &t_fmt(lang, FmtKey::ConfirmRotateWorkerSecret, &[&worker.name])))
                                        }
                                    },
                                ))
                                (danger_row(
                                    t(lang, TextKey::ButtonRevokeSecret),
                                    t(lang, TextKey::DangerRevokeWorkerDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/workers/{}", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="action" value="revoke";
                                            (confirm_button(t(lang, TextKey::ButtonRevokeSecret), &t_fmt(lang, FmtKey::ConfirmRevokeWorkerSecret, &[&worker.name])))
                                        }
                                    },
                                ))
                                (danger_row(
                                    t(lang, TextKey::ButtonInitBaseOs),
                                    t(lang, TextKey::DangerInitWorkerDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/workers/{}", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            input type="hidden" name="action" value="init";
                                            label {
                                                (t(lang, TextKey::ThProduct))
                                                // 选项来自产品表全量（页面 admin-gated）；POST 端仍按产品名校验，空列表提交得 error flash。
                                                (admin_select("product", &product_option_refs, None))
                                            }
                                            (confirm_button(t(lang, TextKey::ButtonInitBaseOs), t(lang, TextKey::ConfirmInitBaseOs)))
                                        }
                                    },
                                ))
                                // Remove 视觉最重，单独一行置底。
                                (danger_row(
                                    t(lang, TextKey::ButtonRemoveWorker),
                                    t(lang, TextKey::DangerRemoveWorkerDesc),
                                    html! {
                                        form class="admin-inline-form" method="post" action=(format!("/ui/workers/{}/remove", id)) {
                                            input type="hidden" name="csrf_token" value=(token);
                                            (confirm_button(t(lang, TextKey::ButtonRemoveWorker), &t_fmt(lang, FmtKey::ConfirmRemoveWorker, &[&worker.name])))
                                        }
                                    },
                                ))
                            },
                        ))
                    }
                }
            },
        ))
        // SSE 快照流仅非离线页渲染（离线页收到终态事件 reload 回本形态，不渲染脚本故不成环）。
        @if !is_offline {
            (worker_sse_script(id, &nonce, lang))
        }
    };
    page_with_csp(
        &format!("Worker #{} {}", id, worker.name),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "workers",
        &headers,
        &app.csrf_key,
        body,
    )
}

// Admin 后台页面

#[derive(serde::Deserialize)]
pub(crate) struct AdminWorkerActionForm {
    pub csrf_token: String,
    pub action: String,
    /// init 动作的目标 product；其它动作不携带该字段。
    #[serde(default)]
    pub product: Option<String>,
}

pub(crate) async fn admin_worker_action(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<AdminWorkerActionForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    enum WorkerActionResult {
        Rotated {
            worker_name: String,
            secret: String,
        },
        Revoked,
        InitDispatched {
            worker_name: String,
            product: String,
            assignment_id: i64,
        },
    }
    // rotate/revoke 走 worker::admin 共享核心（与 REST API 同路径，审计与日志在共享函数内）；init 仅 UI 内联。
    let result: Result<WorkerActionResult, String> = async {
        match form.action.as_str() {
            "rotate" => {
                let secret = crate::server::worker::admin::rotate_secret(
                    &app.state_store,
                    &ctx.user,
                    &ctx.role,
                    id,
                )
                .await
                .map_err(|e| worker_admin_error_to_flash(e, lang))?;
                // reveal 页需 worker 名展示；rotate 已确认存在，仅并发删除竞态取不到 → 回退空串。
                let worker_name = app
                    .state_store
                    .get_worker(id)
                    .await
                    .map_err(|e| storage_error_flash("get worker", &e))?
                    .map(|w| w.name)
                    .unwrap_or_default();
                Ok(WorkerActionResult::Rotated {
                    worker_name,
                    secret,
                })
            }
            "revoke" => {
                crate::server::worker::admin::revoke_secret(
                    &app.state_store,
                    &ctx.user,
                    &ctx.role,
                    id,
                )
                .await
                .map_err(|e| worker_admin_error_to_flash(e, lang))?;
                Ok(WorkerActionResult::Revoked)
            }
            // 与 API `POST /api/v1/admin/workers/{id}/init`（init_worker）同路径同错误语义；flash 按页面语言渲染。
            "init" => {
                let worker = app
                    .state_store
                    .get_worker(id)
                    .await
                    .map_err(|e| storage_error_flash("get worker", &e))?
                    .ok_or_else(|| t_fmt(lang, FmtKey::FlashWorkerNotFound, &[&id.to_string()]))?;
                let product = form
                    .product
                    .as_deref()
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .ok_or_else(|| t(lang, TextKey::FlashInitProductRequired).to_string())?;
                // Validation 按空/非法字符映射双语 key；非 Validation 变体走 storage_error_flash，不透出 {other:?}。
                crate::server::validation::validate_product_name(product).map_err(|e| match e {
                    ApiError::Validation(_) => {
                        if product.is_empty() {
                            t(lang, TextKey::FlashProductNameEmpty).to_string()
                        } else {
                            t_fmt(lang, FmtKey::FlashProductNameInvalidChars, &[product])
                        }
                    }
                    other => storage_error_flash("validate product name", other.message()),
                })?;
                if worker.status == "offline" {
                    return Err(t_fmt(
                        lang,
                        FmtKey::FlashWorkerOfflineInit,
                        &[&id.to_string()],
                    ));
                }
                if let Err(mismatch) =
                    ensure_init_arch_compatible(&app, id, &worker.arch, product).await
                {
                    return Err(t_fmt(
                        lang,
                        FmtKey::FlashInitConflictArch,
                        &[
                            &id.to_string(),
                            &mismatch.worker_arch,
                            product,
                            &mismatch.arches.join(", "),
                        ],
                    ));
                }
                let assignment_id = app
                    .state_store
                    .try_assign_init_to_worker(id, product)
                    .await
                    .map_err(|e| storage_error_flash("assign init", &e))?
                    .map_err(|conflict| match conflict {
                        InitConflict::Building(n) => t_fmt(
                            lang,
                            FmtKey::FlashInitConflictBuilding,
                            &[&id.to_string(), &n.to_string(), product],
                        ),
                        InitConflict::AlreadyActive => t_fmt(
                            lang,
                            FmtKey::FlashInitConflictActive,
                            &[&id.to_string(), product],
                        ),
                    })?;
                crate::server::worker::dispatch::notify_workers(&app, Some(id)).await;
                Ok(WorkerActionResult::InitDispatched {
                    worker_name: worker.name,
                    product: product.to_string(),
                    assignment_id,
                })
            }
            other => Err(t_fmt(lang, FmtKey::FlashUnknownWorkerAction, &[other])),
        }
    }
    .await;
    match result {
        Ok(WorkerActionResult::Rotated {
            worker_name,
            secret,
        }) => {
            let nonce = generate_nonce()?;
            let body = html! {
                h1 { (t(lang, TextKey::WorkerSecretRotated)) }
                p { (t_fmt(lang, FmtKey::WorkerLabel, &[&worker_name])) }
                (secret_reveal_box(&secret, &nonce, lang))
                p { a href=(format!("/ui/workers/{}", id)) { "← " (t(lang, TextKey::BackToWorker)) } }
            };
            let page = page_with_csp(
                t(lang, TextKey::AdminWorkerSecretTitle),
                &nonce,
                auth.as_ref().map(|ext| &ext.0),
                "workers",
                &headers,
                &app.csrf_key,
                body,
            )?;
            // 明文 secret 只展示一次，禁止任何缓存存储。
            Ok(no_store(page))
        }
        Ok(WorkerActionResult::Revoked) => {
            see_other_redirect(&format!("/ui/workers/{}?status=secret_revoked", id))
        }
        Ok(WorkerActionResult::InitDispatched {
            worker_name,
            product,
            assignment_id,
        }) => {
            // detail 与 API init_worker 同结构，保证审计口径一致。
            let detail = serde_json::json!({
                "worker_id": id,
                "worker_name": worker_name,
                "product": product,
                "assignment_id": assignment_id,
            })
            .to_string();
            let _ = app
                .state_store
                .audit_log(
                    &ctx.user,
                    &ctx.role,
                    "init_base_os",
                    Some(&id.to_string()),
                    Some(&detail),
                )
                .await;
            tracing::info!(
                worker_id = %id,
                worker_name = %worker_name,
                product = %product,
                assignment_id = %assignment_id,
                user = %ctx.user,
                "Init base_os dispatched via UI"
            );
            see_other_redirect(&format!("/ui/workers/{}?status=init_dispatched", id))
        }
        Err(msg) => see_other_error_redirect(&format!("/ui/workers/{}", id), &msg, &app.csrf_key),
    }
}

pub(crate) async fn admin_worker_remove(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<CancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let ctx = require_admin_session(
        auth.as_ref().map(|ext| &ext.0),
        &headers,
        &form.csrf_token,
        &app.csrf_key,
    )?;
    let lang = lang_from_headers(&headers);
    // 走 worker::admin 共享核心（与 REST API /api/v1/workers/{id}/remove 同路径，审计与日志在共享函数内）。
    let result: Result<String, String> =
        crate::server::worker::admin::remove_worker(&app.state_store, &ctx.user, &ctx.role, id)
            .await
            .map_err(|e| worker_admin_error_to_flash(e, lang));
    match result {
        Ok(name) => see_other_redirect(&format!(
            "/ui/workers?status=worker_removed&name={}",
            urlencoding::encode(&name)
        )),
        Err(msg) => see_other_error_redirect(&format!("/ui/workers/{}", id), &msg, &app.csrf_key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Disk 列单元格：KB 绝对值文本（十进制），缺采样 / 非正值落 "—"（既有
    /// 缺采样惯例），无条形（无分母）。
    #[test]
    fn disk_telemetry_cell_formats_absolute_value() {
        let s = disk_telemetry_cell(Some(48_832_000)).into_string();
        assert!(s.contains("50.00 GB"), "{s}");
        assert!(!s.contains("load-bar"), "no bar without a denominator: {s}");

        for missing in [None, Some(0), Some(-1)] {
            let s = disk_telemetry_cell(missing).into_string();
            assert_eq!(s, "—", "{missing:?} must render dash");
        }
    }

    /// 能力 chips：置 1 位逐枚徽章、词序与位表一致；全 0 落 "—"。
    #[test]
    fn caps_chips_render_set_bits_only() {
        let s = caps_chips(crbs_core::RESOURCE_CAP_CGROUP_V2 | crbs_core::RESOURCE_CAP_IO_STAT)
            .into_string();
        assert!(s.contains(">cgroup v2<"), "{s}");
        assert!(s.contains(">io<"), "{s}");
        assert!(!s.contains(">peak<"), "{s}");
        assert!(!s.contains(">events<"), "{s}");
        assert!(!s.contains(">psi<"), "{s}");

        assert_eq!(caps_chips(0).into_string(), "—", "zero caps renders dash");

        // 位常量与词表一一对应（bit3 → io，防表序漂移）。
        let bits = resource_cap_bits();
        assert_eq!(bits[3], (crbs_core::RESOURCE_CAP_IO_STAT, "io"));
        assert_eq!(bits[4], (crbs_core::RESOURCE_CAP_PSI, "psi"));
    }
}
