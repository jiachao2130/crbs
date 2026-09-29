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
    format_duration_secs, phase_counts_from_series, rel_time_lang, success_rate_gauge,
    SUCCESS_RATE_WINDOW,
};
use crate::server::auth::visibility::compute_visible_products;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::health::compute_public_status;
use crate::server::routes::tasks::{list_tasks_for_user, TaskListResponse};
use crate::server::routes::ui::components::{
    clickable_rows_script, dashboard_sse_script, donut_chart, empty_state, gauge_chart,
    generate_nonce, load_level, page_with_csp, phase_badge, stat_strip, ChartSegment,
    StatStripItem,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, priority_label, t, t_fmt, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::service::{check_public_access, QueryParams};
use crate::server::state::AppState;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::{html, Markup};
use std::sync::Arc;

const HOME_RECENT_TASKS: usize = 20;

/// 系统条磁盘健康线（显示层判断）：剩余 ≥ 10 GB 视为健康标绿（.ok）。
const DISK_OK_GB: f64 = 10.0;

pub(crate) async fn home_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let auth_ctx = auth.as_ref().map(|ext| &ext.0);
    // 样板页：文案全走 t()/t_fmt()，chrome 层由 page() 同一提取函数处理，两侧一致。
    let lang = lang_from_headers(&headers);
    let status = compute_public_status(&app, auth_ctx).await?;

    // 成功率可见性口径同 compute_public_status——operator/admin 全量，其余按可见产品 +
    // 孤儿豁免，私有产品成功率不外泄；相位序列只取一次（gauge 分母含全窗相位），静态不进 SSE。
    let visible = compute_visible_products(&app, auth_ctx).await?;
    let series = app
        .state_store
        .recent_task_phase_series(visible.as_deref(), SUCCESS_RATE_WINDOW)
        .await
        .map_err(ApiError::from)?;
    let recent_counts = phase_counts_from_series(&series);
    let (success_pct, gauge_side) = success_rate_gauge(&recent_counts, lang);

    // 系统条：服务端门控（非 CSS 隐藏），比 /api/v1/metrics 更严——metrics 对本地
    // 开发的无 AuthContext 请求放行，UI 匿名同为 None，须已认证且 operator+ 才渲染。
    let system_strip = if auth_ctx.is_some_and(|a| a.is_operator()) {
        Some(render_system_strip(&app, lang).await?)
    } else {
        None
    };

    let workers_by_arch = app
        .state_store
        .count_workers_by_arch()
        .await
        .map_err(ApiError::from)?;
    // CPU 均值 chip：在线 worker 利用率（cpu_util_pct）均值；无遥测的架构不在结果中，不渲染 chip。
    let cpu_avg_by_arch: std::collections::HashMap<String, f64> = app
        .state_store
        .worker_arch_cpu_avg()
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .map(|r| (r.arch, r.cpu_avg))
        .collect();

    let filter = crbs_core::types::TaskListFilter {
        limit: Some(HOME_RECENT_TASKS),
        offset: Some(0),
        ..Default::default()
    };
    let resp = list_tasks_for_user(&app, filter, auth_ctx).await?;
    let nonce = generate_nonce()?;

    // donut 六段顺序配色；href 用 running→building、queued→pending 过滤参数映射。
    let phase_url = |phase: &'static str| {
        QueryParams {
            phase: Some(phase),
            ..Default::default()
        }
        .url("/ui/tasks", None)
    };
    let segments = [
        ChartSegment {
            phase: "running",
            label: t(lang, TextKey::LegendRunning),
            count: status.tasks.building,
            color: "var(--running)",
            href: phase_url("building"),
        },
        ChartSegment {
            phase: "queued",
            label: t(lang, TextKey::LegendQueued),
            count: status.tasks.pending,
            color: "var(--queued)",
            href: phase_url("pending"),
        },
        ChartSegment {
            phase: "succeeded",
            label: t(lang, TextKey::LegendSucceeded),
            count: status.tasks.succeeded,
            color: "var(--success)",
            href: phase_url("succeeded"),
        },
        ChartSegment {
            phase: "failed",
            label: t(lang, TextKey::LegendFailed),
            count: status.tasks.failed,
            color: "var(--danger)",
            href: phase_url("failed"),
        },
        ChartSegment {
            phase: "timeout",
            label: t(lang, TextKey::LegendTimeout),
            count: status.tasks.timeout,
            color: "var(--timeout)",
            href: phase_url("timeout"),
        },
        ChartSegment {
            phase: "cancelled",
            label: t(lang, TextKey::LegendCancelled),
            count: status.tasks.cancelled,
            color: "var(--fg-faint)",
            href: phase_url("cancelled"),
        },
    ];

    let body = html! {
        h1 {
            (t(lang, TextKey::NavDashboard))
            span class="live-indicator" title=(t(lang, TextKey::LiveUpdatesEnabled)) { }
        }
        // aria-live 收窄到随 SSE 更新的计数节点（donut 环心、图例行、workers 在线数）：
        // 整区 live 会让读屏器每次播报整个 viz-grid；region+aria-label 留作导航语义。
        div class="viz-grid" role="region" aria-label=(t(lang, TextKey::VizAriaSummary)) {
            section class="viz-panel" {
                h3 { (t(lang, TextKey::PanelTaskStates)) span class="hint-r" { (t(lang, TextKey::HintHoverClick)) } }
                div class="viz-fill" {
                    (donut_chart(
                        "dash",
                        &segments,
                        status.tasks.building,
                        status.tasks.pending,
                        t(lang, TextKey::DonutAriaLabel),
                        lang,
                    ))
                }
            }
            div class="right-col" {
                div class="viz-panel" {
                    h3 { (t(lang, TextKey::PanelSuccessRate)) }
                    div class="viz-fill" { (gauge_chart("dash", success_pct, gauge_side, lang)) }
                }
                div class="viz-panel" {
                    h3 {
                        (t(lang, TextKey::NavWorkers))
                        // span 只含数字：SSE 按 id 改写 textContent，单位词留在 span 外防覆盖；
                        // hint-r 是本面板唯一随 status 流更新的节点，aria-live 收窄至此。
                        span class="hint-r" aria-live="polite" {
                            span id="dash-workers-online" { (status.workers.online) }
                            " " (t(lang, TextKey::WorkersOnlineWord))
                        }
                    }
                    div class="viz-fill" {
                        div style="width:100%" {
                            @if workers_by_arch.is_empty() {
                                div class="viz-note" { (t(lang, TextKey::NoWorkersRegistered)) }
                            } @else {
                                @for w in &workers_by_arch {
                                    div class="arch-row" {
                                        span class="a" { (w.arch) }
                                        span class="bar" {
                                            i style=(format!(
                                                "width:{}%",
                                                (w.online as f64 * 100.0 / w.total as f64).round() as u64
                                            )) { }
                                        }
                                        span class="n" { (t_fmt(lang, FmtKey::ArchOnline, &[&w.online.to_string(), &w.total.to_string()])) }
                                        // CPU 利用率均值 chip（0-100）。
                                        @if let Some(avg) = cpu_avg_by_arch.get(&w.arch) {
                                            span class=(format!("badge {}", load_level(*avg))) title=(t(lang, TextKey::ArchCpuAvgTitle)) {
                                                (t_fmt(lang, FmtKey::ArchCpuAvg, &[&format!("{:.0}", avg)]))
                                            }
                                        }
                                    }
                                }
                                div class="viz-note" {
                                    (t(lang, TextKey::WorkersBarNote))
                                    a href="/ui/workers" { (t(lang, TextKey::ViewWorkers)) }
                                }
                            }
                        }
                    }
                }
            }
        }
        // Recent tasks 表随 SSE 换新：dashboard 脚本在 status 事件（10s 节流）
        // 拉取 /ui/home/recent-tasks 片段整体替换 #recent-tasks，消除"状态卡
        // 已变、最近任务仍是快照"的割裂；行点击经 clickable_rows_script 的
        // 全局绑定器重挂，不逐行挂 aria-live。
        div class="section-heading" {
            h3 { (t(lang, TextKey::SectionRecentTasks)) }
            span class="spacer" { }
            a href="/ui/tasks" { (t(lang, TextKey::ViewAllTasks)) }
        }
        div id="recent-tasks" { (recent_tasks_html(&resp, lang)) }
        // sys-strip 亦为静态 SSR 快照，不随 SSE 更新（磁盘查询刻意不进轮询，见 render_system_strip）。
        @if let Some(strip) = system_strip {
            (strip)
        }
        (clickable_rows_script(&nonce))
        (dashboard_sse_script(&nonce, lang))
    };
    page_with_csp(
        t(lang, TextKey::NavDashboard),
        &nonce,
        auth_ctx,
        "",
        &headers,
        &app.csrf_key,
        body,
    )
}

/// 最近任务区片段：首页 SSR 与 `/ui/home/recent-tasks` 片段路由同一渲染源，
/// dashboard 脚本 SSE 换新即整体替换 `#recent-tasks` 容器（含空态↔表格切换）。
fn recent_tasks_html(resp: &TaskListResponse, lang: Lang) -> Markup {
    if resp.tasks.is_empty() {
        empty_state(
            t(lang, TextKey::EmptyRecentTitle),
            t(lang, TextKey::EmptyRecentHint),
        )
    } else {
        html! {
            div class="table-wrap" {
                table class="fixed" {
                    // 列宽对齐 builds/tasks 列表密度；ID 列窄且左对齐（右对齐数字在窄列悬浮）。
                    colgroup {
                        col style="width:7%" {}
                        col style="width:13%" {}
                        col style="width:auto" {}
                        col style="width:14%" {}
                        col style="width:13%" {}
                        col style="width:17%" {}
                    }
                    thead {
                        tr {
                            th { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::ThProduct)) }
                            th { (t(lang, TextKey::ThPackage)) }
                            th { (t(lang, TextKey::ThPhase)) }
                            th { (t(lang, TextKey::ThUser)) }
                            th class="num" { (t(lang, TextKey::ThSubmitted)) }
                        }
                    }
                    tbody {
                        @for t in &resp.tasks {
                            tr class="clickable-row" {
                                td { (t.id) }
                                td { (t.product) }
                                // clickable_rows_script 跳行内首个 a.row-target，每行必须恰有一个。
                                td class="ellipsis" title=(t.pkg_name) {
                                    a class="row-target" href=(format!("/ui/tasks/{}", t.id)) { (t.pkg_name) }
                                }
                                td { (phase_badge(&t.phase, lang)) }
                                td { (t.user) }
                                td class="num" { (rel_time_lang(t.submitted_at.as_deref(), lang)) }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 首页最近任务片段（dashboard SSE 节流拉取目标）：可见性与首页同口径
/// （check_public_access + list_tasks_for_user 内部按可见产品过滤）。
pub(crate) async fn recent_tasks_fragment(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<Markup, ApiError> {
    check_public_access(
        &app,
        app.server_config.public_access.view,
        auth.as_ref().map(|ext| &ext.0),
    )?;
    let lang = lang_from_headers(&headers);
    let filter = crbs_core::types::TaskListFilter {
        limit: Some(HOME_RECENT_TASKS),
        offset: Some(0),
        ..Default::default()
    };
    let resp = list_tasks_for_user(&app, filter, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok(recent_tasks_html(&resp, lang))
}

/// 采集并渲染系统状态条（uptime / 并发 / 队列深度 / 磁盘可用）。
/// 数据源与 `/api/v1/metrics`（health.rs）一致，"并发"为集群口径（state.rs
/// 快照共源）；仅 operator+（调用方门控），静态输出不进 SSE 轮询——避免每
/// 2s 查磁盘。
async fn render_system_strip(app: &AppState, lang: Lang) -> Result<Markup, ApiError> {
    let uptime = format_duration_secs((chrono::Utc::now() - app.started_at).num_seconds());

    // 分母只计启用车道：auto = 本地槽 + 在线 worker 容量，单车道只计对应项。
    let snap = app.concurrency_snapshot().await.map_err(ApiError::from)?;
    let concurrency = format!("{}/{}", snap.total_active, snap.total_capacity);
    let concurrency_title = match app.server_config.scheduler_mode {
        crbs_core::config::SchedulerMode::Auto => t_fmt(
            lang,
            FmtKey::ConcurrencyTitleAuto,
            &[
                &snap.local_active.to_string(),
                &snap.local_slots.to_string(),
                &snap.distributed_active.to_string(),
                &snap.worker_capacity_online.to_string(),
            ],
        ),
        crbs_core::config::SchedulerMode::DistributedOnly => t_fmt(
            lang,
            FmtKey::ConcurrencyTitleDistributedOnly,
            &[&snap.worker_capacity_online.to_string()],
        ),
        crbs_core::config::SchedulerMode::LocalOnly => t_fmt(
            lang,
            FmtKey::ConcurrencyTitleLocalOnly,
            &[&snap.local_slots.to_string()],
        ),
    };

    let by_priority = app
        .state_store
        .count_pending_by_priority()
        .await
        .map_err(ApiError::from)?;
    let queued: i64 = by_priority.values().sum();
    let mut detail: Vec<_> = by_priority.iter().filter(|(_, c)| **c > 0).collect();
    detail.sort_by(|a, b| b.0.cmp(a.0));
    let queue_title = if detail.is_empty() {
        t(lang, TextKey::QueueNoPending).to_string()
    } else {
        detail
            .iter()
            .map(|(p, c)| {
                t_fmt(
                    lang,
                    FmtKey::QueuePriority,
                    &[&c.to_string(), &priority_label(lang, **p)],
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    // 磁盘查询走 spawn_blocking（health.rs 同款：available_space 是 syscall）。
    let crbs_root = app.crbs_root.clone();
    let available_bytes = tokio::task::spawn_blocking(move || fs4::available_space(&crbs_root))
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("spawn blocking disk check", e))?
        .map_err(|e| ApiError::log_and_internal_with_context("available_space", e))?;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let disk_gb = available_bytes as f64 / GB;

    let items = [
        StatStripItem {
            label: t(lang, TextKey::StatUptime),
            value: uptime,
            ok: false,
            title: None,
        },
        StatStripItem {
            label: t(lang, TextKey::StatQueue),
            value: queued.to_string(),
            ok: false,
            title: Some(queue_title),
        },
        StatStripItem {
            label: t(lang, TextKey::StatConcurrency),
            value: concurrency,
            ok: false,
            title: Some(concurrency_title),
        },
        StatStripItem {
            label: t(lang, TextKey::StatDiskAvailable),
            value: format!("{disk_gb:.1} GB"),
            ok: disk_gb >= DISK_OK_GB,
            title: None,
        },
    ];
    Ok(stat_strip(&items, lang))
}
