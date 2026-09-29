// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次页（operator+）：列表 + 详情 + 取消。数据聚合复用 API 层
//! [`crate::server::routes::batches::batch_detail`]（同口径）；页面门槛与 API
//! `ensure_operator` 同谓词（网关外纵深防御）；取消走 POST 表单 + CSRF。

use std::sync::Arc;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::batches::{batch_detail, batch_summaries, BatchSummary};
use crate::server::routes::ui::components::{
    clickable_rows_script, count_chip, empty_state, generate_nonce, id_link, list_page_head,
    page_with_csp, see_other_error_redirect, see_other_redirect, status_message, StatusQuery,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, Lang, TextKey};
use crate::server::routes::ui::service::{csrf_token_for_request, require_csrf};
use crate::server::state::AppState;
use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::{html, Markup};
use serde::Deserialize;

use super::require_operator_page;

#[derive(Debug, Deserialize)]
pub(crate) struct BatchCancelForm {
    pub csrf_token: String,
}

pub(crate) async fn list_batches_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_operator_page(auth.as_ref().map(|ext| &ext.0))?;

    let rows = batch_summaries(&app, 50, 0).await?;
    let lang = lang_from_headers(&headers);
    let nonce = generate_nonce()?;

    let body = html! {
        (list_page_head(
            html! { (t(lang, TextKey::BatchesPageTitle)) " " (count_chip(rows.len())) },
            html! {},
            html! {},
        ))
        (status_message(&q, &app.csrf_key, lang))
        @if rows.is_empty() {
            (empty_state(t(lang, TextKey::BatchesEmptyTitle), t(lang, TextKey::BatchesEmptyHint)))
        } @else {
            div class="table-card" {
                table class="fixed" {
                    thead {
                        tr {
                            th class="num" { (t(lang, TextKey::ThId)) }
                            th { (t(lang, TextKey::ThProduct)) }
                            th { (t(lang, TextKey::ThStatus)) }
                            th { (t(lang, TextKey::BatchesProgress)) }
                            th class="num" { (t(lang, TextKey::ThTotal)) }
                            th class="num" { (t(lang, TextKey::ThCreated)) }
                        }
                    }
                    tbody {
                        @for row in &rows {
                            tr class="clickable-row" {
                                td class="num" { (id_link(format!("/ui/batches/{}", row.id), row.id)) }
                                td { (row.product) }
                                td { (batch_status_badge(&row.status, lang)) }
                                (progress_bar_cell(row.n_succeeded + row.n_failed + row.n_skipped + row.n_cancelled, row.total_items))
                                td class="num" { (row.total_items) }
                                td class="num" { (super::rel_time_lang(Some(&row.created_at), lang)) }
                            }
                        }
                    }
                }
            }
            (clickable_rows_script(&nonce))
        }
    };
    page_with_csp(
        t(lang, TextKey::BatchesPageTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "batches",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn batch_detail_page(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_operator_page(auth.as_ref().map(|ext| &ext.0))?;
    let detail = batch_detail(&app, id).await?;

    let lang = lang_from_headers(&headers);
    let nonce = generate_nonce()?;
    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let cancellable = matches!(
        detail.summary.status.as_str(),
        "preparing" | "planning" | "running"
    );

    let body = html! {
        (list_page_head(
            html! { (t(lang, TextKey::BatchesPageTitle)) " #" (detail.summary.id) " " (batch_status_badge(&detail.summary.status, lang)) },
            html! {
                span class="chips" {
                    span class="chip" { (detail.summary.product) }
                    span class="chip ellipsis" title=(detail.source_repo_url) { code { (detail.source_repo_url) } }
                    @if let Some(dist) = detail.dist.as_deref() {
                        span class="chip" { code { (dist) } }
                    }
                    span class="chip" { "on_failure=" (detail.on_failure) }
                    @if detail.force_all {
                        span class="chip" { "force-all" }
                    }
                }
            },
            // 在途批次的取消动作（operator 档 + CSRF；终态批次是历史账本）。
            html! {
                @if cancellable {
                    @if let Some(token) = csrf_token.as_ref() {
                        form method="post" action=(format!("/ui/batches/{}", detail.summary.id)) {
                            input type="hidden" name="csrf_token" value=(token);
                            button class="action-button danger" type="submit"
                                data-confirm=(t(lang, TextKey::BatchesCancelConfirm)) {
                                (t(lang, TextKey::BatchesCancel))
                            }
                        }
                    }
                }
            },
        ))
        (status_message(&q, &app.csrf_key, lang))

        section class="viz-panel" {
            h3 { (t(lang, TextKey::BatchesProgress)) }
            (batch_progress_bar(&detail.summary))
            div class="chips" {
                span class="chip" { (t(lang, TextKey::LegendSucceeded)) " " b { (detail.summary.n_succeeded) } }
                span class="chip" { (t(lang, TextKey::LegendFailed)) " " b { (detail.summary.n_failed) } }
                span class="chip" { (t(lang, TextKey::PhaseSkipped)) " " b { (detail.summary.n_skipped) } }
                span class="chip" { (t(lang, TextKey::LegendCancelled)) " " b { (detail.summary.n_cancelled) } }
                span class="chip" { (t(lang, TextKey::ThTotal)) " " b { (detail.summary.total_items) } }
            }
            @if let Some(notes) = detail.notes.as_deref().filter(|n| !n.is_empty()) {
                p class="viz-note" { (notes) }
            }
        }

        // 轮次时间线：每轮一行 + 终态计数柱（宽度=服务端整数百分比，无注入面）。
        div class="admin-section" {
            div class="section-heading" {
                h2 { (t(lang, TextKey::BatchesRounds)) }
                span class="spacer" { }
            }
            @if detail.rounds.is_empty() {
                // 零轮 = 零 item 批次（全部源包被增量跳过）或全准备期失败。
                p class="viz-note" { "—" }
            } @else {
                div class="table-card" {
                    table class="fixed" {
                        thead {
                            tr {
                                th class="num" { (t(lang, TextKey::BatchesRoundCol)) }
                                th class="num" { (t(lang, TextKey::ThTotal)) }
                                th { (t(lang, TextKey::LegendSucceeded)) }
                                th { (t(lang, TextKey::LegendFailed)) }
                                th { (t(lang, TextKey::PhaseSkipped)) }
                                th { (t(lang, TextKey::LegendCancelled)) }
                                th { (t(lang, TextKey::BatchesProgress)) }
                            }
                        }
                        tbody {
                            @for r in &detail.rounds {
                                tr {
                                    td class="num" { (r.round) }
                                    td class="num" { (r.total) }
                                    td class="num" { (r.succeeded) }
                                    td class="num" { (r.failed) }
                                    td class="num" { (r.skipped) }
                                    td class="num" { (r.cancelled) }
                                    (round_bar_cell(r.succeeded + r.failed + r.skipped + r.cancelled, r.total))
                                }
                            }
                        }
                    }
                }
            }
        }

        // 失败分桶卡：error_code 计数 + 样例消息（服务端已截断 200 字符）。
        div class="admin-section" {
            div class="section-heading" {
                h2 { (t(lang, TextKey::BatchesFailures)) }
                span class="spacer" { }
            }
            @if detail.failures.is_empty() {
                (empty_state(t(lang, TextKey::BatchesNoFailures), ""))
            } @else {
                div class="table-card" {
                    table class="fixed" {
                        thead {
                            tr {
                                th { "error_code" }
                                th class="num" { (t(lang, TextKey::ThTotal)) }
                                th { (t(lang, TextKey::ThDetails)) }
                            }
                        }
                        tbody {
                            @for f in &detail.failures {
                                tr {
                                    td { code { (f.error_code) } }
                                    td class="num" { (f.count) }
                                    td class="ellipsis" title=(f.sample) { (f.sample) }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
    page_with_csp(
        t(lang, TextKey::BatchesPageTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        "batches",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn cancel_batch_submit(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<BatchCancelForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    // CSRF 先验，再过 operator 门槛（GC 触发同序）。
    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;
    require_operator_page(auth_ref)?;
    let operator = auth_ref.map(|c| c.user.clone()).unwrap_or_default();

    let back = format!("/ui/batches/{id}");
    match crate::server::batches::cancel_batch(&app, id, &operator).await {
        Ok(()) => see_other_redirect(&format!("{back}?status=batch_cancelled")),
        Err(e) => see_other_error_redirect(&back, e.message(), &app.csrf_key),
    }
}

/// 批次状态徽章（build_batches.status 域 → 双语显示名 + 语义色）。
fn batch_status_badge(status: &str, lang: Lang) -> Markup {
    let (class, label) = match status {
        "preparing" => ("badge queued", t(lang, TextKey::BatchStPreparing)),
        "planning" => ("badge queued", t(lang, TextKey::BatchStPlanning)),
        "running" => ("badge running", t(lang, TextKey::BatchStRunning)),
        "completed" => ("badge success", t(lang, TextKey::BatchStCompleted)),
        "partial" => ("badge warn", t(lang, TextKey::BatchStPartial)),
        "failed" => ("badge failure", t(lang, TextKey::BatchStFailed)),
        "cancelled" => ("badge failure", t(lang, TextKey::BatchStCancelled)),
        other => ("badge", other),
    };
    html! { span class=(class) { (label) } }
}

/// 批次概览进度条：终态计数 / total（0 项批次显示 "—"，避免除零）。
fn batch_progress_bar(summary: &BatchSummary) -> Markup {
    let done = summary.n_succeeded + summary.n_failed + summary.n_skipped + summary.n_cancelled;
    if summary.total_items <= 0 {
        return html! { p class="viz-note" { "—" } };
    }
    let pct = (done * 100 / summary.total_items).clamp(0, 100);
    html! {
        div class="load-bar" {
            i style=(format!("width:{pct}%")) { }
        }
        p class="viz-note" { (done) " / " (summary.total_items) " (" (pct) "%)" }
    }
}

fn progress_bar_cell(done: i64, total: i64) -> Markup {
    if total <= 0 {
        return html! { td class="num" { "—" } };
    }
    let pct = (done * 100 / total).clamp(0, 100) as usize;
    html! {
        td {
            div class="load-bar" { i style=(format!("width:{pct}%")) { } }
        }
    }
}

fn round_bar_cell(done: usize, total: usize) -> Markup {
    if total == 0 {
        return html! { td class="num" { "—" } };
    }
    let pct = (done * 100 / total).clamp(0, 100);
    html! {
        td {
            div class="load-bar" { i style=(format!("width:{pct}%")) { } }
            " " (done) "/" (total)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(status: &str, total: i64, done: i64) -> BatchSummary {
        BatchSummary {
            id: 1,
            product: "p".into(),
            status: status.into(),
            total_items: total,
            n_succeeded: done,
            n_failed: 0,
            n_skipped: 0,
            n_cancelled: 0,
            created_at: "2026-09-18 00:00:00".into(),
            finished_at: None,
        }
    }

    /// 徽章：七个状态域全覆盖（未知状态原样透传）。
    #[test]
    fn batch_status_badge_covers_all_statuses() {
        for s in [
            "preparing",
            "planning",
            "running",
            "completed",
            "partial",
            "failed",
            "cancelled",
        ] {
            let m = batch_status_badge(s, Lang::En).into_string();
            assert!(m.contains("badge"), "{s}: {m}");
        }
        assert!(batch_status_badge("weird", Lang::En)
            .into_string()
            .contains("weird"));
        assert!(batch_status_badge("completed", Lang::Zh)
            .into_string()
            .contains("已完成"));
    }

    /// 进度：0 项批次不除零；正常比例换算 + 钳 100%。
    #[test]
    fn progress_handles_zero_total_and_clamps() {
        assert!(batch_progress_bar(&summary("running", 0, 0))
            .into_string()
            .contains("—"));
        let m = batch_progress_bar(&summary("running", 4, 1)).into_string();
        assert!(m.contains("width:25%"), "{m}");
        assert!(m.contains("1 / 4"), "{m}");
        let m = batch_progress_bar(&summary("running", 2, 5)).into_string();
        assert!(m.contains("width:100%"), "{m}");
    }

    #[test]
    fn bar_cells_render_dash_or_bar() {
        assert_eq!(
            progress_bar_cell(0, 0).into_string(),
            r#"<td class="num">—</td>"#
        );
        assert!(progress_bar_cell(1, 4).into_string().contains("width:25%"));
        assert!(round_bar_cell(3, 4).into_string().contains("3/4"));
    }

    /// 守卫语义锁定：匿名 401、非 operator 403、operator 放行（gc/admin 页守卫同型）。
    #[test]
    fn operator_page_guard_rejects_anonymous_and_underprivileged() {
        assert!(matches!(
            require_operator_page(None),
            Err(ApiError::Unauthorized(_))
        ));
        let builder = AuthContext {
            role: "builder".into(),
            ..Default::default()
        };
        assert!(matches!(
            require_operator_page(Some(&builder)),
            Err(ApiError::PermissionDenied(_))
        ));
        let operator = AuthContext {
            role: "operator".into(),
            ..Default::default()
        };
        assert!(require_operator_page(Some(&operator)).is_ok());
    }
}
