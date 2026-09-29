// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! GC 管理页（operator+）：表单字段与 API `GcRequest` 布尔标志一一对应
//!（dry-run 默认勾选），POST 复用 `gc::start_gc_task` 同一入队路径（303 回
//! 本页 flash）；历史任务在内存 `AppState.gc_tasks`，重启即失（页面注明）。

use std::sync::Arc;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::gc::{start_gc_task, GcRequest};
use crate::server::routes::ui::components::{
    count_chip, empty_state, generate_nonce, list_page_head, page_with_csp,
    see_other_error_redirect, see_other_redirect, status_message, StatusQuery,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::service::{csrf_token_for_request, require_csrf};
use crate::server::state::{AppState, GcTask, GcTaskStatus};
use axum::extract::{Extension, Form, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::{html, Markup};
use serde::Deserialize;

/// GC 触发表单。checkbox 未勾选时字段整体缺席，靠 `#[serde(default)]` 落 false。
#[derive(Debug, Deserialize)]
pub(crate) struct GcTriggerForm {
    pub csrf_token: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub results: bool,
    #[serde(default)]
    pub orphan_mounts: bool,
    #[serde(default)]
    pub cache: bool,
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub policy: bool,
    /// 可选产品过滤（空串视为未设置）。
    pub product: Option<String>,
}

use super::require_operator_page;

pub(crate) async fn gc_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(q): Query<StatusQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_operator_page(auth.as_ref().map(|ext| &ext.0))?;

    // 整条 GcTask 带走：Duration 列要用 finished_at。
    let mut tasks: Vec<(String, GcTask)> = {
        let map = app.gc_tasks.lock().await;
        map.iter().map(|(id, t)| (id.clone(), t.clone())).collect()
    };
    tasks.sort_by_key(|(_, t)| std::cmp::Reverse(t.started_at));

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(&headers);
    let body = html! {
        (list_page_head(
            html! { (t(lang, TextKey::GcPageTitle)) " " (count_chip(tasks.len())) },
            html! {},
            html! {},
        ))
        (status_message(&q, &app.csrf_key, lang))
        section class="viz-panel" {
            h3 { (t(lang, TextKey::GcTrigger)) }
            // 破坏性提示：默认可见（无 JS 时 fail-safe）；勾选 dry-run 时由脚本隐藏。
            div class="message warning" id="gc-destructive-warning" {
                (t(lang, TextKey::GcDestructiveWarning))
            }
            @if let Some(token) = csrf_token.as_ref() {
                form method="post" action="/ui/admin/gc" {
                    input type="hidden" name="csrf_token" value=(token);
                    // dry-run 主开关：label 包住 checkbox，无 JS 也可切换。
                    label class="dryrun-row" {
                        span class="switch" {
                            input type="checkbox" name="dry_run" value="true" checked;
                            i { }
                        }
                        span {
                            span class="dryrun-title" { (t(lang, TextKey::GcDryRun)) }
                            span class="dryrun-desc" {
                                (t(lang, TextKey::GcDryRunDesc))
                            }
                        }
                    }
                    div class="gc-options" {
                        label class="gc-opt" {
                            input type="checkbox" name="results" value="true";
                            span {
                                span class="t" { (t(lang, TextKey::GcOptResults)) }
                                span class="d" { (t(lang, TextKey::GcOptResultsDesc)) }
                            }
                        }
                        label class="gc-opt" {
                            input type="checkbox" name="orphan_mounts" value="true";
                            span {
                                span class="t" { (t(lang, TextKey::GcOptMounts)) }
                                span class="d" { (t(lang, TextKey::GcOptMountsDesc)) }
                            }
                        }
                        label class="gc-opt" {
                            input type="checkbox" name="cache" value="true";
                            span {
                                span class="t" { (t(lang, TextKey::GcOptCache)) }
                                span class="d" { (t(lang, TextKey::GcOptCacheDesc)) }
                            }
                        }
                        label class="gc-opt" {
                            input type="checkbox" name="policy" value="true";
                            span {
                                span class="t" { (t(lang, TextKey::GcOptPolicy)) }
                                span class="d" { (t(lang, TextKey::GcOptPolicyDesc)) }
                            }
                        }
                        // all 非全选别名：cache+all 走 gc_package_cache_all，清空整个缓存
                        // 且不做引用检查（活跃构建在用 RPM 也会删）；validate 要求配 cache。
                        label class="gc-opt" {
                            input type="checkbox" name="all" value="true";
                            span {
                                span class="t" { (t(lang, TextKey::GcOptAll)) }
                                span class="d" { (t(lang, TextKey::GcOptAllDesc)) }
                            }
                        }
                    }
                    div class="gc-submit-row" {
                        // product 过滤：可选（空 = 全部），仅对 results/policy 有意义。
                        input type="text" name="product" placeholder=(t(lang, TextKey::GcProductPlaceholder));
                        span class="spacer" { }
                        // SSR 无 JS 安全方向：danger "Run GC" + data-confirm（dry-run 默认
                        // 勾选，误确认只多跑一次 dry-run）；脚本随开关切主色 "Dry run" 并摘确认。
                        button class="action-button danger" type="submit" id="gc-submit-btn"
                            data-confirm=(t(lang, TextKey::GcRunConfirm)) { (t(lang, TextKey::GcRun)) }
                        span class="gc-hint" { (t(lang, TextKey::GcRunHint)) }
                    }
                }
                (gc_dryrun_warning_script(&nonce, lang))
            } @else {
                p { (t(lang, TextKey::SettingsSessionExpired)) " " a href="/ui/login" { (t(lang, TextKey::ErrLoginCta)) } }
            }
        }
        div class="admin-section" {
            div class="section-heading" {
                h2 { (t(lang, TextKey::GcRecentTasks)) }
                span class="spacer" { }
                span class="viz-note" { (t(lang, TextKey::GcHistoryNote)) }
            }
            @if tasks.is_empty() {
                (empty_state(t(lang, TextKey::EmptyGcTitle), t(lang, TextKey::EmptyGcHint)))
            } @else {
                div class="table-card" {
                    table class="fixed" {
                        // Details 列是 chips 组合：不加 .ellipsis（换行显示，不截断）。
                        colgroup {
                            col style="width:17%" {}
                            col style="width:9%" {}
                            col style="width:13%" {}
                            col style="width:auto" {}
                            col style="width:11%" {}
                        }
                        thead {
                            tr {
                                th class="num" { (t(lang, TextKey::ThStarted)) }
                                th class="num" { (t(lang, TextKey::LabelTask)) }
                                th { (t(lang, TextKey::ThStatus)) }
                                th { (t(lang, TextKey::ThDetails)) }
                                th class="num" { (t(lang, TextKey::LabelDuration)) }
                            }
                        }
                        tbody {
                            @for (id, task) in &tasks {
                                tr {
                                    td class="num" { (super::rel_time_lang(Some(&task.started_at.format(crbs_core::util::DB_TIME_FMT).to_string()), lang)) }
                                    td class="num ellipsis" title=(id) { code { (short_gc_task_id(id)) } }
                                    td { (gc_status_badge(&task.status, lang)) }
                                    td { (gc_summary_chips(&task.status, lang)) }
                                    (gc_duration_cell(&task.started_at, task.finished_at.as_ref()))
                                }
                            }
                        }
                    }
                }
            }
        }
        details class="help" {
            summary { (t(lang, TextKey::GcHelpTitle)) }
            p {
                (t(lang, TextKey::GcHelpP1))
            }
            p {
                // 中英语序一致：strong 固定强调 Dry run 一词。
                (t(lang, TextKey::GcHelpWith)) " " strong { (t(lang, TextKey::GcDryRun)) } " " (t(lang, TextKey::GcHelpCheckedTail))
            }
        }
    };
    page_with_csp(
        t(lang, TextKey::AdminGcPageTitle),
        &nonce,
        auth.as_ref().map(|ext| &ext.0),
        // 独立 nav 键：与 Admin（/ui/admin）区分，避免双高亮（见 components::page）。
        "gc",
        &headers,
        &app.csrf_key,
        body,
    )
}

pub(crate) async fn gc_trigger_post(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<GcTriggerForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;
    let ctx = require_operator_page(auth_ref)?;

    let req = GcRequest {
        dry_run: form.dry_run,
        results: form.results,
        product: form
            .product
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        orphan_mounts: form.orphan_mounts,
        cache: form.cache,
        all: form.all,
        policy: form.policy,
    };

    let lang = lang_from_headers(&headers);
    let product = req.product.clone();
    match start_gc_task(&app, Some(ctx), req).await {
        // 与 API 同路径异步入队：立即 303 回本页，结果看历史表。
        Ok(_task_id) => see_other_redirect("/ui/admin/gc?status=gc_started"),
        Err(e) => see_other_error_redirect(
            "/ui/admin/gc",
            &gc_error_flash(&e, product.as_deref(), lang),
            &app.csrf_key,
        ),
    }
}

/// GC 触发失败（[`start_gc_task`] 的错误）→ 按页面语言本地化的 flash 文案。
/// 可达错误：`validate_gc_request` 三条 scope 校验、core 产品名校验、并发锁
/// Conflict。scope 三条与产品名空串按仓库稳定字面量精确匹配；非法字符一条以
/// 调用方 product 作 {0}（能进 core 校验必非空）；未知文案回退英文原文。
fn gc_error_flash(e: &ApiError, product: Option<&str>, lang: Lang) -> String {
    match e {
        // start_gc_task 里唯一的 Conflict 源是并发信号量（"gc already running"）。
        ApiError::Conflict(_) => t(lang, TextKey::FlashGcAlreadyRunning).to_string(),
        ApiError::Validation(msg) => match msg.as_str() {
            "dry_run must be used with results, orphan_mounts, cache, or policy" => {
                t(lang, TextKey::FlashGcDryRunScope).to_string()
            }
            "product must be used with results or policy" => {
                t(lang, TextKey::FlashGcProductScope).to_string()
            }
            "all must be used with cache" => t(lang, TextKey::FlashGcAllScope).to_string(),
            "product name cannot be empty" => t(lang, TextKey::FlashProductNameEmpty).to_string(),
            // 其余 Validation 只可能是 core validate_product 的非法字符文案。
            _ => match product {
                Some(p) => t_fmt(lang, FmtKey::FlashProductNameInvalidCharsCore, &[p]),
                None => msg.clone(),
            },
        },
        other => other.message().to_string(),
    }
}

/// 历史表 Task 列短 id（uuid 全串放不下 9% 列宽），完整值靠单元格 title 悬停。
fn short_gc_task_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Duration 秒差：终态 `finished - started`（时钟回拨钳 0）；无 finished_at → None。
fn gc_duration_secs(
    started: &chrono::DateTime<chrono::Utc>,
    finished: Option<&chrono::DateTime<chrono::Utc>>,
) -> Option<i64> {
    Some((*finished? - *started).num_seconds().max(0))
}

/// Duration 单元格：终态真实时长；Running / 缺失 finished_at 保持 "—"。
fn gc_duration_cell(
    started: &chrono::DateTime<chrono::Utc>,
    finished: Option<&chrono::DateTime<chrono::Utc>>,
) -> maud::Markup {
    match gc_duration_secs(started, finished) {
        Some(secs) => html! { td class="num" { (super::format_duration_secs(secs)) } },
        None => html! { td class="num" { "—" } },
    }
}

/// dry-run 开关联动：勾选隐藏警示条、按钮切主色 "Dry run" 并摘
/// data-confirm，取消恢复；无 JS 时 SSR 保持 danger + 确认（安全方向）。
fn gc_dryrun_warning_script(nonce: &str, lang: Lang) -> Markup {
    let dry_run_label = crate::server::routes::ui::components::js_str(t(lang, TextKey::GcDryRun));
    let run_gc_label = crate::server::routes::ui::components::js_str(t(lang, TextKey::GcRun));
    html! {
        script nonce=(nonce) { (maud::PreEscaped(format!(r#"
            (function() {{
                var box = document.getElementById('gc-destructive-warning');
                var dry = document.querySelector('form input[name="dry_run"]');
                var btn = document.getElementById('gc-submit-btn');
                if (!dry) {{ return; }}
                var msg = btn ? btn.getAttribute('data-confirm') : null;
                function sync() {{
                    var dryOn = dry.checked;
                    if (box) {{ box.style.display = dryOn ? 'none' : ''; }}
                    if (btn) {{
                        btn.textContent = dryOn ? '{dry_run_label}' : '{run_gc_label}';
                        btn.classList.toggle('danger', !dryOn);
                        if (dryOn) {{ btn.removeAttribute('data-confirm'); }}
                        else if (msg) {{ btn.setAttribute('data-confirm', msg); }}
                    }}
                }}
                dry.addEventListener('change', sync);
                sync();
            }})();
        "#, dry_run_label = dry_run_label, run_gc_label = run_gc_label))) }
    }
}

/// GC 状态徽章：显示名复用 DonutRunning / t_phase 相位表（口径一致）。
fn gc_status_badge(status: &GcTaskStatus, lang: Lang) -> Markup {
    let (class, label) = match status {
        GcTaskStatus::Running => ("badge running", t(lang, TextKey::DonutRunning)),
        GcTaskStatus::Succeeded(_) => (
            "badge success",
            crate::server::routes::ui::i18n::t_phase(lang, "succeeded"),
        ),
        GcTaskStatus::Failed(_) => (
            "badge failure",
            crate::server::routes::ui::i18n::t_phase(lang, "failed"),
        ),
    };
    html! { span class=(class) { (label) } }
}

/// 终态任务统计 chips（一行事实一个 chip）；Running 显示 "—"，Failed 显示 error
/// chip（完整错误文本进 title）。字节用 humansize 十进制格式。
fn gc_summary_chips(status: &GcTaskStatus, lang: Lang) -> Markup {
    match status {
        GcTaskStatus::Running => html! { "—" },
        GcTaskStatus::Failed(msg) => html! {
            span class="chips" {
                span class="chip error" title=(msg) { (t(lang, TextKey::GcChipError)) (msg) }
            }
        },
        GcTaskStatus::Succeeded(summary) => {
            let mut dry = false;
            // 可回收/已回收字节（results + cache；mounts/layers 无字节统计）。
            let mut freed: u64 = 0;
            let mut chips: Vec<Markup> = Vec::new();
            if let Some(r) = &summary.results {
                dry = dry || r.would_remove > 0;
                freed += r.bytes;
                // dry-run 下 removed 恒 0、would_remove 计数（gc/results.rs 契约）。
                let count = if r.would_remove > 0 {
                    r.would_remove
                } else {
                    r.removed
                };
                chips.push(html! { span class="chip" { (t(lang, TextKey::GcChipResults)) " " b { (count) } } });
                if r.policy_removed > 0 {
                    chips.push(html! { span class="chip" { (t(lang, TextKey::GcChipPolicy)) " " b { (r.policy_removed) } } });
                }
            }
            if let Some(m) = &summary.orphan_mounts {
                dry = dry || m.dry_run;
                chips.push(html! {
                    span class="chip" title=(t(lang, TextKey::GcMountsTitle)) { (t(lang, TextKey::GcChipMounts)) " " b { (m.cleaned) } "/" (m.found) }
                });
            }
            if let Some(c) = &summary.package_cache {
                dry = dry || c.dry_run;
                freed += c.bytes;
                chips.push(html! {
                    span class="chip" {
                        (t(lang, TextKey::GcChipCache)) " " b { (humansize::format_size(c.bytes, humansize::DECIMAL)) }
                    }
                });
            }
            if let Some(l) = &summary.shared_layers {
                chips.push(html! { span class="chip" { (t(lang, TextKey::GcChipLayers)) " " b { (l.removed) } } });
            }
            if dry {
                chips.push(html! { span class="chip" { (t(lang, TextKey::GcChipDryRun)) } });
            }
            if freed > 0 {
                let label = if dry {
                    t(lang, TextKey::GcChipWouldFree)
                } else {
                    t(lang, TextKey::GcChipFreed)
                };
                chips.push(html! {
                    span class="chip" {
                        (label) " " b { (humansize::format_size(freed, humansize::DECIMAL)) }
                    }
                });
            }
            if chips.is_empty() {
                html! { (t(lang, TextKey::GcNothingToDo)) }
            } else {
                html! {
                    span class="chips" {
                        @for chip in chips { (chip) }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::routes::ui::i18n::Lang;
    use crbs_core::types::{
        GcOrphanMountsSummary, GcPackageCacheSummary, GcResultsSummary, GcSharedLayersSummary,
        GcSummary,
    };

    #[test]
    fn chips_render_one_chip_per_fact_with_freed_total() {
        let status = GcTaskStatus::Succeeded(GcSummary {
            results: Some(GcResultsSummary {
                removed: 3,
                would_remove: 0,
                bytes: 1_100_000_000,
                policy_removed: 0,
                skipped_latest: 0,
                skipped_missing: 0,
                skipped_invalid: 0,
                failed: 0,
                affected_products: Vec::new(),
            }),
            orphan_mounts: Some(GcOrphanMountsSummary {
                found: 3,
                cleaned: 2,
                removed_dirs: 0,
                dry_run: false,
            }),
            package_cache: Some(GcPackageCacheSummary {
                removed: 5,
                kept: 0,
                bytes: 2_100_000_000,
                lru_evicted: 0,
                lru_bytes: 0,
                dry_run: false,
                all: false,
            }),
            shared_layers: Some(GcSharedLayersSummary {
                removed: 1,
                stale_uppers: 0,
                stale_upper_bytes: 0,
                orphan_dirs_removed: 0,
            }),
        });
        let s = gc_summary_chips(&status, Lang::En).into_string();
        assert!(s.contains(r#"<span class="chips">"#), "{s}");
        assert!(s.contains("results <b>3</b>"), "{s}");
        assert!(s.contains("mounts <b>2</b>/3"), "{s}");
        assert!(s.contains("cache <b>2.10 GB</b>"), "{s}");
        assert!(s.contains("layers <b>1</b>"), "{s}");
        // freed = 1.1 GB + 2.1 GB；实跑无 dry-run chip。
        assert!(s.contains("freed <b>3.20 GB</b>"), "{s}");
        assert!(!s.contains("dry-run"), "{s}");
        assert!(!s.contains("would free"), "{s}");

        let s = gc_summary_chips(&status, Lang::Zh).into_string();
        assert!(s.contains("已释放 <b>3.20 GB</b>"), "{s}");
        assert!(s.contains("结果 <b>3</b>"), "{s}");
    }

    #[test]
    fn chips_mark_dry_run_and_would_free() {
        let status = GcTaskStatus::Succeeded(GcSummary {
            results: Some(GcResultsSummary {
                removed: 0,
                would_remove: 7,
                bytes: 500_000_000,
                policy_removed: 0,
                skipped_latest: 0,
                skipped_missing: 0,
                skipped_invalid: 0,
                failed: 0,
                affected_products: Vec::new(),
            }),
            orphan_mounts: Some(GcOrphanMountsSummary {
                found: 1,
                cleaned: 0,
                removed_dirs: 0,
                dry_run: true,
            }),
            package_cache: None,
            shared_layers: None,
        });
        let s = gc_summary_chips(&status, Lang::En).into_string();
        // dry-run 下计数用 would_remove，并出现 dry-run / would free chip。
        assert!(s.contains("results <b>7</b>"), "{s}");
        assert!(s.contains(">dry-run<"), "{s}");
        assert!(s.contains("would free <b>500 MB</b>"), "{s}");
        assert!(!s.contains("freed <"), "{s}");
    }

    #[test]
    fn chips_failed_renders_error_chip_and_running_dash() {
        let s = gc_summary_chips(&GcTaskStatus::Failed("result dir busy".into()), Lang::En)
            .into_string();
        assert!(s.contains(r#"class="chip error""#), "{s}");
        assert!(s.contains("error: result dir busy"), "{s}");

        assert_eq!(
            gc_summary_chips(&GcTaskStatus::Running, Lang::En).into_string(),
            "—"
        );

        let empty = gc_summary_chips(&GcTaskStatus::Succeeded(GcSummary::default()), Lang::En)
            .into_string();
        assert_eq!(empty, "nothing to do");

        assert!(
            gc_status_badge(&GcTaskStatus::Succeeded(GcSummary::default()), Lang::Zh)
                .into_string()
                .contains("成功")
        );
        assert!(gc_status_badge(&GcTaskStatus::Failed("x".into()), Lang::Zh)
            .into_string()
            .contains("失败"));
    }

    #[test]
    fn short_gc_task_id_truncates_uuid_prefix() {
        assert_eq!(short_gc_task_id("01234567-89ab-cdef"), "01234567");
        assert_eq!(short_gc_task_id("short"), "short");
    }

    #[test]
    fn gc_duration_secs_covers_three_states() {
        let started = chrono::Utc::now();
        assert_eq!(
            gc_duration_secs(&started, Some(&(started + chrono::TimeDelta::seconds(90)))),
            Some(90)
        );
        assert_eq!(gc_duration_secs(&started, None), None);
        // 时钟回拨：finished < started 钳 0。
        assert_eq!(
            gc_duration_secs(&started, Some(&(started - chrono::TimeDelta::seconds(30)))),
            Some(0)
        );
    }

    #[test]
    fn gc_duration_cell_renders_duration_or_dash() {
        let started = chrono::Utc::now();
        assert_eq!(
            gc_duration_cell(&started, Some(&(started + chrono::TimeDelta::seconds(90))))
                .into_string(),
            r#"<td class="num">1m 30s</td>"#
        );
        assert_eq!(
            gc_duration_cell(&started, None).into_string(),
            r#"<td class="num">—</td>"#
        );
    }
}
