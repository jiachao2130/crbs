// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 复现率看板（`/ui/reproducibility`）：verdict 分布 + 按产品小表 + 复现记录
//! （三级 drill-down：重放任务组 → 构建对 → 逐包差异），SSR 直渲无图表库无 JS。
//! 分母口径（单一事实源在 crbs-core `reproducibility.rs` 模块头）：复现率 = same /
//! (same + diff + build_failed)，dep_unavailable / infra_error 单列展示不进分母；
//! 聚合 JSON 编程消费走 `GET /api/v1/reproducibility/stats`。看板/记录口径只计
//! `kind='replay'`（cross_arch_noarch 观测行不入板）。
//! 窗口修剪警示：DB 行级 retention 级联删除超期 `build_reproducibility` 行——长窗口
//! 占比是"现存行"而非"曾发生事件"口径（schema.sql 表注同理）。

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use maud::{html, Markup};

use crate::server::auth::visibility::compute_visible_products;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::{empty_state, generate_nonce, id_link, page_with_csp};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::state::AppState;

use super::rel_time_lang;

use crate::server::routes::{REPLAY_GROUP_LIMIT, REPRO_DEFAULT_WINDOW_DAYS as DEFAULT_WINDOW_DAYS};

/// 窗口 chip 数据（days；None = 全部时间）。标签与 URL 恒由 days 派生
///（[`window_label`]：数字窗口不译，"all" 走 ReproWindowAll；`days=all` ↔ None）。
const WINDOWS: [Option<i64>; 4] = [Some(7), Some(30), Some(90), None];

/// 窗口 chip 可见标签：数字窗口 "{n}d"，全部时间复用 ReproWindowAll（不新增 key）。
fn window_label(days: Option<i64>, lang: Lang) -> String {
    match days {
        Some(d) => format!("{d}d"),
        None => t(lang, TextKey::ReproWindowAll).to_string(),
    }
}

/// `?days=` 解析（UI 宽松语义）：缺省 30 天；`all`/`0` = 全部时间；非法值回退缺省，不 400。
fn parse_window_days(raw: Option<&str>) -> Option<i64> {
    let Some(raw) = raw else {
        return Some(DEFAULT_WINDOW_DAYS);
    };
    if raw == "all" {
        return None;
    }
    match raw.parse::<i64>() {
        Ok(n) if (0..=crbs_core::MAX_STATS_DAYS).contains(&n) => {
            if n == 0 {
                None
            } else {
                Some(n)
            }
        }
        _ => Some(DEFAULT_WINDOW_DAYS),
    }
}

/// 复现率 = same / (same + diff + build_failed) 四舍五入取整；分母 0 → None（渲染 "—"，不伪装 0%）。
pub(crate) fn reproduce_rate(totals: &BTreeMap<String, i64>) -> Option<u64> {
    let get = |k: &str| totals.get(k).copied().unwrap_or(0);
    rate_parts(get("same"), get("diff"), get("build_failed")).0
}

/// 复现率算术单点：分母 = same+diff+build_failed，零分母 None；返回 (率, 分母)。
/// 看板头部、汇总面板与产品行三处口径同源。
fn rate_parts(same: i64, diff: i64, build_failed: i64) -> (Option<u64>, i64) {
    let denominator = same + diff + build_failed;
    let rate = (denominator > 0).then(|| (same as f64 * 100.0 / denominator as f64).round() as u64);
    (rate, denominator)
}

/// verdict 三档语义色：same=success，diff/build_failed=danger 域，其余=基础设施
/// warning 域；返回 (分布条 class, 徽章 class)——两族字面量同域不同名。
fn verdict_tone(verdict: &str) -> (&'static str, &'static str) {
    match verdict {
        "same" => ("success", "success"),
        "diff" | "build_failed" => ("danger", "failure"),
        _ => ("warning", "warn"),
    }
}

/// verdict 分布水平条（workers 面板 `.arch-row` 同款视觉语言），条宽 = 占全部比对行
/// 百分比；配色承载判定语义：same=success，diff/build_failed=danger，其余=warning（基础设施域）。
pub(crate) fn verdict_bars(totals: &BTreeMap<String, i64>, lang: Lang) -> Markup {
    let grand_total: i64 = totals.values().sum();
    let rows = crbs_core::ALL_VERDICTS.iter().map(|v| {
        let count = totals.get(v.as_str()).copied().unwrap_or(0);
        let (tone, _) = verdict_tone(v.as_str());
        let width = if grand_total > 0 && count > 0 {
            ((count as f64 * 100.0 / grand_total as f64).round() as u64).max(1)
        } else {
            0
        };
        html! {
            div class=(format!("arch-row verdict-row verdict-{tone}")) {
                span class="a" { (v.as_str()) }
                @if count > 0 {
                    span class="bar" { i style=(format!("width:{width}%")) { } }
                } @else {
                    span class="bar bar-empty" { }
                }
                span class="n" { (count) }
            }
        }
    });
    if grand_total == 0 {
        empty_state(
            t(lang, TextKey::EmptyReproTitle),
            t(lang, TextKey::EmptyReproHint),
        )
    } else {
        html! { @for row in rows { (row) } }
    }
}

/// 日桶趋势微图（stats API `series` 的页面消费）：每桶一列，列高 = 当日比对总数，
/// 三段按 verdict 配色堆叠（与分布条同契约）；桶稀疏不零填充；桶 >60 取尾部采样（显示预算，窄屏不挤出）。
fn repro_series_chart(series: &[crbs_core::ReproSeriesBucket], lang: Lang) -> Markup {
    const MAX_BUCKETS: usize = 60;
    let view: &[crbs_core::ReproSeriesBucket] = if series.len() > MAX_BUCKETS {
        &series[series.len() - MAX_BUCKETS..]
    } else {
        series
    };
    if view.is_empty() {
        return html! {
            div class="repro-series-empty" { (t(lang, TextKey::ReproSeriesEmpty)) }
        };
    }
    let max_total = view
        .iter()
        .map(|b| b.counts.values().sum::<i64>())
        .max()
        .unwrap_or(0);
    let aria = t(lang, TextKey::ReproSeriesAria).to_string();
    html! {
        div class="repro-series" role="img" aria-label=(aria) {
            @for b in view {
                @let total: i64 = b.counts.values().sum();
                @let height_pct = if max_total > 0 {
                    ((total as f64 / max_total as f64) * 100.0).round() as u64
                } else {
                    0
                };
                @let same = b.counts.get("same").copied().unwrap_or(0);
                @let diff = b.counts.get("diff").copied().unwrap_or(0);
                @let failed = b.counts.get("build_failed").copied().unwrap_or(0);
                @let other = b.counts.get("dep_unavailable").copied().unwrap_or(0)
                    + b.counts.get("infra_error").copied().unwrap_or(0);
                div class="repro-series-col"
                    title=(format!("{bucket}: same {s} / diff {d} / failed {f} / other {o}",
                        bucket = b.bucket, s = same, d = diff, f = failed, o = other)) {
                    div class="repro-series-bar" style=(format!("height:{height_pct}%")) {
                        @if same > 0 { i class="seg-success" style=(format!("flex:{same}")) { } }
                        @if diff > 0 { i class="seg-danger" style=(format!("flex:{diff}")) { } }
                        @if failed > 0 { i class="seg-danger" style=(format!("flex:{failed}")) { } }
                        @if other > 0 { i class="seg-warning" style=(format!("flex:{other}")) { } }
                    }
                }
            }
        }
    }
}

/// 按产品小表的一行聚合（verdict 计数收成列，rate 按分母口径现算）。
pub(crate) struct ProductReproRow {
    pub product: String,
    pub same: i64,
    pub diff: i64,
    pub build_failed: i64,
    /// dep_unavailable + infra_error（基础设施域，单列不进分母）。
    pub other: i64,
    pub total: i64,
}

impl ProductReproRow {
    pub(crate) fn rate(&self) -> Option<u64> {
        rate_parts(self.same, self.diff, self.build_failed).0
    }
}

/// product × verdict 聚合行 → 按产品收行（产品字典序）。
pub(crate) fn product_rows(by_product: &[crbs_core::ProductVerdictCount]) -> Vec<ProductReproRow> {
    let folded = crbs_core::fold_product_counts(by_product);
    folded
        .into_iter()
        .map(|(product, verdicts)| {
            let get = |k: &str| verdicts.get(k).copied().unwrap_or(0);
            let same = get("same");
            let diff = get("diff");
            let build_failed = get("build_failed");
            let other = get("dep_unavailable") + get("infra_error");
            ProductReproRow {
                product,
                same,
                diff,
                build_failed,
                other,
                total: same + diff + build_failed + other,
            }
        })
        .collect()
}

/// 窗口 chips：选中态双通道——`aria-current`（语义）+ `.active` class
///（样式，style.css `.section-heading a.active`）；可见标签经 [`window_label`]。
fn window_chips(current: Option<i64>, lang: Lang) -> Markup {
    html! {
        div class="section-heading" {
            span class="spacer" { }
            @for days in WINDOWS {
                @let active = days == current;
                a.active[active] href=(window_href(days))
                    aria-current=[active.then_some("true")] {
                    (window_label(days, lang))
                }
                " "
            }
        }
    }
}

fn window_href(days: Option<i64>) -> String {
    match days {
        None => "/ui/reproducibility?days=all".to_string(),
        Some(d) => format!("/ui/reproducibility?days={d}"),
    }
}

// ===== 复现记录三级 drill-down（纯 SSR `<details>` 折叠，无 JS）=====
//
// 一级 = 重放任务组（重放任务一组，replay 构建已删的孤儿组按源构建，分组
// 语义见 crbs-core fold_replay_groups；最近比对倒序，上限 [`REPLAY_GROUP_LIMIT`]
// 组）；全一致组不可展开，只占一行"全部一致"徽章。
// 二级 = 构建对（源构建 ↔ 重放构建）。三级 = 逐包差异表（默认只列 diff 与
// 单侧缺失/缺锚，一致的包收进折叠行）。

/// verdict 徽章（tone 与分布条同语义：same=success、diff/build_failed=danger、
/// 其余=基础设施 warning 域）；文本保留 CHECK 域机器串。
fn verdict_badge(verdict: &str) -> Markup {
    let (_, tone) = verdict_tone(verdict);
    html! { span class=(format!("badge {tone}")) { (verdict) } }
}

/// 单包差异形态徽章（diff=danger，单侧缺失/缺锚=warning 域）。
fn pkg_badge(key: TextKey, lang: Lang) -> Markup {
    let tone = match key {
        TextKey::ReproBadgeDiff => "failure",
        _ => "warn",
    };
    html! { span class=(format!("badge {tone}")) { (t(lang, key)) } }
}

/// sha256 短形（8 位 hex，title 挂全量；非 hex 短串原样透传）。
fn hash_cell(sha: Option<&str>) -> Markup {
    match sha {
        Some(s) => html! { code title=(s) { (s.get(..8).unwrap_or(s)) } },
        None => html! { "—" },
    }
}

/// 组头源包名展示上限：去重列表超出部分截断为 "+N"（title 挂全量）。
const PKG_NAMES_SHOW: usize = 3;

/// 一级组行内容（展开 summary 与全一致平铺行共用）：产品、源包名（组内去重
/// 列表）、双侧任务链接（tasks.rs 血缘行同款 "task N" 形态）、架构、verdict
/// 汇总、最近比对。
fn group_head(g: &crbs_core::ReproReplayGroup, lang: Lang) -> Markup {
    let same = g.verdicts.get("same").copied().unwrap_or(0);
    let total: i64 = g.verdicts.values().sum();
    let shown = g.pkg_names.len().min(PKG_NAMES_SHOW);
    let pkg_rest = g.pkg_names.len() - shown;
    let pkg_label = g.pkg_names[..shown].join(" ");
    html! {
        span class="rg-product" {
            a href=(format!("/ui/builds?product={}", urlencoding::encode(&g.product))) { (g.product) }
        }
        span class="rg-pkg" title=(g.pkg_names.join(" ")) {
            (pkg_label)
            @if pkg_rest > 0 { (format!(" +{pkg_rest}")) }
        }
        span class="rg-tasks" {
            @if let Some(st) = g.source_task_id {
                a href=(format!("/ui/tasks/{st}")) { (format!("task {st}")) }
            } @else {
                "—"
            }
            span class="sep" { "→" }
            @if let Some(rt) = g.replay_task_id {
                a href=(format!("/ui/tasks/{rt}")) { (format!("task {rt}")) }
            } @else {
                "—"
            }
        }
        span class="rg-arches" { (g.arches.join(" ")) }
        span class="rg-verdicts" {
            @if same == total {
                span class="badge success" { (t(lang, TextKey::ReproAllSame)) }
            } @else {
                (t_fmt(
                    lang,
                    FmtKey::ReproGroupConsistentFmt,
                    &[&same.to_string(), &total.to_string()],
                ))
                @for v in crbs_core::ALL_VERDICTS {
                    @let n = g.verdicts.get(v.as_str()).copied().unwrap_or(0);
                    @if n > 0 && v.as_str() != "same" {
                        (verdict_badge(v.as_str()))
                        span class="rg-count" { "×" (n) }
                    }
                }
            }
        }
        span class="rg-time" { (rel_time_lang(Some(&g.latest_compared_at), lang)) }
    }
}

/// 三级单包表：默认只列 diff / 单侧缺失 / 缺锚；一致的包收进二级折叠行
///（`<details>` 嵌套，显示一致的 N 个）。detail 缺失/解析失败降级为占位行。
fn package_tables(detail: Option<&crbs_core::CompareDetail>, lang: Lang) -> Markup {
    let Some(d) = detail else {
        return html! { p class="rp-note" { "—" } };
    };
    let mut attention: Vec<Markup> = Vec::new();
    let mut same: Vec<&crbs_core::RpmCompareEntry> = Vec::new();
    for e in &d.rpm {
        let badge = match (e.source_sha256.as_deref(), e.replay_sha256.as_deref()) {
            (Some(s), Some(r)) if s == r => {
                same.push(e);
                continue;
            }
            (Some(_), Some(_)) => TextKey::ReproBadgeDiff,
            // 任一侧缺 unsigned 锚（含重放失败 pseudo 行之外的缺口行）。
            _ => TextKey::ReproBadgeNoAnchor,
        };
        attention.push(html! {
            tr {
                td { (e.file) " " (pkg_badge(badge, lang)) }
                td { (hash_cell(e.source_sha256.as_deref())) }
                td { (hash_cell(e.replay_sha256.as_deref())) }
            }
        });
    }
    for f in &d.only_in_source {
        attention.push(html! {
            tr {
                td { (f) " " (pkg_badge(TextKey::ReproBadgeOnlySource, lang)) }
                td { (hash_cell(None)) }
                td { (hash_cell(None)) }
            }
        });
    }
    for f in &d.only_in_replay {
        attention.push(html! {
            tr {
                td { (f) " " (pkg_badge(TextKey::ReproBadgeOnlyReplay, lang)) }
                td { (hash_cell(None)) }
                td { (hash_cell(None)) }
            }
        });
    }
    // 无 rpm 条目对应的缺锚披露项（失败重放的 pseudo 诊断行走错误摘要分支，
    // 不会到这里；此处兜住历史行孤儿项）。
    for f in &d.missing_unsigned {
        if d.rpm.iter().any(|e| &e.file == f) {
            continue;
        }
        attention.push(html! {
            tr {
                td { (f) " " (pkg_badge(TextKey::ReproBadgeNoAnchor, lang)) }
                td { (hash_cell(None)) }
                td { (hash_cell(None)) }
            }
        });
    }
    let table_head = html! {
        thead {
            tr {
                th { (t(lang, TextKey::ThPackage)) }
                th { (t(lang, TextKey::ThSourceBuild)) }
                th { (t(lang, TextKey::ThReplayBuild)) }
            }
        }
    };
    html! {
        div class="repro-pkgs" {
            @if attention.is_empty() && same.is_empty() {
                p class="rp-note" { "—" }
            } @else {
                table class="repro-pkg-table" {
                    (table_head)
                    tbody {
                        @for row in &attention {
                            (row)
                        }
                    }
                }
                @if !same.is_empty() {
                    details class="repro-same-pkgs" {
                        summary {
                            (t_fmt(lang, FmtKey::ReproSamePkgsFmt, &[&same.len().to_string()]))
                        }
                        table class="repro-pkg-table" {
                            (table_head)
                            tbody {
                                @for e in &same {
                                    tr {
                                        td { (e.file) }
                                        td { (hash_cell(e.source_sha256.as_deref())) }
                                        td { (hash_cell(e.replay_sha256.as_deref())) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 二级构建对 + 三级单包：`<details>` 嵌套；detail_json 宽容解析（历史行缺
/// 字段走空默认），坏行降级为占位不炸页面。重放失败对（detail 带
/// replay_phase/replay_error）以错误摘要 + 分类代替 RPM 表——其
/// missing_unsigned 是诊断文本而非包名。
fn replay_pair(pair: &crbs_core::ReproReplayRow, lang: Lang) -> Markup {
    let extra = pair
        .detail_json
        .as_deref()
        .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok());
    let detail: Option<crbs_core::CompareDetail> = extra
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()).unwrap_or_default());
    let extra_str_field = |k: &str| {
        extra
            .as_ref()
            .and_then(|v| v.get(k).and_then(|x| x.as_str()))
            .map(str::to_string)
    };
    let replay_error = extra_str_field("replay_error");
    let replay_phase = extra_str_field("replay_phase");
    let classification = extra_str_field("classification");
    let failed_replay = replay_error.is_some() || replay_phase.is_some();
    let diff_pkgs = detail.as_ref().map(|d| d.attention_count());

    html! {
        details class="repro-pair" {
            summary class="rp-head" {
                span class="rp-arch" { (pair.replay_arch.as_deref().unwrap_or("—")) }
                (verdict_badge(&pair.verdict))
                @if let Some(n) = diff_pkgs {
                    @if !failed_replay {
                        span class="rp-diffcount" {
                            (t(lang, TextKey::ThDiffPkgs)) " " (n)
                        }
                    }
                }
                span class="rp-builds" {
                    (id_link(format!("/ui/builds/{}", pair.source_build_id), pair.source_build_id))
                    span class="sep" { "→" }
                    @if let Some(rb) = pair.replay_build_id {
                        (id_link(format!("/ui/builds/{rb}"), rb))
                    } @else {
                        "—"
                    }
                }
            }
            div class="rp-body" {
                @if failed_replay {
                    @if let Some(err) = &replay_error {
                        p class="rp-error" { (err) }
                    } @else if let Some(ph) = &replay_phase {
                        p class="rp-error" { (ph) }
                    }
                } @else {
                    (package_tables(detail.as_ref(), lang))
                }
                @if let Some(cls) = &classification {
                    p class="rp-note" { "classification: " (cls) }
                }
            }
        }
    }
}

/// 复现记录列表主体：一级组按可展开/全一致平铺二分渲染。
fn replay_records(groups: &[crbs_core::ReproReplayGroup], lang: Lang) -> Markup {
    html! {
        div class="repro-groups" {
            @for g in groups {
                @let expandable = !g.all_same();
                @if expandable {
                    details class="repro-group" {
                        summary class="rg-head" { (group_head(g, lang)) }
                        div class="repro-pairs" {
                            @for pair in &g.pairs {
                                (replay_pair(pair, lang))
                            }
                        }
                    }
                } @else {
                    div class="repro-group rg-flat" { (group_head(g, lang)) }
                }
            }
        }
    }
}

pub(crate) async fn reproducibility_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, ApiError> {
    // 内部质量观测面，不进公开访问面：认证开启时匿名一律 401；auth 关闭的本地
    // 形态放行。数据随后按产品可见性过滤（builder 仅见自己产品）。
    if app.server_config.auth_enabled {
        auth.as_ref()
            .map(|ext| &ext.0)
            .ok_or_else(|| ApiError::Unauthorized("this page requires authentication".into()))?;
    }
    let lang = lang_from_headers(&headers);
    let auth_ctx = auth.as_ref().map(|ext| &ext.0);
    let days = parse_window_days(params.get("days").map(String::as_str));

    let visible = compute_visible_products(&app, auth_ctx).await?;
    let visible = visible.as_deref();

    let by_kind = app
        .state_store
        .reproducibility_verdict_counts(visible, days)
        .await
        .map_err(ApiError::from)?;
    let totals = crbs_core::fold_verdict_totals(&by_kind);
    let by_product = app
        .state_store
        .reproducibility_counts_by_product(visible, days)
        .await
        .map_err(ApiError::from)?;
    let series = app
        .state_store
        .reproducibility_series(visible, days)
        .await
        .map_err(ApiError::from)?;
    let replay_groups = app
        .state_store
        .reproducibility_replay_groups(visible, days, REPLAY_GROUP_LIMIT)
        .await
        .map_err(ApiError::from)?;

    let nonce = generate_nonce()?;
    // 零比对行不显示比率（"—"/0% 皆误导），显示中性占位；比率仅在分母非空时出现。
    let rate_text = if by_product.is_empty() {
        t(lang, TextKey::ReproBoardEmpty).to_string()
    } else {
        reproduce_rate(&totals)
            .map(|r| format!("{r}%"))
            .unwrap_or_else(|| "—".to_string())
    };
    // 徽章分母绝对数与 rate 同源（same+diff+build_failed）：孤立百分比缺基线。
    let get = |k: &str| totals.get(k).copied().unwrap_or(0);
    let rate_denominator = rate_parts(get("same"), get("diff"), get("build_failed")).1;
    let same_count = totals.get("same").copied().unwrap_or(0);

    let body = html! {
        h1 { (t(lang, TextKey::NavRepro)) }
        (window_chips(days, lang))
        @if days.map(|d| d >= 90).unwrap_or(true) {
            div class="viz-note" { (t(lang, TextKey::ReproRetentionWarning)) }
        }
        div class="viz-grid" {
            section class="viz-panel" {
                h3 {
                    (t(lang, TextKey::SectionReproSummary))
                    span class="hint-r" {
                        (t(lang, TextKey::ReproRateLabel)) " " b { (rate_text) }
                        @if rate_denominator > 0 {
                            " " span class="hint-r" { "(" (same_count) " / " (rate_denominator) ")" }
                        }
                    }
                }
                div class="repro-bars" { (verdict_bars(&totals, lang)) }
                h3 { (t(lang, TextKey::SectionReproTrend)) }
                (repro_series_chart(&series, lang))
                div class="viz-note" { (t(lang, TextKey::ReproDenominatorNote)) }
            }
            div class="right-col" {
                div class="viz-panel" {
                    h3 { (t(lang, TextKey::SectionReproByProduct)) }
                    div class="viz-fill" {
                        @if by_product.is_empty() {
                            (empty_state(
                                t(lang, TextKey::EmptyReproTitle),
                                t(lang, TextKey::EmptyReproHint),
                            ))
                        } @else {
                            div class="table-wrap" {
                                table {
                                    thead {
                                        tr {
                                            th { (t(lang, TextKey::ThProduct)) }
                                            th class="num" { (t(lang, TextKey::ThSame)) }
                                            th class="num" { (t(lang, TextKey::ThDiff)) }
                                            th class="num" { (t(lang, TextKey::ThBuildFailed)) }
                                            th class="num" title=(t(lang, TextKey::ThOtherHint)) { (t(lang, TextKey::ThOther)) }
                                            th class="num" { (t(lang, TextKey::ThTotal)) }
                                            th class="num" { (t(lang, TextKey::ThRate)) }
                                        }
                                    }
                                    tbody {
                                        @for row in product_rows(&by_product) {
                                            tr {
                                                td {
                                                    a href=(format!("/ui/builds?product={}", urlencoding::encode(&row.product))) { (row.product) }
                                                }
                                                td class="num" { (row.same) }
                                                td class="num" { (row.diff) }
                                                td class="num" { (row.build_failed) }
                                                td class="num" { (row.other) }
                                                td class="num" { (row.total) }
                                                td class="num" {
                                                    (row.rate().map(|r| r.to_string()).unwrap_or_else(|| "—".to_string()))
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        div class="section-heading" {
            h3 { (t(lang, TextKey::SectionReproReplays)) }
            span class="spacer" { }
            span class="hint-r" {
                (t_fmt(lang, FmtKey::ReproShowingLatest, &[&REPLAY_GROUP_LIMIT.to_string()]))
            }
        }
        @if replay_groups.is_empty() {
            (empty_state(t(lang, TextKey::EmptyReproTitle), t(lang, TextKey::EmptyReproHint)))
        } @else {
            (replay_records(&replay_groups, lang))
        }
    };
    page_with_csp(
        t(lang, TextKey::NavRepro),
        &nonce,
        auth_ctx,
        "reproducibility",
        &headers,
        &app.csrf_key,
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::AppState;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn totals(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn reproduce_rate_uses_denominator_semantics() {
        // 分母 = same + diff + build_failed：3/4 → 75%（dep/infra 不进分母）。
        let t = totals(&[
            ("same", 3),
            ("diff", 1),
            ("dep_unavailable", 9),
            ("infra_error", 9),
        ]);
        assert_eq!(reproduce_rate(&t), Some(75));
        // 全 same → 100%；四舍五入 2/3 → 67%。
        assert_eq!(reproduce_rate(&totals(&[("same", 5)])), Some(100));
        let t = totals(&[("same", 2), ("diff", 1)]);
        assert_eq!(reproduce_rate(&t), Some(67));
        // 分母为 0（含只有 dep/infra 的窗口）→ None。
        assert_eq!(reproduce_rate(&totals(&[])), None);
        let t = totals(&[("dep_unavailable", 4), ("infra_error", 1)]);
        assert_eq!(reproduce_rate(&t), None);
    }

    #[test]
    fn product_rows_fold_columns_and_rate() {
        let rows = product_rows(&[
            crbs_core::ProductVerdictCount {
                product: "p".into(),
                verdict: "same".into(),
                count: 2,
            },
            crbs_core::ProductVerdictCount {
                product: "p".into(),
                verdict: "infra_error".into(),
                count: 5,
            },
            crbs_core::ProductVerdictCount {
                product: "p".into(),
                verdict: "dep_unavailable".into(),
                count: 1,
            },
        ]);
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.same, 2);
        assert_eq!(r.other, 6, "dep + infra 合入 other 列");
        assert_eq!(r.total, 8);
        assert_eq!(r.rate(), Some(100), "分母只计 same+diff+build_failed");
    }

    #[test]
    fn window_param_lenient_parsing() {
        assert_eq!(parse_window_days(None), Some(30));
        assert_eq!(parse_window_days(Some("7")), Some(7));
        assert_eq!(parse_window_days(Some("all")), None);
        assert_eq!(parse_window_days(Some("0")), None);
        assert_eq!(parse_window_days(Some("nonsense")), Some(30), "宽松回退");
        assert_eq!(parse_window_days(Some("-5")), Some(30));
    }

    /// 组头源包名列表：≤3 个全显（空格连接），超过 3 个截断为前 3 + "+N"（title 挂全量）。
    #[test]
    fn group_head_pkg_names_dedup_list_truncation() {
        let group = |pkg_names: &[&str]| crbs_core::ReproReplayGroup {
            replay_task_id: Some(1),
            source_task_id: Some(1),
            product: "p".into(),
            pkg_name: pkg_names[0].into(),
            pkg_names: pkg_names.iter().map(|s| s.to_string()).collect(),
            latest_compared_at: "2026-01-01 00:00:00".into(),
            arches: vec![],
            verdicts: BTreeMap::from([("same".to_string(), 1)]),
            pairs: vec![],
        };
        let two = group_head(&group(&["a", "b"]), Lang::En).into_string();
        assert!(two.contains(">a b</span>"), "{two}");
        let five = group_head(&group(&["a", "b", "c", "d", "e"]), Lang::En).into_string();
        assert!(five.contains(">a b c +2</span>"), "{five}");
        assert!(
            five.contains(r#"title="a b c d e""#),
            "full list stays in title: {five}"
        );
    }

    async fn test_app() -> (Arc<AppState>, tempfile::TempDir) {
        test_app_auth(false).await
    }

    async fn test_app_auth(auth_enabled: bool) -> (Arc<AppState>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let server_config = crbs_core::config::ServerConfig {
            auth_enabled,
            ..crbs_core::config::ServerConfig::default()
        };
        let app = Arc::new(AppState::for_test(
            store,
            server_config,
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    /// seed：task + 双 build + verdict 行（id 从 MAX+1 起，多次调用不串号）。
    async fn seed_repro_row(app: &AppState, product: &str, verdict: &str) -> (i64, i64) {
        seed_repro_row_with_detail(app, product, verdict, None).await
    }

    /// seed 变体：replay 行可带 detail_json（drill-down 三级内容的测试锚）。
    async fn seed_repro_row_with_detail(
        app: &AppState,
        product: &str,
        verdict: &str,
        detail: Option<&str>,
    ) -> (i64, i64) {
        let task_id = crate::test_support::seed_task(&app.state_store, product, "pkg").await;
        let base: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        for i in [base + 1, base + 2] {
            sqlx::query(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
                 VALUES ($1, $2, $3, 'succeeded', 'chroot', 'tester', $4)",
            )
            .bind(i)
            .bind(product)
            .bind(format!("pkg-1.0-{i}"))
            .bind(task_id)
            .execute(app.state_store.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict, detail_json) \
             VALUES ('replay', $1, $2, $3, $4)",
        )
        .bind(base + 1)
        .bind(base + 2)
        .bind(verdict)
        .bind(detail)
        .execute(app.state_store.pool())
        .await
        .unwrap();
        (base + 1, base + 2)
    }

    async fn render_page(app: Arc<AppState>, days: Option<&str>) -> String {
        render_page_with_headers(app, days, HeaderMap::new()).await
    }

    async fn render_page_with_headers(
        app: Arc<AppState>,
        days: Option<&str>,
        headers: HeaderMap,
    ) -> String {
        let mut params: HashMap<String, String> = HashMap::new();
        if let Some(d) = days {
            params.insert("days".to_string(), d.to_string());
        }
        // handler 返回 impl IntoResponse，into_response 统一取状态码与 body。
        let response = reproducibility_page(State(app), None, headers, Query(params))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn page_renders_summary_product_and_replay_sections() {
        let (app, _tmp) = test_app().await;
        let (source, replay) = seed_repro_row(&app, "test", "diff").await;
        seed_repro_row(&app, "test", "same").await;

        let html = render_page(app, None).await;
        assert!(html.contains("Comparison outcomes"), "{html}");
        assert!(html.contains("By product"), "{html}");
        assert!(html.contains("Replay records"), "{html}");
        // 五类 verdict 行恒在（缺数据为 0 行）。
        for verdict in crbs_core::ALL_VERDICTS {
            assert!(
                html.contains(&format!("<span class=\"a\">{}</span>", verdict.as_str())),
                "{html}"
            );
        }
        // diff 组可展开：组内构建对双侧构建页链接 + 源包名 + 任务链接。
        assert!(html.contains(&format!("/ui/builds/{source}")), "{html}");
        assert!(html.contains(&format!("/ui/builds/{replay}")), "{html}");
        assert!(html.contains(&format!("pkg-1.0-{source}")), "{html}");
        assert!(html.contains("/ui/tasks/"), "{html}");
        assert!(html.contains("test"), "{html}");
        assert!(html.contains(">Rate<"), "{html}");
    }

    /// 全一致组不可展开（用户要求一致不过多显示）：无 `<details>` 组、
    /// 只占一行"全部一致"徽章。
    #[tokio::test]
    async fn page_all_same_group_is_flat_badge_row() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "test", "same").await;

        let html = render_page(app, None).await;
        assert!(!html.contains("<details class=\"repro-group\""), "{html}");
        assert!(html.contains("All consistent"), "{html}");
    }

    /// 三级 drill-down：diff 组 `<details>` 展开 → 构建对 → 逐包表（默认只列
    /// diff/单侧缺失/缺锚，一致的包收进折叠行）；kind=cross_arch 行不入板。
    #[tokio::test]
    async fn page_replay_group_drill_down_levels() {
        let (app, _tmp) = test_app().await;
        let src_sha = "aaaa1111".repeat(8);
        let rpl_sha = "bbbb2222".repeat(8);
        let same_sha = "cccc3333".repeat(8);
        let detail = serde_json::json!({
            "classification": "diff",
            "rpm": [
                { "file": "hello-1.0-1.noarch.rpm",
                  "source_sha256": src_sha,
                  "replay_sha256": rpl_sha },
                { "file": "same-1.0-1.noarch.rpm",
                  "source_sha256": same_sha,
                  "replay_sha256": same_sha },
                { "file": "same2-1.0-1.noarch.rpm",
                  "source_sha256": same_sha,
                  "replay_sha256": same_sha },
            ],
            "only_in_source": ["gone-1.0-1.noarch.rpm"],
        })
        .to_string();
        let (source, replay) =
            seed_repro_row_with_detail(&app, "test", "diff", Some(&detail)).await;
        // 观测面行：cross_arch diff 不得出现在复现记录列表。
        sqlx::query(
            "INSERT INTO build_reproducibility (kind, source_build_id, verdict) \
             VALUES ('cross_arch_noarch', $1, 'diff')",
        )
        .bind(source)
        .execute(app.state_store.pool())
        .await
        .unwrap();

        let html = render_page(app, None).await;
        assert!(html.contains("<details class=\"repro-group\""), "{html}");
        // 一级组行：一致占比（0/1）+ 双任务链接。
        assert!(html.contains("0/1 consistent"), "{html}");
        assert!(html.contains(">task "), "{html}");
        // 二级构建对：双侧构建链接 + 需关注包计数（attention = diff/单侧缺失/缺锚）。
        assert!(html.contains(&format!("/ui/builds/{source}")), "{html}");
        assert!(html.contains(&format!("/ui/builds/{replay}")), "{html}");
        assert!(html.contains("Needs attention"), "{html}");
        // 三级单包：差异包默认展开列出（文件名 + 8 位短哈希），一致的包折叠。
        assert!(html.contains("hello-1.0-1.noarch.rpm"), "{html}");
        assert!(html.contains("gone-1.0-1.noarch.rpm"), "{html}");
        assert!(html.contains("only in source"), "{html}");
        assert!(html.contains("aaaa1111"), "{html}");
        assert!(html.contains("2 identical packages"), "{html}");
        assert!(
            html.contains("<details class=\"repro-same-pkgs\""),
            "{html}"
        );
        // cross_arch 行的观测内容不入板（该 kind 的判定只落在 replay 行）。
        assert!(!html.contains("cross_arch_noarch"), "{html}");
    }

    /// build_failed 构建对展开显示错误摘要与分类，代替 RPM 表（pseudo
    /// missing_unsigned 是诊断文本非包名）。
    #[tokio::test]
    async fn page_failed_replay_pair_shows_error_summary() {
        let (app, _tmp) = test_app().await;
        let detail = serde_json::json!({
            "classification": "build_failed",
            "rpm": [],
            "missing_unsigned": ["replay build terminal phase 'failed': no artifacts compared"],
            "replay_phase": "failed",
            "replay_error": "script /crbs-build.sh failed: exit_code=Some(1)",
        })
        .to_string();
        seed_repro_row_with_detail(&app, "test", "build_failed", Some(&detail)).await;

        let html = render_page(app, None).await;
        assert!(html.contains("<details class=\"repro-group\""), "{html}");
        assert!(
            html.contains("script /crbs-build.sh failed: exit_code=Some(1)"),
            "{html}"
        );
        assert!(html.contains("classification: build_failed"), "{html}");
        assert!(
            !html.contains("no artifacts compared"),
            "pseudo diagnostic line must not render as a package row: {html}"
        );
    }

    #[tokio::test]
    async fn page_empty_state_when_no_rows() {
        let (app, _tmp) = test_app().await;
        let html = render_page(app, Some("7")).await;
        assert!(html.contains("No comparisons recorded"), "{html}");
        // 分布/产品表/diff 清单三面板各一份 empty-state 卡。
        assert_eq!(html.matches(r#"class="empty-state""#).count(), 3, "{html}");
    }

    /// 空序列走兜底文案（防御臂：series 与 totals 同窗口理论上不同时空，仍不得 panic）。
    #[test]
    fn repro_series_chart_renders_stacked_columns() {
        let lang = Lang::En;
        let mut counts = std::collections::BTreeMap::new();
        counts.insert("same".to_string(), 3);
        counts.insert("diff".to_string(), 1);
        let buckets = vec![crbs_core::ReproSeriesBucket {
            bucket: "2026-09-20".to_string(),
            counts,
        }];
        let html = repro_series_chart(&buckets, lang).into_string();
        assert!(html.contains("repro-series-col"), "{html}");
        assert!(html.contains("seg-success"), "{html}");
        assert!(html.contains("seg-danger"), "{html}");
        assert!(html.contains("same 3 / diff 1"), "{html}");
        assert!(html.contains("2026-09-20"), "{html}");

        let empty = repro_series_chart(&[], lang).into_string();
        assert!(empty.contains("repro-series-empty"), "{empty}");
    }

    /// 产品名下钻链接（builds 页 product 过滤器），URL 编码防注入。
    #[tokio::test]
    async fn page_product_rows_link_to_builds_filter() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "test", "same").await;
        let html = render_page(app, Some("7")).await;
        assert!(
            html.contains(r#"<a href="/ui/builds?product=test">test</a>"#),
            "{html}"
        );
    }

    #[tokio::test]
    async fn page_window_chip_selected_state_dual_channel() {
        let (app, _tmp) = test_app().await;
        let html = render_page(app, Some("7")).await;
        assert!(
            html.contains(
                r#"<a class="active" href="/ui/reproducibility?days=7" aria-current="true">7d</a>"#
            ),
            "{html}"
        );
        // 非当前 chip：maud 条件 class 语法渲染空 class（nav 同款），无 active/aria-current。
        assert!(
            html.contains(r#"<a class="" href="/ui/reproducibility?days=30">30d</a>"#),
            "{html}"
        );
        // 整页恰一个 aria-current="true"（nav 当前项是 aria-current="page"，不撞值）。
        assert_eq!(html.matches(r#"aria-current="true""#).count(), 1, "{html}");
    }

    /// zh 页产品表列头与 "all" chip 可见标签本地化；verdict 分布条与复现记录
    /// 的 verdict 徽章是 CHECK 域标识符（机器串），保留原样。
    #[tokio::test]
    async fn page_zh_localizes_product_columns_and_all_chip() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "test", "diff").await;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT_LANGUAGE,
            "zh-CN,zh;q=0.9".parse().unwrap(),
        );
        let html = render_page_with_headers(app, Some("all"), headers).await;
        for zh in ["相同", "差异", "构建失败", "其他"] {
            assert!(
                html.contains(zh),
                "column head must be localized: {zh}\n{html}"
            );
        }
        assert!(
            html.contains("全部时间"),
            "all chip label localized: {html}"
        );
        assert!(
            !html.contains(">all</a>"),
            "raw 'all' visible label must be gone: {html}"
        );
        assert!(html.contains("<span class=\"a\">same</span>"), "{html}");
    }

    /// 匿名可见性：私有产品的行不渲染进看板（孤儿豁免口径同任务列表）。
    #[tokio::test]
    async fn page_filters_private_products_for_anonymous() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "publicp", "same").await;
        seed_repro_row(&app, "secretp", "diff").await;
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(app.state_store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json, owner_id) \
             VALUES ('secretp', 'private', '{}', 1)",
        )
        .execute(app.state_store.pool())
        .await
        .unwrap();

        let html = render_page(app, Some("all")).await;
        assert!(html.contains("publicp"), "{html}");
        assert!(
            !html.contains("secretp"),
            "private product must not leak: {html}"
        );
    }
}
