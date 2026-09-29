// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 可复用图表组件（donut / gauge / 时长条形图 / 状态信息条）。

use maud::{html, Markup};

use crate::server::routes::ui::i18n::{t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::pages::format_duration_secs;
use crbs_core::types::BuildDurationSample;

// ===== 可复用图表组件：`scope` 为组件 id 前缀（首页 "dash"），多页面复用同套组件不冲突 =====

/// 环形图（donut）的一段：一个 phase 的计数与跳转链接。
pub(crate) struct ChartSegment {
    /// phase 键（running/queued/succeeded/failed/timeout/cancelled），兼作 SSE / hover 联动的 `data-phase` 选择器契约。
    pub phase: &'static str,
    pub label: &'static str,
    pub count: i64,
    /// CSS 颜色令牌（如 `var(--running)`）。
    pub color: &'static str,
    /// 点击跳转目标（phase 过滤后的任务列表）。
    pub href: String,
}

/// donut 几何常量：R=81，C=2πR。
const DONUT_RADIUS: f64 = 81.0;
const DONUT_CIRCUMFERENCE: f64 = 2.0 * std::f64::consts::PI * DONUT_RADIUS;
/// 极小扇区保底可见弧占比（2%）；真实数值以图例 / title 为准。
const DONUT_MIN_FRAC: f64 = 0.02;

/// 各段 `(dasharray 长度, dashoffset)` 与总数：frac=n/total
///（total=0 → 0），n>0 且 frac<2% 保底 2%，总和超 1 从最大段扣回（防重叠）；offset 累计。
fn donut_arcs(counts: &[i64]) -> (Vec<(f64, f64)>, i64) {
    let total: i64 = counts.iter().sum();
    let mut fracs: Vec<f64> = counts
        .iter()
        .map(|&n| {
            let frac = if total > 0 {
                n as f64 / total as f64
            } else {
                0.0
            };
            if n > 0 && frac < DONUT_MIN_FRAC {
                DONUT_MIN_FRAC
            } else {
                frac
            }
        })
        .collect();
    let used: f64 = fracs.iter().sum();
    if used > 1.0 {
        let big_idx = (0..fracs.len())
            .max_by(|&a, &b| fracs[a].total_cmp(&fracs[b]))
            .unwrap_or(0);
        fracs[big_idx] -= used - 1.0;
    }
    let mut offset = 0.0;
    let arcs = fracs
        .into_iter()
        .map(|frac| {
            // -0.0 归一为 0.0，避免首段渲染出 dashoffset="-0.00"。
            let dashoffset = if offset == 0.0 {
                0.0
            } else {
                -offset * DONUT_CIRCUMFERENCE
            };
            offset += frac;
            (frac * DONUT_CIRCUMFERENCE, dashoffset)
        })
        .collect();
    (arcs, total)
}

/// 服务端渲染任务状态环形图：SVG 扇区（`circle.seg[data-phase]`，弧长 Rust 侧
/// 算好）+ 环心（总数/running/queued，id `{scope}-donut-*` 供 SSE 更新）+ 可点击图例
///（原生 title 带精确数值；环心单位词与图例 title 走 i18n，seg.label 由调用方经 t() 传入）。
/// 空态（total=0，全新安装）补中性满环 `circle.seg-empty`（--border 色令牌，同 gauge
/// `.track`）；首个任务经 SSE 到达时由脚本移除（见 [`dashboard_sse_script`]）；非空态不渲染。
pub(crate) fn donut_chart(
    scope: &str,
    segments: &[ChartSegment],
    running: i64,
    queued: i64,
    aria_label: &str,
    lang: Lang,
) -> Markup {
    let (arcs, total) = donut_arcs(&segments.iter().map(|s| s.count).collect::<Vec<_>>());
    html! {
        div class="donut-flex" {
            div class="donut-wrap" {
                svg class="donut" id=(format!("{scope}-donut")) width="205" height="205"
                    viewBox="0 0 205 205" role="img" aria-label=(aria_label) {
                    g transform="translate(102.5,102.5)" {
                        // 空态满环垫底（track 语义）；类名单独 seg-empty，不落 .seg 的 hover/dimmed 与 SSE 逐相改写。
                        @if total == 0 {
                            circle class="seg-empty" r=(DONUT_RADIUS) { }
                        }
                        @for (seg, (len, offset)) in segments.iter().zip(&arcs) {
                            circle class="seg" data-phase=(seg.phase) r=(DONUT_RADIUS)
                                stroke=(seg.color)
                                stroke-dasharray=(format!("{len:.2} {:.2}", DONUT_CIRCUMFERENCE - len))
                                stroke-dashoffset=(format!("{offset:.2}")) { }
                        }
                    }
                }
                // aria-live 只包环心计数块（total/running/queued 三个 SSE 改写目标 id）；扇区弧长是 SVG 属性，不播报。
                div class="donut-center" aria-live="polite" {
                    div class="big" id=(format!("{scope}-donut-total")) { (total) }
                    div class="sub" { (t(lang, TextKey::DonutSubTasks)) }
                    div class="active-row" {
                        b id=(format!("{scope}-donut-running")) { (running) } " " (t(lang, TextKey::DonutRunning))
                        br;
                        i id=(format!("{scope}-donut-queued")) { (queued) } " " (t(lang, TextKey::DonutQueued))
                    }
                }
            }
            div class="legend" {
                @for seg in segments {
                    // live 包行级：.count/.pct 随 status 流改写，播报整行上下文而非裸数字。
                    a class="legend-row" data-phase=(seg.phase) href=(seg.href)
                        aria-live="polite"
                        title=(donut_row_title(seg, total, lang)) {
                        span class="dot" style=(format!("background:{}", seg.color)) { }
                        span class="name" { (seg.label) }
                        span class="count" { (seg.count) }
                        span class="pct" { (donut_row_pct(seg.count, total)) }
                        span class="go" { "→" }
                    }
                }
            }
        }
    }
}

/// 图例行 / 扇区的原生 title："failed · 21 tasks · 10.1% — click to view list"
///（zh 同构）；英文复数单位词（task/tasks）作额外 arg 传入，zh 模板忽略。
fn donut_row_title(seg: &ChartSegment, total: i64, lang: Lang) -> String {
    let pct = if total > 0 {
        seg.count as f64 * 100.0 / total as f64
    } else {
        0.0
    };
    let plural = if seg.count == 1 { "task" } else { "tasks" };
    // 段名：En 用裸 phase 键，zh 用图例展示名（seg.label）——running/queued 是图表专属聚合键，不在 t_phase 相位表里。
    let seg_name = match lang {
        Lang::En => seg.phase,
        Lang::Zh => seg.label,
    };
    t_fmt(
        lang,
        FmtKey::DonutRowTitle,
        &[
            seg_name,
            &seg.count.to_string(),
            &format!("{pct:.1}"),
            plural,
        ],
    )
}

/// 图例百分比（四舍五入到整数，与 SSE 脚本 `Math.round` 口径一致）。
fn donut_row_pct(count: i64, total: i64) -> String {
    let pct = if total > 0 {
        (count as f64 * 100.0 / total as f64).round() as i64
    } else {
        0
    };
    format!("{pct}%")
}

/// gauge 几何常量：r=48，C=2πr。
const GAUGE_CIRCUMFERENCE: f64 = 2.0 * std::f64::consts::PI * 48.0;

/// 服务端渲染成功率环形仪表（静态 SSR，无 JS）。
/// `pct`：`Some(0-100)` 有样本——全失败也是 `Some(0)`：0% 空弧 + 中心 "0%"
///（对 0% 是合法几何，渲染不破）；`None` 无样本：空环 + 中心 "—" 占位。
/// 阈值换色：≥90 success / ≥70 warning / 其余（含 0）danger；`side_html` 为右侧口径说明。
pub(crate) fn gauge_chart(scope: &str, pct: Option<u32>, side_html: Markup, lang: Lang) -> Markup {
    let value = pct.unwrap_or(0);
    let color = rate_color(value);
    let offset = GAUGE_CIRCUMFERENCE * (1.0 - value as f64 / 100.0);
    html! {
        div class="gauge-flex" {
            div class="gauge-wrap" {
                svg class="gauge" width="118" height="118" viewBox="0 0 118 118"
                    role="img" aria-label=(match pct {
                        Some(p) => t_fmt(lang, FmtKey::GaugeAria, &[&p.to_string()]),
                        None => t(lang, TextKey::GaugeAriaNoData).to_string(),
                    }) {
                    circle class="track" cx="59" cy="59" r="48" { }
                    circle class="val" cx="59" cy="59" r="48" stroke=(color)
                        stroke-dasharray=(format!("{GAUGE_CIRCUMFERENCE:.2}"))
                        stroke-dashoffset=(format!("{offset:.2}")) { }
                }
                div class="gauge-center" {
                    // `{scope}-gauge-pct` 仅循 SSE id 命名约定、非 SSE 契约：无 JS 消费，仅页面加载时 SSR 计算一次。
                    div class="big" id=(format!("{scope}-gauge-pct")) {
                        @if let Some(p) = pct { (format!("{p}%")) } @else { "—" }
                    }
                    div class="sub" { (t(lang, TextKey::GaugeSubSuccess)) }
                }
            }
            div class="gauge-side" { (side_html) }
        }
    }
}

/// 成功率配色阈值（gauge 环用）：≥90 success / ≥70 warning / 其余（含 0）danger。
fn rate_color(pct: u32) -> &'static str {
    match pct {
        p if p >= 90 => "var(--success)",
        p if p >= 70 => "var(--warning)",
        _ => "var(--danger)",
    }
}

/// 构建时长条形图（静态 SSR 无 JS）：最近 N 个 succeeded 构建，每行 label
///（NVR 短名 · arch，超长 ellipsis）+ 横条（长度 = 时长/最长样本）+ 时长文本
///（与 task 详情同 [`format_duration_secs`]）。a11y：容器 `role="img"` + aria
/// 摘要，每行 title 带完整信息（无障碍替代表）；空样本 → 空态文案同作 aria。
pub(crate) fn duration_chart(samples: &[BuildDurationSample], lang: Lang) -> Markup {
    if samples.is_empty() {
        let empty = t(lang, TextKey::DurationNoData);
        return html! {
            div class="dur-chart" role="img" aria-label=(empty) {
                div class="viz-note" { (empty) }
            }
        };
    }
    let max_secs = samples
        .iter()
        .map(|s| s.duration_secs.max(0))
        .max()
        .unwrap_or(0);
    let aria = t_fmt(
        lang,
        FmtKey::DurationAria,
        &[&samples.len().to_string(), &format_duration_secs(max_secs)],
    );
    html! {
        div class="dur-chart" role="img" aria-label=(aria) {
            @for s in samples {
                @let label = if s.arch.is_empty() {
                    s.pkg_name.clone()
                } else {
                    format!("{} · {}", s.pkg_name, s.arch)
                };
                // 横条长度相对最长样本；全零样本 → 0%（不除零）。
                @let width_pct = if max_secs > 0 {
                    ((s.duration_secs.max(0) as f64 / max_secs as f64) * 100.0).round() as u64
                } else {
                    0
                };
                div class="dur-row" title=(format!("{} · {}", label, format_duration_secs(s.duration_secs))) {
                    span class="a" { (label) }
                    span class="bar" { i style=(format!("width:{width_pct}%")) { } }
                    span class="n" { (format_duration_secs(s.duration_secs)) }
                }
            }
            div class="viz-note" {
                (t_fmt(lang, FmtKey::DurationNote, &[&samples.len().to_string()]))
            }
        }
    }
}

/// 状态信息条（sys-strip）单项：`ok` 为 true 时 value 加绿色 `ok` 类，`title` 携带悬停明细。
pub(crate) struct StatStripItem {
    pub label: &'static str,
    pub value: String,
    pub ok: bool,
    pub title: Option<String>,
}

/// 底部状态信息条（operator+ 系统指标；数据采集在调用方）；item label 由调用方经 t() 传入，`lang` 供 region aria-label。
pub(crate) fn stat_strip(items: &[StatStripItem], lang: Lang) -> Markup {
    html! {
        div class="sys-strip" role="region" aria-label=(t(lang, TextKey::SysStripAria)) {
            @for item in items {
                span title=[item.title.as_deref()] {
                    span class="label" { (item.label) }
                    span class=(if item.ok { "value ok" } else { "value" }) { (item.value) }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(
        phase: &'static str,
        label: &'static str,
        count: i64,
        color: &'static str,
    ) -> ChartSegment {
        ChartSegment {
            phase,
            label,
            count,
            color,
            href: format!("/ui/tasks?phase={phase}"),
        }
    }

    #[test]
    fn donut_chart_renders_segments_legend_and_center() {
        let segments = [
            seg("running", "Running", 2, "var(--running)"),
            seg("succeeded", "Succeeded", 171, "var(--success)"),
            seg("failed", "Failed", 0, "var(--danger)"),
        ];
        let m = donut_chart(
            "dash",
            &segments,
            2,
            3,
            "Task distribution by phase",
            Lang::En,
        )
        .into_string();
        assert!(
            m.contains(r#"circle class="seg" data-phase="running""#),
            "{m}"
        );
        assert!(m.contains(r#"stroke="var(--running)""#), "{m}");
        assert!(m.contains("stroke-dasharray="), "{m}");
        // 环心 id 契约（SSE 脚本更新目标）：总数 173 = 2 + 171 + 0。
        assert!(m.contains(r#"id="dash-donut-total">173<"#), "{m}");
        assert!(m.contains(r#"id="dash-donut-running">2<"#), "{m}");
        assert!(m.contains(r#"id="dash-donut-queued">3<"#), "{m}");
        assert!(
            m.contains(
                r#"<a class="legend-row" data-phase="failed" href="/ui/tasks?phase=failed" aria-live="polite""#
            ),
            "{m}"
        );
        assert!(m.contains(r#"<span class="count">171</span>"#), "{m}");
        assert!(m.contains(r#"<span class="pct">99%</span>"#), "{m}");
        assert!(
            m.contains(r#"<div class="donut-center" aria-live="polite">"#),
            "donut center counts must be a live region: {m}"
        );
        assert!(
            m.contains(r#"title="failed · 0 tasks · 0.0% — click to view list""#),
            "{m}"
        );
        assert!(m.contains(r#"role="img""#), "{m}");
        assert!(m.contains("Task distribution by phase"), "{m}");
    }

    /// 空态（total=0）补 seg-empty 中性满环，色值经 --border 令牌（markup 不硬编码）；非空态不渲染。
    #[test]
    fn donut_chart_empty_state_renders_neutral_ring_only_when_total_zero() {
        let empty = [seg("succeeded", "Succeeded", 0, "var(--success)")];
        let m = donut_chart("dash", &empty, 0, 0, "x", Lang::En).into_string();
        // 满环在位：r 与扇区同径（81），整圆 stroke（自身无 dasharray 归零）。
        assert!(m.contains(r#"circle class="seg-empty" r="81""#), "{m}");
        assert!(m.contains(r#"id="dash-donut-total">0<"#), "{m}");
        // 不带 data-phase：不参与 SSE 逐相改写与 hover 联动（由脚本按类移除）。
        assert!(!m.contains(r#"class="seg-empty" data-phase"#), "{m}");

        let non_empty = [
            seg("running", "Running", 2, "var(--running)"),
            seg("succeeded", "Succeeded", 171, "var(--success)"),
        ];
        let m = donut_chart("dash", &non_empty, 2, 0, "x", Lang::En).into_string();
        assert!(!m.contains("seg-empty"), "{m}");
    }

    #[test]
    fn donut_chart_math_ports_mockup_min_frac_and_deduction() {
        // 100 + 1（total=101）：小段 1/101≈0.99% 保底 2%，超出的 1.01% 从最大段
        // 扣回 → 大段 frac=0.98、小段 0.02。C=2π·81≈508.94。
        let segments = [
            seg("succeeded", "Succeeded", 100, "var(--success)"),
            seg("failed", "Failed", 1, "var(--danger)"),
        ];
        let m = donut_chart("dash", &segments, 0, 0, "x", Lang::En).into_string();
        assert!(m.contains(r#"stroke-dasharray="498.76 10.18""#), "{m}");
        assert!(m.contains(r#"stroke-dashoffset="0.00""#), "{m}");
        assert!(m.contains(r#"stroke-dasharray="10.18 498.76""#), "{m}");
        assert!(m.contains(r#"stroke-dashoffset="-498.76""#), "{m}");

        // 全零：total=0 → 空环（弧长 0），中心总数 0，不出现 NaN。
        let empty = [seg("succeeded", "Succeeded", 0, "var(--success)")];
        let m = donut_chart("dash", &empty, 0, 0, "x", Lang::En).into_string();
        assert!(m.contains(r#"stroke-dasharray="0.00 508.94""#), "{m}");
        assert!(m.contains(r#"id="dash-donut-total">0<"#), "{m}");
    }

    #[test]
    fn gauge_chart_renders_threshold_colors_and_offset() {
        // 75% → warning 档；offset = C·(1-0.75) = 75.40（C=2π·48≈301.59）。
        let m = gauge_chart("dash", Some(75), html! {}, Lang::En).into_string();
        assert!(m.contains(r#"stroke="var(--warning)""#), "{m}");
        assert!(m.contains(r#"stroke-dashoffset="75.40""#), "{m}");
        assert!(m.contains(r#"id="dash-gauge-pct">75%<"#), "{m}");

        assert!(gauge_chart("dash", Some(92), html! {}, Lang::En)
            .into_string()
            .contains("var(--success)"));
        assert!(gauge_chart("dash", Some(50), html! {}, Lang::En)
            .into_string()
            .contains("var(--danger)"));

        // Some(0) 全失败：0% 空弧 + 中心 "0%"（渲染不破），不得回落 "—" 占位。
        let zero = gauge_chart("dash", Some(0), html! {}, Lang::En).into_string();
        assert!(zero.contains(r#"id="dash-gauge-pct">0%<"#), "{zero}");
        assert!(zero.contains(r#"stroke="var(--danger)""#), "{zero}");
        assert!(zero.contains(r#"stroke-dashoffset="301.59""#), "{zero}");

        // None：空环 + "—" 占位；aria 走无数据文案，而非误导性 "0% success rate"。
        let empty = gauge_chart("dash", None, html! { div { "side" } }, Lang::En).into_string();
        assert!(empty.contains(r#"id="dash-gauge-pct">—<"#), "{empty}");
        assert!(empty.contains(r#"stroke-dashoffset="301.59""#), "{empty}");
        assert!(empty.contains("No success data yet"), "{empty}");
        assert!(!empty.contains("0% success rate"), "{empty}");
        assert!(
            empty.contains("side"),
            "side_html must be embedded: {empty}"
        );
    }

    #[test]
    fn duration_chart_renders_rows_aria_and_empty_state() {
        // 时长 600s（最长，100% 条）/ 300s（50% 条）双样本。
        let samples = vec![
            BuildDurationSample {
                pkg_name: "vim-enhanced-9.1.0-4.el9".into(),
                arch: "x86_64".into(),
                duration_secs: 600,
            },
            BuildDurationSample {
                pkg_name: "bash-5.2.26-3.el9".into(),
                arch: "aarch64".into(),
                duration_secs: 300,
            },
        ];
        let m = duration_chart(&samples, Lang::En).into_string();
        assert!(
            m.contains(r#"role="img" aria-label="Durations of the last 2 succeeded builds, longest 10m 0s""#),
            "{m}"
        );
        assert!(m.contains("vim-enhanced-9.1.0-4.el9 · x86_64"), "{m}");
        assert!(m.contains(r#"width:100%"#), "{m}");
        assert!(m.contains(r#"width:50%"#), "{m}");
        assert!(m.contains(">10m 0s</span>"), "{m}");
        assert!(m.contains(">5m 0s</span>"), "{m}");
        assert!(
            m.contains(r#"title="bash-5.2.26-3.el9 · aarch64 · 5m 0s""#),
            "{m}"
        );
        let zh = duration_chart(&samples, Lang::Zh).into_string();
        assert!(zh.contains("最近 2 个成功构建的时长，最长 10m 0s"), "{zh}");

        let empty = duration_chart(&[], Lang::En).into_string();
        assert!(
            empty.contains(r#"aria-label="No finished builds yet""#),
            "{empty}"
        );
        assert!(!empty.contains("dur-row"), "{empty}");

        // 全零时长：不除零，条宽 0%。
        let zeros = vec![BuildDurationSample {
            pkg_name: "zero-1".into(),
            arch: String::new(),
            duration_secs: 0,
        }];
        let m = duration_chart(&zeros, Lang::En).into_string();
        assert!(m.contains(r#"width:0%"#), "{m}");
        // 空 arch：label span 无 " · " 尾巴（title 仍带时长后缀）。
        assert!(m.contains(r#"<span class="a">zero-1</span>"#), "{m}");
    }

    #[test]
    fn stat_strip_renders_items_ok_class_and_titles() {
        let items = [
            StatStripItem {
                label: "Uptime",
                value: "6d 4h".into(),
                ok: false,
                title: None,
            },
            StatStripItem {
                label: "Disk available",
                value: "192.4 GB".into(),
                ok: true,
                title: None,
            },
            StatStripItem {
                label: "Queue",
                value: "3".into(),
                ok: false,
                title: Some("2 at priority normal".into()),
            },
        ];
        let s = stat_strip(&items, Lang::En).into_string();
        assert!(s.contains(r#"class="sys-strip""#), "{s}");
        assert!(
            s.contains(r#"<span class="label">Uptime</span><span class="value">6d 4h</span>"#),
            "{s}"
        );
        assert!(s.contains(r#"class="value ok""#), "{s}");
        assert!(s.contains(r#"title="2 at priority normal""#), "{s}");
        assert!(!s.contains(r#"<span class="note""#), "{s}");
    }
}
