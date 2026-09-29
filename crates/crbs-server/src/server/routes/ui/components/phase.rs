// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 阶段时间线组件（phase_timeline）及其私有辅助。

use maud::{html, Markup};

use crate::server::routes::ui::i18n::{t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::pages::format_duration_secs;

/// 渲染层按名隐藏的工具步骤（ccache-init / ccache-summary，恒 0s 非构建阶段）。
/// 唯一真源：timeline 渲染过滤/pending 骨架、`sse::visible_timeline_spans`、
/// 日志页 JS（STEP_LABELS 除名 + HIDDEN_PHASES 跳过名单）全引用本表，加名只改这里。
/// 渲染层隐藏判定 = 本表 `contains`（phase_timeline 与日志页 SSE 同款过滤）。
pub(crate) const HIDDEN_TOOL_PHASES: [&str; 2] = ["ccache-init", "ccache-summary"];

/// 阶段时长：<60s 保留 0.1s 精度（短 phase 常见亚秒），超分钟截整秒复用
/// [`format_duration_secs`]（与任务详情同口径）；日志页 SSE `fmtDur` 同格式。
fn format_phase_duration(secs: f64) -> String {
    let secs = secs.max(0.0);
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else {
        format_duration_secs(secs as i64)
    }
}

/// 主步骤显示名静态映射（SSR 与日志页 SSE 脚本 STEP_LABELS 同表）；未知名
/// 回退原串（JS live 新建步骤不被打回 zh 键），工具步骤不到达这里。
pub(crate) fn phase_step_label(lang: Lang, name: &str) -> String {
    let (en, zh) = match name {
        "prepare-layer" => ("Prepare env", "环境准备"),
        "install-srpm" => ("Install SRPM", "安装 SRPM"),
        "install-deps" => ("Install deps", "安装依赖"),
        "build" => ("Build", "构建"),
        "collect-artifacts" => ("Collect & sign", "收集与签名"),
        // 原串即标识（mono 呈现）。
        other => return other.to_string(),
    };
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
    .to_string()
}

/// rpmbuild 子阶段说明（失败面板与分段条 title 共用；未知名空串）。
fn sub_phase_desc(lang: Lang, name: &str) -> &'static str {
    let (en, zh) = match name {
        "%prep" => ("Unpack sources, apply patches", "解包源码、打补丁"),
        "%generate_buildrequires" => ("Dynamic build requires", "动态生成构建依赖"),
        "%conf" => ("Configure", "配置"),
        "%build" => ("Compile", "编译"),
        "%install" => ("Install to buildroot", "安装到 buildroot"),
        "%check" => ("Self-check", "自测"),
        "%clean" => ("Clean", "清理"),
        "%mkbuilddir" => ("Create buildroot directories", "创建 buildroot 目录"),
        "%doc" => ("Process %doc files", "处理 %doc 文件"),
        "%license" => ("Process %license files", "处理 %license 文件"),
        _ => ("", ""),
    };
    match lang {
        Lang::En => en,
        Lang::Zh => zh,
    }
}

/// 子阶段无时长时的"进行中"措辞（分段条 title / sse_script 注入共用）；与
/// [`TextKey::DonutRunning`] 的"运行中"是不同词，勿混用。
pub(crate) fn sub_phase_running_word(lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => "进行中",
        Lang::En => "running",
    }
}

/// 节点图标：done ✓ / failed ✕ / running ●（CSS 脉动）/ 其余（skipped、pending）○。
fn timeline_node_glyph(state: &str) -> &'static str {
    match state {
        "done" => "✓",
        "failed" => "✕",
        "running" => "●",
        _ => "○",
    }
}

/// 阶段时间线（步进条版）：`div.phase-timeline > span.phase-step[data-phase]`。
/// DOM 契约（日志页 log_sse_script live 增量更新依赖，见 style.css 头注）：
/// .phase-timeline 是 .phase-step 直接容器，每步带 data-phase + data-start 且
/// 必含 .phase-step-name / .phase-step-detail；JS 整串改写 .phase-step 的
/// className（`phase-step <state>`），装饰类只能挂子节点。状态类 done /
/// failed（END exit!=0）/ skipped（reason 进 detail）/ running（"…"，
/// data-start 供 SSE 在 END 到达时算时长）；工具步骤（[`HIDDEN_TOOL_PHASES`]）
/// 按名隐藏，ccache_disabled SKIP 聚合为 .skip-chip（解析层保留完整标记，日志
/// 页脚本靠 SKIP 标记 live 推进）；build 失败输出失败子阶段面板 .subpanel。
/// `record_phase` 终态（failed/cancelled/timeout）时无 END 的 span 判 failed：
/// set -e 失败步不打 END，按"无 END=running"渲染会把时间线画成进行中、失败
/// 面板不出现。`clickable` 仅日志页终态 true（行号与页内文本自洽，`?line=`
/// 超界 no-op 兜底）；详情页/live 页 false（详情页行号虽真实但全文件行号遇
/// 日志页截断 tail 会错位；live 页 tail 行号不可靠，锚与 log_sse_script 的
/// className 整串改写冲突）。
pub(crate) fn phase_timeline(
    build_id: i64,
    spans: &[crbs_core::engine::profile::PhaseSpan],
    record_phase: &str,
    lang: Lang,
    clickable: bool,
) -> Markup {
    use crbs_core::engine::profile::PhaseSpan;
    let terminal_failed = matches!(record_phase, "failed" | "cancelled" | "timeout");
    let state_of = |s: &PhaseSpan| -> &'static str {
        let base = s.state();
        if base == "running" && terminal_failed {
            "failed"
        } else {
            base
        }
    };
    // 隐藏过滤先于 SKIP 聚合：skip-chip 只统计 ccache_disabled，隐藏步骤不进 chip。
    let considered: Vec<&PhaseSpan> = spans
        .iter()
        .filter(|s| !HIDDEN_TOOL_PHASES.contains(&s.name.as_str()))
        .collect();
    let visible: Vec<&PhaseSpan> = considered
        .iter()
        .copied()
        .filter(|s| !(s.skipped && s.reason.as_deref() == Some("ccache_disabled")))
        .collect();
    let hidden_skips = considered.len() - visible.len();
    let failed_build = visible
        .iter()
        .find(|s| s.name == "build" && state_of(s) == "failed" && !s.sub.is_empty());
    // live 页补 pending 骨架。存在性检查针对全部 span（含被隐藏 SKIP，不重复
    // 占位）；与下方终态失败 collect 占位互斥（building 下 build 失败也可能
    // 触发）。骨架与日志页脚本 live 新建步骤顺序可能交错，不做 DOM 重排。
    let collect_placeholder_due =
        failed_build.is_some() && !visible.iter().any(|s| s.name == "collect-artifacts");
    let pending_steps: Vec<&str> = if matches!(record_phase, "pending" | "assigned" | "building") {
        // canonical 流水线形状（不含 HIDDEN_TOOL_PHASES）。
        [
            "prepare-layer",
            "install-srpm",
            "install-deps",
            "build",
            "collect-artifacts",
        ]
        .iter()
        .copied()
        .filter(|name| !spans.iter().any(|s| &s.name == name))
        .filter(|name| !(name == &"collect-artifacts" && collect_placeholder_due))
        .collect()
    } else {
        Vec::new()
    };

    html! {
        div class="phase-timeline" {
            @for span in &visible {
                @let state = state_of(span);
                @let step = html! {
                    div class="tl-node" { (timeline_node_glyph(state)) }
                    div class="tl-text" {
                        span class="phase-step-name" { (phase_step_label(lang, &span.name)) }
                        @if span.skipped {
                            span class="phase-step-detail" { (span.reason.as_deref().unwrap_or(t(lang, TextKey::PhaseSkipped))) }
                        } @else if span.end.is_none() {
                            span class="phase-step-detail" { "…" }
                        } @else {
                            span class="phase-step-detail" { (format_phase_duration(span.elapsed_seconds(0.0))) }
                        }
                    }
                    @if span.name == "build" && !span.sub.is_empty() {
                        // 分段条：子阶段归并固定三桶逐桶出段（无插桩时长且无
                        // 失败时不画条），细节见 sub_phase_bar。
                        (sub_phase_bar(span, lang))
                    }
                };
                @if clickable {
                    a class=(format!("phase-step {state}")) data-phase=(span.name) data-start=(span.start)
                        href=(format!("/ui/builds/{}/logs?line={}", build_id, span.line)) { (step) }
                } @else {
                    span class=(format!("phase-step {state}")) data-phase=(span.name) data-start=(span.start) { (step) }
                }
            }
            @for name in &pending_steps {
                span class="phase-step pending" data-phase=(name) {
                    div class="tl-node" { (timeline_node_glyph("pending")) }
                    div class="tl-text" {
                        span class="phase-step-name" { (phase_step_label(lang, name)) }
                        span class="phase-step-detail" { "—" }
                    }
                }
            }
            // 失败且未跑到 collect-artifacts：补 pending 占位步（与 live 骨架互斥）。
            @if collect_placeholder_due {
                span class="phase-step pending" data-phase="collect-artifacts" {
                    div class="tl-node" { (timeline_node_glyph("pending")) }
                    div class="tl-text" {
                        span class="phase-step-name" { (phase_step_label(lang, "collect-artifacts")) }
                        span class="phase-step-detail" { (t(lang, TextKey::NotRun)) }
                    }
                }
            }
            @if hidden_skips > 0 {
                span class="skip-chip" { (t_fmt(lang, FmtKey::SkippedChipFmt, &[&hidden_skips.to_string()])) }
            }
        }
        @if let Some(fb) = failed_build {
            (build_subphase_panel(build_id, fb, lang))
        }
    }
}

/// 失败子阶段面板 .subpanel：sp-head 失败归属 + sp-body 每子阶段一行（名 /
/// 说明 / `?line=` 跳转）+ errbox 错误摘录（pre-line）。
fn build_subphase_panel(
    build_id: i64,
    span: &crbs_core::engine::profile::PhaseSpan,
    lang: Lang,
) -> Markup {
    let failed_sub = span.sub.iter().find(|s| s.failed);
    let failed_name = failed_sub.map(|s| s.name.as_str()).unwrap_or("%build");
    html! {
        div class="subpanel" {
            div class="sp-head" {
                span class="sp-ic" aria-hidden="true" { "✕" }
                (t_fmt(lang, FmtKey::SubPanelFailedAt, &[failed_name]))
            }
            div class="sp-body" {
                @for s in &span.sub {
                    div class=(if s.failed { "sp-row bad" } else { "sp-row" }) {
                        span class="ic" { (if s.failed { "✕" } else { "✓" }) }
                        span class="name" { (s.name) }
                        span class="desc" { (sub_phase_desc(lang, &s.name)) }
                        @if let Some(d) = s.duration {
                            span class="dur" { (format_phase_duration(d)) }
                        }
                        a class="jump" href=(format!("/ui/builds/{}/logs?line={}", build_id, s.line)) {
                            (t_fmt(lang, FmtKey::LogAtLine, &[&s.line.to_string()]))
                        }
                    }
                }
            }
            @if let Some(err) = failed_sub.and_then(|s| s.error_line.as_deref()) {
                div class="errbox" { (err) }
            }
        }
    }
}

/// 分段条三桶表（唯一真源）：rpmbuild 子阶段按标记到达序归并为固定三桶
/// prep/build/package，SSR 分段条与日志页 SSE 注入表（SUBPHASE_TIP）都由
/// 本表派生，加桶只改这里。名与说明是显示用桶名（非 spec 原名，无 % 前缀）；
/// 失败面板仍按原始子段名走 [`sub_phase_desc`]。
pub(crate) struct SubPhaseBucket {
    /// 桶显示名（分段条 data-name 与 title 前缀）。
    pub name: &'static str,
    pub desc_en: &'static str,
    pub desc_zh: &'static str,
}

pub(crate) const SUBPHASE_BUCKETS: [SubPhaseBucket; 3] = [
    SubPhaseBucket {
        name: "prep",
        desc_en: "Unpack sources, apply patches",
        desc_zh: "解包源码、打补丁",
    },
    SubPhaseBucket {
        name: "build",
        desc_en: "Compile",
        desc_zh: "编译",
    },
    SubPhaseBucket {
        name: "package",
        desc_en: "Install to buildroot and package",
        desc_zh: "安装到 buildroot 并打包",
    },
];

/// 分段条单桶段：桶名（[`SUBPHASE_BUCKETS`] 之一）/ 桶时长（成员时长和，
/// 任一成员无插桩时长即 None）/ 失败（任一成员失败）。
pub(crate) struct SubBucketSeg {
    pub name: &'static str,
    pub duration: Option<f64>,
    pub failed: bool,
}

/// 子阶段三桶归并（位置式状态机）：初始 prep 桶，遇 %build 切 build、遇
/// %install 切 package，其余子段名（%doc/%license/%clean/%check 等）不切
/// 桶，时长与失败并入当前桶。桶时长 =
/// 成员求和，任一成员 None 即 None；输入全无时长且全无失败（无插桩降级
/// 日志）返回空 Vec，分段条整条不画（失败可见性由失败面板 .subpanel 承载）。
pub(crate) fn merge_sub_buckets(
    subs: &[crbs_core::engine::profile::SubPhase],
) -> Vec<SubBucketSeg> {
    let mut current = 0usize;
    let mut out: Vec<SubBucketSeg> = Vec::new();
    for s in subs {
        // 切桶只认 %build/%install 两个名，桶序 = 标记到达序。
        if s.name == "%build" {
            current = 1;
        } else if s.name == "%install" {
            current = 2;
        }
        let name = SUBPHASE_BUCKETS[current].name;
        match out.last_mut() {
            // 连续同桶成员折叠：失败取或、时长求和（任一 None 即 None）。
            Some(b) if b.name == name => {
                b.failed |= s.failed;
                b.duration = match (b.duration, s.duration) {
                    (Some(acc), Some(d)) => Some(acc + d),
                    _ => None,
                };
            }
            _ => out.push(SubBucketSeg {
                name,
                duration: s.duration,
                failed: s.failed,
            }),
        }
    }
    let has_info = out.iter().any(|b| b.duration.is_some() || b.failed);
    if has_info {
        out
    } else {
        Vec::new()
    }
}

/// 桶 tip 的"`名（说明）— `"前缀（名与说明取自 [`SUBPHASE_BUCKETS`]）；
/// SSR 桶段 title 与 sse_script 注入表（SUBPHASE_TIP）共用拼法，时长各端
/// 自拼（SSR format_phase_duration / JS fmtDur）。
pub(crate) fn sub_bucket_tip_prefix(lang: Lang, name: &str) -> String {
    let desc = SUBPHASE_BUCKETS
        .iter()
        .find(|b| b.name == name)
        .map(|b| match lang {
            Lang::En => b.desc_en,
            Lang::Zh => b.desc_zh,
        })
        .unwrap_or("");
    if desc.is_empty() {
        format!("{name} — ")
    } else if lang == Lang::Zh {
        format!("{name}（{desc}）— ")
    } else {
        format!("{name} ({desc}.) — ")
    }
}

/// 分段条（tl-segbar）：归并桶逐桶出 tl-seg，段宽 = 桶时长占比（无时长
/// 回退等宽），失败桶 bad；每段挂 data-name 与 data-start（= build 起点 +
/// 之前各桶已铺满时长之和，日志页 live JS 据此结算末段），title = 前缀 +
/// 时长，无时长时前缀 + 进行中词。
fn sub_phase_bar(span: &crbs_core::engine::profile::PhaseSpan, lang: Lang) -> Markup {
    let mut seg_start = span.start;
    let mut segs: Vec<Markup> = Vec::new();
    for b in merge_sub_buckets(&span.sub) {
        let w = b.duration.unwrap_or(1.0).max(0.5);
        let dur = match b.duration {
            Some(d) => format_phase_duration(d),
            None => sub_phase_running_word(lang).to_string(),
        };
        let tip = format!("{}{}", sub_bucket_tip_prefix(lang, b.name), dur);
        segs.push(html! {
            div class=(if b.failed { "tl-seg bad" } else { "tl-seg" })
                data-name=(b.name)
                data-start=(seg_start)
                style=(format!("flex:{}; min-width:8px", w))
                title=(tip) {}
        });
        if let Some(d) = b.duration {
            seg_start += d;
        }
    }
    if segs.is_empty() {
        return html! {};
    }
    html! {
        div class="tl-segbar" {
            @for seg in &segs {
                (seg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 时间线 DOM 契约总检（细节见 [`phase_timeline`] doc）：状态类渲染、
    /// 工具步骤两种标记形态隐藏不计 chip、SKIP 聚 chip、build 失败出 .subpanel。
    #[test]
    fn phase_timeline_renders_states_and_step_contract() {
        use crbs_core::engine::profile::{parse_phase_markers, PhaseSpan};
        // 覆盖构造走公开解析器之外的自定义 span（running）+ 解析器输出（其余）。
        let log = "\
# CRBS_PHASE_START install-srpm 100.0
# CRBS_PHASE_END install-srpm 0 100.4
# CRBS_PHASE_SKIP install-deps shared_layer
# CRBS_PHASE_START build 100.4
Executing(%prep): /bin/sh -e /var/tmp/rpm-tmp.aaa
Executing(%check): /bin/sh -e /var/tmp/rpm-tmp.ccc
error: Bad exit status from /var/tmp/rpm-tmp.ccc (%check)
# CRBS_PHASE_END build 2 165.5
# CRBS_PHASE_START prepare-layer 165.5
# CRBS_PHASE_START ccache-summary 165.5
# CRBS_PHASE_END ccache-summary 0 165.5
# CRBS_PHASE_SKIP ccache-init ccache_disabled
# CRBS_PHASE_SKIP test-tool ccache_disabled
";
        let mut spans = parse_phase_markers(log);
        spans.push(PhaseSpan {
            name: "custom".into(),
            start: 1.0,
            end: Some(61.0),
            exit_code: Some(0),
            skipped: false,
            reason: None,
            line: 1,
            sub: Vec::new(),
        });
        let s = phase_timeline(7, &spans, "building", Lang::En, false).into_string();
        assert!(s.contains(r#"<div class="phase-timeline">"#), "{s}");
        assert!(
            s.contains(r#"class="phase-step done" data-phase="install-srpm""#),
            "{s}"
        );
        assert!(s.contains(r#"class="tl-node""#), "{s}");
        assert!(s.contains(r#"class="tl-text""#), "{s}");
        // done 时长 0.4s（亚秒保留 0.1s 精度）。
        assert!(
            s.contains(r#"<span class="phase-step-detail">0.4s</span>"#),
            "{s}"
        );
        assert!(
            s.contains(r#"class="phase-step skipped" data-phase="install-deps""#),
            "{s}"
        );
        assert!(s.contains(">shared_layer</span>"), "{s}");
        assert!(
            s.contains(r#"class="phase-step failed" data-phase="build""#),
            "{s}"
        );
        // failed 时长 65.1s → 超过分钟走 format_duration_secs 口径（1m 5s）。
        assert!(
            s.contains("<span class=\"phase-step-detail\">1m 5s</span>"),
            "{s}"
        );
        assert!(
            s.contains(r#"class="phase-step running" data-phase="prepare-layer""#),
            "{s}"
        );
        assert!(s.contains("data-start=\"165.5\""), "{s}");
        assert!(
            s.contains("<span class=\"phase-step-detail\">…</span>"),
            "{s}"
        );

        let failed = phase_timeline(7, &spans, "failed", Lang::En, false).into_string();
        assert!(
            failed.contains(r#"class="phase-step failed" data-phase="build""#),
            "{failed}"
        );
        assert!(failed.contains(r#"class="tl-node">✕</div>"#), "{failed}");
        // 工具步骤两种标记形态（SKIP / START-END）都不渲染、不计入 chip。
        for hidden in ["ccache-init", "ccache-summary"] {
            assert!(
                !s.contains(&format!(r#"data-phase="{hidden}""#)),
                "hidden tool phase {hidden} must not render: {s}"
            );
        }
        // ccache_disabled SKIP 聚合保持原样：非隐藏名的 test-tool SKIP 聚进 chip。
        assert!(s.contains(r#"class="skip-chip""#), "{s}");
        assert!(s.contains("+1 skipped"), "{s}");
        // build 失败带子阶段：%check 不切桶归入 prep 桶 → 分段条单段 bad +
        // 失败面板（原始失败名 %check + 跳转 + 错误摘录）。
        assert!(s.contains(r#"class="tl-segbar""#), "{s}");
        // 段计数不含 tl-segbar 前缀命中：只数 tl-seg / tl-seg bad 两种形态。
        assert_eq!(
            s.matches(r#"<div class="tl-seg""#).count()
                + s.matches(r#"<div class="tl-seg bad""#).count(),
            1,
            "{s}"
        );
        assert!(
            s.contains(
                r#"<div class="tl-seg bad" data-name="prep" data-start="100.4" style="flex:1; min-width:8px" title="prep (Unpack sources, apply patches.) — running"></div>"#
            ),
            "{s}"
        );
        assert!(s.contains(r#"class="subpanel""#), "{s}");
        assert!(s.contains("rpmbuild failed at the %check stage"), "{s}");
        assert!(
            s.contains(r#"href="/ui/builds/7/logs?line=6""#),
            "subpanel jump link: {s}"
        );
        assert!(
            s.contains("error: Bad exit status from /var/tmp/rpm-tmp.ccc (%check)"),
            "{s}"
        );
        assert!(
            s.contains(r#"class="phase-step pending" data-phase="collect-artifacts""#),
            "{s}"
        );
        assert!(
            s.contains("<span class=\"phase-step-detail\">Not run</span>"),
            "{s}"
        );
        // 非 clickable：必须 span，不得出现锚（与 live 页 className 整串改写冲突）。
        assert!(!s.contains("<a class=\"phase-step"), "{s}");
    }

    /// clickable 变体：`a.phase-step` + href 指向该 phase 标记行（?line=），
    /// data 契约不变，skipped 步 href 即 SKIP 标记行。
    #[test]
    fn phase_timeline_clickable_renders_step_anchors_with_line_href() {
        use crbs_core::engine::profile::parse_phase_markers;
        let log = "\
# CRBS_PHASE_START install-srpm 100.0
# CRBS_PHASE_END install-srpm 0 100.4
# CRBS_PHASE_SKIP install-deps shared_layer
# CRBS_PHASE_START build 100.4
# CRBS_PHASE_END build 2 165.5
";
        let spans = parse_phase_markers(log);
        let s = phase_timeline(9, &spans, "failed", Lang::En, true).into_string();
        assert!(
            s.contains(
                r#"<a class="phase-step done" data-phase="install-srpm" data-start="100" href="/ui/builds/9/logs?line=1">"#
            ),
            "{s}"
        );
        assert!(
            s.contains(r#"class="phase-step skipped" data-phase="install-deps" data-start="0" href="/ui/builds/9/logs?line=3""#),
            "{s}"
        );
        assert!(
            s.contains(r#"class="phase-step failed" data-phase="build" data-start="100.4" href="/ui/builds/9/logs?line=4""#),
            "{s}"
        );
    }

    /// live 页 pending 骨架：canonical 缺失步骤按序补占位（detail "—"）；
    /// 隐藏工具步骤任何形态不渲染不占位；终态不出骨架（仅失败 collect 占位）。
    #[test]
    fn phase_timeline_pending_skeleton_fills_missing_steps_for_live_builds() {
        use crbs_core::engine::profile::parse_phase_markers;
        let log = "\
# CRBS_PHASE_START prepare-layer 1.0
# CRBS_PHASE_END prepare-layer 0 2.0
# CRBS_PHASE_START install-srpm 2.0
# CRBS_PHASE_END install-srpm 0 2.4
# CRBS_PHASE_SKIP ccache-init ccache_disabled
# CRBS_PHASE_START build 2.4
";
        let spans = parse_phase_markers(log);
        let s = phase_timeline(7, &spans, "building", Lang::En, false).into_string();
        for name in ["install-deps", "collect-artifacts"] {
            assert!(
                s.contains(&format!(
                    r#"class="phase-step pending" data-phase="{name}""#
                )),
                "missing skeleton step {name}: {s}"
            );
        }
        for reached in ["prepare-layer", "install-srpm", "build"] {
            assert!(
                !s.contains(&format!(
                    r#"class="phase-step pending" data-phase="{reached}""#
                )),
                "reached step must not get a skeleton placeholder: {s}"
            );
        }
        // 隐藏工具步骤（SKIP / 跑完两种形态）不渲染、不出占位。
        for hidden in ["ccache-init", "ccache-summary"] {
            assert!(
                !s.contains(&format!(r#"data-phase="{hidden}""#)),
                "hidden tool phase {hidden} must not render at all: {s}"
            );
        }
        // 占位步带 data-phase（日志页 stepEl 可在标记到达时回填）+ "—" 详情。
        assert!(
            s.contains(r#"class="tl-node">○</div>"#),
            "skeleton steps use the pending glyph: {s}"
        );
        assert!(
            s.contains("<span class=\"phase-step-detail\">—</span>"),
            "{s}"
        );
        let terminal = phase_timeline(7, &spans, "succeeded", Lang::En, false).into_string();
        assert!(
            !terminal.contains(r#"class="phase-step pending""#),
            "terminal pages must not render the skeleton: {terminal}"
        );
    }

    /// 内部段（%mkbuilddir/%doc/%license）双语说明（失败面板仍显示），未知名空串。
    #[test]
    fn sub_phase_desc_covers_internal_stages() {
        assert_eq!(
            sub_phase_desc(Lang::En, "%mkbuilddir"),
            "Create buildroot directories"
        );
        assert_eq!(sub_phase_desc(Lang::Zh, "%doc"), "处理 %doc 文件");
        assert_eq!(sub_phase_desc(Lang::Zh, "%license"), "处理 %license 文件");
        assert_eq!(sub_phase_desc(Lang::En, "%never-heard-of"), "");
    }

    /// 三桶分段条（build-18 形状）：%license×2/%doc/%clean 不切桶，归并后
    /// 恰好 prep/build/package 三段，package 段吃下 %install 起点到 build END
    /// 的全部时长；双语 title 各含桶说明。
    #[test]
    fn phase_timeline_build_bar_merges_into_three_fixed_buckets() {
        use crbs_core::engine::profile::parse_phase_markers;
        let log = "\
# CRBS_PHASE_START install-srpm 90.0
# CRBS_PHASE_END install-srpm 0 100.5
# CRBS_PHASE_START build 100.5
# CRBS_SUBPHASE %prep 200.0
# CRBS_SUBPHASE %build 210.0
# CRBS_SUBPHASE %install 220.0
# CRBS_SUBPHASE %license 230.0
# CRBS_SUBPHASE %license 235.0
# CRBS_SUBPHASE %doc 240.0
# CRBS_SUBPHASE %clean 250.0
# CRBS_PHASE_END build 0 260.0
";
        let spans = parse_phase_markers(log);
        let s = phase_timeline(7, &spans, "succeeded", Lang::En, false).into_string();
        // 恰好 3 段、顺序 prep/build/package，原始子段名不上条。
        assert_eq!(
            s.matches(r#"<div class="tl-seg""#).count()
                + s.matches(r#"<div class="tl-seg bad""#).count(),
            3,
            "{s}"
        );
        let prep_at = s.find(r#"data-name="prep""#).expect("prep seg");
        let build_at = s.find(r#"data-name="build""#).expect("build seg");
        let package_at = s.find(r#"data-name="package""#).expect("package seg");
        assert!(prep_at < build_at && build_at < package_at, "{s}");
        assert!(!s.contains(r#"data-name="%"#), "no raw %name seg: {s}");
        // package 段：data-start = build 起点 + 前两桶时长，宽度 = END −
        // %install 起点（%install 220 → END 260）。
        assert!(
            s.contains(
                r#"<div class="tl-seg" data-name="package" data-start="120.5" style="flex:40; min-width:8px" title="package (Install to buildroot and package.) — 40.0s"></div>"#
            ),
            "{s}"
        );
        // 三段 title 各含桶说明与桶时长。
        assert!(
            s.contains(r#"title="prep (Unpack sources, apply patches.) — 10.0s""#),
            "{s}"
        );
        assert!(s.contains(r#"title="build (Compile.) — 10.0s""#), "{s}");
        // zh：桶说明全角括号拼法。
        let zh = phase_timeline(7, &spans, "succeeded", Lang::Zh, false).into_string();
        assert!(
            zh.contains(r#"title="prep（解包源码、打补丁）— 10.0s""#),
            "{zh}"
        );
        assert!(zh.contains(r#"title="build（编译）— 10.0s""#), "{zh}");
        assert!(
            zh.contains(r#"title="package（安装到 buildroot 并打包）— 40.0s""#),
            "{zh}"
        );
    }
}
