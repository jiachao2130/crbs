// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建/任务阶段面板 SSE 脚本。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, t_phase, Lang, TextKey};

use super::common::*;

/// 详情页 phase SSE 脚本参数：`base_path`/`event_name`/`id`/`nonce` 定位事件源，
/// 三个 `with_*` 开关按页注入增量小节（children=task、timeline/elapsed=build）。
pub(super) struct PhaseSseScriptOpts<'a> {
    pub(super) base_path: &'a str,
    pub(super) event_name: &'a str,
    pub(super) id: i64,
    pub(super) nonce: &'a str,
    pub(super) with_children: bool,
    pub(super) with_timeline: bool,
    pub(super) with_elapsed: bool,
    pub(super) lang: Lang,
}

/// 详情页 phase SSE 脚本（build/task 共用）。终态事件除切徽章外调度**一次**
/// 1500ms 延迟 reload——产物表/签名/总时长/兄弟列表不随 SSE 增量更新，延迟
/// 给终态收尾留时间；`.terminal-hint` 兜底。检查：仅在"非终态打开、存活期间
/// 迁入终态"（startedLive）才提示+刷新（已终态打开无物可刷）。
///
/// 完成通知：同一 startedLive 检查，`window.__crbsNotify`（notify_button
/// granted 态置位）武装时终态分支弹通知；构造仅在终态分支、权限请求仅在
/// 按钮 click handler。
///
/// `with_children`（task 页）：按 children 更新 arch 矩阵（`[data-build-id=N]`
/// 定位；duration>0 刷新 `.arch-duration`，span 缺位补建：title 同 SSR）。
///
/// `with_timeline`（build 页）：按 timeline 事件的 spans 更新时间线：
/// className 改写 `phase-step <state>`、detail 按 state/duration_seconds/
/// reason 回写（口径同 SSR）；缺失步骤裸形态 append；HIDDEN_TOOL_PHASES
/// 显式跳过；重复/乱序覆写无副作用；终态后不再推；task 页不注入。
///
/// `with_elapsed`（build 页）：注入 Lifecycle"至今"走秒器（.lc-so-far 重渲）。
pub(super) fn phase_sse_script(opts: PhaseSseScriptOpts<'_>) -> Markup {
    let PhaseSseScriptOpts {
        base_path,
        event_name,
        id,
        nonce,
        with_children,
        with_timeline,
        with_elapsed,
        lang,
    } = opts;
    let url = format!("{}/{}/events", base_path, id);
    let hint_text = js_str(match event_name {
        "build" => t(lang, TextKey::HintBuildFinished),
        _ => t(lang, TextKey::HintTaskFinished),
    });
    let notify_title = js_str(match event_name {
        "build" => t(lang, TextKey::NotifyTitleBuild),
        _ => t(lang, TextKey::NotifyTitleTask),
    });
    let notify_lang = lang.html_lang();
    let notify_tag = format!("crbs-{event_name}-{id}");
    let refresh_now = js_str(t(lang, TextKey::RefreshNow));
    let live_title = js_str(t(lang, TextKey::LiveUpdatesEnabled));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    let dead_title = js_str(t(lang, TextKey::ConnectionClosed));
    let set_live = set_live_js(&live_title, &lost_title);
    let terminal_hint = terminal_hint_js(&hint_text, "window.location.href", &refresh_now);
    let phase_labels = [
        "pending",
        "assigned",
        "building",
        "succeeded",
        "failed",
        "timeout",
        "cancelled",
    ]
    .iter()
    .map(|p| format!("\"{}\":\"{}\"", p, js_str(t_phase(lang, p))))
    .collect::<Vec<_>>()
    .join(",");
    let children_fns: String = if with_children {
        let dur_title = js_str(t(lang, TextKey::TitleDuration));
        let dur_fmt = dur_fmt_js("fmtDur");
        format!(
            r#"
                var ARCH_DUR_TITLE = '{dur_title}';
                {dur_fmt}
                function archDurEl(cell) {{
                    var dur = cell.querySelector('.arch-duration');
                    if (!dur) {{
                        dur = document.createElement('span');
                        dur.className = 'arch-duration';
                        dur.title = ARCH_DUR_TITLE;
                        cell.appendChild(dur);
                    }}
                    return dur;
                }}
                function updateChildren(list) {{
                    if (!list) return;
                    for (var i = 0; i < list.length; i++) {{
                        var ch = list[i];
                        var cell = document.querySelector('[data-build-id="' + ch.id + '"]');
                        if (!cell) continue;
                        var badge = cell.querySelector('.badge');
                        if (badge && ch.phase) {{
                            badge.textContent = phaseLabel(ch.phase);
                            badge.setAttribute('data-phase', ch.phase);
                            badge.className = 'badge ' + modClass(ch.phase);
                        }}
                        if (typeof ch.duration === 'number' && ch.duration > 0) {{
                            archDurEl(cell).textContent = fmtDur(ch.duration);
                        }}
                    }}
                    var summary = document.querySelector('.matrix-summary[data-pattern]');
                    if (summary) {{
                        var succ = 0, fail = 0;
                        for (var j = 0; j < list.length; j++) {{
                            var ph = list[j].phase;
                            if (ph === 'succeeded') succ++;
                            else if (ph === 'failed') fail++;
                        }}
                        summary.textContent = summary.getAttribute('data-pattern')
                            .replace('{{0}}', list.length)
                            .replace('{{1}}', succ)
                            .replace('{{2}}', fail);
                    }}
                }}
"#
        )
    } else {
        String::new()
    };
    let children_call: &str = if with_children {
        "                        updateChildren(data.children);"
    } else {
        ""
    };
    let timeline_listener: &str = if with_timeline {
        "                es.addEventListener('timeline', function(ev) {\n                    try { applyTimeline(JSON.parse(ev.data)); } catch (e) {}\n                });\n"
    } else {
        ""
    };
    let timeline_fns: String = if with_timeline {
        let step_labels = step_labels_json(lang);
        let fmt_step_dur = step_duration_js("fmtStepDur");
        let timeline_step_el = step_el_js("timelineStepEl");
        let timeline_set_detail = set_detail_js("timelineSetDetail");
        let find_step: &str = FIND_STEP_JS;
        let hidden_phases = hidden_tool_phases_js();
        let skipped_text = js_str(t(lang, TextKey::PhaseSkipped));
        format!(
            r#"
                var STEP_LABELS = {{{step_labels}}};
                var HIDDEN_PHASES = {{{hidden_phases}}};
                {fmt_step_dur}
                {find_step}
                {timeline_step_el}
                {timeline_set_detail}
                function applyTimeline(list) {{
                    if (!list) return;
                    var timeline = document.querySelector('.phase-timeline');
                    if (!timeline) return;
                    for (var i = 0; i < list.length; i++) {{
                        var sp = list[i];
                        if (!sp || !sp.name || !sp.state) continue;
                        if (HIDDEN_PHASES[sp.name]) continue;
                        var el = timelineStepEl(timeline, sp.name);
                        el.className = 'phase-step ' + sp.state;
                        if (sp.state === 'running') timelineSetDetail(el, '\u2026');
                        else if (sp.state === 'skipped') timelineSetDetail(el, sp.reason || '{skipped_text}');
                        else if (typeof sp.duration_seconds === 'number') timelineSetDetail(el, fmtStepDur(sp.duration_seconds));
                    }}
                }}
"#
        )
    } else {
        String::new()
    };
    let elapsed_fns: String = if with_elapsed {
        let lc_dur = dur_fmt_js("lcDur");
        format!(
            r#"
                {lc_dur}
                function lcWalk() {{
                    var els = document.querySelectorAll('.lc-so-far[data-ts]');
                    for (var i = 0; i < els.length; i++) {{
                        var el = els[i];
                        var t = Date.parse(el.getAttribute('data-ts').replace(' ', 'T') + 'Z');
                        if (isNaN(t)) continue;
                        el.textContent = el.getAttribute('data-tpl').replace('{{0}}', lcDur((Date.now() - t) / 1000));
                    }}
                }}
                setInterval(lcWalk, 10000);
"#
        )
    } else {
        String::new()
    };
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                {set_live}
                function isTerminal(p) {{
                    return p === 'succeeded' || p === 'failed' || p === 'cancelled' || p === 'timeout';
                }}
                function modClass(p) {{
                    return p === 'succeeded' ? 'success' : (p === 'timeout' ? 'timeout' : (p === 'cancelled' ? 'cancelled' : (p === 'failed' ? 'failure' : (p === 'building' || p === 'assigned' ? 'running' : (p === 'pending' ? 'pending' : '')))));
                }}
                var PHASE_LABELS = {{{phase_labels}}};
                function phaseLabel(p) {{
                    return PHASE_LABELS[p] || p;
                }}
                var badge = document.querySelector('.phase-badge');
                var startedLive = !(badge && isTerminal(badge.getAttribute('data-phase')));
                {terminal_hint}
                function notifyFinished(phase) {{
                    if (!window.__crbsNotify || !window.Notification
                        || Notification.permission !== 'granted') return;
                    try {{
                        new Notification('{notify_title}', {{
                            body: phaseLabel(phase) + ' — ' + window.__crbsNotify,
                            lang: '{notify_lang}',
                            tag: '{notify_tag}'
                        }});
                    }} catch (e) {{}}
                }}
                var reloadScheduled = false;
                function scheduleReloadOnce() {{
                    if (reloadScheduled) return;
                    reloadScheduled = true;
                    setTimeout(function() {{ location.reload(); }}, 1500);
                }}
                {children_fns}{timeline_fns}{elapsed_fns}
                var es = new EventSource('{url}');
                es.addEventListener('{event}', function(ev) {{
                    var phase = '';
                    try {{
                        var data = JSON.parse(ev.data);
                        phase = data.phase || '';
                        var el = document.querySelector('.phase-badge');
                        if (el && data.phase) {{
                            el.textContent = phaseLabel(data.phase);
                            el.setAttribute('data-phase', data.phase);
                            el.className = 'badge phase-badge ' + modClass(data.phase);
                        }}
                        {children_call}
                    }} catch (e) {{}}
                    if (isTerminal(phase)) {{
                        es.close();
                        var live = document.querySelector('.live-indicator');
                        if (live) live.style.display = 'none';
                        if (startedLive) {{
                            showTerminalHint(phase);
                            notifyFinished(phase);
                            scheduleReloadOnce();
                        }}
                    }}
                }});
{timeline_listener}
                es.onopen = function() {{ setLive(true); }};
                es.onerror = function() {{
                    setLive(false);
                    if (es.readyState === EventSource.CLOSED) {{
                        var el = document.querySelector('.live-indicator');
                        if (el) el.title = '{dead_title}';
                    }}
                }};
            }})();
        "#, url = url, event = event_name, dead_title = dead_title, notify_title = notify_title, notify_lang = notify_lang, notify_tag = notify_tag, phase_labels = phase_labels, children_fns = children_fns, children_call = children_call, timeline_fns = timeline_fns, elapsed_fns = elapsed_fns, timeline_listener = timeline_listener))) }
    }
}
