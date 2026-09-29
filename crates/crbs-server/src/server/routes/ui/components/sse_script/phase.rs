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
/// 给终态收尾留时间；`.terminal-hint` 兜底。守卫：仅在"非终态打开、存活期间
/// 迁入终态"（startedLive）才提示+刷新（已终态打开无物可刷）。
///
/// 完成通知：同一 startedLive 守卫，`window.__crbsNotify`（notify_button
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
    // 终态提示文案按主体取 key（完整句子，不做前后缀拼接）。
    let hint_text = js_str(match event_name {
        "build" => t(lang, TextKey::HintBuildFinished),
        _ => t(lang, TextKey::HintTaskFinished),
    });
    // 通知 title 同样按主体取 key；lang 进 Notification options 供系统本地化排版。
    let notify_title = js_str(match event_name {
        "build" => t(lang, TextKey::NotifyTitleBuild),
        _ => t(lang, TextKey::NotifyTitleTask),
    });
    let notify_lang = lang.html_lang();
    // tag：同一构建的重复通知（多标签页）互相替换，不叠弹窗。
    let notify_tag = format!("crbs-{event_name}-{id}");
    let refresh_now = js_str(t(lang, TextKey::RefreshNow));
    let live_title = js_str(t(lang, TextKey::LiveUpdatesEnabled));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    // CLOSED 终态文案（EventSource 永久失活后不再声称重连）。
    let dead_title = js_str(t(lang, TextKey::ConnectionClosed));
    let set_live = set_live_js(&live_title, &lost_title);
    let terminal_hint = terminal_hint_js(&hint_text, "window.location.href", &refresh_now);
    // 徽章文本按 lang 注入 7 相位显示名（同 SSR t_phase 表），phaseLabel 查表回写，未知相位回退原键。
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
    // children 增量更新逻辑仅 task 页注入。
    let children_fns: String = if with_children {
        // .arch-duration 补建时的 title 提示词（与 SSR arch_duration 同 key）。
        let dur_title = js_str(t(lang, TextKey::TitleDuration));
        let dur_fmt = dur_fmt_js("fmtDur");
        format!(
            r#"
                var ARCH_DUR_TITLE = '{dur_title}';
                {dur_fmt}
                // .arch-duration get-or-create：SSR 只在 duration 已知时渲染该
                // span（arch_matrix），live 期间完成的子构建 cell 里缺位——首
                // 个 duration>0 事件到达时补建（title 与 SSR 同词、append 到
                // cell 末位，SSR started/未 started 两分支它都是末位子元素），
                // 否则子构建完成时长缺失直到 task 终态 reload。
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
                    // 聚合摘要行随同一次 children payload 重算（data-pattern 为
                    // 服务端注入的带参模板原文；口径与 SSR 一致：total=全量、
                    // succeeded/failed 各只计本相位）。无该元素（非 task 页）跳过。
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
    // timeline 逻辑仅 build 页注入；函数段在 EventSource 前、挂载段在其后（es 须已存在）。
    let timeline_listener: &str = if with_timeline {
        "                es.addEventListener('timeline', function(ev) {\n                    try { applyTimeline(JSON.parse(ev.data)); } catch (e) {}\n                });\n"
    } else {
        ""
    };
    let timeline_fns: String = if with_timeline {
        // 显示名/SKIP 回退词同 log_sse_script 口径；fmtStepDur 同服务端格式；HIDDEN_TOOL_PHASES 显式跳过。
        let step_labels = step_labels_json(lang);
        let fmt_step_dur = step_duration_js("fmtStepDur");
        let timeline_step_el = step_el_js("timelineStepEl");
        let timeline_set_detail = set_detail_js("timelineSetDetail");
        let find_step: &str = FIND_STEP_JS;
        let hidden_phases = hidden_tool_phases_js();
        let skipped_text = js_str(t(lang, TextKey::PhaseSkipped));
        format!(
            r#"
                // 详情页时间线 live 更新：服务端 build SSE 附带 timeline
                // 事件（通知驱动、签名变化才推）。按 name 匹配 .phase-step
                // （缺失则 append——裸形态同 log_sse_script stepEl，style.css
                // 对两种形态都成立），className 与 .phase-step-detail 整步
                // 覆写，重复/乱序事件无副作用。
                var STEP_LABELS = {{{step_labels}}};
                // 隐藏工具步骤名单（服务端 visible_timeline_spans 同表，真源
                // HIDDEN_TOOL_PHASES）：timeline 负载服务端本已过滤，此处防漂移兜底。
                var HIDDEN_PHASES = {{{hidden_phases}}};
                {fmt_step_dur}
                // 按 data-phase 遍历比对定位步骤：name 来自构建输出的
                // CRBS_PHASE 标记（用户可控），拼进 querySelector 遇引号即
                // SyntaxError 并炸掉整个 applyTimeline——遍历 + 属性全等比对
                // 没有注入面。
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
    // Lifecycle 行"至今"走秒器仅 build 页注入（该页 Details 含 .lc-so-far 行；
    // task 页无 .lc-so-far，不注入死代码）。
    let elapsed_fns: String = if with_elapsed {
        let lc_dur = dur_fmt_js("lcDur");
        format!(
            r#"
                // Lifecycle"至今"值走秒：SSR 渲 .lc-so-far[data-ts][data-tpl]
                //（data-tpl 为 i18n 模板原文，{{0}} 占位时长——同 task 页
                // .matrix-summary[data-pattern] 先例），本地 10s 重渲，服务端
                // 签名去重期间也保持新鲜；pending 排队与 running 时长两处消费。
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
                // 相位显示名按 lang 注入（与 SSR t_phase 同表）；未知相位回退原键。
                var PHASE_LABELS = {{{phase_labels}}};
                function phaseLabel(p) {{
                    return PHASE_LABELS[p] || p;
                }}
                var badge = document.querySelector('.phase-badge');
                // 本页打开时的服务端渲染 phase：已终态则整页都是最终字段。
                // 守卫只读 data-phase（语言无关通道；zh 徽章文本是本地化显示名，
                // 不能作终态判定——读文本在语言切换下不可靠）。属性缺失
                // 一律按非终态处理（fail-open 到 live）：文本兜底只在 En 恰好
                // 同值，属不可预测路径，故不采用。
                var startedLive = !(badge && isTerminal(badge.getAttribute('data-phase')));
                {terminal_hint}
                // 仅在用户点击"通知我"武装（window.__crbsNotify）且已授权时
                // 弹系统通知；构造只在本函数（终态分支调用），权限请求不在此。
                function notifyFinished(phase) {{
                    if (!window.__crbsNotify || !window.Notification
                        || Notification.permission !== 'granted') return;
                    try {{
                        new Notification('{notify_title}', {{
                            // body 的相位词经 phaseLabel 查表（与徽章同表），
                            // zh 页通知 body 不再是英文原键。
                            body: phaseLabel(phase) + ' — ' + window.__crbsNotify,
                            lang: '{notify_lang}',
                            tag: '{notify_tag}'
                        }});
                    }} catch (e) {{}}
                }}
                // 终态迁移自动整页刷新一次：产物表/签名状态/总时长/兄弟构建
                // 列表不随 SSE 增量更新，只有整页重取才能拿到终态数据。延迟
                // 1500ms 给终态收尾（产物登记、签名标记、日志落盘）留时间，
                // 避免 reload 回来仍是半终态；reloadScheduled 守卫保证只调度
                // 一次（唯一调用点在下方 startedLive 块内，重复终态事件兜底）。
                // terminal-hint 保留为兜底（reload 被拦截/失败仍可手动刷新）。
                var reloadScheduled = false;
                function scheduleReloadOnce() {{
                    if (reloadScheduled) return;
                    reloadScheduled = true;
                    setTimeout(function() {{ location.reload(); }}, 1500);
                }}
                {children_fns}{timeline_fns}{elapsed_fns}
                var es = new EventSource('{url}');
                es.addEventListener('{event}', function(ev) {{
                    // phase 在一切 DOM 更新之前捕获、终态分支整体在
                    // try/catch 之外（对齐 log 页 end 监听器 close 在 try 外的
                    // 形态）——监听器在终态判定前抛异常（catch 吞）时若漏关流，
                    // 服务端终态即断流、客户端按 retry 间隔重连环。JSON 解析
                    // 失败（phase 未捕获）无法判终态，维持旧语义不 close。
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
                // 瞬时 error 仍由浏览器自动重连（setLive 的重连中文
                // 案）；CLOSED（复鉴权断流、握手终败等）是浏览器已放弃重连的
                // 终态，title 换终态文案（对齐 pending_log 的 CLOSED 判定先例，
                // 幂等覆写无需一次性守卫）。
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
