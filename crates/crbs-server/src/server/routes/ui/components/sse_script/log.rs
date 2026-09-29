// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建日志 SSE 脚本。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, Lang, TextKey};

use super::super::phase::{sub_bucket_tip_prefix, sub_phase_running_word, SUBPHASE_BUCKETS};

use super::common::*;

/// pending/assigned 日志页"转活"脚本：phase 离开排队态即 es.close + 整页
/// reload——该页无可增量更新的控件，reload 即唯一反馈（故无 live-indicator）；
/// 断线仅 CLOSED 一次性插本地化文案，瞬时 error 交浏览器自动重连。
pub(crate) fn pending_log_sse_script(build_id: i64, nonce: &str, lang: Lang) -> Markup {
    let url = format!("/ui/builds/{build_id}/events");
    let closed_text = js_str(t(lang, TextKey::ConnectionClosed));
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                var es = new EventSource('{url}');
                es.addEventListener('build', function(ev) {{
                    try {{
                        var data = JSON.parse(ev.data);
                        if (data.phase && data.phase !== 'pending' && data.phase !== 'assigned') {{
                            es.close();
                            location.reload();
                        }}
                    }} catch (e) {{}}
                }});
                var closedShown = false;
                es.onerror = function() {{
                    if (es.readyState !== EventSource.CLOSED || closedShown) return;
                    closedShown = true;
                    var note = document.createElement('p');
                    note.textContent = '{closed_text}';
                    var main = document.querySelector('main');
                    if (main) main.appendChild(note);
                }};
            }})();
        "#, url = url, closed_text = closed_text))) }
    }
}

/// 日志页 SSE 脚本（building 分支内联）。控件（Follow / Jump to bottom /
/// Download）由服务端在 `.log-actions` 渲染，脚本只按 id 挂事件。终态 `end`：
/// 关流 + 插 `.terminal-hint`。断线交浏览器原生重连（Last-Event-ID 续传），
/// error 只切 live 指示灯。
///
/// 时间线增量更新总是注入：SSE chunk 不按行对齐，自维护行缓冲逐行匹配
/// `CRBS_PHASE_*` 标记更新 `.phase-step`，渲染复用同一缓冲；容器缺位由
/// timelineEl() 就地补建，标记推进不依赖 SSR 快照。
///
/// `offset`：SSR 预览末尾偏移。Some(非零) 拼 `?offset=N`（服务端起播优先级
/// Last-Event-ID > ?offset > 默认 tail），不重放不跳行；None/零值不带参数
/// （默认 tail）。
pub(crate) fn log_sse_script(
    build_id: i64,
    offset: Option<u64>,
    nonce: &str,
    lang: Lang,
) -> Markup {
    let hint_text = js_str(t(lang, TextKey::HintLogComplete));
    let view_label = js_str(t(lang, TextKey::ViewBuildPage));
    let live_title = js_str(t(lang, TextKey::LiveLogStream));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    let skipped_text = js_str(t(lang, TextKey::PhaseSkipped));
    let step_labels = step_labels_json(lang);
    let fmt_dur = step_duration_js("fmtDur");
    let step_el_fn = step_el_js("stepEl");
    let set_detail_fn = set_detail_js("setDetail");
    let find_step: &str = FIND_STEP_JS;
    let set_live = set_live_js(&live_title, &lost_title);
    let hidden_phases = hidden_tool_phases_js();
    let subphase_tip_prefixes = SUBPHASE_BUCKETS
        .iter()
        .map(|b| {
            format!(
                "\"{}\":\"{}\"",
                js_str(b.name),
                js_str(&sub_bucket_tip_prefix(lang, b.name))
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let subphase_running = js_str(sub_phase_running_word(lang));
    let build_url = format!("/ui/builds/{build_id}");
    let terminal_hint = terminal_hint_js(&hint_text, &format!("'{}'", build_url), &view_label);
    let stream_url = match offset {
        Some(n) if n > 0 => format!("/ui/builds/{build_id}/logs/stream?offset={n}"),
        _ => format!("/ui/builds/{build_id}/logs/stream"),
    };
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                {set_live}
                var output = document.getElementById('log-output');
                if (!output) return;
                var followToggle = document.getElementById('follow-toggle');
                var jumpButton = document.getElementById('jump-bottom');
                function nearBottom() {{
                    return output.scrollTop + output.clientHeight >= output.scrollHeight - 10;
                }}
                {terminal_hint}
                function timelineEl() {{
                    var tl = document.querySelector('.phase-timeline');
                    if (!tl) {{
                        tl = document.createElement('div');
                        tl.className = 'phase-timeline';
                        var anchor = document.querySelector('.log-actions') || output;
                        anchor.parentNode.insertBefore(tl, anchor);
                    }}
                    return tl;
                }}
                {fmt_dur}
                {find_step}
                {step_el_fn}
                var STEP_LABELS = {{{step_labels}}};
                var HIDDEN_PHASES = {{{hidden_phases}}};
                {set_detail_fn}
                function applyPhaseMarker(line) {{
                    var m = line.match(/^\s*#?\s*CRBS_PHASE_(START|END|SKIP)\s+(\S+)\s*(.*)$/);
                    if (!m) return;
                    if (HIDDEN_PHASES[m[2]]) return;
                    var el = stepEl(timelineEl(), m[2]);
                    if (m[1] === 'START') {{
                        var ts = parseFloat(m[3].split(/\s+/)[0]);
                        el.className = 'phase-step running';
                        if (isFinite(ts)) el.setAttribute('data-start', String(ts));
                        setDetail(el, '\u2026');
                    }} else if (m[1] === 'END') {{
                        var parts = m[3].split(/\s+/);
                        var start = parseFloat(el.getAttribute('data-start'));
                        var endTs = parseFloat(parts[1]);
                        el.className = 'phase-step ' + (parseInt(parts[0], 10) === 0 ? 'done' : 'failed');
                        setDetail(el, (isFinite(start) && isFinite(endTs)) ? fmtDur(endTs - start) : '');
                        if (m[2] === 'build') settleSubBar(endTs);
                    }} else {{
                        el.className = 'phase-step skipped';
                        setDetail(el, m[3].trim() || '{skipped_text}');
                    }}
                }}
                var SUBPHASE_TIP = {{{subphase_tip_prefixes}}};
                var BUCKET_OF = {{"%prep":"prep","%build":"build","%install":"package"}};
                var SUBPHASE_RUNNING = '{subphase_running}';
                function subphaseTitle(name, dur) {{
                    return (SUBPHASE_TIP[name] || (name + ' — ')) + dur;
                }}
                function applySubPhase(name, ts) {{
                    var bucket = BUCKET_OF[name];
                    if (!bucket) return;
                    var step = document.querySelector('.phase-step[data-phase="build"]');
                    if (!step) return;
                    var bar = step.querySelector('.tl-segbar');
                    if (!bar) {{
                        bar = document.createElement('div');
                        bar.className = 'tl-segbar';
                        step.appendChild(bar);
                    }}
                    var segs = bar.querySelectorAll('.tl-seg');
                    if (segs.length > 0) {{
                        var last = segs[segs.length - 1];
                        if (last.getAttribute('data-name') === bucket) return;
                        var start = parseFloat(last.getAttribute('data-start'));
                        if (isFinite(ts) && isFinite(start)) {{
                            last.style.flex = Math.max(0.5, ts - start);
                            var lastName = last.getAttribute('data-name');
                            if (lastName) {{
                                last.setAttribute('title', subphaseTitle(lastName, fmtDur(ts - start)));
                            }}
                        }}
                    }}
                    var seg = document.createElement('div');
                    seg.className = 'tl-seg';
                    seg.setAttribute('data-start', String(ts));
                    seg.setAttribute('data-name', bucket);
                    seg.setAttribute('title', subphaseTitle(bucket, SUBPHASE_RUNNING));
                    bar.appendChild(seg);
                }}
                function settleSubBar(ts) {{
                    var step = document.querySelector('.phase-step[data-phase="build"]');
                    if (!step) return;
                    var bar = step.querySelector('.tl-segbar');
                    if (!bar) return;
                    var last = bar.querySelector('.tl-seg:last-child');
                    if (!last) return;
                    var start = parseFloat(last.getAttribute('data-start'));
                    if (!isFinite(ts) || !isFinite(start)) return;
                    last.style.flex = Math.max(0.5, ts - start);
                    var nm = last.getAttribute('data-name');
                    if (nm) last.setAttribute('title', subphaseTitle(nm, fmtDur(ts - start)));
                }}
                function applyLine(line) {{
                    applyPhaseMarker(line);
                    var m = line.match(/^\s*#?\s*CRBS_SUBPHASE\s+(\S+)\s+([0-9.]+)/);
                    if (m) applySubPhase(m[1], parseFloat(m[2]));
                }}
                var pendingLine = '';
                var activeLine = null;
                var MAX_LOG_SPANS = 5000;
                function renderLines(lines) {{
                    if (!lines.length) return;
                    if (activeLine) {{
                        activeLine.textContent = lines[0] + '\n';
                        activeLine = null;
                        lines = lines.slice(1);
                        if (!lines.length) return;
                    }}
                    var span = document.createElement('span');
                    span.textContent = lines.join('\n') + '\n';
                    output.appendChild(span);
                    while (output.childNodes.length > MAX_LOG_SPANS) {{
                        output.removeChild(output.firstChild);
                    }}
                }}
                function renderPending() {{
                    if (!pendingLine) return;
                    if (!activeLine) {{
                        activeLine = document.createElement('span');
                        output.appendChild(activeLine);
                        while (output.childNodes.length > MAX_LOG_SPANS) {{
                            output.removeChild(output.firstChild);
                        }}
                    }}
                    activeLine.textContent = pendingLine;
                }}
                var es = new EventSource('{stream_url}');
                es.addEventListener('log', function(ev) {{
                    try {{
                        pendingLine += ev.data;
                        var shouldScroll = !!followToggle && followToggle.checked && nearBottom();
                        var lines = [];
                        var idx;
                        while ((idx = pendingLine.indexOf('\n')) >= 0) {{
                            lines.push(pendingLine.slice(0, idx));
                            pendingLine = pendingLine.slice(idx + 1);
                        }}
                        for (var i = 0; i < lines.length; i++) applyLine(lines[i]);
                        renderLines(lines);
                        renderPending();
                        if (shouldScroll) {{
                            output.scrollTop = output.scrollHeight;
                        }}
                    }} catch (e) {{
                        console.warn('crbs log render failed', e);
                    }}
                }});
                es.addEventListener('end', function(ev) {{
                    es.close();
                    setLive(false);
                    if (pendingLine) {{
                        renderLines([pendingLine]);
                        pendingLine = '';
                    }}
                    var phase = '';
                    try {{
                        phase = (JSON.parse(ev.data) || {{}}).phase || '';
                    }} catch (e) {{}}
                    showTerminalHint(phase);
                }});
                if (jumpButton) {{
                    jumpButton.addEventListener('click', function() {{
                        output.scrollTop = output.scrollHeight;
                    }});
                }}
                es.addEventListener('error', function() {{ setLive(false); }});
                es.onopen = function() {{ setLive(true); }};
                window.addEventListener('beforeunload', function() {{ es.close(); }});
            }})();
        "#, stream_url = stream_url, skipped_text = skipped_text, step_labels = step_labels, subphase_tip_prefixes = subphase_tip_prefixes, subphase_running = subphase_running))) }
    }
}

/// 日志页 `?line=N` 行固定位（失败子阶段 / subpanel 跳转落点）：#log-output
/// 第 N 行包高亮 span 并滚到视口中央；行号超出内容（截断 tail / 空日志）
/// 整体 no-op。终态页与 building 页共用（未截断时行号一致）。
///
/// 重建不受 MAX_LOG_SPANS 约束：本脚本在页面加载时一次性执行、先于 live
/// append，裁头部行会使行号偏移、基准点失准。此后 live append 触顶裁最老，
/// 可能裁掉 .log-line-hit 高亮行——降级可接受，DOM 有上限优先。
pub(crate) fn log_line_anchor_script(line: u64, nonce: &str) -> Markup {
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                var output = document.getElementById('log-output');
                if (!output) return;
                var target = {line};
                var lines = output.textContent.split('\n');
                if (target < 1 || target > lines.length) return;
                output.textContent = '';
                lines.forEach(function(text, i) {{
                    var span = document.createElement('span');
                    span.textContent = text + '\n';
                    if (i === target - 1) span.className = 'log-line-hit';
                    output.appendChild(span);
                }});
                var hit = output.querySelector('.log-line-hit');
                if (hit) hit.scrollIntoView({{ block: 'center' }});
            }})();
        "#))) }
    }
}
