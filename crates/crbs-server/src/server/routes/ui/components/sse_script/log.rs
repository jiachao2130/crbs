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
    // 仅 CLOSED（浏览器已放弃重连）时插入，用 ConnectionClosed key（三脚本同语境）。
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
                // 断线一次性提示：只在 EventSource 永久关闭（CLOSED，
                // 服务端不可达/握手终败）时插入，重连中的瞬时 error 不插；
                // closedShown 保证只插一次。
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
    // ok title 与 SSR 同键（LiveLogStream），首事件覆写后仍是 log 语义；
    // 断线走 ConnectionLost。
    let live_title = js_str(t(lang, TextKey::LiveLogStream));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    // SKIP 标记无 reason 时的回退词（与服务端 phase_timeline 同词）。
    let skipped_text = js_str(t(lang, TextKey::PhaseSkipped));
    // 步骤显示名映射（同 SSR phase_step_label 表）：live 新建 .phase-step
    // 回填本地化标签，未知名回退原串；HIDDEN_TOOL_PHASES 不在表内，显式跳过。
    let step_labels = step_labels_json(lang);
    let fmt_dur = step_duration_js("fmtDur");
    let step_el_fn = step_el_js("stepEl");
    let set_detail_fn = set_detail_js("setDetail");
    let find_step: &str = FIND_STEP_JS;
    let set_live = set_live_js(&live_title, &lost_title);
    let hidden_phases = hidden_tool_phases_js();
    // 分段条桶 title 同 SSR 桶段词与格式，真源 phase.rs：SUBPHASE_TIP 按
    // SUBPHASE_BUCKETS 逐桶生成，BUCKET_OF 的值域即本表键集。
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
    // 预览末尾偏移续接（见函数文档）；零值与 None 同走默认 tail。
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
                // 阶段时间线增量更新：行缓冲 + 标记匹配（与 format_phase_duration 同格式）。
                // SSR（building 分支）恒渲染 .phase-timeline；容器万一缺位（旧页面
                // 缓存等）就近补建在 .log-actions 之前（SSR 同位）——不能再像旧守卫
                // 那样容器缺席就丢弃标记（大日志 SSR spans 曾为空，标记被尽数吞掉）。
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
                // 按 data-phase 遍历比对定位步骤（与详情页 findStep 同形态）：
                // name 来自构建输出的 CRBS_PHASE 标记（用户可控），拼进
                // querySelector 遇引号即 SyntaxError 并炸掉整个 log 监听器。
                {find_step}
                {step_el_fn}
                var STEP_LABELS = {{{step_labels}}};
                // 隐藏工具步骤名单（与服务端渲染过滤同表，真源 HIDDEN_TOOL_PHASES）：
                // ccache-init/ccache-summary 标记仍随日志流到达，不新建/推进步骤。
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
                        // build END（exit!=0 也结算）：分段条末段按 END 时间戳收尾。
                        if (m[2] === 'build') settleSubBar(endTs);
                    }} else {{
                        el.className = 'phase-step skipped';
                        setDetail(el, m[3].trim() || '{skipped_text}');
                    }}
                }}
                // 子阶段分段条 live 推进：CRBS_SUBPHASE <name> <ts>。三桶位置式
                // 状态机（与 SSR 分段条同口径）：只有 %prep/%build/%install 三个
                // 切桶名经 BUCKET_OF 建段，其余子段名（%doc/%license/%clean/
                // %check 等）不建段、也不结算上一段——打包桶时长自然延伸到下一
                // 个切桶标记或 build END。段 title 与 SSR 桶段同词同格式——建段
                // 挂“前缀 + 进行中”，结算（下一标记到达）按段上 data-start 重算
                // “前缀 + 时长”；前缀表与 running 词由服务端按 lang 注入，真源
                // phase.rs 的 SUBPHASE_BUCKETS（BUCKET_OF 值域 = SUBPHASE_TIP 键集）。
                var SUBPHASE_TIP = {{{subphase_tip_prefixes}}};
                var BUCKET_OF = {{"%prep":"prep","%build":"build","%install":"package"}};
                var SUBPHASE_RUNNING = '{subphase_running}';
                function subphaseTitle(name, dur) {{
                    return (SUBPHASE_TIP[name] || (name + ' — ')) + dur;
                }}
                function applySubPhase(name, ts) {{
                    var bucket = BUCKET_OF[name];
                    // 非切桶名直接返回：打包桶不被 %license/%clean 截断。
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
                        // 桶已在条末（同名切桶标记重复到达）不重复建段。
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
                // 分段条末段按给定时间戳结算（宽度 + title）：build END 收尾用。
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
                // 渲染行缓冲：SSE chunk 是 4096 字节任意边界块，渲染必须与
                // 解析（applyLine 路径）共用同一行缓冲对齐——同一事件内处理出
                // 的完整行合并进单个多行 span（行中不换行、行尾恰一个 \n，
                // 语义与逐行 span 一致；DOM 节点数回到 chunk 量级：GB 级日志
                // ~百万行不再生成百万节点、10MB 缓冲满载 ~10 万节点），半行
                // 驻留"活动行" span 覆盖更新（实时可见），下一事件的首行到达
                // 时结算为整行。
                var pendingLine = '';
                var activeLine = null;
                // DOM 上限：#log-output 子节点封顶（超限从顶部裁最老
                // span）。取 5000 的依据：合并渲染下 10MB 日志缓冲整放约 2.6k
                // span（4096 字节 chunk 量级），上限 > 整放量，正常回放永不
                // 裁剪；只有后台标签挂长构建持续 append 才触顶，DOM 有界
                //（只追加不裁剪会无界增长）。裁剪安全性：EventSource 游标
                // （Last-Event-ID）由浏览器管理，与 DOM 节点无关；jump-bottom
                // 按 scrollHeight 滚动；?line=N 行号锚点脚本在页面加载时一次性
                // 执行，先于任何 live append；activeLine 恒为末子节点，顶部
                // 裁剪删不到它。
                var MAX_LOG_SPANS = 5000;
                function renderLines(lines) {{
                    if (!lines.length) return;
                    if (activeLine) {{
                        // 活动 span 持有该行已到达的前缀：结算 = 覆盖为完整行。
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
                        // 与 renderLines 同款裁剪——本函数 append
                        // 后不裁的话稳态上界实为 MAX+1；activeLine 恒为末
                        // 子节点，顶部裁剪删不到它。
                        while (output.childNodes.length > MAX_LOG_SPANS) {{
                            output.removeChild(output.firstChild);
                        }}
                    }}
                    activeLine.textContent = pendingLine;
                }}
                var es = new EventSource('{stream_url}');
                es.addEventListener('log', function(ev) {{
                    // 整体 try/catch（对齐全脚本其他监听器的韧性形态）：
                    // 单监听器异常不得中断后续事件流。
                    try {{
                        pendingLine += ev.data;
                        // Follow 开（且用户仍在底部附近）才自动滚动；关掉 Follow 完全不滚。
                        var shouldScroll = !!followToggle && followToggle.checked && nearBottom();
                        var lines = [];
                        var idx;
                        while ((idx = pendingLine.indexOf('\n')) >= 0) {{
                            lines.push(pendingLine.slice(0, idx));
                            pendingLine = pendingLine.slice(idx + 1);
                        }}
                        // 解析按行（标记匹配以 \n 为界），渲染按事件合并（renderLines）。
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
                    // 残余半行冲刷：流结束时行缓冲可能仍有未换行的最后一行，
                    // 补 \n 落盘显示。
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

/// 日志页 `?line=N` 行锚定位（失败子阶段 / subpanel 跳转落点）：#log-output
/// 第 N 行包高亮 span 并滚到视口中央；行号超出内容（截断 tail / 空日志）
/// 整体 no-op。终态页与 building 页共用（未截断时行号一致）。
///
/// 重建不受 MAX_LOG_SPANS 约束：本脚本在页面加载时一次性执行、先于 live
/// append，裁头部行会使行号漂移、锚点失准。此后 live append 触顶裁最老，
/// 可能裁掉 .log-line-hit 高亮行——降级可接受，DOM 有界优先。
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
