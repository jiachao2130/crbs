// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 仪表盘 SSE 脚本。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{donut_row_title_pattern, t, Lang, TextKey};

use super::common::*;

pub(crate) fn dashboard_sse_script(nonce: &str, lang: Lang) -> Markup {
    let live_title = js_str(t(lang, TextKey::LiveUpdatesEnabled));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    // CLOSED 终态文案（EventSource 永久失活后不再声称重连）。
    let dead_title = js_str(t(lang, TextKey::ConnectionClosed));
    // 图例 title 模板（同 SSR donut_row_title 表）：count/pct 更新后整句重算，不停留在 SSR 快照。
    let title_pattern = js_str(donut_row_title_pattern(lang));
    // 段名口径（同 donut_row_title）：En 用 phase 键，zh 用图例 .name 文本。
    let title_name_from_key = matches!(lang, Lang::En);
    let set_live = set_live_js(&live_title, &lost_title);
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                // 图例 title 模板（{{0}}=段名 {{1}}=count {{2}}=一位小数 pct {{3}}=英文
                // 复数单位词，zh 模板不引用 {{3}}）；TITLE_NAME_FROM_KEY：En 段名
                // 用 phase 键、zh 用图例 .name 文本（与 SSR donut_row_title 同口径）。
                var TITLE_PATTERN = '{title_pattern}';
                var TITLE_NAME_FROM_KEY = {title_name_from_key};
                {set_live}
                // SSE payload（StatusResponse serde 命名）→ 图表 phase 键的映射：
                // running←tasks.building、queued←tasks.pending，其余同名。
                var PHASES = ['running', 'queued', 'succeeded', 'failed', 'timeout', 'cancelled'];
                function payloadCounts(t) {{
                    return {{
                        running: t.building,
                        queued: t.pending,
                        succeeded: t.succeeded,
                        failed: t.failed,
                        timeout: t.timeout,
                        cancelled: t.cancelled
                    }};
                }}
                // 与服务端 donut_chart 相同的弧长数学：
                // 2% 保底可见、超出部分从最大段扣回、累计 offset。
                var R = 81, C = 2 * Math.PI * R, MIN = 0.02;
                function segs(counts) {{
                    var total = 0;
                    PHASES.forEach(function(p) {{ total += counts[p]; }});
                    var out = PHASES.map(function(p) {{
                        var n = counts[p];
                        var frac = total ? n / total : 0;
                        if (n > 0 && frac < MIN) frac = MIN;
                        return {{ phase: p, n: n, frac: frac }};
                    }});
                    var used = 0;
                    out.forEach(function(s) {{ used += s.frac; }});
                    if (used > 1) {{
                        var big = out[0];
                        out.forEach(function(s) {{ if (s.frac > big.frac) big = s; }});
                        big.frac -= used - 1;
                    }}
                    var acc = 0;
                    out.forEach(function(s) {{ s.offset = acc; acc += s.frac; }});
                    return {{ out: out, total: total }};
                }}
                function renderDonut(counts) {{
                    var r = segs(counts);
                    // 空态满环（donut_chart total=0 时 SSR 的 circle.seg-empty）：
                    // 首个非空 status 到达即移除，避免灰环叠在彩色扇区下成双环；
                    // total 回落 0（行清理后的全零 status）时按需按 SSR 同形态
                    // 重建（g 首子垫底、r 与扇区同径、无 data-phase，颜色走
                    // style.css 的 .seg-empty 令牌），donut 不残留"无弧亦无
                    // 灰环"的空态直到 reload。
                    var emptyRing = document.querySelector('circle.seg-empty');
                    if (r.total > 0) {{
                        if (emptyRing) emptyRing.remove();
                    }} else if (!emptyRing) {{
                        var g = document.querySelector('svg.donut g');
                        if (g) {{
                            emptyRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
                            emptyRing.setAttribute('class', 'seg-empty');
                            emptyRing.setAttribute('r', String(R));
                            g.insertBefore(emptyRing, g.firstChild);
                        }}
                    }}
                    r.out.forEach(function(s) {{
                        var seg = document.querySelector('circle.seg[data-phase="' + s.phase + '"]');
                        if (seg) {{
                            var len = s.frac * C;
                            seg.style.strokeDasharray = len + ' ' + (C - len);
                            seg.style.strokeDashoffset = String(-s.offset * C);
                        }}
                        var row = document.querySelector('.legend-row[data-phase="' + s.phase + '"]');
                        if (row) {{
                            var count = row.querySelector('.count');
                            if (count) count.textContent = s.n;
                            var pct = row.querySelector('.pct');
                            if (pct) pct.textContent = (r.total ? Math.round(s.n / r.total * 100) : 0) + '%';
                            // title 与 count/pct 同步重算（复刻 SSR donut_row_title：
                            // 一位小数百分比；段名口径按 TITLE_NAME_FROM_KEY），
                            // 不停留在 SSR 快照。
                            var nm = row.querySelector('.name');
                            var segName = TITLE_NAME_FROM_KEY ? s.phase : (nm ? nm.textContent : s.phase);
                            var pct1 = (r.total ? s.n / r.total * 100 : 0).toFixed(1);
                            // segName 走回调替换——字符串替换参数的
                            // `$` 有特殊语义（$& 等），值来自图例 DOM 文本，
                            // 回调形式免疫该隐性契约（其余参数是数字/固定词）。
                            row.title = TITLE_PATTERN
                                .replace('{{0}}', function() {{ return segName; }})
                                .replace('{{1}}', s.n)
                                .replace('{{2}}', pct1)
                                .replace('{{3}}', s.n === 1 ? 'task' : 'tasks');
                        }}
                    }});
                    var el = document.getElementById('dash-donut-total');
                    if (el) el.textContent = r.total;
                    el = document.getElementById('dash-donut-running');
                    if (el) el.textContent = counts.running;
                    el = document.getElementById('dash-donut-queued');
                    if (el) el.textContent = counts.queued;
                }}
                // Recent tasks 表随 status 事件节流换新（与 donut 同一数据触发，
                // 消除"状态卡已变、最近任务仍是快照"的割裂）：10s 节流防事件
                // 风暴打点；到点重取片段整体替换 #recent-tasks 并重挂行点击。
                var recentLast = 0, recentTimer = null;
                function refreshRecent() {{
                    var box = document.getElementById('recent-tasks');
                    if (!box) return;
                    var now = Date.now();
                    if (now - recentLast < 10000) {{
                        if (!recentTimer) recentTimer = setTimeout(refreshRecent, 10000 - (now - recentLast));
                        return;
                    }}
                    recentLast = now;
                    if (recentTimer) {{ clearTimeout(recentTimer); recentTimer = null; }}
                    fetch('/ui/home/recent-tasks')
                        .then(function(r) {{ return r.ok ? r.text() : null; }})
                        .then(function(html) {{
                            if (html == null) return;
                            var box = document.getElementById('recent-tasks');
                            if (!box) return;
                            box.innerHTML = html;
                            if (window.__crbsBindClickableRows) window.__crbsBindClickableRows();
                        }})
                        .catch(function() {{}});
                }}
                var es = new EventSource('/ui/events');
                es.addEventListener('status', function(ev) {{
                    try {{
                        var data = JSON.parse(ev.data);
                        if (data.tasks) renderDonut(payloadCounts(data.tasks));
                        if (data.workers) {{
                            var w = document.getElementById('dash-workers-online');
                            if (w) w.textContent = data.workers.online;
                        }}
                        refreshRecent();
                    }} catch (e) {{}}
                }});
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
                // hover 联动（事件委托到 document，扇区与图例行共用）：
                // 进入任一 [data-phase] 元素时，同 phase 元素加 .hot、svg 加
                // .dimmed；离开还原。无 tooltip div——精确数值走原生 title。
                function setHot(phase, on) {{
                    var donut = document.querySelector('svg.donut');
                    if (donut) donut.classList.toggle('dimmed', on);
                    var els = document.querySelectorAll('[data-phase="' + phase + '"]');
                    Array.prototype.forEach.call(els, function(x) {{ x.classList.toggle('hot', on); }});
                }}
                document.addEventListener('mouseover', function(e) {{
                    var el = e.target && e.target.closest ? e.target.closest('[data-phase]') : null;
                    if (el) setHot(el.getAttribute('data-phase'), true);
                }});
                document.addEventListener('mouseout', function(e) {{
                    var el = e.target && e.target.closest ? e.target.closest('[data-phase]') : null;
                    if (el) setHot(el.getAttribute('data-phase'), false);
                }});
            }})();
        "#, dead_title = dead_title))) }
    }
}
