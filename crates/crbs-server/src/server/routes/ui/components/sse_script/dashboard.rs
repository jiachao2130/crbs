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
    let dead_title = js_str(t(lang, TextKey::ConnectionClosed));
    let title_pattern = js_str(donut_row_title_pattern(lang));
    let title_name_from_key = matches!(lang, Lang::En);
    let set_live = set_live_js(&live_title, &lost_title);
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                var TITLE_PATTERN = '{title_pattern}';
                var TITLE_NAME_FROM_KEY = {title_name_from_key};
                {set_live}
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
                            var nm = row.querySelector('.name');
                            var segName = TITLE_NAME_FROM_KEY ? s.phase : (nm ? nm.textContent : s.phase);
                            var pct1 = (r.total ? s.n / r.total * 100 : 0).toFixed(1);
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
                es.onerror = function() {{
                    setLive(false);
                    if (es.readyState === EventSource.CLOSED) {{
                        var el = document.querySelector('.live-indicator');
                        if (el) el.title = '{dead_title}';
                    }}
                }};
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
