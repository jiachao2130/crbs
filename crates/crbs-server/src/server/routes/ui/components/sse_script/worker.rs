// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 详情 SSE 脚本。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{
    rel_time_patterns, t, t_fmt, t_phase, FmtKey, Lang, TextKey,
};

use crate::server::routes::ui::pages::REL_TIME_ABSOLUTE_DAYS;

// 直连 layout 姊妹模块：色阶阈值单源注入 worker 脚本（名字域外零消费者）。
use super::super::layout::{resource_cap_bits, LOAD_LEVEL_CRIT_PCT, LOAD_LEVEL_WARN_PCT};

use super::common::*;

/// Worker 详情页 SSE 脚本：`event: worker` 快照就地更新遥测条/状态徽章/
/// 心跳相对时间/活动构建表/Recent builds 卡。与 phase 脚本的关键差异：
/// worker 无"终态 reload"——offline 收到终态事件后 close + reload 一次（SSR
/// 离线页不渲染本脚本，reload 不会成环）；相对时间/活动行耗时由本地 10s
/// ticker 从 data-ts 持续重渲（服务端签名去重期间也保持新鲜；相对时间绝对
/// 化天数与负载色阶阈值由 SSR 常量注入，单源防漂移）。
///
/// DOM 契约（worker_detail_page SSR 产出，id/类名由集成测试钉住）：
/// `.worker-status-badge`（h1 徽章）、`#w-cpu-bar` / `#w-mem-bar`（load-bar span，
/// title 承载辅助口径）、`#w-cpu-pct` / `#w-mem-pct`（% 数字）、`#w-load-val`
/// （负载倍数文本，title 承载绝对口径）、`#w-disk-val`（磁盘绝对值文本）、
/// `#w-caps-chips`（能力 chips 容器，SSR 按需渲染，缺位略过）、`#w-hb` /
/// `#w-tel-time`（相对时间 span，data-ts = DB 时间原文）、`#w-tel-stale`
///（stale 标记，hidden 切换）、`#w-active-table` + `#w-active-tbody` +
/// `#w-active-empty`、`#w-recent-head`（卡头 h2，内含 `.count-chip`）+
/// `#w-recent-table` + `#w-recent-tbody` + `#w-recent-empty`（行重建键
/// `tr[data-recent-build]`，内含 `.badge` 与 `.recent-dur`，data-start/data-done
/// 承载耗时口径）。
pub(crate) fn worker_sse_script(worker_id: i64, nonce: &str, lang: Lang) -> Markup {
    let url = format!("/ui/workers/{worker_id}/events");
    let live_title = js_str(t(lang, TextKey::LiveUpdatesEnabled));
    let lost_title = js_str(t(lang, TextKey::ConnectionLost));
    // CLOSED 终态文案（worker 删除后握手 404 → EventSource 永久失活）。
    let dead_title = js_str(t(lang, TextKey::ConnectionClosed));
    let set_live = set_live_js(&live_title, &lost_title);
    // 徽章/相位显示名注入表：worker 状态三词（stale/online/offline）+ 7 相位。
    let worker_labels = [
        ("online", t(lang, TextKey::WorkerOnline)),
        ("stale", t(lang, TextKey::WorkerStale)),
        ("offline", t(lang, TextKey::WorkerOffline)),
    ]
    .iter()
    .map(|(k, v)| format!("\"{}\":\"{}\"", k, js_str(v)))
    .collect::<Vec<_>>()
    .join(",");
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
    // 相对时间四档模板、CPU 辅助口径 title 与负载绝对口径 title（与 SSR 同表，
    // `{n}` 占位由 JS replace——zh 的 "{0} / {1} 核" 不得回退英文 cores）。
    let rel = rel_time_patterns(lang);
    let cpu_title = js_str(&t_fmt(lang, FmtKey::CpuUtilTitle, &["{0}", "{1}", "{2}"]));
    let load_title = js_str(&t_fmt(lang, FmtKey::LoadAvgTitle, &["{0}", "{1}"]));
    let mem_used_title = js_str(&t_fmt(lang, FmtKey::MemUsedPct, &["{0}"]));
    let fmt_dur = dur_fmt_js("fmtDur");
    // 能力位表注入（SSR chips 同源 resource_cap_bits，防双写漂移）：
    // JSON 数组形态 `[[1,"cgroup v2"],...]`，JS 按位与重建 chips。
    let caps_bits = resource_cap_bits()
        .iter()
        .map(|(mask, label)| format!("[{mask},\"{}\"]", js_str(label)))
        .collect::<Vec<_>>()
        .join(",");
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                {set_live}
                var WORKER_LABELS = {{{worker_labels}}};
                var PHASE_LABELS = {{{phase_labels}}};
                var REL = ['{rel0}', '{rel1}', '{rel2}', '{rel3}'];
                // 阈值由服务端按 SSR 真源注入（REL_ABS_DAYS = rel_time_text_lang
                // 的绝对化天数；LOAD_WARN/LOAD_CRIT = load_level 色阶阈值）。
                var REL_ABS_DAYS = {rel_abs_days};
                var LOAD_WARN = {load_warn};
                var LOAD_CRIT = {load_crit};
                var CPU_TITLE = '{cpu_title}';
                var LOAD_TITLE = '{load_title}';
                var MEM_USED_TITLE = '{mem_used_title}';
                var CAPS_BITS = [{caps_bits}];
                function phaseLabel(p) {{ return PHASE_LABELS[p] || p; }}
                function phaseClass(p) {{
                    return p === 'succeeded' ? 'success'
                        : (p === 'failed' ? 'failure'
                        : (p === 'timeout' ? 'timeout'
                        : (p === 'cancelled' ? 'cancelled'
                        : (p === 'building' || p === 'assigned' ? 'running'
                        : (p === 'pending' ? 'pending' : '')))));
                }}
                function loadLevel(pct) {{
                    return pct < LOAD_WARN ? 'success' : (pct <= LOAD_CRIT ? 'warn' : 'failure');
                }}
                // DB 时间（UTC "YYYY-MM-DD HH:MM:SS"）→ epoch 毫秒；解析失败 null。
                function parseDbTs(s) {{
                    if (!s) return null;
                    var t = Date.parse(s.replace(' ', 'T') + 'Z');
                    return isNaN(t) ? null : t;
                }}
                // 本地时间手拼格式化（Date 本地 getter；toISOString 是 UTC，禁）：
                // withTime=false 出日期 YYYY-MM-DD，true 出 YYYY-MM-DD HH:MM:SS
                // （与 SSR format_local_time 同格式，时区缩写尾注不复制——JS 无
                // 可移植同源）。
                function pad2(n) {{
                    return (n < 10 ? '0' : '') + n;
                }}
                function localStamp(d, withTime) {{
                    var s = d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
                    if (withTime) s += ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
                    return s;
                }}
                // 相对时间文案（秒/分/时/天四档，与 SSR 同阈值）；超 REL_ABS_DAYS
                // 天改显本地绝对日期，与 SSR 刷新结果一致（漂移不再复活）。
                function relText(ts) {{
                    var secs = Math.max(0, Math.floor((Date.now() - ts) / 1000));
                    if (secs > REL_ABS_DAYS * 86400) return localStamp(new Date(ts), false);
                    var i = secs < 60 ? 0 : (secs < 3600 ? 1 : (secs < 86400 ? 2 : 3));
                    var n = secs < 60 ? secs : (secs < 3600 ? Math.floor(secs / 60) : (secs < 86400 ? Math.floor(secs / 3600) : Math.floor(secs / 86400)));
                    return REL[i].replace('{{0}}', n);
                }}
                function setRel(el) {{
                    if (!el) return;
                    var ts = parseDbTs(el.getAttribute('data-ts'));
                    if (ts === null) return;
                    el.textContent = relText(ts);
                    el.title = localStamp(new Date(ts), true);
                }}
                {fmt_dur}
                // 遥测条更新：pct null（无采样）→ 条隐藏、数字落 "—"。
                function setBar(barId, pctId, pct, title) {{
                    var bar = document.getElementById(barId);
                    var pctEl = document.getElementById(pctId);
                    if (!bar || !pctEl) return;
                    if (pct === null || pct === undefined) {{
                        bar.hidden = true;
                        pctEl.textContent = '—';
                        pctEl.removeAttribute('title');
                        return;
                    }}
                    bar.hidden = false;
                    bar.className = 'load-bar ' + loadLevel(pct);
                    if (title) bar.title = title; else bar.removeAttribute('title');
                    bar.querySelector('i').style.width = Math.min(pct, 100) + '%';
                    pctEl.textContent = Math.round(pct) + '%';
                }}
                // KB → 人类可读（十进制 GB/MB，与 SSR humansize DECIMAL 同规则：
                // 整数值不带小数、非整数两位小数），磁盘行 SSE 就地更新用。
                function fmtKb(kb) {{
                    var units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB'];
                    var v = kb * 1024, i = 0;
                    while (v >= 1000 && i < units.length - 1) {{
                        v /= 1000;
                        i++;
                    }}
                    return (Math.floor(v) === v ? v.toFixed(0) : v.toFixed(2)) + ' ' + units[i];
                }}
                function applyActiveBuilds(list) {{
                    var tbody = document.getElementById('w-active-tbody');
                    var table = document.getElementById('w-active-table');
                    var empty = document.getElementById('w-active-empty');
                    if (!tbody || !table || !empty) return;
                    tbody.textContent = '';
                    var has = list && list.length > 0;
                    table.hidden = !has;
                    empty.hidden = has;
                    if (!has) return;
                    for (var i = 0; i < list.length; i++) {{
                        var b = list[i];
                        var tr = document.createElement('tr');
                        var tdId = document.createElement('td');
                        tdId.className = 'num';
                        var a = document.createElement('a');
                        a.href = '/ui/builds/' + b.id;
                        a.textContent = b.id;
                        tdId.appendChild(a);
                        var tdPkg = document.createElement('td');
                        tdPkg.className = 'ellipsis';
                        tdPkg.title = b.pkg_name || '';
                        tdPkg.textContent = b.pkg_name || '';
                        var tdPh = document.createElement('td');
                        var badge = document.createElement('span');
                        badge.className = 'badge ' + phaseClass(b.phase);
                        badge.textContent = phaseLabel(b.phase);
                        tdPh.appendChild(badge);
                        var tdStart = document.createElement('td');
                        tdStart.className = 'num';
                        var rel = document.createElement('span');
                        rel.setAttribute('data-ts', b.started_at || '');
                        // 未开跑（started_at 回退缺失）与 SSR rel_time_lang 同
                        // 口径落 "—"；setRel 对解析失败行不写文本，占位不抖。
                        if (!b.started_at) rel.textContent = '—';
                        tdStart.appendChild(rel);
                        tr.appendChild(tdId);
                        tr.appendChild(tdPkg);
                        tr.appendChild(tdPh);
                        tr.appendChild(tdStart);
                        tbody.appendChild(tr);
                        setRel(rel);
                    }}
                }}
                // Recent builds 行耗时：completed 用 data-done 终值结算，running
                // 行每次调用按 data-start 实时重算（与 SSR 口径一致）。
                function refreshDurations() {{
                    var rows = document.querySelectorAll('tr[data-recent-build]');
                    for (var i = 0; i < rows.length; i++) {{
                        var row = rows[i];
                        var dur = row.querySelector('.recent-dur');
                        if (!dur) continue;
                        var doneTs = parseDbTs(dur.getAttribute('data-done'));
                        var startTs = parseDbTs(dur.getAttribute('data-start'));
                        if (doneTs !== null && startTs !== null) {{
                            dur.textContent = fmtDur((doneTs - startTs) / 1000);
                        }} else if (startTs !== null) {{
                            dur.textContent = fmtDur((Date.now() - startTs) / 1000);
                        }}
                    }}
                }}
                // Recent builds 卡整表重建（与 applyActiveBuilds 同风格，SSE 快照
                // 是行集真源）：新派发行出现 / 旧行跌出 10 条窗口时行集与
                // count-chip 随快照重排，徽章相位与 data-start/data-done 耗时
                // 口径一并刷新——构建在页面打开期间完成时，下次快照即按终值
                // 结算，不再按"至今"口径续涨。空列表只切 hidden（SSR 空态
                // 文案不重建，chip 落 0）。
                function applyRecentBuilds(list) {{
                    var rows = list || [];
                    var tbody = document.getElementById('w-recent-tbody');
                    var table = document.getElementById('w-recent-table');
                    var empty = document.getElementById('w-recent-empty');
                    if (!tbody || !table || !empty) return;
                    var chip = document.querySelector('#w-recent-head .count-chip');
                    if (chip) chip.textContent = rows.length;
                    var has = rows.length > 0;
                    table.hidden = !has;
                    empty.hidden = has;
                    tbody.textContent = '';
                    for (var j = 0; j < rows.length; j++) {{
                        var rb = rows[j];
                        var tr = document.createElement('tr');
                        tr.setAttribute('data-recent-build', rb.id);
                        var tdId = document.createElement('td');
                        tdId.className = 'num';
                        var a = document.createElement('a');
                        a.href = '/ui/builds/' + rb.id;
                        a.textContent = rb.id;
                        tdId.appendChild(a);
                        var tdPkg = document.createElement('td');
                        tdPkg.className = 'ellipsis';
                        tdPkg.title = rb.pkg_name || '';
                        tdPkg.textContent = rb.pkg_name || '';
                        var tdPh = document.createElement('td');
                        var badge = document.createElement('span');
                        badge.className = 'badge ' + phaseClass(rb.phase);
                        badge.textContent = phaseLabel(rb.phase);
                        tdPh.appendChild(badge);
                        var tdDur = document.createElement('td');
                        tdDur.className = 'num';
                        var dur = document.createElement('span');
                        dur.className = 'recent-dur';
                        dur.setAttribute('data-start', rb.started_at || '');
                        dur.setAttribute('data-done', rb.completed_at || '');
                        if (!rb.started_at) dur.textContent = '—';
                        tdDur.appendChild(dur);
                        tr.appendChild(tdId);
                        tr.appendChild(tdPkg);
                        tr.appendChild(tdPh);
                        tr.appendChild(tdDur);
                        tbody.appendChild(tr);
                    }}
                    refreshDurations();
                }}
                function applyWorker(data) {{
                    if (data.status === 'offline') {{
                        // 终态：关流后整页 reload 一次——SSR 离线页不渲染本脚本
                        // （worker_detail_page offline 分支），不会成环。
                        es.close();
                        location.reload();
                        return;
                    }}
                    var badge = document.querySelector('.worker-status-badge');
                    if (badge) {{
                        if (data.stale) {{
                            badge.className = 'badge warn worker-status-badge';
                            badge.textContent = WORKER_LABELS.stale;
                        }} else {{
                            badge.className = 'badge ' + (data.status === 'online' ? 'success' : 'failure') + ' worker-status-badge';
                            badge.textContent = WORKER_LABELS[data.status] || data.status;
                        }}
                    }}
                    var cpuTitle = (data.cpu_util_pct === null || data.cpu_util_pct === undefined
                        || data.load1 === null || data.load1 === undefined
                        || !data.ncpu) ? null
                        : CPU_TITLE.replace('{{0}}', Math.round(data.cpu_util_pct))
                                   .replace('{{1}}', Number(data.load1).toFixed(2))
                                   .replace('{{2}}', data.ncpu);
                    setBar('w-cpu-bar', 'w-cpu-pct', (data.cpu_util_pct === null || data.cpu_util_pct === undefined) ? null : data.cpu_util_pct, cpuTitle);
                    var loadEl = document.getElementById('w-load-val');
                    if (loadEl) {{
                        var hasLoad = data.load1 !== null && data.load1 !== undefined && data.ncpu > 0;
                        // 倍数与绝对口径 title 同步切：SSR 无采样占位是裸 "—" 无 title。
                        if (hasLoad) {{
                            loadEl.textContent = (Number(data.load1) / data.ncpu).toFixed(1) + '×';
                            loadEl.title = LOAD_TITLE.replace('{{0}}', Number(data.load1).toFixed(2)).replace('{{1}}', data.ncpu);
                        }} else {{
                            loadEl.textContent = '—';
                            loadEl.removeAttribute('title');
                        }}
                    }}
                    var memTitle = (data.mem_used_pct === null || data.mem_used_pct === undefined) ? null
                        : MEM_USED_TITLE.replace('{{0}}', Math.round(data.mem_used_pct));
                    setBar('w-mem-bar', 'w-mem-pct', (data.mem_used_pct === null || data.mem_used_pct === undefined) ? null : data.mem_used_pct, memTitle);
                    // 磁盘行：绝对值文本（无分母无条形），缺采样落 "—"（SSR
                    // 占位同形态）。
                    var diskEl = document.getElementById('w-disk-val');
                    if (diskEl) {{
                        var hasDisk = data.disk_free_kb !== null && data.disk_free_kb !== undefined && data.disk_free_kb > 0;
                        diskEl.textContent = hasDisk ? fmtKb(data.disk_free_kb) : '—';
                    }}
                    // 能力 chips：容器由 SSR 渲染（resource_caps NULL 整组不渲染），
                    // 容器缺位即略过；按位与重建，置 1 位各一枚徽章、全 0 落 "—"。
                    var capsEl = document.getElementById('w-caps-chips');
                    if (capsEl && data.resource_caps !== null && data.resource_caps !== undefined) {{
                        capsEl.textContent = '';
                        for (var ci = 0; ci < CAPS_BITS.length; ci++) {{
                            if (data.resource_caps & CAPS_BITS[ci][0]) {{
                                var chip = document.createElement('span');
                                chip.className = 'badge';
                                chip.textContent = CAPS_BITS[ci][1];
                                capsEl.appendChild(chip);
                            }}
                        }}
                        if (!capsEl.firstChild) capsEl.textContent = '—';
                    }}
                    var hb = document.getElementById('w-hb');
                    var tel = document.getElementById('w-tel-time');
                    if (hb) hb.setAttribute('data-ts', data.last_heartbeat || '');
                    if (tel) tel.setAttribute('data-ts', data.last_heartbeat || '');
                    setRel(hb);
                    setRel(tel);
                    var stale = document.getElementById('w-tel-stale');
                    if (stale) stale.hidden = !data.stale;
                    applyActiveBuilds(data.active_builds);
                    applyRecentBuilds(data.recent_builds);
                }}
                // 本地 10s ticker：签名去重期间服务端不推，相对时间/活动行耗时
                // 仍随墙钟推进（data-ts 持久在 DOM 上）。
                setInterval(function() {{
                    var els = document.querySelectorAll('#w-hb, #w-tel-time, #w-active-tbody [data-ts]');
                    for (var i = 0; i < els.length; i++) setRel(els[i]);
                    refreshDurations();
                }}, 10000);
                var es = new EventSource('{url}');
                es.addEventListener('worker', function(ev) {{
                    try {{
                        var data = JSON.parse(ev.data);
                        if (data.status) applyWorker(data);
                    }} catch (e) {{}}
                }});
                es.onopen = function() {{ setLive(true); }};
                // 瞬时 error 仍由浏览器自动重连；CLOSED（复鉴权断流、握手终败
                // 等）是浏览器已放弃重连的终态，title 换终态文案。
                es.onerror = function() {{
                    setLive(false);
                    if (es.readyState === EventSource.CLOSED) {{
                        var el = document.querySelector('.live-indicator');
                        if (el) el.title = '{dead_title}';
                    }}
                }};
            }})();
        "#, url = url, dead_title = dead_title, worker_labels = worker_labels, phase_labels = phase_labels,
            rel0 = js_str(&rel[0]), rel1 = js_str(&rel[1]), rel2 = js_str(&rel[2]), rel3 = js_str(&rel[3]),
            rel_abs_days = REL_TIME_ABSOLUTE_DAYS, load_warn = LOAD_LEVEL_WARN_PCT,
            load_crit = LOAD_LEVEL_CRIT_PCT,
            cpu_title = cpu_title, load_title = load_title, mem_used_title = mem_used_title,
            caps_bits = caps_bits, fmt_dur = fmt_dur))) }
    }
}
