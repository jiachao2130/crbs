// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 页 SSE 脚本测试。

use super::*;
use crate::server::routes::ui::components::layout::{LOAD_LEVEL_CRIT_PCT, LOAD_LEVEL_WARN_PCT};
use crate::server::routes::ui::pages::REL_TIME_ABSOLUTE_DAYS;

#[test]
fn worker_sse_script_pins_dom_contract_and_offline_reload() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(s.contains("new EventSource('/ui/workers/5/events')"), "{s}");
    assert!(s.contains("es.addEventListener('worker'"), "{s}");

    assert!(s.contains("if (data.status === 'offline') {"), "{s}");
    assert_eq!(s.matches("location.reload()").count(), 1, "{s}");
    assert!(s.contains("es.close();"), "{s}");

    for key in [
        "'w-cpu-bar'",
        "'w-mem-bar'",
        "'w-load-val'",
        "'w-disk-val'",
        "'w-caps-chips'",
        "'w-hb'",
        "'w-tel-time'",
        "'w-tel-stale'",
        "'w-active-tbody'",
        "'w-recent-tbody'",
        "'w-recent-table'",
        "'w-recent-empty'",
        "'#w-recent-head .count-chip'",
        ".worker-status-badge",
    ] {
        assert!(s.contains(key), "missing {key}: {s}");
    }

    assert!(s.contains("setInterval("), "{s}");

    let zh = worker_sse_script(5, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("秒前"), "{zh}");
    assert!(zh.contains("负载 {0} / {1} 核"), "{zh}");

    assert!(!s.contains("terminal-hint"), "{s}");
}

#[test]
fn worker_sse_script_load_val_updates_ratio_and_title() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(!s.contains("w-cpu-extra"), "old channel must be gone: {s}");
    assert!(
        !s.contains("CPU_VALUE"),
        "old value template must be gone: {s}"
    );
    assert!(
        s.contains("var LOAD_TITLE = '"),
        "title template missing: {s}"
    );
    assert!(
        s.contains("(Number(data.load1) / data.ncpu).toFixed(1) + '×';"),
        "{s}"
    );
    assert!(
        s.contains(
            "LOAD_TITLE.replace('{0}', Number(data.load1).toFixed(2)).replace('{1}', data.ncpu);"
        ),
        "{s}"
    );
    assert!(s.contains("loadEl.textContent = '—';"), "{s}");
    assert!(s.contains("loadEl.removeAttribute('title');"), "{s}");
}

#[test]
fn worker_sse_script_updates_disk_and_caps() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();

    assert!(
        s.contains("var diskEl = document.getElementById('w-disk-val');"),
        "{s}"
    );
    assert!(
        s.contains("diskEl.textContent = hasDisk ? fmtKb(data.disk_free_kb) : '—';"),
        "{s}"
    );
    assert!(s.contains("function fmtKb(kb) {"), "{s}");

    assert!(
        s.contains("['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB']"),
        "{s}"
    );

    assert!(
        s.contains(
            "if (capsEl && data.resource_caps !== null && data.resource_caps !== undefined) {"
        ),
        "{s}"
    );
    assert!(
        s.contains("if (data.resource_caps & CAPS_BITS[ci][0]) {"),
        "{s}"
    );
    assert!(
        s.contains("if (!capsEl.firstChild) capsEl.textContent = '—';"),
        "{s}"
    );

    assert!(
        s.contains(r#"[[1,"cgroup v2"],[2,"peak"],[4,"events"],[8,"io"],[16,"psi"]]"#),
        "{s}"
    );
}

#[test]
fn worker_sse_script_rebuilds_recent_builds_rows_with_lifecycle_writeback() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();

    assert!(
        !s.contains("querySelector('tr[data-recent-build=\"' + rb.id"),
        "per-row in-place update must be replaced by full rebuild: {s}"
    );
    assert!(s.contains("applyRecentBuilds(data.recent_builds);"), "{s}");

    for key in [
        "tr.setAttribute('data-recent-build', rb.id);",
        "dur.setAttribute('data-start', rb.started_at || '');",
        "dur.setAttribute('data-done', rb.completed_at || '');",
        "dur.className = 'recent-dur';",
        "refreshDurations();",
    ] {
        assert!(s.contains(key), "missing {key}: {s}");
    }

    assert!(s.contains("chip.textContent = rows.length;"), "{s}");
    assert!(s.contains("table.hidden = !has;"), "{s}");
    assert!(s.contains("empty.hidden = has;"), "{s}");

    assert!(s.contains("tdPkg.textContent = rb.pkg_name || '';"), "{s}");

    assert!(
        s.contains("if (!rb.started_at) dur.textContent = '—';"),
        "{s}"
    );
}

#[test]
fn worker_sse_script_active_row_null_start_renders_dash() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(
        s.contains("if (!b.started_at) rel.textContent = '—';"),
        "{s}"
    );

    assert!(s.contains("var ts = parseDbTs(el.getAttribute('data-ts'));\n                    if (ts === null) return;"), "{s}");
}

#[test]
fn worker_sse_script_thresholds_injected_from_ssr_consts() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(
        s.contains(&format!("var REL_ABS_DAYS = {REL_TIME_ABSOLUTE_DAYS};")),
        "{s}"
    );

    assert!(
        s.contains("if (secs > REL_ABS_DAYS * 86400) return localStamp(new Date(ts), false);"),
        "{s}"
    );
    assert!(
        s.contains(&format!("var LOAD_WARN = {LOAD_LEVEL_WARN_PCT};")),
        "{s}"
    );
    assert!(
        s.contains(&format!("var LOAD_CRIT = {LOAD_LEVEL_CRIT_PCT};")),
        "{s}"
    );
    assert!(
        s.contains("return pct < LOAD_WARN ? 'success' : (pct <= LOAD_CRIT ? 'warn' : 'failure');"),
        "{s}"
    );

    assert!(!s.contains("toLocaleString"), "{s}");
    assert!(
        s.contains("el.title = localStamp(new Date(ts), true);"),
        "{s}"
    );
    assert!(s.contains("function localStamp(d, withTime) {"), "{s}");
}
