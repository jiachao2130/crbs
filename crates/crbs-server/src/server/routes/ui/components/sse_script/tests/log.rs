// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 日志页 SSE 脚本测试。

use super::*;

#[test]
fn pending_log_sse_script_injects_connection_closed_once_with_closed_guard() {
    let en = pending_log_sse_script(7, "nonce", Lang::En).into_string();
    assert!(
        en.contains("new EventSource('/ui/builds/7/events')"),
        "{en}"
    );
    assert!(
        en.contains("Connection closed"),
        "ConnectionClosed copy must be injected: {en}"
    );
    assert!(
        !en.contains("reconnecting"),
        "closed terminal copy must not promise reconnection: {en}"
    );
    assert!(en.contains("var closedShown = false;"), "{en}");
    let onerror_at = en.find("es.onerror").expect("onerror handler");
    let onerror = &en[onerror_at..];
    assert!(
        onerror.contains("EventSource.CLOSED"),
        "transient errors must be skipped by the readyState gate: {en}"
    );
    assert!(
        onerror.contains("closedShown = true;"),
        "onerror must arm the one-shot guard: {en}"
    );
    assert!(
        onerror.find("closedShown = true;").expect("guard arm")
            < onerror.find("textContent").expect("note insertion"),
        "guard must be armed before the note is inserted: {en}"
    );

    let zh = pending_log_sse_script(7, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("连接已关闭"), "{zh}");
    assert!(!zh.contains("正在重连"), "{zh}");
    assert!(!zh.contains("Connection closed"), "{zh}");
}

#[test]
fn log_sse_script_handles_end_and_references_page_controls() {
    let s = log_sse_script(7, None, "nonce", Lang::En).into_string();
    assert!(
        s.contains("new EventSource('/ui/builds/7/logs/stream')"),
        "{s}"
    );

    let with_offset = log_sse_script(7, Some(65536), "nonce", Lang::En).into_string();
    assert!(
        with_offset.contains("new EventSource('/ui/builds/7/logs/stream?offset=65536')"),
        "{with_offset}"
    );
    let zero_offset = log_sse_script(7, Some(0), "nonce", Lang::En).into_string();
    assert!(
        zero_offset.contains("new EventSource('/ui/builds/7/logs/stream')"),
        "{zero_offset}"
    );
    assert!(
        !zero_offset.contains("logs/stream?offset"),
        "zero offset must keep the default tail semantics: {zero_offset}"
    );
    assert!(s.contains("addEventListener('end'"), "{s}");

    let end_at = s.find("addEventListener('end'").expect("end listener");
    assert!(
        s[end_at..].contains("es.close();"),
        "end handler must close the EventSource: {s}"
    );
    assert!(
        s.contains("document.getElementById('terminal-hint')"),
        "hint must be guarded by id lookup for idempotency: {s}"
    );
    assert_eq!(s.matches("getElementById('terminal-hint')").count(), 1);
    assert!(s.contains("Build finished — log stream complete"), "{s}");
    assert!(s.contains("getElementById('follow-toggle')"), "{s}");
    assert!(s.contains("followToggle.checked"), "{s}");
    assert!(s.contains("getElementById('jump-bottom')"), "{s}");

    assert!(
        s.contains("es.addEventListener('error', function() { setLive(false); })"),
        "{s}"
    );
    assert_eq!(s.matches("new EventSource").count(), 1, "{s}");

    assert!(s.contains("'Live log stream enabled'"), "{s}");
    assert!(s.contains("'Connection lost, reconnecting...'"), "{s}");
    assert!(
        !s.contains("'Live updates enabled'"),
        "dashboard-generic live title must not leak into the log page: {s}"
    );

    assert!(
        s.contains("function renderLines(lines)"),
        "line-merged render helper missing: {s}"
    );
    assert!(
        s.contains("var activeLine = null;"),
        "active half-line span missing: {s}"
    );
    assert!(
        !s.contains("span.textContent = ev.data + '\\n';"),
        "per-chunk span with unconditional newline must be gone: {s}"
    );
    assert!(
        s.contains("renderLines([pendingLine]);"),
        "end listener must flush the residual half-line: {s}"
    );
    assert!(
        s.contains("lines.join('\\n') + '\\n'"),
        "merged span must embed newlines instead of one span per line: {s}"
    );
    assert!(
        !s.contains("function renderLine(text)"),
        "per-line render helper must be gone (merged render replaces it): {s}"
    );
    assert!(
        s.contains("console.warn('crbs log render failed', e);"),
        "log listener must be wrapped in try/catch: {s}"
    );

    assert!(
        s.contains("var MAX_LOG_SPANS = 5000;"),
        "DOM cap constant missing: {s}"
    );
    assert!(
        s.contains("output.childNodes.length > MAX_LOG_SPANS"),
        "cap check must bound #log-output children: {s}"
    );
    let append_at = s.find("output.appendChild(span);").expect("append call");
    let trim_at = s
        .find("output.removeChild(output.firstChild);")
        .expect("trim call");
    assert!(
        trim_at > append_at,
        "trim-from-top must run after the append it bounds: {s}"
    );

    let pending_body = s
        .split_once("function renderPending()")
        .map(|(_, rest)| {
            &rest[..rest
                .find("activeLine.textContent = pendingLine;")
                .expect("pending body")]
        })
        .expect("renderPending fn");
    assert!(
        pending_body.contains("output.childNodes.length > MAX_LOG_SPANS"),
        "renderPending append must apply the same DOM cap: {s}"
    );
}

#[test]
fn log_sse_script_phase_marker_updates() {
    let build = log_sse_script(7, None, "nonce", Lang::En).into_string();
    assert!(
        build.contains("new EventSource('/ui/builds/7/logs/stream')"),
        "{build}"
    );
    assert!(
        build.contains("CRBS_PHASE_(START|END|SKIP)"),
        "marker regex missing: {build}"
    );
    assert!(
        build.contains("var pendingLine = '';"),
        "line buffer missing: {build}"
    );

    assert!(
        build.contains("function timelineEl()"),
        "timeline get-or-create missing: {build}"
    );

    assert!(
        build.contains("function findStep(timeline, name)"),
        "findStep helper missing: {build}"
    );
    assert!(
        !build.contains(".phase-step[data-phase=\"' + name + '\"]"),
        "querySelector concat with user-controlled name must be gone: {build}"
    );
    assert!(
        build.contains("document.querySelector('.phase-timeline')"),
        "timeline lookup missing: {build}"
    );
    assert!(
        build.contains("document.querySelector('.log-actions') || output"),
        "fallback insertion anchor missing: {build}"
    );
    assert!(
        !build.contains("if (!timeline) return;"),
        "drop-on-missing guard must be gone: {build}"
    );

    assert!(
        build.contains("var HIDDEN_PHASES = {\"ccache-init\":1,\"ccache-summary\":1};"),
        "hidden-phase map missing: {build}"
    );
    assert!(
        build.contains("if (HIDDEN_PHASES[m[2]]) return;"),
        "marker skip for hidden phases missing: {build}"
    );
    assert!(
        !build.contains("\"ccache-init\":\"ccache-init\""),
        "STEP_LABELS must not carry hidden phases: {build}"
    );

    assert!(
        build.contains("CRBS_SUBPHASE\\s+(\\S+)\\s+([0-9.]+)"),
        "subphase regex missing: {build}"
    );
    assert!(
        build.contains("applySubPhase(m[1], parseFloat(m[2]));"),
        "subphase handler not wired into applyLine: {build}"
    );
    assert!(
        build.contains(
            "var BUCKET_OF = {\"%prep\":\"prep\",\"%build\":\"build\",\"%install\":\"package\"};"
        ),
        "bucket map missing: {build}"
    );

    let guard_at = build
        .find("if (!bucket) return;")
        .expect("unknown-name guard");
    let settle_at = build
        .find("last.style.flex = Math.max(0.5, ts - start);")
        .expect("settle call");
    assert!(
        guard_at < settle_at,
        "unknown bucket names must return before settling the last seg: {build}"
    );

    assert!(
        build.contains("if (m[2] === 'build') settleSubBar(endTs);"),
        "build END subbar settlement missing: {build}"
    );
    assert!(build.contains("function settleSubBar(ts)"), "{build}");
}

#[test]
fn log_sse_script_subphase_title_injection_matches_ssr() {
    let zh = log_sse_script(7, None, "nonce", Lang::Zh).into_string();
    assert!(
        zh.contains("\"prep\":\"prep（解包源码、打补丁）— \""),
        "zh bucket tip prefix (fullwidth parens) missing: {zh}"
    );
    assert!(
        zh.contains("\"package\":\"package（安装到 buildroot 并打包）— \""),
        "zh package bucket tip missing: {zh}"
    );
    assert!(
        zh.contains("var SUBPHASE_RUNNING = '进行中';"),
        "zh running word missing: {zh}"
    );
    assert!(
        !zh.contains("\"%check\""),
        "per-subphase-name tips must be gone: {zh}"
    );
    let en = log_sse_script(7, None, "nonce", Lang::En).into_string();
    assert!(
        en.contains("\"prep\":\"prep (Unpack sources, apply patches.) — \""),
        "en bucket tip prefix ('(desc.)' form) missing: {en}"
    );
    assert!(
        en.contains("\"build\":\"build (Compile.) — \""),
        "en build bucket tip missing: {en}"
    );
    assert!(
        en.contains("var SUBPHASE_RUNNING = 'running';"),
        "en running word missing: {en}"
    );
    assert!(
        !en.contains("SUBPHASE_ALLOW"),
        "name allowlist must be gone (bucket map replaces it): {en}"
    );
    assert!(
        en.contains("seg.setAttribute('data-name', bucket);"),
        "seg must carry its bucket name for settlement title recalc: {en}"
    );
    assert!(
        en.contains("subphaseTitle(bucket, SUBPHASE_RUNNING)"),
        "created seg title must use the injected prefix + running word: {en}"
    );
    assert!(
        en.contains("subphaseTitle(lastName, fmtDur(ts - start))"),
        "settled seg title must be recalculated from data-start: {en}"
    );
}

#[test]
fn pending_log_sse_script_reloads_when_phase_leaves_queue() {
    let s = pending_log_sse_script(7, "nonce", Lang::En).into_string();
    assert!(s.contains("new EventSource('/ui/builds/7/events')"), "{s}");
    assert!(s.contains("addEventListener('build'"), "{s}");
    let guard_at = s
        .find("data.phase !== 'pending' && data.phase !== 'assigned'")
        .expect("queue guard");
    assert!(
        s[guard_at..].contains("es.close()"),
        "must close stream before reload: {s}"
    );
    assert!(
        s[guard_at..].contains("location.reload()"),
        "must reload after leaving queue: {s}"
    );
    assert!(!s.contains("live-indicator"), "{s}");

    assert!(
        s.contains("es.readyState !== EventSource.CLOSED"),
        "disconnect hint must fire only when the stream is permanently closed: {s}"
    );
    assert!(
        s.contains("if (es.readyState !== EventSource.CLOSED || closedShown) return;"),
        "{s}"
    );
    assert!(s.contains("closedShown = true;"), "{s}");
    assert!(s.contains("'Connection closed'"), "{s}");
    let zh = pending_log_sse_script(7, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("连接已关闭"), "{zh}");

    assert!(!zh.contains("正在重连"), "{zh}");
}
