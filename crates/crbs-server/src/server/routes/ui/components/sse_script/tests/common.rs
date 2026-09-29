// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! SSE 脚本共享片段测试。

use super::*;

#[test]
fn fmt_dur_single_source_with_sub_minute_branch() {
    let worker = worker_sse_script(5, "nonce", Lang::En).into_string();
    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    for s in [&worker, &task] {
        assert!(
            s.contains("function fmtDur(s) {"),
            "fmtDur must be present: {s}"
        );

        assert!(
            s.contains("return (s % 60) + 's';"),
            "sub-minute branch missing: {s}"
        );
        assert!(
            s.contains("if (m > 0) return m + 'm ' + (s % 60) + 's';"),
            "{s}"
        );
    }

    assert!(
        !worker.contains("return m + 'm ' + (secs % 60) + 's';"),
        "{worker}"
    );
}

#[test]
fn js_str_escapes_script_close_tag_and_newlines() {
    assert_eq!(js_str(r"a\b"), r"a\\b");
    assert_eq!(js_str("it's"), r"it\'s");

    assert_eq!(js_str("</script>"), r"\u003c/script>");
    assert_eq!(
        js_str("</SCRIPT><img src=x>"),
        r"\u003c/SCRIPT>\u003cimg src=x>"
    );
    assert_eq!(js_str("a\nb\rc"), r"a\u000ab\u000dc");

    assert_eq!(js_str("a\u{2028}b\u{2029}c"), r"a\u2028b\u2029c");

    assert_eq!(js_str("say \"hi\""), r"say \u0022hi\u0022");

    assert_eq!(js_str("a\\</script>\n'b'"), r"a\\\u003c/script>\u000a\'b\'");
    assert_eq!(js_str("kernel-6.12.0-1.el9"), "kernel-6.12.0-1.el9");
}

#[test]
fn shared_js_fragments_render_in_all_scripts() {
    let dash = dashboard_sse_script("n", Lang::En).into_string();
    let phase = build_sse_script(7, "n", Lang::En).into_string();
    let log = log_sse_script(7, None, "n", Lang::En).into_string();
    for s in [&dash, &phase, &log] {
        assert!(s.contains("function setLive(ok) {"), "{s}");
        assert!(
            s.contains("el.classList.toggle('disconnected', !ok);"),
            "{s}"
        );
    }

    for s in [&phase, &log] {
        assert!(s.contains("function findStep(timeline, name) {"), "{s}");
        assert!(
            s.contains("if (steps[i].getAttribute('data-phase') === name) return steps[i];"),
            "{s}"
        );
    }

    assert!(phase.contains("function fmtStepDur(s) {"), "{phase}");
    assert!(log.contains("function fmtDur(s) {"), "{log}");

    assert!(
        phase.contains("link.href = window.location.href;"),
        "{phase}"
    );
    assert!(log.contains("link.href = '/ui/builds/7';"), "{log}");

    assert!(log.contains(r"\u2713"), "{log}");
}
