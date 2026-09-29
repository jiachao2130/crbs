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

/// 整秒时长格式化单源：worker recent 行 fmtDur 与 task children 侧
/// fmtDur 同体（dur_fmt_js），不足一分钟输出 "42s" 而非 "0m 42s"。
#[test]
fn fmt_dur_single_source_with_sub_minute_branch() {
    let worker = worker_sse_script(5, "nonce", Lang::En).into_string();
    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    for s in [&worker, &task] {
        assert!(
            s.contains("function fmtDur(s) {"),
            "fmtDur must be present: {s}"
        );
        // 不足一分钟分支（与 SSR format_duration_secs 对齐）。
        assert!(
            s.contains("return (s % 60) + 's';"),
            "sub-minute branch missing: {s}"
        );
        assert!(
            s.contains("if (m > 0) return m + 'm ' + (s % 60) + 's';"),
            "{s}"
        );
    }
    // 旧的不带 sub-minute 分支的 worker 体（"0m 42s" 口径）不得回归。
    assert!(
        !worker.contains("return m + 'm ' + (secs % 60) + 's';"),
        "{worker}"
    );
}

/// js_str 是防注入防线（subject 来自用户可控文件名）：`<` 可经
/// `</script>` 提前终结内联脚本注入 HTML；裸换行断裂字面量；`\` 须最先
/// 转义防二次转义。
#[test]
fn js_str_escapes_script_close_tag_and_newlines() {
    assert_eq!(js_str(r"a\b"), r"a\\b");
    assert_eq!(js_str("it's"), r"it\'s");
    // </script>（含大小写变体）不得原样出现在产物里。
    assert_eq!(js_str("</script>"), r"\u003c/script>");
    assert_eq!(
        js_str("</SCRIPT><img src=x>"),
        r"\u003c/SCRIPT>\u003cimg src=x>"
    );
    assert_eq!(js_str("a\nb\rc"), r"a\u000ab\u000dc");
    // U+2028/U+2029（ES2019 前裸值即整脚本 SyntaxError，纯防御两字符）。
    assert_eq!(js_str("a\u{2028}b\u{2029}c"), r"a\u2028b\u2029c");
    // 双引号：输出拼进 PHASE_LABELS/STEP_LABELS 双引号字面量，须防闭合注入。
    assert_eq!(js_str("say \"hi\""), r"say \u0022hi\u0022");
    // 组合：先转义 \，再插入的 \u003c/\u000a 不被二次转义。
    assert_eq!(js_str("a\\</script>\n'b'"), r"a\\\u003c/script>\u000a\'b\'");
    assert_eq!(js_str("kernel-6.12.0-1.el9"), "kernel-6.12.0-1.el9");
}

/// 共享 JS 片段拼接的字节级回归钉：三脚本的关键片段（setLive/findStep/
/// 时长格式化/终态横幅）必须完整出现在渲染输出中——片段函数改坏缩进或
/// 转义时在此红，无需逐字对比全脚本。
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
    // findStep：phase/log 共用；dashboard 无时间线。
    for s in [&phase, &log] {
        assert!(s.contains("function findStep(timeline, name) {"), "{s}");
        assert!(
            s.contains("if (steps[i].getAttribute('data-phase') === name) return steps[i];"),
            "{s}"
        );
    }
    // 时长格式化两形态（fmtStepDur/fmtDur）同体不同名。
    assert!(phase.contains("function fmtStepDur(s) {"), "{phase}");
    assert!(log.contains("function fmtDur(s) {"), "{log}");
    // 终态横幅两形态：phase 链接=本页刷新，log 链接=构建页字面量。
    assert!(
        phase.contains("link.href = window.location.href;"),
        "{phase}"
    );
    assert!(log.contains("link.href = '/ui/builds/7';"), "{log}");
    // JS 转义序列保持 ASCII 字节（不被 Rust 转义吃掉）。
    assert!(log.contains(r"\u2713"), "{log}");
}
