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

/// pending/assigned 日志页断线面契约：CLOSED 终态文案用 ConnectionClosed
/// 键（不声称重连、随语言切换）；closedShown 守卫一次性插入——瞬时
/// error 不插、CLOSED 后置位拦重入。
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

    // zh 反向钉：终态"连接已关闭"须注入，瞬态"正在重连"文案不得出现。
    let zh = pending_log_sse_script(7, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("连接已关闭"), "{zh}");
    assert!(!zh.contains("正在重连"), "{zh}");
    assert!(!zh.contains("Connection closed"), "{zh}");
}

#[test]
fn log_sse_script_handles_end_and_references_page_controls() {
    // 闭环：end → es.close + 提示条（查重幂等）；控件由页面渲染。
    let s = log_sse_script(7, None, "nonce", Lang::En).into_string();
    assert!(
        s.contains("new EventSource('/ui/builds/7/logs/stream')"),
        "{s}"
    );
    // 预览末尾偏移拼 ?offset=N（续传优先级由服务端保证）；零值与 None 同走默认 tail。
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
    // end 处理必须先关流再提示，否则浏览器对关流自动重连。
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
    // error 只切指示灯，不自建第二个 EventSource。
    assert!(
        s.contains("es.addEventListener('error', function() { setLive(false); })"),
        "{s}"
    );
    assert_eq!(s.matches("new EventSource").count(), 1, "{s}");
    // ok title 与 SSR 同键（LiveLogStream）；断线走 ConnectionLost。
    assert!(s.contains("'Live log stream enabled'"), "{s}");
    assert!(s.contains("'Connection lost, reconnecting...'"), "{s}");
    assert!(
        !s.contains("'Live updates enabled'"),
        "dashboard-generic live title must not leak into the log page: {s}"
    );
    // 渲染按行缓冲对齐：完整行合并 span、半行驻留 activeLine（per-chunk
    // 硬加换行模式必须绝迹）；end 冲刷半行；监听器整体 try/catch。
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
    // DOM 上限：append 后封顶，超限裁最老（正常回放不触发）。
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
    // renderPending 的 append 分支同裁剪，否则稳态上界实为 MAX+1。
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

/// 阶段标记增量更新总是注入（行缓冲 + START/END/SKIP + CRBS_SUBPHASE
/// 推进）；容器缺位时 timelineEl() 就地补建，不按守卫丢弃标记。
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
    // 容器缺位兜底：timelineEl() 查找并补建（SSR 同位）。
    assert!(
        build.contains("function timelineEl()"),
        "timeline get-or-create missing: {build}"
    );
    // findStep 遍历比对（同详情页）：name 用户可控，querySelector 拼接必须绝迹。
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
    // 隐藏工具步骤（真源 HIDDEN_TOOL_PHASES）：名单注入 + 标记处理显式跳过。
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
    // 子阶段分段条推进：CRBS_SUBPHASE 匹配 + 三桶映射（BUCKET_OF 注入，
    // 值域 = 服务端 SUBPHASE_BUCKETS 派生的 SUBPHASE_TIP 键集）。
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
    // 非切桶名不结算上一段：守卫须先于末段结算代码。
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
    // build END（含失败 exit!=0，同一分支）按 END 时间戳结算分段条末段。
    assert!(
        build.contains("if (m[2] === 'build') settleSubBar(endTs);"),
        "build END subbar settlement missing: {build}"
    );
    assert!(build.contains("function settleSubBar(ts)"), "{build}");
}

/// applySubPhase 段 title 与 SSR 桶段同词同格式（真源 phase.rs，按
/// SUBPHASE_BUCKETS 逐桶生成）；建段挂 running 词，结算按 data-name +
/// data-start 重算时长。
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
    // 转活：phase 离开排队态即 es.close + reload；不挂 live-indicator。
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
    // 断线一次性提示：CLOSED 判定 + 单次守卫 + 文案按 lang 注入。
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
    // zh 反向钉：终态文案与瞬态“正在重连”不得同现。
    assert!(!zh.contains("正在重连"), "{zh}");
}
