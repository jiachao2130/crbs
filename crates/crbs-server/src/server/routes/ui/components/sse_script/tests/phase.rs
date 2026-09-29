// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 详情页 phase SSE 脚本测试（build/task 共用）。

use super::*;
use crate::server::routes::ui::components::badge::{phase_badge, phase_badge_with_class};

/// Lifecycle"至今"走秒器仅 build 页注入：lcWalk 从 .lc-so-far 的 data-ts /
/// data-tpl 重渲（10s ticker），task 页无该小节不注入死代码。
#[test]
fn lifecycle_so_far_walker_build_only() {
    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert!(build.contains("function lcWalk() {"), "{build}");
    assert!(build.contains("setInterval(lcWalk, 10000);"), "{build}");
    assert!(
        build.contains("querySelectorAll('.lc-so-far[data-ts]')"),
        "{build}"
    );
    assert!(
        build
            .contains("el.getAttribute('data-tpl').replace('{0}', lcDur((Date.now() - t) / 1000))"),
        "{build}"
    );
    // 走秒时长与 SSR 同格式（单源 dur_fmt_js）。
    assert!(build.contains("function lcDur(s) {"), "{build}");

    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    assert!(
        !task.contains("lcWalk"),
        "task page must not ship walker: {task}"
    );
    assert!(!task.contains("lcDur"), "{task}");
}

#[test]
fn phase_sse_script_inserts_terminal_hint_exactly_once() {
    // 非终态打开、收到终态事件时插 .terminal-hint（查重幂等；已终态打开不提示）。
    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert!(
        build.contains("new EventSource('/ui/builds/7/events')"),
        "{build}"
    );
    assert!(
        build.contains("document.getElementById('terminal-hint')"),
        "hint must be guarded by id lookup for idempotency: {build}"
    );
    assert_eq!(build.matches("getElementById('terminal-hint')").count(), 1);
    assert!(
        build.contains("var startedLive = !(badge && isTerminal("),
        "{build}"
    );
    // 终态分支展开为块：提示条与通知同一 startedLive 守卫。
    assert!(build.contains("if (startedLive) {"), "{build}");
    assert!(build.contains("showTerminalHint(phase);"), "{build}");
    assert!(build.contains("Build finished"), "{build}");
    assert!(build.contains("Refresh now"), "{build}");
    assert!(build.contains("window.location.href"), "{build}");

    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    assert!(
        task.contains("new EventSource('/ui/tasks/9/events')"),
        "{task}"
    );
    assert!(task.contains("Task finished"), "{task}");
    // 提示条只通过 JS 动态插入，不引入第二个 data-confirm 来源。
    assert!(!task.contains("data-confirm"));
    // CLOSED 终态文案两页同形态，双语对齐 dashboard 同键。
    assert!(
        build.contains("es.readyState === EventSource.CLOSED"),
        "{build}"
    );
    assert!(build.contains("el.title = 'Connection closed';"), "{build}");
    assert!(task.contains("el.title = 'Connection closed';"), "{task}");
    assert!(
        build_sse_script(7, "nonce", Lang::Zh)
            .into_string()
            .contains("el.title = '连接已关闭';"),
        "build page zh CLOSED title missing: {build}"
    );
    assert!(
        task_sse_script(9, "nonce", Lang::Zh)
            .into_string()
            .contains("el.title = '连接已关闭';"),
        "task page zh CLOSED title missing: {task}"
    );
}

/// 终态迁移自动刷新一次（按脚本文本钉结构契约）：live 打开的页面收到
/// 终态事件调度一次 1500ms reload；调度点唯一且在 startedLive 守卫块内
/// ——已终态打开（SSE 即推终态 phase）不得 reload；两页同享；hint 兜底。
#[test]
fn phase_sse_script_schedules_single_delayed_reload_on_live_to_terminal_only() {
    for (page, s) in [
        (
            "build",
            build_sse_script(7, "nonce", Lang::En).into_string(),
        ),
        ("task", task_sse_script(9, "nonce", Lang::En).into_string()),
    ] {
        assert!(
            s.contains("setTimeout(function() { location.reload(); }, 1500);"),
            "{page} page must schedule a 1500ms-delayed reload: {s}"
        );
        // 只调度一次：reloadScheduled 标志守卫 + 全脚本唯一 reload 调用点。
        assert!(
            s.contains("if (reloadScheduled) return;"),
            "{page} reload must be guarded to schedule once: {s}"
        );
        assert_eq!(
            s.matches("location.reload()").count(),
            1,
            "{page} must carry exactly one reload call site: {s}"
        );
        assert_eq!(
            s.matches("scheduleReloadOnce();").count(),
            1,
            "{page} must have exactly one reload schedule invocation: {s}"
        );
        // ② 已终态打开无 reload：唯一调度点必须在 startedLive 块内。
        assert!(
            s.contains("var startedLive = !(badge && isTerminal("),
            "{page} startedLive derivation missing: {s}"
        );
        let terminal_at = s.find("if (isTerminal(phase)) {").expect("terminal branch");
        let guard_at = s.find("if (startedLive) {").expect("startedLive block");
        assert!(
            guard_at > terminal_at,
            "{page} startedLive guard must sit inside the terminal branch: {s}"
        );
        assert!(
            s[terminal_at..guard_at].contains("es.close();"),
            "{page} stream must be closed in the terminal branch: {s}"
        );
        assert!(
            s[guard_at..].contains("scheduleReloadOnce();"),
            "{page} reload must be scheduled inside the startedLive guard: {s}"
        );
        // terminal-hint 兜底保留（与 reload 同一 startedLive 守卫）。
        assert!(
            s[guard_at..].contains("showTerminalHint(phase);"),
            "{page} terminal-hint fallback must be kept: {s}"
        );
        // 终态分支在 try/catch 之外：监听器抛异常被吞时仍关流，防 retry 重连环。
        let listener_at = s.find("es.addEventListener('").expect("event listener");
        let catch_at = s[listener_at..]
            .find("} catch (e) {}")
            .expect("listener catch")
            + listener_at;
        let close_at = s[listener_at..].find("es.close();").expect("close call") + listener_at;
        assert!(
            close_at > catch_at,
            "{page} es.close() must sit outside the listener try block: {s}"
        );
    }
}

/// Notification 构造只在 SSE 终态分支（notifyFinished，startedLive 守卫）
/// 内；title 按主体双语、tag 按 crbs-<主体>-<id> 去重；未武装
/// （window.__crbsNotify 缺失）或未授权直接返回。
#[test]
fn phase_sse_script_fires_notification_in_terminal_branch_only() {
    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert_eq!(build.matches("new Notification(").count(), 1, "{build}");
    let notify_fn_at = build.find("function notifyFinished(phase) {").expect("fn");
    let ctor_at = build.find("new Notification(").expect("ctor");
    assert!(
        ctor_at > notify_fn_at,
        "Notification ctor must live inside notifyFinished: {build}"
    );
    let started_at = build.find("if (startedLive) {").expect("startedLive block");
    let call_at = build.find("notifyFinished(phase);").expect("notify call");
    assert!(
        call_at > started_at,
        "notifyFinished must be called inside the startedLive block: {build}"
    );
    // 武装 + 授权双守卫（权限请求不在此脚本，见 notify_button 测试）。
    assert!(
        build.contains("if (!window.__crbsNotify || !window.Notification"),
        "{build}"
    );
    assert!(
        build.contains("Notification.permission !== 'granted') return;"),
        "{build}"
    );
    assert!(build.contains("'Build finished'"), "{build}");
    assert!(
        build.contains("body: phaseLabel(phase) + ' — ' + window.__crbsNotify,"),
        "{build}"
    );
    assert!(build.contains("lang: 'en',"), "{build}");
    assert!(build.contains("tag: 'crbs-build-7'"), "{build}");

    let task = task_sse_script(9, "nonce", Lang::Zh).into_string();
    assert!(task.contains("'任务已完成'"), "{task}");
    assert!(task.contains("lang: 'zh-CN',"), "{task}");
    assert!(task.contains("tag: 'crbs-task-9'"), "{task}");
}

/// SSE 守卫走语言无关的 data-phase 通道：zh 徽章文本是本地化相位名，
/// textContent 判定终态恒 false，会误插提示条；徽章更新经 PHASE_LABELS
/// 查表，zh 页保持中文显示名。
#[test]
fn phase_sse_script_uses_data_phase_channel_and_localized_labels() {
    // 详情徽章（.phase-badge）与子构建矩阵徽章 SSR 带 data-phase。
    let detail = phase_badge_with_class("succeeded", "phase-badge", Lang::Zh).into_string();
    assert!(detail.contains(r#"data-phase="succeeded""#), "{detail}");
    assert!(detail.contains("成功"), "{detail}");
    let child = phase_badge_with_class("building", "", Lang::Zh).into_string();
    assert!(child.contains(r#"data-phase="building""#), "{child}");

    // 列表徽章不带 data-phase：donut hover 联动不卷入列表徽章。
    let list_badge = phase_badge("succeeded", Lang::Zh).into_string();
    assert!(!list_badge.contains("data-phase"), "{list_badge}");

    // 守卫只读 data-phase，属性缺失 fail-open 到 live；不读渲染文本（zh 误判）。
    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert!(
        build.contains("isTerminal(badge.getAttribute('data-phase'))"),
        "{build}"
    );
    assert!(
        !build.contains("badge.textContent || ''"),
        "terminal guard must not read rendered text: {build}"
    );

    // 主徽章与子构建徽章文本更新都经 phaseLabel 查表，并回写 data-phase。
    assert!(
        build.contains("el.textContent = phaseLabel(data.phase);"),
        "{build}"
    );
    assert!(
        build.contains("el.setAttribute('data-phase', data.phase);"),
        "{build}"
    );
    let task = task_sse_script(9, "nonce", Lang::Zh).into_string();
    assert!(
        task.contains("badge.textContent = phaseLabel(ch.phase);"),
        "{task}"
    );
    assert!(
        task.contains("badge.setAttribute('data-phase', ch.phase);"),
        "{task}"
    );

    // zh 脚本注入本地化相位名表；未知相位回退原键。
    assert!(task.contains("\"succeeded\":\"成功\""), "{task}");
    assert!(task.contains("\"building\":\"构建中\""), "{task}");
    assert!(task.contains("return PHASE_LABELS[p] || p;"), "{task}");

    // En 脚本的表是恒等映射（值=键），徽章行为不变。
    let en = task_sse_script(9, "nonce", Lang::En).into_string();
    assert!(en.contains("\"succeeded\":\"succeeded\""), "{en}");
}
