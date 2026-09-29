// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 通知按钮脚本测试。

use super::*;

#[test]
fn notify_button_hidden_by_default_and_requests_permission_on_click_only() {
    let m = notify_button("nonce", Lang::En, "kernel-6.12.0-1.el9").into_string();
    assert!(
        m.contains(
            r#"<button id="crbs-notify" type="button" class="action-button secondary" hidden>"#
        ),
        "{m}"
    );
    assert!(m.contains("Notify me</button>"), "{m}");
    let zh = notify_button("nonce", Lang::Zh, "kernel-6.12.0-1.el9").into_string();
    assert!(zh.contains("通知我</button>"), "{zh}");
    assert!(zh.contains("通知已开启"), "{zh}");
    assert!(zh.contains("请在浏览器设置中重新允许后重试"), "{zh}");

    let unsupported_at = m
        .find("if (!btn || !('Notification' in window)) return;")
        .expect("unsupported guard");
    let show_at = m.find("btn.hidden = false;").expect("show call");
    assert!(
        show_at > unsupported_at,
        "button may only be revealed after the support check: {m}"
    );

    assert_eq!(m.matches("btn.disabled = true;").count(), 1, "{m}");
    let granted_fn_at = m.find("function showGranted() {").expect("showGranted fn");
    let disabled_at = m.find("btn.disabled = true;").expect("granted disable");
    assert!(
        disabled_at > granted_fn_at && disabled_at - granted_fn_at < 200,
        "the only disable must live inside showGranted: {m}"
    );
    let denied_fn_at = m.find("function showDenied() {").expect("showDenied fn");
    let denied_section = &m[denied_fn_at..m.find("function applyStatus").expect("applyStatus fn")];
    assert!(
        !denied_section.contains("btn.disabled = true;"),
        "denied state must not disable the button: {m}"
    );
    assert!(
        denied_section.contains("btn.disabled = false;"),
        "denied state must leave the button clickable: {m}"
    );
    assert!(
        denied_section.contains("btn.title = 'Blocked in browser settings"),
        "denied state must carry the recovery hint as title: {m}"
    );
    assert!(
        denied_section.contains("btn.textContent = 'Notify me';"),
        "denied state keeps the actionable label: {m}"
    );

    assert_eq!(
        m.matches("Notification.requestPermission").count(),
        1,
        "{m}"
    );
    assert!(
        m.contains("Promise.resolve(Notification.requestPermission())"),
        "{m}"
    );
    let click_at = m.find("addEventListener('click'").expect("click handler");
    let req_at = m
        .find("Notification.requestPermission")
        .expect("request call");
    assert!(
        req_at > click_at,
        "permission request must live inside the click handler: {m}"
    );
    assert!(
        m.contains("window.__crbsNotify = 'kernel-6.12.0-1.el9';"),
        "{m}"
    );
    assert!(m.contains("btn.textContent = 'Notifications on';"), "{m}");

    assert!(
        m.contains("navigator.permissions && navigator.permissions.query"),
        "{m}"
    );
    assert!(m.contains("query({ name: 'notifications' })"), "{m}");
    assert!(
        m.contains("status.onchange = function() { applyStatus(status.state); };"),
        "{m}"
    );

    assert!(m.contains(".catch(function() {});"), "{m}");
    assert!(m.contains("Notification.permission === 'granted'"), "{m}");

    assert!(
        m.matches("btn.textContent = 'Blocked in browser settings")
            .count()
            >= 1,
        "click guidance must flash the hint text: {m}"
    );
    assert!(
        m.contains("if (!btn.disabled) btn.textContent = 'Notify me';"),
        "{m}"
    );

    assert!(!m.contains("new Notification"), "{m}");
    let tricky = notify_button("nonce", Lang::En, "it's-1.0-1").into_string();
    assert!(
        tricky.contains("window.__crbsNotify = 'it\\'s-1.0-1';"),
        "{tricky}"
    );
}
