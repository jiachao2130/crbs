// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建完成通知按钮。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, Lang, TextKey};

use super::common::*;

/// 构建完成通知按钮：纯前端能力、不门控。默认 `hidden`，JS 可用且支持
/// Notification 才显示。三态：
/// - granted：disabled + 置 `window.__crbsNotify = <subject>`，供同页 SSE
///   终态分支弹通知；
/// - default：可点，点击请求权限；
/// - denied：**不禁用**——requestPermission 立即 resolve denied 且不再弹窗，
///   禁用是不可恢复死态；title 常驻恢复引导，点击闪示约 2.5s 后还原。
///
/// Permission API 可用时挂 `status.onchange` 自动恢复，否则降级直读
/// `Notification.permission`。requestPermission 只在点击 handler 内
///（user gesture），Promise.resolve 包装——旧 Safari（<13）返回 undefined。
pub(crate) fn notify_button(nonce: &str, lang: Lang, subject: &str) -> Markup {
    let label = js_str(t(lang, TextKey::NotifyMe));
    let enabled_text = js_str(t(lang, TextKey::NotifyEnabled));
    let hint_text = js_str(t(lang, TextKey::NotifyDeniedHint));
    let subject = js_str(subject);
    html! {
        button #crbs-notify type="button" class="action-button secondary" hidden { (t(lang, TextKey::NotifyMe)) }
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                var btn = document.getElementById('crbs-notify');
                if (!btn || !('Notification' in window)) return;
                btn.hidden = false;
                // 三态渲染。granted = 武装 + 禁用；default = 可点；denied =
                // 不禁用（见函数注释），title 常驻恢复引导。
                function showGranted() {{
                    btn.disabled = true;
                    btn.textContent = '{enabled_text}';
                    window.__crbsNotify = '{subject}';
                }}
                function showDefault() {{
                    btn.disabled = false;
                    btn.removeAttribute('title');
                    btn.textContent = '{label}';
                }}
                function showDenied() {{
                    btn.disabled = false;
                    btn.title = '{hint_text}';
                    btn.textContent = '{label}';
                }}
                function applyStatus(state) {{
                    if (state === 'granted') showGranted();
                    else if (state === 'denied') showDenied();
                    else showDefault();
                }}
                var restoreTimer = null;
                btn.addEventListener('click', function() {{
                    var deniedNow = Notification.permission === 'denied';
                    if (deniedNow) {{
                        // 恢复引导闪示：denied 时浏览器不再弹窗，把引导文案
                        // 临时顶上按钮，2.5s 后还原（重复点击重置计时；
                        // 若闪示期间权限变 granted，按钮已 disabled，跳过
                        // 还原以免盖掉 enabled 文案）。
                        btn.title = '{hint_text}';
                        btn.textContent = '{hint_text}';
                        if (restoreTimer) clearTimeout(restoreTimer);
                        restoreTimer = setTimeout(function() {{
                            if (!btn.disabled) btn.textContent = '{label}';
                        }}, 2500);
                    }}
                    // 旧 Safari（<13）requestPermission 回调式返回 undefined，
                    // Promise.resolve 包一层保证 .then 可用。
                    Promise.resolve(Notification.requestPermission()).then(function(p) {{
                        if (p === 'granted') showGranted();
                        else if (!deniedNow) applyStatus(p);
                        // deniedNow：维持引导闪示，无需改写。
                    }});
                }});
                // Permission API 可用：查初始态 + 监听变化，站点设置重新
                // 允许/改回默认后按钮自动恢复；查询失败静默走下方兜底。
                if (navigator.permissions && navigator.permissions.query) {{
                    navigator.permissions.query({{ name: 'notifications' }}).then(function(status) {{
                        applyStatus(status.state);
                        status.onchange = function() {{ applyStatus(status.state); }};
                    }}).catch(function() {{}});
                }} else if (Notification.permission === 'granted') {{
                    // 无 Permission API 的旧浏览器：直接读权限、无自动恢复，
                    // 仅保留点击引导。
                    showGranted();
                }} else if (Notification.permission === 'denied') {{
                    showDenied();
                }} else {{
                    showDefault();
                }}
            }})();
        "#, subject = subject, enabled_text = enabled_text, label = label, hint_text = hint_text))) }
    }
}
