// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! SSE 内联脚本共享片段与字符串安全化。

use crate::server::routes::ui::i18n::Lang;

use super::super::phase::{phase_step_label, HIDDEN_TOOL_PHASES};

/// 内联 JS 字符串字面量安全化——防注入防线：输入含用户可控内容（subject =
/// pkg/NVR 来自文件名）。`\` 必须最先转义（否则后续 `\u003c` 的反斜杠被
/// 二次转义）；`"` 走 `\u0022`（调用点有单引号与 PHASE_LABELS/STEP_LABELS
/// 双引号字面量两种上下文）；`<` 防 `</script` 提前闭合脚本注入 HTML；换行
/// 防断裂；U+2028/U+2029 防 ES2019 前整脚本 SyntaxError；`\uXXXX` 语义等价。
pub(crate) fn js_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('"', "\\u0022")
        .replace('<', "\\u003c")
        .replace('\n', "\\u000a")
        .replace('\r', "\\u000d")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// JS 侧隐藏工具步骤名单字面量，真源 [`HIDDEN_TOOL_PHASES`]：STEP_LABELS
/// 除名后 JS 须显式跳过这些名字，否则 `STEP_LABELS[name] || name` 回退
/// 原串会把隐藏步骤打回页面。
pub(super) fn hidden_tool_phases_js() -> String {
    HIDDEN_TOOL_PHASES
        .iter()
        .map(|p| format!("\"{}\":1", js_str(p)))
        .collect::<Vec<_>>()
        .join(",")
}

// 仪表盘 SSE 脚本。`lang`：setLive 的 title 文案与图例 title 模板。
// ── 共享 JS 片段：三脚本的同形函数体单源。片段为独立 format!/const，按原
// 内联位置的缩进（16/20 空格）逐字节拼接，输出与原文本不变。──

/// `setLive(ok)`：连接状态指示（dashboard/phase/log 三脚本同体），标题按 lang 注入。
pub(super) fn set_live_js(live_title: &str, lost_title: &str) -> String {
    format!(
        "function setLive(ok) {{
                    var el = document.querySelector('.live-indicator');
                    if (!el) return;
                    el.classList.toggle('disconnected', !ok);
                    el.title = ok ? '{live_title}' : '{lost_title}';
                }}"
    )
}

/// `findStep`：按 data-phase 属性全等遍历定位步骤——name 来自构建输出标记
///（用户可控），不走 querySelector 拼接（注入面论证见各调用点注释）。
/// phase/log 两脚本逐字同体。
pub(super) const FIND_STEP_JS: &str = "function findStep(timeline, name) {
                    var steps = timeline.querySelectorAll('.phase-step');
                    for (var i = 0; i < steps.length; i++) {
                        if (steps[i].getAttribute('data-phase') === name) return steps[i];
                    }
                    return null;
                }";

/// 步骤时长格式化（<60s 保留 0.1s，天/时/分降级；与服务端 format_phase_duration
/// 同格式）：phase 侧名 `fmtStepDur`、log 侧名 `fmtDur`，函数体同源。
pub(super) fn step_duration_js(name: &str) -> String {
    format!(
        "function {name}(s) {{
                    s = Math.max(0, s);
                    if (s < 60) return s.toFixed(1) + 's';
                    s = Math.floor(s);
                    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
                    if (d > 0) return d + 'd ' + h + 'h';
                    if (h > 0) return h + 'h ' + m + 'm';
                    return m + 'm ' + (s % 60) + 's';
                }}"
    )
}

/// 整秒时长格式化（与 SSR `pages::format_duration_secs` 同格式，
/// 不足一分钟 "42s" 而非 "0m 42s"）：task children 侧 `fmtDur`、worker recent
/// 行 `fmtDur`、build 页 Lifecycle 走秒器 `lcDur` 三点单源，改格式只改此处。
pub(super) fn dur_fmt_js(name: &str) -> String {
    format!(
        "function {name}(s) {{
                    s = Math.max(0, Math.floor(s));
                    var d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
                    if (d > 0) return d + 'd ' + h + 'h';
                    if (h > 0) return h + 'h ' + m + 'm';
                    if (m > 0) return m + 'm ' + (s % 60) + 's';
                    return (s % 60) + 's';
                }}"
    )
}

/// 步骤元素定位/补建（缺失则 append 裸 .phase-step 形态，style.css 对两种
/// 形态都成立）：phase 侧名 `timelineStepEl`、log 侧名 `stepEl`。
pub(super) fn step_el_js(name: &str) -> String {
    format!(
        "function {name}(timeline, name) {{
                    var el = findStep(timeline, name);
                    if (!el) {{
                        el = document.createElement('span');
                        el.className = 'phase-step pending';
                        el.setAttribute('data-phase', name);
                        var nm = document.createElement('span');
                        nm.className = 'phase-step-name';
                        nm.textContent = STEP_LABELS[name] || name;
                        el.appendChild(nm);
                        timeline.appendChild(el);
                    }}
                    return el;
                }}"
    )
}

/// 步骤 detail 行定位/补建并整行覆写：phase 侧名 `timelineSetDetail`、
/// log 侧名 `setDetail`。
pub(super) fn set_detail_js(name: &str) -> String {
    format!(
        "function {name}(el, text) {{
                    var d = el.querySelector('.phase-step-detail');
                    if (!d) {{
                        d = document.createElement('span');
                        d.className = 'phase-step-detail';
                        el.appendChild(d);
                    }}
                    d.textContent = text;
                }}"
    )
}

/// 终态横幅（succeeded 绿/其余红 + 图标 + 文案 + 链接，幂等）。phase 侧链接
/// 为本页刷新（`window.location.href`），log 侧跳构建页（调用方传带引号的
/// 字面量）；`href_expr` 是完整 JS 表达式文本。图标为 JS 转义序列（\\u2713），
/// 保持与原内联文本一致的 ASCII 字节。
pub(super) fn terminal_hint_js(hint_text: &str, href_expr: &str, label: &str) -> String {
    format!(
        "function showTerminalHint(phase) {{
                    if (document.getElementById('terminal-hint')) return;
                    var hint = document.createElement('div');
                    hint.id = 'terminal-hint';
                    hint.className = 'terminal-hint ' + (phase === 'succeeded' ? 'success' : 'failure');
                    var icon = document.createElement('span');
                    icon.className = 'terminal-hint-icon';
                    icon.setAttribute('aria-hidden', 'true');
                    icon.textContent = phase === 'succeeded' ? '\\u2713' : '\\u2715';
                    var text = document.createElement('span');
                    text.textContent = '{hint_text}';
                    var link = document.createElement('a');
                    link.href = {href_expr};
                    link.textContent = '{label}';
                    hint.appendChild(icon);
                    hint.appendChild(text);
                    hint.appendChild(link);
                    var main = document.querySelector('main');
                    if (main) main.insertBefore(hint, main.firstChild);
                }}"
    )
}

/// 步骤显示名映射 JSON（`var STEP_LABELS = {...}` 的注入值）：五步骤同
/// phase_step_label 表，未知名由 JS 侧回退原键。
pub(super) fn step_labels_json(lang: Lang) -> String {
    [
        "prepare-layer",
        "install-srpm",
        "install-deps",
        "build",
        "collect-artifacts",
    ]
    .iter()
    .map(|p| format!("\"{}\":\"{}\"", p, js_str(&phase_step_label(lang, p))))
    .collect::<Vec<_>>()
    .join(",")
}
