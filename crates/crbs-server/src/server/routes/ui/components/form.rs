// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 表单域组件：列表过滤条、confirm 按钮族与 admin 表单控件、secret 展示框。

use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, Lang, TextKey};

use super::js_str;

/// data-confirm 按钮的公共确认脚本（`page` 在 </body> 前输出一次；点击弹 confirm，取消则 preventDefault）。
pub(crate) const CONFIRM_SCRIPT: &str = r#"
    (function() {
        if (window.__crbsConfirmBound) { return; }
        window.__crbsConfirmBound = true;
        document.addEventListener('click', function(e) {
            var btn = e.target.closest('button[data-confirm]');
            if (!btn) { return; }
            var msg = btn.getAttribute('data-confirm');
            if (!window.confirm(msg)) { e.preventDefault(); }
        });
    })();
"#;

/// [`filter_form`] 的参数包：各过滤字段当前值（`None` = 未过滤）；
/// `chips` 为激活过滤 chip 渲染（filter_chips 输出），无则传 `html! {}`。
pub(crate) struct FilterFormParams<'a> {
    pub(crate) base_path: &'a str,
    pub(crate) product: Option<&'a str>,
    pub(crate) name: Option<&'a str>,
    /// 任务标签过滤原文（`KEY=VALUE`，仅 /ui/tasks 渲染输入框）。
    pub(crate) label: Option<&'a str>,
    pub(crate) phase: Option<&'a str>,
    pub(crate) arch: Option<&'a str>,
    pub(crate) priority: Option<&'a str>,
    pub(crate) sort: Option<&'a str>,
    pub(crate) chips: Markup,
    pub(crate) lang: Lang,
}

/// 列表页过滤条。`lang` 只影响可见 label/占位/选项显示名（走 t() /
/// phase_option_label()）；表单 name 与 option value 是机器面协议值不译，
/// name/默认值/GET action 不变。label 内联包 input 保持隐式关联。
pub(crate) fn filter_form(params: FilterFormParams<'_>) -> Markup {
    let FilterFormParams {
        base_path,
        product,
        name,
        label,
        phase,
        arch,
        priority,
        sort,
        chips,
        lang,
    } = params;
    use crate::server::routes::ui::i18n::phase_option_label;
    html! {
        form class="filter-bar" method="get" action=(base_path) {
            label {
                (t(lang, TextKey::ThProduct))
                input type="text" name="product" value=(product.unwrap_or("")) placeholder=(t(lang, TextKey::PlaceholderProduct));
            }
            label {
                (t(lang, TextKey::ThPackage))
                input type="text" name="name" value=(name.unwrap_or("")) placeholder=(t(lang, TextKey::PlaceholderPackage));
            }
            // 标签过滤仅在任务列表：其他列表页不渲染该输入框（query 参数仍可手工传）。
            @if base_path == "/ui/tasks" {
                label {
                    (t(lang, TextKey::LabelTaskLabels))
                    input type="text" name="label" value=(label.unwrap_or("")) placeholder=(t(lang, TextKey::PlaceholderTaskLabel));
                }
            }
            @if base_path != "/ui/packages" {
                label {
                    (t(lang, TextKey::ThPhase))
                    select name="phase" {
                        option value="" selected[phase.is_none()] { (t(lang, TextKey::FilterAll)) }
                        option value="pending" selected[phase == Some("pending")] { (phase_option_label(lang, "pending")) }
                        option value="assigned" selected[phase == Some("assigned")] { (phase_option_label(lang, "assigned")) }
                        option value="building" selected[phase == Some("building")] { (phase_option_label(lang, "building")) }
                        option value="succeeded" selected[phase == Some("succeeded")] { (phase_option_label(lang, "succeeded")) }
                        option value="failed" selected[phase == Some("failed")] { (phase_option_label(lang, "failed")) }
                        option value="timeout" selected[phase == Some("timeout")] { (phase_option_label(lang, "timeout")) }
                        option value="cancelled" selected[phase == Some("cancelled")] { (phase_option_label(lang, "cancelled")) }
                    }
                }
            }
            @if let Some(arch) = arch {
                label {
                    (t(lang, TextKey::FilterArch))
                    input type="text" name="arch" value=(arch) placeholder=(t(lang, TextKey::PlaceholderArch));
                }
            }
            // Priority 仅 builds 列表有；option 值须与 DB BuildPriority 序列化一致（0/1/2）。
            @if base_path == "/ui/builds" {
                label {
                    (t(lang, TextKey::FilterPriority))
                    select name="priority" {
                        option value="" selected[priority.is_none()] { (t(lang, TextKey::FilterAll)) }
                        option value="0" selected[priority == Some("0")] { (t(lang, TextKey::PriorityNormal)) }
                        option value="1" selected[priority == Some("1")] { (t(lang, TextKey::PriorityHigh)) }
                        option value="2" selected[priority == Some("2")] { (t(lang, TextKey::PriorityCritical)) }
                    }
                }
            }
            @if sort.is_some() {
                label {
                    (t(lang, TextKey::FilterSort))
                    select name="sort" {
                        @if base_path.starts_with("/ui/builds") {
                            option value="id_desc" selected[sort == Some("id_desc")] { (t(lang, TextKey::SortNewestId)) }
                            option value="id_asc" selected[sort == Some("id_asc")] { (t(lang, TextKey::SortOldestId)) }
                            option value="started_desc" selected[sort == Some("started_desc")] { (t(lang, TextKey::SortStartedTime)) }
                        } @else if base_path.starts_with("/ui/tasks") {
                            option value="id_desc" selected[sort == Some("id_desc")] { (t(lang, TextKey::SortNewestId)) }
                            option value="id_asc" selected[sort == Some("id_asc")] { (t(lang, TextKey::SortOldestId)) }
                            option value="submitted_desc" selected[sort == Some("submitted_desc")] { (t(lang, TextKey::SortSubmittedTime)) }
                        } @else {
                            option value="id_desc" selected[sort == Some("id_desc")] { (t(lang, TextKey::SortNewestId)) }
                            option value="id_asc" selected[sort == Some("id_asc")] { (t(lang, TextKey::SortOldestId)) }
                        }
                    }
                }
            }
            (filter_apply(base_path, lang))
            // chips 须尾置：.filter-apply 的 margin-left:auto 把尾组推右，chips 落最右。
            (chips)
        }
    }
}

/// 过滤条右置尾组：Apply 提交当前表单，Reset 回裸 `base_path` 清掉全部过滤参数。
/// workers / admin / products 的手写 filter-bar 与此字节级同构，改动需同步。
pub(crate) fn filter_apply(base_path: &str, lang: Lang) -> Markup {
    html! {
        span class="filter-apply" {
            button type="submit" { (t(lang, TextKey::FilterApply)) }
            a href=(base_path) { (t(lang, TextKey::FilterReset)) }
        }
    }
}

/// POST 确认表单骨架：CSRF 隐藏位 + 带确认框的样式化按钮。三个语义按钮
///（cancel/rebuild/reproduce）共用；`label` 与 `style` 见各包装函数。
fn post_confirm_form(action: &str, csrf_token: Option<&str>, markup: Markup) -> Markup {
    html! {
        form class="action-form" method="post" action=(action) {
            @if let Some(token) = csrf_token {
                input type="hidden" name="csrf_token" value=(token);
            }
            (markup)
        }
    }
}

/// Cancel 按钮 + 确认弹窗（破坏性操作，红色）。`lang`：按钮标签。
pub(crate) fn cancel_button(
    action: &str,
    csrf_token: Option<&str>,
    message: &str,
    lang: Lang,
) -> Markup {
    post_confirm_form(
        action,
        csrf_token,
        confirm_button(t(lang, TextKey::ButtonCancel), message),
    )
}

/// Rebuild 按钮：与 cancel_button 同构；建设性操作（重放任务）用主色而非破坏性红色。
pub(crate) fn rebuild_button(
    action: &str,
    csrf_token: Option<&str>,
    message: &str,
    lang: Lang,
) -> Markup {
    post_confirm_form(
        action,
        csrf_token,
        confirm_button_primary(t(lang, TextKey::ButtonRebuild), message),
    )
}

/// Reproduce 按钮：与 rebuild_button 同构；锁定依赖快照重建（区别于 rebuild
/// 用当前仓库重放），描边次要样式。
pub(crate) fn reproduce_button(
    action: &str,
    csrf_token: Option<&str>,
    message: &str,
    lang: Lang,
) -> Markup {
    post_confirm_form(
        action,
        csrf_token,
        confirm_button_secondary(t(lang, TextKey::ButtonReproduce), message),
    )
}

/// 一次性 Token / Worker secret 展示组件：强警告框 + 复制按钮（nonce-gated inline JS）。
/// secret 字符集 `[a-zA-Z0-9_-]` 不含引号，可直接嵌入属性；`#crbs-secret-value` 带
/// `tabindex="-1"`：复制 API 不可用时脚本 focus + 选中其内容供手动 Ctrl+C（div 默认不可聚焦）。
pub(crate) fn secret_reveal_box(secret: &str, nonce: &str, lang: Lang) -> Markup {
    html! {
        div class="secret-reveal" {
            div class="secret-warning" {
                (t(lang, TextKey::SecretWarning))
            }
            div class="secret-value" id="crbs-secret-value" tabindex="-1" { (secret) }
            button class="secret-copy" type="button" data-secret=(secret) { (t(lang, TextKey::CopyButton)) }
            (copy_secret_script(nonce, lang))
        }
    }
}

fn copy_secret_script(nonce: &str, lang: Lang) -> Markup {
    let fail_text = js_str(t(lang, TextKey::CopyFailedManual));
    let copied_text = js_str(t(lang, TextKey::CopyCopied));
    let copy_text = js_str(t(lang, TextKey::CopyButton));
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                document.querySelectorAll('button.secret-copy').forEach(function(btn) {{
                    btn.addEventListener('click', function() {{
                        var secret = btn.getAttribute('data-secret');
                        if (!secret) return;
                        // 失败反馈：clipboard API 缺失或写入被拒（非安全上下文 /
                        // 权限拒绝）时，改按钮文案并选中 secret 供手动复制。
                        function fail() {{
                            btn.textContent = '{fail_text}';
                            var box = document.getElementById('crbs-secret-value');
                            if (!box) return;
                            var range = document.createRange();
                            range.selectNodeContents(box);
                            var sel = window.getSelection();
                            if (sel) {{
                                sel.removeAllRanges();
                                sel.addRange(range);
                            }}
                            box.focus();
                        }}
                        if (navigator.clipboard && navigator.clipboard.writeText) {{
                            navigator.clipboard.writeText(secret).then(function() {{
                                btn.textContent = '{copied_text}';
                                setTimeout(function() {{ btn.textContent = '{copy_text}'; }}, 2000);
                            }}).catch(fail);
                        }} else {{
                            fail();
                        }}
                    }});
                }});
            }})();
        "#, fail_text = fail_text, copied_text = copied_text, copy_text = copy_text))) }
    }
}

/// 带确认框的提交按钮（破坏性操作，红色）；仅输出 data-confirm 按钮，确认脚本由 `page` 注入一次。
pub(crate) fn confirm_button(label: &str, message: &str) -> Markup {
    confirm_button_styled(label, message, "danger")
}

/// 带确认框的表单提交按钮（非破坏性的主要操作，主色）。
fn confirm_button_primary(label: &str, message: &str) -> Markup {
    confirm_button_styled(label, message, "")
}

/// 带确认框的表单提交按钮（次要正向操作，描边样式，与主色按钮区分）。
fn confirm_button_secondary(label: &str, message: &str) -> Markup {
    confirm_button_styled(label, message, "secondary")
}

/// 带确认框的表格行内 ghost 按钮：链接式弱化视觉，hover 才显 danger 色（`.action-button.danger-ghost`）。
pub(crate) fn confirm_button_ghost(label: &str, message: &str) -> Markup {
    confirm_button_styled(label, message, "danger-ghost")
}

fn confirm_button_styled(label: &str, message: &str, extra_class: &str) -> Markup {
    let class = if extra_class.is_empty() {
        "action-button".to_string()
    } else {
        format!("action-button {}", extra_class)
    };
    html! {
        button class=(class) type="submit" data-confirm=(message) { (label) }
    }
}

/// 内联 admin 操作表单：同路径提交、hidden action 字段分发，适合无复杂客户端校验的 POST。
pub(crate) fn admin_inline_form(
    action: &str,
    csrf_token: &str,
    fields: Markup,
    submit_label: &str,
) -> Markup {
    html! {
        form class="admin-inline-form" method="post" action=(action) {
            input type="hidden" name="csrf_token" value=(csrf_token);
            (fields)
            button class="action-button" type="submit" { (submit_label) }
        }
    }
}

/// 渲染 select 下拉框：仅 option value 与 `selected` 相等时输出 selected 属性，无匹配
/// 不预选（浏览器默认显示第一项）。必须用 maud 空属性开关 `selected[cond]`——
/// `selected=(cond)` 把 bool 渲染成 `selected="false"`，属性存在即选中 → 显示最后一个 option。
pub(crate) fn admin_select(name: &str, options: &[(&str, &str)], selected: Option<&str>) -> Markup {
    html! {
        select name=(name) {
            @for (value, label) in options {
                option value=(value) selected[selected == Some(value)] { (label) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_select_marks_matching_value_selected() {
        // 产品 ACL grant 缺省 Some("viewer")（首项）；回归根因见 admin_select doc。
        let m = admin_select(
            "role",
            &[
                ("viewer", "Viewer"),
                ("builder", "Builder"),
                ("admin", "Admin"),
            ],
            Some("viewer"),
        );
        assert_eq!(
            m.into_string(),
            "<select name=\"role\">\
             <option value=\"viewer\" selected>Viewer</option>\
             <option value=\"builder\">Builder</option>\
             <option value=\"admin\">Admin</option>\
             </select>"
        );
    }

    #[test]
    fn admin_select_no_match_leaves_all_unselected() {
        let m = admin_select(
            "role",
            &[
                ("viewer", "Viewer"),
                ("builder", "Builder"),
                ("admin", "Admin"),
            ],
            None,
        );
        let s = m.into_string();
        assert!(!s.contains("selected"), "no option should be selected: {s}");

        let m = admin_select(
            "action",
            &[("", "All"), ("create_user", "create_user")],
            Some("nope"),
        );
        let s = m.into_string();
        assert!(!s.contains("selected"), "no option should be selected: {s}");
    }

    #[test]
    fn admin_select_echoes_non_default_selection() {
        let m = admin_select(
            "role",
            &[
                ("", "All"),
                ("admin", "admin"),
                ("operator", "operator"),
                ("builder", "builder"),
                ("viewer", "viewer"),
            ],
            Some("admin"),
        );
        let s = m.into_string();
        assert_eq!(s.matches(" selected").count(), 1);
        assert!(
            s.contains("<option value=\"admin\" selected>admin</option>"),
            "{s}"
        );
    }

    #[test]
    fn filter_form_phase_select_echoes_current_value() {
        // 与 admin_select 同根因；builds 页 phase/priority 两下拉并存，按 option 值精确断言。
        let m = filter_form(FilterFormParams {
            base_path: "/ui/builds",
            product: None,
            name: None,
            label: None,
            phase: Some("failed"),
            arch: None,
            priority: None,
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        let s = m.into_string();
        assert_eq!(s.matches(r#"<option value="failed" selected>"#).count(), 1);
        assert!(
            s.contains("<option value=\"failed\" selected>Failed</option>"),
            "{s}"
        );
    }

    #[test]
    fn filter_form_phase_select_defaults_to_all() {
        // builds 页 phase 与 priority 两个下拉在无过滤时各自默认选中 All。
        let m = filter_form(FilterFormParams {
            base_path: "/ui/builds",
            product: None,
            name: None,
            label: None,
            phase: None,
            arch: None,
            priority: None,
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        let s = m.into_string();
        assert_eq!(s.matches(r#"<option value="" selected>"#).count(), 2);
        assert!(
            s.contains("<option value=\"\" selected>All</option>"),
            "{s}"
        );
    }

    #[test]
    fn filter_form_priority_select_echoes_current_value() {
        let m = filter_form(FilterFormParams {
            base_path: "/ui/builds",
            product: None,
            name: None,
            label: None,
            phase: None,
            arch: None,
            priority: Some("1"),
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        let s = m.into_string();
        assert_eq!(s.matches(r#"<option value="1" selected>"#).count(), 1);
        assert!(
            s.contains("<option value=\"1\" selected>high</option>"),
            "{s}"
        );
    }

    #[test]
    fn filter_form_priority_select_only_on_builds_page() {
        let m = filter_form(FilterFormParams {
            base_path: "/ui/tasks",
            product: None,
            name: None,
            label: None,
            phase: None,
            arch: None,
            priority: None,
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        assert!(!m.into_string().contains("name=\"priority\""));
    }

    #[test]
    fn filter_form_label_input_only_on_tasks_page() {
        let m = filter_form(FilterFormParams {
            base_path: "/ui/tasks",
            product: None,
            name: None,
            label: Some("ci=1234"),
            phase: None,
            arch: None,
            priority: None,
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        let s = m.into_string();
        assert!(s.contains(r#"name="label" value="ci=1234""#), "{s}");
        assert!(s.contains("placeholder=\"key=value\""), "{s}");

        let builds = filter_form(FilterFormParams {
            base_path: "/ui/builds",
            product: None,
            name: None,
            label: Some("ci=1234"),
            phase: None,
            arch: None,
            priority: None,
            sort: None,
            chips: html! {},
            lang: Lang::En,
        });
        assert!(!builds.into_string().contains("name=\"label\""));
    }

    #[test]
    fn confirm_button_has_no_inline_script() {
        let m = confirm_button("Revoke", "Revoke access?");
        let s = m.into_string();
        assert!(s.contains("data-confirm=\"Revoke access?\""), "{s}");
        assert!(!s.contains("<script"), "button must not embed script: {s}");
    }

    #[test]
    fn copy_secret_script_has_failure_fallback_for_manual_copy() {
        // clipboard API 缺失/被拒的回退：改按钮文案并选中 secret 节点（focus 依赖 tabindex="-1"）。
        let s = copy_secret_script("nonce", Lang::En).into_string();
        assert!(s.contains("'Copy failed — select manually'"), "{s}");
        assert!(s.contains("getElementById('crbs-secret-value')"), "{s}");
        assert!(s.contains("selectNodeContents"), "{s}");
        assert!(s.contains(".catch(fail)"), "{s}");
        assert!(s.contains("btn.textContent = 'Copied';"), "{s}");

        let box_html = secret_reveal_box("crbs_tok_x", "nonce", Lang::En).into_string();
        assert!(
            box_html.contains(r#"id="crbs-secret-value" tabindex="-1""#),
            "{box_html}"
        );
    }
}
