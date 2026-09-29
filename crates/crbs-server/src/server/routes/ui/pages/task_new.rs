// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交构建页 /ui/tasks/new：复用 API multipart 提交核心，权限 builder+；CSRF token 作
//! multipart 文本字段由流式解析捕获（文件可能先于 csrf 字段落盘，失败路径回收 .incoming/{uuid}）。
//! 双模响应：XHR 进度模式（头 X-Requested-With: crbs-ui）成功/失败均 200 JSON 就地展示；
//! 不能走 ApiError（error_page 中间件会把 JSON 错误重写成 HTML 错误页）；普通 POST 成功 303
//! 到任务详情，验证失败 200 重渲染表单回显（文件输入因 HTML 限制不回填）。

use std::sync::Arc;

use axum::extract::{Extension, FromRequest, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use maud::{html, Markup, PreEscaped};

use crate::server::auth::visibility::is_product_content_visible_to;
use crate::server::auth::AuthContext;
use crate::server::csrf;
use crate::server::error::ApiError;
use crate::server::routes::builds::{
    ensure_disk_space, extract_multipart_build, request_incoming_dir_of,
    submit_multipart_builds_common,
};
use crate::server::routes::ui::components::{
    empty_state, generate_nonce, js_str, page_with_csp, see_other_redirect,
};
use crate::server::routes::ui::i18n::{
    lang_from_headers, priority_label, t, t_fmt, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::service::{check_public_access, csrf_token_for_request};
use crate::server::state::AppState;

/// 下拉中的可提交产品：名称 + 声明架构（逗号拼接，供 data-arches 属性）。
struct ProductOption {
    name: String,
    /// None = 产品未声明架构（或 chain-resolve 失败）：JS 显示"默认架构"提示。
    arches: Option<String>,
}

/// 与提交链路（`ensure_can_submit_to_product` 等）同口径：下拉只出现 POST 能过门禁的产品。
/// ponytail: 未逐产品走整条祖先链可见性——链上不可见祖先属边角场景，POST 侧仍兜底
/// 拒绝并在表单回显错误；需精确过滤时升级为逐产品链检查（每产品一次祖先遍历）。
async fn submittable_products(
    app: &AppState,
    ctx: &AuthContext,
) -> Result<Vec<ProductOption>, ApiError> {
    // 角色门槛先收口：viewer 及以下无可提交产品（与提交门禁 can_submit 同口径）。
    if !ctx.can_submit() {
        return Ok(Vec::new());
    }
    let summaries = app
        .state_store
        .load_product_summaries()
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product summaries", e))?;

    let mut out = Vec::new();
    for s in summaries {
        if !is_product_content_visible_to(s.owner_id, &s.visibility, &s.name, Some(ctx)) {
            continue;
        }
        // 非 operator 登录用户：ACL 仅 viewer 的产品提交会被拒，下拉排除（与提交门禁一致）。
        if !ctx.is_operator() {
            if let Some(uid) = ctx.user_id {
                match app.state_store.get_product_acl_role(uid, &s.name).await {
                    Ok(Some(role)) if role == "viewer" => continue,
                    Ok(_) => {}
                    // 产品不存在，向后兼容放行（与提交路径同语义）。
                    Err(crbs_core::error::CrbsError::NotFound { .. }) => {}
                    Err(e) => {
                        return Err(ApiError::log_and_internal_with_context(
                            "check product ACL role",
                            e,
                        ));
                    }
                }
            }
        }
        // 架构与 POST resolve_arches 同源（chain-resolve）；失败按"未声明"展示，POST 兜底报错。
        let arches = match app.state_store.resolve_any_product_by_name(&s.name).await {
            Ok(r) if !r.config.arches.is_empty() => Some(r.config.arches.join(",")),
            _ => None,
        };
        out.push(ProductOption {
            name: s.name,
            arches,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// 表单回显状态（错误重渲染时保留用户输入；文件输入 HTML 限制不回填）。
#[derive(Default)]
struct PreservedForm {
    product: Option<String>,
    priority: Option<String>,
    arch_text: Option<String>,
    /// 标签原始文本（`KEY=VALUE`，逐行回显）。
    labels: Vec<String>,
    /// 放置契约下限回显（资源需求折叠区文本输入）。
    min_mem: Option<String>,
    min_ncpu: Option<String>,
    min_disk: Option<String>,
}

pub(crate) async fn new_task_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    let ctx = auth_ref.ok_or_else(|| ApiError::Unauthorized("login required".into()))?;
    if !ctx.is_builder() {
        return Err(ApiError::PermissionDenied(
            "builder or higher role required to submit builds".into(),
        ));
    }
    render_task_new_page(&app, auth_ref, &headers, None, &PreservedForm::default()).await
}

pub(crate) async fn new_task_submit(
    State(app): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Result<Response, ApiError> {
    let auth_ctx = req.extensions().get::<AuthContext>().cloned();
    let headers = req.headers().clone();
    let lang = lang_from_headers(&headers);
    let is_xhr = headers
        .get("x-requested-with")
        .and_then(|v| v.to_str().ok())
        == Some("crbs-ui");

    let gate = match auth_ctx.as_ref() {
        None => Err(ApiError::Unauthorized("login required".into())),
        Some(ctx) if !ctx.is_builder() => Err(ApiError::PermissionDenied(
            "builder or higher role required to submit builds".into(),
        )),
        Some(_) => Ok(()),
    };
    if let Err(e) = gate {
        return xhr_or_err(is_xhr, lang, e);
    }

    // 磁盘预检前移（权威检查在落盘后）：避免 SRPM 传完报错；upload_dir、crbs_root 可分卷，查前者。
    if let Err(e) = ensure_disk_space(
        &app.upload_dir(),
        app.server_config.upload_max_size_bytes() as u64,
    )
    .await
    {
        return xhr_or_err(is_xhr, lang, e);
    }
    let multipart = axum::extract::Multipart::from_request(req, &app)
        .await
        .map_err(|e| ApiError::Validation(format!("parse multipart: {}", e)))?;
    let extracted = match extract_multipart_build(
        multipart,
        &app.upload_dir(),
        app.server_config.upload_max_size_bytes(),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            // 解析失败（超限/坏字段名/缺字段）：无表单状态可保留，空表单回显。
            let msg = submit_error_text(lang, &e);
            return if is_xhr {
                Ok(xhr_error(&msg))
            } else {
                render_task_new_page(
                    &app,
                    auth_ctx.as_ref(),
                    &headers,
                    Some(&msg),
                    &PreservedForm::default(),
                )
                .await
            };
        }
    };

    // CSRF：multipart 流式解析后才能拿到 csrf_token 字段（见模块注释）。
    let csrf_err = match csrf::csrf_base_from_headers(&headers) {
        None => Some(ApiError::Unauthorized("missing session token".into())),
        Some(session) => {
            match csrf::validate_csrf_token(
                &session,
                &app.csrf_key,
                extracted.csrf_token.as_deref().unwrap_or(""),
            ) {
                Ok(true) => None,
                Ok(false) => Some(ApiError::PermissionDenied("invalid CSRF token".into())),
                // 5xx 边角（key 异常）：同 CSRF 失败收口——回收 .incoming/{uuid} 后上抛。
                Err(e) => {
                    cleanup_incoming(&app, &extracted.srpm_paths).await;
                    return Err(e);
                }
            }
        }
    };
    if let Some(e) = csrf_err {
        // 已落盘文件不进提交流程（IncomingUploadGuard 未创建）：按命名空间回收 .incoming/{uuid}。
        cleanup_incoming(&app, &extracted.srpm_paths).await;
        return xhr_or_err(is_xhr, lang, e);
    }

    let preserved = PreservedForm {
        product: Some(extracted.product.clone()),
        priority: extracted.opts.priority.map(|p| p.to_string()),
        arch_text: (!extracted.opts.arch_list.is_empty())
            .then(|| extracted.opts.arch_list.join(",")),
        labels: extracted.labels.clone(),
        min_mem: extracted.opts.min_mem.clone(),
        min_ncpu: extracted.opts.min_ncpu.map(|n| n.to_string()),
        min_disk: extracted.opts.min_disk.clone(),
    };
    match submit_multipart_builds_common(
        &app,
        auth_ctx.as_ref(),
        extracted.product,
        extracted.srpm_paths,
        extracted.opts,
        extracted.labels,
        "ui",
    )
    .await
    {
        Ok(resp) => {
            let location = format!("/ui/tasks/{}?status=submitted", resp.task_id);
            if is_xhr {
                Ok(axum::Json(serde_json::json!({ "redirect": location })).into_response())
            } else {
                see_other_redirect(&location).map(|r| r.into_response())
            }
        }
        Err(e) => {
            let msg = submit_error_text(lang, &e);
            if is_xhr {
                Ok(xhr_error(&msg))
            } else {
                render_task_new_page(&app, auth_ctx.as_ref(), &headers, Some(&msg), &preserved)
                    .await
            }
        }
    }
}

fn xhr_error(message: &str) -> Response {
    axum::Json(serde_json::json!({ "error": message })).into_response()
}

/// 表单失败分流：XHR 请求回 JSON 错误体（前端 JS 弹错），常规请求走 Err
/// 通道由错误页渲染；文案先取后 move（submit_error_text 借用 e）。
fn xhr_or_err(is_xhr: bool, lang: Lang, e: ApiError) -> Result<Response, ApiError> {
    let msg = submit_error_text(lang, &e);
    if is_xhr {
        Ok(xhr_error(&msg))
    } else {
        Err(e)
    }
}

/// 面向用户失败文案：本地化外框 + 错误原文（明细不翻译，同 product_editor 回显口径）。
fn submit_error_text(lang: Lang, e: &ApiError) -> String {
    t_fmt(lang, FmtKey::SubmitFailed, &[e.message()])
}

/// CSRF 失败时回收本请求已落盘的 `.incoming/{uuid}` 子目录。
async fn cleanup_incoming(app: &AppState, srpm_paths: &[std::path::PathBuf]) {
    if let Some(dir) = request_incoming_dir_of(&app.upload_dir(), srpm_paths) {
        if let Err(rm) = tokio::fs::remove_dir_all(&dir).await {
            if rm.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %dir.display(),
                    error = %rm,
                    "Failed to clean up incoming dir after CSRF failure"
                );
            }
        }
    }
}

async fn render_task_new_page(
    app: &AppState,
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    error: Option<&str>,
    preserved: &PreservedForm,
) -> Result<Response, ApiError> {
    let Some(ctx) = auth else {
        return Err(ApiError::Unauthorized("login required".into()));
    };
    let products = submittable_products(app, ctx).await?;
    let csrf_token = csrf_token_for_request(headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(headers);
    let max_mb = (app.server_config.upload_max_size_bytes() / (1024 * 1024)).to_string();

    let body = if products.is_empty() {
        html! {
            h1 { (t(lang, TextKey::TaskNewTitle)) }
            // 无可提交产品（或 ACL 在 GET/POST 间被收回）时仍回显失败原因，不静默吞错。
            @if let Some(err) = error {
                div class="message failure" { (err) }
            }
            (empty_state(
                t(lang, TextKey::TaskNewNoProductsTitle),
                t(lang, TextKey::TaskNewNoProductsHint),
            ))
        }
    } else {
        // 优先级 0/1 全员，2（critical）仅 operator 及以上渲染（服务端 validate_build_priority 兜底）。
        let mut priority_options = vec![
            ("0".to_string(), priority_label(lang, 0)),
            ("1".to_string(), priority_label(lang, 1)),
        ];
        if ctx.is_operator() {
            priority_options.push(("2".to_string(), priority_label(lang, 2)));
        }
        let selected_priority = preserved.priority.as_deref().unwrap_or("0");
        let body = html! {
            h1 { (t(lang, TextKey::TaskNewTitle)) }
            p { a href="/ui/tasks" { "← " (t(lang, TextKey::BackToTasks)) } }
            p style="color:var(--fg-muted);font-size:0.875rem" {
                (t_fmt(lang, FmtKey::UploadMaxNote, &[&max_mb]))
            }
            // 服务端错误与 JS 上传错误共用此横幅（id 由脚本引用）。
            div class="message failure" id="upload-error" hidden[error.is_none()] {
                @if let Some(err) = error { (err) }
            }
            // enctype 必须显式声明：默认 urlencoded 会丢文件字段。
            form class="form-card" id="new-task-form" method="post"
                action="/ui/tasks/new" enctype="multipart/form-data" {
                @if let Some(ref token) = csrf_token {
                    input type="hidden" name="csrf_token" value=(token);
                }

                label for="product-select" { (t(lang, TextKey::ThProduct)) }
                select name="product" id="product-select" required {
                    @for p in &products {
                        option value=(p.name.as_str())
                            data-arches=(p.arches.as_deref().unwrap_or(""))
                            selected[preserved.product.as_deref() == Some(p.name.as_str())] {
                            (p.name.as_str())
                        }
                    }
                }

                label for="srpm-files" { (t(lang, TextKey::LabelSrpmFiles)) }
                div class="dropzone" id="dropzone" {
                    p class="drop-hint" { (t(lang, TextKey::TaskNewDropHint)) }
                    input type="file" id="srpm-files" name="srpm" multiple
                        accept=".src.rpm" required;
                    ul class="file-list" id="file-list" { }
                }

                label { (t(lang, TextKey::LabelArches)) }
                // JS 按所选产品 data-arches 重建复选框组（未声明架构→默认架构提示）；
                // data-selected 为失败回显保留值，据此预勾选；初始 hidden，noscript 不出现。
                div id="arch-checkboxes"
                    data-selected=(preserved.arch_text.as_deref().unwrap_or(""))
                    hidden { }
                p id="arch-default-note" style="color:var(--fg-muted);font-size:0.875rem"
                    hidden { (t(lang, TextKey::TaskNewArchDefaultNote)) }
                // 无 JS 回退：逗号分隔文本输入；JS 启用时 noscript 按规范不进表单，规避空 arch。
                noscript {
                    input type="text" name="arch"
                        value=(preserved.arch_text.as_deref().unwrap_or(""))
                        placeholder="x86_64,aarch64";
                    p style="color:var(--fg-muted);font-size:0.875rem" {
                        (t(lang, TextKey::TaskNewArchNoscript))
                    }
                }

                label for="priority-select" { (t(lang, TextKey::FilterPriority)) }
                select name="priority" id="priority-select" {
                    @for (value, label) in &priority_options {
                        option value=(value.as_str())
                            selected[selected_priority == value.as_str()] { (label.as_str()) }
                    }
                }

                // 首个构建语义选项：SRPM 头参数回放（repro-from-srpm）。label 包住 checkbox
                // （无 JS 可切换）；勾选提交 value="true"（parse_bool_field 解析），缺席 = 默认关。
                label class="gc-opt" {
                    input type="checkbox" name="repro_from_srpm" value="true";
                    span { (t(lang, TextKey::TaskNewReproFromSrpm)) }
                }

                // 任务标签（可选）：每行一条 KEY=VALUE，提交为重复 label 字段；
                // 空行服务端忽略，无 JS 时单行仍可用。
                label { (t(lang, TextKey::LabelTaskLabels)) }
                p class="label-help" { (t(lang, TextKey::TaskNewLabelsHelp)) }
                div class="label-rows" id="label-rows" {
                    @if preserved.labels.is_empty() {
                        (label_input_row(lang, ""))
                    } @else {
                        @for value in &preserved.labels {
                            (label_input_row(lang, value))
                        }
                    }
                }
                button type="button" class="label-add" id="label-add-button" {
                    "+ " (t(lang, TextKey::TaskNewAddLabel))
                }
                template id="label-row-template" { (label_input_row(lang, "")) }

                // 资源需求（放置契约下限，可选）：默认收起；字段名与 API multipart
                // 臂同名（min_mem/min_ncpu/min_disk），语法与上界由服务端统一校验。
                (resource_req_section(lang, preserved))

                p {
                    button type="submit" class="action-button" id="submit-button"
                        { (t(lang, TextKey::ButtonSubmit)) }
                }
                div class="upload-progress" id="upload-progress" role="progressbar"
                    aria-label=(t(lang, TextKey::TaskNewUploadProgress))
                    aria-hidden="true" hidden {
                    div class="upload-progress-fill" id="upload-progress-fill" { }
                }
                p class="upload-progress-note" id="upload-progress-pct" hidden { }
            }
            (submit_progress_script(
                &nonce,
                lang,
                app.server_config.upload_max_size_bytes(),
            ))
        };
        body
    };
    page_with_csp(
        t(lang, TextKey::TaskNewTitle),
        &nonce,
        auth,
        "tasks",
        headers,
        &app.csrf_key,
        body,
    )
    .map(|r| r.into_response())
}

/// 单行标签输入（`KEY=VALUE`，name 固定为 `label` 重复字段）：删除按钮由
/// 表单脚本按 `.label-row-remove` 事件委托处理；无 JS 时按钮无动作，输入照常提交。
fn label_input_row(lang: Lang, value: &str) -> Markup {
    let max_len = crbs_core::validation::MAX_TASK_LABEL_KEY_LEN
        + 1
        + crbs_core::validation::MAX_TASK_LABEL_VALUE_LEN;
    html! {
        div class="label-row" {
            input type="text" name="label" value=(value)
                placeholder=(t(lang, TextKey::PlaceholderTaskLabel))
                maxlength=(max_len);
            button type="button" class="label-row-remove"
                title=(t(lang, TextKey::TaskNewRemoveLabel))
                aria-label=(t(lang, TextKey::TaskNewRemoveLabel)) { "×" }
        }
    }
}

/// 资源需求折叠区（可选放置契约下限）：`<details>` 默认收起，回显 preserved
/// 保留值；字段名与 API multipart 臂一一对应（min_mem / min_ncpu / min_disk），
/// 输入语法与上界的权威校验在服务端（validate_options），HTML min/max 仅客户端提示。
fn resource_req_section(lang: Lang, preserved: &PreservedForm) -> Markup {
    html! {
        details class="help" {
            summary { (t(lang, TextKey::TaskNewResSection)) }
            p style="color:var(--fg-muted);font-size:0.875rem" {
                (t(lang, TextKey::TaskNewResHelp))
            }
            label for="min-mem-input" { (t(lang, TextKey::TaskNewResMemLabel)) }
            input type="text" name="min_mem" id="min-mem-input"
                value=(preserved.min_mem.as_deref().unwrap_or(""))
                placeholder="4G";
            label for="min-ncpu-input" { (t(lang, TextKey::TaskNewResNcpuLabel)) }
            input type="number" name="min_ncpu" id="min-ncpu-input"
                value=(preserved.min_ncpu.as_deref().unwrap_or(""))
                min="1" max="1024" step="1";
            label for="min-disk-input" { (t(lang, TextKey::TaskNewResDiskLabel)) }
            input type="text" name="min_disk" id="min-disk-input"
                value=(preserved.min_disk.as_deref().unwrap_or(""))
                placeholder="20G";
        }
    }
}

/// 提交表单的内联脚本（nonce 锁定；CSP connect-src 'self' 允许 XHR）。a) 提交前本地超限预检；
/// b) XHR + FormData 上传与进度条（crbs-ui 头；inFlight 防重入 + 按钮 disabled）；c) 成功跳
/// JSON.redirect、失败就地展示、JS 异常回退原生提交（form.submit() 不触发 submit 事件，无死循环）；
/// d) 拖拽填充 file input 与文件清单；e) 产品切换按 data-arches 重建 arch 复选框（按
/// data-selected 预勾选回显值）；f) 标签行添加/删除。JS 关闭时退化为原生表单 + noscript
/// arch 输入，仍完整可用。
fn submit_progress_script(nonce: &str, lang: Lang, max_bytes: usize) -> Markup {
    // 超限文案：{1}（上限）服务端插值，{0}（实际大小）留给 JS 回填。
    let too_large = js_str(&t_fmt(
        lang,
        FmtKey::UploadTooLarge,
        &["{0}", &(max_bytes / (1024 * 1024)).to_string()],
    ));
    let upload_failed = js_str(t(lang, TextKey::UploadFailed));
    let uploading = js_str(t(lang, TextKey::TaskNewUploadProgress));
    html! {
        script nonce=(nonce) { (PreEscaped(format!(r#"
            (function() {{
                var form = document.getElementById('new-task-form');
                if (!form) {{ return; }}
                var dropzone = document.getElementById('dropzone');
                var fileInput = document.getElementById('srpm-files');
                var fileList = document.getElementById('file-list');
                var productSel = document.getElementById('product-select');
                var archBox = document.getElementById('arch-checkboxes');
                var archNote = document.getElementById('arch-default-note');
                var errBox = document.getElementById('upload-error');
                var progress = document.getElementById('upload-progress');
                var progressFill = document.getElementById('upload-progress-fill');
                var progressPct = document.getElementById('upload-progress-pct');
                var submitBtn = document.getElementById('submit-button');
                // 防重入：XHR 上传进行中忽略再次 submit（双击/回车连击）。
                var inFlight = false;
                var MAX_BYTES = {max_bytes};
                var TOO_LARGE = '{too_large}';
                var UPLOAD_FAILED = '{upload_failed}';
                var UPLOADING = '{uploading}';

                function showError(msg) {{
                    if (!errBox) {{ return; }}
                    errBox.textContent = msg;
                    errBox.hidden = false;
                }}
                function fmtMB(n) {{
                    return Math.round(n / 1048576 * 10) / 10;
                }}
                // 复位防重入标志与提交按钮（失败可重试；JS 异常回退原生提交前也先复位）。
                function resetSubmit() {{
                    inFlight = false;
                    if (submitBtn) {{ submitBtn.disabled = false; }}
                }}

                // e) 产品切换 → 按声明的 arches 重建复选框组；未声明则提示默认架构。
                // data-selected 是服务端失败回显保留的 arch 值，据此预勾选。
                function renderArch() {{
                    var opt = productSel.options[productSel.selectedIndex];
                    var arches = (opt && opt.getAttribute('data-arches')) || '';
                    var selectedRaw = archBox.getAttribute('data-selected') || '';
                    var selected = {{}};
                    selectedRaw.split(',').forEach(function(s) {{
                        var t = s.trim();
                        if (t) {{ selected[t] = true; }}
                    }});
                    archBox.innerHTML = '';
                    if (!arches) {{
                        archBox.hidden = true;
                        archNote.hidden = false;
                        return;
                    }}
                    archNote.hidden = true;
                    archBox.hidden = false;
                    arches.split(',').forEach(function(a) {{
                        var label = document.createElement('label');
                        label.className = 'radio-label';
                        var cb = document.createElement('input');
                        cb.type = 'checkbox';
                        cb.name = 'arch';
                        cb.value = a;
                        cb.checked = Object.prototype.hasOwnProperty.call(selected, a.trim());
                        label.appendChild(cb);
                        label.appendChild(document.createTextNode(' ' + a));
                        archBox.appendChild(label);
                    }});
                }}
                productSel.addEventListener('change', renderArch);
                renderArch();

                // f) 标签行：添加/删除（始终保留一行空输入，空行由服务端忽略）。
                var labelRows = document.getElementById('label-rows');
                var labelAddBtn = document.getElementById('label-add-button');
                var labelRowTpl = document.getElementById('label-row-template');
                function addLabelRow() {{
                    if (labelRows && labelRowTpl && labelRowTpl.content) {{
                        labelRows.appendChild(labelRowTpl.content.cloneNode(true));
                    }}
                }}
                if (labelAddBtn) {{ labelAddBtn.addEventListener('click', addLabelRow); }}
                if (labelRows) {{
                    labelRows.addEventListener('click', function(e) {{
                        var btn = e.target.closest('button.label-row-remove');
                        if (!btn) {{ return; }}
                        var row = btn.parentElement;
                        if (row) {{ row.remove(); }}
                        if (!labelRows.querySelector('.label-row')) {{ addLabelRow(); }}
                    }});
                }}

                // d) 拖拽：高亮 + 填充 file input（DataTransfer）+ 文件名/大小清单。
                function listFiles() {{
                    fileList.innerHTML = '';
                    for (var i = 0; i < fileInput.files.length; i++) {{
                        var li = document.createElement('li');
                        li.textContent = fileInput.files[i].name + ' (' + fmtMB(fileInput.files[i].size) + ' MB)';
                        fileList.appendChild(li);
                    }}
                }}
                fileInput.addEventListener('change', listFiles);
                ['dragenter', 'dragover'].forEach(function(ev) {{
                    dropzone.addEventListener(ev, function(e) {{
                        e.preventDefault();
                        dropzone.classList.add('drag');
                    }});
                }});
                ['dragleave', 'drop'].forEach(function(ev) {{
                    dropzone.addEventListener(ev, function(e) {{
                        e.preventDefault();
                        dropzone.classList.remove('drag');
                    }});
                }});
                dropzone.addEventListener('drop', function(e) {{
                    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {{
                        fileInput.files = e.dataTransfer.files;
                        listFiles();
                    }}
                }});

                // a/b/c) 提交拦截：本地超限预检 + XHR 进度上传；异常回退原生提交。
                form.addEventListener('submit', function(e) {{
                    e.preventDefault();
                    // 上传进行中直接忽略（防双击/回车重入造成并发重复提交）。
                    if (inFlight) {{ return; }}
                    errBox.hidden = true;
                    var total = 0;
                    for (var i = 0; i < fileInput.files.length; i++) {{
                        total += fileInput.files[i].size;
                    }}
                    if (total > MAX_BYTES) {{
                        showError(TOO_LARGE.replace('{{0}}', String(fmtMB(total))));
                        return;
                    }}
                    try {{
                        var fd = new FormData(form);
                        var xhr = new XMLHttpRequest();
                        xhr.open('POST', form.getAttribute('action') || window.location.pathname);
                        xhr.setRequestHeader('X-Requested-With', 'crbs-ui');
                        inFlight = true;
                        if (submitBtn) {{ submitBtn.disabled = true; }}
                        progress.hidden = false;
                        progress.setAttribute('aria-hidden', 'false');
                        // 进度文本先给"上传中"状态，首个 onprogress 事件到达后
                        // 覆盖为百分比。
                        progressPct.textContent = UPLOADING;
                        progressPct.hidden = false;
                        xhr.upload.onprogress = function(ev) {{
                            if (ev.lengthComputable) {{
                                var pct = Math.round(ev.loaded * 100 / ev.total);
                                progressFill.style.width = pct + '%';
                                progressPct.textContent = pct + '%';
                            }}
                        }};
                        xhr.onload = function() {{
                            var data = null;
                            try {{ data = JSON.parse(xhr.responseText); }} catch (ex) {{}}
                            if (data && data.redirect) {{
                                window.location.assign(data.redirect);
                                return;
                            }}
                            progress.hidden = true;
                            progressPct.hidden = true;
                            resetSubmit();
                            showError(data && data.error ? data.error : UPLOAD_FAILED);
                        }};
                        xhr.onerror = function() {{
                            progress.hidden = true;
                            progressPct.hidden = true;
                            resetSubmit();
                            showError(UPLOAD_FAILED);
                        }};
                        xhr.send(fd);
                    }} catch (err) {{
                        // 任何 JS 异常回退原生提交：form.submit() 不触发 submit
                        // 事件（等价于一次性 submit 标志），无死循环。先复位按钮
                        // 与防重入标志再提交。
                        resetSubmit();
                        form.submit();
                    }}
                }});
            }})();
        "#, max_bytes = max_bytes, too_large = too_large, upload_failed = upload_failed, uploading = uploading))) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 资源需求折叠区：三输入字段名与 API multipart 臂同名、preserved 值回显进
    /// value 属性、默认全空形态与中英文案均可渲染（失败重渲染回显链路的 UI 半边）。
    #[test]
    fn resource_req_section_renders_names_and_preserved_values() {
        let preserved = PreservedForm {
            min_mem: Some("4G".into()),
            min_ncpu: Some("8".into()),
            min_disk: Some("20G".into()),
            ..Default::default()
        };
        let s = resource_req_section(Lang::En, &preserved).into_string();
        assert!(s.contains(r#"<details class="help">"#), "{s}");
        assert!(s.contains(r#"name="min_mem""#), "{s}");
        assert!(s.contains(r#"name="min_ncpu""#), "{s}");
        assert!(s.contains(r#"name="min_disk""#), "{s}");
        assert!(s.contains(r#"value="4G""#), "{s}");
        assert!(s.contains(r#"value="8""#), "{s}");
        assert!(s.contains(r#"value="20G""#), "{s}");
        assert!(s.contains("Resource requirements (optional)"), "{s}");

        // 默认形态：全空 value 仍渲染（空提交 = 未声明，multipart 臂按空串丢弃）。
        let empty = resource_req_section(Lang::En, &PreservedForm::default()).into_string();
        assert!(empty.contains(r#"value="""#), "{empty}");

        // 中文文案键生效。
        let zh = resource_req_section(Lang::Zh, &PreservedForm::default()).into_string();
        assert!(zh.contains("资源需求（可选）"), "{zh}");
    }
}
