// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品网页管理：新建产品 + 在线编辑本层配置（含语法检查）。
//! 权限对齐 API 的 `is_owner_or_admin`：新建 admin 可建官方/私人产品、
//! builder+ 仅 owner=self 私人；编辑 owner/admin 可用、他人 404。
//! 错误回显为"重渲染表单"模式（非 PRG），保证 textarea 保留用户输入。

use super::rel_time_lang;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::product::load_record_for_owner_or_admin;
use crate::server::routes::ui::components::{
    back_link, detail_page_head, generate_nonce, page_with_csp,
};
use crate::server::routes::ui::i18n::{lang_from_headers, t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::service::{
    check_public_access, csrf_token_for_request, require_csrf,
};
use crate::server::state::AppState;
use crate::server::validation::{validate_product_name, validate_product_name_for_write};
use axum::extract::{Extension, Form, Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use crbs_core::error::CrbsError;
use maud::{html, Markup, PreEscaped};
use std::sync::Arc;

struct EditPageCtx<'a> {
    name: &'a str,
    current_revision: i64,
    config_toml: &'a str,
    reason: &'a str,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct NewProductForm {
    pub csrf_token: String,
    pub name: String,
    pub display_name: String,
    pub parent_name: String,
    /// owner 输入框仅 admin 视图渲染，builder 表单无此键缺省空串；handler：非 admin 忽略 owner 强制 self+private，admin 空串 = official 公有产品。
    #[serde(default)]
    pub owner: String,
    pub visibility: String,
    pub config_toml: String,
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct EditProductForm {
    pub csrf_token: String,
    pub action: String,
    pub expected_revision: i64,
    pub reason: String,
    pub config_toml: String,
}

// ── GET /ui/products/new ──

pub(crate) async fn new_product_page(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    let ctx = auth_ref.ok_or_else(|| ApiError::Unauthorized("login required".into()))?;
    if !ctx.is_builder() {
        return Err(ApiError::PermissionDenied(
            "builder or higher role required to create products".into(),
        ));
    }

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let is_admin = ctx.is_admin();
    let lang = lang_from_headers(&headers);

    let placeholder = r#"base_packages = ["bash", "rpm-build", "gcc", "make"]

[[repos]]
name = "base"
baseurl = "http://example.com/repo/$basearch"
gpgcheck = false"#;

    // 前端联动的 setCustomValidity 文案（与下方 hint 同词，按 lang 注入）。
    let private_needs_owner =
        crate::server::routes::ui::components::js_str(t(lang, TextKey::PrivateNeedsOwner));
    let body = html! {
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToProducts), "/ui/products", None))
        }
        div class="page-head" {
            div class="title-block" {
                h1 { (t(lang, TextKey::NewProductPageTitle)) }
            }
        }
        form class="form-card" method="post" {
            @if let Some(ref token) = csrf_token {
                input type="hidden" name="csrf_token" value=(token);
            }

            label for="name" { (t(lang, TextKey::LabelProductNameSlug)) }
            input type="text" id="name" name="name" required
                pattern="[a-z0-9_-]+" placeholder="my-product";

            label for="display_name" { (t(lang, TextKey::LabelDisplayNameOptional)) }
            input type="text" id="display_name" name="display_name"
                placeholder=(t(lang, TextKey::PlaceholderDisplayName));

            label for="parent_name" { (t(lang, TextKey::LabelParentOptional)) }
            input type="text" id="parent_name" name="parent_name" placeholder=(t(lang, TextKey::PlaceholderEmptyRoot));

            @if is_admin {
                label for="owner" { (t(lang, TextKey::LabelOwnerOptional)) }
                input type="text" id="owner" name="owner" placeholder=(t(lang, TextKey::PlaceholderEmptyOfficial));

                label { (t(lang, TextKey::ThVisibility)) }
                label class="radio-label" {
                    input type="radio" name="visibility" value="public" checked;
                    " " (t(lang, TextKey::VisPublic))
                }
                label class="radio-label" {
                    input type="radio" name="visibility" value="private";
                    " " (t(lang, TextKey::VisPrivate))
                }
                // 前端联动（服务端校验前半边）：Private+空 owner 时下方脚本解除 hidden 并 setCustomValidity 阻止提交。
                p id="owner-private-hint" style="color:var(--fg-muted);font-size:0.875rem"
                    hidden[true] { (t(lang, TextKey::PrivateNeedsOwner)) }
            } @else {
                input type="hidden" name="visibility" value="private";
                p { (t(lang, TextKey::BuilderVisibilityNote)) }
            }

            label for="config_toml" { (t(lang, TextKey::LabelConfigToml)) }
            textarea id="config_toml" name="config_toml" rows="24" spellcheck="false"
                placeholder=(placeholder) {}

            p {
                button type="submit" class="action-button" { (t(lang, TextKey::ButtonCreate)) }
            }
        }
        // 前端联动：Private 选中且 owner 空时 setCustomValidity 阻止提交 +
        // muted 提示；change/input 双事件即时更新；无 JS 退化为服务端校验（双保险后半边）。
        @if is_admin {
            script nonce=(nonce) { (PreEscaped(format!(r#"
                (function() {{
                    var owner = document.getElementById('owner');
                    var hint = document.getElementById('owner-private-hint');
                    if (!owner || !hint) {{ return; }}
                    var radios = document.querySelectorAll('input[name="visibility"]');
                    function update() {{
                        var priv = false;
                        radios.forEach(function(r) {{
                            if (r.checked && r.value === 'private') {{ priv = true; }}
                        }});
                        if (priv && !owner.value.trim()) {{
                            owner.setCustomValidity('{private_needs_owner}');
                            hint.hidden = false;
                        }} else {{
                            owner.setCustomValidity('');
                            hint.hidden = true;
                        }}
                    }}
                    radios.forEach(function(r) {{ r.addEventListener('change', update); }});
                    owner.addEventListener('input', update);
                    update();
                }})();
            "#, private_needs_owner = private_needs_owner))) }
        }
    };

    page_with_csp(
        t(lang, TextKey::NewProductPageTitle),
        &nonce,
        auth_ref,
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

// ── POST /ui/products/new ──

pub(crate) async fn new_product_submit(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<NewProductForm>,
) -> Result<axum::response::Response, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    let ctx = auth_ref.ok_or_else(|| ApiError::Unauthorized("login required".into()))?;
    if !ctx.is_builder() {
        return Err(ApiError::PermissionDenied(
            "builder or higher role required".into(),
        ));
    }
    let is_admin = ctx.is_admin();

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    // 回显文案按页面语言本地化：handler 内联字面量 + core 变体调用侧映射（见 product_editor_core_error_flash），render_* 只渲染成品句。
    let lang = lang_from_headers(&headers);

    // slug 校验（create 严格版，≤128 上限）。校验字面量与 API JSON 面共用、一字不动；
    // 空名/非法字符/超长按字面量（含 form.name 重组）比对，映射 FlashProductName* key。
    if let Err(e) = validate_product_name_for_write(&form.name) {
        let msg = match e {
            ApiError::Validation(m) => m,
            other => return Err(other),
        };
        let localized = if msg == "product name cannot be empty" {
            t(lang, TextKey::FlashProductNameEmpty).to_string()
        } else if msg
            == format!(
                "product name '{}' has invalid characters; only [a-z0-9_-] are allowed",
                form.name
            )
        {
            t_fmt(lang, FmtKey::FlashProductNameInvalidChars, &[&form.name])
        } else if msg
            == format!(
                "product name too long (max 128 characters, got {})",
                form.name.len()
            )
        {
            t_fmt(
                lang,
                FmtKey::FlashProductNameTooLong,
                &[&form.name.len().to_string()],
            )
        } else {
            msg
        };
        return render_new_with_error(&app, auth_ref, &headers, &form, &localized)
            .await
            .map(|r| r.into_response());
    }

    let config = match crbs_core::config::ProductConfig::from_str(&form.config_toml) {
        Ok(c) => c,
        Err(e) => {
            return render_new_with_error(
                &app,
                auth_ref,
                &headers,
                &form,
                &product_editor_core_error_flash(&e, lang),
            )
            .await
        }
    };

    let (owner_id, visibility) = if is_admin {
        // admin 表单 visibility 是自由提交字符串，须校验枚举（API 侧同款）；非法值按"重渲染保留输入"模式回显，不静默降级、不入库。
        if form.visibility != crbs_core::VISIBILITY_PUBLIC
            && form.visibility != crbs_core::VISIBILITY_PRIVATE
        {
            let msg = t_fmt(
                lang,
                FmtKey::FlashInvalidVisibilityEditor,
                &[&form.visibility],
            );
            return render_new_with_error(&app, auth_ref, &headers, &form, &msg)
                .await
                .map(|r| r.into_response());
        }
        if form.owner.trim().is_empty() {
            // Private+空 owner 显式报错让 admin 二选一（补 owner 或改 Public）；
            // owner=None 官方产品受 SCHEMA CHECK 约束必须 public。
            if form.visibility == crbs_core::VISIBILITY_PRIVATE {
                let msg = t(lang, TextKey::FlashPrivateNeedsOwnerPick).to_string();
                return render_new_with_error(&app, auth_ref, &headers, &form, &msg)
                    .await
                    .map(|r| r.into_response());
            }
            (None, crbs_core::VISIBILITY_PUBLIC)
        } else {
            let owner_name = form.owner.trim();
            match app.state_store.find_user_by_name(owner_name).await? {
                Some(u) => (Some(u.id), form.visibility.as_str()),
                None => {
                    return render_new_with_error(
                        &app,
                        auth_ref,
                        &headers,
                        &form,
                        &t_fmt(lang, FmtKey::FlashOwnerNotFound, &[owner_name]),
                    )
                    .await;
                }
            }
        }
    } else {
        (ctx.user_id, crbs_core::VISIBILITY_PRIVATE)
    };

    let parent_id = if form.parent_name.trim().is_empty() {
        None
    } else {
        let pname = form.parent_name.trim();
        match app.state_store.get_product_by_name(pname).await? {
            Some(p) => {
                // builder 只能挂 public 产品下
                if !is_admin && p.visibility == crbs_core::VISIBILITY_PRIVATE {
                    return render_new_with_error(
                        &app,
                        auth_ref,
                        &headers,
                        &form,
                        &t_fmt(lang, FmtKey::FlashParentPrivateAttach, &[pname]),
                    )
                    .await;
                }
                Some(p.id)
            }
            None => {
                return render_new_with_error(
                    &app,
                    auth_ref,
                    &headers,
                    &form,
                    &t_fmt(lang, FmtKey::FlashParentProductNotFound, &[pname]),
                )
                .await;
            }
        }
    };

    // public 产品不能挂私有祖先
    if visibility == crbs_core::VISIBILITY_PUBLIC {
        if let Some(pid) = parent_id {
            if let Some(parent) = app.state_store.get_product_by_id(pid).await? {
                if parent.visibility != crbs_core::VISIBILITY_PUBLIC {
                    return render_new_with_error(
                        &app,
                        auth_ref,
                        &headers,
                        &form,
                        t(lang, TextKey::FlashPublicAttachPrivateParent),
                    )
                    .await;
                }
            }
        }
    }

    if let Err(e) = app
        .state_store
        .resolve_preview_for_create(parent_id, &form.name, &config)
        .await
    {
        return render_new_with_error(
            &app,
            auth_ref,
            &headers,
            &form,
            &product_editor_core_error_flash(&e, lang),
        )
        .await;
    }

    let input = crbs_core::CreateProductInput {
        name: &form.name,
        display_name: Some(form.display_name.as_str()).filter(|s| !s.is_empty()),
        owner_id,
        parent_id,
        visibility,
        config: &config,
        changed_by_user_id: ctx.user_id,
        reason: Some("created via web UI"),
    };

    match app.state_store.create_product(input).await {
        Ok(_id) => {
            let location = format!(
                "/ui/products/{}?status=product_created",
                urlencoding::encode(&form.name)
            );
            crate::server::routes::ui::components::see_other_redirect(&location)
                .map(|r| r.into_response())
        }
        Err(e) => render_new_with_error(
            &app,
            auth_ref,
            &headers,
            &form,
            &product_editor_core_error_flash(&e, lang),
        )
        .await
        .map(|r| r.into_response()),
    }
}

// ── GET /ui/products/{name}/edit ──

pub(crate) async fn edit_product_page(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    validate_product_name(&name)?;

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let csrf_token = csrf_token_for_request(&headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let config_toml = record.config.to_toml_string().unwrap_or_default();

    let parent_name: Option<String> = match record.parent_id {
        Some(pid) => app
            .state_store
            .get_product_by_id(pid)
            .await?
            .map(|p| p.name),
        None => None,
    };

    // "最近变更"取 list_product_history 首条（revision DESC 即最新）；加载失败不挡编辑页，只省略该部分。
    let latest_history = match app.state_store.list_product_history(record.id).await {
        Ok(entries) => entries.into_iter().next(),
        Err(e) => {
            tracing::warn!(product = %name, error = %e, "Failed to load product history for edit page");
            None
        }
    };
    // 变更人 username（行缺失 / 查询失败回退 user#N）。
    let changed_by: Option<String> = match latest_history
        .as_ref()
        .and_then(|e| e.changed_by_user_id)
    {
        Some(id) => match app.state_store.get_user(id).await {
            Ok(Some(u)) => Some(u.name),
            Ok(None) => {
                tracing::warn!(user_id = id, "user row missing for edit page revision line");
                Some(format!("user#{id}"))
            }
            Err(e) => {
                tracing::warn!(user_id = id, error = %e, "get_user failed for edit page revision line");
                Some(format!("user#{id}"))
            }
        },
        None => None,
    };

    let is_owner_not_admin = auth_ref.is_some_and(|c| !c.is_admin())
        && auth_ref.and_then(|c| c.user_id) == record.owner_id;

    let lang = lang_from_headers(&headers);
    let body = html! {
        // 页头条带：crumb 返回详情 + 标题 + revision/最近变更 meta 行。
        (detail_page_head(
            html! {
                (back_link(
                    t(lang, TextKey::BackToProduct),
                    &format!("/ui/products/{}", urlencoding::encode(&name)),
                    None,
                ))
            },
            html! { (t_fmt(lang, FmtKey::EditTitle, &[&name])) },
            html! {
                (t(lang, TextKey::MeRevision)) " " (record.revision)
                @if let Some(entry) = &latest_history {
                    span class="sep" { "·" }
                    (t(lang, TextKey::EditLastChanged)) " " (rel_time_lang(Some(entry.changed_at.as_str()), lang))
                    @if let Some(who) = &changed_by {
                        " " (t_fmt(lang, FmtKey::EditChangedBy, &[who]))
                    }
                }
            },
            html! {},
        ))
        @match parent_name.as_deref() {
            Some(parent) => p { (t_fmt(lang, FmtKey::ParentLabel, &[parent])) " " a href=(format!("/ui/products/{}", urlencoding::encode(parent))) { (parent) } },
            None => {},
        }
        @if is_owner_not_admin {
            p { (t(lang, TextKey::YouAreOwner)) }
        }
        (edit_form(&csrf_token, record.revision, "web edit", &config_toml, lang))
    };

    page_with_csp(
        &t_fmt(lang, FmtKey::EditPageTitle, &[&name]),
        &nonce,
        auth_ref,
        "products",
        &headers,
        &app.csrf_key,
        body,
    )
}

// ── POST /ui/products/{name}/edit ──

pub(crate) async fn edit_product_submit(
    State(app): State<Arc<AppState>>,
    Path(name): Path<String>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    Form(form): Form<EditProductForm>,
) -> Result<impl IntoResponse, ApiError> {
    let auth_ref = auth.as_ref().map(|ext| &ext.0);
    check_public_access(&app, app.server_config.public_access.view, auth_ref)?;
    let ctx = auth_ref.ok_or_else(|| ApiError::Unauthorized("login required".into()))?;
    // update 入口 name 是既有产品标识符（不可变），走宽松版（长度上限只挡 create 新名），口径同 API PUT。
    validate_product_name(&name)?;

    require_csrf(&headers, &form.csrf_token, &app.csrf_key)?;

    let lang = lang_from_headers(&headers);

    let record = load_record_for_owner_or_admin(&app, &name, auth_ref).await?;

    let edit_ctx = EditPageCtx {
        name: &name,
        current_revision: record.revision,
        config_toml: &form.config_toml,
        reason: &form.reason,
    };

    let config = match crbs_core::config::ProductConfig::from_str(&form.config_toml) {
        Ok(c) => c,
        Err(e) => {
            return render_edit_with_error(
                &app,
                auth_ref,
                &headers,
                &edit_ctx,
                &product_editor_core_error_flash(&e, lang),
            )
            .map(|r| r.into_response());
        }
    };

    if form.expected_revision != record.revision {
        return render_edit_with_error(
            &app,
            auth_ref,
            &headers,
            &edit_ctx,
            &t_fmt(
                lang,
                FmtKey::FlashProductRevisionMoved,
                &[&record.revision.to_string()],
            ),
        )
        .map(|r| r.into_response());
    }

    let preview = app
        .state_store
        .resolve_preview_for_edit(record.id, &config)
        .await;

    // check 动作：只显示校验结果，不落库
    if form.action == "check" {
        return render_edit_with_check(&app, auth_ref, &headers, &edit_ctx, &preview)
            .map(|r| r.into_response());
    }

    if let Err(ref e) = preview {
        return render_edit_with_error(
            &app,
            auth_ref,
            &headers,
            &edit_ctx,
            &product_editor_core_error_flash(e, lang),
        )
        .map(|r| r.into_response());
    }

    let reason = if form.reason.trim().is_empty() {
        None
    } else {
        Some(form.reason.trim())
    };

    match app
        .state_store
        .update_product_config(
            record.id,
            &config,
            ctx.user_id,
            reason,
            Some(form.expected_revision),
        )
        .await
    {
        Ok(_outcome) => {
            let location = format!(
                "/ui/products/{}?status=product_updated",
                urlencoding::encode(&name)
            );
            crate::server::routes::ui::components::see_other_redirect(&location)
                .map(|r| r.into_response())
        }
        Err(e) => render_edit_with_error(
            &app,
            auth_ref,
            &headers,
            &edit_ctx,
            &product_editor_core_error_flash(&e, lang),
        )
        .map(|r| r.into_response()),
    }
}

/// product_editor 的 core 错误（TOML 解析 / 链级 dry-run 预览 / create / update）
/// → 按页面语言本地化的回显文案（形态照 gc_error_flash）。只映射结构化变体：
/// AlreadyExists（产品名占用，前后缀锚定拆名）、RevisionConflict（乐观锁冲突，
/// 覆盖 handler 前置 expected_revision 之外的竞态窗口）、ProductChainTooDeep、
/// 两条链 walk NotFound。其余回退 `safe_message()` 原文——自由文本族
///（ProductChainInvalid reason / ValidationFailed / toml parse）与 API JSON 面共用，字面量不能动。
fn product_editor_core_error_flash(e: &CrbsError, lang: Lang) -> String {
    match e {
        CrbsError::AlreadyExists { message } => match message
            .strip_prefix("product name '")
            .and_then(|s| s.strip_suffix("' is taken (namespace is global)"))
        {
            Some(name) => t_fmt(lang, FmtKey::FlashProductNameTaken, &[name]),
            None => message.clone(),
        },
        CrbsError::RevisionConflict { expected, current } => t_fmt(
            lang,
            FmtKey::FlashRevisionConflictStore,
            &[&expected.to_string(), &current.to_string()],
        ),
        CrbsError::ProductChainTooDeep { max } => {
            t_fmt(lang, FmtKey::FlashProductChainTooDeep, &[&max.to_string()])
        }
        CrbsError::NotFound { message } => {
            if let Some(id) = message
                .strip_prefix("product id=")
                .and_then(|s| s.strip_suffix(" not found in chain walk"))
            {
                t_fmt(lang, FmtKey::FlashChainWalkParentMissing, &[id])
            } else if let Some(id) = message
                .strip_prefix("product ")
                .and_then(|s| s.strip_suffix(" resolved to empty chain"))
            {
                t_fmt(lang, FmtKey::FlashChainWalkEmptyChain, &[id])
            } else {
                message.clone()
            }
        }
        other => other.safe_message(),
    }
}

/// 重渲染新建表单 + 错误 banner，保留用户输入。
async fn render_new_with_error(
    app: &AppState,
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    form: &NewProductForm,
    error: &str,
) -> Result<axum::response::Response, ApiError> {
    let csrf_token = csrf_token_for_request(headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let is_admin = auth.is_some_and(|c| c.is_admin());
    let lang = lang_from_headers(headers);

    let placeholder = r#"base_packages = ["bash", "rpm-build", "gcc", "make"]

[[repos]]
name = "base"
baseurl = "http://example.com/repo/$basearch"
gpgcheck = false"#;

    let body = html! {
        // 页头条带：与 GET new 页同构（重渲染保留输入）。
        div class="crumb" {
            (back_link(t(lang, TextKey::BackToProducts), "/ui/products", None))
        }
        div class="page-head" {
            div class="title-block" {
                h1 { (t(lang, TextKey::NewProductPageTitle)) }
            }
        }
        div class="message failure" { (error) }
        form class="form-card" method="post" {
            @if let Some(ref token) = csrf_token {
                input type="hidden" name="csrf_token" value=(token);
            }

            label for="name" { (t(lang, TextKey::LabelProductNameSlug)) }
            input type="text" id="name" name="name" required
                pattern="[a-z0-9_-]+" value=(&form.name) placeholder="my-product";

            label for="display_name" { (t(lang, TextKey::LabelDisplayNameOptional)) }
            input type="text" id="display_name" name="display_name"
                value=(&form.display_name) placeholder=(t(lang, TextKey::PlaceholderDisplayName));

            label for="parent_name" { (t(lang, TextKey::LabelParentOptional)) }
            input type="text" id="parent_name" name="parent_name"
                value=(&form.parent_name) placeholder=(t(lang, TextKey::PlaceholderEmptyRoot));

            @if is_admin {
                label for="owner" { (t(lang, TextKey::LabelOwnerOptional)) }
                input type="text" id="owner" name="owner" value=(&form.owner)
                    placeholder=(t(lang, TextKey::PlaceholderEmptyOfficial));

                label { (t(lang, TextKey::ThVisibility)) }
                label class="radio-label" {
                    input type="radio" name="visibility" value="public"
                        checked[form.visibility == "public"];
                    " " (t(lang, TextKey::VisPublic))
                }
                label class="radio-label" {
                    input type="radio" name="visibility" value="private"
                        checked[form.visibility == "private"];
                    " " (t(lang, TextKey::VisPrivate))
                }
            } @else {
                input type="hidden" name="visibility" value="private";
                p { (t(lang, TextKey::BuilderVisibilityNote)) }
            }

            label for="config_toml" { (t(lang, TextKey::LabelConfigToml)) }
            textarea id="config_toml" name="config_toml" rows="24" spellcheck="false"
                placeholder=(placeholder) {
                (&form.config_toml)
            }

            p {
                button type="submit" class="action-button" { (t(lang, TextKey::ButtonCreate)) }
            }
        }
    };

    page_with_csp(
        t(lang, TextKey::NewProductPageTitle),
        &nonce,
        auth,
        "products",
        headers,
        &app.csrf_key,
        body,
    )
    .map(|r| r.into_response())
}

/// 编辑表单骨架（GET 首渲与 error/check 重渲染三处共用）：CSRF/expected_revision
/// 隐藏域 + reason/config_toml 输入 + check/save 提交组。
fn edit_form(
    token: &Option<String>,
    revision: i64,
    reason: &str,
    config: &str,
    lang: Lang,
) -> Markup {
    html! {
        form class="form-card" method="post" {
            @if let Some(token) = token {
                input type="hidden" name="csrf_token" value=(token);
            }
            input type="hidden" name="expected_revision" value=(revision);
            label for="reason" { (t(lang, TextKey::LabelChangeReason)) }
            input type="text" id="reason" name="reason" value=(reason) placeholder=(t(lang, TextKey::PlaceholderDescribeChange));
            label for="config_toml" { (t(lang, TextKey::LabelConfigToml)) }
            textarea id="config_toml" name="config_toml" rows="24" spellcheck="false" {
                (config)
            }
            p {
                button type="submit" name="action" value="check" class="action-button secondary" { (t(lang, TextKey::ButtonCheck)) }
                " "
                button type="submit" name="action" value="save" class="action-button" { (t(lang, TextKey::SettingsSaveButton)) }
            }
        }
    }
}

/// 重渲染编辑表单 + 错误 banner，保留用户输入。
fn render_edit_with_error(
    app: &AppState,
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    ctx: &EditPageCtx<'_>,
    error: &str,
) -> Result<axum::response::Response, ApiError> {
    let csrf_token = csrf_token_for_request(headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(headers);

    let body = html! {
        // 页头条带：与 GET edit 页同构（重渲染保留输入）。
        (detail_page_head(
            html! {
                (back_link(
                    t(lang, TextKey::BackToProduct),
                    &format!("/ui/products/{}", urlencoding::encode(ctx.name)),
                    None,
                ))
            },
            html! { (t_fmt(lang, FmtKey::EditTitle, &[ctx.name])) },
            html! {
                (t(lang, TextKey::MeRevision)) " " (ctx.current_revision)
            },
            html! {},
        ))
        div class="message failure" { (error) }
        (edit_form(&csrf_token, ctx.current_revision, ctx.reason, ctx.config_toml, lang))
    };

    page_with_csp(
        &t_fmt(lang, FmtKey::EditPageTitle, &[ctx.name]),
        &nonce,
        auth,
        "products",
        headers,
        &app.csrf_key,
        body,
    )
    .map(|r| r.into_response())
}

/// 重渲染编辑表单 + check 结果（成功/失败 banner + 合并预览）。
fn render_edit_with_check(
    app: &AppState,
    auth: Option<&AuthContext>,
    headers: &HeaderMap,
    ctx: &EditPageCtx<'_>,
    preview: &Result<String, CrbsError>,
) -> Result<axum::response::Response, ApiError> {
    let csrf_token = csrf_token_for_request(headers, &app.csrf_key);
    let nonce = generate_nonce()?;
    let lang = lang_from_headers(headers);

    let body = html! {
        // 页头条带：与 GET edit 页同构（check 结果重渲染）。
        (detail_page_head(
            html! {
                (back_link(
                    t(lang, TextKey::BackToProduct),
                    &format!("/ui/products/{}", urlencoding::encode(ctx.name)),
                    None,
                ))
            },
            html! { (t_fmt(lang, FmtKey::EditTitle, &[ctx.name])) },
            html! {
                (t(lang, TextKey::MeRevision)) " " (ctx.current_revision)
            },
            html! {},
        ))
        // 结果区锚点 + 一次性滚动脚本：Check banner 在长表单上方，无锚点视口停在页首看不到。
        div id="check-result" {
            @match preview {
                Ok(merged_toml) => {
                    div class="message success" { (t(lang, TextKey::ConfigValid)) }
                    details {
                        summary { (t(lang, TextKey::MergedPreview)) }
                        pre class="code-block" { (merged_toml) }
                    }
                }
                Err(e) => {
                    // Check 结果的失败回显同走 core 变体映射。
                    div class="message failure" { (product_editor_core_error_flash(e, lang)) }
                }
            }
        }
        script nonce=(nonce) { (PreEscaped(r#"
            (function() {
                var el = document.getElementById('check-result');
                if (el) { el.scrollIntoView({block: 'center'}); }
            })();
        "#)) }
        (edit_form(&csrf_token, ctx.current_revision, ctx.reason, ctx.config_toml, lang))
    };

    page_with_csp(
        &t_fmt(lang, FmtKey::EditPageTitle, &[ctx.name]),
        &nonce,
        auth,
        "products",
        headers,
        &app.csrf_key,
        body,
    )
    .map(|r| r.into_response())
}

#[cfg(test)]
mod tests {
    use super::NewProductForm;

    /// axum::Form 对 urlencoded 表单走 serde_urlencoded，测试用同一反序列化器覆盖真实解析路径。
    #[test]
    fn new_product_form_without_owner_key_parses() {
        let body =
            "csrf_token=t&name=foo&display_name=&parent_name=&visibility=private&config_toml=";
        let form: NewProductForm =
            serde_urlencoded::from_str(body).expect("form without owner key must parse");
        // 空 owner 语义：非 admin 忽略 owner 强制 self+private；admin 空串 = official。
        assert_eq!(form.owner, "");
        assert_eq!(form.visibility, "private");
    }

    #[test]
    fn new_product_form_with_owner_key_parses() {
        let body = "csrf_token=t&name=foo&display_name=&parent_name=&owner=cc&visibility=public&config_toml=";
        let form: NewProductForm =
            serde_urlencoded::from_str(body).expect("form with owner key must parse");
        assert_eq!(form.owner, "cc");
        assert_eq!(form.visibility, "public");
    }
}
