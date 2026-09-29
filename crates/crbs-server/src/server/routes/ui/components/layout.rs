// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 页面骨架与布局小件：page 骨架族与安全响应头、页头条带、双栏详情小件、
//! redirect/flash 工具。

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use maud::{html, Markup, PreEscaped, DOCTYPE};

use crate::server::auth::AuthContext;
use crate::server::csrf;
use crate::server::error::ApiError;
use crate::server::routes::ui::i18n::{
    lang_from_headers, status_reason_localized, t, t_fmt, FmtKey, Lang, TextKey,
};
use crate::server::routes::ui::pages::theme::{theme_from_headers, Theme};
use crate::server::routes::ui::service::{csrf_token_for_request, safe_back_path};

use super::form::CONFIRM_SCRIPT;
use super::{clickable_rows_script, StatusQuery};

pub(crate) fn generate_nonce() -> Result<String, ApiError> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).map_err(|e| {
        tracing::error!(error = %e, "Failed to generate CSP nonce");
        ApiError::Internal("failed to generate CSP nonce".into())
    })?;
    Ok(hex::encode(buf))
}

/// nav 当前项的 `aria-current` 值；`None` = maud 可选属性不渲染。
fn aria_current(current: bool) -> Option<&'static str> {
    current.then_some("page")
}

/// 主题态 → nav 文案 key（按钮 aria/title 用当前态与下一态文案）。
fn theme_label_key(theme: Theme) -> TextKey {
    match theme {
        Theme::Auto => TextKey::NavThemeAuto,
        Theme::Light => TextKey::NavThemeLight,
        Theme::Dark => TextKey::NavThemeDark,
    }
}

/// 内嵌 favicon（圆角方块 + "C"）。CSP default-src 'self' 禁 data: URI，
/// 故走独立静态路由。固定单套配色（#2563eb 蓝底白字，对比度 ~5.2:1），
/// 勿回退 prefers-color-scheme 双套——media query 跟 OS 外观而非页面主题。
const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><rect width="16" height="16" rx="3" fill="#2563eb"/><text x="8" y="12" font-size="10" text-anchor="middle" font-family="sans-serif" fill="#fff">C</text></svg>"##;

/// 全站样式表（nonce 内联进每页 `<head>`，两骨架共用同一份）。
const STYLE_CSS: &str = include_str!("../style.css");

/// 返回内嵌 favicon SVG，带一天的缓存头。
pub(crate) async fn favicon() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}

/// 渲染整页骨架（导航栏 + CSP nonce 脚本）；nav logout 的 CSRF token 从
/// 请求 cookie 自行派生，不经调用方传参。
fn page(
    title: &str,
    nonce: &str,
    auth: Option<&AuthContext>,
    active: &str,
    headers: &HeaderMap,
    csrf_key: &[u8; 32],
    content: Markup,
) -> Markup {
    // 无会话 cookie → None：渲染 Login 链接而非 Logout 表单。
    let csrf_token = csrf_token_for_request(headers, csrf_key);
    // 主题 cookie → data-theme；Auto 不输出属性（走系统媒体查询）。
    let theme = theme_from_headers(headers);
    // 语言从请求头提取（?lang= > cookie > Accept-Language），与 handler 侧
    // 同一函数——html lang 与页面文案永不漂移；数据值（用户名/角色/版本号）不译。
    let lang = lang_from_headers(headers);
    // 主题按钮 aria/title："当前 X，切换到 Y"（Y = 循环下一态）。
    let theme_next = theme.next();
    let theme_toggle_label = t_fmt(
        lang,
        FmtKey::ThemeToggleAria,
        &[
            t(lang, theme_label_key(theme)),
            t(lang, theme_label_key(theme_next)),
        ],
    );
    // 语言按钮：当前语言自称 + 目标语言自称（自称不译）；cookie 值小写
    // en/zh（与 set-lang 白名单一致）。
    let (lang_self, lang_target, lang_target_value) = match lang {
        Lang::Zh => ("中", "EN", "en"),
        Lang::En => ("EN", "中", "zh"),
    };
    let lang_toggle_label = t_fmt(lang, FmtKey::LangToggleAria, &[lang_self, lang_target]);
    html! {
        (DOCTYPE)
        html lang=(lang.html_lang()) data-theme=[theme.data_theme_attr()] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · CRBS" }
                link rel="icon" href="/ui/favicon.svg" type="image/svg+xml";
                style nonce=(nonce) { (PreEscaped(STYLE_CSS)) }
            }
            body {
                nav {
                    div class="nav-inner" {
                        a class="nav-brand" href="/ui/" {
                            img src="/ui/favicon.svg" alt="" class="nav-logo";
                            "CRBS"
                        }
                        // 导航链接：active 键与各页 page()/page_with_csp() 传入值
                        // 一一对应，Dashboard 是空串。
                        div class="nav-links" {
                            a.active[active.is_empty()] aria-current=[aria_current(active.is_empty())]
                                href="/ui/" { (t(lang, TextKey::NavDashboard)) }
                            a.active[active == "builds"] aria-current=[aria_current(active == "builds")]
                                href="/ui/builds" { (t(lang, TextKey::NavBuilds)) }
                            a.active[active == "tasks"] aria-current=[aria_current(active == "tasks")]
                                href="/ui/tasks" { (t(lang, TextKey::NavTasks)) }
                            a.active[active == "products"] aria-current=[aria_current(active == "products")]
                                href="/ui/products" { (t(lang, TextKey::NavProducts)) }
                            a.active[active == "packages"] aria-current=[aria_current(active == "packages")]
                                href="/ui/packages" { (t(lang, TextKey::NavPackages)) }
                            a.active[active == "workers"] aria-current=[aria_current(active == "workers")]
                                href="/ui/workers" { (t(lang, TextKey::NavWorkers)) }
                            // 复现率看板：全角色可见（页面按产品可见性过滤）。
                            a.active[active == "reproducibility"] aria-current=[aria_current(active == "reproducibility")]
                                href="/ui/reproducibility" { (t(lang, TextKey::NavRepro)) }
                            // GC 链接：operator+ 可见（与页面 can_gc 门槛一致，
                            // 低于 ⚙ 的 admin-only）。active 键独立 "gc"，
                            // 与 ⚙ 的 "admin" 分开避免双高亮。
                            @if auth.is_some_and(|a| a.is_operator()) {
                                a.active[active == "gc"] aria-current=[aria_current(active == "gc")]
                                    href="/ui/admin/gc" { (t(lang, TextKey::NavGc)) }
                            }
                            // 整仓重建链接：operator+ 可见（与 /ui/batches 门槛一致）；active 键 "batches"。
                            @if auth.is_some_and(|a| a.is_operator()) {
                                a.active[active == "batches"] aria-current=[aria_current(active == "batches")]
                                    href="/ui/batches" { (t(lang, TextKey::NavBatches)) }
                            }
                        }
                        // 全局搜索：GET 表单提交 /ui/search（CSP form-action
                        // 'self'，无 JS 可用；匿名可渲染——匿名本就公开浏览）。
                        // 无提交按钮，Enter 隐式提交。
                        form class="nav-search" method="get" action="/ui/search" {
                            input type="search" name="q" aria-label=(t(lang, TextKey::SearchPlaceholder))
                                placeholder=(t(lang, TextKey::SearchPlaceholder));
                        }
                        // Logout 表单结构（hidden csrf_token + action）是测试
                        // 钉住的契约，逐字保留。
                        div class="nav-auth" {
                            // 主题单按钮：POST 循环下一态（auto→light→dark→auto），
                            // Set-Cookie + 303 回原页，无 JS。CSRF 分级：有凭据
                            // 校验 hidden csrf_token，匿名空串放行。
                            form method="post" action="/ui/set-theme" class="nav-pref-form" {
                                input type="hidden" name="theme" value=(theme_next.cookie_value());
                                input type="hidden" name="csrf_token" value=(csrf_token.as_deref().unwrap_or(""));
                                button type="submit" class="nav-icon-btn"
                                    title=(theme_toggle_label) aria-label=(theme_toggle_label) {
                                    (theme.icon())
                                }
                            }
                            // 语言单按钮：POST /ui/set-lang 切另一语言
                            //（Set-Cookie + 303 回原页），CSRF 分级同上。
                            form method="post" action="/ui/set-lang" class="nav-pref-form" {
                                input type="hidden" name="lang" value=(lang_target_value);
                                input type="hidden" name="csrf_token" value=(csrf_token.as_deref().unwrap_or(""));
                                button type="submit" class="nav-icon-btn"
                                    title=(lang_toggle_label) aria-label=(lang_toggle_label) {
                                    (lang_self)
                                }
                            }
                            @if let Some(a) = auth {
                                @if a.is_admin() {
                                    a.nav-icon-btn.active[active == "admin"]
                                        aria-current=[aria_current(active == "admin")]
                                        href="/ui/admin" title=(t(lang, TextKey::NavAdmin))
                                        aria-label=(t(lang, TextKey::NavAdmin)) {
                                        "⚙"
                                    }
                                }
                                @if !a.user.is_empty() {
                                    a class="nav-user" href="/ui/me" title=(a.user) { (a.user) }
                                }
                                @if !a.role.is_empty() {
                                    span class="nav-role" { (a.role) }
                                }
                                form class="nav-logout" method="post" action="/ui/logout" {
                                    @if let Some(ref token) = csrf_token {
                                        input type="hidden" name="csrf_token" value=(token);
                                    }
                                    button type="submit" class="nav-logout-button" { (t(lang, TextKey::NavLogout)) }
                                }
                            } @else {
                                a href="/ui/login" { (t(lang, TextKey::NavLogin)) }
                            }
                        }
                    }
                }
                main { (content) }
                // 全局页脚：左版本号，右 /api/v1/health 链接（公开存活探针）。
                footer class="site-footer" {
                    div class="site-footer-inner" {
                        span { "CRBS " b { (env!("CARGO_PKG_VERSION")) } }
                        span class="spacer" { }
                        a href="/api/v1/health" { (t(lang, TextKey::FooterApiHealth)) }
                    }
                }
                // confirm 脚本每页仅一份，事件委托 document 覆盖全部 data-confirm 按钮。
                script nonce=(nonce) { (PreEscaped(CONFIRM_SCRIPT)) }
                script nonce=(nonce) { (PreEscaped(SEARCH_FOCUS_SCRIPT)) }
            }
        }
    }
}

/// "/" 快捷键聚焦 nav 搜索框：无修饰键且目标非可交互元素才触发，框不存在
/// 则不动。无文案，无需 lang。
const SEARCH_FOCUS_SCRIPT: &str = r#"
    (function() {
        if (window.__crbsSearchFocusBound) { return; }
        window.__crbsSearchFocusBound = true;
        document.addEventListener('keydown', function(ev) {
            if (ev.key !== '/' || ev.ctrlKey || ev.metaKey || ev.altKey || ev.shiftKey) { return; }
            if (ev.target.closest('a, button, input, select, textarea, [contenteditable]')) { return; }
            var input = document.querySelector('.nav-search input');
            if (input) { ev.preventDefault(); input.focus(); }
        });
    })();
"#;

pub(crate) fn page_with_csp(
    title: &str,
    nonce: &str,
    auth: Option<&AuthContext>,
    active: &str,
    headers: &HeaderMap,
    csrf_key: &[u8; 32],
    content: Markup,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    page_with_csp_status(PageCspParams {
        title,
        nonce,
        auth,
        active,
        headers,
        csrf_key,
        content,
        status: StatusCode::OK,
    })
}

/// 一次性敏感页（明文 secret 展示）禁缓存：给 [`page_with_csp`] 元组的
/// headers 分量就地落 no-store，四处 secret 展示页共用。
pub(crate) fn no_store(page: (StatusCode, HeaderMap, Markup)) -> (StatusCode, HeaderMap, Markup) {
    let (status, mut headers, body) = page;
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    (status, headers, body)
}

/// [`page_with_csp_status`] 的参数包（页面 chrome + 安全上下文 + 状态码）。
pub(crate) struct PageCspParams<'a> {
    pub(crate) title: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) auth: Option<&'a AuthContext>,
    pub(crate) active: &'a str,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) csrf_key: &'a [u8; 32],
    pub(crate) content: Markup,
    pub(crate) status: StatusCode,
}

pub(crate) fn page_with_csp_status(
    params: PageCspParams<'_>,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let PageCspParams {
        title,
        nonce,
        auth,
        active,
        headers,
        csrf_key,
        content,
        status,
    } = params;
    // 注意：`headers` 是请求头（nav logout CSRF 派生用），响应头另起 `resp_headers`。
    let resp_headers = response_security_headers(nonce)?;
    Ok((
        status,
        resp_headers,
        page(title, nonce, auth, active, headers, csrf_key, content),
    ))
}

/// UI 页面公共安全响应头，两骨架共用同一份——header 值由
/// integration_public_access 的 ui_pages_set_csp_and_security_headers 钉住。
fn response_security_headers(nonce: &str) -> Result<HeaderMap, ApiError> {
    let mut resp_headers = HeaderMap::new();
    // style-src 放宽 'unsafe-inline' + 扩展协议源：WebKit 按页面 CSP 拦截
    // vim 导航扩展（Vimium 族）经 <link> 注入的样式表，须显式放行
    // safari-web-extension: / chrome-extension:；Chromium 本就不对内容脚本
    // 样式执行页面 CSP，协议源惰性。XSS 防线不变：script-src nonce 锁死、
    // maud 全自动转义，样式无法执行脚本；扩展改用 CSSOM 时可收紧回 'self'。
    let csp = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline' safari-web-extension: chrome-extension:; connect-src 'self'; form-action 'self'; base-uri 'self'"
    );
    resp_headers.insert(
        header::CONTENT_SECURITY_POLICY,
        csp.parse()
            .map_err(|_| ApiError::Internal("failed to build CSP header".into()))?,
    );
    resp_headers.insert(
        header::X_FRAME_OPTIONS,
        "DENY"
            .parse()
            .map_err(|_| ApiError::Internal("failed to build X-Frame-Options header".into()))?,
    );
    resp_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().map_err(|_| {
            ApiError::Internal("failed to build X-Content-Type-Options header".into())
        })?,
    );
    // HSTS 恒设置（明文 HTTP 下浏览器忽略）；无 includeSubDomains——子域未必全支持 TLS。
    resp_headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=31536000".parse().map_err(|_| {
            ApiError::Internal("failed to build Strict-Transport-Security header".into())
        })?,
    );
    // 页面含用户态内容（flash、构建详情），no-store 禁浏览器与中间层缓存。
    resp_headers.insert(
        header::CACHE_CONTROL,
        "no-store"
            .parse()
            .map_err(|_| ApiError::Internal("failed to build Cache-Control header".into()))?,
    );
    Ok(resp_headers)
}

/// 裸认证页骨架（登录 / 注册 / 限流 429）：无 nav / footer / 全局脚本，
/// body 直接放 content（调用方渲染 .login-card 品牌卡）。head 与安全头
/// 语义同 [`page`]；无 nav 登出表单，故不需 auth / csrf_key。
pub(crate) fn page_bare_with_csp_status(
    title: &str,
    nonce: &str,
    headers: &HeaderMap,
    content: Markup,
    status: StatusCode,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let resp_headers = response_security_headers(nonce)?;
    let theme = theme_from_headers(headers);
    let lang = lang_from_headers(headers);
    let markup = html! {
        (DOCTYPE)
        html lang=(lang.html_lang()) data-theme=[theme.data_theme_attr()] {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · CRBS" }
                link rel="icon" href="/ui/favicon.svg" type="image/svg+xml";
                style nonce=(nonce) { (PreEscaped(STYLE_CSS)) }
            }
            body {
                (content)
            }
        }
    };
    Ok((status, resp_headers, markup))
}

/// 空态组件（图标 + 标题 + 说明）：列表页无数据时替代空表格。
pub(crate) fn empty_state(title: &str, hint: &str) -> Markup {
    html! {
        div class="empty-state" {
            div class="empty-icon" {
                // 内联 SVG（文档内元素，不受 CSP 资源限制）描边随 currentColor。
                svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"
                    stroke="currentColor" stroke-width="2" stroke-linecap="round"
                    stroke-linejoin="round" aria-hidden="true" {
                    polyline points="22 12 16 12 14 15 10 15 8 12 2 12" {}
                    path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" {}
                }
            }
            div class="empty-title" { (title) }
            div class="empty-hint" { (hint) }
        }
    }
}

/// 将 HTTP 状态码格式化为错误页标题，如 "404 Not Found" / "404 未找到"；
/// 未知状态用 "Error <code>"（zh："错误 <code>"）。
pub(crate) fn error_title(status: StatusCode, lang: Lang) -> String {
    let code = status.as_u16().to_string();
    match status_reason_localized(lang, status) {
        Some(reason) => t_fmt(lang, FmtKey::ErrTitleKnown, &[&code, reason]),
        None => t_fmt(lang, FmtKey::ErrTitleUnknown, &[&code]),
    }
}

/// 渲染 UI 错误页正文（4xx/5xx，`error_page_middleware` 重写 JSON 错误时用）。
/// `login_next` 仅 401 且过 [`crate::server::routes::ui::service::safe_back_path`]
/// 校验时渲染 login CTA（401 → login → 回原页）；`message` 机器面不译。
pub(crate) fn error_content(
    status: StatusCode,
    message: &str,
    login_next: Option<&str>,
    lang: Lang,
) -> Markup {
    let login_href = match safe_back_path(login_next) {
        Some(next) => format!("/ui/login?next={}", urlencoding::encode(next)),
        None => "/ui/login".to_string(),
    };
    html! {
        h1 { (error_title(status, lang)) }
        div class="message failure" { (message) }
        @if status == StatusCode::UNAUTHORIZED {
            p { a class="action-button" href=(login_href) { (t(lang, TextKey::ErrLoginCta)) } }
        }
        p { a href="/ui/" { (t(lang, TextKey::ErrBackToDashboard)) } }
    }
}

/// 详情页返回链接：`back` 过 [`crate::server::routes::ui::service::safe_back_path`]
/// 校验回来源列表，否则回退默认页。
pub(crate) fn back_link(label: &str, fallback: &str, back: Option<&str>) -> Markup {
    let href = safe_back_path(back).unwrap_or(fallback);
    html! { p { a href=(href) { "← " (label) } } }
}

/// 列表页页头条带：title-block（h1 + meta）+ 右侧操作区；`meta` / `actions`
/// 传空 `html! {}` 时对应区块不渲染。
pub(crate) fn list_page_head(title: Markup, meta: Markup, actions: Markup) -> Markup {
    html! {
        div class="page-head" {
            div class="title-block" {
                h1 { (title) }
                @if !meta.0.is_empty() {
                    div class="page-meta" { (meta) }
                }
            }
            @if !actions.0.is_empty() {
                div class="header-actions" { (actions) }
            }
        }
    }
}

/// 详情页页头条带：crumb + title-block + 可选操作区；crumb 独立在条带外
/// （不受 flex 挤压）。空 `meta` / `actions` 不渲染（同 [`list_page_head`]）。
pub(crate) fn detail_page_head(
    crumb: Markup,
    title: Markup,
    meta: Markup,
    actions: Markup,
) -> Markup {
    html! {
        div class="crumb" { (crumb) }
        div class="page-head" {
            div class="title-block" {
                h1 { (title) }
                @if !meta.0.is_empty() {
                    div class="page-meta" { (meta) }
                }
            }
            @if !actions.0.is_empty() {
                div class="header-actions" { (actions) }
            }
        }
    }
}

// ── 详情页双栏共享组件 ──
// 骨架/侧栏卡/Danger zone 一律先进本模块再逐页调用，禁止页面级复制；纯 CSS + HTML，零 JS。

/// 详情页双栏骨架：主列 + 320px 侧栏，≤1024 回落单栏（侧栏按源序沉底，
/// main 恒在前）；卡复用 `.admin-section` 卡壳。
pub(crate) fn detail_grid(main_col: Markup, sidebar: Markup) -> Markup {
    html! {
        div class="detail-grid" {
            div class="detail-main" { (main_col) }
            div class="detail-side" { (sidebar) }
        }
    }
}

/// 侧栏卡壳：`.admin-section` + 可选变体类（`"danger-zone"` 红边卡，空串
/// 无附加类）。
pub(crate) fn side_card(variant: &str, title: &str, body: Markup) -> Markup {
    let class = if variant.is_empty() {
        "admin-section".to_string()
    } else {
        format!("admin-section {variant}")
    };
    html! {
        div class=(class) {
            h2 { (title) }
            (body)
        }
    }
}

/// 侧栏 kv 行集：dt / dd 两列 grid。
pub(crate) fn side_kv(rows: &[(Markup, Markup)]) -> Markup {
    html! {
        dl class="side-kv" {
            @for (k, v) in rows {
                dt { (k) }
                dd { (v) }
            }
        }
    }
}

/// 负载色阶阈值（%）：低于 WARN 绿、WARN–CRIT（含两端）琥珀、超 CRIT 红；
/// worker SSE 脚本 loadLevel 注入同源，防 SSR/JS 双写漂移。
pub(crate) const LOAD_LEVEL_WARN_PCT: f64 = 70.0;
pub(crate) const LOAD_LEVEL_CRIT_PCT: f64 = 90.0;

/// 负载色阶 → 徽章类名（success / warn / failure）：<70 绿 / 70–90 琥珀 /
/// >90 红；workers 遥测条与首页均值 chip 共用同一阈值。
pub(crate) fn load_level(pct: f64) -> &'static str {
    if pct < LOAD_LEVEL_WARN_PCT {
        "success"
    } else if pct <= LOAD_LEVEL_CRIT_PCT {
        "warn"
    } else {
        "failure"
    }
}

/// KB → 人读单位（<1M 裸 KB，<1G 一位小数 M，其余一位小数 G）；画像页与
/// 归因徽章的内存量展示共用本表，防双写漂移。
pub(crate) fn format_kb_human(kb: i64) -> String {
    const M: f64 = 1024.0;
    const G: f64 = 1024.0 * 1024.0;
    let v = kb as f64;
    if v >= G {
        format!("{:.1}G", v / G)
    } else if v >= M {
        format!("{:.1}M", v / M)
    } else {
        format!("{kb}K")
    }
}

/// worker 采集能力位 → 显示词表（`workers.resource_caps` 位图，位常量
/// [`crbs_core::RESOURCE_CAP_CGROUP_V2`] 等；词是机器 token 不走文案表）。
/// SSR caps chips 与 worker SSE 脚本 CAPS_BITS 注入共用本表，防两侧漂移。
pub(crate) fn resource_cap_bits() -> Vec<(i64, &'static str)> {
    vec![
        (crbs_core::RESOURCE_CAP_CGROUP_V2, "cgroup v2"),
        (crbs_core::RESOURCE_CAP_MEMORY_PEAK, "peak"),
        (crbs_core::RESOURCE_CAP_MEMORY_EVENTS, "events"),
        (crbs_core::RESOURCE_CAP_IO_STAT, "io"),
        (crbs_core::RESOURCE_CAP_PSI, "psi"),
    ]
}

/// `?status=` / `?error=` flash 渲染：status 走 t() 双语表，已签名 `?error=` 原文
/// （机器面消息）原样透传；失败语义机器码同走 `?status=`，渲染 `message failure`。
pub(crate) fn status_message(query: &StatusQuery, csrf_key: &[u8; 32], lang: Lang) -> Markup {
    let status_html = match query.status.as_deref() {
        Some("cancelled") => Some((TextKey::FlashCancelled, false)),
        Some("rebuilt") => Some((TextKey::FlashRebuilt, false)),
        Some("reproduced") => Some((TextKey::FlashReproduced, false)),
        Some("submitted") => Some((TextKey::FlashSubmitted, false)),
        Some("created") => Some((TextKey::FlashUserCreated, false)),
        Some("role_updated") => Some((TextKey::FlashRoleUpdated, false)),
        Some("status_updated") => Some((TextKey::FlashUserStatusUpdated, false)),
        Some("token_revoked") => Some((TextKey::FlashTokenRevoked, false)),
        Some("password_changed") => Some((TextKey::FlashPasswordChanged, false)),
        Some("sessions_revoked") => Some((TextKey::FlashSessionsRevoked, false)),
        Some("acl_granted") => Some((TextKey::FlashAclGranted, false)),
        Some("acl_revoked") => Some((TextKey::FlashAclRevoked, false)),
        Some("secret_revoked") => Some((TextKey::FlashSecretRevoked, false)),
        Some("worker_removed") => Some((TextKey::FlashWorkerRemoved, false)),
        Some("init_dispatched") => Some((TextKey::FlashInitDispatched, false)),
        Some("product_created") => Some((TextKey::FlashProductCreated, false)),
        Some("product_updated") => Some((TextKey::FlashProductUpdated, false)),
        Some("visibility_updated") => Some((TextKey::FlashVisibilityUpdated, false)),
        Some("ownership_transferred") => Some((TextKey::FlashOwnershipTransferred, false)),
        Some("repo_rebuilt") => Some((TextKey::FlashRepoRebuilt, false)),
        Some("gc_started") => Some((TextKey::FlashGcStarted, false)),
        Some("batch_cancelled") => Some((TextKey::FlashBatchCancelled, false)),
        Some("profile_floors_updated") => Some((TextKey::FlashProfileFloorsUpdated, false)),
        Some(STORAGE_ERROR_STATUS) => Some((TextKey::FlashStorageError, true)),
        Some(INTERNAL_ERROR_STATUS) => Some((TextKey::FlashInternalError, true)),
        _ => None,
    }
    .map(|(key, failure)| {
        html! { div class=(if failure { "message failure" } else { "message success" }) { (t(lang, key)) } }
    });
    let error_html = query.error.as_deref().filter(|e| !e.is_empty()).map(|e| {
        // `?error=` 须携带 `&es=` 签名（见 [`crate::server::csrf::sign_ui_error_flash`]）；
        // 缺失或不匹配 = URL 外部构造，只渲染固定文案，不反射原文。
        let verified = query
            .es
            .as_deref()
            .and_then(|sig| csrf::verify_ui_error_flash(e, csrf_key, sig).ok())
            .unwrap_or(false);
        let text = if verified {
            e
        } else {
            t(lang, TextKey::FlashOperationFailed)
        };
        html! {
            div class="message failure" { (text) }
        }
    });

    match (status_html, error_html) {
        (Some(s), Some(e)) => html! { (s) (e) },
        (Some(s), None) => s,
        (None, Some(e)) => e,
        _ => html! {},
    }
}

/// 303 响应体：文案 / title / `<html lang>` 按传入 lang 输出（浏览器自动
/// 跟随，语言只影响禁跟随客户端）。`lang` 就近协商：一般传
/// `lang_from_headers(&headers)`，set-lang 传刚选中的目标语言。
pub(crate) fn redirect_body(lang: Lang) -> Markup {
    let text = t(lang, TextKey::Redirecting);
    html! {
        (DOCTYPE)
        html lang=(lang.html_lang()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (text) " · CRBS" }
            }
            body { p { (text) } }
        }
    }
}

/// Location 头值统一构造：`HeaderValue::from_str` 放行 ≥0x80 字节（obs-text），
/// 直接 parse 会把原始多字节字符送上 wire——RFC 9110 要求 Location 为
/// URI-reference，非 ASCII 必须百分号编码。只编码非可见 ASCII 字节，'%'
/// 原样保留（已编码输入不二次编码）。
pub(crate) fn ascii_location_value(next: &str) -> HeaderValue {
    let mut out = String::with_capacity(next.len());
    for &b in next.as_bytes() {
        if !(0x20..0x7f).contains(&b) {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out.parse()
        .unwrap_or_else(|_| HeaderValue::from_static("/ui/"))
}

pub(crate) fn see_other_redirect(
    location: &str,
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, ascii_location_value(location));
    // 303 体恒 En：本签名无请求上下文，浏览器自动跟随从不渲染该体。
    // ponytail: 需要双语时给 see_other_redirect / see_other_error_redirect
    // 加 Lang 参数并逐点传 lang_from_headers。
    Ok((StatusCode::SEE_OTHER, headers, redirect_body(Lang::En)))
}

/// 构造带签名的 error flash Location（`?error=<urlencoded>&es=<sig>`）；
/// 渲染端校验失败退回固定文案。签名失败退化为不带 `es`——同样 fail-closed。
pub(crate) fn error_flash_location(path: &str, message: &str, csrf_key: &[u8; 32]) -> String {
    match csrf::sign_ui_error_flash(message, csrf_key) {
        Ok(sig) => format!("{}?error={}&es={}", path, urlencoding::encode(message), sig),
        Err(_) => format!("{}?error={}", path, urlencoding::encode(message)),
    }
}

/// 303 到带签名 error flash 的页面（`see_other_redirect` 的 error 变体）：
/// 业务消息走签名 `?error=` 原文透传；两个固定机器码（storage_error /
/// internal_error）例外改道 `?status=` 双语 flash——zh 页由此拿到本地化文案。
pub(crate) fn see_other_error_redirect(
    path: &str,
    message: &str,
    csrf_key: &[u8; 32],
) -> Result<(StatusCode, HeaderMap, Markup), ApiError> {
    if message == STORAGE_ERROR_STATUS || message == INTERNAL_ERROR_STATUS {
        return see_other_redirect(&format!("{path}?status={message}"));
    }
    see_other_redirect(&error_flash_location(path, message, csrf_key))
}

/// 存储错误 flash 的 `?status=` 机器码（status_message 映射 FlashStorageError）。
const STORAGE_ERROR_STATUS: &str = "storage_error";
/// 内部错误 flash 的 `?status=` 机器码（status_message 映射 FlashInternalError）。
const INTERNAL_ERROR_STATUS: &str = "internal_error";

/// 存储/DB 错误 → flash 机器码：原文含 DB 细节只留 tracing（`context` 字段），
/// 页面走 `?status=` 双语通道（见 [`see_other_error_redirect`]）。
pub(crate) fn storage_error_flash(context: &str, err: impl std::fmt::Display) -> String {
    tracing::warn!(context = %context, error = %err, "storage operation failed (flash sanitized)");
    STORAGE_ERROR_STATUS.to_string()
}

/// 非存储内部错误（口令哈希、密钥/随机数等）→ 机器码，同 storage_error 通道。
pub(crate) fn internal_error_flash(context: &str, err: impl std::fmt::Display) -> String {
    tracing::warn!(context = %context, error = %err, "internal operation failed (flash sanitized)");
    INTERNAL_ERROR_STATUS.to_string()
}

/// 渲染 Admin 首页入口卡片网格（admin-gated；GC 卡无需再按角色隐藏——
/// admin ⊃ operator 即 GC 页门槛）。`lang`：标题与描述文案。
pub(crate) fn admin_card_grid(nonce: &str, lang: Lang) -> Markup {
    html! {
        div class="admin-grid" {
            a class="admin-card" href="/ui/admin/users" {
                div class="admin-card-title" { (t(lang, TextKey::AdminUsersTitle)) }
                div class="admin-card-desc" { (t(lang, TextKey::AdminCardUsersDesc)) }
            }
            a class="admin-card" href="/ui/admin/audit" {
                div class="admin-card-title" { (t(lang, TextKey::AuditLogsTitle)) }
                div class="admin-card-desc" { (t(lang, TextKey::AdminCardAuditDesc)) }
            }
            a class="admin-card" href="/ui/workers" {
                div class="admin-card-title" { (t(lang, TextKey::NavWorkers)) }
                div class="admin-card-desc" { (t(lang, TextKey::AdminCardWorkersDesc)) }
            }
            a class="admin-card" href="/ui/admin/gc" {
                div class="admin-card-title" { (t(lang, TextKey::AdminCardGcTitle)) }
                div class="admin-card-desc" { (t(lang, TextKey::AdminCardGcDesc)) }
            }
            a class="admin-card" href="/ui/admin/settings" {
                div class="admin-card-title" { (t(lang, TextKey::SettingsTitle)) }
                div class="admin-card-desc" { (t(lang, TextKey::AdminCardSettingsDesc)) }
            }
        }
        (clickable_rows_script(nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Location 百分号编码：非 ASCII → %XX；已编码输入不二次编码。
    #[test]
    fn see_other_redirect_percent_encodes_non_ascii_location() {
        let (status, headers, _body) =
            see_other_redirect("/ui/x?q=中文").expect("redirect with non-ascii target");
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(
            headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("/ui/x?q=%E4%B8%AD%E6%96%87"),
            "non-ASCII location must be percent-encoded on the wire"
        );

        let (_, headers, _) = see_other_redirect("/ui/x?q=%E4%B8%AD%E6%96%87").unwrap();
        assert_eq!(
            headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("/ui/x?q=%E4%B8%AD%E6%96%87"),
            "already-encoded location must pass through unchanged"
        );

        let (_, headers, _) = see_other_redirect("/ui/builds?phase=failed").unwrap();
        assert_eq!(
            headers.get(header::LOCATION).and_then(|v| v.to_str().ok()),
            Some("/ui/builds?phase=failed")
        );
    }

    /// redirect_body 双语：正文 / title / `<html lang>` 随 lang 输出。
    #[test]
    fn redirect_body_follows_language() {
        let en = redirect_body(Lang::En).into_string();
        assert!(en.contains("Redirecting..."), "{en}");
        assert!(en.contains(r#"lang="en""#), "{en}");
        assert!(en.contains("<title>Redirecting... · CRBS</title>"), "{en}");

        let zh = redirect_body(Lang::Zh).into_string();
        assert!(zh.contains("正在跳转…"), "{zh}");
        assert!(zh.contains(r#"lang="zh-CN""#), "{zh}");
        assert!(zh.contains("<title>正在跳转… · CRBS</title>"), "{zh}");
        assert!(!zh.contains("Redirecting"), "{zh}");
    }

    /// load_level 阈值钉死：<70 绿 / 70–90 琥珀（含两端）/ >90 红。
    #[test]
    fn load_level_thresholds_pin_boundaries() {
        assert_eq!(load_level(69.9), "success");
        assert_eq!(load_level(70.0), "warn");
        assert_eq!(load_level(90.0), "warn");
        assert_eq!(load_level(90.1), "failure");
    }

    #[test]
    fn page_emits_confirm_script_exactly_once() {
        let m = page(
            "T",
            "nonce",
            None,
            "builds",
            &HeaderMap::new(),
            &[0u8; 32],
            html! { p { "x" } },
        );
        let s = m.into_string();
        assert!(
            s.contains("nonce=\"nonce\""),
            "script/style must carry CSP nonce"
        );
        assert_eq!(
            s.matches("btn.getAttribute('data-confirm')").count(),
            1,
            "confirm script must be emitted exactly once per page"
        );
    }

    #[test]
    fn page_derives_nav_logout_csrf_from_session_cookie() {
        let key = [7u8; 32];
        let session = "crbs_tok_abc123";
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("crbs_token={session}").parse().unwrap(),
        );
        let expected = csrf_token_for_request(&headers, &key).unwrap();

        let m = page(
            "T",
            "nonce",
            Some(&AuthContext::default()),
            "builds",
            &headers,
            &key,
            html! { p { "x" } },
        );
        let s = m.into_string();
        assert!(
            s.contains(&format!(
                r#"<input type="hidden" name="csrf_token" value="{expected}">"#
            )),
            "nav logout form must embed the derived CSRF token: {s}"
        );
        assert!(s.contains(r#"action="/ui/logout""#));

        // 无会话 cookie：偏好表单空值 csrf hidden 是仅有的 csrf_token 输入（分级 CSRF：匿名放行）。
        let m = page(
            "T",
            "nonce",
            Some(&AuthContext::default()),
            "builds",
            &HeaderMap::new(),
            &key,
            html! { p { "x" } },
        );
        let s = m.into_string();
        assert_eq!(
            s.matches(r#"<input type="hidden" name="csrf_token" value="">"#)
                .count(),
            2,
            "only the two nav preference forms carry the empty token: {s}"
        );
        assert!(!s.contains(&expected));
    }

    #[test]
    fn status_message_error_without_signature_renders_generic_text() {
        let q = StatusQuery {
            error: Some("Your account is compromised, visit evil.example".into()),
            ..Default::default()
        };
        let s = status_message(&q, &[1u8; 32], Lang::En).into_string();
        assert!(s.contains("message failure"), "{s}");
        assert!(s.contains("Operation failed."), "{s}");
        assert!(!s.contains("evil.example"), "{s}");
        let s = status_message(&q, &[1u8; 32], Lang::Zh).into_string();
        assert!(s.contains("操作失败。"), "{s}");
        assert!(!s.contains("evil.example"), "{s}");
    }

    #[test]
    fn status_message_error_with_valid_signature_renders_text() {
        let key = [1u8; 32];
        let msg = "Build 42 is not cancellable";
        let sig = crate::server::csrf::sign_ui_error_flash(msg, &key).unwrap();
        let q = StatusQuery {
            error: Some(msg.into()),
            es: Some(sig),
            ..Default::default()
        };
        let s = status_message(&q, &key, Lang::En).into_string();
        assert!(s.contains("message failure"), "{s}");
        assert!(s.contains(msg), "{s}");
    }

    #[test]
    fn status_message_error_with_mismatched_signature_renders_generic_text() {
        let key = [1u8; 32];
        let sig = crate::server::csrf::sign_ui_error_flash("original failure", &key).unwrap();
        let q = StatusQuery {
            error: Some("tampered message".into()),
            es: Some(sig),
            ..Default::default()
        };
        let s = status_message(&q, &key, Lang::En).into_string();
        assert!(s.contains("Operation failed."), "{s}");
        assert!(!s.contains("tampered message"), "{s}");
    }

    /// `?status=` flash 表全部走 TextKey（双语），代表值抽查 en/zh。
    #[test]
    fn status_message_status_values_render_bilingually() {
        let q = |status: &str| StatusQuery {
            status: Some(status.into()),
            ..Default::default()
        };
        let en = status_message(&q("gc_started"), &[1u8; 32], Lang::En).into_string();
        assert!(en.contains("Garbage collection started."), "{en}");
        let zh = status_message(&q("gc_started"), &[1u8; 32], Lang::Zh).into_string();
        assert!(zh.contains("垃圾回收已启动"), "{zh}");
        let zh = status_message(&q("cancelled"), &[1u8; 32], Lang::Zh).into_string();
        assert!(zh.contains("取消请求已接受。"), "{zh}");
    }

    /// 失败机器码走 `?status=` 渲染双语 failure 条；成功码仍 success。
    #[test]
    fn status_message_failure_codes_render_bilingual_failure_bar() {
        let q = |status: &str| StatusQuery {
            status: Some(status.into()),
            ..Default::default()
        };
        let en = status_message(&q(STORAGE_ERROR_STATUS), &[1u8; 32], Lang::En).into_string();
        assert!(en.contains("message failure"), "{en}");
        assert!(en.contains("Storage error, please retry."), "{en}");
        let zh = status_message(&q(STORAGE_ERROR_STATUS), &[1u8; 32], Lang::Zh).into_string();
        assert!(zh.contains("message failure"), "{zh}");
        assert!(zh.contains("存储错误，请重试。"), "{zh}");
        let zh = status_message(&q(INTERNAL_ERROR_STATUS), &[1u8; 32], Lang::Zh).into_string();
        assert!(zh.contains("内部错误，请重试。"), "{zh}");
        let ok = status_message(&q("gc_started"), &[1u8; 32], Lang::En).into_string();
        assert!(ok.contains("message success"), "{ok}");
    }

    /// 机器码由 *_flash 返回（日志留痕归 tracing），经 see_other_error_redirect
    /// 改道 `?status=`；业务消息走签名 `?error=`。
    #[test]
    fn error_redirect_routes_machine_codes_to_status_param() {
        let key = [1u8; 32];
        for (flash, code) in [
            (
                storage_error_flash("insert task", "db down"),
                STORAGE_ERROR_STATUS,
            ),
            (
                internal_error_flash("hash password", "oops"),
                INTERNAL_ERROR_STATUS,
            ),
        ] {
            assert_eq!(flash, code);
            let (status, headers, _) =
                see_other_error_redirect("/ui/admin/users", &flash, &key).unwrap();
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(
                headers.get(header::LOCATION).unwrap().to_str().unwrap(),
                format!("/ui/admin/users?status={code}")
            );
        }
        let (_, headers, _) =
            see_other_error_redirect("/ui/me", "token name cannot be empty", &key).unwrap();
        let loc = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        assert!(loc.starts_with("/ui/me?error=token"), "{loc}");
        assert!(loc.contains("&es="), "{loc}");
    }

    #[test]
    fn back_link_uses_whitelisted_back_and_falls_back_to_default() {
        let m = back_link(
            "Back to builds",
            "/ui/builds",
            Some("/ui/builds?phase=failed&offset=50"),
        );
        assert_eq!(
            m.into_string(),
            r#"<p><a href="/ui/builds?phase=failed&amp;offset=50">← Back to builds</a></p>"#
        );

        for back in [
            None,
            Some("https://evil.example/ui/builds"),
            Some("/api/v1/x"),
        ] {
            let m = back_link("Back to builds", "/ui/builds", back);
            assert!(
                m.into_string().contains(r#"<a href="/ui/builds">"#),
                "back={back:?}"
            );
        }
    }

    #[test]
    fn admin_card_grid_includes_gc_card() {
        let s = admin_card_grid("nonce", Lang::En).into_string();
        assert!(s.contains(r#"href="/ui/admin/gc""#), "{s}");
        assert!(s.contains("Garbage Collection"), "{s}");
        let s = admin_card_grid("nonce", Lang::Zh).into_string();
        assert!(s.contains("垃圾回收"), "{s}");
        assert!(s.contains("审计日志"), "{s}");
    }

    #[test]
    fn favicon_svg_uses_fixed_accent_scheme_for_both_themes() {
        // 禁止回退 prefers-color-scheme 双套（跟 OS 外观而非页面主题）。
        assert!(
            !FAVICON_SVG.contains("@media (prefers-color-scheme"),
            "{FAVICON_SVG}"
        );
        assert!(FAVICON_SVG.contains(r##"fill="#2563eb""##), "{FAVICON_SVG}");
        assert!(FAVICON_SVG.contains(r##"fill="#fff""##), "{FAVICON_SVG}");
        assert!(FAVICON_SVG.contains("rx=\"3\""), "{FAVICON_SVG}");
        assert!(FAVICON_SVG.contains(">C</text>"), "{FAVICON_SVG}");
        assert!(
            FAVICON_SVG.contains("text-anchor=\"middle\""),
            "{FAVICON_SVG}"
        );
    }

    #[test]
    fn error_flash_location_appends_signature_param() {
        let key = [1u8; 32];
        let sig = crate::server::csrf::sign_ui_error_flash("boom", &key).unwrap();
        let loc = error_flash_location("/ui/builds/1", "boom", &key);
        assert_eq!(loc, format!("/ui/builds/1?error=boom&es={}", sig), "{loc}");
    }
}

/// 暗色令牌双选择器一致性：style.css 暗色规则两份逐字同步——@media
/// (prefers-color-scheme: dark) 内 `:root:not([data-theme="light"])`（Auto
/// 路径）与显式 `:root[data-theme="dark"]`（手动 Dark），漂移即渲染不一致，
/// 单测强制声明集等价（比较前剥注释、归一空白）；`#log-output` 同理。
#[cfg(test)]
mod dark_theme_css {
    const CSS: &str = include_str!("../style.css");
    const DARK_MEDIA: &str = "@media (prefers-color-scheme: dark)";

    /// 去掉 /* ... */ 注释。
    fn strip_comments(css: &str) -> String {
        let mut out = String::with_capacity(css.len());
        let mut rest = css;
        while let Some(start) = rest.find("/*") {
            out.push_str(&rest[..start]);
            match rest[start..].find("*/") {
                Some(end) => rest = &rest[start + end + 2..],
                None => rest = "",
            }
        }
        out.push_str(rest);
        out
    }

    /// 空白归一：所有连续空白折叠为单个空格。
    fn norm(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// 从 `start` 起提取花括号配平的块内部内容（不含花括号）。
    fn balanced_block<'a>(css: &'a str, start: usize, what: &str) -> &'a str {
        let open = css[start..]
            .find('{')
            .map(|i| i + start)
            .unwrap_or_else(|| panic!("{what}: block missing"));
        let mut depth = 0usize;
        for (i, c) in css[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &css[open + 1..open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("{what}: unbalanced block");
    }

    /// `marker` 第 `nth`（0 起）次出现处的配平块内部内容。
    fn nth_media_block<'a>(css: &'a str, marker: &str, nth: usize) -> &'a str {
        let start = css
            .match_indices(marker)
            .nth(nth)
            .map(|(i, _)| i)
            .unwrap_or_else(|| panic!("{marker} occurrence #{nth} missing"));
        balanced_block(css, start, marker)
    }

    /// scope 内首个 `selector` 的配平块内部内容。
    fn inner_block<'a>(scope: &'a str, selector: &str) -> &'a str {
        let start = scope
            .find(selector)
            .unwrap_or_else(|| panic!("selector missing: {selector}"));
        balanced_block(scope, start, selector)
    }

    #[test]
    fn dark_token_blocks_stay_identical() {
        let css = strip_comments(CSS);

        let media_scope = nth_media_block(&css, DARK_MEDIA, 0);
        let auto_dark = inner_block(media_scope, ":root:not([data-theme=\"light\"])");
        let manual_dark = inner_block(&css, ":root[data-theme=\"dark\"]");
        assert_eq!(
            norm(auto_dark),
            norm(manual_dark),
            "dark token copies drifted: keep the @media (:not guard) block and \
             the :root[data-theme=\"dark\"] block byte-identical (comments and \
             whitespace aside)"
        );

        // #log-output 深色规则（第二个 dark 媒体查询块）。
        let log_scope = nth_media_block(&css, DARK_MEDIA, 1);
        let auto_log = inner_block(log_scope, "#log-output");
        let manual_log = inner_block(&css, ":root[data-theme=\"dark\"] #log-output");
        assert_eq!(
            norm(auto_log),
            norm(manual_log),
            "#log-output dark copies drifted: sync the media-query copy and the \
             explicit :root[data-theme=\"dark\"] copy"
        );
    }
}
