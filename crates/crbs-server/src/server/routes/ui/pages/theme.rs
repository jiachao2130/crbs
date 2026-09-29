// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 手动主题切换：三态 Auto/Light/Dark，服务端 cookie，无 JS。
//!
//! 状态存 `crbs_theme` cookie（白名单外按 auto），渲染端在 `<html>` 输出
//! `data-theme` 驱动 style.css 暗色令牌；Auto 不输出，走 prefers-color-scheme。

use super::cookie_secure_suffix;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::ascii_location_value;
use crate::server::routes::ui::components::redirect_body;
use crate::server::routes::ui::i18n::{lang_from_headers, Lang};
use crate::server::routes::ui::service::require_csrf;
use crate::server::state::AppState;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use std::sync::Arc;

/// 主题三态。Auto = 跟随系统（不输出 data-theme 属性）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Theme {
    Auto,
    Light,
    Dark,
}

impl Theme {
    /// cookie / query 白名单解析：非 light/dark（缺失/非法）一律静默回落 Auto。
    pub(crate) fn from_value(v: Option<&str>) -> Theme {
        match v {
            Some("light") => Theme::Light,
            Some("dark") => Theme::Dark,
            _ => Theme::Auto,
        }
    }

    /// 写入 `crbs_theme` cookie 的值。
    pub(crate) fn cookie_value(self) -> &'static str {
        match self {
            Theme::Auto => "auto",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    /// `<html data-theme="...">` 属性值；Auto 返回 None（不输出属性）。
    pub(crate) fn data_theme_attr(self) -> Option<&'static str> {
        match self {
            Theme::Auto => None,
            Theme::Light => Some("light"),
            Theme::Dark => Some("dark"),
        }
    }

    /// 单按钮的下一态（点击循环）：auto → light → dark → auto。
    pub(crate) fn next(self) -> Theme {
        match self {
            Theme::Auto => Theme::Light,
            Theme::Light => Theme::Dark,
            Theme::Dark => Theme::Auto,
        }
    }

    /// 单按钮字形：◐ 自动 / ☀ 浅色 / ☾ 深色（Unicode，系统字体稳定渲染）。
    pub(crate) fn icon(self) -> &'static str {
        match self {
            Theme::Auto => "◐",
            Theme::Light => "☀",
            Theme::Dark => "☾",
        }
    }
}

/// 从 Cookie 解析 `crbs_theme`（共享 [`crate::server::csrf::cookie_value_from_headers`]；缺失/非法 → Auto）。
pub(crate) fn theme_from_headers(headers: &HeaderMap) -> Theme {
    Theme::from_value(
        crate::server::csrf::cookie_value_from_headers(headers, "crbs_theme").as_deref(),
    )
}

/// 偏好 cookie 共享有效期：一年（theme/lang/page_size 长寿命偏好，非会话凭证不轮换）。
pub(crate) const PREFERENCE_COOKIE_MAX_AGE_SECS: i64 = 31_536_000;

/// 从 Referer 头推导回跳目标（path+query）：仅采纳站内 UI 路径——`/ui/` 开头
/// 且不以 `//` 开头（协议相对 `//host` 对浏览器是跨源跳转，防 open redirect；
/// 双重检查防未来前缀放宽）。缺失、无路径、站外一律回 `/ui/`。手动解析不引
/// url crate；set-lang（i18n/ 目录）复用同一白名单。
pub(crate) fn redirect_target_from_referer(referer: Option<&axum::http::HeaderValue>) -> String {
    const FALLBACK: &str = "/ui/";
    let Some(raw) = referer.and_then(|v| v.to_str().ok()) else {
        return FALLBACK.to_string();
    };
    let after_scheme = match raw.find("://") {
        Some(i) => &raw[i + 3..],
        None => raw,
    };
    let Some(path_at) = after_scheme.find('/') else {
        return FALLBACK.to_string();
    };
    let path_query = &after_scheme[path_at..];
    // 去 fragment（Referer 规范上不含，防御性截断）。
    let end = path_query.find('#').unwrap_or(path_query.len());
    let path_query = &path_query[..end];
    if path_query.starts_with("/ui/") && !path_query.starts_with("//") {
        path_query.to_string()
    } else {
        FALLBACK.to_string()
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct SetThemeForm {
    theme: Option<String>,
    csrf_token: Option<String>,
}

/// 偏好端点（set-theme / set-lang / set-page-size 共用）的分级 CSRF：无会话
/// 凭据（无 csrf base）直接放行——偏好只写调用者自己的 cookie、无越权面，
/// nav 单按钮在 login 页也必须可用；有凭据走 [`require_csrf`] 全量校验。
pub(crate) fn require_preference_csrf(
    headers: &HeaderMap,
    provided_token: Option<&str>,
    csrf_key: &[u8; 32],
) -> Result<(), ApiError> {
    if crate::server::csrf::csrf_base_from_headers(headers).is_none() {
        return Ok(());
    }
    require_csrf(headers, provided_token.unwrap_or(""), csrf_key).map(|_| ())
}

/// 偏好 cookie 303 切换的共享收尾（set-theme / set-lang / set-page-size）：
/// Referer 白名单回跳 + 可选 Set-Cookie + 303。`cookie` Some 时写固定格式
/// cookie（集成测试钉住）；None 不写 Set-Cookie——set-page-size"非法值不入库"，
/// theme/lang 非法值回落默认后仍传 Some；`lang` 定 303 体文案与 `<html lang>`。
pub(crate) fn preference_see_other(
    app: &AppState,
    referer: Option<&axum::http::HeaderValue>,
    cookie: Option<(&str, &str)>,
    lang: Lang,
) -> Result<(StatusCode, HeaderMap, maud::Markup), ApiError> {
    let target = redirect_target_from_referer(referer);
    let mut resp_headers = HeaderMap::new();
    if let Some((name, value)) = cookie {
        let cookie = format!(
            "{name}={value}; Path=/; Max-Age={PREFERENCE_COOKIE_MAX_AGE_SECS}; SameSite=Lax; HttpOnly{}",
            cookie_secure_suffix(app),
        );
        resp_headers.insert(
            header::SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| ApiError::Internal("failed to build Set-Cookie header".into()))?,
        );
    }
    // Location 统一经 ascii_location_value：非 ASCII query 百分号编码后才上 wire。
    resp_headers.insert(header::LOCATION, ascii_location_value(&target));

    Ok((StatusCode::SEE_OTHER, resp_headers, redirect_body(lang)))
}

/// 偏好端点 HEAD 短路：204 无副作用（不写 cookie、不产出回跳 Location）。axum
/// 对 GET 路由自动派生 HEAD（回落执行 GET handler，副作用原样发生），显式
/// `.head()` 注册优先于回落——健康探测/预取拿零成本 204。
pub(crate) async fn preference_head() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// `POST /ui/set-theme`（表单字段 `theme=light|dark|auto`）：Set-Cookie + 303 回跳。
/// 仅 POST：写语义端点不接受状态变更 GET（prefetch 误触发、代理缓存副作用）；
/// 注册在公开段（登录前也能切主题），CSRF 走 [`require_preference_csrf`] 分级校验。
pub(crate) async fn set_theme(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SetThemeForm>,
) -> Result<impl IntoResponse, ApiError> {
    require_preference_csrf(&headers, form.csrf_token.as_deref(), &app.csrf_key)?;
    let theme = Theme::from_value(form.theme.as_deref());
    preference_see_other(
        &app,
        headers.get(header::REFERER),
        Some(("crbs_theme", theme.cookie_value())),
        lang_from_headers(&headers),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_from_value_whitelists_and_falls_back_to_auto() {
        assert_eq!(Theme::from_value(Some("light")), Theme::Light);
        assert_eq!(Theme::from_value(Some("dark")), Theme::Dark);
        assert_eq!(Theme::from_value(Some("auto")), Theme::Auto);
        assert_eq!(Theme::from_value(None), Theme::Auto);
        assert_eq!(Theme::from_value(Some("hack")), Theme::Auto);
        assert_eq!(Theme::from_value(Some("DARK")), Theme::Auto);
        assert_eq!(Theme::from_value(Some(" dark ")), Theme::Auto);
    }

    #[test]
    fn theme_from_headers_extracts_crbs_theme() {
        let headers = |cookie: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, cookie.parse().unwrap());
            h
        };
        assert_eq!(theme_from_headers(&headers("crbs_theme=dark")), Theme::Dark);
        assert_eq!(
            theme_from_headers(&headers("crbs_theme=light")),
            Theme::Light
        );
        // 与其它 cookie 并存 / 多 cookie 边界：首个 crbs_theme 生效。
        assert_eq!(
            theme_from_headers(&headers("crbs_token=abc; crbs_theme=dark")),
            Theme::Dark
        );
        assert_eq!(
            theme_from_headers(&headers("crbs_theme=dark; crbs_token=abc")),
            Theme::Dark
        );
        assert_eq!(theme_from_headers(&headers("crbs_theme=hack")), Theme::Auto);
        assert_eq!(theme_from_headers(&headers("crbs_token=abc")), Theme::Auto);
        assert_eq!(theme_from_headers(&HeaderMap::new()), Theme::Auto);
    }

    #[test]
    fn theme_next_cycles_and_icon_is_stable_per_state() {
        assert_eq!(Theme::Auto.next(), Theme::Light);
        assert_eq!(Theme::Light.next(), Theme::Dark);
        assert_eq!(Theme::Dark.next(), Theme::Auto);
        // 三态字形两两不同（按钮视觉区分的唯一通道，无文字标签）。
        let icons = [Theme::Auto.icon(), Theme::Light.icon(), Theme::Dark.icon()];
        assert_eq!(icons, ["◐", "☀", "☾"]);
    }

    #[test]
    fn redirect_target_accepts_only_ui_paths() {
        let target_for = |referer: Option<&str>| -> String {
            let hv = referer.and_then(|s| s.parse().ok());
            redirect_target_from_referer(hv.as_ref())
        };
        assert_eq!(
            target_for(Some("http://crbs.local/ui/builds?phase=failed")),
            "/ui/builds?phase=failed"
        );
        assert_eq!(target_for(Some("https://crbs.local/ui/")), "/ui/");
        assert_eq!(target_for(Some("https://evil.com/evil")), "/ui/");
        assert_eq!(target_for(Some("//evil.com/x")), "/ui/");
        assert_eq!(target_for(Some("https://evil.com")), "/ui/");
        assert_eq!(
            target_for(Some("https://crbs.local/ui/builds#frag")),
            "/ui/builds"
        );
        assert_eq!(target_for(Some("https://crbs.local/api/v1/health")), "/ui/");
        assert_eq!(target_for(None), "/ui/");
    }

    /// Location 须纯 ASCII：浏览器已编码的 query 经 ascii_location_value 原样透传（不二次编码）。
    #[tokio::test]
    async fn preference_see_other_location_is_ascii_encoded() {
        let tmp = tempfile::tempdir().unwrap();
        let store = std::sync::Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        );

        // 浏览器形态：中文 query 已编码（HeaderValue to_str 拒绝非 ASCII，解析只接受该形态）。
        let referer = "http://crbs.local/ui/search?q=%E4%B8%AD%E6%96%87"
            .parse()
            .unwrap();
        let (status, headers, _body) =
            preference_see_other(&app, Some(&referer), Some(("crbs_theme", "dark")), Lang::En)
                .expect("preference redirect");
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("location header");
        assert_eq!(
            location, "/ui/search?q=%E4%B8%AD%E6%96%87",
            "encoded referer query must pass through unchanged (no double encoding)"
        );
        assert!(
            location.is_ascii(),
            "Location must be ASCII-only on the wire"
        );
    }
}
