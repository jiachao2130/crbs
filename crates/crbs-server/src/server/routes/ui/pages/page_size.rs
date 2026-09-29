// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of this Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 每页条数偏好：`crbs_page_size` cookie 记住 50/100/200，优先级 `?limit=` query >
//! cookie > 默认 50；size 不进 URL（分页/过滤链接字节级不变），本模块只管 cookie 读写。

use crate::server::error::ApiError;
use crate::server::state::AppState;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use std::sync::Arc;

/// 每页条数可选项：切换药丸、cookie 白名单与 handler 校验共用。
pub(crate) const PAGE_SIZE_CHOICES: &[usize] = &[50, 100, 200];

pub(crate) const PAGE_SIZE_COOKIE: &str = "crbs_page_size";

/// 从请求头解析 `crbs_page_size`：白名单（50/100/200）外一律 `None` 静默回落
/// 默认值；走共享 [`crate::server::csrf::cookie_value_from_headers`]（首个匹配生效）。
pub(crate) fn page_size_from_headers(headers: &HeaderMap) -> Option<usize> {
    crate::server::csrf::cookie_value_from_headers(headers, PAGE_SIZE_COOKIE)?
        .parse::<usize>()
        .ok()
        .filter(|v| PAGE_SIZE_CHOICES.contains(v))
}

/// 列表页 limit/offset 解析（admin 用户/审计、workers 三页共用）：limit 优先级
/// `?limit=` query > `crbs_page_size` cookie > 默认 50，query 路径 clamp(1,1000)；
/// offset clamp(0, MAX_LIST_OFFSET)（usize 上限，查询参数是 i64）。与
/// [`super::super::service::UI_PAGE_SIZE_MAX`] 的 200 上限是两个口径，勿并。
pub(crate) fn list_limit_offset(q_limit: i64, q_offset: i64, headers: &HeaderMap) -> (i64, i64) {
    let limit = if q_limit <= 0 {
        page_size_from_headers(headers)
            .map(|v| v as i64)
            .unwrap_or(super::super::service::UI_PAGE_SIZE as i64)
    } else {
        q_limit.clamp(1, 1000)
    };
    let offset = q_offset.clamp(0, crate::server::validation::MAX_LIST_OFFSET as i64);
    (limit, offset)
}

#[derive(serde::Deserialize)]
pub(crate) struct SetPageSizeForm {
    size: Option<String>,
    csrf_token: Option<String>,
}

/// `POST /ui/set-page-size`（表单字段 `size=50|100|200`）：Set-Cookie + 303 回跳。
/// 公开段 + 分级 CSRF，Referer 仅采纳 `/ui/` 前缀站内路径；非法值只回跳、
/// 不写 cookie，用户偏好不被坏链接改写。
pub(crate) async fn set_page_size(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SetPageSizeForm>,
) -> Result<impl IntoResponse, ApiError> {
    super::theme::require_preference_csrf(&headers, form.csrf_token.as_deref(), &app.csrf_key)?;
    let size = form
        .size
        .as_deref()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|v| PAGE_SIZE_CHOICES.contains(v))
        .map(|s| s.to_string());
    super::theme::preference_see_other(
        &app,
        headers.get(header::REFERER),
        size.as_deref().map(|s| (PAGE_SIZE_COOKIE, s)),
        crate::server::routes::ui::i18n::lang_from_headers(&headers),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[test]
    fn page_size_from_headers_whitelists_choices() {
        for size in PAGE_SIZE_CHOICES {
            assert_eq!(
                page_size_from_headers(&headers_with(&format!("{PAGE_SIZE_COOKIE}={size}"))),
                Some(*size)
            );
        }
        assert_eq!(
            page_size_from_headers(&headers_with("crbs_token=abc; crbs_page_size=100")),
            Some(100)
        );
        assert_eq!(
            page_size_from_headers(&headers_with("crbs_page_size=200; crbs_token=abc")),
            Some(200)
        );
    }

    #[test]
    fn page_size_from_headers_rejects_out_of_whitelist_and_garbage() {
        for bad in [
            "crbs_page_size=30",
            "crbs_page_size=500",
            "crbs_page_size=0",
            "crbs_page_size=abc",
            "crbs_page_size=50.0",
        ] {
            assert_eq!(
                page_size_from_headers(&headers_with(bad)),
                None,
                "must reject {bad:?}"
            );
        }
        assert_eq!(
            page_size_from_headers(&headers_with("crbs_token=abc")),
            None
        );
        assert_eq!(page_size_from_headers(&HeaderMap::new()), None);
    }
}
