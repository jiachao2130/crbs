// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 分页链接组件与列表页通用查询参数（PaginationParams / StatusQuery）。

use maud::{html, Markup};

use crate::server::routes::ui::i18n::{t, t_fmt, FmtKey, Lang, TextKey};
use crate::server::routes::ui::pages::page_size::PAGE_SIZE_CHOICES;
use crate::server::routes::ui::service::{current_list_url, QueryParams};

/// 分页链接组件参数。
#[derive(Debug, Clone)]
pub(crate) struct PaginationParams<'a> {
    pub base_path: &'a str,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    /// 渲染语言：区间文案 "1-50 of 56" / "第 1-50 条，共 56 条"。
    pub lang: Lang,
    /// 结构化过滤参数（QueryParams 型列表页：builds/tasks/packages）。
    pub query: QueryParams<'a>,
    /// 裸过滤器查询串（filter_qs 型列表页：workers/users/audit/products，
    /// key 不在 QueryParams 里）。`Some` 时替代 `query` 序列化拼 URL。
    pub raw_filter_qs: Option<&'a str>,
    /// 每页条数 POST 表单的 CSRF token（有会话时校验）；匿名传 None（hidden 落空串放行）。
    pub csrf_token: Option<&'a str>,
}

/// 分页链接组件（全列表页共用）。URL 两条路径：`query`（offset>0 才追加）
/// 或 `raw_filter_qs`（已编码 `k=v&k=v` 串 + offset），后者覆盖前者；区间
/// 双向收敛到 total，越界（手工改 URL）渲染 "50-50 of 50" 不倒挂。药丸：
/// 50/100/200 POST 到 `/ui/set-page-size`（Set-Cookie + 303 回当前页，无
/// JS）；生效 `limit`（query > cookie）加 `.active`、非档位值无高亮；size
/// 不进分页 URL，链接字节不变。
pub(crate) fn pagination_links(params: &PaginationParams<'_>) -> Markup {
    if params.total == 0 {
        return html! {};
    }
    let prev_offset = params.offset.saturating_sub(params.limit);
    let next_offset = params.offset + params.limit;
    let has_prev = params.offset > 0;
    let has_next = next_offset < params.total;
    let current_start = (params.offset + 1).min(params.total);
    let current_end = (params.offset + params.limit).min(params.total);
    let make_url = |off: usize| -> String {
        match params.raw_filter_qs {
            // 与 QueryParams::url 同口径：offset=0 不带参，链接字节不变。
            Some(filter_qs) => current_list_url(params.base_path, filter_qs, off),
            None => params.query.url(params.base_path, Some(off)),
        }
    };
    html! {
        div class="table-foot" {
            @if has_prev {
                a href=(make_url(prev_offset)) { "← " (t(params.lang, TextKey::PaginationPrev)) }
            } @else {
                span class="disabled" { "← " (t(params.lang, TextKey::PaginationPrev)) }
            }
            span class="pagination-info" {
                (t_fmt(
                    params.lang,
                    FmtKey::PaginationInfo,
                    &[
                        &current_start.to_string(),
                        &current_end.to_string(),
                        &params.total.to_string(),
                    ],
                ))
            }
            // 药丸（title 提供可访问名称）；csrf_token 分级校验见 set-page-size（匿名空串放行）。
            span class="page-size-picker" title=(t(params.lang, TextKey::PageSizeTitle)) {
                @for size in PAGE_SIZE_CHOICES {
                    form method="post" action="/ui/set-page-size" class="page-size-form" {
                        input type="hidden" name="size" value=(size);
                        input type="hidden" name="csrf_token" value=(params.csrf_token.unwrap_or(""));
                        button type="submit" class=(format!(
                            "pill{}",
                            if *size == params.limit { " active" } else { "" }
                        )) { (size) }
                    }
                }
            }
            @if has_next {
                a href=(make_url(next_offset)) { (t(params.lang, TextKey::PaginationNext)) " →" }
            } @else {
                span class="disabled" { (t(params.lang, TextKey::PaginationNext)) " →" }
            }
        }
    }
}

#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct StatusQuery {
    pub status: Option<String>,
    pub error: Option<String>,
    /// `error` 的 HMAC 签名（hex），由重定向生成方经 sign_ui_error_flash 附加。
    pub es: Option<String>,
    /// 详情页返回目标（`?back=`，列表页 path+query）：经 safe_back_path 校验后作 "← Back" 目标。
    pub back: Option<String>,
    /// Worker 详情页遥测趋势档位（`?range=1h|24h|7d`）；其余页面不消费该字段。
    pub range: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_links_clamps_range_when_offset_exceeds_total() {
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/builds",
            total: 50,
            limit: 50,
            offset: 1_000_000,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: None,
            csrf_token: Some("tok"),
        });
        let s = m.into_string();
        assert!(s.contains("50-50 of 50"), "{s}");
        assert!(!s.contains("1000001"), "{s}");
        // 正常页不受影响（分页形状另由 integration "1-50 of 56"/"51-56 of 56" 钉住）。
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/builds",
            total: 56,
            limit: 50,
            offset: 0,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: None,
            csrf_token: Some("tok"),
        });
        assert!(m.into_string().contains("1-50 of 56"));
    }

    /// filter_qs 型 URL 逐字节钉住：过滤器串原样保留、offset=0 不追加、offset>0 以 & 拼接。
    #[test]
    fn pagination_links_raw_filter_qs_urls_are_byte_stable() {
        // 第 2 页：prev 回 offset=0（不带参），next 到 100。
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/workers",
            total: 120,
            limit: 50,
            offset: 50,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: Some("name=w1&status=online"),
            csrf_token: None,
        });
        let s = m.into_string();
        assert!(
            s.contains(r#"href="/ui/workers?name=w1&amp;status=online""#),
            "prev link (offset=0) must omit the offset param: {s}"
        );
        assert!(
            s.contains(r#"href="/ui/workers?name=w1&amp;status=online&amp;offset=100""#),
            "next link must append offset=100: {s}"
        );
        assert!(s.contains("51-100 of 120"), "{s}");

        // 第 1 页：prev 禁用、next offset=50；空过滤器首页即裸路径。
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/workers",
            total: 120,
            limit: 50,
            offset: 0,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: Some(""),
            csrf_token: None,
        });
        let s = m.into_string();
        assert!(
            s.contains(r#"<span class="disabled">← Previous</span>"#),
            "{s}"
        );
        assert!(s.contains(r#"href="/ui/workers?offset=50""#), "{s}");

        // 越界区间收敛（raw_filter_qs 变体）。
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/admin/users",
            total: 50,
            limit: 50,
            offset: 1_000_000,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: Some(""),
            csrf_token: None,
        });
        let s = m.into_string();
        assert!(s.contains("50-50 of 50"), "{s}");
        assert!(!s.contains("1000001"), "{s}");
    }

    /// QueryParams 型分页 URL 回归：结构化参数序列化不受 raw_filter_qs 分支影响。
    #[test]
    fn pagination_links_query_params_urls_preserve_filters() {
        let m = pagination_links(&PaginationParams {
            base_path: "/ui/builds",
            total: 56,
            limit: 50,
            offset: 0,
            lang: Lang::En,
            query: QueryParams {
                product: Some("mydist"),
                phase: Some("failed"),
                ..Default::default()
            },
            raw_filter_qs: None,
            csrf_token: Some("tok"),
        });
        let s = m.into_string();
        assert!(
            s.contains(r#"href="/ui/builds?product=mydist&amp;phase=failed&amp;offset=50""#),
            "{s}"
        );
    }

    /// 药丸：三档位 POST 表单，生效 limit 加 .active；size 纯 cookie 承载；
    /// total=0 整个分页区（含药丸）省略。
    #[test]
    fn pagination_links_render_size_picker_with_active_state() {
        let render = |limit: usize| {
            pagination_links(&PaginationParams {
                base_path: "/ui/builds",
                total: 230,
                limit,
                offset: 0,
                lang: Lang::En,
                query: QueryParams::default(),
                raw_filter_qs: None,
                csrf_token: None,
            })
            .into_string()
        };
        let s = render(50);
        assert!(
            s.contains(r#"<span class="page-size-picker" title="Rows per page">"#),
            "{s}"
        );
        assert!(
            s.contains(
                r#"<form method="post" action="/ui/set-page-size" class="page-size-form">"#,
            ),
            "{s}"
        );
        assert!(
            s.contains(
                r#"<input type="hidden" name="csrf_token" value=""><button type="submit" class="pill active">50</button>"#
            ),
            "{s}"
        );
        assert!(
            s.contains(r#"<button type="submit" class="pill">100</button>"#),
            "{s}"
        );
        assert!(
            s.contains(r#"<button type="submit" class="pill">200</button>"#),
            "{s}"
        );
        assert!(
            s.contains(r#"href="/ui/builds?offset=50""#),
            "next link must stay byte-stable: {s}"
        );
        assert!(!s.contains("limit="), "{s}");

        // cookie 生效档位 100：active 落 100。
        let s = render(100);
        assert!(
            s.contains(r#"<button type="submit" class="pill">50</button>"#),
            "{s}"
        );
        assert!(
            s.contains(r#"<button type="submit" class="pill active">100</button>"#),
            "{s}"
        );

        // 手工 ?limit= 非档位值：无高亮项。
        let s = render(30);
        assert_eq!(s.matches(r#"class="pill active""#).count(), 0, "{s}");
        assert!(
            s.contains(r#"<form method="post" action="/ui/set-page-size""#),
            "{s}"
        );

        // 空列表：分页区整体不渲染（含药丸）。
        let s = render(50);
        let empty = pagination_links(&PaginationParams {
            base_path: "/ui/builds",
            total: 0,
            limit: 50,
            offset: 0,
            lang: Lang::En,
            query: QueryParams::default(),
            raw_filter_qs: None,
            csrf_token: None,
        })
        .into_string();
        assert!(empty.is_empty(), "{empty}");
        assert!(!s.is_empty());
    }
}
