// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 页面 handler。

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::ui::components::phase_modifier;
use crate::server::routes::ui::i18n::{t_fmt, t_phase, FmtKey, Lang};
use crate::server::state::AppState;
use chrono::Utc;
use maud::{html, Markup};

pub(crate) mod admin;
pub(crate) mod auth;
pub(crate) mod batches;
pub(crate) mod builds;
pub(crate) mod changelog;
pub(crate) mod gc;
pub(crate) mod home;
pub(crate) mod me;
pub(crate) mod packages;
pub(crate) mod page_size;
pub(crate) mod product_editor;
pub(crate) mod product_profiles;
pub(crate) mod products;
pub(crate) mod register;
pub(crate) mod reproducibility;
pub(crate) mod search;
pub(crate) mod settings;
pub(crate) mod task_new;
pub(crate) mod tasks;
pub(crate) mod theme;
pub(crate) mod workers;

/// 页面门槛：operator/admin（与 API `ensure_operator` 同谓词）；匿名一律 401
///（运维观测面不进公开访问），权限不足 403。
pub(crate) fn require_operator_page(auth: Option<&AuthContext>) -> Result<&AuthContext, ApiError> {
    let ctx =
        auth.ok_or_else(|| ApiError::Unauthorized("operator authentication required".into()))?;
    if !ctx.is_operator() {
        return Err(ApiError::PermissionDenied(
            "only operator and admin can access this page".into(),
        ));
    }
    Ok(ctx)
}

/// 页面门槛：admin；匿名 401，权限不足 403。
pub(crate) fn require_admin_page(auth: Option<&AuthContext>) -> Result<&AuthContext, ApiError> {
    let ctx = auth.ok_or_else(|| ApiError::Unauthorized("admin authentication required".into()))?;
    if !ctx.is_admin() {
        return Err(ApiError::PermissionDenied(
            "only admin can access this page".into(),
        ));
    }
    Ok(ctx)
}

/// 返回 cookie 属性是否附加 `Secure`：内置 TLS 启用，或 `force_secure_cookies`
/// （反代终止 TLS、crbs-server 走 loopback HTTP 的拓扑）时附加。
pub(crate) fn cookie_secure_suffix(app: &AppState) -> &'static str {
    cookie_secure_suffix_for(&app.server_config)
}

fn cookie_secure_suffix_for(cfg: &crbs_core::config::ServerConfig) -> &'static str {
    if cfg.tls.is_some() || cfg.force_secure_cookies {
        "; Secure"
    } else {
        ""
    }
}

/// 子构建 count-badge 固定展示序：排队在前、终态在后；表外 phase 排最后、按字母序。
const COUNT_BADGE_PHASE_ORDER: [&str; 7] = [
    "pending",
    "assigned",
    "building",
    "succeeded",
    "failed",
    "timeout",
    "cancelled",
];

/// 渲染 Task 下各 phase 子构建数量 badge 列表：链接到 `/ui/builds` 按 phase
/// 下钻，着色见 [`phase_modifier`]，显示名经 [`t_phase`]。
fn child_build_counts(
    task_id: i64,
    counts: &std::collections::HashMap<String, i64>,
    lang: Lang,
) -> Markup {
    if counts.is_empty() {
        return html! { "—" };
    }
    let phase_rank = |phase: &str| {
        COUNT_BADGE_PHASE_ORDER
            .iter()
            .position(|p| *p == phase)
            .unwrap_or(COUNT_BADGE_PHASE_ORDER.len())
    };
    let mut items: Vec<(&String, &i64)> = counts.iter().collect();
    items.sort_by(|a, b| {
        phase_rank(a.0)
            .cmp(&phase_rank(b.0))
            .then_with(|| a.0.cmp(b.0))
    });
    html! {
        @for (phase, count) in items {
            a href=(format!("/ui/builds?task_id={}&phase={}", task_id, phase)) {
                span class=(format!("count-badge {}", phase_modifier(phase)).trim_end()) {
                    (t_phase(lang, phase)) ": " (count)
                }
            }
        }
    }
}

/// 渲染 Package 名链接；若 name 为空（无法解析的 NVR）则只显示文本。
fn package_link(pkg_name: &str, name: &str) -> Markup {
    if name.is_empty() {
        html! { (pkg_name) }
    } else {
        html! { a href=(format!("/ui/packages/{}", urlencoding::encode(name))) { (pkg_name) } }
    }
}

fn default_acl_role() -> String {
    "viewer".to_string()
}

/// 相对时间截断阈值（天）：超过即改显本地绝对日期；SSR 与 worker SSE 脚本
/// （JS `REL_ABS_DAYS` 注入）共用，防两侧漂移。
pub(crate) const REL_TIME_ABSOLUTE_DAYS: i64 = 30;

// 空值标记约定：数据层与 CLI 用 ASCII "-"，UI 渲染层统一渲染 "—"。

/// 详情侧绝对时间列空值口径（与 [`rel_time_lang`] 同口径）：`None` / 空串 /
/// `"-"`（DB 老行占位）→ "—"，其余本地化绝对时间。
pub(crate) fn abs_time_or_dash(dt: Option<&str>) -> String {
    dt.filter(|s| !s.is_empty() && *s != "-")
        .map(crbs_core::util::format_local_time)
        .unwrap_or_else(|| "—".to_string())
}

/// 列表页时间列统一相对时间渲染：`<span title="绝对时间">相对时间</span>`。
/// `None` / 空串 / `"-"` → "—"；s/min/h/d 四档阈值（单位词经 [`t_fmt`] 本地化），>30 天
/// 改显本地绝对日期 `YYYY-MM-DD`（不本地化）；非 DB 格式（如 RFC3339）
/// 解析失败 → 原样透传、不包 span；详情页保留绝对时间（审计需精确），勿用于详情列。
pub(crate) fn rel_time_lang(dt: Option<&str>, lang: Lang) -> Markup {
    match dt.filter(|s| !s.is_empty() && *s != "-") {
        None => html! { "—" },
        // 解析失败 → 原样透传，不包 span。
        Some(s) if crbs_core::util::parse_db_time(s).is_none() => {
            html! { (s) }
        }
        Some(s) => html! {
            span title=(crbs_core::util::format_local_time(s)) {
                (rel_time_text_lang(dt, lang))
            }
        },
    }
}

/// [`rel_time_lang`] 的纯文本版：同阈值/同截断/同降级，仅去掉外层
/// span/title 包装——供只收 String 的组件（产品总览带的 Last build 值）复用。
pub(crate) fn rel_time_text_lang(dt: Option<&str>, lang: Lang) -> String {
    let Some(s) = dt.filter(|s| !s.is_empty() && *s != "-") else {
        return "—".to_string();
    };
    let Some(naive) = crbs_core::util::parse_db_time(s) else {
        return s.to_string();
    };
    // 时钟轻微超前（负差值）按 0 处理，避免渲染出 "-3s ago"。
    let secs = (Utc::now() - naive.and_utc()).num_seconds().max(0);
    if secs > REL_TIME_ABSOLUTE_DAYS * 86400 {
        naive
            .and_utc()
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d")
            .to_string()
    } else {
        // 单位词走 i18n 双语表；阈值单源在此判定，[`rel_time_lang`] 委托本
        // 函数渲染、无阈值副本，改阈值只需改此处。
        let (key, n) = if secs < 60 {
            (FmtKey::RelSecs, secs)
        } else if secs < 3600 {
            (FmtKey::RelMins, secs / 60)
        } else if secs < 86400 {
            (FmtKey::RelHours, secs / 3600)
        } else {
            (FmtKey::RelDays, secs / 86400)
        };
        t_fmt(lang, key, &[&n.to_string()])
    }
}

/// 秒数 → 人类可读时长：最高两个单位（"3m 42s" / "1d 3h"），第二单位为零
/// 也显示（"2h 0m"）；不足一分钟 "42s"；负值按 0。task 详情与首页 Uptime 共用。
pub(crate) fn format_duration_secs(secs: i64) -> String {
    let s = secs.max(0);
    let (d, h, m, sec) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

/// 成功率 gauge 窗口（/ui/me 个人带与产品详情带共用）：最近 N 条任务，与 home 仪表盘同口径。
pub(crate) const SUCCESS_RATE_WINDOW: i64 = 200;

/// 构建时长条形图样本数：最近 N 个 succeeded 构建，每 arch 一条。
pub(crate) const BUILD_DURATION_BARS: i64 = 15;

/// 相位序列 → gauge 口径计数表（窗口内每 phase 计一次出现）。
pub(crate) fn phase_counts_from_series(
    series: &[String],
) -> std::collections::HashMap<String, i64> {
    let mut counts = std::collections::HashMap::new();
    for phase in series {
        *counts.entry(phase.clone()).or_insert(0) += 1;
    }
    counts
}

/// phase 计数表取值：DB 只为窗口内出现过的 phase 建键，缺失按 0。
pub(crate) fn phase_count(m: &std::collections::HashMap<String, i64>, phase: &str) -> i64 {
    m.get(phase).copied().unwrap_or(0)
}

/// 成功率 gauge 公共构造：窗口 phase 计数 → (成功率, 右侧口径说明)。有样本
/// → `Some(0-100)`（全失败为 `Some(0)`，不与无样本的 `None`/"—" 占位混淆）；
/// 无样本 → `None`。side 的 `<b>` 数字为服务端算出的整数（无用户输入），
/// 经 PreEscaped 输出简单标记是安全的。
pub(crate) fn success_rate_gauge(
    recent_counts: &std::collections::HashMap<String, i64>,
    lang: Lang,
) -> (Option<u32>, Markup) {
    let window_total: i64 = recent_counts.values().sum();
    let window_succeeded = phase_count(recent_counts, "succeeded");
    let pct = if window_total > 0 {
        Some((window_succeeded as f64 * 100.0 / window_total as f64).round() as u32)
    } else {
        None
    };
    let succeeded_b = format!("<b>{window_succeeded}</b>");
    let total_b = format!("<b>{window_total}</b>");
    let side = html! {
        div class="k" {
            (maud::PreEscaped(t_fmt(lang, FmtKey::RecentSucceeded, &[&succeeded_b, &total_b])))
        }
        div class="k faint" { (t_fmt(lang, FmtKey::WindowLastTasks, &[&SUCCESS_RATE_WINDOW.to_string()])) }
    };
    (pct, side)
}

#[cfg(test)]
mod cookie_secure_tests {
    use super::cookie_secure_suffix_for;
    use crbs_core::config::{ServerConfig, ServerTlsConfig};
    use std::path::PathBuf;

    fn cfg_with(tls: bool, force: bool) -> ServerConfig {
        ServerConfig {
            force_secure_cookies: force,
            tls: tls.then(|| ServerTlsConfig {
                cert: PathBuf::from("/dev/null"),
                key: PathBuf::from("/dev/null"),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn plain_http_no_force_omits_secure() {
        assert_eq!(cookie_secure_suffix_for(&cfg_with(false, false)), "");
    }

    #[test]
    fn in_process_tls_sets_secure() {
        assert_eq!(cookie_secure_suffix_for(&cfg_with(true, false)), "; Secure");
    }

    #[test]
    fn force_secure_cookies_sets_secure_without_tls() {
        assert_eq!(cookie_secure_suffix_for(&cfg_with(false, true)), "; Secure");
    }

    #[test]
    fn tls_and_force_together_still_set_secure_once() {
        // 幂等：两者都开时仍只加一次 "; Secure"。
        assert_eq!(cookie_secure_suffix_for(&cfg_with(true, true)), "; Secure");
    }
}

#[cfg(test)]
mod rel_time_tests {
    use super::{format_duration_secs, rel_time_lang};
    use crate::server::routes::ui::i18n::Lang;
    use chrono::{Local, TimeDelta, Utc};
    use maud::Markup;

    /// 以当前时间倒推 delta 的 DB 时间串（SQLite/PG 统一的 UTC 墙钟帧）。
    fn ago(delta: TimeDelta) -> String {
        (Utc::now() - delta)
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string()
    }

    fn render(m: Markup) -> String {
        m.into_string()
    }

    #[test]
    fn none_and_placeholder_render_dash() {
        assert_eq!(render(rel_time_lang(None, Lang::En)), "—");
        assert_eq!(render(rel_time_lang(Some(""), Lang::En)), "—");
        assert_eq!(render(rel_time_lang(Some("-"), Lang::En)), "—");
    }

    #[test]
    fn unparseable_value_passes_through_without_span() {
        let s = render(rel_time_lang(Some("2026-08-26T10:00:00Z"), Lang::En));
        assert_eq!(s, "2026-08-26T10:00:00Z");
        assert!(!s.contains("<span"), "{s}");
    }

    #[test]
    fn seconds_minutes_hours_days_render_relative_with_absolute_title() {
        for (delta, expect) in [
            (TimeDelta::seconds(40), "40s ago"),
            (TimeDelta::minutes(5), "5 min ago"),
            (TimeDelta::hours(3), "3 h ago"),
            (TimeDelta::days(4), "4 d ago"),
        ] {
            let s = ago(delta);
            let out = render(rel_time_lang(Some(&s), Lang::En));
            let title = crbs_core::util::format_local_time(&s);
            let expected = format!("<span title=\"{title}\">{expect}</span>");
            assert_eq!(out, expected, "delta={delta}");
        }
    }

    #[test]
    fn zh_units_render_chinese_words() {
        let s = ago(TimeDelta::minutes(5));
        let out = render(rel_time_lang(Some(&s), Lang::Zh));
        assert!(out.contains("5 分钟前"), "{out}");
        let s = ago(TimeDelta::days(4));
        let out = render(rel_time_lang(Some(&s), Lang::Zh));
        assert!(out.contains("4 天前"), "{out}");
    }

    #[test]
    fn over_30_days_renders_local_date() {
        let s = ago(TimeDelta::days(45));
        let out = render(rel_time_lang(Some(&s), Lang::En));
        let expected_date = (Local::now() - TimeDelta::days(45))
            .format("%Y-%m-%d")
            .to_string();
        assert!(
            out.contains(&format!(">{expected_date}</span>")),
            "expected local date {expected_date}: {out}"
        );
        assert!(!out.contains(" ago"), "{out}");
        assert!(out.contains("<span title="), "{out}");
    }

    #[test]
    fn exactly_30_days_stays_relative() {
        let s = ago(TimeDelta::days(30));
        let out = render(rel_time_lang(Some(&s), Lang::En));
        assert!(out.contains("30 d ago"), "{out}");
    }

    #[test]
    fn slightly_future_timestamp_clamps_to_zero() {
        let s = (Utc::now() + TimeDelta::seconds(3))
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string();
        let out = render(rel_time_lang(Some(&s), Lang::En));
        assert!(out.contains("0s ago"), "{out}");
    }

    #[test]
    fn duration_formats_two_most_significant_units() {
        assert_eq!(format_duration_secs(0), "0s");
        assert_eq!(format_duration_secs(42), "42s");
        assert_eq!(format_duration_secs(222), "3m 42s");
        assert_eq!(format_duration_secs(7320), "2h 2m");
        assert_eq!(format_duration_secs(97200), "1d 3h");
        assert_eq!(format_duration_secs(7200), "2h 0m");
        assert_eq!(format_duration_secs(12 * 60 + 30), "12m 30s");
        assert_eq!(format_duration_secs(4 * 3600 + 12 * 60), "4h 12m");
        assert_eq!(format_duration_secs(3 * 86400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration_secs(-5), "0s");
    }
}

#[cfg(test)]
mod success_rate_tests {
    use super::{phase_count, success_rate_gauge};
    use crate::server::routes::ui::i18n::Lang;

    fn counts(pairs: &[(&str, i64)]) -> std::collections::HashMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn phase_count_missing_key_is_zero() {
        let m = counts(&[("succeeded", 3)]);
        assert_eq!(phase_count(&m, "succeeded"), 3);
        assert_eq!(phase_count(&m, "building"), 0);
    }

    #[test]
    fn no_samples_yields_none_with_zero_zero_side() {
        let (pct, side) = success_rate_gauge(&counts(&[]), Lang::En);
        assert_eq!(pct, None);
        let side = side.into_string();
        assert!(side.contains("<b>0</b> / <b>0</b>"), "{side}");
        assert!(side.contains("window: last 200 tasks"), "{side}");
        assert!(!side.contains("computed on page load"), "{side}");
    }

    #[test]
    fn all_failed_samples_yield_some_zero_not_none() {
        let m = counts(&[("failed", 2)]);
        assert_eq!(success_rate_gauge(&m, Lang::En).0, Some(0));
    }

    #[test]
    fn mixed_samples_round_to_nearest_percent() {
        let m = counts(&[
            ("succeeded", 3),
            ("failed", 1),
            ("building", 1),
            ("pending", 1),
        ]);
        assert_eq!(success_rate_gauge(&m, Lang::En).0, Some(50));
        // 2/3 → 66.67% 四舍五入 67。
        let m = counts(&[("succeeded", 2), ("failed", 1)]);
        assert_eq!(success_rate_gauge(&m, Lang::En).0, Some(67));
    }
}
