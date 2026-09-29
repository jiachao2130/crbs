// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 状态徽章组件：phase 徽章族、worker/user 状态徽章与心跳新鲜度判定。

use chrono::Utc;
use maud::{html, Markup};

use crate::server::routes::ui::i18n::{t, t_fmt, t_phase, FmtKey, Lang, TextKey};

/// phase 徽章（带 `data-phase`）。`lang`：文本走 [`t_phase`] 显示名（En 恒等原串，未迁移
/// 调用点行为不变）；class 映射只看原始枚举值。`data-phase` 是语言无关相位通道，供
/// `phase_sse_script` 终态守卫/live 更新读写——zh SSR 文本是本地化显示名，不得作相位
/// 判定/回写依据；列表页 [`phase_badge`] 无 data-phase，donut hover（`.hot`/`.dimmed`）不卷入。
pub(crate) fn phase_badge_with_class(phase: &str, extra_class: &str, lang: Lang) -> Markup {
    phase_badge_inner(phase, extra_class, lang, true)
}

pub(crate) fn phase_badge(phase: &str, lang: Lang) -> Markup {
    phase_badge_inner(phase, "", lang, false)
}

/// phase → 语义修饰类（未知 phase 空串）；badge / count-badge / .status 三族唯一共用映射，
/// 各自拼前缀。timeout/cancelled 非 failure：超时属 warning 族、人为终止属中性族，
/// 与仪表盘卡片左边条配色对齐（.card.timeout / 中性卡）。
pub(crate) fn phase_modifier(phase: &str) -> &'static str {
    match phase {
        "succeeded" => "success",
        "failed" => "failure",
        "timeout" => "timeout",
        "cancelled" => "cancelled",
        "building" | "assigned" => "running",
        "pending" => "pending",
        _ => "",
    }
}

/// 列表状态列：色点 + 文字；mod 映射见 [`phase_modifier`]，文字色复用徽章族深文字令牌，
/// running 点呼吸动画（style.css .status）。无 data-phase / 无 JS——donut hover 不卷入。
pub(crate) fn phase_status(phase: &str, lang: Lang) -> Markup {
    let modifier = phase_modifier(phase);
    let class = if modifier.is_empty() {
        "status".to_string()
    } else {
        format!("status {modifier}")
    };
    html! { span class=(class) { span class="dot" {} (t_phase(lang, phase)) } }
}

fn phase_badge_inner(phase: &str, extra_class: &str, lang: Lang, with_data_phase: bool) -> Markup {
    let mut class = String::from("badge");
    for part in [phase_modifier(phase), extra_class] {
        if !part.is_empty() {
            class.push(' ');
            class.push_str(part);
        }
    }
    let data_phase: Option<&str> = with_data_phase.then_some(phase);
    html! { span class=(class) data-phase=[data_phase] { (t_phase(lang, phase)) } }
}

/// UI 心跳"不再新鲜"阈值（秒）：5 min = 10 个心跳周期（worker 默认 30s/跳，crbs-worker 配置），
/// 高于 scheduler 判离线 120s（`WORKER_HEARTBEAT_TIMEOUT_SECS`）——纯显示层警示，防抖动误报。
const WORKER_HEARTBEAT_STALE_SECS: i64 = 300;

/// 心跳距当前 UTC 超 `secs` 秒返回 true；缺失（None）/ 解析失败视为新鲜返回 false（不误报）。
/// 徽章 stale（300s，[`WORKER_HEARTBEAT_STALE_SECS`]）与遥测 stale（120s）共用本判定。
pub(crate) fn worker_heartbeat_older_than(last_heartbeat: Option<&str>, secs: i64) -> bool {
    let Some(s) = last_heartbeat else {
        return false;
    };
    let Some(naive) = crbs_core::util::parse_db_time(s) else {
        return false;
    };
    (Utc::now() - naive.and_utc()).num_seconds() > secs
}

/// Worker 状态徽章（online/offline）；`lang` 定显示名与 stale 降级词。online 但心跳超
/// [`WORKER_HEARTBEAT_STALE_SECS`] 未更新时降级 warn "stale"（服务端尚未判 offline）。
pub(crate) fn worker_status_badge(
    status: &str,
    last_heartbeat: Option<&str>,
    lang: Lang,
) -> Markup {
    worker_status_badge_with_class(status, last_heartbeat, "", lang)
}

/// [`worker_status_badge`] 的带附加类变体（SSE 页把 `worker-status-badge`
/// 定位类拼进徽章，`worker_sse_script` 按类名就地改写；stale 降级分支同样
/// 携带附加类）。
pub(crate) fn worker_status_badge_with_class(
    status: &str,
    last_heartbeat: Option<&str>,
    extra_class: &str,
    lang: Lang,
) -> Markup {
    let with = |base: &str| {
        if extra_class.is_empty() {
            base.to_string()
        } else {
            format!("{base} {extra_class}")
        }
    };
    if status == "online"
        && worker_heartbeat_older_than(last_heartbeat, WORKER_HEARTBEAT_STALE_SECS)
    {
        return html! { span class=(with("badge warn")) { (t(lang, TextKey::WorkerStale)) } };
    }
    let class = match status {
        "online" => with("badge success"),
        "offline" => with("badge failure"),
        _ => with("badge"),
    };
    html! { span class=(class) { (crate::server::routes::ui::i18n::worker_status_label(lang, status)) } }
}

/// 渲染用户状态徽章（active / disabled）。`lang`：状态显示名。
pub(crate) fn user_status_badge(status: &str, lang: Lang) -> Markup {
    let class = match status {
        "active" => "badge success",
        "disabled" => "badge failure",
        _ => "badge",
    };
    html! { span class=(class) { (crate::server::routes::ui::i18n::user_status_label(lang, status)) } }
}

// ===== 派发归因徽章（内存态诊断，重启清空）=====

/// pending 构建的最近派发拒绝归因徽章：文本 = 原因短语（i18n），title =
/// 完整诊断（原因 + 水位生效压载对照 / 硬下限维度 + 水位等待时长 + 内存态
/// 说明）。归因只在 pending 期存在（派发成功即清除），调用方按
/// phase == "pending" 门控。`watermark_effective_load` 仅 WatermarkBlocked
/// 消费——该字段跨原因残留（后续 no_fit 不清），其他原因下不展示。水位压载
/// 按拒绝维（Mem/Cpu/Tmpfs）分别对照对应水位：`watermarks` 传运行期配置值，
/// 百分比随配置变化（Tmpfs 是学习门，不涉水位系数）。
pub(crate) fn attribution_badge(
    reason: crate::server::scheduler::planner::RejectReason,
    first_watermark_reject_at: Option<std::time::Instant>,
    watermark_effective_load: Option<crate::server::scheduler::CommittedLoad>,
    watermarks: crate::server::scheduler::AdmitWatermarks,
    lang: Lang,
) -> Markup {
    use crate::server::scheduler::planner::RejectReason as R;
    use crate::server::scheduler::WatermarkDimension;
    let label = match reason {
        R::NoFitArch => t(lang, TextKey::AttribNoFitArch),
        R::NoFitCapacity => t(lang, TextKey::AttribNoFitCapacity),
        R::WatermarkBlocked { .. } => t(lang, TextKey::AttribWatermarkBlocked),
        R::InitGated => t(lang, TextKey::AttribInitGated),
        R::NoFitHardReq { .. } => t(lang, TextKey::AttribNoFitHardReq),
        R::BackgroundGated => t(lang, TextKey::AttribBackgroundGated),
    };
    let mut title_parts: Vec<String> = vec![label.to_string()];
    if let R::NoFitHardReq { dimension } = reason {
        title_parts.push(t_fmt(lang, FmtKey::AttribHardReqDim, &[dimension.as_str()]).to_string());
    }
    if let (R::WatermarkBlocked { dimension }, Some(load)) = (&reason, watermark_effective_load) {
        let mem = super::format_kb_human(load.mem_kb.round() as i64);
        let cores = format!("{:.1}", load.cpu_cores);
        let detail = match dimension {
            WatermarkDimension::Mem => t_fmt(
                lang,
                FmtKey::AttribWatermarkLoadMem,
                &[&mem, &cores, &format_watermark_pct(watermarks.mem)],
            ),
            WatermarkDimension::Cpu => t_fmt(
                lang,
                FmtKey::AttribWatermarkLoadCpu,
                &[&mem, &cores, &format_watermark_pct(watermarks.cpu)],
            ),
            WatermarkDimension::Tmpfs => t(lang, TextKey::AttribTmpfsGate).to_string(),
        };
        title_parts.push(detail);
    }
    if let Some(first) = first_watermark_reject_at {
        let waiting = format_waiting(std::time::Instant::now().duration_since(first));
        title_parts.push(t_fmt(lang, FmtKey::AttribWatermarkWaiting, &[&waiting]).to_string());
    }
    title_parts.push(t(lang, TextKey::AttribDiagnosticNote).to_string());
    html! { span class="badge pending" title=(title_parts.join(" · ")) { (label) } }
}

/// 水位系数 → 百分比文案（0.9 → "90%"，0.875 → "87.5%"）。
fn format_watermark_pct(coefficient: f64) -> String {
    let pct = format!("{:.1}", coefficient * 100.0);
    match pct.strip_suffix(".0") {
        Some(trimmed) => format!("{trimmed}%"),
        None => format!("{pct}%"),
    }
}

/// 等待时长 → 人读（<60s "40s"，<60m "25m"，否则 "1h23m"）。
fn format_waiting(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试基线水位（= serde 默认 0.90/1.00）。
    fn default_wm() -> crate::server::scheduler::AdmitWatermarks {
        crate::server::scheduler::AdmitWatermarks::from_config(
            &crbs_core::config::ServerConfig::default(),
        )
    }

    /// 归因徽章：watermark 文本 + title 含等待时长与内存态说明；
    /// hard-floor title 带维度名；生效压载只随 WatermarkBlocked 展示，
    /// 且按拒绝维对照对应水位（百分比取运行配置，Tmpfs 学习门不涉水位）。
    #[test]
    fn attribution_badge_labels_and_titles() {
        use crate::server::scheduler::planner::{HardReqDimension, RejectReason};
        use crate::server::scheduler::{CommittedLoad, WatermarkDimension};

        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Mem,
            },
            None,
            None,
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(html.contains("held by watermark gate"), "{html}");
        assert!(html.contains("badge pending"), "{html}");
        assert!(html.contains("diagnostic in-memory attribution"), "{html}");

        // 等待时长进入 title（首拒 30 分钟前 → waiting 30m）。
        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Mem,
            },
            Some(std::time::Instant::now() - std::time::Duration::from_secs(1800)),
            None,
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(html.contains("waiting 30m"), "{html}");

        // 生效压载进 title：30_000_000 KB → 28.6G，63.0 核（一位小数）；
        // mem 维对照默认内存水位 90%。
        let load = CommittedLoad {
            mem_kb: 30_000_000.0,
            cpu_cores: 63.0,
        };
        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Mem,
            },
            None,
            Some(load),
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(
            html.contains("effective 28.6G / 63.0 cores vs mem watermark 90% of node total"),
            "{html}"
        );

        // cpu 维对照 CPU 水位（默认 100% = ncpu）。
        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Cpu,
            },
            None,
            Some(load),
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(
            html.contains("effective 28.6G / 63.0 cores vs cpu watermark 100% of ncpu"),
            "{html}"
        );

        // 百分比随运行配置：0.85/0.75 → 85%/75%（去尾 .0）。
        let custom = crate::server::scheduler::AdmitWatermarks {
            mem: 0.85,
            cpu: 0.75,
        };
        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Cpu,
            },
            None,
            Some(load),
            custom,
            Lang::En,
        )
        .into_string();
        assert!(html.contains("cpu watermark 75% of ncpu"), "{html}");

        // tmpfs 学习门无水位系数：只给门说明，不展示 mem/cpu 压载对照。
        let html = attribution_badge(
            RejectReason::WatermarkBlocked {
                dimension: WatermarkDimension::Tmpfs,
            },
            None,
            Some(load),
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(html.contains("learned tmpfs gate"), "{html}");
        assert!(!html.contains("effective"), "{html}");

        // 压载字段跨原因残留：非 WatermarkBlocked 不展示。
        let html = attribution_badge(
            RejectReason::NoFitCapacity,
            None,
            Some(load),
            default_wm(),
            Lang::En,
        )
        .into_string();
        assert!(!html.contains("effective"), "{html}");

        let html = attribution_badge(
            RejectReason::NoFitHardReq {
                dimension: HardReqDimension::Mem,
            },
            None,
            None,
            default_wm(),
            Lang::Zh,
        )
        .into_string();
        assert!(html.contains("硬下限无人满足"), "{html}");
        assert!(html.contains("维度：mem"), "{html}");
    }

    #[test]
    fn worker_status_badge_online_with_fresh_heartbeat() {
        let hb = (Utc::now() - chrono::TimeDelta::seconds(30))
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string();
        let s = worker_status_badge("online", Some(&hb), Lang::En).into_string();
        assert!(s.contains("badge success"), "{s}");
        assert!(s.contains("online"), "{s}");
    }

    #[test]
    fn worker_status_badge_online_with_stale_heartbeat() {
        let hb = (Utc::now() - chrono::TimeDelta::minutes(6))
            .format(crbs_core::util::DB_TIME_FMT)
            .to_string();
        let s = worker_status_badge("online", Some(&hb), Lang::En).into_string();
        assert!(s.contains("badge warn"), "{s}");
        assert!(s.contains("stale"), "{s}");
    }

    #[test]
    fn worker_status_badge_offline() {
        let s = worker_status_badge("offline", None, Lang::En).into_string();
        assert!(s.contains("badge failure"), "{s}");
        assert!(s.contains("offline"), "{s}");
    }
}

/// 徽章对比度门槛（CI 强制）：解析内嵌 style.css 亮/暗两套令牌与全部 `.badge`
/// 规则，按主题把 rgba 底色合成到 `--surface` 上，逐类断言 WCAG 2.1 对比度 ≥4.5:1。
#[cfg(test)]
mod badge_contrast {
    use std::collections::HashMap;

    const CSS: &str = include_str!("../style.css");

    /// 三族下标（badge_family 返回值，兼作按族计数器位）。
    const BADGE: usize = 0;
    const COUNT_BADGE: usize = 1;
    const STATUS: usize = 2;

    /// 按族完备性守卫下限（现状数，见测试尾部注释）。
    const FAMILY_MIN: [(&str, usize); 3] = [("badge", 9), ("count-badge", 7), ("status", 6)];

    /// #rrggbb（本文件令牌全为 6 位 hex 或 rgba()）。
    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Rgb([u8; 3]);

    fn hex(s: &str) -> Option<Rgb> {
        let h = s.trim().strip_prefix('#')?;
        if h.len() != 6 {
            return None;
        }
        Some(Rgb([
            u8::from_str_radix(&h[0..2], 16).ok()?,
            u8::from_str_radix(&h[2..4], 16).ok()?,
            u8::from_str_radix(&h[4..6], 16).ok()?,
        ]))
    }

    /// CSS 颜色值 → (颜色, alpha)。仅支持本文件用到的 #hex 与 rgba()。
    fn css_color(v: &str) -> Option<(Rgb, f32)> {
        let v = v.trim();
        if let Some(c) = hex(v) {
            return Some((c, 1.0));
        }
        let inner = v.strip_prefix("rgba(")?.strip_suffix(')')?;
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        if parts.len() != 4 {
            return None;
        }
        let r = parts[0].parse::<u8>().ok()?;
        let g = parts[1].parse::<u8>().ok()?;
        let b = parts[2].parse::<u8>().ok()?;
        let a = parts[3].parse::<f32>().ok()?;
        Some((Rgb([r, g, b]), a))
    }

    /// rgba 底色合成到 surface（WCAG 无预乘概念，直接按 alpha 线性插值）。
    fn composite(bg: Rgb, alpha: f32, base: Rgb) -> Rgb {
        let mix = |c: u8, s: u8| (c as f32 * alpha + s as f32 * (1.0 - alpha)).round() as u8;
        Rgb([
            mix(bg.0[0], base.0[0]),
            mix(bg.0[1], base.0[1]),
            mix(bg.0[2], base.0[2]),
        ])
    }

    fn rel_lum(c: Rgb) -> f64 {
        let ch = |v: u8| -> f64 {
            let s = v as f64 / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(c.0[0]) + 0.7152 * ch(c.0[1]) + 0.0722 * ch(c.0[2])
    }

    fn contrast(a: Rgb, b: Rgb) -> f64 {
        let (la, lb) = (rel_lum(a), rel_lum(b));
        let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// 去掉 /* ... */ 注释（注释里提到的令牌名不得进解析结果）。
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

    fn tokens(scope: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let mut rest = scope;
        while let Some(pos) = rest.find("--") {
            let after = &rest[pos + 2..];
            let Some(colon) = after.find(':') else {
                break;
            };
            let name = &after[..colon];
            let valid =
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
            if !valid {
                rest = after;
                continue;
            }
            let val_scope = &after[colon + 1..];
            let end = val_scope.find(';').unwrap_or(val_scope.len());
            map.insert(format!("--{name}"), val_scope[..end].trim().to_string());
            rest = &val_scope[end..];
        }
        map
    }

    fn resolve_color(value: &str, theme: &HashMap<String, String>) -> Option<(Rgb, f32)> {
        let v = value.trim();
        if let Some(name) = v.strip_prefix("var(").and_then(|s| s.strip_suffix(')')) {
            return theme.get(name.trim()).and_then(|raw| css_color(raw));
        }
        css_color(v)
    }

    /// marker（如 @media …dark）对应块的内部内容（花括号配平截取）。
    fn media_block<'a>(css: &'a str, marker: &str) -> Option<&'a str> {
        let start = css.find(marker)?;
        let open = css[start..].find('{')? + start;
        let mut depth = 0usize;
        for (i, c) in css[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&css[open + 1..open + i]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn rules(css: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut rest = css;
        while let Some(open) = rest.find('{') {
            let selector = rest[..open].trim().to_string();
            let body_start = open + 1;
            let mut depth = 1usize;
            let mut body_end = None;
            for (i, c) in rest[body_start..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body_end = Some(body_start + i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(body_end) = body_end else {
                break;
            };
            let body = &rest[body_start..body_end];
            if body.contains('{') {
                out.extend(rules(body));
            } else if !selector.is_empty() {
                out.push((selector, body.to_string()));
            }
            rest = &rest[body_end + 1..];
        }
        out
    }

    /// 选择器任一分段命中 .badge / .count-badge / .status（含 `.<modifier>`）时返回族下标
    /// （BADGE / COUNT_BADGE / STATUS）。三族都承载 phase 语义色、同守 WCAG（Attempts 纯
    /// 计数 badge 只用中性基类，同样被覆盖）；.status 无背景填充，缺 background 按 var(--surface) 合成。
    fn badge_family(sel: &str) -> Option<usize> {
        sel.split(',').find_map(|part| {
            let p = part.trim();
            if p == ".badge" || p.starts_with(".badge.") {
                Some(BADGE)
            } else if p == ".count-badge" || p.starts_with(".count-badge.") {
                Some(COUNT_BADGE)
            } else if p == ".status" || p.starts_with(".status.") {
                Some(STATUS)
            } else {
                None
            }
        })
    }

    fn decl<'a>(body: &'a str, prop: &str) -> Option<&'a str> {
        body.split(';').map(str::trim).find_map(|d| {
            let (k, v) = d.split_once(':')?;
            (k.trim() == prop).then_some(v.trim())
        })
    }

    #[test]
    fn badge_text_meets_wcag_aa_on_composite_background() {
        let css = strip_comments(CSS);
        let dark_marker = "@media (prefers-color-scheme: dark)";
        let dark_at = css.find(dark_marker).expect("dark theme block present");
        let light_scope = &css[..dark_at];
        let dark_scope = media_block(&css, dark_marker).expect("balanced dark media block");

        let light_tokens = tokens(light_scope);
        let dark_tokens = tokens(dark_scope);
        assert!(!light_tokens.is_empty() && !dark_tokens.is_empty());

        // 徽章底色合成基：--surface（表格/卡片背景），两主题各自取值。
        for (theme, tk) in [("light", &light_tokens), ("dark", &dark_tokens)] {
            let surface_hex = tk.get("--surface").map(String::as_str).unwrap_or("");
            let surface = hex(surface_hex)
                .unwrap_or_else(|| panic!("{theme}: unparseable --surface {surface_hex}"));
            let mut families = [0usize; 3];
            for (sel, body) in rules(&css) {
                let Some(family) = badge_family(&sel) else {
                    continue;
                };
                let Some(fg_val) = decl(&body, "color") else {
                    continue;
                };
                // .status 缺 background 按 --surface 合成是近似：行 hover 实际面为更深的
                // --surface-hover；现状最低余量 亮 5.5:1（.status.cancelled）/ 暗 5.6:1
                // （.status.failure），调深 hover 底色需复查；徽章族仍强制显式声明（防解析回归）。
                let bg_val = match decl(&body, "background") {
                    Some(v) => v,
                    None if family == STATUS => "var(--surface)",
                    None => panic!("{theme} {sel}: badge rule lacks background"),
                };
                let (fg, _) = resolve_color(fg_val, tk)
                    .unwrap_or_else(|| panic!("{theme} {sel}: unparseable color {fg_val}"));
                let (bg, alpha) = resolve_color(bg_val, tk)
                    .unwrap_or_else(|| panic!("{theme} {sel}: unparseable background {bg_val}"));
                let ratio = contrast(fg, composite(bg, alpha, surface));
                assert!(
                    ratio >= 4.5,
                    "{theme} {sel}: contrast {ratio:.2} < 4.5 (color {fg_val} on {bg_val})"
                );
                families[family] += 1;
            }
            // 按族守卫（现状数）：badge 9（基类+6 phase 修饰+warn/accent）、count-badge
            // 7（基类+6 phase 修饰）、status 6（基类无 color 不进检查）——新增规则自动纳入，
            // 删规则/解析回归按族暴露（总数式会让"一族涨、另一族跌"互相抵消）。
            for (idx, (name, min)) in FAMILY_MIN.iter().enumerate() {
                assert!(
                    families[idx] >= *min,
                    "{theme}: expected >= {min} {name} rules checked, got {}",
                    families[idx]
                );
            }
        }
    }
}
