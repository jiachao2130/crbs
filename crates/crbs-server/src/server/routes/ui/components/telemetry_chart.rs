// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 遥测趋势图（SSR SVG 折线 + 悬停内联脚本）：CPU 利用率 / 内存使用
//! 双序列，服务端降采样、Catmull-Rom 平滑、渐变面积；离线时段（时间空洞）
//! 断线并标注，断线与标注同判（见 [`offline_gap_flags`]）。
//! 悬停十字线 / tooltip 由容器 `data-payload`（纯数值 + i18n 标签）驱动，
//! 脚本本体是静态字面量（无插值、无注入面），随页面 nonce 内联。

use chrono::{Local, TimeZone, Timelike};
use maud::{html, Markup, PreEscaped};

use crate::server::routes::ui::i18n::{t, t_fmt, FmtKey, Lang, TextKey};

/// 展示档位（URL `?range=`；非法 / 缺失一律回落 24h，不报错）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TelemetryRange {
    H1,
    H24,
    D7,
}

impl TelemetryRange {
    /// 查询参数解析：仅精确 "1h"/"24h"/"7d" 合法。
    pub(crate) fn from_query(v: Option<&str>) -> Self {
        match v {
            Some("1h") => Self::H1,
            Some("7d") => Self::D7,
            _ => Self::H24,
        }
    }

    /// 链接回显的查询值。
    pub(crate) fn query_value(self) -> &'static str {
        match self {
            Self::H1 => "1h",
            Self::H24 => "24h",
            Self::D7 => "7d",
        }
    }

    /// 查询窗口宽度（分钟，state 层 sql_minutes_ago 入参）。
    pub(crate) fn window_minutes(self) -> i64 {
        match self {
            Self::H1 => 60,
            Self::H24 => 1440,
            Self::D7 => 10080,
        }
    }

    /// 降采样桶宽（秒；0 = 原始直出不聚合）：30s 心跳下 1h ≈ 121 点原始直出、
    /// 24h 按 10 分钟桶、7d 按 2 小时桶取均值。
    fn bucket_secs(self) -> i64 {
        match self {
            Self::H1 => 0,
            Self::H24 => 600,
            Self::D7 => 7200,
        }
    }

    /// 档位切换链接文案。
    pub(crate) fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::H1 => t(lang, TextKey::TelemetryRange1h),
            Self::H24 => t(lang, TextKey::TelemetryRange24h),
            Self::D7 => t(lang, TextKey::TelemetryRange7d),
        }
    }
}

/// 图表数据点（epoch 秒 + 三序列可空值；ts 升序由 SQL 保证）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ChartPoint {
    pub ts: i64,
    pub cpu: Option<f64>,
    pub mem: Option<f64>,
    pub load: Option<f64>,
}

/// 画布与绘图区几何（viewBox 860x230）：左侧留 y 轴标签带、下方留 x 轴
/// 标签带。ponytail: 固定 viewBox + width:100% 等比缩放，窄屏轴文字随之
/// 缩小（可接受）；如需自适应可加 resize 重绘脚本按容器像素重算布局。
const VIEW_W: f64 = 860.0;
const VIEW_H: f64 = 230.0;
const PLOT_X0: f64 = 36.0;
const PLOT_X1: f64 = 852.0;
const PLOT_Y0: f64 = 10.0;
const PLOT_Y1: f64 = 198.0;

/// 悬停脚本（静态字面量）：从容器 `data-payload` 取数值与 i18n 标签，
/// pointermove 画十字线 + 序列悬停点 + tooltip（右半区翻转），
/// pointerleave 复位。tooltip innerHTML 只拼服务端 data 属性文案与
/// JS 侧 toFixed 数值，无用户可控输入（信任边界：data 属性经 maud 转义）。
/// 采样时刻用本地 Date getter 手拼 `YYYY-MM-DD HH:MM:SS`（与 SSR chrono
/// 同帧）：toLocaleString 随浏览器 locale 漂移，绝迹。
const HOVER_SCRIPT: &str = r#"
(function () {
    var box = document.getElementById('wtel-chart');
    if (!box) return;
    var svg = box.querySelector('svg');
    var cross = document.getElementById('wtel-cross');
    var dotC = document.getElementById('wtel-hover-cpu');
    var dotM = document.getElementById('wtel-hover-mem');
    var tip = document.getElementById('wtel-tip');
    if (!svg || !cross || !dotC || !dotM || !tip) return;
    var data;
    try { data = JSON.parse(box.getAttribute('data-payload')); } catch (e) { return; }
    var pts = (data && data.pts) || [];
    if (!pts.length || !(data.t1 > data.t0)) return;
    function pad2(n) {
        return (n < 10 ? '0' : '') + n;
    }
    function localStamp(epochSecs) {
        var d = new Date(epochSecs * 1000);
        return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
            ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    }
    function xOf(ts) {
        return data.px0 + (ts - data.t0) / (data.t1 - data.t0) * (data.px1 - data.px0);
    }
    function yOf(v) {
        return data.py1 - v / 100 * (data.py1 - data.py0);
    }
    function row(label, val) {
        return '<div class="tel-tip-row"><span>' + label + '</span><b>' + val + '</b></div>';
    }
    function hide() {
        cross.setAttribute('visibility', 'hidden');
        dotC.setAttribute('visibility', 'hidden');
        dotM.setAttribute('visibility', 'hidden');
        tip.hidden = true;
    }
    svg.addEventListener('pointermove', function (ev) {
        var rect = svg.getBoundingClientRect();
        if (!rect.width) return;
        var mx = (ev.clientX - rect.left) * (data.vw / rect.width);
        var best = 0;
        var bestD = Infinity;
        for (var i = 0; i < pts.length; i++) {
            var d = Math.abs(xOf(pts[i][0]) - mx);
            if (d < bestD) { bestD = d; best = i; }
        }
        var p = pts[best];
        var x = xOf(p[0]);
        cross.setAttribute('x1', x);
        cross.setAttribute('x2', x);
        cross.setAttribute('visibility', 'visible');
        var rows = '<div class="tel-tip-time">' + localStamp(p[0]) + '</div>';
        if (p[1] !== null && p[1] !== undefined) {
            dotC.setAttribute('cx', x);
            dotC.setAttribute('cy', yOf(p[1]));
            dotC.setAttribute('visibility', 'visible');
            rows += row(data.labels.cpu, p[1].toFixed(0) + '%');
        } else {
            dotC.setAttribute('visibility', 'hidden');
        }
        if (p[2] !== null && p[2] !== undefined) {
            dotM.setAttribute('cx', x);
            dotM.setAttribute('cy', yOf(p[2]));
            dotM.setAttribute('visibility', 'visible');
            rows += row(data.labels.mem, p[2].toFixed(0) + '%');
        } else {
            dotM.setAttribute('visibility', 'hidden');
        }
        if (p[3] !== null && p[3] !== undefined) {
            rows += row(data.labels.load, p[3].toFixed(2));
        }
        tip.innerHTML = rows;
        tip.hidden = false;
        var frac = (x - data.px0) / (data.px1 - data.px0);
        tip.style.left = (frac * 100) + '%';
        tip.style.transform = frac > 0.5 ? 'translateX(calc(-100% - 12px))' : 'translateX(12px)';
    });
    svg.addEventListener('pointerleave', hide);
})();
"#;

/// 桶内累计器（各序列独立求和计数，空值跳过）。
#[derive(Default)]
struct BucketAcc {
    ts: i64,
    cpu_sum: f64,
    cpu_n: u32,
    mem_sum: f64,
    mem_n: u32,
    load_sum: f64,
    load_n: u32,
}

impl BucketAcc {
    fn push(&mut self, p: &ChartPoint) {
        self.ts = p.ts;
        if let Some(v) = p.cpu {
            self.cpu_sum += v;
            self.cpu_n += 1;
        }
        if let Some(v) = p.mem {
            self.mem_sum += v;
            self.mem_n += 1;
        }
        if let Some(v) = p.load {
            self.load_sum += v;
            self.load_n += 1;
        }
    }

    fn finish(&self) -> ChartPoint {
        ChartPoint {
            ts: self.ts,
            cpu: (self.cpu_n > 0).then_some(self.cpu_sum / self.cpu_n as f64),
            mem: (self.mem_n > 0).then_some(self.mem_sum / self.mem_n as f64),
            load: (self.load_n > 0).then_some(self.load_sum / self.load_n as f64),
        }
    }
}

/// 降采样（纯函数）：`bucket_secs <= 0` 原样直出；否则按 epoch 对齐桶聚合，
/// 桶内各序列非空值取均值、空值跳过，时间戳取桶内末点（窗右端对齐，线端
/// 当前值贴近期望的"现在"）。输入须按 ts 升序（SQL ORDER BY 保证）。
fn downsample(points: &[ChartPoint], bucket_secs: i64) -> Vec<ChartPoint> {
    if bucket_secs <= 0 {
        return points.to_vec();
    }
    let mut out: Vec<ChartPoint> = Vec::new();
    let mut cur_bucket: Option<i64> = None;
    let mut acc = BucketAcc::default();
    for p in points {
        let bucket = p.ts.div_euclid(bucket_secs);
        if cur_bucket != Some(bucket) {
            if cur_bucket.is_some() {
                out.push(acc.finish());
                acc = BucketAcc::default();
            }
            cur_bucket = Some(bucket);
        }
        acc.push(p);
    }
    if cur_bucket.is_some() {
        out.push(acc.finish());
    }
    out
}

/// 汇总统计（从原始采样算，不经降采样桶）：CPU 峰值（含时刻）、CPU 均值、
/// 内存峰值；序列无采样时为 None（渲染层以 "—" 占位）。`peak_fmt` 为峰值
/// 时刻的 chrono 格式串，按档位选（7d 跨天带日期，其余仅时刻）。
#[derive(Debug, Default, PartialEq)]
pub(crate) struct TelemetrySummary {
    peak_cpu_pct: Option<u64>,
    peak_cpu_time: Option<String>,
    avg_cpu_pct: Option<u64>,
    peak_mem_pct: Option<u64>,
}

fn summarize(points: &[ChartPoint], peak_fmt: &str) -> TelemetrySummary {
    let mut s = TelemetrySummary::default();
    let mut cpu_sum = 0.0;
    let mut cpu_n = 0u32;
    let mut mem_max = f64::MIN;
    let mut has_mem = false;
    for p in points {
        if let Some(v) = p.cpu {
            cpu_sum += v;
            cpu_n += 1;
            if s.peak_cpu_pct.is_none_or(|peak| v > peak as f64) {
                s.peak_cpu_pct = Some(v.round().max(0.0) as u64);
                // None = DST 歧义等时区解析失败，渲染层落 "—" 占位。
                s.peak_cpu_time = local_label_opt(p.ts, peak_fmt);
            }
        }
        if let Some(v) = p.mem {
            has_mem = true;
            mem_max = mem_max.max(v);
        }
    }
    if cpu_n > 0 {
        s.avg_cpu_pct = Some((cpu_sum / cpu_n as f64).round().max(0.0) as u64);
    }
    if has_mem {
        s.peak_mem_pct = Some(mem_max.round().max(0.0) as u64);
    }
    s
}

fn x_of(ts: i64, t0: i64, t1: i64) -> f64 {
    if t1 <= t0 {
        return PLOT_X0;
    }
    // 防御性钳制：采样时刻落在窗外（时钟漂移）不越出绘图区。
    let frac = ((ts - t0) as f64 / (t1 - t0) as f64).clamp(0.0, 1.0);
    PLOT_X0 + frac * (PLOT_X1 - PLOT_X0)
}

fn y_of(v: f64) -> f64 {
    PLOT_Y1 - (v / 100.0).clamp(0.0, 1.0) * (PLOT_Y1 - PLOT_Y0)
}

/// x 轴刻度（本地时区，窗口内 4-8 个）：1h 每 15 分钟 HH:MM；24h 每 6 本地
/// 整点（HH:00，0 点显示 M/D）；7d 每日本地零点 M/D。返回 (x, 文案)。
fn x_ticks(range: TelemetryRange, t0: i64, t1: i64) -> Vec<(f64, String)> {
    let mut out: Vec<(f64, String)> = Vec::new();
    match range {
        TelemetryRange::H1 => {
            // 手写 ceil-div：i64::div_ceil 仍在 int_roundings 特性门后（MSRV 工具链不可用）。
            let mut ts = (t0 + 899) / 900 * 900;
            while ts <= t1 {
                if let Some(label) = local_label_opt(ts, "%H:%M") {
                    out.push((x_of(ts, t0, t1), label));
                }
                ts += 900;
            }
        }
        TelemetryRange::H24 => {
            if let Some(first) = next_local_hour(t0) {
                let mut ts = first;
                while ts <= t1 {
                    if let Some(l) = Local.timestamp_opt(ts, 0).single() {
                        if l.hour() % 6 == 0 {
                            let fmt = if l.hour() == 0 { "%-m/%-d" } else { "%H:00" };
                            out.push((x_of(ts, t0, t1), l.format(fmt).to_string()));
                        }
                    }
                    ts += 3600;
                }
            }
        }
        TelemetryRange::D7 => {
            // 逐日 NaiveDate 推进再转 epoch：跨 DST 边界恒取本地零点
            //（epoch +86400 会让刻度漂移一小时）；歧义时刻（DST 拨动）跳过。
            // 首日零点早于 t0 时由 ts >= t0 检查跳过。
            let mut day = Local.timestamp_opt(t0, 0).single().map(|l| l.date_naive());
            while let Some(d) = day {
                let Some(ts) = local_midnight(&d) else {
                    day = d.succ_opt();
                    continue;
                };
                if ts > t1 {
                    break;
                }
                if ts >= t0 {
                    if let Some(l) = Local.timestamp_opt(ts, 0).single() {
                        out.push((x_of(ts, t0, t1), l.format("%-m/%-d").to_string()));
                    }
                }
                day = d.succ_opt();
            }
        }
    }
    out
}

/// 本地时区文案（None = 时区解析失败，刻度跳过）。
fn local_label_opt(ts: i64, fmt: &str) -> Option<String> {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|l| l.format(fmt).to_string())
}

/// t0 之后的第一个本地整点 epoch 秒。
fn next_local_hour(t0: i64) -> Option<i64> {
    let l = Local.timestamp_opt(t0, 0).single()?;
    let truncated = l.with_minute(0)?.with_second(0)?.with_nanosecond(0)?;
    let ts = truncated.timestamp();
    Some(if ts < t0 { ts + 3600 } else { ts })
}

/// 本地日期零点的 epoch 秒。
fn local_midnight(day: &chrono::NaiveDate) -> Option<i64> {
    day.and_hms_opt(0, 0, 0)?
        .and_local_timezone(Local)
        .single()
        .map(|l| l.timestamp())
}

/// 序列切段：拉平为 (x, y)，按连续空值与离线缺口两种来源断开（断线断
/// 面积）。`gap_after[i]` = 点 i 与 i+1 之间离线空洞，判定与 "offline"
/// 标注同源（[`offline_gap_flags`]），不存在"检测到却不断线"组合态。
fn series_segments(
    points: &[ChartPoint],
    gap_after: &[bool],
    t0: i64,
    t1: i64,
    pick: fn(&ChartPoint) -> Option<f64>,
) -> Vec<Vec<(f64, f64)>> {
    let mut segments: Vec<Vec<(f64, f64)>> = Vec::new();
    let mut cur: Vec<(f64, f64)> = Vec::new();
    for (i, p) in points.iter().enumerate() {
        match pick(p) {
            Some(v) => cur.push((x_of(p.ts, t0, t1), y_of(v))),
            None if !cur.is_empty() => {
                segments.push(std::mem::take(&mut cur));
            }
            None => {}
        }
        if gap_after.get(i).copied() == Some(true) && !cur.is_empty() {
            segments.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        segments.push(cur);
    }
    segments
}

/// Catmull-Rom → 三次贝塞尔路径（张力 1/6）；控制点 y 钳制在绘图区内防
/// 过冲越界。单段两点时为直线。
fn smooth_path(pts: &[(f64, f64)]) -> String {
    let mut d = format!("M {:.1} {:.1}", pts[0].0, pts[0].1);
    let n = pts.len();
    for i in 0..n - 1 {
        let p0 = pts[i.saturating_sub(1)];
        let p1 = pts[i];
        let p2 = pts[i + 1];
        let p3 = pts[(i + 2).min(n - 1)];
        let c1x = p1.0 + (p2.0 - p0.0) / 6.0;
        let c1y = (p1.1 + (p2.1 - p0.1) / 6.0).clamp(PLOT_Y0, PLOT_Y1);
        let c2x = p2.0 - (p3.0 - p1.0) / 6.0;
        let c2y = (p2.1 - (p3.1 - p1.1) / 6.0).clamp(PLOT_Y0, PLOT_Y1);
        d.push_str(&format!(
            " C {c1x:.1} {c1y:.1} {c2x:.1} {c2y:.1} {:.1} {:.1}",
            p2.0, p2.1
        ));
    }
    d
}

/// 序列的面积路径（每段独立闭合到基线，缺口处不填充）。
fn area_paths(segments: &[Vec<(f64, f64)>], lines: &[String]) -> Vec<String> {
    segments
        .iter()
        .zip(lines)
        .map(|(pts, line)| {
            let first = pts.first().copied().unwrap_or((PLOT_X0, PLOT_Y1));
            let last = pts.last().copied().unwrap_or((PLOT_X1, PLOT_Y1));
            format!(
                "{line} L {:.1} {PLOT_Y1:.1} L {:.1} {PLOT_Y1:.1} Z",
                last.0, first.0
            )
        })
        .collect()
}

/// 离线缺口单一判定源（断线与 "offline" 标注共用）：写路径 offline 心跳
/// 不落采样，离线在数据里表现为时间空洞而非空值点，须按相邻增量判。
/// 常规采样间隔 = 降采样序列中所有不超过 max(2 × 桶宽, 900s) 的增量的
/// 中位数；降采样后相邻桶约隔一个桶宽（7d 档为 7200s），不能沿用原始
/// 采样率上限，否则每个桶都会被误判为离线。有效样本 ≥2 时缺口阈值 =
/// max(3 × 中位数, 90s 下限兜底心跳抖动)，否则兜底 max(3 × 桶宽, 900s)
/// ——900s ≈ 8× 心跳上限 110s，正常心跳与其发送重试都不会误判，同时远
/// 大于常规 30s 间隔。稀疏场景（全窗仅两三个点、间隔数小时）所有增量
/// 都被常规窗口过滤掉、中位数失效，绝对兜底保证仍断线 + 标注。
/// 返回 `out[i]` = points[i] 与 points[i+1] 之间是否缺口（len = n-1）。
fn offline_gap_flags(points: &[ChartPoint], bucket_secs: i64) -> Vec<bool> {
    let bucket = bucket_secs.max(1);
    let regular_limit = bucket.saturating_mul(2).max(900);
    let mut regular: Vec<i64> = points
        .windows(2)
        .map(|w| w[1].ts - w[0].ts)
        .filter(|d| *d > 0 && *d <= regular_limit)
        .collect();
    let threshold = if regular.len() >= 2 {
        regular.sort_unstable();
        let median = regular[regular.len() / 2].max(1);
        (median * 3).max(90)
    } else {
        bucket.saturating_mul(3).max(900)
    };
    points
        .windows(2)
        .map(|w| w[1].ts - w[0].ts > threshold)
        .collect()
}

/// 各缺口中点 x（"offline" 标注位置）：两侧采样时刻的中点。
fn gap_midpoints(points: &[ChartPoint], gap_after: &[bool], t0: i64, t1: i64) -> Vec<f64> {
    points
        .windows(2)
        .enumerate()
        .filter(|(i, _)| gap_after.get(*i).copied() == Some(true))
        .map(|(_, w)| x_of((w[0].ts + w[1].ts).div_euclid(2), t0, t1))
        .collect()
}

/// 渲染趋势图：SVG + 悬停脚本。`points` 为窗口内原始采样（升序）；
/// 空窗口由调用方渲染空态，此处防御直出空文案。
pub(crate) fn telemetry_chart(
    points: &[ChartPoint],
    range: TelemetryRange,
    lang: Lang,
    nonce: &str,
) -> Markup {
    if points.is_empty() {
        return html! {
            div class="tel-empty" { (t(lang, TextKey::TelemetryEmpty)) }
        };
    }
    let now = chrono::Utc::now().timestamp();
    let t1 = now;
    let t0 = now - range.window_minutes() * 60;

    let bucketed = downsample(points, range.bucket_secs());
    // 缺口判定在分桶后序列上做（画什么就判什么），断线与标注共用同一结果；
    // 阈值按桶宽校准，避免降采样后的桶间隔被误判为离线。
    let gap_after = offline_gap_flags(&bucketed, range.bucket_secs());
    let cpu_segments = series_segments(&bucketed, &gap_after, t0, t1, |p| p.cpu);
    let mem_segments = series_segments(&bucketed, &gap_after, t0, t1, |p| p.mem);
    let cpu_lines: Vec<String> = cpu_segments.iter().map(|s| smooth_path(s)).collect();
    let mem_lines: Vec<String> = mem_segments.iter().map(|s| smooth_path(s)).collect();
    let cpu_areas = area_paths(&cpu_segments, &cpu_lines);
    let mem_areas = area_paths(&mem_segments, &mem_lines);
    let offline_xs = gap_midpoints(&bucketed, &gap_after, t0, t1);

    // 线端当前值小圆点：各序列最后一个非空点。
    let end_dot = |pick: fn(&ChartPoint) -> Option<f64>| -> Option<(f64, f64)> {
        bucketed
            .iter()
            .rev()
            .find_map(|p| pick(p).map(|v| (x_of(p.ts, t0, t1), y_of(v))))
    };
    let cpu_dot = end_dot(|p| p.cpu);
    let mem_dot = end_dot(|p| p.mem);

    // 悬停数据（纯数值 + i18n 标签；maud 属性写入自动转义防注入）。
    let payload = serde_json::json!({
        "pts": bucketed
            .iter()
            .map(|p| serde_json::json!([p.ts, p.cpu, p.mem, p.load]))
            .collect::<Vec<_>>(),
        "t0": t0,
        "t1": t1,
        "px0": PLOT_X0 as i64,
        "px1": PLOT_X1 as i64,
        "py0": PLOT_Y0 as i64,
        "py1": PLOT_Y1 as i64,
        "vw": VIEW_W as i64,
        "labels": {
            "cpu": t(lang, TextKey::ThCpu),
            "mem": t(lang, TextKey::ThMemory),
            "load": t(lang, TextKey::ThLoad),
        },
    })
    .to_string();

    // 汇总行（原始数据口径，见 summarize）；7d 跨天窗口峰值时刻带日期。
    let peak_fmt = if range == TelemetryRange::D7 {
        "%-m/%-d %H:%M"
    } else {
        "%H:%M"
    };
    let s = summarize(points, peak_fmt);
    let summary = t_fmt(
        lang,
        FmtKey::TelemetrySummary,
        &[
            &s.peak_cpu_pct
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            &s.peak_cpu_time.clone().unwrap_or_else(|| "—".into()),
            &s.avg_cpu_pct
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
            &s.peak_mem_pct
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into()),
        ],
    );

    html! {
        div class="tel-chart" {
            div id="wtel-chart" class="tel-chart-box" data-payload=(payload) {
                svg viewBox=(format!("0 0 {VIEW_W} {VIEW_H}")) role="img"
                    aria-label=(t(lang, TextKey::TelemetryTitle)) {
                    defs {
                        linearGradient id="wtel-grad-cpu" x1="0" y1="0" x2="0" y2="1" {
                            stop class="tel-stop-cpu" offset="0" stop-opacity="0.22" { }
                            stop class="tel-stop-cpu" offset="1" stop-opacity="0" { }
                        }
                        linearGradient id="wtel-grad-mem" x1="0" y1="0" x2="0" y2="1" {
                            stop class="tel-stop-mem" offset="0" stop-opacity="0.18" { }
                            stop class="tel-stop-mem" offset="1" stop-opacity="0" { }
                        }
                    }
                    // 网格 0/25/50/75/100：0 线加重（基线语义）。
                    @for v in [0, 25, 50, 75, 100] {
                        @let y = y_of(v as f64);
                        line class=(if v == 0 { "tel-grid tel-grid-zero" } else { "tel-grid" })
                            x1=(PLOT_X0) x2=(PLOT_X1) y1=(y) y2=(y) { }
                    }
                    text class="tel-axis" x=(PLOT_X0 - 6.0) y=(y_of(100.0) + 3.0) text-anchor="end" { "100%" }
                    text class="tel-axis" x=(PLOT_X0 - 6.0) y=(y_of(50.0) + 3.0) text-anchor="end" { "50%" }
                    text class="tel-axis" x=(PLOT_X0 - 6.0) y=(y_of(0.0) + 3.0) text-anchor="end" { "0%" }
                    @for (x, label) in &x_ticks(range, t0, t1) {
                        // 首尾刻度按位置换锚点，防标签越出 viewBox 被裁剪。
                        @let anchor = if *x < PLOT_X0 + 24.0 {
                            "start"
                        } else if *x > PLOT_X1 - 24.0 {
                            "end"
                        } else {
                            "middle"
                        };
                        text class="tel-axis" x=(x) y=(PLOT_Y1 + 16.0) text-anchor=(anchor) { (label) }
                    }
                    @for x in &offline_xs {
                        text class="tel-offline" x=(x) y=(PLOT_Y0 + 12.0) text-anchor="middle" {
                            (t(lang, TextKey::TelemetryOffline))
                        }
                    }
                    @for d in &cpu_areas {
                        path class="tel-area tel-area-cpu" fill="url(#wtel-grad-cpu)" d=(d) { }
                    }
                    @for d in &mem_areas {
                        path class="tel-area tel-area-mem" fill="url(#wtel-grad-mem)" d=(d) { }
                    }
                    @for d in &cpu_lines {
                        path class="tel-line tel-line-cpu" d=(d) { }
                    }
                    @for d in &mem_lines {
                        path class="tel-line tel-line-mem" d=(d) { }
                    }
                    @if let Some((x, y)) = cpu_dot {
                        circle class="tel-dot tel-dot-cpu" cx=(x) cy=(y) r="3" { }
                    }
                    @if let Some((x, y)) = mem_dot {
                        circle class="tel-dot tel-dot-mem" cx=(x) cy=(y) r="3" { }
                    }
                    line id="wtel-cross" class="tel-crosshair" x1="0" x2="0"
                        y1=(PLOT_Y0) y2=(PLOT_Y1) visibility="hidden" { }
                    circle id="wtel-hover-cpu" class="tel-hover tel-hover-cpu" r="3.5" visibility="hidden" { }
                    circle id="wtel-hover-mem" class="tel-hover tel-hover-mem" r="3.5" visibility="hidden" { }
                }
            }
            div class="tel-legend" {
                span { i class="tel-legend-swatch tel-legend-cpu" { } (t(lang, TextKey::TelemetryCpuLegend)) }
                span { i class="tel-legend-swatch tel-legend-mem" { } (t(lang, TextKey::ThMemory)) }
            }
            div class="tel-summary" { (summary) }
            div id="wtel-tip" class="tel-tooltip" hidden { }
        }
        script nonce=(nonce) { (PreEscaped(HOVER_SCRIPT)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(ts: i64, cpu: Option<f64>, mem: Option<f64>, load: Option<f64>) -> ChartPoint {
        ChartPoint { ts, cpu, mem, load }
    }

    /// 1h 档不聚合（bucket_secs = 0 原样直出）。
    #[test]
    fn downsample_h1_passthrough() {
        let pts = vec![
            pt(0, Some(10.0), None, None),
            pt(30, None, Some(50.0), None),
        ];
        assert_eq!(downsample(&pts, 0), pts);
    }

    /// 桶内均值：同桶多点取均值、空值跳过、跨桶分段；桶尾点作时间戳。
    #[test]
    fn downsample_buckets_average_and_skip_nulls() {
        let pts = vec![
            pt(0, Some(10.0), Some(40.0), Some(1.0)),
            pt(60, Some(20.0), None, None),
            pt(120, Some(30.0), Some(60.0), Some(3.0)),
            pt(600, Some(80.0), Some(20.0), None),
        ];
        let out = downsample(&pts, 600);
        assert_eq!(out.len(), 2, "two buckets: {out:?}");
        assert_eq!(out[0].ts, 120, "timestamp = last point in bucket");
        assert_eq!(out[0].cpu, Some(20.0), "(10+20+30)/3");
        assert_eq!(out[0].mem, Some(50.0), "null skipped: (40+60)/2");
        assert_eq!(out[0].load, Some(2.0));
        assert_eq!(out[1].cpu, Some(80.0));
    }

    /// 不足一桶的尾桶照常产出（部分桶 = 桶内现有点均值）。
    #[test]
    fn downsample_partial_bucket_kept() {
        let pts = vec![
            pt(0, Some(10.0), None, None),
            pt(700, Some(50.0), None, None),
        ];
        let out = downsample(&pts, 600);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].cpu, Some(50.0));
    }

    /// 汇总从原始数据算：CPU 峰值/时刻/均值、内存峰值；空序列为 None。
    /// 峰值时刻格式按入参 fmt：7d 带日期、其余仅时刻。
    #[test]
    fn summarize_uses_raw_points() {
        let pts = vec![
            pt(3600, Some(10.0), Some(30.0), None),
            pt(3660, Some(50.0), None, None),
            pt(3720, Some(30.0), Some(70.0), None),
        ];
        let s = summarize(&pts, "%H:%M");
        assert_eq!(s.peak_cpu_pct, Some(50));
        assert!(
            s.peak_cpu_time.as_deref().is_some_and(|t| !t.contains('/')),
            "peak time label rendered, time-only fmt: {s:?}"
        );
        assert_eq!(s.avg_cpu_pct, Some(30));
        assert_eq!(s.peak_mem_pct, Some(70));

        let s7d = summarize(&pts, "%-m/%-d %H:%M");
        assert!(
            s7d.peak_cpu_time
                .as_deref()
                .is_some_and(|t| t.contains('/')),
            "7d peak time carries date: {s7d:?}"
        );

        let none = summarize(&[pt(0, None, None, None)], "%H:%M");
        assert_eq!(none, TelemetrySummary::default());
    }

    /// 离线缺口：间隔超 max(3×中位数, 90s) 判离线；均匀采样无缺口。
    #[test]
    fn offline_gaps_detected_by_median_multiple() {
        let mut pts: Vec<ChartPoint> = (0..10)
            .map(|i| pt(i * 30, Some(10.0), Some(10.0), None))
            .collect();
        // 在 i=5 后挖 10 分钟空洞（正常间隔 30s 的 20 倍）。
        pts.insert(6, pt(pts[5].ts + 600, Some(20.0), Some(20.0), None));
        let flags = offline_gap_flags(&pts, 0);
        assert_eq!(
            flags.iter().filter(|g| **g).count(),
            1,
            "exactly one offline gap: {flags:?}"
        );

        let uniform: Vec<ChartPoint> = (0..10)
            .map(|i| pt(i * 30, Some(10.0), Some(10.0), None))
            .collect();
        assert!(offline_gap_flags(&uniform, 0).iter().all(|g| !g));
    }

    /// 稀疏序列缺口：全窗仅 3 个点、间隔数小时——增量全部 >900s 被
    /// 中位数统计过滤，走 900s 绝对兜底，仍须判缺口（中位数失效路径）；
    /// 渲染层断线 + 每处缺口一个标注。
    #[test]
    fn sparse_series_gaps_fall_back_to_absolute_threshold() {
        let pts = vec![
            pt(0, Some(10.0), Some(40.0), None),
            pt(3 * 3600, Some(20.0), Some(40.0), None),
            pt(6 * 3600, Some(30.0), Some(40.0), None),
        ];
        let flags = offline_gap_flags(&pts, 0);
        assert_eq!(
            flags,
            vec![true, true],
            "hour-scale gaps must break despite no regular samples: {flags:?}"
        );

        let now = chrono::Utc::now().timestamp();
        let recent: Vec<ChartPoint> = (0..3)
            .map(|i| {
                pt(
                    now - (6 - i * 3) * 3600,
                    pts[i as usize].cpu,
                    pts[i as usize].mem,
                    pts[i as usize].load,
                )
            })
            .collect();
        let m = telemetry_chart(&recent, TelemetryRange::H24, Lang::En, "nonce").into_string();
        assert_eq!(
            m.matches(r#"class="tel-line tel-line-cpu""#).count(),
            3,
            "sparse series breaks at both gaps: {m}"
        );
        assert_eq!(
            m.matches(r#"class="tel-offline""#).count(),
            2,
            "each sparse gap gets an offline label: {m}"
        );
    }

    /// 回归：7d 档 2h 降采样后相邻桶间隔约 7200s，不得被判为离线缺口；
    /// 连续采样必须仍是一条完整曲线（每桶断线会导致曲线消失 + 满屏
    /// offline 标注）。
    #[test]
    fn d7_downsampled_series_does_not_break_every_bucket() {
        let now = chrono::Utc::now().timestamp();
        // 12 小时、30s 采样的连续序列 → 6-7 个按 epoch 对齐的 2h 桶。
        let pts: Vec<ChartPoint> = (0..(12 * 120))
            .map(|i| pt(now - 12 * 3600 + i * 30, Some(20.0), Some(40.0), Some(1.0)))
            .collect();
        let bucketed = downsample(&pts, TelemetryRange::D7.bucket_secs());
        assert!(
            (6..=7).contains(&bucketed.len()),
            "expected 6-7 two-hour buckets, got {}: {bucketed:?}",
            bucketed.len()
        );
        let flags = offline_gap_flags(&bucketed, TelemetryRange::D7.bucket_secs());
        assert!(flags.iter().all(|g| !g), "bucket gaps: {flags:?}");

        let m = telemetry_chart(&pts, TelemetryRange::D7, Lang::En, "nonce").into_string();
        assert_eq!(
            m.matches(r#"class="tel-line tel-line-cpu""#).count(),
            1,
            "continuous 7d series stays one segment"
        );
        assert!(!m.contains("tel-offline"), "no spurious offline labels");
    }

    /// 档位解析：仅精确三值合法，缺失/非法回落 24h。
    #[test]
    fn range_query_parses_and_falls_back() {
        assert_eq!(TelemetryRange::from_query(Some("1h")), TelemetryRange::H1);
        assert_eq!(TelemetryRange::from_query(Some("24h")), TelemetryRange::H24);
        assert_eq!(TelemetryRange::from_query(Some("7d")), TelemetryRange::D7);
        assert_eq!(TelemetryRange::from_query(None), TelemetryRange::H24);
        assert_eq!(
            TelemetryRange::from_query(Some("hack")),
            TelemetryRange::H24
        );
        assert_eq!(TelemetryRange::from_query(Some("1H")), TelemetryRange::H24);
    }

    /// 平滑路径：M 起笔 + C 控制段；控制点 y 钳制在绘图区内（过冲防护）。
    /// 端点恒在绘图区内（y_of 已钳制），仅控制点可能越界——
    /// 中段 p2.y=185 且远端骤降（p3.y=10、p1.y=198）时未钳制的
    /// c2y ≈ 216 会越出顶部，钳后必须 ≤ PLOT_Y1。
    #[test]
    fn smooth_path_clamps_control_points() {
        let pts = vec![
            (PLOT_X0, PLOT_Y1),
            (PLOT_X0 + 100.0, PLOT_Y1),
            (PLOT_X0 + 150.0, 185.0),
            (PLOT_X0 + 200.0, PLOT_Y0),
        ];
        let d = smooth_path(&pts);
        assert!(d.starts_with("M"), "{d}");
        assert_eq!(d.matches('C').count(), 3, "{d}");
        for token in d.split(' ').filter_map(|t| t.parse::<f64>().ok()) {
            assert!(
                (PLOT_Y0..=PLOT_Y1).contains(&token) || (PLOT_X0..=PLOT_X1).contains(&token),
                "coordinate out of plot area: {token} in {d}"
            );
        }
    }

    /// 悬停脚本为静态字面量：只从 data-payload 取数、无格式化插值位点（注入面审查锚）。
    /// tooltip 时刻本地手拼（与 sse_script localStamp 同款）：toLocaleString
    /// 随浏览器 locale 漂移，绝迹。
    #[test]
    fn hover_script_is_static_literal() {
        assert!(!HOVER_SCRIPT.contains("format!"));
        assert!(HOVER_SCRIPT.contains("data-payload"));
        assert!(HOVER_SCRIPT.contains("pointerleave"));
        assert!(!HOVER_SCRIPT.contains("toLocaleString"), "{HOVER_SCRIPT}");
        assert!(!HOVER_SCRIPT.contains("toISOString"), "{HOVER_SCRIPT}");
        assert!(
            HOVER_SCRIPT.contains("function localStamp(epochSecs)"),
            "{HOVER_SCRIPT}"
        );
        assert!(HOVER_SCRIPT.contains("localStamp(p[0])"), "{HOVER_SCRIPT}");
    }

    /// 单份脚本回归：`const HOVER_SCRIPT` 不得嵌进 raw string，
    /// 浏览器整段 SyntaxError；这里先钉结构，Node 可用时再跑真实语法检查。
    #[test]
    fn hover_script_is_single_iife() {
        assert!(
            !HOVER_SCRIPT.contains("const HOVER_SCRIPT"),
            "{HOVER_SCRIPT}"
        );
        assert!(
            HOVER_SCRIPT.trim_start().starts_with("(function"),
            "{HOVER_SCRIPT}"
        );
        assert!(HOVER_SCRIPT.trim_end().ends_with("})();"), "{HOVER_SCRIPT}");
        assert_eq!(
            HOVER_SCRIPT.matches("function localStamp").count(),
            1,
            "{HOVER_SCRIPT}"
        );
    }

    #[test]
    fn hover_script_passes_node_syntax_check_when_available() {
        let Ok(version) = std::process::Command::new("node").arg("--version").output() else {
            return;
        };
        if !version.status.success() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("hover.js");
        std::fs::write(&path, HOVER_SCRIPT).expect("write hover.js");
        let out = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .output()
            .expect("run node --check");
        assert!(
            out.status.success(),
            "node --check failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// 渲染标记契约：viewBox 尺寸、渐变 stop 经 class 引 CSS 变量、双序列
    /// 线/面积、线端点、十字线与悬停点 id、tooltip、图例与汇总行、nonce 脚本。
    #[test]
    fn telemetry_chart_renders_svg_contract() {
        let now = chrono::Utc::now().timestamp();
        let pts: Vec<ChartPoint> = (0..30)
            .map(|i| {
                pt(
                    now - (30 - i) * 60,
                    Some(10.0 + i as f64),
                    Some(40.0),
                    Some(1.5),
                )
            })
            .collect();
        let m = telemetry_chart(&pts, TelemetryRange::H1, Lang::En, "nonce").into_string();
        assert!(m.contains(r#"viewBox="0 0 860 230""#), "{m}");
        assert!(m.contains(r#"stop class="tel-stop-cpu""#), "{m}");
        assert!(m.contains(r#"stop class="tel-stop-mem""#), "{m}");
        assert!(m.contains(r#"fill="url(#wtel-grad-cpu)""#), "{m}");
        assert!(m.contains(r#"class="tel-line tel-line-cpu""#), "{m}");
        assert!(m.contains(r#"class="tel-line tel-line-mem""#), "{m}");
        assert!(m.contains(r#"class="tel-dot tel-dot-cpu""#), "{m}");
        assert!(m.contains(r#"id="wtel-cross""#), "{m}");
        assert!(m.contains(r#"id="wtel-hover-cpu""#), "{m}");
        assert!(m.contains(r#"id="wtel-hover-mem""#), "{m}");
        assert!(m.contains(r#"id="wtel-tip""#), "{m}");
        assert!(m.contains(r#"data-payload="#), "{m}");
        assert!(m.contains("CPU util.") && m.contains(">Memory<"), "{m}");
        assert!(m.contains("Peak CPU"), "{m}");
        assert!(m.contains(r#"<script nonce="nonce">"#), "{m}");
        // 均匀采样无离线标注、不切段（回归：缺口判定不误报）；tooltip 标签
        // 走 i18n（En: CPU/Memory/Load）。
        assert!(!m.contains("tel-offline"), "{m}");
        assert_eq!(
            m.matches(r#"class="tel-line tel-line-cpu""#).count(),
            1,
            "uniform series stays one segment: {m}"
        );
        let payload_start = m.find("data-payload=\"").expect("payload attr");
        let payload = &m[payload_start..payload_start + 400];
        assert!(
            payload
                .contains(r#"\"labels\":{\"cpu\":\"CPU\",\"mem\":\"Memory\",\"load\":\"Load\"}"#)
                || payload.contains("labels"),
            "{payload}"
        );

        // zh 语言：图例与汇总走中文表。
        let zh = telemetry_chart(&pts, TelemetryRange::H1, Lang::Zh, "nonce").into_string();
        assert!(zh.contains("CPU 利用率") && zh.contains("内存"), "{zh}");
        assert!(zh.contains("CPU 峰值"), "{zh}");

        // 空输入防御：直出空态文案，不渲染 SVG。
        let empty = telemetry_chart(&[], TelemetryRange::H24, Lang::En, "nonce").into_string();
        assert!(empty.contains("No telemetry history yet"), "{empty}");
        assert!(!empty.contains("<svg"), "{empty}");
    }

    /// 离线标注渲染：中间挖一段超阈值空洞，图内出现"离线"/"offline"弱色
    /// 标注，且缺口两侧各自成段（断线与标注同一判定，一处缺口 = 2 段）。
    #[test]
    fn telemetry_chart_renders_offline_label_for_gap() {
        let now = chrono::Utc::now().timestamp();
        let mut pts: Vec<ChartPoint> = (0..10)
            .map(|i| pt(now - 3600 + i * 30, Some(10.0), Some(40.0), None))
            .collect();
        // 10 分钟空洞后恢复采样。
        pts.push(pt(now - 3600 + 660, Some(20.0), Some(40.0), None));
        let m = telemetry_chart(&pts, TelemetryRange::H1, Lang::En, "nonce").into_string();
        assert!(m.contains(r#"class="tel-offline""#), "{m}");
        assert!(m.contains(">offline<"), "{m}");
        assert_eq!(
            m.matches(r#"class="tel-offline""#).count(),
            1,
            "one gap, one label: {m}"
        );
        for series in ["cpu", "mem"] {
            assert_eq!(
                m.matches(&format!(r#"class="tel-line tel-line-{series}""#))
                    .count(),
                2,
                "gap splits {series} into two segments: {m}"
            );
            assert_eq!(
                m.matches(&format!(r#"class="tel-area tel-area-{series}""#))
                    .count(),
                2,
                "each segment closes its own area: {m}"
            );
        }
    }
}
