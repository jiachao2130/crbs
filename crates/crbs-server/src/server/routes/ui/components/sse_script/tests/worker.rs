// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 页 SSE 脚本测试。

use super::*;
use crate::server::routes::ui::components::layout::{LOAD_LEVEL_CRIT_PCT, LOAD_LEVEL_WARN_PCT};
use crate::server::routes::ui::pages::REL_TIME_ABSOLUTE_DAYS;

/// worker SSE 脚本契约钉死：端点 URL、worker 事件监听、offline 终态
/// close+reload（唯一 reload 调用点，SSR 离线页不渲染脚本故不成环）、
/// 遥测/活动表/Recent builds 卡的 DOM 定位键、本地 ticker 与双语模板注入。
#[test]
fn worker_sse_script_pins_dom_contract_and_offline_reload() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(s.contains("new EventSource('/ui/workers/5/events')"), "{s}");
    assert!(s.contains("es.addEventListener('worker'"), "{s}");
    // offline 终态：关流 + 单次 reload（页内唯一 location.reload）。
    assert!(s.contains("if (data.status === 'offline') {"), "{s}");
    assert_eq!(s.matches("location.reload()").count(), 1, "{s}");
    assert!(s.contains("es.close();"), "{s}");
    // DOM 定位键（worker_detail_page SSR 契约，集成测试同步钉住）。
    for key in [
        "'w-cpu-bar'",
        "'w-mem-bar'",
        "'w-load-val'",
        "'w-disk-val'",
        "'w-caps-chips'",
        "'w-hb'",
        "'w-tel-time'",
        "'w-tel-stale'",
        "'w-active-tbody'",
        "'w-recent-tbody'",
        "'w-recent-table'",
        "'w-recent-empty'",
        "'#w-recent-head .count-chip'",
        ".worker-status-badge",
    ] {
        assert!(s.contains(key), "missing {key}: {s}");
    }
    // 本地 ticker（签名去重期间相对时间仍推进）。
    assert!(s.contains("setInterval("), "{s}");
    // 双语注入：zh 相对时间与负载绝对口径模板来自同一文案表。
    let zh = worker_sse_script(5, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("秒前"), "{zh}");
    assert!(zh.contains("负载 {0} / {1} 核"), "{zh}");
    // 无 terminal-hint（worker 无相位终态横幅语义）。
    assert!(!s.contains("terminal-hint"), "{s}");
}

/// 现值条负载组就地更新契约：倍数 `toFixed(1)+'×'` 不封顶、绝对口径 title
/// 模板注入（load1 两位小数与 SSR 同精度）、缺采样置 "—" 且摘 title；
/// `#w-cpu-extra` 明文通道不得回归。
#[test]
fn worker_sse_script_load_val_updates_ratio_and_title() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(!s.contains("w-cpu-extra"), "old channel must be gone: {s}");
    assert!(
        !s.contains("CPU_VALUE"),
        "old value template must be gone: {s}"
    );
    assert!(
        s.contains("var LOAD_TITLE = '"),
        "title template missing: {s}"
    );
    assert!(
        s.contains("(Number(data.load1) / data.ncpu).toFixed(1) + '×';"),
        "{s}"
    );
    assert!(
        s.contains(
            "LOAD_TITLE.replace('{0}', Number(data.load1).toFixed(2)).replace('{1}', data.ncpu);"
        ),
        "{s}"
    );
    assert!(s.contains("loadEl.textContent = '—';"), "{s}");
    assert!(s.contains("loadEl.removeAttribute('title');"), "{s}");
}

/// 现值条磁盘行与能力 chips 的就地更新契约：磁盘绝对值走 fmtKb（缺采样
/// 落 "—"）、chips 按注入位表重建（容器缺位略过、全 0 落 "—"）、CAPS_BITS
/// 与 SSR resource_cap_bits 同源注入。
#[test]
fn worker_sse_script_updates_disk_and_caps() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    // 磁盘行：id 定位 + 非正值落 "—" + fmtKb 换算。
    assert!(
        s.contains("var diskEl = document.getElementById('w-disk-val');"),
        "{s}"
    );
    assert!(
        s.contains("diskEl.textContent = hasDisk ? fmtKb(data.disk_free_kb) : '—';"),
        "{s}"
    );
    assert!(s.contains("function fmtKb(kb) {"), "{s}");
    // 十进制单位表（与 SSR humansize DECIMAL 同纲，非二进制 KiB）。
    assert!(
        s.contains("['B', 'kB', 'MB', 'GB', 'TB', 'PB', 'EB']"),
        "{s}"
    );
    // 能力 chips：容器缺位略过（先查再动）、按位与重建、全 0 落 "—"。
    assert!(
        s.contains(
            "if (capsEl && data.resource_caps !== null && data.resource_caps !== undefined) {"
        ),
        "{s}"
    );
    assert!(
        s.contains("if (data.resource_caps & CAPS_BITS[ci][0]) {"),
        "{s}"
    );
    assert!(
        s.contains("if (!capsEl.firstChild) capsEl.textContent = '—';"),
        "{s}"
    );
    // 位表注入与 SSR 词表同源（位常量 + 机器 token）。
    assert!(
        s.contains(r#"[[1,"cgroup v2"],[2,"peak"],[4,"events"],[8,"io"],[16,"psi"]]"#),
        "{s}"
    );
}

/// Recent builds 卡整表重建：applyWorker 以 applyRecentBuilds 消费
/// recent_builds 快照——行重建时 data-start/data-done 同步回写（构建页面
/// 打开期间完成 → 下次快照起按终值结算，不按"至今"口径续涨）、行集与
/// count-chip 随快照增减、hidden 切换、末尾 refreshDurations 结算耗时。
#[test]
fn worker_sse_script_rebuilds_recent_builds_rows_with_lifecycle_writeback() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    // applyWorker 统一走整表重建，无按 id 找旧行的就地循环。
    assert!(
        !s.contains("querySelector('tr[data-recent-build=\"' + rb.id"),
        "per-row in-place update must be replaced by full rebuild: {s}"
    );
    assert!(s.contains("applyRecentBuilds(data.recent_builds);"), "{s}");
    // 耗时口径回写：data-start/data-done 来自快照字段（rb.started_at /
    // rb.completed_at），重建行带定位键与 recent-dur span。
    for key in [
        "tr.setAttribute('data-recent-build', rb.id);",
        "dur.setAttribute('data-start', rb.started_at || '');",
        "dur.setAttribute('data-done', rb.completed_at || '');",
        "dur.className = 'recent-dur';",
        "refreshDurations();",
    ] {
        assert!(s.contains(key), "missing {key}: {s}");
    }
    // 行集/count-chip/空态切换。
    assert!(s.contains("chip.textContent = rows.length;"), "{s}");
    assert!(s.contains("table.hidden = !has;"), "{s}");
    assert!(s.contains("empty.hidden = has;"), "{s}");
    // 重建行消费 pkg_name（sse.rs 负载侧同步补齐该字段）。
    assert!(s.contains("tdPkg.textContent = rb.pkg_name || '';"), "{s}");
    // 未开跑行占位与 SSR 同口径（"—"）。
    assert!(
        s.contains("if (!rb.started_at) dur.textContent = '—';"),
        "{s}"
    );
}

/// 活动表重建行 started_at 缺失时与 SSR rel_time_lang 同落 "—"，
/// 且 ticker setRel 对解析失败行不覆写文本。
#[test]
fn worker_sse_script_active_row_null_start_renders_dash() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(
        s.contains("if (!b.started_at) rel.textContent = '—';"),
        "{s}"
    );
    // setRel 对坏帧/缺值早退，"—" 占位不被 ticker 抖掉。
    assert!(s.contains("var ts = parseDbTs(el.getAttribute('data-ts'));\n                    if (ts === null) return;"), "{s}");
}

/// 阈值单源注入钉死：REL_ABS_DAYS == SSR REL_TIME_ABSOLUTE_DAYS、
/// LOAD_WARN/LOAD_CRIT == load_level 具名常量——worker 脚本不双写魔数，
/// 改 SSR 常量即两侧同动；漏注入（数值回退硬编码）在此红。
#[test]
fn worker_sse_script_thresholds_injected_from_ssr_consts() {
    let s = worker_sse_script(5, "nonce", Lang::En).into_string();
    assert!(
        s.contains(&format!("var REL_ABS_DAYS = {REL_TIME_ABSOLUTE_DAYS};")),
        "{s}"
    );
    // 长龄绝对化分支：超阈值改显本地日期（与 SSR 刷新结果一致）。
    assert!(
        s.contains("if (secs > REL_ABS_DAYS * 86400) return localStamp(new Date(ts), false);"),
        "{s}"
    );
    assert!(
        s.contains(&format!("var LOAD_WARN = {LOAD_LEVEL_WARN_PCT};")),
        "{s}"
    );
    assert!(
        s.contains(&format!("var LOAD_CRIT = {LOAD_LEVEL_CRIT_PCT};")),
        "{s}"
    );
    assert!(
        s.contains("return pct < LOAD_WARN ? 'success' : (pct <= LOAD_CRIT ? 'warn' : 'failure');"),
        "{s}"
    );
    // title 与 SSR format_local_time 同格式（本地手拼）；toLocaleString
    // 随 locale 漂移，绝迹。日期与时间两用同一 helper。
    assert!(!s.contains("toLocaleString"), "{s}");
    assert!(
        s.contains("el.title = localStamp(new Date(ts), true);"),
        "{s}"
    );
    assert!(s.contains("function localStamp(d, withTime) {"), "{s}");
}
