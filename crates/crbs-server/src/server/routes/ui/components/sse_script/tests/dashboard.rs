// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 仪表盘 SSE 脚本测试。

use super::*;

#[test]
fn dashboard_sse_script_updates_donut_legend_and_workers() {
    // status payload（StatusResponse serde 命名）重算六段环与图例/环心/workers；id/类名契约见 style.css 头注。
    let s = dashboard_sse_script("nonce", Lang::En).into_string();
    assert!(s.contains("running: t.building"), "{s}");
    assert!(s.contains("queued: t.pending"), "{s}");
    for phase in ["succeeded", "failed", "timeout", "cancelled"] {
        assert!(
            s.contains(&format!("{phase}: t.{phase}")),
            "payload field {phase} must feed the donut: {s}"
        );
    }
    assert!(s.contains("circle.seg[data-phase="), "{s}");
    assert!(s.contains(".legend-row[data-phase="), "{s}");
    assert!(s.contains("querySelector('.count')"), "{s}");
    assert!(s.contains("querySelector('.pct')"), "{s}");
    // 图例 title 随 count/pct 重算（模板 + 一位小数 + 整句 replace）。
    assert!(
        s.contains("var TITLE_PATTERN = '{0} · {1} {3} · {2}% — click to view list';"),
        "{s}"
    );
    assert!(s.contains("row.title = TITLE_PATTERN"), "{s}");
    // 段名替换走回调：`$` 在 replace 参数有特殊语义，segName 来自 DOM 文本。
    assert!(
        s.contains(".replace('{0}', function() { return segName; })"),
        "{s}"
    );
    assert!(s.contains(".replace('{2}', pct1)"), "{s}");
    assert!(s.contains("var TITLE_NAME_FROM_KEY = true;"), "{s}");
    let zh = dashboard_sse_script("nonce", Lang::Zh).into_string();
    assert!(
        zh.contains("var TITLE_PATTERN = '{0} · {1} 个任务 · {2}% — 点击查看列表';"),
        "{zh}"
    );
    assert!(zh.contains("var TITLE_NAME_FROM_KEY = false;"), "{zh}");
    for id in [
        "dash-donut-total",
        "dash-donut-running",
        "dash-donut-queued",
        "dash-workers-online",
    ] {
        assert!(
            s.contains(&format!("getElementById('{id}')")),
            "SSE script must update #{id}: {s}"
        );
    }
    assert!(s.contains("EventSource('/ui/events')"), "{s}");
    // hover 联动与 live 断连切换保留。
    assert!(s.contains("classList.toggle('dimmed'"), "{s}");
    assert!(s.contains(".live-indicator"), "{s}");
    // CLOSED 终态文案：永久关闭后 title 不再声称重连；zh 同键注入。
    assert!(s.contains("es.readyState === EventSource.CLOSED"), "{s}");
    assert!(s.contains("el.title = 'Connection closed';"), "{s}");
    assert!(zh.contains("el.title = '连接已关闭';"), "{zh}");
}

/// 空态满环互操作：total=0 时 SSR 一枚中性满环（circle.seg-empty），首个
/// 非空 status 到达须移除（否则灰环叠成双环）；total 回落 0 时按 SSR
/// 同形态重建（否则无弧亦无灰环直到 reload）。
#[test]
fn dashboard_sse_script_removes_and_restores_empty_state_ring() {
    let s = dashboard_sse_script("nonce", Lang::En).into_string();
    assert!(
        s.contains("querySelector('circle.seg-empty')"),
        "empty-state ring lookup missing: {s}"
    );
    assert!(s.contains("emptyRing.remove()"), "{s}");
    // 移除以 total>0 为守卫（全零 status 不清空态环），守卫先于移除调用。
    let guard_at = s.find("if (r.total > 0)").expect("total guard");
    let remove_at = s.find("emptyRing.remove()").expect("remove call");
    assert!(
        guard_at < remove_at,
        "removal must be gated on total > 0: {s}"
    );
    // 复原分支：total=0 且环不在时按 SSR 形态重建。
    assert!(
        s.contains("createElementNS('http://www.w3.org/2000/svg', 'circle')"),
        "empty ring must be rebuilt as an SVG-namespaced element: {s}"
    );
    assert!(
        s.contains("emptyRing.setAttribute('r', String(R));"),
        "rebuilt ring radius must derive from the script's R constant: {s}"
    );
    assert!(
        s.contains("g.insertBefore(emptyRing, g.firstChild);"),
        "rebuilt ring must sit before the seg circles (SSR renders it first): {s}"
    );
}
