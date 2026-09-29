// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建详情页 SSE 脚本测试。

use super::*;

/// build 详情页脚本消费 timeline 事件（定位/改写/回写/append）；task 页不注入。
#[test]
fn build_sse_script_handles_timeline_event() {
    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert!(
        build.contains("es.addEventListener('timeline'"),
        "timeline listener missing: {build}"
    );
    assert!(build.contains("function applyTimeline("), "{build}");
    // DOM 契约：.phase-timeline 直属 .phase-step[data-phase]，className 整串改写。
    assert!(
        build.contains(".phase-timeline"),
        "timeline container lookup missing: {build}"
    );
    // findStep 遍历比对：name 用户可控，querySelector 拼接必须绝迹（引号即 SyntaxError）。
    assert!(
        build.contains("function findStep(timeline, name)"),
        "findStep helper missing: {build}"
    );
    assert!(
        build.contains("getAttribute('data-phase') === name"),
        "data-phase equality lookup missing: {build}"
    );
    assert!(
        !build.contains(".phase-step[data-phase=\"' + name + '\"]"),
        "querySelector concat with user-controlled name must be gone: {build}"
    );
    assert!(
        build.contains("el.className = 'phase-step ' + sp.state"),
        "className rewrite missing: {build}"
    );
    assert!(build.contains("phase-step-detail"), "{build}");
    // running 步骤画 "…"（与 SSR phase_timeline 同文案）；skipped 回退词。
    assert!(build.contains("'\\u2026'"), "{build}");
    assert!(build.contains("skipped"), "{build}");
    // append 裸形态（无 tl-node/tl-text，style.css 契约）+ STEP_LABELS 回填。
    assert!(build.contains("function timelineStepEl("), "{build}");
    assert!(build.contains("STEP_LABELS[name] || name"), "{build}");
    // 隐藏工具步骤（真源 HIDDEN_TOOL_PHASES）：名单注入 + 显式跳过。
    assert!(
        build.contains("var HIDDEN_PHASES = {\"ccache-init\":1,\"ccache-summary\":1};"),
        "hidden-phase map missing: {build}"
    );
    assert!(
        build.contains("if (HIDDEN_PHASES[sp.name]) continue;"),
        "timeline skip for hidden phases missing: {build}"
    );
    assert!(
        !build.contains("\"ccache-init\":\"ccache-init\""),
        "STEP_LABELS must not carry hidden phases: {build}"
    );
    // zh 页步骤名映射注入本地化标签（与 SSR phase_step_label 同表）。
    let zh = build_sse_script(7, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("\"build\":\"构建\""), "{zh}");

    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    assert!(
        !task.contains("timeline"),
        "task page must not carry timeline logic: {task}"
    );
}
