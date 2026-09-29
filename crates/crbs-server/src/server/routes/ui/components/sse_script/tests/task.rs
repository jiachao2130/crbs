// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务详情页 SSE 脚本测试。

use super::*;

#[test]
fn task_sse_script_updates_children_cells_and_build_variant_does_not() {
    // task 页按 [data-build-id] 定位子构建 cell，duration>0 刷新
    // .arch-duration（fmtDur 同服务端格式）；span 缺位经 archDurEl 补建
    // （title 同 SSR、append 到 cell 末位）；build 页不注入。
    let task = task_sse_script(9, "nonce", Lang::En).into_string();
    assert!(task.contains("updateChildren(data.children)"), "{task}");
    assert!(
        task.contains(r#"'[data-build-id="' + ch.id + '"]'"#),
        "{task}"
    );
    assert!(task.contains("'badge ' + modClass(ch.phase)"), "{task}");
    assert!(
        task.contains("archDurEl(cell).textContent = fmtDur(ch.duration);"),
        "{task}"
    );
    assert!(task.contains("function archDurEl(cell)"), "{task}");
    assert!(task.contains("dur.className = 'arch-duration';"), "{task}");
    assert!(task.contains("cell.appendChild(dur);"), "{task}");
    assert!(task.contains("var ARCH_DUR_TITLE = 'duration';"), "{task}");
    let zh = task_sse_script(9, "nonce", Lang::Zh).into_string();
    assert!(zh.contains("var ARCH_DUR_TITLE = '时长';"), "{zh}");

    let build = build_sse_script(7, "nonce", Lang::En).into_string();
    assert!(!build.contains("updateChildren"), "{build}");
    assert!(!build.contains("data-build-id"), "{build}");
}
