// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 任务详情 SSE 脚本。

use maud::Markup;

use crate::server::routes::ui::i18n::Lang;

use super::phase::{phase_sse_script, PhaseSseScriptOpts};

/// task 详情页版本：附带 children 增量更新（arch 矩阵实时）；无 .lc-so-far 走秒行。
pub(crate) fn task_sse_script(task_id: i64, nonce: &str, lang: Lang) -> Markup {
    phase_sse_script(PhaseSseScriptOpts {
        base_path: "/ui/tasks",
        event_name: "task",
        id: task_id,
        nonce,
        with_children: true,
        with_timeline: false,
        with_elapsed: false,
        lang,
    })
}
