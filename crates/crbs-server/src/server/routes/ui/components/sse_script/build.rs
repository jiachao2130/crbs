// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 构建详情 SSE 脚本。

use maud::Markup;

use crate::server::routes::ui::i18n::Lang;

use super::phase::{phase_sse_script, PhaseSseScriptOpts};

/// build 详情页版本：附带时间线增量更新（`event: timeline` 的 spans 状态）
/// 与 Lifecycle"至今"行走秒器（pending 排队 / running 时长）。
pub(crate) fn build_sse_script(build_id: i64, nonce: &str, lang: Lang) -> Markup {
    phase_sse_script(PhaseSseScriptOpts {
        base_path: "/ui/builds",
        event_name: "build",
        id: build_id,
        nonce,
        with_children: false,
        with_timeline: true,
        with_elapsed: true,
        lang,
    })
}
