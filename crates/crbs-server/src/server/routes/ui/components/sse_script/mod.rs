// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! SSE 内联脚本组件：按页面拆分，共享片段见 [`common`]。

mod build;
mod common;
mod dashboard;
mod log;
mod notify;
mod phase;
mod task;
#[cfg(test)]
mod tests;
mod worker;

pub(crate) use build::build_sse_script;
pub(crate) use common::js_str;
pub(crate) use dashboard::dashboard_sse_script;
pub(crate) use log::{log_line_anchor_script, log_sse_script, pending_log_sse_script};
pub(crate) use notify::notify_button;
pub(crate) use task::task_sse_script;
pub(crate) use worker::worker_sse_script;
