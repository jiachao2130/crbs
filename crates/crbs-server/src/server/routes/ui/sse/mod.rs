// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Web UI 实时 SSE 端点：按数据域拆分，共享件见 [`common`]。

#[macro_use]
mod common;
mod build;
mod dashboard;
mod log;
mod task;
#[cfg(test)]
mod tests;
mod worker;

pub(crate) use build::build_sse;
pub(crate) use common::sse_db_retry_backoff_multiplier;
pub(crate) use dashboard::dashboard_sse;
pub(crate) use log::log_sse;
pub(crate) use task::task_sse;
pub(crate) use worker::worker_sse;
