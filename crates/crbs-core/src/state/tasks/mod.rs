// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Task 状态存储方法。

use std::collections::HashMap;

use sqlx::Row;

use super::{
    build_record_from_row, BuildRecord, Dialect, StateStore, TaskInsert, TaskRebuildInfo,
    TaskRecord, BUILD_COLUMNS,
};
use crate::error::DbResultExt;
use crate::types::BuildPriority;

mod lifecycle;
mod query;
mod queue;
mod stats;
#[cfg(test)]
mod tests;

pub(crate) use lifecycle::aggregate_task_phase_on;
#[cfg(test)]
use lifecycle::complete_task_on;
pub(crate) use lifecycle::finalize_cancelled_task_on;
#[cfg(test)]
use lifecycle::update_task_phase_on;
pub use lifecycle::FinalizeOutcome;
