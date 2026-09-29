// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! BuildEngine GC 子模块入口：`orphan`（孤儿挂载清理与僵尸构建修复）、
//! `results`（结果目录 GC：grace-hours / policy）。

mod orphan;
mod results;

pub(crate) use orphan::should_skip_orphan_cleanup;
pub use orphan::{repair_zombie_builds, OrphanScanRoots};
pub use results::{run_result_gc_standalone, ResultGcOutcome};
