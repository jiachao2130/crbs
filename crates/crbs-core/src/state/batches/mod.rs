// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次存储：`build_batches` / `batch_items` 表的写路径与查询。
//!
//! 状态机：批次 preparing → planning → running → 终态（completed/partial/
//! failed/cancelled）；项 pending → released → 终态，失败项可 reset 回 pending，
//! 待派发项与未完成项可分别直接收口。项终态为 succeeded / failed / dep_skipped /
//! skipped_conflict / arch_skipped / cancelled。
//!
//! 计数器口径（单一事实源）：`n_*` 是项终态的镜像聚合，与项状态同事务维护，
//! 任意时刻 `sum(n_*) == 已终态项数`，全部终态时 `== total_items`；finish 时
//! 对账，漂移显式报错。减向仅 reset（failed → pending 减 n_failed）与清空计划
//!（按被删行终态减全部 n_*，否则计划失败/取消会卡死配额）。

mod insert;
mod lifecycle;
mod query;
mod sql;
#[cfg(test)]
mod tests;
mod types;

pub use types::{
    BatchInsert, BatchItemRecord, BatchProgress, BatchRecord, FailedBatchItem, NewBatchItem,
    SkippedBatchItem,
};
