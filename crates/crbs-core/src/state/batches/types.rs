// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次记录、进度聚合与写入参数。

/// 批次行（`build_batches` 全列；`force_all` 以 bool 透出）。
#[derive(Debug, Clone)]
pub struct BatchRecord {
    pub id: i64,
    pub product_id: Option<i64>,
    pub created_by: Option<i64>,
    pub status: String,
    pub source_repo_url: String,
    /// repodata 指纹，防规划期源仓漂移；规划完成前可为 NULL。
    pub source_fingerprint: Option<String>,
    /// NULL = 产品默认 dist。
    pub dist: Option<String>,
    /// 序列化的目标架构列表 JSON，原样透传。
    pub arch_targets: Option<String>,
    pub on_failure: String,
    pub force_all: bool,
    pub total_items: i64,
    pub n_succeeded: i64,
    pub n_failed: i64,
    pub n_skipped: i64,
    pub n_cancelled: i64,
    pub request_json: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

/// 批次项行（`batch_items` 全列）。
#[derive(Debug, Clone)]
pub struct BatchItemRecord {
    pub id: i64,
    pub batch_id: i64,
    pub pkg_name: String,
    pub srpm_nevra: Option<String>,
    pub srpm_staging_path: Option<String>,
    /// 拓扑轮次；0 = 环/未解析（先试构建）。
    pub round: i64,
    pub state: String,
    /// 进入 pending 的次数（首次为 0，每次恢复轮 reset +1）。
    pub attempt: i64,
    pub task_id: Option<i64>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub updated_at: String,
}

/// 项状态计数聚合（[`StateStore::batch_item_summary`](crate::state::StateStore::batch_item_summary) 产物）。`failed_with_task` 是 failed
/// 子集（已建 task）；准备期失败项无 task_id 只进 failed，供 on_failure=abort 判定真构建失败。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchProgress {
    pub pending: i64,
    pub released: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub failed_with_task: i64,
    pub dep_skipped: i64,
    pub skipped_conflict: i64,
    /// plan 期因 spec 架构约束（ExclusiveArch/ExcludeArch）与批次 arch 目标
    /// 不兼容而跳过的项（带原因落 error_code/error_message）。
    pub arch_skipped: i64,
    pub cancelled: i64,
}

impl BatchProgress {
    /// 全部状态计数之和（= 该批次项总数）。
    pub fn total(&self) -> i64 {
        self.pending
            + self.released
            + self.succeeded
            + self.failed
            + self.dep_skipped
            + self.skipped_conflict
            + self.arch_skipped
            + self.cancelled
    }

    /// 已进终态的项数（与 `build_batches.n_*` 之和同口径）。
    pub fn terminal(&self) -> i64 {
        self.succeeded
            + self.failed
            + self.dep_skipped
            + self.skipped_conflict
            + self.arch_skipped
            + self.cancelled
    }
}

/// 新批次项插入参数（[`StateStore::insert_batch_items`](crate::state::StateStore::insert_batch_items) 用）。
#[derive(Debug, Clone)]
pub struct NewBatchItem<'a> {
    pub pkg_name: &'a str,
    pub srpm_nevra: Option<&'a str>,
    pub srpm_staging_path: Option<&'a str>,
    pub round: i64,
}

/// 准备期失败项插入参数（[`StateStore::insert_failed_batch_items`](crate::state::StateStore::insert_failed_batch_items) 用）：
/// 无暂存路径（下载未成功），错误码/错误信息必填落账。
#[derive(Debug, Clone)]
pub struct FailedBatchItem<'a> {
    pub pkg_name: &'a str,
    pub srpm_nevra: Option<&'a str>,
    pub error_code: &'a str,
    pub error_message: &'a str,
}

/// plan 期架构跳过项插入参数（[`StateStore::insert_arch_skipped_batch_items`](crate::state::StateStore::insert_arch_skipped_batch_items) 用）：
/// 暂存路径保留（SRPM 已下载，仅不构建）；错误信息必填（点名不兼容 arch 与约束取值）。
#[derive(Debug, Clone)]
pub struct SkippedBatchItem<'a> {
    pub pkg_name: &'a str,
    pub srpm_nevra: Option<&'a str>,
    pub srpm_staging_path: Option<&'a str>,
    pub error_code: &'a str,
    pub error_message: &'a str,
}

/// 批次行插入参数。
pub struct BatchInsert<'a> {
    pub product_id: Option<i64>,
    pub created_by: Option<i64>,
    pub source_repo_url: &'a str,
    pub dist: Option<&'a str>,
    pub arch_targets_json: Option<&'a str>,
    pub on_failure: &'a str,
    pub force_all: bool,
    pub request_json: Option<&'a str>,
}
