// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批次 SQL 语句（双方言 `NOW()` 由 [`Dialect`] 生成）。

use crate::state::Dialect;

/// 在途状态 SQL 片段（终态 CAS 的 IN 列表）；字面量与 baseline CHECK 约束同步，漂移由 CHECK 拒写暴露。
const ACTIVE_STATUS_LIST_SQL: &str = "('preparing', 'planning', 'running')";

/// 批次配额的事务级 advisory lock 键（PostgreSQL）。与 schema 迁移闩
/// （524372339）互异，避免批次创建与迁移互堵。
pub(super) const PG_BATCH_QUOTA_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock(524372340)";

pub(super) const BATCH_COLUMNS: &str = "id, product_id, created_by, status, source_repo_url, \
     source_fingerprint, dist, arch_targets, on_failure, force_all, total_items, \
     n_succeeded, n_failed, n_skipped, n_cancelled, request_json, notes, created_at, \
     started_at, finished_at";

pub(super) const ITEM_COLUMNS: &str = "id, batch_id, pkg_name, srpm_nevra, \
     srpm_staging_path, round, state, attempt, task_id, error_code, error_message, updated_at";

/// 建批次行：status 显式落 'preparing'，created_at 走列 DEFAULT（双方言同）。
pub(super) const INSERT_BATCH: &str = "INSERT INTO build_batches \
     (product_id, created_by, status, source_repo_url, dist, arch_targets, on_failure, \
      force_all, request_json) \
     VALUES ($1, $2, 'preparing', $3, $4, $5, $6, $7, $8) RETURNING id";

/// preparing → planning CAS；started_at 在此落值（离开 preparing 即视为开始）。0 行 = 竞态 → Conflict。
pub(super) fn set_batch_planning(dialect: Dialect) -> String {
    format!(
        "UPDATE build_batches SET status = 'planning', started_at = {} \
         WHERE id = $1 AND status = 'preparing'",
        dialect.sql_now()
    )
}

/// planning → running CAS + total_items 同语句原子落值（隐式事务，无半写）。
pub(super) const SET_BATCH_RUNNING: &str = "UPDATE build_batches \
     SET status = 'running', total_items = $2 WHERE id = $1 AND status = 'planning'";

/// 非终态 → 终态 CAS（finished_at 落值）。0 行 = 已终态（先到者生效）。
pub(super) fn finish_batch(dialect: Dialect) -> String {
    format!(
        "UPDATE build_batches SET status = $2, finished_at = {}, notes = $3 \
         WHERE id = $1 AND status IN {ACTIVE_STATUS_LIST_SQL}",
        dialect.sql_now()
    )
}

pub(super) const SELECT_BATCH_COUNTERS: &str = "SELECT total_items, n_succeeded, n_failed, \
     n_skipped, n_cancelled FROM build_batches WHERE id = $1";

/// 按 id 取批次全列（列清单单源）。
pub(super) fn batch_by_id() -> String {
    format!("SELECT {BATCH_COLUMNS} FROM build_batches WHERE id = $1")
}

/// 批次列表（id DESC，limit 必传；limit <= 0 在 Rust 侧短路返回空）。
pub(super) fn list_batches() -> String {
    format!("SELECT {BATCH_COLUMNS} FROM build_batches ORDER BY id DESC LIMIT $1")
}

/// 产品在途批次：按 id DESC 取首条；"每产品至多一个在途"是调用方约定，本查询不保证。
pub(super) const ACTIVE_BATCH_FOR_PRODUCT: &str = "SELECT id FROM build_batches \
     WHERE product_id = $1 AND status IN ('preparing', 'planning', 'running') \
     ORDER BY id DESC LIMIT 1";

/// 同 [`ACTIVE_BATCH_FOR_PRODUCT`]，附带产品名（配额拒绝文案用）。
pub(super) const ACTIVE_BATCH_FOR_PRODUCT_NAMED: &str = "SELECT b.id, p.name \
     FROM build_batches b JOIN products p ON p.id = b.product_id \
     WHERE b.product_id = $1 AND b.status IN ('preparing', 'planning', 'running') \
     ORDER BY b.id DESC LIMIT 1";

pub(super) const COUNT_ACTIVE_BATCHES: &str = "SELECT COUNT(*) FROM build_batches \
     WHERE status IN ('preparing', 'planning', 'running')";

/// 建计划项：state 显式落 'pending'（列无 DEFAULT），attempt/updated_at 走列 DEFAULT。
pub(super) const INSERT_ITEM: &str = "INSERT INTO batch_items \
     (batch_id, pkg_name, srpm_nevra, srpm_staging_path, round, state) \
     VALUES ($1, $2, $3, $4, $5, 'pending')";

/// 建准备期失败项：state/round/attempt 直接落 'failed'/0/0（绕过 pending→released
/// 状态机：无 task、无释放语义，attempt 语义是"进 pending 次数"本就为 0），暂存
/// 路径恒 NULL（不得让恢复路径认领半截产物），n_failed 由调用方同事务 bump。
pub(super) const INSERT_FAILED_ITEM: &str = "INSERT INTO batch_items \
     (batch_id, pkg_name, srpm_nevra, srpm_staging_path, round, state, error_code, \
      error_message) \
     VALUES ($1, $2, $3, NULL, 0, 'failed', $4, $5)";

/// 建 plan 期架构跳过项：直落终态 'arch_skipped'/round 0/attempt 0（同
/// INSERT_FAILED_ITEM 的"绕过状态机"理由）；暂存路径保留（下载成功、仅不
/// 构建，批次级清理照旧），n_skipped 由调用方同事务 bump。
pub(super) const INSERT_ARCH_SKIPPED_ITEM: &str = "INSERT INTO batch_items \
     (batch_id, pkg_name, srpm_nevra, srpm_staging_path, round, state, error_code, \
      error_message) \
     VALUES ($1, $2, $3, $4, 0, 'arch_skipped', $5, $6)";

/// 批次 notes 更新（仅非终态可写，终态是历史账本）；无 now() 落值列，双方言
/// 同一条 SQL，状态字面量与 baseline CHECK 同步（同 [`ACTIVE_STATUS_LIST_SQL`]）。
pub(super) const SET_BATCH_NOTES: &str = "UPDATE build_batches SET notes = $2 \
     WHERE id = $1 AND status IN ('preparing', 'planning', 'running')";

/// 清批次计划：仅非终态批次可清（终态批次是历史账本，计划不得再动）。
pub(super) const DELETE_BATCH_ITEMS: &str = "DELETE FROM batch_items WHERE batch_id = $1 \
     AND EXISTS (SELECT 1 FROM build_batches b WHERE b.id = batch_items.batch_id \
                 AND b.status IN ('preparing', 'planning', 'running'))";

pub(super) fn items_in_round() -> String {
    format!(
        "SELECT {ITEM_COLUMNS} FROM batch_items WHERE batch_id = $1 AND round = $2 \
         ORDER BY id ASC"
    )
}

pub(super) const BATCH_ROUNDS: &str =
    "SELECT DISTINCT round FROM batch_items WHERE batch_id = $1 ORDER BY round ASC";

pub(super) fn batch_item_summary() -> &'static str {
    // CASE WHEN 聚合双方言通用（FILTER 是 PG 专属）；COALESCE 兜空批次（SUM 空集为 NULL）。
    "SELECT \
       COALESCE(SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END), 0) AS pending, \
       COALESCE(SUM(CASE WHEN state = 'released' THEN 1 ELSE 0 END), 0) AS released, \
       COALESCE(SUM(CASE WHEN state = 'succeeded' THEN 1 ELSE 0 END), 0) AS succeeded, \
       COALESCE(SUM(CASE WHEN state = 'failed' THEN 1 ELSE 0 END), 0) AS failed, \
       COALESCE(SUM(CASE WHEN state = 'failed' AND task_id IS NOT NULL THEN 1 ELSE 0 END), 0) \
         AS failed_with_task, \
       COALESCE(SUM(CASE WHEN state = 'dep_skipped' THEN 1 ELSE 0 END), 0) AS dep_skipped, \
       COALESCE(SUM(CASE WHEN state = 'skipped_conflict' THEN 1 ELSE 0 END), 0) AS skipped_conflict, \
       COALESCE(SUM(CASE WHEN state = 'arch_skipped' THEN 1 ELSE 0 END), 0) AS arch_skipped, \
       COALESCE(SUM(CASE WHEN state = 'cancelled' THEN 1 ELSE 0 END), 0) AS cancelled \
     FROM batch_items WHERE batch_id = $1"
}

pub(super) fn items_in_state() -> String {
    format!(
        "SELECT {ITEM_COLUMNS} FROM batch_items WHERE batch_id = $1 AND state = $2 \
         ORDER BY id ASC"
    )
}

pub(super) fn unfinished_items() -> String {
    format!(
        "SELECT {ITEM_COLUMNS} FROM batch_items WHERE batch_id = $1 \
         AND state IN ('pending', 'released') ORDER BY id ASC"
    )
}

/// 释放门禁二合一：项 pending CAS + 批次 running EXISTS 守卫（消除"查状态再更新"的
/// TOCTOU 窗口）。released 非终态，计数器不动。
pub(super) fn mark_item_released(dialect: Dialect) -> String {
    format!(
        "UPDATE batch_items SET state = 'released', task_id = $3, updated_at = {} \
         WHERE id = $2 AND batch_id = $1 AND state = 'pending' \
           AND EXISTS (SELECT 1 FROM build_batches b \
                       WHERE b.id = $1 AND b.status = 'running')",
        dialect.sql_now()
    )
}

/// 项终态 CAS：仅 released 可进终态（pending 未派发，走 fail_unfinished_items）；
/// 计数器由调用方在同事务内追加语句。
pub(super) fn mark_item_terminal(dialect: Dialect) -> String {
    format!(
        "UPDATE batch_items SET state = $3, error_code = $4, error_message = $5, \
         updated_at = {} WHERE batch_id = $1 AND id = $2 AND state = 'released'",
        dialect.sql_now()
    )
}

/// 计数器 +1（列名来自 terminal_counter_column 的固定映射，无外部输入）。
pub(super) fn bump_counter(column: &str) -> String {
    format!("UPDATE build_batches SET {column} = {column} + 1 WHERE id = $1")
}

/// 恢复轮：failed → pending，attempt +1，错误信息清空；n_failed 由调用方同事务
/// 按翻转行数减回。批次 running 是 CAS 前置条件（同 [`mark_item_released`]）：
/// 取消/终态收尾与恢复轮并发时，终态批次不得被翻回 pending（计数漂移且再无
/// 驱动器收尾）。
pub(super) fn reset_items_to_pending(dialect: Dialect, placeholders: &str) -> String {
    format!(
        "UPDATE batch_items SET state = 'pending', attempt = attempt + 1, \
         error_code = NULL, error_message = NULL, updated_at = {} \
         WHERE batch_id = $1 AND id IN ({placeholders}) AND state = 'failed' \
           AND EXISTS (SELECT 1 FROM build_batches b \
                       WHERE b.id = $1 AND b.status = 'running')",
        dialect.sql_now()
    )
}

/// 收尾翻转前的在途 task 快照（与 UPDATE 同一写事务）：调用方据此取消
/// 在途构建，避免"先快照 released、后翻转状态"窗口漏掉刚释放的项。
pub(super) const UNFINISHED_TASK_IDS: &str = "SELECT task_id FROM batch_items \
     WHERE batch_id = $1 AND state IN ('pending', 'released') AND task_id IS NOT NULL";

/// 中止/取消收尾：pending 与 released 项统一收口 failed，计数器调用方同事务按翻转行数同步。
pub(super) fn fail_unfinished_items(dialect: Dialect) -> String {
    format!(
        "UPDATE batch_items SET state = 'failed', error_code = $2, error_message = $3, \
         updated_at = {} WHERE batch_id = $1 AND state IN ('pending', 'released')",
        dialect.sql_now()
    )
}

/// 派发失败直收终态 CAS：pending → 终态（驱动器 task 创建/启动失败路径，项从未
/// released、无 task 可挂；skipped_conflict 与派发 failed 均走此）。计数器调用方同事务追加。
pub(super) fn mark_pending_item_terminal(dialect: Dialect) -> String {
    format!(
        "UPDATE batch_items SET state = $3, error_code = $4, error_message = $5, \
         updated_at = {} WHERE batch_id = $1 AND id = $2 AND state = 'pending'",
        dialect.sql_now()
    )
}

/// 取消收尾：pending/released 统一收口 cancelled（fail_unfinished_items 的镜像），
/// 计数器调用方同事务按翻转行数同步。
pub(super) fn cancel_unfinished_items(dialect: Dialect) -> String {
    format!(
        "UPDATE batch_items SET state = 'cancelled', error_code = $2, error_message = $3, \
         updated_at = {} WHERE batch_id = $1 AND state IN ('pending', 'released')",
        dialect.sql_now()
    )
}
