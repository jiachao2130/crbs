// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 终态完成公共咽喉：参数载体、统一 UPDATE、任务相位聚合与计数归约。

use std::collections::HashMap;

use super::sql;
use crate::engine::ResourceUsage;
use crate::error::DbResultExt;
use crate::state::Dialect;
use crate::types::{build_phase_is_terminal, BuildPriority};

/// error_summary 字节上限（截断保留前缀）：防超长自由文本写入单行。
pub(super) const MAX_ERROR_SUMMARY_BYTES: usize = 1024;

/// 截断到 `<= max` 字节（UTF-8 字符边界安全；找不到可行边界时返回空串）。
pub(super) fn truncate_to_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let boundary = s
        .char_indices()
        .take_while(|(i, ch)| i + ch.len_utf8() <= max)
        .map(|(i, ch)| i + ch.len_utf8())
        .last()
        .unwrap_or(0);
    &s[..boundary]
}

/// [`complete_build_update`] 的参数集（executor 属泛型借用，留作独立参数）。
pub(crate) struct CompleteBuildParams<'a> {
    pub(crate) dialect: Dialect,
    pub(crate) id: i64,
    pub(crate) phase: &'a str,
    pub(crate) result_dir: Option<&'a str>,
    pub(crate) error: Option<&'a str>,
    pub(crate) worker_id: Option<i64>,
    pub(crate) resources: Option<&'a ResourceUsage>,
}

/// `complete_build` 族唯一公共咽喉 UPDATE（任意 executor，事务内可复用）：
/// phase 终态白名单在此收口，非法值 fail-closed `ValidationFailed`（非裸
/// Database 错误）。`worker_id` 归属谓词：None 供无 assignment 行可考的
/// 路径（fail_assignment 已自证归属且先行删行、引擎本地构建），worker 上
/// 报传 Some；返回行数 0 = 守卫或归属谓词拒绝。`resources` None = 不采集，
/// 资源列落 NULL——绝不让缺数据阻塞终态写入。
pub(crate) async fn complete_build_update<'e, E>(
    executor: E,
    params: CompleteBuildParams<'_>,
) -> crate::Result<u64>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let CompleteBuildParams {
        dialect,
        id,
        phase,
        result_dir,
        error,
        worker_id,
        resources,
    } = params;
    if !build_phase_is_terminal(phase) {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: format!(
                "invalid terminal build phase '{phase}': only 'succeeded', 'failed', 'cancelled' or 'timeout' are allowed"
            ),
        });
    }
    // 浮点列 TEXT 绑定 + SQL CAST：绕开 sqlx Any 驱动 NULL 浮点钉 FLOAT4 的坑。
    let (peak_rss_kb, cpu_secs, cpu_p90_cores) = match resources {
        Some(r) => (
            r.peak_rss_kb,
            r.cpu_secs.map(|v| v.to_string()),
            r.cpu_p90_cores.map(|v| v.to_string()),
        ),
        None => (None, None, None),
    };
    // 采集包络五列 + tmpfs 峰值：None 资源 → 全 NULL；oom_killed bool 折 0/1
    // 绑定（双方言 INTEGER 列 CHECK IN (0,1) 同语义），新绑定接队尾（占位符
    // 序=绑定序）。
    let (peak_total_kb, disk_wbytes, oom_killed, sample_backend, sample_ncpu, peak_tmpfs_kb) =
        match resources {
            Some(r) => (
                r.peak_total_kb,
                r.disk_wbytes,
                r.oom_killed.map(i64::from),
                r.sample_backend,
                r.sample_ncpu,
                r.peak_tmpfs_kb,
            ),
            None => (None, None, None, None, None, None),
        };
    let affected = sqlx::query(&sql::complete_build(dialect))
        .bind(phase)
        .bind(result_dir)
        .bind(id)
        .bind(error)
        .bind(worker_id)
        .bind(peak_rss_kb)
        .bind(cpu_secs)
        .bind(cpu_p90_cores)
        .bind(peak_total_kb)
        .bind(disk_wbytes)
        .bind(oom_killed)
        .bind(sample_backend)
        .bind(sample_ncpu)
        .bind(peak_tmpfs_kb)
        .execute(executor)
        .await
        .db_ctx("complete build")?
        .rows_affected();
    Ok(affected)
}

/// 取 build 所属 task_id（事务内/池上共用；只取聚合所需单列）。
async fn task_id_of_build_on(
    conn: &mut sqlx::AnyConnection,
    build_id: i64,
) -> crate::Result<Option<i64>> {
    let task_id: Option<Option<i64>> =
        sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(build_id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("get build task id")?;
    Ok(task_id.flatten())
}

/// 同写事务连接上 best-effort 聚合 build 所属 task 的 phase：task_id 查询
/// 失败上抛（随主路径回滚），聚合本身失败仅 warn 不阻塞 COMMIT——phase 更新 /
/// complete / cancel 三个事务信封共用。必须用本事务连接（池连接提交后跑会与
/// 主更新分裂）。
pub(super) async fn aggregate_task_phase_best_effort(
    conn: &mut sqlx::AnyConnection,
    dialect: Dialect,
    build_id: i64,
    after: &'static str,
) -> crate::Result<()> {
    if let Some(task_id) = task_id_of_build_on(conn, build_id).await? {
        if let Err(e) = crate::state::tasks::aggregate_task_phase_on(conn, dialect, task_id).await {
            tracing::warn!(build_id = %build_id, error = %e, "Failed to aggregate task phase after {after}");
        }
    }
    Ok(())
}

/// priority × cnt 行集 → 计数映射（两处 priority 统计查询共用归约）。
pub(super) fn priority_count_map(rows: Vec<sqlx::any::AnyRow>) -> HashMap<BuildPriority, i64> {
    use sqlx::Row as _;
    let mut map = HashMap::new();
    for r in rows {
        let p: i64 = r.get("priority");
        let cnt: i64 = r.get("cnt");
        map.insert(p as BuildPriority, cnt);
    }
    map
}
