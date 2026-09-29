// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 状态存储方法。

use super::*;

/// worker_tasks.status 活跃词汇（可被终态写入覆盖，但不得由终态回退而来）。
const WORKER_TASK_ACTIVE_STATUSES: [&str; 2] = ["assigned", "running"];

/// worker_tasks.status 终态词汇（生命周期终点，不可回退到活跃态）。
const WORKER_TASK_TERMINAL_STATUSES: [&str; 3] = ["completed", "failed", "cancelled"];

/// 校验 worker_tasks.status 词汇表（守卫）：纯生命周期词汇、与 builds.phase 解耦，
/// verbatim 写入任意串 = COUNT active / IN terminal 都看不见的幽灵行，永久泄漏。
fn validate_worker_task_status(status: &str) -> crate::Result<()> {
    if WORKER_TASK_ACTIVE_STATUSES.contains(&status)
        || WORKER_TASK_TERMINAL_STATUSES.contains(&status)
    {
        Ok(())
    } else {
        Err(CrbsError::ValidationFailed {
            message: format!(
                "invalid worker task status {status:?}; expected one of assigned/running/completed/failed/cancelled"
            ),
        })
    }
}

impl StateStore {
    /// 统计 Worker 当前活跃任务数。
    pub async fn count_worker_active_tasks(&self, worker_id: i64) -> crate::Result<i64> {
        let count: i64 = sqlx::query_scalar(sql::COUNT_WORKER_ACTIVE_TASKS)
            .bind(worker_id)
            .fetch_one(self.pool())
            .await
            .db_ctx("count worker tasks")?;

        Ok(count)
    }

    /// 列出 Worker 当前活跃的 build（`count_worker_active_tasks` 列表等价物，
    /// UI 详情页用）：status IN ('assigned','running') 且 kind='build'，init 不列。
    pub async fn list_worker_active_builds(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<WorkerActiveBuild>> {
        sqlx::query_as::<_, WorkerActiveBuild>(sql::LIST_WORKER_ACTIVE_BUILDS)
            .bind(worker_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list worker active builds")
    }

    /// 列出 Worker 最近 10 条 build 分配（UI 详情页 Recent builds 卡，含终态
    /// 行；排序按分配行 id 倒序）。
    pub async fn list_worker_recent_builds(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<WorkerRecentBuild>> {
        sqlx::query_as::<_, WorkerRecentBuild>(sql::LIST_WORKER_RECENT_BUILDS)
            .bind(worker_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list worker recent builds")
    }

    /// Worker 每产品最近一次 init 分配（UI 详情页 Base OS inits 卡）：取最近
    /// 20 条 init 行后按 init_product 去重（保序，首个出现即最新），窗口耗尽
    /// 前未覆盖到的更老产品不出现——展示语义为"最近活动"而非全量台账。
    pub async fn list_worker_recent_inits(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<WorkerRecentInit>> {
        let rows: Vec<WorkerRecentInit> =
            sqlx::query_as::<_, WorkerRecentInit>(sql::LIST_WORKER_RECENT_INITS)
                .bind(worker_id)
                .fetch_all(self.pool())
                .await
                .db_ctx("list worker recent inits")?;
        let mut seen = std::collections::HashSet::new();
        Ok(rows
            .into_iter()
            .filter(|r| seen.insert(r.product.clone()))
            .collect())
    }

    /// build 生命周期时刻（UI 详情页 Lifecycle 小节）：builds.created_at
    /// （NULL 回退 tasks.submitted_at）+ 最新一条 build 型分配行的 assigned/
    /// started + builds.completed_at + worker 标识。行不存在（build 被清理）
    /// 返回 None。
    pub async fn get_build_lifecycle(
        &self,
        build_id: i64,
    ) -> crate::Result<Option<BuildLifecycle>> {
        let row = sqlx::query(sql::SELECT_BUILD_LIFECYCLE)
            .bind(build_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get build lifecycle")?;
        Ok(row.map(|r| BuildLifecycle {
            submitted_at: r.get("submitted_at"),
            assigned_at: r.get("assigned_at"),
            started_at: r.get("started_at"),
            completed_at: r.get("completed_at"),
            worker_id: r.get("worker_id"),
            worker_name: r.get("worker_name"),
        }))
    }

    /// 批量统计所有 worker 的活跃任务数（UI Load 列 active/capacity）：无活跃
    /// 任务的 worker 不出现在结果中，由调用方按缺省 0 处理。
    pub async fn count_active_tasks_by_worker(
        &self,
    ) -> crate::Result<std::collections::HashMap<i64, i64>> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(sql::COUNT_ACTIVE_TASKS_BY_WORKER)
            .fetch_all(self.pool())
            .await
            .db_ctx("count active tasks by worker")?;

        Ok(rows.into_iter().collect())
    }

    /// 批量列出所有 worker 活跃构建的
    /// (worker_id, product, source_name, arch)：调度 Σ 权重数据源，调用方按
    /// (product, source_name, arch) 三维画像键折算各 worker 在跑权重合计
    ///（source_name = builds.name 源码包基础名，跨版本共享画像行）；口径：
    /// assigned/running + kind='build'（同 list_worker_active_builds），
    /// 限定爬坡窗口（`ramp_secs`）内的行——started_at 在派发与领取时即写入，
    /// NULL 臂仅防御历史脏行（视同爬坡期计入），槽位已占按保守预留处理；
    /// 起跑超窗的行已体现在 load1 中、不再供给。arch 经 NULLIF 归一（PG 空串 /
    /// SQLite NULL 同语义）。
    pub async fn list_worker_active_build_pkgs(
        &self,
        ramp_secs: i64,
    ) -> crate::Result<Vec<(i64, String, String, Option<String>)>> {
        let sql = sql::list_active_build_pkgs_by_worker(self.dialect, ramp_secs);
        sqlx::query_as(&sql)
            .fetch_all(self.pool())
            .await
            .db_ctx("list active build pkgs by worker")
    }

    /// 列出该 worker 名下 build 已取消的 assignment id（心跳下行取消通知数据源）：
    /// 信号源 `builds.phase='cancelled'`（first-winner 终态），故意不过滤
    /// worker_tasks.status，重复 id 由 worker 注册表幂等吸收（SQL 说明见同名 sql 常量）。
    pub async fn list_cancelled_assignment_ids_for_worker(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<i64>> {
        sqlx::query_scalar(sql::LIST_CANCELLED_ASSIGNMENT_IDS_FOR_WORKER)
            .bind(worker_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list cancelled assignment ids for worker")
    }

    /// 该 worker 名下"已 running 且 build 仍 building"的 assignment（poll 响应
    /// 丢失重投递）：正常领取只 CAS 'assigned'，hub 提交先于 HTTP 响应，响应
    /// 丢失后行停留 running、续 poll 恒 204、capacity 永久占用——poll 等待到期
    /// 以此兜底重发，不重置回 pending（复刻双执行），worker 按取消注册表去重，
    /// 取最旧一条；init running 行同漏失面、触发面更窄，不在覆盖（见 SQL 注释）；
    /// 返回 `AssignedTaskInfo::Build` 与正常领取同构，dispatch 走同一水合路径。
    pub async fn list_running_assignments_for_worker(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<AssignedTaskInfo>> {
        let rows = sqlx::query(sql::LIST_RUNNING_ASSIGNMENTS_FOR_WORKER)
            .bind(worker_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list running assignments for worker")?;
        Ok(rows
            .iter()
            .map(|r| AssignedTaskInfo::Build {
                assignment_id: r.get("id"),
                task_id: r.get("task_id"),
                build_id: r.get("build_id"),
                product: r.get("product"),
                srpm_path: r.get("srpm_path"),
                request_json: r.get("request_json"),
                repo_consume: r.get::<i64, _>("repo_consume") != 0,
            })
            .collect())
    }

    /// 兜底回收：释放所有指向已终态 build 的僵尸 worker_task（弥补 report_result
    /// 迁出写入丢失，避免调度容量永久占用）。不动 build 本身，仅把 worker_task
    /// 迁出 running；终态词汇按关联 build 的 phase 映射（与 report_result 同口径：
    /// succeeded→completed、cancelled→cancelled、failed/timeout→failed）。
    /// 返回 `(受影响行数, 去重 build_id 列表)`，后者供 server reclaimer 驱逐
    /// LogBuffer（弥补 report 丢失时 `evict_log_buffer_if_persisted` 未触发的泄漏）。
    pub async fn release_terminal_worker_tasks(&self) -> crate::Result<(u64, Vec<i64>)> {
        let build_ids: Vec<i64> =
            sqlx::query_scalar(&sql::release_terminal_worker_tasks(self.dialect))
                .fetch_all(self.pool())
                .await
                .db_ctx("release terminal worker tasks")?;
        let affected = build_ids.len() as u64;
        let mut seen = std::collections::HashSet::new();
        let unique = build_ids
            .into_iter()
            .filter(|id| seen.insert(*id))
            .collect();
        Ok((affected, unique))
    }

    /// 获取单个 Worker。
    pub async fn get_worker(&self, id: i64) -> crate::Result<Option<WorkerStatus>> {
        let row = sqlx::query_as::<_, WorkerStatusRow>(sql::SELECT_WORKER_BY_ID)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get worker")?;

        Ok(row.map(|r| r.into()))
    }

    /// 更新 Worker 任务状态：词汇表守卫见 `validate_worker_task_status`；SQL 侧
    /// 另拒终态→活跃回退（0 行 no-op）。
    pub async fn update_worker_task_status(&self, task_id: i64, status: &str) -> crate::Result<()> {
        validate_worker_task_status(status)?;
        sqlx::query(&sql::update_worker_task_status(self.dialect))
            .bind(status)
            .bind(task_id)
            .execute(self.pool())
            .await
            .db_ctx("update worker task status")?;
        Ok(())
    }

    /// 按 build_id 更新对应 Worker 任务状态（一个 build 通常只对应一条 worker_task）。
    pub async fn update_worker_task_status_for_build(
        &self,
        build_id: i64,
        status: &str,
    ) -> crate::Result<()> {
        validate_worker_task_status(status)?;
        sqlx::query(&sql::update_worker_task_status_for_build(self.dialect))
            .bind(status)
            .bind(build_id)
            .execute(self.pool())
            .await
            .db_ctx(&format!("update worker task status for build {}", build_id))?;
        Ok(())
    }

    /// 一次行查询 worker_task 的 (build_id, worker_id, kind, status)：init 任务
    /// build_id 为 None；行不存在时四元组全 None（worker_id 为 None 使归属校验
    /// 自然落入 403 分支）。
    pub async fn get_worker_task_meta(
        &self,
        task_id: i64,
    ) -> crate::Result<(Option<i64>, Option<i64>, Option<String>, Option<String>)> {
        let row: Option<(Option<i64>, i64, String, String)> =
            sqlx::query_as(sql::SELECT_WORKER_TASK_META)
                .bind(task_id)
                .fetch_optional(self.pool())
                .await
                .db_ctx("get worker task meta")?;
        Ok(match row {
            Some((build_id, worker_id, kind, status)) => {
                (build_id, Some(worker_id), Some(kind), Some(status))
            }
            None => (None, None, None, None),
        })
    }

    /// 取 build 最近一次 assignment 的 worker 名（UI 详情侧栏"执行节点"行）：
    /// `worker_tasks.id` 单调递增取最近；不限定状态，终态后行保留（展示
    /// "谁执行了"，与 [`Self::worker_assigned_to_build`] 同口径）；无则 None。
    pub async fn latest_assigned_worker_name(
        &self,
        build_id: i64,
    ) -> crate::Result<Option<String>> {
        let name: Option<String> = sqlx::query_scalar(sql::SELECT_LATEST_BUILD_WORKER_NAME)
            .bind(build_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get latest assigned worker name")?;
        Ok(name)
    }

    /// 校验 worker 是否持有该 build 的**活跃**分配行（worker_tasks）：产物上传
    /// 会触发签名与发布重建，越界写入会污染发布仓库。`assignment_id` 为
    /// Some 时精确匹配该次分配（同 worker 重派后旧 attempt 的迟到上传不再
    /// 命中新分配）；None 不做 attempt 精确匹配，仅限首轮 attempt。
    pub async fn worker_assigned_to_build(
        &self,
        worker_id: i64,
        build_id: i64,
        assignment_id: Option<i64>,
    ) -> crate::Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(sql::SELECT_WORKER_TASK_OWNED_BY)
            .bind(build_id)
            .bind(worker_id)
            .bind(assignment_id)
            .fetch_optional(self.pool())
            .await
            .db_ctx("check worker assigned to build")?;
        Ok(row.is_some())
    }

    /// 构建实际宿主架构（最新 build 型归属的 worker 绑定架构）：noarch 复现
    /// 钉住宿主用——依赖快照按宿主架构锁定，跨架构领取必然解析失败。无归属
    ///（本地构建/无分配行）返回 None，调用方回退开放行并告警。
    pub async fn build_host_arch(&self, build_id: i64) -> crate::Result<Option<String>> {
        let arch: Option<(String,)> = sqlx::query_as(
            "SELECT w.arch FROM worker_tasks wt JOIN workers w ON w.id = wt.worker_id \
             WHERE wt.build_id = $1 AND wt.kind = 'build' ORDER BY wt.id DESC LIMIT 1",
        )
        .bind(build_id)
        .fetch_optional(self.pool())
        .await
        .db_ctx("select build host arch")?;
        Ok(arch.map(|(a,)| a))
    }
}
