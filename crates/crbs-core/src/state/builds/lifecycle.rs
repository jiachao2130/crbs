// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建插入、相位更新、完成/取消与陈旧本地行回收。

use super::completion::{
    aggregate_task_phase_best_effort, complete_build_update, truncate_to_bytes,
    CompleteBuildParams, MAX_ERROR_SUMMARY_BYTES,
};
use super::{active_duplicate_conflict, sql, GuardedBuildInfo};
use crate::engine::ResourceUsage;
use crate::error::DbResultExt;
use crate::state::{BuildInsert, StateStore};
use crate::types::build_phase_is_terminal;

impl StateStore {
    /// 插入构建记录并返回自增 ID（started_at 自动落当前时间）。
    /// task 关联守卫：`task_id` 非空时同一写事务内复查 task phase——cancel
    /// 与 submit fan-out（先插 task 复制 SRPM，再逐个插 builds）并发时，终态
    /// task 只拒活跃 phase 构建；挂终态构建行是历史记账，放行。
    /// 活跃去重守卫：同事务复查同 product+pkg+arch 活跃构建，命中返回
    /// `Conflict`（409）；锁形态见函数内注释。
    pub async fn insert_build(&self, build: BuildInsert<'_>) -> crate::Result<i64> {
        let (name, version, release) = crate::util::split_nvr(build.pkg_name);

        // BEGIN IMMEDIATE：复查与插入同一写锁窗口，取消事务无法楔进其间。
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误先 best-effort ROLLBACK，防开事务连接回池污染。
        let outcome: crate::Result<i64> = async {
            if let Some(task_id) = build.task_id {
                let phase: Option<String> = sqlx::query_scalar(sql::SELECT_TASK_PHASE)
                    .bind(task_id)
                    .fetch_optional(&mut *conn)
                    .await
                    .db_ctx("select task phase for build insert")?;
                match phase {
                    None => {
                        return Err(crate::error::CrbsError::ValidationFailed {
                            message: format!("task {task_id} not found; refusing to attach build"),
                        })
                    }
                    // 终态 task 只拒活跃 phase 构建；终态构建行是历史记账，放行。
                    Some(ref p)
                        if build_phase_is_terminal(p) && matches!(
                            build.phase,
                            "pending" | "assigned" | "building"
                        ) =>
                    {
                        return Err(crate::error::CrbsError::ValidationFailed {
                            message: format!(
                                "task {task_id} already terminal ('{p}'); refusing to attach runnable build ('{}')",
                                build.phase
                            ),
                        });
                    }
                    Some(_) => {}
                }
            }

            // 同 product+pkg+arch 活跃去重：权威兜底是 partial UNIQUE 表达式索引
            // uq_active_builds_identity（COALESCE(arch,'') 归一，NULL-arch 双插也
            // 拦），PG READ COMMITTED 语句间隙由索引在提交点拒绝（错误臂归一
            // Conflict）；本复查只为可读 409，SQLite 写事务串行下先手拒绝。
            // 索引与查询的 phase IN 集须逐字同序（planner 识别 partial 索引前提）。
            if matches!(build.phase, "pending" | "assigned" | "building") {
                let dup: Option<(i64,)> = sqlx::query_as(sql::EXISTS_ACTIVE_DUPLICATE_BUILD)
                    .bind(build.product)
                    .bind(build.pkg_name)
                    .bind(build.arch)
                    .fetch_optional(&mut *conn)
                    .await
                    .db_ctx("check active duplicate build")?;
                if dup.is_some() {
                    return Err(active_duplicate_conflict(&build));
                }
            }

            let product_id: Option<i64> =
                sqlx::query_scalar("SELECT id FROM products WHERE name = $1 AND owner_id IS NULL")
                    .bind(build.product)
                    .fetch_optional(&mut *conn)
                    .await
                    .db_ctx("lookup product")?;

            // task 关联走守卫 INSERT（收口 PG 语句间隙），否则裸形态。
            let insert_sql = match build.task_id {
                Some(_) => sql::insert_build_guarded(self.dialect),
                None => sql::insert_build(self.dialect),
            };
            let inserted: Option<i64> = sqlx::query_scalar::<_, i64>(&insert_sql)
                .bind(build.product)
                .bind(build.pkg_name)
                .bind(name)
                .bind(version)
                .bind(release)
                .bind(build.phase)
                .bind(build.result_dir)
                .bind(build.layer_digest)
                .bind(build.base_os_digest)
                .bind(build.backend)
                .bind(build.user)
                .bind(build.user_id)
                .bind(build.crbs_pid)
                .bind(build.priority)
                .bind(build.arch)
                .bind(build.host_arches)
                .bind(build.task_id)
                .bind(product_id)
                // INTEGER 0/1 双方言同型：PG 严格类型拒 bool 绑定 int4 列（sqlite 宽容，测试不可见）
                .bind(i64::from(build.repo_publish))
                .bind(i64::from(build.repo_consume))
                .bind(build.req_min_mem_kb)
                .bind(build.req_min_ncpu)
                .bind(build.req_min_disk_kb)
                .fetch_optional(&mut *conn)
                .await
                // 先 db_ctx 再判唯一冲突：索引在提交点拒绝并发双插时，归一为
                // 与复查同语义的 Conflict。
                .db_ctx("insert build")
                .map_err(|e| {
                    if crate::error::is_unique_violation(&e) {
                        active_duplicate_conflict(&build)
                    } else {
                        e
                    }
                })?;
            let id = match (build.task_id, inserted) {
                (_, Some(id)) => id,
                (Some(task_id), None) => {
                    // 守卫拒绝：task 在复查-INSERT 间隙被并发翻终态，与复查
                    // 同款 ValidationFailed（仅活跃 phase 可达）。
                    return Err(crate::error::CrbsError::ValidationFailed {
                        message: format!(
                            "task {task_id} turned terminal between recheck and insert; \
                             refusing to attach runnable build ('{}')",
                            build.phase
                        ),
                    });
                }
                (None, None) => {
                    return Err(crate::error::CrbsError::Database(
                        "insert build returned no id (unreachable)".into(),
                    ));
                }
            };

            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit insert build")?;
            Ok(id)
        }
        .await;

        match outcome {
            Ok(id) => {
                self.notify_state_changed();
                Ok(id)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    /// 更新构建阶段（中间态），同一事务内聚合所属 task 阶段。
    /// 目标 phase 仅接受 'assigned'/'building'（worker 上报直达 SQL，放行
    /// pending 会被重新取走 → 双执行）；非法目标与 0 行均 fail-closed
    /// `ValidationFailed`；聚合失败仅 warn 照常 COMMIT。无归属谓词（引擎本地
    /// 路径用），worker 上报走 [`Self::update_build_phase_guarded`]。
    pub async fn update_build_phase(&self, id: i64, phase: &str) -> crate::Result<()> {
        let affected = self.update_build_phase_inner(id, phase, None).await?;
        if affected == 0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!("Build {id} is not in an active state or does not exist"),
            });
        }
        Ok(())
    }

    /// [`Self::update_build_phase`] 的 worker 上报变体：写入自带 assignment
    /// 归属 CAS（见 `sql::UPDATE_BUILD_PHASE_GUARDED`）。0 = 已终态/不存在，或
    /// assignment 已被 reclaim 剥夺——调用方按预期恢复路径静默丢弃。
    pub async fn update_build_phase_guarded(
        &self,
        id: i64,
        worker_id: i64,
        phase: &str,
    ) -> crate::Result<u64> {
        self.update_build_phase_inner(id, phase, Some(worker_id))
            .await
    }

    /// 两入口共享实现：`worker_id` Some 走归属谓词、None 走裸 UPDATE；0 行
    /// 不聚合，返回行数由入口决定错误语义。
    async fn update_build_phase_inner(
        &self,
        id: i64,
        phase: &str,
        worker_id: Option<i64>,
    ) -> crate::Result<u64> {
        if !matches!(phase, "assigned" | "building") {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: format!(
                    "invalid build phase '{phase}': only 'assigned' or 'building' are allowed"
                ),
            });
        }
        let mut conn = self.begin_write().await?;
        // BEGIN 之后任何错误（含 COMMIT 自身失败）返回前先 best-effort
        // ROLLBACK，避免仍开着事务的连接回池污染（PG 25P02 / SQLite 持写锁）。
        let outcome: crate::Result<u64> = async {
            let query = if worker_id.is_some() {
                sqlx::query(sql::UPDATE_BUILD_PHASE_GUARDED)
            } else {
                sqlx::query(sql::UPDATE_BUILD_PHASE)
            };
            let mut query = query.bind(phase).bind(id);
            if let Some(worker_id) = worker_id {
                query = query.bind(worker_id);
            }
            let affected = query
                .execute(&mut *conn)
                .await
                .db_ctx("update build phase")?
                .rows_affected();
            if affected > 0 {
                aggregate_task_phase_best_effort(&mut conn, self.dialect, id, "update").await?;
            }
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit update build phase")?;
            Ok(affected)
        }
        .await;
        match outcome {
            Ok(affected) => {
                if affected > 0 {
                    self.notify_state_changed();
                }
                Ok(affected)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    /// 补充构建记录的 layer_digest（SharedLayer 创建成功后调用）。
    pub async fn update_build_layer_info(&self, id: i64, layer_digest: &str) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_BUILD_LAYER_DIGEST)
            .bind(layer_digest)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build layer info")?;
        Ok(())
    }

    /// 补充构建信息（result_dir, base_os_digest, backend）：无相位守卫的整体
    /// 覆写 UPDATE（None 抹掉已有值）。生产调用链在活跃期内；终态行写入是
    /// 测试 fixture 隐性契约。并发敏感路径（上传提交点）必须走
    /// `Self::update_build_info_tx_guarded`。
    pub async fn update_build_info(
        &self,
        id: i64,
        result_dir: Option<&str>,
        base_os_digest: Option<&str>,
        backend: &str,
    ) -> crate::Result<()> {
        sqlx::query(sql::UPDATE_BUILD_INFO)
            .bind(result_dir)
            .bind(base_os_digest)
            .bind(backend)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("update build info")?;
        // result_dir 落定是 log SSE 来源探测信号，写成功即广播。
        self.notify_state_changed();
        Ok(())
    }

    /// [`Self::update_build_info`] 的 upload 落库事务内变体：自带 phase CAS +
    /// assignment 归属 CAS（见 `UPDATE_BUILD_INFO_GUARDED`）。0 = 相位被并发翻
    /// 转或 assignment 被 reclaim 剥夺，调用方必须 ROLLBACK；tx 版不广播。
    pub(crate) async fn update_build_info_tx_guarded(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Any>,
        info: GuardedBuildInfo<'_>,
    ) -> crate::Result<u64> {
        let res = sqlx::query(sql::UPDATE_BUILD_INFO_GUARDED)
            .bind(info.result_dir)
            .bind(info.base_os_digest)
            .bind(info.backend)
            .bind(info.id)
            .bind(info.worker_id)
            .bind(info.assignment_id)
            .execute(&mut **tx)
            .await
            .db_ctx("update build info guarded")?;
        Ok(res.rows_affected())
    }

    /// 更新构建终态、完成时间与耗时（秒），同一事务内聚合所属 task 阶段。
    /// `phase` 仅接受终态词汇（白名单见 `complete_build_update`）；聚合失败仍
    /// COMMIT——物理构建已发生，聚合交 `reconcile_stale_task_phases` 兜底。
    /// 返回行数：0 = 终态守卫拒绝，调用方按需处理。
    pub async fn complete_build(
        &self,
        id: i64,
        phase: &str,
        result_dir: Option<&str>,
    ) -> crate::Result<u64> {
        self.complete_build_with_error(id, phase, result_dir, None)
            .await
    }

    /// [`Self::complete_build`] 的带失败原因版本：`error` 落 error_summary
    ///（超限截断保留前缀），`None` 保留已有值（COALESCE）。
    pub async fn complete_build_with_error(
        &self,
        id: i64,
        phase: &str,
        result_dir: Option<&str>,
        error: Option<&str>,
    ) -> crate::Result<u64> {
        self.complete_build_inner(id, None, phase, result_dir, error, None)
            .await
    }

    /// [`Self::complete_build_with_error`] 的 worker 上报变体：写入自带
    /// assignment 归属 CAS（见 `sql::complete_build`）。0 = 已被并发翻终态，或
    /// assignment 已被 reclaim 剥夺（否则迟到上报会把重派 build 翻终态并触发
    /// repo regen），调用方 warn 留痕丢弃。
    pub async fn complete_build_guarded(
        &self,
        id: i64,
        worker_id: i64,
        phase: &str,
        result_dir: Option<&str>,
        error: Option<&str>,
    ) -> crate::Result<u64> {
        self.complete_build_inner(id, Some(worker_id), phase, result_dir, error, None)
            .await
    }

    /// [`Self::complete_build`] 的带资源版本（引擎本地路径）：资源列（三值 +
    /// 采集包络）随终态落库，无数据传 `None`（列保持 NULL）。
    pub async fn complete_build_with_resources(
        &self,
        id: i64,
        phase: &str,
        result_dir: Option<&str>,
        resources: Option<ResourceUsage>,
    ) -> crate::Result<u64> {
        self.complete_build_inner(id, None, phase, result_dir, None, resources.as_ref())
            .await
    }

    /// [`Self::complete_build_guarded`] 的带资源版本（worker 上报路径）：守卫
    /// 语义不变；取消臂不传资源——取消不是执行方的能力度量。
    pub async fn complete_build_guarded_resources(
        &self,
        id: i64,
        worker_id: i64,
        phase: &str,
        result_dir: Option<&str>,
        error: Option<&str>,
        resources: Option<&ResourceUsage>,
    ) -> crate::Result<u64> {
        self.complete_build_inner(id, Some(worker_id), phase, result_dir, error, resources)
            .await
    }

    /// 共享实现：`worker_id` 透传 [`complete_build_update`] 的归属谓词；`error`
    /// 统一在此截断（[`MAX_ERROR_SUMMARY_BYTES`]），资源入口不传 error 不受影响。
    async fn complete_build_inner(
        &self,
        id: i64,
        worker_id: Option<i64>,
        phase: &str,
        result_dir: Option<&str>,
        error: Option<&str>,
        resources: Option<&ResourceUsage>,
    ) -> crate::Result<u64> {
        let error = error.map(|e| truncate_to_bytes(e, MAX_ERROR_SUMMARY_BYTES));
        let mut conn = self.begin_write().await?;
        // BEGIN 后任何错误先 best-effort ROLLBACK，防开事务连接回池污染。
        let outcome: crate::Result<u64> = async {
            let affected = complete_build_update(
                &mut *conn,
                CompleteBuildParams {
                    dialect: self.dialect,
                    id,
                    phase,
                    result_dir,
                    error,
                    worker_id,
                    resources,
                },
            )
            .await?;
            aggregate_task_phase_best_effort(&mut conn, self.dialect, id, "complete").await?;
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit complete build")?;
            Ok(affected)
        }
        .await;
        match outcome {
            Ok(0) => {}
            Ok(_) => self.notify_state_changed(),
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e);
            }
        }
        outcome
    }

    /// 取消构建（终态守卫：仅活跃态可取消）。返回行数：0 = 已终态拒绝（调用方
    /// 409 语义）；task 聚合同事务，失败仅 warn 照常 COMMIT。
    pub async fn mark_build_cancelled(&self, id: i64) -> crate::Result<u64> {
        let mut conn = self.begin_write().await?;
        // BEGIN 后任何错误先 best-effort ROLLBACK，防开事务连接回池污染。
        let outcome: crate::Result<u64> = async {
            let affected = sqlx::query(&sql::mark_build_cancelled(self.dialect))
                .bind(id)
                .execute(&mut *conn)
                .await
                .db_ctx("mark build cancelled")?
                .rows_affected();
            aggregate_task_phase_best_effort(&mut conn, self.dialect, id, "cancel").await?;
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit mark build cancelled")?;
            Ok(affected)
        }
        .await;
        match outcome {
            Ok(0) => Ok(0),
            Ok(affected) => {
                self.notify_state_changed();
                Ok(affected)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    /// 回收本机陈旧活跃构建行（worker 启动期，crash 恢复的本地半边）：把死者
    ///（pid_alive = false，含未记录 pid）名下的活跃行置 failed——否则重派
    /// insert 撞 uq_active_builds_identity、orphan-mount GC 跳过泄漏挂载；
    /// 活进程行不动（防双执行）；返回回收 id（日志用）。
    pub async fn gc_stale_local_builds(&self) -> crate::Result<Vec<i64>> {
        let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(sql::LIST_ACTIVE_LOCAL_BUILD_ROWS)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list active local builds")?;

        let mut reclaimed = Vec::new();
        for (id, crbs_pid) in rows {
            let stale = match crbs_pid {
                // 行由引擎创建时必写 pid；NULL = 半写入残留，同样等不到上报。
                None => true,
                Some(pid) => !crate::util::pid_alive(pid),
            };
            if !stale {
                continue;
            }
            let summary = match crbs_pid {
                Some(pid) => {
                    format!("stale local build: pid {pid} no longer exists (worker restart GC)")
                }
                None => "stale local build: no crbs_pid recorded (worker restart GC)".to_string(),
            };
            let affected = self.mark_stale_local_build_failed(id, &summary).await?;
            if affected > 0 {
                reclaimed.push(id);
            }
        }
        Ok(reclaimed)
    }

    /// 镜像播种拆引信的候选列表：同 product+pkg_name、活跃 phase、arch 归一
    /// 为 ''（`COALESCE(arch,'')=''`——新镜像行 arch 恒 NULL，撞
    /// uq_active_builds_identity 的正是本集合）。只列表不裁决：pid 归属与
    /// 在途排除的认领判定在调用方（worker 播种前拆引信，见 crbs-worker
    /// executor），state 层不掌握进程语义。
    pub async fn list_claimable_active_rows(
        &self,
        product: &str,
        pkg_name: &str,
    ) -> crate::Result<Vec<(i64, Option<i64>)>> {
        let rows: Vec<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT id, crbs_pid FROM builds \
             WHERE product = $1 AND pkg_name = $2 \
               AND COALESCE(arch, '') = '' \
               AND phase IN ('pending', 'assigned', 'building')",
        )
        .bind(product)
        .bind(pkg_name)
        .fetch_all(&self.pool)
        .await
        .db_ctx("list claimable active build rows")?;
        Ok(rows)
    }

    /// 单条陈旧活跃行置 failed（终态守卫同 [`Self::gc_stale_local_builds`]，
    /// 仅活跃态可写）；返回行数：0 = 已终态/不存在，重放幂等。
    pub async fn mark_stale_local_build_failed(
        &self,
        id: i64,
        summary: &str,
    ) -> crate::Result<u64> {
        let affected = sqlx::query(&sql::mark_stale_local_build_failed(self.dialect))
            .bind(id)
            .bind(summary)
            .execute(&self.pool)
            .await
            .db_ctx("mark stale local build failed")?
            .rows_affected();
        if affected > 0 {
            self.notify_state_changed();
        }
        Ok(affected)
    }
}
