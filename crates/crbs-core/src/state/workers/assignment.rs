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
use crate::state::rollback_and_return;

impl StateStore {
    /// 分配构建任务给 Worker（事务内完成 INSERT + builds 状态更新）。
    pub async fn assign_build_to_worker(
        &self,
        build_id: i64,
        worker_id: i64,
    ) -> crate::Result<(i64, Option<i64>)> {
        // begin_write() 先拿写锁：DEFERRED 读后升级会撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await?;

        // 错误路径（含 COMMIT 自身失败）先 ROLLBACK：带事务连接回池（SQLite 持写锁 / PG 池污染）。
        let task_id: Option<i64> = match sqlx::query_scalar(sql::SELECT_BUILD_TASK_ID)
            .bind(build_id)
            .fetch_one(&mut *conn)
            .await
            .db_ctx("get build task_id")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };

        let assignment_id =
            match sqlx::query_scalar::<_, i64>(&sql::insert_worker_task_build(self.dialect))
                .bind(build_id)
                .bind(worker_id)
                .bind(task_id)
                .fetch_one(&mut *conn)
                .await
                .db_ctx("assign build to worker")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };

        // phase='pending' 守卫：无守卫可复活终态 build 或对同一 build 二次分配
        //（双 worker 并发构建同产物目录）；0 行 = 冲突，整事务回滚（含已 INSERT 的 worker_task 行）。
        match sqlx::query(sql::SET_BUILD_ASSIGNED)
            .bind(build_id)
            .execute(&mut *conn)
            .await
            .db_ctx("update build phase to assigned")
        {
            Ok(res) if res.rows_affected() == 1 => {}
            Ok(_) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(CrbsError::Conflict {
                    message: format!(
                        "build {} is not pending (already assigned/terminal); refusing assignment",
                        build_id
                    ),
                });
            }
            Err(e) => rollback_and_return!(conn, e),
        };

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit tx")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        self.notify_state_changed();
        Ok((assignment_id, task_id))
    }

    /// 检查 Worker 的已分配任务并原子置 running：SELECT 与两处状态更新同一事务，
    /// 避免中途失败留下 assignment 已 running 而 builds 未推进的不一致。
    /// 返回 [`AssignedTaskInfo`]，区分 build / init 两种 kind。
    pub async fn check_assigned_task(
        &self,
        worker_id: i64,
    ) -> crate::Result<Option<AssignedTaskInfo>> {
        // begin_write() 先拿写锁：DEFERRED 读后升级会撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await?;

        // 错误路径（含 COMMIT 自身失败）先 ROLLBACK：带事务连接回池（SQLite 持写锁 / PG 池污染）。
        // 先查 init 型（无 build 行，不 JOIN builds），再查 build 型。
        let init_row = match sqlx::query(sql::SELECT_INIT_ASSIGNMENT)
            .bind(worker_id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("check init task")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };

        let result = if let Some(r) = init_row {
            let assignment_id: i64 = r.get("id");
            let product: String = r.get("init_product");

            let won = match sqlx::query(&sql::mark_assignment_running(self.dialect))
                .bind(assignment_id)
                .execute(&mut *conn)
                .await
                .db_ctx("update init task status")
            {
                // 0 行 = status='assigned' CAS 未命中：并发 poll 已置 running
                //（同 worker 双 poll/客户端 bug），按"无任务"返回，否则同构建双执行。
                Ok(res) => res.rows_affected() > 0,
                Err(e) => rollback_and_return!(conn, e),
            };
            if !won {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Ok(None);
            }

            Some(AssignedTaskInfo::Init {
                assignment_id,
                product,
            })
        } else {
            let row = match sqlx::query(sql::SELECT_BUILD_ASSIGNMENT)
                .bind(worker_id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("check assigned task")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };

            match row {
                Some(r) => {
                    let assignment_id: i64 = r.get("id");
                    let task_id: Option<i64> = r.get("task_id");
                    let build_id: i64 = r.get("build_id");
                    let product: String = r.get("product");
                    let srpm_path: Option<String> = r.get("srpm_path");
                    let request_json: Option<String> = r.get("request_json");
                    let repo_consume: bool = r.get::<i64, _>("repo_consume") != 0;

                    let won_assignment =
                        match sqlx::query(&sql::mark_assignment_running(self.dialect))
                            .bind(assignment_id)
                            .execute(&mut *conn)
                            .await
                            .db_ctx("update task status")
                        {
                            // 0 行 = 并发 poll 已置 running：按"无任务"返回（同上）。
                            Ok(res) => res.rows_affected() > 0,
                            Err(e) => rollback_and_return!(conn, e),
                        };
                    if !won_assignment {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Ok(None);
                    }

                    // phase='assigned' 守卫：0 行 = 取消窗口内 build 已离开 assigned，
                    // 与上方 CAS 失败同型——ROLLBACK 按"无任务"返回，绝不下发已取消构建。
                    let won_building = match sqlx::query(sql::SET_BUILD_BUILDING)
                        .bind(build_id)
                        .execute(&mut *conn)
                        .await
                        .db_ctx("update build phase")
                    {
                        Ok(res) => res.rows_affected() > 0,
                        Err(e) => rollback_and_return!(conn, e),
                    };
                    if !won_building {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Ok(None);
                    }

                    Some(AssignedTaskInfo::Build {
                        assignment_id,
                        task_id,
                        build_id,
                        product,
                        srpm_path,
                        request_json,
                        repo_consume,
                    })
                }
                None => None,
            }
        };

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit tx")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        // 迁移（assigned → running / builds → building）即广播；None 无状态变化不广播。
        if result.is_some() {
            self.notify_state_changed();
        }
        Ok(result)
    }

    /// 标记单个已分配任务失败并删 worker_tasks 记录（Worker 端发现任务无法执行时，
    /// 避免反复被取到卡住）；删除与 builds 终态更新同一事务。
    pub async fn fail_assignment(&self, assignment_id: i64, build_id: i64) -> crate::Result<()> {
        // begin_write()（SQLite BEGIN IMMEDIATE / PG BEGIN）：事务首句即写。
        let mut conn = self.begin_write().await.db_ctx("begin tx")?;

        // 任何错误（含 COMMIT 失败）返回前先 ROLLBACK，避免带事务连接回池。
        // 迟到报告守卫：DELETE 0 行 = assignment 已被 reclaimer 回收重派（水合
        // 失败 vs 回收竞态），不得把重派后另一 worker 在跑的构建打成 failed，直接返回。
        let deleted = match sqlx::query(sql::DELETE_WORKER_TASK)
            .bind(assignment_id)
            .execute(&mut *conn)
            .await
        {
            Ok(res) => res.rows_affected(),
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e).db_ctx("delete worker task");
            }
        };
        if deleted == 0 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            tracing::warn!(
                assignment_id = %assignment_id,
                build_id = %build_id,
                "fail_assignment hit already-reclaimed assignment; late report dropped"
            );
            return Ok(());
        }

        if let Err(e) = crate::state::builds::complete_build_update(
            &mut *conn,
            crate::state::builds::CompleteBuildParams {
                dialect: self.dialect,
                id: build_id,
                phase: "failed",
                result_dir: None,
                error: None,
                // 归属谓词 None：行刚被本事务 DELETE，EXISTS worker_tasks 必假，
                // Some 恒拒本写入（归属已由上方 rows_affected 自证）。
                worker_id: None,
                // 资源三元 None：归属剥夺属崩溃修复，无执行方采样数据可信。
                resources: None,
            },
        )
        .await
        {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e);
        }

        if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e).db_ctx("commit tx");
        }

        // 与 complete_build 一致的 best-effort 聚合（提交后执行）
        if let Err(e) = self.aggregate_task_phase_for_build(build_id).await {
            tracing::warn!(build_id = %build_id, error = %e, "Failed to aggregate task phase after fail_assignment");
        }
        Ok(())
    }

    /// 重入预算耗尽的收口：reset 守卫（`attempt < MAX_BUILD_ATTEMPTS`）拒绝后
    /// 把达上限的活跃行转终态 failed（否则永卡 building/pending 边缘），
    /// completed_at/duration 同步落值。false = 并发路径已推进该行。
    pub async fn fail_build_if_retry_exhausted(
        &self,
        conn: &mut sqlx::pool::PoolConnection<sqlx::Any>,
        build_id: i64,
    ) -> crate::Result<bool> {
        let res = sqlx::query(&sql::fail_build_if_retry_exhausted(self.dialect))
            .bind(build_id)
            .bind(crate::state::MAX_BUILD_ATTEMPTS)
            .execute(&mut **conn)
            .await
            .db_ctx("fail build on retry budget exhaustion")?;
        Ok(res.rows_affected() > 0)
    }

    /// 释放单个已分配任务重回 pending 队列（Worker 端无法执行该任务时回退）：
    /// 删 `worker_tasks` 记录 + `builds.phase` 重置 pending，两写同一事务。
    pub async fn release_assignment(&self, assignment_id: i64, build_id: i64) -> crate::Result<()> {
        let mut conn = self.begin_write().await.db_ctx("begin tx")?;

        // 迟到释放守卫：DELETE 0 行 = assignment 已被 reclaimer 回收重派，不得把
        // 重派后另一 worker 在跑的构建拉回 pending 造成双执行——跳过重置直接返回。
        let deleted = match sqlx::query(sql::DELETE_WORKER_TASK)
            .bind(assignment_id)
            .execute(&mut *conn)
            .await
        {
            Ok(res) => res.rows_affected(),
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e).db_ctx("delete worker task");
            }
        };
        if deleted == 0 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            tracing::warn!(
                assignment_id = %assignment_id,
                build_id = %build_id,
                "release_assignment hit already-reclaimed assignment; late release dropped"
            );
            return Ok(());
        }

        let reset = match sqlx::query(&sql::reset_build_to_pending(self.dialect))
            .bind(build_id)
            .execute(&mut *conn)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e).db_ctx("reset build to pending");
            }
        };
        if reset.rows_affected() == 0 {
            // 拒绝两形态：已终态（并发推进，无需动作）或重入预算耗尽——后者必须收口终态。
            if self
                .fail_build_if_retry_exhausted(&mut conn, build_id)
                .await?
            {
                tracing::warn!(
                    build_id = %build_id,
                    "Build failed: retry budget exhausted on release_assignment"
                );
            }
        }

        if let Err(e) = sqlx::query("COMMIT").execute(&mut *conn).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(e).db_ctx("commit tx");
        }

        self.notify_state_changed();
        Ok(())
    }
}
