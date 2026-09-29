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

/// 将过滤条件追加为 WHERE 片段与绑定参数（list/count 共用，条件与 bind 顺序一致）。
/// 不用 `QueryBuilder<sqlx::Any>`（生成 `?` 占位符，PG 语法错），手动维护 `$N` 编号。
fn push_worker_filter(parts: &mut Vec<String>, binds: &mut Vec<String>, filter: &WorkerFilter<'_>) {
    // LIKE 站点专用：escape_like 转义（\ % _）后字面匹配；不走 push_eq_and——
    // ESCAPE '\' 必须紧跟占位符，统一构造把 ${idx} 拼在末尾放不下。
    let push_like = |col: &str, v: &str, parts: &mut Vec<String>, binds: &mut Vec<String>| {
        let idx = binds.len() + 1;
        parts.push(format!(" AND {} LIKE ${} ESCAPE '\\'", col, idx));
        binds.push(format!("%{}%", crate::state::db::escape_like(v)));
    };
    if let Some(v) = filter.name {
        push_like("name", v, parts, binds);
    }
    if let Some(v) = filter.arch {
        push_like("arch", v, parts, binds);
    }
    if let Some(v) = filter.status {
        crate::state::db::push_eq_and(parts, binds, "status", "=", v.to_string());
    }
}

impl StateStore {
    /// 查找心跳超时的 Worker（`last_heartbeat < now - timeout_secs`），返回 `(worker_id, name)` 列表。
    pub async fn list_offline_workers(
        &self,
        timeout_secs: i64,
    ) -> crate::Result<Vec<(i64, String)>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(&sql::list_offline_workers(self.dialect))
            .bind(timeout_secs)
            .fetch_all(self.pool())
            .await
            .db_ctx("list offline workers")?;

        Ok(rows)
    }

    /// 列出优雅停机后过龄的 offline Worker（`status='offline'` 且心跳过龄，
    /// 起点 = mark_offline 刷新的心跳）；reclaimer 用此回收其 running 行
    ///（`list_offline_workers` 只匹配 online）。返回 `(worker_id, name)` 列表。
    pub async fn list_gone_workers(&self, timeout_secs: i64) -> crate::Result<Vec<(i64, String)>> {
        let rows: Vec<(i64, String)> = sqlx::query_as(&sql::list_gone_workers(self.dialect))
            .bind(timeout_secs)
            .fetch_all(self.pool())
            .await
            .db_ctx("list gone workers")?;

        Ok(rows)
    }

    /// 列出所有 Worker（不限在线状态），按 id 排序。
    pub async fn list_workers(&self) -> crate::Result<Vec<WorkerStatus>> {
        let rows = sqlx::query_as::<_, WorkerStatusRow>(sql::LIST_WORKERS)
            .fetch_all(self.pool())
            .await
            .db_ctx("list workers")?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// 按过滤条件分页查询 Worker（name/arch LIKE 子串搜索，status 精确匹配）。
    pub async fn list_workers_filtered(
        &self,
        filter: &WorkerFilter<'_>,
    ) -> crate::Result<Vec<WorkerStatus>> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_worker_filter(&mut parts, &mut binds, filter);
        // limit/offset 已归一化为 i64，字面量拼接无注入面，且避开
        // "参数 + 表达式混合" 在 sqlx Any 下的 Bind 协议坑（同 audit.rs）。
        let sql_text = format!(
            "{}{} ORDER BY id LIMIT {} OFFSET {}",
            sql::LIST_WORKERS_FILTERED_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );

        let mut q = sqlx::query_as::<_, WorkerStatusRow>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_all(self.pool())
            .await
            .db_ctx("list workers filtered")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 按相同过滤条件统计 Worker 总数（忽略 limit/offset）。
    pub async fn count_workers_filtered(&self, filter: &WorkerFilter<'_>) -> crate::Result<i64> {
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_worker_filter(&mut parts, &mut binds, filter);
        let sql_text = format!("{}{}", sql::COUNT_WORKERS_FILTERED_PREFIX, parts.join(""));

        let mut q = sqlx::query_scalar::<_, i64>(&sql_text);
        for b in &binds {
            q = q.bind(b.as_str());
        }
        q.fetch_one(self.pool())
            .await
            .db_ctx("count workers filtered")
    }

    /// 按 secret hash 查 Worker（认证用）；`None` = hash 不匹配（认证失败）。
    pub async fn find_worker_by_secret(
        &self,
        secret_hash: &str,
    ) -> crate::Result<Option<WorkerStatus>> {
        let row = sqlx::query_as::<_, WorkerStatusRow>(sql::FIND_WORKER_BY_SECRET)
            .bind(secret_hash)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find worker by secret")?;

        Ok(row.map(|r| r.into()))
    }

    /// 设置 Worker secret hash（用于 `worker add` / `worker rotate-secret`）。
    pub async fn set_worker_secret(&self, worker_id: i64, secret_hash: &str) -> crate::Result<()> {
        sqlx::query(sql::SET_WORKER_SECRET)
            .bind(secret_hash)
            .bind(worker_id)
            .execute(self.pool())
            .await
            .db_ctx("set worker secret")?;
        // 换密钥改变 secret→身份映射：bump 代数使旧 secret 缓存快照下请求即失效
        //（401 即时生效，无 TTL 残留窗口）。
        self.bump_user_generation();
        Ok(())
    }

    /// 清除 Worker secret（撤销，Worker 立即无法认证）。
    pub async fn clear_worker_secret(&self, worker_id: i64) -> crate::Result<()> {
        sqlx::query(sql::CLEAR_WORKER_SECRET)
            .bind(worker_id)
            .execute(self.pool())
            .await
            .db_ctx("clear worker secret")?;
        // 同 set_worker_secret：撤销改变映射，bump 让缓存即时失效。
        self.bump_user_generation();
        Ok(())
    }

    /// 原子删除 Worker 及其 worker_tasks 记录（事务内，不留半删态）；仅非
    /// online 可删（守卫 SELECT 拒 online + DELETE 自带 `status <> 'online'`
    /// CAS）。TOCTOU 双层防线：PG BEGIN 不锁行，守卫读与 DELETE 之间心跳可能
    /// 把 offline 翻回 online，CAS 折叠为 0 行 → 整事务 ROLLBACK（不留半清理态）
    /// 返回 `Online`。用 `begin_write()`（SQLite BEGIN IMMEDIATE）而非 DEFERRED
    /// `pool().begin()`：读后写序列，DEFERRED 首写才升级写锁、可撞 SQLITE_BUSY；
    /// 错误路径显式 ROLLBACK。
    pub async fn delete_worker_if_offline(
        &self,
        worker_id: i64,
    ) -> crate::Result<DeleteWorkerOutcome> {
        let mut conn = self.begin_write().await?;
        let status: Option<(String,)> = sqlx::query_as(sql::SELECT_WORKER_STATUS)
            .bind(worker_id)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("select worker status")?;
        match status {
            None => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Ok(DeleteWorkerOutcome::NotFound)
            }
            Some((ref s,)) if s == "online" => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Ok(DeleteWorkerOutcome::Online)
            }
            _ => {
                // BEGIN 后任何错误（含 COMMIT 失败）返回前先 best-effort
                // ROLLBACK，避免开着事务的连接回池污染（PG 25P02 / SQLite 持写锁）。
                let outcome: crate::Result<bool> = async {
                    // 删分配行前重置名下非终态 build（终态守卫仅 assigned/building
                    // 可重置）：worker 删后 reclaimer（按 workers 表枚举）看不到；
                    // assigned 连 zombie 修复（只扫 pending/building）入口都没有，
                    // 不重置即永久孤儿。init 行（build_id NULL）无 build 可重置。
                    let build_ids: Vec<Option<i64>> =
                        sqlx::query_scalar(sql::LIST_WORKER_TASK_BUILD_IDS)
                            .bind(worker_id)
                            .fetch_all(&mut *conn)
                            .await
                            .db_ctx("list worker task build ids")?;
                    for build_id in build_ids.into_iter().flatten() {
                        let reset = sqlx::query(&sql::reset_build_to_pending(self.dialect))
                            .bind(build_id)
                            .execute(&mut *conn)
                            .await
                            .db_ctx("reset build to pending on worker delete")?;
                        // reset 0 行 = 并发推进或预算耗尽；后者就地转终态防永卡。
                        if reset.rows_affected() > 0 {
                            tracing::info!(
                                worker_id = %worker_id,
                                build_id = %build_id,
                                "Reset non-terminal build to pending on worker delete"
                            );
                        } else if self
                            .fail_build_if_retry_exhausted(&mut conn, build_id)
                            .await?
                        {
                            tracing::warn!(
                                build_id = %build_id,
                                "Build failed: retry budget exhausted on worker delete reclaim"
                            );
                        }
                    }
                    sqlx::query(sql::DELETE_WORKER_TASKS_BY_WORKER)
                        .bind(worker_id)
                        .execute(&mut *conn)
                        .await
                        .db_ctx("delete worker tasks")?;
                    // DELETE 的 offline CAS 0 行（守卫读后心跳翻回 online）：
                    // 半清理态必须整体 ROLLBACK 后按 Online 返回。
                    let del = sqlx::query(sql::DELETE_WORKER_IF_OFFLINE)
                        .bind(worker_id)
                        .execute(&mut *conn)
                        .await
                        .db_ctx("delete worker")?;
                    if del.rows_affected() == 0 {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Ok(false);
                    }
                    sqlx::query("COMMIT")
                        .execute(&mut *conn)
                        .await
                        .db_ctx("commit tx")?;
                    Ok(true)
                }
                .await;
                match outcome {
                    Ok(true) => {
                        // 有 build 回退 pending 即广播，调度器立刻重派。
                        self.notify_state_changed();
                        // 删除连带删 secret：bump 使缓存里的 secret→身份快照
                        // 失效，否则已删 worker 的凭据在 TTL 窗口内仍可通过认证。
                        self.bump_user_generation();
                        Ok(DeleteWorkerOutcome::Deleted)
                    }
                    Ok(false) => Ok(DeleteWorkerOutcome::Online),
                    Err(e) => {
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        Err(e)
                    }
                }
            }
        }
    }

    /// 全量回收（assigned + running，builds 重置 pending、删 worker_tasks 分配行），
    /// 供失联超**双倍**心跳阈值者（scheduler
    /// `WORKER_RUNNING_RECLAIM_TIMEOUT_SECS`）；仅超标准阈值用
    /// [`Self::reclaim_assigned_worker_tasks`]。全部写操作（含 Worker 置
    /// offline）单事务完成，不留半回收态。`min_stale_secs`：事务内首条语句复查
    /// `last_heartbeat` 仍超阈才动手——决策基于事务外离线快照，刚恢复者免误回收
    /// 重派（双执行根因）。返回 `(task_id, build_id)`（init 为 None）；复查不过
    ///（worker 恢复/行已删）返回空列表且不改任何状态。
    pub async fn reclaim_worker_tasks(
        &self,
        worker_id: i64,
        min_stale_secs: i64,
    ) -> crate::Result<Vec<(i64, Option<i64>)>> {
        self.reclaim_worker_tasks_scoped(worker_id, true, min_stale_secs)
            .await
    }

    /// 只回收 `assigned`（未开跑），`running` 保留——双阈值回收第一档。running
    /// 失联超双倍阈值才重置（心跳 30s / 判死 120s = 丢 4 拍）：瞬时过载/抖动下
    /// 重置仍在构建的任务会被他机领取，两台交错上传同一 `{artifact_dir}/{build_id}/`
    /// 产物互相覆盖。双倍阈值只缩小不消除竞态：被剥夺者在途上传在
    /// `update_build_info_tx_guarded` 归属谓词处被拒（0 行 → rollback + 清已写盘
    /// 文件），迟到 report_result 经 `complete_build_guarded` 归属 CAS 提交点被拒；
    /// 协议级 lease 仍为升级路径。`min_stale_secs` 语义同 [`Self::reclaim_worker_tasks`]。
    pub async fn reclaim_assigned_worker_tasks(
        &self,
        worker_id: i64,
        min_stale_secs: i64,
    ) -> crate::Result<Vec<(i64, Option<i64>)>> {
        self.reclaim_worker_tasks_scoped(worker_id, false, min_stale_secs)
            .await
    }

    /// Worker（重）注册时回收其名下 `running` assignment。缺此回收：崩溃秒级
    /// 重注册翻回 online、心跳新鲜，reclaimer（要求 online 且心跳超龄）与
    /// zombie 修复（跳过有活跃 worker_task 行的 building 行）都收不到 → build
    /// 永卡 building、capacity 楔死。`assigned` 不在此重置（poll 自然重新交付，
    /// at-least-once）；init 行（build_id NULL）只删行。不改 worker status、
    /// 不碰其他 worker 的行；仅限自身重注册路径（register 路由 role=worker
    /// 分支）——管理员代注册时进程可能仍活着，重置 running 会双执行。
    /// 返回 `(task_id, build_id)`（init 为 None）。
    pub async fn reclaim_running_assignments_on_register(
        &self,
        worker_id: i64,
    ) -> crate::Result<Vec<(i64, Option<i64>)>> {
        // 读-then-写：begin_write() 先拿写锁，避免 DEFERRED 读后升级撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await?;

        const LIST_RUNNING_WORKER_TASKS: &str =
            "SELECT id, build_id FROM worker_tasks WHERE worker_id = $1 AND status = 'running'";

        let running: Vec<(i64, Option<i64>)> = match sqlx::query_as(LIST_RUNNING_WORKER_TASKS)
            .bind(worker_id)
            .fetch_all(&mut *conn)
            .await
            .db_ctx("list running worker tasks")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };

        let mut affected = Vec::new();
        for (task_id, build_id_opt) in running {
            match sqlx::query(sql::DELETE_WORKER_TASK)
                .bind(task_id)
                .execute(&mut *conn)
                .await
                .db_ctx("delete running worker task")
            {
                Ok(_) => {}
                Err(e) => rollback_and_return!(conn, e),
            };

            if let Some(build_id) = build_id_opt {
                match sqlx::query(&sql::reset_build_to_pending(self.dialect))
                    .bind(build_id)
                    .execute(&mut *conn)
                    .await
                    .db_ctx("reset running build to pending")
                {
                    Ok(_) => {}
                    Err(e) => rollback_and_return!(conn, e),
                };
            }

            affected.push((task_id, build_id_opt));
        }

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("commit tx")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        if !affected.is_empty() {
            // 回收（builds 回退 pending）即广播，调度器立刻重派。
            self.notify_state_changed();
        }
        Ok(affected)
    }

    /// [`Self::reclaim_worker_tasks`] 的实现：`include_running=false` 时只处理
    /// `assigned` 状态的 worker_tasks 行。`min_stale_secs`：事务内心跳复查阈值。
    async fn reclaim_worker_tasks_scoped(
        &self,
        worker_id: i64,
        include_running: bool,
        min_stale_secs: i64,
    ) -> crate::Result<Vec<(i64, Option<i64>)>> {
        // 读-then-写：begin_write() 先拿写锁，避免 DEFERRED 读后升级撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await?;

        // BEGIN 后任何错误（含 COMMIT 失败）先 ROLLBACK：开着事务的连接回池
        // 会污染（SQLite 持写锁 / PG 池污染）。
        // 事务内首条语句复查心跳仍超阈：决策来自事务外离线快照，刚过阈即恢复
        // 心跳的 worker 不复查会被强制 offline + 任务重派（双执行根因）。复查
        // 0 行（心跳恢复/行已删）→ 本轮全跳过（含 SET offline），下一轮快照自纠。
        let stale: Option<i64> =
            match sqlx::query_scalar(&sql::worker_heartbeat_stale(self.dialect))
                .bind(worker_id)
                .bind(min_stale_secs)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("recheck worker heartbeat staleness")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };
        if stale.is_none() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            tracing::info!(
                worker_id = %worker_id,
                min_stale_secs = min_stale_secs,
                "Reclaim skipped: worker heartbeat recovered since reclaimer snapshot"
            );
            return Ok(Vec::new());
        }

        // 双阈值第一档只回收 assigned（未开跑，重派零代价）。
        const LIST_ASSIGNED_WORKER_TASKS: &str =
            "SELECT id, build_id FROM worker_tasks WHERE worker_id = $1 AND status = 'assigned'";
        let stuck_sql = if include_running {
            sql::LIST_STUCK_WORKER_TASKS
        } else {
            LIST_ASSIGNED_WORKER_TASKS
        };

        let stuck: Vec<(i64, Option<i64>)> = match sqlx::query_as(stuck_sql)
            .bind(worker_id)
            .fetch_all(&mut *conn)
            .await
            .db_ctx("list stuck tasks")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };

        let mut affected = Vec::new();
        for (task_id, build_id_opt) in stuck {
            match sqlx::query(sql::DELETE_WORKER_TASK)
                .bind(task_id)
                .execute(&mut *conn)
                .await
                .db_ctx("delete worker task")
            {
                Ok(_) => {}
                Err(e) => rollback_and_return!(conn, e),
            };

            if let Some(build_id) = build_id_opt {
                // 重置为 pending（started_at 重置见 reset_build_to_pending）。
                // 0 行 = 并发推进或重试预算耗尽：后者必须就地转终态——本函数
                // 随后删掉 assignment，assigned 行再无回收入口（zombie 只扫
                // pending/building），会永久占住任务与产品活跃额度。
                let reset = match sqlx::query(&sql::reset_build_to_pending(self.dialect))
                    .bind(build_id)
                    .execute(&mut *conn)
                    .await
                    .db_ctx("reset build to pending")
                {
                    Ok(r) => r.rows_affected(),
                    Err(e) => rollback_and_return!(conn, e),
                };
                if reset == 0
                    && self
                        .fail_build_if_retry_exhausted(&mut conn, build_id)
                        .await?
                {
                    tracing::warn!(
                        build_id = %build_id,
                        "Build failed: retry budget exhausted on stale-worker reclaim"
                    );
                }
            }

            affected.push((task_id, build_id_opt));
        }

        match sqlx::query(sql::SET_WORKER_OFFLINE)
            .bind(worker_id)
            .execute(&mut *conn)
            .await
            .db_ctx("update worker status")
        {
            Ok(_) => {}
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

        // 回收（worker 下线 + builds 回退 pending）即广播；无回收行只是无害唤醒。
        self.notify_state_changed();
        Ok(affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state::create_test_store;
    use crate::state::BuildInsert;

    /// 夹具：插一条挂本地任务的 pending build（builds.task_id NOT NULL，
    /// 先插任务行承接）。
    async fn mk_build(store: &StateStore, pkg: &str) -> i64 {
        let task_id = crate::state::test_state::seed_task(store, "mydist", pkg).await;
        store
            .insert_build(BuildInsert {
                product: "mydist",
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    /// 双阈值第一档：`reclaim_assigned_worker_tasks` 只回收 assigned（未开跑），
    /// running（已开跑）保留，到全量档 `reclaim_worker_tasks` 才回收。
    #[tokio::test]
    async fn test_reclaim_assigned_only_spares_running_tasks() {
        let (store, _tmp) = create_test_store().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 4, "0.15.0-dev", "online", None)
            .await
            .unwrap();

        let b_assigned = mk_build(&store, "p1").await;
        let b_running = mk_build(&store, "p2").await;
        store
            .assign_build_to_worker(b_assigned, worker_id)
            .await
            .unwrap();
        store
            .assign_build_to_worker(b_running, worker_id)
            .await
            .unwrap();
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
            .bind(b_running)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(b_running)
            .execute(store.pool())
            .await
            .unwrap();

        // 心跳回拨至远超阈值（失联夹具）；阈值按各档语义透传（第一档 120s /
        // 全量档 240s，与 scheduler 调用形态一致）。
        sqlx::query(&format!(
            "UPDATE workers SET last_heartbeat = {} WHERE id = $1",
            crate::state::test_state::sql_time_offset(store.dialect(), "-300 seconds")
        ))
        .bind(worker_id)
        .execute(store.pool())
        .await
        .unwrap();

        // 第一档（失联 >120s 未达双阈值）：assigned 回收重派，running 保留。
        let affected = store
            .reclaim_assigned_worker_tasks(worker_id, 120)
            .await
            .unwrap();
        assert_eq!(affected.len(), 1, "only the assigned task is reclaimed");
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_assigned)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "pending");
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_running)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            phase, "building",
            "running task must survive the first tier"
        );
        let running_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
                .bind(b_running)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(running_rows, 1, "running worker_task row must survive");

        // 第二档（失联 > 双阈值）：running 也回收（心跳仍过期，复查放行；
        // 第一档已把 worker 置 offline——复查不带 status 谓词，gone 档同一刻度）。
        let affected = store.reclaim_worker_tasks(worker_id, 240).await.unwrap();
        assert_eq!(affected.len(), 1);
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_running)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "pending");
    }

    /// 快照后 worker 恢复心跳（回拨后再推新）→ reclaim 整轮跳过；失联仍过期
    /// 的对照臂照常回收。
    #[tokio::test]
    async fn reclaim_skips_worker_when_heartbeat_recovered() {
        let (store, _tmp) = create_test_store().await;
        let worker_id = store
            .upsert_worker("w-recovered", "x86_64", 4, "0.15.0-dev", "online", None)
            .await
            .unwrap();

        let task_id = crate::state::test_state::seed_task(&store, "mydist", "p-recover").await;
        let build_id = store
            .insert_build(BuildInsert {
                product: "mydist",
                pkg_name: "p-recover",
                phase: "pending",
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .assign_build_to_worker(build_id, worker_id)
            .await
            .unwrap();

        let set_heartbeat = |offset: &'static str| {
            let store = &store;
            async move {
                sqlx::query(&format!(
                    "UPDATE workers SET last_heartbeat = {} WHERE id = $1",
                    crate::state::test_state::sql_time_offset(store.dialect(), offset)
                ))
                .bind(worker_id)
                .execute(store.pool())
                .await
                .unwrap();
            }
        };

        // 快照时刻：失联 300s（>120s 阈值，reclaimer 会把该 worker 收进快照）。
        set_heartbeat("-300 seconds").await;

        set_heartbeat("+0 seconds").await;
        let affected = store
            .reclaim_assigned_worker_tasks(worker_id, 120)
            .await
            .unwrap();
        assert!(
            affected.is_empty(),
            "recovered worker must be skipped this round"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM workers WHERE id = $1")
            .bind(worker_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            status, "online",
            "recovered worker must not be forced offline"
        );
        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(
            phase, "assigned",
            "recovered worker's task must be preserved"
        );
        let wt_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(wt_rows, 1, "assignment row must survive the skipped round");

        // 对照臂：心跳仍过期（回拨）→ 复查放行，照常回收。
        set_heartbeat("-300 seconds").await;
        let affected = store
            .reclaim_assigned_worker_tasks(worker_id, 120)
            .await
            .unwrap();
        assert_eq!(
            affected,
            vec![(task_id, Some(build_id))],
            "stale heartbeat must reclaim as usual"
        );
    }

    /// `delete_worker_if_offline` 三态语义：offline 时删除，online 时拒绝，不存在返 NotFound。
    #[tokio::test]
    async fn test_delete_worker_if_offline_three_states() {
        let (store, _tmp) = create_test_store().await;

        let outcome = store.delete_worker_if_offline(9999).await.unwrap();
        assert_eq!(outcome, DeleteWorkerOutcome::NotFound);

        let wid = store
            .upsert_worker("w1", "x86_64", 4, "1.0", "online", None)
            .await
            .unwrap();
        sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
            .bind(wid)
            .execute(store.pool())
            .await
            .unwrap();

        let outcome = store.delete_worker_if_offline(wid).await.unwrap();
        assert_eq!(outcome, DeleteWorkerOutcome::Deleted);
        let outcome = store.delete_worker_if_offline(wid).await.unwrap();
        assert_eq!(outcome, DeleteWorkerOutcome::NotFound);

        let wid2 = store
            .upsert_worker("w2", "aarch64", 2, "1.0", "online", None)
            .await
            .unwrap();

        let outcome = store.delete_worker_if_offline(wid2).await.unwrap();
        assert_eq!(outcome, DeleteWorkerOutcome::Online);
        let w = store.get_worker(wid2).await.unwrap();
        assert!(w.is_some());
    }

    /// 注册回收：只回收本 worker 的 `running` 行并重置对应 build；`assigned`
    /// 行（poll 自然重新交付）、其他 worker 的行、worker status 一律不动。
    #[tokio::test]
    async fn test_reclaim_running_on_register_scopes_to_own_running_rows() {
        let (store, _tmp) = create_test_store().await;
        let w1 = store
            .upsert_worker("w-reg", "x86_64", 2, "1.0", "online", None)
            .await
            .unwrap();
        let w2 = store
            .upsert_worker("w-other", "x86_64", 2, "1.0", "online", None)
            .await
            .unwrap();

        let b_running = mk_build(&store, "p-run").await;
        let b_assigned = mk_build(&store, "p-asg").await;
        let b_other = mk_build(&store, "p-other").await;
        store.assign_build_to_worker(b_running, w1).await.unwrap();
        store.assign_build_to_worker(b_assigned, w1).await.unwrap();
        store.assign_build_to_worker(b_other, w2).await.unwrap();
        for build_id in [b_running, b_other] {
            sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
                .bind(build_id)
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
                .bind(build_id)
                .execute(store.pool())
                .await
                .unwrap();
        }

        let affected = store
            .reclaim_running_assignments_on_register(w1)
            .await
            .unwrap();
        assert_eq!(affected.len(), 1, "only w1's running row is reclaimed");

        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_running)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "pending");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
            .bind(b_running)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(rows, 0, "running worker_task row must be deleted");

        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_assigned)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "assigned");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
            .bind(b_assigned)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(rows, 1, "assigned worker_task row must survive");

        let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(b_other)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(phase, "building");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
            .bind(b_other)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(rows, 1, "other worker's running row must survive");

        let w = store.get_worker(w1).await.unwrap().unwrap();
        assert_eq!(w.status, "online");
    }

    /// 注册回收的调用方守卫（仅 register 路由 role=worker 分支）在 server 侧；
    /// 状态层钉住：空 worker（无 assignment）调用是 no-op。
    #[tokio::test]
    async fn test_reclaim_running_on_register_noop_without_rows() {
        let (store, _tmp) = create_test_store().await;
        let wid = store
            .upsert_worker("w-empty", "x86_64", 2, "1.0", "online", None)
            .await
            .unwrap();
        let affected = store
            .reclaim_running_assignments_on_register(wid)
            .await
            .unwrap();
        assert!(affected.is_empty());
    }

    /// 锁定过滤 SQL 形态（纯文本，不执行）：bind 占位符必须是 `$N` 编号风格
    /// （PG 兼容；QueryBuilder<Any> 生成 `?`，PG 在 ORDER 附近报语法错）。
    #[test]
    fn workers_filtered_query_uses_numbered_placeholders() {
        let filter = WorkerFilter {
            name: Some("build"),
            arch: Some("x86"),
            status: Some("online"),
            ..Default::default()
        };
        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_worker_filter(&mut parts, &mut binds, &filter);
        let sql = format!(
            "{}{} ORDER BY id LIMIT {} OFFSET {}",
            sql::LIST_WORKERS_FILTERED_PREFIX,
            parts.join(""),
            filter.normalized_limit(),
            filter.offset.max(0),
        );
        assert!(!sql.contains('?'), "must use $N placeholders, got: {sql}");
        assert!(
            sql.contains("$1") && sql.contains("$2") && sql.contains("$3"),
            "each condition gets its own numbered bind: {sql}"
        );
        assert_eq!(
            binds,
            vec![
                "%build%".to_string(),
                "%x86%".to_string(),
                "online".to_string()
            ]
        );

        let mut parts = Vec::new();
        let mut binds = Vec::new();
        push_worker_filter(&mut parts, &mut binds, &WorkerFilter::default());
        assert!(parts.is_empty());
        assert!(binds.is_empty());
    }

    /// DELETE 的 `status <> 'online'` CAS 只排除 online：draining / suspended
    ///（管理员状态）与 offline 同样可删（三态测试只钉 offline，此处钉住不误伤）。
    #[tokio::test]
    async fn delete_worker_if_offline_deletes_draining_and_suspended() {
        let (store, _tmp) = create_test_store().await;
        for status in ["draining", "suspended"] {
            let wid = store
                .upsert_worker("w-del", "x86_64", 2, "1.0", "online", None)
                .await
                .unwrap();
            sqlx::query("UPDATE workers SET status = $1 WHERE id = $2")
                .bind(status)
                .bind(wid)
                .execute(store.pool())
                .await
                .unwrap();
            let outcome = store.delete_worker_if_offline(wid).await.unwrap();
            assert_eq!(
                outcome,
                DeleteWorkerOutcome::Deleted,
                "{status} must be deletable"
            );
            assert!(
                store.get_worker(wid).await.unwrap().is_none(),
                "{status} worker row must be gone"
            );
        }
    }

    /// 删 offline worker：非终态 build（assigned/building）重置 pending（分配行
    /// 删后 reclaimer 看不到，不重置即永久孤儿）；终态不动；本体与分配行删除。
    #[tokio::test]
    async fn delete_worker_if_offline_resets_nonterminal_builds() {
        let (store, _tmp) = create_test_store().await;
        let wid = store
            .upsert_worker("w-del", "x86_64", 2, "1.0", "online", None)
            .await
            .unwrap();
        sqlx::query("UPDATE workers SET status = 'offline' WHERE id = $1")
            .bind(wid)
            .execute(store.pool())
            .await
            .unwrap();

        let b_assigned = mk_build(&store, "p-asg").await;
        let b_building = mk_build(&store, "p-bld").await;
        let b_done = mk_build(&store, "p-done").await;
        let b_other = mk_build(&store, "p-other").await;
        store.assign_build_to_worker(b_assigned, wid).await.unwrap();
        store.assign_build_to_worker(b_building, wid).await.unwrap();
        store.assign_build_to_worker(b_done, wid).await.unwrap();

        // 终态构建：分配行在，但 build 已 succeeded——不得被重置。
        sqlx::query("UPDATE builds SET phase = 'succeeded' WHERE id = $1")
            .bind(b_done)
            .execute(store.pool())
            .await
            .unwrap();

        // 其他 worker 的 assigned build：不得被波及。
        let other = store
            .upsert_worker("w-keep", "x86_64", 2, "1.0", "online", None)
            .await
            .unwrap();
        store.assign_build_to_worker(b_other, other).await.unwrap();

        let outcome = store.delete_worker_if_offline(wid).await.unwrap();
        assert_eq!(outcome, DeleteWorkerOutcome::Deleted);

        let phase = |id: i64| {
            let store = &store;
            async move {
                let p: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
                p
            }
        };
        assert_eq!(phase(b_assigned).await, "pending", "assigned must be reset");
        assert_eq!(phase(b_building).await, "pending", "building must be reset");
        assert_eq!(
            phase(b_done).await,
            "succeeded",
            "terminal must be untouched"
        );
        assert_eq!(
            phase(b_other).await,
            "assigned",
            "other worker's build must be untouched"
        );
        assert!(store.get_worker(wid).await.unwrap().is_none());
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE worker_id = $1")
                .bind(wid)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(rows, 0, "deleted worker's assignment rows must be gone");
    }
}
