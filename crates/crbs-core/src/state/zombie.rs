// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 僵尸构建修复：失联 worker 与崩溃残留的状态回收。

use sqlx::any::AnyRow;
use sqlx::Row;
use tracing::warn;

use super::StateStore;
use crate::error::DbResultExt;

mod sql {
    pub(super) const LIST_ACTIVE_BUILDS_FOR_PRODUCT: &str =
        "SELECT id, phase, crbs_pid, layer_digest, result_dir FROM builds \
         WHERE product = $1 AND phase IN ('pending', 'building')";

    pub(super) const LIST_ACTIVE_BUILDS_ALL: &str =
        "SELECT id, phase, crbs_pid, layer_digest, result_dir FROM builds \
         WHERE phase IN ('pending', 'building')";

    /// 该 build 是否仍有活跃 worker_tasks 行；"活跃"口径（assigned/running）与其他活跃判定保持一致。
    pub(super) const EXISTS_ACTIVE_WORKER_TASK: &str = "\
        SELECT 1 FROM worker_tasks \
        WHERE build_id = $1 AND status IN ('assigned', 'running') \
        LIMIT 1";

    /// pick→attach 崩溃窗口修复：building 且从未 attach 的行重置回 pending。
    /// 年龄守卫度量自 pick 时刻（pick SQL 置 building 时重置 started_at），仅接受
    /// started_at 早于 5 分钟宽限的行：宽限远大于最坏 spawn 积压、远小于兄弟修复器
    /// 的 30 分钟；无守卫会把刚 pick 的活构建重置回 pending，调度器二次派发、双执行。
    /// started_at 重置折进同一语句 SET 子句（WHERE 年龄谓词按 UPDATE 前行值求值，
    /// 不受影响），避免卡死期等待时间经 sql_priority_wait_weight 转化为插队优先级。
    pub(super) fn reset_unattached_build_to_pending(dialect: crate::state::Dialect) -> String {
        format!(
            "UPDATE builds \
            SET phase = 'pending', started_at = {}, completed_at = NULL, duration = NULL, crbs_pid = NULL, \
                attempt = attempt + 1 \
            WHERE id = $1 AND phase = 'building' \
              AND started_at <= {} \
              AND attempt < {}",
            dialect.sql_now(),
            dialect.sql_minutes_ago(5),
            crate::state::MAX_BUILD_ATTEMPTS
        )
    }
}

impl StateStore {
    /// 修复指定产品下的僵尸活跃构建记录，返回 `(已修复数, 未修复数)`。
    ///
    /// 扫描 `phase IN ('pending', 'building')`：死 pid 行置 `failed`（补全
    /// `completed_at` / `duration`，building 行释放 SharedLayer 引用），NULL pid
    /// 行分类见 `Self::repair_zombie_rows`；存活行保持原状。第二个计数含
    /// 存活 pid 行与 NULL pid 远程行，并非本地存活构建数。
    pub async fn repair_zombie_active_builds_for_product(
        &self,
        product: &str,
    ) -> crate::Result<(usize, usize)> {
        let rows = sqlx::query(sql::LIST_ACTIVE_BUILDS_FOR_PRODUCT)
            .bind(product)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list active builds for repair")?;

        let (repaired, live) = self.repair_zombie_rows(rows).await?;
        Ok((repaired.len(), live))
    }

    /// 修复所有产品下的僵尸活跃构建记录，Server 启动时与孤儿清扫循环周期调用。
    ///
    /// 返回 `(修复的 build id 集, 未修复数)`：id 集供上层对每个修复行触发
    /// `spawn_on_build_terminal` 终态钩子，含翻终态 failed 的死 pid 行与重置
    /// pending 的崩溃窗口行（后者非终态写入，钩子的终态守卫 no-op）。
    /// 第二个计数含存活 pid 行与 NULL pid 远程行，并非本地存活构建数。
    pub async fn repair_all_zombie_active_builds(&self) -> crate::Result<(Vec<i64>, usize)> {
        let rows = sqlx::query(sql::LIST_ACTIVE_BUILDS_ALL)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list active builds for repair")?;

        self.repair_zombie_rows(rows).await
    }

    /// [`Self::repair_zombie_active_builds_for_product`] 的日志包装（init 守卫与
    /// clean 共用）：失败只 warn 不阻断调用方，真实存活的构建仍由各自 active 守卫拦截。
    pub async fn repair_zombie_active_builds_logged(&self, product: &str) {
        match self.repair_zombie_active_builds_for_product(product).await {
            Ok((repaired, live)) if repaired > 0 => {
                warn!(product = %product, repaired, live, "Repaired zombie active builds");
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    product = %product,
                    error = %e,
                    "Failed to repair zombie active builds, continuing"
                );
            }
        }
    }

    /// 返回 `(修复的 build id 集, 未修复数)`：id 集语义见
    /// [`Self::repair_all_zombie_active_builds`]，供 for_product 包装折回计数。
    async fn repair_zombie_rows(&self, rows: Vec<AnyRow>) -> crate::Result<(Vec<i64>, usize)> {
        let mut repaired: Vec<i64> = Vec::new();
        let mut live = 0usize;
        for row in rows {
            let id: i64 = row.get("id");
            let phase: String = row.get("phase");
            let pid: Option<i64> = row.get("crbs_pid");
            let layer_digest: Option<String> = row.get("layer_digest");
            let result_dir: Option<String> = row.get("result_dir");

            match pid {
                Some(pid) if crate::util::is_process_alive(pid).await => {
                    live += 1;
                    continue;
                }
                Some(_) => {
                    // crbs_pid 已设置但进程已死 → 僵尸，落入下方修复逻辑。
                }
                None => {
                    // crbs_pid 为 NULL 的两类行（区分假设见 has_active_worker_task 文档）：
                    // - 有活跃 worker_tasks 行：远程构建，生命周期由 worker 上报推进，跳过。
                    // - building 且无活跃行：pick→attach 崩溃窗口，从未真正开跑（无
                    //   SharedLayer 引用），重置回 pending 重试；SRPM 缺失由调度器快速失败兜底。
                    if phase == "building" && !self.has_active_worker_task(id).await? {
                        match self.reset_unattached_building_to_pending(id).await {
                            // 0 行 = 并发已推进该行，或重试预算耗尽（attempt 毒丸封顶）：转终态防永卡活跃边缘。
                            Ok(0) => {
                                let mut conn =
                                    self.pool().acquire().await.db_ctx("acquire conn")?;
                                if self.fail_build_if_retry_exhausted(&mut conn, id).await? {
                                    warn!(
                                        build_id = %id,
                                        "Build failed: retry budget exhausted on zombie repair"
                                    );
                                }
                            }
                            Ok(_) => {
                                // started_at 已随同一语句重置（全新等待计时）。
                                warn!(
                                    build_id = %id,
                                    "Reset unattached building (pick->attach crash window) back to pending"
                                );
                                repaired.push(id);
                            }
                            Err(e) => {
                                warn!(
                                    build_id = %id,
                                    error = %e,
                                    "reset unattached building to pending failed"
                                );
                            }
                        }
                        continue;
                    }
                    live += 1;
                    continue;
                }
            }

            // 终态守卫先行、赢了才释放层引用：phase 是早前快照，并发路径（执行者
            // cleanup guard / CLI cancel / 另一次 repair）先转终态时 complete_build
            // 返回 0，不得再 dec（双重扣减会把仍被引用的共享层提前 GC 掉）。
            match self
                .complete_build(id, "failed", result_dir.as_deref())
                .await
            {
                // 0 行 = 已被并发路径转终态，无需修复。
                Ok(0) => {}
                Ok(_) => {
                    repaired.push(id);
                    // 赢下翻转 ⇒ 行确实停在 building（执行者已死、guard 未跑），释放其
                    // SharedLayer 引用；宽限用与 repair_stale_builds 同款编译期默认
                    // 168h、非配置值（漂移口径见 state/gc.rs），复用窗口内不以 0 宽限提前装 GC。
                    if phase == "building" {
                        if let Some(ref digest) = layer_digest {
                            let grace_hours =
                                crate::config::defaults::default_shared_layer_gc_grace_hours();
                            if let Err(e) = self.layer_ref_dec(digest, grace_hours).await {
                                warn!(
                                    build_id = %id,
                                    digest = %digest,
                                    error = %e,
                                    "layer_ref_dec failed while repairing zombie build"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(build_id = %id, error = %e, "repair zombie build failed");
                }
            }
        }
        Ok((repaired, live))
    }

    /// 该 build 是否仍有活跃（assigned/running）worker_tasks 行。
    ///
    /// 区分假设：远程 building 构建必有活跃 worker_tasks 行（派发/开跑/回收均单事务
    /// 同步维护两表），故 `building` + pid NULL + 无活跃行只能来自本地
    /// pick_and_lock_pending 与 execute_build attach 写 pid 之间的 hub 崩溃窗口。
    async fn has_active_worker_task(&self, build_id: i64) -> crate::Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(sql::EXISTS_ACTIVE_WORKER_TASK)
            .bind(build_id)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("check active worker task for zombie repair")?;
        Ok(row.is_some())
    }

    /// pick→attach 崩溃窗口修复：把从未 attach 的 building 行重置回 pending。
    /// 返回受影响行数：`0` 表示守卫拒绝（并发路径已推进该行）。
    async fn reset_unattached_building_to_pending(&self, build_id: i64) -> crate::Result<u64> {
        let result = sqlx::query(&sql::reset_unattached_build_to_pending(self.dialect))
            .bind(build_id)
            .execute(&self.pool)
            .await
            .db_ctx("reset unattached building to pending")?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {

    use crate::state::test_state::{create_test_store, sql_time_offset};
    use crate::state::{BuildInsert, StateStore, TaskInsert};

    /// builds.task_id NOT NULL：测试造 build 前先插一条本地任务行。
    async fn seed_task_id(store: &StateStore, product: &str, pkg_name: &str) -> i64 {
        store
            .insert_task(TaskInsert {
                product,
                pkg_name,
                user: "test",
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn build_phase(store: &StateStore, id: i64) -> String {
        sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    /// pick→attach 崩溃窗口：building + pid NULL + 无活跃 worker_tasks 行 →
    /// 重置回 pending 并计入 repaired，started_at 同语句重置（全新等待计时）。
    #[tokio::test]
    async fn repair_resets_unattached_building_to_pending() {
        let (store, _tmp) = create_test_store().await;
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "test",
                crbs_pid: None,
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        // 年龄守卫：started_at 回拨到 5 分钟宽限之外（刚 pick 的行在保护窗口内）。
        // 回拨 SQL 方言感知：钉住守卫谓词 sql_minutes_ago(5) 的 PG 渲染面
        // （UTC 帧 to_char 形态）与列存储 TEXT 同帧可比。
        let time_sql = sql_time_offset(store.dialect(), "-10 minutes");
        sqlx::query(&format!("UPDATE builds SET started_at = {time_sql}"))
            .execute(store.pool())
            .await
            .unwrap();
        let aged: String = sqlx::query_scalar("SELECT started_at FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();

        let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(
            repaired_ids.len(),
            1,
            "aged unattached building must be repaired"
        );
        // 崩溃窗口重置行计入 id 集（非终态写入，终态钩子守卫 no-op）。
        assert_eq!(repaired_ids, vec![id]);
        assert_eq!(live, 0);
        assert_eq!(
            build_phase(&store, id).await,
            "pending",
            "build never actually started; must be retried, not failed"
        );
        let reset: String = sqlx::query_scalar("SELECT started_at FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(
            reset > aged,
            "repaired pending build must get a fresh started_at in the same statement \
             (aged={aged}, reset={reset})"
        );
    }

    /// 宽限窗口内的行不得重置：否则刚 pick 的活构建被重置，调度器二次派发、双执行。
    #[tokio::test]
    async fn repair_keeps_fresh_unattached_building_within_grace() {
        let (store, _tmp) = create_test_store().await;
        let _id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "test",
                crbs_pid: None,
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let (repaired_ids, _live) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(
            repaired_ids.len(),
            0,
            "fresh pick→attach window must be protected"
        );
    }

    /// 远程在跑构建（crbs_pid NULL 但有活跃 worker_tasks 行）不受影响：
    /// 生命周期由 worker 管理，保持 building。
    #[tokio::test]
    async fn repair_keeps_remote_building_with_active_worker_task() {
        let (store, _tmp) = create_test_store().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0", "online", None)
            .await
            .unwrap();
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "pending",
                backend: "nspawn",
                user: "test",
                arch: Some("x86_64"),
                crbs_pid: None,
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        // 模拟完整远程链路：派发（建 worker_tasks 行）→ worker 开跑（running + building）。
        store.assign_build_to_worker(id, worker_id).await.unwrap();
        sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap();

        let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(repaired_ids.len(), 0, "remote building must not be touched");
        assert_eq!(live, 1);
        assert_eq!(
            build_phase(&store, id).await,
            "building",
            "remote build lifecycle is owned by the worker"
        );
    }

    /// assigned 阶段（worker 未开跑）不在扫描范围（`phase IN ('pending','building')`
    /// 不含 assigned），保持原状：回收归 reclaimer 管。
    #[tokio::test]
    async fn repair_keeps_assigned_remote_build() {
        let (store, _tmp) = create_test_store().await;
        let worker_id = store
            .upsert_worker("w1", "x86_64", 2, "0.15.0", "online", None)
            .await
            .unwrap();
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "pending",
                backend: "nspawn",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();
        store.assign_build_to_worker(id, worker_id).await.unwrap();

        let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(repaired_ids.len(), 0);
        assert_eq!(live, 0, "assigned rows are outside the repair scan");
        assert_eq!(build_phase(&store, id).await, "assigned");
    }

    /// pending + crbs_pid NULL（尚未被调度）保持原状——这是 recover 路径的地盘。
    #[tokio::test]
    async fn repair_keeps_null_pid_pending_build() {
        let (store, _tmp) = create_test_store().await;
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "pending",
                backend: "chroot",
                user: "test",
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(repaired_ids.len(), 0);
        assert_eq!(live, 1);
        assert_eq!(build_phase(&store, id).await, "pending");
    }

    /// 死 pid 行翻终态 failed 时 id 落入修复 id 集（供上层触发终态钩子），存活行
    /// 不计入——钉"id 集非空且仅含翻终态的行"。
    #[tokio::test]
    async fn repair_collects_ids_for_terminal_flips_only() {
        let (store, _tmp) = create_test_store().await;
        let live_pid = std::process::id() as i64;
        // pkg 名错开避开 (product, pkg_name) 活跃去重口径（见 test_state 夹具说明）。
        let dead = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "test",
                crbs_pid: Some(999_999), // 死 pid 夹具口径同 test_state
                task_id: Some(seed_task_id(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();
        let live = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello-live",
                phase: "pending",
                backend: "chroot",
                user: "test",
                crbs_pid: Some(live_pid),
                task_id: Some(seed_task_id(&store, "fedora", "hello-live").await),
                ..Default::default()
            })
            .await
            .unwrap();

        let (repaired_ids, live_count) = store.repair_all_zombie_active_builds().await.unwrap();
        assert_eq!(
            repaired_ids,
            vec![dead],
            "修复 id 集恰为翻终态的行，存活行不计入"
        );
        assert_eq!(live_count, 1);
        assert_eq!(build_phase(&store, dead).await, "failed");
        assert_eq!(build_phase(&store, live).await, "pending");
    }
}
