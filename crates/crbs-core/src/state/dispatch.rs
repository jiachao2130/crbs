// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 资源感知调度的状态层派发 API：候选只读流 + 指定 build CAS 领取
//! （build-outer planner 的地基）。
//!
//! 谓词与排序与本地 `pick_and_lock_pending_for_local_arch`（builds.rs，hub 本地
//! 路径仍在用）同源。planner 的决策是"建议"，原子性由本层 CAS 承担。

use sqlx::Row;

use super::{pending_build_info_from_row, PendingBuildInfo, StateStore};
use crate::error::DbResultExt;
use crate::state::rollback_and_return;
use crate::state::workers::sql::insert_worker_task_build;

mod sql {
    use crate::state::Dialect;

    /// 候选列清单（分布式候选流与本地 peek 共用）。arch 经 NULLIF 归一：
    /// PG 侧列 DEFAULT ''（空串 = 未指定）、SQLite 侧 NULL = 未指定，
    /// 统一归 NULL 后 planner 内存过滤单口径。`b.name` 是源码包基础名
    ///（NVR 去 version/release）：画像/声明键用它，跨版本共享同一契约。
    const CANDIDATE_COLUMNS: &str = "b.id, b.task_id, b.product, b.pkg_name, \
        b.name AS source_name, \
        NULLIF(b.arch, '') AS arch, b.host_arches, b.priority, \
        b.created_at, b.started_at, \
        b.req_min_mem_kb, b.req_min_ncpu, b.req_min_disk_kb, b.srpm_size_bytes";

    /// 只读派发候选流（planner 输入）：就绪谓词 + 后台闸 + score 排序，与
    /// 既有 pick 的选行子查询同源；不带 UPDATE。
    ///
    /// 架构谓词与 init 门是 per-worker 判定，不在本查询（planner 内存过滤）；
    /// NULL-arch 行照常进流（无架构谓词可过滤它，planner 侧按"任意 worker
    /// 可执行但分布式 pick 从不命中 NULL 行"的既有口径处理）。
    ///
    /// 后台闸为全局谓词：单条候选流服务全部架构池、无 arch 参数可绑定，
    /// fg 子查询不带既有 pick 的 worker 架构作用域——任一架构池存在就绪
    /// 前台 pending 即压住全部后台候选（比 per-arch 作用域保守：宁少派不越
    /// 闸，前台清空即放行，无饿死面）。
    pub(super) fn list_pending_dispatch_candidates(dialect: Dialect) -> String {
        format!(
            "SELECT {CANDIDATE_COLUMNS} FROM builds b \
             WHERE b.phase = 'pending' \
               AND b.srpm_path IS NOT NULL AND b.request_json IS NOT NULL \
               AND (b.priority >= 0 OR NOT EXISTS ( \
                   SELECT 1 FROM builds fg \
                   WHERE fg.phase = 'pending' AND fg.priority >= 0 \
                     AND fg.srpm_path IS NOT NULL \
               )) \
             ORDER BY {order} \
             LIMIT $1",
            CANDIDATE_COLUMNS = CANDIDATE_COLUMNS,
            order = dialect.sql_priority_wait_weight()
        )
    }

    /// worker arch 单列查询（指定 CAS 事务内取架构参数，既有 pick 的 arch
    /// 形参同源；workers.arch 双方言 NOT NULL）。
    pub(super) const SELECT_WORKER_ARCH: &str = "SELECT arch FROM workers WHERE id = $1";

    /// 指定 build 的 CAS 领取 UPDATE：谓词 = 既有 pick 选行子查询全量复查
    /// （phase + 架构 + 就绪 + 后台闸 + init 门），仅目标由"子查询取最优"
    /// 换成"指定 id"。0 行 = 被抢 / 谓词失效。worker 在线与容量由调度器
    /// 内存态保证，不在 SQL 判（同现状）。
    ///
    /// 后台闸的 fg 子查询带 $3（worker 架构）作用域，与既有 pick 同款。
    /// 参数序：$1=build_id、$2=worker_id、$3=worker 架构。
    pub(super) fn assign_specific_build_to_worker(dialect: Dialect) -> String {
        // noarch 行可领取谓词：host_arches IS NULL = 不限制；非 NULL = 集合
        // 成员判定。主谓词与 fg 子查询必须同款（同 pick 的注释约束）。
        let claimable = |alias: &str| {
            format!(
                "({a}.arch = $3 OR ({a}.arch = 'noarch' AND ({a}.host_arches IS NULL OR {contains})))",
                a = alias,
                contains = dialect.sql_csv_contains(&format!("{alias}.host_arches"), 3)
            )
        };
        format!(
            "UPDATE builds \
             SET phase = 'assigned', \
                 started_at = {now}, \
                 completed_at = NULL, \
                 duration = NULL, \
                 crbs_pid = NULL \
             WHERE id = $1 AND phase = 'pending' \
               AND srpm_path IS NOT NULL AND request_json IS NOT NULL \
               AND {claim_b} \
               AND (priority >= 0 OR NOT EXISTS ( \
                   SELECT 1 FROM builds fg \
                   WHERE fg.phase = 'pending' AND fg.priority >= 0 \
                     AND {claim_fg} \
                     AND fg.srpm_path IS NOT NULL \
               )) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM worker_tasks \
                   WHERE worker_id = $2 \
                     AND kind = 'init' \
                     AND worker_tasks.init_product = builds.product \
                     AND status IN ('assigned', 'running') \
               ) \
             RETURNING id, task_id",
            now = dialect.sql_now(),
            claim_b = claimable("builds"),
            claim_fg = claimable("fg"),
        )
    }

    /// 本地候选流（hub 伪 worker）：只读，谓词与 `pick_and_lock_pending`
    /// 选行子查询同源——本地架构 claim 含 NULL-arch 行（COALESCE 归一）+
    /// 后台闸按本地架构作用域。无 init 门（本地路径无 init）、无 priority
    /// 过滤（低优预留语义由 planner 在候选上判定，查询返回全量就绪行）。
    pub(super) fn peek_local_candidates(dialect: Dialect) -> String {
        let claimable = |alias: &str| {
            format!(
                "({a}.arch = $1 OR ({a}.arch = 'noarch' AND ({a}.host_arches IS NULL OR {contains})) \
                 OR COALESCE({a}.arch, '') = '')",
                a = alias,
                contains = dialect.sql_csv_contains(&format!("{alias}.host_arches"), 1)
            )
        };
        format!(
            "SELECT {CANDIDATE_COLUMNS} FROM builds b \
             WHERE b.phase = 'pending' \
               AND b.srpm_path IS NOT NULL AND b.request_json IS NOT NULL \
               AND {claim_b} \
               AND (b.priority >= 0 OR NOT EXISTS ( \
                   SELECT 1 FROM builds fg \
                   WHERE fg.phase = 'pending' AND fg.priority >= 0 \
                     AND {claim_fg} \
                     AND fg.srpm_path IS NOT NULL \
               )) \
             ORDER BY {order} \
             LIMIT $2",
            CANDIDATE_COLUMNS = CANDIDATE_COLUMNS,
            claim_b = claimable("b"),
            claim_fg = claimable("fg"),
            order = dialect.sql_priority_wait_weight()
        )
    }

    /// 指定本地 build 的 CAS 锁定（置 building）：谓词 = `pick_and_lock_
    /// pending` 全量复查（phase + 本地架构 claim + 就绪 + 后台闸），目标为
    /// 指定 id；0 行 = 被抢 / 谓词失效。置 building 时重置 started_at（列
    /// 语义 = 本次执行尝试起点，与既有 pick 相同）。参数序：$1=build_id、
    /// $2=本地架构。
    pub(super) fn lock_specific_local_build(dialect: Dialect) -> String {
        let claimable = |alias: &str| {
            format!(
                "({a}.arch = $2 OR ({a}.arch = 'noarch' AND ({a}.host_arches IS NULL OR {contains})) \
                 OR COALESCE({a}.arch, '') = '')",
                a = alias,
                contains = dialect.sql_csv_contains(&format!("{alias}.host_arches"), 2)
            )
        };
        format!(
            "UPDATE builds \
             SET phase = 'building', started_at = {now} \
             WHERE id = $1 AND phase = 'pending' \
               AND srpm_path IS NOT NULL AND request_json IS NOT NULL \
               AND {claim_b} \
               AND (priority >= 0 OR NOT EXISTS ( \
                   SELECT 1 FROM builds fg \
                   WHERE fg.phase = 'pending' AND fg.priority >= 0 \
                     AND {claim_fg} \
                     AND fg.srpm_path IS NOT NULL \
               )) \
             RETURNING id, product, srpm_path, request_json, crbs_pid",
            now = dialect.sql_now(),
            claim_b = claimable("builds"),
            claim_fg = claimable("fg"),
        )
    }
}

/// 派发候选（planner 候选流单行）。
/// 行序 = SQL 返回序（score DESC），planner 不得重排。
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DispatchCandidate {
    pub id: i64,
    pub task_id: Option<i64>,
    pub product: String,
    /// 构建标识（NVR/NEVR），日志与展示用。
    pub pkg_name: String,
    /// 源码包基础名（builds.name）：画像/声明键，跨版本共享。
    pub source_name: String,
    /// NULL = 未指定架构（任意架构可领；分布式 pick 谓词不命中 NULL 行，
    /// 仅本地路径实际领取），planner 按 worker 架构内存过滤。
    pub arch: Option<String>,
    /// noarch 行的宿主架构 CSV（如 "x86_64,aarch64"）；NULL = 不限制。
    pub host_arches: Option<String>,
    pub priority: i32,
    /// 入队时刻（TEXT UTC 帧，双方言同型）。
    pub created_at: Option<String>,
    /// 等待权重时钟（score 的等待秒自该列起算，置 assigned/building 归零）。
    /// score = priority*86400 + started_at 起算等待秒，组分齐备 planner 自算。
    pub started_at: Option<String>,
    /// 硬下限声明（提交侧随 BuildInsert 落列；调度按逐维 fail-closed 消费）。
    pub req_min_mem_kb: Option<i64>,
    pub req_min_ncpu: Option<i64>,
    pub req_min_disk_kb: Option<i64>,
    /// 输入 SRPM 字节数（heavy 判定用；staging 侧写入）。
    pub srpm_size_bytes: Option<i64>,
}

/// 指定 CAS 领取成功的结果。
#[derive(Debug, Clone)]
pub struct Assignment {
    pub assignment_id: i64,
    pub task_id: Option<i64>,
    pub build_id: i64,
}

/// 学习门影子输入快照（单键，三维画像键一行）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LearnedGateSnapshot {
    /// 学习峰值内存 KB（内存门需求基准；NULL = 该键无 mem 学习值，内存门跳过）。
    pub max_mem_kb: Option<i64>,
    /// 学习 tmpfs 峰值 KB（tmpfs 门需求基准；NULL = 无 tmpfs 学习值，门不适用）。
    pub max_tmpfs_kb: Option<i64>,
}

impl StateStore {
    /// 列出可派发的 pending 候选（只读）：就绪谓词 + 后台闸 + score 排序与
    /// 既有 pick 同源，LIMIT 即候选扫描深度（planner 常量）。架构匹配与
    /// init 门是 per-worker 判定，由 planner 内存过滤。
    pub async fn list_pending_dispatch_candidates(
        &self,
        limit: i64,
    ) -> crate::Result<Vec<DispatchCandidate>> {
        // SQLite LIMIT 负数 = 无界扫描，防御性归零（调用方传代码常量，正常不为负）。
        let limit = limit.max(0);
        let rows = sqlx::query_as::<_, DispatchCandidate>(&sql::list_pending_dispatch_candidates(
            self.dialect,
        ))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .db_ctx("list pending dispatch candidates")?;
        Ok(rows)
    }

    /// 指定 build CAS 领取：UPDATE 0 行 = 被抢/谓词失效 → `None`，planner
    /// 重试下一候选。CAS 复查 pick 全部谓词（phase/架构/就绪/后台闸/init
    /// 门——读候选到领取之间全局态可变，就绪谓词与后台闸一并复查）；worker
    /// 在线与容量由调度器内存态保证，不在本层判。命中则同事务 INSERT
    /// worker_tasks，无"build 已 assigned 而无分配行"的中间态。
    pub async fn assign_specific_build_to_worker(
        &self,
        build_id: i64,
        worker_id: i64,
    ) -> crate::Result<Option<Assignment>> {
        // begin_write() 先拿写锁：首条语句读 worker arch，DEFERRED 读后升级
        // 写撞不可重试 SQLITE_BUSY_SNAPSHOT（try_assign_init_to_worker 同论证）。
        let mut conn = self.begin_write().await?;

        // arch 取自 workers 行（与既有 pick 的 arch 形参同源，重注册换 arch
        // 的窗口收窄到本事务内；workers.arch 双方言 NOT NULL）；行不存在 =
        // 调度器内存态与 DB 撕裂，按谓词失效返回 None（唯一调用方保证在线，
        // 不在此报错）。
        let worker_arch: Option<String> =
            match sqlx::query_scalar::<_, String>(sql::SELECT_WORKER_ARCH)
                .bind(worker_id)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("select worker arch for specific assignment")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };
        let Some(worker_arch) = worker_arch else {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(None);
        };

        let row = match sqlx::query(&sql::assign_specific_build_to_worker(self.dialect))
            .bind(build_id)
            .bind(worker_id)
            .bind(worker_arch)
            .fetch_optional(&mut *conn)
            .await
            .db_ctx("assign specific build to worker")
        {
            Ok(v) => v,
            Err(e) => rollback_and_return!(conn, e),
        };

        let Some(r) = row else {
            // 0 行 = 被抢/谓词失效：无状态变化，ROLLBACK 后 None（不广播）。
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Ok(None);
        };
        let claimed_build_id: i64 = r.get("id");
        let task_id: Option<i64> = r.get("task_id");

        let assignment_id =
            match sqlx::query_scalar::<_, i64>(&insert_worker_task_build(self.dialect))
                .bind(claimed_build_id)
                .bind(worker_id)
                .bind(task_id)
                .fetch_one(&mut *conn)
                .await
                .db_ctx("insert worker task in specific assignment")
            {
                Ok(v) => v,
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

        // 迁移（pending → assigned）即广播；None 无状态变化不广播（既有 pick 同口径）。
        self.notify_state_changed();
        Ok(Some(Assignment {
            assignment_id,
            task_id,
            build_id: claimed_build_id,
        }))
    }

    /// 本地（hub 伪 worker）候选流：只读，谓词与 `pick_and_lock_pending` 同源
    /// （本地架构 claim 含 NULL-arch 行 + 后台闸本地作用域）。低优预留语义由
    /// planner 在候选上判定；本查询返回全量就绪行、无 priority 过滤。
    pub async fn peek_local_candidates(
        &self,
        arch: &str,
        limit: i64,
    ) -> crate::Result<Vec<DispatchCandidate>> {
        let limit = limit.max(0);
        let rows =
            sqlx::query_as::<_, DispatchCandidate>(&sql::peek_local_candidates(self.dialect))
                .bind(arch)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .db_ctx("peek local dispatch candidates")?;
        Ok(rows)
    }

    /// 指定本地 build CAS 锁定（置 building）：命中返回与
    /// `pick_and_lock_pending_for_local_arch` 同构的 `PendingBuildInfo`；
    /// 0 行 = 被抢/谓词失效（后台闸复查覆盖 peek 到 lock 之间入队的前台行）。
    pub async fn lock_specific_local_build(
        &self,
        build_id: i64,
        arch: &str,
    ) -> crate::Result<Option<PendingBuildInfo>> {
        let row = sqlx::query(&sql::lock_specific_local_build(self.dialect))
            .bind(build_id)
            .bind(arch)
            .fetch_optional(&self.pool)
            .await
            .db_ctx("lock specific local build")?;

        let picked = row.map(|r| pending_build_info_from_row(&r));
        // 本地调度迁移（pending → building）即广播；None 无状态变化不广播。
        if picked.is_some() {
            self.notify_state_changed();
        }
        Ok(picked)
    }

    /// 列出活跃 init 占用的 (worker_id, init_product)：planner 内存侧 init 门
    /// 过滤用（省 CAS；指定领取事务内仍复查同谓词）。与既有 pick 的 init 门
    /// 同谓词（status IN ('assigned','running')）。
    pub async fn list_active_init_worker_products(&self) -> crate::Result<Vec<(i64, String)>> {
        let rows = sqlx::query_as::<_, (i64, String)>(
            "SELECT worker_id, init_product FROM worker_tasks \
             WHERE kind = 'init' AND status IN ('assigned', 'running')",
        )
        .fetch_all(&self.pool)
        .await
        .db_ctx("list active init worker products")?;
        Ok(rows)
    }

    /// 批量读学习门影子输入（三维键精确匹配，影子内存门/tmpfs 门的调度热路径
    /// 回源点；禁逐键 N+1）。只返回 learned_samples > 0 的行——行存在即键已
    /// 学习，零样本行（declared-only upsert 建）按未学习处理。空键集不发 SQL。
    pub async fn learned_gate_batch(
        &self,
        keys: &[(String, String, String)],
    ) -> crate::Result<std::collections::HashMap<(String, String, String), LearnedGateSnapshot>>
    {
        use std::collections::HashMap;
        let mut out: HashMap<(String, String, String), LearnedGateSnapshot> = HashMap::new();
        if keys.is_empty() {
            return Ok(out);
        }
        let tuples = crate::state::db::row_value_in_placeholders3(1, keys.len())?;
        let sql_text = format!(
            "SELECT product, source_name, arch, learned_max_mem_kb, learned_max_tmpfs_kb \
             FROM package_resource_profiles \
             WHERE (product, source_name, arch) IN {tuples} AND learned_samples > 0"
        );
        let mut query =
            sqlx::query_as::<_, (String, String, String, Option<i64>, Option<i64>)>(&sql_text);
        for (product, pkg, arch) in keys {
            query = query.bind(product).bind(pkg).bind(arch);
        }
        let rows = query
            .fetch_all(&self.pool)
            .await
            .db_ctx("learned gate inputs batch")?;
        for (product, pkg, arch, max_mem, max_tmpfs) in rows {
            out.insert(
                (product, pkg, arch),
                LearnedGateSnapshot {
                    max_mem_kb: max_mem,
                    max_tmpfs_kb: max_tmpfs,
                },
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{LearnedGateSnapshot, StateStore};
    use crate::state::test_state::{create_test_store, seed_task, set_build_started_at};
    use crate::state::BuildInsert;
    use crate::types::{PRIORITY_BACKGROUND, PRIORITY_CRITICAL, PRIORITY_DEFAULT};

    /// 测试辅助：种子 pending 候选行（arch/host_arches 可空、就绪可选）。
    async fn seed_candidate(
        store: &StateStore,
        product: &str,
        pkg: &str,
        arch: Option<&str>,
        host_arches: Option<&str>,
        priority: i32,
        ready: bool,
    ) -> i64 {
        let task_id = seed_task(store, product, pkg).await;
        let id = store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase: "pending",
                backend: "chroot",
                user: "test",
                priority,
                arch,
                host_arches,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        if ready {
            store
                .set_build_request_info(id, "/tmp/test.src.rpm", r#"{"arch":"x86_64"}"#)
                .await
                .unwrap();
        }
        id
    }

    async fn candidate_ids(store: &StateStore, limit: i64) -> Vec<i64> {
        store
            .list_pending_dispatch_candidates(limit)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.id)
            .collect()
    }

    async fn local_ids(store: &StateStore, arch: &str, limit: i64) -> Vec<i64> {
        store
            .peek_local_candidates(arch, limit)
            .await
            .unwrap()
            .into_iter()
            .map(|c| c.id)
            .collect()
    }

    async fn build_phase(store: &StateStore, id: i64) -> String {
        sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    async fn worker_task_count(store: &StateStore, build_id: i64, worker_id: i64) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1 AND worker_id = $2",
        )
        .bind(build_id)
        .bind(worker_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
    }

    /// 候选流 score 序：priority 权重（×86400）占主导，同优先级按等待秒
    /// aging，LIMIT 截前缀；limit 负数防御归零（SQLite LIMIT 负 = 无界扫描）。
    #[tokio::test]
    async fn list_candidates_orders_by_score_and_limits() {
        let (store, _tmp) = create_test_store().await;
        let crit = seed_candidate(
            &store,
            "test",
            "pkg-crit",
            Some("x86_64"),
            None,
            PRIORITY_CRITICAL,
            true,
        )
        .await;
        let aged = seed_candidate(
            &store,
            "test",
            "pkg-aged",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        let fresh = seed_candidate(
            &store,
            "test",
            "pkg-fresh",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        set_build_started_at(&store, aged, "-1 hour").await;

        assert_eq!(candidate_ids(&store, 10).await, vec![crit, aged, fresh]);
        assert_eq!(candidate_ids(&store, 2).await, vec![crit, aged]);
        assert_eq!(candidate_ids(&store, -1).await, Vec::<i64>::new());
    }

    /// 后台闸（全局形态）：任一架构池的就绪前台 pending 压住全部后台候选；
    /// 前台终态后放行；未就绪前台行不持闸（fg 侧只查 srpm_path，与既有 pick 同）。
    #[tokio::test]
    async fn list_candidates_background_gate_is_global() {
        let (store, _tmp) = create_test_store().await;
        let replay = seed_candidate(
            &store,
            "test",
            "pkg-replay",
            Some("x86_64"),
            None,
            PRIORITY_BACKGROUND,
            true,
        )
        .await;
        assert_eq!(candidate_ids(&store, 10).await, vec![replay]);

        // 其它架构池的前台行同样持闸（本查询无 arch 作用域，故意的保守形态）。
        let user = seed_candidate(
            &store,
            "test",
            "pkg-user",
            Some("aarch64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert_eq!(
            candidate_ids(&store, 10).await,
            vec![user],
            "ready foreground pending in any arch pool holds the global gate"
        );

        store.mark_build_cancelled(user).await.unwrap();
        let _dead = seed_candidate(
            &store,
            "test",
            "pkg-dead",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            false,
        )
        .await;
        assert_eq!(
            candidate_ids(&store, 10).await,
            vec![replay],
            "unready foreground row must not hold the gate"
        );
    }

    /// 就绪谓词：srpm_path/request_json 未落库的 pending 行不进候选流，补齐后进入。
    #[tokio::test]
    async fn list_candidates_skip_unready_rows() {
        let (store, _tmp) = create_test_store().await;
        let unready = seed_candidate(
            &store,
            "test",
            "pkg-unready",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            false,
        )
        .await;
        assert!(candidate_ids(&store, 10).await.is_empty());
        store
            .set_build_request_info(unready, "/tmp/test.src.rpm", "{}")
            .await
            .unwrap();
        assert_eq!(candidate_ids(&store, 10).await, vec![unready]);
    }

    /// 指定 CAS 成功：phase='assigned'、同事务插 worker_tasks('assigned')、
    /// 返回的 task_id 与 build 行一致；二次领取 → None（phase 守卫），不产生
    /// 第二行分配。
    #[tokio::test]
    async fn assign_specific_claims_once() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-spec", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let b = seed_candidate(
            &store,
            "test",
            "pkg-claim",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        let a = store
            .assign_specific_build_to_worker(b, w)
            .await
            .unwrap()
            .expect("first claim must win");
        assert_eq!(a.build_id, b);
        let task_id: Option<i64> = sqlx::query_scalar("SELECT task_id FROM builds WHERE id = $1")
            .bind(b)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(a.task_id, task_id);
        assert_eq!(build_phase(&store, b).await, "assigned");
        assert_eq!(worker_task_count(&store, b, w).await, 1);

        assert!(
            store
                .assign_specific_build_to_worker(b, w)
                .await
                .unwrap()
                .is_none(),
            "second claim on assigned build must lose"
        );
        assert_eq!(worker_task_count(&store, b, w).await, 1);
    }

    /// 指定 CAS 置 assigned 时重置 started_at（列语义 = 本次执行尝试起点）：
    /// duration 与等待权重自该列起算，排队期计时不得计入执行时长。
    #[tokio::test]
    async fn assign_specific_resets_started_at() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-reset", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let b = seed_candidate(
            &store,
            "test",
            "pkg-reset",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        set_build_started_at(&store, b, "-1 hour").await;
        let aged: String = sqlx::query_scalar("SELECT started_at FROM builds WHERE id = $1")
            .bind(b)
            .fetch_one(store.pool())
            .await
            .unwrap();

        store
            .assign_specific_build_to_worker(b, w)
            .await
            .unwrap()
            .expect("ready row must claim");
        let reset: String = sqlx::query_scalar("SELECT started_at FROM builds WHERE id = $1")
            .bind(b)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(
            reset > aged,
            "assigned build's started_at must be reset to now (execution-attempt start),              got aged={aged}, reset={reset}"
        );
    }

    /// 双 worker 并发抢同一 build：CAS 相位守卫下恰一方
    /// 成功，无第二行分配、无双重领取。
    #[tokio::test]
    async fn assign_specific_race_two_workers_single_winner() {
        let (store, _tmp) = create_test_store().await;
        let w1 = store
            .upsert_worker("w-race-1", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let w2 = store
            .upsert_worker("w-race-2", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let b = seed_candidate(
            &store,
            "test",
            "pkg-race",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        let (r1, r2) = tokio::join!(
            store.assign_specific_build_to_worker(b, w1),
            store.assign_specific_build_to_worker(b, w2),
        );
        let winners = [r1.unwrap(), r2.unwrap()]
            .into_iter()
            .filter(|a| a.is_some())
            .count();
        assert_eq!(winners, 1, "exactly one worker may win the same build");
        assert_eq!(build_phase(&store, b).await, "assigned");
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1")
                .bind(b)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(total, 1, "no orphan second assignment row");
    }

    /// 被抢：build 已离开 pending（legacy 路径手工分配）→ None 且不留孤儿
    /// worker_tasks 行（UPDATE 与 INSERT 同事务）。
    #[tokio::test]
    async fn assign_specific_returns_none_when_stolen() {
        let (store, _tmp) = create_test_store().await;
        let w1 = store
            .upsert_worker("w-steal-1", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let w2 = store
            .upsert_worker("w-steal-2", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let b = seed_candidate(
            &store,
            "test",
            "pkg-steal",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        store.assign_build_to_worker(b, w1).await.unwrap();
        assert!(
            store
                .assign_specific_build_to_worker(b, w2)
                .await
                .unwrap()
                .is_none(),
            "claiming an already-assigned build must return None"
        );
        assert_eq!(worker_task_count(&store, b, w2).await, 0);
    }

    /// 架构谓词：aarch64 build 对 x86_64 worker → None（行留 pending）；
    /// noarch 宿主 CSV 三态——钉其它架构拒、钉含 worker 架构收、未钉收。
    #[tokio::test]
    async fn assign_specific_checks_arch_and_host_arches() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-arch", "x86_64", 4, "test", "online", None)
            .await
            .unwrap();

        let wrong = seed_candidate(
            &store,
            "test",
            "pkg-wrong",
            Some("aarch64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert!(
            store
                .assign_specific_build_to_worker(wrong, w)
                .await
                .unwrap()
                .is_none(),
            "arch mismatch must not claim"
        );
        assert_eq!(build_phase(&store, wrong).await, "pending");

        let pinned_other = seed_candidate(
            &store,
            "test",
            "pkg-pin-other",
            Some("noarch"),
            Some("aarch64"),
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert!(
            store
                .assign_specific_build_to_worker(pinned_other, w)
                .await
                .unwrap()
                .is_none(),
            "noarch pinned to another host must not claim"
        );

        let pinned_local = seed_candidate(
            &store,
            "test",
            "pkg-pin-local",
            Some("noarch"),
            Some("x86_64,aarch64"),
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert!(
            store
                .assign_specific_build_to_worker(pinned_local, w)
                .await
                .unwrap()
                .is_some(),
            "noarch pinned with worker arch in CSV must claim"
        );

        let unpinned = seed_candidate(
            &store,
            "test",
            "pkg-unpinned",
            Some("noarch"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert!(
            store
                .assign_specific_build_to_worker(unpinned, w)
                .await
                .unwrap()
                .is_some(),
            "unpinned noarch must claim"
        );
    }

    /// init 门：同 worker 同 product 活跃 init 拦截指定领取；其它 product
    /// 放行；init 落终态后放行。
    #[tokio::test]
    async fn assign_specific_respects_init_gate() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-init", "x86_64", 4, "test", "online", None)
            .await
            .unwrap();
        let b_same = seed_candidate(
            &store,
            "test",
            "pkg-gated",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        let b_other = seed_candidate(
            &store,
            "other",
            "pkg-other",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        let init_id = store
            .try_assign_init_to_worker(w, "test")
            .await
            .unwrap()
            .expect("init fixture");

        assert!(
            store
                .assign_specific_build_to_worker(b_same, w)
                .await
                .unwrap()
                .is_none(),
            "active init for same worker+product must block the claim"
        );
        assert_eq!(build_phase(&store, b_same).await, "pending");
        assert!(
            store
                .assign_specific_build_to_worker(b_other, w)
                .await
                .unwrap()
                .is_some(),
            "init gate is per-product and must not block other products"
        );

        store
            .update_worker_task_status(init_id, "completed")
            .await
            .unwrap();
        assert!(
            store
                .assign_specific_build_to_worker(b_same, w)
                .await
                .unwrap()
                .is_some(),
            "completed init must release the gate"
        );
    }

    /// 后台闸复查：读候选到 CAS 之间入队的前台就绪行，压住后台 build 的指定
    /// 领取；前台领走后闸解除。
    #[tokio::test]
    async fn assign_specific_rechecks_background_gate() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-gate", "x86_64", 4, "test", "online", None)
            .await
            .unwrap();
        let replay = seed_candidate(
            &store,
            "test",
            "pkg-replay2",
            Some("x86_64"),
            None,
            PRIORITY_BACKGROUND,
            true,
        )
        .await;
        let user = seed_candidate(
            &store,
            "test",
            "pkg-user2",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        assert!(
            store
                .assign_specific_build_to_worker(replay, w)
                .await
                .unwrap()
                .is_none(),
            "foreground pending holds the gate at CAS time"
        );
        assert!(
            store
                .assign_specific_build_to_worker(user, w)
                .await
                .unwrap()
                .is_some(),
            "foreground build claims through the gate"
        );
        assert!(
            store
                .assign_specific_build_to_worker(replay, w)
                .await
                .unwrap()
                .is_some(),
            "gate must clear once the foreground row leaves pending"
        );
    }

    /// 就绪谓词复查与 worker 缺行防御：未就绪 → None 且行留 pending；
    /// worker id 不存在（调度器内存态与 DB 撕裂）→ None 而非报错。
    #[tokio::test]
    async fn assign_specific_requires_ready_and_existing_worker() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-ready", "x86_64", 2, "test", "online", None)
            .await
            .unwrap();
        let b = seed_candidate(
            &store,
            "test",
            "pkg-notready",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            false,
        )
        .await;

        assert!(
            store
                .assign_specific_build_to_worker(b, w)
                .await
                .unwrap()
                .is_none(),
            "unready row must not claim"
        );
        assert_eq!(build_phase(&store, b).await, "pending");
        assert!(
            store
                .assign_specific_build_to_worker(b, 999_999)
                .await
                .unwrap()
                .is_none(),
            "missing worker row must degrade to None"
        );

        store
            .set_build_request_info(b, "/tmp/test.src.rpm", "{}")
            .await
            .unwrap();
        assert!(
            store
                .assign_specific_build_to_worker(b, w)
                .await
                .unwrap()
                .is_some(),
            "ready row claims once request info lands"
        );
    }

    /// 本地候选流与本地 pick 谓词同源：NULL-arch 行可领、noarch 宿主约束
    /// 生效；NULL-arch 行同样出现在分布式候选流（该流无架构谓词，架构判定
    /// 归 planner）。
    #[tokio::test]
    async fn peek_local_candidates_mirror_local_pick_predicates() {
        let (store, _tmp) = create_test_store().await;
        let null_arch = seed_candidate(
            &store,
            "test",
            "pkg-null",
            None,
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        let pinned = seed_candidate(
            &store,
            "test",
            "pkg-pinned",
            Some("noarch"),
            Some("aarch64"),
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        let free = seed_candidate(
            &store,
            "test",
            "pkg-free",
            Some("noarch"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        assert!(
            candidate_ids(&store, 10).await.contains(&null_arch),
            "distributed candidate stream has no arch predicate: NULL-arch rows appear"
        );

        assert_eq!(
            local_ids(&store, "x86_64", 10).await,
            vec![null_arch, free],
            "local stream claims NULL-arch rows and respects noarch host pinning"
        );
        assert_eq!(
            local_ids(&store, "aarch64", 10).await,
            vec![null_arch, pinned, free],
            "pinned noarch row lists only for the pinned arch"
        );
    }

    /// 本地候选流的后台闸与 LIMIT：就绪前台行压住后台行；前台终态后放行；
    /// LIMIT 截前缀。
    #[tokio::test]
    async fn peek_local_candidates_gate_and_limit() {
        let (store, _tmp) = create_test_store().await;
        let replay = seed_candidate(
            &store,
            "test",
            "pkg-local-replay",
            Some("x86_64"),
            None,
            PRIORITY_BACKGROUND,
            true,
        )
        .await;
        let user = seed_candidate(
            &store,
            "test",
            "pkg-local-user",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        assert_eq!(local_ids(&store, "x86_64", 10).await, vec![user]);
        assert_eq!(local_ids(&store, "x86_64", 1).await, vec![user]);

        store.mark_build_cancelled(user).await.unwrap();
        assert_eq!(local_ids(&store, "x86_64", 10).await, vec![replay]);
    }

    /// 指定本地锁：返回与既有本地 pick 同构的 PendingBuildInfo、置 building；
    /// 重复 lock / 未就绪行 → None。
    #[tokio::test]
    async fn lock_specific_local_build_locks_once() {
        let (store, _tmp) = create_test_store().await;
        let b = seed_candidate(
            &store,
            "test",
            "pkg-lock",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;
        assert_eq!(local_ids(&store, "x86_64", 10).await, vec![b]);

        let info = store
            .lock_specific_local_build(b, "x86_64")
            .await
            .unwrap()
            .expect("lock must win");
        assert_eq!(info.id, b);
        assert_eq!(info.product, "test");
        assert_eq!(info.srpm_path, "/tmp/test.src.rpm");
        assert_eq!(info.request_json, r#"{"arch":"x86_64"}"#);
        assert!(info.crbs_pid.is_none());
        assert_eq!(build_phase(&store, b).await, "building");

        assert!(
            store
                .lock_specific_local_build(b, "x86_64")
                .await
                .unwrap()
                .is_none(),
            "double lock must lose"
        );

        let c = seed_candidate(
            &store,
            "test",
            "pkg-lock-unready",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            false,
        )
        .await;
        assert!(
            store
                .lock_specific_local_build(c, "x86_64")
                .await
                .unwrap()
                .is_none(),
            "unready row must not lock"
        );
        assert_eq!(build_phase(&store, c).await, "pending");
    }

    /// 本地锁的后台闸复查：peek 到 lock 之间入队的前台就绪行压住后台锁定；
    /// 前台锁走后解除。
    #[tokio::test]
    async fn lock_specific_local_build_rechecks_background_gate() {
        let (store, _tmp) = create_test_store().await;
        let replay = seed_candidate(
            &store,
            "test",
            "pkg-lock-replay",
            Some("x86_64"),
            None,
            PRIORITY_BACKGROUND,
            true,
        )
        .await;
        let user = seed_candidate(
            &store,
            "test",
            "pkg-lock-user",
            Some("x86_64"),
            None,
            PRIORITY_DEFAULT,
            true,
        )
        .await;

        assert!(
            store
                .lock_specific_local_build(replay, "x86_64")
                .await
                .unwrap()
                .is_none(),
            "foreground pending holds the gate at lock time"
        );
        assert!(
            store
                .lock_specific_local_build(user, "x86_64")
                .await
                .unwrap()
                .is_some(),
            "foreground build locks through the gate"
        );
        assert!(
            store
                .lock_specific_local_build(replay, "x86_64")
                .await
                .unwrap()
                .is_some(),
            "gate must clear once the foreground row leaves pending"
        );
    }

    /// 活跃 init 列表：try_assign_init 后 (worker, product) 在列，init 落终态
    /// 后移出——planner 内存侧 init 门的批量输入。
    #[tokio::test]
    async fn list_active_init_worker_products_tracks_lifecycle() {
        let (store, _tmp) = create_test_store().await;
        let w = store
            .upsert_worker("w-init-list", "x86_64", 4, "test", "online", None)
            .await
            .unwrap();

        assert!(store
            .list_active_init_worker_products()
            .await
            .unwrap()
            .is_empty());

        let init_id = store
            .try_assign_init_to_worker(w, "test")
            .await
            .unwrap()
            .expect("init fixture");
        assert_eq!(
            store.list_active_init_worker_products().await.unwrap(),
            vec![(w, "test".to_string())]
        );

        store
            .update_worker_task_status(init_id, "completed")
            .await
            .unwrap();
        assert!(store
            .list_active_init_worker_products()
            .await
            .unwrap()
            .is_empty());
    }

    /// 学习门输入批读：只命中 learned_samples > 0 的键，零样本行（declared-only）
    /// 与无行键按未学习缺席；tmpfs NULL 随行透传。空键集不发 SQL。
    #[tokio::test]
    async fn learned_gate_batch_returns_learned_keys_only() {
        let (store, _tmp) = create_test_store().await;
        for (product, pkg, arch, samples, max_mem, max_tmpfs) in [
            (
                "p",
                "learned",
                "x86_64",
                1_i64,
                Some(2048_i64),
                Some(512_i64),
            ),
            ("p", "no-tmpfs", "x86_64", 3, Some(4096), None),
            ("p", "zero-samples", "x86_64", 0, Some(8192), Some(1024)),
        ] {
            sqlx::query(
                "INSERT INTO package_resource_profiles \
                 (product, source_name, arch, learned_samples, learned_max_mem_kb, \
                  learned_max_tmpfs_kb) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(product)
            .bind(pkg)
            .bind(arch)
            .bind(samples)
            .bind(max_mem)
            .bind(max_tmpfs)
            .execute(store.pool())
            .await
            .unwrap();
        }

        assert!(store.learned_gate_batch(&[]).await.unwrap().is_empty());

        let keys = vec![
            ("p".to_string(), "learned".to_string(), "x86_64".to_string()),
            (
                "p".to_string(),
                "no-tmpfs".to_string(),
                "x86_64".to_string(),
            ),
            (
                "p".to_string(),
                "zero-samples".to_string(),
                "x86_64".to_string(),
            ),
            ("p".to_string(), "absent".to_string(), "x86_64".to_string()),
        ];
        let out = store.learned_gate_batch(&keys).await.unwrap();
        assert_eq!(out.len(), 2, "零样本行与无行键不入返回 map");
        assert_eq!(
            out.get(&keys[0]),
            Some(&LearnedGateSnapshot {
                max_mem_kb: Some(2048),
                max_tmpfs_kb: Some(512),
            })
        );
        assert_eq!(
            out.get(&keys[1]),
            Some(&LearnedGateSnapshot {
                max_mem_kb: Some(4096),
                max_tmpfs_kb: None,
            })
        );
    }
}
