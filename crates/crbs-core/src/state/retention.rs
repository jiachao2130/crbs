// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! DB 行级保留：按 FK 安全序删除超期历史行，限住 SQLite 体积增长。
//!
//! 磁盘产物（result_dir）由既有 result GC 负责，此处仅删"行"；builds 只删
//! `result_dir IS NULL` 的行（目录已被磁盘 GC 清掉，不产生孤儿目录）。
//! 批次只删终态且 finished_at 超期的行，在途保守保留；batch_items 经
//! batch_id ON DELETE CASCADE 级联删除，无需单独删除步。

use crate::error::DbResultExt;

/// 一次保留清理的删除统计（按表）：只计各表直删行数——级联行（builds →
/// build_reproducibility / build_artifacts，批次 → batch_items）由库执行，
/// 不回传 rows_affected 不计入，看板/metrics 勿当作全部关联数据量。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetentionStats {
    pub audit_logs: u64,
    pub worker_tasks: u64,
    pub builds: u64,
    pub build_batches: u64,
    pub tasks: u64,
    pub product_history: u64,
    pub worker_telemetry_samples: u64,
}

impl RetentionStats {
    /// 各表删除总数。
    pub fn total(&self) -> u64 {
        self.audit_logs
            + self.worker_tasks
            + self.builds
            + self.build_batches
            + self.tasks
            + self.product_history
            + self.worker_telemetry_samples
    }
}

/// 每产品保留的最新 `product_config_history` 快照数；更旧的由 prune_old_records 删除。
const PRODUCT_HISTORY_KEEP_LATEST: i64 = 20;

/// 遥测采样独立保留上限（天）：30s/条的高频追加写，保窗远短于其余历史表
/// （图表最大窗口 7d，14 天留余量）；全局 retention_days 收得更紧时按紧者走
///（取 min），只影响本表、不动别的表。
const TELEMETRY_SAMPLE_RETENTION_DAYS: i64 = 14;

/// 单批删除行数上限：分批提交避免一条大 DELETE 长持写锁（SQLite 全库写锁 /
/// PG 行锁累积）。批间独立提交，单批失败已提交批次保留（谓词幂等，重跑续删）。
pub(crate) const PRUNE_BATCH_ROWS: i64 = 5_000;

mod sql {
    use crate::state::Dialect;

    /// cutoff 表达式（方言感知），DELETE 谓词共享：须产出与 TEXT 时间列同类
    /// 可比较的值（`YYYY-MM-DD HH:MM:SS`，见 db::sql_now）——timestamptz 与
    /// text 比较在 PG 直接 `operator does not exist`，to_char 收窄即为此。
    pub(super) fn cutoff_days_ago(dialect: Dialect) -> &'static str {
        match dialect {
            Dialect::Sqlite => "datetime('now', '-' || $1 || ' days')",
            #[cfg(feature = "postgres")]
            Dialect::Postgres => {
                "to_char((NOW() AT TIME ZONE 'UTC') - ($1 || ' days')::interval, \
                 'YYYY-MM-DD HH24:MI:SS')"
            }
        }
    }

    /// 分批 DELETE 模板：调用方填表名 + 谓词（$1=cutoff 天数、$2=批大小）；
    /// ORDER BY id 保证批次确定推进，删的恒是谓词全集的子序列，与全删无偏差。
    fn delete_batched(table: &str, predicate: String) -> String {
        format!(
            "DELETE FROM {table} WHERE id IN (\
             SELECT id FROM {table} WHERE {predicate} ORDER BY id LIMIT $2)"
        )
    }

    pub(super) fn delete_audit_logs_older_than(dialect: Dialect) -> String {
        delete_batched(
            "audit_logs",
            format!("created_at <= {}", cutoff_days_ago(dialect)),
        )
    }

    pub(super) fn delete_terminal_worker_tasks_older_than(dialect: Dialect) -> String {
        delete_batched(
            "worker_tasks",
            format!(
                "completed_at IS NOT NULL AND completed_at <= {}",
                cutoff_days_ago(dialect)
            ),
        )
    }

    /// 仅删已被磁盘 GC 清空目录（`result_dir IS NULL`）且非 building 的历史构建。
    pub(super) fn delete_gcd_builds_older_than(dialect: Dialect) -> String {
        delete_batched(
            "builds",
            format!(
                "result_dir IS NULL AND phase != 'building' \
                 AND completed_at IS NOT NULL AND completed_at <= {}",
                cutoff_days_ago(dialect)
            ),
        )
    }

    /// 仅删已无 builds 引用的孤儿任务，满足 builds.task_id 外键。
    pub(super) fn delete_childless_tasks_older_than(dialect: Dialect) -> String {
        delete_batched(
            "tasks",
            format!(
                "completed_at IS NOT NULL AND completed_at <= {} \
                 AND id NOT IN (SELECT DISTINCT task_id FROM builds WHERE task_id IS NOT NULL)",
                cutoff_days_ago(dialect)
            ),
        )
    }

    /// 批次终态集合：全集 7 值中 preparing/planning/running 为在途态，须等批次
    /// 收口（终态 + finished_at 落值）后才可清理。值集与 baseline CHECK 的
    /// status 域对齐，渲染形态由 `terminal_batch_status_sql_list_pins_rendered_set` 钉住。
    pub(super) fn terminal_batch_status_sql_list() -> String {
        ["completed", "partial", "failed", "cancelled"]
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// 仅删终态且 finished_at 超期的批次。finished_at IS NOT NULL 与终态谓词
    /// 双保险：在途批次即便 finished_at 意外有值也保守保留。
    pub(super) fn delete_terminal_batches_older_than(dialect: Dialect) -> String {
        delete_batched(
            "build_batches",
            format!(
                "status IN ({}) AND finished_at IS NOT NULL AND finished_at <= {}",
                terminal_batch_status_sql_list(),
                cutoff_days_ago(dialect)
            ),
        )
    }

    /// 终态集合 IN 列表（worker 本地库 prune 用）：从 `TERMINAL_BUILD_PHASES`
    /// 渲染，与 `build_phase_is_terminal` 同一常量（值集结构性同步）；渲染
    /// 形态由 `terminal_phase_sql_list_pins_rendered_set` 单测钉住。
    pub(super) fn terminal_phases_sql_list() -> String {
        crate::types::TERMINAL_BUILD_PHASES
            .iter()
            .map(|p| format!("'{p}'"))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// worker 本地库 builds 行 prune：终态且 completed_at 超期（NULL 行视为
    /// 未完成保守保留）。
    pub(super) fn delete_terminal_local_builds_older_than(dialect: Dialect) -> String {
        delete_batched(
            "builds",
            format!(
                "phase IN ({}) AND completed_at IS NOT NULL AND completed_at <= {}",
                terminal_phases_sql_list(),
                cutoff_days_ago(dialect)
            ),
        )
    }

    /// 遥测采样只按 sampled_at 删（追加写表，无终态/引用语义可附加）。
    /// 批次顺序走 `(sampled_at, id)` 索引：通用 delete_batched 的 `ORDER BY id`
    /// 会让时间谓词全表扫，且每批重扫（O(n²)）。
    pub(super) fn delete_telemetry_samples_older_than(dialect: Dialect) -> String {
        format!(
            "DELETE FROM worker_telemetry_samples WHERE id IN (\
             SELECT id FROM worker_telemetry_samples WHERE sampled_at <= {} \
             ORDER BY sampled_at, id LIMIT $2)",
            cutoff_days_ago(dialect)
        )
    }

    /// 每产品只保留最新 $1 个快照（revision 降序），更旧的删除。无入边 FK，
    /// 顺序无约束。行值 IN + ROW_NUMBER 窗口（SQLite 3.25+ / PG 通用）；
    /// 删除量天然有界（每产品每次至多超限差额），不分批。
    pub(super) const DELETE_OLD_PRODUCT_HISTORY: &str = "\
        DELETE FROM product_config_history \
        WHERE (product_id, revision) IN ( \
            SELECT product_id, revision FROM ( \
                SELECT product_id, revision, \
                       ROW_NUMBER() OVER (PARTITION BY product_id ORDER BY revision DESC) AS rn \
                FROM product_config_history \
            ) ranked WHERE rn > $1)";
}

/// days=0 校验：0 不是"禁用"（禁用 = 不调用清理），cutoff now 会一次清空全部
/// 终态行——拒绝。
fn validate_retention_days(retention_days: u64) -> crate::Result<()> {
    if retention_days == 0 {
        return Err(crate::error::CrbsError::ValidationFailed {
            message: "retention_days must be >= 1 (0 would purge everything immediately)"
                .to_string(),
        });
    }
    Ok(())
}

impl super::StateStore {
    /// 遥测采样独立清理（14 天固定上限）：即使全局 `db_retention_days=0`
    /// （保留构建历史），高频心跳采样也必须按自身窗口回收，否则无界增长。
    pub async fn prune_worker_telemetry_samples_default(&self) -> crate::Result<u64> {
        self.prune_table_in_batches(
            &sql::delete_telemetry_samples_older_than(self.dialect),
            TELEMETRY_SAMPLE_RETENTION_DAYS,
            PRUNE_BATCH_ROWS,
            "prune worker_telemetry_samples",
        )
        .await
    }

    /// 删除超过 `retention_days` 的历史行，并把每产品 `product_config_history`
    /// 压到最新 `PRODUCT_HISTORY_KEEP_LATEST` 个快照。
    ///
    /// 按 FK 安全序删除（audit_logs → worker_tasks → builds → build_batches →
    /// tasks → product_config_history → worker_telemetry_samples，末位无 FK
    /// 依赖），各表谓词见 mod sql。硬约束：每表删空
    /// 全部批次后才进下一表（tasks 的 childless 判定依赖 builds 行已删）；批次
    /// 先于 tasks——级联只带走终态批次 items，存留 items 的 task_id 到 tasks
    /// 步按需 SET NULL。worker_tasks 三 FK 在位（build_id/task_id SET NULL、
    /// worker_id CASCADE），先行删除不产生悬挂引用。批间独立提交：单批失败
    /// ROLLBACK 该批并整体返回 Err，已提交批次保留（谓词幂等，重跑续删）。
    /// 每批事务走 `begin_write()`（SQLite BEGIN IMMEDIATE：避免 DEFERRED 起步
    /// 首条 DELETE 才拿锁的排队，并压短写锁持有时长）。
    pub async fn prune_old_records(&self, retention_days: u64) -> crate::Result<RetentionStats> {
        self.prune_old_records_with_batch(retention_days, PRUNE_BATCH_ROWS)
            .await
    }

    /// 分批版 retention 清理（生产走 [`PRUNE_BATCH_ROWS`]，小 batch 供测试
    /// 覆盖多批路径）。
    pub(crate) async fn prune_old_records_with_batch(
        &self,
        retention_days: u64,
        batch: i64,
    ) -> crate::Result<RetentionStats> {
        validate_retention_days(retention_days)?;
        // batch <= 0 非法：SQLite `LIMIT -1` = 无上限（静默绕过分批），LIMIT 0 恒删 0 行。
        if batch <= 0 {
            return Err(crate::error::CrbsError::ValidationFailed {
                message: "prune batch size must be >= 1".to_string(),
            });
        }
        // u64 → i64 饱和：≥ 2^63 回绕成负会把 cutoff 推到未来、清空全部历史行
        //（配置层已拒，此处兜底未过校验路径）。
        let days = crate::util::u64_to_i64_saturating(retention_days);

        let audit_logs = self
            .prune_table_in_batches(
                &sql::delete_audit_logs_older_than(self.dialect),
                days,
                batch,
                "prune audit_logs",
            )
            .await?;
        let worker_tasks = self
            .prune_table_in_batches(
                &sql::delete_terminal_worker_tasks_older_than(self.dialect),
                days,
                batch,
                "prune worker_tasks",
            )
            .await?;
        let builds = self
            .prune_table_in_batches(
                &sql::delete_gcd_builds_older_than(self.dialect),
                days,
                batch,
                "prune builds",
            )
            .await?;
        // 批次步先于 tasks 步（FK 安全序与归属语义见 prune_old_records 文档）。
        let build_batches = self
            .prune_table_in_batches(
                &sql::delete_terminal_batches_older_than(self.dialect),
                days,
                batch,
                "prune build_batches",
            )
            .await?;
        let tasks = self
            .prune_table_in_batches(
                &sql::delete_childless_tasks_older_than(self.dialect),
                days,
                batch,
                "prune tasks",
            )
            .await?;

        let product_history = self
            .execute_delete_tx(
                sql::DELETE_OLD_PRODUCT_HISTORY,
                &[PRODUCT_HISTORY_KEEP_LATEST],
                "prune product_config_history",
            )
            .await?;

        // 遥测采样独立 14 天上限（min：全局收得更紧按紧者走），无 FK 依赖、
        // 顺序无关，放最后一步。
        let worker_telemetry_samples = self
            .prune_table_in_batches(
                &sql::delete_telemetry_samples_older_than(self.dialect),
                days.min(TELEMETRY_SAMPLE_RETENTION_DAYS),
                batch,
                "prune worker_telemetry_samples",
            )
            .await?;

        Ok(RetentionStats {
            audit_logs,
            worker_tasks,
            builds,
            build_batches,
            tasks,
            product_history,
            worker_telemetry_samples,
        })
    }

    /// worker 本地库 builds 行 prune：删终态且 completed_at 超期的 builds 行
    ///（收口本地行数无界增长），随后收走因此 childless 的任务行（每条本地
    /// 构建先插任务行承接 FK）。返回删除的 builds 行数。与
    /// [`Self::prune_old_records`] 的差异：不按 `result_dir IS NULL` 过滤
    /// ——本地行目录已即时回收，删行不产生孤儿目录；其余纪律同款（分批 +
    /// 幂等谓词 + builds → tasks 序）。
    pub async fn prune_local_build_rows(&self, retention_days: u64) -> crate::Result<u64> {
        // 与 prune_old_records 同款拒绝（见 validate_retention_days）。
        validate_retention_days(retention_days)?;
        let days = crate::util::u64_to_i64_saturating(retention_days);
        let builds = self
            .prune_table_in_batches(
                &sql::delete_terminal_local_builds_older_than(self.dialect),
                days,
                PRUNE_BATCH_ROWS,
                "prune local builds",
            )
            .await?;
        // builds 删完再收孤儿任务行（childless 判定依赖 builds 行已删）。
        self.prune_table_in_batches(
            &sql::delete_childless_tasks_older_than(self.dialect),
            days,
            PRUNE_BATCH_ROWS,
            "prune local childless tasks",
        )
        .await?;
        Ok(builds)
    }

    /// 单表分批删除：循环"单批 DELETE 事务"直到 `rows_affected == 0`——
    /// "实删 < batch 即停"在恰整数批会漏删或提前停（最后一批也满批，须再拿
    /// 0 才确认删空）。`sql_text` 绑定 $1=cutoff 天数、$2=批大小。
    async fn prune_table_in_batches(
        &self,
        sql_text: &str,
        days: i64,
        batch: i64,
        ctx: &str,
    ) -> crate::Result<u64> {
        let mut total: u64 = 0;
        loop {
            let n = self
                .execute_delete_tx(sql_text, &[days, batch], ctx)
                .await?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok(total)
    }

    /// 单事务执行一条 DELETE 并返回 `rows_affected`。手动事务：任何一步失败
    /// 都要 ROLLBACK（`?` 穿透会泄漏写锁），主体放 async 块统一在汇聚点收尾。
    async fn execute_delete_tx(
        &self,
        sql_text: &str,
        binds: &[i64],
        ctx: &str,
    ) -> crate::Result<u64> {
        let mut conn = self.begin_write().await.db_ctx("begin retention tx")?;
        let result: crate::Result<u64> = async {
            let mut query = sqlx::query(sql_text);
            for v in binds {
                query = query.bind(*v);
            }
            Ok(query.execute(&mut *conn).await.db_ctx(ctx)?.rows_affected())
        }
        .await;

        match result {
            Ok(n) => match sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .db_ctx("commit retention tx")
            {
                Ok(_) => Ok(n),
                Err(e) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    Err(e)
                }
            },
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // 双方言测试工厂 + 方言感知时间偏移（test_state 单源；fixture 勿内嵌
    // SQLite 专属时间字面量——PG 腿会直接语法炸）。
    use crate::state::test_state::{create_test_store, sql_time_offset};

    /// 旧记录（超期）被删，新记录保留；builds 仅删 result_dir IS NULL 的；FK 安全。
    #[tokio::test]
    async fn prunes_old_rows_and_keeps_recent() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();

        // 一个 user + 一个 worker，满足 builds.user_id / worker_tasks.worker_id 外键。
        sqlx::query("INSERT INTO users (name, role) VALUES ('alice', 'operator')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')")
            .execute(pool)
            .await
            .unwrap();

        let old = sql_time_offset(store.dialect(), "-100 days");
        let recent = sql_time_offset(store.dialect(), "-1 days");

        sqlx::query(&format!(
            "INSERT INTO audit_logs (action, created_at) VALUES ('a', {})",
            old
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO audit_logs (action, created_at) VALUES ('b', {})",
            recent
        ))
        .execute(pool)
        .await
        .unwrap();

        // tasks：task1（旧，将被 builds 引用→保留到 builds 删后）、task2（旧且无引用→删）。
        sqlx::query(&format!(
            "INSERT INTO tasks (product, pkg_name, phase, completed_at) VALUES ('p','t1','succeeded', {})", old))
            .execute(pool).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO tasks (product, pkg_name, phase, completed_at) VALUES ('p','t2','succeeded', {})", old))
            .execute(pool).await.unwrap();

        // builds：b1 旧+result_dir NULL→删；b2 旧+非空→保留；b3 新+NULL→保留。
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, user_id, completed_at) \
             VALUES ('p','b1','succeeded', 1, 1, {})",
            old
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, user_id, result_dir, completed_at) \
             VALUES ('p','b2','succeeded', 1, 1, '/x', {})", old))
            .execute(pool).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, user_id, completed_at) \
             VALUES ('p','b3','succeeded', 1, 1, {})",
            recent
        ))
        .execute(pool)
        .await
        .unwrap();

        // worker_tasks：终态旧→删；非终态（completed_at NULL）→保留。status
        // 取 'completed' 因表 CHECK 约束值域无 'done'（判定本就只看 completed_at）。
        sqlx::query(&format!(
            "INSERT INTO worker_tasks (build_id, worker_id, status, completed_at) VALUES (1, 1, 'completed', {})", old))
            .execute(pool).await.unwrap();
        sqlx::query(
            "INSERT INTO worker_tasks (build_id, worker_id, status) VALUES (2, 1, 'running')",
        )
        .execute(pool)
        .await
        .unwrap();

        let stats = store.prune_old_records(90).await.unwrap();

        assert_eq!(stats.audit_logs, 1, "old audit row pruned");
        assert_eq!(stats.worker_tasks, 1, "terminal old worker_task pruned");
        assert_eq!(
            stats.builds, 1,
            "only GC'd (result_dir NULL) old build pruned"
        );
        assert_eq!(
            stats.tasks, 1,
            "childless old task pruned, referenced task kept"
        );

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "b2 (dir set) + b3 (recent) kept");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "task1 kept (still referenced)");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_tasks")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 1, "non-terminal worker_task kept");
    }

    /// prune_local_build_rows 语义：终态超期删；近期终态 / 非终态 /
    /// completed_at NULL 保守保留；childless 任务行随删，被引用的保留。
    #[tokio::test]
    async fn prune_local_build_rows_semantics() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();

        // 本地任务行（builds.task_id NOT NULL）：t1 → 超期终态 build；
        // t2 → 近期终态；t3 → 超期非终态（completed_at NULL，同真实在途
        // 路径）；t4 → 仅任务行（终态超期，builds 删后 childless → 删）。
        let old = sql_time_offset(store.dialect(), "-30 days");
        let recent = sql_time_offset(store.dialect(), "-1 day");
        for (i, phase, ts) in [
            ("t1", "succeeded", old.as_str()),
            ("t2", "succeeded", recent.as_str()),
            ("t3", "building", "NULL"),
        ] {
            sqlx::query(&format!(
                "INSERT INTO tasks (product, pkg_name, phase, completed_at) \
                 VALUES ('p', '{i}', '{phase}', {ts})"
            ))
            .execute(pool)
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "INSERT INTO tasks (product, pkg_name, phase, completed_at) \
             VALUES ('p', 't4', 'succeeded', {old})"
        ))
        .execute(pool)
        .await
        .unwrap();

        // b1 超期终态→删；b2 近期终态→保留；b3 超期 building→保留；b4 超期终态但 completed_at NULL→保守保留。
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b1', 'succeeded', (SELECT id FROM tasks WHERE pkg_name = 't1'), {})",
            old
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b2', 'succeeded', (SELECT id FROM tasks WHERE pkg_name = 't2'), {})",
            recent
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b3', 'building', (SELECT id FROM tasks WHERE pkg_name = 't3'), {})",
            old
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, task_id) \
             VALUES ('p', 'b4', 'cancelled', (SELECT id FROM tasks WHERE pkg_name = 't1'))",
        )
        .execute(pool)
        .await
        .unwrap();

        let pruned = store.prune_local_build_rows(7).await.unwrap();
        assert_eq!(pruned, 1, "only the old terminal build row is pruned");

        let phases: Vec<String> =
            sqlx::query_scalar("SELECT pkg_name FROM builds ORDER BY pkg_name")
                .fetch_all(pool)
                .await
                .unwrap();
        assert_eq!(
            phases,
            vec!["b2", "b3", "b4"],
            "recent / non-terminal / NULL-completed kept"
        );

        // t1 仍被 b4（NULL completed 保守保留行）引用、t2/t3 同理；t4（无引用且超期）被收走。
        let tasks: Vec<String> = sqlx::query_scalar("SELECT pkg_name FROM tasks ORDER BY pkg_name")
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(
            tasks,
            vec!["t1", "t2", "t3"],
            "childless t4 pruned, referenced tasks kept"
        );
    }

    /// profiles 表不在 prune 序列的回归保护：retention 清掉命中条件的超期
    /// 终态 builds 行，同键画像行完好（画像寿命 = 集群寿命——
    /// 豁免 = 不加 prune 段；此测试防的是未来有人顺手把它加进删除序列）。
    #[tokio::test]
    async fn prune_old_records_leaves_resource_profiles_intact() {
        use crate::state::{ResourceSampleOutcome, SampleBackend, DEFAULT_CENSOR_HEADROOM};

        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();

        // 超期终态 build（result_dir NULL → prune 谓词命中）；先造任务行承接 FK。
        let old = sql_time_offset(store.dialect(), "-100 days");
        sqlx::query(&format!(
            "INSERT INTO tasks (product, pkg_name, phase, completed_at) \
             VALUES ('p', 'pkg', 'succeeded', {old})"
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'pkg', 'succeeded', (SELECT MAX(id) FROM tasks), {old})"
        ))
        .execute(pool)
        .await
        .unwrap();

        // 同键画像行（走真实学习写入路径创建）。
        store
            .apply_learning_sample(
                "p",
                "pkg",
                "x86_64",
                &ResourceSampleOutcome::Succeeded {
                    backend: SampleBackend::Cgroup,
                    peak_rss_kb: 2048,
                    peak_tmpfs_kb: None,
                    cpu_p90_cores: None,
                    sample_ncpu: Some(4),
                },
                None,
                DEFAULT_CENSOR_HEADROOM,
            )
            .await
            .unwrap();

        let stats = store.prune_old_records(90).await.unwrap();
        assert_eq!(stats.builds, 1, "expired terminal build pruned");

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let profile = store
            .get_profile("p", "pkg", "x86_64")
            .await
            .unwrap()
            .expect("profile row must survive builds prune");
        assert_eq!(profile.learned_ema_mem_kb, Some(2048));
        assert_eq!(profile.learned_sample_ncpu, Some(4));
    }

    /// 终态 IN 列表钉渲染形态与值集字面量（渲染回归或值集误改必红）；值集
    /// 有意扩容时在此红是提示同步白名单与残余 SQL/JS 站点，不是阻拦。
    #[test]
    fn terminal_phase_sql_list_pins_rendered_set() {
        assert_eq!(
            super::sql::terminal_phases_sql_list(),
            "'succeeded','failed','cancelled','timeout'"
        );
        // 接线面：prune 语句真的携带渲染出的 IN 谓词。
        let sql =
            super::sql::delete_terminal_local_builds_older_than(crate::state::Dialect::Sqlite);
        assert!(
            sql.contains("phase IN ('succeeded','failed','cancelled','timeout')"),
            "local-build prune SQL must carry the rendered terminal IN list: {sql}"
        );
    }

    /// 批次终态 IN 列表同款钉法：CHECK 域 7 值中仅 4 终态可清，漏词/错拼/
    /// 在途混入必红；接线面钉 prune 语句带 IN 谓词 + finished_at 双条件。
    #[test]
    fn terminal_batch_status_sql_list_pins_rendered_set() {
        assert_eq!(
            super::sql::terminal_batch_status_sql_list(),
            "'completed','partial','failed','cancelled'"
        );
        let sql = super::sql::delete_terminal_batches_older_than(crate::state::Dialect::Sqlite);
        assert!(
            sql.contains("status IN ('completed','partial','failed','cancelled')"),
            "batch prune SQL must carry the rendered terminal IN list: {sql}"
        );
        assert!(
            sql.contains("finished_at IS NOT NULL"),
            "batch prune SQL must require finished_at (in-flight guard): {sql}"
        );
        assert!(
            sql.contains("FROM build_batches"),
            "batch prune SQL must target build_batches: {sql}"
        );
    }

    /// 批次 retention 语义：过期终态批次删且 items 级联，在途与未超期终态
    /// 批次保留。批次步先于 tasks 步——被级联项引用的超期 childless 任务
    /// 同轮收走、存留项按需 SET NULL，全程无 FK 冲突。
    #[tokio::test]
    async fn prunes_expired_terminal_batches_and_cascades_items() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();

        let old = sql_time_offset(store.dialect(), "-100 days");
        let recent = sql_time_offset(store.dialect(), "-1 days");

        // b1/b2 过期终态→删；b3 在途（running，finished_at NULL）→保留；b4 未超期终态→保留。
        for (id, status, ts) in [
            (1, "completed", old.as_str()),
            (2, "failed", old.as_str()),
            (3, "running", "NULL"),
            (4, "cancelled", recent.as_str()),
        ] {
            sqlx::query(&format!(
                "INSERT INTO build_batches (id, status, source_repo_url, finished_at) \
                 VALUES ({id}, '{status}', 'https://example.test/repo', {ts})"
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        // 超期 childless 任务 t1 被批次项引用：若 tasks 步先行，引用只会被
        // SET NULL；t1 同轮被收走且无 FK 错 = 先批后任务序的行为面证据。
        sqlx::query(&format!(
            "INSERT INTO tasks (product, pkg_name, phase, completed_at) \
             VALUES ('p', 't1', 'succeeded', {old})"
        ))
        .execute(pool)
        .await
        .unwrap();

        // items：b1 一项随批次级联；b3/b4 各一项存留（t1 删后 task_id SET NULL）。
        for (id, batch, pkg) in [(1, 1, "b1p"), (2, 3, "b3p"), (3, 4, "b4p")] {
            sqlx::query(&format!(
                "INSERT INTO batch_items (id, batch_id, pkg_name, round, state, task_id) \
                 VALUES ({id}, {batch}, '{pkg}', 1, 'pending', (SELECT MAX(id) FROM tasks))"
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        let stats = store.prune_old_records(90).await.unwrap();
        assert_eq!(stats.build_batches, 2, "expired terminal batches pruned");
        assert_eq!(
            stats.tasks, 1,
            "expired childless task pruned after batch step"
        );

        let batches: Vec<i64> = sqlx::query_scalar("SELECT id FROM build_batches ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(batches, vec![3, 4], "in-flight and recent batches kept");
        let items: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT id, task_id FROM batch_items ORDER BY id")
                .fetch_all(pool)
                .await
                .unwrap();
        assert_eq!(
            items,
            vec![(2, None), (3, None)],
            "surviving batches keep their items; t1 deletion SET NULL their task_id"
        );
    }

    /// 在途批次（status running）即便 finished_at 有值也保守保留——终态
    /// 谓词与 finished_at 双条件缺一不可。
    #[tokio::test]
    async fn keeps_in_flight_batches_even_with_finished_at() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();
        let old = sql_time_offset(store.dialect(), "-100 days");
        sqlx::query(&format!(
            "INSERT INTO build_batches (id, status, source_repo_url, finished_at) \
             VALUES (1, 'running', 'https://example.test/repo', {old})"
        ))
        .execute(pool)
        .await
        .unwrap();

        let stats = store.prune_old_records(90).await.unwrap();
        assert_eq!(
            stats.build_batches, 0,
            "in-flight batch must be kept even with finished_at set"
        );
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM build_batches")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    /// building 阶段的 builds 即使超期也不删（在途构建保护）。
    #[tokio::test]
    async fn keeps_in_flight_builds() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();
        // builds.task_id NOT NULL：先插任务行承接；"user" 是 PG 保留字，裸 SQL 须加引号。
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ('p','x','','building')",
        )
        .execute(pool)
        .await
        .unwrap();
        let old = sql_time_offset(store.dialect(), "-100 days");
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, completed_at, task_id) \
             VALUES ('p','x','building', {old}, (SELECT MAX(id) FROM tasks))"
        ))
        .execute(pool)
        .await
        .unwrap();

        let stats = store.prune_old_records(90).await.unwrap();
        assert_eq!(stats.builds, 0, "in-flight build must be kept");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    /// 每产品保留最新 PRODUCT_HISTORY_KEEP_LATEST 个快照，未超限的产品不动。
    #[tokio::test]
    async fn prunes_product_history_to_keep_latest_per_product() {
        use super::PRODUCT_HISTORY_KEEP_LATEST;

        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();

        for name in ["p", "q"] {
            sqlx::query(&format!(
                "INSERT INTO products (name, visibility, config_json) VALUES ('{}', 'public', '{{}}')",
                name
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        // p（id=1）：25 条 → 删最旧 5 条；q（id=2）：3 条 → 不动。
        for (product_id, max_rev) in [(1, 25), (2, 3)] {
            for rev in 1..=max_rev {
                sqlx::query(
                    "INSERT INTO product_config_history \
                     (product_id, revision, config_json, base_os_revision) \
                     VALUES ($1, $2, '{}', 1)",
                )
                .bind(product_id)
                .bind(rev)
                .execute(pool)
                .await
                .unwrap();
            }
        }

        let stats = store.prune_old_records(90).await.unwrap();

        assert_eq!(
            stats.product_history, 5,
            "only the 5 oldest snapshots of p pruned"
        );

        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM product_config_history WHERE product_id = 1")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(n, PRODUCT_HISTORY_KEEP_LATEST);
        // 保留的是最新 20 条：revision 6..=25。
        let oldest: i64 = sqlx::query_scalar(
            "SELECT MIN(revision) FROM product_config_history WHERE product_id = 1",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(oldest, 26 - PRODUCT_HISTORY_KEEP_LATEST);

        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM product_config_history WHERE product_id = 2")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(n, 3, "product within keep-limit untouched");
    }

    /// 分批跨批全删 + stats 聚合：batch=3 × 7 条旧 audit_logs（2 满批 + 1
    /// 零批），stats.audit_logs 按批累加为 7，表删空。
    #[tokio::test]
    async fn batched_prune_drains_all_batches_and_aggregates_stats() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();
        let old = sql_time_offset(store.dialect(), "-100 days");
        for i in 0..7 {
            sqlx::query(&format!(
                "INSERT INTO audit_logs (action, created_at) VALUES ('a{i}', {})",
                old
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        let stats = store.prune_old_records_with_batch(90, 3).await.unwrap();
        assert_eq!(stats.audit_logs, 7, "cross-batch total must aggregate");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "all batches must drain the table");
    }

    /// 恰整数批终止：2×batch 条跑完满批后须再拿一批 0 才 break（防"实删
    /// < batch 即停"漏删或提前停），钉住不挂死且删净。
    #[tokio::test]
    async fn batched_prune_terminates_on_exact_multiple_batches() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();
        let old = sql_time_offset(store.dialect(), "-100 days");
        for i in 0..6 {
            sqlx::query(&format!(
                "INSERT INTO audit_logs (action, created_at) VALUES ('a{i}', {})",
                old
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        let stats = store.prune_old_records_with_batch(90, 3).await.unwrap();
        assert_eq!(stats.audit_logs, 6);
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(n, 0, "exact-multiple batches must fully drain");
    }

    /// 跨表批序 FK 保持：builds 多批删净后其 childless task 才可删，
    /// 全链小 batch 走完无 FK 错。
    #[tokio::test]
    async fn batched_prune_preserves_fk_order_across_tables() {
        let (store, _tmp) = create_test_store().await;
        let pool = store.pool();
        let old = sql_time_offset(store.dialect(), "-100 days");

        sqlx::query("INSERT INTO users (name, role) VALUES ('alice', 'operator')")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workers (name, arch) VALUES ('w1', 'x86_64')")
            .execute(pool)
            .await
            .unwrap();

        // 超期已完成 task 挂 5 个已 GC（result_dir NULL）超期子构建（batch=2
        // 时跨 3 批），各配一条终态 worker_task；"user" 加引号（PG 保留字）。
        let task_id: i64 = sqlx::query_scalar(&format!(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase, completed_at) \
             VALUES ('p','batch-fk','alice','succeeded', {}) RETURNING id",
            old
        ))
        .fetch_one(pool)
        .await
        .unwrap();
        for i in 0..5 {
            let build_id: i64 = sqlx::query_scalar(&format!(
                "INSERT INTO builds (product, pkg_name, phase, task_id, user_id, completed_at) \
                 VALUES ('p','bf-{i}','succeeded', {task_id}, 1, {}) RETURNING id",
                old
            ))
            .fetch_one(pool)
            .await
            .unwrap();
            sqlx::query(&format!(
                "INSERT INTO worker_tasks (build_id, worker_id, status, completed_at) \
                 VALUES ({build_id}, 1, 'completed', {})",
                old
            ))
            .execute(pool)
            .await
            .unwrap();
        }

        let stats = store.prune_old_records_with_batch(90, 2).await.unwrap();
        assert_eq!(stats.worker_tasks, 5);
        assert_eq!(stats.builds, 5, "builds must drain across 3 batches");
        assert_eq!(
            stats.tasks, 1,
            "task becomes childless only after builds drained"
        );

        for table in ["worker_tasks", "builds", "tasks"] {
            let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(pool)
                .await
                .unwrap();
            assert_eq!(n, 0, "{table} must be drained");
        }
    }
}
