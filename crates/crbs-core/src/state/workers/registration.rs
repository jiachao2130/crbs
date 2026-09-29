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

/// `worker_telemetry_samples` 查询行（平铺列 → [`TelemetrySamplePoint`]）。
/// 浮点直读无钉型问题（钉型坑只在参数绑定侧，见各写入站注释）。
#[derive(Debug, sqlx::FromRow)]
struct TelemetrySampleRow {
    sampled_at: String,
    load1: Option<f64>,
    ncpu: Option<i64>,
    cpu_util_pct: Option<f64>,
    mem_used_pct: Option<f64>,
    mem_total_kb: Option<i64>,
    #[sqlx(default)]
    disk_free_kb: Option<i64>,
}

impl From<TelemetrySampleRow> for TelemetrySamplePoint {
    fn from(r: TelemetrySampleRow) -> Self {
        Self {
            sampled_at: r.sampled_at,
            telemetry: WorkerTelemetry {
                load1: r.load1,
                ncpu: r.ncpu,
                cpu_util_pct: r.cpu_util_pct,
                mem_used_pct: r.mem_used_pct,
                mem_total_kb: r.mem_total_kb,
                disk_free_kb: r.disk_free_kb,
            },
        }
    }
}

impl StateStore {
    /// 注册或更新 Worker。`initial_status` 仅作用于 INSERT 分支（server 注册传
    /// `'online'`；`crbs-server worker add` 预置传 `'offline'`，预置行不应立即可调度）；
    /// 冲突分支不改 status（见 `sql::upsert_worker`），由 `worker_recover_online` 语义化翻转。
    pub async fn upsert_worker(
        &self,
        name: &str,
        arch: &str,
        capacity: i64,
        version: &str,
        initial_status: &str,
        resource_caps: Option<i64>,
    ) -> crate::Result<i64> {
        let id: i64 = sqlx::query_scalar(&sql::upsert_worker(self.dialect))
            .bind(name)
            .bind(arch)
            .bind(capacity)
            .bind(version)
            .bind(initial_status)
            // 新绑定接队尾（占位符序=绑定序）；INTEGER 直绑无钉型坑。
            .bind(resource_caps)
            .fetch_one(&self.pool)
            .await
            .db_ctx("upsert worker")?;

        // 注册（在线状态面变化）即广播；conflict 分支重复注册 = 无害唤醒。
        self.notify_state_changed();
        // 注册可能引入新 secret→身份映射（新行 id），bump 代数让认证缓存回源（宁多勿漏，conflict 重复注册无害）。
        self.bump_user_generation();
        Ok(id)
    }

    /// 常规心跳：bump last_heartbeat 并覆写负载遥测列，不改动 status（只有明确的下线信号才能改）。
    /// 生产路径走 `worker_heartbeat_upsert`（单 UPDATE 合并）；本方法保留给测试夹具及潜在外部调用方。
    pub async fn worker_touch_heartbeat(
        &self,
        id: i64,
        telemetry: WorkerTelemetry,
        resource_caps: Option<i64>,
    ) -> crate::Result<()> {
        // 浮点以 TEXT 绑定 + SQL 侧 CAST：绕开 sqlx Any 驱动 NULL 浮点 Real/Double 互换钉型 FLOAT4 的坑。
        sqlx::query(&sql::touch_worker_heartbeat(self.dialect))
            .bind(id)
            .bind(telemetry.load1.map(|v| v.to_string()))
            .bind(telemetry.ncpu)
            .bind(telemetry.cpu_util_pct.map(|v| v.to_string()))
            .bind(telemetry.mem_used_pct.map(|v| v.to_string()))
            // INTEGER 直绑（无浮点钉型坑）；新绑定接队尾（占位符序=绑定序）。
            .bind(telemetry.mem_total_kb)
            .bind(telemetry.disk_free_kb)
            .bind(resource_caps)
            .execute(&self.pool)
            .await
            .db_ctx("worker heartbeat")?;

        // 刻意不广播：心跳 30s 一次，广播唤醒全部 SSE 连接（W worker → 每连接 2W+2 查询/分钟，规模下反而劣化）；
        // 翻转由 upsert_worker / mark_offline / recover_online 收口，新鲜度漂移由 dashboard 30s 兜底轮询覆盖。
        Ok(())
    }

    /// 主动下线：status 置 'offline' 并更新心跳时间，遥测各列同时置 NULL（见 `sql::mark_worker_offline`：
    /// offline 心跳本身刷新 last_heartbeat，保留旧采样会让 UI 在无 stale 标记窗口展示过期值）。
    /// 仅 online/offline 行可翻转（SQL `WHERE status IN ('online','offline')`），
    /// suspended/draining 等管理员保留态不被下线信号覆盖（0 行 no-op，广播无害）。生产路径走
    /// `worker_heartbeat_upsert` offline=true 分支；本方法保留给测试夹具及潜在外部调用方。
    pub async fn worker_mark_offline(&self, id: i64) -> crate::Result<()> {
        sqlx::query(&sql::mark_worker_offline(self.dialect))
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("worker mark offline")?;

        self.notify_state_changed();
        Ok(())
    }

    /// 收到健康心跳（payload.status != 'offline'）时，若 DB status 仍为 'offline' 则翻回
    /// 'online'；'draining'、'suspended' 等管理员标记原样保留。worker 偶发 reconnect 不重跑
    /// register，offline 行永不自愈。安全约束：SQL `WHERE id=$1 AND status='offline'` 只翻转
    /// 严格等于 'offline' 的行，管理员 / 调度器写下的任何非 'offline' 状态（含 'draining'）不被心跳覆盖。
    pub async fn worker_recover_online(&self, id: i64) -> crate::Result<bool> {
        let res = sqlx::query(sql::RECOVER_WORKER_ONLINE)
            .bind(id)
            .execute(&self.pool)
            .await
            .db_ctx("worker recover online")?;

        let recovered = res.rows_affected() > 0;
        if recovered {
            self.notify_state_changed();
        }
        Ok(recovered)
    }

    /// 心跳主 UPDATE + best-effort 采样 INSERT。`offline=true` 优雅停机：status 置 'offline'、
    /// 遥测各列置 NULL；仅 online/offline 行翻转，suspended/draining 等管理员保留态保持，
    /// 但 last_heartbeat / 遥测列照常更新、行仍计 affected。落到存在的行才广播（affected=0
    /// 路由 404 不广播）。`offline=false` 常规心跳：当前 'offline' 则翻 'online'（recover_online
    /// 安全约束，不覆盖 draining/suspended）、遥测覆写（None → NULL）。
    /// offline→online 翻转**不**广播：双方言 RETURNING 只回新值无法识别翻转、SQLite 无
    /// data-modifying CTE，再读一次识别翻转会多一次往返；降级为 dashboard 30s 兜底轮询。
    /// 返回 rows_affected（0 = 行不存在 → 调用方 404，替代 get_worker 存在性预检）。
    /// 心跳有效（affected>0、非 offline、cpu 或 mem 至少一项有采样）时顺带向
    /// `worker_telemetry_samples` 追加一条历史采样（best-effort，见函数体内注）。
    pub async fn worker_heartbeat_upsert(
        &self,
        id: i64,
        offline: bool,
        telemetry: WorkerTelemetry,
        resource_caps: Option<i64>,
    ) -> crate::Result<u64> {
        // 浮点以 TEXT 绑定 + SQL 侧 CAST：绕开 sqlx Any 驱动 NULL 浮点 Real/Double 互换钉型 FLOAT4 的坑。
        let res = sqlx::query(&sql::worker_heartbeat_upsert(self.dialect))
            .bind(id)
            .bind(if offline { "offline" } else { "online" })
            .bind(telemetry.load1.map(|v| v.to_string()))
            .bind(telemetry.ncpu)
            .bind(telemetry.cpu_util_pct.map(|v| v.to_string()))
            .bind(telemetry.mem_used_pct.map(|v| v.to_string()))
            // INTEGER 直绑；新绑定接队尾（占位符序=绑定序）。
            .bind(telemetry.mem_total_kb)
            .bind(telemetry.disk_free_kb)
            .bind(resource_caps)
            .execute(&self.pool)
            .await
            .db_ctx("worker heartbeat upsert")?;

        let affected = res.rows_affected();
        // 历史采样 best-effort 追加写：与心跳 UPDATE 分两条语句（不并一个事务）
        // ——采样失败只 warn 不使心跳失败（历史是展示性数据，心跳可用性优先；
        // 同事务原子性会让 best-effort 降级失效）。offline / 全指标 None 的
        // 心跳不落采样（无有效观测值，offline 时段由图表断线表达）。
        if affected > 0
            && !offline
            && (telemetry.cpu_util_pct.is_some()
                || telemetry.mem_used_pct.is_some()
                || telemetry.disk_free_kb.is_some())
        {
            let sample = sqlx::query(&sql::insert_telemetry_sample(self.dialect))
                .bind(id)
                .bind(telemetry.load1.map(|v| v.to_string()))
                .bind(telemetry.ncpu)
                .bind(telemetry.cpu_util_pct.map(|v| v.to_string()))
                .bind(telemetry.mem_used_pct.map(|v| v.to_string()))
                .bind(telemetry.mem_total_kb)
                .bind(telemetry.disk_free_kb)
                .execute(&self.pool)
                .await;
            if let Err(e) = sample {
                tracing::warn!(
                    worker_id = %id,
                    error = ?e,
                    "Failed to append telemetry sample (best-effort)"
                );
            }
        }
        if offline && affected > 0 {
            // 停机 = 状态面变化即广播（mark_offline 语义）；affected=0 路由 404 不广播。
            self.notify_state_changed();
        }
        Ok(affected)
    }

    /// 按 worker 拉时间窗内遥测采样（详情页趋势图数据源）。`window_minutes`
    /// 为窗口宽度（sql_minutes_ago 入参，双侧同帧 TEXT 比较机制见 sql 模块）；
    /// `limit` 经 [`TELEMETRY_SAMPLE_QUERY_LIMIT`] 钳制防御，超限按最新保留
    /// （SQL DESC 取限）；返回仍 sampled_at 升序。
    pub async fn list_telemetry_samples(
        &self,
        worker_id: i64,
        window_minutes: i64,
        limit: i64,
    ) -> crate::Result<Vec<TelemetrySamplePoint>> {
        let limit = limit.clamp(1, TELEMETRY_SAMPLE_QUERY_LIMIT);
        let rows = sqlx::query_as::<_, TelemetrySampleRow>(&sql::list_telemetry_samples(
            self.dialect,
            window_minutes,
        ))
        .bind(worker_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .db_ctx("list telemetry samples")?;

        Ok(rows.into_iter().rev().map(|r| r.into()).collect())
    }

    /// 获取在线 Worker 列表。
    pub async fn list_online_workers(
        &self,
        arch: Option<&str>,
    ) -> crate::Result<Vec<WorkerStatus>> {
        let rows = match arch {
            Some(a) => sqlx::query_as::<_, WorkerStatusRow>(&sql::list_online_workers_by_arch(
                self.dialect,
            ))
            .bind(a)
            .fetch_all(&self.pool)
            .await
            .db_ctx("list online workers")?,
            None => sqlx::query_as::<_, WorkerStatusRow>(&sql::list_online_workers(self.dialect))
                .fetch_all(&self.pool)
                .await
                .db_ctx("list online workers")?,
        };

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// 统计在线 Worker 数量（可选按架构过滤）。
    pub async fn count_online_workers(&self, arch: Option<&str>) -> crate::Result<usize> {
        let count: i64 = match arch {
            Some(a) => sqlx::query_scalar(&sql::count_online_workers_by_arch(self.dialect))
                .bind(a)
                .fetch_one(&self.pool)
                .await
                .db_ctx("count online workers")?,
            None => sqlx::query_scalar(&sql::count_online_workers(self.dialect))
                .fetch_one(&self.pool)
                .await
                .db_ctx("count online workers")?,
        };

        Ok(count as usize)
    }

    /// 按架构聚合注册 / 在线 Worker 数（UI 仪表盘 Workers 面板）；结果按 arch 字典序返回，无注册 worker 时为空 Vec。
    pub async fn count_workers_by_arch(&self) -> crate::Result<Vec<WorkerArchCounts>> {
        let rows = sqlx::query_as::<_, WorkerArchCounts>(&sql::count_workers_by_arch(self.dialect))
            .fetch_all(&self.pool)
            .await
            .db_ctx("count workers by arch")?;

        Ok(rows)
    }

    /// 按架构聚合**在线** worker 的 CPU 利用率均值（首页架构条均值 chip）。
    /// 行口径：status='online' 且 2min 内有心跳（与 [`Self::count_workers_by_arch`]
    /// 的 online 同 freshness）、cpu_util_pct 非空；无有效遥测的架构
    /// 不出现，调用方按缺省不渲染 chip。SQL 细节见 `sql::worker_arch_cpu_avg`。
    pub async fn worker_arch_cpu_avg(&self) -> crate::Result<Vec<WorkerArchCpuAvg>> {
        let rows = sqlx::query_as::<_, WorkerArchCpuAvg>(&sql::worker_arch_cpu_avg(self.dialect))
            .fetch_all(&self.pool)
            .await
            .db_ctx("worker arch cpu avg")?;

        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_state::create_test_store;

    /// `worker_arch_cpu_avg` 口径：在线 + 心跳新鲜 + cpu_util_pct 非空才计入；
    /// offline / NULL 遥测排除，全无遥测的架构不出现。
    #[tokio::test]
    async fn test_worker_arch_cpu_avg_excludes_offline_and_null_telemetry() {
        let (store, _tmp) = create_test_store().await;

        // arch x86_64：两台有效在线（50% + 100% → 均值 75%）。
        let w1 = store
            .upsert_worker("avg-a", "x86_64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(
                w1,
                WorkerTelemetry {
                    load1: Some(4.0),
                    ncpu: Some(8),
                    cpu_util_pct: Some(50.0),
                    mem_used_pct: None,
                    mem_total_kb: None,
                    disk_free_kb: None,
                },
                None,
            )
            .await
            .unwrap();
        let w2 = store
            .upsert_worker("avg-b", "x86_64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(
                w2,
                WorkerTelemetry {
                    load1: Some(8.0),
                    ncpu: Some(8),
                    cpu_util_pct: Some(100.0),
                    mem_used_pct: None,
                    mem_total_kb: None,
                    disk_free_kb: None,
                },
                None,
            )
            .await
            .unwrap();
        // 同架构应排除的两台：offline、无遥测（NULL）。
        let w3 = store
            .upsert_worker("avg-off", "x86_64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(
                w3,
                WorkerTelemetry {
                    load1: Some(16.0),
                    ncpu: Some(8),
                    cpu_util_pct: Some(95.0),
                    mem_used_pct: None,
                    mem_total_kb: None,
                    disk_free_kb: None,
                },
                None,
            )
            .await
            .unwrap();
        store.worker_mark_offline(w3).await.unwrap();
        let w4 = store
            .upsert_worker("avg-null", "x86_64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(w4, WorkerTelemetry::default(), None)
            .await
            .unwrap();

        // arch aarch64：仅一台有效（25%）。
        let w6 = store
            .upsert_worker("avg-arm", "aarch64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(
                w6,
                WorkerTelemetry {
                    load1: Some(1.0),
                    ncpu: Some(4),
                    cpu_util_pct: Some(25.0),
                    mem_used_pct: None,
                    mem_total_kb: None,
                    disk_free_kb: None,
                },
                None,
            )
            .await
            .unwrap();

        // arch riscv64：唯一一台无遥测 → 架构整体不出现在结果中。
        let w7 = store
            .upsert_worker("avg-none", "riscv64", 4, "1.0", "online", None)
            .await
            .unwrap();
        store
            .worker_touch_heartbeat(w7, WorkerTelemetry::default(), None)
            .await
            .unwrap();

        let mut rows = store.worker_arch_cpu_avg().await.unwrap();
        rows.sort_by(|a, b| a.arch.cmp(&b.arch));
        assert_eq!(rows.len(), 2, "riscv64 has no valid telemetry: {rows:?}");
        assert_eq!(rows[0].arch, "aarch64");
        assert!((rows[0].cpu_avg - 25.0).abs() < 1e-9);
        assert_eq!(rows[1].arch, "x86_64");
        assert!(
            (rows[1].cpu_avg - 75.0).abs() < 1e-9,
            "offline/NULL rows must be excluded: {rows:?}"
        );
    }
}
