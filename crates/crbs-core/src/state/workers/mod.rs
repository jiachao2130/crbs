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

use sqlx::Row;

use super::StateStore;
use crate::error::{CrbsError, DbResultExt};

mod admin;
mod assignment;
mod init;
mod registration;
mod tasks;
#[cfg(test)]
mod tests;

/// worker 采集能力位（`workers.resource_caps` 位图，bit 编号见 schema 列注）；
/// 后续新能力只加位不改表。探测实现见 crbs-worker（启动探测，注册/心跳携带）。
pub const RESOURCE_CAP_CGROUP_V2: i64 = 1 << 0;
/// 根 cgroup 下 `memory.peak` 可读（总内存高水位采集能力）。
pub const RESOURCE_CAP_MEMORY_PEAK: i64 = 1 << 1;
/// 根 cgroup 下 `memory.events` 可读（oom_kill 检出能力）。
pub const RESOURCE_CAP_MEMORY_EVENTS: i64 = 1 << 2;
/// 根 cgroup 下 `io.stat` 可读（写足迹采集能力）。
pub const RESOURCE_CAP_IO_STAT: i64 = 1 << 3;
/// `/proc/pressure/{cpu,memory,io}` 任一存在（PSI 压力信息能力，仅探测不采集）。
pub const RESOURCE_CAP_PSI: i64 = 1 << 4;

/// hub 本地车道伪 worker 名：scheduler 内存态本地兜底车道以此名构造伪 worker
/// （不入库，仅参与水位判定与归因）。该名被 server 独占接管，真实 worker 注册 /
/// `worker add` 均拒用，防与内存态车道混淆。
pub const HUB_LOCAL_WORKER_NAME: &str = "hub-local";

// pub(crate)：insert_worker_task_build 由 dispatch.rs（指定 CAS 领取）共用，
// 单一 SQL 源防双写漂移；其余项仍 pub(super) 收口在本域内。
pub(crate) mod sql {
    use crate::state::Dialect;

    /// worker 心跳新鲜度阈值（秒，120s = 2min），在线判定 / 派发谓词共用。
    /// 语义孪生：crbs-server `scheduler::WORKER_HEARTBEAT_TIMEOUT_SECS`，改其一
    /// 必须同步另一个；worker 侧 `MAX_HEARTBEAT_INTERVAL_SECS = 110` 须低于此值。
    const WORKER_STALE_HEARTBEAT_SECS: i64 = 120;

    /// 整除防呆：窗口按分钟渲染进 SQL（`/ 60`），非整分钟会被静默取整
    /// （90→1min 收紧、59→0min 全员判 stale），在此编译期报错。
    const _: () = assert!(WORKER_STALE_HEARTBEAT_SECS % 60 == 0);

    /// Upsert worker（方言感知）。冲突分支不强制翻回 online：suspended/
    /// draining/offline 等管理员状态只能由显式管理操作或
    /// `worker_recover_online`（仅 offline→online）改变；INSERT 初始 status
    /// 由 `$5` 参数化：注册传 'online'，`worker add` 预置 'offline'。
    /// `resource_caps`（$6）注册/重复注册都覆写：重注册 = 进程重启 = 重新探测。
    pub(super) fn upsert_worker(dialect: Dialect) -> String {
        let now = dialect.sql_now();
        format!(
            "INSERT INTO workers (name, arch, capacity, version, status, last_heartbeat, resource_caps) \
             VALUES ($1, $2, $3, $4, $5, {}, $6) \
             ON CONFLICT(name) DO UPDATE SET \
                arch = excluded.arch, \
                capacity = excluded.capacity, \
                version = excluded.version, \
                resource_caps = excluded.resource_caps, \
                last_heartbeat = {} \
             RETURNING id",
            now, now
        )
    }

    /// 更新 worker 心跳（方言感知）。遥测列随心跳覆写，`None` 写
    /// NULL——旧采样必须清掉，UI 才能诚实显示 "—"。浮点各列 TEXT 绑定 +
    /// CAST 规避 sqlx Any 钉型坑：首个全 NULL 心跳把语句参数钉在 FLOAT4，
    /// 后续 `Some(f64)` 报 PG "incorrect binary data format"。
    pub(super) fn touch_worker_heartbeat(dialect: Dialect) -> String {
        format!(
            "UPDATE workers SET last_heartbeat = {}, load1 = {}, ncpu = $3, cpu_util_pct = {}, \
                mem_used_pct = {}, mem_total_kb = $6, disk_free_kb = $7, resource_caps = $8 \
             WHERE id = $1",
            dialect.sql_now(),
            dialect.float_param_cast(2),
            dialect.float_param_cast(4),
            dialect.float_param_cast(5),
        )
    }

    /// 标记 worker 离线（方言感知）。`WHERE status IN ('online','offline')`：
    /// suspended/draining 等管理员保留态不被下线信号覆盖；同时清空遥测各列
    /// ——offline 心跳仍刷新 last_heartbeat，旧采样会在无 stale 标记窗口展示过期遥测。
    pub(super) fn mark_worker_offline(dialect: Dialect) -> String {
        format!(
            "UPDATE workers SET status = 'offline', last_heartbeat = {}, \
                load1 = NULL, ncpu = NULL, cpu_util_pct = NULL, \
                mem_used_pct = NULL, mem_total_kb = NULL, \
                disk_free_kb = NULL, resource_caps = NULL \
             WHERE id = $1 AND status IN ('online', 'offline')",
            dialect.sql_now()
        )
    }

    /// 心跳单 UPDATE：存在性预检 + 恢复 online + touch/mark_offline 合并。
    ///
    /// status 翻转：offline 心跳仅当 status IN ('online','offline') 落
    /// 'offline'（管理员保留态不被覆盖，但照常刷新 last_heartbeat / 遥测
    /// 列）；online 心跳仅当当前 offline 翻 'online'，其余保持。遥测列
    /// offline 置 NULL（旧采样在无 stale 标记窗口展示过期值），online 覆写
    /// （None→NULL）。字符串绑定进 CASE 避 bool 双方言绑定面；浮点各列
    /// TEXT + CAST 同 `touch_worker_heartbeat`；rows_affected=0 = 行不存在（404）。
    /// 参数序：$1=id、$2=status、$3=load1、$4=ncpu、$5=cpu_util_pct、
    /// $6=mem_used_pct、$7=mem_total_kb、$8=disk_free_kb、$9=resource_caps。
    pub(super) fn worker_heartbeat_upsert(dialect: Dialect) -> String {
        format!(
            "UPDATE workers SET \
                last_heartbeat = {}, \
                status = CASE WHEN $2 = 'offline' AND status IN ('online', 'offline') THEN 'offline' \
                              WHEN $2 = 'online' AND status = 'offline' THEN 'online' \
                              ELSE status END, \
                load1 = CASE WHEN $2 = 'offline' THEN NULL ELSE {} END, \
                ncpu = CASE WHEN $2 = 'offline' THEN NULL ELSE $4 END, \
                cpu_util_pct = CASE WHEN $2 = 'offline' THEN NULL ELSE {} END, \
                mem_used_pct = CASE WHEN $2 = 'offline' THEN NULL ELSE {} END, \
                mem_total_kb = CASE WHEN $2 = 'offline' THEN NULL ELSE $7 END, \
                disk_free_kb = CASE WHEN $2 = 'offline' THEN NULL ELSE $8 END, \
                resource_caps = CASE WHEN $2 = 'offline' THEN NULL ELSE $9 END \
             WHERE id = $1",
            dialect.sql_now(),
            dialect.float_param_cast(3),
            dialect.float_param_cast(5),
            dialect.float_param_cast(6),
        )
    }

    /// 仅当 DB 中 status='offline' 时翻 'online'，其它状态（如管理员设置的
    /// 'draining'/'suspended'）保持不变——防心跳路径擦除管理员 / 调度器状态。
    pub(super) const RECOVER_WORKER_ONLINE: &str = "\
        UPDATE workers SET status = 'online' \
         WHERE id = $1 AND status = 'offline'";

    /// 追加一条遥测采样（心跳路径 best-effort 调用，失败只 warn 不回传）。
    /// sampled_at 用方言 `sql_now`，与同一心跳刷新的 last_heartbeat 同源同帧
    /// （两条语句先后执行，时钟差为语句间隔，展示口径无损）；浮点 TEXT 绑定
    /// + CAST 同 `worker_heartbeat_upsert`（参数序 $2/$4/$5 浮点，INTEGER 直绑）。
    pub(super) fn insert_telemetry_sample(dialect: Dialect) -> String {
        format!(
            "INSERT INTO worker_telemetry_samples \
                 (worker_id, sampled_at, load1, ncpu, cpu_util_pct, mem_used_pct, mem_total_kb, disk_free_kb) \
             VALUES ($1, {}, {}, $3, {}, {}, $6, $7)",
            dialect.sql_now(),
            dialect.float_param_cast(2),
            dialect.float_param_cast(4),
            dialect.float_param_cast(5),
        )
    }

    /// 按 worker 拉时间窗内采样（$2 = limit）。窗口比较机制同
    /// `worker_arch_cpu_avg`：方言感知"now - N 分钟"渲染进 SQL 与 TEXT
    /// 时间列字典序比较（两侧同帧 `YYYY-MM-DD HH:MM:SS`，字典序=时序）。
    /// DESC 取限（超限保留最新采样，趋势图"现在"端不缺），Rust 侧倒序
    /// 回升序（调用方契约，见 [`StateStore::list_telemetry_samples`]）。
    pub(super) fn list_telemetry_samples(dialect: Dialect, window_minutes: i64) -> String {
        format!(
            "SELECT sampled_at, load1, ncpu, cpu_util_pct, mem_used_pct, mem_total_kb, disk_free_kb \
             FROM worker_telemetry_samples \
             WHERE worker_id = $1 AND sampled_at >= {} \
             ORDER BY sampled_at DESC, id DESC \
             LIMIT $2",
            dialect.sql_minutes_ago(window_minutes)
        )
    }

    /// 列出指定架构的在线 worker（方言感知，120s 超时阈值）。遥测四列随行
    /// 拉出，供调度派发序与内存准入门直接消费。
    pub(super) fn list_online_workers_by_arch(dialect: Dialect) -> String {
        format!(
            "SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash, \
                    load1, ncpu, mem_used_pct, mem_total_kb \
             FROM workers \
             WHERE status = 'online' AND arch = $1 \
               AND last_heartbeat > {} \
             ORDER BY id",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    /// 列出所有在线 worker（方言感知，120s 超时阈值）。遥测四列见
    /// [`Self::list_online_workers_by_arch`]。
    pub(super) fn list_online_workers(dialect: Dialect) -> String {
        format!(
            "SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash, \
                    load1, ncpu, mem_used_pct, mem_total_kb \
             FROM workers \
             WHERE status = 'online' \
               AND last_heartbeat > {} \
             ORDER BY id",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    /// 统计指定架构的在线 worker 数量（方言感知）。
    pub(super) fn count_online_workers_by_arch(dialect: Dialect) -> String {
        format!(
            "SELECT COUNT(*) FROM workers \
             WHERE status = 'online' AND arch = $1 \
               AND last_heartbeat > {}",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    /// 统计所有在线 worker 数量（方言感知）。
    pub(super) fn count_online_workers(dialect: Dialect) -> String {
        format!(
            "SELECT COUNT(*) FROM workers \
             WHERE status = 'online' \
               AND last_heartbeat > {}",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    /// 按架构聚合注册 / 在线 worker 数（仪表盘 Workers 面板，方言感知）。
    /// `online` 口径同 [`Self::count_online_workers`]；`total` 为全部注册行
    /// ——workers 表硬删除（无 revoked 概念），COUNT(*) 即注册总量。
    pub(super) fn count_workers_by_arch(dialect: Dialect) -> String {
        format!(
            "SELECT arch, \
                    COUNT(*) AS total, \
                    SUM(CASE WHEN status = 'online' AND last_heartbeat > {} THEN 1 ELSE 0 END) AS online \
             FROM workers \
             GROUP BY arch \
             ORDER BY arch",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    /// 按架构聚合在线 worker 的 CPU 利用率均值（首页均值 chip，方言感知）。
    /// freshness 口径同 [`Self::count_workers_by_arch`]；`cpu_util_pct IS NOT
    /// NULL` 排除无采样行（NULL 行该比较不成立，同样排除）。
    pub(super) fn worker_arch_cpu_avg(dialect: Dialect) -> String {
        format!(
            "SELECT arch, AVG(cpu_util_pct) AS cpu_avg \
             FROM workers \
             WHERE status = 'online' \
               AND last_heartbeat > {} \
               AND cpu_util_pct IS NOT NULL \
             GROUP BY arch",
            dialect.sql_minutes_ago(WORKER_STALE_HEARTBEAT_SECS / 60)
        )
    }

    pub(super) const COUNT_WORKER_ACTIVE_TASKS: &str = "\
        SELECT COUNT(*) FROM worker_tasks \
        WHERE worker_id = $1 AND status IN ('assigned', 'running')";

    /// 批量统计各 worker 的活跃任务数（UI Load 列用；单条聚合、双方言）。
    pub(super) const COUNT_ACTIVE_TASKS_BY_WORKER: &str = "\
        SELECT worker_id, COUNT(*) FROM worker_tasks \
        WHERE status IN ('assigned', 'running') \
        GROUP BY worker_id";

    /// 批量列出各 worker 活跃构建的 (worker_id, product, source_name, arch)
    ///（调度准入门权重数据源；source_name = builds.name 源码包基础名，口径同
    /// [`Self::COUNT_ACTIVE_TASKS_BY_WORKER`]）。爬坡窗口谓词（`ramp_secs`）：
    /// 只供"派发后未爬满"的行——started_at 在派发与领取时即写入，NULL 臂仅
    /// 防御历史脏行（视同爬坡期计入）；窗口内已起跑的权重尚未完全体现进
    /// load1，爬满后在跑负载由 load1 承载，再计 Σ 即时间维双计。
    pub(super) fn list_active_build_pkgs_by_worker(dialect: Dialect, ramp_secs: i64) -> String {
        format!(
            "SELECT wt.worker_id, b.product, b.name AS source_name, NULLIF(b.arch, '') AS arch \
             FROM worker_tasks wt \
             JOIN builds b ON wt.build_id = b.id \
             WHERE wt.kind = 'build' \
               AND wt.status IN ('assigned', 'running') \
               AND (b.started_at IS NULL OR b.started_at >= {})",
            dialect.sql_seconds_ago(ramp_secs)
        )
    }

    /// 列出 worker 当前活跃 build（UI 详情页）。口径同
    /// [`Self::COUNT_WORKER_ACTIVE_TASKS`]；`started_at` 回退分配时间——
    /// assigned-but-not-started 的 build 尚无 started_at。
    pub(super) const LIST_WORKER_ACTIVE_BUILDS: &str = "\
        SELECT b.id, b.product, b.pkg_name, b.phase, \
               COALESCE(b.started_at, wt.assigned_at) AS started_at \
        FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 \
          AND wt.kind = 'build' \
          AND wt.status IN ('assigned', 'running') \
        ORDER BY b.id DESC";

    /// 列出 worker 最近 10 条 build 分配（UI 详情页 Recent builds 卡，含终态
    /// 行）：按分配行 id 倒序（重派后的新行排前）；`completed_at` 供耗时计算
    /// （running 行为 NULL，UI 实时计 elapsed）。
    pub(super) const LIST_WORKER_RECENT_BUILDS: &str = "\
        SELECT b.id, b.product, b.pkg_name, b.phase, \
               COALESCE(b.started_at, wt.assigned_at) AS started_at, \
               b.completed_at \
        FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 \
          AND wt.kind = 'build' \
        ORDER BY wt.id DESC \
        LIMIT 10";

    /// 列出 worker 最近 20 条 init 分配（UI 详情页 Base OS inits 卡原始行集）
    /// ：每产品"最近一次"由 Rust 侧按 init_product 去重（窗口函数 / GROUP BY
    /// 取整行的方言差异规避），20 条窗口足够覆盖产品数；init_product 非空
    /// （INSERT 收口恒非空，NULL 防御过滤）。
    pub(super) const LIST_WORKER_RECENT_INITS: &str = "\
        SELECT init_product AS product, status, assigned_at, completed_at \
        FROM worker_tasks \
        WHERE worker_id = $1 \
          AND kind = 'init' \
          AND init_product IS NOT NULL \
        ORDER BY id DESC \
        LIMIT 20";

    /// 心跳取消通知数据源：该 worker 名下 build 已被取消的 assignment id。
    /// **故意不过滤 worker_tasks.status**——取消对它的写入是 best-effort，
    /// 失败行滞留 running 直至被终态 sweep 收走，按 status 过滤会永久丢
    /// 通知；重复 id 无害（worker 侧注册表幂等）。
    pub(super) const LIST_CANCELLED_ASSIGNMENT_IDS_FOR_WORKER: &str = "\
        SELECT wt.id FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 AND b.phase = 'cancelled' \
        ORDER BY wt.id DESC LIMIT 1000";

    /// poll 响应丢失重投递：该 worker 名下已 running 且 build 仍 building 的
    /// assignment。hub 把 assignment CAS 到 running 后 COMMIT 在 HTTP 响应
    /// 前，响应丢失则行停留 running、worker 续 poll 恒 204、capacity 永久
    /// 占用——不重置回 pending（会复刻双执行，worker 侧按取消注册表去重）。
    pub(super) const LIST_RUNNING_ASSIGNMENTS_FOR_WORKER: &str = "\
        SELECT wt.id, wt.task_id, wt.build_id, b.product, b.srpm_path, b.request_json, b.repo_consume \
        FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 AND wt.status = 'running' \
          AND wt.kind = 'build' \
          AND b.phase = 'building' \
        ORDER BY wt.id";

    pub(super) const SELECT_WORKER_BY_ID: &str = "\
        SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash, \
               load1, ncpu, cpu_util_pct, mem_used_pct, mem_total_kb, \
               disk_free_kb, resource_caps, created_at, secret_expires_at \
        FROM workers WHERE id = $1";

    /// 更新 worker_task 状态（方言感知时间）。词汇表校验在 Rust 侧（tasks.rs）；
    /// SQL 拒绝终态→活跃回退：cancel/完成竞态不得把已终态行拉回活跃占容量。
    /// 终态写入顺带 stamp `completed_at`（retention 终态清理以该列判定可删，
    /// 不 stamp 会永久泄漏）；非终态保持原值；守卫只挡终态→活跃，不挡终态→异终态。
    pub(super) fn update_worker_task_status(dialect: Dialect) -> String {
        format!(
            "UPDATE worker_tasks SET status = $1, \
                completed_at = CASE WHEN $1 IN ('completed', 'failed', 'cancelled') \
                                    THEN {} ELSE completed_at END \
             WHERE id = $2 \
               AND NOT (status IN ('completed', 'failed', 'cancelled') \
                        AND $1 IN ('assigned', 'running'))",
            dialect.sql_now()
        )
    }

    /// 同上（按 build_id 定位），终态守卫与 completed_at stamp 语义一致。
    pub(super) fn update_worker_task_status_for_build(dialect: Dialect) -> String {
        format!(
            "UPDATE worker_tasks SET status = $1, \
                completed_at = CASE WHEN $1 IN ('completed', 'failed', 'cancelled') \
                                    THEN {} ELSE completed_at END \
             WHERE build_id = $2 \
               AND NOT (status IN ('completed', 'failed', 'cancelled') \
                        AND $1 IN ('assigned', 'running'))",
            dialect.sql_now()
        )
    }

    /// 一次行查询 worker_task 归属元组（report 入口归属校验 / 终态截断用）。
    pub(super) const SELECT_WORKER_TASK_META: &str =
        "SELECT build_id, worker_id, kind, status FROM worker_tasks WHERE id = $1";

    /// 查询指定 worker 是否持有该 build 的分配行。不限定状态：终态后行仍
    /// 保留，覆盖 worker 上传失败重试场景。
    pub(super) const SELECT_WORKER_TASK_OWNED_BY: &str = "\
        SELECT id FROM worker_tasks \
        WHERE build_id = $1 AND worker_id = $2 AND kind = 'build' \
          AND status IN ('assigned', 'running') \
          AND ($3 IS NULL OR id = $3) \
        LIMIT 1";

    /// build 最近一次 assignment 的 worker 名（UI 详情"执行节点"）。不限定
    /// 状态（终态后行保留，与上传归属校验的活跃口径不同）。
    pub(super) const SELECT_LATEST_BUILD_WORKER_NAME: &str = "\
        SELECT w.name FROM worker_tasks wt \
        JOIN workers w ON w.id = wt.worker_id \
        WHERE wt.build_id = $1 AND wt.kind = 'build' \
        ORDER BY wt.id DESC \
        LIMIT 1";

    /// build 生命周期时刻单行查询（UI 详情 Lifecycle 小节）。最新一条 build
    /// 型分配行经 JOIN ON 标量子查询定位（双方言同构），LEFT JOIN 保留无分配
    /// 行（pending/本地构建）的 build；Submitted 取 builds.created_at、NULL
    /// 回退 tasks.submitted_at（created_at 列晚于 tasks 加入，老行可空）。
    pub(super) const SELECT_BUILD_LIFECYCLE: &str = "\
        SELECT COALESCE(b.created_at, t.submitted_at) AS submitted_at, \
               wt.assigned_at, wt.started_at, b.completed_at, \
               wt.worker_id, w.name AS worker_name \
        FROM builds b \
        LEFT JOIN tasks t ON t.id = b.task_id \
        LEFT JOIN worker_tasks wt ON wt.id = ( \
            SELECT id FROM worker_tasks \
            WHERE build_id = b.id AND kind = 'build' \
            ORDER BY id DESC LIMIT 1 \
        ) \
        LEFT JOIN workers w ON w.id = wt.worker_id \
        WHERE b.id = $1";

    pub(super) const SELECT_BUILD_TASK_ID: &str = "SELECT task_id FROM builds WHERE id = $1";

    /// 插入 worker 任务关联（方言感知时间）。dispatch.rs 指定 CAS 领取共用
    /// 本单源（pub(crate)），新增列/改状态语义两处同步。
    pub(crate) fn insert_worker_task_build(dialect: Dialect) -> String {
        format!(
            "INSERT INTO worker_tasks (build_id, worker_id, task_id, status, assigned_at) \
             VALUES ($1, $2, $3, 'assigned', {}) \
             RETURNING id",
            dialect.sql_now()
        )
    }

    pub(super) const SET_BUILD_ASSIGNED: &str =
        "UPDATE builds SET phase = 'assigned' WHERE id = $1 AND phase = 'pending'";

    pub(super) const SELECT_INIT_ASSIGNMENT: &str = "\
        SELECT id, init_product \
        FROM worker_tasks \
        WHERE worker_id = $1 AND status = 'assigned' AND kind = 'init' \
        ORDER BY id \
        LIMIT 1";

    /// 标记任务为 running（方言感知时间）。终态守卫：仅 `assigned` 可转
    /// running——SELECT 与 UPDATE 之间 cancel 可能已置 cancelled，无条件
    /// 覆盖会撤销取消。
    pub(super) fn mark_assignment_running(dialect: Dialect) -> String {
        format!(
            "UPDATE worker_tasks SET status = 'running', started_at = {} \
             WHERE id = $1 AND status = 'assigned'",
            dialect.sql_now()
        )
    }

    pub(super) const SELECT_BUILD_ASSIGNMENT: &str = "\
        SELECT wt.id, wt.task_id, wt.build_id, b.product, b.srpm_path, b.request_json, b.repo_consume \
        FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 AND wt.status = 'assigned' \
          AND wt.kind = 'build' \
        ORDER BY wt.id \
        LIMIT 1";

    /// worker 拉取时的 builds 状态推进：仅 `assigned` 可转 building（与
    /// `mark_assignment_running` 同一守卫，cancel 竞态不撤销取消）。
    /// started_at 不在此重置：assign 时已归零，再重置会丢掉"派发到开跑"
    /// 的真实执行段（duration 自 started_at 起算）。
    pub(super) const SET_BUILD_BUILDING: &str =
        "UPDATE builds SET phase = 'building' WHERE id = $1 AND phase = 'assigned'";

    pub(super) const DELETE_WORKER_TASK: &str = "DELETE FROM worker_tasks WHERE id = $1";

    /// 回收后重置为 pending（方言感知时间）。终态守卫：仅活跃态可重置——
    /// cancel 竞态下不得把已取消的构建重新排队。started_at 一并重置：死
    /// worker 上耗掉的等待时间不得转化为插队优先级或拉高 stale 年龄判定，
    /// 语义是"全新等待计时"。
    pub(super) fn reset_build_to_pending(dialect: Dialect) -> String {
        format!(
            "UPDATE builds \
             SET phase = 'pending', \
                 started_at = {}, \
                 completed_at = NULL, \
                 duration = NULL, \
                 crbs_pid = NULL, \
                 attempt = attempt + 1 \
             WHERE id = $1 AND phase IN ('assigned', 'building') \
               AND attempt < {}",
            dialect.sql_now(),
            crate::state::MAX_BUILD_ATTEMPTS
        )
    }

    /// 重入预算耗尽收口：attempt 达上限仍活跃的 build 落 failed，
    /// completed_at/duration 同步落值，error_summary 供 UI/账本归因。
    pub(super) fn fail_build_if_retry_exhausted(dialect: Dialect) -> String {
        format!(
            "UPDATE builds \
             SET phase = 'failed', completed_at = {}, duration = {}, \
                 error_summary = 'retry budget exhausted: repeated reclaim without progress' \
             WHERE id = $1 AND phase IN ('assigned', 'building') AND attempt >= $2",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at")
        )
    }

    /// 插入 init 任务分配（方言感知时间）。`assigned_at` 显式写 sql_now()
    /// 而非列默认，保证与读取侧同 UTC 帧，不随列默认演进漂移。
    pub(super) fn insert_init_assignment(dialect: Dialect) -> String {
        format!(
            "INSERT INTO worker_tasks (build_id, worker_id, task_id, status, kind, init_product, assigned_at) \
             VALUES (NULL, $1, NULL, 'assigned', 'init', $2, {}) \
             RETURNING id",
            dialect.sql_now()
        )
    }

    pub(super) const COUNT_WORKER_BUILDING_FOR_PRODUCT: &str = "\
        SELECT COUNT(*) FROM worker_tasks wt \
        JOIN builds b ON wt.build_id = b.id \
        WHERE wt.worker_id = $1 \
          AND wt.kind = 'build' \
          AND b.phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout') \
          AND b.product = $2";

    pub(super) const HAS_ACTIVE_INIT: &str = "\
        SELECT 1 FROM worker_tasks \
        WHERE worker_id = $1 AND kind = 'init' AND init_product = $2 \
          AND status IN ('assigned', 'running') \
        LIMIT 1";

    /// 完成 init 任务（方言感知时间）。终态守卫：仅 `assigned`/`running`
    /// 可落终态，迟到 completion 不得覆写重复上报 / 已回收的 assignment。
    pub(super) fn complete_init_assignment(dialect: Dialect) -> String {
        format!(
            "UPDATE worker_tasks \
             SET status = $1, completed_at = {}, result_json = $2 \
             WHERE id = $3 AND status IN ('assigned', 'running')",
            dialect.sql_now()
        )
    }

    /// 列出超时变为离线的 worker（方言感知，参数化秒数）。
    ///
    /// PG 分支用与写入同帧的 UTC TEXT 词法比较（同 SQLite，词法序即时间序）
    /// ——`to_timestamp`/`NOW()` 按会话时区解释，TZ=+8 活 worker 全被判
    /// 超时（反复回收重派双执行）、TZ=-5 死 worker 永不回收。
    pub(super) fn list_offline_workers(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => "SELECT id, name FROM workers \
                 WHERE status = 'online' AND last_heartbeat < datetime('now', '-' || $1 || ' seconds')"
                .to_string(),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => "SELECT id, name FROM workers \
                 WHERE status = 'online' \
                   AND last_heartbeat < to_char((NOW() AT TIME ZONE 'UTC') - $1::BIGINT * INTERVAL '1 second', 'YYYY-MM-DD HH24:MI:SS')"
                .to_string(),
        }
    }

    /// 列出优雅停机后过龄的 offline worker（参数化秒数）：优雅停机心跳置
    /// offline 且刷新 last_heartbeat，[`Self::list_offline_workers`] 只匹配
    /// online，其 running 行由此回收（PG 同帧 TEXT 形态同上）。
    pub(super) fn list_gone_workers(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => "SELECT id, name FROM workers \
                 WHERE status = 'offline' AND last_heartbeat < datetime('now', '-' || $1 || ' seconds')"
                .to_string(),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => "SELECT id, name FROM workers \
                 WHERE status = 'offline' \
                   AND last_heartbeat < to_char((NOW() AT TIME ZONE 'UTC') - $1::BIGINT * INTERVAL '1 second', 'YYYY-MM-DD HH24:MI:SS')"
                .to_string(),
        }
    }

    /// 回收事务内的心跳新鲜度复查。reclaimer 基于事务外快照决定回收，快照
    /// 与事务之间 worker 可能恰好恢复心跳——不复查会把刚恢复的 worker 强制
    /// offline 并重派其任务（双执行）。0 行 = 行不存在或心跳已恢复，跳过本轮；
    /// 不带 status 谓词（online/gone 共用），形态同 [`Self::list_offline_workers`]。
    pub(super) fn worker_heartbeat_stale(dialect: Dialect) -> String {
        match dialect {
            Dialect::Sqlite => "SELECT 1 FROM workers \
                 WHERE id = $1 AND last_heartbeat < datetime('now', '-' || $2 || ' seconds')"
                .to_string(),
            #[cfg(feature = "postgres")]
            Dialect::Postgres => "SELECT 1 FROM workers \
                 WHERE id = $1 \
                   AND last_heartbeat < to_char((NOW() AT TIME ZONE 'UTC') - $2::BIGINT * INTERVAL '1 second', 'YYYY-MM-DD HH24:MI:SS') \
                 FOR UPDATE"
                .to_string(),
        }
    }

    pub(super) const LIST_WORKERS: &str = "\
        SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash \
        FROM workers \
        ORDER BY id";

    /// 过滤列表查询前缀：`WHERE 1=1` 后由调用方追加过滤、ORDER BY、分页。
    /// 遥测四列与 disk_free_kb 自此拉出，
    /// 未拉列的查询靠 sqlx(default) 降级为 None。
    pub(super) const LIST_WORKERS_FILTERED_PREFIX: &str = "\
        SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash, \
               load1, ncpu, cpu_util_pct, mem_used_pct, disk_free_kb \
        FROM workers \
        WHERE 1=1";

    /// 过滤计数查询前缀（同上，仅追加过滤条件）。
    pub(super) const COUNT_WORKERS_FILTERED_PREFIX: &str = "SELECT COUNT(*) FROM workers WHERE 1=1";

    pub(super) const FIND_WORKER_BY_SECRET: &str = "\
        SELECT id, name, arch, capacity, status, last_heartbeat, version, secret_hash \
        FROM workers \
        WHERE secret_hash = $1";

    pub(super) const SET_WORKER_SECRET: &str = "UPDATE workers SET secret_hash = $1 WHERE id = $2";

    pub(super) const CLEAR_WORKER_SECRET: &str =
        "UPDATE workers SET secret_hash = NULL WHERE id = $1";

    pub(super) const DELETE_WORKER_TASKS_BY_WORKER: &str =
        "DELETE FROM worker_tasks WHERE worker_id = $1";

    /// 该 worker 名下挂了 build 的分配行（删除 worker 前重置非终态 build
    /// 用；init 行 build_id 为 NULL，调用方 flatten 跳过）。
    pub(super) const LIST_WORKER_TASK_BUILD_IDS: &str =
        "SELECT build_id FROM worker_tasks WHERE worker_id = $1 AND build_id IS NOT NULL";

    /// 自带谓词的删除 CAS：PG BEGIN 不锁行，守卫 SELECT 与 DELETE 之间心跳
    /// 可能把 offline 翻回 online，rows==0 即竞态翻转（SQLite BEGIN
    /// IMMEDIATE 写事务串行，此为冗余防线）。
    pub(super) const DELETE_WORKER_IF_OFFLINE: &str =
        "DELETE FROM workers WHERE id = $1 AND status <> 'online'";

    /// 仅查 worker status（`delete_worker_if_offline` 事务内用）。
    pub(super) const SELECT_WORKER_STATUS: &str = "SELECT status FROM workers WHERE id = $1";

    pub(super) const LIST_STUCK_WORKER_TASKS: &str = "\
        SELECT id, build_id FROM worker_tasks \
        WHERE worker_id = $1 AND status IN ('assigned', 'running')";

    /// 兜底 sweep：把指向已终态 build 的僵尸 worker_task 迁出 running（方言
    /// 感知时间）。与 offline 回收严格区分：build 已正确终态，绝不重置
    /// build，只释放槽位。status 按关联 build 的 phase 映射，与上报路径同
    /// 口径（统一盖 'completed' 会丢失败/取消区分）；RETURNING 供伴随清理。
    pub(super) fn release_terminal_worker_tasks(dialect: Dialect) -> String {
        format!(
            "UPDATE worker_tasks SET \
                status = CASE (SELECT phase FROM builds WHERE id = worker_tasks.build_id) \
                              WHEN 'succeeded' THEN 'completed' \
                              WHEN 'cancelled' THEN 'cancelled' \
                              ELSE 'failed' END, \
                completed_at = {} \
             WHERE status IN ('assigned', 'running') \
               AND build_id IN ( \
                   SELECT id FROM builds \
                   WHERE phase IN ('succeeded', 'failed', 'cancelled', 'timeout') \
               ) \
             RETURNING build_id",
            dialect.sql_now()
        )
    }

    /// 回收路径置 offline：谓词同 `mark_worker_offline`，suspended/draining
    /// 等管理员保留态不被回收信号覆盖。
    pub(super) const SET_WORKER_OFFLINE: &str =
        "UPDATE workers SET status = 'offline' WHERE id = $1 AND status IN ('online', 'offline')";
}

/// 已分配任务的信息（build 或 init）。

#[derive(Debug, Clone)]
pub enum AssignedTaskInfo {
    /// 普通构建任务。
    Build {
        assignment_id: i64,
        task_id: Option<i64>,
        build_id: i64,
        product: String,
        srpm_path: Option<String>,
        request_json: Option<String>,
        /// 消费轴生效值快照（builds.repo_consume，提交时合流）：false = 派发
        /// 不注入产品 repo。
        repo_consume: bool,
    },
    /// 远程重建 base_os 任务（无 build 行）。
    Init { assignment_id: i64, product: String },
}

/// 事务性 init 派发的冲突类型。
#[derive(Debug, Clone)]
pub enum InitConflict {
    /// 该 (worker, product) 上仍有活跃 build。
    Building(i64),
    /// 该 (worker, product) 上已有活跃 init。
    AlreadyActive,
}

/// Worker 状态。
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkerStatus {
    pub id: i64,
    pub name: String,
    pub arch: String,
    pub capacity: i64,
    pub status: String,
    pub last_heartbeat: Option<String>,
    pub version: String,
    /// 是否已设置 secret（不暴露 hash 本身）。
    #[serde(default)]
    pub has_secret: bool,
    /// 负载遥测（`None` = 无采样，UI 显示 "—"）。未拉列的查询靠
    /// sqlx(default) 为 None；API 序列化纯新增字段。
    #[serde(default)]
    pub load1: Option<f64>,
    #[serde(default)]
    pub ncpu: Option<i64>,
    /// CPU 利用率百分比 0-100（/proc/stat 差分口径）；`None` = 无采样。
    #[serde(default)]
    pub cpu_util_pct: Option<f64>,
    #[serde(default)]
    pub mem_used_pct: Option<f64>,
    /// 节点内存总量 KB（内存准入门的换算基准；`None` = 未上报 / 无采样）。
    #[serde(default)]
    pub mem_total_kb: Option<i64>,
    /// 节点可用磁盘 KB（构建工件卷 statvfs；`None` = 未上报 / 探测失败）。
    #[serde(default)]
    pub disk_free_kb: Option<i64>,
    /// 采集能力位图（bit 见 [`RESOURCE_CAP_CGROUP_V2`] 等常量；`None` = 未上报）。
    #[serde(default)]
    pub resource_caps: Option<i64>,
    /// 注册时刻（workers.created_at）；未拉列的查询靠 sqlx(default) 为 None。
    #[serde(default)]
    pub created_at: Option<String>,
    /// 密钥过期时刻（`None` = 永不过期 / 未拉列）。
    #[serde(default)]
    pub secret_expires_at: Option<String>,
}

/// 心跳携带的负载遥测。`None` = 无采样（非 Linux / 读取失败 /
/// 心跳缺字段），落库 NULL，UI 显示 "—"。
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerTelemetry {
    /// 1 分钟平均负载（/proc/loadavg 第一列，原始值；归一化百分比 UI 侧算）。
    pub load1: Option<f64>,
    /// CPU 逻辑核数（std::thread::available_parallelism）。
    pub ncpu: Option<i64>,
    /// CPU 利用率百分比 0-100（/proc/stat 相邻两心跳差分，busy = Δtotal −
    /// Δidle − Δiowait；首轮无上一帧快照 → None）。
    pub cpu_util_pct: Option<f64>,
    /// 内存已用百分比（/proc/meminfo，(1 - MemAvailable/MemTotal) * 100）。
    pub mem_used_pct: Option<f64>,
    /// 节点内存总量 KB（/proc/meminfo MemTotal，内存准入门基准；`None` =
    /// 未上报 / 非 Linux）。
    pub mem_total_kb: Option<i64>,
    /// 节点可用磁盘 KB（worker 构建工件卷 statvfs 可用空间；`None` = 未
    /// 上报 / 探测失败，降级缺值）。心跳同时落 workers.disk_free_kb
    /// 与 worker_telemetry_samples.disk_free_kb（折线数据源）。
    pub disk_free_kb: Option<i64>,
}

/// 遥测历史单点（详情页趋势图数据源；`worker_telemetry_samples` 一行）。
/// `sampled_at` 为 DB_TIME_FMT TEXT UTC 帧，与 workers.last_heartbeat 同源。
#[derive(Debug, Clone)]
pub struct TelemetrySamplePoint {
    pub sampled_at: String,
    pub telemetry: WorkerTelemetry,
}

/// `list_telemetry_samples` 的 limit 防御上限：30s 心跳 × 7d 窗 ≈ 2 万点，
/// 5 万余量足够全采样直出；超出只可能来自异常高频写入，按最新保留截断
/// （SQL DESC 取限后 Rust 侧倒序回升序），趋势图"现在"端不缺。
pub const TELEMETRY_SAMPLE_QUERY_LIMIT: i64 = 50_000;

/// 按架构聚合的 worker 计数（UI 仪表盘 Workers 面板）。`online` 口径同
/// [`StateStore::count_online_workers`]；`total` 为该架构全部注册行。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkerArchCounts {
    pub arch: String,
    pub online: i64,
    pub total: i64,
}

/// 按架构聚合的在线 worker CPU 利用率均值（首页架构条均值 chip）。行口径
/// 见 [`StateStore::worker_arch_cpu_avg`]，无有效遥测的架构不出现。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkerArchCpuAvg {
    pub arch: String,
    /// cpu_util_pct 的架构内均值（0-100 区间内）。
    pub cpu_avg: f64,
}

/// Worker 当前活跃（非终态分配）的 build 行（UI 详情页 Active builds 区块）。
/// `started_at` 未开工时回退显示派发时间（COALESCE assigned_at）。
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct WorkerActiveBuild {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub phase: String,
    pub started_at: Option<String>,
}

/// Worker 最近分派的 build 行（UI 详情页 Recent builds 卡，含终态行）。
/// `started_at` 未开工时回退派发时间；`completed_at` 为 NULL = 仍在跑。
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct WorkerRecentBuild {
    pub id: i64,
    pub product: String,
    pub pkg_name: String,
    pub phase: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Worker 每产品最近一次 init 分配（UI 详情页 Base OS inits 卡；查询侧取
/// 最近 20 条、Rust 侧按产品去重后的行）。`completed_at` 为 NULL = 仍在跑。
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct WorkerRecentInit {
    pub product: String,
    pub status: String,
    pub assigned_at: Option<String>,
    pub completed_at: Option<String>,
}

/// build 生命周期时刻（UI 详情页 Lifecycle 小节；单行查询，无分配行时
/// assigned/started/worker 全 None）。`submitted_at` = builds.created_at
/// （NULL 回退 tasks.submitted_at），`completed_at` = builds.completed_at。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BuildLifecycle {
    pub submitted_at: Option<String>,
    pub assigned_at: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub worker_id: Option<i64>,
    pub worker_name: Option<String>,
}

/// [`StateStore::delete_worker_if_offline`] 的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteWorkerOutcome {
    /// worker 不存在（含已被并发删除）。
    NotFound,
    /// 仍在线，拒绝删除。
    Online,
    /// 已删除（offline / draining / suspended 等非 online 状态）。
    Deleted,
}

/// Worker 列表查询过滤条件。
#[derive(Debug, Default)]
pub struct WorkerFilter<'a> {
    /// 名称子串（LIKE 模糊匹配，搜索语义）。
    pub name: Option<&'a str>,
    /// 架构子串（LIKE 模糊匹配，搜索语义）。
    pub arch: Option<&'a str>,
    /// 状态（精确匹配：online/offline）。
    pub status: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

impl WorkerFilter<'_> {
    /// 返回合理的 limit（默认 100，最大 1000）。
    pub fn normalized_limit(&self) -> i64 {
        super::db::clamp_list_limit(self.limit)
    }
}

#[derive(sqlx::FromRow)]
struct WorkerStatusRow {
    id: i64,
    name: String,
    arch: String,
    capacity: i64,
    status: String,
    last_heartbeat: Option<String>,
    version: String,
    #[sqlx(default)]
    secret_hash: Option<String>,
    // 遥测各列并非所有共享本 row 的查询都拉出：未拉列靠 sqlx(default)
    // 降级为 None（同 secret_hash 模式）。
    #[sqlx(default)]
    load1: Option<f64>,
    #[sqlx(default)]
    ncpu: Option<i64>,
    #[sqlx(default)]
    cpu_util_pct: Option<f64>,
    #[sqlx(default)]
    mem_used_pct: Option<f64>,
    #[sqlx(default)]
    mem_total_kb: Option<i64>,
    #[sqlx(default)]
    disk_free_kb: Option<i64>,
    #[sqlx(default)]
    resource_caps: Option<i64>,
    #[sqlx(default)]
    created_at: Option<String>,
    #[sqlx(default)]
    secret_expires_at: Option<String>,
}

impl From<WorkerStatusRow> for WorkerStatus {
    fn from(r: WorkerStatusRow) -> Self {
        WorkerStatus {
            id: r.id,
            name: r.name,
            arch: r.arch,
            capacity: r.capacity,
            status: r.status,
            last_heartbeat: r.last_heartbeat,
            version: r.version,
            has_secret: r.secret_hash.is_some(),
            load1: r.load1,
            ncpu: r.ncpu,
            cpu_util_pct: r.cpu_util_pct,
            mem_used_pct: r.mem_used_pct,
            mem_total_kb: r.mem_total_kb,
            disk_free_kb: r.disk_free_kb,
            resource_caps: r.resource_caps,
            created_at: r.created_at,
            secret_expires_at: r.secret_expires_at,
        }
    }
}
