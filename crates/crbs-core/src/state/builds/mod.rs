// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建状态存储（按生命周期 / 查询 / 列更新 / 完成收口分文件）。

use super::{BuildInsert, BUILD_COLUMNS};

mod columns;
mod completion;
mod lifecycle;
mod queries;
#[cfg(test)]
mod tests;

pub(crate) use completion::{complete_build_update, CompleteBuildParams};

mod sql {
    use super::BUILD_COLUMNS;
    use crate::state::Dialect;

    /// 插入构建记录（方言感知：datetime('now') / NOW()）。repo_publish /
    /// repo_consume 是双轴生效值快照，提交侧（BuildInsert）写入；
    /// req_min_* 是放置契约声明快照（同自 BuildInsert，声明落列无害）。
    pub(super) fn insert_build(dialect: Dialect) -> String {
        format!(
            "INSERT INTO builds (product, pkg_name, name, version, release, phase, result_dir, layer_digest, base_os_digest, backend, \"user\", user_id, crbs_pid, priority, arch, host_arches, task_id, product_id, repo_publish, repo_consume, req_min_mem_kb, req_min_ncpu, req_min_disk_kb, started_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, {}, {}) \
             RETURNING id",
            dialect.sql_now(),
            dialect.sql_now()
        )
    }

    /// `insert_build` 的守卫形态（task_id 有值时用）：`INSERT ... SELECT ...
    /// WHERE EXISTS` 把 phase 复查压进 INSERT 本身，收口复查-INSERT 语句间隙
    ///（PG READ COMMITTED；SQLite 写事务本就串行）。谓词与 Rust 复查同口径：
    /// 终态 task 只拒活跃 phase 构建，`$6` 终态 = 历史记账放行，拒绝 0 行映射
    /// ValidationFailed；`$6`/`$17` 名值绑定一次出现两次（见 test_state 契约）。
    pub(super) fn insert_build_guarded(dialect: Dialect) -> String {
        format!(
            "INSERT INTO builds (product, pkg_name, name, version, release, phase, result_dir, layer_digest, base_os_digest, backend, \"user\", user_id, crbs_pid, priority, arch, host_arches, task_id, product_id, repo_publish, repo_consume, req_min_mem_kb, req_min_ncpu, req_min_disk_kb, started_at, created_at) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, {}, {} \
             WHERE EXISTS ( \
                 SELECT 1 FROM tasks \
                 WHERE id = $17 \
                   AND ($6 IN ('succeeded', 'failed', 'cancelled', 'timeout') \
                        OR phase NOT IN ('succeeded', 'failed', 'cancelled', 'timeout')) \
             ) \
             RETURNING id",
            dialect.sql_now(),
            dialect.sql_now()
        )
    }

    /// task 关联守卫用：查宿主任务 phase（`insert_build` 事务内复查）。
    pub(super) const SELECT_TASK_PHASE: &str = "SELECT phase FROM tasks WHERE id = $1";

    /// 中间态更新（含幂等重复 building 汇报）；终态守卫仅活跃态可更新——
    /// 迟到汇报不得把已取消构建拉回活跃态。
    pub(super) const UPDATE_BUILD_PHASE: &str = "UPDATE builds SET phase = $1 WHERE id = $2 AND phase IN ('pending', 'assigned', 'building')";

    /// `UPDATE_BUILD_PHASE` 的归属 CAS 变体（worker 上报路径用）：`EXISTS
    /// worker_tasks`（不限 status——终态后行保留，幂等重报不受影响；kind='build'）。
    /// 无谓词时 reclaim 删行重派后，迟到中间态上报会把重派间隙的行翻
    /// building、楔死容量回收；谓词让迟到上报提交点 0 行静默。
    pub(super) const UPDATE_BUILD_PHASE_GUARDED: &str = "\
        UPDATE builds SET phase = $1 \
         WHERE id = $2 AND phase IN ('pending', 'assigned', 'building') \
           AND EXISTS ( \
               SELECT 1 FROM worker_tasks wt \
               WHERE wt.build_id = builds.id AND wt.worker_id = $3 AND wt.kind = 'build' \
           )";
    pub(super) const UPDATE_BUILD_LAYER_DIGEST: &str =
        "UPDATE builds SET layer_digest = $1 WHERE id = $2";

    pub(super) const UPDATE_BUILD_INFO: &str =
        "UPDATE builds SET result_dir = $1, base_os_digest = $2, backend = $3 WHERE id = $4";

    /// `UPDATE_BUILD_INFO` 的 upload 落库事务内变体：PG BEGIN 不锁行，写入自带
    /// phase CAS + 活跃 assignment 归属 CAS（kind='build'；$6 非 NULL 时精确到
    /// 该次分配，同 worker 重派后旧 attempt 的迟到写入不再命中新分配）。
    /// rows==0 = 相位被并发翻转，或 assignment 被 reclaim 剥夺/重派 → rollback + 409。
    pub(super) const UPDATE_BUILD_INFO_GUARDED: &str = "\
        UPDATE builds SET result_dir = $1, base_os_digest = $2, backend = $3 \
         WHERE id = $4 AND phase IN ('pending', 'assigned', 'building') \
           AND EXISTS ( \
               SELECT 1 FROM worker_tasks wt \
               WHERE wt.build_id = builds.id AND wt.worker_id = $5 AND wt.kind = 'build' \
                 AND wt.status IN ('assigned', 'running') \
                 AND ($6 IS NULL OR wt.id = $6) \
           )";

    pub(super) const SET_BUILD_REQUEST_INFO: &str =
        "UPDATE builds SET srpm_path = $1, request_json = $2 WHERE id = $3";

    /// 产品配置快照写入（构建创建 / hub 派发时点）；独立于 request_json，
    /// 避免派发路径覆盖请求信息。
    pub(super) const SET_BUILD_PRODUCT_CONFIG_TOML: &str =
        "UPDATE builds SET product_config_toml = $1 WHERE id = $2";

    /// 产品配置快照读取（`crbs debug` 复现锚）。
    pub(super) const SELECT_BUILD_PRODUCT_CONFIG_TOML: &str =
        "SELECT product_config_toml FROM builds WHERE id = $1";

    /// request_json 原文读取（reproduce 来源判定与 API 透出共用同一条 SQL）。
    pub(super) const SELECT_REQUEST_JSON: &str = "SELECT request_json FROM builds WHERE id = $1";

    pub(super) const UPDATE_BUILD_CRBS_PID: &str = "UPDATE builds SET crbs_pid = $1 WHERE id = $2";

    /// worker 镜像行播种：显式 id 插入（id = hub 下发 build id，本地自增序列
    /// 不受影响），余列取最小集合（schema NOT NULL 无默认者：product/pkg_name/
    /// phase/task_id）。
    pub(super) fn insert_build_with_id(dialect: Dialect) -> String {
        format!(
            "INSERT INTO builds (id, product, pkg_name, name, version, release, phase, \"user\", task_id, started_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, {})",
            dialect.sql_now()
        )
    }

    /// 重派重执行入口：终态镜像行重置 pending（本库已收尾而 hub 侧上报丢失
    /// 后的 re-delivery），started_at 归零对齐 pick 语义。
    pub(super) fn reset_mirror_build_row(dialect: Dialect) -> String {
        format!(
            "UPDATE builds SET phase = 'pending', error_summary = NULL, result_dir = NULL, \
             layer_digest = NULL, base_os_digest = NULL, completed_at = NULL, duration = NULL, \
             crbs_pid = NULL, started_at = {} WHERE id = $1",
            dialect.sql_now()
        )
    }

    pub(super) const LIST_PENDING_WITH_REQUEST_INFO: &str =
        "SELECT id, product, srpm_path, request_json, crbs_pid \
         FROM builds \
         WHERE phase = 'pending' AND srpm_path IS NOT NULL AND request_json IS NOT NULL";

    pub(super) fn select_build_by_id() -> String {
        format!("SELECT {BUILD_COLUMNS} FROM builds WHERE id = $1")
    }

    /// 不变量：挂载存在 ⇒ phase='building'（pick/claim 翻相先于挂载建立）。
    /// 不得扩到 pending/assigned：繁忙队列 pending 恒存在，计数恒非零会杀死
    /// 孤儿清理与 package cache GC 的空转前提。
    pub(super) const COUNT_BUILDING_BUILDS: &str =
        "SELECT COUNT(*) FROM builds WHERE phase = 'building'";

    /// 列表模板：`{WHERE}` / `{ORDER}` / `{PAGE}` 由调用方 replace。
    /// `COUNT(*) OVER () AS total` 单次扫描携带过滤后总数（SQLite ≥3.25 / PG 支持）。
    pub(super) fn list_builds_template() -> String {
        format!(
            "SELECT {BUILD_COLUMNS}, COUNT(*) OVER () AS total \
             FROM builds WHERE {{WHERE}} ORDER BY {{ORDER}}{{PAGE}}"
        )
    }

    pub(super) fn list_in_progress_by_pid() -> String {
        format!(
            "SELECT {BUILD_COLUMNS} FROM builds \
             WHERE crbs_pid = $1 AND phase IN ('pending', 'building') ORDER BY started_at DESC"
        )
    }

    pub(super) const UPDATE_BUILD_SIGNED: &str = "UPDATE builds SET signed = $1 WHERE id = $2";

    /// 发布轴翻转：更新 `builds.repo_publish`（publish/unpublish 命令；提交侧
    /// 逐构建收紧走 insert 快照，不经本语句）。
    pub(super) const UPDATE_BUILD_REPO_PUBLISH: &str =
        "UPDATE builds SET repo_publish = $1 WHERE id = $2";

    /// 确定性模式打标：翻转 `builds.deterministic`（幂等）。
    pub(super) const UPDATE_BUILD_DETERMINISTIC: &str =
        "UPDATE builds SET deterministic = $1 WHERE id = $2";

    /// 血缘锚：写 `builds.canonical_srpm_sha256`（幂等）。
    pub(super) const UPDATE_BUILD_CANONICAL_SRPM: &str =
        "UPDATE builds SET canonical_srpm_sha256 = $1 WHERE id = $2";

    /// SRPM 原样字节大小落列（heavy steering 门槛用；staging 完成后由
    /// 提交侧写，失败仅 warn 不回滚——缺失由消费侧"无值不分桶"兜底）。
    pub(super) const UPDATE_BUILD_SRPM_SIZE: &str =
        "UPDATE builds SET srpm_size_bytes = $1 WHERE id = $2";

    /// 批次归属回填：task 下 batch_id IS NULL 的构建行标到批次（不抢占既有归属）。
    pub(super) const ATTACH_TASK_BUILDS_TO_BATCH: &str =
        "UPDATE builds SET batch_id = $1 WHERE task_id = $2 AND batch_id IS NULL";

    /// 向 error_summary 追加非失败态提示（软告警通道）：`||` 拼接在既有文本后
    ///（NULL 视为空串），substr 截断 1000 字符防单行膨胀。
    pub(super) const APPEND_BUILD_NOTE: &str =
        "UPDATE builds SET error_summary = substr(COALESCE(error_summary, '') || $2, 1, 1000) WHERE id = $1";

    /// 重置 pending 构建时间戳（方言感知）。
    pub(super) fn reset_pending_build_timestamp(dialect: Dialect) -> String {
        format!(
            "UPDATE builds SET started_at = {} WHERE id = $1 AND phase = 'pending'",
            dialect.sql_now()
        )
    }

    /// 原子取任务：condition-UPDATE + RETURNING（方言感知时间排序）；
    /// `with_priority` 控制是否附加 `AND priority = $2`。arch 谓词用
    /// COALESCE(arch, '') = ''：三值逻辑下 `arch = ''` 不命中 NULL 行，归一
    /// 后 NULL arch = 任意架构，双方言一致。空闲派发闸：priority < 0（后台
    /// 档 = 自动重放）仅在无非后台 pending 构建时可被取走（重放不占坑）。
    pub(super) fn pick_and_lock_pending(dialect: Dialect, with_priority: bool) -> String {
        let priority_clause = if with_priority {
            " AND priority = $2"
        } else {
            ""
        };
        // noarch 宿主约束与分布式派发同款（host_arches 集合成员）；漏掉会让
        // 钉了宿主的 noarch 构建被 hub 本地领取（错架构执行、依赖解析必挂）。
        let claimable = |a: &str| {
            format!(
                "({a}.arch = $1 OR ({a}.arch = 'noarch' AND ({a}.host_arches IS NULL OR {contains})) \
                 OR COALESCE({a}.arch, '') = '')",
                a = a,
                contains = dialect.sql_csv_contains(&format!("{a}.host_arches"), 1)
            )
        };
        format!(
            // 外层 phase='pending' 守卫：PG READ COMMITTED 下子查询快照与外层
            // UPDATE 重评之间目标行可能被并发取走，守卫让其落空而非双重领取。
            "UPDATE builds \
             SET phase = 'building', started_at = {} \
             WHERE id = ( \
                 SELECT id FROM builds \
                 WHERE phase = 'pending' \
                   AND srpm_path IS NOT NULL \
                   AND request_json IS NOT NULL \
                   AND {claim}{priority_clause} \
                   AND (priority >= 0 OR NOT EXISTS ( \
                       SELECT 1 FROM builds fg \
                       WHERE fg.phase = 'pending' AND fg.priority >= 0 \
                         AND {claim_fg} \
                         AND fg.srpm_path IS NOT NULL \
                   )) \
                 ORDER BY {} \
                 LIMIT 1 \
             ) \
             AND phase = 'pending' \
             RETURNING id, product, srpm_path, request_json, crbs_pid",
            // started_at 随置 building 重置（列语义 = 本次执行尝试的起点）：
            // 僵尸判定 / duration / reset_unattached 年龄守卫依赖其随 pick 归零。
            dialect.sql_now(),
            dialect.sql_priority_wait_weight(),
            claim = claimable("builds"),
            claim_fg = claimable("fg")
        )
    }

    pub(super) const UPDATE_BUILD_PRIORITY_IF_PENDING: &str =
        "UPDATE builds SET priority = $1 WHERE id = $2 AND phase = 'pending'";

    pub(super) const COUNT_PENDING_BY_PRIORITY: &str =
        "SELECT priority, COUNT(*) as cnt FROM builds WHERE phase = 'pending' GROUP BY priority";

    /// 本地活跃构建（building 且无 worker_tasks 行）按 priority 分组。
    /// 子查询须带 `build_id IS NOT NULL`：init 型 assignment 行 build_id 为
    /// NULL，三值逻辑下 `id NOT IN (…, NULL)` 恒 UNKNOWN，任一活跃 init 行即
    /// 令本地计数恒空集、优先级预留静默失效。
    pub(super) const COUNT_LOCAL_BUILDING_BY_PRIORITY: &str =
        "SELECT priority, COUNT(*) as cnt FROM builds \
         WHERE phase = 'building' \
           AND id NOT IN ( \
               SELECT build_id FROM worker_tasks \
               WHERE status IN ('assigned', 'running') AND build_id IS NOT NULL \
           ) \
         GROUP BY priority";

    /// insert_build 事务内复查同 product+pkg_name+arch 的活跃构建（与 INSERT
    /// 同一写锁窗口）。arch 谓词 COALESCE 两侧归一 NULL：NULL 对 NULL 相等
    /// 正是引擎本地构建并发双提交的命中形态。
    pub(super) const EXISTS_ACTIVE_DUPLICATE_BUILD: &str = "SELECT 1 FROM builds \
         WHERE product = $1 AND pkg_name = $2 \
           AND COALESCE(arch, '') = COALESCE($3, '') \
           AND phase IN ('pending', 'assigned', 'building') \
         LIMIT 1";

    /// 完成构建（方言感知时间计算）。`$4` error_summary、`$5` 归属 worker_id
    ///（可 NULL）按绑定顺序在末尾；`$5` 名值绑定一次出现两次（契约见
    /// placeholders_driver_binding_contract）。终态守卫：仅活跃态可写终态，
    /// 先到者生效，rows==0 = 拒绝。归属 CAS（`$5 IS NULL` 短路）：EXISTS
    /// worker_tasks 不限 status、kind='build'，被 reclaim 剥夺 worker 的迟到
    /// 终态在提交点被拒（0 行 → 丢弃）。资源三列（$6/$7/$8）+ 采集包络五列
    ///（$9..$13：peak_total_kb / disk_wbytes / oom_killed / sample_backend /
    /// sample_ncpu）+ tmpfs 峰值（$14，缺数据绑 NULL）随终态一次写入；
    /// peak_rss_kb 口径见 engine::resource_sample；浮点两列 TEXT 绑定 + SQL
    /// CAST（绕 Any 驱动 NULL 浮点钉 FLOAT4），其余 INTEGER/TEXT 直绑。
    pub(super) fn complete_build(dialect: Dialect) -> String {
        format!(
            "UPDATE builds \
             SET phase = $1, \
                 result_dir = COALESCE($2, result_dir), \
                 error_summary = COALESCE($4, error_summary), \
                 completed_at = {}, \
                 duration = {}, \
                 peak_rss_kb = $6, \
                 cpu_secs = {}, \
                 cpu_p90_cores = {}, \
                 peak_total_kb = $9, \
                 disk_wbytes = $10, \
                 oom_killed = $11, \
                 sample_backend = $12, \
                 sample_ncpu = $13, \
                 peak_tmpfs_kb = $14 \
             WHERE id = $3 \
               AND phase IN ('pending', 'building', 'assigned') \
               AND ($5 IS NULL OR EXISTS ( \
                   SELECT 1 FROM worker_tasks wt \
                   WHERE wt.build_id = builds.id AND wt.worker_id = $5 AND wt.kind = 'build'))",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at"),
            dialect.float_param_cast(7),
            dialect.float_param_cast(8)
        )
    }

    /// 取消构建：仅活跃态可被取消（终态不可变）；返回行数，0 = 已终态拒绝。
    /// completed_at/duration 必须落值：result-GC 以 completed_at IS NOT NULL
    /// 为门，不写则 result_dir 永不回收；取消同为终态，duration 口径对齐。
    pub(super) fn mark_build_cancelled(dialect: Dialect) -> String {
        format!(
            "UPDATE builds SET phase = 'cancelled', completed_at = {}, duration = {} \
             WHERE id = $1 AND phase IN ('pending', 'building', 'assigned')",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at")
        )
    }

    /// 本机陈旧活跃行的列表（worker 启动期陈旧行回收用）。
    pub(super) const LIST_ACTIVE_LOCAL_BUILD_ROWS: &str =
        "SELECT id, crbs_pid FROM builds WHERE phase IN ('pending', 'building', 'assigned')";

    /// 陈旧本地行置 failed：终态守卫同 [`mark_build_cancelled`]，error_summary
    /// 由调用方携带，completed_at/duration 同步落值。
    pub(super) fn mark_stale_local_build_failed(dialect: Dialect) -> String {
        format!(
            "UPDATE builds SET phase = 'failed', error_summary = $2, completed_at = {}, duration = {} \
             WHERE id = $1 AND phase IN ('pending', 'building', 'assigned')",
            dialect.sql_now(),
            dialect.sql_seconds_since("started_at")
        )
    }
}

/// 活跃构建重复的 `Conflict`（服务端 409）。两触发臂共用文案：事务内复查
/// 命中，或 uq_active_builds_identity 在提交点兜底拒绝并发双插。
fn active_duplicate_conflict(build: &BuildInsert<'_>) -> crate::error::CrbsError {
    crate::error::CrbsError::Conflict {
        message: format!(
            "an active build for '{}' (arch {}) already exists in product '{}'; wait for it to finish or cancel it before resubmitting",
            build.pkg_name,
            build.arch.unwrap_or("unspecified"),
            build.product
        ),
    }
}

/// `update_build_info_tx_guarded` 的参数载体：写入三列 + 构建 id +
/// worker/assignment 双 CAS 归属（参数超过 clippy 阈值，按项目惯例成组）。
pub(crate) struct GuardedBuildInfo<'a> {
    pub(crate) id: i64,
    pub(crate) result_dir: Option<&'a str>,
    pub(crate) base_os_digest: Option<&'a str>,
    pub(crate) backend: &'a str,
    pub(crate) worker_id: i64,
    pub(crate) assignment_id: Option<i64>,
}
