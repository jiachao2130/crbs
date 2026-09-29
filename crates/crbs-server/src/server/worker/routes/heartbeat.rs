// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker 心跳与遥测清洗。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::require_own_worker;

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default = "default_online")]
    pub(super) status: String,
    /// 1 分钟平均负载（/proc/loadavg 第一列原始值，归一化 UI 侧算）；
    /// 缺字段 / null / 无采样 → None（落库 NULL，UI 显示 "—"）。
    #[serde(default)]
    pub(super) load1: Option<f64>,
    /// CPU 逻辑核数（std::thread::available_parallelism）。
    #[serde(default)]
    pub(super) ncpu: Option<i64>,
    /// CPU 利用率百分比 0-100（worker 侧 /proc/stat 相邻两心跳差分）；
    /// 缺字段 / null / 首跳无上一帧 → None（落库 NULL）。
    #[serde(default)]
    pub(super) cpu_util_pct: Option<f64>,
    /// 内存已用百分比（/proc/meminfo MemAvailable/MemTotal）。
    #[serde(default)]
    pub(super) mem_used_pct: Option<f64>,
    /// 节点内存总量 KB（/proc/meminfo MemTotal，内存准入门换算基准）；
    /// 缺字段 / null / 无采样 → None（落库 NULL）。
    #[serde(default)]
    pub(super) mem_total_kb: Option<i64>,
    /// 节点可用磁盘 KB（worker 构建工件卷 statvfs；缺字段 / null /
    /// 探测失败 → None，落库 NULL）。
    #[serde(default)]
    pub(super) disk_free_kb: Option<i64>,
    /// 采集能力位图（worker 启动探测；缺字段 / null → None）。
    #[serde(default)]
    pub(super) resource_caps: Option<i64>,
}

fn default_online() -> String {
    "online".to_string()
}

/// 心跳遥测的合理界：worker 侧不可信输入，越界 / NaN 按 None 落库（与无
/// 遥测同款诚实降级，不把 -1/1e308 写进 DB 拖歪均值）。load1 ∈ [0, 1e6]、
/// ncpu 与 capacity 同界 1..=1024、cpu_util_pct / mem_used_pct [0, 100]、
/// mem_total_kb ≤ 1e9 KB = 1 TB（界宽于物理值）、disk_free_kb ≤ 1e12 KB
/// = 1 PB（多 TB 工件卷放宽一个量级以上）。
pub(super) fn sanitize_telemetry(req: &HeartbeatRequest) -> crbs_core::WorkerTelemetry {
    crbs_core::WorkerTelemetry {
        load1: req.load1.filter(|v| (0.0..=1e6).contains(v)),
        ncpu: req.ncpu.filter(|v| (1..=1024).contains(v)),
        cpu_util_pct: req.cpu_util_pct.filter(|v| (0.0..=100.0).contains(v)),
        mem_used_pct: req.mem_used_pct.filter(|v| (0.0..=100.0).contains(v)),
        mem_total_kb: req.mem_total_kb.filter(|v| (1..=1_000_000_000).contains(v)),
        disk_free_kb: req
            .disk_free_kb
            .filter(|v| (0..=1_000_000_000_000).contains(v)),
    }
}

/// 采集能力位图合理界：bit0..bit4 已定义、后续只加位，钳 [0, u32::MAX]
///（位图语义上限；负数 / 巨值按 None 落库，全部能力按不可用降级）。
pub(super) fn sanitize_resource_caps(caps: Option<i64>) -> Option<i64> {
    caps.filter(|v| (0..=u32::MAX as i64).contains(v))
}

#[derive(Serialize)]
pub struct HeartbeatResponse {
    pub(super) accepted: bool,
    /// 本 worker 名下已取消 build 的 assignment id（心跳搭车取消下行）；
    /// 空时字段整体缺席，响应体逐字节保持 `{"accepted":true}`。
    /// 扩展约定：只由顶层可选字段组成、禁 `deny_unknown_fields`。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) cancelled_assignments: Vec<i64>,
}

pub(super) async fn worker_heartbeat(
    State(app): State<Arc<AppState>>,
    Path(id): Path<i64>,
    auth: Option<axum::extract::Extension<AuthContext>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let _ctx = require_own_worker(&auth, id)?;

    // 单 UPDATE 语义：行不存在（0 行）→ 404；offline 心跳 → status offline +
    // 遥测 NULL + 恒广播；online 心跳 → 当前 offline 翻 online（`WHERE
    // status='offline'` 不覆盖 draining/suspended）+ 遥测覆写（无采样 /
    // 缺字段全 None 落 NULL，越界经 sanitize 降 None）。offline→online
    // 翻转不广播（识别翻转需双方言不可得的 RETURNING/CTE）——dashboard 30s
    // 兜底轮询（取舍见 `worker_heartbeat_upsert` 注释）。
    let offline = req.status == "offline";
    let telemetry = sanitize_telemetry(&req);
    let affected = app
        .state_store
        .worker_heartbeat_upsert(
            id,
            offline,
            telemetry,
            sanitize_resource_caps(req.resource_caps),
        )
        .await
        .map_err(ApiError::from)?;
    if affected == 0 {
        return Err(ApiError::not_found("worker", id));
    }

    // 取消下行信号源 builds.phase='cancelled'（first-winner 终态），故意不看
    // worker_tasks.status（best-effort 写失败 + 兜底 sweep 下不可靠）；同一 id
    // 每心跳重复返回直至 retention 清理（build_id 随 ON DELETE SET NULL 断开
    // JOIN），worker 侧对无 token id 幂等。查询失败 500——心跳循环
    // warn+continue，下一 tick 补上。
    let cancelled_assignments = app
        .state_store
        .list_cancelled_assignment_ids_for_worker(id)
        .await
        .map_err(ApiError::from)?;
    if !cancelled_assignments.is_empty() {
        // 仅 debug：同一 id 每心跳重复返回，info 会刷屏数天；取消事件在
        // cancel_distributed_build 已有日志。
        tracing::debug!(
            worker_id = %id,
            assignment_ids = ?cancelled_assignments,
            "Heartbeat carries cancellation notices"
        );
    }

    Ok(Json(HeartbeatResponse {
        accepted: true,
        cancelled_assignments,
    }))
}

// ======== 拉取任务（Long-poll）========
