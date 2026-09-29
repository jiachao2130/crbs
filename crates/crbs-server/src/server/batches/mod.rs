// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次：准备服务、规划服务与驱动器（running 批次按轮推进）。

mod driver;
mod plan;
mod prepare;

pub(crate) use driver::spawn_batch_driver;
// TickReport 走 pub 再导出：test_support 桥接集成测试需 pub 可见性（E0365）；本模块 pub(crate) 封住可达面。
pub use driver::TickReport;
pub(crate) use driver::{batch_driver_tick, cancel_batch};
pub(crate) use plan::plan_batch;
pub(crate) use prepare::{
    dry_run_split, run_prepare_phase, validate_and_insert_batch, PrepareBatchRequest,
};

/// preparing/planning 批次的心跳键（app_meta KV）。孤儿清扫按"created_at 超宽限
/// 且心跳过旧"双条件收口：prepare 下载在 8000 包量级需数小时，仅按 created_at 会误杀活批次。
pub(crate) fn batch_heartbeat_key(batch_id: i64) -> String {
    format!("{BATCH_HEARTBEAT_KEY_PREFIX}{batch_id}")
}

/// 心跳键前缀（孤儿清扫判活 + 终态键回收共用）。
pub(crate) const BATCH_HEARTBEAT_KEY_PREFIX: &str = "batch:hb:";

/// 心跳写入间隔与判活阈值：30s 写、10min 视为过旧（20 倍余量容忍 DB 抖动）。
pub(crate) const BATCH_HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub(crate) const BATCH_HEARTBEAT_STALE_SECS: i64 = 600;

/// 刷一次心跳（unix 秒）；失败仅 warn：best-effort 判活证据，写失败的代价是批次更早收口。
pub(crate) async fn touch_batch_heartbeat(
    store: &std::sync::Arc<crbs_core::StateStore>,
    batch_id: i64,
) {
    let ts = chrono::Utc::now().timestamp().to_string();
    if let Err(e) = store
        .set_app_meta(&batch_heartbeat_key(batch_id), &ts)
        .await
    {
        tracing::warn!(batch_id, error = ?e, "batch heartbeat write failed");
    }
}

/// 长阶段伴生心跳的协程句柄：Drop 时 abort；调用方 `let _hb = ...` 绑到阶段函数作用域尾，勿显式
/// `abort()`——主体 panic 时直线 abort 永不执行，残留协程把死批次伪造成"活"，孤儿清扫永不收口。
pub(crate) struct BatchHeartbeatGuard(tokio::task::JoinHandle<()>);

impl Drop for BatchHeartbeatGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn spawn_batch_heartbeat(
    store: std::sync::Arc<crbs_core::StateStore>,
    batch_id: i64,
) -> BatchHeartbeatGuard {
    BatchHeartbeatGuard(tokio::spawn(async move {
        let mut tick = tokio::time::interval(BATCH_HEARTBEAT_INTERVAL);
        loop {
            tick.tick().await;
            touch_batch_heartbeat(&store, batch_id).await;
        }
    }))
}
