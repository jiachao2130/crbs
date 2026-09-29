// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 资源门限与 assignment 归属探测。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::config::WorkerConfig;
use crate::executor::BuildResult;

use super::*;

/// 水位门决策（磁盘/内存两门共用判定）：查询结果 + 阈值 → 是否拦截本轮领
/// 任务。0 = 关闭恒放行；边界取等放行；查询失败恒放行（fail-open——止损门
/// 不得演化为卡死不领任务；含非 Linux 无 /proc/meminfo）。
pub(super) fn gate_blocks(available: &std::io::Result<u64>, min_free_bytes: u64) -> bool {
    min_free_bytes > 0 && matches!(available, Ok(a) if *a < min_free_bytes)
}

/// 读 /proc/meminfo 的 MemAvailable（KB → 字节）；失败 → Err（上游
/// fail-open 放行）。
pub(super) async fn mem_available_bytes() -> std::io::Result<u64> {
    let text = tokio::fs::read_to_string("/proc/meminfo").await?;
    parse_mem_available_kb(&text)
        .ok_or_else(|| std::io::Error::other("MemAvailable not found in /proc/meminfo"))
        .map(|kb| kb.saturating_mul(1024))
}

/// /proc/meminfo 文本 → MemAvailable 值（KB）；无该行（旧内核）→ None。
pub(super) fn parse_mem_available_kb(text: &str) -> Option<u64> {
    for line in text.lines() {
        // trim_start：容忍行首缩进（/proc/meminfo 顶格，测试 fixture 未必）。
        if let Some(rest) = line.trim_start().strip_prefix("MemAvailable:") {
            return rest.trim().trim_end_matches("kB").trim().parse().ok();
        }
    }
    None
}

/// 查询 `path` 所在盘的剩余空间（字节）；statvfs 是阻塞 syscall，包
/// spawn_blocking。路径可能尚未创建（首个任务才 ensure build_dir）：不存在
/// 时向上收敛到最近现存祖先探测——缺失尾部分量必然与祖先同卷。已知边界：
/// build_dir 位于未挂载的挂载点或悬空 symlink 下时 `exists()` 为 false，
/// 探测停在祖先、量到的是别的盘。
/// statvfs 在停滞存储（NFS 软挂载 / IO 挂死）上可无限阻塞：10s 有界等待，
/// 超时按查询失败返回（上游 gate fail-open 放行，不拦任务领取）。
pub(crate) async fn free_disk_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    const STATVFS_TIMEOUT: Duration = Duration::from_secs(10);
    // 并行测试共用同一进程内的全局单飞标志：任一测试的在飞探针会把其它测试的
    // 成功路径打成 TimedOut（生产上游把该瞬态 fail-open，测试却断言数值必须
    // 到达）。测试构建下用异步互斥串行化探针，生产路径不变。
    #[cfg(test)]
    static DISK_PROBE_TEST_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    #[cfg(test)]
    let _test_gate = DISK_PROBE_TEST_GATE.lock().await;
    // spawn_blocking 不可取消：停滞挂载上每次超时都会永久占一个 blocking
    // 线程（每 poll 一拍一个，最终耗死 512 池）。单飞：上一探针未返回时
    // 直接按超时失败（上游 disk gate fail-open），不叠加新线程。
    static DISK_PROBE_INFLIGHT: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if DISK_PROBE_INFLIGHT.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "previous disk free probe still hung",
        ));
    }
    let path = path.to_path_buf();
    let probe = tokio::task::spawn_blocking(move || {
        let mut probe = path.as_path();
        while !probe.exists() {
            match probe.parent() {
                Some(parent) => probe = parent,
                None => break,
            }
        }
        let result = fs4::available_space(probe);
        DISK_PROBE_INFLIGHT.store(false, std::sync::atomic::Ordering::SeqCst);
        result
    });
    match tokio::time::timeout(STATVFS_TIMEOUT, probe).await {
        Ok(r) => r.map_err(|e| std::io::Error::other(format!("spawn blocking disk check: {e}")))?,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "disk free check timed out",
        )),
    }
}

/// 探针周期下限（秒）：30s 一拍把 403/409 收敛延迟压到远低于 reclaimer 兜底。
const OWNERSHIP_PROBE_MIN_INTERVAL_SECS: u64 = 30;

/// 探针周期上限（秒）：慢心跳部署（110s 合法）下收敛延迟仍有界。
const OWNERSHIP_PROBE_MAX_INTERVAL_SECS: u64 = 60;

/// 探针单次尝试超时：探针在构建 select 内 await，黑洞 hub 不得拖住完成/
/// 取消的感知。
const OWNERSHIP_PROBE_PER_ATTEMPT: Duration = Duration::from_secs(10);

/// 探针周期（纯函数）：对齐 worker 心跳节拍，钳在 [30, 60]。
pub(super) fn ownership_probe_interval_secs(heartbeat_interval_secs: u64) -> u64 {
    heartbeat_interval_secs.clamp(
        OWNERSHIP_PROBE_MIN_INTERVAL_SECS,
        OWNERSHIP_PROBE_MAX_INTERVAL_SECS,
    )
}

/// 归属探针对本地在跑构建的处置（三分支）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProbeAction {
    /// 2xx：归属仍在（hub 对中间态写入带 assignment 归属 CAS）→ 继续构建。
    Continue,
    /// 409：hub 已终态（被取消/完成）→ 取消本地构建，走
    /// [`report_terminal_after_cancel`] 补报（409 幂等吸收）。
    FinishTerminal,
    /// 403：归属校验失败（行被回收/改派）→ 取消本地构建、保留产物、跳过上报。
    AbortLocal,
}

/// 三分支决策：`Some` 为明确 HTTP 应答，`None` 为网络错误/超时/取消。
/// 只认阳性证据（2xx/409/403），其余（含 401，由认证退出路径收敛）一律
/// Continue——阴性判据会在 hub 滚动重启窗口误杀全集群在跑构建。
pub(super) fn probe_decision(status: Option<reqwest::StatusCode>) -> ProbeAction {
    match status {
        Some(s) if s.is_success() => ProbeAction::Continue,
        Some(s) if s == reqwest::StatusCode::CONFLICT => ProbeAction::FinishTerminal,
        Some(s) if s == reqwest::StatusCode::FORBIDDEN => ProbeAction::AbortLocal,
        _ => ProbeAction::Continue,
    }
}

/// 发一次归属探针：复用 `report_phase("building")` 通道（幂等，hub 中间态
/// 写入带归属 CAS）；单次不重试——失败即无证据，下一拍天然重试。
pub(super) async fn probe_assignment_ownership(
    cfg: &WorkerConfig,
    worker_id: i64,
    task: &AssignedTask,
    cancel_token: &CancellationToken,
) -> ProbeAction {
    let request = async {
        let client = cfg.build_http_client().await.ok()?;
        let url = format!(
            "{}/api/v1/workers/{}/assignments/{}/result",
            cfg.hub_url, worker_id, task.assignment_id
        );
        let payload = serde_json::json!({ "phase": "building" });
        client
            .post(&url)
            .json(&payload)
            .timeout(OWNERSHIP_PROBE_PER_ATTEMPT)
            .send()
            .await
            .ok()
            .map(|resp| resp.status())
    };
    // 外层取消优先（biased）：探针绝不反向拖延 shutdown / 取消路径。
    let status = tokio::select! {
        biased;
        _ = cancel_token.cancelled() => None,
        status = request => status,
    };
    debug!(
        assignment_id = %task.assignment_id,
        status = ?status,
        "Ownership probe observation"
    );
    probe_decision(status)
}

/// 探针参与下的构建收尾形态。
pub(super) enum ProbedBuild {
    /// run_build 自然返回（成功/失败/shutdown/hub 心跳取消——既有路径不变）。
    Finished(crbs_core::Result<BuildResult>),
    /// 探针 409：本地已取消，result 已归一（见 [`probe_terminal_result`]），
    /// 由调用方走取消后补报。
    HubTerminal(BuildResult),
    /// 探针 403：本地已取消、本地产物保留、跳过终态上报。
    Reclaimed,
}

/// 探针终态路径的 Err 归一：取消 → cancelled 不带 error；其余按真实
/// phase（executor::failure_phase）折叠。
pub(super) fn probe_terminal_result(result: crbs_core::Result<BuildResult>) -> BuildResult {
    match result {
        Ok(r) => r,
        Err(e) => {
            let phase = crate::executor::failure_phase(&e);
            BuildResult::terminal(
                phase,
                if phase == "cancelled" {
                    None
                } else {
                    Some(e.to_string())
                },
                None,
            )
        }
    }
}
