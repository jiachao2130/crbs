// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 心跳定时器：每隔固定间隔向 Hub 发送心跳（携带本机负载遥测），并接收搭车下发的
//! 取消通知。

use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config::WorkerConfig;
use crate::poller::CancelRegistry;

/// 心跳失败后的快速重试间隔上限（秒）：失败后不等满整个 interval。
const HEARTBEAT_RETRY_MAX_DELAY_SECS: u64 = 10;

/// 下一次心跳前的等待秒数：失败后 min(interval, 10) 快速重试，成功恢复整 interval。
/// 固定 ticker 下失败后下一跳仍按整点来，interval 上限 110s 时单次失败的静默窗口
/// 最长 ≈230s（请求超时+整 interval），会越过 hub 侧 120s 失联判定、擦边
/// 240s running 回收档。
fn next_heartbeat_delay(last_failed: bool, interval_secs: u64) -> u64 {
    if last_failed {
        interval_secs.min(HEARTBEAT_RETRY_MAX_DELAY_SECS)
    } else {
        interval_secs
    }
}

/// 启动心跳后台任务。cancel_token 与主退出流程共享（取消即退出，含中断在途请求）；
/// main 关机须先 cancel 并等本任务退出、再发 offline 心跳，否则迟到的 online 心跳会
/// 把刚写的 offline 翻回 online（僵尸 worker）。401/403 导致任务退出、主循环级联
/// 关机；其余错误（含暂态 4xx）仅告警继续。
pub fn spawn_heartbeat(
    worker_id: i64,
    cfg: WorkerConfig,
    active_tasks: Arc<std::sync::atomic::AtomicI32>,
    cancel_registry: CancelRegistry,
    cancel_token: CancellationToken,
    resource_caps: i64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut warn_throttle = crbs_core::util::WarnThrottle::new(20);

        let mut last_failed = false;
        let mut first_beat = true;

        let mut prev_cpu: Option<CpuSnapshot> = None;

        loop {
            let delay = if first_beat {
                first_beat = false;
                0
            } else {
                next_heartbeat_delay(last_failed, cfg.heartbeat_interval_secs)
            };

            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("Heartbeat task received shutdown signal, exiting");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(delay)) => {}
            }

            // 上一心跳的 /proc/stat cpu 采样：与本次采样差分出利用率；本次采样缺失（读失败/
            // 非 Linux）保留上一份，绝不影响心跳本身。
            let cur_cpu = sample_cpu_snapshot().await;
            let cpu_util_pct = match (&prev_cpu, &cur_cpu) {
                (Some(prev), Some(cur)) => cpu_util_pct_between(prev, cur),
                _ => None,
            };
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("Heartbeat task received shutdown signal, exiting");
                    break;
                }
                res = send_heartbeat(
                    worker_id,
                    &cfg,
                    &active_tasks,
                    &cancel_registry,
                    cpu_util_pct,
                    resource_caps,
                ) => {
                    if let Err(e) = res {
                        last_failed = true;


                        if crate::error::is_auth_rejected(&e) {
                            error!(
                                error = %e,
                                "Heartbeat rejected by auth (401/403), shutting down; \
                                 the worker row or its secret may have been removed by an \
                                 admin — re-issue the secret (crbs-server worker rotate-secret \
                                 or create), update token in worker.toml, and restart the \
                                 worker to recover"
                            );
                            break;
                        }
                        if warn_throttle.fail() {
                            warn!(
                                error = %e,
                                consecutive_failures = warn_throttle.consecutive(),
                                "Heartbeat failed"
                            );
                        }
                    } else {
                        last_failed = false;
                        warn_throttle.reset();
                    }
                }
            }

            if cur_cpu.is_some() {
                // 仅采到采样才覆盖上一份（cancel 提前 break 不推进）。
                prev_cpu = cur_cpu;
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct LoadTelemetry {
    load1: f64,
    ncpu: i64,
    mem_used_pct: f64,

    mem_total_kb: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CpuSnapshot {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuSnapshot {
    fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    fn idle_all(&self) -> u64 {
        self.idle + self.iowait
    }
}

/// 两份采样差分求 CPU 利用率（0-100）。计算规则：busy = Δtotal − Δidle − Δiowait
/// （等待 IO 的核时间不计忙），与 top 的 %iowait 同一套规则。Δtotal == 0（时钟未
/// 走/重复采样）或计数器回绕（Δtotal 下溢）返回 None，绝不负值；减法按饱和语义
/// 处理，异常采样不会得出负值，利用率落在 [0, 100]。
fn cpu_util_pct_between(prev: &CpuSnapshot, cur: &CpuSnapshot) -> Option<f64> {
    let total_delta = cur.total().checked_sub(prev.total())?;
    if total_delta == 0 {
        return None;
    }
    let idle_delta = cur.idle_all().saturating_sub(prev.idle_all());
    Some((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64 * 100.0)
}

/// 采样本机负载遥测（Linux 读 /proc）：读取或解析失败整体返回 None（hub 落 NULL、
/// UI 显示 "—"），绝不影响心跳本身。
#[cfg(target_os = "linux")]
async fn sample_load_telemetry() -> Option<LoadTelemetry> {
    let loadavg = tokio::fs::read_to_string("/proc/loadavg").await.ok()?;
    let meminfo = tokio::fs::read_to_string("/proc/meminfo").await.ok()?;
    Some(LoadTelemetry {
        load1: parse_load1(&loadavg)?,
        ncpu: std::thread::available_parallelism().ok()?.get() as i64,
        mem_used_pct: parse_mem_used_pct(&meminfo)?,
        mem_total_kb: parse_mem_total_kb(&meminfo)?,
    })
}

#[cfg(not(target_os = "linux"))]
async fn sample_load_telemetry() -> Option<LoadTelemetry> {
    None
}

#[cfg(target_os = "linux")]
async fn sample_cpu_snapshot() -> Option<CpuSnapshot> {
    parse_cpu_snapshot(&tokio::fs::read_to_string("/proc/stat").await.ok()?)
}

#[cfg(not(target_os = "linux"))]
async fn sample_cpu_snapshot() -> Option<CpuSnapshot> {
    None
}

/// /proc/stat 首行聚合计数：`"cpu  u n s idle iowait irq softirq steal …"` → 快照。
/// 仅认首 token 恰为 "cpu" 的行（"cpu0" 等每核行不匹配）；前 8 列缺列或非数字返回
/// None；尾部 guest 列忽略（内核已计入 user）。
#[cfg(any(target_os = "linux", test))]
fn parse_cpu_snapshot(s: &str) -> Option<CpuSnapshot> {
    let mut fields = s.lines().next()?.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    let mut vals = fields.map(|v| v.parse::<u64>());
    let mut next = || vals.next()?.ok();
    Some(CpuSnapshot {
        user: next()?,
        nice: next()?,
        system: next()?,
        idle: next()?,
        iowait: next()?,
        irq: next()?,
        softirq: next()?,
        steal: next()?,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_load1(s: &str) -> Option<f64> {
    s.split_whitespace().next()?.parse().ok()
}

/// /proc/meminfo MemTotal/MemAvailable → 已用百分比；旧内核（<3.14）无 MemAvailable
/// 行返回 None（优于用 MemFree 高估已用）。
#[cfg(any(target_os = "linux", test))]
fn parse_mem_used_pct(s: &str) -> Option<f64> {
    let mut total = None;
    let mut available = None;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_meminfo_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_meminfo_kb(rest);
        }
    }
    let (total, available) = (total?, available?);
    if total <= 0.0 || available > total {
        return None;
    }
    Some((1.0 - available / total) * 100.0)
}

#[cfg(any(target_os = "linux", test))]
fn parse_meminfo_kb(rest: &str) -> Option<f64> {
    rest.trim_end_matches("kB").trim().parse().ok()
}

#[cfg(any(target_os = "linux", test))]
fn parse_mem_total_kb(s: &str) -> Option<i64> {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            return parse_meminfo_kb(rest).map(|v| v as i64);
        }
    }
    None
}

/// 发送一次心跳。cpu_util_pct 由心跳循环按两份 /proc/stat 采样差分传入（首跳、读失败、
/// 非 Linux → None）；disk_free_kb 逐跳采 build_dir 工件卷可用空间（复用 poller 的
/// statvfs 探针），失败 → None。
async fn send_heartbeat(
    worker_id: i64,
    cfg: &WorkerConfig,
    active_tasks: &Arc<std::sync::atomic::AtomicI32>,
    cancel_registry: &CancelRegistry,
    cpu_util_pct: Option<f64>,
    resource_caps: i64,
) -> crbs_core::Result<()> {
    let client = cfg.build_http_client().await?;
    let url = format!("{}/api/v1/workers/{}/heartbeat", cfg.hub_url, worker_id);

    let active = active_tasks.load(Ordering::Relaxed);
    let telemetry = sample_load_telemetry().await;
    if telemetry.is_none() {
        debug!("load telemetry unavailable (non-linux or /proc read failed)");
    }

    let (load1, ncpu, mem_used_pct, mem_total_kb) = match telemetry {
        Some(t) => (
            Some(t.load1),
            Some(t.ncpu),
            Some(t.mem_used_pct),
            Some(t.mem_total_kb),
        ),
        None => (None, None, None, None),
    };

    let disk_free_kb = match crate::poller::free_disk_bytes(Path::new(&cfg.build_dir)).await {
        Ok(bytes) => Some(i64::try_from(bytes / 1024).unwrap_or(i64::MAX)),
        Err(e) => {
            debug!(path = %cfg.build_dir, error = %e, "disk free telemetry unavailable");
            None
        }
    };

    let payload = serde_json::json!({
        "status": "online",
        "active_tasks": active,
        "load1": load1,
        "ncpu": ncpu,
        "cpu_util_pct": cpu_util_pct,
        "mem_used_pct": mem_used_pct,
        "mem_total_kb": mem_total_kb,
        "disk_free_kb": disk_free_kb,
        "resource_caps": resource_caps,
    });

    let resp = client
        .post(&url)
        .json(&payload)
        // 请求级超时：TCP 黑洞时单次心跳会挂到客户端 600s 总超时，而 hub 侧 120s
        // 即判 offline 回收任务，收紧到 min(间隔, 10s) 防长期静默。
        .timeout(Duration::from_secs(cfg.heartbeat_interval_secs.min(10)))
        .send()
        .await
        .map_err(|e| crate::error::reqwest("send heartbeat", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(crate::error::http_response_error("heartbeat", status, text));
    }

    let body = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "Heartbeat response body read failed; skipping cancel notices");
            return Ok(());
        }
    };
    match serde_json::from_slice::<HeartbeatNotices>(&body) {
        Ok(notices) => {
            for id in notices.cancelled_assignments {
                // 命中未取消的 token 才打 info；未知 id / 已取消 / 已自然结束的通知静默忽略。
                if cancel_registry.cancel(id) {
                    info!(assignment_id = %id, "Cancellation received via heartbeat");
                }
            }
        }
        Err(e) => {
            // 2xx 却不是预期 JSON 意味着取消通知持续丢失，会拖慢在建构建的取消确认，
            // 需可见；但不终止心跳循环——心跳本身已被 Hub 接受。
            warn!(error = %e, "Heartbeat response parse failed; skipping cancel notices");
        }
    }

    Ok(())
}

#[derive(serde::Deserialize)]
/// 心跳响应体的下行通知部分（worker 本地镜像，不共享 hub 侧类型）；其余键 serde
/// 默认忽略、字段缺失走 default（扩展约定），禁 deny_unknown_fields。
struct HeartbeatNotices {
    #[serde(default)]
    cancelled_assignments: Vec<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poller::CancelRegistry;
    use crate::test_util::{read_request, test_cfg};
    use std::sync::atomic::AtomicI32;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn serve_one_heartbeat(listener: TcpListener, body: &'static str) {
        let (mut sock, _) = listener.accept().await.unwrap();
        read_request(&mut sock).await;
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
        sock.flush().await.unwrap();
    }

    #[tokio::test]
    async fn heartbeat_cancel_notices_trigger_registered_tokens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one_heartbeat(
            listener,
            r#"{"accepted":true,"cancelled_assignments":[42,999]}"#,
        ));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let registry = CancelRegistry::default();
        let token = CancellationToken::new();
        registry.insert(42, token.clone());
        let active = Arc::new(AtomicI32::new(0));

        send_heartbeat(1, &cfg, &active, &registry, None, 0)
            .await
            .unwrap();

        assert!(token.is_cancelled(), "注册表内 42 的 token 必须被取消");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn heartbeat_without_cancel_field_is_noop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one_heartbeat(listener, r#"{"accepted":true}"#));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let registry = CancelRegistry::default();
        let token = CancellationToken::new();
        registry.insert(42, token.clone());
        let active = Arc::new(AtomicI32::new(0));

        send_heartbeat(1, &cfg, &active, &registry, None, 0)
            .await
            .unwrap();

        assert!(!token.is_cancelled(), "无取消字段不得触发任何 token");
        server.await.unwrap();
    }

    #[test]
    fn next_heartbeat_delay_fast_retries_after_failure() {
        assert_eq!(next_heartbeat_delay(false, 30), 30);
        assert_eq!(next_heartbeat_delay(false, 110), 110);
        assert_eq!(next_heartbeat_delay(true, 30), 10);
        assert_eq!(next_heartbeat_delay(true, 110), 10);
        assert_eq!(next_heartbeat_delay(true, 5), 5);
        assert_eq!(next_heartbeat_delay(true, 10), 10);
    }

    #[tokio::test]
    async fn heartbeat_unparseable_response_is_not_fatal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_one_heartbeat(listener, "not-json"));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let registry = CancelRegistry::default();
        let token = CancellationToken::new();
        registry.insert(42, token.clone());
        let active = Arc::new(AtomicI32::new(0));

        send_heartbeat(1, &cfg, &active, &registry, None, 0)
            .await
            .unwrap();

        assert!(!token.is_cancelled());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn heartbeat_payload_carries_cpu_util_pct() {
        for (util, needle) in [
            (Some(66.5), r#""cpu_util_pct":66.5"#),
            (None, r#""cpu_util_pct":null"#),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                let req = read_request(&mut sock).await;
                let body = r#"{"accepted":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.flush().await.unwrap();
                req
            });

            let cfg = test_cfg(format!("http://{addr}"), None).await;
            let active = Arc::new(AtomicI32::new(0));
            send_heartbeat(1, &cfg, &active, &CancelRegistry::default(), util, 0)
                .await
                .unwrap();

            let req = server.await.unwrap();
            let body = String::from_utf8_lossy(&req);
            assert!(body.contains(needle), "body must contain {needle}: {body}");
        }
    }

    #[tokio::test]
    async fn heartbeat_payload_carries_disk_free_and_resource_caps() {
        let tmp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_request(&mut sock).await;
            let body = r#"{"accepted":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
            req
        });

        let cfg = test_cfg(format!("http://{addr}"), Some(tmp.path())).await;
        let active = Arc::new(AtomicI32::new(0));
        send_heartbeat(
            1,
            &cfg,
            &active,
            &CancelRegistry::default(),
            None,
            crbs_core::RESOURCE_CAP_CGROUP_V2 | crbs_core::RESOURCE_CAP_PSI,
        )
        .await
        .unwrap();

        let req = server.await.unwrap();
        let body = String::from_utf8_lossy(&req);
        assert!(
            body.contains(r#""resource_caps":17"#),
            "caps bitmap verbatim: {body}"
        );
        let disk = body
            .split(r#""disk_free_kb":"#)
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .and_then(|v| v.parse::<i64>().ok());
        assert!(
            disk.is_some_and(|v| v > 0),
            "numeric disk KB expected: {body}"
        );
    }

    #[test]
    fn parse_load1_reads_first_column() {
        assert_eq!(parse_load1("0.52 0.58 0.59 1/367 12345\n"), Some(0.52));
        assert_eq!(parse_load1("2.000000 2.1 2.2 3/400 999\n"), Some(2.0));
    }

    #[test]
    fn parse_load1_rejects_bad_input() {
        assert_eq!(parse_load1(""), None);
        assert_eq!(parse_load1("garbage 0.58 0.59 1/367 12345"), None);

        assert_eq!(parse_load1("\n0.52 0.58"), Some(0.52));
    }

    #[test]
    fn parse_mem_used_pct_reads_meminfo() {
        let meminfo = "\
MemTotal:       16000000 kB\n\
MemFree:         1234567 kB\n\
MemAvailable:    8000000 kB\n\
Buffers:          234567 kB\n";
        assert_eq!(parse_mem_used_pct(meminfo), Some(50.0));
        let full = "MemTotal:       100 kB\nMemAvailable:      100 kB\n";
        assert_eq!(parse_mem_used_pct(full), Some(0.0));
    }

    #[test]
    fn parse_mem_used_pct_degrades_without_mem_available() {
        let old_kernel = "MemTotal:       16000000 kB\nMemFree:         1234567 kB\n";
        assert_eq!(parse_mem_used_pct(old_kernel), None);
        assert_eq!(parse_mem_used_pct("MemAvailable:    8000000 kB\n"), None);
    }

    #[test]
    fn parse_mem_total_kb_extracts_meminfo_line() {
        let meminfo = "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\n";
        assert_eq!(parse_mem_total_kb(meminfo), Some(16_000_000));
        assert_eq!(parse_mem_total_kb("MemFree: 1234567 kB\n"), None);
        assert_eq!(parse_mem_total_kb("MemTotal:       n/a kB\n"), None);
    }

    #[test]
    fn parse_mem_used_pct_rejects_bad_input() {
        assert_eq!(parse_mem_used_pct(""), None);
        assert_eq!(
            parse_mem_used_pct("MemTotal:       n/a kB\nMemAvailable:    8 kB\n"),
            None
        );

        assert_eq!(
            parse_mem_used_pct("MemTotal:       0 kB\nMemAvailable:      0 kB\n"),
            None
        );
    }

    #[test]
    fn parse_cpu_snapshot_reads_aggregate_row() {
        let line = "cpu  1102 1 903 750835 21432 0 3103 0 0 0\n";
        let s = parse_cpu_snapshot(line).unwrap();
        assert_eq!(
            s,
            CpuSnapshot {
                user: 1102,
                nice: 1,
                system: 903,
                idle: 750_835,
                iowait: 21_432,
                irq: 0,
                softirq: 3103,
                steal: 0,
            }
        );
    }

    #[test]
    fn parse_cpu_snapshot_rejects_bad_input() {
        assert_eq!(parse_cpu_snapshot(""), None);
        assert_eq!(
            parse_cpu_snapshot("cpu0 1102 1 903 750835 21432 0 3103 0\n"),
            None
        );

        assert_eq!(parse_cpu_snapshot("cpu  1 2 3\n"), None);
        assert_eq!(parse_cpu_snapshot("cpu  1 2 3 4 5 6 7 nan\n"), None);
    }

    fn zero_frame() -> CpuSnapshot {
        CpuSnapshot {
            user: 0,
            nice: 0,
            system: 0,
            idle: 0,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        }
    }

    #[test]
    fn cpu_util_pct_between_busy_idle_and_mixed() {
        let busy = CpuSnapshot {
            user: 100,
            ..zero_frame()
        };
        assert_eq!(cpu_util_pct_between(&zero_frame(), &busy), Some(100.0));

        let idle = CpuSnapshot {
            idle: 100,
            ..zero_frame()
        };
        assert_eq!(cpu_util_pct_between(&zero_frame(), &idle), Some(0.0));

        let prev = CpuSnapshot {
            user: 10,
            idle: 10,
            ..zero_frame()
        };
        let cur = CpuSnapshot {
            user: 70,
            idle: 50,
            ..zero_frame()
        };
        assert_eq!(cpu_util_pct_between(&prev, &cur), Some(60.0));
    }

    #[test]
    fn cpu_util_pct_between_excludes_iowait() {
        let base = CpuSnapshot {
            user: 100,
            idle: 100,
            iowait: 10,
            ..zero_frame()
        };
        let cur = CpuSnapshot { iowait: 60, ..base };
        assert_eq!(cpu_util_pct_between(&base, &cur), Some(0.0));
    }

    #[test]
    fn cpu_util_pct_between_degenerate_frames() {
        let s = CpuSnapshot {
            user: 10,
            idle: 20,
            ..zero_frame()
        };
        assert_eq!(cpu_util_pct_between(&s, &s), None);

        let rewound = CpuSnapshot {
            user: 5,
            idle: 5,
            ..zero_frame()
        };
        assert_eq!(cpu_util_pct_between(&s, &rewound), None);
    }
}
