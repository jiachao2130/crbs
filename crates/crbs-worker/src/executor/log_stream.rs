// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建日志流式上报与日志文件上传。

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::WorkerConfig;
use crate::poller::AssignedTask;
use crate::retry::retry_with_backoff;

/// 实时流式读取 build.log 并分 chunk 上报到 Hub，构建完成或收到取消信号后退出。
/// 等待引擎回报的确切 result_dir 定位 build.log（避免同包并发时 mtime 扫描误抓
/// 兄弟构建），超时未回报才降级 mtime 扫描 + warn。重派语义：assignment 被 reclaim
/// 重派后，同 build_id 新执行的日志从字节 0 起 append 到既有文件，与前次尝试的
/// 半截输出相邻且无分隔标记。
pub(crate) async fn stream_build_log_to_hub(
    cfg: WorkerConfig,
    worker_id: i64,
    task: AssignedTask,
    pkg_name: String,
    result_root: PathBuf,
    mut exact_result_dir_rx: tokio::sync::watch::Receiver<Option<PathBuf>>,
    cancel: CancellationToken,
) {
    let product = &task.product;
    let build_id = task.build_id;

    let pkg_root = result_root.join(product).join(&pkg_name);

    // 构建开始即向 Hub 注册空 chunk（log_buffer 首条日志前即成立）；失败不阻塞
    // 构建，首个真实 chunk 到达时 Hub 也会注册。注册 chunk 不占序号。
    let mut upload = LogUpload::new(format!(
        "{}/api/v1/workers/{}/assignments/{}/logs",
        cfg.hub_url, worker_id, task.assignment_id
    ));

    if let Err(e) =
        upload_log_chunk_with_retry(&cfg, &upload.url, None, bytes::Bytes::new(), Some(&cancel))
            .await
    {
        warn!(build_id = %build_id, error = %e, "Failed to register log stream with hub");
    }

    const EXACT_DIR_TIMEOUT: Duration = Duration::from_secs(60);
    let log_path = match wait_for_exact_result_dir(
        &mut exact_result_dir_rx,
        &cancel,
        EXACT_DIR_TIMEOUT,
    )
    .await
    {
        ExactDirOutcome::Reported(result_dir) => {
            match wait_for_build_log_in_dir(&result_dir, &cancel).await {
                Some(p) => p,
                None => {
                    info!(build_id = %build_id, "Log stream cancelled before build.log appeared");
                    return;
                }
            }
        }
        ExactDirOutcome::Aborted => {
            // 发送端未回报即关闭或已取消 = 本 build 无日志目录，直接退出不降级
            // mtime 扫描——防误抓并发兄弟构建的日志。
            info!(
                build_id = %build_id,
                "Log stream stopping: no result dir reported (build ended before creation or cancelled)"
            );
            return;
        }
        ExactDirOutcome::TimedOut => {
            warn!(
                build_id = %build_id,
                "Engine did not report exact result_dir within timeout; falling back to mtime scan"
            );
            match wait_for_build_log(&pkg_root, &cancel).await {
                Some(p) => p,
                None => {
                    info!(build_id = %build_id, "Log stream cancelled before build.log appeared (fallback)");
                    return;
                }
            }
        }
    };

    info!(build_id = %build_id, path = %log_path.display(), "Log stream started");

    let file = match tokio::fs::File::open(&log_path).await {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %log_path.display(), error = %e, "Failed to open build.log for streaming");
            return;
        }
    };

    let mut reader = tokio::io::BufReader::new(file);
    let mut buf = vec![0u8; 4096];

    let mut batch = LogBatcher::new();

    let mut flush_warn = crbs_core::util::WarnThrottle::new(20);

    let mut consecutive_empty = 0u32;
    let mut silent_limit = MAX_SILENT_POLLS;
    let mut total_read: u64 = 0;
    let mut exited_by_silence = false;
    loop {
        if cancel.is_cancelled() {
            break;
        }

        if batch.should_flush() {
            flush_pending_batch(
                &mut batch,
                &cfg,
                &mut upload,
                build_id,
                Some(&cancel),
                &mut flush_warn,
            )
            .await;
        }

        match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
            Ok(0) => {
                consecutive_empty += 1;
                match silent_poll_action(consecutive_empty, silent_limit, cancel.is_cancelled()) {
                    SilentPollAction::KeepPolling => {}
                    SilentPollAction::ExitNormally => break,
                    SilentPollAction::Escalate => {
                        silent_limit = EXTENDED_SILENT_POLLS;
                        info!(
                            build_id = %build_id,
                            path = %log_path.display(),
                            bytes_read = total_read,
                            "build.log silent for 10 minutes without cancellation; extending log-stream watch to 20 minutes"
                        );
                    }
                    SilentPollAction::GiveUp => {
                        warn!(
                            build_id = %build_id,
                            path = %log_path.display(),
                            bytes_read = total_read,
                            silent_polls = consecutive_empty,
                            "Log stream giving up: build.log silent for 20 minutes without cancellation; live tail ends here (full log still lands in the artifact build.log)"
                        );
                        exited_by_silence = true;
                        break;
                    }
                }

                flush_pending_batch(
                    &mut batch,
                    &cfg,
                    &mut upload,
                    build_id,
                    Some(&cancel),
                    &mut flush_warn,
                )
                .await;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(n) => {
                consecutive_empty = 0;

                // 数据恢复即复位档位：每个静默段独立走两档决策，避免后续静默段
                // 直接享受 20 分钟预算且无翻档日志。
                silent_limit = MAX_SILENT_POLLS;
                total_read += n as u64;
                batch.push(&buf[..n]);
                if batch.should_flush() {
                    flush_pending_batch(
                        &mut batch,
                        &cfg,
                        &mut upload,
                        build_id,
                        Some(&cancel),
                        &mut flush_warn,
                    )
                    .await;
                }
            }
            Err(e) => {
                warn!(build_id = %build_id, error = %e, "Failed to read build.log");
                break;
            }
        }
    }

    // 尾批（保序）：EOF / 取消 / 读错误各退出路径统一把剩余缓冲刷出，尾部数据不丢。
    // 传 None：retry_with_policy 对已取消令牌零尝试，而尾批必须真实尝试上传。
    flush_warn.reset();
    let chunk = batch.take();
    flush_log_batch(&cfg, &mut upload, build_id, chunk, None, &mut flush_warn).await;

    if !exited_by_silence {
        info!(build_id = %build_id, "Log stream stopped");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SilentPollAction {
    KeepPolling,

    Escalate,

    GiveUp,

    ExitNormally,
}

/// 静默轮询的档位决策（纯函数，单测覆盖）；silent_limit 为当前档位上限。
fn silent_poll_action(
    consecutive_empty: u32,
    silent_limit: u32,
    cancelled: bool,
) -> SilentPollAction {
    if consecutive_empty < silent_limit {
        SilentPollAction::KeepPolling
    } else if cancelled {
        SilentPollAction::ExitNormally
    } else if silent_limit == MAX_SILENT_POLLS {
        SilentPollAction::Escalate
    } else {
        SilentPollAction::GiveUp
    }
}

/// 攒批目标量：累计到该字节数即整批上传。单次 read 至多 4KB，批上限
/// 64KB + 4KB - 1，远低于服务端单 chunk 上限 MAX_LOG_CHUNK_BYTES = 1MB（超限 400）。
const LOG_BATCH_TARGET_BYTES: usize = 64 * 1024;

/// EOF 静默第一档上限：600 polls × 1s = 10 分钟（chroot init / 大 tarball 解包 /
/// 静默编译段轻松超 60s，一档即退会让实时流中途夭折、剩余日志全丢）。
const MAX_SILENT_POLLS: u32 = 600;

/// EOF 静默第二档上限：1200 polls × 1s = 20 分钟。构建真正的结束由取消信号通知，
/// 静默档位只是防御性措施；超 20 分钟仍无输出且未收取消已属异常，继续放大上限
/// 只会让泄漏的日志流 task 挂更久。
const EXTENDED_SILENT_POLLS: u32 = 2 * MAX_SILENT_POLLS;

const LOG_BATCH_FLUSH_WINDOW: Duration = Duration::from_millis(200);

fn log_batch_ready(pending_len: usize, batch_age: Duration) -> bool {
    pending_len >= LOG_BATCH_TARGET_BYTES || batch_age >= LOG_BATCH_FLUSH_WINDOW
}

struct LogBatcher {
    pending: Vec<u8>,

    started_at: Option<tokio::time::Instant>,
}

impl LogBatcher {
    fn new() -> Self {
        Self {
            pending: Vec::with_capacity(LOG_BATCH_TARGET_BYTES),
            started_at: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.started_at.is_none() {
            self.started_at = Some(tokio::time::Instant::now());
        }
        self.pending.extend_from_slice(bytes);
    }

    fn should_flush(&self) -> bool {
        self.started_at
            .is_some_and(|start| log_batch_ready(self.pending.len(), start.elapsed()))
    }

    fn take(&mut self) -> Vec<u8> {
        self.started_at = None;
        std::mem::replace(
            &mut self.pending,
            Vec::with_capacity(LOG_BATCH_TARGET_BYTES),
        )
    }
}

/// 日志上传上下文：hub 端点 + 下一个 chunk 序号。
///
/// 序号按"独立载荷"递增（含缺口占位），同一次载荷的所有重试复用同一序号：
/// hub 记录各 assignment 已接受的最大序号，重试到达时直接回 200 不再追加——
/// 响应丢失（写入成功但客户端超时）不会再让 build.log 与实时缓冲各重复一段。
/// 注册用的空 chunk 不带序号（不占日志位置）。
struct LogUpload {
    url: String,
    next_seq: u64,
}

impl LogUpload {
    fn new(url: String) -> Self {
        Self { url, next_seq: 1 }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}

/// 把攒批缓冲整批上传到 Hub（空批 no-op）。批数据由调用方 take() 进来，一次性
/// 转 bytes::Bytes，重试每次尝试只做 O(1) 克隆。失败语义：告警（调用方节流）+
/// 补发占位 chunk 把缺口显式标出（N = 丢弃的字节数）；占位也失败则放弃。
/// 占位固定传 None 取消令牌：retry_with_policy 对已取消令牌零尝试，而占位必须
/// 真实尝试一次，否则缺口标记丢失。
/// 死网络下最坏 ≈190s：主体批 + 占位各 3 次尝试 × 30s 单次超时 + 退避 ≈95s/轮；
/// log_task.await 位于产物采集 / 结果上报之前（executor/mod.rs），死网络 + 取消
/// 交叠时构建结果上报被拖 ~3 分钟。
async fn flush_log_batch(
    cfg: &WorkerConfig,
    upload: &mut LogUpload,
    build_id: i64,
    chunk: Vec<u8>,
    cancel: Option<&CancellationToken>,
    warn_throttle: &mut crbs_core::util::WarnThrottle,
) {
    if chunk.is_empty() {
        return;
    }
    let chunk = bytes::Bytes::from(chunk);
    let seq = upload.next_seq();
    if let Err(e) =
        upload_log_chunk_with_retry(cfg, &upload.url, Some(seq), chunk.clone(), cancel).await
    {
        if warn_throttle.fail() {
            warn!(
                build_id = %build_id,
                error = %e,
                consecutive_failures = warn_throttle.consecutive(),
                "Failed to upload log chunk"
            );
        }
        let placeholder = format!(
            "[crbs-worker] {} bytes of log lost during upload retry exhaustion\n",
            chunk.len()
        );
        let placeholder_seq = upload.next_seq();
        if let Err(pe) = upload_log_chunk_with_retry(
            cfg,
            &upload.url,
            Some(placeholder_seq),
            bytes::Bytes::from(placeholder),
            None,
        )
        .await
        {
            if warn_throttle.fail() {
                warn!(
                    build_id = %build_id,
                    error = %pe,
                    consecutive_failures = warn_throttle.consecutive(),
                    "Failed to upload log-loss placeholder"
                );
            }
        }
        return;
    }
    warn_throttle.reset();
}

async fn flush_pending_batch(
    batch: &mut LogBatcher,
    cfg: &WorkerConfig,
    upload: &mut LogUpload,
    build_id: i64,
    cancel: Option<&CancellationToken>,
    warn_throttle: &mut crbs_core::util::WarnThrottle,
) {
    if batch.started_at.is_none() {
        return;
    }
    flush_log_batch(cfg, upload, build_id, batch.take(), cancel, warn_throttle).await;
}

/// wait_for_exact_result_dir 的结果，区分"降级"与"直接退出"两种语义。
enum ExactDirOutcome {
    Reported(PathBuf),

    Aborted,

    TimedOut,
}

/// 等待引擎通过 watch 通道回报确切的 result_dir。
async fn wait_for_exact_result_dir(
    rx: &mut tokio::sync::watch::Receiver<Option<PathBuf>>,
    cancel: &CancellationToken,
    timeout: Duration,
) -> ExactDirOutcome {
    if let Some(dir) = rx.borrow().clone() {
        return ExactDirOutcome::Reported(dir);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return ExactDirOutcome::Aborted,
            _ = tokio::time::sleep_until(deadline) => return ExactDirOutcome::TimedOut,
            changed = rx.changed() => {

                if changed.is_err() {
                    return ExactDirOutcome::Aborted;
                }
                if let Some(dir) = rx.borrow().clone() {
                    return ExactDirOutcome::Reported(dir);
                }
            }
        }
    }
}

/// 等待确切 result_dir 下的 build.log 出现，直到找到或收到取消信号；2 小时
/// 防御性超时防取消信号因 bug 未传播时日志流 task 永久挂起。
async fn wait_for_build_log_in_dir(
    result_dir: &std::path::Path,
    cancel: &CancellationToken,
) -> Option<PathBuf> {
    let log_path = result_dir.join("build.log");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2 * 3600);
    loop {
        if cancel.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return None;
        }
        if tokio::fs::try_exists(&log_path).await.unwrap_or(false) {
            return Some(log_path);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// 循环等待 build.log 出现在 pkg_root 下直到找到或取消；2 小时防御性超时
/// （远超合理构建时长，含 base_os init）。
async fn wait_for_build_log(
    pkg_root: &std::path::Path,
    cancel: &CancellationToken,
) -> Option<PathBuf> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2 * 3600);
    loop {
        if cancel.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return None;
        }
        if let Some(path) = find_build_log_in_pkg_root(pkg_root).await {
            return Some(path);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn find_build_log_in_pkg_root(pkg_root: &std::path::Path) -> Option<PathBuf> {
    let mut entries = match tokio::fs::read_dir(pkg_root).await {
        Ok(e) => e,
        Err(_) => return None,
    };

    let mut latest_log: Option<(PathBuf, SystemTime)> = None;

    while let Ok(Some(entry)) = entries.next_entry().await {
        let is_dir = match entry.file_type().await {
            Ok(t) => t.is_dir(),
            Err(_) => continue,
        };
        if !is_dir {
            continue;
        }
        let log_path = entry.path().join("build.log");
        if tokio::fs::try_exists(&log_path).await.unwrap_or(false) {
            if let Ok(meta) = tokio::fs::metadata(&log_path).await {
                let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let replace = match latest_log.as_ref() {
                    Some((_, latest_modified)) => modified > *latest_modified,
                    None => true,
                };
                if replace {
                    latest_log = Some((log_path, modified));
                }
            }
        }
    }

    latest_log.map(|(path, _)| path)
}

/// 上传单块日志数据到 Hub，失败时重试。chunk 收 bytes::Bytes：每次尝试只做
/// O(1) 引用计数克隆。seq 为 chunk 序号（None 仅注册空 chunk）：重试复用同一序号，
/// hub 侧幂等去重依赖它。cancel 为 None 时重试不可取消（尾批 / 标记类上传：取消后
/// 仍要真实尝试）。
async fn upload_log_chunk_with_retry(
    cfg: &WorkerConfig,
    url: &str,
    seq: Option<u64>,
    chunk: bytes::Bytes,
    cancel: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    let seq_header = seq.map(|s| s.to_string());
    retry_with_backoff("upload_log_chunk", cancel, || async {
        let client = cfg.build_http_client().await?;
        let mut request = client.post(url).body(chunk.clone());
        if let Some(seq) = &seq_header {
            request = request.header("X-Crbs-Log-Seq", seq.clone());
        }
        let resp = request
            .send()
            .await
            .map_err(|e| crate::error::reqwest("send log chunk", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(crate::error::http_response_error(
                "upload log chunk",
                status,
                text,
            ));
        }
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_poll_action_decision_table() {
        use SilentPollAction as A;
        assert_eq!(
            silent_poll_action(0, MAX_SILENT_POLLS, false),
            A::KeepPolling
        );
        assert_eq!(
            silent_poll_action(MAX_SILENT_POLLS - 1, MAX_SILENT_POLLS, false),
            A::KeepPolling
        );
        assert_eq!(
            silent_poll_action(EXTENDED_SILENT_POLLS - 1, EXTENDED_SILENT_POLLS, false),
            A::KeepPolling
        );
        assert_eq!(
            silent_poll_action(MAX_SILENT_POLLS, MAX_SILENT_POLLS, false),
            A::Escalate
        );
        assert_eq!(
            silent_poll_action(EXTENDED_SILENT_POLLS, EXTENDED_SILENT_POLLS, false),
            A::GiveUp
        );
        assert_eq!(
            silent_poll_action(MAX_SILENT_POLLS, MAX_SILENT_POLLS, true),
            A::ExitNormally
        );
        assert_eq!(
            silent_poll_action(EXTENDED_SILENT_POLLS, EXTENDED_SILENT_POLLS, true),
            A::ExitNormally
        );

        assert_eq!(EXTENDED_SILENT_POLLS, 2 * MAX_SILENT_POLLS);
    }

    #[test]
    fn log_batch_ready_triggers_on_size_or_window() {
        assert!(!log_batch_ready(0, Duration::from_millis(0)));
        assert!(!log_batch_ready(
            LOG_BATCH_TARGET_BYTES - 1,
            LOG_BATCH_FLUSH_WINDOW - Duration::from_millis(1)
        ));
        assert!(log_batch_ready(LOG_BATCH_TARGET_BYTES, Duration::ZERO));
        assert!(log_batch_ready(1, LOG_BATCH_FLUSH_WINDOW));
        assert!(log_batch_ready(
            LOG_BATCH_TARGET_BYTES - 1,
            LOG_BATCH_FLUSH_WINDOW
        ));
    }

    #[tokio::test]
    async fn log_batcher_take_resets_window_and_content() {
        let mut batch = LogBatcher::new();
        assert!(!batch.should_flush(), "empty batch must never flush");

        batch.push(b"hello");
        assert!(!batch.should_flush(), "small fresh batch must not flush");
        tokio::time::sleep(LOG_BATCH_FLUSH_WINDOW + Duration::from_millis(50)).await;
        assert!(batch.should_flush(), "window expiry must flush small batch");

        let taken = batch.take();
        assert_eq!(taken, b"hello".to_vec());
        assert!(batch.pending.is_empty());
        assert!(batch.started_at.is_none());
        assert!(!batch.should_flush(), "taken batch must be reset to empty");
    }

    #[tokio::test]
    async fn log_batcher_size_cap_stays_under_server_chunk_limit() {
        const SERVER_MAX_LOG_CHUNK_BYTES: usize = 1024 * 1024;
        let mut batch = LogBatcher::new();
        let read = 4096;
        while batch.pending.len() < LOG_BATCH_TARGET_BYTES {
            batch.push(&vec![b'x'; read]);
        }
        assert!(
            batch.should_flush(),
            "reaching target size must flush regardless of window"
        );
        assert!(batch.pending.len() <= LOG_BATCH_TARGET_BYTES + read);
        assert!(batch.pending.len() + read < SERVER_MAX_LOG_CHUNK_BYTES);
    }

    #[tokio::test]
    async fn wait_for_build_log_returns_when_file_appears_late() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path().to_path_buf();
        let cancel = CancellationToken::new();

        let wait_root = pkg_root.clone();
        let wait_cancel = cancel.clone();
        let handle =
            tokio::spawn(async move { wait_for_build_log(&wait_root, &wait_cancel).await });

        tokio::time::sleep(Duration::from_millis(1200)).await;
        let build_dir = pkg_root.join("20260717-120000-1");
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::write(build_dir.join("build.log"), b"data")
            .await
            .unwrap();

        let found = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found, Some(build_dir.join("build.log")));
    }

    #[tokio::test]
    async fn wait_for_build_log_returns_none_on_cancel() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path().to_path_buf();
        let cancel = CancellationToken::new();

        let wait_cancel = cancel.clone();
        let handle = tokio::spawn(async move { wait_for_build_log(&pkg_root, &wait_cancel).await });

        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();

        let found = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn wait_for_exact_result_dir_returns_value_sent_before_call() {
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);
        let cancel = CancellationToken::new();
        let dir = PathBuf::from("/tmp/crbs/result/prod/pkg/20260728-1001");
        tx.send(Some(dir.clone())).unwrap();

        let got = wait_for_exact_result_dir(&mut rx, &cancel, Duration::from_secs(5)).await;
        assert!(matches!(got, ExactDirOutcome::Reported(d) if d == dir));
    }

    #[tokio::test]
    async fn wait_for_exact_result_dir_returns_value_sent_late() {
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);
        let cancel = CancellationToken::new();
        let dir = PathBuf::from("/tmp/crbs/result/prod/pkg/20260728-late");
        let send_dir = dir.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = tx.send(Some(send_dir));
        });

        let got = wait_for_exact_result_dir(&mut rx, &cancel, Duration::from_secs(5)).await;
        assert!(matches!(got, ExactDirOutcome::Reported(d) if d == dir));
    }

    #[tokio::test]
    async fn wait_for_exact_result_dir_times_out_without_blocking() {
        let (_tx, mut rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);
        let cancel = CancellationToken::new();

        let got = tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_exact_result_dir(&mut rx, &cancel, Duration::from_millis(200)),
        )
        .await
        .expect("must not block past its own timeout");
        assert!(matches!(got, ExactDirOutcome::TimedOut));
        assert!(!cancel.is_cancelled());
    }

    #[tokio::test]
    async fn wait_for_exact_result_dir_aborts_when_sender_dropped_without_value() {
        let (tx, mut rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);
        let cancel = CancellationToken::new();
        drop(tx);

        let got = wait_for_exact_result_dir(&mut rx, &cancel, Duration::from_secs(5)).await;
        assert!(matches!(got, ExactDirOutcome::Aborted));
    }

    #[tokio::test]
    async fn wait_for_exact_result_dir_aborts_on_cancel() {
        let (_tx, mut rx) = tokio::sync::watch::channel::<Option<PathBuf>>(None);
        let cancel = CancellationToken::new();
        cancel.cancel();

        let got = wait_for_exact_result_dir(&mut rx, &cancel, Duration::from_secs(5)).await;
        assert!(matches!(got, ExactDirOutcome::Aborted));
    }

    #[tokio::test]
    async fn wait_for_build_log_in_dir_reads_only_exact_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path();

        let sibling = pkg_root.join("20260728-100000-1001");
        tokio::fs::create_dir_all(&sibling).await.unwrap();
        tokio::fs::write(sibling.join("build.log"), b"SIBLING")
            .await
            .unwrap();

        let exact = pkg_root.join("20260728-095959-1002");
        tokio::fs::create_dir_all(&exact).await.unwrap();
        tokio::fs::write(exact.join("build.log"), b"EXACT")
            .await
            .unwrap();

        let cancel = CancellationToken::new();
        let found = wait_for_build_log_in_dir(&exact, &cancel).await.unwrap();
        assert_eq!(found, exact.join("build.log"));
        assert_eq!(tokio::fs::read(&found).await.unwrap(), b"EXACT");
    }
}
