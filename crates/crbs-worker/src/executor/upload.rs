// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建产物上传。

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crbs_core::engine::artifact_harvest::collect_crbs_logs_files;
use crbs_core::error::CrbsError;
use crbs_core::types::BuildOutputs;

use crate::config::{WorkerConfig, HTTP_FALLBACK_TIMEOUT_SECS};
use crate::poller::AssignedTask;
use crate::retry::{retry_with_timeout, wait_for_cancel};

use super::ensure_not_cancelled;

/// 单文件大小上限：2GB。
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// 单任务产物总大小上限：10GB。
const MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// 流式上传分块大小：内存占用与系统调用次数的折中。
const UPLOAD_CHUNK_SIZE: usize = 64 * 1024;

/// 调试/复现所依赖的内部文件名。build_packages.json 仅在 reproduce_enabled 命中时
/// 由引擎写入，不存在即跳过（文件存在性即判定）。
const DEBUG_FILES: &[&str] = &[
    "crbs-build.sh",
    "profile.json",
    "build_packages.json",
    "crbs-artifacts.json",
];

/// 上传流的尺寸一致性检查：读满声明长度后探到追加字节，或提前 EOF（哈希后文件
/// 被改动），都转读错误 → reqwest 中止请求、按可重试 Network 处理，绝不静默截断。
/// 不设防时 reqwest/hyper 对"流长 > 声明"静默截断照常成功，"不足"才报错。
struct ExactSizeRead<R> {
    inner: R,
    remaining: u64,
    probe: [u8; 1],
}

impl<R> ExactSizeRead<R> {
    fn new(inner: R, declared: u64) -> Self {
        Self {
            inner,
            remaining: declared,
            probe: [0u8; 1],
        }
    }

    fn size_drift_error(what: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("artifact {} after manifest hash", what),
        )
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for ExactSizeRead<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            let mut probe = tokio::io::ReadBuf::new(&mut this.probe);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut probe) {
                std::task::Poll::Ready(Ok(())) if probe.filled().is_empty() => {
                    std::task::Poll::Ready(Ok(()))
                }
                std::task::Poll::Ready(Ok(())) => {
                    std::task::Poll::Ready(Err(Self::size_drift_error("size grew")))
                }
                other => other,
            }
        } else if buf.remaining() as u64 <= this.remaining {
            let before = buf.filled().len();
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, buf) {
                std::task::Poll::Ready(Ok(())) => {
                    let n = buf.filled().len() - before;
                    if n == 0 {
                        std::task::Poll::Ready(Err(Self::size_drift_error("size shrank")))
                    } else {
                        this.remaining -= n as u64;
                        std::task::Poll::Ready(Ok(()))
                    }
                }
                other => other,
            }
        } else {
            let mut tmp = vec![0u8; this.remaining as usize];
            let mut tmp_buf = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                std::task::Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled();
                    if filled.is_empty() {
                        std::task::Poll::Ready(Err(Self::size_drift_error("size shrank")))
                    } else {
                        this.remaining -= filled.len() as u64;
                        buf.put_slice(filled);
                        std::task::Poll::Ready(Ok(()))
                    }
                }
                other => other,
            }
        }
    }
}

/// 上传构建产物到 Hub：BuildOutputs 记录的实际产物（rpms/srpms/logs）+ 调试/复现
/// 内部文件 + 约定目录 crbs-logs/ 的自定义日志，除该目录外不递归扫描 result_dir。
pub(crate) async fn upload_build_outputs(
    cfg: &WorkerConfig,
    task: &AssignedTask,
    outputs: &BuildOutputs,
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    ensure_not_cancelled(cancel_token)?;

    let base = &outputs.result_dir;
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    files.extend(outputs.rpms.iter().cloned());
    files.extend(outputs.srpms.iter().cloned());
    files.extend(outputs.logs.iter().cloned());

    for name in DEBUG_FILES {
        let p = base.join(name);
        match tokio::fs::try_exists(&p).await {
            Ok(true) => files.push(p),
            Ok(false) => {
                tracing::debug!(path = %p.display(), "Debug artifact not found, skipping");
            }
            Err(e) => {
                tracing::warn!(path = %p.display(), error = %e, "Failed to check debug artifact");
            }
        }
    }

    files.extend(collect_crbs_logs_files(base).await);

    files.sort();
    files.dedup();

    upload_files(cfg, task, base, &files, cancel_token).await
}

/// 仅上传指定日志文件（build.log）到 Hub 持久化；构建失败产物不完整时日志也必须
/// 回传。crbs-logs/ 同批并入——失败场景恰是 dmesg 等自定义日志最有价值的场景。
pub(crate) async fn upload_log_files(
    cfg: &WorkerConfig,
    task: &AssignedTask,
    base_dir: &Path,
    log_paths: &[std::path::PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    ensure_not_cancelled(cancel_token)?;
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for p in log_paths {
        if tokio::fs::try_exists(p).await.unwrap_or(false) {
            files.push(p.clone());
        }
    }

    files.extend(collect_crbs_logs_files(base_dir).await);
    // 失败路径同样收集 crbs-logs/；build.log 缺失时也不能跳过——crbs-logs 恰是
    // 失败排障最有价值的数据。
    if files.is_empty() {
        return Ok(());
    }
    files.sort();
    files.dedup();
    upload_files(cfg, task, base_dir, &files, cancel_token).await
}

fn open_upload_file() -> tokio::fs::OpenOptions {
    // O_NOFOLLOW 拒绝 symlink：结果目录对构建容器可写，恶意 spec 可预植指向宿主
    // 文件的链接——跟随读会把 worker 配置或本地库上传出去（词法 strip_prefix 挡不住
    // 预植链接，Worker 特权运行必须 fd 级拒绝）。
    let mut opts = tokio::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(nix::libc::O_NOFOLLOW);
    opts
}

/// 上传指定文件列表到 Hub，附带 SHA256 manifest 供校验。base_dir 用于计算 multipart
/// 相对文件名；文件必须落在其下否则拒绝（防泄露 Worker 目录结构）。
async fn upload_files(
    cfg: &WorkerConfig,
    task: &AssignedTask,
    base_dir: &Path,
    files: &[std::path::PathBuf],
    cancel_token: Option<&CancellationToken>,
) -> crbs_core::Result<()> {
    ensure_not_cancelled(cancel_token)?;

    let url = format!(
        "{}/api/v1/builds/{}/artifacts/upload",
        cfg.hub_url, task.build_id
    );

    if files.is_empty() {
        return Ok(());
    }

    retry_with_timeout(
        "upload_build_outputs",
        cancel_token,
        // 大产物 multipart 上传远超默认 30s：超时对齐客户端的总超时
        //（HTTP_FALLBACK_TIMEOUT_SECS）。
        Duration::from_secs(HTTP_FALLBACK_TIMEOUT_SECS),
        || async {
            // manifest（元数据 + SHA256）必须在重试闭包内每次尝试重算：哈希后文件
            // 被追加/截短时复用首算结果，三次尝试全拿过期 manifest，瞬态变化固化成
            // 永久失败；重算后稳定即恢复。
            let mut skipped_files = 0usize;
            let mut skipped_critical = 0usize;
            let mut total_size: u64 = 0;
            let mut checked_files: Vec<(std::path::PathBuf, String, u64)> = Vec::new();
            let mut manifest: HashMap<String, String> = HashMap::new();

            for path in files {
                ensure_not_cancelled(cancel_token)?;

                let metadata = match tokio::fs::symlink_metadata(path).await {
                    Ok(m) if m.file_type().is_file() => m,
                    Ok(_) | Err(_) => {
                        skipped_files += 1;
                        if path.file_name().is_some_and(|n| n == "build.log")
                            || path.extension().is_some_and(|e| e == "rpm")
                        {
                            skipped_critical += 1;
                        }
                        continue;
                    }
                };

                let size = metadata.len();
                if size > MAX_FILE_SIZE {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "artifact {} exceeds max file size ({} > {} bytes)",
                            path.display(),
                            size,
                            MAX_FILE_SIZE
                        ),
                    });
                }
                total_size += size;
                if total_size > MAX_TOTAL_SIZE {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "total artifacts size exceeds limit ({} > {} bytes)",
                            total_size, MAX_TOTAL_SIZE
                        ),
                    });
                }

                let relative = match path.strip_prefix(base_dir) {
                    Ok(r) => r,
                    Err(_) => {
                        // 安全边界：文件必须位于 base_dir 下，相对路径仅普通组件。
                        return Err(CrbsError::ValidationFailed {
                            message: format!(
                                "artifact {} is outside of result_dir {}",
                                path.display(),
                                base_dir.display()
                            ),
                        });
                    }
                };
                let file_name = relative
                    .to_string_lossy()
                    .replace('\\', "/")
                    .trim_start_matches('/')
                    .to_string();
                if file_name.is_empty()
                    || file_name.ends_with('/')
                    || Path::new(&file_name)
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    return Err(CrbsError::ValidationFailed {
                        message: format!("invalid artifact relative path: {}", file_name),
                    });
                }

                let mut hasher = Sha256::new();
                let mut file = open_upload_file()
                    .open(path)
                    .await
                    .map_err(|e| CrbsError::from_io_context("open artifact", e))?;
                let mut buf = vec![0u8; UPLOAD_CHUNK_SIZE];
                loop {
                    let n = file
                        .read(&mut buf)
                        .await
                        .map_err(|e| CrbsError::from_io_context("read artifact", e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                let sha256 = format!("{:x}", hasher.finalize());

                manifest.insert(file_name.clone(), sha256);
                checked_files.push((path.clone(), file_name, size));
            }

            if skipped_files > 0 {
                warn!(
                    requested = files.len(),
                    kept = checked_files.len(),
                    skipped = skipped_files,
                    "Artifacts skipped during metadata check"
                );
            }

            if skipped_critical > 0 {
                // RPM/SRPM/build.log 缺失或不可读 = 构建产物不完整：必须失败，否则
                // hub 记 succeeded 后 worker 删除本地唯一副本（静默丢产物）。
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "{skipped_critical} critical build output(s) (RPM/SRPM/build.log) \
                         disappeared or became unreadable before upload"
                    ),
                });
            }

            if checked_files.is_empty() {
                // files 非空（闭包外早退），空 checked_files 必为全跳过：必须
                // ValidationFailed 而非静默 Ok——否则 executor 置 error=None、本地
                // 唯一副本被当"hub 已持有"删掉；非 transient，不进重试。
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "all {} requested artifacts failed metadata check; nothing to upload",
                        files.len()
                    ),
                });
            }

            let manifest_json = serde_json::to_string(&manifest)
                .map_err(|e| crate::error::serde("serialize manifest", e))?;

            let client = cfg.build_http_client().await?;

            let mut form = reqwest::multipart::Form::new().text("manifest", manifest_json);

            for (path, file_name, size) in &checked_files {
                let file = open_upload_file().open(path).await.map_err(|e| {
                    CrbsError::from_io_context(format!("open artifact {}", path.display()), e)
                })?;
                let reader = ExactSizeRead::new(file, *size);
                let stream = tokio_util::io::ReaderStream::with_capacity(reader, UPLOAD_CHUNK_SIZE);
                let part = reqwest::multipart::Part::stream_with_length(
                    reqwest::Body::wrap_stream(stream),
                    *size,
                )
                .file_name(file_name.clone())
                .mime_str("application/octet-stream")
                .map_err(|e| crate::error::reqwest("set part mime", e))?;
                form = form.part("file", part);
            }

            let request = client
                .post(&url)
                .header("X-Crbs-Assignment-Id", task.assignment_id.to_string())
                .multipart(form)
                .send();

            let resp = tokio::select! {
                _ = wait_for_cancel(cancel_token) => {
                    return Err(CrbsError::Cancelled);
                }
                result = request => {
                    result.map_err(|e| crate::error::reqwest("send artifacts", e))?
                }
            };

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(crate::error::http_response_error(
                    "upload artifacts",
                    status,
                    text,
                ));
            }

            info!(
                build_id = %task.build_id,
                count = checked_files.len(),
                "Artifacts uploaded"
            );
            Ok(())
        },
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{find_subslice, test_cfg, test_task};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct HubCapture {
        content_length: usize,
        manifest: serde_json::Value,

        file_sha256: String,
    }

    async fn mock_hub_upload(listener: TcpListener) -> HubCapture {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 64 * 1024];
        let mut carry: Vec<u8> = Vec::new();

        let header_end = loop {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "client closed before sending headers");
            carry.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subslice(&carry, b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&carry[..header_end]).to_lowercase();
        let content_length: usize = header_text
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("streaming upload must declare content-length");
        let boundary = header_text
            .lines()
            .find_map(|l| l.strip_prefix("content-type: multipart/form-data; boundary="))
            .expect("multipart content-type with boundary")
            .trim()
            .to_string();
        let delim = format!("\r\n--{boundary}");
        let end_delim = format!("{delim}--");
        carry.drain(..header_end);

        macro_rules! read_until {
            ($marker:expr) => {{
                let marker: &[u8] = $marker;
                loop {
                    if let Some(pos) = find_subslice(&carry, marker) {
                        let before = carry[..pos].to_vec();
                        carry.drain(..pos + marker.len());
                        break before;
                    }
                    let n = sock.read(&mut tmp).await.unwrap();
                    assert!(n > 0, "unexpected EOF while parsing multipart body");
                    carry.extend_from_slice(&tmp[..n]);
                }
            }};
        }

        read_until!(b"\r\n\r\n");
        let manifest_bytes = read_until!(delim.as_bytes());
        let part2_headers = read_until!(b"\r\n\r\n");
        assert!(
            String::from_utf8_lossy(&part2_headers).contains("name=\"file\""),
            "second part must be the file part: {}",
            String::from_utf8_lossy(&part2_headers)
        );

        let mut hasher = Sha256::new();
        loop {
            if let Some(pos) = find_subslice(&carry, end_delim.as_bytes()) {
                hasher.update(&carry[..pos]);
                break;
            }
            if carry.len() > end_delim.len() {
                let cut = carry.len() - end_delim.len();
                hasher.update(&carry[..cut]);
                carry.drain(..cut);
            }
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "unexpected EOF inside file part");
            carry.extend_from_slice(&tmp[..n]);
        }

        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .unwrap();
        sock.flush().await.unwrap();

        HubCapture {
            content_length,
            manifest: serde_json::from_slice(&manifest_bytes).unwrap(),
            file_sha256: format!("{:x}", hasher.finalize()),
        }
    }

    async fn mock_hub_first_503_then_upload(
        listener: TcpListener,
        attempt1_done: tokio::sync::mpsc::Sender<()>,
    ) -> HubCapture {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 64 * 1024];
        let header_end = loop {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "client closed before sending headers");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
        let content_length: usize = header_text
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = buf.len() - header_end;
        while body < content_length {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            body += n;
        }
        sock.write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        drop(sock);

        attempt1_done.send(()).await.unwrap();

        mock_hub_upload(listener).await
    }

    async fn write_test_file(base: &Path, size_mb: u64) -> String {
        let path = base.join("big.rpm");
        let mut hasher = Sha256::new();
        let mut file = tokio::io::BufWriter::new(tokio::fs::File::create(&path).await.unwrap());
        let mut chunk = vec![0u8; 1024 * 1024];
        let mut state: u64 = 0x2545F4914F6CDD1D;
        for _ in 0..size_mb {
            for b in chunk.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 33) as u8;
            }
            hasher.update(&chunk);
            tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
                .await
                .unwrap();
        }
        file.flush().await.unwrap();
        drop(file);
        format!("{:x}", hasher.finalize())
    }

    async fn run_upload_and_verify(size_mb: u64) -> HubCapture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(mock_hub_upload(listener));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let task = test_task();
        let dir = tempfile::tempdir().unwrap();
        let expected_sha = write_test_file(dir.path(), size_mb).await;
        let files = vec![dir.path().join("big.rpm")];

        upload_files(&cfg, &task, dir.path(), &files, None)
            .await
            .unwrap();

        let cap = server.await.unwrap();
        assert_eq!(cap.file_sha256, expected_sha);
        assert_eq!(
            cap.manifest["big.rpm"].as_str().unwrap(),
            expected_sha,
            "manifest sha256 mismatch: {}",
            cap.manifest
        );

        assert!(
            cap.content_length > size_mb as usize * 1024 * 1024,
            "content-length {} too small for {}MB body",
            cap.content_length,
            size_mb
        );
        cap
    }

    #[tokio::test]
    async fn upload_files_streams_and_hashes_match() {
        run_upload_and_verify(8).await;
    }

    #[tokio::test]
    async fn retry_after_transient_failure_recomputes_manifest_on_drifted_file() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (attempt1_tx, mut attempt1_rx) = tokio::sync::mpsc::channel::<()>(1);
        let server = tokio::spawn(mock_hub_first_503_then_upload(listener, attempt1_tx));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let task = test_task();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.rpm");
        let initial = b"v1-payload";
        tokio::fs::write(&path, initial).await.unwrap();

        let upload = {
            let cfg = cfg.clone();
            let task = task.clone();
            let base = dir.path().to_path_buf();
            let files = vec![path.clone()];
            tokio::spawn(async move { upload_files(&cfg, &task, &base, &files, None).await })
        };

        attempt1_rx.recv().await.unwrap();
        let appended = b"-appended-during-backoff";
        {
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .await
                .unwrap();
            use tokio::io::AsyncWriteExt;
            f.write_all(appended).await.unwrap();
        }

        let outcome = tokio::time::timeout(Duration::from_secs(30), upload)
            .await
            .expect("upload must settle within retries")
            .unwrap();
        assert!(
            outcome.is_ok(),
            "drift after transient failure must recover via manifest recompute: {outcome:?}"
        );

        let cap = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("mock hub must finish")
            .unwrap();

        let mut final_content = initial.to_vec();
        final_content.extend_from_slice(appended);
        let mut hasher = Sha256::new();
        hasher.update(&final_content);
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(cap.file_sha256, expected, "hub received the drifted bytes");
        assert_eq!(
            cap.manifest["big.rpm"].as_str().unwrap(),
            expected,
            "manifest must be recomputed from the drifted content: {}",
            cap.manifest
        );
    }

    #[tokio::test]
    async fn upload_files_fails_when_every_artifact_is_skipped() {
        let cfg = test_cfg("http://127.0.0.1:1".to_string(), None).await;
        let task = test_task();
        let dir = tempfile::tempdir().unwrap();
        let dir_entry = dir.path().join("not-a-file.rpm");
        tokio::fs::create_dir(&dir_entry).await.unwrap();
        let dangling = dir.path().join("dangling.rpm");
        tokio::fs::symlink(dir.path().join("missing-target"), &dangling)
            .await
            .unwrap();

        let files = vec![dir_entry, dangling];
        match upload_files(&cfg, &task, dir.path(), &files, None).await {
            Err(CrbsError::ValidationFailed { message }) => assert!(
                message.contains("critical build output"),
                "message must state the skipped critical artifacts: {message}"
            ),
            other => panic!("all-skipped upload must fail, got: {other:?}"),
        }
    }

    async fn capture_upload_body(listener: TcpListener) -> Vec<u8> {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut tmp = [0u8; 64 * 1024];
        let mut buf: Vec<u8> = Vec::new();
        let header_end = loop {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "client closed before sending headers");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
        let content_length: usize = header_text
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .expect("upload must declare content-length");
        while buf.len() - header_end < content_length {
            let n = sock.read(&mut tmp).await.unwrap();
            assert!(n > 0, "unexpected EOF while reading upload body");
            buf.extend_from_slice(&tmp[..n]);
        }
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .unwrap();
        sock.flush().await.unwrap();
        buf
    }

    #[tokio::test]
    async fn upload_log_files_includes_crbs_logs_dir() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(capture_upload_body(listener));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let task = test_task();
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("build.log"), b"top")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join("crbs-logs/sub"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("crbs-logs/sub/dmesg.txt"), b"dmesg")
            .await
            .unwrap();

        upload_log_files(
            &cfg,
            &task,
            dir.path(),
            &[dir.path().join("build.log")],
            None,
        )
        .await
        .unwrap();

        let body = server.await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("\"build.log\""),
            "manifest must include build.log"
        );
        assert!(
            text.contains("\"crbs-logs/sub/dmesg.txt\""),
            "manifest must include crbs-logs entry with subdir preserved: {text}"
        );
    }

    #[tokio::test]
    async fn upload_log_files_collects_crbs_logs_without_build_log() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(capture_upload_body(listener));

        let cfg = test_cfg(format!("http://{addr}"), None).await;
        let task = test_task();
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("crbs-logs"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("crbs-logs/dmesg.txt"), b"dmesg")
            .await
            .unwrap();

        upload_log_files(&cfg, &task, dir.path(), &[], None)
            .await
            .unwrap();

        let body = server.await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("\"crbs-logs/dmesg.txt\""),
            "custom logs must upload without build.log: {text}"
        );
    }

    #[tokio::test]
    #[ignore = "writes a 300MB file; run explicitly for memory verification"]
    async fn upload_files_large_file_streams_with_bounded_memory() {
        let size_mb: u64 = std::env::var("CRBS_UPLOAD_TEST_SIZE_MB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);
        run_upload_and_verify(size_mb).await;
    }

    async fn probe_server(listener: TcpListener, respond_200: bool) -> usize {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 {
                return 0;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
        let content_length: usize = header_text
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut extra = buf.len() - header_end;
        while extra < content_length {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 {
                return extra;
            }
            extra += n;
        }
        extra -= content_length;
        if respond_200 {
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            sock.flush().await.unwrap();
        }

        let mut over = extra;
        loop {
            match tokio::time::timeout(Duration::from_millis(300), sock.read(&mut tmp)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => over += n,
            }
        }
        over
    }

    #[tokio::test]
    async fn raw_stream_under_declared_length_fails_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(probe_server(listener, false));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let stream = tokio_util::io::ReaderStream::new(std::io::Cursor::new(vec![b'x'; 256]));
        let part =
            reqwest::multipart::Part::stream_with_length(reqwest::Body::wrap_stream(stream), 512);
        let form = reqwest::multipart::Form::new().part("file", part);
        let result = client
            .post(format!("http://{addr}/up"))
            .multipart(form)
            .send()
            .await;
        assert!(result.is_err(), "undersized stream must fail: {result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "mismatch should error immediately, not hang"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn raw_stream_over_declared_length_is_silently_truncated() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(probe_server(listener, true));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let stream = tokio_util::io::ReaderStream::new(std::io::Cursor::new(vec![b'x'; 1024]));
        let part =
            reqwest::multipart::Part::stream_with_length(reqwest::Body::wrap_stream(stream), 512);
        let form = reqwest::multipart::Form::new().part("file", part);
        let result = client
            .post(format!("http://{addr}/up"))
            .multipart(form)
            .send()
            .await;
        let over = server.await.unwrap();
        let status = result
            .expect("reqwest currently succeeds on oversized stream")
            .status();
        assert_eq!(status, 200);
        assert_eq!(over, 0, "hyper drops the over-declared tail silently");
    }

    #[tokio::test]
    async fn exact_size_read_passes_exact_bytes_through() {
        let mut reader = ExactSizeRead::new(std::io::Cursor::new(vec![7u8; 256]), 256);
        let mut out = vec![0u8; 256];
        reader.read_exact(&mut out).await.unwrap();
        assert!(out.iter().all(|&b| b == 7));
        let mut tail = [0u8; 8];
        let n = reader.read(&mut tail).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn exact_size_read_errors_when_source_shrinks() {
        let mut reader = ExactSizeRead::new(std::io::Cursor::new(vec![7u8; 256]), 512);
        let mut out = vec![0u8; 512];
        let err = reader.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("shrank"), "err: {err}");
    }

    #[tokio::test]
    async fn exact_size_read_errors_when_source_grows() {
        let mut reader = ExactSizeRead::new(std::io::Cursor::new(vec![7u8; 1024]), 256);
        let mut out = vec![0u8; 256];
        reader.read_exact(&mut out).await.unwrap();

        let mut tail = [0u8; 8];
        let err = reader.read(&mut tail).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("grew"), "err: {err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_upload_file_rejects_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(
            open_upload_file().open(&link).await.is_err(),
            "O_NOFOLLOW must reject a planted symlink"
        );
        assert!(open_upload_file().open(&target).await.is_ok());
    }
}
