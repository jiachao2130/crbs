// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程产物下载、服务器数据的路径安全与响应体流式输出。

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use crbs_core::engine::artifact_harvest::CRBS_LOGS_DIR;
use crbs_core::error::CrbsError;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use super::http::{http_status_error, list_artifacts, list_artifacts_public, ArtifactsResponse};
use super::target::RemoteTarget;

/// 从远程 server 下载构建产物到本地目录。
pub async fn download_artifacts(
    target: &RemoteTarget,
    id: i64,
    artifacts: &ArtifactsResponse,
    local_dir: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    use tracing::debug;
    let client = target.client().await?;
    let mut files: Vec<&String> = Vec::new();
    files.extend(&artifacts.rpms);
    files.extend(&artifacts.srpms);
    files.extend(&artifacts.other);

    for rel in files {
        // 服务器数据不可信：绝对路径 / `..` 分量在 join 后即任意文件写。
        let rel = safe_server_rel_path(rel)?;
        let url = format!(
            "{}/api/v1/builds/{}/artifacts/download?file={}",
            target.url,
            id,
            urlencoding::encode(rel)
        );
        let resp = fetch_artifact_checked(client, &url, rel, cancel).await?;

        let dest = local_dir.join(rel);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| CrbsError::Io {
                    context: format!("create dir {}", parent.display()),
                    kind: e.kind(),
                    detail: e.to_string(),
                })?;
            enforce_crbs_dir_perms(parent).await;
        }
        save_response_body_to_file(resp, &dest, cancel).await?;
        debug!(file = %rel, "Downloaded artifact");
    }

    Ok(())
}

// ── 服务器数据的路径安全（下载侧纵深防御）────────────────────────────
// 清单/arch 字段来自 server 响应，被攻破或篡改时即 CLI（常 root）的文件写
// 原语：join 绝对分量整体替换基目录、`..` 逐级逃逸；两条校验各堵一边。

/// 校验服务器提供的产物相对路径可安全拼接进本地下载目录：必须相对，且每个
/// 分量都是 Normal（拒绝 `..`、`.`、绝对路径）。失败归 [`CrbsError::Network`]
/// （ENVIRONMENT=6）——数据源是 server 而非用户参数，USAGE(4) 的"修参数"
/// hint 会误导排障；文案逐字保留原 anyhow bail。
fn safe_server_rel_path(rel: &str) -> Result<&str> {
    let p = Path::new(rel);
    if !p.is_relative() {
        return Err(CrbsError::Network {
            message: format!("server returned non-relative artifact path: {rel:?}"),
        }
        .into());
    }
    if rel.is_empty()
        || !p
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    {
        return Err(CrbsError::Network {
            message: format!(
                "server returned unsafe artifact path: {rel:?} (only plain relative components allowed)"
            ),
        }
        .into());
    }
    Ok(rel)
}

/// 校验服务器提供的目录名（arch 等）是单个安全分量（字母数字与 _-.，不为
/// `.`/`..`），防拼进本地路径后逃逸。失败归 `Network`，裁定同 [`safe_server_rel_path`]。
pub(crate) fn safe_server_dir_component(name: &str) -> Result<&str> {
    let ok = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.');
    if !ok {
        return Err(CrbsError::Network {
            message: format!("server returned unsafe directory name: {name:?}"),
        }
        .into());
    }
    Ok(name)
}

/// 大文件下载/上传的总超时：multi-GB debuginfo 与多 SRPM 提交常超通用 300s；
/// 连接阶段仍受 client 级 `connect_timeout` 约束。
pub(crate) const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// 日志/构建跟随流的总超时：`--follow` 的合法时长由取消令牌决定（Ctrl-C），
/// 这里只设 24h 兜底防连接僵死后永久挂死。
pub(crate) const LONG_BODY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// 把已确认 2xx 的响应体流式落盘到 `dest`：写入同目录临时文件后原子 `rename`，
/// 中断（Ctrl-C/超时）不留半截假完整文件（重跑的"file already exists"判定只
/// 见完整产物）；落盘即补权限不变量（0660 + crbs 组），root 下载的
/// 0644/root:root 会让组内身份 EACCES。chmod 失败仅 warn，chown 失败仅 debug。
async fn save_response_body_to_file(
    resp: reqwest::Response,
    dest: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // parent()/file_name() 的 Option context 豁免：dest 恒由已过 safe_server_*
    // 校验的安全相对路径（第三调用方 download_artifact_to_dir 的 basename 为
    // file_name() 派生分量，无路径分隔/穿越段，含 join("") 空串边界）join 而来，
    // 恒为 Some；真触发即逻辑 bug，anyhow INTERNAL(1)（"this is a bug"）语义恰确。
    let parent = dest
        .parent()
        .with_context(|| format!("artifact path has no parent dir: {}", dest.display()))?;
    // 同上豁免：见 parent() 注记。
    let leaf = dest
        .file_name()
        .with_context(|| format!("artifact path has no file name: {}", dest.display()))?
        .to_string_lossy();
    let tmp_path = parent.join(format!("{leaf}.part-{}", uuid::Uuid::new_v4()));

    // 取消（Ctrl-C）也走 Err 路径：落入下方统一的 remove_file 清理，不留 `.part-<uuid>` 残留。
    let write_result: Result<()> = async {
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("create temp file {}", tmp_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        let mut stream = resp.bytes_stream();
        loop {
            let chunk = tokio::select! {
                _ = crbs_core::http_retry::wait_for_cancel(cancel) => {
                    return Err(CrbsError::Cancelled.into());
                }
                maybe = stream.next() => match maybe {
                    Some(c) => c,
                    None => break,
                },
            };
            let chunk = chunk.map_err(|e| CrbsError::Network {
                message: format!("download {}: {e}", dest.display()),
            })?;
            file.write_all(&chunk).await.map_err(|e| CrbsError::Io {
                context: format!("write {}", tmp_path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        }
        file.sync_all().await.map_err(|e| CrbsError::Io {
            context: format!("sync {}", tmp_path.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
        Ok(())
    }
    .await;

    match write_result {
        Ok(()) => {
            if let Err(e) =
                tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o660)).await
            {
                tracing::warn!(
                    path = %dest.display(),
                    error = %e,
                    "Failed to enforce 0660 on downloaded artifact"
                );
            }
            crbs_core::privilege::chown_to_crbs_group_async(&tmp_path, false, "artifact").await;
            if let Err(e) = tokio::fs::rename(&tmp_path, dest).await {
                // rename 失败（如 dest 被同名目录占用）：统一清掉半截临时文件
                // 再返回原错误（对齐下方 Err 分支的 remove_file 清理）。
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(CrbsError::Io {
                    context: format!("rename temp file to {}", dest.display()),
                    kind: e.kind(),
                    detail: e.to_string(),
                }
                .into());
            }
            Ok(())
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            Err(e)
        }
    }
}

/// 对 CLI 创建的下载目录补权限不变量（2770 + crbs 组）。失败语义同上：
/// chmod 失败 warn，chown 失败 debug。
async fn enforce_crbs_dir_perms(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Err(e) = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o2770)).await
    {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "Failed to enforce 2770 on download dir"
        );
    }
    crbs_core::privilege::chown_to_crbs_group_async(path, false, "download dir").await;
}

/// 远程任务产物下载选项。
#[derive(Clone, Debug, Default)]
pub struct DownloadArtifactsOptions {
    /// 是否包含 debuginfo / debugsource / debug 包。
    pub include_debuginfo: bool,
    /// 是否包含日志文件（*.log、*.log.*）。
    pub include_logs: bool,
    /// 是否包含 SRPM（下载到共享 SRPMS 目录并去重）。
    pub include_srpm: bool,
    /// 是否包含其它文件（如 profile.json 内部文件始终跳过）。
    pub include_other: bool,
    /// 遇到已存在文件时是否覆盖。
    pub force: bool,
}

/// 下载某个远程任务的所有子构建产物到本地目录：`{base_local_dir}/{arch}/`
/// 放架构相关 RPM 与 other 文件，`{base_local_dir}/SRPMS/` 放跨架构共享的
/// 源码包；`builds` 由调用方经 `fetch_task_record`（认证）或
/// `fetch_public_download_info`（匿名）取得。返回实际下载的文件数量。
pub async fn download_task_artifacts(
    target: &RemoteTarget,
    builds: &[crbs_core::types::ChildBuildSummary],
    base_local_dir: &Path,
    options: &DownloadArtifactsOptions,
    cancel: Option<&CancellationToken>,
) -> Result<usize> {
    let mut total_count = 0usize;
    let mut downloaded_srpm_basenames: HashSet<String> = HashSet::new();

    // SRPMS 目录是跨架构共享的，不同后缀的 SRPM 都保留。
    let srpm_dir = base_local_dir.join("SRPMS");

    for build in builds {
        if !crbs_core::types::build_phase_is_terminal(&build.phase) {
            continue;
        }

        let arch = if build.arch.is_empty() {
            "unknown"
        } else {
            // 服务器数据不可信：arch 拼进本地路径，必须是单个安全分量。
            safe_server_dir_component(build.arch.as_str())?
        };

        // 无 token profile 全程走 public 匿名端点：任务摘要与制品清单必须同源，
        // 混用会让匿名在 protected 清单上 401。
        let artifacts = if target.token.is_none() {
            list_artifacts_public(target, build.id, cancel).await?
        } else {
            list_artifacts(target, build.id, cancel).await?
        };

        let arch_dir = base_local_dir.join(arch);
        tokio::fs::create_dir_all(&arch_dir)
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("create local arch dir {}", arch_dir.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        enforce_crbs_dir_perms(&arch_dir).await;

        // 下载 RPM（arch-specific 和 noarch 都放到各自架构目录，不做跨架构去重）
        for rpm_rel in &artifacts.rpms {
            let basename = Path::new(rpm_rel)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(rpm_rel);

            if !options.include_debuginfo && is_debug_package(basename) {
                continue;
            }

            download_artifact_to_dir(
                target,
                build.id,
                rpm_rel,
                &arch_dir,
                basename,
                options.force,
                cancel,
            )
            .await?;
            total_count += 1;
        }

        // 下载 SRPM：只下载一次（源码包架构无关）
        if options.include_srpm {
            for srpm_rel in &artifacts.srpms {
                let basename = Path::new(srpm_rel)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(srpm_rel);
                if downloaded_srpm_basenames.contains(basename) {
                    continue;
                }
                tokio::fs::create_dir_all(&srpm_dir)
                    .await
                    .map_err(|e| CrbsError::Io {
                        context: format!("create local srpm dir {}", srpm_dir.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    })?;
                enforce_crbs_dir_perms(&srpm_dir).await;
                match download_artifact_to_dir(
                    target,
                    build.id,
                    srpm_rel,
                    &srpm_dir,
                    basename,
                    options.force,
                    cancel,
                )
                .await
                {
                    Ok(()) => {
                        downloaded_srpm_basenames.insert(basename.to_string());
                        total_count += 1;
                    }
                    Err(e) => {
                        // 失败也记入已见集合：失败原因跨架构稳定（产品禁下载/
                        // 角色权限不足），不记则 N 架构任务各失败一次、各打一对
                        // 告警；成功路径不变（total_count 只在 Ok 计）。
                        downloaded_srpm_basenames.insert(basename.to_string());
                        // SRPM 下载失败可能因 server 禁下载（allow_srpm_download=false），不中断。
                        tracing::warn!(error = %e, "Failed to download SRPM, skipping");
                        eprintln!(
                            "Warning: could not download SRPM (may require operator role): {e}"
                        );
                    }
                }
            }
        }

        if options.include_other {
            for other_rel in &artifacts.other {
                if !other_bucket_should_download(other_rel, options.include_logs) {
                    continue;
                }
                // crbs-logs/ 条目保留子目录结构落盘（见 other_dest_rel）
                download_artifact_to_dir(
                    target,
                    build.id,
                    other_rel,
                    &arch_dir,
                    &other_dest_rel(other_rel),
                    options.force,
                    cancel,
                )
                .await?;
                total_count += 1;
            }
        }
    }

    Ok(total_count)
}

/// GET artifact 的取消感知收口（两下载路径共用）：Ctrl-C → Cancelled；环境域
/// 错误直映射 Network（ENVIRONMENT=6，不经 anyhow context——那会落 INTERNAL(1)
/// 误报 bug，message 含 URL 与底层错误文本）；非 2xx → http_status_error。
/// 路径安全校验由调用方在调用前完成（safe_server_rel_path）。
async fn fetch_artifact_checked(
    client: &reqwest::Client,
    url: &str,
    rel: &str,
    cancel: Option<&CancellationToken>,
) -> Result<reqwest::Response> {
    let resp = tokio::select! {
        _ = crbs_core::http_retry::wait_for_cancel(cancel) => {
            return Err(CrbsError::Cancelled.into());
        }
        result = client.get(url).timeout(DOWNLOAD_TIMEOUT).send() => {
            result.map_err(|e| CrbsError::Network {
                message: format!("GET {url}: {e}"),
            })?
        }
    };
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
        return Err(http_status_error(&format!("download {rel}"), status, &body).into());
    }
    Ok(resp)
}

/// 下载单个产物到 `dest_dir` 下：`dest_name` 为落盘相对路径（可含子目录，
/// 如 crbs-logs/ 结构落地，父目录自动创建并补权限不变量），rpm/srpm 调用方
/// 传 basename（维持扁平落盘），other 桶传 [`other_dest_rel`] 结果。
async fn download_artifact_to_dir(
    target: &RemoteTarget,
    build_id: i64,
    rel_path: &str,
    dest_dir: &Path,
    dest_name: &str,
    force: bool,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    // 服务器数据不可信：dest_name 可保留子路径后，basename 扁平化的隐式防
    // 穿越不再成立，源相对路径必须先过显式校验（拒绝绝对路径与 `..` 分量）。
    let rel_path = safe_server_rel_path(rel_path)?;
    let client = target.client().await?;
    let url = format!(
        "{}/api/v1/builds/{}/artifacts/download?file={}",
        target.url,
        build_id,
        urlencoding::encode(rel_path)
    );
    let resp = fetch_artifact_checked(client, &url, rel_path, cancel).await?;

    let dest = dest_dir.join(dest_name);
    if let Some(parent) = dest.parent() {
        if parent != dest_dir {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| CrbsError::Io {
                    context: format!("create dir {}", parent.display()),
                    kind: e.kind(),
                    detail: e.to_string(),
                })?;
            enforce_crbs_dir_perms(parent).await;
        }
    }
    if !force && tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        // 已存在文件可由用户 --force 修正——ValidationFailed（USAGE=4），
        // 不落 INTERNAL(1)；文案逐字保留，仅加 "validation failed: " 前缀。
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "file already exists: {} (use --force to overwrite)",
                dest.display()
            ),
        }
        .into());
    }
    save_response_body_to_file(resp, &dest, cancel).await?;
    Ok(())
}

/// other 桶条目的落盘相对路径：含 `/` 的（即 crbs-logs/ 下一切，见
/// [`CRBS_LOGS_DIR`]）原样保留子目录结构（`{arch}/crbs-logs/a/dmesg.txt`，
/// 防递归收集后同名互踩），顶层条目维持 basename 扁平落盘。
fn other_dest_rel(rel: &str) -> String {
    if rel.contains('/') {
        rel.to_string()
    } else {
        Path::new(rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(rel)
            .to_string()
    }
}

/// other 桶单条目是否随本次下载：crbs-build.sh / profile.json 恒跳过（内部
/// 文件）；日志判定 = basename 以 .log 结尾或含 .log.，或相对路径位于
/// crbs-logs/ 约定目录下（不限扩展名，见 [`CRBS_LOGS_DIR`]）——非日志恒下载，
/// 日志仅 include_logs 为真才下载。
fn other_bucket_should_download(rel: &str, include_logs: bool) -> bool {
    let basename = Path::new(rel)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(rel);
    if basename == "crbs-build.sh" || basename == "profile.json" {
        return false;
    }
    let is_log = basename.ends_with(".log")
        || basename.contains(".log.")
        || rel
            .strip_prefix(CRBS_LOGS_DIR)
            .is_some_and(|rest| rest.starts_with('/'));
    !is_log || include_logs
}

/// 文件名是否为 debuginfo/debugsource 包（`-debuginfo-` / `-debugsource-`
/// 精确 token，远程与本地下载共用同一过滤口径）。刻意不含裸 `-debug-`：
/// 调试子包仅这两种命名，裸子串会把 kernel-debug 类真实风味包在默认下载中
/// 误剔（需 --debuginfo 才能下载）。
pub(crate) fn is_debug_package(name: &str) -> bool {
    name.contains("-debuginfo-") || name.contains("-debugsource-")
}

/// 将 HTTP 响应体按字节流写到 stdout。
///
/// - 404 视为"尚无内容"，直接返回 Ok；
/// - 非 2xx 读取 body 后 bail；
/// - 2xx 用 `bytes_stream()` 分块输出，支持 `cancel_token` 提前终止。
pub(crate) async fn stream_response_to_stdout(
    resp: reqwest::Response,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        // 日志文件尚未生成是正常路径（构建早期），404 视为"暂无内容"。
        return Ok(());
    }
    if !status.is_success() {
        let body = resp
            .text()
            .await
            .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
        return Err(http_status_error("logs stream", status, &body).into());
    }

    let mut stdout = tokio::io::stdout();
    let mut stream = resp.bytes_stream();
    loop {
        let chunk = tokio::select! {
            _ = async {
                if let Some(t) = cancel_token {
                    t.cancelled().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => break,
            Some(chunk) = stream.next() => chunk,
            else => break,
        };

        let chunk = chunk.map_err(|e| CrbsError::Network {
            message: format!("read log stream: {e}"),
        })?;
        if !chunk.is_empty() {
            stdout.write_all(&chunk).await.map_err(|e| CrbsError::Io {
                context: "write log chunk to stdout".into(),
                kind: e.kind(),
                detail: e.to_string(),
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SRPM 下载失败也按 basename 入去重集合：首架构失败后，其余架构的同名
    /// SRPM 直接跳过——不再重复请求、不再重复告警（失败不计 total_count）。
    #[tokio::test]
    async fn srpm_download_failure_not_retried_across_arches() {
        use crbs_core::types::ChildBuildSummary;
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 两个架构子构建各报一份同名 SRPM 清单（hub 真实布局）。
        for id in [1, 2] {
            Mock::given(method("GET"))
                .and(path_regex(format!("/api/v1/public/builds/{id}/artifacts")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "rpms": [],
                    "srpms": ["SRPMS/hello-1.0-1.src.rpm"],
                    "other": []
                })))
                .mount(&server)
                .await;
        }
        // SRPM 拉取恒 403（产品禁下载/角色不足）；expect(1) 钉住第二架构不再重试。
        Mock::given(method("GET"))
            .and(path_regex(r"/api/v1/builds/\d+/artifacts/download"))
            .and(query_param("file", "SRPMS/hello-1.0-1.src.rpm"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .expect(1)
            .mount(&server)
            .await;

        let builds: Vec<ChildBuildSummary> = [("x86_64", 1), ("aarch64", 2)]
            .into_iter()
            .map(|(arch, id)| ChildBuildSummary {
                id,
                arch: arch.to_string(),
                phase: "succeeded".to_string(),
                result_dir: None,
                started_at: None,
                duration: None,
                worker: None,
            })
            .collect();

        let tmp = tempfile::tempdir().unwrap();
        let target = RemoteTarget::new(server.uri(), None, None);
        let options = DownloadArtifactsOptions {
            include_srpm: true,
            ..Default::default()
        };
        let count = download_task_artifacts(&target, &builds, tmp.path(), &options, None)
            .await
            .unwrap();
        assert_eq!(count, 0, "failed SRPM downloads must not count");
        // 校验全部 mock 的 expect：SRPM 下载端点恰被命中 1 次。
        server.verify().await;
        assert!(!tmp
            .path()
            .join("SRPMS")
            .join("hello-1.0-1.src.rpm")
            .exists());
    }

    /// 产物已存在且未给 --force（用户可修正）——ValidationFailed（USAGE=4）。
    /// 变体 + 退出码 + 原文案三形态钉住（wiremock 模拟 server，dest 预置同名文件）。
    #[tokio::test]
    async fn download_existing_file_without_force_maps_to_validation_failed_exit_4() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/builds/9/artifacts/download"))
            .respond_with(ResponseTemplate::new(200).set_body_string("artifact-bytes"))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let dest_dir = tmp.path().join("rpms");
        tokio::fs::create_dir_all(&dest_dir)
            .await
            .expect("create dest dir");
        std::fs::write(dest_dir.join("hello.rpm"), b"old-bytes").expect("seed existing dest");

        let target = RemoteTarget::new(server.uri(), None, None);
        let err = download_artifact_to_dir(
            &target,
            9,
            "x86_64/hello.rpm",
            &dest_dir,
            "hello.rpm",
            false,
            None,
        )
        .await
        .expect_err("existing dest without --force must fail");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        let msg = format!("{ce}");
        assert!(
            msg.starts_with("validation failed: ")
                && msg.contains("file already exists:")
                && msg.contains("hello.rpm (use --force to overwrite)"),
            "original bail text must be preserved after the variant prefix: {msg}"
        );

        // --force 放行负例：直调生产函数覆盖 force=true 分支，断言预置旧内容确被响应体覆盖。
        download_artifact_to_dir(
            &target,
            9,
            "x86_64/hello.rpm",
            &dest_dir,
            "hello.rpm",
            true,
            None,
        )
        .await
        .expect("force overwrite must succeed");
        let dest = dest_dir.join("hello.rpm");
        assert_eq!(std::fs::read(&dest).expect("read dest"), b"artifact-bytes");
    }

    /// other 桶落盘相对路径：含 `/` 的（crbs-logs/ 下一切）原样保留子目录，
    /// 顶层条目维持 basename 扁平落盘。
    #[test]
    fn other_dest_rel_preserves_subdirs_for_crbs_logs() {
        assert_eq!(other_dest_rel("build.log"), "build.log");
        assert_eq!(other_dest_rel("crbs-logs/a.txt"), "crbs-logs/a.txt");
        assert_eq!(other_dest_rel("crbs-logs/sub/x"), "crbs-logs/sub/x");
    }

    /// crbs-logs/ 子路径落盘：crbs-logs/sub/build.log 与顶层 build.log 同名
    /// 并存、crbs-logs/a/x.txt 与 crbs-logs/b/x.txt 同名并存，均按相对子路径
    /// 分开落盘（basename 扁平化会冲突报错/静默覆盖）。
    #[tokio::test]
    async fn include_other_preserves_crbs_logs_subpaths() {
        use crbs_core::types::ChildBuildSummary;
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/api/v1/public/builds/1/artifacts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rpms": [],
                "srpms": [],
                "other": [
                    "build.log",
                    "crbs-logs/sub/build.log",
                    "crbs-logs/a/x.txt",
                    "crbs-logs/b/x.txt"
                ]
            })))
            .mount(&server)
            .await;
        // 同名四件：各按 file 参数回不同内容，落盘断言内容互异
        for (file, body) in [
            ("build.log", "top"),
            ("crbs-logs/sub/build.log", "in-sub"),
            ("crbs-logs/a/x.txt", "aa"),
            ("crbs-logs/b/x.txt", "bb"),
        ] {
            Mock::given(method("GET"))
                .and(path_regex(r"/api/v1/builds/\d+/artifacts/download"))
                .and(query_param("file", file))
                .respond_with(ResponseTemplate::new(200).set_body_string(body))
                .expect(1)
                .mount(&server)
                .await;
        }

        let builds: Vec<ChildBuildSummary> = vec![ChildBuildSummary {
            id: 1,
            arch: "x86_64".to_string(),
            phase: "succeeded".to_string(),
            result_dir: None,
            started_at: None,
            duration: None,
            worker: None,
        }];

        let tmp = tempfile::tempdir().unwrap();
        let target = RemoteTarget::new(server.uri(), None, None);
        let options = DownloadArtifactsOptions {
            include_logs: true,
            include_other: true,
            ..Default::default()
        };
        let count = download_task_artifacts(&target, &builds, tmp.path(), &options, None)
            .await
            .unwrap();
        assert_eq!(count, 4);
        server.verify().await;

        let base = tmp.path().join("x86_64");
        assert_eq!(
            std::fs::read_to_string(base.join("build.log")).unwrap(),
            "top"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("crbs-logs/sub/build.log")).unwrap(),
            "in-sub"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("crbs-logs/a/x.txt")).unwrap(),
            "aa"
        );
        assert_eq!(
            std::fs::read_to_string(base.join("crbs-logs/b/x.txt")).unwrap(),
            "bb"
        );
    }

    /// 钉住 `is_debug_package` 只剔 debuginfo/debugsource：`kernel-debug` 类
    /// 真实风味包不得被裸 `-debug-` 子串在默认下载中误剔。
    #[test]
    fn is_debug_package_filters_only_debuginfo_and_debugsource() {
        assert!(is_debug_package("hello-debuginfo-1.0-1.x86_64.rpm"));
        assert!(is_debug_package("hello-debugsource-1.0-1.noarch.rpm"));
        assert!(!is_debug_package("kernel-debug-6.12.0-1.x86_64.rpm"));
        assert!(!is_debug_package(
            "kernel-debug-modules-6.12.0-1.x86_64.rpm"
        ));
        assert!(!is_debug_package("hello-1.0-1.x86_64.rpm"));
    }

    /// other 桶取舍：crbs-logs/ 约定目录文件与 *.log 同待遇——include_logs
    /// 真才下载；普通文件恒下载；crbs-build.sh / profile.json 恒跳过。
    #[test]
    fn other_bucket_filter_gates_logs_and_crbs_logs_dir() {
        // 普通文件与日志在两档 include_logs 下的取舍
        for include_logs in [false, true] {
            assert!(
                other_bucket_should_download("c.txt", include_logs),
                "non-log always downloads (include_logs={include_logs})"
            );
            assert_eq!(
                other_bucket_should_download("b.log", include_logs),
                include_logs,
                "top-level .log is log-gated (include_logs={include_logs})"
            );
            assert_eq!(
                other_bucket_should_download("crbs-logs/a.txt", include_logs),
                include_logs,
                "crbs-logs/ entry is log-gated regardless of extension (include_logs={include_logs})"
            );
            assert_eq!(
                other_bucket_should_download("crbs-logs/sub/rotate.log.1", include_logs),
                include_logs,
                "nested crbs-logs/ entry is log-gated (include_logs={include_logs})"
            );
        }
        // 内部文件恒跳过
        for rel in ["crbs-build.sh", "profile.json", "crbs-logs/profile.json"] {
            assert!(
                !other_bucket_should_download(rel, true),
                "{rel} must always be skipped"
            );
        }
    }

    /// 回归：rename 失败时必须清掉 `.part-<uuid>` 临时文件再返回错误。
    #[tokio::test]
    async fn save_response_body_cleans_part_tmp_when_rename_fails() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/artifact.rpm"))
            .respond_with(ResponseTemplate::new(200).set_body_string("artifact-bytes"))
            .mount(&server)
            .await;
        let resp = reqwest::get(format!("{}/artifact.rpm", server.uri()))
            .await
            .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("artifact.rpm");
        // dest 同名目录占用 → rename(file → 已存在目录) 失败（EISDIR/ENOTEMPTY）。
        std::fs::create_dir(&dest).unwrap();

        let err = save_response_body_to_file(resp, &dest, None)
            .await
            .expect_err("rename onto an existing directory must fail");
        assert!(
            format!("{err:#}").contains("rename temp file"),
            "unexpected error: {err:#}"
        );

        // 半截 `.part-<uuid>` 不得残留（占位目录本身仍在，属调用方环境）。
        let part_leftovers: Vec<std::ffi::OsString> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| n.to_string_lossy().starts_with("artifact.rpm.part-"))
            .collect();
        assert!(
            part_leftovers.is_empty(),
            "rename 失败后不得残留 .part-* 临时文件: {:?}",
            part_leftovers
        );
    }

    /// 服务器提供的产物相对路径：绝对路径与 `..` 分量必须拒绝（任意文件写原语）。
    /// `.` / `//` 分量被 `Path::components()` 规范化（内核同口径解析，无逃逸），放行。
    #[test]
    fn safe_server_rel_path_rejects_traversal() {
        use super::safe_server_rel_path;
        assert!(safe_server_rel_path("RPMS/x86_64/pkg-1.0.rpm").is_ok());
        assert!(safe_server_rel_path("pkg.rpm").is_ok());
        assert!(safe_server_rel_path("a/./b").is_ok());
        assert!(safe_server_rel_path("RPMS//pkg.rpm").is_ok());
        for evil in [
            "/etc/passwd",
            "../../etc/cron.d/x",
            "RPMS/../../escape",
            "",
            "../a",
            "a/..",
        ] {
            assert!(safe_server_rel_path(evil).is_err(), "must reject {evil:?}");
        }
    }

    /// 服务器提供的目录名（arch/product）：仅单个安全分量通过；`+`/`~` 等
    /// RPM 包名字符必须拒绝——pkg_name 的宽松口径在 `validate_pkg_name`，勿混用。
    #[test]
    fn safe_server_dir_component_rejects_traversal() {
        use super::safe_server_dir_component;
        for ok in ["x86_64", "aarch64", "noarch", "riscv64.fc40"] {
            assert!(safe_server_dir_component(ok).is_ok(), "{ok}");
        }
        for evil in [
            "..",
            ".",
            "a/b",
            "../x",
            "a b",
            "",
            "/x",
            "a\nb",
            "libstdc++",
            "1.0~rc1",
        ] {
            assert!(
                safe_server_dir_component(evil).is_err(),
                "must reject {evil:?}"
            );
        }
    }

    /// 净化失败归 Network（ENVIRONMENT=6）：数据源是 server 而非用户参数，
    /// USAGE(4) 的"修参数" hint 会误导排障。变体 + 退出码 + 文案逐字三形态钉住。
    #[test]
    fn safe_server_sanitization_failures_map_to_network_exit_6() {
        use super::{safe_server_dir_component, safe_server_rel_path, CrbsError};
        use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};

        let rel_err = safe_server_rel_path("/etc/passwd").unwrap_err();
        let ce = rel_err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert_eq!(
            ce.to_string(),
            r#"network error: server returned non-relative artifact path: "/etc/passwd""#
        );

        let unsafe_err = safe_server_rel_path("../escape").unwrap_err();
        let ce = unsafe_err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert_eq!(
            ce.to_string(),
            r#"network error: server returned unsafe artifact path: "../escape" (only plain relative components allowed)"#
        );

        let dir_err = safe_server_dir_component("a/b").unwrap_err();
        let ce = dir_err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert_eq!(
            ce.to_string(),
            r#"network error: server returned unsafe directory name: "a/b""#
        );
    }
}
