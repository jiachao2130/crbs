// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

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

/// 校验服务器提供的产物相对路径可安全拼接进本地下载目录：必须相对，且每个分量都是 Normal（拒绝 `..`、`.`、绝对路径）。失败归
/// CrbsError::Network（ENVIRONMENT=6）——数据源是 server 而非用户参数，USAGE(4) 的"修参数"提示会误导排障。
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

/// 校验服务器提供的目录名（arch 等）是单个安全分量（字母数字与 _-.），防拼进本地路径后逃逸。失败归 Network，判定同上。
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

pub(crate) const DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

pub(crate) const LONG_BODY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

/// 把已确认 2xx 的响应体流式落盘到 dest：写入同目录临时文件后原子 rename，中断（Ctrl-C/超时）不留半截假完整文件；落盘即补权限不变量（0660 + crbs 组），
/// root 下载的 0644/root:root 会让组内身份 EACCES。chmod 失败仅 warn，chown 失败仅 debug。
async fn save_response_body_to_file(
    resp: reqwest::Response,
    dest: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let parent = dest
        .parent()
        .with_context(|| format!("artifact path has no parent dir: {}", dest.display()))?;

    let leaf = dest
        .file_name()
        .with_context(|| format!("artifact path has no file name: {}", dest.display()))?
        .to_string_lossy();
    let tmp_path = parent.join(format!("{leaf}.part-{}", uuid::Uuid::new_v4()));

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

#[derive(Clone, Debug, Default)]
pub struct DownloadArtifactsOptions {
    pub include_debuginfo: bool,

    pub include_logs: bool,

    pub include_srpm: bool,

    pub include_other: bool,

    pub force: bool,
}

/// 下载某个远程任务的所有子构建产物到本地目录：{base}/{arch}/ 放架构相关 RPM 与 other 文件，{base}/SRPMS/ 放跨架构共享的源码包。
pub async fn download_task_artifacts(
    target: &RemoteTarget,
    builds: &[crbs_core::types::ChildBuildSummary],
    base_local_dir: &Path,
    options: &DownloadArtifactsOptions,
    cancel: Option<&CancellationToken>,
) -> Result<usize> {
    let mut total_count = 0usize;
    let mut downloaded_srpm_basenames: HashSet<String> = HashSet::new();

    let srpm_dir = base_local_dir.join("SRPMS");

    for build in builds {
        if !crbs_core::types::build_phase_is_terminal(&build.phase) {
            continue;
        }

        let arch = if build.arch.is_empty() {
            "unknown"
        } else {
            safe_server_dir_component(build.arch.as_str())?
        };

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
                        downloaded_srpm_basenames.insert(basename.to_string());

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

async fn download_artifact_to_dir(
    target: &RemoteTarget,
    build_id: i64,
    rel_path: &str,
    dest_dir: &Path,
    dest_name: &str,
    force: bool,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
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

pub(crate) fn is_debug_package(name: &str) -> bool {
    name.contains("-debuginfo-") || name.contains("-debugsource-")
}

pub(crate) async fn stream_response_to_stdout(
    resp: reqwest::Response,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
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

    #[tokio::test]
    async fn srpm_download_failure_not_retried_across_arches() {
        use crbs_core::types::ChildBuildSummary;
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

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

        server.verify().await;
        assert!(!tmp
            .path()
            .join("SRPMS")
            .join("hello-1.0-1.src.rpm")
            .exists());
    }

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

    #[test]
    fn other_dest_rel_preserves_subdirs_for_crbs_logs() {
        assert_eq!(other_dest_rel("build.log"), "build.log");
        assert_eq!(other_dest_rel("crbs-logs/a.txt"), "crbs-logs/a.txt");
        assert_eq!(other_dest_rel("crbs-logs/sub/x"), "crbs-logs/sub/x");
    }

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

    #[test]
    fn other_bucket_filter_gates_logs_and_crbs_logs_dir() {
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

        for rel in ["crbs-build.sh", "profile.json", "crbs-logs/profile.json"] {
            assert!(
                !other_bucket_should_download(rel, true),
                "{rel} must always be skipped"
            );
        }
    }

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

        std::fs::create_dir(&dest).unwrap();

        let err = save_response_body_to_file(resp, &dest, None)
            .await
            .expect_err("rename onto an existing directory must fail");
        assert!(
            format!("{err:#}").contains("rename temp file"),
            "unexpected error: {err:#}"
        );

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
