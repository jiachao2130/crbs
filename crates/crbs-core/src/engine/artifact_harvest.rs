// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建产物采集器（worker 净室外、hub 本地构建共享代码）；
//! 采集不改构建环境，crbs-artifacts.json 兼作磁盘 provenance 与 DB 数据源，
//! sha256 流式计算（大 RPM 不占内存）。

use crate::error::CrbsError;
use crate::state::artifacts::{ArtifactJsonEntry, ArtifactKind, ArtifactsJson};
use crate::util::split_nvr;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;

/// 构建日志自定义收集约定目录名（容器内即 /builddir/result/crbs-logs/）。
/// 构建期间任何脚本/hook 放入的文件，构建结束后随产物上传并登记为日志；
/// 仅收普通文件（不跟随 symlink），目录本身永不上传，缺失或为空时不可见。
pub const CRBS_LOGS_DIR: &str = "crbs-logs";

/// 自定义日志文件数上限：防构建脚本在 crbs-logs/ 下制造海量小文件拖垮
/// manifest/上传预算；超限截断并 warn，其余日志仍可正常上传。
const MAX_CRBS_LOG_FILES: usize = 10_000;

/// 递归收集 `base/crbs-logs/` 下全部普通文件（约定目录见 [`CRBS_LOGS_DIR`]），
/// 返回绝对路径、排序保证确定性，不跟随 symlink。
/// 跳过任何名为 `latest` 的条目（文件或目录）：与 [`collect_artifacts`] 的
/// latest 跳过对齐，收集侧不同步会上传 harvest 不登记的文件（hub 孤儿）。
/// 目录缺失/为空返回空 Vec——非 NotFound 读失败 warn 后按为空处理，不阻断。
pub async fn collect_crbs_logs_files(base: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![base.join(CRBS_LOGS_DIR)];

    'walk: while let Some(dir) = stack.pop() {
        let mut read_dir = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "crbs-logs scan failed");
                continue;
            }
        };
        while let Ok(Some(ent)) = read_dir.next_entry().await {
            // latest（文件或目录）跳过，同 collect_recursive 口径
            if ent.file_name() == std::ffi::OsStr::new("latest") {
                continue;
            }
            let p = ent.path();
            let file_type = match ent.file_type().await {
                Ok(ft) => ft,
                Err(e) => {
                    tracing::warn!(path = %p.display(), error = %e, "crbs-logs entry type check failed");
                    continue;
                }
            };
            if file_type.is_dir() {
                stack.push(p);
            } else if file_type.is_file() {
                files.push(p);
                if files.len() >= MAX_CRBS_LOG_FILES {
                    tracing::warn!(
                        dir = %dir.display(),
                        limit = MAX_CRBS_LOG_FILES,
                        "crbs-logs file cap reached; truncating custom log collection"
                    );
                    break 'walk;
                }
            }
        }
    }

    files.sort();
    files
}

/// 按相对路径分类 artifact 类型（规则表，自上而下先中先生效）。
/// arch 事实源是目录布局：`RPMS/<arch>/` 取中间目录名、SRPMS 固定 `src`、
/// 布局外 rpm 为 None，文件名 NEVRA 后缀不参与判定。
pub fn classify(relative_path: &str) -> (ArtifactKind, Option<String>) {
    let path = Path::new(relative_path);

    // 约定目录 crbs-logs/ 前缀强制 Log（先于扩展名/布局判定）：非 .log 命名
    //（如 dmesg.txt）也归日志；顶层同名单文件不属目录内，不受此规则影响。
    if relative_path
        .strip_prefix(CRBS_LOGS_DIR)
        .is_some_and(|rest| rest.starts_with('/'))
    {
        return (ArtifactKind::Log, None);
    }

    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    if ext == "rpm" {
        // .src.rpm 须先于 RPMS/<arch> 分支判定，否则 `RPMS/src/*.src.rpm`
        // 会被中间目录误分类为 Rpm+arch="src"。
        if path.to_string_lossy().ends_with(".src.rpm")
            || path.parent().and_then(|p| p.file_name()) == Some(std::ffi::OsStr::new("SRPMS"))
        {
            return (ArtifactKind::Srpm, Some("src".to_string()));
        }
        if let Some(parent2) = path.parent().and_then(|p| p.parent()) {
            if parent2.file_name() == Some(std::ffi::OsStr::new("RPMS")) {
                if let Some(arch_dir) = path.parent().and_then(|p| p.file_name()) {
                    let arch = arch_dir.to_string_lossy().to_string();
                    return (ArtifactKind::Rpm, Some(arch));
                }
            }
        }
        return (ArtifactKind::Rpm, None);
    }

    if ext == "log" {
        return (ArtifactKind::Log, None);
    }

    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        if name == "profile.json" || name == "build_packages.json" {
            return (ArtifactKind::Metadata, None);
        }
        if name == "crbs-build.sh" {
            return (ArtifactKind::Script, None);
        }
    }

    (ArtifactKind::Other, None)
}

/// split_nvr 三元组带形状校验：version/release 任一为空（无 N-V-R 形状）即
/// 整体 None，SRPM 与带 arch 的 rpm 两条剥离路径共用。
fn split_nvr_or_none(stem: &str) -> (Option<String>, Option<String>, Option<String>) {
    let (name, version, release) = split_nvr(stem);
    if version.is_empty() || release.is_empty() {
        (None, None, None)
    } else {
        (
            Some(name.to_string()),
            Some(version.to_string()),
            Some(release.to_string()),
        )
    }
}

/// 从文件名解析 NEVRA（仅 RPM/SRPM；非 RPM 或解析失败返回全 None）。
/// 入参必须是裸文件名（不含目录分量），持有路径先 `Path::file_name()`。
pub fn parse_nevra(filename: &str) -> (Option<String>, Option<String>, Option<String>) {
    let is_srpm = filename.ends_with(".src.rpm");
    let stem = if is_srpm {
        filename.strip_suffix(".src.rpm")
    } else {
        filename.strip_suffix(".rpm")
    };
    match stem {
        None => (None, None, None),
        Some(stem) => {
            if is_srpm {
                split_nvr_or_none(stem)
            } else {
                let stem_no_arch = stem.rsplit_once('.').map(|(s, _)| s).unwrap_or(stem);
                split_nvr_or_none(stem_no_arch)
            }
        }
    }
}

/// 流式计算文件 SHA256 + 文件大小；分块读不占内存（RPM 可达 GB 级）。
pub async fn sha256_file_with_size(path: &Path) -> crate::Result<(String, u64)> {
    let mut file = File::open(path).await.map_err(|e| CrbsError::Io {
        context: format!("open for sha256 {}", path.display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    let metadata = file.metadata().await.map_err(|e| CrbsError::Io {
        context: format!("metadata for sha256 {}", path.display()),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    let size = metadata.len();

    let mut reader = BufReader::new(&mut file);
    let mut hasher = Sha256::new();

    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await.map_err(|e| CrbsError::Io {
            context: format!("read for sha256 {}", path.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let result = hasher.finalize();
    Ok((format!("{:x}", result), size))
}

/// 流式计算文件 SHA256。
pub async fn sha256_file(path: &Path) -> crate::Result<String> {
    sha256_file_with_size(path).await.map(|(sha, _)| sha)
}

/// 目录下的 .rpm 清单（本层 + 一层子目录，`RPMS/{arch}/*.rpm` 布局）：排序
/// 返回，选择确定。目录缺失/无 .rpm 返回空；非 NotFound 读失败 warn 留痕
///（如 EACCES，与"无产物"区分）。
pub async fn rpms_under(dir: &Path) -> Vec<PathBuf> {
    let mut rpms: Vec<PathBuf> = Vec::new();
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return rpms,
        Err(e) => {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "rpm scan failed"
            );
            return rpms;
        }
    };
    while let Ok(Some(ent)) = rd.next_entry().await {
        let p = ent.path();
        if p.extension().is_some_and(|x| x.to_str() == Some("rpm")) {
            rpms.push(p);
        } else if let Ok(mut rd2) = tokio::fs::read_dir(&p).await {
            while let Ok(Some(ent2)) = rd2.next_entry().await {
                let p2 = ent2.path();
                if p2.extension().is_some_and(|x| x.to_str() == Some("rpm")) {
                    rpms.push(p2);
                }
            }
        }
    }
    rpms.sort();
    rpms
}

/// 采集 result_dir 下所有产物，写入 crbs-artifacts.json。
/// 遍历不跟随 symlink、latest 不入行、只认普通文件；epoch 用宿主
/// `rpm -qp --queryformat '%{EPOCHNUM}'` 采集，失败/无 rpm 命令 → warning + NULL；
/// cancel/超时先触发者终止 rpm 查询，任一失败路径降级 None + warning 不影响整体。
pub async fn collect_artifacts(
    result_dir: &Path,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<ArtifactsJson> {
    let mut entries = Vec::new();
    collect_recursive(result_dir, &mut entries).await?;

    let mut artifacts = Vec::with_capacity(entries.len());

    const HARVEST_CONCURRENCY: usize = 4;
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(HARVEST_CONCURRENCY));
    let mut set = tokio::task::JoinSet::new();
    for (relative_path, abs_path) in entries {
        if relative_path == "crbs-artifacts.json" {
            continue;
        }
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| CrbsError::io_message(format!("acquire harvest semaphore: {e}")))?;
        let cancel = cancel_token.cloned();
        set.spawn(async move {
            let _permit = permit;
            let (kind, arch) = classify(&relative_path);
            let filename = Path::new(&relative_path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let (name, version, release) = parse_nevra(filename);

            let (sha256, size) = sha256_file_with_size(&abs_path).await?;

            let epoch = if matches!(kind, ArtifactKind::Rpm | ArtifactKind::Srpm) {
                extract_epoch(&abs_path, cancel.as_ref()).await
            } else {
                None
            };

            Ok::<_, CrbsError>(ArtifactJsonEntry {
                path: relative_path,
                kind: kind.as_str().to_string(),
                size,
                sha256,
                arch,
                name,
                version,
                release,
                epoch,
            })
        });
    }
    // 单条目失败（ENOENT 竞态、EACCES）降级 warn+skip 而非整体失败——
    // 避免成功构建整体丢失 artifacts 元数据；下游 url_map/provenance 容忍缺失。
    let mut skipped = 0usize;
    while let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(entry)) => artifacts.push(entry),
            Ok(Err(e)) => {
                skipped += 1;
                tracing::warn!(error = %e, "artifact harvest: skipping unreadable entry");
            }
            Err(e) => {
                return Err(CrbsError::io_message(format!("harvest task panicked: {e}")));
            }
        }
    }
    if skipped > 0 {
        tracing::error!(
            skipped,
            collected = artifacts.len(),
            "artifact harvest degraded: some entries missing from metadata"
        );
    }
    // 成功构建零 RPM 采集几乎必然是采集面问题（symlink 全跳过、布局变化），告警防静默空元数据。
    if !artifacts.is_empty()
        && !artifacts
            .iter()
            .any(|a| matches!(a.kind.as_str(), "rpm" | "srpm"))
    {
        tracing::error!(
            count = artifacts.len(),
            "artifact harvest collected no RPM/SRPM entries for a build result dir"
        );
    }

    // 按路径排序保证 JSON 输出确定性。
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ArtifactsJson {
        version: 1,
        build_id: None, // 调用方填充
        artifacts,
    })
}

/// 深度优先迭代遍历 result_dir，收集 (relative_path, abs_path) 对；
/// 不跟随 symlink、跳过 latest、只返普通文件。Vec 作栈避免 async fn 递归 boxing。
async fn collect_recursive(base: &Path, entries: &mut Vec<(String, PathBuf)>) -> crate::Result<()> {
    let mut stack = vec![base.to_path_buf()];

    while let Some(current) = stack.pop() {
        let mut read_dir = tokio::fs::read_dir(&current)
            .await
            .map_err(|e| CrbsError::Io {
                context: format!("read dir {}", current.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| CrbsError::Io {
            context: format!("read dir entry {}", current.display()),
            kind: e.kind(),
            detail: e.to_string(),
        })? {
            let path = entry.path();
            let file_type = entry.file_type().await.map_err(|e| CrbsError::Io {
                context: format!("file type {}", path.display()),
                kind: e.kind(),
                detail: e.to_string(),
            })?;

            if file_type.is_symlink() {
                continue;
            }

            if file_type.is_dir() {
                // latest 通常是 symlink 指向最新构建，跳过其内文件
                if let Some(dir_name) = path.file_name() {
                    if dir_name == "latest" {
                        continue;
                    }
                }
                stack.push(path);
            } else if file_type.is_file() {
                // latest 文件同规则跳过
                if let Some(filename) = path.file_name() {
                    if filename == "latest" {
                        continue;
                    }
                }
                let rel = path.strip_prefix(base).map_err(|_| CrbsError::Io {
                    context: "path not under base directory".to_string(),
                    kind: std::io::ErrorKind::InvalidInput,
                    detail: format!("path {} not under base {}", path.display(), base.display()),
                })?;
                entries.push((rel.to_string_lossy().to_string().replace('\\', "/"), path));
            }
        }
    }

    Ok(())
}

/// 尝试用宿主 rpm 命令提取 RPM 的 epoch；失败/非 RPM/无命令 → None + warning。
/// cancel/60s 超时兜底：停滞存储上挂死的单包查询不得拖住整个采集 future。
/// `%{EPOCHNUM}` 归一（纯函数，生产与测试共用）：`"(none)"`/空/`"0"`（无
/// epoch 的包）统一 None；其余按 i64 解析，parse 失败 None（调用方 warn 区分）。
fn normalize_epoch(trimmed: &str) -> Option<i64> {
    if trimmed == "(none)" || trimmed.is_empty() || trimmed == "0" {
        None
    } else {
        trimmed.parse::<i64>().ok()
    }
}

async fn extract_epoch(path: &Path, cancel_token: Option<&CancellationToken>) -> Option<i64> {
    use tokio::process::Command;
    let mut cmd = Command::new("rpm");
    cmd.args(["-qp", "--queryformat", "%{EPOCHNUM}"]).arg(path);
    let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qp EPOCHNUM",
        cancel_token,
        std::time::Duration::from_secs(60),
    )
    .await;

    match output {
        Ok(out) if out.status.success() => {
            let trimmed = String::from_utf8_lossy(&out.stdout).trim().to_string();
            match normalize_epoch(&trimmed) {
                Some(epoch) => Some(epoch),
                None => {
                    // 归一三形态之外的 None 是 parse 失败（损坏头）：warn 留痕。
                    if trimmed != "(none)" && !trimmed.is_empty() && trimmed != "0" {
                        tracing::warn!(path = %path.display(), value = %trimmed, "epoch parse failed");
                    }
                    None
                }
            }
        }
        Ok(out) => {
            tracing::warn!(
                path = %path.display(),
                status = %out.status,
                stderr_tail = %String::from_utf8_lossy(&out.stderr),
                "rpm command failed"
            );
            None
        }
        Err(e) => {
            // Err 臂承接超时/取消等全部执行失败，不限于 spawn 失败
            tracing::warn!(path = %path.display(), err = ?e, "epoch query failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_path() {
        let (kind, arch) = classify("RPMS/x86_64/hello-1.0-1.x86_64.rpm");
        assert!(matches!(kind, ArtifactKind::Rpm));
        assert_eq!(arch.as_deref(), Some("x86_64"));

        let (kind, arch) = classify("SRPMS/hello-1.0-1.src.rpm");
        assert!(matches!(kind, ArtifactKind::Srpm));
        assert_eq!(arch.as_deref(), Some("src"));

        let (kind, arch) = classify("build.log");
        assert!(matches!(kind, ArtifactKind::Log));
        assert!(arch.is_none());

        let (kind, arch) = classify("profile.json");
        assert!(matches!(kind, ArtifactKind::Metadata));
        assert!(arch.is_none());

        let (kind, arch) = classify("crbs-build.sh");
        assert!(matches!(kind, ArtifactKind::Script));
        assert!(arch.is_none());

        let (kind, arch) = classify("random.file");
        assert!(matches!(kind, ArtifactKind::Other));
        assert!(arch.is_none());

        // 约定目录 crbs-logs/ 强制 Log：非 .log 命名也归日志（下载侧按日志门控）
        let (kind, arch) = classify("crbs-logs/dmesg.txt");
        assert!(matches!(kind, ArtifactKind::Log));
        assert!(arch.is_none());

        let (kind, _) = classify("crbs-logs/sub/inner.log");
        assert!(matches!(kind, ArtifactKind::Log));

        // 顶层同名单文件不属约定目录
        let (kind, _) = classify("crbs-logs");
        assert!(matches!(kind, ArtifactKind::Other));
    }

    #[test]
    fn test_parse_nevra() {
        let (name, version, release) = parse_nevra("hello-1.0-1.x86_64.rpm");
        assert_eq!(name.as_deref(), Some("hello"));
        assert_eq!(version.as_deref(), Some("1.0"));
        assert_eq!(release.as_deref(), Some("1"));

        // 包名含连字符
        let (name, version, release) = parse_nevra("kernel-devel-5.4.0-1.x86_64.rpm");
        assert_eq!(name.as_deref(), Some("kernel-devel"));
        assert_eq!(version.as_deref(), Some("5.4.0"));
        assert_eq!(release.as_deref(), Some("1"));

        let (name, version, release) = parse_nevra("hello-1.0-1.src.rpm");
        assert_eq!(name.as_deref(), Some("hello"));
        assert_eq!(version.as_deref(), Some("1.0"));
        assert_eq!(release.as_deref(), Some("1"));

        let (name, version, release) = parse_nevra("build.log");
        assert!(name.is_none());
        assert!(version.is_none());
        assert!(release.is_none());

        // 格式不正确（无版本/发行）
        let (name, version, release) = parse_nevra("justname.rpm");
        assert!(name.is_none());
        assert!(version.is_none());
        assert!(release.is_none());
    }

    #[tokio::test]
    async fn test_sha256_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        tokio::fs::write(&file, b"hello world").await.unwrap();

        let hash = sha256_file(&file).await.unwrap();
        // echo -n "hello world" | sha256sum
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[tokio::test]
    async fn test_collect_artifacts_basic() {
        let tmp = tempfile::tempdir().unwrap();

        tokio::fs::create_dir_all(tmp.path().join("RPMS/x86_64"))
            .await
            .unwrap();
        tokio::fs::write(
            tmp.path().join("RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
            b"fake rpm content",
        )
        .await
        .unwrap();
        tokio::fs::write(tmp.path().join("build.log"), b"build log content")
            .await
            .unwrap();

        let result = collect_artifacts(tmp.path(), None).await.unwrap();

        assert_eq!(result.version, 1);
        assert_eq!(result.artifacts.len(), 2);

        let paths: Vec<&str> = result.artifacts.iter().map(|a| a.path.as_str()).collect();
        assert!(paths.contains(&"RPMS/x86_64/hello-1.0-1.x86_64.rpm"));
        assert!(paths.contains(&"build.log"));

        let rpm = result
            .artifacts
            .iter()
            .find(|a| a.path.ends_with(".rpm"))
            .unwrap();
        assert_eq!(rpm.name.as_deref(), Some("hello"));
        assert_eq!(rpm.version.as_deref(), Some("1.0"));
        assert_eq!(rpm.release.as_deref(), Some("1"));
        assert_eq!(rpm.arch.as_deref(), Some("x86_64"));
        assert_eq!(rpm.size, 16);
    }

    #[tokio::test]
    async fn test_collect_artifacts_skips_latest_symlink() {
        let tmp = tempfile::tempdir().unwrap();

        tokio::fs::write(tmp.path().join("build.log"), b"log")
            .await
            .unwrap();

        tokio::fs::create_dir_all(tmp.path().join("latest"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("latest/build.log"), b"should be skipped")
            .await
            .unwrap();

        let result = collect_artifacts(tmp.path(), None).await.unwrap();

        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].path, "build.log");
    }

    #[tokio::test]
    async fn test_collect_artifacts_nested_directories() {
        let tmp = tempfile::tempdir().unwrap();

        tokio::fs::create_dir_all(tmp.path().join("a/b/c"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("a/b/c/deep.log"), b"deep content")
            .await
            .unwrap();

        let result = collect_artifacts(tmp.path(), None).await.unwrap();

        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(result.artifacts[0].path, "a/b/c/deep.log");
    }

    /// crbs-logs 收集：递归收普通文件（不限扩展名）、跳 symlink 与 latest
    /// 条目（文件或目录）；目录缺失/为空零条目；约定目录外的文件不受影响。
    #[tokio::test]
    async fn test_collect_crbs_logs_files_variants() {
        let dir = tempfile::tempdir().unwrap();

        // 目录不存在：零条目、零报错
        assert!(collect_crbs_logs_files(dir.path()).await.is_empty());

        // 空目录：零条目
        tokio::fs::create_dir(dir.path().join(CRBS_LOGS_DIR))
            .await
            .unwrap();
        assert!(collect_crbs_logs_files(dir.path()).await.is_empty());

        tokio::fs::write(dir.path().join("build.log"), b"top-level log")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join(format!("{CRBS_LOGS_DIR}/a.log")), b"a")
            .await
            .unwrap();
        tokio::fs::create_dir(dir.path().join(format!("{CRBS_LOGS_DIR}/sub")))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join(format!("{CRBS_LOGS_DIR}/sub/b.txt")), b"b")
            .await
            .unwrap();
        tokio::fs::symlink(
            dir.path().join(format!("{CRBS_LOGS_DIR}/a.log")),
            dir.path().join(format!("{CRBS_LOGS_DIR}/link.txt")),
        )
        .await
        .unwrap();
        // latest 文件与 latest 目录（含内部文件）都跳过
        tokio::fs::write(dir.path().join(format!("{CRBS_LOGS_DIR}/latest")), b"x")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(format!("{CRBS_LOGS_DIR}/nd/latest")))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path()
                .join(format!("{CRBS_LOGS_DIR}/nd/latest/inner.log")),
            b"i",
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join(format!("{CRBS_LOGS_DIR}/nd/keep.log")),
            b"k",
        )
        .await
        .unwrap();

        let files = collect_crbs_logs_files(dir.path()).await;
        let rels: Vec<String> = files
            .iter()
            .map(|p| {
                p.strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(
            rels,
            vec![
                format!("{CRBS_LOGS_DIR}/a.log"),
                format!("{CRBS_LOGS_DIR}/nd/keep.log"),
                format!("{CRBS_LOGS_DIR}/sub/b.txt"),
            ],
            "must collect plain files recursively, skip symlinks and latest entries"
        );
    }

    #[test]
    fn test_epoch_zero_normalization() {
        // %{EPOCHNUM} 归一口径："(none)"/""/"0" → None（直测生产函数，
        // 防手抄副本随生产漂移）。
        for case in ["(none)", "", "0"] {
            assert_eq!(
                normalize_epoch(case),
                None,
                "case '{case}' should normalize to None"
            );
        }
        for case in ["1", "10", "42"] {
            assert!(
                normalize_epoch(case).is_some(),
                "case '{case}' should not normalize"
            );
        }
    }
}
