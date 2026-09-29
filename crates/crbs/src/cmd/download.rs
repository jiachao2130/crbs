// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! download 子命令：按任务拉取产物、源码/debuginfo/日志。

use anyhow::{Context, Result};
use crbs_core::engine::artifact_harvest::collect_crbs_logs_files;
use crbs_core::error::CrbsError;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;
use tracing::info;

pub(crate) struct DownloadArgs {
    pub task: String,
    pub output_dir: Option<PathBuf>,
    pub src: bool,
    pub debuginfo: bool,
    pub logs: bool,
    pub arches: Vec<String>,
    pub force: bool,
    pub remote: Option<String>,
    pub token: Option<String>,
    pub local: bool,
    pub format: crate::cli::OutputFormat,
}

/// `crbs download` 统一输出，本地（copied/found）与远程（downloaded）共用：
/// `mode` 同时驱动 text 措辞与 json 语义，`paths` 仅本地有（远程接口只回计数）。
#[derive(serde::Serialize)]
struct DownloadOutput {
    /// 成功信封 command（与 json_error_contract 同源）。
    command: &'static str,
    task_id: i64,
    artifact_count: usize,
    /// 产物落地/所在目录（copy 目标 / result_dir / 下载保存目录）。
    output_dir: String,
    /// "copied" | "found" | "downloaded"
    mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    paths: Option<Vec<String>>,
}

impl crate::cli::CommandOutput for DownloadOutput {
    fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn print_text(&self) {
        match self.mode {
            "copied" => println!(
                "Copied {} artifact(s) for task {} to {}",
                self.artifact_count, self.task_id, self.output_dir
            ),
            "found" => println!(
                "Found {} artifact(s) for task {} at {}",
                self.artifact_count, self.task_id, self.output_dir
            ),
            _ => println!(
                "Downloaded {} artifact(s) for remote task {} (saved to {})",
                self.artifact_count, self.task_id, self.output_dir
            ),
        }
    }
}

/// 校验 --output-dir：禁路径穿越、存在须为目录；参数误用走 `ValidationFailed`（USAGE=4）不落 INTERNAL(1)。
fn validate_output_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "output_dir cannot be empty".into(),
        }
        .into());
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!(
                "output_dir cannot contain '..' traversal: {}",
                path.display()
            ),
        }
        .into());
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "output_dir cannot contain NUL byte".into(),
        }
        .into());
    }
    if path.exists() && !path.is_dir() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: format!(
                "output_dir exists but is not a directory: {}",
                path.display()
            ),
        }
        .into());
    }
    Ok(())
}

/// 子构建 arch → 本地落盘子目录名。服务器/DB 数据不可信：必须是单个安全
/// 分量（与远程下载 remote::download_task_artifacts 同口径）；缺失记 "unknown"。
fn arch_subdir(arch: Option<&str>) -> Result<String> {
    match arch {
        None | Some("") => Ok("unknown".to_string()),
        Some(a) => Ok(crate::remote::safe_server_dir_component(a)?.to_string()),
    }
}

/// 本地 --logs 收集清单：result_dir 顶层 *.log / *.log.*（engine 把 build.log
/// 写在其根，见 engine/build/execution.rs；顶层沿用跟随 symlink 的 metadata
/// 语义）+ crbs-logs/ 约定目录经共享收集器递归全部普通文件（不限扩展名、
/// 跳 symlink 与 latest，见 [`collect_crbs_logs_files`]）。约定目录缺失/为空
/// 零条目，目录本身不入清单；返回路径排序保证确定。
async fn collect_local_log_files(result_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();

    let mut entries = tokio::fs::read_dir(result_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let p = entry.path();
        // 顶层沿用 is_file 语义（跟随 symlink）
        if !tokio::fs::metadata(&p)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.ends_with(".log") || name.contains(".log.")) {
            continue;
        }
        out.push(p);
    }

    out.extend(collect_crbs_logs_files(result_dir).await);

    out.sort();
    Ok(out)
}

/// 下载构建产物到本地。本地模式按 task id 聚合全部终态子构建产物：无
/// --output-dir 仅定位输出清单，有则按 {output_dir}/{arch}/ + {output_dir}/SRPMS/
/// 拷贝（与远程下载同形）；远程模式从 server 下载到 {cwd}/{pkg_name}-{task_id}/（或 --output-dir）。
pub(crate) async fn handle_download(
    args: DownloadArgs,
    ctx: crbs_core::privilege::CallerContext,
    state: Option<&crbs_core::StateStore>,
) -> Result<()> {
    // --arches 值先过白名单：空白/`/`/`..` 等非法字符属参数误用，在 CLI 层带
    // 上下文报错退出（本地/远程两路共用入口，收口一处）。
    for arch in &args.arches {
        crbs_core::validation::validate_arch(arch)
            .with_context(|| format!("invalid --arches value {arch:?}"))?;
    }

    // Ctrl-C/SIGTERM 优雅取消：中断时清理半截文件，不留假完整产物。
    let cancel_token = crate::cmd::build::setup_cancel_token();
    let remote = args.remote.clone();
    let token = args.token.clone();
    if let Some(target) = crate::remote::resolve(remote, token, None, args.local).await? {
        handle_download_remote(&args, &target, Some(&cancel_token)).await
    } else {
        // 缺本地 StateStore 属调用误用——ValidationFailed（USAGE=4）。
        let state = crate::cmd::require_state_store(
            state,
            "state store required for local download; did you mean --remote?",
        )?;
        handle_download_local(args, ctx, state, Some(&cancel_token)).await
    }
}

async fn handle_download_local(
    args: DownloadArgs,
    ctx: crbs_core::privilege::CallerContext,
    state: &crbs_core::StateStore,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    if let Some(ref output_dir) = args.output_dir {
        validate_output_dir(output_dir)?;
    }

    // root 不限用户（与 logs/diff 同口径）。
    let user_filter = crate::cmd::visible_user_filter(&ctx);
    let task_id = state.resolve_task_id(&args.task, user_filter).await?;
    let mut children = state.get_builds_by_task_id(task_id).await?;
    // --arches 过滤子构建：空列表=不过滤；任务里不存在的架构静默忽略，由最终
    // 产物计数自然反映（与远程下载同口径）。
    if !args.arches.is_empty() {
        children.retain(|b| {
            b.arch
                .as_deref()
                .is_some_and(|a| args.arches.iter().any(|w| w == a))
        });
    }

    // 逐终态子构建收集（非终态产物未定型，同远程口径跳过；result_dir 缺失/被 GC 记日志跳过）。
    let mut collected: Vec<(PathBuf, String)> = Vec::new(); // (产物路径, 目的子路径)
    let mut srpm_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for build in &children {
        if !crbs_core::types::build_phase_is_terminal(&build.phase) {
            continue;
        }
        let Some(ref dir) = build.result_dir else {
            info!(
                task_id = %task_id,
                build_id = %build.id,
                "child build has no result_dir (GC'd?); skipped"
            );
            continue;
        };
        let result_dir = Path::new(dir);
        if !result_dir.exists() {
            info!(
                task_id = %task_id,
                build_id = %build.id,
                path = %result_dir.display(),
                "child build result_dir missing on disk; skipped"
            );
            continue;
        }
        let arch = arch_subdir(build.arch.as_deref())?;
        for rpm in crbs_core::util::collect_rpm_paths(result_dir, true).await? {
            let is_srpm = rpm
                .components()
                .any(|c| c.as_os_str() == std::ffi::OsStr::new("SRPMS"));
            if is_srpm {
                // --src 默认关：SRPM 不收集（与远程 include_srpm 同口径）。
                if !args.src {
                    continue;
                }
                // SRPM 架构无关：跨子构建按 basename 去重（远程同口径）。
                let basename = rpm
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !srpm_seen.insert(basename) {
                    continue;
                }
                collected.push((rpm, "SRPMS".to_string()));
            } else {
                // 未开 --debuginfo 时跳过 debuginfo 包（与远程同用 is_debug_package 判定）。
                let basename = rpm
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !args.debuginfo && crate::remote::is_debug_package(&basename) {
                    continue;
                }
                collected.push((rpm, arch.clone()));
            }
        }

        // --logs：顶层 *.log + 约定目录 crbs-logs/ 递归（见 collect_local_log_files），
        // 落 {output_dir}/{arch}/；无日志就不拷（不报错）。
        if args.logs {
            for p in collect_local_log_files(result_dir).await? {
                // 收集清单里带父目录的条目必属 crbs-logs/：按 result_dir 相对
                // 子路径落 {out}/{arch}/crbs-logs/...（子目录同名不互踩），
                // 顶层日志维持 {out}/{arch}/{basename}。
                let dest_sub = match p.strip_prefix(result_dir).ok().and_then(|rel| rel.parent()) {
                    Some(parent) if !parent.as_os_str().is_empty() => {
                        format!("{arch}/{}", parent.to_string_lossy())
                    }
                    _ => arch.clone(),
                };
                collected.push((p, dest_sub));
            }
        }
    }

    if collected.is_empty() {
        // 任务不存在属"未找到"语义——NotFound（USAGE=4），不落 INTERNAL(1)。
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!(
                "task {task_id} has no artifacts in terminal child builds (nothing to download)"
            ),
        }
        .into());
    }

    let count = collected.len();
    let output = if let Some(ref output_dir) = args.output_dir {
        for (path, sub) in &collected {
            let dest_dir = output_dir.join(sub);
            tokio::fs::create_dir_all(&dest_dir).await?;
            // 无文件名的输入 fail-closed，不生成空目标名：path 恒来自上方枚举（目录
            // join 文件名构造）必有 file_name，真触发即逻辑 bug，INTERNAL(1)（"this is a bug" hint）恰确。
            let name = path
                .file_name()
                .with_context(|| format!("rpm path has no file name: {}", path.display()))?;
            let dest = dest_dir.join(name);
            if !args.force && tokio::fs::try_exists(&dest).await.unwrap_or(false) {
                // 目标冲突是请求参数问题——ValidationFailed（USAGE=4）。
                return Err(crbs_core::error::CrbsError::ValidationFailed {
                    message: format!(
                        "file already exists: {} (use --force to overwrite)",
                        dest.display()
                    ),
                }
                .into());
            }
            // Ctrl-C 中断 copy：删半截目标文件再返回（dest 原不存在，或
            // --force 已授权覆盖，删除均正确），不留假完整产物。
            let copy_result = tokio::select! {
                _ = crbs_core::http_retry::wait_for_cancel(cancel) => {
                    let _ = tokio::fs::remove_file(&dest).await;
                    return Err(crbs_core::error::CrbsError::Cancelled.into());
                }
                r = tokio::fs::copy(path, &dest) => r,
            };
            copy_result?;
        }
        DownloadOutput {
            command: "download",
            task_id,
            artifact_count: count,
            output_dir: output_dir.display().to_string(),
            mode: "copied",
            paths: Some(
                collected
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect(),
            ),
        }
    } else {
        // found 只定位不拷贝：output_dir 取任务级 result_dir（子构建共同父级），缺失回退首个产物目录。
        let task_dir = state
            .get_task(task_id)
            .await
            .ok()
            .flatten()
            .and_then(|t| t.result_dir);
        let fallback = collected
            .first()
            .and_then(|(p, _)| p.parent().map(|d| d.display().to_string()))
            .unwrap_or_default();
        DownloadOutput {
            command: "download",
            task_id,
            artifact_count: count,
            output_dir: task_dir.unwrap_or(fallback),
            mode: "found",
            paths: Some(
                collected
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect(),
            ),
        }
    };
    args.format.print(&output)?;

    info!(
        task = %task_id,
        count = count,
        "local task artifacts"
    );
    Ok(())
}

/// pkg_name 来自远端任务记录（服务器数据不可信），拼路径前净化；失败属远端
/// 异常 → Network（ENVIRONMENT=6）不落 INTERNAL(1)。底层 `validate_pkg_name` 的
/// ValidationFailed 是本地输入语义（USAGE=4）不保真；文案逐字保留原 anyhow!。
fn validate_remote_pkg_name(pkg_name: &str) -> Result<()> {
    crbs_core::util::validate_pkg_name(pkg_name).map_err(|e| {
        CrbsError::Network {
            message: format!("server returned unsafe package name {pkg_name:?}: {e}"),
        }
        .into()
    })
}

async fn handle_download_remote(
    args: &DownloadArgs,
    target: &crate::remote::RemoteTarget,
    cancel: Option<&CancellationToken>,
) -> Result<()> {
    if let Some(ref output_dir) = args.output_dir {
        validate_output_dir(output_dir)?;
    }

    // task id 解析失败属参数误用——ValidationFailed（USAGE=4）不落 INTERNAL(1)；
    // 消息合串保留原 anyhow context 链完整可见文本。
    let task_id = crate::cmd::parse_task_id(&args.task)?;
    // 无 token profile 走 public 匿名受限端点（公开产品；门控在服务端），
    // 有 token 走常规认证链路——匿名下载与 Web 端体验对齐。
    let (pkg_name, mut builds) = if target.token.is_none() {
        let info = crate::remote::fetch_public_download_info(target, task_id, cancel).await?;
        (info.pkg_name, info.builds)
    } else {
        let detail = crate::remote::fetch_task_record(target, task_id, cancel).await?;
        (detail.task.pkg_name.clone(), detail.builds)
    };

    let base_local_dir = if let Some(ref dir) = args.output_dir {
        dir.clone()
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // pkg_name 不可信：不净化直接拼 cwd，被攻破 server 可用 `../` 让 CLI
        // （常 root）写穿目录树；默认路径不走 validate_output_dir，须拼路径前净化。
        validate_remote_pkg_name(&pkg_name)?;
        cwd.join(format!("{}-{}", pkg_name, task_id))
    };

    // --arches 过滤子构建：空列表=不过滤；任务里不存在的架构静默忽略，由最终
    // "Downloaded 0 artifact(s)" 计数自然反映（与本地下载同口径）。
    if !args.arches.is_empty() {
        builds.retain(|b| args.arches.iter().any(|a| a == &b.arch));
    }

    let options = crate::remote::DownloadArtifactsOptions {
        include_debuginfo: args.debuginfo,
        include_logs: args.logs,
        include_srpm: args.src,
        include_other: true,
        force: args.force,
    };
    let total_count =
        crate::remote::download_task_artifacts(target, &builds, &base_local_dir, &options, cancel)
            .await?;

    let output = DownloadOutput {
        command: "download",
        task_id,
        artifact_count: total_count,
        output_dir: base_local_dir.display().to_string(),
        mode: "downloaded",
        paths: None,
    };
    args.format.print(&output)?;

    info!(
        task = %task_id,
        count = total_count,
        path = %base_local_dir.display(),
        "download remote task artifacts"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CommandOutput as _;

    /// arch 落盘与远程下载同口径：缺失记 "unknown"，不安全分量报错而非拼进路径。
    #[test]
    fn arch_subdir_validates_untrusted_arch() {
        assert_eq!(arch_subdir(None).unwrap(), "unknown");
        assert_eq!(arch_subdir(Some("")).unwrap(), "unknown");
        assert_eq!(arch_subdir(Some("x86_64")).unwrap(), "x86_64");
        let err = arch_subdir(Some("../evil")).expect_err("traversal arch must be rejected");
        assert!(
            err.to_string().contains("unsafe directory name"),
            "unexpected message: {err}"
        );
    }

    /// 不安全 pkg_name（服务器数据不可信）→ Network（ENVIRONMENT=6）不落 INTERNAL(1)，不沿用底层 ValidationFailed（本地输入语义），文案逐字保留。
    #[test]
    fn remote_unsafe_pkg_name_maps_to_network() {
        let err = validate_remote_pkg_name("../evil").expect_err("traversal pkg must be rejected");
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::ENVIRONMENT
        );
        let msg = format!("{ce}");
        assert!(
            msg.contains(r#"server returned unsafe package name "../evil""#),
            "msg must be preserved verbatim: {msg}"
        );
        assert!(validate_remote_pkg_name("hello").is_ok());
    }

    #[test]
    fn download_output_json_roundtrip() {
        let out = DownloadOutput {
            command: "download",
            task_id: 42,
            artifact_count: 2,
            output_dir: "/tmp/out".to_string(),
            mode: "copied",
            paths: Some(vec![
                "/tmp/out/hello-1.0-1.x86_64.rpm".to_string(),
                "/tmp/out/hello-1.0-1.src.rpm".to_string(),
            ]),
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "download");
        assert_eq!(parsed["task_id"], 42);
        assert_eq!(parsed["artifact_count"], 2);
        assert_eq!(parsed["output_dir"], "/tmp/out");
        assert_eq!(parsed["mode"], "copied");
        assert_eq!(parsed["paths"][0], "/tmp/out/hello-1.0-1.x86_64.rpm");

        let out = DownloadOutput {
            command: "download",
            task_id: 7,
            artifact_count: 5,
            output_dir: "/tmp/hello-7".to_string(),
            mode: "downloaded",
            paths: None,
        };
        let parsed: serde_json::Value = serde_json::from_str(&out.to_json().unwrap()).unwrap();
        assert_eq!(parsed["command"], "download");
        assert_eq!(parsed["task_id"], 7);
        assert_eq!(parsed["artifact_count"], 5);
        assert_eq!(parsed["mode"], "downloaded");
        assert!(parsed.get("paths").is_none(), "None 字段应省略");
    }

    async fn tmp_store() -> (tempfile::TempDir, crbs_core::StateStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = crbs_core::StateStore::new(tmp.path()).await.unwrap();
        (tmp, store)
    }

    async fn insert_task(store: &crbs_core::StateStore) -> i64 {
        store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "tester",
                phase: "succeeded",
                ..Default::default()
            })
            .await
            .unwrap()
    }

    /// 造一个终态子构建：result_dir 下 RPMS/{arch}/ 一个 RPM + SRPMS/ 一个 SRPM。
    async fn insert_terminal_build(
        store: &crbs_core::StateStore,
        task_id: i64,
        arch: &str,
        base: &Path,
    ) -> i64 {
        let result_dir = base.join(format!("result-{arch}"));
        tokio::fs::create_dir_all(result_dir.join("RPMS").join(arch))
            .await
            .unwrap();
        tokio::fs::create_dir_all(result_dir.join("SRPMS"))
            .await
            .unwrap();
        tokio::fs::write(
            result_dir
                .join("RPMS")
                .join(arch)
                .join(format!("hello-1.0-1.{arch}.rpm")),
            b"rpm",
        )
        .await
        .unwrap();
        // 两个子构建放同名 SRPM（真实布局即跨 arch 共享同一源码包）。
        tokio::fs::write(
            result_dir.join("SRPMS").join("hello-1.0-1.src.rpm"),
            b"srpm",
        )
        .await
        .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(result_dir.to_str().unwrap()),
                backend: "chroot",
                user: "tester",
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    fn tester_ctx() -> crbs_core::privilege::CallerContext {
        crbs_core::privilege::CallerContext::new(
            crbs_core::privilege::CallerInfo {
                uid: 1000,
                gid: 1000,
                username: "tester".to_string(),
            },
            false,
        )
    }

    fn download_args(task: String, output_dir: Option<PathBuf>) -> DownloadArgs {
        DownloadArgs {
            task,
            output_dir,
            src: false,
            debuginfo: false,
            logs: false,
            arches: Vec::new(),
            force: false,
            remote: None,
            token: None,
            local: true,
            format: crate::cli::OutputFormat::Text,
        }
    }

    /// --logs 收集：顶层 *.log / *.log.* 与 crbs-logs/ 递归全部普通文件都收；
    /// 其它文件不入清单；crbs-logs 缺失时仅收顶层。
    #[tokio::test]
    async fn collect_local_log_files_top_level_and_crbs_logs() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("g.log"), b"g")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("rotate.log.1"), b"r")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("notes.txt"), b"no")
            .await
            .unwrap();

        let names = |files: &[PathBuf]| -> Vec<String> {
            let mut v: Vec<String> = files
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };

        // crbs-logs 缺失：仅顶层日志
        assert_eq!(
            names(&collect_local_log_files(dir.path()).await.unwrap()),
            vec!["g.log".to_string(), "rotate.log.1".to_string()],
            "non-log files must not be collected"
        );

        tokio::fs::create_dir_all(dir.path().join("crbs-logs/sub"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("crbs-logs/sub/f.txt"), b"f")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("crbs-logs/dmesg.txt"), b"d")
            .await
            .unwrap();

        assert_eq!(
            names(&collect_local_log_files(dir.path()).await.unwrap()),
            vec![
                "dmesg.txt".to_string(),
                "f.txt".to_string(),
                "g.log".to_string(),
                "rotate.log.1".to_string()
            ],
            "crbs-logs/ plain files must be collected regardless of extension"
        );
    }

    /// 本地 download 按 task id 聚合并镜像远程布局：RPM 落 {out}/{arch}/；
    /// SRPM 默认跳过，--src 开启后落 {out}/SRPMS/ 且跨子构建按名去重。
    #[tokio::test]
    async fn handle_download_local_copies_per_arch_with_srpm_dedup() {
        // 钉非 Helper 特权后端：防有 setuid helper 的宿主机上 config 加载把进程楔死成 Helper。
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store).await;
        insert_terminal_build(&store, task_id, "x86_64", _tmp.path()).await;
        insert_terminal_build(&store, task_id, "aarch64", _tmp.path()).await;

        let out = _tmp.path().join("out");
        handle_download(
            download_args(task_id.to_string(), Some(out.clone())),
            tester_ctx(),
            Some(&store),
        )
        .await
        .unwrap();

        assert!(out.join("x86_64/hello-1.0-1.x86_64.rpm").exists());
        assert!(out.join("aarch64/hello-1.0-1.aarch64.rpm").exists());
        // 默认 --src 关：SRPM 不收集，连 SRPMS 目录都不落。
        assert!(!out.join("SRPMS").exists());

        let out2 = _tmp.path().join("out2");
        let mut args = download_args(task_id.to_string(), Some(out2.clone()));
        args.src = true;
        handle_download(args, tester_ctx(), Some(&store))
            .await
            .unwrap();
        assert!(out2.join("SRPMS/hello-1.0-1.src.rpm").exists());
        assert_eq!(
            std::fs::read_dir(out2.join("SRPMS")).unwrap().count(),
            1,
            "SRPM must be deduplicated across child builds"
        );
    }

    /// --arches 过滤本地子构建：只收集白名单架构的产物；任务里不存在的架构
    /// 静默忽略（与远程同口径），未匹配任何架构时走 "no artifacts" 错误。
    #[tokio::test]
    async fn handle_download_local_arches_filter() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store).await;
        insert_terminal_build(&store, task_id, "x86_64", _tmp.path()).await;
        insert_terminal_build(&store, task_id, "aarch64", _tmp.path()).await;

        let out = _tmp.path().join("out");
        let mut args = download_args(task_id.to_string(), Some(out.clone()));
        args.arches = vec!["aarch64".to_string(), "riscv64".to_string()];
        handle_download(args, tester_ctx(), Some(&store))
            .await
            .unwrap();
        assert!(out.join("aarch64/hello-1.0-1.aarch64.rpm").exists());
        assert!(
            !out.join("x86_64").exists(),
            "filtered arch must not be copied"
        );

        // 白名单与任务架构零交集：无产物可下，报清晰错误（而非静默成功）。
        let mut args = download_args(task_id.to_string(), None);
        args.arches = vec!["riscv64".to_string()];
        let err = handle_download(args, tester_ctx(), Some(&store))
            .await
            .expect_err("arch filter matching nothing must fail");
        assert!(
            err.to_string()
                .contains("no artifacts in terminal child builds"),
            "unexpected message: {err}"
        );
    }

    /// found 模式（无 --output-dir）：聚合全部终态子构建的产物路径。
    #[tokio::test]
    async fn handle_download_local_found_mode_aggregates_children() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store).await;
        insert_terminal_build(&store, task_id, "x86_64", _tmp.path()).await;
        insert_terminal_build(&store, task_id, "aarch64", _tmp.path()).await;

        handle_download(
            download_args(task_id.to_string(), None),
            tester_ctx(),
            Some(&store),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn handle_download_local_not_found_shape() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let err = handle_download(
            download_args("424242".to_string(), None),
            tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("missing task must fail");
        assert!(
            err.to_string().contains("task 424242 not found"),
            "unexpected message: {err}"
        );
    }

    /// 任务存在但子构建均非终态：无产物可下，报清晰错误（而非静默成功）。
    #[tokio::test]
    async fn handle_download_local_no_terminal_children_bails() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        // 活跃子构建不能挂终态 task（insert_build 守卫），故 task 以 building phase 落库。
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "fedora",
                pkg_name: "hello",
                user: "tester",
                phase: "building",
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "building",
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let err = handle_download(
            download_args(task_id.to_string(), None),
            tester_ctx(),
            Some(&store),
        )
        .await
        .expect_err("no terminal children must fail");
        assert!(
            err.to_string()
                .contains("no artifacts in terminal child builds"),
            "unexpected message: {err}"
        );
    }

    /// --debuginfo/--logs：默认跳过 debuginfo 包；--logs 拷 result_dir 顶层 *.log
    /// 与 crbs-logs/ 条目到 {out}/{arch}/（crbs-logs/ 下按相对子路径落盘，与远程同口径）。
    #[tokio::test]
    async fn handle_download_local_debuginfo_filter_and_logs() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store).await;

        let result_dir = _tmp.path().join("result-x86_64");
        tokio::fs::create_dir_all(result_dir.join("RPMS").join("x86_64"))
            .await
            .unwrap();
        tokio::fs::write(
            result_dir
                .join("RPMS")
                .join("x86_64")
                .join("hello-1.0-1.x86_64.rpm"),
            b"rpm",
        )
        .await
        .unwrap();
        tokio::fs::write(
            result_dir
                .join("RPMS")
                .join("x86_64")
                .join("hello-debuginfo-1.0-1.x86_64.rpm"),
            b"dbg",
        )
        .await
        .unwrap();
        tokio::fs::write(result_dir.join("build.log"), b"log")
            .await
            .unwrap();
        // 约定目录：非 .log 命名也按 --logs 门控收放
        tokio::fs::create_dir_all(result_dir.join("crbs-logs"))
            .await
            .unwrap();
        tokio::fs::write(result_dir.join("crbs-logs/dmesg.txt"), b"dmesg")
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(result_dir.to_str().unwrap()),
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let out = _tmp.path().join("out");
        handle_download(
            download_args(task_id.to_string(), Some(out.clone())),
            tester_ctx(),
            Some(&store),
        )
        .await
        .unwrap();
        assert!(out.join("x86_64/hello-1.0-1.x86_64.rpm").exists());
        assert!(!out.join("x86_64/hello-debuginfo-1.0-1.x86_64.rpm").exists());
        assert!(!out.join("x86_64/build.log").exists());
        assert!(!out.join("x86_64/dmesg.txt").exists());

        let out2 = _tmp.path().join("out2");
        let mut args = download_args(task_id.to_string(), Some(out2.clone()));
        args.debuginfo = true;
        args.logs = true;
        handle_download(args, tester_ctx(), Some(&store))
            .await
            .unwrap();
        assert!(out2.join("x86_64/hello-1.0-1.x86_64.rpm").exists());
        assert!(out2
            .join("x86_64/hello-debuginfo-1.0-1.x86_64.rpm")
            .exists());
        assert!(out2.join("x86_64/build.log").exists());
        assert!(out2.join("x86_64/crbs-logs/dmesg.txt").exists());
    }

    /// crbs-logs/ 子路径落盘：crbs-logs/sub/build.log 与顶层 build.log 同名
    /// 并存、crbs-logs/a/x.txt 与 crbs-logs/b/x.txt 同名并存，两份都落盘且
    /// 路径不同（basename 扁平化会冲突报错/静默覆盖）。
    #[tokio::test]
    async fn handle_download_local_logs_preserve_crbs_logs_subpaths() {
        crate::test_support::pin_setuid_privilege_backend();
        let (_tmp, store) = tmp_store().await;
        let _env = crate::test_support::EnvGuard::new(_tmp.path());
        let task_id = insert_task(&store).await;

        let result_dir = _tmp.path().join("result-x86_64");
        tokio::fs::create_dir_all(result_dir.join("RPMS").join("x86_64"))
            .await
            .unwrap();
        tokio::fs::write(
            result_dir
                .join("RPMS")
                .join("x86_64")
                .join("hello-1.0-1.x86_64.rpm"),
            b"rpm",
        )
        .await
        .unwrap();
        tokio::fs::write(result_dir.join("build.log"), b"top-level")
            .await
            .unwrap();
        tokio::fs::create_dir_all(result_dir.join("crbs-logs/sub"))
            .await
            .unwrap();
        tokio::fs::write(result_dir.join("crbs-logs/sub/build.log"), b"in-sub")
            .await
            .unwrap();
        tokio::fs::create_dir_all(result_dir.join("crbs-logs/a"))
            .await
            .unwrap();
        tokio::fs::write(result_dir.join("crbs-logs/a/x.txt"), b"aa")
            .await
            .unwrap();
        tokio::fs::create_dir_all(result_dir.join("crbs-logs/b"))
            .await
            .unwrap();
        tokio::fs::write(result_dir.join("crbs-logs/b/x.txt"), b"bb")
            .await
            .unwrap();
        store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(result_dir.to_str().unwrap()),
                backend: "chroot",
                user: "tester",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let out = _tmp.path().join("out");
        let mut args = download_args(task_id.to_string(), Some(out.clone()));
        args.logs = true;
        handle_download(args, tester_ctx(), Some(&store))
            .await
            .unwrap();

        let read = |rel: &str| std::fs::read_to_string(out.join(rel)).unwrap();
        assert_eq!(read("x86_64/build.log"), "top-level");
        assert_eq!(read("x86_64/crbs-logs/sub/build.log"), "in-sub");
        assert_eq!(read("x86_64/crbs-logs/a/x.txt"), "aa");
        assert_eq!(read("x86_64/crbs-logs/b/x.txt"), "bb");
    }
}
