// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层持久化：包清单保存与层恢复。

use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::engine::build::packages::is_gpg_pubkey_nevra;
use crate::engine::shared_layer::chroot_output_with_cancel;
use crate::error::CrbsError;

/// `dnf install` 恢复参数序列（纯函数便于单测）。`--refresh` 与层创建路径
/// （create.rs builddep_args）一致：恢复元数据须回源校验，keepcache 陈旧 repodata 不得屏蔽上游更新。
pub(crate) fn restore_install_args() -> Vec<String> {
    vec![
        "install".to_string(),
        "-y".to_string(),
        "--refresh".to_string(),
        "--setopt=tsflags=nodocs".to_string(),
        "--setopt=install_weak_deps=False".to_string(),
        "--setopt=keepcache=1".to_string(),
    ]
}

/// `rpm -qa` 原始输出 → 剔除 gpg-pubkey 伪包的包清单文本（纯函数便于单测）。
/// 产物原样喂 `dnf install`；gpg-pubkey 是 RPMDB 伪包不可安装，谓词与消费侧
/// 同口径（[`is_gpg_pubkey_nevra`]）；全量伪包 → 空串，由恢复侧空清单 fail-closed 兜底。
pub(crate) fn filter_gpg_pubkey_packages(rpm_output: &[u8]) -> String {
    let text = String::from_utf8_lossy(rpm_output);
    let filtered: Vec<&str> = text.lines().filter(|l| !is_gpg_pubkey_nevra(l)).collect();
    if filtered.is_empty() {
        String::new()
    } else {
        format!("{}\n", filtered.join("\n"))
    }
}

/// 从已安装的 rootfs 中提取包列表（NEVRA，剔除 gpg-pubkey 伪包），写入
/// `packages.txt` 并持久化到 `layer_packages` 表（供恢复，不受 layer GC 影响）。
pub(crate) async fn save_packages_list(
    merged: &Path,
    layer_dir: &Path,
    state: &crate::state::StateStore,
    digest: &str,
    product: &str,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<()> {
    let rpm_output = chroot_output_with_cancel(
        merged,
        "rpm",
        &[
            "-qa",
            "--queryformat",
            "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n",
        ],
        cancel_token,
        timeout,
    )
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn rpm -qa: {}", e)))?;
    if !rpm_output.status.success() {
        warn!(digest = %digest, "rpm -qa failed, skipping packages.txt");
        return Ok(());
    }

    let packages_text = filter_gpg_pubkey_packages(&rpm_output.stdout);
    let pkg_count = packages_text.lines().count();
    let packages_path = layer_dir.join("packages.txt");
    tokio::fs::write(&packages_path, packages_text.as_bytes())
        .await
        .map_err(|e| CrbsError::from_io_context("write packages.txt", e))?;
    // 先建后修（after-create）：见 fix_layer_file_perms doc。
    super::fix_layer_file_perms(&packages_path).await;
    if let Err(e) = state
        .insert_layer_packages(digest, product, &packages_text)
        .await
    {
        warn!(digest = %digest, error = %e, "Failed to persist layer packages to DB");
    }

    info!(digest = %digest, count = pkg_count, "Saved package list");
    Ok(())
}

/// restore 的包清单收集滤网（纯函数便于单测）：trim、去空行、剔除 gpg-pubkey
/// 伪包，与保存侧（[`filter_gpg_pubkey_packages`]）同口径——legacy 行（保存侧
/// 过滤落盘前持久化）仍含伪包，`dnf install` 遇一条 "No match for argument:
/// gpg-pubkey-..." 即整批失败、层退化 scratch 重建；全量伪包 → 空表，恢复侧 fail-closed 兜底。
pub(crate) fn collect_restore_packages(packages_text: &str) -> Vec<&str> {
    packages_text
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| !is_gpg_pubkey_nevra(s))
        .collect()
}

/// 从持久化包列表恢复 SharedLayer（`dnf install` 替代 `dnf builddep`，不提取 SRPM/spec 直接安装）。
pub(crate) async fn restore_from_packages(
    layer_dir: &Path,
    merged: &Path,
    packages_text: &str,
    digest: &str,
    cancel_token: Option<&CancellationToken>,
    timeout: Option<Duration>,
) -> crate::Result<()> {
    let packages = collect_restore_packages(packages_text);

    if packages.is_empty() {
        // 空列表"恢复成功"会在空层上写 .complete 并共享给该 digest 的全部构建——
        // 合法流程的 packages.txt 恒非空（rpm -qa 输出），空即数据损坏，走 Err 让上层重建层。
        return Err(CrbsError::io_message(format!(
            "persisted package list for layer {digest} is empty; refusing empty restore"
        )));
    }
    if let Some(bad) = packages.iter().find(|s| s.starts_with('-')) {
        // `-` 开头行会被 dnf 解析为选项；内容源自本系统 rpm -qa，到此处即 DB 被篡改，fail-closed。
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "persisted package list for layer {digest} contains option-like entry: {bad:?}"
            ),
        });
    }

    info!(digest = %digest, count = packages.len(), "Restoring SharedLayer from package list");
    let log_path = layer_dir.join("restore.log");

    // 分批安装，避免命令行超过 ARG_MAX（与 xargs 行为类似）。
    const BATCH_SIZE: usize = 1024;
    let mut log = tokio::fs::File::create(&log_path)
        .await
        .map_err(|e| CrbsError::from_io_context("create restore log", e))?;
    // 先建后修（after-create）：见 fix_layer_file_perms doc。
    super::fix_layer_file_perms(&log_path).await;
    use tokio::io::AsyncWriteExt;

    for chunk in packages.chunks(BATCH_SIZE) {
        let mut args = restore_install_args();
        args.extend(chunk.iter().map(|s| s.to_string()));
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = chroot_output_with_cancel(merged, "dnf", &arg_refs, cancel_token, timeout)
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn dnf install: {}", e)))?;
        if let Err(e) = log.write_all(&output.stdout).await {
            warn!(path = %log_path.display(), error = %e, "Failed to write restore stdout to log");
        }
        if let Err(e) = log.write_all(&output.stderr).await {
            warn!(path = %log_path.display(), error = %e, "Failed to write restore stderr to log");
        }
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = format!(
                "dnf restore failed: exit_code={:?}, see {}",
                output.status.code(),
                log_path.display()
            );
            return Err(if crate::error::looks_like_network_failure(&stderr) {
                CrbsError::Network { message }
            } else {
                CrbsError::io_message(message)
            });
        }
    }

    info!(digest = %digest, "SharedLayer restored from package list");
    Ok(())
}

/// 从 merged rootfs 的 dnf cache 生成 layer 的 .lockfile（仅在需要 provenance 时）。
pub(crate) async fn write_layer_lockfile(
    merged: &Path,
    layer_dir: &Path,
    package_cache_path: &Path,
    digest: &str,
    context: &str,
) -> crate::Result<()> {
    let Some(index) = crate::engine::cache::cache_dnf_cache(merged, package_cache_path, None)
        .await
        .map_err(|e| {
            CrbsError::io_message(format!(
                "{context}: cache RPM packages for .lockfile: {}",
                e
            ))
        })?
    else {
        return Ok(());
    };
    let lockfile_path = layer_dir.join(".lockfile");
    if index.is_empty() {
        info!(digest = %digest, "No RPM files found in dnf cache for .lockfile");
        return Ok(());
    }
    crate::engine::cache::write_lockfile(&lockfile_path, &index)
        .await
        .map_err(|e| CrbsError::io_message(format!("{context}: write .lockfile: {}", e)))?;
    info!(digest = %digest, count = index.len(), "Wrote .lockfile");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{collect_restore_packages, filter_gpg_pubkey_packages};

    #[test]
    fn filter_gpg_pubkey_packages_strips_pseudo_packages() {
        let input =
            b"bash-5.2.26-3.el9.x86_64\ngpg-pubkey-f4a80eb5-53a7ff4b\nrpm-4.16.1.3-23.el9.x86_64\n";
        assert_eq!(
            filter_gpg_pubkey_packages(input),
            "bash-5.2.26-3.el9.x86_64\nrpm-4.16.1.3-23.el9.x86_64\n"
        );
    }

    /// 真实包名与伪包形态相邻（gpg-pubkey-utils）不误杀；带 arch 后缀伪包同样命中。
    #[test]
    fn filter_gpg_pubkey_packages_keeps_real_packages() {
        let input = b"gpg-pubkey-utils-1.0-1.noarch\ngpg-pubkey-64d62633-52f3f0bb.noarch\n";
        assert_eq!(
            filter_gpg_pubkey_packages(input),
            "gpg-pubkey-utils-1.0-1.noarch\n"
        );
    }

    #[test]
    fn filter_gpg_pubkey_packages_all_pseudo_or_empty_is_empty() {
        assert_eq!(
            filter_gpg_pubkey_packages(b"gpg-pubkey-f4a80eb5-53a7ff4b\n"),
            ""
        );
        assert_eq!(filter_gpg_pubkey_packages(b""), "");
    }

    /// legacy 行（保存侧过滤落盘前）含伪包，收集滤网同口径剔除；真实包名
    /// 相邻形态（gpg-pubkey-utils）不误杀，空行 / 纯空白行照旧剔除。
    #[test]
    fn collect_restore_packages_strips_legacy_gpg_pubkey_lines() {
        let legacy = "bash-5.2.26-3.el9.x86_64\ngpg-pubkey-f4a80eb5-53a7ff4b\n   \ngpg-pubkey-utils-1.0-1.noarch\ngpg-pubkey-64d62633-52f3f0bb\nrpm-4.16.1.3-23.el9.x86_64\n";
        assert_eq!(
            collect_restore_packages(legacy),
            vec![
                "bash-5.2.26-3.el9.x86_64",
                "gpg-pubkey-utils-1.0-1.noarch",
                "rpm-4.16.1.3-23.el9.x86_64"
            ]
        );
    }

    #[test]
    fn collect_restore_packages_all_pseudo_or_empty_is_empty() {
        assert!(collect_restore_packages("gpg-pubkey-64d62633-52f3f0bb\n").is_empty());
        assert!(collect_restore_packages("").is_empty());
    }
}
