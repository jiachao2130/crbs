// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain 构建 local repo 管理：repo 文件生成、目录初始化与产物发布。

use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};

use crate::engine::lock::lock_exclusive_async;
use crate::error::CrbsError;

/// 生成单个 repo 的 `.repo` 文件内容（禁用 repo 返回 `None`）；installroot
/// 与 host 受信 repo 目录两处写入共用，保证 repo 集合语义一致。
pub(crate) fn repo_file_content(repo: &crate::config::RepoConfig) -> Option<String> {
    if !repo.enabled {
        return None;
    }
    let mut content = format!(
        "[{}]\nname={}\nbaseurl={}\nenabled=1\ngpgcheck={}\npriority={}\ncost={}\n",
        repo.name,
        repo.name,
        repo.baseurl,
        if repo.gpgcheck { 1 } else { 0 },
        repo.priority,
        repo.cost,
    );
    if repo.gpgcheck {
        if let Some(gpgkey) = &repo.gpgkey {
            content.push_str(&format!("gpgkey={}\n", gpgkey));
        } else {
            warn!(repo = %repo.name, "gpgcheck=true but gpgkey not set");
        }
    }
    if repo.module_hotfixes {
        content.push_str("module_hotfixes=1\n");
    }
    if !repo.exclude.is_empty() {
        // 分隔符按消费端：.repo 文件空格 join、dnf --setopt 逗号 join；
        // validate_repo_config 保证包 glob 不含空格/逗号，两种 join 语义不变。
        content.push_str(&format!("exclude={}\n", repo.exclude.join(" ")));
    }
    if !repo.includepkgs.is_empty() {
        content.push_str(&format!("includepkgs={}\n", repo.includepkgs.join(" ")));
    }
    if let Some(extra) = &repo.extra {
        let trimmed = extra.trim();
        if !trimmed.is_empty() {
            content.push_str(trimmed);
            content.push('\n');
        }
    }
    Some(content)
}

/// 将仓库配置写入指定目录。
pub(crate) async fn write_repo_files(
    repo_dir: &std::path::Path,
    repos: &[crate::config::RepoConfig],
) -> crate::Result<()> {
    for repo in repos {
        if let Some(content) = repo_file_content(repo) {
            let repo_path = repo_dir.join(format!("{}.repo", repo.name));
            tokio::fs::write(&repo_path, content)
                .await
                .map_err(|e| CrbsError::from_io_context("write repo file", e))?;
        }
    }
    Ok(())
}

/// 计算需要从 `etc/yum.repos.d` 清理的 `*.repo` 文件名（纯函数）：不在任何
/// enabled repo 对应的 `{name}.repo` 之列、且不在 `reserved` 保留名单内
/// （crbs 自管文件，如 crbs-local/crbs-product）。非 `*.repo` 文件一律不动。
pub(crate) fn stale_repo_files(
    existing: &[String],
    repos: &[crate::config::RepoConfig],
    reserved: &[&str],
) -> Vec<String> {
    existing
        .iter()
        .filter(|name| {
            name.ends_with(".repo")
                && !reserved.contains(&name.as_str())
                && !repos
                    .iter()
                    .any(|repo| repo.enabled && name.as_str() == format!("{}.repo", repo.name))
        })
        .cloned()
        .collect()
}

/// 删除 `repo_dir` 下不在当前 enabled repo 集合内的 `*.repo` 文件（先清后写）。
/// 依赖 overlayfs whiteout：合并视图 unlink 在 upperdir 生成 whiteout 遮蔽
/// base_os lower 层同名旧源；普通目录等价直接删除，目录不存在视为无需清理。
pub(crate) async fn remove_stale_repo_files(
    repo_dir: &Path,
    repos: &[crate::config::RepoConfig],
    reserved: &[&str],
) -> crate::Result<()> {
    let mut entries = match tokio::fs::read_dir(repo_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(CrbsError::from_io_context(
                "read yum.repos.d for stale repo cleanup",
                e,
            ));
        }
    };

    let mut names = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("iterate yum.repos.d for stale repo cleanup", e))?
    {
        // 只处理普通文件，目录/符号链接不动。
        match entry.file_type().await {
            Ok(t) if t.is_file() => {}
            _ => continue,
        }
        if let Some(name) = entry.file_name().to_str() {
            names.push(name.to_string());
        }
    }

    for name in stale_repo_files(&names, repos, reserved) {
        let path = repo_dir.join(&name);
        tokio::fs::remove_file(&path)
            .await
            .map_err(|e| CrbsError::from_io_context("remove stale repo file", e))?;
        debug!(path = %path.display(), "Removed stale repo file (whiteout over base_os)");
    }
    Ok(())
}

/// 生成 crbs-local.repo 配置内容。
pub(crate) fn write_local_repo_conf() -> String {
    "[crbs-local]\n\
     name=crbs local build output\n\
     baseurl=file:///mnt/crbs-repo\n\
     enabled=1\n\
     gpgcheck=0\n\
     priority=1\n\
     cost=500\n"
        .to_string()
}

/// 生成 crbs-product.repo 配置内容（hub 远端产品 repo，注入 chroot 内的 yum 源）。
/// 模板约束：gpgcheck=0（v1 repomd 未签名）、skip_if_unavailable=1、不写
/// priority；https 附加 sslverify=0，http 不写。
/// 校验：baseurl 仅接受 http(s)://（file:// 走 local_repo 路径，与本选项互斥）；
/// 空白/控制字符一律拒绝——url 是模板唯一插值点，可向 `.repo` 注入额外 dnf 指令。
pub fn write_product_repo_conf(url: &str) -> crate::Result<String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "product repo baseurl must start with 'http://' or 'https://', got: {}",
                url
            ),
        });
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "product repo baseurl contains whitespace or control characters: {:?}",
                url
            ),
        });
    }
    let mut content = format!(
        "[crbs-product]\n\
         name=crbs product repo\n\
         baseurl={}\n\
         enabled=1\n\
         gpgcheck=0\n\
         skip_if_unavailable=1\n",
        url,
    );
    if url.starts_with("https://") {
        content.push_str("sslverify=0\n");
    }
    Ok(content)
}

/// createrepo_c 执行器错误的收口映射：Timeout 原样透传——保 is_transient=true
/// 的可重试分类与 CLI INTERRUPTED(3) 退出码，同 rpm_query_release/map_probe_err
/// 口径；其余错误附 spawn 上下文转 Io。纯函数便于单测钉透传。
fn map_createrepo_c_error(e: CrbsError) -> CrbsError {
    match e {
        CrbsError::Timeout => CrbsError::Timeout,
        other => CrbsError::io_message(other.to_string()),
    }
}

/// 运行 `createrepo_c`（`update=true` 附加 `--update`）；spawn 失败与非 0 退出
/// 统一转 `CrbsError`。
pub(crate) async fn run_createrepo_c(repo_dir: &Path, update: bool) -> crate::Result<()> {
    let label = if update {
        "createrepo_c --update"
    } else {
        "createrepo_c"
    };
    let mut cmd = tokio::process::Command::new("createrepo_c");
    if update {
        cmd.arg("--update");
    }
    cmd.arg(repo_dir);
    // 10 分钟预算：停滞存储卡死的 createrepo_c 不得无限占用持锁 repo 更新路径。
    let output = crate::engine::command::run_command_capped_output_with_timeout(
        cmd,
        &format!("spawn {label}"),
        std::time::Duration::from_secs(600),
    )
    .await
    .map_err(map_createrepo_c_error)?;
    if !output.status.success() {
        return Err(CrbsError::io_message(format!(
            "{} failed: {}",
            label,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// 初始化 chain local repo：确保目录权限不变量（2770 + crbs 组）并首建 repodata。
pub(crate) async fn init_local_repo(repo_dir: &Path) -> crate::Result<()> {
    // 默认路径 {crbs_root}/repo/{product} 不在 config ensure 清单内：root 首建
    // 0755 后组内其他身份 chain 构建/createrepo 全 EACCES，统一 ensure_directory
    // 收敛 2770+crbs；父目录 setgid 只保组继承不保 mode，`Packages/` 单级补收敛。
    let dirs = vec![repo_dir.to_path_buf(), repo_dir.join("Packages")];
    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        for d in &dirs {
            crate::privilege::ensure_directory(d, "chain local repo")?;
        }
        Ok(())
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking ensure local repo: {e}")))??;

    // 与 update_local_repo 同一把排他锁：try_exists(repodata) + 首建 createrepo_c
    // 全程持锁，防两个进程并发写 repodata 产出损坏元数据。
    let lock_path = repo_dir.join(".repodata.lock");
    let _lock_file =
        lock_exclusive_async(lock_path, crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT).await?;

    let repodata_dir = repo_dir.join("repodata");
    if !tokio::fs::try_exists(&repodata_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("check repodata dir", e))?
    {
        info!(path = %repo_dir.display(), "Initializing local repo");
        run_createrepo_c(repo_dir, false).await?;
    }

    Ok(())
}

/// 判断 RPM 的 release 是否携带期望的 dist 标签（纯函数）：以 `expected_dist`
/// 结尾即匹配；`expected_dist` 需带前导 `.`（normalize_dist 保证），不带
/// dist tag 的 release 视为错配。
//
// pub：crates/crbs 的 chain 预检跨 crate 复用同一判定，避免语义漂移。
pub fn rpm_release_suffix_matches(release: &str, expected_dist: &str) -> bool {
    release.ends_with(expected_dist)
}

/// `rpm -qp` 单包查询时限：停滞存储挂死的 rpm 不得无限占用持
/// `.repodata.lock` 的更新路径；Timeout 由 `update_local_repo` 分流为整链中止。
const RPM_QUERY_RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// [`rpm_query_release`] 探测错误映射（纯函数，可单测钉死分流）：Timeout
/// 原样上抛（变体保持，供 update_local_repo 分流整链中止），其余拍平为
/// DepsolveFailed 并附包路径（否则无法定位哪个包查询失败）。
fn map_probe_err(rpm_path: &Path, e: CrbsError) -> CrbsError {
    if matches!(e, CrbsError::Timeout) {
        e
    } else {
        CrbsError::DepsolveFailed {
            message: format!("rpm -qp RELEASE for {}: {}", rpm_path.display(), e),
        }
    }
}

/// 读取 RPM/SRPM 的 `RPMTAG_RELEASE`（`rpm -qp --queryformat %{RELEASE}`）。
/// Timeout 不拍平原样上抛（update_local_repo 分流为整链中止），其余 Err 拍平
/// DepsolveFailed。PathBuf 入参 = update_local_repo 逐包探测注入缝
///（chain 传本函数，测试传 stub）；PathBuf 非 &Path：泛型
/// `F: Fn(PathBuf) -> Fut` 的返回 Future 不借入参生命周期，async fn 函数项
/// 才能直接作 `F` 传入。
pub(crate) async fn rpm_query_release(rpm_path: PathBuf) -> crate::Result<String> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp")
        .arg("--queryformat")
        .arg("%{RELEASE}")
        .arg(&rpm_path);
    let output = crate::engine::command::run_command_capped_output_with_timeout(
        cmd,
        "spawn rpm -qp RELEASE",
        RPM_QUERY_RELEASE_TIMEOUT,
    )
    .await
    .map_err(|e| map_probe_err(&rpm_path, e))?;

    if !output.status.success() {
        return Err(CrbsError::DepsolveFailed {
            message: format!(
                "rpm -qp RELEASE failed for {}: {}",
                rpm_path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 更新 local repo：清理悬空符号链接、按 `rpm_paths` 重建符号链接并跑
/// `createrepo_c --update`。
///
/// 与 `init_local_repo` 同一把排他锁，覆盖 Packages/ 变更 + createrepo 全程：
/// 只锁 createrepo 的话并发 chain 在窗口期摘除/重建 symlink，扫描读到缺失
/// RPM 产出损坏元数据。空输入不跳过维护（chain 每轮调用，悬空 symlink 与
/// 陈旧 repodata 不能留到下个非空注入轮）；仅空输入且 `Packages/` 不存在
/// （仓库未初始化）时早退。
///
/// `expected_dist` 为 Some 时注入前逐包校验 release dist 后缀：错配跳过
/// （防与产品 base 包 EVR 冲突），读不到 release 保守放行（warn），None
/// 完全旁路。`query_release` 为逐包探测注入缝（生产传 [`rpm_query_release`]，
/// 测试传 stub）。探测 Timeout 不保守放行——停滞存储下无 dist 校验注入的
/// "成功"是假象，整链中止并给出存储排查指引；变体取 DepsolveFailed{message}
/// （Timeout 变体 Display 固定 "build timed out"，放不下指引）。
pub(crate) async fn update_local_repo<F, Fut>(
    repo_dir: &Path,
    rpm_paths: &[PathBuf],
    expected_dist: Option<&str>,
    query_release: F,
) -> crate::Result<()>
where
    F: Fn(PathBuf) -> Fut,
    Fut: std::future::Future<Output = crate::Result<String>>,
{
    let packages_dir = repo_dir.join("Packages");
    if rpm_paths.is_empty()
        && !tokio::fs::try_exists(&packages_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("check Packages dir", e))?
    {
        return Ok(());
    }

    let lock_path = repo_dir.join(".repodata.lock");
    let _lock_file =
        lock_exclusive_async(lock_path, crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT).await?;

    cleanup_dangling_symlinks(&packages_dir).await?;

    let mut linked = 0usize;
    for rpm_path in rpm_paths {
        if let Some(expected) = expected_dist {
            let release = query_release(rpm_path.clone()).await;
            match release {
                Ok(rel) if rpm_release_suffix_matches(&rel, expected) => {}
                Ok(rel) => {
                    warn!(
                        rpm = %rpm_path.display(),
                        release = %rel,
                        expected_dist = %expected,
                        "Skip injecting RPM with mismatched dist tag; refusing injection to avoid EVR conflict with product base packages"
                    );
                    continue;
                }
                Err(CrbsError::Timeout) => {
                    // 60s 无响应 = 疑似停滞存储，整链中止，不带未校验的包继续。
                    return Err(CrbsError::DepsolveFailed {
                        message: format!(
                            "rpm -qp RELEASE for {} hit the {}s timeout — suspected \
                             stalled storage (e.g., NFS hang); check the storage layer \
                             and retry. Refusing to inject the RPM into the local repo \
                             without the dist tag check to avoid EVR conflict \
                             with product base packages.",
                            rpm_path.display(),
                            RPM_QUERY_RELEASE_TIMEOUT.as_secs(),
                        ),
                    });
                }
                Err(e) => {
                    // 读不到 tag：保守放行（warn），不因查询工具缺失阻塞构建
                    warn!(rpm = %rpm_path.display(), error = %e, "Cannot read RPMTAG_RELEASE, injecting without dist check");
                }
            }
        }
        let file_name = rpm_path.file_name().ok_or_else(|| {
            CrbsError::io_message(format!("no file name: {}", rpm_path.display()))
        })?;
        let link_path = packages_dir.join(file_name);
        if tokio::fs::symlink_metadata(&link_path).await.is_ok() {
            if let Err(e) = tokio::fs::remove_file(&link_path).await {
                warn!(path = %link_path.display(), error = %e, "Failed to remove stale repo symlink");
            }
        }
        tokio::fs::symlink(rpm_path, &link_path)
            .await
            .map_err(|e| CrbsError::from_io_context("symlink ->", e))?;
        linked += 1;
    }

    run_createrepo_c(repo_dir, true).await?;

    info!(path = %repo_dir.display(), count = linked, "Updated local repo");
    Ok(())
}

async fn cleanup_dangling_symlinks(packages_dir: &Path) -> crate::Result<()> {
    if !tokio::fs::try_exists(packages_dir).await? {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(packages_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("read Packages dir", e))?;

    while let Some(entry) = entries.next_entry().await.map_err(|e| {
        CrbsError::from_io_context("iterate Packages dir for dangling symlink cleanup", e)
    })? {
        let path = entry.path();
        let meta = match tokio::fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_symlink() && !tokio::fs::try_exists(&path).await? {
            let Some(name) = path.file_name() else {
                continue;
            };
            let name = name.to_string_lossy().to_string();
            warn!(link = %name, "Cleaning dangling symlink");
            if let Err(e) = tokio::fs::remove_file(&path).await {
                warn!(path = %path.display(), error = %e, "Failed to remove dangling symlink");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 超时透传钉：拍平回 Io 会让 is_transient 翻 false（丢自动重试）且退出码
    /// 从 INTERRUPTED(3) 变 ENVIRONMENT(6)，误导演练脚本分流。
    #[test]
    fn createrepo_c_timeout_passes_through_unwrapped() {
        assert!(matches!(
            map_createrepo_c_error(CrbsError::Timeout),
            CrbsError::Timeout
        ));
        let mapped = map_createrepo_c_error(CrbsError::Io {
            context: "spawn createrepo_c".into(),
            kind: std::io::ErrorKind::NotFound,
            detail: "no such file".into(),
        });
        assert!(
            matches!(mapped, CrbsError::Io { .. }),
            "non-timeout errors keep the Io envelope: {mapped:?}"
        );
    }

    #[test]
    fn write_product_repo_conf_http_has_skip_and_no_priority_or_ssl() {
        let content = write_product_repo_conf("http://hub.example.com/repo/prod/x86_64").unwrap();
        assert!(content.contains("baseurl=http://hub.example.com/repo/prod/x86_64"));
        assert!(content.contains("skip_if_unavailable=1"));
        assert!(content.contains("gpgcheck=0"));
        assert!(content.contains("enabled=1"));
        // 不写 priority，不赌 dnf priorities 插件
        assert!(
            !content.contains("priority="),
            "http product repo must not set priority: {content}"
        );
        assert!(
            !content.contains("cost="),
            "http product repo must not set cost: {content}"
        );
        assert!(
            !content.contains("sslverify="),
            "http product repo must not set sslverify: {content}"
        );
    }

    #[test]
    fn write_product_repo_conf_https_adds_sslverify_zero() {
        let content = write_product_repo_conf("https://hub.example.com/repo/prod/x86_64").unwrap();
        assert!(content.contains("baseurl=https://hub.example.com/repo/prod/x86_64"));
        assert!(content.contains("skip_if_unavailable=1"));
        assert!(content.contains("sslverify=0"));
        assert!(
            !content.contains("priority="),
            "https product repo must not set priority: {content}"
        );
        assert!(
            !content.contains("cost="),
            "https product repo must not set cost: {content}"
        );
    }

    #[test]
    fn write_product_repo_conf_https_default_port_works() {
        // https 默认端口 :443 不出现（baseurl 直接是 scheme://host/path）
        let content = write_product_repo_conf("https://h/p/a").unwrap();
        assert!(content.contains("baseurl=https://h/p/a"));
        assert!(content.contains("sslverify=0"));
    }

    #[test]
    fn release_suffix_matches_expected_dist() {
        assert!(rpm_release_suffix_matches("1.ule3", ".ule3"));
        assert!(!rpm_release_suffix_matches("1.oe2203sp4", ".ule3"));
        assert!(rpm_release_suffix_matches(".fc42", ".fc42"));
        assert!(!rpm_release_suffix_matches("1", ".ule3"));
    }

    /// 回归：Timeout 不拍平、变体保持。stub 化的端到端测试对"映射回退无条件
    /// 拍平"仍绿，本测试直接钉映射纯函数本体。
    #[test]
    fn map_probe_err_preserves_timeout_variant() {
        let out = map_probe_err(
            Path::new("/repo/Packages/foo-1.fc42.x86_64.rpm"),
            CrbsError::Timeout,
        );
        assert!(matches!(out, CrbsError::Timeout), "got: {out:?}");
    }

    /// 其余 io 错维持拍平 DepsolveFailed，消息含包路径以定位失败包。
    #[test]
    fn map_probe_err_flattens_other_errors_with_path() {
        let e = CrbsError::Io {
            context: "spawn rpm -qp RELEASE".into(),
            kind: std::io::ErrorKind::NotFound,
            detail: "rpm: No such file or directory".into(),
        };
        let path = "/repo/Packages/foo-1.fc42.x86_64.rpm";
        let out = map_probe_err(Path::new(path), e);
        match out {
            CrbsError::DepsolveFailed { message } => {
                assert!(message.contains(path), "message lacks path: {message}");
                assert!(
                    message.contains("No such file or directory"),
                    "message lacks source detail: {message}"
                );
            }
            other => panic!("expected DepsolveFailed, got: {other:?}"),
        }
    }

    #[test]
    fn write_product_repo_conf_rejects_non_http_scheme() {
        // file:// 走 local_repo 路径，互斥
        assert!(write_product_repo_conf("file:///mnt/crbs-repo").is_err());
        // 任意其它 scheme / 空串 / 没 scheme 都拒绝（不静默降级）
        assert!(write_product_repo_conf("ftp://h/p").is_err());
        assert!(write_product_repo_conf("").is_err());
        assert!(write_product_repo_conf("hub.example.com/repo").is_err());
    }

    /// 注入面：baseurl 内嵌换行可向 `.repo` 注入 dnf 指令，空白/控制字符一律拒绝。
    #[test]
    fn write_product_repo_conf_rejects_whitespace_and_control_chars() {
        assert!(write_product_repo_conf("http://hub/repo/prod/x86_64\ngpgcheck=0").is_err());
        assert!(write_product_repo_conf("https://h/p/a b").is_err());
        assert!(write_product_repo_conf("http://h/p/a\tb").is_err());
        assert!(write_product_repo_conf("http://h/p/a\u{0}b").is_err());
    }

    #[tokio::test]
    async fn init_local_repo_takes_repodata_lock_and_skips_when_initialized() {
        // repodata 已存在：跳过 createrepo_c（宿主可能未装），锁文件与 Packages/ 仍须落盘。
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path();
        tokio::fs::create_dir(repo_dir.join("repodata"))
            .await
            .unwrap();

        init_local_repo(repo_dir)
            .await
            .expect("initialized repo needs no createrepo_c");

        assert!(repo_dir.join("Packages").try_exists().unwrap());
        assert!(repo_dir.join(".repodata.lock").try_exists().unwrap());
    }

    /// `Packages/` 权限不变量：init_local_repo 后收敛 2770（setgid + group
    /// rwx），已存在的 0755 同样收敛。仅断言 mode：非 root 下 chown 到 crbs
    /// 组必然 EPERM（debug 降级预期路径，见 privilege::ensure_directory）。
    #[tokio::test]
    async fn init_local_repo_converges_packages_dir_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path();
        // repodata 已存在：跳过依赖宿主工具的 createrepo_c。
        tokio::fs::create_dir(repo_dir.join("repodata"))
            .await
            .unwrap();
        // 预置 umask 裸建形态的 0755 Packages/，钉"已存在也收敛"的回归面。
        let packages = repo_dir.join("Packages");
        tokio::fs::create_dir(&packages).await.unwrap();

        init_local_repo(repo_dir).await.unwrap();

        let mode = tokio::fs::metadata(&packages)
            .await
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o2770, "Packages/ must converge to 2770");
    }

    /// 回归：`.repodata.lock` 必须在改动 Packages/ 之前获取（只锁 createrepo
    /// 会被并发窗口期摘链破坏）；持锁期间 update 阻塞在锁获取、Packages/ 零变更。
    #[tokio::test]
    async fn update_local_repo_waits_for_repodata_lock_before_mutating_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path();
        let packages = repo_dir.join("Packages");
        tokio::fs::create_dir_all(&packages).await.unwrap();
        // 真实 RPM 内容无关：expected_dist=None 时不会调 rpm 查询
        let rpm = tmp.path().join("foo-1-1.noarch.rpm");
        tokio::fs::write(&rpm, b"stub").await.unwrap();

        let holder = lock_exclusive_async(
            repo_dir.join(".repodata.lock"),
            crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT,
        )
        .await
        .unwrap();
        let task_repo_dir = repo_dir.to_path_buf();
        let task_rpm_paths = vec![rpm];
        let task = tokio::task::spawn(async move {
            update_local_repo(&task_repo_dir, &task_rpm_paths, None, rpm_query_release).await
        });
        // 换出主任务时间片让 spawned task 跑到锁获取点
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        assert!(!task.is_finished(), "must block while lock is held");
        let mut entries = tokio::fs::read_dir(&packages).await.unwrap();
        assert!(
            entries.next_entry().await.unwrap().is_none(),
            "Packages/ must stay untouched while lock is held"
        );

        // 后续 createrepo_c 依赖宿主工具，不在单测断言范围；直接终止
        task.abort();
        drop(holder);
    }

    /// 空输入且 `Packages/` 不存在（仓库未初始化）→ 早退 Ok，不建锁文件、不跑 createrepo。
    #[tokio::test]
    async fn update_local_repo_empty_input_skips_when_no_packages_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path();

        update_local_repo(repo_dir, &[], None, rpm_query_release)
            .await
            .unwrap();

        assert!(!repo_dir.join("Packages").try_exists().unwrap());
        assert!(!repo_dir.join(".repodata.lock").try_exists().unwrap());
    }

    /// 空输入但 `Packages/` 已存在（chain 每轮的仓库卫生路径）→ 仍持锁清理
    /// 悬空 symlink；createrepo_c 依赖宿主工具不断言，只断言 cleanup 已发生。
    #[tokio::test]
    async fn update_local_repo_empty_input_cleans_dangling_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path();
        let packages = repo_dir.join("Packages");
        tokio::fs::create_dir_all(&packages).await.unwrap();
        let dangling = packages.join("gone-1-1.noarch.rpm");
        tokio::fs::symlink(tmp.path().join("does-not-exist.rpm"), &dangling)
            .await
            .unwrap();

        // 有无 createrepo_c 的宿主分别 Ok/Err；清理先于 createrepo，均须已完成。
        let _ = update_local_repo(repo_dir, &[], None, rpm_query_release).await;

        assert!(
            tokio::fs::symlink_metadata(&dangling).await.is_err(),
            "dangling symlink must be cleaned even with empty input"
        );
    }

    // --- 逐包探测注入缝的 Timeout/Err/Ok 分流 -----------------------

    async fn probe_timeout(_: PathBuf) -> crate::Result<String> {
        Err(CrbsError::Timeout)
    }

    async fn probe_other_err(_: PathBuf) -> crate::Result<String> {
        Err(CrbsError::DepsolveFailed {
            message: "rpm: command not found".to_string(),
        })
    }

    async fn probe_ok_match(_: PathBuf) -> crate::Result<String> {
        Ok("1.ule3".to_string())
    }

    async fn probe_ok_mismatch(_: PathBuf) -> crate::Result<String> {
        Ok("1.oe2203sp4".to_string())
    }

    fn stub_rpm(tmp: &std::path::Path, name: &str) -> PathBuf {
        let p = tmp.join(name);
        std::fs::write(&p, b"stub").unwrap();
        p
    }

    /// 预建 Packages/：生产由 init_local_repo 首建，update_local_repo 不负责创建。
    fn seeded_repo(tmp: &std::path::Path) -> std::path::PathBuf {
        let repo_dir = tmp.join("repo");
        std::fs::create_dir_all(repo_dir.join("Packages")).unwrap();
        repo_dir
    }

    /// (a)：探测 Timeout → 返 Err 整链中止，变体 DepsolveFailed{message}
    /// （Timeout 变体 Display 放不下指引），文案须含包路径与停滞存储指引。
    #[tokio::test]
    async fn update_local_repo_probe_timeout_aborts_with_stalled_storage_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = seeded_repo(tmp.path());
        let rpm = stub_rpm(tmp.path(), "foo-1-1.ule3.noarch.rpm");

        let err = update_local_repo(
            &repo_dir,
            std::slice::from_ref(&rpm),
            Some(".ule3"),
            probe_timeout,
        )
        .await
        .expect_err("rpm -qp timeout must abort the chain");
        match &err {
            CrbsError::DepsolveFailed { message } => {
                assert_eq!(
                    crate::exit_code::crbs_error_exit_code(&err),
                    crate::exit_code::BUILD_FAILED,
                    "exit code contract for the guidance-carrying variant"
                );
                assert!(
                    message.contains(&format!("rpm -qp RELEASE for {}", rpm.display())),
                    "must name the offending rpm path: {message}"
                );
                assert!(
                    message.contains("60s timeout"),
                    "must state the 60s budget: {message}"
                );
                assert!(
                    message.contains("suspected stalled storage (e.g., NFS hang)"),
                    "must carry the stalled-storage suspicion: {message}"
                );
                assert!(
                    message.contains("check the storage layer and retry"),
                    "must carry troubleshooting guidance: {message}"
                );
                assert!(
                    message.contains("without the dist tag check"),
                    "must state the no-dist-check injection refusal: {message}"
                );
            }
            other => panic!("expected DepsolveFailed, got {other:?}"),
        }
        // 中止发生在注入之前：Packages/ 下不得出现该包的符号链接。
        assert!(
            !repo_dir
                .join("Packages")
                .join("foo-1-1.ule3.noarch.rpm")
                .try_exists()
                .unwrap(),
            "timed-out rpm must not be injected"
        );
    }

    /// (b)：探测其他 Err（如 rpm 缺失）→ 保守放行注入，不因查询工具缺失阻塞构建。
    #[tokio::test]
    async fn update_local_repo_probe_other_err_still_injects_conservatively() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = seeded_repo(tmp.path());
        let rpm = stub_rpm(tmp.path(), "foo-1-1.ule3.noarch.rpm");

        // 无 createrepo_c 宿主整体 Err；判定点在 symlink 已建，而非整体退出。
        let _ = update_local_repo(&repo_dir, &[rpm], Some(".ule3"), probe_other_err).await;
        assert!(
            repo_dir
                .join("Packages")
                .join("foo-1-1.ule3.noarch.rpm")
                .try_exists()
                .unwrap(),
            "non-timeout probe error must keep the conservative inject path"
        );
    }

    /// (c)：Ok 匹配放行注入、错配跳过（防与产品 base 包 EVR 冲突）不回归。
    #[tokio::test]
    async fn update_local_repo_probe_ok_match_and_mismatch_keep_behavior() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = seeded_repo(tmp.path());
        let matched = stub_rpm(tmp.path(), "foo-1-1.ule3.noarch.rpm");
        let mismatched = stub_rpm(tmp.path(), "bar-1-1.oe2203sp4.noarch.rpm");

        let _ = update_local_repo(&repo_dir, &[matched], Some(".ule3"), probe_ok_match).await;
        let _ = update_local_repo(&repo_dir, &[mismatched], Some(".ule3"), probe_ok_mismatch).await;

        let packages = repo_dir.join("Packages");
        assert!(
            packages
                .join("foo-1-1.ule3.noarch.rpm")
                .try_exists()
                .unwrap(),
            "matched dist tag must be injected"
        );
        assert!(
            !packages
                .join("bar-1-1.oe2203sp4.noarch.rpm")
                .try_exists()
                .unwrap(),
            "mismatched dist tag must be skipped"
        );
    }

    fn repo_cfg(name: &str, enabled: bool) -> crate::config::RepoConfig {
        crate::config::RepoConfig {
            name: name.to_string(),
            baseurl: format!("http://host/{}", name),
            enabled,
            ..Default::default()
        }
    }

    #[test]
    fn stale_repo_files_removes_disabled_and_unknown_repos() {
        let repos = vec![
            repo_cfg("everything", true),
            repo_cfg("updates", false), // init 后被禁用 → 旧文件必须清
        ];
        let existing = vec![
            "everything.repo".to_string(), // enabled：保留
            "updates.repo".to_string(),    // 禁用：清理
            "removed.repo".to_string(),    // 已从配置删除：清理
            "crbs-local.repo".to_string(), // crbs 自管：保留
            "crbs-product.repo".to_string(),
            "README".to_string(), // 非 .repo：不动
            "repo.backup".to_string(),
        ];
        let mut got =
            stale_repo_files(&existing, &repos, &["crbs-local.repo", "crbs-product.repo"]);
        got.sort();
        assert_eq!(
            got,
            vec!["removed.repo".to_string(), "updates.repo".to_string()]
        );
    }

    #[test]
    fn stale_repo_files_keeps_everything_when_config_unchanged() {
        let repos = vec![repo_cfg("everything", true)];
        let existing = vec!["everything.repo".to_string()];
        assert!(stale_repo_files(&existing, &repos, &[]).is_empty());
    }

    #[tokio::test]
    async fn remove_stale_repo_files_prunes_dir_but_keeps_reserved_and_non_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("etc/yum.repos.d");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        for name in [
            "everything.repo", // enabled：保留
            "updates.repo",    // 禁用：删除
            "removed.repo",    // 不在配置：删除
            "crbs-local.repo", // 保留名单：保留
            "README",          // 非 .repo：不动
        ] {
            tokio::fs::write(dir.join(name), "").await.unwrap();
        }
        // 模拟目录项中的子目录：不是普通文件，不动
        tokio::fs::create_dir(dir.join("subdir.repo"))
            .await
            .unwrap();

        let repos = vec![repo_cfg("everything", true), repo_cfg("updates", false)];
        remove_stale_repo_files(&dir, &repos, &["crbs-local.repo", "crbs-product.repo"])
            .await
            .unwrap();

        for kept in [
            "everything.repo",
            "crbs-local.repo",
            "README",
            "subdir.repo",
        ] {
            assert!(dir.join(kept).exists(), "{} must survive", kept);
        }
        for removed in ["updates.repo", "removed.repo"] {
            assert!(!dir.join(removed).exists(), "{} must be removed", removed);
        }
    }

    #[tokio::test]
    async fn remove_stale_repo_files_missing_dir_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        // overlay 合并视图上目录可能尚未创建；视为无需清理
        remove_stale_repo_files(&tmp.path().join("etc/yum.repos.d"), &[], &[])
            .await
            .unwrap();
    }
}
