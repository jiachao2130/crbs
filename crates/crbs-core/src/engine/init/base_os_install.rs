// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Base OS 安装实现：在 installroot 中安装基础包、创建 builder 用户、配置
//! sudoers/PAM、缓存 RPM 并计算 base_os digest；与 `BuildEngine` 的 init 编排解耦。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::engine::cache::{cache_dnf_cache, write_packages_json, CacheEntry};
use crate::engine::command::run_command_quiet_with_cancel_timeout;
use crate::engine::init::chroot::{chroot_output, chroot_status, mount_base_os_pseudo_fs};
use crate::engine::repo::{repo_file_content, write_repo_files};
use crate::engine::BuildEngine;
use crate::error::CrbsError;
use crate::privilege::get_privilege_backend;

use super::{merge_base_packages, REQUIRED_BASE_PACKAGES};

/// host 侧受信 repo 目录：`{crbs_root}/dnf-repos/{product}/`（每产品隔离）；
/// 派生规则与 crbs-priv-helper spawn.rs 布局校验共用，改名需双侧同改。
pub(crate) fn trusted_dnf_repos_dir(config: &crate::config::Config) -> PathBuf {
    config.crbs_root.join("dnf-repos").join(&config.product)
}

/// 受信 repo 目录内的 dnf 主配置文件名（与 crbs-priv-helper spawn.rs 同名手抄）：
/// 最小锚点配置，repo 来源由 --setopt=reposdir 钉死，钉 --config 防读 installroot 内 dnf.conf。
const TRUSTED_DNF_CONF_NAME: &str = "dnf.conf";

/// 预置 host 侧 dnf 受信 repo 集合（幂等：清集合外残留后重写，残留走特权 rm-rf）。
/// 目录特权钉 root:root 0755、文件特权写 0644 uid/gid=0——engine 自身无写权限是
/// 设计意图（受信目录只许 root 写）。并发不变量：.init.lock 只护 init，同产品
/// init/reproduce 先后重写本目录，逐文件原子 rename 下 dnf 最多读到旧集合，读不到越权来源。
pub(crate) async fn prepare_trusted_dnf_repos(
    trusted_dir: &Path,
    repos: &[crate::config::RepoConfig],
) -> crate::Result<()> {
    // 信任锚不变量：目录须 root 属主且组/他不可写（spawn-dnf trusted_asset_ok），
    // mkdir_chown 对 dnf-repos 根与产品层各钉一次（幂等，归一已存在的误形态）。
    // write_file 父目录补建走 mkdir(0777)&~umask 且无 chmod，UMask=0002/setgid
    // 下会落成 root:crbs 2775 被 spawn-dnf 拒绝，全新 worker 首次 init 必失败。
    let dnf_repos_root = trusted_dir
        .parent()
        .ok_or_else(|| {
            CrbsError::io_message(format!(
                "trusted repos dir {} has no parent component",
                trusted_dir.display()
            ))
        })?
        .to_path_buf();
    let leaf = trusted_dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        crate::privilege::mkdir_chown(&dnf_repos_root, "root", "root", 0o755)?;
        crate::privilege::mkdir_chown(&leaf, "root", "root", 0o755)
    })
    .await
    .map_err(|e| {
        CrbsError::io_message(format!("spawn_blocking provision trusted repos dir: {e}"))
    })??;

    let mut fresh_names: Vec<std::ffi::OsString> = repos
        .iter()
        .filter(|r| r.enabled)
        .map(|r| format!("{}.repo", r.name).into())
        .collect();
    fresh_names.push(TRUSTED_DNF_CONF_NAME.into());

    let dir = trusted_dir.to_path_buf();
    let stale: Vec<PathBuf> =
        tokio::task::spawn_blocking(move || -> crate::Result<Vec<PathBuf>> {
            let mut stale = Vec::new();
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                // 目录未创建 = 首次预置，无残留。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(stale),
                Err(e) => return Err(CrbsError::from_io_context("read trusted repos dir", e)),
            };
            for entry in entries {
                let entry = entry
                    .map_err(|e| CrbsError::from_io_context("iterate trusted repos dir", e))?;
                if !fresh_names.contains(&entry.file_name()) {
                    stale.push(entry.path());
                }
            }
            Ok(stale)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking scan trusted repos: {e}")))??;
    if !stale.is_empty() {
        let refs: Vec<&Path> = stale.iter().map(|p| p.as_path()).collect();
        crate::privilege::rm_rf_async(&refs).await?;
    }

    for repo in repos {
        if let Some(content) = repo_file_content(repo) {
            crate::privilege::write_file_async(
                &trusted_dir.join(format!("{}.repo", repo.name)),
                content.as_bytes(),
                Some(0o644),
                Some(0),
                Some(0),
            )
            .await?;
        }
    }
    crate::privilege::write_file_async(
        &trusted_dir.join(TRUSTED_DNF_CONF_NAME),
        b"[main]\n",
        Some(0o644),
        Some(0),
        Some(0),
    )
    .await?;
    Ok(())
}

impl BuildEngine {
    /// 在指定目录安装 base OS 层：装 base_packages、建 builder 用户/组、配置
    /// sudoers 与 ccache 链接、缓存 RPM 进 package_cache。`.digest` 完成标志由
    /// 调用方在各自流程末尾写入——树完整前写入会让崩溃半成品被当成品。
    /// `resolution_repos` 是安装事务的解析域（host 受信 repo 集合 + installroot
    /// 安装期 repo 文件；正常 init = base 快照，复现旗标 = 复现快照仓）——安装
    /// 收尾仍把 `config.repos`（产品镜像仓）重写回 installroot，作为 chroot 侧
    /// builddep 域的 lower 层来源，解析域与落盘 repo 文件二者解耦。
    /// `manifest_index` 是快照 manifest 的逐包锚：快照仓安装不留 dnf cache 时，
    /// `.packages.json` 由它播种（dnf cache 实收条目优先）。
    pub(super) async fn install_base_os(
        base_os: &std::path::Path,
        config: &crate::config::Config,
        cancel_token: Option<&CancellationToken>,
        timeout: Option<Duration>,
        resolution_repos: &[crate::config::RepoConfig],
        manifest_index: Option<&HashMap<String, CacheEntry>>,
    ) -> crate::Result<String> {
        // 崩溃残留防护：树存在但无 .digest = 上次 init 半成品（SIGKILL/断电跳过
        // 清理链，installroot 缺 /tmp 等"已装即存在"目录），原地续装会在后续
        // chown/脚本步 ENOENT；清空残骸（特权 rm-rf 删子项留根）按全新安装走。
        if tokio::fs::try_exists(base_os).await.unwrap_or(false)
            && !tokio::fs::try_exists(base_os.join(".digest"))
                .await
                .unwrap_or(false)
        {
            warn!(
                base_os = %base_os.display(),
                "Stale partial base_os residue detected (no .digest); cleaning before install"
            );
            cleanup_failed_base_os(
                base_os,
                "stale partial base_os without .digest (crashed init residue)",
            )
            .await;
        }

        // 合并必需包+用户包+可选 ccache；REQUIRED_BASE_PACKAGES 前置防漏写致 init 中途失败。
        let base_packages = merge_base_packages(&config.base_packages, &config.ccache_enabled);
        info!(
            product = %config.product,
            required = ?REQUIRED_BASE_PACKAGES,
            user_count = config.base_packages.len(),
            "Merged base packages for init"
        );

        // 先写入解析域 repo 配置（root dnf 经受信目录解析，installroot 内文件是
        // 安装期备用源）
        let repo_dir = base_os.join("etc/yum.repos.d");
        tokio::fs::create_dir_all(&repo_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("create repo dir", e))?;
        write_repo_files(&repo_dir, resolution_repos).await?;

        // host 侧受信 repo 集合：root dnf 的 repo 来源钉死到
        // {crbs_root}/dnf-repos/{product}/；installroot 内 repo 文件只是第二消费者
        //（chroot 构建 / reproduce 重放），root dnf 不读，三次 spawn-dnf 共用同一份。
        let trusted_repos_dir = trusted_dnf_repos_dir(config);
        prepare_trusted_dnf_repos(&trusted_repos_dir, resolution_repos).await?;

        // RPM 脚本片段（如 selinux-policy-targeted 的 %post）需要 /proc、/sys、/dev。
        let mut pseudo_guard = mount_base_os_pseudo_fs(base_os).await?;

        // dnf 安装主体：任何早退（? 传播）都经块末显式 umount——MountGuard 的 Drop
        // 只派发分离线程做 MNT_DETACH，失败清理 rm-rf 会与仍在挂载点竞争误删宿主 /dev、/proc。
        let install_body = async {
        let releasever = config.effective_releasever()?;
        let backend = get_privilege_backend();
        let base_install_timeout = timeout.or(Some(std::time::Duration::from_secs(7200)));
        let dnf_args: Vec<String> = std::iter::once("install".to_string())
            .chain(std::iter::once("-y".to_string()))
            .chain(std::iter::once("--setopt=keepcache=1".to_string()))
            .chain(base_packages.iter().cloned())
            .collect();
        let base_install_cmd = backend.spawn_dnf(base_os, &releasever, &trusted_repos_dir, &dnf_args)?;
        let base_install_cmd = tokio::process::Command::from(base_install_cmd);
        if let Err(e) = run_command_quiet_with_cancel_timeout(
            base_install_cmd,
            "dnf install",
            cancel_token,
            base_install_timeout,
        )
        .await
        {
            // 卸载伪文件系统后再清理目录，否则 remove_dir_all 会失败。
            let _ = pseudo_guard.umount().await;
            cleanup_failed_base_os(base_os, "dnf install failure").await;
            return Err(e);
        }

        // dnf 装完后 base_os 内文件保持 root 属主（保护 sudo 等 setuid 二进制）；
        // 根与 repo 目录归属 root:crbs 0775 而非当次调用者——base_os 缓存被多个
        // crbs 身份复用，chown 给当次调用者会让下一个 uid 在 overlay 写 repo 文件时撞 0755。
        let crbs_gid = crate::privilege::crbs_group_gid_async().await?;
        crate::privilege::chown_async(base_os, 0, crbs_gid, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!(
                    "chown base_os root {} to root:crbs: {e}",
                    base_os.display(),
                ))
            })?;
        crate::privilege::chmod_async(base_os, 0o775, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!(
                    "chmod base_os root {} to 775: {e}",
                    base_os.display()
                ))
            })?;
        crate::privilege::chown_async(&repo_dir, 0, crbs_gid, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!(
                    "chown repo dir {} to root:crbs: {e}",
                    repo_dir.display(),
                ))
            })?;
        crate::privilege::chmod_async(&repo_dir, 0o775, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("chmod repo dir {} to 775: {e}", repo_dir.display()))
            })?;
        // /tmp 供 post_init 临时脚本任意 uid 写入（sticky 1777 已放行，归属统一 root:crbs）。
        let tmp_dir = base_os.join("tmp");
        crate::privilege::chown_async(&tmp_dir, 0, crbs_gid, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!(
                    "chown tmp dir {} to root:crbs: {e}",
                    tmp_dir.display(),
                ))
            })?;
        crate::privilege::chmod_async(&tmp_dir, 0o1777, false)
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("chmod tmp dir {} to 1777: {e}", tmp_dir.display()))
            })?;

        // fedora-release 等发行版包会在安装中覆盖 /etc/yum.repos.d/ 并缓存错误
        // metadata：装 builddep 插件前必须清空重写（回写产品镜像仓并清缓存）。
        info!(product = %config.product, "Rewriting repo files after dnf install");
        // read_dir / 迭代出错必须传播：发行版默认 repo 残留会让 chroot 内 dnf 继续
        // 从错误源解析依赖；单文件删除失败维持 warn（部分成功可接受）。
        let mut entries = tokio::fs::read_dir(&repo_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("read repo dir for rewrite", e))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("iterate repo dir for rewrite", e))?
        {
            let path = entry.path();
            let is_file = match entry.file_type().await {
                Ok(t) => t.is_file(),
                Err(_) => continue,
            };
            if is_file {
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    warn!(path = %path.display(), error = %e, "Failed to remove existing repo file");
                }
            }
        }
        write_repo_files(&repo_dir, &config.repos).await?;

        info!(product = %config.product, "Cleaning dnf metadata cache after rewriting repo files");
        let clean_timeout = timeout.or(Some(Duration::from_secs(300)));
        let clean_cmd = backend.spawn_dnf(
            base_os,
            &releasever,
            &trusted_repos_dir,
            &["clean".to_string(), "metadata".to_string()],
        )?;
        let clean_cmd = tokio::process::Command::from(clean_cmd);
        if let Err(e) = run_command_quiet_with_cancel_timeout(
            clean_cmd,
            "dnf clean metadata",
            cancel_token,
            clean_timeout,
        )
        .await
        {
            warn!(
                product = %config.product,
                error = %e,
                "dnf clean metadata failed; stale metadata may cause subsequent dnf errors"
            );
        }

        // 安装与 installroot 内 dnf 版本匹配的 builddep 插件：检测 dnf5 二进制选包名
        //（dnf5 → dnf5-plugins，否则 dnf-plugins-core），不在模板写死发行版特定包名。
        let dnf5_exists = dnf5_binary_present(base_os).await;
        let plugin_pkg = if dnf5_exists {
            "dnf5-plugins"
        } else {
            "dnf-plugins-core"
        };
        let plugin_install_timeout = timeout.or(Some(std::time::Duration::from_secs(600)));
        let plugin_args: Vec<String> = vec![
            "install".to_string(),
            "-y".to_string(),
            "--setopt=keepcache=1".to_string(),
            plugin_pkg.to_string(),
        ];
        let plugin_install_cmd =
            backend.spawn_dnf(base_os, &releasever, &trusted_repos_dir, &plugin_args)?;
        let plugin_install_cmd = tokio::process::Command::from(plugin_install_cmd);
        if let Err(e) = run_command_quiet_with_cancel_timeout(
            plugin_install_cmd,
            "dnf install builddep plugin",
            cancel_token,
            plugin_install_timeout,
        )
        .await
        {
            let _ = pseudo_guard.umount().await;
            cleanup_failed_base_os(base_os, "builddep plugin failure").await;
            return Err(e);
        }

        Ok::<(), CrbsError>(())
        }
        .await;

        // 幂等 umount：内部失败分支已先 umount 过，再次调用是 no-op（挂载列表已被取走）。
        pseudo_guard.umount().await;
        install_body?;

        let mut base_package_index: HashMap<String, CacheEntry> = if !config
            .package_cache_path
            .as_os_str()
            .is_empty()
        {
            match cache_dnf_cache(base_os, &config.package_cache_path, None).await {
                Ok(Some(index)) => {
                    info!(
                        product = %config.product,
                        count = index.len(),
                        "Base packages cached"
                    );
                    index
                }
                Ok(None) => {
                    warn!(product = %config.product, "No dnf cache dir found in base_os, skipping base package cache");
                    HashMap::new()
                }
                Err(e) => {
                    warn!(product = %config.product, error = %e, "Failed to cache base packages");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        // 快照钉死的安装源不留 dnf cache，缓存收割为空；逐包锚改由 manifest 播种，
        // 已收割条目优先（sha 来自实际下载体）。
        if let Some(seed) = manifest_index {
            for (nevra, entry) in seed {
                base_package_index
                    .entry(nevra.clone())
                    .or_insert_with(|| entry.clone());
            }
        }

        // 写入 base_os 包清单，构建时直接读取，避免重复扫描/下载。
        let packages_json_path = base_os.join(".packages.json");
        if should_skip_packages_json_write(
            &base_package_index,
            tokio::fs::try_exists(&packages_json_path)
                .await
                .unwrap_or(false),
        ) {
            // 空索引 = dnf cache 缺失/缓存失败的降级，非真无包；覆写会清空既有
            // base_os 的包引用——package_cache GC（collect_referenced_sha256）读此
            // 清单，会误删 base_os 引用的包、--reproduce 无法重建。保留旧清单。
            warn!(
                product = %config.product,
                path = %packages_json_path.display(),
                "Empty base package index with existing .packages.json; keeping existing manifest"
            );
        } else if let Err(e) = write_packages_json(&packages_json_path, &base_package_index).await {
            warn!(
                product = %config.product,
                path = %packages_json_path.display(),
                error = %e,
                "Failed to write .packages.json"
            );
        } else {
            info!(
                product = %config.product,
                count = base_package_index.len(),
                path = %packages_json_path.display(),
                "Wrote .packages.json"
            );
        }

        info!(user = %config.builder_user, uid = %config.builder_uid, "Creating builder user");

        // 幂等：残留 base 上重建时组/用户可能已存在，groupadd/useradd 对已存在条目
        // 报错（exit 9）卡死 init；getent 探测存在即跳过，探测失败按不存在处理。
        let group_exists = chroot_status(
            base_os,
            &["getent", "group", &config.builder_group],
            cancel_token,
            None,
        )
        .await
        .map(|s| s.success())
        .unwrap_or(false);

        if !group_exists {
            let groupadd = chroot_status(
                base_os,
                &[
                    "groupadd",
                    "-g",
                    &config.builder_gid.to_string(),
                    &config.builder_group,
                ],
                cancel_token,
                None,
            )
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn groupadd: {}", e)))?;

            if !groupadd.success() {
                cleanup_failed_base_os(base_os, "groupadd failure").await;
                return Err(CrbsError::io_message(format!(
                    "groupadd failed: exit_code={:?}",
                    groupadd.code()
                )));
            }
        }

        let user_exists = chroot_status(
            base_os,
            &["getent", "passwd", &config.builder_user],
            cancel_token,
            None,
        )
        .await
        .map(|s| s.success())
        .unwrap_or(false);

        if !user_exists {
            let useradd = chroot_status(
                base_os,
                &[
                    "useradd",
                    "-u",
                    &config.builder_uid.to_string(),
                    "-g",
                    &config.builder_group,
                    "-m",
                    &config.builder_user,
                ],
                cancel_token,
                None,
            )
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn useradd: {}", e)))?;

            if !useradd.success() {
                cleanup_failed_base_os(base_os, "useradd failure").await;
                return Err(CrbsError::io_message(format!(
                    "useradd failed: exit_code={:?}",
                    useradd.code()
                )));
            }
        }

        // sudoers NOPASSWD 配置（Pipeline 所有 step sudo -u builder）：须 root 属主
        // 严格权限，经特权 helper 写入，普通用户不可直写。
        let sudoers_path = base_os.join("etc/sudoers.d").join(&config.builder_user);
        let sudoers_content = format!("{} ALL=(ALL) NOPASSWD: ALL\n", config.builder_user);
        crate::privilege::write_file_async(
            &sudoers_path,
            sudoers_content.as_bytes(),
            Some(0o440),
            Some(0),
            Some(0),
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("write sudoers: {}", e)))?;

        // chroot 内无 systemd/logind，sudo 默认 PAM（pam_systemd/pam_faillock）会因
        // /var/log/faillock 不可达等失败；覆盖 /etc/pam.d/sudo 为最小配置保 sudo 可用。
        let sudo_pam_path = base_os.join("etc/pam.d/sudo");
        let sudo_pam_content = "#%PAM-1.0\n\
             auth       sufficient   pam_permit.so\n\
             account    sufficient   pam_permit.so\n\
             password   sufficient   pam_permit.so\n\
             session    optional     pam_permit.so\n";
        crate::privilege::write_file_async(
            &sudo_pam_path,
            sudo_pam_content.as_bytes(),
            Some(0o644),
            Some(0),
            Some(0),
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("write sudo pam: {}", e)))?;

        // base_packages 含 ccache 时补 /usr/lib64/ccache/ 链接：dnf --installroot 不执行
        // post-install scriptlet，alternatives 链接缺失；/usr/lib64 归 root，经 helper 创建。
        if base_packages.contains(&"ccache".to_string()) {
            let ccache_script = "mkdir -p /usr/lib64/ccache && \
                cd /usr/lib64/ccache && \
                rm -f gcc g++ cc c++ && \
                ln -sf ../../bin/ccache gcc && \
                ln -sf ../../bin/ccache g++ && \
                ln -sf ../../bin/ccache cc && \
                ln -sf ../../bin/ccache c++";
            let ccache_status =
                chroot_status(base_os, &["bash", "-c", ccache_script], cancel_token, None)
                    .await
                    .map_err(|e| {
                        CrbsError::io_message(format!("spawn ccache symlink setup: {}", e))
                    })?;
            if !ccache_status.success() {
                warn!(product = %config.product, exit_code = ?ccache_status.code(), "ccache symlink setup failed");
            }
        }

        info!(product = %config.product, base_os = %base_os.display(), "Computing base_os digest");
        let rpm_qa = chroot_output(
            base_os,
            &["rpm", "-qa", "--qf", "%{NEVRA}%{SIGPGP:pgpsig}\n"],
            cancel_token,
            None,
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn rpm -qa: {}", e)))?;

        if !rpm_qa.status.success() {
            let stderr = String::from_utf8_lossy(&rpm_qa.stderr);
            cleanup_failed_base_os(base_os, "rpm -qa failure").await;
            return Err(CrbsError::io_message(format!("rpm -qa failed: {}", stderr)));
        }
        // digest 是 base_os/共享层身份键：输出被 32MB 截断时静默继续会得错误身份，fail-closed。
        if crate::engine::command::output_hit_capture_cap(&rpm_qa) {
            cleanup_failed_base_os(base_os, "rpm -qa output cap").await;
            return Err(CrbsError::io_message(
                "rpm -qa output exceeded capture cap; base_os digest would be computed from a truncated package list".to_string(),
            ));
        }

        let stdout = String::from_utf8_lossy(&rpm_qa.stdout).into_owned();
        let digest = tokio::task::spawn_blocking(move || {
            let mut packages: Vec<String> = stdout
                .lines()
                .filter(|l| !l.is_empty())
                .map(|s| s.to_string())
                .collect();
            packages.sort();
            packages.dedup();
            let digest_input = packages.join("\n");
            let digest = blake3::hash(digest_input.as_bytes()).to_hex().to_string();
            (digest, digest_input)
        })
        .await
        .map_err(|e| {
            CrbsError::io_message(format!("spawn_blocking compute base_os digest: {}", e))
        })?;

        tokio::fs::write(base_os.join(".packages"), &digest.1)
            .await
            .map_err(|e| CrbsError::from_io_context("write .packages", e))?;

        Ok(digest.0)
    }

    /// 装侧 builddep 能力不变量（fail-closed）：快照闭包声明了插件候选而装后
    /// base 缺 builddep 能力即失败——quiet 装包路径不判 dnf 退出码，插件静默
    /// 缺失会让坏 base 直接上线（install-deps 全量 "No match"）；闭包本无候选
    ///（产品镜像显式不含插件）跳过检查。调用时机 = install_base_os 之后、
    /// swap 之前；复现域闭包（记录全集）同样适用。
    pub(crate) async fn verify_base_builddep_capability(
        base_os: &std::path::Path,
        manifest: Option<&super::snapshot::SnapshotManifest>,
    ) -> crate::Result<()> {
        let Some(manifest) = manifest else {
            return Ok(());
        };
        let nevras: Vec<&str> = manifest.packages.iter().map(|p| p.nevra.as_str()).collect();
        if !closure_declares_builddep_plugin(&nevras) {
            return Ok(());
        }
        // 选包判据与插件事务同款（dnf5 二进制存在性）：装了什么插件由该判定决定。
        let dnf5_exists = dnf5_binary_present(base_os).await;
        if builddep_capability_present(base_os, dnf5_exists).await {
            return Ok(());
        }
        Err(CrbsError::ValidationFailed {
            message: format!(
                "installed base {} lacks the dnf builddep capability (declared by the \
                 base snapshot closure); refusing to publish a base without builddep",
                base_os.display()
            ),
        })
    }
}

/// dnf5 树 builddep 插件文件名：dnf5-plugins 落在 `<libdir>/dnf5/plugins/`，实测
/// dnf5 5.4.6 文件为 `builddep_cmd_plugin.so`。
const BUILDDEP_DNF5_PLUGIN_FILE: &str = "builddep_cmd_plugin.so";

/// 闭包是否声明 builddep 插件候选（纯函数）：任一 nevra 的 rpm 名命中候选清单
/// 即声明——声明者才受装后能力不变量约束。
fn closure_declares_builddep_plugin(nevras: &[&str]) -> bool {
    nevras.iter().any(|nevra| {
        super::snapshot::BUILDDEP_PLUGIN_CANDIDATES
            .contains(&crate::util::rpm_name_of_nevra(nevra).as_str())
    })
}

/// builddep 能力文件判据：落盘布局随发行版，按实测枚举——dnf5 树查
/// `<libdir>/dnf5/plugins/`（lib64/lib 两布局）；dnf4 树查 Fedora 布局
/// `/usr/lib/dnf/plugins/builddep.py` 与 EL/openEuler 布局
/// `/usr/lib/python3.*/site-packages/dnf-plugins/builddep.py`（python3.x 段扫
/// /usr/lib[64] 得出）。全部未命中 = 能力缺失。
async fn builddep_capability_present(base_os: &Path, dnf5_exists: bool) -> bool {
    if dnf5_exists {
        for dir in ["usr/lib64/dnf5/plugins", "usr/lib/dnf5/plugins"] {
            if tokio::fs::try_exists(base_os.join(dir).join(BUILDDEP_DNF5_PLUGIN_FILE))
                .await
                .unwrap_or(false)
            {
                return true;
            }
        }
        return false;
    }
    if tokio::fs::try_exists(base_os.join("usr/lib/dnf/plugins/builddep.py"))
        .await
        .unwrap_or(false)
    {
        return true;
    }
    for libdir in ["usr/lib", "usr/lib64"] {
        let mut entries = match tokio::fs::read_dir(base_os.join(libdir)).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("python3.") {
                continue;
            }
            let candidate = entry.path().join("site-packages/dnf-plugins/builddep.py");
            if tokio::fs::try_exists(&candidate).await.unwrap_or(false) {
                return true;
            }
        }
    }
    false
}

/// dnf5 二进制存在性判据（装侧选包名与装后验侧共用，防两处判据漂移）。
async fn dnf5_binary_present(base_os: &std::path::Path) -> bool {
    tokio::fs::try_exists(base_os.join("usr/bin/dnf5"))
        .await
        .unwrap_or(false)
}

/// 失败清理：经特权 rm-rf 清空 base_os（root 属主文件普通删除必 EPERM 残留）。优先
/// 整树删除：helper 遍历经 `unlinkat(dirfd, …)` 只作用于 dirfd 下名字，树内 symlink
/// 一律删其本身，天然安全；base_os 恰为允许根（显式 `base_os_path` 边界态）被拒时
/// 退逐子项：根本身保留、语义等价（空目录与不存在对后续流程同构）；顶层 symlink
/// 叶子被 helper 拒（fail-closed），单子项失败仅 warn 不中断；清理失败仅 warn 不掩盖原始错误。
async fn cleanup_failed_base_os(base_os: &Path, context: &str) {
    let target = base_os.to_path_buf();
    let whole_tree = {
        let t = target.clone();
        tokio::task::spawn_blocking(move || {
            let refs: Vec<&std::path::Path> = std::iter::once(t.as_path()).collect();
            crate::privilege::rm_rf(&refs)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking rm_rf: {e}")))
        .and_then(|r| r)
    };
    // 整树成功即清理完成。
    let Err(whole_err) = whole_tree else {
        return;
    };
    warn!(
        path = %base_os.display(),
        error = %whole_err,
        "Whole-tree base_os removal refused; falling back to per-child cleanup after {}",
        context
    );
    let result = tokio::task::spawn_blocking(move || -> crate::Result<()> {
        let mut children: Vec<std::path::PathBuf> = Vec::new();
        let entries = match std::fs::read_dir(&target) {
            Ok(entries) => entries,
            // 未创建（repo 写入前失败）：无内容可清。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(CrbsError::from_io_context("read base_os for cleanup", e));
            }
        };
        for entry in entries {
            let entry =
                entry.map_err(|e| CrbsError::from_io_context("iterate base_os for cleanup", e))?;
            children.push(entry.path());
        }
        // 单子项失败只 warn 不中断——整批中止会让残骸越积越多。
        let mut first_err: Option<CrbsError> = None;
        for child in &children {
            let child_ref: &std::path::Path = child.as_path();
            if let Err(e) = crate::privilege::rm_rf(std::slice::from_ref(&child_ref)) {
                tracing::warn!(
                    path = %child.display(),
                    error = %e,
                    "Failed to remove base_os child during cleanup"
                );
                first_err.get_or_insert(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking rm_rf: {e}")))
    .and_then(|r| r);
    if let Err(e) = result {
        warn!(
            path = %base_os.display(),
            error = %e,
            "Failed to remove base_os contents after {}",
            context
        );
    }
}

/// `.packages.json` 跳写判定（纯函数便于单测，install_base_os 依赖 dnf 无法直测）。
/// 空索引 + 清单已存在 → 跳写：空索引是缓存降级（dnf cache 缺失/缓存失败），非真
/// 无包（REQUIRED_BASE_PACKAGES 恒非空），覆写会清空包引用、连带 package_cache GC
/// 误删；全新安装与非空索引照写。
fn should_skip_packages_json_write(
    index: &HashMap<String, CacheEntry>,
    target_exists: bool,
) -> bool {
    index.is_empty() && target_exists
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：空索引（缓存降级）+ 既有清单 → 跳写保留清单；其余组合照写。
    #[test]
    fn packages_json_skip_write_only_for_empty_index_with_existing_manifest() {
        let mut index = HashMap::new();
        index.insert(
            "bash-5.2.26-1.fc40.x86_64".to_string(),
            CacheEntry {
                sha256: "0".repeat(64),
                repo_id: None,
            },
        );

        assert!(should_skip_packages_json_write(&HashMap::new(), true));
        assert!(!should_skip_packages_json_write(&HashMap::new(), false));
        assert!(!should_skip_packages_json_write(&index, true));
        assert!(!should_skip_packages_json_write(&index, false));
    }

    /// 闭包候选声明判定（纯函数）：候选包按 rpm 名命中，非候选包与带版本
    /// nevra 的解析形态都覆盖。
    #[test]
    fn closure_declares_builddep_plugin_by_rpm_name() {
        assert!(closure_declares_builddep_plugin(&[
            "bash-5.2.26-1.fc40.x86_64",
            "dnf-plugins-core-4.3.0-5.el9.noarch",
        ]));
        assert!(closure_declares_builddep_plugin(&[
            "dnf5-plugins-5.1.0-1.fc40.x86_64"
        ]));
        assert!(!closure_declares_builddep_plugin(&[
            "bash-5.2.26-1.fc40.x86_64",
            "dnf-data-4.3.0-5.el9.noarch",
        ]));
        assert!(!closure_declares_builddep_plugin(&[]));
    }

    /// dnf4 能力判据布局矩阵：Fedora 布局（/usr/lib/dnf/plugins）与 EL/openEuler
    /// 布局（python3.x site-packages）都放行；python3 目录名版本段任意。
    #[tokio::test]
    async fn dnf4_builddep_capability_layout_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        assert!(!builddep_capability_present(base, false).await);

        // Fedora 布局。
        tokio::fs::create_dir_all(base.join("usr/lib/dnf/plugins"))
            .await
            .unwrap();
        tokio::fs::write(base.join("usr/lib/dnf/plugins/builddep.py"), b"")
            .await
            .unwrap();
        assert!(builddep_capability_present(base, false).await);

        // EL/openEuler 布局（仅 python sitelib 在位，无 /usr/lib/dnf/plugins）。
        let tmp2 = tempfile::tempdir().unwrap();
        let base2 = tmp2.path();
        let sitelib = base2.join("usr/lib/python3.11/site-packages/dnf-plugins");
        tokio::fs::create_dir_all(&sitelib).await.unwrap();
        tokio::fs::write(sitelib.join("builddep.py"), b"")
            .await
            .unwrap();
        assert!(builddep_capability_present(base2, false).await);

        // 其他 python3.x 版本段同判。
        let tmp3 = tempfile::tempdir().unwrap();
        let base3 = tmp3.path();
        let sitelib3 = base3.join("usr/lib64/python3.9/site-packages/dnf-plugins");
        tokio::fs::create_dir_all(&sitelib3).await.unwrap();
        tokio::fs::write(sitelib3.join("builddep.py"), b"")
            .await
            .unwrap();
        assert!(builddep_capability_present(base3, false).await);
    }

    /// dnf5 能力判据布局矩阵：builddep_cmd_plugin.so 落 lib64 或 lib 任一即放行。
    #[tokio::test]
    async fn dnf5_builddep_capability_layout_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();
        tokio::fs::create_dir_all(base.join("usr/bin"))
            .await
            .unwrap();
        tokio::fs::write(base.join("usr/bin/dnf5"), b"")
            .await
            .unwrap();
        assert!(!builddep_capability_present(base, true).await);

        tokio::fs::create_dir_all(base.join("usr/lib64/dnf5/plugins"))
            .await
            .unwrap();
        tokio::fs::write(
            base.join("usr/lib64/dnf5/plugins/builddep_cmd_plugin.so"),
            b"",
        )
        .await
        .unwrap();
        assert!(builddep_capability_present(base, true).await);

        // lib 布局（非 lib64）同判。
        let tmp2 = tempfile::tempdir().unwrap();
        let base2 = tmp2.path();
        tokio::fs::create_dir_all(base2.join("usr/bin"))
            .await
            .unwrap();
        tokio::fs::write(base2.join("usr/bin/dnf5"), b"")
            .await
            .unwrap();
        let plugdir = base2.join("usr/lib/dnf5/plugins");
        tokio::fs::create_dir_all(&plugdir).await.unwrap();
        tokio::fs::write(plugdir.join("builddep_cmd_plugin.so"), b"")
            .await
            .unwrap();
        assert!(builddep_capability_present(base2, true).await);
    }

    /// 装侧不变量端到端矩阵：manifest 缺失 / 闭包无候选 → 空树放行；闭包声明
    /// 候选而能力在位 → 放行；声明而缺失 → fail-closed（坏 base 不得 swap）。
    #[tokio::test]
    async fn base_builddep_capability_invariant_matrix() {
        let manifest =
            |nevras: &[&str]| -> Option<crate::engine::init::snapshot::SnapshotManifest> {
                Some(crate::engine::init::snapshot::SnapshotManifest {
                    snapshot_id: "snap".to_string(),
                    packages: nevras
                        .iter()
                        .map(|n| crate::state::BuildPackage {
                            build_id: 0,
                            nevra: (*n).to_string(),
                            sha256: "aa".to_string(),
                            repo: None,
                            url: None,
                        })
                        .collect(),
                })
            };

        // manifest 缺失（复现锚发布失败域）：放行。
        let tmp = tempfile::tempdir().unwrap();
        BuildEngine::verify_base_builddep_capability(tmp.path(), None)
            .await
            .unwrap();
        // 闭包无候选：放行（产品镜像显式不含插件）。
        BuildEngine::verify_base_builddep_capability(
            tmp.path(),
            manifest(&["bash-5.2.26-1.fc40.x86_64"]).as_ref(),
        )
        .await
        .unwrap();

        // 声明候选 + 能力在位（EL python sitelib 布局）：放行。
        let tmp2 = tempfile::tempdir().unwrap();
        let sitelib = tmp2
            .path()
            .join("usr/lib/python3.11/site-packages/dnf-plugins");
        tokio::fs::create_dir_all(&sitelib).await.unwrap();
        tokio::fs::write(sitelib.join("builddep.py"), b"")
            .await
            .unwrap();
        BuildEngine::verify_base_builddep_capability(
            tmp2.path(),
            manifest(&["dnf-plugins-core-4.3.0-5.el9.noarch"]).as_ref(),
        )
        .await
        .unwrap();

        // 声明候选 + 能力缺失：fail-closed。
        let tmp3 = tempfile::tempdir().unwrap();
        let err = BuildEngine::verify_base_builddep_capability(
            tmp3.path(),
            manifest(&["dnf-plugins-core-4.3.0-5.el9.noarch"]).as_ref(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("lacks the dnf builddep capability"),
            "fail-closed message must name the missing capability: {err}"
        );
    }
}
