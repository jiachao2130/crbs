// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品初始化：base OS 安装、仓库接入与 builder 环境准备。

mod base_os_install;
mod chroot;
mod snapshot;

use crate::config::BoolOrPackages;
use crate::engine::init::chroot::{chroot_status, run_post_init_command, PostInitAuditContext};
use crate::engine::lock::{lock_file_async_cancellable, LockMode};
use crate::engine::BuildEngine;
use crate::error::CrbsError;
use std::path::Path;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

impl BuildEngine {
    /// 自动 init 入口（shell/auto 路径）：base_os 缺失时跑一次 init。
    /// `bypass_guard` 语义同 [`Self::init`]：默认 `false` 保留 active build 检查。
    pub async fn auto_init(
        &self,
        cancel_token: Option<&CancellationToken>,
        timeout: Option<Duration>,
        bypass_guard: bool,
    ) -> crate::Result<bool> {
        let base_os = self.config.base_os_path();
        let expected = Self::requested_fingerprint(&self.config);
        if Self::base_os_request_fresh(&base_os, &expected).await {
            return Ok(false);
        }
        info!(
            product = %self.config.product,
            "base_os not found, auto-init starting..."
        );
        self.init(false, cancel_token, timeout, bypass_guard)
            .await?;
        info!(product = %self.config.product, "auto-init completed");
        Ok(true)
    }

    /// 配置要求的 base_os 指纹：合并清单 "\n" join + releasever/builder 四元组
    ///（`\0` 分隔防伪造换行）的 blake3 hex。与 .digest（实际装了什么）正交：
    /// 本指纹回答"要求装什么、在哪个身份下装"。repos / overlay_dir /
    /// post_init 不入指纹，需 `crbs init --force` 重建；指纹格式变化 =
    /// 存量 base_os 一次性判不一致重建。
    fn requested_fingerprint(config: &crate::config::Config) -> String {
        let mut input =
            merge_base_packages(&config.base_packages, &config.ccache_enabled).join("\n");
        input.push_str(&format!(
            "\n\0releasever={}\0builder_user={}\0builder_uid={}\0builder_group={}\0builder_gid={}",
            config.releasever.as_deref().unwrap_or(""),
            config.builder_user,
            config.builder_uid,
            config.builder_group,
            config.builder_gid,
        ));
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }

    /// base_os 是否与当前配置请求一致（快路径 no-op 条件）：`.digest` 存在
    /// 且 `.requested` 与期望指纹一致。fail-safe：`.requested` 缺失/读失败
    ///（含非 UTF-8）一律按不一致处理，触发重建。
    async fn base_os_request_fresh(base_os: &Path, expected_fingerprint: &str) -> bool {
        if !tokio::fs::try_exists(base_os.join(".digest"))
            .await
            .unwrap_or(false)
        {
            return false;
        }
        match tokio::fs::read_to_string(base_os.join(".requested")).await {
            Ok(content) => content.trim() == expected_fingerprint,
            Err(_) => false,
        }
    }

    /// 初始化构建环境：安装 base OS 层、配置仓库、创建构建用户（.digest /
    /// .requested 完成标志在流程末尾成对写入）；GPG 导入、RPM 宏未覆盖。
    ///
    /// # `bypass_guard` 语义
    ///
    /// - `false`（CLI/server admin 路径）：保留 active build 检查——同产品有
    ///   phase IN ('building', 'pending', 'assigned') 的 build 返回 `ValidationFailed`。
    /// - `true`（任务执行者路径）：跳过检查。chain build 并发 task 各自 INSERT
    ///   一条 pending 后才进 init，不跳过会自己撞自己；并发串行化由
    ///   `.init.lock` (flock) 守护，zombie 兜底由 `do_repair_zombie_builds` 处理。
    pub async fn init(
        &self,
        force: bool,
        cancel_token: Option<&CancellationToken>,
        timeout: Option<Duration>,
        bypass_guard: bool,
    ) -> crate::Result<()> {
        let config = &self.config;
        let timeout = timeout.or(self.build_timeout);
        let base_os = config.base_os_path();
        let product_root = config.product_root();
        let lock_wait = timeout.unwrap_or(crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT);

        let existing_base_os = tokio::fs::try_exists(&base_os.join(".digest")).await?;
        let expected = Self::requested_fingerprint(config);
        if existing_base_os && !force {
            let lock_path = product_root.join(".init.lock");
            let _lock_file = lock_file_async_cancellable(
                lock_path,
                LockMode::Exclusive,
                lock_wait,
                cancel_token.cloned(),
            )
            .await?;

            Self::cleanup_orphan_mounts_for_product(
                &product_root,
                &config.product,
                &crate::engine::gc::OrphanScanRoots::from_engine_config(config),
                self.state.as_ref(),
            )
            .await;

            Self::cleanup_stale_init_temp_dirs(&base_os, std::process::id()).await;

            if Self::base_os_request_fresh(&base_os, &expected).await {
                debug!(
                    product = %config.product,
                    base_os = %base_os.display(),
                    "base_os already exists, skipping init"
                );
                if let Err(e) = Self::repair_base_package_cache(&base_os, config).await {
                    warn!(
                        product = %config.product,
                        error = %e,
                        "Repair base package cache failed, continuing"
                    );
                }
                if let Err(e) = snapshot::heal_base_snapshot(&base_os, config).await {
                    warn!(
                        product = %config.product,
                        error = %e,
                        "Heal base snapshot failed, continuing"
                    );
                }
                return Ok(());
            }
            info!(
                product = %config.product,
                base_os = %base_os.display(),
                "base_os config drift detected (requested fingerprint mismatch), rebuilding"
            );
            drop(_lock_file);
        }

        let product_root_c = product_root.clone();
        tokio::task::spawn_blocking(move || {
            crate::privilege::mkdir_chown(&product_root_c, "root", "crbs", 0o2770)
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("create product root: {}", e)))??;

        let lock_path = product_root.join(".init.lock");
        let _lock_file = lock_file_async_cancellable(
            lock_path,
            LockMode::Exclusive,
            lock_wait,
            cancel_token.cloned(),
        )
        .await?;

        if !force && Self::base_os_request_fresh(&base_os, &expected).await {
            info!(
                product = %config.product,
                "base_os already rebuilt with current config by a concurrent init, skipping"
            );
            return Ok(());
        }

        Self::check_active_guard(self.state.as_ref(), &config.product, bypass_guard).await?;

        Self::cleanup_orphan_mounts_for_product(
            &product_root,
            &config.product,
            &crate::engine::gc::OrphanScanRoots::from_engine_config(config),
            self.state.as_ref(),
        )
        .await;

        let protect_existing = tokio::fs::try_exists(&base_os.join(".digest"))
            .await
            .unwrap_or(false);

        let pid = std::process::id();
        let temp_base = base_os.with_extension(format!("tmp-{pid}"));
        Self::cleanup_stale_init_temp_dirs(&base_os, pid).await;
        if tokio::fs::try_exists(&temp_base).await.unwrap_or(false) {
            debug!(path = %temp_base.display(), "Cleaning stale temp base_os from previous failed init");
            crate::privilege::rm_rf_async(&[temp_base.as_path()])
                .await
                .map_err(|e| CrbsError::io_message(format!("remove stale temp base_os: {e}")))?;
        }
        let target_dir: std::path::PathBuf = if protect_existing {
            info!(
                product = %config.product,
                temp_base = %temp_base.display(),
                "Installing to temp dir for atomic swap (force or config drift rebuild)"
            );
            temp_base.clone()
        } else {
            base_os.clone()
        };

        info!(product = %config.product, base_os = %target_dir.display(), "Installing base packages");

        let mut published_snapshot_id: Option<String> = None;

        let install_result = async {
            let snapshot_domain =
                snapshot::ensure_init_snapshot_domain(self, config, cancel_token).await?;
            let manifest_package_index = if self.replay_snapshot_domain() {
                None
            } else {
                snapshot_domain
                    .manifest
                    .as_ref()
                    .map(snapshot::manifest_package_index)
            };
            let base_os_digest = Self::install_base_os(
                &target_dir,
                config,
                cancel_token,
                timeout,
                &snapshot_domain.repos,
                manifest_package_index.as_ref(),
            )
            .await?;
            Self::verify_base_builddep_capability(&target_dir, snapshot_domain.manifest.as_ref())
                .await?;
            if let Some(manifest) = snapshot_domain.manifest {
                crate::engine::cache::write_json_atomic(
                    &target_dir.join(snapshot::MANIFEST_NAME),
                    &manifest,
                )
                .await
                .map_err(|e| CrbsError::io_message(format!("write .snapshot-manifest: {e}")))?;
                published_snapshot_id = Some(manifest.snapshot_id);
            }

            if let Some(overlay_dir) = &config.overlay_dir {
                if tokio::fs::try_exists(overlay_dir).await? {
                    let canonical = tokio::fs::canonicalize(overlay_dir)
                        .await
                        .map_err(|e| CrbsError::from_io_context("canonicalize overlay_dir", e))?;
                    let allowed_prefix = crate::config::config_path("overlays")?;
                    if !canonical.starts_with(&allowed_prefix) {
                        return Err(CrbsError::ValidationFailed {
                            message: format!(
                                "overlay_dir {} is outside of {}",
                                overlay_dir.display(),
                                allowed_prefix.display()
                            ),
                        });
                    }
                    info!(
                        product = %config.product,
                        overlay = %overlay_dir.display(),
                        "Applying overlay"
                    );
                    Self::copy_overlay_dir(&canonical, &target_dir).await?;
                } else {
                    warn!(
                        product = %config.product,
                        overlay = %overlay_dir.display(),
                        "overlay_dir configured but does not exist, skipping"
                    );
                }
            }

            for cmd in &config.post_init {
                info!(product = %config.product, command = %cmd.command, "Running post_init");
                let status = run_post_init_command(
                    &target_dir,
                    &cmd.command,
                    PostInitAuditContext {
                        state: self.state.as_ref(),
                        actor: "crbs-init",
                        role: "system",
                        product: &config.product,
                    },
                    cancel_token,
                    timeout,
                )
                .await
                .map_err(|e| CrbsError::io_message(format!("spawn post_init: {}", e)))?;
                if let Some(err) = post_init_failure(
                    &cmd.command,
                    cmd.ignore_failure,
                    status.success(),
                    status.code(),
                ) {
                    Err(err)?;
                } else if !status.success() {
                    warn!(
                        product = %config.product,
                        command = %cmd.command,
                        exit_code = ?status.code(),
                        "post_init failed (ignore_failure=true), continuing"
                    );
                }
            }

            let caller = crate::privilege::get_caller_info_async().await;
            Self::harden_base_os_for_nspawn(&target_dir, caller.gid)
                .await
                .map_err(|e| CrbsError::io_message(format!("harden base_os for nspawn: {}", e)))?;

            tokio::fs::write(target_dir.join(".digest"), &base_os_digest)
                .await
                .map_err(|e| CrbsError::from_io_context("write .digest", e))?;

            tokio::fs::write(target_dir.join(".requested"), &expected)
                .await
                .map_err(|e| CrbsError::from_io_context("write .requested", e))?;

            Ok::<(), CrbsError>(())
        }
        .await;

        if let Err(e) = install_result {
            if protect_existing {
                if let Err(rm) = crate::privilege::rm_rf_async(&[temp_base.as_path()]).await {
                    warn!(
                        product = %config.product,
                        error = %rm,
                        "Init failed; temp dir cleanup also failed (will be reclaimed by next init GC)"
                    );
                }
                warn!(product = %config.product, error = %e, "Init failed, temp dir cleaned, old base_os preserved");
            } else {
                warn!(product = %config.product, error = %e, "Init failed; removing completion markers so next build re-runs full init");
                for marker in [".digest", ".requested"] {
                    if let Err(rm) = tokio::fs::remove_file(base_os.join(marker)).await {
                        if rm.kind() != std::io::ErrorKind::NotFound {
                            warn!(product = %config.product, marker = marker, error = %rm, "Init failed; removing marker also failed, next build may reuse a half-baked base_os");
                        }
                    }
                }
            }
            return Err(e);
        }

        if protect_existing {
            let backup = base_os.with_extension(format!("old-{pid}"));
            if tokio::fs::try_exists(&backup).await.unwrap_or(false) {
                let b = backup.clone();
                let rm = tokio::task::spawn_blocking(move || {
                    let refs: Vec<&std::path::Path> = vec![b.as_path()];
                    crate::privilege::rm_rf(&refs)
                })
                .await
                .map_err(|e| {
                    CrbsError::io_message(format!("spawn_blocking remove stale backup: {e}"))
                })
                .and_then(|r| r);
                if let Err(e) = rm {
                    warn!(
                        product = %config.product,
                        path = %backup.display(),
                        error = %e,
                        "Failed to remove stale backup base_os; continuing (reclaimed by next init GC)"
                    );
                }
            }
            if let Err(e) = tokio::fs::rename(&base_os, &backup).await {
                if let Err(rm) = crate::privilege::rm_rf_async(&[temp_base.as_path()]).await {
                    warn!(
                        product = %config.product,
                        error = %rm,
                        "rename base_os to backup failed; temp dir cleanup also failed (will be reclaimed by next init GC)"
                    );
                }
                return Err(CrbsError::from_io_context(
                    "rename old base_os to backup",
                    e,
                ));
            }
            if let Err(e) = tokio::fs::rename(&temp_base, &base_os).await {
                warn!(error = %e, "Atomic swap failed, attempting rollback");
                if let Err(rbe) = tokio::fs::rename(&backup, &base_os).await {
                    warn!(
                        product = %config.product,
                        backup = %backup.display(),
                        base_os = %base_os.display(),
                        error = %rbe,
                        "Swap rollback rename failed; base_os missing, old tree left at backup path"
                    );
                }
                if let Err(rm) = crate::privilege::rm_rf_async(&[temp_base.as_path()]).await {
                    warn!(
                        product = %config.product,
                        error = %rm,
                        "swap rollback; temp dir cleanup also failed (reclaimed by next init GC)"
                    );
                }
                return Err(CrbsError::from_io_context(
                    "rename temp base_os to base_os (atomic swap)",
                    e,
                ));
            }
            let b = backup.clone();
            let rm = tokio::task::spawn_blocking(move || {
                let refs: Vec<&std::path::Path> = vec![b.as_path()];
                crate::privilege::rm_rf(&refs)
            })
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn_blocking remove old backup: {e}")))
            .and_then(|r| r);
            if let Err(e) = rm {
                warn!(
                    product = %config.product,
                    path = %backup.display(),
                    error = %e,
                    "Failed to remove old backup base_os after swap; new base_os is live (backup reclaimed by next init GC)"
                );
            }
            info!(product = %config.product, "Atomic swap completed: new base_os is live");
        }

        let digest = tokio::fs::read_to_string(base_os.join(".digest"))
            .await
            .map_err(|e| CrbsError::from_io_context("read .digest", e))?;

        if self.replay_snapshot_domain() {
            warn!(
                product = %config.product,
                digest = %digest,
                trigger = "replay record set",
                "Replay flag triggered resident base_os rebuild; product base is now anchored to the replay snapshot repo"
            );
        }

        snapshot::prune_base_snapshots(config, published_snapshot_id.as_deref()).await;

        info!(product = %config.product, digest = %digest, "Init completed");
        Ok(())
    }

    /// per-product active build 检查。`bypass_guard=false` 时先修复僵尸活跃
    /// 构建（`crbs_pid` 已死的 pending/building），再查 `count_active_for_product`，
    /// 仍有 active 才返回 `ValidationFailed` 拒 init/clean——否则僵尸会把 init
    /// 永远挡在"等构建结束"上（单机无 server 侧 sweeper 兜底）。
    /// `bypass_guard=true` 直接放行。语义矩阵见 `tests::active_build_guard_matrix`。
    async fn check_active_guard(
        state: &crate::state::StateStore,
        product: &str,
        bypass_guard: bool,
    ) -> crate::Result<()> {
        if bypass_guard {
            return Ok(());
        }
        state.repair_zombie_active_builds_logged(product).await;
        match state.count_active_for_product(product).await {
            Ok(count) if count > 0 => Err(CrbsError::ValidationFailed {
                message: format!(
                    "Cannot init '{}': {} active/pending build(s) in progress. \
                     Wait for them to finish or cancel before init.",
                    product, count
                ),
            }),
            Ok(_) => Ok(()),
            Err(e) => Err(CrbsError::io_message(format!(
                "Failed to query active builds: {e}"
            ))),
        }
    }

    /// temp+swap init 启动时回收崩溃残留的 `tmp-{pid}`/`old-{pid}` 目录：
    /// pid 隔离只防并发不防崩溃，须按属主 pid 存活判定（见
    /// [`Self::stale_init_temp_dirs`]）后走 helper 特权 rm-rf（dnf root 产物
    /// remove_dir_all 必然 EPERM）。清理失败仅 warn，不阻断 init。
    async fn cleanup_stale_init_temp_dirs(base_os: &Path, current_pid: u32) {
        let stale = match Self::stale_init_temp_dirs(base_os, current_pid).await {
            Ok(s) => s,
            Err(e) => {
                warn!(base_os = %base_os.display(), error = %e, "Scan stale init temp dirs failed");
                return;
            }
        };
        if stale.is_empty() {
            return;
        }
        let refs: Vec<&Path> = stale.iter().map(|p| p.as_path()).collect();
        match crate::privilege::rm_rf_async(&refs).await {
            Ok(()) => {
                for p in &stale {
                    info!(path = %p.display(), "Removed stale init temp dir from crashed run");
                }
            }
            Err(e) => {
                warn!(error = %e, "Remove stale init temp dirs failed, continuing");
            }
        }
    }

    /// 扫描崩溃残留的 `tmp-*`/`old-*` 目录，返回待删路径：`{base_os_stem}.tmp-{pid}`/
    /// `{base_os_stem}.old-{pid}` 中属主 pid 已死（或被无关进程复用——
    /// `is_process_alive` 的 crbs 前缀校验判死）的条目。跳过：当前 pid 的
    ///（重入时 tmp 可能仍在使用，由 init 流程自清）；属主仍存活的（长驻
    /// 进程失败后的残留可能仍被其收尾/重试引用）；后缀解析不出 pid 的
    ///（无法归属保守跳过）。纯扫描不删除，便于单测断言。
    async fn stale_init_temp_dirs(
        base_os: &Path,
        current_pid: u32,
    ) -> crate::Result<Vec<std::path::PathBuf>> {
        let Some(parent) = base_os.parent() else {
            return Ok(Vec::new());
        };
        let Some(stem) = base_os.file_stem().and_then(|s| s.to_str()) else {
            return Ok(Vec::new());
        };
        let tmp_prefix = format!("{stem}.tmp-");
        let old_prefix = format!("{stem}.old-");

        let mut stale = Vec::new();
        let mut entries = tokio::fs::read_dir(parent)
            .await
            .map_err(|e| CrbsError::from_io_context("read product root for stale init dirs", e))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("scan product root for stale init dirs", e))?
        {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let pid_suffix = name
                .strip_prefix(&tmp_prefix)
                .or_else(|| name.strip_prefix(&old_prefix));
            let Some(pid) = pid_suffix.and_then(|s| s.parse::<i64>().ok()) else {
                continue;
            };
            if pid == i64::from(current_pid) {
                continue;
            }
            if crate::util::is_process_alive(pid).await {
                info!(
                    path = %entry.path().display(),
                    pid,
                    "Skipping init temp dir owned by a live process"
                );
                continue;
            }
            stale.push(entry.path());
        }
        Ok(stale)
    }

    /// 恢复 nspawn 容器内必须 root 拥有的关键文件：sudoers 族属主/模式经特权
    /// chown/chmod 通道修复（无需 setuid 位，剥位无影响）；usr/bin/sudo、
    /// sudoedit 的 setuid 位不能走同一通道——特权 chmod 对文件确定性剥
    /// S_ISUID/S_ISGID（防借 helper 铸 suid-root，两后端均有单测固定），无
    /// CAP_FSETID 的 chown(2) 亦独立清位。setuid 二进制改经 chroot 在 base_os
    /// 内以 root 顺序执行 chown→chmod：euid=0 的 chmod 重设 4755 不经过 crbs
    /// 剥位层，落盘即真实 setuid（bash 在 helper chroot 程序白名单内）。
    async fn harden_base_os_for_nspawn(base_os: &Path, gid: u32) -> crate::Result<()> {
        let base = base_os.to_path_buf();
        tokio::task::spawn_blocking(move || -> crate::Result<()> {
            let backend = crate::privilege::get_privilege_backend();
            let fix =
                |path: std::path::PathBuf, uid: u32, gid: u32, mode: u32| -> crate::Result<()> {
                    let path = match path.canonicalize() {
                        Ok(p) => p,
                        Err(_) => path,
                    };
                    if path.exists() {
                        backend.chown(&path, uid, gid, false)?;
                        backend.chmod(&path, mode, false)?;
                    }
                    Ok(())
                };
            fix(base.join("etc/sudoers"), 0, gid, 0o440)?;
            fix(base.join("etc/sudo.conf"), 0, gid, 0o640)?;
            fix(base.join("etc/sudoers.d"), 0, gid, 0o755)?;
            Ok(())
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("harden base_os sudoers files: {}", e)))??;

        const FIX_TIMEOUT: Duration = Duration::from_secs(60);
        let script = format!(
            "for f in /usr/bin/sudo /usr/bin/sudoedit; do\n  [ -e \"$f\" ] || continue\n  chown 0:{gid} \"$f\"\n  chmod 4755 \"$f\"\ndone\n"
        );
        let status = chroot_status(
            base_os,
            &["/usr/bin/bash", "-c", &script],
            None,
            Some(FIX_TIMEOUT),
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("harden base_os suid binaries: {}", e)))?;
        if !status.success() {
            return Err(CrbsError::io_message(format!(
                "harden base_os suid binaries failed: {status}"
            )));
        }
        Ok(())
    }

    /// 修复 base_os 对应的 package_cache（被误删/不完整时）：重扫 base_os 内
    /// dnf cache 补缺失包并同步 .packages.json。合并策略：既有条目优先
    ///（防 dnf cache 被清理后清单截断），仅追加新条目；无 dnf cache 时按快照
    /// manifest 播种（快照仓安装不留 RPM），清单无变化则不重写。
    async fn repair_base_package_cache(
        base_os: &Path,
        config: &crate::config::Config,
    ) -> crate::Result<()> {
        if config.package_cache_path.as_os_str().is_empty() {
            return Ok(());
        }
        let packages_json_path = base_os.join(".packages.json");

        let existing = if tokio::fs::try_exists(&packages_json_path).await? {
            Some(
                crate::engine::cache::read_packages_json(&packages_json_path)
                    .await
                    .map_err(|e| {
                        CrbsError::io_message(format!("read existing .packages.json: {}", e))
                    })?,
            )
        } else {
            None
        };

        let mut index = crate::engine::cache::cache_dnf_cache(
            base_os,
            &config.package_cache_path,
            existing.as_ref(),
        )
        .await
        .map_err(|e| CrbsError::io_message(format!("repair base package cache from: {}", e)))?
        .unwrap_or_default();

        if let Some(existing) = &existing {
            for (k, v) in existing {
                index.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        if let Some(seed) = snapshot::snapshot_package_index(base_os).await? {
            for (k, v) in seed {
                index.entry(k).or_insert(v);
            }
        }

        if index.is_empty() || existing.as_ref().is_some_and(|e| *e == index) {
            return Ok(());
        }
        debug!(
            product = %config.product,
            count = index.len(),
            "Repaired base package cache"
        );
        crate::engine::cache::write_packages_json(&packages_json_path, &index)
            .await
            .map_err(|e| CrbsError::io_message(format!("write .packages.json: {}", e)))?;
        Ok(())
    }

    /// 递归复制 overlay 目录到 base_os，保留权限。路径穿越检查由调用方完成
    ///（canonicalize + starts_with）；symlink 复制链接本身，不跟随。
    async fn copy_overlay_dir(src: &std::path::Path, dst: &std::path::Path) -> crate::Result<()> {
        let mut entries = tokio::fs::read_dir(src)
            .await
            .map_err(|e| CrbsError::from_io_context("read overlay dir", e))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("read overlay dir entry", e))?
        {
            let src_path = entry.path();
            let name = src_path.file_name().ok_or_else(|| {
                CrbsError::io_message(format!(
                    "overlay entry has no file name: {}",
                    src_path.display()
                ))
            })?;
            let dst_path = dst.join(name);

            let metadata = tokio::fs::symlink_metadata(&src_path)
                .await
                .map_err(|e| CrbsError::from_io_context("symlink_metadata", e))?;

            if metadata.file_type().is_symlink() {
                let target = tokio::fs::read_link(&src_path)
                    .await
                    .map_err(|e| CrbsError::from_io_context("read overlay symlink", e))?;
                if target.is_absolute() {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "overlay contains absolute symlink {} -> {}; refusing to copy",
                            src_path.display(),
                            target.display()
                        ),
                    });
                }
                #[cfg(unix)]
                {
                    tokio::fs::symlink(&target, &dst_path)
                        .await
                        .map_err(|e| CrbsError::from_io_context("create overlay symlink", e))?;
                }
                #[cfg(not(unix))]
                {
                    tracing::warn!(
                        src = %src_path.display(),
                        dst = %dst_path.display(),
                        "Skipping overlay symlink on non-Unix platform"
                    );
                }
            } else if metadata.is_dir() {
                tokio::fs::create_dir_all(&dst_path)
                    .await
                    .map_err(|e| CrbsError::from_io_context("create overlay dir", e))?;
                Box::pin(Self::copy_overlay_dir(&src_path, &dst_path)).await?;
            } else {
                tokio::fs::copy(&src_path, &dst_path)
                    .await
                    .map_err(|e| CrbsError::from_io_context("copy overlay file ->", e))?;
            }
        }
        Ok(())
    }
}

/// post_init 执行结果决策（纯函数便于单测）。失败且未声明 `ignore_failure`
/// 时返回错误——定制（证书、镜像配置等）静默缺失会让半成品 base_os 被
/// 当成品使用；成功或 `ignore_failure=true`（尽力而为）返回 None。
fn post_init_failure(
    command: &str,
    ignore_failure: bool,
    success: bool,
    exit_code: Option<i32>,
) -> Option<CrbsError> {
    if success || ignore_failure {
        None
    } else {
        Some(CrbsError::io_message(format!(
            "post_init '{}' failed: exit_code={:?}",
            command, exit_code
        )))
    }
}

/// CRBS 自身运行必需的基础包，与用户 `base_packages` 无关：无论怎么配置
/// init 都自动安装。`dnf` 在列：无 SharedLayer 时 install-deps 在 chroot 内
/// 跑 `dnf builddep`，base 不装 dnf 则全新 root 首次构建必死于
/// "dnf: command not found"。
pub(super) const REQUIRED_BASE_PACKAGES: &[&str] =
    &["bash", "coreutils", "shadow", "sudo", "dnf", "gawk"];

/// 合并 CRBS 运行时必需包、用户构建工具链和可选的 ccache。
///
/// 顺序：必需包 → 用户包（去重） → ccache（若启用且未显式列出）。
pub(super) fn merge_base_packages(
    user_packages: &[String],
    ccache_enabled: &BoolOrPackages,
) -> Vec<String> {
    let mut pkgs: Vec<String> = REQUIRED_BASE_PACKAGES
        .iter()
        .map(|s| s.to_string())
        .collect();
    for p in user_packages {
        if !pkgs.contains(p) {
            pkgs.push(p.clone());
        }
    }
    if ccache_enabled.is_configured() && !pkgs.contains(&"ccache".to_string()) {
        pkgs.push("ccache".to_string());
    }
    pkgs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_base_packages_injects_required_packages() {
        let user = vec!["rpm-build".to_string()];
        let merged = merge_base_packages(&user, &BoolOrPackages::Bool(false));

        assert_eq!(
            &merged[..5],
            &["bash", "coreutils", "shadow", "sudo", "dnf"]
        );
        assert!(merged.contains(&"rpm-build".to_string()));
        assert!(!merged.contains(&"ccache".to_string()));
    }

    #[test]
    fn merge_base_packages_deduplicates_user_and_required() {
        let user = vec!["sudo".to_string(), "dnf".to_string()];
        let merged = merge_base_packages(&user, &BoolOrPackages::Bool(false));

        let sudo_count = merged.iter().filter(|p| *p == "sudo").count();
        assert_eq!(sudo_count, 1);
        let dnf_count = merged.iter().filter(|p| *p == "dnf").count();
        assert_eq!(dnf_count, 1);
        let gawk_count = merged.iter().filter(|p| *p == "gawk").count();
        assert_eq!(gawk_count, 1);
        assert_eq!(merged.len(), 6);
    }

    #[test]
    fn merge_base_packages_appends_ccache_when_configured() {
        let user = vec!["rpm-build".to_string()];
        let merged = merge_base_packages(&user, &BoolOrPackages::Bool(true));
        assert_eq!(merged.last(), Some(&"ccache".to_string()));
    }

    #[test]
    fn merge_base_packages_does_not_duplicate_explicit_ccache() {
        let user = vec!["ccache".to_string(), "rpm-build".to_string()];
        let merged = merge_base_packages(&user, &BoolOrPackages::Bool(true));
        let ccache_count = merged.iter().filter(|p| *p == "ccache").count();
        assert_eq!(ccache_count, 1);
    }

    /// 指纹确定性 + 配置敏感性：同配置恒等；base_packages / ccache_enabled /
    /// releasever / builder 四元组任一变更都必须换指纹——这是不一致检测的根基。
    #[test]
    fn requested_fingerprint_is_deterministic_and_config_sensitive() {
        fn config(packages: &[&str], ccache: bool) -> crate::config::Config {
            crate::config::Config {
                base_packages: packages.iter().map(|s| s.to_string()).collect(),
                ccache_enabled: BoolOrPackages::Bool(ccache),
                ..Default::default()
            }
        }
        let base = BuildEngine::requested_fingerprint(&config(&["rpm-build"], false));
        assert_eq!(
            base,
            BuildEngine::requested_fingerprint(&config(&["rpm-build"], false))
        );
        assert_eq!(base.len(), 64);
        assert_ne!(
            base,
            BuildEngine::requested_fingerprint(&config(&["rpm-build", "gcc"], false))
        );
        assert_ne!(
            base,
            BuildEngine::requested_fingerprint(&config(&["rpm-build"], true))
        );

        let with_env = crate::config::Config {
            releasever: Some("9".into()),
            builder_user: "builder".into(),
            builder_uid: 1000,
            builder_group: "builders".into(),
            builder_gid: 1000,
            ..config(&["rpm-build"], false)
        };
        let env_base = BuildEngine::requested_fingerprint(&with_env);
        let mut bumped_releasever = with_env.clone();
        bumped_releasever.releasever = Some("10".into());
        assert_ne!(
            env_base,
            BuildEngine::requested_fingerprint(&bumped_releasever)
        );
        let mut no_releasever = with_env.clone();
        no_releasever.releasever = None;
        let mut empty_releasever = with_env.clone();
        empty_releasever.releasever = Some(String::new());
        assert_eq!(
            BuildEngine::requested_fingerprint(&no_releasever),
            BuildEngine::requested_fingerprint(&empty_releasever)
        );
        let mut u = with_env.clone();
        u.builder_user = "other-builder".into();
        assert_ne!(env_base, BuildEngine::requested_fingerprint(&u));
        let mut uid = with_env.clone();
        uid.builder_uid = 1001;
        assert_ne!(env_base, BuildEngine::requested_fingerprint(&uid));
        let mut g = with_env.clone();
        g.builder_group = "other-group".into();
        assert_ne!(env_base, BuildEngine::requested_fingerprint(&g));
        let mut gid = with_env.clone();
        gid.builder_gid = 1002;
        assert_ne!(env_base, BuildEngine::requested_fingerprint(&gid));
    }

    /// `base_os_request_fresh` 矩阵：.digest 存在且 .requested 匹配才 true；
    /// 缺失 / 不一致 / 空 / 乱码（非 UTF-8）/ .digest 缺失一律 false。
    /// 编排逻辑依赖 dnf 装机，单测跑不到。
    #[tokio::test]
    async fn base_os_request_fresh_matrix() {
        let tmp = tempfile::tempdir().unwrap();
        let base_os = tmp.path().join("base");
        std::fs::create_dir_all(&base_os).unwrap();
        let expected = "expected-fingerprint";

        std::fs::write(base_os.join(".digest"), b"digest").unwrap();
        std::fs::write(base_os.join(".requested"), format!("{expected}\n")).unwrap();
        assert!(BuildEngine::base_os_request_fresh(&base_os, expected).await);

        std::fs::write(base_os.join(".requested"), b"stale-fingerprint").unwrap();
        assert!(!BuildEngine::base_os_request_fresh(&base_os, expected).await);

        std::fs::write(base_os.join(".requested"), b"").unwrap();
        assert!(!BuildEngine::base_os_request_fresh(&base_os, expected).await);

        std::fs::write(base_os.join(".requested"), [0xff, 0xfe, b'x']).unwrap();
        assert!(!BuildEngine::base_os_request_fresh(&base_os, expected).await);

        std::fs::remove_file(base_os.join(".requested")).unwrap();
        assert!(!BuildEngine::base_os_request_fresh(&base_os, expected).await);

        std::fs::write(base_os.join(".requested"), expected).unwrap();
        std::fs::remove_file(base_os.join(".digest")).unwrap();
        assert!(!BuildEngine::base_os_request_fresh(&base_os, expected).await);
    }

    /// post_init 失败决策三态：成功 / ignore_failure 失败 / 硬失败。
    #[test]
    fn post_init_failure_decision_matrix() {
        assert!(post_init_failure("ok", false, true, None).is_none());
        assert!(post_init_failure("notify", true, false, Some(1)).is_none());
        let err = post_init_failure("cert", false, false, Some(2)).unwrap();
        assert!(err.to_string().contains("cert"));
        assert!(err.to_string().contains("2"));
    }

    /// 其它已死 pid 的 tmp-*/old-* 兄弟目录被选出待删；当前 pid（重入时可能
    /// 仍在使用）、属主进程仍存活的、base_os 本体与无关目录必须跳过。
    #[tokio::test]
    async fn stale_init_temp_dirs_selects_other_pid_tmp_and_old_only() {
        let dead = reaped_pid().await;
        let live_dir = tempfile::tempdir().unwrap();
        let mut live_child = if cfg!(target_os = "linux") {
            let live_bin = live_dir.path().join("crbs-sleeper");
            std::fs::copy("/usr/bin/sleep", &live_bin).unwrap();
            std::process::Command::new(&live_bin)
                .arg("30")
                .spawn()
                .unwrap()
        } else {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        };
        let live = live_child.id();

        let tmp = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let base_os = tmp.path().join("base");
        for name in [
            format!("base.tmp-{dead}"),
            format!("base.old-{dead}"),
            format!("base.tmp-{pid}"),
            format!("base.old-{pid}"),
            format!("base.old-{live}"),
            "base".to_string(),
            "base.tmp".to_string(),
            "base.other-1".to_string(),
            "base.tmp-garbage".to_string(),
            "dnf-cache".to_string(),
            ".init.lock".to_string(),
        ] {
            std::fs::create_dir_all(tmp.path().join(name)).unwrap();
        }

        let stale = BuildEngine::stale_init_temp_dirs(&base_os, pid)
            .await
            .unwrap();
        let mut names: Vec<String> = stale
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut expected = vec![format!("base.old-{dead}"), format!("base.tmp-{dead}")];
        expected.sort();
        assert_eq!(
            names, expected,
            "must select exactly the dead-pid tmp/old dirs"
        );

        let _ = live_child.kill();
        let _ = live_child.wait();
    }

    /// 端到端：残留目录经特权 rm-rf 真正删除、当前 pid 保留。
    /// SetuidBackend::rm_rf 是纯 std::fs 实现，unix 全平台可跑。
    #[tokio::test]
    async fn cleanup_stale_init_temp_dirs_removes_stale_keeps_own_pid() {
        let dead = reaped_pid().await;
        let tmp = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let base_os = tmp.path().join("base");
        std::fs::create_dir_all(tmp.path().join(format!("base.tmp-{dead}"))).unwrap();
        std::fs::create_dir_all(tmp.path().join(format!("base.old-{dead}"))).unwrap();
        std::fs::create_dir_all(tmp.path().join(format!("base.tmp-{pid}"))).unwrap();
        std::fs::write(tmp.path().join(format!("base.tmp-{dead}/payload")), b"x").unwrap();

        BuildEngine::cleanup_stale_init_temp_dirs(&base_os, pid).await;

        assert!(!tmp.path().join(format!("base.tmp-{dead}")).exists());
        assert!(!tmp.path().join(format!("base.old-{dead}")).exists());
        assert!(tmp.path().join(format!("base.tmp-{pid}")).exists());
    }

    /// 返回一个确定已死亡的 pid：spawn 短命子进程并 wait 收尸（reap 后
    /// getpgid 报 ESRCH）；极小概率被立即复用成活进程时换下一个。
    async fn reaped_pid() -> u32 {
        for _ in 0..16 {
            let mut child = std::process::Command::new("sleep")
                .arg("0")
                .spawn()
                .unwrap();
            let pid = child.id();
            let _ = child.wait().unwrap();
            if !crate::util::is_process_alive(i64::from(pid)).await {
                return pid;
            }
        }
        panic!("could not obtain a reaped pid after 16 attempts");
    }

    /// `check_active_guard` 矩阵：false 时 0 active 放行，building / pending /
    /// assigned 拒（ValidationFailed）；僵尸（crbs_pid 死）先修复再放行。
    /// true 全放行——chain build 并发 task 各自 INSERT pending 后进 init，
    /// 不应被自己撞自己。
    mod active_build_guard_matrix {
        use super::*;
        use crate::state::{BuildInsert, StateStore};
        use std::sync::Arc;

        async fn tmp_store() -> (tempfile::TempDir, Arc<StateStore>) {
            let tmp = tempfile::tempdir().unwrap();
            let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
            (tmp, store)
        }

        /// builds.task_id NOT NULL：build 行挂到先插好的本地任务行上。
        async fn insert<'a>(
            store: &StateStore,
            product: &'a str,
            pkg: &'a str,
            phase: &'a str,
        ) -> BuildInsert<'a> {
            let task_id = crate::state::test_state::seed_task(store, product, pkg).await;
            BuildInsert {
                product,
                pkg_name: pkg,
                phase,
                backend: "chroot",
                user: "tester",
                crbs_pid: Some(std::process::id() as i64),
                task_id: Some(task_id),
                ..Default::default()
            }
        }

        #[tokio::test]
        async fn bypass_false_zero_active_allows() {
            let (_tmp, store) = tmp_store().await;
            let r = BuildEngine::check_active_guard(&store, "p", false).await;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
        }

        #[tokio::test]
        async fn bypass_false_building_rejects() {
            let (_tmp, store) = tmp_store().await;
            store
                .insert_build(insert(&store, "p", "pkg-1", "building").await)
                .await
                .unwrap();
            let r = BuildEngine::check_active_guard(&store, "p", false).await;
            match r {
                Err(CrbsError::ValidationFailed { message }) => {
                    assert!(message.contains("active/pending"), "msg: {}", message);
                }
                other => panic!("expected ValidationFailed, got {:?}", other),
            }
        }

        #[tokio::test]
        async fn bypass_false_pending_rejects_preserves_daa4e0e_semantics() {
            let (_tmp, store) = tmp_store().await;
            store
                .insert_build(insert(&store, "p", "pkg-1", "pending").await)
                .await
                .unwrap();
            let r = BuildEngine::check_active_guard(&store, "p", false).await;
            assert!(
                matches!(r, Err(CrbsError::ValidationFailed { .. })),
                "expected ValidationFailed, got {:?}",
                r
            );
        }

        /// 'assigned'（已派发到 worker、尚未开始）同样算 active：dispatch 后
        /// worker 接手前 init/clean 重建 base_os 会踢掉该 build，必须拒。
        #[tokio::test]
        async fn bypass_false_assigned_rejects() {
            let (_tmp, store) = tmp_store().await;
            store
                .insert_build(insert(&store, "p", "pkg-1", "assigned").await)
                .await
                .unwrap();
            let r = BuildEngine::check_active_guard(&store, "p", false).await;
            assert!(
                matches!(r, Err(CrbsError::ValidationFailed { .. })),
                "expected ValidationFailed for assigned build, got {:?}",
                r
            );
        }

        #[tokio::test]
        async fn bypass_false_dead_pid_zombie_repaired_allows() {
            let (_tmp, store) = tmp_store().await;
            let mut zombie = insert(&store, "p", "pkg-1", "building").await;
            zombie.crbs_pid = Some(2_000_000_000);
            let id = store.insert_build(zombie).await.unwrap();

            let r = BuildEngine::check_active_guard(&store, "p", false).await;
            assert!(r.is_ok(), "expected Ok after zombie repair, got {:?}", r);

            let rec = store.get_build(id).await.unwrap().unwrap();
            assert_eq!(rec.phase, "failed", "zombie should be repaired to failed");
        }

        #[tokio::test]
        async fn bypass_true_zero_active_allows() {
            let (_tmp, store) = tmp_store().await;
            let r = BuildEngine::check_active_guard(&store, "p", true).await;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
        }

        /// chain 修复点：10 个 pending 模拟 chain round 并发，必须放行。
        #[tokio::test]
        async fn bypass_true_many_pending_allows_chain_repair() {
            let (_tmp, store) = tmp_store().await;
            for i in 0..10 {
                store
                    .insert_build(insert(&store, "p", &format!("pkg-{}", i), "pending").await)
                    .await
                    .unwrap();
            }
            let r = BuildEngine::check_active_guard(&store, "p", true).await;
            assert!(
                r.is_ok(),
                "bypass_guard=true must NOT trip on pending rows (chain build repair), got {:?}",
                r
            );
        }

        #[tokio::test]
        async fn bypass_true_building_allows() {
            let (_tmp, store) = tmp_store().await;
            store
                .insert_build(insert(&store, "p", "pkg-1", "building").await)
                .await
                .unwrap();
            let r = BuildEngine::check_active_guard(&store, "p", true).await;
            assert!(r.is_ok(), "expected Ok, got {:?}", r);
        }
    }
}
