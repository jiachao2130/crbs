// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建脚本执行编排：宏合并、阶段推进、日志与资源采样。

use crate::engine::build::packages::load_base_os_packages_at;
use crate::engine::build::phase::{run_script_phase, worker_hostname, RunScriptArgs};
use crate::engine::build::script::{write_hook_files, write_script};
use crate::engine::pipeline;
use crate::error::CrbsError;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// reproduce 两阶段共用的 bind mount 列表：可选本地仓库目录 + 结果目录（容器内 `/builddir/result`）。
fn reproduce_binds(
    local_repo_dir: Option<&std::path::Path>,
    result_dir: &std::path::Path,
) -> Vec<crate::engine::backend::BindMount> {
    let mut binds = Vec::new();
    if let Some(repo) = local_repo_dir {
        binds.push(crate::engine::backend::BindMount {
            host: repo.display().to_string(),
            container: "/mnt/crbs-repo".to_string(),
            read_only: false,
        });
    }
    binds.push(crate::engine::backend::BindMount {
        host: result_dir.display().to_string(),
        container: "/builddir/result".to_string(),
        read_only: false,
    });
    binds
}

/// 回放沙箱的 rpm 验签中和宏：镜像策略 `%_pkgverify_level all` 会无视 repo 的
/// gpgcheck=0 强制验签，而沙箱 rpmdb 无任何 gpg-pubkey。回放完整性由逐包
/// sha256 锚保证，GPG 不参与。写入构建 overlay 的 /etc/rpm——install-deps 的
/// dnf（容器内）与后续 rpmbuild 读到 none，压过镜像 all。
const REPRODUCE_PKGVERIFY_MACRO: &str = concat!(
    "# crbs reproduce sandbox: integrity is per-package sha256; signature policy neutralized\n",
    "%_pkgverify_level none\n"
);

/// 中和宏在构建 overlay 内的落点（`/etc/rpm` 由镜像 rpm 包创建，缺目录的
/// 镜像上写失败即复现失败，fail-closed）。
fn pkgverify_macro_path(root: &Path) -> PathBuf {
    root.join("etc/rpm/macros.crbs-reproduce")
}

/// [`BuildEngine::execute_build_script`] 的参数包（全 Copy；noarch 失败重试仅
/// 回退 `target_override` 复用同一份）。`target_override` 携带 effective target：
/// 调用方已折入引擎级 `target_arch`（override 优先），重试清成 `None` 即落回宿主 arch。
#[derive(Clone, Copy)]
pub(crate) struct ExecuteScriptParams<'a> {
    pub(crate) root: &'a std::path::Path,
    pub(crate) build_dir: &'a std::path::Path,
    pub(crate) result_dir: &'a std::path::Path,
    pub(crate) result_rpms: &'a std::path::Path,
    pub(crate) result_srpms: &'a std::path::Path,
    pub(crate) config: &'a crate::config::Config,
    pub(crate) pkg_name: &'a str,
    pub(crate) build_id: i64,
    pub(crate) srpm: &'a std::path::Path,
    pub(crate) has_shared_layer: bool,
    pub(crate) ccache_for_this_pkg: bool,
    pub(crate) cancel_token: &'a tokio_util::sync::CancellationToken,
    pub(crate) build_start: std::time::Instant,
    pub(crate) build_timeout: Option<std::time::Duration>,
    pub(crate) target_override: Option<&'a str>,
    /// 资源采样器（构建级共享）。`None` = 采样关闭。
    pub(crate) resource_sampler: Option<&'a crate::engine::resource_sample::ResourceSampler>,
    /// tmpfs 观测目标（prepare 产出，构建级恒定；None = 不采样 tmpfs）。
    pub(crate) tmpfs_watch: Option<&'a crate::engine::resource_sample::TmpfsWatch>,
}

impl crate::engine::BuildEngine {
    /// 在 overlay 挂载完成后执行构建脚本、收集产物，返回 `BuildOutputs`（GPG
    /// 签名由调用方在本函数之外执行）。reproduce Phase 1 扫描的 cache/快照索引
    /// 仅在函数内部消费（mismatch/missing 校验与计数日志），不随返回值外传——
    /// provenance 的 dep_index 恒用源记录锚（见 provenance.rs）。
    pub(crate) async fn execute_build_script(
        &self,
        params: ExecuteScriptParams<'_>,
    ) -> crate::Result<crate::types::BuildOutputs> {
        let ExecuteScriptParams {
            root,
            build_dir,
            result_dir,
            result_rpms,
            result_srpms,
            config,
            pkg_name,
            build_id,
            srpm,
            has_shared_layer,
            ccache_for_this_pkg,
            cancel_token,
            build_start,
            build_timeout,
            target_override,
            resource_sampler,
            tmpfs_watch,
        } = params;

        // 时间自锚定（mtime_normalize，非 det）：构建起点取墙钟 S，BUILDTIME
        // 头与 payload mtime 统一为 S——回放锚（源构建 BUILDTIME）因此与源构
        // 建逐字节对齐。此时尚无 payload 文件，钳制全覆盖。det（changelog-SDE）
        // 与 replay（源 SRPM/源构建锚）走各自时间语义，不叠加。
        if config.mtime_normalize
            && !config.deterministic
            && self.replay_build_time.is_none()
            && self.reproduce_expected.is_none()
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            self.time_anchor_epoch
                .store(now, std::sync::atomic::Ordering::Relaxed);
        }
        let time_anchor_epoch = {
            let v = self
                .time_anchor_epoch
                .load(std::sync::atomic::Ordering::Relaxed);
            (v > 0).then_some(v)
        };

        // 时间锚局部快照：replay BUILDTIME 优先，落 mtime_normalize 构建起点；
        // SOURCE_DATE_EPOCH 单点读此处，无锚（det 普通构建走 changelog-SDE）为 None。
        let sde_epoch = self.replay_build_time.or(time_anchor_epoch);

        // worker 主机名：容器 hostname 决策入参（decide_container_hostname——
        // 非 det 源构建的钉值、其余形态的回落锚），函数级取一次供全部 spawn
        // 阶段共用。
        let worker_hostname = worker_hostname();

        for subdir in &["SPECS", "SOURCES", "SRPMS"] {
            tokio::fs::create_dir_all(build_dir.join(subdir))
                .await
                .map_err(|e| CrbsError::from_io_context("create dir", e))?;
        }
        // build dir 改属 builder、保留 crbs 组可写：非 root 主进程仍需复制 SRPM / 写脚本。
        let crbs_gid = crate::privilege::crbs_group_gid_async()
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("lookup crbs group gid for build dir: {}", e))
            })?;
        crate::engine::build::permissions::chown_chmod_2770(
            build_dir,
            config.builder_uid,
            crbs_gid,
            "build dir",
        )
        .await?;

        // 复制 SRPM 到 /builddir/INPUT：避开 nspawn 内 /tmp 被 tmpfs 覆盖、/builddir/SRPMS 与 result_dir/SRPMS 的 mount 冲突。
        let dest_srpm = root.join("builddir").join("INPUT").join(
            srpm.file_name()
                .ok_or_else(|| CrbsError::io_message("srpm path has no file name"))?,
        );
        let input_dir = dest_srpm
            .parent()
            .ok_or_else(|| CrbsError::io_message("dest_srpm has no parent"))?;
        tokio::fs::create_dir_all(input_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("create INPUT dir", e))?;
        tokio::fs::copy(srpm, &dest_srpm)
            .await
            .map_err(|e| CrbsError::from_io_context("copy srpm", e))?;
        // fs::copy 保留源权限位：server 世界的源是上传暂存文件（组不变量
        // 0660，builder 用户不在 crbs 组），原样拷进 INPUT 会让容器内
        // install-srpm 的 rpm open 直接 EACCES（135 实测）。INPUT 内文件按 0644 落盘。
        {
            let mut perm = tokio::fs::metadata(&dest_srpm)
                .await
                .map_err(|e| CrbsError::from_io_context("stat copied srpm", e))?
                .permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perm, 0o644);
            tokio::fs::set_permissions(&dest_srpm, perm)
                .await
                .map_err(|e| CrbsError::from_io_context("chmod copied srpm 0644", e))?;
        }

        let srpm_name = dest_srpm
            .file_name()
            .ok_or_else(|| CrbsError::io_message("dest_srpm path has no file name"))?
            .to_string_lossy();

        // BTreeMap：key 排序迭代，保证生成的 --define 序列（构建脚本）逐字节确定，
        // reproduce/provenance 才能跨 run 比对（合并序见 merge_build_macros）。
        let (macros, det_overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &config.rpm_macros,
            dist: self.dist.as_deref(),
            with_features: &self.with_features,
            without_features: &self.without_features,
            deterministic: config.deterministic,
            buildhost: &config.buildhost,
            replay_build_host: self.replay_build_host.as_deref(),
            replay_build_time: self.replay_build_time,
            time_anchor_epoch,
            cli_macros: &self.cli_macros,
        });
        // CLI --define 覆盖核心确定性宏：不阻止（显式覆盖口子保留），warning 留痕。
        for key in &det_overrides {
            warn!(
                pkg = %pkg_name,
                macro_key = %key,
                value = %macros[*key],
                "deterministic mode: CLI --define overrides a core determinism macro; \
                 byte-identical output is no longer guaranteed"
            );
        }
        // ccache 不变量：CCACHE_NOHASHDIR=1 安全依赖 _topdir 恒为 /builddir（merge_rpm_macros
        // 强制 + parse_macros 拒覆盖）；路径进缓存键会让冷/热 ccache 命中分叉，漂移显式报错。
        if ccache_for_this_pkg && macros.get("_topdir").map(String::as_str) != Some("/builddir") {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "ccache build invariant violated: _topdir must be /builddir for \
                     CCACHE_NOHASHDIR=1 to be safe, got {:?}",
                    macros.get("_topdir")
                ),
            });
        }
        // 内容归一化门控与宏注入同源：det 组、replay 时间锚、mtime 自锚定
        // （sde_epoch = replay_build_time.or(time_anchor_epoch)，恰为两个带锚
        // 注入点的并集）。二进制随门控落沙箱根顶层（容器内 /crbs-normalize）；
        // 宿主缺失 = 宿主包过旧，fail-closed 拒绝构建（与宏体 [ -x ] 守卫、
        // || exit 1 三重兜底，错误指明版本不匹配）。
        if config.deterministic || sde_epoch.is_some() {
            install_normalize_binary(root, Path::new(NORMALIZE_HOST_BIN), pkg_name).await?;
        }
        let rpm_macros_owned: Vec<(String, String)> = macros.into_iter().collect();

        let ctx = pipeline::StepContext {
            builder_user: &config.builder_user,
            build_target: &config.build_target,
            rpm_macros: &rpm_macros_owned,
            srpm_name: &srpm_name,
            ccache_enabled: ccache_for_this_pkg,
            ccache_max_size: &config.ccache_max_size,
            dnf_cache_enabled: config.dnf_cache_enabled,
            has_shared_layer,
            hooks: &config.hooks,
            nocheck: self.nocheck,
            noclean: self.noclean,
            nodebuginfo: self.nodebuginfo,
            // target_override 已是 effective target（引擎级 target_arch 已折入），不得再
            // .or(self.target_arch)：noarch 重试清 override 后要连引擎级 noarch 压掉，落回宿主 arch。
            target_arch: target_override,
            local_repo_dir: self.local_repo_dir.as_deref().and_then(|p| p.to_str()),
            follow_logs: self.follow_logs,
            deterministic: config.deterministic,
            // reproduce（重放）一律走冷 ccache——CCACHE_DIR 指向容器内临时
            // 空目录，强制真实编译路径（见 StepContext::ccache_cold 注）。
            ccache_cold: self.reproduce_expected.is_some(),
            // builddep weak deps 开关透传（None = dnf 默认行为）。
            builddep_install_weak_deps: config.builddep_install_weak_deps.unwrap_or(true),
            // repro-from-srpm：SRPM 头 BUILDTIME 作为容器内 SOURCE_DATE_EPOCH；须透传进
            // rpmbuild 的 sudo env 前缀——sudo env_reset 会剥掉脚本 shell 环境，缺此拿不到 epoch。
            source_date_epoch: sde_epoch,
            // 复现解析域旗标透传：install-deps 据此 disablerepo=* 钉死唯一源。
            replay_snapshot_domain: self.replay_snapshot_domain,
        };

        let build_log_path = result_dir.join("build.log");
        let mut log_opts = tokio::fs::OpenOptions::new();
        log_opts
            .create(true)
            // 必须带 read：失败分类（classify_script_failure → read_tail/全文件扫描）
            // 从本 fd try_clone 读尾部；只写 fd 的 dup 读返回 EBADF，分类器失明、
            // 根因无法透传（实测：ExcludeArch 快速失败路径两条 EBADF 告警）。
            .read(true)
            .write(true)
            .append(true);
        // 结果目录对构建容器可写：上一次尝试可预植 build.log symlink 指向宿主
        // 文件，跟随 open 会把构建日志写进目标。O_NOFOLLOW 命中即 ELOOP 失败。
        #[cfg(unix)]
        log_opts.custom_flags(nix::libc::O_NOFOLLOW);
        let build_log_file = log_opts
            .open(&build_log_path)
            .await
            .map_err(|e| CrbsError::from_io_context("open build.log", e))?;

        // prepare-layer START 进时间线；标记与 pipeline 脚本步骤标记同一格式（parse_phase_markers 消费）。
        append_phase_marker(
            &build_log_file,
            format!(
                "\n# CRBS_PHASE_START prepare-layer {:.3}\n",
                phase_marker_ts()
            ),
        )
        .await;

        // 三处 spawn 共用的 RunScriptArgs 装配：仅 script/binds 随 phase 变化，
        // 其余字段（backend/日志/取消/超时/hostname/env 锚/采样器）恒定。
        let phase_args =
            |script: &'static str, binds: Vec<crate::engine::backend::BindMount>| RunScriptArgs {
                backend: &*self.backend,
                root,
                script,
                build_log_file: &build_log_file,
                terminal_tx: self.terminal_tx.clone(),
                cancel_token,
                build_start,
                build_timeout,
                network: config.network,
                binds,
                machine_name_suffix: Some(build_id.to_string()),
                deterministic: config.deterministic,
                // replay：值存在时 hostname 同样钉死（nspawn 消费，与 deterministic 模式对齐）。
                pin_hostname: self.replay_mode(),
                replay_build_host: self.replay_build_host.as_deref(),
                worker_hostname: worker_hostname.as_deref(),
                source_date_epoch: sde_epoch,
                resource_sampler,
                tmpfs_watch,
            };

        if let Some(ref expected) = self.reproduce_expected {
            // hook 文件先于两阶段脚本落盘（0640 builder 属主，见 write_hook_files）：
            // Phase 1 的 install-srpm 会 patch spec 引用 spec hook 文件，Phase 2
            // 的 scriptlet 才消费它。
            write_hook_files(
                root,
                &pipeline::hook_files(&ctx),
                config.builder_uid,
                config.builder_gid,
            )
            .await?;

            // 验签中和宏先于 Phase 1 落盘（/etc/rpm 属 root，经特权层 root:root
            // 0644 写入）：install-deps 的 dnf 在容器内读 /etc/rpm，晚于该步则
            // 强制验签的镜像上 builddep 全灭（GPG check FAILED）。
            crate::privilege::write_file_async(
                &pkgverify_macro_path(root),
                REPRODUCE_PKGVERIFY_MACRO.as_bytes(),
                Some(0o644),
                Some(0),
                Some(0),
            )
            .await?;

            let deps_script_content = pipeline::Pipeline::rpm_build()
                .disable("build")
                .disable("ccache-summary")
                .compose(&ctx);
            let deps_script_path = root.join("crbs-reproduce-deps.sh");
            write_script(&deps_script_path, &deps_script_content, 0o755).await?;

            info!(pkg = %pkg_name, backend = %self.backend.name(), "Reproduce Phase 1: installing deps");
            let binds = reproduce_binds(self.local_repo_dir.as_deref(), result_dir);
            run_script_phase(phase_args("/crbs-reproduce-deps.sh", binds)).await?;

            // 加载 base_os 包清单，区分真缺失 builddep 与 base_os 已有包；加载失败必须传播（否则误判缺失、校验失真）。
            let packages_json_path = config
                .crbs_root
                .join(&config.product)
                .join("base")
                .join(".packages.json");
            let base_os_pkgs = load_base_os_packages_at(&packages_json_path)
                .await
                .map_err(|e| {
                    CrbsError::io_message(format!(
                        "reproduce Phase 1: load base_os packages: {}",
                        e
                    ))
                })?;
            if base_os_pkgs.is_none() {
                // 清单缺失：missing 无法区分 builddep 与 base_os 包（不可校验 ≠ 缺失），
                // 跳过该部分（SHA256 校验不受影响）；deterministic 硬失败（静默会误记 same）。
                if config.deterministic {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "deterministic mode provenance hard gate: base_os package \
                             manifest ({}) is missing; \
                             missing-check for base_os packages cannot run (reinit the \
                             product base_os to regenerate it)",
                            packages_json_path.display(),
                        ),
                    });
                }
                warn!(
                    product = %config.product,
                    "Reproduce: base_os package manifest missing; skipping missing-check for base_os packages"
                );
            }

            let cache_scan =
                crate::engine::cache::cache_dnf_cache(root, &config.package_cache_path, None)
                    .await
                    .map_err(|e| {
                        CrbsError::io_message(format!("reproduce Phase 1: scan dnf cache: {}", e))
                    })?;
            // 第三源：快照仓 Packages。dnf4 对 file:// 仓不落 dnf 缓存，builddep
            // --enablerepo=crbs-local 实际安装的就是快照文件——cache 扫描覆盖不到，
            // 须并入已验集合并独立现算 sha256（不复用恢复时的校验结论）。
            let snapshot_index = match self.local_repo_dir.as_deref() {
                Some(repo) => Some(
                    crate::engine::cache::scan_repo_packages(repo)
                        .await
                        .map_err(|e| {
                            CrbsError::io_message(format!(
                                "reproduce Phase 1: scan snapshot repo: {}",
                                e
                            ))
                        })?,
                ),
                None => None,
            };
            // cache 目录是否在场（区别"目录存在但无 RPM"与"无目录"），供收口
            // 日志区分两形态；merge 会 move cache_scan，先取。
            let cache_scan_present = cache_scan.is_some();
            let actual = merge_verified_sources(cache_scan, snapshot_index);
            // 空已验集合收口：dnf 缓存与快照 Packages 均无 RPM 时，expected 非空
            // 则逐依赖做 base_os 归属判定（见
            // verify_expected_against_base_os_when_sources_empty），守住 provenance 的
            // record ⊆ cache ∪ snapshot ∪ base_os 硬门；清单缺失仅非 deterministic 可达，跳过升 warn。
            let actual = if actual.is_empty() {
                if !expected.is_empty() {
                    let cache_form = if cache_scan_present {
                        "dnf cache present but has no RPMs"
                    } else {
                        "no dnf cache directory"
                    };
                    match verify_expected_against_base_os_when_sources_empty(
                        expected,
                        base_os_pkgs.as_ref(),
                    ) {
                        Ok(true) => info!(
                            pkg = %pkg_name,
                            cache = cache_form,
                            "Reproduce: expected deps all in base_os manifest, proceeding to build"
                        ),
                        Ok(false) => warn!(
                            pkg = %pkg_name,
                            cache = cache_form,
                            "Reproduce: no RPMs in dnf cache or snapshot repo and base_os manifest missing; cannot verify expected deps, skipping fail-fast"
                        ),
                        Err(e) => return Err(e),
                    }
                }
                None
            } else {
                Some(actual)
            };
            if let Some(actual) = actual {
                let (mismatched, missing) =
                    classify_expected_against_sources(expected, &actual, base_os_pkgs.as_ref());
                if !mismatched.is_empty() {
                    let mut msg = String::from("SHA256 mismatch:\n");
                    for m in &mismatched {
                        msg.push_str(&format!("  ! {}\n", m));
                    }
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "Reproduce fail-fast: package verification failed\n{}",
                            msg
                        ),
                    });
                }
                if !missing.is_empty() {
                    // Phase 1 只装 builddep（base_os 包重建时已校验、不进 dnf cache）；非 base_os 包缺失必须失败。
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "Reproduce fail-fast: {} builddep package(s) missing from Phase 1 dnf cache, snapshot repo Packages, and base_os manifest:\n  {}",
                            missing.len(),
                            missing.join("\n  ")
                        ),
                    });
                }
                info!(pkg = %pkg_name, count = actual.len(), "Reproduce: SHA256 verified, proceeding to build");
            }

            let build_script_content = pipeline::Pipeline::rpm_build()
                .disable("ccache-init")
                .disable("install-srpm")
                .disable("install-deps")
                .compose(&ctx);
            let build_script = root.join("crbs-reproduce-build.sh");
            write_script(&build_script, &build_script_content, 0o755).await?;

            append_phase_marker(
                &build_log_file,
                format!(
                    "\n# CRBS_PHASE_END prepare-layer 0 {:.3}\n",
                    phase_marker_ts()
                ),
            )
            .await;

            // 保存脚本到 result_dir（debug 用）：hook 体外置后脚本不含敏感内容
            //（只有外置 hook 文件的路径引用），直接持久化原文，无需脱敏副本。
            let result_script = result_dir.join("crbs-build.sh");
            if let Err(e) = crate::util::write_result_file_no_follow(
                &result_script,
                build_script_content.as_bytes(),
            )
            .await
            {
                warn!(pkg = %pkg_name, path = %result_script.display(), error = %e, "Failed to save script");
            }

            info!(pkg = %pkg_name, backend = %self.backend.name(), "Reproduce Phase 2: building");
            let binds = reproduce_binds(self.local_repo_dir.as_deref(), result_dir);
            run_script_phase(phase_args("/crbs-reproduce-build.sh", binds)).await?;
        } else {
            // hook 文件落盘（0640 builder 属主，见 write_hook_files）：脚本只引用路径，
            // hook 体不出现在容器内全体可读的脚本文件里。
            write_hook_files(
                root,
                &pipeline::hook_files(&ctx),
                config.builder_uid,
                config.builder_gid,
            )
            .await?;
            let build_script = root.join("crbs-build.sh");
            let script = pipeline::Pipeline::rpm_build().compose(&ctx);
            crate::engine::build::script::write_script(&build_script, &script, 0o755).await?;
            append_phase_marker(
                &build_log_file,
                format!(
                    "\n# CRBS_PHASE_END prepare-layer 0 {:.3}\n",
                    phase_marker_ts()
                ),
            )
            .await;
            // result_dir 副本：脚本原文无 hook 体（已外置，见上），无需
            // 脱敏重组；顺带规避 overlayfs → ext4 的 copy_file_range EPERM。
            let result_script = result_dir.join("crbs-build.sh");
            if let Err(e) =
                crate::util::write_result_file_no_follow(&result_script, script.as_bytes()).await
            {
                warn!(
                    pkg = %pkg_name,
                    path = %result_script.display(),
                    error = %e,
                    "Failed to write build script to result_dir"
                );
            }

            info!(pkg = %pkg_name, backend = %self.backend.name(), "Executing build script");
            run_script_phase(phase_args("/crbs-build.sh", Vec::new())).await?;
        }

        info!(pkg = %pkg_name, "Build script exited successfully");

        // collect-artifacts START：产物收集；错误路径留未闭合 START，时间线按"unclosed = running"渲染。
        append_phase_marker(
            &build_log_file,
            format!(
                "\n# CRBS_PHASE_START collect-artifacts {:.3}\n",
                phase_marker_ts()
            ),
        )
        .await;

        let mut rpms = Vec::new();
        let mut srpms = Vec::new();
        for scan_root in [result_rpms, result_srpms] {
            let mut dirs = vec![scan_root.to_path_buf()];
            while let Some(dir) = dirs.pop() {
                let mut entries = match tokio::fs::read_dir(&dir).await {
                    Ok(e) => e,
                    Err(e) => {
                        // 静默跳过会把"成功构建但零 RPM"伪装成合法 -bs 场景，须留排障线索。
                        warn!(
                            pkg = %pkg_name,
                            path = %dir.display(),
                            error = %e,
                            "read result dir during artifact scan failed"
                        );
                        continue;
                    }
                };
                loop {
                    match entries.next_entry().await {
                        Ok(Some(entry)) => {
                            let path = entry.path();
                            let file_type = match entry.file_type().await {
                                Ok(t) => t,
                                Err(e) => {
                                    warn!(
                                        pkg = %pkg_name,
                                        path = %path.display(),
                                        error = %e,
                                        "stat result entry during artifact scan failed"
                                    );
                                    continue;
                                }
                            };
                            if file_type.is_dir() {
                                dirs.push(path);
                            } else if file_type.is_file()
                                && path.extension().map(|e| e == "rpm").unwrap_or(false)
                            {
                                if scan_root.as_os_str() == result_srpms.as_os_str() {
                                    srpms.push(path);
                                } else {
                                    rpms.push(path);
                                }
                            }
                            // symlink 不收集：构建根内可植入指向 root 外的链接，签名/chain
                            // 会沿链接读写宿主文件（与 util::collect_rpm_paths 同口径）。
                        }
                        Ok(None) => break,
                        Err(e) => {
                            warn!(
                                pkg = %pkg_name,
                                path = %dir.display(),
                                error = %e,
                                "iterate result dir during artifact scan failed"
                            );
                            break;
                        }
                    }
                }
            }
        }
        // 排序保证签名/上报顺序逐字节确定（与 util::collect_rpm_paths 一致）。
        rpms.sort();
        srpms.sort();

        // mock 不重写 SRPM → result_dir/SRPMS 为空；复制输入 SRPM 使结果目录自包含（reproduce/diff 依赖）。
        if srpms.is_empty() {
            if let Some(name) = srpm.file_name() {
                let dest = result_srpms.join(name);
                tokio::fs::copy(srpm, &dest)
                    .await
                    .map_err(|e| CrbsError::from_io_context("copy input srpm to result dir", e))?;
                debug!(pkg = %pkg_name, src = %srpm.display(), dst = %dest.display(), "Copied input SRPM to result dir");
                srpms.push(dest);
            }
        }

        // collect-artifacts END（GPG 签名在调用方执行，不在本 span 覆盖范围）。
        append_phase_marker(
            &build_log_file,
            format!(
                "\n# CRBS_PHASE_END collect-artifacts 0 {:.3}\n",
                phase_marker_ts()
            ),
        )
        .await;

        Ok(crate::types::BuildOutputs {
            build_id,
            pkg_name: pkg_name.to_string(),
            rpms,
            srpms,
            logs: vec![result_dir.join("build.log")],
            result_dir: result_dir.to_path_buf(),
            retries: 0,
            signed: false,
        })
    }
}

/// [`merge_build_macros`] 的参数集合（纯函数入参，便于单测注入）。
pub(crate) struct MergeBuildMacrosArgs<'a> {
    pub(crate) config_macros: &'a std::collections::BTreeMap<String, String>,
    pub(crate) dist: Option<&'a str>,
    pub(crate) with_features: &'a [String],
    pub(crate) without_features: &'a [String],
    pub(crate) deterministic: bool,
    pub(crate) buildhost: &'a str,
    /// repro-from-srpm 回放主机名（`None` = 头缺失/未探测）；`Some` 注入 `_buildhost` 并参与时间宏门控。
    pub(crate) replay_build_host: Option<&'a str>,
    /// repro-from-srpm 回放时间（SRPM 头 BUILDTIME epoch 秒，None = 头缺失）。
    /// host/time 任一存在即注入时间宏（与 replay_mode 同口径）；_buildhost 只跟 host。
    pub(crate) replay_build_time: Option<i64>,
    /// 时间自锚定（mtime_normalize，非 det）：Some = 注入时间宏组（SDE 由调用
    /// 方注入 env），宏组与 replay 组同两键、幂等。
    pub(crate) time_anchor_epoch: Option<i64>,
    pub(crate) cli_macros: &'a std::collections::BTreeMap<String, String>,
}

/// 确定性模式注入的核心宏（注入值恒 "1"，`_buildhost` 例外取配置值）；CLI
/// --define 覆盖告警面 = 本数组 + [`NORMALIZE_PAYLOAD_MACRO`]（后者是脚本体
/// 宏，注入门控不同，不进本注入循环）。
pub(crate) const DETERMINISM_CORE_MACROS: [&str; 4] = [
    "source_date_epoch_from_changelog",
    "use_source_date_epoch_as_buildtime",
    "clamp_mtime_to_source_date_epoch",
    "_buildhost",
];

/// 内容归一化宏键：值是脚本体而非 "1" 布尔（见 [`CRBS_NORMALIZE_PAYLOAD_BODY`]），
/// 且注入门控与 det 组不同（replay 时间锚 / mtime 自锚定也注入，走
/// [`inject_normalize_payload`]），因此不进 DETERMINISM_CORE_MACROS 的 "1"
/// 注入循环；CLI --define 覆盖告警与核心宏同等对待（覆盖会替换归一化链，
/// 破坏逐字节复现）。
pub(crate) const NORMALIZE_PAYLOAD_MACRO: &str = "crbs_normalize_payload";

/// crbs_normalize_payload 宏体：构建后内容归一化调用（ar/zip/gzip 内嵌时间
/// 戳统一到构建锚，helper 见 crates/crbs-normalize）。经 pipeline 的
/// install-post 挂载点（__brp_strip_static_archive 复合宏，位于最后一个
/// .a/zip 触碰步骤之后）在 %install 收尾执行。锚取 scriptlet 内
/// `$SOURCE_DATE_EPOCH`——det 组由 rpm 自 changelog 导出（rpmbuild 在跑各
/// scriptlet 前 setenv），replay/mtime_normalize 组由 sudo env 前缀注入；值
/// 缺失/非法时归一化失败 `|| exit 1` 使构建失败（fail-closed：det 包缺
/// changelog 本就无确定性可言，fail-fast 显性化）。
pub(crate) const CRBS_NORMALIZE_PAYLOAD_BODY: &str = "[ -x /crbs-normalize ] && /crbs-normalize --root \"$RPM_BUILD_ROOT\" --epoch \"$SOURCE_DATE_EPOCH\" || exit 1";

/// 注入内容归一化宏键（调用方须同时按门控把沙箱二进制落到 root 顶层，
/// 宏体 `[ -x /crbs-normalize ]` 守卫与引擎落盘互为 fail-closed 双保险）。
fn inject_normalize_payload(macros: &mut std::collections::BTreeMap<String, String>) {
    macros.insert(
        NORMALIZE_PAYLOAD_MACRO.to_string(),
        CRBS_NORMALIZE_PAYLOAD_BODY.to_string(),
    );
}

/// 构建宏合并（纯函数）：配置文件 → --dist → --with/--without → deterministic
/// 宏组 → replay 宏组 → CLI `--define`。deterministic 宏组压过产品/全局
/// `rpm_macros`（开启即接管），仍在 CLI --define 之前（用户显式覆盖口子保留）；
/// 返回 `(合并结果, 被 CLI 覆盖的核心确定性宏键列表)` 供调用方 warning（不阻止）。
/// replay 宏组 = `_buildhost`（SRPM 头原样，仅 host 存在时）+ 两个时间宏
/// （host/time 任一存在即注入，对齐 replay_mode 判定口径），刻意不注
/// `source_date_epoch_from_changelog`——它会把 changelog 日期覆盖注入的
/// BUILDTIME，而 SRPM 头恒有 BUILDTIME 无需兜底；对确定性宏组的覆盖是等值
/// 操作，静默不进 det_overrides。
/// `crbs_normalize_payload`（内容归一化宏体）与 clamp 同门控随三组注入：
/// det 组、replay 组（仅时间锚存在时）、mtime 自锚定组——host-only 回放
/// 无锚不注。
pub(crate) fn merge_build_macros(
    args: MergeBuildMacrosArgs<'_>,
) -> (
    std::collections::BTreeMap<String, String>,
    Vec<&'static str>,
) {
    let mut macros: std::collections::BTreeMap<String, String> = args
        .config_macros
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(d) = args.dist {
        macros.insert("dist".to_string(), d.to_string());
    }
    for feat in args.with_features {
        macros.insert(format!("with_{}", feat), "1".to_string());
    }
    for feat in args.without_features {
        macros.insert(format!("without_{}", feat), "1".to_string());
    }
    if args.deterministic {
        for key in DETERMINISM_CORE_MACROS
            .iter()
            // _buildhost 单独注入配置值（非 "1"）
            .filter(|k| **k != "_buildhost")
        {
            macros.insert((*key).to_string(), "1".to_string());
        }
        macros.insert("_buildhost".to_string(), args.buildhost.to_string());
        // 内容归一化与 clamp 同门控：锚 = rpm 自 changelog 导出的
        // $SOURCE_DATE_EPOCH，在 install-post 链执行、先于 payload 生成期的
        // clamp 钳制（顺序不变量见 pipeline INSTALL_POST_HOOK_DEFINE）。
        inject_normalize_payload(&mut macros);
    }
    // 时间宏与 replay_mode 同口径（host 或 time 任一存在即注入）：SDE 只按 time
    // 注入，宏缺席则 BUILDTIME 驱动不了 %buildtime/mtime。
    if args.replay_build_host.is_some() || args.replay_build_time.is_some() {
        macros.insert(
            "use_source_date_epoch_as_buildtime".to_string(),
            "1".to_string(),
        );
        macros.insert(
            "clamp_mtime_to_source_date_epoch".to_string(),
            "1".to_string(),
        );
        // 归一化只在时间锚存在时注入：host-only 回放无 SDE，宏体拿不到锚
        // 值（clamp 在无 SDE 时本就空转，不受影响）。
        if args.replay_build_time.is_some() {
            inject_normalize_payload(&mut macros);
        }
    }
    if let Some(host) = args.replay_build_host {
        macros.insert("_buildhost".to_string(), host.to_string());
    }
    // 时间自锚定（mtime_normalize）：同 replay 组两键（无 _buildhost——头主机
    // 名保持执行节点实名，回放锚会原样对齐源构建主机）。
    if args.time_anchor_epoch.is_some() {
        macros.insert(
            "use_source_date_epoch_as_buildtime".to_string(),
            "1".to_string(),
        );
        macros.insert(
            "clamp_mtime_to_source_date_epoch".to_string(),
            "1".to_string(),
        );
        // 锚存在才注入（锚 = sudo env 前缀写入的 $SOURCE_DATE_EPOCH）。
        inject_normalize_payload(&mut macros);
    }
    let mut det_overrides = Vec::new();
    for (k, v) in args.cli_macros {
        if args.deterministic {
            // 告警面 = 核心确定性宏 + crbs_normalize_payload（后者不进上方
            // "1" 注入循环，仅共用 CLI 覆盖告警，warning 留痕不阻止）。
            let override_warned = DETERMINISM_CORE_MACROS
                .iter()
                .chain(std::iter::once(&NORMALIZE_PAYLOAD_MACRO))
                .find(|c| *c == k);
            if let Some(key) = override_warned {
                det_overrides.push(*key);
            }
        }
        macros.insert(k.clone(), v.clone());
    }
    (macros, det_overrides)
}

/// 宿主侧 crbs-normalize 安装路径（crbs 主包 %files 落点）。
const NORMALIZE_HOST_BIN: &str = "/usr/libexec/crbs/crbs-normalize";

/// 把宿主 crbs-normalize 读出并原子写进沙箱根顶层（容器内 `/crbs-normalize`，
/// 0755，builder 可执行；复用 write_script 的同目录 tmp + rename 先例，字节
/// 版见 [`write_script_bytes`]）。宿主路径缺失 = 宿主 crbs 包落后于引擎预期
///（版本不匹配），构建明确失败（fail-closed）。
async fn install_normalize_binary(
    root: &Path,
    host_bin: &Path,
    pkg_name: &str,
) -> crate::Result<()> {
    let bytes = tokio::fs::read(host_bin).await.map_err(|e| {
        CrbsError::io_message(format!(
            "read host helper {} for payload normalization (pkg {pkg_name}): {e}; \
             the installed crbs host package predates the crbs-normalize binary \
             (version mismatch), refusing this build",
            host_bin.display()
        ))
    })?;
    crate::engine::build::script::write_script_bytes(&root.join("crbs-normalize"), &bytes, 0o755)
        .await
}

/// phase 标记时间戳：epoch 秒（f64，毫秒精度），解析端按 f64 读。
fn phase_marker_ts() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 空已验集合收口：dnf 缓存与快照 Packages 均无 RPM（`cache_dnf_cache` 返回
/// None / 索引空集且快照扫描为空）时，源记录 expected（NEVRA → SHA256）的
/// base_os 归属判定。`Ok(true)` = 全部 expected 在 base_os 清单（真·全在
/// base_os），放行；`Ok(false)` = 清单缺失不可判定（仅非 deterministic 可达），
/// 调用方升 warn 跳过；`Err(ValidationFailed)` = 任一 expected 既不在 dnf 缓存 /
/// 快照仓也不在 base_os 清单，环境与源记录不符——provenance 的 record ⊆
/// cache ∪ snapshot ∪ base_os 论证以本判定为唯一拦截面。
fn verify_expected_against_base_os_when_sources_empty(
    expected: &std::collections::HashMap<String, String>,
    base_os_pkgs: Option<&std::collections::HashSet<String>>,
) -> crate::Result<bool> {
    let Some(pkgs) = base_os_pkgs else {
        return Ok(false);
    };
    let missing: Vec<String> = expected
        .iter()
        .filter(|(nevra, _)| !pkgs.contains(nevra.as_str()))
        .map(|(nevra, sha)| format!("{nevra} ({sha})"))
        .collect();
    if missing.is_empty() {
        return Ok(true);
    }
    Err(CrbsError::ValidationFailed {
        message: format!(
            "Reproduce fail-fast: {} expected builddep package(s) absent from \
             Phase 1 dnf cache, snapshot repo Packages, and base_os manifest \
             (environment does not match the source build's recorded deps):\n  {}",
            missing.len(),
            missing.join("\n  ")
        ),
    })
}

/// 两源索引合并（纯函数，可注入测试）：cache 扫描为底、快照 Packages 条目覆盖
/// 同键——沙箱安装源就是快照文件，对账以快照为准，快照被篡改时不得被 cache
/// 好副本掩护（fail-safe）。
fn merge_verified_sources(
    cache_scan: Option<std::collections::HashMap<String, crate::engine::cache::CacheEntry>>,
    snapshot_index: Option<std::collections::HashMap<String, crate::engine::cache::CacheEntry>>,
) -> std::collections::HashMap<String, crate::engine::cache::CacheEntry> {
    let mut actual = cache_scan.unwrap_or_default();
    for (nevra, entry) in snapshot_index.into_iter().flatten() {
        actual.insert(nevra, entry);
    }
    actual
}

/// 三源对账分类（纯函数，可注入测试）：expected（NEVRA → sha256）逐包对照
/// 已验集合 actual（dnf cache ∪ 快照 Packages，sha 均为扫描时现算值）与 base_os
/// 清单，返回 (mismatched, missing)：前者 = 已验集合有但 sha 不符，后者 = 已验
/// 集合与 base_os 清单皆无。清单缺失时无法判定缺失包归属，missing 判定跳过
/// （调用方已在清单加载处 warn）。
fn classify_expected_against_sources(
    expected: &std::collections::HashMap<String, String>,
    actual: &std::collections::HashMap<String, crate::engine::cache::CacheEntry>,
    base_os_pkgs: Option<&std::collections::HashSet<String>>,
) -> (Vec<String>, Vec<String>) {
    let mut mismatched = Vec::new();
    let mut missing = Vec::new();
    for (nevra, expected_sha) in expected {
        match actual.get(nevra) {
            Some(entry) if entry.sha256 == *expected_sha => {}
            Some(entry) => {
                mismatched.push(format!(
                    "{}: expected {} got {}",
                    nevra, expected_sha, entry.sha256
                ));
            }
            None => match base_os_pkgs {
                // 缺失的包必须能在 base_os 清单中找到，否则视为真正缺失。
                Some(pkgs) if pkgs.contains(nevra) => {
                    debug!(nevra = %nevra, "Reproduce: package expected in base_os, not in Phase 1 dnf cache or snapshot repo");
                }
                Some(_) => {
                    missing.push(format!("{} ({})", nevra, expected_sha));
                }
                // 清单缺失：无法判定缺失包归属，跳过 missing 判定（见加载处 warn）。
                None => {}
            },
        }
    }
    (mismatched, missing)
}

/// 向 build.log 追加一条 `# CRBS_PHASE_*` 标记行（best-effort：失败仅 warn）。
/// 格式与 pipeline 脚本标记一致（profile::parse_phase_markers / 日志页 SSE 消费）；
/// `try_clone` 独立句柄 append——O_APPEND 下单次 `write_all` 与并发 tee 写互不撕裂。
async fn append_phase_marker(build_log_file: &tokio::fs::File, line: String) {
    use tokio::io::AsyncWriteExt as _;
    let mut handle = match build_log_file.try_clone().await {
        Ok(f) => f,
        Err(e) => {
            warn!(marker = %line.trim(), error = %e, "Failed to clone build.log fd for phase marker");
            return;
        }
    };
    if let Err(e) = handle.write_all(line.as_bytes()).await {
        warn!(marker = %line.trim(), error = %e, "Failed to append phase marker to build.log");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn cli_macros(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// deterministic 宏组注入 + 合并序：四个核心宏就位（`_buildhost` 用配置值）；
    /// 内容归一化宏随组注入（锚 = rpm 自 changelog 导出的 SDE）。
    #[test]
    fn merge_build_macros_injects_determinism_group() {
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        });
        assert_eq!(macros.get("source_date_epoch_from_changelog").unwrap(), "1");
        assert_eq!(
            macros.get("use_source_date_epoch_as_buildtime").unwrap(),
            "1"
        );
        assert_eq!(macros.get("clamp_mtime_to_source_date_epoch").unwrap(), "1");
        assert_eq!(macros.get("_buildhost").unwrap(), "crbs");
        assert_eq!(
            macros.get("crbs_normalize_payload").map(String::as_str),
            Some(CRBS_NORMALIZE_PAYLOAD_BODY)
        );
        assert!(overrides.is_empty());
    }

    /// 内容归一化宏体逐字节钉死：shell 片段、引号口径与 $RPM_BUILD_ROOT/
    /// $SOURCE_DATE_EPOCH 用法变更都会破坏 install-post 链执行与 fail-closed。
    #[test]
    fn normalize_payload_body_is_pinned() {
        assert_eq!(
            CRBS_NORMALIZE_PAYLOAD_BODY,
            "[ -x /crbs-normalize ] && /crbs-normalize --root \"$RPM_BUILD_ROOT\" \
             --epoch \"$SOURCE_DATE_EPOCH\" || exit 1"
        );
    }

    /// 时间自锚定（mtime_normalize）：注入两键时间宏（无 _buildhost——头主机
    /// 名保持执行节点实名，回放锚会原样对齐源构建主机）；非 det 基线不注入
    /// det 组其余宏。内容归一化宏随锚注入（锚 = sudo env 前缀写入的 SDE）。
    #[test]
    fn merge_build_macros_time_anchor_injects_time_macros() {
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: Some(1791458952),
            cli_macros: &Default::default(),
        });
        assert!(overrides.is_empty());
        assert_eq!(
            macros
                .get("use_source_date_epoch_as_buildtime")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            macros
                .get("clamp_mtime_to_source_date_epoch")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            macros.get("crbs_normalize_payload").map(String::as_str),
            Some(CRBS_NORMALIZE_PAYLOAD_BODY)
        );
        assert!(!macros.contains_key("_buildhost"));
    }

    /// 非 deterministic：宏组不注入，CLI 宏照常生效。
    #[test]
    fn merge_build_macros_without_determinism_is_unchanged() {
        let cli = cli_macros(&[("dist", ".fc42")]);
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &cli,
        });
        assert!(!macros.contains_key("source_date_epoch_from_changelog"));
        assert!(!macros.contains_key("_buildhost"));
        assert!(!macros.contains_key("crbs_normalize_payload"));
        assert_eq!(macros.get("dist").unwrap(), ".fc42");
        assert!(overrides.is_empty());
    }

    /// deterministic 宏组压过产品 rpm_macros（开启即接管）；CLI --define 仍最后生效。
    #[test]
    fn merge_build_macros_cli_define_wins_with_override_flag() {
        let config_macros = cli_macros(&[("_buildhost", "product-host"), ("dist", ".el9")]);
        let cli = cli_macros(&[("_buildhost", "my-host"), ("dist", ".fc42")]);
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &config_macros,
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &cli,
        });
        assert_eq!(macros.get("_buildhost").unwrap(), "my-host");
        assert_eq!(macros.get("dist").unwrap(), ".fc42");
        assert_eq!(overrides, vec!["_buildhost"]);
    }

    /// CLI --define 覆盖 crbs_normalize_payload 与核心宏同进告警面（脚本体
    /// 宏被覆盖会替换归一化链、破坏逐字节复现，warning 留痕不阻止；非 det
    /// 时该宏本就不注入，覆盖静默）。
    #[test]
    fn merge_build_macros_cli_define_of_normalize_payload_is_flagged() {
        let cli = cli_macros(&[("crbs_normalize_payload", "echo hijacked")]);
        let (det, det_overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &cli,
        });
        assert_eq!(
            det.get("crbs_normalize_payload").map(String::as_str),
            Some("echo hijacked")
        );
        assert_eq!(det_overrides, vec!["crbs_normalize_payload"]);

        let (_, silent) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &cli,
        });
        assert!(silent.is_empty());
    }

    /// 产品 rpm_macros 的非核心键保留；deterministic 宏组不误伤。
    #[test]
    fn merge_build_macros_keeps_unrelated_product_macros() {
        let config_macros = cli_macros(&[("_vendor", "UnitedLinux"), ("_buildhost", "x")]);
        let (macros, _) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &config_macros,
            dist: Some(".el9"),
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        });
        assert_eq!(macros.get("_vendor").unwrap(), "UnitedLinux");
        assert_eq!(macros.get("_buildhost").unwrap(), "crbs");
        assert_eq!(macros.get("dist").unwrap(), ".el9");
    }

    /// replay 宏组 × deterministic=true：replay 值胜出（`_buildhost` 覆盖为
    /// SRPM 头值）且 `det_overrides` 为空——等值/有意覆盖，静默不告警；CLI 仍最后生效。
    #[test]
    fn merge_build_macros_replay_wins_over_determinism_silently() {
        let cli = cli_macros(&[("dist", ".fc42")]);
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: Some("probehost"),
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &cli,
        });
        assert_eq!(macros.get("_buildhost").unwrap(), "probehost");
        assert_eq!(
            macros.get("use_source_date_epoch_as_buildtime").unwrap(),
            "1"
        );
        assert_eq!(macros.get("clamp_mtime_to_source_date_epoch").unwrap(), "1");
        assert!(overrides.is_empty(), "replay overrides must be silent");
        assert_eq!(macros.get("dist").unwrap(), ".fc42");
    }

    /// replay 宏组 × deterministic=false：仅 replay 宏注入（不带入确定性语义），det_overrides 恒空。
    /// host-only 回放（只有 BUILDHOST 无 BUILDTIME）无时间锚：clamp 照注
    /// （无 SDE 时空转），内容归一化宏不注（宏体拿不到锚值）。
    #[test]
    fn merge_build_macros_replay_without_determinism_injects_only_replay_group() {
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: Some("probehost"),
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        });
        assert_eq!(macros.get("_buildhost").unwrap(), "probehost");
        assert_eq!(
            macros.get("use_source_date_epoch_as_buildtime").unwrap(),
            "1"
        );
        assert_eq!(macros.get("clamp_mtime_to_source_date_epoch").unwrap(), "1");
        assert!(!macros.contains_key("crbs_normalize_payload"));
        assert!(overrides.is_empty());
    }

    /// 无 BUILDHOST 有 BUILDTIME 的外部包：时间宏仍注入，_buildhost 不注入；
    /// 内容归一化宏随时间锚注入。
    #[test]
    fn merge_build_macros_replay_time_only_injects_time_macros() {
        let (macros, overrides) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: Some(1_700_000_000),
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        });
        assert_eq!(
            macros.get("use_source_date_epoch_as_buildtime").unwrap(),
            "1"
        );
        assert_eq!(macros.get("clamp_mtime_to_source_date_epoch").unwrap(), "1");
        assert_eq!(
            macros.get("crbs_normalize_payload").map(String::as_str),
            Some(CRBS_NORMALIZE_PAYLOAD_BODY)
        );
        assert!(!macros.contains_key("_buildhost"));
        assert!(overrides.is_empty());
    }

    /// 负向钉：replay 宏组永不含 `source_date_epoch_from_changelog`（会用
    /// changelog 日期覆盖注入的 BUILDTIME，而 SRPM 头恒有 BUILDTIME 无需兜底）。
    /// 非 deterministic（replay 独自注入）时该键必须缺席；deterministic 时
    /// replay 叠加不得改动 det 宏组的该值。
    #[test]
    fn merge_build_macros_replay_never_injects_changelog_epoch() {
        let (macros, _) = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: false,
            buildhost: "crbs",
            replay_build_host: Some("probehost"),
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        });
        assert!(
            !macros.contains_key("source_date_epoch_from_changelog"),
            "replay group must not inject source_date_epoch_from_changelog"
        );

        let det_only = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: None,
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        })
        .0;
        let det_replay = merge_build_macros(MergeBuildMacrosArgs {
            config_macros: &Default::default(),
            dist: None,
            with_features: &[],
            without_features: &[],
            deterministic: true,
            buildhost: "crbs",
            replay_build_host: Some("probehost"),
            replay_build_time: None,
            time_anchor_epoch: None,
            cli_macros: &Default::default(),
        })
        .0;
        assert_eq!(
            det_only.get("source_date_epoch_from_changelog"),
            det_replay.get("source_date_epoch_from_changelog"),
            "replay overlay must not alter the det group's changelog epoch entry"
        );
    }

    /// 空已验集合收口决策表：①expected 非空且任一依赖不在 base_os 清单 →
    /// ValidationFailed（消息点名依赖并说明 cache/快照/清单三源皆无）；②全在清单
    /// → Ok(true)（含空 expected 退化形态）；③清单缺失（仅非 deterministic）→ Ok(false)。
    #[test]
    fn empty_source_scan_verification_covers_missing_manifest_and_mismatch() {
        use std::collections::{HashMap, HashSet};

        let expected: HashMap<String, String> = [
            ("bash-5.2-1.x86_64".to_string(), "sha-bash".to_string()),
            ("gcc-14.0-1.x86_64".to_string(), "sha-gcc".to_string()),
        ]
        .into_iter()
        .collect();
        let manifest: HashSet<String> = ["bash-5.2-1.x86_64".to_string()].into_iter().collect();

        let err = verify_expected_against_base_os_when_sources_empty(&expected, Some(&manifest))
            .unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("gcc-14.0-1.x86_64"), "message: {message}");
                assert!(message.contains("sha-gcc"), "message: {message}");
                assert!(
                    message.contains("snapshot repo Packages"),
                    "must name the snapshot repo as a verified source: {message}"
                );
            }
            other => panic!("expected ValidationFailed, got: {other:?}"),
        }

        let full: HashSet<String> = [
            "bash-5.2-1.x86_64".to_string(),
            "gcc-14.0-1.x86_64".to_string(),
        ]
        .into_iter()
        .collect();
        assert!(
            verify_expected_against_base_os_when_sources_empty(&expected, Some(&full)).unwrap()
        );
        assert!(
            verify_expected_against_base_os_when_sources_empty(&HashMap::new(), Some(&full))
                .unwrap()
        );

        assert!(!verify_expected_against_base_os_when_sources_empty(&expected, None).unwrap());
    }

    /// 三源对账分类：cache/快照命中（sha 相符）不报、sha 不符进 mismatch、
    /// 三源皆无进 missing、base_os 豁免不报、清单缺失跳过 missing 判定。
    #[test]
    fn classify_expected_covers_cache_snapshot_and_manifest_arms() {
        use std::collections::{HashMap, HashSet};

        type Index = HashMap<String, crate::engine::cache::CacheEntry>;
        let entry = |sha: &str| crate::engine::cache::CacheEntry {
            sha256: sha.to_string(),
            repo_id: None,
        };
        let actual: Index = [
            ("cache-hit-1.0-1.x86_64".to_string(), entry("sha-cache")),
            // 快照命中臂：cache 与 manifest 皆无、仅快照条目在已验集合（合并后
            // 与 cache 条目同形，见 merge_verified_sources 的覆盖语义钉测试）。
            (
                "snapshot-only-2.0-1.noarch".to_string(),
                entry("sha-snapshot"),
            ),
            ("corrupt-3.0-1.x86_64".to_string(), entry("sha-wrong")),
        ]
        .into_iter()
        .collect();
        let manifest: HashSet<String> =
            ["base-only-4.0-1.x86_64".to_string()].into_iter().collect();
        let expected: HashMap<String, String> = [
            (
                "cache-hit-1.0-1.x86_64".to_string(),
                "sha-cache".to_string(),
            ),
            (
                "snapshot-only-2.0-1.noarch".to_string(),
                "sha-snapshot".to_string(),
            ),
            ("corrupt-3.0-1.x86_64".to_string(), "sha-right".to_string()),
            ("base-only-4.0-1.x86_64".to_string(), "sha-base".to_string()),
            ("gone-5.0-1.x86_64".to_string(), "sha-gone".to_string()),
        ]
        .into_iter()
        .collect();

        let (mismatched, missing) =
            classify_expected_against_sources(&expected, &actual, Some(&manifest));
        assert_eq!(mismatched.len(), 1, "only the corrupt entry mismatches");
        assert!(
            mismatched[0].contains("corrupt-3.0-1.x86_64")
                && mismatched[0].contains("sha-right")
                && mismatched[0].contains("sha-wrong"),
            "mismatch must name package and both hashes: {}",
            mismatched[0]
        );
        assert_eq!(missing, vec!["gone-5.0-1.x86_64 (sha-gone)".to_string()]);

        // 清单缺失：missing 判定跳过（归属不可判），mismatch 照报。
        let (mismatched, missing) = classify_expected_against_sources(&expected, &actual, None);
        assert_eq!(mismatched.len(), 1);
        assert!(
            missing.is_empty(),
            "manifest absent must skip missing judgment"
        );

        // 空 expected 退化形态。
        let (mismatched, missing) =
            classify_expected_against_sources(&HashMap::new(), &actual, Some(&manifest));
        assert!(mismatched.is_empty() && missing.is_empty());
    }

    /// 两源合并：快照条目覆盖同键 cache 条目（沙箱安装源是快照文件，对账以
    /// 快照为准），cache 独有键保留；两源皆空得空表（触发 base_os 收口）。
    #[test]
    fn merge_verified_sources_snapshot_overrides_cache_on_key_conflict() {
        use std::collections::HashMap;

        let make = |sha: &str, repo: Option<&str>| crate::engine::cache::CacheEntry {
            sha256: sha.to_string(),
            repo_id: repo.map(str::to_string),
        };
        let mut cache = HashMap::new();
        cache.insert(
            "pkg-1.0-1.x86_64".to_string(),
            make("sha-from-cache", Some("src")),
        );
        cache.insert(
            "cache-only-2.0-1.noarch".to_string(),
            make("sha-only", None),
        );

        let mut snapshot = HashMap::new();
        snapshot.insert(
            "pkg-1.0-1.x86_64".to_string(),
            make("sha-from-snapshot", None),
        );

        let merged = merge_verified_sources(Some(cache.clone()), Some(snapshot));
        assert_eq!(
            merged["pkg-1.0-1.x86_64"].sha256, "sha-from-snapshot",
            "snapshot entry must override the same-key cache entry"
        );
        assert_eq!(
            merged["cache-only-2.0-1.noarch"].sha256, "sha-only",
            "cache-only keys must survive the merge"
        );

        assert!(merge_verified_sources(None, None).is_empty());
        let merged = merge_verified_sources(Some(cache), None);
        assert_eq!(merged["pkg-1.0-1.x86_64"].sha256, "sha-from-cache");
    }

    /// 验签中和宏的落点与策略行钉死：路径漂移或策略值非 none 都会令强制验签
    /// 的镜像上回放全灭（install-deps 的 dnf 读 overlay 内 /etc/rpm）。
    #[test]
    fn pkgverify_neutralization_pinned() {
        assert_eq!(
            pkgverify_macro_path(std::path::Path::new("/overlay-root")),
            PathBuf::from("/overlay-root/etc/rpm/macros.crbs-reproduce")
        );
        assert!(REPRODUCE_PKGVERIFY_MACRO.contains("%_pkgverify_level none"));
    }

    /// 归一化二进制落沙箱：宿主字节原样进 root 顶层、0755 可执行；
    /// 宿主缺失 → Err 且消息指明版本不匹配（fail-closed）。
    #[tokio::test]
    async fn install_normalize_binary_writes_sandbox_helper() {
        let host = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let host_bin = host.path().join("crbs-normalize");
        std::fs::write(&host_bin, b"\x7fELF-fake-bytes").unwrap();

        install_normalize_binary(root.path(), &host_bin, "testpkg")
            .await
            .unwrap();
        let installed = root.path().join("crbs-normalize");
        assert_eq!(std::fs::read(&installed).unwrap(), b"\x7fELF-fake-bytes");
        let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);

        let err = install_normalize_binary(root.path(), &host.path().join("missing"), "testpkg")
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("version mismatch"),
            "error must flag host package version mismatch: {message}"
        );
        assert!(
            message.contains("crbs-normalize"),
            "error must name the helper: {message}"
        );
    }
}
