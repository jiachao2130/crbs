// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地构建入口与公共导出：build/build_into 及构建选项处理。

pub(crate) mod cleanup_guard;
pub(crate) mod execution;
pub(crate) mod packages;
pub(crate) mod permissions;
pub(crate) mod phase;
pub(crate) mod provenance;
pub(crate) mod script;
pub(crate) mod url;

// url 模块 pub(crate)，经 pub use 开出 engine:: 根路径供 crbs-server 枚举入口消费。
pub use url::{enumerate_repo_src_rpms, SrcRpmEntry, ENUMERATE_SRC_RPMS_TIMEOUT};

use crate::engine::build::cleanup_guard::BuildCleanupGuard;
use crate::engine::build::execution::ExecuteScriptParams;
use crate::engine::build::packages::read_overlay_installed_packages;
use crate::engine::build::provenance::ProvenanceParams;
use crate::engine::prepare::MountOptions;
use crate::engine::shared_layer::{
    get_or_create_shared_layer, repo_fingerprint, SharedLayerParams,
};
use crate::engine::{BuildLifecycle, BuildOutcome};
use crate::error::CrbsError;
use crate::types::OVERLAY_READ_FAILURE_MARKER;
use tracing::{debug, error, info, warn};

/// SRPM 头查询（rpm -qp）的单次上限：正常查询亚秒级，停滞存储上可无限
/// 挂死，占住构建 future。
const RPM_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// 从 SRPM 路径派生包名：file_stem 去 `.src` 后缀，剩余须含 `-`（N-V-R
/// 最小校验）。Worker 须按同款规则推断 pkg_name 才能定位 `{product}/{pkg_name}/`
/// 结果目录（srpm_url 是下载端点，不能用于推断）。边界拒绝（空 / `.` / `..` /
/// 前导点 → `ValidationFailed`）：pkg_name 直接拼结果目录路径，会落
/// CurDir/ParentDir 或隐藏目录。stem 缺失 / 非 UTF-8 / 无 `.src` / 无 `-`
/// 同样拒绝、不回退——共享目录会让 chain 增量检查误判已建。
pub fn srpm_pkg_name(srpm: &std::path::Path) -> crate::Result<String> {
    let name = srpm
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_suffix(".src"))
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!(
                "cannot derive pkg_name from SRPM {}: file name is not N-V-R.src.rpm \
                 (malformed SRPM file name?)",
                srpm.display()
            ),
        })?
        .to_string();
    if name.is_empty() || name == "." || name == ".." || name.starts_with('.') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "cannot derive a safe pkg_name from SRPM {}: got {:?}",
                srpm.display(),
                name
            ),
        });
    }
    if !name.contains('-') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "cannot derive pkg_name from SRPM {}: {:?} has no N-V-R structure \
                 (malformed SRPM file name?)",
                srpm.display(),
                name
            ),
        });
    }
    Ok(name)
}

/// [`BuildEngine::run_build_in_dir`] 的参数包：result_dir/srpm 定位输入，
/// lifecycle/shell_lock 按值移动，target_override 覆盖本次 `--target`。
struct RunBuildParams<'a> {
    result_dir: &'a std::path::Path,
    srpm: &'a std::path::Path,
    /// 调用方入口已派生并校验的包名（build_into / build_with_target），避免逐层重算。
    pkg_name: &'a str,
    cancel_token: &'a tokio_util::sync::CancellationToken,
    lifecycle: BuildLifecycle,
    shell_lock: Option<std::fs::File>,
    build_start: std::time::Instant,
    target_override: Option<&'a str>,
    /// 资源采样器（None = 关闭）；脚本 phase 内启动/收尾，结果由 finish() 取走。
    resource_sampler: Option<&'a crate::engine::resource_sample::ResourceSampler>,
}

/// 把采样器快照句柄写入槽位（poller 预算 abort 路径的兜底取值入口；多包
/// 构建逐构建覆盖，abort 方读最近一次构建的累计值）。Mutex 中毒取内部值继续
///（缺兜底快照不影响构建本身，与采样侧同一降级姿态）。
fn store_snapshot_slot(
    slot: &crate::engine::ResourceSnapshotSlot,
    snapshot: crate::engine::ResourceSnapshot,
) {
    let fill = |mut guard: std::sync::MutexGuard<'_, Option<crate::engine::ResourceSnapshot>>| {
        *guard = Some(snapshot);
    };
    match slot.lock() {
        Ok(g) => fill(g),
        Err(p) => fill(p.into_inner()),
    }
}

impl crate::engine::BuildEngine {
    /// 按配置构造资源采样器（双口径间隔，见 `resource_sample::ResourceSampler`）；
    /// 已注入快照槽位时把句柄写入。双口径全关返回 `None`。
    fn new_resource_sampler(
        &self,
        config: &crate::config::Config,
    ) -> Option<crate::engine::resource_sample::ResourceSampler> {
        let sampler = crate::engine::resource_sample::ResourceSampler::from_intervals(
            config.resource_sample_interval_secs,
            config.resource_sample_interval_cgroup_secs,
        )?;
        if let Some(slot) = &self.resource_snapshot_slot {
            store_snapshot_slot(slot, sampler.snapshot());
        }
        Some(sampler)
    }

    /// 返回调用方提供的 lifecycle，否则按当前 caller/priority 新建；`srpm`
    /// 落本地任务行 srpm_path（可溯源）。
    async fn ensure_lifecycle(
        &self,
        product: &str,
        pkg_name: &str,
        srpm: &std::path::Path,
        prebuilt: Option<BuildLifecycle>,
    ) -> crate::Result<BuildLifecycle> {
        match prebuilt {
            Some(l) => Ok(l),
            None => {
                let user = self.caller().map(|c| c.username.as_str());
                let srpm_path = srpm.to_str();
                let context = crate::engine::BuildContext::new(self.priority)
                    .with_user(user.unwrap_or(""), None)
                    .with_crbs_pid(Some(std::process::id() as i64))
                    .with_srpm_path(srpm_path)
                    .with_product_config_toml(self.product_config_toml.as_deref())
                    .with_task_labels(&self.task_labels);
                let identity = crate::engine::BuildIdentity::new(product, pkg_name);
                BuildLifecycle::new_with_task(self.state.clone(), &identity, &context).await
            }
        }
    }

    /// 单包构建（外部提供结果目录）：不建时间戳子目录、不动 `latest`
    /// 链接，目录命名与链接管理归调用方。
    pub async fn build_into(
        &self,
        result_dir: &std::path::Path,
        srpm: &std::path::Path,
        cancel_token: &tokio_util::sync::CancellationToken,
        prebuilt_lifecycle: Option<BuildLifecycle>,
    ) -> crate::Result<crate::types::BuildOutputs> {
        let build_start = std::time::Instant::now();

        let pkg_name = srpm_pkg_name(srpm)?;
        crate::util::validate_pkg_name(&pkg_name)?;

        let config = &self.config;

        let lifecycle = self
            .ensure_lifecycle(&config.product, &pkg_name, srpm, prebuilt_lifecycle)
            .await?;

        let resource_sampler = self.new_resource_sampler(config);
        let outputs = self
            .run_build_in_dir(RunBuildParams {
                result_dir,
                srpm,
                pkg_name: &pkg_name,
                cancel_token,
                lifecycle,
                shell_lock: None,
                build_start,
                target_override: None,
                resource_sampler: resource_sampler.as_ref(),
            })
            .await?;

        if let Err(e) = crate::engine::build::permissions::finalize_result_dir(result_dir).await {
            warn!(path = %result_dir.display(), error = %e, "finalize result_dir permissions failed");
        }

        Ok(outputs)
    }

    /// 单包构建（最简路径）：无 SharedLayer，每次独立 dnf install；跳过
    /// Depsolve Cache / SQLite 状态 / GPG 签名。
    pub async fn build(
        &self,
        srpm: &std::path::Path,
        cancel_token: &tokio_util::sync::CancellationToken,
        prebuilt_lifecycle: Option<BuildLifecycle>,
    ) -> crate::Result<crate::types::BuildOutputs> {
        self.build_with_dir(srpm, cancel_token, prebuilt_lifecycle, None)
            .await
            .outputs
    }

    /// 与 `build_with_target` 相同，但不覆盖 `--target`。
    pub async fn build_with_dir(
        &self,
        srpm: &std::path::Path,
        cancel_token: &tokio_util::sync::CancellationToken,
        prebuilt_lifecycle: Option<BuildLifecycle>,
        result_dir_tx: Option<tokio::sync::watch::Sender<Option<std::path::PathBuf>>>,
    ) -> crate::types::BuildExecutionResult {
        self.build_with_target(srpm, cancel_token, prebuilt_lifecycle, result_dir_tx, None)
            .await
    }

    /// 与 `build` 相同，但返回 `BuildExecutionResult`：成败都携带 `result_dir`
    ///（Worker 失败时据此定位上传 build.log）。`result_dir_tx`：确切 result_dir
    /// 建成后、耗时步骤前回报，供日志流精确定位（同包并发按 mtime 扫描会误报
    /// 兄弟构建日志）。`target_override` 覆盖本次 `--target`（noarch 失败自动
    /// 回退宿主架构重试一次）。
    pub async fn build_with_target(
        &self,
        srpm: &std::path::Path,
        cancel_token: &tokio_util::sync::CancellationToken,
        prebuilt_lifecycle: Option<BuildLifecycle>,
        result_dir_tx: Option<tokio::sync::watch::Sender<Option<std::path::PathBuf>>>,
        target_override: Option<&str>,
    ) -> crate::types::BuildExecutionResult {
        let build_start = std::time::Instant::now();

        // 三处早退共用：此时 result_dir 尚未创建，result_dir 字段为空路径。
        let early_err = |e: CrbsError| crate::types::BuildExecutionResult {
            result_dir: std::path::PathBuf::new(),
            outputs: Err(e),
            resources: None,
        };

        let pkg_name = match srpm_pkg_name(srpm) {
            Ok(n) => n,
            Err(e) => return early_err(e),
        };
        if let Err(e) = crate::util::validate_pkg_name(&pkg_name) {
            return early_err(e);
        }

        let config = &self.config;

        let lifecycle = match self
            .ensure_lifecycle(&config.product, &pkg_name, srpm, prebuilt_lifecycle)
            .await
        {
            Ok(l) => l,
            Err(e) => return early_err(e),
        };
        let build_id = lifecycle.build_id();

        let pkg_root = config.result_dir.join(&config.product).join(&pkg_name);

        // 结果目录：{result_dir}/{product}/{pkg_name}/{timestamp}-{build_id}/
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let result_dir = pkg_root.join(format!("{}-{}", ts, build_id));

        // 父目录须 crbs 组共享可写并持久化 group-write + setgid，后续创建依赖它。
        let product_dir = pkg_root.parent().unwrap_or(&pkg_root).to_path_buf();
        let top_result_dir = config.result_dir.clone();
        if let Err(e) = tokio::fs::create_dir_all(&pkg_root).await {
            let err = CrbsError::from_io_context("create result parent dirs", e);
            let build_id = lifecycle.build_id();
            if let Err(e2) = lifecycle.complete(BuildOutcome::Failed, None).await {
                tracing::error!(build_id = %build_id, error = %e2, "Failed to mark build as completed after setup failure");
            }
            return crate::types::BuildExecutionResult {
                result_dir: result_dir.clone(),
                outputs: Err(err),
                resources: None,
            };
        }
        if let Err(e) =
            prepare_build_parent_dirs(&[top_result_dir, product_dir, pkg_root.clone()]).await
        {
            warn!(error = %e, "Failed to prepare parent directories for shared write");
        }

        if let Err(e) = tokio::fs::create_dir_all(&result_dir).await {
            let err = CrbsError::from_io_context("create result dir", e);
            let build_id = lifecycle.build_id();
            if let Err(e2) = lifecycle.complete(BuildOutcome::Failed, None).await {
                tracing::error!(build_id = %build_id, error = %e2, "Failed to mark build as completed after setup failure");
            }
            return crate::types::BuildExecutionResult {
                result_dir: result_dir.clone(),
                outputs: Err(err),
                resources: None,
            };
        }

        // result_dir 后建，须单独 prepare（父目录前一步已做）；必须在
        // create_dir_all 之后，否则 ENOENT 被 prepare 的 warn 吞掉。
        if let Err(e) = prepare_build_parent_dirs(std::slice::from_ref(&result_dir)).await {
            warn!(result_dir = %result_dir.display(), error = %e, "Failed to prepare result_dir for shared write");
        }

        if let Some(tx) = &result_dir_tx {
            let _ = tx.send(Some(result_dir.clone()));
        }

        let resource_sampler = self.new_resource_sampler(config);
        let run_result = self
            .run_build_in_dir(RunBuildParams {
                result_dir: &result_dir,
                srpm,
                pkg_name: &pkg_name,
                cancel_token,
                lifecycle,
                shell_lock: None,
                build_start,
                target_override,
                resource_sampler: resource_sampler.as_ref(),
            })
            .await;

        let outputs = match run_result {
            Ok(o) => o,
            Err(e) => {
                return crate::types::BuildExecutionResult {
                    result_dir: result_dir.clone(),
                    outputs: Err(e),
                    resources: resource_sampler.as_ref().and_then(|s| s.finish()),
                };
            }
        };

        // 更新 latest 软链接（临时名按 build_id 隔离，详见 update_latest_symlink）。
        let file_name = match outputs.result_dir.file_name() {
            Some(n) => n.to_os_string(),
            None => {
                return crate::types::BuildExecutionResult {
                    result_dir: result_dir.clone(),
                    outputs: Err(CrbsError::io_message("result_dir has no file name")),
                    resources: None,
                };
            }
        };
        // latest 链接是 advisory：lifecycle 已终态 Succeeded，链接失败只 warn，
        // 不能因此把构建报失败（DB 与上报口径会分叉）。
        if let Err(e) = update_latest_symlink(&pkg_root, &file_name, build_id).await {
            warn!(path = %pkg_root.display(), error = %e, "Failed to update latest symlink (advisory)");
        }

        crate::types::BuildExecutionResult {
            result_dir: result_dir.clone(),
            outputs: Ok(outputs),
            resources: resource_sampler.as_ref().and_then(|s| s.finish()),
        }
    }

    /// bind mount 一个构建子目录（result/RPMS/SRPMS）：chroot 侧建目录 + 私有 bind。
    async fn bind_build_subdir(
        cleanup_guard: &mut BuildCleanupGuard,
        build_dir: &std::path::Path,
        host: &std::path::Path,
        sub: &str,
        label: &str,
    ) -> crate::Result<()> {
        let chroot_dir = build_dir.join(sub);
        tokio::fs::create_dir_all(&chroot_dir)
            .await
            .map_err(|e| CrbsError::from_io_context(format!("create {sub} chroot dir"), e))?;
        cleanup_guard
            .mount_guard()?
            .bind_mount_private(Some(host), &chroot_dir, label)
            .await
    }

    async fn run_build_in_dir(
        &self,
        params: RunBuildParams<'_>,
    ) -> crate::Result<crate::types::BuildOutputs> {
        let RunBuildParams {
            result_dir,
            srpm,
            pkg_name,
            cancel_token,
            lifecycle,
            shell_lock,
            build_start,
            target_override,
            resource_sampler,
        } = params;

        let config = &self.config;
        let base_os = self.base_os_path();
        let result_dir_str = result_dir.to_string_lossy().to_string();
        let build_id = lifecycle.build_id();

        // pending → building：幂等（服务端已提前调过无害）；本地/Worker 路径
        // 缺此调用会让运行期 phase 恒 pending（影响 count_building_builds）。
        if let Err(e) = lifecycle.start_building().await {
            if let Err(e2) = lifecycle.complete(BuildOutcome::Failed, None).await {
                tracing::error!(build_id = %build_id, error = %e2, "Failed to mark build as completed after start_building failure");
            }
            return Err(e);
        }

        // 前置准备（base_os init / shell lock / SRPM 校验 / 结果目录）：错误统一
        // 经 complete_setup_failure 标终态，不留 stuck 活跃行。
        let setup_result: crate::Result<_> = async {
            if cancel_token.is_cancelled() {
                return Err(CrbsError::Cancelled);
            }
            if let Some(timeout) = self.build_timeout {
                if build_start.elapsed() > timeout {
                    return Err(CrbsError::Timeout);
                }
            }

            // init(false) 由 .init.lock 独占保护，已存在时 no-op（防并发进安装/清理）。
            let init_timeout = self
                .build_timeout
                .map(|t| t.saturating_sub(build_start.elapsed()));
            self.init(false, Some(cancel_token), init_timeout, true)
                .await?;

            // shell 互斥对全部构建生效（含 reproduce 重放）：重放与正常构建同用
            // 产品 base_os，须同样防与 crbs shell/clean 并发冲突。
            let _lock = match shell_lock {
                Some(lock) => Some(lock),
                None => Some(self.acquire_shell_lock().await?),
            };
            crate::util::validate_srpm_path(srpm)?;

            let mut magic = [0u8; 4];
            let mut srpm_file = tokio::fs::File::open(srpm)
                .await
                .map_err(|e| CrbsError::from_io_context("open srpm", e))?;
            tokio::io::AsyncReadExt::read_exact(&mut srpm_file, &mut magic)
                .await
                .map_err(|e| CrbsError::from_io_context("read srpm", e))?;
            if magic != crate::util::RPM_MAGIC {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "{} is not a valid SRPM (magic bytes mismatch)",
                        srpm.display()
                    ),
                });
            }

            tokio::fs::create_dir_all(&result_dir)
                .await
                .map_err(|e| CrbsError::from_io_context("create result dir", e))?;

            let result_rpms = result_dir.join("RPMS");
            tokio::fs::create_dir_all(&result_rpms)
                .await
                .map_err(|e| CrbsError::from_io_context("create result dir", e))?;
            let result_srpms = result_dir.join("SRPMS");
            tokio::fs::create_dir_all(&result_srpms)
                .await
                .map_err(|e| CrbsError::from_io_context("create result dir", e))?;

            // builder 在 chroot 内写、crbs 主进程也要写 build.log →
            // owner=builder、group=crbs、setgid 可写。
            let crbs_gid = crate::privilege::crbs_group_gid_async()
                .await
                .map_err(|e| {
                    CrbsError::io_message(format!("lookup crbs group gid for result dir: {}", e))
                })?;
            crate::engine::build::permissions::prepare_for_build(
                result_dir,
                config.builder_uid,
                crbs_gid,
            )
            .await?;
            debug!(
                result_dir = %result_dir.display(),
                uid = config.builder_uid,
                gid = crbs_gid,
                "Prepared result dir permissions for builder/crbs"
            );

            Ok((result_rpms, result_srpms, _lock))
        }
        .await;

        let (result_rpms, result_srpms, _lock) = match setup_result {
            Ok(v) => v,
            // setup 块内失败：目录可能未建，保守传 None。
            Err(e) => return Err(complete_setup_failure(lifecycle, None, e).await),
        };

        info!(product = %config.product, pkg = %pkg_name, "Starting build");

        // 提取 BuildRequires：位于 guard 构造前，错误必须经 complete_setup_failure
        // 补终态，否则构建停在 building。
        let build_requires = {
            let mut cmd = tokio::process::Command::new("rpm");
            cmd.arg("-qp")
                .arg("--queryformat")
                .arg("[%{REQUIRENAME} %{REQUIREFLAGS:depflags} %{REQUIREVERSION}\n]")
                .arg(srpm);
            // cancel+timeout 感知变体：rpm -qp 在停滞存储（SRPM 落在 NFS）上可
            // 无限挂死，300s 上限覆盖正常查询的量级冗余。
            let output =
                match crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
                    cmd,
                    "spawn rpm -qp",
                    Some(cancel_token),
                    RPM_QUERY_TIMEOUT,
                )
                .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        return Err(complete_setup_failure(
                            lifecycle,
                            Some(result_dir_str.as_str()),
                            e,
                        )
                        .await)
                    }
                };
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(complete_setup_failure(
                    lifecycle,
                    Some(result_dir_str.as_str()),
                    CrbsError::io_message(format!("rpm -qp failed: {}", stderr)),
                )
                .await);
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut reqs: Vec<String> = stdout
                .lines()
                .filter(|l| !l.is_empty() && !l.starts_with("rpmlib("))
                .map(|s| s.to_string())
                .collect();
            // sudo 注入参与列表：fingerprint 变化触发含 sudo 的新 SharedLayer。
            let sudo_dep = "sudo";
            if !reqs
                .iter()
                .any(|r| r.split_whitespace().next() == Some(sudo_dep))
            {
                reqs.push(sudo_dep.to_string());
            }
            reqs
        };

        let base_os_digest = match tokio::fs::read_to_string(base_os.join(".digest")).await {
            Ok(d) => d,
            Err(e) => {
                return Err(complete_setup_failure(
                    lifecycle,
                    Some(result_dir_str.as_str()),
                    CrbsError::from_io_context("read base_os digest", e),
                )
                .await);
            }
        };

        let srpm_name = srpm.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let shared_layer_for_this_pkg = config.shared_layer.is_enabled_for(srpm_name);
        let ccache_for_this_pkg = config.ccache_enabled.is_enabled_for(srpm_name);
        // deterministic 强制记录溯源（sha256/url 是重放正确性锚，缺失令复现率
        // 静默失真），不排除 reproduce 重放（det 产品一切构建都过溯源硬门）；
        // repro-from-srpm（replay 值存在）排除：无环境还原、无锚，误录无价值
        //（reproduce 重放复用源记录，临时 repo URL 无持久价值）。
        let record_provenance = should_record_provenance(
            config.deterministic,
            self.replay_mode(),
            // 槽位极性：reproduce_expected Some = reproduce 重放（源记录回放），
            // 与 replay-from-srpm（replay_mode）是两个独立排除维度
            self.reproduce_expected.is_some(),
            self.reproduce_enabled.is_enabled_for(srpm_name),
        );

        // builds.deterministic 打标（后置翻转，插入走 DB 默认 0）；失败仅
        // warn，缺失可由 DB 侧对账发现。
        if config.deterministic {
            if let Err(e) = self.state.set_build_deterministic(build_id, true).await {
                warn!(
                    build_id = %build_id,
                    error = %e,
                    "Failed to set builds.deterministic flag"
                );
            }
        }

        if let Err(e) = lifecycle
            .set_info(
                Some(&result_dir_str),
                Some(&base_os_digest),
                self.backend.name(),
            )
            .await
        {
            tracing::error!(build_id = %lifecycle.build_id(), error = %e, "Failed to update build info; continuing build");
        }

        let shared_layer_operation_timeout = self
            .build_timeout
            .map(|t| t.saturating_sub(build_start.elapsed()));
        let (lowerdir, layer_digest) = if build_requires.is_empty() || !shared_layer_for_this_pkg {
            if build_requires.is_empty() {
                debug!(pkg = %pkg_name, "Empty BuildRequires, skipping SharedLayer");
            } else {
                debug!(pkg = %pkg_name, "shared_layer disabled, skipping SharedLayer");
            }
            (base_os.display().to_string(), None)
        } else {
            // 层指纹须反映 repo 配置：repo 集变化令旧层失效（防 config 已变
            // 而 base_os 未重建的缓存盲区，见 repo_fingerprint 文档）。
            let repo_fp = repo_fingerprint(&config.repos);
            match get_or_create_shared_layer(SharedLayerParams {
                product: &config.product,
                build_requires: &build_requires,
                base_os_digest: &base_os_digest,
                repo_fingerprint: &repo_fp,
                srpm,
                base_os: &base_os,
                shared_layers_dir: &config.shared_layers_dir,
                tmp_dir: &config.tmp_dir,
                state: self.state.as_ref(),
                poll_interval: self.shared_layer_poll_interval,
                timeout: self.shared_layer_timeout,
                max_retries: self.shared_layer_max_retries,
                staleness: self.shared_layer_staleness,
                dnf_cache_enabled: config.dnf_cache_enabled,
                dnf_cache_path: &config.dnf_cache_path(),
                package_cache_path: &config.package_cache_path,
                record_provenance,
                cancel_token: Some(cancel_token),
                operation_timeout: shared_layer_operation_timeout,
            })
            .await
            {
                // Ok(None)：并发首建超时降级 base_os 单层；未持层引用，guard 不会 dec。
                Ok(None) => (base_os.display().to_string(), None),
                Ok(Some((shared_layer_path, digest))) => {
                    // set_layer_digest 失败重试一次，仍失败则 dec 回滚已 inc 的
                    // 层引用、降级无层构建（构建不中断）；layer_digest=None
                    // 保证 guard 不会二次 dec，inc/dec 对称。
                    let digest_recorded = match lifecycle.set_layer_digest(&digest).await {
                        Ok(()) => true,
                        Err(first_err) => {
                            warn!(
                                build_id = %lifecycle.build_id(),
                                digest = %digest,
                                error = %first_err,
                                "Failed to update layer digest; retrying once"
                            );
                            match lifecycle.set_layer_digest(&digest).await {
                                Ok(()) => true,
                                Err(second_err) => {
                                    error!(
                                        build_id = %lifecycle.build_id(),
                                        digest = %digest,
                                        error = %second_err,
                                        "Failed to update layer digest after retry; rolling back layer ref and continuing build without SharedLayer"
                                    );
                                    if let Err(dec_err) = self
                                        .state
                                        .layer_ref_dec(&digest, config.shared_layer_gc_grace_hours)
                                        .await
                                    {
                                        error!(
                                            build_id = %lifecycle.build_id(),
                                            digest = %digest,
                                            error = %dec_err,
                                            "Failed to roll back layer ref after set_layer_digest failure; ref_count may leak"
                                        );
                                    }
                                    false
                                }
                            }
                        }
                    };
                    if digest_recorded {
                        info!(pkg = %pkg_name, digest = %digest, "Using SharedLayer");
                        (
                            format!("{}:{}", shared_layer_path.display(), base_os.display()),
                            Some(digest),
                        )
                    } else {
                        (base_os.display().to_string(), None)
                    }
                }
                Err(e) => {
                    let build_id = lifecycle.build_id();
                    if let Err(e2) = lifecycle
                        .complete(BuildOutcome::Failed, Some(&result_dir_str))
                        .await
                    {
                        tracing::error!(build_id = %build_id, error = %e2, "Failed to mark build as failed after shared layer error");
                    }
                    return Err(CrbsError::io_message(format!(
                        "get or create shared layer: {}",
                        e
                    )));
                }
            }
        };

        // repro-from-srpm 指纹 note：把层 packages.txt（实际安装清单）中命中的
        // 字节泄漏子集工具链 NVRA 写入 build note（跨环境 payload 一致首先取决于
        // 其版本）。best-effort：读失败 / 无命中 / 无共享层均静默跳过。
        if self.replay_mode() {
            if let Some(ref digest) = layer_digest {
                let packages_path = config.shared_layers_dir.join(digest).join("packages.txt");
                match tokio::fs::read_to_string(&packages_path).await {
                    Ok(text) => {
                        let hits = filter_toolchain_nevras(&text);
                        if !hits.is_empty() {
                            let note = format!(
                                "\nnote: repro-from-srpm toolchain fingerprint (byte-leaking \
                                 subset present in this build environment; cross-environment \
                                 payload identity requires these versions to match): {}",
                                hits.join(", ")
                            );
                            if let Err(e) = self.state.append_build_note(build_id, &note).await {
                                warn!(
                                    build_id = %build_id,
                                    error = %e,
                                    "Failed to append repro-from-srpm toolchain fingerprint note"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            build_id = %build_id,
                            path = %packages_path.display(),
                            error = %e,
                            "shared layer package list unreadable; skipping toolchain fingerprint note"
                        );
                    }
                }
            }
        }

        // 层引用 inc 后立即构造 guard：overlay 建立前的取消/超时/挂载失败
        // 也完成 lifecycle 并释放层引用。
        let mut cleanup_guard = BuildCleanupGuard::new(
            lifecycle,
            crate::engine::mount_guard::MountGuard::new(),
            BuildOutcome::Failed,
            result_dir_str.clone(),
            layer_digest.clone(),
            self.state.clone(),
            config.shared_layer_gc_grace_hours,
        );

        if cancel_token.is_cancelled() {
            cleanup_guard.set_outcome(BuildOutcome::Cancelled);
            cleanup_guard.run().await;
            return Err(CrbsError::Cancelled);
        }
        if let Some(timeout) = self.build_timeout {
            if build_start.elapsed() > timeout {
                cleanup_guard.set_outcome(BuildOutcome::Timeout);
                cleanup_guard.run().await;
                return Err(CrbsError::Timeout);
            }
        }

        // 创建 overlay；失败显式 run guard（优于 Drop 兜底的另线程异步清理）。
        let (e, root, mount_guard, tmpfs_watch) = match self.setup_overlay(&lowerdir).await {
            Ok(v) => v,
            Err(e) => {
                cleanup_guard.run().await;
                return Err(e);
            }
        };
        // env tempdir 交 guard 收口：umount 严格先于 tempdir 删除，删除经
        // spawn_blocking（TempDir 同步 remove_dir_all 可达 GB 级）；正常/错误/
        // abort 兜底全部出口同一序列。
        cleanup_guard.set_env_temp(e);
        cleanup_guard.set_mount_guard(mount_guard);

        let mount_common_result = self
            .mount_common_features(
                &root,
                cleanup_guard.mount_guard()?,
                &MountOptions {
                    ccache: ccache_for_this_pkg,
                    dnf_cache: layer_digest.is_none(),
                    tmpfs: layer_digest.is_some(),
                    local_repo: self.local_repo_dir.clone(),
                    product_repo_url: self.product_repo_url.clone(),
                    user_binds: Vec::new(),
                },
            )
            .await
            .map_err(|e| CrbsError::io_message(format!("mount common features: {}", e)));
        if let Err(e) = mount_common_result {
            cleanup_guard.run().await;
            return Err(e);
        }

        // BUILD tmpfs 挂载点观测（shared_layer 形态）：谓词与 mount_common_features
        // 的挂载分支同源（opts.tmpfs = 有 shared_layer × build_tmpfs），与全内存
        // 构建形态（use_tmpfs，setup_overlay 产出 memroot watch）互斥——两分支
        // 不会同时产出 watch。
        let tmpfs_watch = if layer_digest.is_some() && config.build_tmpfs {
            Some(crate::engine::resource_sample::TmpfsWatch {
                path: crate::engine::prepare::build_tmpfs_mount_point(&root),
            })
        } else {
            tmpfs_watch
        };

        let build_dir = root.join("builddir");

        // bind mount result/RPMS/SRPMS；任一失败先显式 run guard，保证
        // umount → complete → ref_dec → tempdir 删除整条序列收口。
        for (host, sub, label) in [
            (result_dir, "result", "result dir"),
            (result_rpms.as_path(), "RPMS", "result rpms"),
            (result_srpms.as_path(), "SRPMS", "result srpms"),
        ] {
            let bind =
                Self::bind_build_subdir(&mut cleanup_guard, &build_dir, host, sub, label).await;
            if let Err(e) = bind {
                cleanup_guard.run().await;
                return Err(e);
            }
        }
        // mount 完成后执行构建脚本、收集产物、签名。target_override 在此折成
        // effective target（override 优先，其次引擎级 self.target_arch），noarch
        // 回退对派发 / CLI 两路径统一生效（重试不新建 lifecycle）。reproduce
        // Phase 1 的缓存扫描索引在 execute_build_script 内校验后即弃（provenance
        // 的 dep_index 恒用源记录锚，见 provenance.rs）。
        let mut script_params = ExecuteScriptParams {
            root: &root,
            build_dir: &build_dir,
            result_dir,
            result_rpms: &result_rpms,
            result_srpms: &result_srpms,
            config,
            pkg_name,
            build_id,
            srpm,
            has_shared_layer: layer_digest.is_some(),
            ccache_for_this_pkg,
            cancel_token,
            build_start,
            build_timeout: self.build_timeout,
            target_override: target_override.or(self.target_arch.as_deref()),
            resource_sampler,
            tmpfs_watch: tmpfs_watch.as_ref(),
        };
        let mut build_result = 'retry: loop {
            match self.execute_build_script(script_params).await {
                Ok(outputs) => break Ok(outputs),
                Err(e) => {
                    // noarch 重试清 override 后 effective 变 None（宿主 arch），
                    // 不会再次命中本分支。
                    if script_params.target_override == Some("noarch")
                        && !matches!(e, CrbsError::Cancelled | CrbsError::Timeout)
                    {
                        warn!(
                            pkg = %pkg_name,
                            error = %e,
                            "noarch target failed, retrying with host arch"
                        );
                        // noarch 首试可能在失败前已写入 RPM：重试前清空 RPMS/SRPMS
                        // 内容但保留目录（bind mount 目标，删目录留悬空挂载），防
                        // 两次尝试产物混作一次。清理失败必须中止重试而非仅 warn：
                        // 残留 RPM 混入重试产物是数据级错误。
                        for dir in [&result_rpms, &result_srpms] {
                            if let Err(clear_err) = clear_dir_contents(dir).await {
                                break 'retry Err(CrbsError::io_message(format!(
                                    "clear {} before host arch retry: {} \
                                     (aborting retry: leftover RPMs from the failed noarch \
                                     attempt would be mixed into this build's outputs)",
                                    dir.display(),
                                    clear_err
                                )));
                            }
                        }
                        append_build_log_separator(
                            &result_dir.join("build.log"),
                            "noarch attempt failed; retrying with host arch",
                        )
                        .await;
                        script_params.target_override = None;
                        continue;
                    }
                    break Err(e);
                }
            }
        };

        // 资源采样随终态落库：noarch 重试两段在同一采样器累计（峰最大、CPU
        // 求和、p90 全样本）；取消/无样本 None，资源列保持 NULL。
        cleanup_guard.set_resources(resource_sampler.and_then(|s| s.finish()));

        // 尾段取消检查点（脚本结束后的采集段边界共用）：取消已到且构建本可
        // 成功时折为 Cancelled——后续采集段以 is_ok 门自然跳过，outcome 走
        // 取消终态、cleanup_guard 全路径保活。
        tail_cancel_checkpoint(cancel_token, build_id, &mut build_result);

        // umount 前扫描 dnf cache 提取包索引（无层 + 需 provenance 时）。
        let no_layer_index: Option<
            std::collections::HashMap<String, crate::engine::cache::CacheEntry>,
        > = if record_provenance && build_result.is_ok() && layer_digest.is_none() {
            if self.reproduce_expected.is_some() {
                // replay 的 dep_index 恒用源记录锚（provenance.rs），本扫描无
                // 消费者——跳过第二次全缓存扫描 + 全量重哈希。
                None
            } else {
                match crate::engine::cache::cache_dnf_cache(&root, &config.package_cache_path, None)
                    .await
                {
                    Ok(Some(index)) if !index.is_empty() => Some(index),
                    _ => None,
                }
            }
        } else {
            None
        };

        // 尾段取消检查点（二段）：dnf cache 扫描后取消到达，跳过 rpm -qa 采集
        //（同样可达分钟级）。
        tail_cancel_checkpoint(cancel_token, build_id, &mut build_result);

        // umount 前读取 overlay 实装包清单（umount 后 rpm -qa 读不到）。
        // 读取失败在 deterministic/replay 下是构建错误：overlay 清单是漂移检测
        // 关键来源（dep_index 用源记录锚，记录外包只能从这里暴露），静默 None
        // 会让失真环境照抄源记录过硬门；非 det 维持 warn + None 降级。
        let overlay_installed_packages = if record_provenance && build_result.is_ok() {
            match read_overlay_installed_packages(&root, Some(cancel_token)).await {
                Ok(pkgs) => Some(pkgs),
                Err(e) => {
                    if config.deterministic || self.reproduce_expected.is_some() {
                        error!(
                            build_id = %build_id,
                            root = %root.display(),
                            error = %e,
                            "read overlay installed packages failed in deterministic/replay mode; failing the build"
                        );
                        // 文案片段经 OVERLAY_READ_FAILURE_MARKER 引用，
                        // classify_replay_failure 以其为判据。
                        build_result = Err(CrbsError::io_message(format!(
                            "{OVERLAY_READ_FAILURE_MARKER} (rpm -qa --root={}): {}",
                            root.display(),
                            e
                        )));
                        None
                    } else {
                        warn!(build_id = %build_id, error = %e, "read overlay installed packages failed");
                        None
                    }
                }
            }
        } else {
            None
        };

        // 更新构建终态（失败也保留 result_dir，日志还在）
        let mut outcome = match &build_result {
            Ok(outputs) => {
                // provenance 记录失败同样显式 run guard（避免 Drop 兜底异步清理）。
                match self
                    .record_build_provenance(ProvenanceParams {
                        outputs,
                        record_provenance,
                        deterministic: config.deterministic,
                        layer_digest: &layer_digest,
                        no_layer_index,
                        overlay_installed_packages,
                        base_os: &base_os,
                        config,
                        build_id,
                        srpm_name,
                        ccache_for_this_pkg,
                        build_start,
                        result_dir,
                        cleanup_guard: &mut cleanup_guard,
                    })
                    .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        cleanup_guard.run().await;
                        return Err(e);
                    }
                }
            }
            Err(CrbsError::Cancelled) => BuildOutcome::Cancelled,
            Err(CrbsError::Timeout) => BuildOutcome::Timeout,
            Err(_) => BuildOutcome::Failed,
        };

        // 成功后 result_dir chown 回调用者：owner=caller 本人读写、group=crbs
        // 供 server/组用户访问（权限不变量）；crbs 组查询失败回退 caller.gid。
        // chown 失败则调用者读不到产物，视为构建失败（更新 outcome 与返回值）。
        if matches!(outcome, BuildOutcome::Succeeded) {
            if let Some(ref caller) = self.caller {
                let gid = crate::privilege::crbs_group_gid_async()
                    .await
                    .unwrap_or(caller.gid);
                if let Err(e) =
                    crate::engine::layer::chown_recursive(result_dir, caller.uid, gid).await
                {
                    warn!(path = %result_dir.display(), error = %e, "chown result_dir to caller failed");
                    outcome = BuildOutcome::Failed;
                    build_result = Err(CrbsError::PermissionDenied {
                        message: format!("chown result_dir to caller failed: {e}"),
                    });
                }
            }
        }

        cleanup_guard.set_outcome(outcome);
        cleanup_guard.run().await;

        // 成功后产物收敛到权限不变量终态：目录 0o2770、文件 0o0660、group
        // crbs，world-read 收敛掉。
        if matches!(outcome, BuildOutcome::Succeeded) {
            if let Err(e) = crate::engine::build::permissions::finalize_result_dir(result_dir).await
            {
                warn!(path = %result_dir.display(), error = %e, "finalize result_dir permissions failed");
            }
        }

        // env tempdir 已折入 guard（见 set_env_temp 注释）。

        build_result
    }
}

/// provenance 记录判定（纯函数，单测锚点）：deterministic 强制记录；否则需
/// 非 reproduce 重放、非 repro-from-srpm 回放（无环境还原，录了也无锚）、
/// 且 reproduce_enabled 对本 SRPM 生效。
fn should_record_provenance(
    deterministic: bool,
    replay_values_present: bool,
    is_reproduce_replay: bool,
    reproduce_enabled_for_pkg: bool,
) -> bool {
    deterministic || (!replay_values_present && !is_reproduce_replay && reproduce_enabled_for_pkg)
}

/// 脚本结束后的尾段采集取消检查点（纯函数）：取消已到且构建本可成功时折为
/// `Cancelled`——采集段（dnf cache 全扫 / rpm -qa）可达分钟级，取消后继续跑
/// 只拖长收敛；已失败的构建不改写（错误语义保留）。
fn tail_cancel_checkpoint(
    cancel_token: &tokio_util::sync::CancellationToken,
    build_id: i64,
    build_result: &mut crate::Result<crate::types::BuildOutputs>,
) {
    if cancel_token.is_cancelled() && build_result.is_ok() {
        info!(
            build_id = %build_id,
            "Cancellation reached during post-script tail; folding successful build to cancelled \
             and skipping remaining collection"
        );
        *build_result = Err(CrbsError::Cancelled);
    }
}

/// NEVRA 行的包名段（纯函数）：RPM 命名规则下 name 可含 `-` 而 version/release
/// 不可，故 name 取 `rsplitn(3, '-')` 的末段；畸形行（段数不足）返回空串。
fn nevra_pkg_name(nevra: &str) -> &str {
    nevra.rsplitn(3, '-').nth(2).unwrap_or("")
}

/// 字节泄漏子集工具链判定（纯函数）：版本会烧进产物字节的包——gcc*/glibc*/
/// binutils* 前缀命中，make/rpm-build 全名命中。
fn is_toolchain_pkg_name(name: &str) -> bool {
    name.starts_with("gcc")
        || name.starts_with("glibc")
        || name.starts_with("binutils")
        || name == "make"
        || name == "rpm-build"
}

/// 从层 packages.txt（NEVRA 行集）过滤工具链 NVRA（纯函数）；排序去重保证
/// note 行字节稳定。
fn filter_toolchain_nevras(packages_text: &str) -> Vec<String> {
    let mut hits: Vec<String> = packages_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && is_toolchain_pkg_name(nevra_pkg_name(l)))
        .map(str::to_string)
        .collect();
    hits.sort();
    hits.dedup();
    hits
}

/// setup 阶段失败路径共用：按错误类型映射终态（Cancelled/Timeout/Failed）并
/// 完成 lifecycle，原错误原样返回；complete 自身失败只记 error 不掩盖原错误。
/// `result_dir`：目录已建好的失败点传 `Some`（终态记录供下载/日志定位），
/// 目录可能未建传 `None`。覆盖 setup 块与 guard 构造之间的错误返回——
/// 不补 complete 构建会停在 building。
async fn complete_setup_failure(
    lifecycle: BuildLifecycle,
    result_dir: Option<&str>,
    e: CrbsError,
) -> CrbsError {
    let outcome = match &e {
        CrbsError::Cancelled => BuildOutcome::Cancelled,
        CrbsError::Timeout => BuildOutcome::Timeout,
        _ => BuildOutcome::Failed,
    };
    let build_id = lifecycle.build_id();
    if let Err(e2) = lifecycle.complete(outcome, result_dir).await {
        tracing::error!(build_id = %build_id, error = %e2, "Failed to mark build as completed after setup failure");
    }
    e
}

/// 清空目录内容但保留目录本身：目录是 bind mount 目标时删掉目录会留下悬空挂载。
/// 仅用于清空本构建命名空间内的目录（调用方负责保证路径归属）。
async fn clear_dir_contents(dir: &std::path::Path) -> std::io::Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if entry.file_type().await?.is_dir() {
            tokio::fs::remove_dir_all(entry.path()).await?;
        } else {
            tokio::fs::remove_file(entry.path()).await?;
        }
    }
    Ok(())
}

/// 向 build.log 追加一行分隔注释（best-effort：失败只 warn，不影响构建流程）。
async fn append_build_log_separator(path: &std::path::Path, note: &str) {
    use tokio::io::AsyncWriteExt as _;
    let line = format!("\n===== {} =====\n", note);
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()).await {
                warn!(path = %path.display(), error = %e, "Failed to append separator to build.log");
            }
        }
        Err(e) => {
            warn!(path = %path.display(), error = %e, "Failed to open build.log for separator");
        }
    }
}

/// 确保构建父目录对 crbs 组共享可写（setgid + group rwx，server/worker/本地
/// CLI 共建同一目录树）。单目录失败分级上报、不阻断构建：chown 失败 debug
/// （非 root chown 非自有目录必然 EPERM，group rw 已够本进程）；chmod 失败
/// warn 带精确路径（权限可能未生效）。
async fn prepare_build_parent_dirs(dirs: &[std::path::PathBuf]) -> crate::Result<()> {
    let crbs_gid = crate::privilege::crbs_group_gid_async()
        .await
        .map_err(|e| {
            CrbsError::io_message(format!("lookup crbs group gid for parent dirs: {e}"))
        })?;

    let dirs = dirs.to_vec();
    tokio::task::spawn_blocking(move || {
        let uid = nix::unistd::getuid().as_raw();
        for dir in &dirs {
            if let Err(e) = crate::privilege::chown(dir, uid, crbs_gid, false) {
                debug!(path = %dir.display(), error = %e, "chown parent dir to crbs group failed (expected for non-root)");
            }
            if let Err(e) = crate::privilege::chmod(dir, 0o2770, false) {
                warn!(path = %dir.display(), error = %e, "chmod parent dir to 2770 failed; shared write may not be effective");
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn blocking for parent dir permissions: {e}")))?
}

/// 在 `pkg_root` 下以 `target_dir` 为相对目标更新 `latest` 软链接：先建临时
/// 链接 `.latest.new.{build_id}` 再 rename 覆盖。临时名按 build_id 隔离，同包
/// 并发互不删除（否则 rename 拿 ENOENT）。顺手清扫：legacy 固定名
/// `.latest.new` 无条件清；异 build_id 临时链接只在 mtime 超过
/// [`LATEST_TEMP_STALE_AFTER`] 时按崩溃残留清——在途链接是并发构建的活
/// 资源，无条件清会重新引入 ENOENT 竞态。
pub(crate) async fn update_latest_symlink(
    pkg_root: &std::path::Path,
    target_dir: &std::ffi::OsStr,
    build_id: i64,
) -> crate::Result<()> {
    let latest_link = pkg_root.join("latest");
    let latest_new = pkg_root.join(format!(".latest.new.{}", build_id));

    sweep_stale_latest_temps(pkg_root, build_id).await;

    tokio::fs::symlink(target_dir, &latest_new)
        .await
        .map_err(|e| CrbsError::from_io_context("create latest symlink", e))?;

    tokio::fs::rename(&latest_new, &latest_link)
        .await
        .map_err(|e| CrbsError::from_io_context("rename latest symlink ->", e))?;

    Ok(())
}

/// 崩溃残留宽限：symlink→rename 间隔亚秒级，60s 远超任何在途窗口。
const LATEST_TEMP_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// 清扫 latest 临时链接残留：固定名 `.latest.new`（历史遗留）与自身
/// `.latest.new.{build_id}` 无条件清（无并发写方）；其余 `.latest.new.*` 是
/// 并发构建在途链接，只在 mtime 超宽限时按崩溃残留清，mtime 不可得按新鲜
/// 处理（宁可不清理）；读目录失败仅告警跳过，不阻断本次更新。
async fn sweep_stale_latest_temps(pkg_root: &std::path::Path, build_id: i64) {
    let own_temp = format!(".latest.new.{}", build_id);
    let mut rd = match tokio::fs::read_dir(pkg_root).await {
        Ok(rd) => rd,
        // pkg_root 缺失/不可读：跳过清扫，后续 symlink 走正常报错路径。
        Err(e) => {
            debug!(
                path = %pkg_root.display(),
                error = %e,
                "Failed to read pkg root for latest temp link sweep; skipping"
            );
            return;
        }
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let Some(name) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !name.starts_with(".latest.new") {
            continue;
        }
        if name != ".latest.new" && name != own_temp {
            // DirEntry::metadata 不跟随 symlink，取的是链接自身 mtime。
            let stale = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .map(|age| age >= LATEST_TEMP_STALE_AFTER)
                .unwrap_or(false);
            if !stale {
                continue;
            }
        }
        if let Err(e) = tokio::fs::remove_file(entry.path()).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    path = %entry.path().display(),
                    error = %e,
                    "Failed to remove stale latest symlink temp"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::srpm_pkg_name;
    use super::update_latest_symlink;
    use crate::engine::BuildLifecycle;
    use crate::error::CrbsError;
    use std::path::Path;

    #[test]
    fn srpm_pkg_name_strips_src_suffix() {
        assert_eq!(
            srpm_pkg_name(Path::new("/build/nginx-1.21.5-17.oe2203sp4.src.rpm")).unwrap(),
            "nginx-1.21.5-17.oe2203sp4"
        );
    }

    #[test]
    fn srpm_pkg_name_handles_placeholder_name() {
        // Worker 下载 SRPM 时若无 Content-Disposition，使用 {product}-{build_id} 占位名。
        assert_eq!(
            srpm_pkg_name(Path::new("/build/mydist-11.src.rpm")).unwrap(),
            "mydist-11"
        );
    }

    /// 畸形文件名（无 `.src` 后缀 / 无 file_stem）拒绝而非回退——共享
    /// `{product}/unknown/` 会让 chain 增量检查误判已建而跳包。
    #[test]
    fn srpm_pkg_name_rejects_malformed_filenames() {
        for bad in ["/build/foo.rpm", "/"] {
            let err = srpm_pkg_name(Path::new(bad)).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message }
                    if message.contains("malformed SRPM file name")),
                "SRPM {bad:?} must be rejected as malformed, got: {err:?}"
            );
        }
    }

    /// strip 后不含 `-`（无 N-V-R 结构）同样拒绝；占位名与真实 N-V-R 都含 `-`。
    #[test]
    fn srpm_pkg_name_rejects_stem_without_nvr_structure() {
        let err = srpm_pkg_name(Path::new("/build/foo.src.rpm")).unwrap_err();
        assert!(
            matches!(&err, CrbsError::ValidationFailed { message }
                if message.contains("malformed SRPM file name")),
            "got: {err:?}"
        );
    }

    /// provenance 排除回归钉：repro-from-srpm 值存在时非 det 不录（防默认
    /// 开启误录）；det 强制 / reproduce 重放排除 / enabled 透传语义不回退。
    #[test]
    fn should_record_provenance_excludes_replay_mode() {
        assert!(!super::should_record_provenance(false, true, false, true));
        assert!(super::should_record_provenance(true, true, false, false));
        assert!(!super::should_record_provenance(false, false, true, true));
        assert!(super::should_record_provenance(false, false, false, true));
        assert!(!super::should_record_provenance(false, false, false, false));
    }

    /// 尾段取消检查点三态：取消 + 本可成功 → 折 Cancelled；未取消不动；
    /// 已失败的构建不改写（错误语义保留）。
    #[test]
    fn tail_cancel_checkpoint_folds_only_freshly_cancelled_success() {
        use tokio_util::sync::CancellationToken;

        fn outputs() -> crate::types::BuildOutputs {
            crate::types::BuildOutputs {
                build_id: 14,
                pkg_name: "hello".to_string(),
                rpms: vec![],
                srpms: vec![],
                logs: vec![],
                result_dir: Path::new("/tmp/r").to_path_buf(),
                retries: 0,
                signed: false,
            }
        }

        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let mut ok = Ok(outputs());
        super::tail_cancel_checkpoint(&cancelled, 14, &mut ok);
        assert!(
            matches!(ok, Err(CrbsError::Cancelled)),
            "取消到达时本可成功的构建必须折为 Cancelled"
        );

        let mut untouched = Ok(outputs());
        super::tail_cancel_checkpoint(&CancellationToken::new(), 14, &mut untouched);
        assert!(untouched.is_ok(), "未取消不得改写成功结果");

        let mut already_failed = Err::<crate::types::BuildOutputs, _>(CrbsError::io_message(
            "script failed".to_string(),
        ));
        super::tail_cancel_checkpoint(&cancelled, 14, &mut already_failed);
        assert!(
            already_failed
                .err()
                .unwrap()
                .to_string()
                .contains("script failed"),
            "已失败的构建不得被改写成 Cancelled"
        );
    }

    /// 过滤：前缀命中含派生包（gcc-c++ / glibc-common），make/rpm-build 全名
    /// 命中，前缀相近名不误收；输出排序去重保留完整 NVRA。
    #[test]
    fn filter_toolchain_nevras_matches_byte_leaking_subset() {
        let text = "\
glibc-2.38-124.oe2403sp1.x86_64
glibc-common-2.38-124.oe2403sp1.x86_64
gcc-14.0.1-11.oe2403sp1.x86_64
gcc-c++-14.0.1-11.oe2403sp1.x86_64
binutils-2.41-28.oe2403sp1.x86_64
make-4.3-5.oe2403sp1.x86_64
rpm-build-4.19-1.oe2403sp1.x86_64
python3-3.11-5.oe2403sp1.x86_64
cmake-3.27-1.oe2403sp1.x86_64
glibc-debuginfo-2.38-124.oe2403sp1.x86_64

";
        let hits = super::filter_toolchain_nevras(text);
        assert_eq!(
            hits,
            vec![
                "binutils-2.41-28.oe2403sp1.x86_64",
                "gcc-14.0.1-11.oe2403sp1.x86_64",
                "gcc-c++-14.0.1-11.oe2403sp1.x86_64",
                "glibc-2.38-124.oe2403sp1.x86_64",
                "glibc-common-2.38-124.oe2403sp1.x86_64",
                "glibc-debuginfo-2.38-124.oe2403sp1.x86_64",
                "make-4.3-5.oe2403sp1.x86_64",
                "rpm-build-4.19-1.oe2403sp1.x86_64",
            ]
        );
        // name 含 '-' 按 rsplitn 解析：python3-six 不因 "six" 起始误判。
        let with_dash_name = "python3-six-1.16.0-3.oe2403sp1.noarch\n";
        assert!(super::filter_toolchain_nevras(with_dash_name).is_empty());
    }

    /// name 可含 '-'（version/release 不可），取 rsplitn(3, '-') 末段；畸形空串。
    #[test]
    fn nevra_pkg_name_parses_name_segment() {
        assert_eq!(
            super::nevra_pkg_name("gcc-c++-14.0.1-11.oe2403sp1.x86_64"),
            "gcc-c++"
        );
        assert_eq!(super::nevra_pkg_name("make-4.3-5.el9.x86_64"), "make");
        assert_eq!(super::nevra_pkg_name("bad"), "");
        assert_eq!(super::nevra_pkg_name("a-b"), "");
    }

    /// setup 块与 guard 构造间的错误经 complete_setup_failure：DB 落按错误
    /// 映射的终态、原错误原样返回、目录已建好的失败点把 result_dir 记进行。
    /// run_build_in_dir 依赖真实 base_os/容器，单测直接覆盖补全函数。
    #[tokio::test]
    async fn setup_failure_completes_lifecycle_terminal_phase() {
        let tmp = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        for (err, want_phase) in [
            (
                CrbsError::io_message("rpm -qp failed: boom".to_string()),
                "failed",
            ),
            (CrbsError::Cancelled, "cancelled"),
            (CrbsError::Timeout, "timeout"),
        ] {
            let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
                .await
                .unwrap();
            lifecycle.start_building().await.unwrap();
            let build_id = lifecycle.build_id();
            let want_display = err.to_string();

            let returned =
                super::complete_setup_failure(lifecycle, Some("/tmp/setup-fail-result"), err).await;

            assert_eq!(
                returned.to_string(),
                want_display,
                "original error must be returned unchanged"
            );
            let record = state.get_build(build_id).await.unwrap().unwrap();
            assert_eq!(record.phase, want_phase);
            assert_eq!(
                record.result_dir.as_deref(),
                Some("/tmp/setup-fail-result"),
                "post-setup 失败必须记录 result_dir（失败记录口径）"
            );
        }
    }

    /// 目录可能未建的失败传 None：result_dir 保持 NULL，不指向不存在目录。
    #[tokio::test]
    async fn setup_failure_without_result_dir_keeps_it_null() {
        let tmp = tempfile::tempdir().unwrap();
        let state = std::sync::Arc::new(crate::state::StateStore::new(tmp.path()).await.unwrap());

        let lifecycle = BuildLifecycle::new(state.clone(), "fedora", "hello", None, None, 0)
            .await
            .unwrap();
        lifecycle.start_building().await.unwrap();
        let build_id = lifecycle.build_id();

        let _ = super::complete_setup_failure(lifecycle, None, CrbsError::Cancelled).await;

        let record = state.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(record.phase, "cancelled");
        assert_eq!(
            record.result_dir, None,
            "pre-creation 失败不得写入未经确认的 result_dir"
        );
    }

    /// 边界：stem 为 CurDir / 前导点 / 空 → ValidationFailed 带 SRPM 名；
    /// 正常 N-V-R 名不受影响。
    #[test]
    fn srpm_pkg_name_rejects_dot_and_leading_dot_stems() {
        assert_eq!(
            srpm_pkg_name(std::path::Path::new("hello-1.0-1.src.rpm")).unwrap(),
            "hello-1.0-1"
        );
        assert!(srpm_pkg_name(std::path::Path::new("plain.rpm")).is_err());
        // `..src.rpm` → stem `..src` → strip 得 "."（CurDir）→ 拒绝
        for evil in ["..src.rpm", ".src.rpm", ".foo.src.rpm"] {
            let err = srpm_pkg_name(std::path::Path::new(evil)).unwrap_err();
            assert!(
                matches!(&err, CrbsError::ValidationFailed { message }
                    if message.contains(evil)),
                "SRPM {evil:?} must be rejected with its name, got: {err:?}"
            );
        }
    }

    /// 同 pkg_root 两个 build_id 并发更新 latest：都成功，latest 最终指向
    /// 有效构建目录（不因临时名竞态 ENOENT）。
    #[tokio::test]
    async fn concurrent_latest_symlink_updates_all_succeed() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path().to_path_buf();

        let dir_a = "20260728-100000-1001";
        let dir_b = "20260728-100001-1002";
        tokio::fs::create_dir_all(pkg_root.join(dir_a))
            .await
            .unwrap();
        tokio::fs::create_dir_all(pkg_root.join(dir_b))
            .await
            .unwrap();

        let name_a: std::ffi::OsString = dir_a.into();
        let name_b: std::ffi::OsString = dir_b.into();
        let (ra, rb) = tokio::join!(
            update_latest_symlink(&pkg_root, &name_a, 1001),
            update_latest_symlink(&pkg_root, &name_b, 1002),
        );
        assert!(ra.is_ok(), "build A latest update failed: {:?}", ra);
        assert!(rb.is_ok(), "build B latest update failed: {:?}", rb);

        let target = tokio::fs::read_link(pkg_root.join("latest")).await.unwrap();
        let target_str = target.to_string_lossy();
        assert!(
            target_str == dir_a || target_str == dir_b,
            "latest should point to a valid build dir, got: {}",
            target_str
        );

        assert!(!pkg_root.join(format!(".latest.new.{}", 1001)).exists());
        assert!(!pkg_root.join(format!(".latest.new.{}", 1002)).exists());
    }

    /// 超宽限异 build_id 临时链与 legacy 固定名随本次更新清掉；latest
    /// 正常指向新构建。
    #[tokio::test]
    async fn stale_foreign_latest_temp_links_are_swept() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path().to_path_buf();
        let dir_a = "20260728-100000-1001";
        tokio::fs::create_dir_all(pkg_root.join(dir_a))
            .await
            .unwrap();

        // 伪残留：异 build_id 临时链（mtime 回拨 1h 超宽限）+ legacy 固定名。
        let residue = pkg_root.join(".latest.new.99999");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir_a, &residue).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(dir_a, &residue).unwrap();
        let stale = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() - std::time::Duration::from_secs(3600),
        );
        filetime::set_symlink_file_times(&residue, stale, stale).unwrap();
        let legacy = pkg_root.join(".latest.new");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir_a, &legacy).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(dir_a, &legacy).unwrap();

        let name_a: std::ffi::OsString = dir_a.into();
        update_latest_symlink(&pkg_root, &name_a, 1001)
            .await
            .unwrap();

        assert!(
            !residue.exists(),
            "超宽限的异 build_id 临时链必须按崩溃残留清掉"
        );
        assert!(!legacy.exists(), "legacy 固定临时名必须被清");
        let target = tokio::fs::read_link(pkg_root.join("latest")).await.unwrap();
        assert_eq!(
            target.to_string_lossy(),
            dir_a,
            "真 latest 必须指向本次构建，不受清扫影响"
        );
    }

    /// 对照臂：新鲜异 build_id 临时链是在途资源，不得清扫（否则对方 rename
    /// 拿 ENOENT）。
    #[tokio::test]
    async fn fresh_foreign_latest_temp_links_survive() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_root = tmp.path().to_path_buf();
        let dir_a = "20260728-100000-1001";
        tokio::fs::create_dir_all(pkg_root.join(dir_a))
            .await
            .unwrap();

        let in_flight = pkg_root.join(".latest.new.99999");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir_a, &in_flight).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(dir_a, &in_flight).unwrap();

        let name_a: std::ffi::OsString = dir_a.into();
        update_latest_symlink(&pkg_root, &name_a, 1001)
            .await
            .unwrap();

        assert!(
            in_flight.exists(),
            "宽限内的异 build_id 临时链是在途资源，必须保留"
        );
        assert!(
            !pkg_root.join(".latest.new.1001").exists(),
            "自身临时名用后即清"
        );
    }
}

/// 槽位写入（abort 保样本的引擎侧半边）端到端：采样器累计样本后，从槽位读
/// 到与采样器 finish 同源的值；新采样器写入覆盖旧快照（多包构建逐构建语义）。
#[cfg(test)]
mod snapshot_slot_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn store_snapshot_slot_exposes_sampler_accumulation() {
        // /proc fixture：pgrp == pid 的单进程，RSS 100 页。
        let tmp = tempfile::tempdir().unwrap();
        let pid_dir = tmp.path().join("7000");
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(
            pid_dir.join("stat"),
            "7000 (some proc (v1)) S 7000 7000 0 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 100 100 0 0 0 0 0 0 0\n",
        )
        .unwrap();

        let slot = crate::engine::new_resource_snapshot_slot();
        let sampler = crate::engine::resource_sample::ResourceSampler::from_intervals(1, None)
            .expect("proc interval on");
        store_snapshot_slot(&slot, sampler.snapshot());

        let (handle, stop) = sampler
            .spawn_phase(7000, None, None, tmp.path(), None)
            .expect("proc interval on");
        for _ in 0..100 {
            if sampler.finish().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.notify_one();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("stop must end the loop")
            .unwrap();

        // 采样器累计的值从槽位同样可读（abort 方视角）。
        let via_slot = crate::engine::snapshot_slot_resources(&slot)
            .expect("slot must expose the sampler snapshot");
        assert!(
            via_slot.peak_rss_kb.is_some(),
            "sampled peak must be visible via slot: {via_slot:?}"
        );
        assert_eq!(
            via_slot.sample_backend,
            Some(crate::engine::SAMPLE_BACKEND_PROC)
        );

        // 多包构建逐构建覆盖：新采样器写入后旧快照被替换（新采样器无样本 → None）。
        let newer = crate::engine::resource_sample::ResourceSampler::from_intervals(1, None)
            .expect("proc interval on");
        store_snapshot_slot(&slot, newer.snapshot());
        assert_eq!(
            crate::engine::snapshot_slot_resources(&slot),
            None,
            "fresh sampler with no samples aggregates to None"
        );
    }
}
