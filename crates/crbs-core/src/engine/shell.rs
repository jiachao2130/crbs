// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建环境 shell 入口：交互 shell 与单命令调试。

use crate::engine::prepare::MountOptions;
use crate::error::CrbsError;
use std::io::IsTerminal;
use std::os::unix::process::ExitStatusExt;
use tracing::{info, warn};

/// shell/debug 的挂载选项：ccache/dnf 缓存/tmpfs 全开、无 repo 注入。
fn interactive_mount_options(user_binds: Vec<crate::bind::UserBind>) -> MountOptions {
    MountOptions {
        ccache: true,
        dnf_cache: true,
        tmpfs: true,
        local_repo: None,
        product_repo_url: None,
        user_binds,
    }
}

/// shell/debug 的 spawn 选项：LC_ALL=C 环境底座 + interactive 基础形态。
fn interactive_spawn_options(
    builder_user: &str,
    network: bool,
    binds: Vec<crate::engine::backend::BindMount>,
) -> crate::engine::backend::SpawnOptions {
    let mut env_vars = std::collections::BTreeMap::new();
    env_vars.insert("LC_ALL".to_string(), "C".to_string());
    crate::engine::backend::SpawnOptions {
        user: Some(builder_user.to_string()),
        env: env_vars,
        network,
        binds,
        ..crate::engine::backend::SpawnOptions::interactive()
    }
}

/// 把 CLI 用户 --bind 规格转成 SpawnOptions.binds。
///
/// host 侧挂载对 nspawn 独立 mount namespace 不可见，须经 `--bind` / `--bind-ro`
/// 再传入一次；read_only 必须如实传递：用户 --bind 默认只读，rw bind 即绕过只读预期。
fn shell_binds(user_binds: &[crate::bind::UserBind]) -> Vec<crate::engine::backend::BindMount> {
    user_binds
        .iter()
        .map(|b| crate::engine::backend::BindMount {
            host: b.host.display().to_string(),
            container: b.container.display().to_string(),
            read_only: b.read_only,
        })
        .collect()
}

impl crate::engine::BuildEngine {
    /// 进入产品环境的交互式 shell：自动查找最新 SharedLayer 叠加到 base_os
    ///（无则仅用 base_os），复用 prepare_env() 统一挂载。
    pub async fn shell(
        &self,
        command: Option<String>,
        interactive: bool,
        user_binds: Vec<crate::bind::UserBind>,
    ) -> crate::Result<()> {
        let config = &self.config;
        let base_os = config.base_os_path();
        let product_root = config.product_root();

        if !tokio::fs::try_exists(&base_os).await? {
            // shell 是 CLI 路径：保留 active build 守卫
            self.auto_init(None, None, false).await?;
        }

        // 前置清理孤儿挂载（扫描域用引擎 pin 后配置，不重读全局配置文件）。
        Self::cleanup_orphan_mounts_for_product(
            &product_root,
            &config.product,
            &crate::engine::gc::OrphanScanRoots::from_engine_config(config),
            self.state.as_ref(),
        )
        .await;

        let _lock = self.acquire_shell_lock().await?;

        let (lowerdir, has_layer) = if config.shared_layer.is_globally_enabled() {
            let shared_layer = self
                .state
                .get_latest_layer_for_product(&config.product)
                .await
                .map_err(|e| CrbsError::io_message(format!("query shared layer: {}", e)))?;
            let has = shared_layer.is_some();
            let lower = if let Some((ref _digest, ref path)) = shared_layer {
                format!("{}:{}", path, base_os.display())
            } else {
                base_os.display().to_string()
            };
            (lower, has)
        } else {
            (base_os.display().to_string(), false)
        };

        // 须在 user_binds move 进 MountOptions 之前转换（见 shell_binds；chroot 忽略 binds）。
        let binds = shell_binds(&user_binds);
        let mut env = self
            .prepare_env(&lowerdir, &interactive_mount_options(user_binds))
            .await?;

        if self.backend.name() == "nspawn"
            && (config.memory_max.is_some() || config.cpu_quota.is_some())
        {
            warn!(
                product = %config.product,
                "resource limits in config are ignored for interactive shell"
            );
        }

        info!(
            product = %config.product,
            user = %config.builder_user,
            backend = %self.backend.name(),
            has_layer = has_layer,
            "Starting shell"
        );

        let opts = interactive_spawn_options(&config.builder_user, config.network, binds);
        let status_result = self
            .backend
            .shell(&env.root, command.as_deref(), &opts)
            .await;

        info!(product = %config.product, "Shell exited, cleaning up");

        // 先卸载再传播错误：提前 `?` 会在挂载存活时 drop(env) 删 overlay 临时目录，umount EBUSY 泄漏。
        env.umount().await;
        drop(env);

        let status = status_result?;

        if !interactive && !status.success() {
            // `shell -c` 容器内命令非零退出 = "容器执行失败"契约（BUILD_FAILED=2）：
            // 输出直通终端未捕获，stderr 只放固定判语，信号死因经 ExitStatusExt::signal 保留。
            return Err(CrbsError::ContainerExecFailed {
                exit_code: status.code(),
                signal: status.signal(),
                stderr: "shell command failed".to_string(),
            });
        }

        Ok(())
    }

    /// 复现某次构建环境（base_os ± SharedLayer），进入交互式 shell 或执行命令。
    pub async fn debug(
        &self,
        build_id: i64,
        command: Option<String>,
        user_binds: Vec<crate::bind::UserBind>,
    ) -> crate::Result<()> {
        let config = &self.config;
        let base_os = config.base_os_path();

        if !tokio::fs::try_exists(&base_os).await? {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "base_os not found: {}. Run 'crbs init {}' first",
                    base_os.display(),
                    config.product
                ),
            });
        }

        let _lock = self.acquire_shell_lock().await?;

        let record = self
            .state
            .get_build(build_id)
            .await
            .map_err(|e| CrbsError::io_message(format!("query build: {}", e)))?
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: format!("Build task {} not found", build_id),
            })?;

        if record.phase == "building" {
            return Err(CrbsError::ValidationFailed {
                message: format!("Build task {} is still in progress", build_id),
            });
        }

        if let Some(ref build_base_os_digest) = record.base_os_digest {
            let current_digest = tokio::fs::read_to_string(base_os.join(".digest"))
                .await
                .map_err(|e| CrbsError::from_io_context("read .digest", e))?;
            if current_digest != *build_base_os_digest {
                warn!(
                    build_id = %build_id,
                    current = %current_digest,
                    expected = %build_base_os_digest,
                    "base_os digest mismatch: environment may have changed since build"
                );
            }
        }

        let (lowerdir, layer_digest) = if let Some(ref digest) = record.layer_digest {
            let layer_path = self
                .state
                .get_layer_path(digest)
                .await
                .map_err(|e| CrbsError::io_message(format!("query layer: {}", e)))?
                .ok_or_else(|| CrbsError::ValidationFailed {
                    message: format!(
                        "SharedLayer {} no longer exists. Run 'crbs init {}' to rebuild.",
                        digest, config.product
                    ),
                })?;
            let shared_upper = std::path::Path::new(&layer_path);
            if !tokio::fs::try_exists(shared_upper).await? {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "SharedLayer path {} does not exist. Run 'crbs init {}' to rebuild.",
                        shared_upper.display(),
                        config.product
                    ),
                });
            }
            info!(
                build_id = %build_id,
                layer = %digest,
                "Reproducing build with SharedLayer"
            );
            (
                format!("{}:{}", shared_upper.display(), base_os.display()),
                Some(digest.clone()),
            )
        } else {
            info!(build_id = %build_id, "Reproducing build without SharedLayer");
            (base_os.display().to_string(), None)
        };

        // result_dir 校验与脚本存在性检查必须在 layer_ref_inc / prepare_env
        // 之前完成：inc 之后到统一清理（umount + layer_ref_dec）间错误路径不得
        // 提前 `?` 返回，否则 SharedLayer 引用计数泄漏、该层无法 GC。
        let (script_src, result_dir) = match record.result_dir {
            Some(ref d) => {
                let validated = crate::util::validate_result_dir(d, &config.result_dir)
                    .await
                    .map_err(|e| CrbsError::ValidationFailed {
                        message: format!("invalid result_dir for build {}: {}", build_id, e),
                    })?;
                let script = validated.join("crbs-build.sh");
                let script = if tokio::fs::try_exists(&script).await? {
                    Some(script)
                } else {
                    None
                };
                (script, Some(validated))
            }
            None => (None, None),
        };

        // 须在 user_binds move 进 MountOptions 之前转换（见 shell_binds）。
        let binds = shell_binds(&user_binds);

        // 挂载之前先 inc SharedLayer 引用：inc 失败即返回（尚未持有任何资源，
        // 无需清理）；prepare_env 失败是唯一需补偿的出口（下方 match 内 best-effort dec）。
        if let Some(ref digest) = layer_digest {
            if let Err(e) = self.state.layer_ref_inc(digest).await {
                return Err(CrbsError::io_message(format!(
                    "inc SharedLayer ref for debug shell: {}",
                    e
                )));
            }
        }

        let mut env = match self
            .prepare_env(&lowerdir, &interactive_mount_options(user_binds))
            .await
        {
            Ok(env) => env,
            Err(e) => {
                // inc 已成功而 env 未建成：best-effort dec 补偿（失败只 warn，
                // gc 兜底）；无需 umount——prepare_env 失败时 MountGuard 随 drop 派发 lazy umount。
                if let Some(ref digest) = layer_digest {
                    if let Err(dec_err) = self
                        .state
                        .layer_ref_dec(digest, config.shared_layer_gc_grace_hours)
                        .await
                    {
                        warn!(digest = %digest, error = %dec_err, "compensating layer_ref_dec after prepare_env failure failed");
                    }
                }
                return Err(e);
            }
        };

        // 复制 result_dir 保存的构建脚本供复现（校验已提前完成，失败仅 warn）。
        let has_script = if let Some(ref path) = script_src {
            let dest = env.root.join("crbs-build.sh");
            if let Err(e) = tokio::fs::copy(path, &dest).await {
                warn!(
                    build_id = %build_id,
                    src = %path.display(),
                    dst = %dest.display(),
                    error = %e,
                    "Failed to copy build script for debug"
                );
                false
            } else {
                info!(build_id = %build_id, script = %path.display(), "Reusing build script from result_dir");
                true
            }
        } else {
            false
        };
        if !has_script {
            warn!(
                build_id = %build_id,
                "Build script not found in result_dir; prep skipped, user needs to run install/rpmbuild steps manually"
            );
        }

        // debug prep：执行留档脚本的截断版（ccache-init → install-srpm →
        // install-deps），停在 rpmbuild 之前——进 shell 时 /builddir 已含解包的
        // spec+sources、依赖已装齐。任何失败（无脚本/无 SRPM/脚本非零）都不阻
        // 断：debug 的兜底语义是无论如何停在可手动 rpmbuild 的状态。
        if let Some(script_path) = script_src.as_deref() {
            match resolve_debug_srpm(record.srpm_path.as_deref(), result_dir.as_deref()).await {
                Some(srpm) => {
                    match self
                        .run_debug_prep(&env.root, script_path, &srpm, binds.clone(), build_id)
                        .await
                    {
                        Ok(()) => info!(
                            build_id = %build_id,
                            "debug prep done: SRPM unpacked, deps installed; stopped before rpmbuild"
                        ),
                        Err(e) => warn!(
                            build_id = %build_id,
                            error = %e,
                            "debug prep failed; entering shell with bare environment"
                        ),
                    }
                }
                None => warn!(
                    build_id = %build_id,
                    "input SRPM not found; prep skipped — run install steps manually via /crbs-build.sh"
                ),
            }
        }

        info!(build_id = %build_id, user = %config.builder_user, backend = %self.backend.name(), "Starting debug shell");

        let interactive = command.is_none() && std::io::stdin().is_terminal();
        let opts = interactive_spawn_options(&config.builder_user, config.network, binds);

        // 错误先捕获后传播：shell 失败不得提前 `?`，须走统一的 umount + dec 清理。
        let shell_result: crate::Result<std::process::ExitStatus> = async {
            let status = self
                .backend
                .shell(&env.root, command.as_deref(), &opts)
                .await
                .map_err(|e| CrbsError::io_message(format!("debug shell: {}", e)))?;
            Ok(status)
        }
        .await;

        info!(build_id = %build_id, "Debug shell exited, cleaning up");

        env.umount().await;
        drop(env);

        // dec 与前置 inc 对称（inc 失败即返回，到达此处必已成功）。
        // 宽限口径：引擎侧 dec 用 operator 配置值，修复/回滚释放侧恒用编译期
        // 默认 168h，operator 配大（如 720h）时经释放侧归零的层会早于预期进
        // GC 候选（配小反向滞后），仅影响调度时刻，ref=0 闸门保正确性；
        // 漂移全图见 state/gc.rs 注释。
        if let Some(ref digest) = layer_digest {
            if let Err(e) = self
                .state
                .layer_ref_dec(digest, config.shared_layer_gc_grace_hours)
                .await
            {
                warn!(digest = %digest, error = %e, "layer_ref_dec failed");
            }
        }

        let status = shell_result?;
        if !interactive && !status.success() {
            // `debug -c` 同 shell -c 契约：ContainerExecFailed（BUILD_FAILED=2），信号死因保留。
            return Err(CrbsError::ContainerExecFailed {
                exit_code: status.code(),
                signal: status.signal(),
                stderr: "debug command failed".to_string(),
            });
        }

        Ok(())
    }

    /// debug prep：把留档构建脚本截断到 `# [step:build]` 之前（ccache-init →
    /// install-srpm → install-deps）写入容器执行；宿主侧先备好 /builddir 目录
    /// 树并放入 SRPM。脚本以 root 运行（与正常构建同形态，内部经 sudo 切
    /// builder），stdio 直通终端让用户实时看到 builddep 输出。
    async fn run_debug_prep(
        &self,
        env_root: &std::path::Path,
        archived_script: &std::path::Path,
        srpm: &std::path::Path,
        binds: Vec<crate::engine::backend::BindMount>,
        build_id: i64,
    ) -> crate::Result<()> {
        let full = tokio::fs::read_to_string(archived_script)
            .await
            .map_err(|e| CrbsError::from_io_context("read archived build script", e))?;
        let prep = truncate_script_to_prep(&full).ok_or_else(|| CrbsError::ValidationFailed {
            message: "archived script has no '# [step:build]' marker; cannot derive prep script"
                .into(),
        })?;

        // hook 体只存在于构建时的临时 overlay，不随脚本留档：为脚本引用到的
        // /crbs-hooks/... 建空桩，`. path` 与 HOOK_*=path 引用不因 ENOENT 中断
        //（hook 语义在 debug 场景 best-effort，为空即跳过）。消费身份有二：root
        // 脚本 `. ` 源行（root 可读一切）与 scriptlet 内 builder 普通 `cat`（spec
        // hook 注入行），统一走 write_hook_files 的 0750/0640 + builder 属主不变量。
        let stubs: Vec<crate::engine::pipeline::HookFile> = hook_paths_in_script(prep)
            .into_iter()
            .map(|rel| crate::engine::pipeline::HookFile {
                container_path: rel,
                content: String::new(),
            })
            .collect();
        crate::engine::build::script::write_hook_files(
            env_root,
            &stubs,
            self.config.builder_uid,
            self.config.builder_gid,
        )
        .await?;

        let prep_path = env_root.join("crbs-debug-prep.sh");
        crate::engine::build::script::write_script(&prep_path, prep, 0o755).await?;

        // /builddir 目录树 + SRPM：与正常构建同构（execution.rs）。INPUT 内文件
        // 由 fs::copy 落盘并保留源权限位（server 世界的源是组不变量 0660）；可
        // 读性不靠改权限位——随后的 chown_recursive 把属主交给 builder，0660
        // 属主可读，正是 135 实测先例（builder 读不了组属 0660 暂存文件）的修
        // 复路径，chmod_recursive 再把文件收敛到 0660（2770 & 0o666），无其它
        // 暴露面。result 子目录是留档脚本 PHASE 标记 `>> /builddir/result/
        // build.log` 的重定向目标，缺了会被 set -e 杀掉。
        let build_dir = env_root.join("builddir");
        for sub in ["SPECS", "SOURCES", "SRPMS", "INPUT", "result"] {
            tokio::fs::create_dir_all(build_dir.join(sub))
                .await
                .map_err(|e| CrbsError::from_io_context("create debug builddir", e))?;
        }
        let dest = build_dir
            .join("INPUT")
            .join(
                srpm.file_name()
                    .ok_or_else(|| CrbsError::ValidationFailed {
                        message: format!("srpm path has no file name: {}", srpm.display()),
                    })?,
            );
        tokio::fs::copy(srpm, &dest)
            .await
            .map_err(|e| CrbsError::from_io_context("copy srpm for debug prep", e))?;
        let crbs_gid = crate::privilege::crbs_group_gid_async()
            .await
            .map_err(|e| CrbsError::io_message(format!("lookup crbs group gid: {e}")))?;
        crate::engine::build::permissions::chown_chmod_2770(
            &build_dir,
            self.config.builder_uid,
            crbs_gid,
            "debug build dir",
        )
        .await?;

        let mut env_vars = std::collections::BTreeMap::new();
        env_vars.insert("LC_ALL".to_string(), "C".to_string());
        let opts = crate::engine::backend::SpawnOptions {
            user: None,
            env: env_vars,
            network: self.config.network,
            binds,
            ..crate::engine::backend::SpawnOptions::interactive()
        };
        info!(
            build_id = %build_id,
            script = %prep_path.display(),
            "Running debug prep (ccache-init / install-srpm / install-deps)"
        );
        let status = self
            .backend
            .shell(env_root, Some("/crbs-debug-prep.sh"), &opts)
            .await
            .map_err(|e| CrbsError::io_message(format!("debug prep: {}", e)))?;
        if !status.success() {
            return Err(CrbsError::ContainerExecFailed {
                exit_code: status.code(),
                signal: status.signal(),
                stderr: "debug prep script failed".to_string(),
            });
        }
        Ok(())
    }
}

/// 截断留档构建脚本到 `# [step:build]` 之前：保留 ccache-init / install-srpm /
/// install-deps 三步（含 hook 引用与 PHASE 标记），作为 debug prep 脚本；
/// 整行锚定防误切。找不到标记返回 None（历史留档 / 已截断脚本）。
fn truncate_script_to_prep(script: &str) -> Option<&str> {
    const MARKER: &str = "\n# [step:build]\n";
    let idx = script.find(MARKER)?;
    Some(&script[..idx + 1])
}

/// 收集脚本引用的 `/crbs-hooks/...` 路径（`# [hook:*]` + `. path` 源行与 spec
/// 插桩的 `HOOK_*=path` env 行两种形态）。token 边界取空白与引号；去重排序。
fn hook_paths_in_script(script: &str) -> Vec<String> {
    const PREFIX: &str = "/crbs-hooks/";
    let mut out: Vec<String> = script
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter(|t| t.starts_with(PREFIX) && t.len() > PREFIX.len())
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// debug prep 的 SRPM 解析：记录的 srpm_path 优先（本机构建可溯源，缺失/已清
/// 理时回退），再回退 result_dir/SRPMS/ 下字典序首个 *.src.rpm（hub 收集的产
/// 物 SRPM，普通构建与输入 SRPM 同包）。都找不到返回 None（调用方跳过 prep）。
async fn resolve_debug_srpm(
    record_srpm_path: Option<&str>,
    result_dir: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    if let Some(p) = record_srpm_path {
        let p = std::path::PathBuf::from(p);
        if tokio::fs::try_exists(&p).await.unwrap_or(false) {
            return Some(p);
        }
    }
    let dir = result_dir?.join("SRPMS");
    let mut rd = tokio::fs::read_dir(&dir).await.ok()?;
    let mut candidates = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".src.rpm") {
            candidates.push(dir.join(name));
        }
    }
    candidates.sort();
    candidates.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 截断保留 build 标记之前全部内容（含 install-deps 的 PHASE_END 行）。
    #[test]
    fn truncate_keeps_prep_steps_only() {
        let script = "#!/bin/bash\nset -e\n# [step:ccache-init]\necho a\n# [step:install-srpm]\necho b\n# [step:install-deps]\necho c\n# [step:build]\necho rpmbuild\n";
        let cut = truncate_script_to_prep(script).expect("marker present");
        assert!(cut.contains("# [step:install-deps]"));
        assert!(!cut.contains("# [step:build]"));
        assert!(cut.ends_with("echo c\n"));
    }

    #[test]
    fn truncate_returns_none_without_marker() {
        assert!(truncate_script_to_prep("#!/bin/bash\nset -e\n").is_none());
    }

    /// hook 路径收集覆盖 `# [hook:*]` 源行与 spec 插桩 env 行两种形态，去重排序。
    #[test]
    fn hook_paths_collected_and_deduped() {
        let s = "# [hook:pre-install-srpm]\n. /crbs-hooks/pre-install-srpm.sh\nHOOK_PRE=%pre /crbs-hooks/spec-pre-%pre HOOK_POST=%post /crbs-hooks/spec-post-%post\n. /crbs-hooks/pre-install-srpm.sh\n";
        assert_eq!(
            hook_paths_in_script(s),
            vec![
                "/crbs-hooks/pre-install-srpm.sh",
                "/crbs-hooks/spec-post-%post",
                "/crbs-hooks/spec-pre-%pre",
            ]
        );
    }

    #[test]
    fn hook_paths_empty_without_hooks() {
        assert!(hook_paths_in_script("#!/bin/bash\necho hi\n").is_empty());
    }
}
