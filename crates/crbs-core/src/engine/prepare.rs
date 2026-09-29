// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建准备：overlay 环境搭建、挂载选项与 shell 锁。

use std::path::{Path, PathBuf};

use crate::engine::mount::MsFlags;

use crate::engine::layer::{bind_mount_dnf_cache, mount_build_layer, setup_ccache_dir};
use crate::engine::lock::lock_shared_async;
use crate::engine::mount_guard::MountGuard;
use crate::error::CrbsError;

/// 环境准备结果：overlay root + mount guard + 临时目录。
/// Drop 顺序不变量：先 umount（guard）再删临时目录——反序会在挂载仍存活时
/// remove_dir_all；字段按此序声明，`Drop` 移入同一 detached 线程串行执行。
pub(crate) struct PreparedEnv {
    guard: MountGuard,
    pub root: PathBuf,
    env_temp: Option<tempfile::TempDir>,
}

impl PreparedEnv {
    /// 显式逆序卸载所有挂载点并删临时目录；正常/错误路径都应先调用，Drop 仅兜底。
    pub(crate) async fn umount(&mut self) {
        self.guard.umount().await;
        // TempDir Drop 是同步 remove_dir_all（upperdir 可达 GB 级），不能在 tokio
        // worker 上直接执行；且必须后于 umount，避免删到活挂载下的文件。
        if let Some(t) = self.env_temp.take() {
            if let Err(e) = tokio::task::spawn_blocking(move || drop(t)).await {
                tracing::warn!(error = %e, "env tempdir cleanup task failed");
            }
        }
    }
}

impl Drop for PreparedEnv {
    fn drop(&mut self) {
        // panic/早退兜底（正常路径先 `umount()`，此处两者均已取空）。Drop 不能
        // await：umount + 删临时目录移入同一 detached 线程串行执行——自然 Drop
        // 序下 detached umount 线程与同步 remove_dir_all 存在竞态，且 worker
        // 线程禁阻塞 IO。TempDir 删除 best-effort，失败仅残留目录待 GC 兜底。
        let mounts = self.guard.take_mounts();
        let temp = self.env_temp.take();
        if mounts.is_empty() && temp.is_none() {
            return;
        }
        std::thread::spawn(move || {
            crate::engine::mount_guard::sync_lazy_umount_all(mounts);
            drop(temp);
        });
    }
}

/// 可选挂载选项，控制 build/shell/debug 的公共挂载行为。
pub(crate) struct MountOptions {
    pub ccache: bool,
    pub dnf_cache: bool,
    pub tmpfs: bool,
    pub local_repo: Option<PathBuf>,
    /// hub 远端产品 repo baseurl；`Some` 时写 `crbs-product.repo`，与 `local_repo` 互斥。
    pub product_repo_url: Option<String>,
    pub user_binds: Vec<crate::bind::UserBind>,
}

/// setup_overlay 失败路径的 temp 收口：take 后经 spawn_blocking 删除（TempDir
/// Drop 是同步 remove_dir_all，GB 级，不落 async worker）；调用点已先
/// `guard.umount().await`，删除严格后于 umount。
async fn drop_temp_blocking(temp: &mut Option<tempfile::TempDir>) {
    if let Some(t) = temp.take() {
        if let Err(e) = tokio::task::spawn_blocking(move || drop(t)).await {
            tracing::warn!(
                error = ?e,
                "env tempdir cleanup task failed in setup_overlay error path"
            );
        }
    }
}

/// backend 是否自管理容器内挂载（/dev 与 proc/sys 由其自行挂载，宿主侧预挂载
/// 须跳过）；纯函数，便于单测判定逻辑。
fn backend_manages_own_mounts(backend_name: &str) -> bool {
    backend_name == "nspawn"
}

/// BUILD tmpfs 挂载点路径：mount_common_features 的挂载点与 tmpfs 观测的
/// shared_layer 形态共用同一推导，防两处字面量漂移。
pub(crate) fn build_tmpfs_mount_point(root: &Path) -> PathBuf {
    root.join("builddir/BUILD")
}

impl crate::engine::BuildEngine {
    /// 获取 .shell.lock 共享锁（shell 并发兼容，clean 独占等待）；锁获取经
    /// `spawn_blocking` 执行，避免阻塞 tokio worker。
    pub(crate) async fn acquire_shell_lock(&self) -> crate::Result<std::fs::File> {
        let shell_lock = self.config.product_root().join(".shell.lock");
        lock_shared_async(shell_lock, crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT).await
    }

    /// 创建临时 overlayfs 并挂载，返回 (temp_dir, root_path, mount_guard,
    /// tmpfs 观测目标)。`build_tmpfs=true` 且未用 SharedLayer 时全内存构建：
    /// 锚点 tempdir 落磁盘 tmp_dir，其内挂**独立** tmpfs 实例（memroot），
    /// upper/work/root 全落其上，观测产出该挂载点——statfs 绝对读数即本构建
    /// 精确占用，并发构建互不可见；其余情况磁盘 tempdir。shared_layer 形态的
    /// BUILD 挂载点观测由调用方在挂载成功后取（[`build_tmpfs_mount_point`]），
    /// 两处互斥。
    pub(crate) async fn setup_overlay(
        &self,
        lowerdir: &str,
    ) -> crate::Result<(
        Option<tempfile::TempDir>,
        PathBuf,
        MountGuard,
        Option<crate::engine::resource_sample::TmpfsWatch>,
    )> {
        let config = &self.config;
        // lowerdir 以 ':' 分隔多层（shared layer 叠加 base_os），含 ':' 即视为
        // shared layer；单路径含 ':' 会误判，但该语法下路径含 ':' 本就非法/极罕见。
        let has_shared_layer = lowerdir.contains(':');
        let use_tmpfs = !has_shared_layer && config.build_tmpfs;

        // 锚点 tempdir 一律落 tmp_dir（磁盘，默认 /var/tmp）：memroot 只占目录
        // 项，构建数据是否进内存由 memroot 实例自身决定，与共享 tmpfs 余量无关；
        // 亦避开 /tmp（tmpfs）在磁盘模式耗尽内存。
        let t = crate::engine::cache::spawn_blocking_tempdir_in(config.tmp_dir.clone(), "tempdir")
            .await?;
        // guard 由本函数持有：memroot 入 guard 后任何半程失败先显式 await
        // umount、再经 drop_temp_blocking 删 temp、最后返回 Err——直接 Drop 只派
        // 分离线程 lazy umount，与同 tick temp 的同步 Drop 竞争（纪律见
        // `PreparedEnv::drop`）。
        let mut guard = MountGuard::new();
        let (root_base, tmpfs_watch) = if use_tmpfs {
            let memroot = t.path().join("memroot");
            tokio::fs::create_dir_all(&memroot)
                .await
                .map_err(|e| CrbsError::from_io_context("create memroot dir", e))?;
            let memroot_c = memroot.clone();
            tokio::task::spawn_blocking(move || {
                crate::engine::mount::mount(
                    Some(std::path::Path::new("tmpfs")),
                    &memroot_c,
                    Some("tmpfs"),
                    MsFlags::empty(),
                    None::<&str>,
                )
            })
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("spawn_blocking mount memroot tmpfs: {}", e))
            })?
            .map_err(|e| CrbsError::io_message(format!("mount memroot tmpfs: {}", e)))?;
            guard.push(memroot.clone());
            (
                memroot.clone(),
                Some(crate::engine::resource_sample::TmpfsWatch { path: memroot }),
            )
        } else {
            (t.path().to_path_buf(), None)
        };
        let upperdir = root_base.join("upper");
        let workdir = root_base.join("work");
        let root = root_base.join("root");
        let mut temp = Some(t);

        // memroot 已入 guard：目录创建失败须显式卸载后删 temp 再返回。
        let dirs_result = async {
            tokio::fs::create_dir_all(&upperdir)
                .await
                .map_err(|e| CrbsError::from_io_context("create upperdir", e))?;
            tokio::fs::create_dir_all(&workdir)
                .await
                .map_err(|e| CrbsError::from_io_context("create workdir", e))?;
            tokio::fs::create_dir_all(&root)
                .await
                .map_err(|e| CrbsError::from_io_context("create root", e))?;
            Ok::<(), CrbsError>(())
        }
        .await;
        if let Err(e) = dirs_result {
            guard.umount().await;
            drop_temp_blocking(&mut temp).await;
            return Err(e);
        }

        let skip_dev_mounts = backend_manages_own_mounts(self.backend.name());
        // 与 /dev 同谓词：nspawn 自管理 proc/sys，宿主侧 procfs 进入容器会使
        // /proc 探测随宿主 pid 状态翻转，由 nspawn 自挂全新 procfs。
        let skip_pseudo_mounts = backend_manages_own_mounts(self.backend.name());
        if let Err(e) = mount_build_layer(
            &root,
            &upperdir,
            &workdir,
            lowerdir,
            skip_dev_mounts,
            skip_pseudo_mounts,
            &mut guard,
        )
        .await
        {
            guard.umount().await;
            drop_temp_blocking(&mut temp).await;
            return Err(CrbsError::io_message(format!("mount build layer: {}", e)));
        }

        // overlay root 初始属主通常 root:root，而 crbs 主进程以普通用户运行；
        // 不改属回调用者，后续写操作会 Permission denied。
        let caller = crate::privilege::get_caller_info_async().await;
        let root_c = root.clone();
        let chown_result = tokio::task::spawn_blocking(move || {
            crate::privilege::chown(&root_c, caller.uid, caller.gid, false)?;
            // 子目录多来自 lowerdir（root 所有），crbs 需在其下建 resolv.conf、
            // ccache/dnf cache 挂载点、local repo 与 results 挂载点等；
            // 非递归改属，不动 lowerdir 现有文件，目录不存在时跳过。
            for subdir in ["etc", "var", "var/cache", "var/lib", "mnt"] {
                let p = root_c.join(subdir);
                if p.exists() {
                    crate::privilege::chown(&p, caller.uid, caller.gid, false)?;
                }
            }
            Ok::<(), crate::error::CrbsError>(())
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking chown overlay root: {}", e)))
        .and_then(|inner| {
            inner.map_err(|e| CrbsError::io_message(format!("chown overlay root: {}", e)))
        });
        if let Err(e) = chown_result {
            // 同上：显式 await umount 后经 spawn_blocking 删 temp，再返回 Err。
            guard.umount().await;
            drop_temp_blocking(&mut temp).await;
            return Err(e);
        }

        Ok((temp, root, guard, tmpfs_watch))
    }

    /// 挂载可选特性（ccache、dnf_cache、BUILD tmpfs、local_repo 等）到已存在 root；build/shell/debug 共享。
    pub(crate) async fn mount_common_features(
        &self,
        root: &Path,
        guard: &mut MountGuard,
        opts: &MountOptions,
    ) -> crate::Result<()> {
        let config = &self.config;

        // 预清理合并层遗留的 `*.repo`：直接改写触发 overlay copy-up 保留旧属主，跨身份
        // 重写即 EACCES；unlink 只需目录组写（0775 root:crbs），删后按当前身份重建，才能跨身份复用缓存。
        let repo_conf_dir = root.join("etc/yum.repos.d");
        if tokio::fs::try_exists(&repo_conf_dir).await.unwrap_or(false) {
            let mut entries = tokio::fs::read_dir(&repo_conf_dir)
                .await
                .map_err(|e| CrbsError::from_io_context("scan yum.repos.d", e))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| CrbsError::from_io_context("iterate yum.repos.d", e))?
            {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("repo") {
                    if let Err(e) = tokio::fs::remove_file(&path).await {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            return Err(CrbsError::from_io_context(
                                "remove stale merged repo file",
                                e,
                            ));
                        }
                    }
                }
            }
        }

        if opts.ccache {
            let ccache_host = config.ccache_dir.clone();
            setup_ccache_dir(&ccache_host, config.builder_uid).await?;
            let ccache_chroot = root.join("var/cache/ccache-crbs");
            tokio::fs::create_dir_all(&ccache_chroot)
                .await
                .map_err(|e| CrbsError::from_io_context("create ccache chroot dir", e))?;
            guard
                .bind_mount_private(Some(&ccache_host), &ccache_chroot, "ccache")
                .await?;
        }

        if opts.dnf_cache && config.dnf_cache_enabled {
            let dnf_cache = config.dnf_cache_path();
            bind_mount_dnf_cache(root, &dnf_cache, guard)
                .await
                .map_err(|e| CrbsError::io_message(format!("bind mount dnf cache: {}", e)))?;
        }

        // BUILD tmpfs（无 shared_layer 时 upper 已在 tmpfs，此挂载仅 shared_layer
        // 场景有实质作用）
        if opts.tmpfs && config.build_tmpfs {
            let build_tmpfs = build_tmpfs_mount_point(root);
            tokio::fs::create_dir_all(&build_tmpfs)
                .await
                .map_err(|e| CrbsError::from_io_context("create BUILD dir", e))?;
            let build_tmpfs_c = build_tmpfs.clone();
            tokio::task::spawn_blocking(move || {
                crate::engine::mount::mount(
                    Some(std::path::Path::new("tmpfs")),
                    &build_tmpfs_c,
                    Some("tmpfs"),
                    MsFlags::empty(),
                    None::<&str>,
                )
            })
            .await
            .map_err(|e| CrbsError::io_message(format!("spawn_blocking mount tmpfs: {}", e)))?
            .map_err(|e| CrbsError::io_message(format!("mount BUILD tmpfs: {}", e)))?;
            guard.push(build_tmpfs);
        }

        // local repo bind mount（--chain 时使用）
        if let Some(ref repo_dir) = opts.local_repo {
            tokio::fs::metadata(repo_dir)
                .await
                .map_err(|e| CrbsError::from_io_context("check local repo source", e))?;

            let repo_target = root.join("mnt/crbs-repo");
            tokio::fs::create_dir_all(&repo_target)
                .await
                .map_err(|e| CrbsError::from_io_context("create local repo mount point", e))?;
            guard
                .bind_mount_private(Some(repo_dir), &repo_target, "local repo")
                .await?;

            let repo_conf_dir = root.join("etc/yum.repos.d");
            tokio::fs::create_dir_all(&repo_conf_dir)
                .await
                .map_err(|e| CrbsError::from_io_context("create yum.repos.d", e))?;
            let repo_conf = repo_conf_dir.join("crbs-local.repo");
            tokio::fs::write(&repo_conf, crate::engine::repo::write_local_repo_conf())
                .await
                .map_err(|e| CrbsError::from_io_context("write crbs-local.repo", e))?;

            // local repo 内 RPM 经 symlink 指向 results，须在容器内挂载 results 使 symlink 可解析。
            let results_host = &self.config.result_dir;
            crate::util::validate_path_no_traversal(results_host, false)?;
            let results_chroot = if let Some(s) = results_host.to_str() {
                if let Some(stripped) = s.strip_prefix('/') {
                    root.join(stripped)
                } else {
                    root.join(s)
                }
            } else {
                root.join(results_host)
            };
            tokio::fs::create_dir_all(&results_chroot)
                .await
                .map_err(|e| CrbsError::from_io_context("create results mount point", e))?;
            tokio::fs::metadata(results_host)
                .await
                .map_err(|e| CrbsError::from_io_context("check results source", e))?;
            guard
                .bind_mount_private(Some(results_host), &results_chroot, "results")
                .await?;
        }

        // product repo baseurl 写 chroot（http 源，无 bind 挂载），互斥与门禁见 `validate_product_repo_inject`
        if let Some(url) = opts.product_repo_url.as_deref() {
            validate_product_repo_inject(opts.local_repo.as_deref(), Some(url))?;
            // 双保险：误配复现旗标 + with_product_repo_url 时重放 chroot 也不进 crbs-product.repo。
            if !dynamic_repo_injection_enabled(self.replay_snapshot_domain) {
                tracing::debug!(
                    baseurl = %url,
                    "Skipped crbs-product.repo injection: replay chroot hermetic"
                );
            } else if self.config.network {
                write_product_repo_to_root(root, url).await?;
                // 主机名形式 baseurl 需要容器内名字解析：追加 hosts 映射（best-effort，
                // 失败不阻断——后果只是 dnf 在容器内解析不了该主机名）。
                if let Err(e) = append_repo_host_entry(
                    root,
                    url,
                    resolve_repo_host,
                    // 特权层写回（root:root 0644）：/etc/hosts 属 root，crbs 身份
                    // 直写必 EACCES；写法同 reproduce 验签中和宏（root 落盘）。
                    |path, content| async move {
                        crate::privilege::write_file_async(
                            &path,
                            &content,
                            Some(0o644),
                            Some(0),
                            Some(0),
                        )
                        .await
                    },
                )
                .await
                {
                    tracing::warn!(
                        baseurl = %url,
                        error = %e,
                        "Failed to append product repo host mapping to sandbox /etc/hosts; \
                         dnf inside the container may fail to resolve it"
                    );
                }
                tracing::debug!(
                    baseurl = %url,
                    "Injected crbs-product.repo into chroot",
                );
            } else {
                // network=false 不注入（http 源无意义，且违背构建网络策略）
                tracing::debug!(
                    baseurl = %url,
                    "Skipped crbs-product.repo injection: network disabled",
                );
            }
        }

        // 产品 repos 动态注入：覆写 base_os init 写入的同名 repo 文件（写 overlay 层，base_os
        // 不受影响；内容不变则 dnf 缓存不失效）。replay 跳过——重放密闭 = dnf
        // 侧 repo 唯一源（install-deps disablerepo=* 只看 crbs-local 记录全集
        // 仓），base lower 层的产品镜像仓被 dnf 禁用不参与解析，overlay 无需遮蔽。
        if dynamic_repo_injection_enabled(self.replay_snapshot_domain) {
            let repo_conf_dir = root.join("etc/yum.repos.d");
            tokio::fs::create_dir_all(&repo_conf_dir)
                .await
                .map_err(|e| {
                    CrbsError::from_io_context("create yum.repos.d for product repos", e)
                })?;
            // 先清后写（只动 `*.repo`）：init 后删除/禁用的 repo 文件仍在 lower 层生效，
            // unlink 生成 whiteout 遮蔽之；crbs-local/crbs-product.repo 刚由上方分支写入，保留。
            crate::engine::repo::remove_stale_repo_files(
                &repo_conf_dir,
                &config.repos,
                &["crbs-local.repo", "crbs-product.repo"],
            )
            .await?;
            crate::engine::repo::write_repo_files(&repo_conf_dir, &config.repos).await?;
            tracing::debug!(
                product = %config.product,
                repo_count = config.repos.len(),
                "Injected product repos into chroot"
            );
        } else {
            tracing::debug!(
                product = %config.product,
                "Skipped product repos injection: replay chroot hermetic"
            );
        }

        // 用户自定义 bind mount（--bind 选项）
        for ub in &opts.user_binds {
            crate::util::validate_path_no_traversal(&ub.container, true)?;
            let container_path = root.join(ub.container.strip_prefix("/").unwrap_or(&ub.container));
            tokio::fs::create_dir_all(&container_path)
                .await
                .map_err(|e| CrbsError::from_io_context("create bind target", e))?;

            guard
                .bind_mount_private(Some(&ub.host), &container_path, "user bind")
                .await?;

            if ub.read_only {
                let container_c = container_path.clone();
                tokio::task::spawn_blocking(move || -> crate::Result<()> {
                    crate::engine::mount::mount(
                        None,
                        &container_c,
                        None::<&str>,
                        crate::engine::mount::MsFlags::MS_BIND
                            | crate::engine::mount::MsFlags::MS_REMOUNT
                            | crate::engine::mount::MsFlags::MS_RDONLY,
                        None::<&str>,
                    )?;
                    Ok(())
                })
                .await
                .map_err(|e| CrbsError::io_message(format!("spawn_blocking user bind ro: {}", e)))?
                .map_err(|e| CrbsError::io_message(format!("remount readonly: {}", e)))?;
            }

            tracing::debug!(
                host = %ub.host.display(),
                container = %ub.container.display(),
                ro = ub.read_only,
                "User bind mount",
            );
        }

        Ok(())
    }

    /// 准备构建/shell/debug 共享环境：创建 overlay + `mount_common_features` 挂载可选特性。
    pub(crate) async fn prepare_env(
        &self,
        lowerdir: &str,
        opts: &MountOptions,
    ) -> crate::Result<PreparedEnv> {
        // shell/debug 无采样消费方，tmpfs 观测目标在此弃置（构建路径直接调
        // setup_overlay 取用）。
        let (env_temp, root, mut guard, _tmpfs_watch) = self.setup_overlay(lowerdir).await?;
        if let Err(e) = self.mount_common_features(&root, &mut guard, opts).await {
            // 半程失败：显式 await umount 后经 spawn_blocking 删 temp（照
            // PreparedEnv::umount 形态）——直接 Drop 的分离线程 lazy umount 与 temp
            // 同步 remove_dir_all 竞争，rm 穿过活 bind 挂载点删宿主侧 ccache/dnf 缓存与 results 内容。
            guard.umount().await;
            if let Some(t) = env_temp {
                if let Err(warn_e) = tokio::task::spawn_blocking(move || drop(t)).await {
                    tracing::warn!(error = %warn_e, "env tempdir cleanup task failed");
                }
            }
            return Err(e);
        }
        Ok(PreparedEnv {
            env_temp,
            root,
            guard,
        })
    }
}

/// 产品 repo 动态注入（`config.repos` 覆写 + `crbs-product.repo`）是否启用。
///
/// replay（判别器 = 复现解析域旗标，`with_replay_snapshot_domain` 置位）跳过
/// 注入：重放密闭 = dnf 侧 repo 唯一源（install-deps `--disablerepo=*` 只看
/// crbs-local 记录全集仓），base lower 层的产品镜像仓不参与解析，overlay 无需
/// 遮蔽。
pub(crate) fn dynamic_repo_injection_enabled(replay_snapshot_domain: bool) -> bool {
    !replay_snapshot_domain
}

/// 校验 `local_repo` 与 `product_repo_url` 互斥：chain 本地构建走 `file://`，
/// hub 远程走 `http(s)://`，同产品同构建只选一种。
pub fn validate_product_repo_inject(
    local_repo: Option<&Path>,
    product_repo_url: Option<&str>,
) -> crate::Result<()> {
    if local_repo.is_some() && product_repo_url.is_some() {
        return Err(CrbsError::ValidationFailed {
            message: "local_repo and product_repo_url are mutually exclusive \
                      (chain local build vs hub remote product repo)"
                .to_string(),
        });
    }
    Ok(())
}

/// 写入 `crbs-product.repo` 到 chroot `etc/yum.repos.d/`（无 bind 挂载）。
/// `url` 须已是合法 `http(s)://` baseurl（由 `write_product_repo_conf` 校验）。
pub async fn write_product_repo_to_root(root: &Path, url: &str) -> crate::Result<()> {
    let conf_dir = root.join("etc/yum.repos.d");
    tokio::fs::create_dir_all(&conf_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create yum.repos.d for product repo", e))?;
    let conf_path = conf_dir.join("crbs-product.repo");
    let content = crate::engine::repo::write_product_repo_conf(url)?;
    tokio::fs::write(&conf_path, content)
        .await
        .map_err(|e| CrbsError::from_io_context("write crbs-product.repo", e))?;
    Ok(())
}

/// 产品 repo baseurl 的 host 段（不含端口）：scheme 后到首个 `/`、`:`、`?`、`#`；
/// `[` 开头按 IPv6 字面量取到 `]`（内层）。无 host 段返回 `None`。
fn baseurl_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    if let Some(bracketed) = rest.strip_prefix('[') {
        return bracketed.split_once(']').map(|(inner, _)| inner);
    }
    let end = rest.find(['/', ':', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    (!host.is_empty()).then_some(host)
}

/// hosts 内容是否已有 `host` 的映射行（非注释行的第 2+ 字段命中即算——
/// `1.2.3.4 hub` 与 `1.2.3.4 hub alias` 都算；主机名大小写不敏感）：base 层
/// 运维手工映射与代码层追加查重共存，已映射则不双写。
fn hosts_entry_exists(content: &str, host: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        line.split_whitespace()
            .skip(1)
            .any(|alias| alias.eq_ignore_ascii_case(host))
    })
}

/// 宿主侧解析 repo host（生产解析缝）：取首个解析地址的 IP。容器与宿主共享
/// 网络命名空间（nspawn 仅 `network=false` 才 `--private-network`），宿主可达
/// 的 IP 容器即可达。
async fn resolve_repo_host(host: String) -> Option<std::net::IpAddr> {
    match tokio::net::lookup_host((host.as_str(), 0)).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip()),
        Err(e) => {
            tracing::debug!(host = %host, error = %e, "Product repo host lookup failed");
            None
        }
    }
}

/// 产品 repo URL host 为**主机名**（非 IP）时，把 `{解析出的 IP} {host}` 写进
/// 沙箱 /etc/hosts（overlay 层追加，base 层文件不动）：base 镜像 hosts 无该
/// 映射，且 nspawn 不处理 /etc/hosts（argv 无 bind，容器看到的就是 rootfs 内
/// 的文件），不写入则容器内解析该主机名必败。IP 形式 URL 容器内可直接连接，
/// 不动作。
///
/// 写通道走特权层（root:root 0644 整文件重写，见 [`crate::privilege::write_file_async`]）：
/// overlay rootfs 内 /etc/hosts 属 root:root 0644，crbs 身份直写/追加必 EACCES
///——读现有内容（0644 全员可读，普通读即可；缺失按空处理）查重后经特权写回。
///
/// best-effort：解析失败 / host 字符集非法 warn 后返回 Ok（跳过不写）；hosts
/// 读写失败返回 Err 由调用方 warn 跳过——缺条目的后果只是 dnf 在容器内解析
/// 不了该主机名，且运维在 base 层的手工映射（查重后不双写）可能已覆盖。
/// `resolver` 注入解析缝（生产 = [`resolve_repo_host`]，测试注入固定值）；
/// `writer` 注入写缝（生产 = 特权 `write_file_async`，测试注入普通写盘）。
async fn append_repo_host_entry<R, FutR, W, FutW>(
    root: &Path,
    url: &str,
    resolver: R,
    writer: W,
) -> crate::Result<()>
where
    R: Fn(String) -> FutR,
    FutR: std::future::Future<Output = Option<std::net::IpAddr>>,
    W: Fn(PathBuf, Vec<u8>) -> FutW,
    FutW: std::future::Future<Output = crate::Result<()>>,
{
    let Some(host) = baseurl_host(url) else {
        tracing::debug!(baseurl = %url, "Product repo URL has no host part; skipping /etc/hosts entry");
        return Ok(());
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        tracing::debug!(host = %host, "Product repo URL host is an IP; skipping /etc/hosts entry");
        return Ok(());
    }
    // hosts 条目字符集收口：该值拼进 /etc/hosts 由 glibc 逐行解析，畸形行破坏
    // 整文件解析（`write_product_repo_conf` 已拒空白/控制字符，此处按 hosts
    // 语义再收一次，非法值跳过而非报错——repo 文件本身已带完整校验）。
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        tracing::warn!(
            host = %host,
            "Product repo URL host is not a valid hostname; skipping /etc/hosts entry"
        );
        return Ok(());
    }
    let Some(ip) = resolver(host.to_string()).await else {
        tracing::warn!(
            host = %host,
            "Failed to resolve product repo host on the host side; skipping /etc/hosts entry"
        );
        return Ok(());
    };

    let hosts_path = root.join("etc/hosts");
    // base 镜像恒有 /etc（create 只兜极端缺目录的裸 root，语义同 write_product_repo_to_root）。
    if let Some(parent) = hosts_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| CrbsError::from_io_context("create sandbox etc directory", e))?;
    }
    let existing = match tokio::fs::read_to_string(&hosts_path).await {
        Ok(c) => c,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(CrbsError::from_io_context("read sandbox /etc/hosts", e)),
    };
    if hosts_entry_exists(&existing, host) {
        tracing::debug!(
            host = %host,
            "Sandbox /etc/hosts already maps the product repo host; skipping append"
        );
        return Ok(());
    }
    let mut updated = existing;
    updated.push_str(&format!("{ip} {host}\n"));
    writer(hosts_path, updated.into_bytes()).await?;
    tracing::debug!(
        host = %host,
        ip = %ip,
        "Appended product repo host mapping to sandbox /etc/hosts"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== drop_temp_blocking take 语义 =====
    // umount 先于 temp 删除的顺序不在此直测（需真实 overlayfs）：顺序由代码结构
    // 保证，同族防线由 cleanup_guard.rs 的 e2e 回归覆盖。

    /// None 输入不动作（take 后 None 短路，不 spawn 删除任务）。
    #[tokio::test]
    async fn drop_temp_blocking_none_is_noop() {
        let mut temp: Option<tempfile::TempDir> = None;
        drop_temp_blocking(&mut temp).await;
        assert!(temp.is_none());
    }

    /// Some 输入被消费（take 后置空），await 返回即删除完成（spawn_blocking join 语义）。
    #[tokio::test]
    async fn drop_temp_blocking_takes_and_removes_dir() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        assert!(path.exists());
        let mut slot = Some(temp);
        drop_temp_blocking(&mut slot).await;
        assert!(slot.is_none(), "Some must be consumed (take semantics)");
        assert!(
            !path.exists(),
            "tempdir must be gone once the awaited cleanup returns"
        );
    }

    #[test]
    fn validate_allows_local_only() {
        assert!(validate_product_repo_inject(Some(Path::new("/var/lib/crbs/repo")), None).is_ok());
    }

    #[test]
    fn validate_allows_product_only() {
        assert!(validate_product_repo_inject(None, Some("http://h/r/p/x")).is_ok());
    }

    #[test]
    fn validate_rejects_both() {
        let err =
            validate_product_repo_inject(Some(Path::new("/var/lib/crbs/repo")), Some("http://h/r"));
        assert!(err.is_err());
    }

    #[test]
    fn validate_allows_neither() {
        assert!(validate_product_repo_inject(None, None).is_ok());
    }

    // ===== backend 自管理挂载判定 =====

    /// nspawn 自管理 /dev 与 proc/sys：宿主侧预挂载全部跳过，容器内 /proc 由
    /// nspawn 自挂全新 procfs。
    #[test]
    fn nspawn_backend_manages_own_mounts() {
        assert!(backend_manages_own_mounts("nspawn"));
    }

    /// chroot 依赖宿主侧预挂载（含 proc/sys）：不跳过，行为零变化。
    #[test]
    fn chroot_backend_keeps_host_mounts() {
        assert!(!backend_manages_own_mounts("chroot"));
    }

    // ===== 产品 repo 动态注入开关 =====

    /// 复现旗标未置位（normal build/shell/debug）→ 注入启用。
    #[test]
    fn dynamic_repo_injection_enabled_without_replay_flag() {
        assert!(dynamic_repo_injection_enabled(false));
    }

    /// 复现旗标置位（replay 的快照解析域）→ 注入关闭：重放 overlay 密闭。
    #[test]
    fn dynamic_repo_injection_disabled_with_replay_flag() {
        assert!(!dynamic_repo_injection_enabled(true));
    }

    #[tokio::test]
    async fn write_product_repo_to_root_writes_expected_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_product_repo_to_root(root, "http://hub.example.com/repo/prod/x86_64")
            .await
            .unwrap();
        let conf = root.join("etc/yum.repos.d/crbs-product.repo");
        let body = tokio::fs::read_to_string(&conf).await.unwrap();
        assert!(body.contains("baseurl=http://hub.example.com/repo/prod/x86_64"));
        assert!(body.contains("skip_if_unavailable=1"));
        assert!(!body.contains("priority="), "must not set priority: {body}");
        assert!(!body.contains("cost="), "must not set cost: {body}");
    }

    // ===== 产品 repo hosts 注入（容器内 DNS） =====

    /// 固定值解析注入缝。
    fn fake_resolver(
        ip: Option<&str>,
    ) -> impl Fn(String) -> std::future::Ready<Option<std::net::IpAddr>> {
        let ip = ip.map(std::net::IpAddr::from_str).map(|r| r.unwrap());
        move |_host| std::future::ready(ip)
    }

    /// 普通写盘注入缝（tempdir 属当前用户，无需特权层——生产侧为特权
    /// `write_file_async`，经 `writer` 参数替换，权限/属主参数不进本测试面）。
    fn plain_writer() -> impl Fn(
        PathBuf,
        Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<()>> + Send>,
    > {
        |path: PathBuf, content: Vec<u8>| {
            Box::pin(async move {
                tokio::fs::write(&path, &content)
                    .await
                    .map_err(|e| CrbsError::from_io_context("test write sandbox hosts", e))
            })
        }
    }

    use std::str::FromStr;

    /// 主机名形式 baseurl：追加 `{IP} {host}` 映射行。
    #[tokio::test]
    async fn repo_hosts_entry_appended_for_hostname_url() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        append_repo_host_entry(
            root,
            "http://crbs-hub:8080/repo/prod/x86_64",
            fake_resolver(Some("10.0.0.7")),
            plain_writer(),
        )
        .await
        .unwrap();

        let hosts = tokio::fs::read_to_string(root.join("etc/hosts"))
            .await
            .unwrap();
        assert!(
            hosts.contains("10.0.0.7 crbs-hub\n"),
            "hosts must gain the mapping line: {hosts:?}"
        );
    }

    /// base 层运维手工映射（查重命中）：不双写——追加与既有条目共存且唯一。
    #[tokio::test]
    async fn repo_hosts_entry_not_duplicated_when_ops_entry_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let hosts = root.join("etc/hosts");
        tokio::fs::create_dir_all(root.join("etc")).await.unwrap();
        tokio::fs::write(&hosts, "127.0.0.1 localhost\n10.9.9.9 CRBS-Hub hub.local\n")
            .await
            .unwrap();

        append_repo_host_entry(
            root,
            "http://crbs-hub/repo/prod/x86_64",
            fake_resolver(Some("10.0.0.7")),
            plain_writer(),
        )
        .await
        .unwrap();

        let body = tokio::fs::read_to_string(&hosts).await.unwrap();
        assert!(
            !body.contains("10.0.0.7"),
            "已有映射（大小写不敏感）不得双写: {body:?}"
        );
        assert_eq!(body.lines().count(), 2, "既有条目不动");
    }

    /// 注释行与纯 IP 行不算映射；别名命中算（`hub alias` 形态）。
    #[test]
    fn hosts_entry_exists_matches_aliases_not_comments() {
        assert!(hosts_entry_exists("1.2.3.4 hub\n", "hub"));
        assert!(hosts_entry_exists("1.2.3.4 hub alias\n", "alias"));
        assert!(hosts_entry_exists("1.2.3.4 HUB\n", "hub"));
        assert!(!hosts_entry_exists("# 1.2.3.4 hub\n", "hub"));
        assert!(!hosts_entry_exists("1.2.3.4 other\n", "hub"));
        assert!(!hosts_entry_exists("\n", "hub"));
        // 首字段是 IP 列：第 2+ 字段才算主机名。
        assert!(!hosts_entry_exists("hub\n", "hub"));
    }

    /// IP 形式 baseurl（v4 与 v6 字面量）不动作。
    #[tokio::test]
    async fn repo_hosts_entry_skipped_for_ip_url() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for url in [
            "http://10.0.0.7:8080/repo/prod/x86_64",
            "http://[fd00::7]/repo/prod/x86_64",
        ] {
            append_repo_host_entry(root, url, fake_resolver(Some("10.0.0.7")), plain_writer())
                .await
                .unwrap();
        }
        assert!(
            !root.join("etc/hosts").exists(),
            "IP 形式 URL 不得创建/改动 hosts"
        );
    }

    /// 宿主侧解析失败：不写条目、不报错（best-effort，调用方 warn 后继续）。
    #[tokio::test]
    async fn repo_hosts_entry_skipped_when_unresolvable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        append_repo_host_entry(
            root,
            "http://crbs-hub/repo/prod/x86_64",
            fake_resolver(None),
            plain_writer(),
        )
        .await
        .unwrap();
        assert!(!root.join("etc/hosts").exists());
    }

    /// host 字符集非法（可破坏 hosts 整文件解析）：跳过不写。
    #[tokio::test]
    async fn repo_hosts_entry_skipped_for_invalid_hostname() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // user@host / 空白已在 write_product_repo_conf 拒绝，这里钉 hosts 侧收口。
        append_repo_host_entry(
            root,
            "http://user@crbs-hub/repo/prod/x86_64",
            fake_resolver(Some("10.0.0.7")),
            plain_writer(),
        )
        .await
        .unwrap();
        assert!(!root.join("etc/hosts").exists());
    }

    /// baseurl host 段解析：主机名 / 带端口 / IP / IPv6 字面量 / 无 host。
    #[test]
    fn baseurl_host_parses_all_forms() {
        assert_eq!(baseurl_host("http://hub/repo/p/a"), Some("hub"));
        assert_eq!(baseurl_host("http://hub:8080/repo/p/a"), Some("hub"));
        assert_eq!(baseurl_host("https://10.0.0.7/repo/p/a"), Some("10.0.0.7"));
        assert_eq!(baseurl_host("https://[fd00::7]:8443/r"), Some("fd00::7"));
        assert_eq!(baseurl_host("http://hub"), Some("hub"));
        assert_eq!(baseurl_host("http:///repo"), None);
        assert_eq!(baseurl_host("hub/repo"), None);
        assert_eq!(baseurl_host(""), None);
    }

    #[tokio::test]
    async fn write_product_repo_to_root_https_adds_sslverify() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_product_repo_to_root(root, "https://h/p/a")
            .await
            .unwrap();
        let conf = root.join("etc/yum.repos.d/crbs-product.repo");
        let body = tokio::fs::read_to_string(&conf).await.unwrap();
        assert!(body.contains("baseurl=https://h/p/a"));
        assert!(body.contains("sslverify=0"));
    }

    #[tokio::test]
    async fn write_product_repo_to_root_rejects_non_http_scheme() {
        let tmp = tempfile::tempdir().unwrap();
        let err = write_product_repo_to_root(tmp.path(), "file:///mnt/crbs-repo")
            .await
            .expect_err("file:// must be rejected");
        let msg = format!("{}", err);
        assert!(msg.contains("http://") || msg.contains("https://"));
        assert!(!tmp
            .path()
            .join("etc/yum.repos.d/crbs-product.repo")
            .exists());
    }
}
