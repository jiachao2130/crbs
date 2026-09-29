// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地环境清理：残留挂载解除与数据目录受控删除。

use std::path::PathBuf;

use crate::engine::mount::{umount2, MntFlags};
use tracing::{info, warn};

use crate::engine::lock::lock_exclusive_async;
use crate::error::CrbsError;

/// MNT_DETACH 批量卸载：`label`（"clean" / "clean retry"）区分两轮 warn 文案；
/// umount2 是同步系统调用，spawn_blocking 防卡 runtime。
async fn lazy_umount_all(mounts: Vec<PathBuf>, label: &'static str) {
    tokio::task::spawn_blocking(move || {
        for m in mounts {
            if let Err(e) = umount2(&m, MntFlags::MNT_DETACH) {
                warn!(path = %m.display(), error = %e, "Failed to umount during {label}");
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        warn!(error = %e, "spawn_blocking umount task failed during {label}");
    });
}

/// 读取 /proc/mounts，返回 mountpoint 位于 `root` 之下的挂载点列表；空白按八进制
/// 转义还原（空格=\040、制表=\011、换行=\012），否则带空格的 crbs_root 静默匹配不到。
async fn mounts_under(root: &std::path::Path) -> crate::Result<Vec<PathBuf>> {
    let content = tokio::fs::read_to_string("/proc/mounts")
        .await
        .map_err(|e| CrbsError::from_io_context("read /proc/mounts", e))?;
    Ok(content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                // 共享解码（orphan::decode_proc_mounts_field 覆盖全部内核转义含 \134），两处扫描同孤儿扫描口径。
                let mountpoint =
                    PathBuf::from(crate::engine::orphan::decode_proc_mounts_field(parts[1]));
                if mountpoint.starts_with(root) {
                    Some(mountpoint)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect())
}

/// rm -rf `product_root` 的直接子项，豁免两个 flock 锁文件（见 `clean` 内注释）。
async fn rm_children_excluding_locks(product_root: &std::path::Path) -> crate::Result<()> {
    let pr = product_root.to_path_buf();
    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        let mut children: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&pr)
            .map_err(|e| CrbsError::from_io_context("read product root for clean", e))?
        {
            let entry = entry
                .map_err(|e| CrbsError::from_io_context("iterate product root for clean", e))?;
            let name = entry.file_name();
            // 只按确切文件名豁免锁文件，其余一律删（children 全部位于 product_root 命名空间内）。
            if name == ".init.lock" || name == ".shell.lock" {
                continue;
            }
            children.push(entry.path());
        }
        let refs: Vec<&std::path::Path> = children.iter().map(|p| p.as_path()).collect();
        crate::privilege::rm_rf(&refs)
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking rm_rf: {e}")))?
}

impl crate::engine::BuildEngine {
    /// 清理构建环境：独占 flock .shell.lock 等 shell 退出 → 扫描 /proc/mounts →
    /// lazy umount → rm -rf product_root。`bypass_guard` 同 [`Self::init`]：
    /// false = CLI/server 保留 active build 守卫，true = 任务执行者路径跳过。
    pub async fn clean(&self, bypass_guard: bool) -> crate::Result<()> {
        let config = &self.config;
        let product_root = config.product_root();

        if !tokio::fs::try_exists(&product_root).await? {
            return Err(CrbsError::ValidationFailed {
                message: format!("product not found: {}", product_root.display()),
            });
        }

        // 先获取 .init.lock 独占锁：防止并发 init 创建目录
        let init_lock = product_root.join(".init.lock");
        let _init_lock_file =
            lock_exclusive_async(init_lock, crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT).await?;

        // 再获取 .shell.lock 独占锁：等待所有 shell 退出
        let shell_lock = product_root.join(".shell.lock");
        let _shell_lock_file =
            lock_exclusive_async(shell_lock, crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT)
                .await?;

        info!(product = %config.product, "Cleaning up");

        // 先修复僵尸活跃构建（崩溃残留的 pending/building 孤儿），真实存活的由下方 active 检查继续拦截。
        self.state
            .repair_zombie_active_builds_logged(&config.product)
            .await;

        // 安全守卫：同产品有 active（building + pending）build 时拒绝清理；bypass_guard=true
        //（任务执行者路径）跳过——同链路再被自己挡是 TOCTOU 自残，并发安全由上方 flock 守护。
        if !bypass_guard {
            match self.state.count_active_for_product(&config.product).await {
                Ok(count) if count > 0 => {
                    // 收集其他用户的活跃 build 信息（用于错误提示）
                    let caller_name = self
                        .caller
                        .as_ref()
                        .map(|c| c.username.as_str())
                        .unwrap_or("");
                    match self
                        .state
                        .active_build_users_for_product(&config.product, caller_name)
                        .await
                    {
                        Ok(users) if !users.is_empty() => {
                            return Err(CrbsError::ValidationFailed {
                                message: format!(
                                    "Cannot clean '{}': active builds by user(s): {}. Wait for them to finish.",
                                    config.product,
                                    users.join(", ")
                                ),
                            });
                        }
                        _ => {
                            return Err(CrbsError::ValidationFailed {
                                message: format!(
                                    "Cannot clean '{}': {} active/pending build(s) in progress. Wait for them to finish.",
                                    config.product, count
                                ),
                            });
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(CrbsError::io_message(format!(
                        "Failed to query active builds: {}",
                        e
                    )));
                }
            }
        }

        // 先回收共享层目录（必须先于行删除）：目录在 shared_layers/ 下与 product_root
        // 平级 rm 碰不到；行删后行驱动 GC 看不到、orphan GC 跳过 .complete → 每 clean
        // 一产品永久泄漏数 GB dep 层。协议同 run_gc：flock → refcount 复检 → 命名空间断言 → 特权 rm。
        let shared_layers_dir = config.shared_layers_dir.clone();
        // kept_for_gc = 因任何原因跳过目录删除、留给 GC 的 digest（refcount≠0/锁失败
        // 或被占/复检失败/rm 失败）：行删除必须排除，行没了行驱动 GC 看不到仍在盘的层目录。
        let mut kept_for_gc: Vec<String> = Vec::new();
        match self.state.list_layers_for_product(&config.product).await {
            Ok(layers) => {
                for (digest, path) in layers {
                    let expected = shared_layers_dir.join(&digest);
                    if std::path::Path::new(&path) != expected {
                        warn!(
                            product = %config.product,
                            digest = %digest,
                            path = %path,
                            "layer path outside expected namespace during clean, skipping dir removal"
                        );
                        kept_for_gc.push(digest);
                        continue;
                    }
                    let lock_path = expected.join(".lock");
                    let lock_file = match tokio::fs::OpenOptions::new()
                        .create(true)
                        .truncate(false)
                        .write(true)
                        .open(&lock_path)
                        .await
                    {
                        Ok(f) => f,
                        Err(e) => {
                            // 行与目录都留，交行驱动 GC 复检。
                            warn!(digest = %digest, error = %e, "open layer lock during clean failed, skipping dir removal; keeping layer row for GC");
                            kept_for_gc.push(digest);
                            continue;
                        }
                    };
                    use fs4::tokio::AsyncFileExt;
                    if lock_file.try_lock_exclusive().is_err() {
                        warn!(digest = %digest, "layer locked during clean, skipping dir removal; keeping layer row for GC");
                        kept_for_gc.push(digest);
                        continue;
                    }
                    // create(true) 建出的 .lock 受 umask 影响（0644）：补 0660+crbs
                    //（同 acquire_layer_lock/run_gc），否则该 digest 后续创建/GC 跨身份 EACCES。
                    {
                        let lp = lock_path.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::gc::fix_created_lock_perms(&lp)
                        })
                        .await;
                    }
                    // 删行前 refcount 复核：非 0 = 泄漏计数，目录留 GC 并记入 kept_for_gc 使行删除跳过。
                    match self.state.get_layer_ref_count(&digest).await {
                        Ok(Some(0)) => {}
                        Ok(_) => {
                            info!(digest = %digest, "layer ref_count non-zero during clean, leaving dir to GC");
                            kept_for_gc.push(digest);
                            continue;
                        }
                        Err(e) => {
                            // 引用状态未知：目录不动、行也保留，交 GC 复检。
                            warn!(digest = %digest, error = %e, "recheck layer ref_count during clean failed, skipping dir removal; keeping layer row for GC");
                            kept_for_gc.push(digest);
                            continue;
                        }
                    }
                    if let Err(e) =
                        crate::gc::assert_delete_under_root(&shared_layers_dir, &expected)
                    {
                        warn!(digest = %digest, error = %e, "layer dir fails namespace assert during clean, skipping");
                        kept_for_gc.push(digest);
                        continue;
                    }
                    let dir_rm = expected.clone();
                    let rm = tokio::task::spawn_blocking(move || {
                        let refs = [dir_rm.as_path()];
                        crate::privilege::rm_rf(&refs)
                    })
                    .await;
                    match rm {
                        Ok(Ok(())) => {
                            info!(digest = %digest, "Removed shared layer dir during clean")
                        }
                        // rm 失败目录仍带 .complete（orphan GC 不回收），行保留给行驱动 GC 重试。
                        Ok(Err(e)) => {
                            warn!(digest = %digest, error = %e, "remove shared layer dir during clean failed; keeping layer row for GC recheck");
                            kept_for_gc.push(digest);
                        }
                        Err(e) => {
                            warn!(digest = %digest, error = %e, "spawn_blocking remove layer dir failed; keeping layer row for GC recheck");
                            kept_for_gc.push(digest);
                        }
                    }
                }
            }
            Err(e) => {
                // 目录清单未知却删行 = kept_for_gc 漏记 → 该产品全部 layer 行删光，行驱动
                // GC 从此看不到仍在盘的层目录（数 GB 泄漏）。fail-closed 让整个 clean 失败。
                return Err(CrbsError::io_message(format!(
                    "list layers for clean failed; keeping layer rows and dirs for GC: {}",
                    e
                )));
            }
        }

        // 删 layers + layer_packages 行；kept_for_gc 中的 digest 排除（行在，行驱动 GC 才能回收目录）。
        match self
            .state
            .delete_layers_for_product_except(&config.product, &kept_for_gc)
            .await
        {
            Ok((layers, pkgs)) => {
                if kept_for_gc.is_empty() {
                    info!(product = %config.product, layers, pkgs, "Deleted layer records from DB");
                } else {
                    info!(
                        product = %config.product,
                        layers,
                        pkgs,
                        kept = kept_for_gc.len(),
                        "Deleted layer records from DB (kept rows of layers left for GC)"
                    );
                }
            }
            Err(e) => {
                warn!(product = %config.product, error = %e, "Failed to delete layer records");
            }
        }

        let mut to_umount = mounts_under(&product_root).await?;
        // 去重并逆序 umount（子目录先卸载）
        to_umount.sort();
        to_umount.dedup();
        to_umount.reverse();

        if !to_umount.is_empty() {
            info!(
                mounts = ?to_umount.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "Unmounting"
            );
            lazy_umount_all(to_umount, "clean").await;
        }

        // MNT_DETACH 是异步的：sleep 后复检。rm -rf 会穿过仍在的挂载点删掉挂载源的
        // 内容（跨构建数据丢失），卸不净时重试一次，仍失败则中止而非继续删除。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut remaining = mounts_under(&product_root).await?;
        if !remaining.is_empty() {
            warn!(
                mounts = ?remaining.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                "mounts still present after MNT_DETACH, retrying umount"
            );
            remaining.sort();
            remaining.reverse();
            lazy_umount_all(remaining, "clean retry").await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let still = mounts_under(&product_root).await?;
            if !still.is_empty() {
                return Err(CrbsError::io_message(format!(
                    "Cannot clean '{}': {} mountpoint(s) under product root failed to unmount \
                     (refusing rm -rf through live mounts): {}",
                    config.product,
                    still.len(),
                    still
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }

        // rm -rf product_root 内容但保留两个 flock 锁文件：锁 inode 被 unlink 后，等锁
        // 进程（旧 inode）与 rm 期间新开锁进程（新 inode）分裂在两条锁上失去互斥——新
        // init/shell 可并发写入正被删除的树；保留锁文件 → 目录留存（空 + 锁），语义 =
        // 内容清空。root-owned 文件（dnf installroot 写入）必须走 helper 以 root 递归删除。
        let first = rm_children_excluding_locks(&product_root).await;
        if let Err(e) = first {
            // EBUSY 靠文本匹配：from_io_context 不保留 os error，误匹配仅多一次重试无正确性影响。
            let msg = format!("{e:?}");
            if msg.contains("busy") || msg.contains("Busy") {
                warn!(product = %config.product, "rm_rf EBUSY, waiting for mounts to detach");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                rm_children_excluding_locks(&product_root)
                    .await
                    .map_err(|e| CrbsError::io_message(format!("remove after retry: {e}")))?;
            } else {
                return Err(CrbsError::io_message(format!("remove: {e}")));
            }
        }

        info!(product = %config.product, "Clean completed");

        // flock 随 lock_file Drop 自动释放
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    /// 回归守卫：命名空间外 skip 臂必须把 digest 记入 kept_for_gc（同其余 skip 臂），
    /// 否则删行后行驱动 GC 看不到仍在盘的层目录（数 GB 泄漏）。/proc/mounts 扫描在
    /// 层回收之后（macOS 无 /proc/mounts 报错收场），故只断言层回收与删行。
    #[tokio::test]
    async fn clean_keeps_row_for_out_of_namespace_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = crate::engine::minimal_engine(tmp.path()).await;

        // 逃逸层：DB path ≠ shared_layers_dir/{digest} → 必命中 namespace-escape 臂（先于其锁/refcount 检查）。
        engine
            .state_store()
            .insert_layer(
                "escaped-digest",
                "/somewhere/else/escaped-digest",
                "prod_a",
                0,
            )
            .await
            .unwrap();

        tokio::fs::create_dir_all(engine.config().product_root())
            .await
            .unwrap();

        let _ = engine.clean(false).await;

        let row = engine
            .state_store()
            .get_layer_path("escaped-digest")
            .await
            .unwrap();
        assert!(row.is_some(), "namespace-escape 的层行必须保留交行驱动 GC");
    }

    /// 回归守卫：`assert_delete_under_root` 拒删臂与其余 skip 臂同口径记入 kept_for_gc；
    /// 否则 digest 含 `..` 时（前置精确路径相等检查反而放行、锁与 refcount 全过、词法
    /// 断言拒删）行删目录在，行驱动 GC 从此看不到（数 GB 泄漏）。
    #[tokio::test]
    async fn clean_keeps_row_for_namespace_assert_rejected_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = crate::engine::minimal_engine(tmp.path()).await;

        // 对抗 digest ".."：DB path 与 shared_layers_dir.join(digest) 逐字相等（逃逸臂
        // 放行），assert_delete_under_root 按 ParentDir 拒删，命中本测试守的臂；
        // shared_layers 目录须真实存在，否则 .lock open 先 ENOENT 走更早的锁失败臂。
        tokio::fs::create_dir_all(engine.config().shared_layers_dir.to_owned())
            .await
            .unwrap();
        let expected = engine.config().shared_layers_dir.join("..");
        engine
            .state_store()
            .insert_layer("..", &expected.display().to_string(), "prod_a", 0)
            .await
            .unwrap();

        tokio::fs::create_dir_all(engine.config().product_root())
            .await
            .unwrap();

        let _ = engine.clean(false).await;

        let row = engine.state_store().get_layer_path("..").await.unwrap();
        assert!(
            row.is_some(),
            "namespace assert 拒删的层行必须保留交行驱动 GC"
        );
    }
}
