// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 结果域 GC：结果目录、产物行与磁盘删除的回收流程。

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::config::{Config, CrbsConfig};

/// Result GC 执行结果。
pub struct ResultGcOutcome {
    /// 实际删除的结果目录数（dry-run 为 0）。
    pub removed: usize,
    /// dry-run 模式下将被删除的目录数。
    pub would_remove: usize,
    /// 释放（或 dry-run 估算）的字节数。
    pub bytes: u64,
    /// 其中命中保留策略（数量上限 / 保留期）的目录数。
    pub policy_removed: usize,
    /// 观测计数：latest 软链接保护跳过的候选数（latest 指向的候选永不被删，与 worker 先删后回收链有意不对称）。
    pub skipped_latest: usize,
    /// 观测计数：目录已缺失、走自愈清行分支的候选数。
    pub skipped_missing: usize,
    /// 观测计数：目录 IO 异常 / 越界等安全检查拒绝的候选数。
    pub skipped_invalid: usize,
    /// 观测计数：rm / 翻 on_disk / 清 result_dir 落库失败的候选数（failed>0 = 有候选留待下一轮重试）。
    pub failed: usize,
    /// 实删**且已翻 on_disk=0（regen 可收敛）**的产品集合：mark 失败的候选不入（见步骤 8），dry-run 为空。
    pub affected_products: Vec<String>,
}

/// 运行 Result GC（独立入口，无需 BuildEngine 实例），合并 grace-hours 与
/// policy 候选（数量上限 / 保留期）；`artifact_dir` 覆盖 hub 侧日志副本根
/// （server.toml），None = CLI 世界随 `crbs.crbs_root` 派生 `{crbs_root}/artifacts`。
/// 前提（候选按行选）：builds 行不以 result_dir 非 NULL 被删；未来删 build
/// 行的 API 须补 {result_root}/{product}/{pkg}/{leaf} 的 disk→DB 对账 sweep
/// （"行不存在 + 24h mtime 宽限"口径），否则孤儿泄漏。
pub async fn run_result_gc_standalone(
    product: Option<&str>,
    dry_run: bool,
    crbs: &CrbsConfig,
    artifact_dir: Option<&Path>,
    state: &crate::state::StateStore,
) -> crate::Result<ResultGcOutcome> {
    let products = if let Some(p) = product {
        vec![p.to_string()]
    } else {
        state.list_products_with_results().await?
    };

    let mut all_candidates = Vec::new();
    let mut policy_ids = std::collections::HashSet::new();
    for p in &products {
        // 产品配置 DB chain-resolve，全局层用传入的世界配置——GC 自行重读
        // /etc/crbs/crbs.toml 会架空 server pin 的 root；miss/解析失败回退全局默认。
        let (grace_hours, max_count, retention_days) = match state
            .load_merged_config_for_product_with_root(p, crbs)
            .await
        {
            Ok(cfg) => (
                cfg.result_gc_grace_hours,
                cfg.result_max_count_per_pkg,
                cfg.result_retention_days,
            ),
            Err(e) => {
                tracing::warn!(product = %p, error = %e, "Failed to load config, using global default");
                (
                    crbs.result_gc_grace_hours,
                    crbs.result_max_count_per_pkg,
                    crbs.result_retention_days,
                )
            }
        };

        let mut candidates = state.list_results_for_gc(Some(p), grace_hours).await?;
        all_candidates.append(&mut candidates);

        if let Some(max_count) = max_count {
            let mut extra = state
                .list_results_exceeding_count_per_pkg(Some(p), max_count)
                .await?;
            for c in &extra {
                policy_ids.insert(c.id);
            }
            all_candidates.append(&mut extra);
        }

        if let Some(days) = retention_days {
            let mut extra = state.list_results_older_than_days(Some(p), days).await?;
            for c in &extra {
                policy_ids.insert(c.id);
            }
            all_candidates.append(&mut extra);
        }
    }

    // 按 id 去重（grace 与 policy 可能重叠，保留先加入者）
    let mut seen = std::collections::HashSet::new();
    all_candidates.retain(|c| seen.insert(c.id));

    let mut config_cache: HashMap<String, Config> = HashMap::new();
    let mut removed = 0usize;
    let mut would_remove = 0usize;
    let mut removed_bytes = 0u64;
    let mut policy_removed = 0usize;
    let mut affected_products: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    let mut skipped_latest = 0usize;
    let mut skipped_missing = 0usize;
    let mut skipped_invalid = 0usize;
    let mut failed = 0usize;

    for candidate in &all_candidates {
        let result_dir = &candidate.result_dir;

        // 1. 存在性检查：单目录 IO 异常只跳过该候选，不中止整轮 GC。
        let result_dir_exists = match tokio::fs::try_exists(result_dir).await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    id = %candidate.id,
                    path = %result_dir.display(),
                    error = %e,
                    "Failed to check result dir existence, skipping"
                );
                skipped_invalid += 1;
                continue;
            }
        };
        if !result_dir_exists {
            if !dry_run {
                // 自愈与正常路径同序：先翻 on_disk=0（幂等）再清 result_dir
                //（候选查询以 result_dir IS NOT NULL 为门）：先清后翻且翻失败
                // 则幽灵行永无自愈入口、遮蔽在盘老副本；mark 失败必须闸住 clear。
                if let Err(e) = state.mark_artifacts_off_disk(candidate.id).await {
                    warn!(
                        build_id = %candidate.id,
                        error = %e,
                        "Failed to mark artifacts off_disk for missing result dir; kept retryable"
                    );
                    failed += 1;
                    continue;
                }
                if let Err(e) = state.clear_build_result_dir(candidate.id).await {
                    warn!(build_id = %candidate.id, error = %e, "Failed to clear build result dir record for missing directory");
                    // clear 失败 = 行保留 result_dir 下一轮再命中自愈，计入 failed。
                    failed += 1;
                }
                // 行已清 result_dir：日志副本联动清理（见 remove_gc_artifact_dir）。
                remove_gc_artifact_dir(crbs, artifact_dir, candidate.id).await;
                // 与实删同口径把产品记入 affected_products，靠 regen 对账摘除
                // Packages/ 死引用（dry-run 不动磁盘不入集合）。
                affected_products.insert(candidate.product.clone());
            }
            skipped_missing += 1;
            continue;
        }

        // 2. O_NOFOLLOW | O_DIRECTORY 打开取 fd，后续操作基于 fd 路径，防检查后 symlink 替换的 TOCTOU race。
        let dir_file = match open_dir_nofollow(result_dir).await {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    id = %candidate.id,
                    path = %result_dir.display(),
                    error = %e,
                    "Result dir is a symlink or not a directory, skipping"
                );
                skipped_invalid += 1;
                continue;
            }
        };

        // 3. 按产品加载 Config 并 canonicalize result_root；config_cache 仅
        //    本次 GC 调用内去重，防每候选重复 name→id + resolve。
        let product = candidate.product.clone();
        let product_config = match config_cache.entry(product.clone()) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => match state
                .load_merged_config_for_product_with_root(&product, crbs)
                .await
            {
                Ok(cfg) => e.insert(cfg),
                // 解析失败（典型：已删产品，products 行已删而 builds 行保留
                // product）不得 skipped_invalid（目录与行永不回收、package
                // cache 引用集永久 pin）：回退全局安全根并进 cache，每产品只
                // WARN 一次；残留：曾有根外 override 的已删产品永久跳过。
                Err(err) => {
                    warn!(
                        product = %candidate.product,
                        error = %err,
                        "Failed to load config for product, falling back to global result root"
                    );
                    e.insert(Config {
                        product,
                        result_dir: crbs.result_dir_or_derived(),
                        ..Default::default()
                    })
                }
            },
        };
        let result_root = match tokio::fs::canonicalize(&product_config.result_dir).await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    product = %candidate.product,
                    path = %product_config.result_dir.display(),
                    error = %e,
                    "Failed to canonicalize result_dir, skipping"
                );
                skipped_invalid += 1;
                continue;
            }
        };

        // 4. 安全边界：candidate 必须位于 result_root 内部，且不能是 result_root 本身。
        if candidate.product.contains('/')
            || candidate.product.contains("..")
            || candidate.pkg_name.contains('/')
            || candidate.pkg_name.contains("..")
        {
            warn!(
                id = %candidate.id,
                product = %candidate.product,
                pkg_name = %candidate.pkg_name,
                "Product or pkg_name contains path separator, skipping"
            );
            skipped_invalid += 1;
            continue;
        }

        // 通过 fd 路径 canonicalize，确保与打开时指向同一目录，且不被 symlink 替换。
        let fd_path = fd_path(&dir_file);
        let candidate_canon = match tokio::fs::canonicalize(&fd_path).await {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    id = %candidate.id,
                    path = %result_dir.display(),
                    error = %e,
                    "Failed to canonicalize candidate result_dir via fd, skipping"
                );
                skipped_invalid += 1;
                continue;
            }
        };
        if !candidate_canon.starts_with(&result_root)
            || candidate_canon == result_root
            || candidate_canon.parent().is_none()
        {
            warn!(
                id = %candidate.id,
                path = %candidate_canon.display(),
                result_root = %result_root.display(),
                "Result dir outside result root, skipping"
            );
            skipped_invalid += 1;
            continue;
        }

        // 4.5 安全边界：产物目录必须是 result_root 的至少二级子目录——防异常
        //    DB 记录误删根下一级目录（builds、shared_layers 等）。
        if candidate_canon
            .parent()
            .map(|p| p == result_root)
            .unwrap_or(false)
        {
            warn!(
                id = %candidate.id,
                path = %candidate_canon.display(),
                result_root = %result_root.display(),
                "Result dir is a direct child of result root, skipping"
            );
            skipped_invalid += 1;
            continue;
        }

        // 5. latest 软链接保护（基于父目录，兼容 {product}/{pkg} 与扁平 {task_id}）；
        //    latest_link 提升到外层供步骤 7 删除前紧贴复检。不变量：latest 指向
        //    的候选永不被删，防 advisory 链悬空；代价 = 每 {product}/{pkg} 至多
        //    滞留一个目录（挂 pkg_root 级、同包多 arch 共享），下次构建覆盖
        //    latest 后恢复可删。与 worker sweep 的先删后回收链有意不对称，勿对齐。
        let latest_link = candidate_canon.parent().map(|p| p.join("latest"));
        if let Some(latest_link) = &latest_link {
            let latest_exists = match tokio::fs::try_exists(latest_link).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        id = %candidate.id,
                        path = %latest_link.display(),
                        error = %e,
                        "Failed to check latest link existence, skipping"
                    );
                    skipped_invalid += 1;
                    continue;
                }
            };
            if latest_exists && is_latest_target(result_dir, latest_link).await {
                skipped_latest += 1;
                continue;
            }
        }

        // 6. 计算大小（dry-run 与实删都需要）。
        let size = crate::gc::calc_dir_size(&fd_path).await;

        if dry_run {
            info!(
                id = %candidate.id,
                path = %result_dir.display(),
                size_bytes = size,
                "Would remove result dir"
            );
            would_remove += 1;
            removed_bytes += size;
            if policy_ids.contains(&candidate.id) {
                policy_removed += 1;
            }
            continue;
        }

        // 7. 经 fd canonicalize 出的真实路径删除（非重新 walk 原路径），删前
        //    复核 fd 指向未变；不能用 fd_path 本体删除：/proc/self/fd/{fd} 是
        //    procfs 魔法 symlink，顶层 rmdir 必然 EPERM（macOS 走 F_GETPATH 不受影响）。
        let pre_remove_check = tokio::fs::canonicalize(&fd_path).await.ok();
        if pre_remove_check.as_ref() != Some(&candidate_canon) {
            warn!(
                id = %candidate.id,
                path = %result_dir.display(),
                "Result dir changed between validation and removal, skipping"
            );
            skipped_invalid += 1;
            continue;
        }
        // 紧贴删除前复检 latest：步骤 5 与此处隔着 calc_dir_size（大目录分钟
        // 级，pre_remove_check 不覆盖 latest），并发构建可在窗口内把 latest
        // rename 指向本候选，直接删会悬空新 advisory 链（advisory 且自愈）。
        if let Some(latest_link) = &latest_link {
            // 缺链时 read_link 失败 → is_latest_target 返回 false → 正常删除。
            if is_latest_target(result_dir, latest_link).await {
                skipped_latest += 1;
                info!(
                    id = %candidate.id,
                    path = %result_dir.display(),
                    "latest link started pointing at candidate during GC, skipping"
                );
                continue;
            }
        }
        if let Err(e) = crate::privilege::rm_rf_async(&[candidate_canon.as_path()]).await {
            warn!(
                id = %candidate.id,
                path = %result_dir.display(),
                error = %e,
                "Failed to remove result dir"
            );
            failed += 1;
            continue;
        }

        // 8. 翻 on_disk=0（行保留供历史溯源；幂等），必须先于清 result_dir：
        //    候选查询以 result_dir IS NOT NULL 为门，先清后翻且翻失败（或
        //    mark 失败而 clear 成功）→ on_disk=1 幽灵行永不再入选且遮蔽在盘
        //    老副本，repo_publish 对账把包从 Packages/ 静默摘除；mark 失败即
        //    闸住本候选（下一轮走缺失分支自愈重试）。
        //    mark 失败也不入 affected_products：regen 以 DB 候选集（on_disk=1）
        //    为准，ghost 行摘不掉 Packages/ 硬链接也重链不上（源缺失
        //    SkippedMissing），insert 只会空跑 createrepo；收敛前置 = mark
        //    成功，下一轮自愈后才收录（滞后一轮，非丢弃）。
        if let Err(e) = state.mark_artifacts_off_disk(candidate.id).await {
            warn!(
                id = %candidate.id,
                error = %e,
                "Failed to mark artifacts off_disk in DB; kept retryable (result_dir preserved for next GC round)"
            );
            failed += 1;
            continue;
        }

        // 9. 清 result_dir。失败不回滚磁盘删除与 on_disk 翻转（removed 照计），
        //    但计入 failed：行保留 result_dir 下一轮走缺失分支自愈（二者不互斥）。
        if let Err(e) = state.clear_build_result_dir(candidate.id).await {
            warn!(
                id = %candidate.id,
                error = %e,
                "Failed to clear build result_dir in DB"
            );
            failed += 1;
        }

        // 9.5 联动清理 hub 日志副本 `{artifact_dir}/{build_id}/`（结果目录已 GC，副本无读取方）。
        remove_gc_artifact_dir(crbs, artifact_dir, candidate.id).await;

        removed += 1;
        removed_bytes += size;
        affected_products.insert(candidate.product.clone());
        if policy_ids.contains(&candidate.id) {
            policy_removed += 1;
        }
    }

    let matched = all_candidates.len();
    info!(
        matched,
        skipped_latest,
        skipped_missing,
        skipped_invalid,
        failed,
        removed,
        would_remove,
        policy_removed,
        removed_bytes,
        dry_run,
        "Result GC completed"
    );

    Ok(ResultGcOutcome {
        removed,
        would_remove,
        bytes: removed_bytes,
        policy_removed,
        skipped_latest,
        skipped_missing,
        skipped_invalid,
        failed,
        affected_products: affected_products.into_iter().collect(),
    })
}

/// 结果 GC 联动清理：删除 hub 侧 Worker 日志副本 `{artifact_dir}/{build_id}/`
///（report_logs 落盘的 build.log 是终态失败日志的唯一持久化；结果目录 GC 后
/// 副本无读取方，随删防 artifacts/ 无界增长）。隔离不变量：目标必须是
/// artifacts 根下纯数字 build_id 的一级子目录（`assert_delete_under_root` +
/// i64 拼接保证），绝不删根或共享名派生的兄弟目录。
async fn remove_gc_artifact_dir(crbs: &CrbsConfig, artifact_dir: Option<&Path>, build_id: i64) {
    let artifacts_root = match artifact_dir {
        Some(root) => root.to_path_buf(),
        None => crbs.crbs_root.join("artifacts"),
    };
    let target = artifacts_root.join(build_id.to_string());
    if let Err(e) = crate::gc::assert_delete_under_root(&artifacts_root, &target) {
        warn!(build_id = %build_id, error = %e, "Refusing to remove artifact dir for GC'd build");
        return;
    }
    match tokio::fs::remove_dir_all(&target).await {
        Ok(()) => {
            info!(build_id = %build_id, path = %target.display(), "Removed artifact log dir of GC'd build")
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            build_id = %build_id,
            path = %target.display(),
            error = %e,
            "Failed to remove artifact log dir of GC'd build"
        ),
    }
}

/// 判断 candidate 是否是 latest 软链接当前指向的目录（canonical 比较）。
async fn is_latest_target(candidate: &Path, latest_link: &Path) -> bool {
    let candidate_canon = match tokio::fs::canonicalize(candidate).await {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target = match tokio::fs::read_link(latest_link).await {
        Ok(t) => t,
        Err(_) => return false,
    };
    let resolved = if target.is_absolute() {
        target
    } else {
        latest_link.parent().unwrap_or(Path::new("/")).join(target)
    };
    let target_canon = match tokio::fs::canonicalize(&resolved).await {
        Ok(p) => p,
        Err(_) => return false,
    };
    candidate_canon == target_canon
}

/// 用 `O_NOFOLLOW | O_DIRECTORY` 打开目录返回 `File`：fd 保证指向真实目录
/// 而非 symlink，经 [`fd_path`] 转路径操作防 TOCTOU race。
#[cfg(unix)]
async fn open_dir_nofollow(path: &Path) -> std::io::Result<tokio::fs::File> {
    use nix::libc;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::FromRawFd;

    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC;
    // open(2) 要求 NUL 结尾（as_bytes() 不带）；c_path 随闭包 move 保活。
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains interior NUL byte",
        )
    })?;
    let fd = tokio::task::spawn_blocking(move || unsafe { libc::open(c_path.as_ptr(), flags, 0) })
        .await
        .map_err(std::io::Error::other)?;

    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Safety: fd 是刚打开的合法文件描述符。
    let std_file = unsafe { std::fs::File::from_raw_fd(fd) };
    Ok(tokio::fs::File::from_std(std_file))
}

#[cfg(not(unix))]
async fn open_dir_nofollow(path: &Path) -> std::io::Result<tokio::fs::File> {
    // 非 Unix 无 O_NOFOLLOW，回退普通打开（仅开发环境）。
    tokio::fs::File::open(path).await
}

/// 返回指向已打开 fd 的路径字符串。
/// Linux 用 `/proc/self/fd/{fd}`（不跟随 symlink）；macOS 等无 /proc 的 Unix
/// 用 `fcntl(F_GETPATH)` 取已解析绝对路径（随后仍统一 canonicalize 比较）；
/// 都拿不到回退 `"."`：通不过 result_root 安全边界检查，候选被跳过。
fn fd_path(file: &tokio::fs::File) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::os::unix::io::AsRawFd;
        // F_GETPATH 要求 MAXPATHLEN（PATH_MAX）字节缓冲，写入 NUL 结尾的路径。
        let mut buf = [0u8; nix::libc::PATH_MAX as usize];
        // Safety: buf 是足够大的可写缓冲；fcntl 只向其写入路径字符串。
        let ret = unsafe {
            nix::libc::fcntl(
                file.as_raw_fd(),
                nix::libc::F_GETPATH,
                buf.as_mut_ptr() as *mut nix::libc::c_char,
            )
        };
        if ret >= 0 {
            if let Some(len) = buf.iter().position(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(&buf[..len]) {
                    return PathBuf::from(s);
                }
            }
        }
        PathBuf::from(".")
    }
    #[cfg(not(unix))]
    {
        // 非 Unix 无 /proc 与 F_GETPATH，回退 "."（仅开发环境）。
        let _ = file;
        PathBuf::from(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // ─── calc_dir_size ───

    #[tokio::test]
    async fn calc_dir_size_empty_dir_returns_zero() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(crate::gc::calc_dir_size(tmp.path()).await, 0);
    }

    #[tokio::test]
    async fn calc_dir_size_single_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("file.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"hello world").unwrap();
        assert_eq!(crate::gc::calc_dir_size(tmp.path()).await, 11);
    }

    #[tokio::test]
    async fn calc_dir_size_nested_dirs_sum_correctly() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let mut file = std::fs::File::create(sub.join("file.txt")).unwrap();
        file.write_all(b"hello").unwrap();
        assert_eq!(crate::gc::calc_dir_size(tmp.path()).await, 5);
    }

    #[tokio::test]
    async fn calc_dir_size_ignores_symlinks() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("file.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"hello").unwrap();
        let link_path = tmp.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&file_path, &link_path).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_file(&file_path, &link_path).unwrap();
        assert_eq!(crate::gc::calc_dir_size(tmp.path()).await, 5);
    }

    // ─── is_latest_target ───

    #[tokio::test]
    async fn is_latest_target_matches_when_is_target() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let latest = tmp.path().join("latest");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &latest).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(&target, &latest).unwrap();
        assert!(is_latest_target(&target, &latest).await);
    }

    #[tokio::test]
    async fn is_latest_target_mismatches_when_not_target() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        let other = tmp.path().join("other");
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(&other).unwrap();
        let latest = tmp.path().join("latest");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&other, &latest).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(&other, &latest).unwrap();
        assert!(!is_latest_target(&target, &latest).await);
    }

    #[tokio::test]
    async fn is_latest_target_returns_false_when_link_missing() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let latest = tmp.path().join("latest");
        assert!(!is_latest_target(&target, &latest).await);
    }

    // ─── fd_path ───

    #[tokio::test]
    async fn fd_path_resolves_opened_dir() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        let file = tokio::fs::File::open(&dir).await.unwrap();
        let path = fd_path(&file);
        // 三个分支都须指向打开的目录（或 proc-fd 别名）；回退 "."（CWD）
        // 会让安全边界检查误跳过所有候选。
        #[cfg(target_os = "linux")]
        assert!(path
            .as_os_str()
            .to_string_lossy()
            .starts_with("/proc/self/fd/"));
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let resolved = tokio::fs::canonicalize(&path).await.unwrap();
            let expected = tokio::fs::canonicalize(&dir).await.unwrap();
            assert_eq!(resolved, expected);
        }
        #[cfg(not(unix))]
        assert_eq!(path, PathBuf::from("."));
    }

    // ─── open_dir_nofollow ───

    #[tokio::test]
    async fn open_dir_nofollow_opens_real_directory() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        let result = open_dir_nofollow(&dir).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn open_dir_nofollow_rejects_symlink() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("dir");
        let link = tmp.path().join("link");
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        #[cfg(not(unix))]
        {
            // 非 Unix 平台回退不保证拒绝 symlink，跳过此断言。
            return;
        }
        let result = open_dir_nofollow(&link).await;
        assert!(result.is_err());
    }

    // ─── run_result_gc_standalone：缺失目录候选的自愈 ───

    use crate::state::test_state::{create_test_store, seed_task};
    use crate::state::BuildInsert;

    /// 通用 seed：succeeded 构建 + 指定 result_dir，completed_at 置于过去（grace=0 即成候选）。
    async fn seed_gc_candidate(
        store: &crate::state::StateStore,
        product: &str,
        result_dir: &Path,
    ) -> i64 {
        let task_id = seed_task(store, product, "hello").await;
        let dir_str = result_dir.to_string_lossy().to_string();
        let build_id = store
            .insert_build(BuildInsert {
                product,
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(dir_str.as_str()),
                backend: "chroot",
                user: "test",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        sqlx::query("UPDATE builds SET completed_at = $1 WHERE id = $2")
            .bind("2026-01-01 00:00:00")
            .bind(build_id)
            .execute(store.pool())
            .await
            .unwrap();
        build_id
    }

    /// 回归：缺失目录候选必须先翻 on_disk=0 再清 result_dir——先清则候选
    /// 查询不再命中，on_disk=1 幽灵行永无自愈入口，repo_publish 的
    /// `MAX(build_id)` 分组让幽灵行遮蔽在盘老副本、摘除 Packages/ 包。
    #[tokio::test]
    async fn missing_result_dir_candidate_marks_artifacts_off_disk() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        let missing_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1")
            .to_string_lossy()
            .to_string();
        let build_id = seed_gc_candidate(&store, "fedora", Path::new(&missing_dir)).await;

        sqlx::query(
            "INSERT INTO build_artifacts \
             (build_id, relative_path, kind, size_bytes, sha256, on_disk, created_at) \
             VALUES ($1, 'hello-1.0-1.x86_64/hello-1.0-1.x86_64.rpm', 'rpm', 123, \
                     '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 1, \
                     '2026-01-01 00:00:00')",
        )
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

        // 产品不在 DB：配置加载走全局默认回退（grace=0 → 立即成候选）。
        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(outcome.removed, 0, "缺失目录不产生实删");

        let rec = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(rec.result_dir, None, "缺失目录候选的 result_dir 必须被清空");

        // 核心回归断言：on_disk 必须被翻 0。
        let on_disk: i64 =
            sqlx::query_scalar("SELECT on_disk FROM build_artifacts WHERE build_id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(
            on_disk, 0,
            "缺失目录候选的产物行必须翻 on_disk=0，否则成为遮蔽在盘副本的幽灵行"
        );
    }

    /// 缺失目录自愈须记入 affected_products（routes/gc 据此驱动 regen 摘 Packages/ 死引用）；dry-run 不入。
    #[tokio::test]
    async fn missing_result_dir_self_heal_feeds_affected_products() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        let missing_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        seed_gc_candidate(&store, "fedora", &missing_dir).await;

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };

        let dry = run_result_gc_standalone(Some("fedora"), true, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(dry.skipped_missing, 1);
        assert!(
            dry.affected_products.is_empty(),
            "dry-run 无磁盘变更，不得触发 regen"
        );

        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(outcome.skipped_missing, 1);
        assert_eq!(
            outcome.affected_products,
            vec!["fedora".to_string()],
            "自愈清了行与引用，必须像实删一样触发 repo regen"
        );
    }

    /// latest 软链接保护命中的候选计入 outcome.skipped_latest（不实删）。
    #[tokio::test]
    async fn latest_target_candidate_counts_skipped_latest() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        let pkg_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("build.log"), b"payload")
            .await
            .unwrap();
        let latest = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("latest");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&pkg_dir, &latest).unwrap();
        #[cfg(not(unix))]
        std::os::windows::fs::symlink_dir(&pkg_dir, &latest).unwrap();

        seed_gc_candidate(&store, "fedora", &pkg_dir).await;

        // 产品不在 DB：候选段与删除段都走全局回退，根 = {crbs_root}/results。
        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(
            outcome.skipped_latest, 1,
            "latest 目标候选计 skipped_latest"
        );
        assert_eq!(outcome.removed, 0);
        assert!(
            tokio::fs::try_exists(&pkg_dir).await.unwrap(),
            "latest 目标目录必须保留"
        );
    }

    /// 越界 result_dir 候选计入 outcome.skipped_invalid（不实删）。
    #[tokio::test]
    async fn out_of_root_result_dir_counts_skipped_invalid() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        // 全局根存在（canonicalize 成功、能走到安全边界检查）；候选在根外。
        tokio::fs::create_dir_all(tmp.path().join("results"))
            .await
            .unwrap();
        let outside = tmp
            .path()
            .join("elsewhere")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&outside).await.unwrap();

        seed_gc_candidate(&store, "fedora", &outside).await;

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert!(
            outcome.skipped_invalid >= 1,
            "越界候选计 skipped_invalid（removed={}，invalid={}）",
            outcome.removed,
            outcome.skipped_invalid
        );
        assert_eq!(outcome.removed, 0);
        assert!(
            tokio::fs::try_exists(&outside).await.unwrap(),
            "越界目录必须保留（安全边界拒绝删除）"
        );
    }

    /// `failed` 观测计数透出：空库为 0；`GcResultsSummary` 序列化含 "failed"
    /// key。透传函数为私有路径，按字段集手搬构造锁定 serde 契约。
    #[tokio::test]
    async fn result_gc_outcome_exposes_failed_field() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();
        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(outcome.failed, 0, "empty library must report zero failures");

        let summary = crate::types::GcResultsSummary {
            removed: outcome.removed,
            would_remove: outcome.would_remove,
            bytes: outcome.bytes,
            policy_removed: outcome.policy_removed,
            skipped_latest: outcome.skipped_latest,
            skipped_missing: outcome.skipped_missing,
            skipped_invalid: outcome.skipped_invalid,
            failed: outcome.failed,
            affected_products: outcome.affected_products,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert!(
            json.get("failed").is_some(),
            "GcResultsSummary JSON must carry the failed key: {json}"
        );
    }

    /// 实删路径 clear 落库失败计入 `outcome.failed`，不回滚磁盘删除与
    /// on_disk 翻转（removed 照计，二者不互斥）；行保留 result_dir 下一轮
    /// 自愈。注入：SQLite `BEFORE UPDATE OF result_dir` 触发器精确只打
    /// clear（mark 动 `build_artifacts`、候选查询是 SELECT，不受影响）；
    /// SQLite 专属语法，`StateStore::new` 直构库不经 PG 分支。
    #[tokio::test]
    async fn clear_failure_counts_failed_without_undoing_removal() {
        let db_root = TempDir::new().unwrap();
        let store = crate::state::StateStore::new(db_root.path()).await.unwrap();
        let tmp = TempDir::new().unwrap();

        let pkg_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("build.log"), b"payload")
            .await
            .unwrap();
        let build_id = seed_gc_candidate(&store, "fedora", &pkg_dir).await;

        sqlx::query(
            "CREATE TRIGGER fail_gc_clear BEFORE UPDATE OF result_dir ON builds \
             BEGIN SELECT RAISE(ABORT, 'injected clear failure'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();

        assert_eq!(outcome.removed, 1, "clear 失败不得回滚已完成的磁盘删除");
        assert_eq!(outcome.failed, 1, "clear 失败必须计入 failed 观测计数");
        assert_eq!(outcome.skipped_missing, 0);
        assert_eq!(outcome.skipped_invalid, 0);
        assert!(
            !tokio::fs::try_exists(&pkg_dir).await.unwrap(),
            "目录已被实删，clear 失败只影响落库不影响磁盘"
        );
        let rec = store
            .get_build(build_id)
            .await
            .unwrap()
            .expect("build row must exist");
        assert!(
            rec.result_dir.is_some(),
            "clear 失败的行必须保留 result_dir 留待下一轮自愈"
        );
        assert_eq!(
            outcome.affected_products,
            vec!["fedora".to_string()],
            "实删已发生，regen 集合照常收录"
        );
    }

    /// 两轮语义钉子：mark 失败 → 目录已删但 affected_products **有意**不
    /// 入（naive"照样 insert"在此红：regen 以 DB 候选集（on_disk=1）为准，
    /// ghost 行摘不掉 Packages/ 硬链接也重链不上，insert 只会空跑
    /// createrepo）；收敛前置 = mark 成功，滞后一轮（见实删路径步骤 8）。
    /// 注入同 clear_failure 测试：`BEFORE UPDATE OF on_disk` 触发器只打
    /// mark；SQLite 专属语法，直构库不经 PG 分支。
    #[tokio::test]
    async fn mark_failure_excludes_affected_products_until_next_round() {
        let db_root = TempDir::new().unwrap();
        let store = crate::state::StateStore::new(db_root.path()).await.unwrap();
        let tmp = TempDir::new().unwrap();

        let pkg_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("build.log"), b"payload")
            .await
            .unwrap();
        let build_id = seed_gc_candidate(&store, "fedora", &pkg_dir).await;
        sqlx::query(
            "INSERT INTO build_artifacts \
             (build_id, relative_path, kind, size_bytes, sha256, on_disk, created_at) \
             VALUES ($1, 'hello-1.0-1.x86_64/hello-1.0-1.x86_64.rpm', 'rpm', 123, \
                     '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 1, \
                     '2026-01-01 00:00:00')",
        )
        .bind(build_id)
        .execute(store.pool())
        .await
        .unwrap();

        sqlx::query(
            "CREATE TRIGGER fail_gc_mark BEFORE UPDATE OF on_disk ON build_artifacts \
             BEGIN SELECT RAISE(ABORT, 'injected mark failure'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };

        // （trigger 在）：磁盘删除先于 mark 完成，mark 被 ABORT。
        let r1 = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(r1.failed, 1, "mark 失败必须计入 failed");
        assert_eq!(r1.removed, 0, "mark 闸住本候选，removed 不计");
        assert!(
            r1.affected_products.is_empty(),
            "核心断言：mark 失败不入 affected_products——ghost 行本轮 regen 不可收敛，insert 是空跑"
        );
        assert!(
            !tokio::fs::try_exists(&pkg_dir).await.unwrap(),
            "磁盘删除先于 mark，目录已删"
        );
        let rec = store.get_build(build_id).await.unwrap().unwrap();
        assert!(
            rec.result_dir.is_some(),
            "行保留 result_dir 待下一轮自愈重试"
        );
        let on_disk: i64 =
            sqlx::query_scalar("SELECT on_disk FROM build_artifacts WHERE build_id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(on_disk, 1, "mark 被 ABORT，on_disk 仍为 1");

        // （DROP TRIGGER 后）：行再入选、目录已缺失 → 自愈分支重试成功才入集合。
        sqlx::query("DROP TRIGGER fail_gc_mark")
            .execute(store.pool())
            .await
            .unwrap();
        let r2 = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(r2.skipped_missing, 1, "缺失目录走自愈分支");
        assert_eq!(r2.failed, 0);
        assert_eq!(
            r2.affected_products,
            vec!["fedora".to_string()],
            "mark 重试成功后产品入集合（滞后一轮收敛）"
        );
        let rec = store.get_build(build_id).await.unwrap().unwrap();
        assert_eq!(rec.result_dir, None, "自愈完成后 result_dir 清空");
        let on_disk: i64 =
            sqlx::query_scalar("SELECT on_disk FROM build_artifacts WHERE build_id = $1")
                .bind(build_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(on_disk, 0, "mark 重试成功翻 on_disk=0");
    }

    /// artifact_dir=None（CLI 世界）回退 {crbs_root}/artifacts，联动删除 hub 日志副本不回归。
    #[tokio::test]
    async fn artifact_dir_none_falls_back_to_crbs_root_artifacts() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();

        let missing_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        let build_id = seed_gc_candidate(&store, "fedora", &missing_dir).await;

        let hub_copy = tmp.path().join("artifacts").join(build_id.to_string());
        tokio::fs::create_dir_all(&hub_copy).await.unwrap();
        tokio::fs::write(hub_copy.join("build.log"), b"hub copy")
            .await
            .unwrap();

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(Some("fedora"), false, &crbs, None, &store)
            .await
            .unwrap();
        assert_eq!(outcome.removed, 0, "缺失目录不产生实删");
        assert!(
            !tokio::fs::try_exists(&hub_copy).await.unwrap(),
            "None 回退默认根 {{crbs_root}}/artifacts，副本必须被联动删除"
        );
    }

    /// artifact_dir=Some(override) 时只清覆盖根，默认根 {crbs_root}/artifacts 不受影响。
    #[tokio::test]
    async fn artifact_dir_override_directs_log_copy_cleanup() {
        let (store, tmp) = create_test_store().await;
        let tmp = tmp.unwrap();
        let override_root = tempfile::tempdir().unwrap();

        let pkg_dir = tmp
            .path()
            .join("results")
            .join("fedora")
            .join("hello")
            .join("1.0-1");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("build.log"), b"payload")
            .await
            .unwrap();
        let build_id = seed_gc_candidate(&store, "fedora", &pkg_dir).await;

        let override_copy = override_root.path().join(build_id.to_string());
        tokio::fs::create_dir_all(&override_copy).await.unwrap();
        tokio::fs::write(override_copy.join("build.log"), b"override copy")
            .await
            .unwrap();
        let default_copy = tmp.path().join("artifacts").join(build_id.to_string());
        tokio::fs::create_dir_all(&default_copy).await.unwrap();
        tokio::fs::write(default_copy.join("build.log"), b"default copy")
            .await
            .unwrap();

        let crbs = CrbsConfig {
            crbs_root: tmp.path().to_path_buf(),
            result_gc_grace_hours: 0,
            ..Default::default()
        };
        let outcome = run_result_gc_standalone(
            Some("fedora"),
            false,
            &crbs,
            Some(override_root.path()),
            &store,
        )
        .await
        .unwrap();
        assert_eq!(outcome.removed, 1);
        assert!(
            !tokio::fs::try_exists(&override_copy).await.unwrap(),
            "覆盖根下的日志副本必须被联动删除"
        );
        assert!(
            tokio::fs::try_exists(&default_copy).await.unwrap(),
            "默认根 {{crbs_root}}/artifacts 不受覆盖影响"
        );
    }
}
