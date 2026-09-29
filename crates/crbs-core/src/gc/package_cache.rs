// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 包缓存 GC：容量统计、过期回收与全量清理。

use crate::config::CrbsConfig;
use crate::engine::lock::{lock_exclusive_async, DEFAULT_FILE_LOCK_TIMEOUT};
use crate::error::CrbsError;
use crate::state::StateStore;
use crate::types::GcPackageCacheSummary;
use tracing::{info, warn};

use super::assert_delete_under_root;
use super::shared_layers::{collect_recipe_pinned_sha256, collect_referenced_sha256};

pub(crate) async fn gc_package_cache(
    dry_run: bool,
    crbs_cfg: &CrbsConfig,
    state: &StateStore,
) -> crate::Result<GcPackageCacheSummary> {
    // advisory flock 串行化 package_cache GC，防并发 `crbs gc --cache` / server 后台 GC 同时扫描/删除。
    let _lock = acquire_gc_lock(crbs_cfg).await.map_err(|e| {
        CrbsError::io_message(format!(
            "acquire package_cache GC lock {}: {}",
            gc_lock_path(crbs_cfg).display(),
            e
        ))
    })?;

    // 安全守卫：活跃构建可能已引用缓存 RPM 但尚未写入 build_packages.json，故有
    // 构建运行即跳过回收（锁后复查收窄竞态窗）；计数失败保守跳过，宁可不回收不误删。
    match state.count_building_builds().await {
        Ok(n) if n > 0 => {
            info!(building = n, "Skipping package_cache GC: builds are active");
            return Ok(GcPackageCacheSummary::empty(dry_run, false));
        }
        Ok(_) => {}
        Err(e) => {
            warn!(
                error = %e,
                "Failed to count building builds; skipping package_cache GC"
            );
            return Ok(GcPackageCacheSummary::empty(dry_run, false));
        }
    }

    // 引用集一次收集，引用清理与 LRU 淘汰共用（collect 为全量扫描）。
    let mut referenced = collect_referenced_sha256(crbs_cfg, state).await?;

    // recipe 钉住（性能优化非正确性前提）：retention 窗口内 recipe
    // 引用的 sha256 并入引用集免驱逐；收集失败不中断 GC，下轮重放重下载兜底。
    let (recipe_pinned, pinned_recipes) = match collect_recipe_pinned_sha256(state).await {
        Ok(v) => v,
        Err(e) => {
            warn!(
                error = %e,
                "Failed to collect recipe GC pins; proceeding without them (cache miss recovers via URL re-download)"
            );
            (Default::default(), 0)
        }
    };
    let recipe_pinned_count = recipe_pinned.len();
    referenced.extend(recipe_pinned);
    info!(
        pinned_recipes,
        recipe_pinned_sha256 = recipe_pinned_count,
        "Recipe GC pins merged into referenced set (hot replay window)"
    );

    let mut summary = gc_package_cache_by_reference(dry_run, crbs_cfg, &referenced).await?;

    if let Some(limit_gb) = crbs_cfg.package_cache_max_size_gb {
        let lru_summary = gc_package_cache_by_size(
            dry_run,
            crbs_cfg,
            &referenced,
            limit_gb,
            crbs_cfg.package_cache_evict_referenced,
        )
        .await?;
        summary.lru_evicted = lru_summary.removed;
        summary.lru_bytes = lru_summary.bytes;
    }

    Ok(summary)
}

async fn gc_package_cache_by_reference(
    dry_run: bool,
    crbs_cfg: &CrbsConfig,
    referenced: &std::collections::HashSet<String>,
) -> crate::Result<GcPackageCacheSummary> {
    let cache_root = package_cache_root(crbs_cfg);
    if !tokio::fs::metadata(&cache_root)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Ok(GcPackageCacheSummary::empty(dry_run, false));
    }

    let mut to_remove = Vec::new();
    let mut kept = 0usize;
    let mut total_size: u64 = 0;

    for entry in scan_cache_entries(&cache_root).await? {
        let Some(sha_name) = entry.sha else {
            continue;
        };
        if referenced.contains(&sha_name) {
            kept += 1;
            continue;
        }
        let size = calc_dir_size(&entry.path).await;
        to_remove.push((entry.path, size));
    }

    // bytes 仅删除成功后累计（部分失败不高估释放量）；dry-run 按全部候选汇总（= 将释放）。
    let removed = if dry_run {
        total_size = to_remove.iter().map(|(_, s)| s).sum();
        0
    } else {
        let mut count = 0usize;
        for (path, size) in &to_remove {
            if let Err(e) = assert_delete_under_root(&cache_root, path) {
                warn!(path = %path.display(), error = %e, "Refusing to remove cache entry");
                continue;
            }
            if let Err(e) = tokio::fs::remove_dir_all(path).await {
                warn!(path = %path.display(), error = %e, "Failed to remove cache entry");
            } else {
                count += 1;
                total_size += size;
            }
        }
        count
    };

    Ok(GcPackageCacheSummary {
        removed,
        kept,
        bytes: total_size,
        lru_evicted: 0,
        lru_bytes: 0,
        dry_run,
        all: false,
    })
}

/// 按容量上限 LRU 淘汰；目标水位 `limit_gb * 0.9`，留缓冲免每轮贴线上限反复触发。
async fn gc_package_cache_by_size(
    dry_run: bool,
    crbs_cfg: &CrbsConfig,
    referenced: &std::collections::HashSet<String>,
    limit_gb: u64,
    evict_referenced: bool,
) -> crate::Result<GcPackageCacheSummary> {
    let cache_root = package_cache_root(crbs_cfg);
    if !tokio::fs::metadata(&cache_root)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Ok(GcPackageCacheSummary::empty(dry_run, false));
    }

    const GB: u64 = 1024 * 1024 * 1024;
    let limit_bytes = limit_gb.saturating_mul(GB);
    let target_bytes = limit_bytes.saturating_sub(limit_bytes / 10);

    #[derive(Debug)]
    struct CacheEntry {
        path: std::path::PathBuf,
        sha: String,
        size: u64,
        atime: u64,
        referenced: bool,
    }

    let mut entries = Vec::new();
    let mut total_size: u64 = 0;

    for entry in scan_cache_entries(&cache_root).await? {
        let Some(sha) = entry.sha else {
            continue;
        };
        let size = calc_dir_size(&entry.path).await;
        let atime = entry_access_time(&entry.path).await.unwrap_or(0);
        let is_referenced = referenced.contains(&sha);
        total_size += size;
        entries.push(CacheEntry {
            path: entry.path,
            sha,
            size,
            atime,
            referenced: is_referenced,
        });
    }

    if total_size <= target_bytes {
        return Ok(GcPackageCacheSummary {
            removed: 0,
            kept: entries.len(),
            bytes: 0,
            lru_evicted: 0,
            lru_bytes: 0,
            dry_run,
            all: false,
        });
    }

    let mut to_free = total_size.saturating_sub(target_bytes);
    entries.sort_by_key(|e| e.atime);

    let mut removed = 0usize;
    let mut bytes = 0u64;

    for entry in entries.iter().filter(|e| !e.referenced) {
        if to_free == 0 {
            break;
        }
        if !dry_run {
            if let Err(e) = assert_delete_under_root(&cache_root, &entry.path) {
                warn!(path = %entry.path.display(), error = %e, "Refusing to evict cache entry");
                continue;
            }
            if let Err(e) = tokio::fs::remove_dir_all(&entry.path).await {
                warn!(path = %entry.path.display(), error = %e, "Failed to evict cache entry");
                continue;
            }
        }
        info!(sha = %entry.sha, size = entry.size, "Evicted unreferenced package cache entry");
        to_free = to_free.saturating_sub(entry.size);
        removed += 1;
        bytes += entry.size;
    }

    // 仍超限且 evict_referenced 时，才继续驱逐被引用条目。
    if evict_referenced {
        for entry in entries.iter().filter(|e| e.referenced) {
            if to_free == 0 {
                break;
            }
            if !dry_run {
                if let Err(e) = assert_delete_under_root(&cache_root, &entry.path) {
                    warn!(path = %entry.path.display(), error = %e, "Refusing to evict referenced cache entry");
                    continue;
                }
                if let Err(e) = tokio::fs::remove_dir_all(&entry.path).await {
                    warn!(path = %entry.path.display(), error = %e, "Failed to evict referenced cache entry");
                    continue;
                }
            }
            warn!(
                sha = %entry.sha,
                size = entry.size,
                "Evicted referenced package cache entry (--reproduce may be affected)"
            );
            to_free = to_free.saturating_sub(entry.size);
            removed += 1;
            bytes += entry.size;
        }
    }

    if to_free > 0 {
        warn!(
            limit_gb,
            target_bytes,
            total_size,
            remaining = to_free,
            "Package cache still over limit after LRU eviction; consider increasing package_cache_max_size_gb"
        );
    }

    Ok(GcPackageCacheSummary {
        removed,
        kept: entries.len().saturating_sub(removed),
        bytes,
        lru_evicted: removed,
        lru_bytes: bytes,
        dry_run,
        all: false,
    })
}

async fn entry_access_time(path: &std::path::Path) -> crate::Result<u64> {
    let meta = tokio::fs::symlink_metadata(path).await.map_err(|e| {
        crate::error::CrbsError::from_io_context("get package cache entry metadata", e)
    })?;
    let time = meta
        .accessed()
        .or_else(|_| meta.modified())
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    Ok(time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "Entry access time before epoch, using 0");
            std::time::Duration::ZERO
        })
        .as_secs())
}

/// 删除所有包缓存（跳过数据库引用检查；用于 DB 丢失/损坏后完全重建）。
/// 有意绕过引用检查：活跃构建在用的 RPM 会一并删除，入口仅 warn 不拦截。
pub(crate) async fn gc_package_cache_all(
    dry_run: bool,
    crbs_cfg: &CrbsConfig,
    state: &StateStore,
) -> crate::Result<GcPackageCacheSummary> {
    let _lock = acquire_gc_lock(crbs_cfg).await.map_err(|e| {
        CrbsError::io_message(format!(
            "acquire package_cache GC lock {}: {}",
            gc_lock_path(crbs_cfg).display(),
            e
        ))
    })?;

    // 可观测性 warn：--all 绕过 DB 不查引用，活跃构建在用缓存也删；计数失败仅 debug 留痕。
    match state.count_building_builds().await {
        Ok(n) if n > 0 => {
            warn!(
                building = n,
                "gc --cache --all is clearing the ENTIRE package cache while builds are active; in-use RPMs will be deleted"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(error = %e, "Failed to count building builds before cache --all");
        }
    }

    let cache_root = package_cache_root(crbs_cfg);
    if !tokio::fs::metadata(&cache_root)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
    {
        return Ok(GcPackageCacheSummary::empty(dry_run, true));
    }

    let mut to_remove = Vec::new();
    let mut total_size: u64 = 0;

    for entry in scan_cache_entries(&cache_root).await? {
        let size = calc_dir_size(&entry.path).await;
        to_remove.push((entry.path, size));
    }

    // bytes 仅删除成功后累计；dry-run 按全部候选汇总（= 将释放）。
    let removed = if dry_run {
        total_size = to_remove.iter().map(|(_, s)| s).sum();
        0
    } else {
        let mut count = 0usize;
        for (path, size) in &to_remove {
            if let Err(e) = assert_delete_under_root(&cache_root, path) {
                warn!(path = %path.display(), error = %e, "Refusing to remove cache entry");
                continue;
            }
            if let Err(e) = tokio::fs::remove_dir_all(path).await {
                warn!(path = %path.display(), error = %e, "Failed to remove cache entry");
            } else {
                count += 1;
                total_size += size;
            }
        }
        count
    };

    Ok(GcPackageCacheSummary {
        removed,
        kept: 0,
        bytes: total_size,
        lru_evicted: 0,
        lru_bytes: 0,
        dry_run,
        all: true,
    })
}

/// package_cache 叶子条目（{cache_root}/{prefix}/{sha}/ 结构中的 sha 目录）。
struct PackageCacheEntry {
    path: std::path::PathBuf,
    /// 目录名（sha256 哈希）；非 UTF-8 名称时为 None，由调用方决定是否跳过。
    sha: Option<String>,
}

/// 遍历 {cache_root}/{prefix}/{sha}/ 两层结构，收集所有 sha 目录条目。
async fn scan_cache_entries(cache_root: &std::path::Path) -> crate::Result<Vec<PackageCacheEntry>> {
    let mut entries = Vec::new();
    let mut prefix_entries = tokio::fs::read_dir(cache_root)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read package cache root", e))?;
    while let Some(prefix_entry) = prefix_entries.next_entry().await.map_err(|e| {
        crate::error::CrbsError::from_io_context("read package cache prefix entry", e)
    })? {
        if !prefix_entry
            .file_type()
            .await
            .map_err(|e| {
                crate::error::CrbsError::from_io_context("get package cache prefix file type", e)
            })?
            .is_dir()
        {
            continue;
        }
        let mut sha_entries = tokio::fs::read_dir(prefix_entry.path())
            .await
            .map_err(|e| {
                crate::error::CrbsError::from_io_context("read package cache prefix dir", e)
            })?;
        while let Some(sha_entry) = sha_entries.next_entry().await.map_err(|e| {
            crate::error::CrbsError::from_io_context("read package cache sha entry", e)
        })? {
            if !sha_entry
                .file_type()
                .await
                .map_err(|e| {
                    crate::error::CrbsError::from_io_context("get package cache sha file type", e)
                })?
                .is_dir()
            {
                continue;
            }
            entries.push(PackageCacheEntry {
                path: sha_entry.path(),
                sha: sha_entry.file_name().to_str().map(str::to_string),
            });
        }
    }
    Ok(entries)
}

/// package_cache 实际根目录：优先使用配置，否则默认到 {crbs_root}/cache/packages。
fn package_cache_root(crbs_cfg: &CrbsConfig) -> std::path::PathBuf {
    crbs_cfg
        .package_cache_path
        .clone()
        .unwrap_or_else(|| crbs_cfg.crbs_root.join("cache").join("packages"))
}

/// GC 锁文件路径（串行化 package_cache 回收）。锁放 `crbs_root` 稳定目录而非
/// cache 内：cache 被 `--all` 整体删除后锁仍在，串行语义不失效。
fn gc_lock_path(crbs_cfg: &CrbsConfig) -> std::path::PathBuf {
    crbs_cfg
        .crbs_root
        .join("locks")
        .join("package_cache.gc.lock")
}

/// 获取 package_cache GC 独占锁；锁文件不存在则创建，drop 返回的 File 即释放 flock。
async fn acquire_gc_lock(crbs_cfg: &CrbsConfig) -> crate::Result<std::fs::File> {
    let lock_dir = crbs_cfg.crbs_root.join("locks");
    // 裸 create_dir_all 是 0755 creator:creator-group，root 跑过 gc 后 server 侧
    // 在 locks/ 下建锁文件即 EACCES，须走 ensure_directory 保 crbs 组权限。
    let ld = lock_dir.clone();
    tokio::task::spawn_blocking(move || crate::privilege::ensure_directory(&ld, "gc locks"))
        .await
        .map_err(|e| crate::error::CrbsError::io_message(format!("ensure gc locks dir: {e}")))??;
    let lock_path = gc_lock_path(crbs_cfg);
    lock_exclusive_async(lock_path, DEFAULT_FILE_LOCK_TIMEOUT).await
}

/// 目录大小计算的最大递归深度。cache 为内容寻址 prefix 分片结构，正常深度
/// 有限；上限防异常符号链接/循环挂载导致栈溢出或长时间挂起。
const CALC_DIR_SIZE_MAX_DEPTH: usize = 128;

pub(crate) async fn calc_dir_size(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![(path.to_path_buf(), 0usize)];
    while let Some((current, depth)) = stack.pop() {
        if depth > CALC_DIR_SIZE_MAX_DEPTH {
            tracing::warn!(path = %current.display(), depth, "calc_dir_size reached max depth, skipping subtree");
            continue;
        }
        let mut entries = match tokio::fs::read_dir(&current).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        // size 非纯度量（累进 total_size 推出 to_free 定 LRU 淘汰量）：迭代失败
        // warn 后低报不传播——少淘汰下轮重算自愈，传播则炸掉整轮容量 GC。
        // ponytail: 需单轮收敛（如强制出清）时，升级路径是签名改 Result<u64> 按步失败收口。
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| {
                tracing::warn!(
                    path = %current.display(),
                    error = %e,
                    "calc_dir_size iterate failed; size may be underreported"
                );
                e
            })
            .ok()
            .flatten()
        {
            // file_type 不跟随符号链接，防跨目录/循环链接导致错误统计。
            let ft = match entry.file_type().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push((entry.path(), depth + 1));
            } else if ft.is_symlink() {
                continue;
            } else {
                let meta = match entry.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                total += meta.len();
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::super::shared_layers::tests as shared_tests;
    use super::*;

    async fn seed_cache_entry(cache_root: &std::path::Path, sha: &str) {
        let dir = cache_root.join(&sha[..2]).join(sha);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("pkg.rpm"), b"rpm-bytes")
            .await
            .unwrap();
    }

    fn gc_cfg(
        crbs_root: &std::path::Path,
        cache_root: &std::path::Path,
    ) -> crate::config::CrbsConfig {
        crate::config::CrbsConfig {
            crbs_root: crbs_root.to_path_buf(),
            package_cache_path: Some(cache_root.to_path_buf()),
            ..Default::default()
        }
    }

    /// 端到端：窗口内 recipe 钉住的 sha256 免驱逐、无引用条目正常驱逐、窗口外钉住失效。
    #[tokio::test]
    async fn recipe_pin_protects_entry_from_eviction_and_expires() {
        let (store, db_tmp) = crate::state::test_state::create_test_store().await;
        let world = db_tmp.as_ref().unwrap().path().to_path_buf();
        let cache_root = world.join("cache");
        let results = world.join("results");
        tokio::fs::create_dir_all(&results).await.unwrap();

        let pinned_sha = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000";
        let free_sha = "eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444eeee4444";
        seed_cache_entry(&cache_root, pinned_sha).await;
        seed_cache_entry(&cache_root, free_sha).await;

        shared_tests::seed_recipe_task(
            &store,
            &results,
            "det",
            "fresh-1.0-1",
            &crate::util::db_now_utc(),
            pinned_sha,
        )
        .await
        .unwrap();

        let cfg = gc_cfg(&world, &cache_root);
        let summary = gc_package_cache(false, &cfg, &store).await.unwrap();
        assert_eq!(summary.removed, 1, "only the unreferenced entry is evicted");
        assert!(
            cache_root.join(&pinned_sha[..2]).join(pinned_sha).exists(),
            "recipe-pinned entry survives"
        );
        assert!(
            !cache_root.join(&free_sha[..2]).join(free_sha).exists(),
            "unreferenced entry evicted"
        );

        // 窗口外：91 天前 recipe 的钉住已失效 → stale_sha 下轮 GC 被驱逐。
        let stale_sha = "dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333dddd3333";
        seed_cache_entry(&cache_root, stale_sha).await;
        let stale_task_id = shared_tests::seed_recipe_task(
            &store,
            &results,
            "det",
            "stale-1.0-1",
            &(chrono::Utc::now() - chrono::Duration::days(91))
                .format(crate::util::DB_TIME_FMT)
                .to_string(),
            stale_sha,
        )
        .await
        .unwrap();
        // 删 per-build build_packages.json 模拟结果 GC 已清走：live result_dir 下
        // 该文件属 always-referenced 扫描，删后 stale_sha 只凭窗口外钉住失效驱逐。
        let task_root = results.join(stale_task_id.to_string());
        let mut arches = tokio::fs::read_dir(&task_root).await.unwrap();
        while let Some(arch) = arches.next_entry().await.unwrap() {
            if !arch.path().is_dir() {
                continue;
            }
            let mut builds = tokio::fs::read_dir(arch.path()).await.unwrap();
            while let Some(build) = builds.next_entry().await.unwrap() {
                let bp = build.path().join("build_packages.json");
                if bp.exists() {
                    tokio::fs::remove_file(&bp).await.unwrap();
                }
            }
        }
        let summary = gc_package_cache(false, &cfg, &store).await.unwrap();
        assert_eq!(
            summary.removed, 1,
            "stale recipe no longer protects its entry"
        );
        assert!(!cache_root.join(&stale_sha[..2]).join(stale_sha).exists());
        assert!(
            cache_root.join(&pinned_sha[..2]).join(pinned_sha).exists(),
            "fresh pin still holds"
        );
    }
}
