// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 本地磁盘清理：结果目录按保留天数 + build_dir 崩溃残留 + tmp 目录
//! `.tmpXXXX` 残留清扫 + 本地 SQLite 行级 prune。
//! 已知边界：`crbs shell` 长会话不在活跃门控内（引擎 CLI 路径不落 building 行、
//! 不注册内存活跃集），超 1h 的会话 tmp 挂载可能被惰性回收，受影响会话表现为环境内
//! 路径 ENOENT，退出重进即恢复；nspawn 容器挂载在独立 mount namespace，宿主侧回收
//! 不影响运行中容器。

use std::collections::HashSet;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::WorkerConfig;

/// sweeper 周期。
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// 下载目录清扫的 mtime 宽限：活跃复查（锁内 contains）→ remove 两步 TOCTOU 的
/// 兜底。assignment id 双方言自增不复用、重派产生新目录——复查是主防线，宽限只
/// 覆盖 id 复用 / 时钟异常；量级 10 分钟，仅启动清扫让刚领任务目录跳过首轮。
const DOWNLOAD_DIR_SWEEP_GRACE: Duration = Duration::from_secs(10 * 60);

/// tempfile 残留目录前缀：reproduce tempfile::tempdir_in(build_dir) 的 `.tmpXXXX`
/// 崩溃后无人回收。
const TEMPFILE_DIR_PREFIX: &str = ".tmp";

/// 本地 SQLite 行 prune 宽限天数。只删 completed_at 非空终态行——崩溃 building 行
/// 永不动（engine/orphan.rs 消费非终态行）。
const LOCAL_DB_PRUNE_GRACE_DAYS: u64 = 7;

/// 活跃 assignment id 集合（poller 执行中的 `task.assignment_id`，hub id 空
/// 间）。按 assignment 区分条目（同一 assignment 至多一个执行）：重派后新旧
/// 执行各占一条目，先结束方的 Drop 不夺走后结束方的保护；`std::sync::Mutex`
/// 短临界区，不跨 await。
pub(crate) type ActiveBuildIds = Arc<Mutex<HashSet<i64>>>;

pub(crate) struct ActiveBuildGuard {
    ids: ActiveBuildIds,
    assignment_id: i64,
}

impl ActiveBuildGuard {
    pub(crate) fn new(ids: ActiveBuildIds, assignment_id: i64) -> Self {
        ids.lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(assignment_id);
        Self { ids, assignment_id }
    }
}

impl Drop for ActiveBuildGuard {
    fn drop(&mut self) {
        self.ids
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.assignment_id);
    }
}

/// 启动周期 sweeper：启动即扫一次（覆盖崩溃残留），此后每 24h 一轮。
pub(crate) fn spawn_sweeper(
    cfg: WorkerConfig,
    active_build_ids: ActiveBuildIds,
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        info!(
            result_retention_days = cfg.result_retention_days,
            interval_secs = SWEEP_INTERVAL.as_secs(),
            "Worker disk sweeper started"
        );
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = cancel.cancelled() => {
                    info!("Worker disk sweeper shutting down");
                    break;
                }
            }
            sweep_once(&cfg, &active_build_ids).await;
        }
    })
}

async fn sweep_once(cfg: &WorkerConfig, active_build_ids: &ActiveBuildIds) {
    let build_root = std::path::PathBuf::from(&cfg.build_dir);
    sweep_build_download_dirs(&build_root, active_build_ids).await;

    reclaim_orphan_tmp_mounts(cfg, active_build_ids).await;

    sweep_tmp_domains(cfg).await;

    prune_local_db_rows(&build_root).await;

    if cfg.result_retention_days > 0 {
        let cutoff = Duration::from_secs(cfg.result_retention_days.saturating_mul(86_400));
        sweep_result_dirs(
            &std::path::PathBuf::from(&cfg.crbs_root).join("results"),
            cutoff,
            active_build_ids,
        )
        .await;
    }
}

/// tmp 清扫范围的全部根目录：显式配置的 tmp_dir/tmpfs_dir 加引擎派生目录 {crbs_root}/tmp
/// （引擎 tmp_dir 未显式配置时的 tempdir 落点，不补则全默认部署下 overlay 残留域
/// 扫不到）。派生域与显式域重合时只扫一遍。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn tmp_domain_roots(cfg: &WorkerConfig) -> Vec<std::path::PathBuf> {
    let mut roots = vec![
        std::path::PathBuf::from(&cfg.tmp_dir),
        std::path::PathBuf::from(&cfg.tmpfs_dir),
    ];
    let derived = std::path::PathBuf::from(&cfg.crbs_root).join("tmp");
    if !roots.contains(&derived) {
        roots.push(derived);
    }
    roots
}

async fn sweep_tmp_domains(cfg: &WorkerConfig) {
    #[cfg(target_os = "linux")]
    {
        crbs_core::engine::tmp_sweep::sweep_tmp_domain(
            &tmp_domain_roots(cfg),
            crbs_core::engine::tmp_sweep::PROC_MOUNTS,
            crbs_core::engine::tmp_sweep::TMP_SWEEP_GRACE,
            |p| async move { crbs_core::privilege::rm_rf_async(&[p.as_path()]).await },
        )
        .await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        tracing::debug!(
            "Skipping tmp domain tempdir body sweep: not Linux (/proc/mounts unavailable)"
        );
    }
}

/// tmp 无主挂载回收：崩溃构建遗留的仍挂载层（tmp 下 `.tmp*` 内的 overlay / bind）
/// 若无周期回收会在共享节点上积累直至打满 tmpfs（手动 `crbs gc --orphan-mounts`
/// 保留为兜底）。目录体交紧随其后的 sweep_tmp_domains 同轮清除。
///
/// 活跃门控（绝不卸载活跃构建的挂载）：内存活跃 assignment 集（覆盖记录落库前的
/// 执行窗口）+ 本机两个状态库（worker 本地 {build_dir}/crbs.db 与引擎 CLI 的
/// {crbs_root}/crbs.db，均仅当库文件已存在才打开）——先做一轮僵尸修复（超时 + pid
/// 已死的 building 记录标 failed，不修则死 pid 行永久挡门），回收循环内再实时查
/// building 计数：任一非零或查询失败 = busy 跳过（失败即拒绝）。
async fn reclaim_orphan_tmp_mounts(cfg: &WorkerConfig, active: &ActiveBuildIds) {
    #[cfg(target_os = "linux")]
    {
        let Some(stores) = open_gate_stores(cfg).await else {
            return;
        };

        for store in &stores {
            // 僵尸修复（round 级一次）：死 pid 的超时 building 记录标 failed，否则
            // 永久令门控命中、回收饿死。
            crbs_core::engine::gc::repair_zombie_builds(store).await;
        }

        let roots = tmp_domain_roots(cfg);
        let allowed_roots = vec![std::path::PathBuf::from(&cfg.crbs_root)];
        let active_for_gate = Arc::clone(active);
        crbs_core::engine::tmp_sweep::umount_orphan_tmp_mounts(
            &roots,
            crbs_core::engine::tmp_sweep::PROC_MOUNTS,
            crbs_core::engine::tmp_sweep::TMP_SWEEP_GRACE,
            &allowed_roots,
            move || {
                let stores = stores.clone();
                let active = Arc::clone(&active_for_gate);
                async move { reclaim_gate_busy(&stores, &active).await }
            },
            |p| async move { crbs_core::privilege::umount_detach(p).await },
        )
        .await;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cfg, active);
        tracing::debug!("Skipping tmp domain orphan mount reclaim: not Linux");
    }
}

#[cfg(target_os = "linux")]
async fn reclaim_gate_busy(stores: &[crbs_core::StateStore], active: &ActiveBuildIds) -> bool {
    if !active.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
        return true;
    }
    for store in stores {
        match store.count_building_builds().await {
            Ok(0) => {}
            Ok(_) => return true,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to query building builds for orphan mount reclaim gate; \
                     skipping candidate (fail-closed)"
                );
                return true;
            }
        }
    }
    false
}

/// 打开活跃门控用状态库：worker 本地（{build_dir}/crbs.db）+ 引擎 CLI
/// （{crbs_root}/crbs.db，仅当库文件已存在——不凭空建库）。任一库存在但打不开：
/// 无法判定构建活跃性，返回 None（整轮跳过）。
#[cfg(target_os = "linux")]
async fn open_gate_stores(cfg: &WorkerConfig) -> Option<Vec<crbs_core::StateStore>> {
    let db_dirs = [
        std::path::PathBuf::from(&cfg.build_dir),
        std::path::PathBuf::from(&cfg.crbs_root),
    ];
    let mut stores = Vec::new();
    for db_dir in &db_dirs {
        let db_path = db_dir.join("crbs.db");
        match tokio::fs::try_exists(&db_path).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                warn!(
                    path = %db_path.display(),
                    error = %e,
                    "Failed to stat state db for orphan mount reclaim gate; skipping round"
                );
                return None;
            }
        }
        match crbs_core::StateStore::new(db_dir).await {
            Ok(s) => stores.push(s),
            Err(e) => {
                warn!(
                    path = %db_path.display(),
                    error = %e,
                    "Failed to open state db for orphan mount reclaim gate; skipping round"
                );
                return None;
            }
        }
    }
    Some(stores)
}

async fn sweep_build_download_dirs(build_root: &Path, active: &ActiveBuildIds) {
    let mut rd = match tokio::fs::read_dir(build_root).await {
        Ok(rd) => rd,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                path = %build_root.display(),
                error = %e,
                "Failed to read build_dir for sweep"
            );
            return;
        }
    };

    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                warn!(
                    path = %build_root.display(),
                    error = %e,
                    "Failed to iterate build_dir during sweep"
                );
                return;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.is_empty() {
            continue;
        }

        if name.starts_with(TEMPFILE_DIR_PREFIX) {
            let target = build_root.join(name);
            if remove_stale_download_dir(build_root, &target).await {
                info!(
                    path = %target.display(),
                    "Swept leftover tempfile dir in build_dir"
                );
            }
            continue;
        }

        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(assignment_id) = name.parse::<i64>() else {
            continue;
        };

        if active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&assignment_id)
        {
            continue;
        }

        let target = build_root.join(name);
        if remove_stale_download_dir(build_root, &target).await {
            info!(
                assignment_id = assignment_id,
                path = %target.display(),
                "Swept leftover build download dir"
            );
        }
    }
}

async fn remove_stale_download_dir(build_root: &Path, target: &Path) -> bool {
    if !crate::executor::dir_strictly_under_root(target, build_root) {
        warn!(
            target = %target.display(),
            "Build dir sweep target failed isolation assertion; refusing to remove"
        );
        return false;
    }
    match tokio::fs::metadata(target).await {
        Ok(meta) => {
            if !meta.is_dir() {
                return false;
            }
            let fresh = meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age < DOWNLOAD_DIR_SWEEP_GRACE)
                .unwrap_or(true);
            if fresh {
                return false;
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            warn!(
                path = %target.display(),
                error = %e,
                "Failed to stat build download dir for grace check; skipping"
            );
            return false;
        }
    }
    match tokio::fs::remove_dir_all(target).await {
        Ok(()) => true,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            warn!(
                path = %target.display(),
                error = %e,
                "Failed to remove leftover build download dir"
            );
            false
        }
    }
}

async fn prune_local_db_rows(build_root: &Path) {
    let db_path = build_root.join("crbs.db");
    match tokio::fs::try_exists(&db_path).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            warn!(
                path = %db_path.display(),
                error = %e,
                "Failed to stat local state db for prune; skipping"
            );
            return;
        }
    }
    match crbs_core::StateStore::new(build_root).await {
        Ok(store) => match store
            .prune_local_build_rows(LOCAL_DB_PRUNE_GRACE_DAYS)
            .await
        {
            Ok(0) => {}
            Ok(n) => info!(
                pruned_builds = n,
                grace_days = LOCAL_DB_PRUNE_GRACE_DAYS,
                "Pruned local builds rows (and orphaned local task rows)"
            ),
            Err(e) => warn!(
                path = %db_path.display(),
                error = %e,
                "Failed to prune local builds rows"
            ),
        },
        Err(e) => warn!(
            path = %db_path.display(),
            error = %e,
            "Failed to open local state db for prune"
        ),
    }
}

/// 判断目录名是否为引擎结果叶子 `{ts}-{build_id}`（ts 为 %Y%m%d-%H%M%S）。
/// 调用方只做存在性判定，不消费拆分值。
fn is_engine_result_leaf(name: &str) -> bool {
    let Some((ts, id)) = name.rsplit_once('-') else {
        return false;
    };
    if ts.is_empty() || id.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return false;
    }
    if !id.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    ts.len() >= 15 && id.parse::<i64>().is_ok()
}

/// 活跃 assignment 非空时整轮跳过：叶子后缀是引擎本地 build id，与活跃集合
/// 的 hub assignment_id 不同 id 空间无法逐叶排除，且 mtime 判活有盲区——
/// hang 构建静默超 retention 会被 mid-build 删除；整轮跳过误删面压到零。
///
/// 饿死上界（已知代价）：饱和 worker 下可连续跳过、失败残留无界累积。
async fn sweep_result_dirs(result_root: &Path, cutoff: Duration, active: &ActiveBuildIds) {
    if !active.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
        tracing::debug!("Skipping result dir sweep: active assignments in progress");
        return;
    }

    let mut product_rd = match tokio::fs::read_dir(result_root).await {
        Ok(rd) => rd,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                path = %result_root.display(),
                error = %e,
                "Failed to read result root for sweep"
            );
            return;
        }
    };

    'outer: loop {
        let product_entry = match product_rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                warn!(
                    path = %result_root.display(),
                    error = %e,
                    "Failed to iterate result root during sweep"
                );
                return;
            }
        };

        let product_dir = product_entry.path();
        if !crate::executor::dir_strictly_under_root(&product_dir, result_root) {
            continue;
        }
        let mut pkg_rd = match tokio::fs::read_dir(&product_dir).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        loop {
            let pkg_entry = match pkg_rd.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => continue 'outer,
                Err(_) => continue 'outer,
            };

            let pkg_dir = pkg_entry.path();
            if !crate::executor::dir_strictly_under_root(&pkg_dir, &product_dir) {
                continue;
            }
            let mut leaf_rd = match tokio::fs::read_dir(&pkg_dir).await {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            loop {
                let leaf_entry = match leaf_rd.next_entry().await {
                    Ok(Some(e)) => e,
                    Ok(None) => break,
                    Err(_) => break,
                };

                let leaf = leaf_entry.path();
                let Some(name) = leaf.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if !is_engine_result_leaf(name) {
                    continue;
                }
                if !crate::executor::dir_strictly_under_root(&leaf, &pkg_dir) {
                    continue;
                }

                let stale = leaf_staleness(&leaf)
                    .await
                    .map(|age| age >= cutoff)
                    .unwrap_or(false);
                if !stale {
                    continue;
                }
                match tokio::fs::remove_dir_all(&leaf).await {
                    Ok(()) => {
                        info!(path = %leaf.display(), "Swept expired local result dir");

                        remove_latest_link_if_pointing(&pkg_dir, name).await;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => warn!(
                        path = %leaf.display(),
                        error = %e,
                        "Failed to remove expired local result dir"
                    ),
                }
            }
        }
    }
}

async fn leaf_staleness(leaf: &Path) -> Option<std::time::Duration> {
    let log = leaf.join("build.log");
    let meta_path = if tokio::fs::try_exists(&log).await.unwrap_or(false) {
        log
    } else {
        leaf.to_path_buf()
    };
    tokio::fs::metadata(&meta_path)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
}

pub(crate) async fn delete_build_result_dir(
    result_dir: &Path,
    engine_build_id: i64,
    result_root: &Path,
) {
    let refuse = |reason: &str| {
        warn!(
            path = %result_dir.display(),
            root = %result_root.display(),
            "Refusing to delete local result dir: {reason}"
        );
    };

    let rel = match result_dir.strip_prefix(result_root) {
        Ok(rel)
            if rel.components().count() == 3
                && rel.components().all(|c| matches!(c, Component::Normal(_))) =>
        {
            rel
        }
        _ => {
            refuse("not exactly {root}/{product}/{pkg}/{leaf}");
            return;
        }
    };
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        refuse("leaf name is not valid UTF-8");
        return;
    };
    let suffix = format!("-{engine_build_id}");
    let prefix = match name.strip_suffix(&suffix) {
        Some(p) if !p.is_empty() => p,
        _ => {
            refuse("leaf name does not match engine build id");
            return;
        }
    };
    if !is_engine_result_leaf(name) || prefix.len() < 8 {
        refuse("leaf is not an engine result layout {ts}-{build_id}");
        return;
    }
    match tokio::fs::remove_dir_all(result_dir).await {
        Ok(()) => {
            info!(path = %result_dir.display(), "Deleted local result dir after confirmed upload and report");

            if let Some(pkg_dir) = result_dir.parent() {
                remove_latest_link_if_pointing(pkg_dir, name).await;
            }
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %result_dir.display(),
            error = %e,
            "Failed to delete local result dir after confirmed upload and report"
        ),
    }
}

async fn remove_latest_link_if_pointing(pkg_dir: &Path, leaf_name: &str) {
    let latest = pkg_dir.join("latest");
    let aside = pkg_dir.join(format!(".latest.gone.{leaf_name}"));

    if let Err(e) = tokio::fs::rename(&latest, &aside).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!(path = %latest.display(), error = %e, "Failed to rename latest symlink aside");
        }
        return;
    }
    match tokio::fs::read_link(&aside).await {
        Ok(target) if target.to_str() == Some(leaf_name) => {
            if let Err(e) = tokio::fs::remove_file(&aside).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!(path = %aside.display(), error = %e, "Failed to remove latest symlink");
                }
            }
        }
        _ => {
            if let Err(e) = tokio::fs::rename(&aside, &latest).await {
                warn!(
                    path = %latest.display(),
                    error = %e,
                    "Failed to restore latest symlink after mismatch (advisory link, rebuilt by next build)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_dir_sweep_removes_numeric_and_keeps_active() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(build_root.join("1001"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join("1002"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join("junk"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join(".incoming"))
            .await
            .unwrap();
        backdate_mtime(&build_root.join("1001"));

        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(1002);
        sweep_build_download_dirs(&build_root, &active).await;

        assert!(!build_root.join("1001").exists(), "非活跃数字目录应被清");
        assert!(
            build_root.join("1002").exists(),
            "活跃 assignment 目录必须保留"
        );
        assert!(build_root.join("junk").exists());
        assert!(build_root.join(".incoming").exists());
    }

    #[tokio::test]
    async fn build_dir_sweep_respects_mtime_grace() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(build_root.join("2001"))
            .await
            .unwrap();

        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        sweep_build_download_dirs(&build_root, &active).await;
        assert!(
            build_root.join("2001").exists(),
            "宽限期内的新鲜目录不得被删（可能已被重派执行复用）"
        );

        backdate_mtime(&build_root.join("2001"));
        sweep_build_download_dirs(&build_root, &active).await;
        assert!(!build_root.join("2001").exists(), "超过宽限的目录应被清");
    }

    #[tokio::test]
    async fn build_dir_sweep_noop_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        sweep_build_download_dirs(
            &tmp.path().join("none"),
            &Arc::new(Mutex::new(HashSet::new())),
        )
        .await;
    }

    #[tokio::test]
    async fn local_db_prune_removes_old_terminal_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        let store = crbs_core::StateStore::new(&build_root).await.unwrap();
        let pool = store.pool();

        let old = "datetime('now', '-30 days')";
        let recent = "datetime('now', '-1 day')";
        for (pkg, phase, ts) in [
            ("t1", "succeeded", old),
            ("t2", "succeeded", recent),
            ("t3", "building", "NULL"),
        ] {
            sqlx::query(&format!(
                "INSERT INTO tasks (product, pkg_name, phase, completed_at) \
                 VALUES ('p', '{pkg}', '{phase}', {ts})"
            ))
            .execute(pool)
            .await
            .unwrap();
        }
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b1', 'succeeded', (SELECT id FROM tasks WHERE pkg_name = 't1'), {old})"
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b2', 'succeeded', (SELECT id FROM tasks WHERE pkg_name = 't2'), {recent})"
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, completed_at) \
             VALUES ('p', 'b3', 'building', (SELECT id FROM tasks WHERE pkg_name = 't3'), {old})"
        ))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (product, pkg_name, phase, task_id) \
             VALUES ('p', 'b4', 'cancelled', (SELECT id FROM tasks WHERE pkg_name = 't1'))",
        )
        .execute(pool)
        .await
        .unwrap();
        drop(store);

        prune_local_db_rows(&build_root).await;

        let store = crbs_core::StateStore::new(&build_root).await.unwrap();
        let pool = store.pool();
        let builds: Vec<String> =
            sqlx::query_scalar("SELECT pkg_name FROM builds ORDER BY pkg_name")
                .fetch_all(pool)
                .await
                .unwrap();
        assert_eq!(builds, vec!["b2", "b3", "b4"], "仅超期终态行被删");
        let tasks: Vec<String> = sqlx::query_scalar("SELECT pkg_name FROM tasks ORDER BY pkg_name")
            .fetch_all(pool)
            .await
            .unwrap();
        assert_eq!(
            tasks,
            vec!["t1", "t2", "t3"],
            "childless 任务行收走，被引用的保留"
        );
    }

    #[tokio::test]
    async fn local_db_prune_skips_when_db_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(&build_root).await.unwrap();

        prune_local_db_rows(&build_root).await;

        assert!(
            !build_root.join("crbs.db").exists(),
            "prune 不得在无库的 build_dir 上创建 crbs.db"
        );
    }

    #[tokio::test]
    async fn build_dir_sweep_removes_stale_tempfile_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(build_root.join(".tmpAbCdEf"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join(".tmp123456"))
            .await
            .unwrap();
        backdate_mtime(&build_root.join(".tmpAbCdEf"));

        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        sweep_build_download_dirs(&build_root, &active).await;

        assert!(
            !build_root.join(".tmpAbCdEf").exists(),
            "超宽限的 tempfile 残留目录应被清"
        );
        assert!(
            build_root.join(".tmp123456").exists(),
            "宽限期内的新鲜 tempfile 目录不得被删"
        );

        backdate_mtime(&build_root.join(".tmp123456"));
        sweep_build_download_dirs(&build_root, &active).await;
        assert!(!build_root.join(".tmp123456").exists());
    }

    #[tokio::test]
    async fn build_dir_sweep_tempfile_prefix_only_targets_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(&build_root).await.unwrap();
        tokio::fs::write(build_root.join(".tmp-not-a-dir"), b"x")
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join(".incoming"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(build_root.join("3001"))
            .await
            .unwrap();
        backdate_mtime(&build_root.join(".tmp-not-a-dir"));
        backdate_mtime(&build_root.join(".incoming"));
        backdate_mtime(&build_root.join("3001"));

        sweep_build_download_dirs(&build_root, &empty_active()).await;

        assert!(
            build_root.join(".tmp-not-a-dir").exists(),
            "前缀撞名的文件不动（remove_dir_all 对文件必失败，is_dir 预检跳过）"
        );
        assert!(build_root.join(".incoming").exists(), "非 .tmp 点目录不动");
        assert!(!build_root.join("3001").exists(), "数字目录照常清扫");
    }

    #[tokio::test]
    async fn build_dir_sweep_rechecks_active_set_per_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(build_root.join("1001"))
            .await
            .unwrap();
        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));

        let _guard = ActiveBuildGuard::new(active.clone(), 1001);
        sweep_build_download_dirs(&build_root, &active).await;
        assert!(
            build_root.join("1001").exists(),
            "guard 存活期间清扫必须实时看见活跃 assignment"
        );
    }

    #[tokio::test]
    async fn result_sweep_deletes_leaf_dirs_only() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();
        let bad_leaf = root.join("prod").join("pkg").join("not-a-leaf");
        tokio::fs::create_dir_all(&bad_leaf).await.unwrap();
        tokio::fs::create_dir_all(root.join("prod").join("other-pkg"))
            .await
            .unwrap();
        tokio::fs::write(root.join("prod").join("README"), b"x")
            .await
            .unwrap();

        sweep_result_dirs(&root, Duration::ZERO, &empty_active()).await;

        assert!(!leaf.exists(), "过期叶子目录应被删");
        assert!(bad_leaf.exists(), "非引擎布局的目录不动");
        assert!(
            root.join("prod").join("other-pkg").exists(),
            "空包目录不删内容（无叶子）"
        );
        assert!(root.join("prod").exists(), "产品目录本身绝不删");
        assert!(root.join("prod").join("README").exists(), "产品层文件不动");
    }

    #[tokio::test]
    async fn result_sweep_skipped_while_assignments_active() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();

        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        active.lock().unwrap_or_else(|e| e.into_inner()).insert(7);
        sweep_result_dirs(&root, Duration::ZERO, &active).await;

        assert!(
            leaf.exists(),
            "活跃 assignment 非空时必须整轮跳过 result 清扫（cutoff=0 也不例外）"
        );
    }

    #[tokio::test]
    async fn result_sweep_keeps_fresh_leaves() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();

        sweep_result_dirs(&root, Duration::from_secs(3600 * 24 * 365), &empty_active()).await;

        assert!(leaf.exists(), "未过保留期的叶子必须保留");
    }

    #[tokio::test]
    async fn result_sweep_freshness_prefers_build_log_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();

        let log = leaf.join("build.log");
        tokio::fs::write(&log, b"line1\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        {
            use tokio::io::AsyncWriteExt;
            let mut f = tokio::fs::OpenOptions::new()
                .append(true)
                .open(&log)
                .await
                .unwrap();
            f.write_all(b"line2\n").await.unwrap();
        }

        sweep_result_dirs(&root, Duration::from_secs(1), &empty_active()).await;

        assert!(
            leaf.exists(),
            "build.log 仍活跃（刚 append）的结果目录不得按目录 mtime 误删"
        );
    }

    #[tokio::test]
    async fn delete_result_dir_removes_matching_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let pkg_dir = root.join("prod").join("pkg");
        let leaf = pkg_dir.join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();

        std::os::unix::fs::symlink("20260825-010203-7", pkg_dir.join("latest")).unwrap();
        std::os::unix::fs::symlink("20260825-010203-8", pkg_dir.join(".latest.new.8")).unwrap();

        delete_build_result_dir(&leaf, 7, &root).await;
        assert!(!leaf.exists());
        assert!(
            std::fs::symlink_metadata(pkg_dir.join("latest")).is_err(),
            "指向被删叶子的 latest 软链应一并回收"
        );
        assert!(
            std::fs::symlink_metadata(pkg_dir.join(".latest.new.8")).is_ok(),
            "指向其它叶子的链接不动"
        );
    }

    #[tokio::test]
    async fn delete_result_dir_refuses_mismatched_or_shallow_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let other_leaf = root.join("prod").join("pkg").join("20260825-010203-8");
        tokio::fs::create_dir_all(&other_leaf).await.unwrap();
        delete_build_result_dir(&other_leaf, 7, &root).await;
        assert!(other_leaf.exists(), "build id 不匹配的叶子必须保留");

        let traversal = root.join("prod/pkg/20260825-010203-7/../../../victim");
        delete_build_result_dir(&traversal, 7, &root).await;
        assert!(other_leaf.exists());

        let shallow = root.join("20260825-010203-7");
        tokio::fs::create_dir_all(&shallow).await.unwrap();
        delete_build_result_dir(&shallow, 7, &root).await;
        assert!(shallow.exists(), "浅层目录必须保留（可能是共享目录）");

        let deep = root
            .join("prod")
            .join("pkg")
            .join("20260825-010203-7")
            .join("x");
        tokio::fs::create_dir_all(&deep).await.unwrap();
        delete_build_result_dir(&deep, 7, &root).await;
        assert!(deep.exists(), "非第三级目录必须保留");

        let outside = tmp.path().join("elsewhere").join("20260825-010203-7");
        tokio::fs::create_dir_all(&outside).await.unwrap();
        delete_build_result_dir(&outside, 7, &root).await;
        assert!(outside.exists(), "root 外目录必须保留");
    }

    #[tokio::test]
    async fn active_build_guard_tracks_lifecycle() {
        let ids: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        {
            let _g = ActiveBuildGuard::new(ids.clone(), 42);
            assert!(ids.lock().unwrap().contains(&42));
        }
        assert!(!ids.lock().unwrap().contains(&42));
    }

    #[test]
    fn is_engine_result_leaf_accepts_only_engine_layout() {
        assert!(is_engine_result_leaf("20260825-010203-7"));
        assert!(is_engine_result_leaf("20260825-010203-12345"));
        assert!(!is_engine_result_leaf("7"));
        assert!(!is_engine_result_leaf("-7"));
        assert!(!is_engine_result_leaf("20260825-010203-"));
        assert!(!is_engine_result_leaf("20260825-010203-x7"));
        assert!(!is_engine_result_leaf("latest"));

        assert!(!is_engine_result_leaf("20260825-7"));
        assert!(!is_engine_result_leaf("20260825-0102-7"));
    }

    #[tokio::test]
    async fn sweeper_exits_promptly_on_cancel() {
        let tmp = tempfile::tempdir().unwrap();
        let content = format!(
            "name = \"sweep-test\"\nhub_url = \"http://127.0.0.1:1\"\ntoken = \"t\"\n\
             build_dir = \"{}\"\ncrbs_root = \"{}\"\nresult_retention_days = 0\n",
            tmp.path().join("builds").display(),
            tmp.path().display(),
        );
        let cfg_file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(cfg_file.path(), content).await.unwrap();
        let cfg = WorkerConfig::load(cfg_file.path()).await.unwrap();

        let cancel = CancellationToken::new();
        let handle = spawn_sweeper(cfg, Arc::new(Mutex::new(HashSet::new())), cancel.clone());
        cancel.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("sweeper must exit promptly after cancel");
        assert!(joined.is_ok(), "sweeper task must not panic: {joined:?}");
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn tmp_domain_sweep_is_noop_on_non_linux() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join("var-tmp");
        let target = tmp_dir.join(".tmpAb12");
        for sub in ["upper", "work", "root"] {
            tokio::fs::create_dir_all(target.join(sub)).await.unwrap();
        }
        let cfg = config_with_domains(tmp.path(), &tmp_dir, &tmp.path().join("shm")).await;

        sweep_tmp_domains(&cfg).await;

        assert!(
            target.exists(),
            "非 Linux 上 tmp 域清扫必须整体跳过（无 /proc/mounts）"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tmp_domain_sweep_noop_on_empty_domains() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join("var-tmp");
        let shm_dir = tmp.path().join("shm");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
        tokio::fs::create_dir_all(&shm_dir).await.unwrap();
        let cfg = config_with_domains(tmp.path(), &tmp_dir, &shm_dir).await;

        sweep_tmp_domains(&cfg).await;

        assert!(tmp_dir.exists() && shm_dir.exists(), "空域 no-op，域根不删");
    }

    #[tokio::test]
    async fn tmp_domain_roots_append_engine_derived_root_and_dedup() {
        let tmp = tempfile::tempdir().unwrap();

        let cfg = config_with_domains(
            &tmp.path().join("crbs"),
            Path::new("/var/tmp"),
            Path::new("/dev/shm"),
        )
        .await;
        assert_eq!(
            tmp_domain_roots(&cfg),
            vec![
                std::path::PathBuf::from("/var/tmp"),
                std::path::PathBuf::from("/dev/shm"),
                tmp.path().join("crbs").join("tmp"),
            ]
        );

        let cfg = config_with_domains(
            Path::new("/var"),
            Path::new("/var/tmp"),
            Path::new("/dev/shm"),
        )
        .await;
        assert_eq!(
            tmp_domain_roots(&cfg),
            vec![
                std::path::PathBuf::from("/var/tmp"),
                std::path::PathBuf::from("/dev/shm")
            ],
            "派生域恰为显式 tmp_dir 时去重"
        );

        let cfg = config_with_domains(
            Path::new("/srv/crbs"),
            Path::new("/var/tmp"),
            Path::new("/srv/crbs/tmp"),
        )
        .await;
        assert_eq!(
            tmp_domain_roots(&cfg),
            vec![
                std::path::PathBuf::from("/var/tmp"),
                std::path::PathBuf::from("/srv/crbs/tmp")
            ],
            "派生域恰为显式 tmpfs_dir 时去重"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn tmp_domain_sweep_covers_engine_derived_crbs_root_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let crbs_root = tmp.path().join("crbs");
        let derived = crbs_root.join("tmp");
        let target = derived.join(".tmpDeriv");
        for sub in ["upper", "work", "root"] {
            tokio::fs::create_dir_all(target.join(sub)).await.unwrap();
        }
        backdate_mtime(&target);
        let cfg = config_with_domains(
            &crbs_root,
            &tmp.path().join("var-tmp"),
            &tmp.path().join("shm"),
        )
        .await;

        sweep_tmp_domains(&cfg).await;

        assert!(
            !target.exists(),
            "派生域 {} 下的残留必须被清扫",
            derived.display()
        );
    }

    async fn config_with_domains(
        crbs_root: &Path,
        tmp_dir: &Path,
        tmpfs_dir: &Path,
    ) -> WorkerConfig {
        let content = format!(
            "name = \"sweep-test\"\nhub_url = \"http://127.0.0.1:1\"\ntoken = \"t\"\n\
             build_dir = \"{}\"\ncrbs_root = \"{}\"\nresult_retention_days = 0\n\
             tmp_dir = \"{}\"\ntmpfs_dir = \"{}\"\n",
            crbs_root.join("builds").display(),
            crbs_root.display(),
            tmp_dir.display(),
            tmpfs_dir.display(),
        );
        let cfg_file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(cfg_file.path(), content).await.unwrap();
        WorkerConfig::load(cfg_file.path()).await.unwrap()
    }

    #[cfg(target_os = "linux")]
    async fn seed_building_row(store: &crbs_core::StateStore, crbs_pid: i64, started_at: &str) {
        let pool = store.pool();
        sqlx::query(
            "INSERT INTO tasks (product, pkg_name, phase) VALUES ('p', 'hello', 'building')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO builds (product, pkg_name, phase, task_id, crbs_pid, started_at) \
             VALUES ('p', 'hello', 'building', \
                     (SELECT id FROM tasks WHERE pkg_name = 'hello'), {crbs_pid}, {started_at})"
        ))
        .execute(pool)
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_gate_busy_when_active_assignment_registered() {
        let ids: ActiveBuildIds = Arc::new(Mutex::new(HashSet::from([7])));
        assert!(reclaim_gate_busy(&[], &ids).await);
        assert!(!reclaim_gate_busy(&[], &empty_active()).await);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_gate_busy_when_worker_db_has_building_row() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(&build_root).await.unwrap();
        let store = crbs_core::StateStore::new(&build_root).await.unwrap();
        seed_building_row(&store, std::process::id() as i64, "datetime('now')").await;

        assert!(
            reclaim_gate_busy(std::slice::from_ref(&store), &empty_active()).await,
            "活跃构建（pid 存活）的 building 行必须挡住回收门"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_gate_busy_when_recent_dead_pid_row() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(&build_root).await.unwrap();
        let store = crbs_core::StateStore::new(&build_root).await.unwrap();
        seed_building_row(&store, 999_999, "datetime('now')").await;

        assert!(
            reclaim_gate_busy(std::slice::from_ref(&store), &empty_active()).await,
            "未达僵尸阈值的近期 building 行必须保守挡门"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_round_repairs_zombie_rows_in_both_dbs() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join("var-tmp");
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
        tokio::fs::create_dir_all(&build_root).await.unwrap();
        let cfg = config_with_domains(tmp.path(), &tmp_dir, &tmp.path().join("shm")).await;

        let worker_store = crbs_core::StateStore::new(&build_root).await.unwrap();
        seed_building_row(&worker_store, 999_999, "datetime('now', '-60 minutes')").await;
        let engine_store = crbs_core::StateStore::new(std::path::Path::new(&cfg.crbs_root))
            .await
            .unwrap();
        seed_building_row(&engine_store, 999_999, "datetime('now', '-60 minutes')").await;
        drop(worker_store);
        drop(engine_store);

        reclaim_orphan_tmp_mounts(&cfg, &empty_active()).await;

        for reopen in [&build_root, std::path::Path::new(&cfg.crbs_root)] {
            let store = crbs_core::StateStore::new(reopen).await.unwrap();
            assert_eq!(
                store.count_building_builds().await.unwrap(),
                0,
                "两库的僵尸行都应被轮首修复标 failed: {}",
                reopen.display()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_round_does_not_create_missing_dbs() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join("var-tmp");
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();
        let cfg = config_with_domains(tmp.path(), &tmp_dir, &tmp.path().join("shm")).await;

        reclaim_orphan_tmp_mounts(&cfg, &empty_active()).await;

        assert!(
            !tmp.path().join("builds").join("crbs.db").exists(),
            "worker 本地库缺失时不得凭空创建"
        );
        assert!(
            !tmp.path().join("crbs.db").exists(),
            "crbs_root 库缺失时不得凭空创建"
        );
    }

    #[tokio::test]
    async fn latest_link_removed_when_pointing_at_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("pkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        let leaf = "20260825-010203-7";
        tokio::fs::symlink(leaf, pkg_dir.join("latest"))
            .await
            .unwrap();

        remove_latest_link_if_pointing(&pkg_dir, leaf).await;

        let meta = tokio::fs::symlink_metadata(pkg_dir.join("latest")).await;
        assert!(meta.is_err(), "latest 链必须已被删除");
        let leaked = globish_latest_gone(&pkg_dir).await;
        assert!(
            leaked.is_empty(),
            "不得残留 rename-aside 临时名: {leaked:?}"
        );
    }

    #[tokio::test]
    async fn latest_link_preserved_when_pointing_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("pkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        let new_leaf = "20260826-000000-9";
        tokio::fs::symlink(new_leaf, pkg_dir.join("latest"))
            .await
            .unwrap();

        remove_latest_link_if_pointing(&pkg_dir, "20260825-010203-7").await;

        assert!(
            tokio::fs::symlink_metadata(pkg_dir.join("latest"))
                .await
                .unwrap()
                .file_type()
                .is_symlink(),
            "指向他处的 latest 链必须保留"
        );
        assert_eq!(
            tokio::fs::read_link(pkg_dir.join("latest")).await.unwrap(),
            std::path::Path::new(new_leaf),
            "保留的 latest 指向不得被改变"
        );
        let leaked = globish_latest_gone(&pkg_dir).await;
        assert!(
            leaked.is_empty(),
            "不得残留 rename-aside 临时名: {leaked:?}"
        );
    }

    #[tokio::test]
    async fn latest_link_missing_is_silent_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("pkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();

        remove_latest_link_if_pointing(&pkg_dir, "20260825-010203-7").await;

        assert!(!pkg_dir.join("latest").exists());
        let leaked = globish_latest_gone(&pkg_dir).await;
        assert!(
            leaked.is_empty(),
            "不得残留 rename-aside 临时名: {leaked:?}"
        );
    }

    async fn globish_latest_gone(pkg_dir: &Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(pkg_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with(".latest.gone."))
                {
                    found.push(entry.path());
                }
            }
        }
        found
    }

    fn empty_active() -> ActiveBuildIds {
        Arc::new(Mutex::new(HashSet::new()))
    }

    fn backdate_mtime(dir: &Path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let old = filetime::FileTime::from_unix_time(now.as_secs() as i64 - 3600, 0);
        filetime::set_file_mtime(dir, old).unwrap();
    }
}
