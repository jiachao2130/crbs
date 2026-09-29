// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Worker 本地磁盘清理：结果目录按保留天数 + build_dir 崩溃残留 + tmp 域
//! `.tmpXXXX` 目录体清扫 + 本地 SQLite 行级 prune。结果布局
//! `{result_root}/{product}/{pkg}/{ts}-{build_id}/`（build_id 本地自增），
//! 正常路径 [`delete_build_result_dir`] 双成功后即时删除，sweeper 兜底残留。
//!
//! 已知边界（接受口径）：`crbs shell` 长会话不在活跃门控内（引擎 CLI 路径
//! 不落 building 行、不注册内存活跃集）；tempdir mtime 冻结使超 1h 会话的
//! tmp 域挂载满足回收候选形态，会被惰性卸载、目录体同轮清扫。会话锁
//! `{product_root}/.shell.lock`（共享 flock）位于产品树而非 tmp 域候选树内，
//! 回收侧无法在候选上探测，不做锁探测。影响面 = chroot 后端（挂载在宿主
//! 命名空间，/proc/mounts 可见）；nspawn 容器挂载在独立 mount namespace，
//! 宿主侧回收不影响运行中容器。受影响会话表现为环境内路径 ENOENT，退出
//! 重进即恢复（auto_init 重建）。

use std::collections::HashSet;
use std::path::{Component, Path};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::WorkerConfig;

/// sweeper 周期（小时）。
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// 下载目录清扫的 mtime 宽限：活跃复查（锁内 contains）→ remove 两步
/// TOCTOU 的兜底。assignment id 双方言自增不复用、重派产生新目录——复查
/// 是主防线，宽限只覆盖 id 复用 / 时钟异常；量级 10 分钟（下载目录生命
/// 周期小时级），仅启动清扫让刚领任务目录跳过首轮。
const DOWNLOAD_DIR_SWEEP_GRACE: Duration = Duration::from_secs(10 * 60);

/// tempfile 残留目录前缀：reproduce `tempfile::tempdir_in(build_dir)` 的
/// `.tmpXXXX` 崩溃后无人回收；`.latest.gone.*` 族在 pkg 目录，不在本范围。
const TEMPFILE_DIR_PREFIX: &str = ".tmp";

/// 本地 SQLite 行 prune 宽限天数：每 assignment 留一行 builds + 一条任务
/// 行，不删则无界增长（仅体积；本地行只服务构建期簿记，消费者最长按周）。
/// 只删 completed_at 非空终态行——崩溃 building 行永不动（engine/orphan.rs
/// 消费非终态行）。
const LOCAL_DB_PRUNE_GRACE_DAYS: u64 = 7;

/// 活跃 assignment id 集合（poller 执行中的 `task.assignment_id`，hub id 空间）。
/// 按 assignment 键控（同 assignment 至多一个执行）：reclaim 重派新旧执行各占
/// 一条目，先结束方 Drop 不夺走后结束方保护；Mutex 短临界区不跨 await。
pub(crate) type ActiveBuildIds = Arc<Mutex<HashSet<i64>>>;

/// 注册一个 assignment 进入活跃集合；Drop 时移除（panic 安全）。
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
    // build_dir/{assignment_id}/ 下载目录：崩溃残留兜底；逐条实时复查而非入口快照（见函数注释）。
    let build_root = std::path::PathBuf::from(&cfg.build_dir);
    sweep_build_download_dirs(&build_root, active_build_ids).await;

    // tmp 域孤儿挂载回收：崩溃构建遗留的仍挂载层惰性卸载（活跃门控 fail-closed），
    // 目录体由紧随其后的 tmp 域清扫同轮收走。
    reclaim_orphan_tmp_mounts(cfg, active_build_ids).await;

    // tmp 域 `.tmpXXXX` 目录体清扫：收走挂载被回收后的目录体（判定见
    // crbs_core::engine::tmp_sweep）。不做活跃门控——复扫 fail-closed 更精准。
    sweep_tmp_domains(cfg).await;

    // 本地 SQLite 行级 prune：终态超宽限 builds / childless tasks 行删除（与磁盘清扫独立）。
    prune_local_db_rows(&build_root).await;

    // 结果目录保留清扫（0 = 永久保留）。
    if cfg.result_retention_days > 0 {
        // 清扫根与引擎回退解析同源（worker 构造引擎 config 时 pin 同一
        // crbs_root，未配置 result_dir 即按 {crbs_root}/results 派生）；hub
        // 产品配置覆盖 result_dir 的目录不在本清扫范围。
        // 取舍：产品级 result_dir 覆盖不清扫；升级路径是收集引擎回报的
        // result root 列表逐根清扫。
        let cutoff = Duration::from_secs(cfg.result_retention_days.saturating_mul(86_400));
        sweep_result_dirs(
            &std::path::PathBuf::from(&cfg.crbs_root).join("results"),
            cutoff,
            active_build_ids,
        )
        .await;
    }
}

/// tmp 域扫描根全集：显式配置域（tmp_dir/tmpfs_dir，默认 /var/tmp、/dev/shm）
/// 加引擎派生域 `{crbs_root}/tmp`（引擎 tmp_dir 未显式配置时的 tempdir 落点，
/// 不补则全默认部署下磁盘形态 overlay 残留域扫不到）。字面路径去重：派生域
/// 与显式域重合时只扫一遍，显式域恒保留（不因去重丢失）。
/// 非 Linux 上 `sweep_tmp_domains` 的调用块被 cfg 整段编译掉，本函数只剩
/// 测试引用——dead_code 豁免仅限该平台（Linux 正常消费）。
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

/// tmp 域 `.tmpXXXX` 目录体清扫入口——扫 [`tmp_domain_roots`] 全集，config
/// 键语义须与部署的 crbs.toml 引擎配置一致（[`WorkerConfig::tmp_dir`]）。
/// 判定与删除委托 `crbs_core::engine::tmp_sweep`（删除走 `privilege::rm_rf_async`
/// 特权 rm-rf）；挂载表读 `/proc/mounts`，非 Linux 整体跳过（debug 留痕）。
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

/// tmp 域孤儿挂载回收：崩溃构建遗留的**仍挂载**层（tmp 域 `.tmp*` 内的
/// overlay / bind）若无周期回收会在共享节点上积累直至打满 tmpfs（手动
/// `crbs gc --orphan-mounts` 保留为兜底）。本轮对超宽限 + 布局签名吻合 +
/// 有挂载引用的候选惰性卸载（MNT_DETACH 经特权层），目录体交紧随其后的
/// [`sweep_tmp_domains`] 同轮清除。判定与卸载委托
/// `crbs_core::engine::tmp_sweep::umount_orphan_tmp_mounts`（回收域全集、
/// umount 域预过滤、双重形态校验、深度倒序、卸载后复扫确认，见其文档）；
/// allowed_roots 传 crbs_root（部署 priv-helper.toml allowed_paths 的功能
/// 不变量成员）；非 Linux 整体跳过。
///
/// 活跃门控（既有 orphan 判定口径，绝不卸载活跃构建的挂载）：内存活跃
/// assignment 集（覆盖记录落库前的执行窗口）+ 本机两个状态库——worker 本地
/// `{build_dir}/crbs.db` 与引擎 CLI 的 `{crbs_root}/crbs.db`（均仅当库文件
/// 已存在才打开，不凭空建库）——先做一轮僵尸修复（超时 + pid 已死的 building
/// 记录标 failed，不修则死 pid 行永久挡门），回收循环内再实时查 building 计数：
/// 任一非零或查询失败 = busy 跳过（fail-closed）。两库的 crbs_pid 都是本机
/// 进程，pid 存活判定在本节点有效；门控实时查询把"放行 → 新构建建挂载 → 被
/// 卸载"竞态压到毫秒级（`crbs gc --orphan-mounts` post_scan_guard 同口径）。
/// shell 会话不落 building 行，边界口径见模块文档。
async fn reclaim_orphan_tmp_mounts(cfg: &WorkerConfig, active: &ActiveBuildIds) {
    #[cfg(target_os = "linux")]
    {
        let Some(stores) = open_gate_stores(cfg).await else {
            return;
        };

        // 僵尸修复（round 级一次）：死 pid 的超时 building 记录标 failed，否则
        // 永久令门控命中、回收饿死（与 gc --orphan-mounts 同一修复口径）。
        for store in &stores {
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

/// 孤儿挂载回收的活跃门控（真实查询，回收循环内对每个挂载候选实时调用）：
/// 内存活跃 assignment 集非空，或任一状态库仍有 building 记录（含未达僵尸
/// 阈值的近期崩溃行——保守挡门），或查询失败 → busy（fail-closed）。
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

/// 打开活跃门控用状态库：worker 本地（`{build_dir}/crbs.db`）+ 引擎 CLI
/// （`{crbs_root}/crbs.db`，仅当库文件已存在——不凭空建库）。任一库存在但
/// 打不开：无法判定构建活跃性，返回 `None`（整轮跳过，fail-closed）。
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

/// 清扫 `build_root` 下两类崩溃残留目录（共用 mtime 宽限与隔离断言，
/// 见 [`remove_stale_download_dir`]）：
///
/// 1. 纯数字目录（`{assignment_id}/` 下载暂存）：启动时活跃集合为空 → 全清；
///    运行期排除活跃 assignment（数字判定天然兼容历史 build_id 命名残留）。
///    须逐条实时加锁复查（guard 注册先于目录创建，锁内 contains 可见）：
///    入口快照与"领任务→插入→目录创建"竞态会删掉重派构建的新目录。
/// 2. `.tmp` 前缀目录（reproduce tempfile 崩溃残留）：无 assignment 归属，
///    仅 mtime 宽限。
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
        // 锁内实时复查（std::sync::Mutex 不跨 await：临界区只有 contains）。
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

/// 删除 build_dir 下超过 mtime 宽限的残留目录（数字目录与 `.tmp` 共用），
/// 返回是否已删除。隔离断言用组件级判定（[`crate::executor::dir_strictly_under_root`]
/// ——`starts_with` 放行 `../` 逃逸）：目标严格位于 `build_root` 之下且不等
/// 于其本身；非目录条目不删（`.tmp` 前缀只按名字判定，可能撞上文件）。
/// 宽限内不删；metadata 失败按新鲜处理；NotFound = 已被并发方回收。
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

/// prune 本地 SQLite（`{build_root}/crbs.db`）的终态旧行（背景见
/// [`LOCAL_DB_PRUNE_GRACE_DAYS`]）。库不存在时静默跳过（不凭空建库）；
/// 失败仅 warn，下轮自然重试。
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

/// 判断目录名是否为引擎结果叶子 `{ts}-{build_id}`（ts 为 `%Y%m%d-%H%M%S`）。
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
    // ts 完整帧 15 字符（YYYYMMDD-HHMMSS，引擎写侧恒 `%Y%m%d-%H%M%S`）；
    // 判非叶子 = 不识别不删（保守侧）。
    ts.len() >= 15 && id.parse::<i64>().is_ok()
}

/// 清扫结果根下超过保留期的构建叶子目录：布局
/// `{result_root}/{product}/{pkg}/{ts}-{build_id}/`，叶子层判定名称形态 +
/// mtime 超 `cutoff`，逐层 under-root 断言。
///
/// 活跃 assignment 非空时整轮跳过：叶子后缀是引擎本地 build id，与活跃集合
/// 的 hub assignment_id 不同 id 空间无法逐叶排除，且 mtime 判活有盲区——
/// hang 构建静默超 retention 会被 mid-build 删除；整轮跳过误删面压到零。
///
/// 饿死上界（已知代价）：饱和 worker 下可连续跳过、失败残留无界累积。
/// 升级路径：按活跃构建启动时的本地 build id 做排除集强扫。
async fn sweep_result_dirs(result_root: &Path, cutoff: Duration, active: &ActiveBuildIds) {
    // std::sync::Mutex 短临界区（is_empty），不跨 await。
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
        // 一级目录：产品名。跳过 `latest` 软链与非目录。
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
            // 二级目录：包名。
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
                // 三级：{ts}-{build_id} 叶子。
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
                // staleness 口径见 [`leaf_staleness`]：优先 build.log mtime（append 只刷文件 mtime）。
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
                        // 叶子被清后回收仍指向它的 `latest` 软链（见 helper 注释）。
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

/// 叶子 staleness 信号：优先目录内 `build.log` mtime（活跃构建持续 append
/// 时是新鲜度真值），无则回退目录 mtime；metadata 失败返回 None（按不过期）。
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

/// 删除单个构建的结果目录（上传 + 终态上报双成功后的即时回收）。路径来自
/// 引擎自有产出（非外部输入，断言是纵深防御）：`result_dir` 须恰为
/// `result_root` 下第三级 `{product}/{pkg}/{leaf}`（剩余组件恰 3 个全
/// Normal）、叶子名后缀匹配本次引擎 build id——绝不触及 pkg/产品/根本身。
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
    // 词法断言：恰为 root 下第三级，无 `..`/`.`/绝对逃逸。
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
            // 引擎维护 latest → 本次叶子的 advisory 软链；按目标精确回收（其它不动）。
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

/// 删除 `pkg_dir/latest` 软链，仅当它指向 `leaf_name`（相对目标）；指向
/// 其它叶子或不存在时 no-op。朴素 read_link → remove 两步间，同包并发新
/// 构建可 rename 覆盖 `latest` 指向新叶子而被误删——改用 rename-aside：
/// 1. `latest` rename 到 `.latest.gone.{leaf_name}`（含 build_id 命名空间
///    隔离，此后并发 rename 覆盖的是原名位，互不相扰）；
/// 2. 对临时名 read_link 校验：指向本叶子 → remove；否则 rename 回原名
///    （保持并发方刚写入的指向）。
///
/// 首步 rename NotFound 属正常（链已被并发方删走）；advisory 链失败仅告警。
async fn remove_latest_link_if_pointing(pkg_dir: &Path, leaf_name: &str) {
    let latest = pkg_dir.join("latest");
    let aside = pkg_dir.join(format!(".latest.gone.{leaf_name}"));
    // 崩溃残留接受：rename 后校验/放回前崩溃会留 `.latest.gone.*`（仅占 inode，不清理）。
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
            // 校验不通过：放回原名，不误删并发方刚覆盖的新链。放回仍有 µs 级
            // 窗口可能覆盖并发方刚写入的新链——advisory 链下次构建自愈，接受。
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

    /// build_dir 清扫：数字目录被删、活跃 assignment 与非数字条目保留（待删目录须回拨 mtime 超宽限）。
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

    /// mtime 宽限：新鲜目录即使不在活跃集合也不删（见
    /// DOWNLOAD_DIR_SWEEP_GRACE）；回拨超宽限后恢复清扫。
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

    /// build_dir 不存在时 no-op。
    #[tokio::test]
    async fn build_dir_sweep_noop_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        sweep_build_download_dirs(
            &tmp.path().join("none"),
            &Arc::new(Mutex::new(HashSet::new())),
        )
        .await;
    }

    /// 本地库行 prune——终态超期 builds 行（连带 childless 任务行）
    /// 被删，近期终态、非终态（building）与 completed_at NULL 的终态行保留。
    #[tokio::test]
    async fn local_db_prune_removes_old_terminal_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        let store = crbs_core::StateStore::new(&build_root).await.unwrap();
        let pool = store.pool();

        // 本地任务行（builds.task_id NOT NULL）+ 子构建：t1/b1 超期终态
        //（删，任务行 childless 一并删）；t2/b2 近期终态与 t3/b3 超期 building
        // 留；t1/b4 超期终态但 completed_at NULL（留，t1 仍被引用 → 任务行也留）。
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

    /// 本地库不存在（fresh build_dir）时 no-op，且不凭空建库。
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

    /// tempfile 残留（`.tmp` 前缀）：超宽限被清、宽限内保留。
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

    /// `.tmp` 前缀边界：同前缀的文件不删；非 `.tmp` 点目录与数字目录不变。
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

    /// 清扫直接消费共享活跃集合（实时锁内判活），guard 存活期间其下载目录
    /// 保留。单线程无法构造真交错，竞态消除依赖逐条实时复查的实现本身。
    #[tokio::test]
    async fn build_dir_sweep_rechecks_active_set_per_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let build_root = tmp.path().join("builds");
        tokio::fs::create_dir_all(build_root.join("1001"))
            .await
            .unwrap();
        let active: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));

        // poller 同款注册路径：guard 存活 = assignment 在途（注册先于下载目录创建）。
        let _guard = ActiveBuildGuard::new(active.clone(), 1001);
        sweep_build_download_dirs(&build_root, &active).await;
        assert!(
            build_root.join("1001").exists(),
            "guard 存活期间清扫必须实时看见活跃 assignment"
        );
    }

    /// 结果清扫：cutoff=0 删掉叶子；非叶子形态与浅层目录（产品/包目录）不删。
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

    /// 活跃 assignment 非空时整轮跳过——mtime 判活盲区（hang 构建静默超
    /// retention）下只有不扫才不误删。
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

    /// 结果清扫：cutoff 很大（远未过期）时叶子保留。
    #[tokio::test]
    async fn result_sweep_keeps_fresh_leaves() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();

        sweep_result_dirs(&root, Duration::from_secs(3600 * 24 * 365), &empty_active()).await;

        assert!(leaf.exists(), "未过保留期的叶子必须保留");
    }

    /// staleness 优先 build.log mtime：构造"目录 mtime 已超 cutoff、
    /// build.log 刚 append"——活跃结果目录不得按目录 mtime 被 mid-build 删除。
    #[tokio::test]
    async fn result_sweep_freshness_prefers_build_log_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let leaf = root.join("prod").join("pkg").join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();
        // 建文件后目录 mtime 停在创建时刻；此后仅 append。
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

        // cutoff=1s：目录 mtime 已过期，build.log 刚写（新鲜）。
        sweep_result_dirs(&root, Duration::from_secs(1), &empty_active()).await;

        assert!(
            leaf.exists(),
            "build.log 仍活跃（刚 append）的结果目录不得按目录 mtime 误删"
        );
    }

    /// 即时删除：合法叶子被删，指向它的 `latest` 软链一并回收，指向其它
    /// 叶子的不动（dangling 判定用 symlink_metadata，exists() 会跟随目标）。
    #[tokio::test]
    async fn delete_result_dir_removes_matching_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let pkg_dir = root.join("prod").join("pkg");
        let leaf = pkg_dir.join("20260825-010203-7");
        tokio::fs::create_dir_all(&leaf).await.unwrap();
        // 引擎同款 advisory 链接：latest → 本次叶子；另一条指向别的叶子。
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

    /// 即时删除的安全护栏：后缀不匹配 / 遍历组件 / 浅层或过深目录 /
    /// 结果根本身 → 拒绝删除。
    #[tokio::test]
    async fn delete_result_dir_refuses_mismatched_or_shallow_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("results");
        let other_leaf = root.join("prod").join("pkg").join("20260825-010203-8");
        tokio::fs::create_dir_all(&other_leaf).await.unwrap();
        delete_build_result_dir(&other_leaf, 7, &root).await;
        assert!(other_leaf.exists(), "build id 不匹配的叶子必须保留");

        // 含 .. 的路径 → strip_prefix 剩余组件含 ParentDir → 拒绝。
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

    /// ActiveBuildGuard：注册 + Drop 移除（panic 安全由 Drop 保证）。
    #[tokio::test]
    async fn active_build_guard_tracks_lifecycle() {
        let ids: ActiveBuildIds = Arc::new(Mutex::new(HashSet::new()));
        {
            let _g = ActiveBuildGuard::new(ids.clone(), 42);
            assert!(ids.lock().unwrap().contains(&42));
        }
        assert!(!ids.lock().unwrap().contains(&42));
    }

    /// 叶子名判定：合法形态通过，畸形形态拒绝。
    #[test]
    fn is_engine_result_leaf_accepts_only_engine_layout() {
        assert!(is_engine_result_leaf("20260825-010203-7"));
        assert!(is_engine_result_leaf("20260825-010203-12345"));
        assert!(!is_engine_result_leaf("7"));
        assert!(!is_engine_result_leaf("-7"));
        assert!(!is_engine_result_leaf("20260825-010203-"));
        assert!(!is_engine_result_leaf("20260825-010203-x7"));
        assert!(!is_engine_result_leaf("latest"));
        // ts 不足完整 15 字符帧（日期无时间部分）不是引擎叶子。
        assert!(!is_engine_result_leaf("20260825-7"));
        assert!(!is_engine_result_leaf("20260825-0102-7"));
    }

    /// sweeper 对 CancellationToken 感知：cancel 后须有界时间内正常退出
    ///（shutdown 有界 join 前提）；首 tick 空域 no-op。macOS 可跑、无特权。
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

    /// tmp 域清扫接线：非 Linux 整体跳过——域内残留目录体原样保留、不报错；
    /// Linux 判定逻辑归 crbs-core tmp_sweep 测试，此处只锚定跳过语义。
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

    /// tmp 域清扫接线（Linux）：真实 /proc/mounts 上空域 no-op；判定路径归 crbs-core 测试。
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

    /// tmp 域扫描根：显式两域恒在，引擎派生域 `{crbs_root}/tmp` 追加在后；
    /// 派生域与显式域字面重合时去重不重复（对齐 tmp_dir 与 tmpfs_dir 两臂）。
    #[tokio::test]
    async fn tmp_domain_roots_append_engine_derived_root_and_dedup() {
        let tmp = tempfile::tempdir().unwrap();
        // 全默认形态：worker tmp_dir 默认 /var/tmp，引擎 tmp_dir 未显式配置时
        // 派生为 {crbs_root}/tmp——两域须同扫。
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

        // 派生域恰为显式 tmpfs_dir（crbs_root = /srv/crbs → 派生 /srv/crbs/tmp）。
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

    /// 引擎派生域 `{crbs_root}/tmp` 内的崩溃残留（全默认部署的 overlay 残留
    /// 落点）被目录体清扫收走——tmp_dir 显式域之外不漏扫的回归锚。
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

    /// 构造自定义 crbs_root/tmp_dir/tmpfs_dir 的 WorkerConfig（测试辅助）。
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

    // ─── 孤儿挂载回收接线（活跃门控）───

    /// 门控用 building 行播种（task_id NOT NULL：先插任务行）。
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

    /// 门控：内存活跃 assignment 集非空 → busy（覆盖记录落库前的执行窗口）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reclaim_gate_busy_when_active_assignment_registered() {
        let ids: ActiveBuildIds = Arc::new(Mutex::new(HashSet::from([7])));
        assert!(reclaim_gate_busy(&[], &ids).await);
        assert!(!reclaim_gate_busy(&[], &empty_active()).await);
    }

    /// 门控：worker 本地库有 building 行（pid 存活的活跃构建）→ busy。
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

    /// 门控：近期崩溃行（pid 已死但未达僵尸阈值）保守挡门——僵尸修复不碰它，
    /// 计数仍 > 0；回收等下一轮（修复生效后放行）。
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

    /// 回收轮接线：轮首僵尸修复把"超时 + pid 已死"的 building 行标 failed，
    /// 此后门控放行；crbs_root 库（引擎 CLI 世界，存在才检查）同样被修复。
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

    /// 回收轮不凭空建库：两库都不存在时整轮门控零库放行，且不得在 build_dir /
    /// crbs_root 留下新建的 crbs.db（"不凭空建库"不变量）。
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

    // ─── remove_latest_link_if_pointing（rename-aside）───

    /// latest 指向本叶子：链被删除，且不留 `.latest.gone.*` 临时残留。
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

    /// latest 指向其它叶子（并发新链）：不得误删，原名仍在位且指向不变。
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

    /// latest 不存在：静默 no-op（不报错、不留临时文件）。
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

    /// 列出 pkg_dir 下残留的 `.latest.gone.*` 临时条目（测试辅助）。
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

    /// 空活跃集合（测试辅助）：全局空闲语义。
    fn empty_active() -> ActiveBuildIds {
        Arc::new(Mutex::new(HashSet::new()))
    }

    /// 把目录 mtime 回拨 1 小时（filetime dev-dep），跨过清扫宽限。
    fn backdate_mtime(dir: &Path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let old = filetime::FileTime::from_unix_time(now.as_secs() as i64 - 3600, 0);
        filetime::set_file_mtime(dir, old).unwrap();
    }
}
