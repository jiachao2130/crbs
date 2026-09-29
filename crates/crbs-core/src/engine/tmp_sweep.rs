// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! tmp 域 `.tmpXXXX` 目录体清扫与孤儿挂载回收。
//!
//! 对象是 tmp_dir/tmpfs_dir（默认 /var/tmp、/dev/shm；worker sweeper 另加引擎
//! 派生域 `{crbs_root}/tmp`）下崩溃残留的 crbs tempdir：形态 A = overlay 构建
//! 目录（`prepare` tempdir），形态 A2 = 全内存构建目录（tempdir 内 memroot，
//! 其下布局同形态 A），形态 B = reproduce 临时 repo
//!（`cache::restore_packages_to_repo` tempdir）；C 形态与空目录留观。引擎 GC/umount
//! 只卸载不删体，删除由本模块独立窄门承担（worker sweeper 周期调用）。
//!
//! 三重守卫（全过才删，宁可 under-clean——共享目录误删三方数据不可接受）：
//! 布局签名 [`tmp_residue_signature`]、mtime 宽限 [`TMP_SWEEP_GRACE`]、
//! 挂载复扫 fail-closed（见 [`sweep_tmp_domain`]；从不 umount）。
//!
//! 孤儿挂载（[`umount_orphan_tmp_mounts`]）：超宽限 + 签名吻合 + 有挂载引用且活跃
//! 门控放行才 MNT_DETACH 卸载，目录体交回 [`sweep_tmp_domain`] 同轮清除；
//! `crbs gc --orphan-mounts` 为手动兜底。非 Linux 无 /proc/mounts，调用方整体跳过。

use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::{info, warn};

use crate::engine::orphan;

/// Linux 挂载表路径：生产清扫传给 [`sweep_tmp_domain`]，测试注入替代文件（orphan 同先例）。
#[cfg(target_os = "linux")]
pub const PROC_MOUNTS: &str = "/proc/mounts";

/// tmp 域目录体清扫的 mtime 宽限：1 小时。共享系统目录（/var/tmp、/dev/shm）
/// 下三方 tempfile 与 crbs 残留混居，宽限是防误删第一道时间窗；而 tempdir
/// 自身 mtime 冻结在最后一次条目增删，长构建（>1h）的活跃 tempdir 也能过
/// 宽限——活跃目标由挂载复扫兜住，宽限只防时钟异常 / 未知并发写入者。
pub const TMP_SWEEP_GRACE: Duration = Duration::from_secs(3600);

/// tempfile 默认临时目录命名前缀（`tempfile::tempdir_in` 产生 `.tmpXXXX`）。
/// `.tmp` 非 crbs 专属——三方 tempdir 同前缀——故须布局签名守卫。
const TEMPDIR_PREFIX: &str = ".tmp";

/// tmp 域目录体的布局签名分类（[`tmp_residue_signature`] 的判定结果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TmpResidueKind {
    /// 形态 A：overlay 构建目录——恰含 `upper/`、`work/`、`root/` 三个子目录
    /// （engine `prepare` tempdir 的完整布局），或恰含 `upper/`、`work/` 两个
    /// （root 建成前即崩溃的中断态）；GB 级残留主体。
    Overlay,
    /// 形态 A2：全内存构建目录——tempdir 恰含 `memroot/` 一个子目录，且其内
    /// 恰含 `upper/`、`work/` 两个子目录（root 建成前即崩溃的中断态）或再加
    /// `root/` 三个（完整布局）。memroot 是 `setup_overlay` 在 tempdir 内挂载
    /// 的构建专属 tmpfs 实例；崩溃时目录体与挂载可能同时残留。
    Memroot,
    /// 形态 B：reproduce 临时 repo——**恰**含 `Packages/` 与 `repodata/`
    /// 两个子目录，且 `repodata/repomd.xml` 是常规文件（createrepo_c 布局）。
    TempRepo,
}

/// 判定 tmp 域下一个目录的布局签名，三形态之外一律返回 `None`（对应 engine
/// 的 `tempdir_in` 调用点）：
/// - 形态 A（[`TmpResidueKind::Overlay`]）：**恰**含 `upper/`、`work/`、
///   `root/` 三个子目录，或**恰**含 `upper/`、`work/` 两个：两件套是
///   `setup_overlay` 建序 upper→work→root 中 root 建成前即崩溃的中断态
///   （root 缺失 = overlay 从未挂载、构建未开始，无用户数据可保）。两种布局
///   都是多出任何条目、缺一、任一实为文件就不认；
/// - 形态 A2（[`TmpResidueKind::Memroot`]）：**恰**含一个 `memroot/` 子目录，
///   且其内恰为形态 A 的 upper+work 两件套或 upper+work+root 三件套（全内存
///   构建 tempdir 的完整布局与中断态）。memroot 为空（挂载创建前后极短窗口）
///   不认：无内容可鉴别，留启动 GC 兜底；
/// - 形态 B（[`TmpResidueKind::TempRepo`]）：**恰**含 `Packages/` 与
///   `repodata/` 两个子目录，且 `repodata/repomd.xml` 是常规文件
///   （symlink_metadata 不跟随，symlink 冒名不认）。恰两条目零覆盖损失：
///   ISO 解包/reposync 输出顶层条目通常更多，包含式匹配会误删三方数据。
///
/// 其余（空目录、C 形态、杂物、遍历出错）一律 `None`：宁可 under-clean
///（fail-closed：读不全就不认），误删共享系统目录下三方数据不可接受。
pub async fn tmp_residue_signature(dir: &std::path::Path) -> Option<TmpResidueKind> {
    let entries = read_dir_entries(dir).await?;

    if entries_match(&entries, &["upper", "work"])
        || entries_match(&entries, &["upper", "work", "root"])
    {
        return Some(TmpResidueKind::Overlay);
    }

    // 形态 A2：memroot 必须是唯一顶层条目且为真实目录；其内布局与形态 A 同判。
    if let [(name, true)] = entries.as_slice() {
        if name == "memroot" {
            let inner = read_dir_entries(&dir.join("memroot")).await?;
            if entries_match(&inner, &["upper", "work"])
                || entries_match(&inner, &["upper", "work", "root"])
            {
                return Some(TmpResidueKind::Memroot);
            }
        }
    }

    if entries.len() == 2
        && entries.iter().all(|(name, is_dir)| {
            matches!(
                (name.as_str(), *is_dir),
                ("Packages", true) | ("repodata", true)
            )
        })
        && tokio::fs::symlink_metadata(dir.join("repodata").join("repomd.xml"))
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
    {
        return Some(TmpResidueKind::TempRepo);
    }

    None
}

/// 读取一层目录条目（lossy 名 + 是否目录）；读取或类型探测失败返回 `None`
///（fail-closed：读不全就不认）。
async fn read_dir_entries(dir: &Path) -> Option<Vec<(String, bool)>> {
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    // 非 UTF-8 名以 lossy 参与条目计数——匹配不到已知名，算作多余条目。
    let mut entries: Vec<(String, bool)> = Vec::new();
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => return None,
        };
        let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
        entries.push((entry.file_name().to_string_lossy().into_owned(), is_dir));
    }
    Some(entries)
}

/// 条目集是否恰为 `wanted` 且全为目录：read_dir 无重名，"恰定长 + 全为集合成员"
/// 即恰集合。
fn entries_match(entries: &[(String, bool)], wanted: &[&str]) -> bool {
    entries.len() == wanted.len()
        && entries
            .iter()
            .all(|(name, is_dir)| *is_dir && wanted.contains(&name.as_str()))
}

/// 一轮 tmp 域清扫的汇总统计（随 [`sweep_tmp_domain`] 返回并进 info 日志）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepStats {
    /// 候选数：tmp_root 下 `.tmp` 前缀的一级真实目录（symlink 不算）。
    pub scanned: usize,
    /// 实际删除的目录数。
    pub removed: usize,
    /// 删除失败数（仅 warn，下轮重试）。
    pub failed: usize,
    /// 跳过：mtime 未满宽限，或 metadata 不可得（按新鲜处理）。
    pub skipped_fresh: usize,
    /// 跳过：布局签名不认（C 形态 / 空目录 / 杂物 / 遍历出错）。
    pub skipped_no_signature: usize,
    /// 跳过：挂载复扫发现目标被引用（挂载点 / bind source / 选项路径任一）。
    pub skipped_mounted: usize,
    /// 跳过：mounts 文件读取/解析失败（fail-closed）。
    pub skipped_mount_scan_error: usize,
}

/// 读 tmp 域根目录：`NotFound` 静默（tmpfs 未挂载 / 尚无构建属正常），其余
/// 错误 warn 后按 None 跳过该根（`ctx` 标注调用场景进日志）。
async fn read_tmp_domain_root(root: &Path, ctx: &str) -> Option<tokio::fs::ReadDir> {
    match tokio::fs::read_dir(root).await {
        Ok(rd) => Some(rd),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(
                root = %root.display(),
                error = %e,
                "Failed to read tmp domain root for {ctx}; skipping root"
            );
            None
        }
    }
}

/// 目录迭代单步：错误 warn 后按 None 结束该根遍历（跳过剩余，`ctx` 标注场景）。
async fn next_tmp_entry(
    rd: &mut tokio::fs::ReadDir,
    root: &Path,
    ctx: &str,
) -> Option<tokio::fs::DirEntry> {
    match rd.next_entry().await {
        Ok(Some(e)) => Some(e),
        Ok(None) => None,
        Err(e) => {
            warn!(
                root = %root.display(),
                error = %e,
                "Failed to iterate tmp domain root during {ctx}; skipping rest"
            );
            None
        }
    }
}

/// `.tmp` 前缀一级真实目录候选：返回文件名（UTF-8）。symlink 不跟随
///（file_type 不解引用），非前缀或非目录返回 None。
async fn tmp_dir_candidate_name(entry: &tokio::fs::DirEntry) -> Option<String> {
    let file_name = entry.file_name();
    let name = file_name.to_str()?;
    if !name.starts_with(TEMPDIR_PREFIX) {
        return None;
    }
    let is_dir = entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
    is_dir.then(|| name.to_string())
}

/// mtime 宽限判定：修改时间不可得按新鲜处理（宁可不清理也不误删）。
async fn entry_past_grace(entry: &tokio::fs::DirEntry, grace: Duration) -> bool {
    match entry.metadata().await {
        Ok(meta) => meta
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|age| age >= grace)
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// 清扫 tmp 域（tmp_dir/tmpfs_dir）下挂载已消失的 `.tmpXXXX` 目录体残留：
/// 每个 `tmp_root` 只看**一级**子目录中 `.tmp` 前缀的真实目录（symlink 不
/// 跟随出域），依次过三重守卫（模块文档）：宽限 → 布局签名 → 隔离断言 →
/// 挂载复扫 → 特权删除（`remover`）。
///
/// 复扫的竞态论证（第三道守卫的安全前提）：引擎从不复用旧 tempdir（tempfile
/// 随机后缀），新构建挂载必落新目录——复扫在超宽限目标上发现的引用只能是
/// 崩溃构建的孤儿挂载（跳过，留启动 GC / 每构建 init 回收）或仍活跃的长
/// 构建（tempdir mtime 冻结使宽限失效）；引用形态见 `mount_references_target`，
/// 复扫与删除间的残余 TOCTOU 按此论证不可达。本函数从不 umount。
///
/// fail-closed：`read_dir` 失败整根跳过；mounts 扫描失败跳过该目标；删除
/// 失败仅 warn 下轮重试。`mounts_file` 测试可注入，生产传 [`PROC_MOUNTS`]；
/// `remover` 生产传 `privilege::rm_rf_async`（非 root 删 root 属主残留必
/// EPERM）。
pub async fn sweep_tmp_domain<R, Fut>(
    tmp_roots: &[PathBuf],
    mounts_file: &str,
    grace: Duration,
    remover: R,
) -> SweepStats
where
    R: Fn(PathBuf) -> Fut,
    Fut: std::future::Future<Output = crate::Result<()>>,
{
    let mut stats = SweepStats::default();

    for tmp_root in tmp_roots {
        let Some(mut rd) = read_tmp_domain_root(tmp_root, "sweep").await else {
            continue;
        };
        loop {
            let Some(entry) = next_tmp_entry(&mut rd, tmp_root, "sweep").await else {
                break;
            };
            // 只认 `.tmp` 前缀一级真实目录；symlink 不跟随（file_type 不解引用）。
            let Some(name) = tmp_dir_candidate_name(&entry).await else {
                continue;
            };

            stats.scanned += 1;
            let target = tmp_root.join(&name);

            // 守卫一：mtime 宽限；不可得按新鲜处理（宁可不清理也不误删）。
            if !entry_past_grace(&entry, grace).await {
                stats.skipped_fresh += 1;
                continue;
            }

            // 守卫二：布局签名（C 形态 / 空目录 / 杂物在此被拒）。
            let Some(kind) = tmp_residue_signature(&target).await else {
                stats.skipped_no_signature += 1;
                continue;
            };

            // 隔离断言：目标严格位于 tmp_root 之下且不等于 tmp_root 本身（纵深防御）。
            if !crate::util::strictly_within(&target, tmp_root) {
                warn!(
                    target = %target.display(),
                    root = %tmp_root.display(),
                    "Tmp domain sweep target failed isolation assertion; refusing to remove"
                );
                continue;
            }

            // 守卫三：挂载复扫 fail-closed——任一引用即跳过（竞态论证见函数文档）。
            match mount_references_target(mounts_file, &target).await {
                Ok(true) => {
                    stats.skipped_mounted += 1;
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    stats.skipped_mount_scan_error += 1;
                    warn!(
                        target = %target.display(),
                        error = %e,
                        "Failed to scan mounts for tmp sweep target; skipping (fail-closed)"
                    );
                    continue;
                }
            }

            match remover(target.clone()).await {
                Ok(()) => {
                    stats.removed += 1;
                    info!(
                        path = %target.display(),
                        kind = ?kind,
                        "Swept orphaned crbs tempdir body under tmp domain"
                    );
                }
                Err(e) => {
                    stats.failed += 1;
                    warn!(
                        path = %target.display(),
                        error = %e,
                        "Failed to remove orphaned crbs tempdir body; will retry next round"
                    );
                }
            }
        }
    }

    info!(
        roots = ?tmp_roots,
        scanned = stats.scanned,
        removed = stats.removed,
        failed = stats.failed,
        skipped_fresh = stats.skipped_fresh,
        skipped_no_signature = stats.skipped_no_signature,
        skipped_mounted = stats.skipped_mounted,
        skipped_mount_scan_error = stats.skipped_mount_scan_error,
        "Tmp domain tempdir body sweep finished"
    );
    stats
}

/// 一轮孤儿挂载回收的汇总统计（随 [`umount_orphan_tmp_mounts`] 返回并进 info 日志）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OrphanReclaimStats {
    /// 候选数：tmp_root 下 `.tmp` 前缀的一级真实目录（与 [`SweepStats::scanned`] 同口径）。
    pub scanned: usize,
    /// 超宽限 + 签名吻合且有挂载引用的候选数（回收对象全集）。
    pub mounted_candidates: usize,
    /// 完成惰性卸载且复扫确认引用清零的候选数（目录体由后续 [`sweep_tmp_domain`] 清除）。
    pub reclaimed: usize,
    /// 卸载失败或卸载后复扫仍有引用（warn，下轮重试）。
    pub umount_failed: usize,
    /// 跳过：活跃门控命中（存在非终态构建——绝不卸载活跃构建的挂载）。
    pub skipped_busy: usize,
    /// 跳过：mounts 文件读取/解析或目标 canonicalize 失败（fail-closed）。
    pub skipped_mount_scan_error: usize,
}

/// 回收 tmp 域下崩溃构建遗留的**仍挂载**目录体上的孤儿挂载。
///
/// - 候选：过宽限 + 布局签名 + 隔离断言的 `.tmp*`；mounts 表任一行（挂载点 /
///   bind source / 选项路径）落入目标之下即视为引用（同 `mount_references_target`）。
/// - 卸载：挂载点按深度倒序 MNT_DETACH（`umounter` 注入，生产传
///   `privilege::umount_detach`）；复扫确认引用清零才计成功，目录体不动，
///   由调用方紧随的 [`sweep_tmp_domain`] 清除。
/// - 活跃门控（安全核心）：每个有引用的候选都**实时**调用 `activity_busy`，
///   返回 true 即跳过；调用方按 orphan 判定口径实现（worker sweeper：内存活跃
///   assignment + 僵尸修复后 building 计数，任一非零/查询失败 = busy，fail-closed）。
///   门控后毫秒级竞态窗口与 `crbs gc --orphan-mounts` 的 post_scan_guard 同口径
///   （构建记录先于首个挂载创建，查到 0 时新挂载尚不存在）。
/// - 误卸防线：布局签名 + 挂载引用 + mtime 宽限 + 隔离断言，守卫集与目录体清扫
///   对齐；卸载失败仅 warn，下轮重试（24h 周期即退避）。
/// - umount 域预过滤：`allowed_roots` 为调用方卸载允许根（worker 传 crbs_root，
///   与 priv-helper.toml allowed_paths 对齐）；域外挂载点不进卸载列表，消除永续
///   拒绝 warn；域外引用由卸载后复扫与目录体清扫守卫三识别（fail-closed 保体），
///   残留交人工 `crbs gc --orphan-mounts`。
/// - `mounts_file` 测试可注入，生产传 [`PROC_MOUNTS`]。
pub async fn umount_orphan_tmp_mounts<G, FutG, U, FutU>(
    tmp_roots: &[PathBuf],
    mounts_file: &str,
    grace: Duration,
    allowed_roots: &[PathBuf],
    activity_busy: G,
    umounter: U,
) -> OrphanReclaimStats
where
    G: Fn() -> FutG,
    FutG: std::future::Future<Output = bool>,
    U: Fn(PathBuf) -> FutU,
    FutU: std::future::Future<Output = crate::Result<()>>,
{
    let mut stats = OrphanReclaimStats::default();

    for tmp_root in tmp_roots {
        let Some(mut rd) = read_tmp_domain_root(tmp_root, "orphan mount reclaim").await else {
            continue;
        };
        loop {
            let Some(entry) = next_tmp_entry(&mut rd, tmp_root, "orphan mount reclaim").await
            else {
                break;
            };
            let Some(name) = tmp_dir_candidate_name(&entry).await else {
                continue;
            };

            stats.scanned += 1;
            let target = tmp_root.join(&name);

            // 守卫：mtime 宽限；不可得按新鲜处理（与目录体清扫同口径）。
            if !entry_past_grace(&entry, grace).await {
                continue;
            }

            // 守卫：布局签名——只回收引擎 tempdir 的已知布局形态（双重形态校验之一）。
            if tmp_residue_signature(&target).await.is_none() {
                continue;
            }

            // 隔离断言：目标严格位于 tmp_root 之下且不等于 tmp_root 本身。
            if !crate::util::strictly_within(&target, tmp_root) {
                warn!(
                    target = %target.display(),
                    root = %tmp_root.display(),
                    "Orphan mount reclaim target failed isolation assertion; refusing to umount"
                );
                continue;
            }

            let points = match mount_points_referencing(mounts_file, &target).await {
                Ok(p) => p,
                Err(e) => {
                    stats.skipped_mount_scan_error += 1;
                    warn!(
                        target = %target.display(),
                        error = %e,
                        "Failed to scan mounts for orphan mount reclaim; skipping (fail-closed)"
                    );
                    continue;
                }
            };
            // umount 域预过滤（同 helper umount_target_domain 谓词，见
            // [`point_in_umount_domain`]）：域外点特权层必拒，直接不进卸载
            // 列表，消除每轮永续拒绝 warn；域外引用仍被卸载后复扫与目录体
            // 清扫守卫三识别（fail-closed 保体），残留交人工 gc 兜底。
            let mut points = points;
            points.retain(|p| {
                let in_domain = point_in_umount_domain(p, allowed_roots);
                if !in_domain {
                    tracing::debug!(
                        path = %p.display(),
                        "Umount point outside the privileged umount domain; \
                         skipped, mount left for manual gc --orphan-mounts"
                    );
                }
                in_domain
            });
            if points.is_empty() {
                // 无域内挂载引用：不是本轮回收对象，目录体交 sweep_tmp_domain。
                continue;
            }
            stats.mounted_candidates += 1;

            // 活跃门控（实时）：存在非终态构建 = busy，绝不卸载（见函数文档）。
            if activity_busy().await {
                stats.skipped_busy += 1;
                continue;
            }

            match umount_referenced_mounts(&points, &umounter).await {
                Ok(()) => {
                    // 复扫确认：引用清零才算回收成功（fail-closed，残留下轮重试）。
                    match mount_points_referencing(mounts_file, &target).await {
                        Ok(p) if p.is_empty() => {
                            stats.reclaimed += 1;
                            info!(
                                target = %target.display(),
                                umounted = points.len(),
                                "Lazy umounted orphan mounts on crashed-build tempdir; \
                                 body left for tmp domain sweep"
                            );
                        }
                        Ok(p) => {
                            stats.umount_failed += 1;
                            warn!(
                                target = %target.display(),
                                remaining = p.len(),
                                "Orphan mounts still referenced after lazy umount; \
                                 will retry next round"
                            );
                        }
                        Err(e) => {
                            stats.umount_failed += 1;
                            warn!(
                                target = %target.display(),
                                error = %e,
                                "Failed to re-scan mounts after lazy umount; \
                                 body left for next round"
                            );
                        }
                    }
                }
                Err(()) => {
                    stats.umount_failed += 1;
                }
            }
        }
    }

    info!(
        roots = ?tmp_roots,
        scanned = stats.scanned,
        mounted_candidates = stats.mounted_candidates,
        reclaimed = stats.reclaimed,
        umount_failed = stats.umount_failed,
        skipped_busy = stats.skipped_busy,
        skipped_mount_scan_error = stats.skipped_mount_scan_error,
        "Tmp domain orphan mount reclaim finished"
    );
    stats
}

/// umount 候选点域判定，与 priv-helper `validate::umount_target_domain` 同谓词
///（helper 独立成包，两处实现须同步）：严格位于某 allowed root 之下（等于根
/// 本身不算），或标准临时目录（/tmp、/var/tmp、/dev/shm）下且第一级组件
/// `.tmp` 开头。不等号须保持与 helper 侧逐字同形的 `as_os_str` 字节比较——
/// `Path` 组件级 `!=` 对尾斜杠变体真值不同，不可改用 `util::strictly_within`。
/// 域外点交特权层必被 Validation 拒绝，收集侧预过滤免每轮空转。
fn point_in_umount_domain(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    if allowed_roots
        .iter()
        .any(|root| path.as_os_str() != root.as_os_str() && path.starts_with(root))
    {
        return true;
    }
    ["/dev/shm", "/var/tmp", "/tmp"].iter().any(|prefix| {
        path.strip_prefix(prefix).is_ok_and(|rest| {
            rest.components()
                .next()
                .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with(".tmp"))
        })
    })
}

/// 逐点惰性卸载（深度倒序已由收集方排序）；任一点失败记录 warn 继续——
/// 同一挂载子树的深层点失败时，父点 MNT_DETACH 会连子树一并脱离，复扫兜底判定。
async fn umount_referenced_mounts<U, FutU>(points: &[PathBuf], umounter: &U) -> Result<(), ()>
where
    U: Fn(PathBuf) -> FutU,
    FutU: std::future::Future<Output = crate::Result<()>>,
{
    let mut failed = false;
    for p in points {
        if let Err(e) = umounter(p.clone()).await {
            failed = true;
            warn!(
                path = %p.display(),
                error = %e,
                "Failed to lazy umount orphan mount on crashed-build tempdir; \
                 will retry next round"
            );
        }
    }
    if failed {
        Err(())
    } else {
        Ok(())
    }
}

/// mounts 表中引用 `target` 的行的挂载点集合（umount 目标）：判定面与
/// [`mount_references_target`] 一致（挂载点 / bind source / overlay 选项路径
/// canonicalize 后落入目标之下即算该行引用），umount 目标取该行挂载点——bind
/// source 形态（reproduce 临时 repo bind 进 chroot）挂载点在目标之外，同样按
/// 行收集。深度倒序去重（深层先卸，复用 [`orphan::sort_and_dedup_mounts`]）。
/// 目标 canonicalize 失败返回 `Err`（并发消失等异常，无可靠比较基准，fail-closed）。
async fn mount_points_referencing(mounts_file: &str, target: &Path) -> crate::Result<Vec<PathBuf>> {
    let content = tokio::fs::read_to_string(mounts_file)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read mounts for tmp sweep", e))?;
    let target_canon = match tokio::fs::canonicalize(target).await {
        Ok(p) => p,
        Err(e) => {
            return Err(crate::error::CrbsError::from_io_context(
                "canonicalize tmp sweep target",
                e,
            ));
        }
    };
    let mut points: Vec<orphan::OrphanMount> = Vec::new();
    for line in content.lines() {
        if mount_line_references(line, &target_canon).await {
            let parts: Vec<&str> = line.split_whitespace().collect();
            points.push(orphan::OrphanMount {
                path: PathBuf::from(orphan::decode_proc_mounts_field(parts[1])),
                fstype: String::new(),
            });
        }
    }
    Ok(orphan::sort_and_dedup_mounts(points)
        .into_iter()
        .map(|m| m.path)
        .collect())
}

/// 挂载复扫（守卫三实现）：读 mounts 原始行，检测目标是否被任何一行**引用**：
/// 任一候选路径 canonicalize 后位于目标之下（含等于目标）即 `Ok(true)`。
/// 本地实现而非复用 [`orphan::scan_mounts_from`]：后者只比挂载点，覆盖不了
/// bind source / overlay 层目录形态。比对对象：
/// - 挂载点（field 1）：孤儿挂载 / 活跃 overlay 的 root 挂载；
/// - **source 侧**（field 0）：bind mount 源路径——活跃 reproduce 的 temp
///   repo 被 bind 进 chroot 时，mountpoint 在构建 root 之下、不在 repo 之下；
/// - **挂载选项中的路径**（field 3）：`upperdir=`/`workdir=`/`lowerdir=`/
///   `dir=`/`bind=` 选项值（lowerdir 多路径按 `:` 再拆）。
///
/// 失败语义：mounts 读取失败返回 `Err` 交调用方 fail-closed；非路径 source
///（`overlay`、`tmpfs`、`none` 等伪名）canonicalize 失败按不匹配，误判
/// 方向是"多跳过"（安全侧）。字段解码复用 [`orphan::decode_proc_mounts_field`]。
async fn mount_references_target(mounts_file: &str, target: &Path) -> crate::Result<bool> {
    let content = tokio::fs::read_to_string(mounts_file)
        .await
        .map_err(|e| crate::error::CrbsError::from_io_context("read mounts for tmp sweep", e))?;
    let target_canon = match tokio::fs::canonicalize(target).await {
        Ok(p) => p,
        // canonicalize 失败 = 并发消失等异常，无可靠比较基准，按被引用处理（fail-closed）。
        Err(_) => return Ok(true),
    };
    for line in content.lines() {
        if mount_line_references(line, &target_canon).await {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 单条 mounts 行是否引用 `target_canon`（少于 3 字段的残行不算）：挂载点 /
/// source / 挂载选项路径（[`mount_line_candidate_paths`] 全集）任一 canonicalize
/// 后落入目标之下（含等于）即真。canonicalize 失败按不匹配——非路径 source
///（`overlay`/`tmpfs` 等伪名）的误判方向是"多跳过"（安全侧）。挂载点引用与
/// 挂载复扫两处判定的共享内核。
async fn mount_line_references(line: &str, target_canon: &Path) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return false;
    }
    for path in mount_line_candidate_paths(&parts) {
        if tokio::fs::canonicalize(&path)
            .await
            .map(|c| c.starts_with(target_canon))
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// 单条 mounts 行的候选路径集（挂载点 / source / 选项路径），引用判定两处共用；
/// 字段八进制转义在此解码。
fn mount_line_candidate_paths(parts: &[&str]) -> Vec<PathBuf> {
    let mut paths = vec![
        orphan::decode_proc_mounts_field(parts[0]),
        orphan::decode_proc_mounts_field(parts[1]),
    ];
    if let Some(opts) = parts.get(3) {
        for opt in opts.split(',') {
            let Some((key, value)) = opt.split_once('=') else {
                continue;
            };
            if matches!(key, "upperdir" | "workdir" | "lowerdir" | "dir" | "bind") {
                paths.extend(value.split(':').map(orphan::decode_proc_mounts_field));
            }
        }
    }
    paths.into_iter().map(PathBuf::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    // ─── 测试辅助 ───

    fn make_overlay_dir(dir: &Path) {
        for sub in ["upper", "work", "root"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
    }

    fn make_temp_repo_dir(dir: &Path) {
        std::fs::create_dir_all(dir.join("Packages")).unwrap();
        std::fs::create_dir_all(dir.join("repodata")).unwrap();
        std::fs::write(dir.join("repodata").join("repomd.xml"), b"<repomd/>").unwrap();
    }

    /// 回拨 mtime 2 小时，跨过 [`TMP_SWEEP_GRACE`]（1 小时）。
    fn backdate_mtime(dir: &Path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let old = filetime::FileTime::from_unix_time(now.as_secs() as i64 - 2 * 3600, 0);
        filetime::set_file_mtime(dir, old).unwrap();
    }

    /// 记录型删除注入缝：把目标记入 log、不动磁盘。
    fn recording_remover(
        log: Arc<Mutex<Vec<PathBuf>>>,
    ) -> impl Fn(PathBuf) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send>> {
        move |p: PathBuf| {
            log.lock().unwrap_or_else(|e| e.into_inner()).push(p);
            Box::pin(async { Ok(()) })
        }
    }

    /// 真删除注入缝：普通 remove_dir_all（测试目录属当前用户，无需特权）。
    fn real_remover() -> impl Fn(PathBuf) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send>>
    {
        |p: PathBuf| {
            Box::pin(async move {
                tokio::fs::remove_dir_all(&p)
                    .await
                    .map_err(|e| crate::error::CrbsError::from_io_context("sweep test remove", e))
            })
        }
    }

    fn empty_mounts_file(dir: &Path) -> PathBuf {
        let p = dir.join("mounts");
        std::fs::write(&p, "").unwrap();
        p
    }

    // ─── 签名分类器 ───

    #[tokio::test]
    async fn signature_matches_overlay_form() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".tmpAb12");
        make_overlay_dir(&dir);
        assert_eq!(
            tmp_residue_signature(&dir).await,
            Some(TmpResidueKind::Overlay)
        );
    }

    /// 形态 A 两件套（恰 upper+work，无 root）：`setup_overlay` 建序 upper→work→
    /// root 中 root 建成前即崩溃的中断态（overlay 从未挂载、构建未开始，无用户
    /// 数据可保），认领为 Overlay——生产实锤该形态被 `skipped_no_signature`
    /// 永续累积。
    #[tokio::test]
    async fn signature_matches_overlay_two_piece_form() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".tmpEf56");
        std::fs::create_dir_all(dir.join("upper")).unwrap();
        std::fs::create_dir_all(dir.join("work")).unwrap();
        assert_eq!(
            tmp_residue_signature(&dir).await,
            Some(TmpResidueKind::Overlay)
        );
    }

    /// 两件套的"不多不少"：缺一（upper+root / work+root）、任一实为文件、
    /// 多余条目都不认——认领面只收窄到建序可解释的中断态。
    #[tokio::test]
    async fn signature_rejects_imperfect_two_piece_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cases");
        std::fs::create_dir_all(&root).unwrap();

        // work+root（缺 upper）→ 不认。
        let missing_upper = root.join("missing-upper");
        std::fs::create_dir_all(missing_upper.join("work")).unwrap();
        std::fs::create_dir_all(missing_upper.join("root")).unwrap();
        assert_eq!(tmp_residue_signature(&missing_upper).await, None);

        // upper+root（缺 work）→ 不认。
        let missing_work = root.join("missing-work");
        std::fs::create_dir_all(missing_work.join("upper")).unwrap();
        std::fs::create_dir_all(missing_work.join("root")).unwrap();
        assert_eq!(tmp_residue_signature(&missing_work).await, None);

        // work 是文件不是目录 → 不认。
        let file_impostor = root.join("file-impostor");
        std::fs::create_dir_all(&file_impostor).unwrap();
        std::fs::create_dir_all(file_impostor.join("upper")).unwrap();
        std::fs::write(file_impostor.join("work"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&file_impostor).await, None);

        // 两件套 + 多余文件 → 不认。
        let extra = root.join("extra");
        std::fs::create_dir_all(extra.join("upper")).unwrap();
        std::fs::create_dir_all(extra.join("work")).unwrap();
        std::fs::write(extra.join("stray"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&extra).await, None);
    }

    /// 形态 A2：全内存构建 tempdir 恰含 memroot/，其内 overlay 布局两件套
    ///（mount 后 root 建成前崩溃）与三件套（完整布局）都认。
    #[tokio::test]
    async fn signature_matches_memroot_forms() {
        let tmp = tempfile::tempdir().unwrap();

        let complete = tmp.path().join(".tmpMemFull");
        make_overlay_dir(&complete.join("memroot"));
        assert_eq!(
            tmp_residue_signature(&complete).await,
            Some(TmpResidueKind::Memroot)
        );

        let interrupted = tmp.path().join(".tmpMemEarly");
        std::fs::create_dir_all(interrupted.join("memroot").join("upper")).unwrap();
        std::fs::create_dir_all(interrupted.join("memroot").join("work")).unwrap();
        assert_eq!(
            tmp_residue_signature(&interrupted).await,
            Some(TmpResidueKind::Memroot)
        );
    }

    /// 形态 A2 的"不多不少"：memroot 为空（极短窗口）、缺一、多余条目、
    /// memroot 实为文件或 symlink 全不认——memroot 这个常见名字不能单独构成
    /// 删除依据。
    #[tokio::test]
    async fn signature_rejects_imperfect_memroot() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cases");
        std::fs::create_dir_all(&root).unwrap();

        // memroot 空目录：无内容可鉴别 → 不认。
        let empty = root.join(".tmpMemEmpty");
        std::fs::create_dir_all(empty.join("memroot")).unwrap();
        assert_eq!(tmp_residue_signature(&empty).await, None);

        // 缺 work → 不认。
        let missing = root.join(".tmpMemMissing");
        std::fs::create_dir_all(missing.join("memroot").join("upper")).unwrap();
        assert_eq!(tmp_residue_signature(&missing).await, None);

        // 三件套 + 多余文件 → 不认。
        let extra = root.join(".tmpMemExtra");
        make_overlay_dir(&extra.join("memroot"));
        std::fs::write(extra.join("memroot").join("stray"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&extra).await, None);

        // memroot 实为文件 → 不认。
        let file_impostor = root.join(".tmpMemFile");
        std::fs::create_dir_all(&file_impostor).unwrap();
        std::fs::write(file_impostor.join("memroot"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&file_impostor).await, None);

        // memroot 是指向合法布局的 symlink → 不认：不跟随出域。
        let symlink_impostor = root.join(".tmpMemSym");
        let real = root.join("real-memroot");
        make_overlay_dir(&real);
        std::fs::create_dir_all(&symlink_impostor).unwrap();
        std::os::unix::fs::symlink(&real, symlink_impostor.join("memroot")).unwrap();
        assert_eq!(tmp_residue_signature(&symlink_impostor).await, None);
    }

    #[tokio::test]
    async fn signature_matches_temp_repo_form() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".tmpCd34");
        make_temp_repo_dir(&dir);
        assert_eq!(
            tmp_residue_signature(&dir).await,
            Some(TmpResidueKind::TempRepo)
        );
    }

    /// 形态 B 收严为恰 {Packages, repodata} 两条目：多余文件 / 多余目录 /
    /// repodata 文件冒名 / repomd.xml symlink 冒名（不跟随）全不认。
    #[tokio::test]
    async fn signature_temp_repo_requires_exactly_two_entries() {
        let tmp = tempfile::tempdir().unwrap();

        // 多一个顶层文件（ISO 解包 / reposync 输出形态）→ 不认。
        let extra_file = tmp.path().join(".tmpExtraFile");
        make_temp_repo_dir(&extra_file);
        std::fs::write(extra_file.join(".treeinfo"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&extra_file).await, None);

        // 多一个顶层目录 → 不认。
        let extra_dir = tmp.path().join(".tmpExtraDir");
        make_temp_repo_dir(&extra_dir);
        std::fs::create_dir(extra_dir.join("extra")).unwrap();
        assert_eq!(tmp_residue_signature(&extra_dir).await, None);

        // repodata 被同名文件冒名（只有 Packages）→ 不认。
        let repo_as_file = tmp.path().join(".tmpRepoFile");
        std::fs::create_dir_all(repo_as_file.join("Packages")).unwrap();
        std::fs::write(repo_as_file.join("repodata"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&repo_as_file).await, None);

        // repomd.xml 是 symlink（指向域外）→ 不认：不跟随，否则域外内容进判定。
        let symlink_impostor = tmp.path().join(".tmpSym");
        make_temp_repo_dir(&symlink_impostor);
        let real = tmp.path().join("real-repomd.xml");
        std::fs::write(&real, b"<repomd/>").unwrap();
        let repomd = symlink_impostor.join("repodata").join("repomd.xml");
        std::fs::remove_file(&repomd).unwrap();
        std::os::unix::fs::symlink(&real, &repomd).unwrap();
        assert_eq!(tmp_residue_signature(&symlink_impostor).await, None);
    }

    /// 空目录不认；形态 A 的"不多不少"：多余 / 缺一 / 文件冒名全不认。
    #[tokio::test]
    async fn signature_rejects_empty_and_imperfect_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("cases");
        std::fs::create_dir_all(&root).unwrap();

        let empty = root.join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert_eq!(tmp_residue_signature(&empty).await, None);

        // 形态 A + 多余文件。
        let extra_file = root.join("extra-file");
        make_overlay_dir(&extra_file);
        std::fs::write(extra_file.join("stray"), b"x").unwrap();
        assert_eq!(tmp_residue_signature(&extra_file).await, None);

        // 形态 A + 多余子目录。
        let extra_dir = root.join("extra-dir");
        make_overlay_dir(&extra_dir);
        std::fs::create_dir(extra_dir.join("Packages")).unwrap();
        assert_eq!(tmp_residue_signature(&extra_dir).await, None);

        // 缺 work。
        let missing = root.join("missing");
        std::fs::create_dir_all(missing.join("upper")).unwrap();
        std::fs::create_dir_all(missing.join("root")).unwrap();
        assert_eq!(tmp_residue_signature(&missing).await, None);

        // upper 是文件不是目录（"文件不算"）。
        let file_impostor = root.join("file-impostor");
        std::fs::create_dir_all(&file_impostor).unwrap();
        std::fs::write(file_impostor.join("upper"), b"x").unwrap();
        std::fs::create_dir_all(file_impostor.join("work")).unwrap();
        std::fs::create_dir_all(file_impostor.join("root")).unwrap();
        assert_eq!(tmp_residue_signature(&file_impostor).await, None);
    }

    /// C 形态（base_os 根树）与普通文件不认——明确不覆盖面（误删三方数据不可接受）。
    #[tokio::test]
    async fn signature_rejects_base_os_tree_and_plain_files() {
        let tmp = tempfile::tempdir().unwrap();

        // C 形态：base_os 根树（install_base_os 装出的 etc/usr/var + 常规文件）。
        let base_os = tmp.path().join(".tmpBase");
        std::fs::create_dir_all(base_os.join("etc/yum.repos.d")).unwrap();
        std::fs::create_dir_all(base_os.join("usr/bin")).unwrap();
        std::fs::create_dir_all(base_os.join("var/lib/rpm")).unwrap();
        std::fs::write(base_os.join("etc/hostname"), b"crbs").unwrap();
        assert_eq!(tmp_residue_signature(&base_os).await, None);

        // 形态 B 的近亲：只有 Packages/ 没有 repodata（createrepo 前崩溃）不认。
        let partial_repo = tmp.path().join(".tmpPartial");
        std::fs::create_dir_all(partial_repo.join("Packages")).unwrap();
        assert_eq!(tmp_residue_signature(&partial_repo).await, None);

        // 目标本身是文件。
        let plain_file = tmp.path().join(".tmpPlainFile");
        std::fs::write(&plain_file, b"x").unwrap();
        assert_eq!(tmp_residue_signature(&plain_file).await, None);
    }

    // ─── 清扫（mounts_file + remover 注入） ───

    #[tokio::test]
    async fn sweep_removes_stale_unmounted_overlay_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpAb12");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mounts = empty_mounts_file(tmp.path());
        let stats = sweep_tmp_domain(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            real_remover(),
        )
        .await;

        assert!(!target.exists(), "无挂载且超宽限的形态 A 目录体应被删");
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.skipped_fresh, 0);
    }

    /// 两件套中断态目录体（恰 upper+work）被认领并实际回收——生产实锤该形态
    /// 每轮 `skipped_no_signature` 永续累积的回归锚。
    #[tokio::test]
    async fn sweep_removes_stale_unmounted_overlay_two_piece_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpTwo");
        std::fs::create_dir_all(target.join("upper")).unwrap();
        std::fs::create_dir_all(target.join("work")).unwrap();
        backdate_mtime(&target);

        let mounts = empty_mounts_file(tmp.path());
        let stats = sweep_tmp_domain(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            real_remover(),
        )
        .await;

        assert!(!target.exists(), "两件套中断态目录体应被删");
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.skipped_no_signature, 0);
    }

    /// 形态 A2：全内存构建残留（memroot 内 overlay 布局）同轮回收——memroot
    /// 实例占用内存，崩溃后目录体与挂载都由本模块与孤儿挂载回收兜住。
    #[tokio::test]
    async fn sweep_removes_stale_unmounted_memroot_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpMem");
        make_overlay_dir(&target.join("memroot"));
        backdate_mtime(&target);

        let mounts = empty_mounts_file(tmp.path());
        let stats = sweep_tmp_domain(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            real_remover(),
        )
        .await;

        assert!(!target.exists(), "无挂载且超宽限的全内存构建目录体应被删");
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.skipped_no_signature, 0);
    }

    /// 两件套与三件套并存同轮处理；内容体积不设防——生产侧 remover 是特权
    /// rm-rf（`privilege::rm_rf_async`，root 属主内容可删），此处以记录型注入
    /// 缝 stand-in，断言两种布局都在过守卫后交给删除通道。
    #[tokio::test]
    async fn sweep_hands_two_piece_and_three_piece_bodies_to_remover() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        // 三件套 + upper 内 GB 级内容 stand-in；两件套中断态。
        let three = domain.join(".tmpThree");
        make_overlay_dir(&three);
        std::fs::write(three.join("upper").join("big-payload"), vec![0u8; 4096]).unwrap();
        let two = domain.join(".tmpTwo");
        std::fs::create_dir_all(two.join("upper")).unwrap();
        std::fs::create_dir_all(two.join("work")).unwrap();
        backdate_mtime(&three);
        backdate_mtime(&two);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        let mut handled = log.lock().unwrap().clone();
        handled.sort();
        assert_eq!(
            handled,
            vec![three.clone(), two.clone()],
            "两种布局都必须交给删除通道"
        );
        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.removed, 2);
        assert_eq!(stats.skipped_no_signature, 0);
    }

    /// 挂载复扫：目标之下有挂载点（含目标自身是挂载点）一律跳过（fail-closed）。
    #[tokio::test]
    async fn sweep_skips_targets_with_mounts() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let with_mount_under = domain.join(".tmpA1");
        make_overlay_dir(&with_mount_under);
        backdate_mtime(&with_mount_under);
        let mount_itself = domain.join(".tmpB2");
        make_overlay_dir(&mount_itself);
        backdate_mtime(&mount_itself);

        // macOS /var 是 /private/var 的 symlink：挂载点经 canonicalize 后与传入根对齐（orphan.rs 同款）。
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "overlay {}/root overlay rw 0 0\noverlay {} overlay rw 0 0\n",
                with_mount_under.display(),
                mount_itself.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(with_mount_under.exists(), "目标之下有挂载的目录体必须保留");
        assert!(mount_itself.exists(), "目标自身是挂载点的目录体必须保留");
        assert!(log.lock().unwrap().is_empty(), "不得有任何删除动作");
        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.skipped_mounted, 2);
        assert_eq!(stats.removed, 0);
    }

    /// 目标作为 bind mount 的 **source** 被引用（活跃 reproduce temp repo
    /// 形态）→ 必须检出并跳过——只比挂载点会漏检，特权 rm-rf 同 inode 穿透。
    #[tokio::test]
    async fn sweep_skips_target_referenced_as_bind_source() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpRepo");
        make_temp_repo_dir(&target);
        backdate_mtime(&target);

        // mounts 行：source = 目标本体，mountpoint 在不存在的 chroot 内——只能靠 source 侧命中。
        let chroot_mnt = tmp.path().join("build-root").join("mnt").join("crbs-repo");
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "{} {} ext4 rw 0 0\n",
                target.display(),
                chroot_mnt.display()
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(target.exists(), "bind source 被引用的目录体必须保留");
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.skipped_mounted, 1);
        assert_eq!(stats.removed, 0);
    }

    /// 目标被 overlay 挂载选项引用（upperdir/workdir 在目标之下，mountpoint
    /// 与 lowerdir 前段域外/不存在）→ 跳过；lowerdir `:` 多路径分段同覆盖。
    #[tokio::test]
    async fn sweep_skips_target_referenced_in_mount_options() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpOvl");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mnt_point = tmp.path().join("merged");
        std::fs::create_dir_all(&mnt_point).unwrap();
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "overlay {} overlay rw,lowerdir=/var/lib/crbs/base:{},upperdir={},workdir={} 0 0\n",
                mnt_point.display(),
                target.display(),
                target.join("upper").display(),
                target.join("work").display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(target.exists(), "被 overlay 选项引用的目录体必须保留");
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.skipped_mounted, 1);
        assert_eq!(stats.removed, 0);
    }

    /// 未满宽限（mtime 新鲜）保留——即便签名与挂载条件都满足。
    #[tokio::test]
    async fn sweep_keeps_fresh_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpFresh");
        make_overlay_dir(&target);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(target.exists(), "宽限内的目录体必须保留");
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.skipped_fresh, 1);
        assert_eq!(stats.removed, 0);
    }

    /// 非 `.tmp` 前缀不碰（即便带完整形态 A 签名）；`.tmp` 前缀文件不入候选。
    #[tokio::test]
    async fn sweep_ignores_non_tmp_prefix_and_files() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let decoy = domain.join(".incoming");
        make_overlay_dir(&decoy);
        backdate_mtime(&decoy);
        let plain_file = domain.join(".tmpNotADir");
        std::fs::write(&plain_file, b"x").unwrap();
        backdate_mtime(&plain_file);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(decoy.exists(), "非 .tmp 前缀目录必须保留（即便签名吻合）");
        assert!(plain_file.exists(), "前缀撞名的文件不动");
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 0, "两者都不构成候选");
        assert_eq!(stats.removed, 0);
    }

    /// 隔离断言：只删声明的 tmp_root 之内——域外同名残留、tmp_root 本身绝不删。
    #[tokio::test]
    async fn sweep_stays_inside_declared_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpIn1");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        // 域外兄弟：同为 .tmp 前缀 + 形态 A + 超宽限，但不在 tmp_root 内。
        let outside = tmp.path().join(".tmpOutside");
        make_overlay_dir(&outside);
        backdate_mtime(&outside);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert_eq!(
            log.lock().unwrap().as_slice(),
            vec![target.clone()],
            "只有域内候选被删"
        );
        assert!(domain.exists(), "tmp_root 自身绝不入删除面");
        assert!(outside.exists(), "域外目录不得被触碰");
        assert_eq!(stats.removed, 1);
    }

    #[tokio::test]
    async fn sweep_removes_stale_temp_repo_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpRepo");
        make_temp_repo_dir(&target);
        backdate_mtime(&target);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert_eq!(log.lock().unwrap().as_slice(), vec![target]);
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.skipped_no_signature, 0);
    }

    /// mounts 文件读取失败 → fail-closed 跳过目标（不删、不报错抬级）。
    #[tokio::test]
    async fn sweep_fail_closed_when_mounts_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpFc");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let missing = tmp.path().join("no-such-mounts");
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[domain],
            missing.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log.clone()),
        )
        .await;

        assert!(target.exists(), "mounts 扫描失败必须跳过目标");
        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.skipped_mount_scan_error, 1);
        assert_eq!(stats.removed, 0);
    }

    /// tmp_root 不存在时静默 no-op（tmpfs_dir 未挂载 / 尚无构建的正常态）。
    #[tokio::test]
    async fn sweep_noop_when_domain_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let stats = sweep_tmp_domain(
            &[tmp.path().join("does-not-exist")],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            recording_remover(log),
        )
        .await;
        assert_eq!(stats, SweepStats::default());
    }

    // ─── 孤儿挂载回收（umount_orphan_tmp_mounts） ───

    /// 记录型卸载注入缝：把挂载点记入 log、不动 mounts 文件（复扫仍见引用）。
    fn recording_umounter(
        log: Arc<Mutex<Vec<PathBuf>>>,
    ) -> impl Fn(PathBuf) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send>> {
        move |p: PathBuf| {
            log.lock().unwrap_or_else(|e| e.into_inner()).push(p);
            Box::pin(async { Ok(()) })
        }
    }

    /// 卸载注入缝 + 同步改写 mounts 文件（删除指定行）并记录卸载点：模拟真实
    /// MNT_DETACH 后引用从 /proc/mounts 消失，复扫确认与卸载次序均可测。
    fn effective_umounter(
        mounts_path: PathBuf,
        log: Arc<Mutex<Vec<PathBuf>>>,
    ) -> impl Fn(PathBuf) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send>> {
        move |p: PathBuf| {
            let mounts_path = mounts_path.clone();
            log.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(p.clone());
            Box::pin(async move {
                let content = tokio::fs::read_to_string(&mounts_path).await.unwrap();
                let kept: Vec<&str> = content
                    .lines()
                    .filter(|l| !l.contains(&p.display().to_string()))
                    .collect();
                tokio::fs::write(&mounts_path, kept.join("\n") + "\n")
                    .await
                    .unwrap();
                Ok(())
            })
        }
    }

    /// 全局空闲门控（false = 无活跃构建）。
    fn idle_gate() -> impl Fn() -> std::future::Ready<bool> {
        || std::future::ready(false)
    }

    /// 全局繁忙门控（true = 存在非终态构建）。
    fn busy_gate() -> impl Fn() -> std::future::Ready<bool> {
        || std::future::ready(true)
    }

    /// 全局空闲 + 崩溃构建残留（门控通过）：目标之下有挂载的形态 A 目录体，
    /// 挂载点（含子挂载）按深度倒序被惰性卸载；复扫引用清零计 reclaimed。
    #[tokio::test]
    async fn reclaim_umounts_mounted_overlay_when_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let target = domain.join(".tmpCrash");
        make_overlay_dir(&target);
        // 真实挂载点路径必存在（挂载表只列存在的路径）；root/proc 为容器伪 fs 挂载点。
        std::fs::create_dir_all(target.join("root").join("proc")).unwrap();
        backdate_mtime(&target);

        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "overlay {root} overlay rw,lowerdir=/var/lib/crbs/base,upperdir={target}/upper,workdir={target}/work 0 0\n\
                 proc {root}/proc proc rw 0 0\n",
                root = target.join("root").display(),
                target = target.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            effective_umounter(mounts.clone(), log.clone()),
        )
        .await;

        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(stats.reclaimed, 1);
        assert_eq!(stats.skipped_busy, 0);
        // 深度倒序：子挂载点先于 overlay root。
        assert_eq!(
            log.lock().unwrap().as_slice(),
            vec![target.join("root/proc"), target.join("root")]
        );
    }

    /// 形态 A2 的挂载回收：memroot tmpfs 与其上 overlay 按深度倒序卸载
    /// （overlay 先于 memroot，否则 upper/work 仍被引用），复扫清零计 reclaimed。
    #[tokio::test]
    async fn reclaim_umounts_mounted_memroot_when_idle() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpMemCrash");
        make_overlay_dir(&target.join("memroot"));
        backdate_mtime(&target);

        let memroot = target.join("memroot");
        let root = memroot.join("root");
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "tmpfs {memroot} tmpfs rw 0 0\n\
                 overlay {root} overlay rw,lowerdir=/var/lib/crbs/base,upperdir={memroot}/upper,workdir={memroot}/work 0 0\n",
                memroot = memroot.display(),
                root = root.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            effective_umounter(mounts.clone(), log.clone()),
        )
        .await;

        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(stats.reclaimed, 1);
        assert_eq!(stats.skipped_busy, 0);
        // 深度倒序：overlay root 先于 memroot 实例。
        assert_eq!(log.lock().unwrap().as_slice(), vec![root, memroot]);
    }

    /// 活跃门控命中（存在非终态构建）：有挂载引用的候选绝不卸载（skipped_busy）。
    #[tokio::test]
    async fn reclaim_skips_mounted_candidate_when_builds_active() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let target = domain.join(".tmpLive");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "overlay {} overlay rw,lowerdir=/x,upperdir={}/upper 0 0\n",
                target.join("root").display(),
                target.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            busy_gate(),
            recording_umounter(log.clone()),
        )
        .await;

        assert!(log.lock().unwrap().is_empty(), "活跃构建挂载不得被卸载");
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(stats.skipped_busy, 1);
        assert_eq!(stats.reclaimed, 0);
    }

    /// 形态不符（C 形态 base_os 树）与宽限内（mtime 新鲜）的挂载候选不回收。
    #[tokio::test]
    async fn reclaim_skips_signature_mismatch_and_fresh_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");

        // C 形态：不在签名内（即便有挂载引用）。
        let base_os = domain.join(".tmpBase");
        std::fs::create_dir_all(base_os.join("usr/bin")).unwrap();
        backdate_mtime(&base_os);

        // 形态 A 但 mtime 新鲜（活跃长构建的正常态）。
        let fresh = domain.join(".tmpLong");
        make_overlay_dir(&fresh);

        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "overlay {b} overlay rw 0 0\noverlay {f}/root overlay rw 0 0\n",
                b = base_os.display(),
                f = fresh.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            recording_umounter(log.clone()),
        )
        .await;

        assert!(log.lock().unwrap().is_empty(), "无候选应被卸载");
        assert_eq!(stats.scanned, 2);
        assert_eq!(stats.mounted_candidates, 0);
        assert_eq!(stats.reclaimed, 0);
    }

    /// bind source 形态（reproduce 临时 repo bind 进 chroot，挂载点在目标之外）：
    /// 引用经 source 侧命中，umount 目标 = 该行挂载点（chroot 内挂载位置）；
    /// 挂载点在 allowed root 下走 AllowedRoot 域臂。
    #[tokio::test]
    async fn reclaim_umounts_mountpoint_of_bind_source_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpRepo");
        make_temp_repo_dir(&target);
        backdate_mtime(&target);

        let chroot_mnt = tmp.path().join("base-root").join("mnt").join("crbs-repo");
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "{} {} ext4 rw 0 0\n",
                target.display(),
                chroot_mnt.display()
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            effective_umounter(mounts.clone(), log.clone()),
        )
        .await;

        assert_eq!(log.lock().unwrap().as_slice(), vec![chroot_mnt]);
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(stats.reclaimed, 1);
    }

    /// 卸载后复扫仍有引用（umounter 未真正改 mounts）→ 不计成功（umount_failed），
    /// 目录体留给下轮（与目录体清扫的 fail-closed 对齐）。
    #[tokio::test]
    async fn reclaim_counts_failure_when_reference_remains() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let target = domain.join(".tmpStuck");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!("overlay {} overlay rw 0 0\n", target.join("root").display(),),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            recording_umounter(log.clone()),
        )
        .await;

        assert_eq!(log.lock().unwrap().len(), 1, "卸载动作发生了");
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(stats.umount_failed, 1);
        assert_eq!(stats.reclaimed, 0);
    }

    /// 无挂载引用的候选不入回收面（mounted_candidates = 0，umounter 零调用）——
    /// 目录体删除仍归 sweep_tmp_domain，两阶段职责不重叠。
    #[tokio::test]
    async fn reclaim_ignores_unmounted_candidates() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let target = domain.join(".tmpPlain");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mounts = empty_mounts_file(tmp.path());
        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().to_path_buf()];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            recording_umounter(log.clone()),
        )
        .await;

        assert!(log.lock().unwrap().is_empty());
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.mounted_candidates, 0);
        assert_eq!(stats.reclaimed, 0);
    }

    /// 端到端语义：回收卸载改写 mounts 后，同轮 sweep_tmp_domain 即可清体
    /// （挂载已消失，守卫三放行）——周期清扫"先回收后清体"的编排依据。
    #[tokio::test]
    async fn reclaim_enables_body_sweep_in_same_round() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("shm");
        let target = domain.join(".tmpCombo");
        make_overlay_dir(&target);
        backdate_mtime(&target);

        let mounts = tmp.path().join("mounts");
        let mount_line = format!("overlay {} overlay rw 0 0\n", target.join("root").display(),);
        std::fs::write(&mounts, &mount_line).unwrap();

        umount_orphan_tmp_mounts(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &[tmp.path().to_path_buf()],
            idle_gate(),
            effective_umounter(mounts.clone(), Arc::new(Mutex::new(Vec::new()))),
        )
        .await;

        let stats = sweep_tmp_domain(
            std::slice::from_ref(&domain),
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            real_remover(),
        )
        .await;
        assert!(!target.exists(), "挂载回收后目录体应被同轮清扫删除");
        assert_eq!(stats.removed, 1);
        assert_eq!(stats.skipped_mounted, 0);
    }

    /// umount 域预过滤：挂载点在 allowed root 之外、也非标准临时目录 `.tmp`
    /// 形态（自定义盘区 chroot 的部署形态）的候选点直接不进卸载列表——特权层
    /// umount 域收紧必拒，域内预过滤消除每轮永续拒绝 warn；全域外候选按无
    /// 回收对象处理（不计 mounted_candidates、umounter 零调用）。
    #[tokio::test]
    async fn reclaim_skips_umount_points_outside_privileged_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpRepo");
        make_temp_repo_dir(&target);
        backdate_mtime(&target);

        // bind source 形态：source = 目标（引用命中），挂载点在域外字面路径。
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "{} /srv/bigdisk/chroot/repo ext4 rw 0 0\n",
                target.display()
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().join("crbs-root")];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            recording_umounter(log.clone()),
        )
        .await;

        assert!(log.lock().unwrap().is_empty(), "域外挂载点不得进卸载列表");
        assert_eq!(stats.scanned, 1);
        assert_eq!(stats.mounted_candidates, 0, "全域外候选按无回收对象处理");
        assert_eq!(stats.reclaimed, 0);
    }

    /// 混合候选：域内点照常卸载（行从 mounts 消失），域外点保留引用——卸载后
    /// 复扫仍见域外行 → umount_failed（诚实计数），目录体由守卫三保住不删。
    #[tokio::test]
    async fn reclaim_mixed_domain_candidate_umounts_in_domain_and_counts_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let domain = tmp.path().join("var-tmp");
        let target = domain.join(".tmpMix");
        make_temp_repo_dir(&target);
        backdate_mtime(&target);

        // 域内 bind 位置（allowed root 下）+ 域外 bind 位置，两行都经 source 引用目标。
        let in_domain_mnt = tmp.path().join("crbs-root").join("products").join("repo");
        let mounts = tmp.path().join("mounts");
        std::fs::write(
            &mounts,
            format!(
                "{t} {m} ext4 rw 0 0\n{t} /srv/elsewhere/chroot/repo ext4 rw 0 0\n",
                t = target.display(),
                m = in_domain_mnt.display(),
            ),
        )
        .unwrap();

        let log = Arc::new(Mutex::new(Vec::new()));
        let allowed = vec![tmp.path().join("crbs-root")];
        let stats = umount_orphan_tmp_mounts(
            &[domain],
            mounts.to_str().unwrap(),
            TMP_SWEEP_GRACE,
            &allowed,
            idle_gate(),
            effective_umounter(mounts.clone(), log.clone()),
        )
        .await;

        assert_eq!(
            log.lock().unwrap().as_slice(),
            vec![in_domain_mnt],
            "仅域内点被卸载"
        );
        assert_eq!(stats.mounted_candidates, 1);
        assert_eq!(
            stats.umount_failed, 1,
            "域外引用仍在，复扫不过 → 诚实计失败"
        );
        assert_eq!(stats.reclaimed, 0);
    }
}
