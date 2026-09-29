// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产品 repo 组装（发布型 YUM 仓库）：把产品"可发布"成功构建产物
//! （`list_publishable_rpms` 去重后的 RPM/SRPM）整树硬链接进
//! `.staging-*` 暂存目录（Packages/ + 全量 `createrepo_c`），再与
//! `{result_root}/_repo/{product}/{arch}/` 整目录换位。核心不变量：
//!
//! - **(文件, repodata) 恒自洽**：新 Packages 与新 repodata 在 staging 内
//!   成对建成后一次换位，磁盘任意时刻只见完整旧树或完整新树：同 NEVR
//!   重发（文件名不变、字节更新）绝不出现"旧 repodata 配新字节"窗口
//!   （读取端 checksum mismatch 的根因，压力测试批次实弹复现）；失败臂
//!   staging 就地清理、旧树全程未动，无需隔离回放。
//! - **对账式重建**：以 DB 候选集为准整树重铺，不在候选集的陈旧文件随
//!   换位消失（`unlinked` 按旧树清点）；hardlink 幂等，同名同 inode 不计
//!   `linked`。
//! - **换位形态**：优先 `renameat2(RENAME_EXCHANGE)`（单系统调用，读者无
//!   任何中间态）；不可用 → 两段 rename 兜底（arch 目录瞬时缺失，读者可能
//!   瞬态失败；该次构建失败重跑即恢复）；首建 → staging 直接 rename 入位。
//! - **hardlink 而非 copy**：GC 删源后 repo 数据存活；EXDEV → error + skip，
//!   绝不降级 copy（copy 产物 GC 管不到成孤儿）。
//! - **源缺失 skip+warn**：`on_disk=1` 但被并发 GC 删除 → 跳过不中断
//!   （staging 与 repodata 同缺该文件，仍自洽）。
//! - **noarch**：硬链进该产品每个具体 arch 的 repo。
//! - **`_repo` 路径隔离**：rename/删除前断言目标严格位于 `_repo` 命名空间
//!   下、不等于共享根。
//! - **锁在换位树之外**：`.repodata-{arch}.lock` 落 `repo_base`（arch 目录
//!   整体会被换位，锁文件在内会随换位分裂锁域）；串行化同 arch regen vs
//!   regen（读者无锁），全量 createrepo_c 幂等。
//! - **staging 残留**：`?` 早退臂就地清理；崩溃残留无 reaper，由产品删除
//!   整树回收——内容非敏感，`.staging-*` 经 `GET /repo/{product}/...` 可达
//!   但只暴露同产品本就（或曾在）公开通道的 repo 内容（server routes/repo.rs），
//!   私有产品另有可见性门 404。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tracing::{debug, error, info, warn};

use crate::engine::lock::{lock_exclusive_async, DEFAULT_FILE_LOCK_TIMEOUT};
use crate::error::CrbsError;
use crate::state::StateStore;

const NOARCH: &str = "noarch";
const SRPMS_DIR: &str = "SRPMS";

/// 一次 repo 组装的统计（供触发方结构化日志）。
#[derive(Debug, Clone, Default)]
pub struct RepoAssembleReport {
    /// 本次触及并重建的目标目录（arch 或 `SRPMS`）。
    pub arches: Vec<String>,
    /// 新建的 hardlink 数。
    pub linked: usize,
    /// 摘除的陈旧文件数（对账式 unlink）。
    pub unlinked: usize,
    /// 源不可用（无 result_dir / 并发 GC 删源）——GC 竞态，下次自然收敛。
    pub skipped_missing: usize,
    /// 候选行无效（result_dir/relative_path/arch/basename 校验失败）——数据
    /// 错误，重试不自愈，需人工排查。
    pub skipped_invalid: usize,
    /// 跨文件系统（EXDEV）而跳过的文件数。
    pub skipped_exdev: usize,
    /// 其他 hardlink 错误而跳过的文件数。
    pub skipped_other: usize,
}

/// 单个源文件的放置结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Linked,
    SkippedMissing,
    SkippedExdev,
    SkippedOther,
}

/// 待硬链接的一个源文件。
#[derive(Debug, Clone)]
struct PlacedFile {
    /// 绝对源路径（`{result_dir}/{relative_path}`）。
    source: PathBuf,
    /// 目标文件名（`N-V-R.A.rpm`）。
    basename: String,
}

/// 路径组件安全性：非空、非 `.`/`..`、不含分隔符/NUL（防穿越）。
fn safe_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\', '\0'])
}

/// relative_path 必须是纯相对路径：非空且每个组件均为 `Component::Normal`——
/// 绝对路径 join 时会**替换** base、`..` 穿越父目录。
fn plain_relative(p: &str) -> bool {
    let mut comps = Path::new(p).components();
    comps
        .next()
        .is_some_and(|c| matches!(c, std::path::Component::Normal(_)))
        && comps.all(|c| matches!(c, std::path::Component::Normal(_)))
}

/// `(dev, ino)` 相同即同一文件（同一 hardlink 链）。
fn same_dev_ino(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// EXDEV（跨文件系统）判定：`nix::libc::EXDEV` 在 Linux/macOS 均为 18。
fn is_exdev(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(nix::libc::EXDEV)
}

/// 由 hardlink 的 io 错误分类放置结果：NotFound（并发 GC 删源）→
/// SkippedMissing，EXDEV → SkippedExdev（**绝不降级 copy**），其他 → SkippedOther。
fn classify_link_error(e: &std::io::Error) -> Placement {
    if e.kind() == std::io::ErrorKind::NotFound {
        Placement::SkippedMissing
    } else if is_exdev(e) {
        Placement::SkippedExdev
    } else {
        Placement::SkippedOther
    }
}

/// 断言目标 arch repo 目录严格位于该产品 `_repo` 命名空间之下、不等于共享根。
fn assert_isolated(result_root: &Path, arch_repo: &Path) -> crate::Result<()> {
    let repo_root = result_root.join("_repo");
    if !crate::util::strictly_within(arch_repo, &repo_root) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "repo arch dir {} escapes _repo namespace under {}",
                arch_repo.display(),
                repo_root.display()
            ),
        });
    }
    Ok(())
}

/// 逐文件跳过日志的聚合器：每类首条带 path，其余静默（轮末计数汇总）。
#[derive(Default)]
struct SkipLogOnce {
    missing: bool,
    exdev: bool,
    other: bool,
}

/// 硬链接一个源文件到目标；EXDEV/缺失一律 skip，**绝不 copy**（日志经 `log` 聚合）。
async fn place_hardlink(source: &Path, dest: &Path, log: &mut SkipLogOnce) -> Placement {
    match tokio::fs::hard_link(source, dest).await {
        Ok(()) => Placement::Linked,
        Err(e) => {
            let outcome = classify_link_error(&e);
            match outcome {
                Placement::SkippedMissing => {
                    if !log.missing {
                        log.missing = true;
                        warn!(
                            source = %source.display(),
                            "publishable RPM source missing (concurrent GC?); skipping"
                        );
                    }
                }
                Placement::SkippedExdev => {
                    if !log.exdev {
                        log.exdev = true;
                        error!(
                            source = %source.display(),
                            dest = %dest.display(),
                            "cross-filesystem hardlink (EXDEV); skipping, refusing silent copy"
                        );
                    }
                }
                _ => {
                    if !log.other {
                        log.other = true;
                        warn!(
                            source = %source.display(),
                            dest = %dest.display(),
                            error = %e,
                            "hardlink failed; skipping"
                        );
                    }
                }
            }
            outcome
        }
    }
}

/// 组装某产品的发布型 repo（`result_root` 为 `result_dir_for_or_default`
/// 解析出的结果根）。`repo_publish` 是产品级发布开关：`false` 时候选集按空
/// → Packages/ 摘空、repo 保留零包。`require_signed=true`（产品声明了签名
/// 策略）时候选集只含已签名构建——未签名产物不得进发布 repo。每 arch 目录
/// 写盘前复查 `products` 行；行已删 → 整轮放弃 `Err(NotFound)`，不重建孤儿
/// `_repo/{product}`。
pub async fn assemble_product_repo(
    state: &StateStore,
    product: &str,
    result_root: &Path,
    repo_publish: bool,
    require_signed: bool,
) -> crate::Result<RepoAssembleReport> {
    assemble_product_repo_impl(
        state,
        product,
        result_root,
        repo_publish,
        require_signed,
        true,
    )
    .await
}

/// `assemble_product_repo` 的实现；`run_createrepo=false` 时不跑
/// `createrepo_c`（单测用）。
async fn assemble_product_repo_impl(
    state: &StateStore,
    product: &str,
    result_root: &Path,
    repo_publish: bool,
    require_signed: bool,
    run_createrepo: bool,
) -> crate::Result<RepoAssembleReport> {
    if !safe_component(product) {
        return Err(CrbsError::ValidationFailed {
            message: format!("unsafe product name for repo assembly: {product}"),
        });
    }

    let mut report = RepoAssembleReport::default();

    // 产品级组装互斥：候选快照必须晚于锁获取。否则两次 regen 交错时，
    // 旧快照（unpublish 前）可在操作员的新 regen 之后拿锁，把已下架的
    // 构建重新链回发布树。per-arch `.repodata` 锁只串行同一目录。
    let lock_dir = result_root.join("_repo").join(".locks");
    tokio::fs::create_dir_all(&lock_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("create repo lock dir", e))?;
    let _assemble_lock = crate::engine::lock::lock_exclusive_async(
        lock_dir.join(format!("{product}.assemble.lock")),
        crate::engine::lock::DEFAULT_FILE_LOCK_TIMEOUT,
    )
    .await?;
    // 对账目录集合 = 期望 ∪ 磁盘现存（把已下线/全 GC 的 arch 目录摘空收敛）。
    let repo_base = result_root.join("_repo").join(product);

    let candidates = if repo_publish {
        state.list_publishable_rpms(product, require_signed).await?
    } else {
        Vec::new()
    };

    let mut targets: BTreeMap<String, Vec<PlacedFile>> = BTreeMap::new();
    let mut noarch_files: Vec<PlacedFile> = Vec::new();
    let mut concrete: BTreeSet<String> = BTreeSet::new();

    for c in &candidates {
        let Some(placed) = resolve_placed_file(c, result_root, &mut report).await else {
            continue;
        };
        match c.kind.as_str() {
            "srpm" => targets
                .entry(SRPMS_DIR.to_string())
                .or_default()
                .push(placed),
            "rpm" => match c.arch.as_deref() {
                Some(NOARCH) => noarch_files.push(placed),
                Some(a) if safe_component(a) => {
                    concrete.insert(a.to_string());
                    targets.entry(a.to_string()).or_default().push(placed);
                }
                other => {
                    warn!(
                        build_id = c.build_id,
                        arch = ?other,
                        "rpm with missing/unsafe arch; skipping"
                    );
                    report.skipped_invalid += 1;
                }
            },
            _ => {}
        }
    }

    // noarch → 硬链进每个具体 arch。候选行的 rpm arch ∪ 产品配置 arches 全集：
    // 只看候选行会在"本轮只有一个具体 arch 候选 + 产品多架构"时漏掉其余架构
    // （已发布的 noarch 副本被对账摘空）；配置解析失败退化为候选集。
    if !noarch_files.is_empty() {
        concrete.extend(product_concrete_arches(state, product).await);
    }
    if !noarch_files.is_empty() && concrete.is_empty() {
        warn!(
            product,
            "noarch RPMs present but product has no concrete arch; noarch left unplaced"
        );
    }
    for nf in &noarch_files {
        for arch in &concrete {
            targets.entry(arch.clone()).or_default().push(nf.clone());
        }
    }

    let mut all_dirs: BTreeSet<String> = targets.keys().cloned().collect();
    if tokio::fs::try_exists(&repo_base).await.unwrap_or(false) {
        let mut rd = tokio::fs::read_dir(&repo_base)
            .await
            .map_err(|e| CrbsError::from_io_context("read _repo dir", e))?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("read _repo entry", e))?
        {
            let ft = entry
                .file_type()
                .await
                .map_err(|e| CrbsError::from_io_context("stat _repo entry", e))?;
            if ft.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    // 点前缀目录（`.staging-*`）不是 arch 目录，不进对账集合
                    // ——否则下轮 regen 会给它建 Packages/ 并跑 createrepo。
                    if safe_component(name) && !name.starts_with('.') {
                        all_dirs.insert(name.to_string());
                    }
                }
            }
        }
    }

    // 逐目录对账 + createrepo（各自持 repo_base 下 `.repodata-{arch}.lock`）。
    // 单目录失败不中断其余目录，但全部走完后仍向上报错——重试只补失败目录。
    let empty: Vec<PlacedFile> = Vec::new();
    let mut failed_dirs: Vec<String> = Vec::new();
    let mut skip_log = SkipLogOnce::default();
    for arch_dir in &all_dirs {
        let desired = targets.get(arch_dir).unwrap_or(&empty);
        if let Err(e) = reconcile_dir(ReconcileDirCtx {
            state,
            product,
            result_root,
            arch_dir,
            desired,
            run_createrepo,
            report: &mut report,
            skip_log: &mut skip_log,
        })
        .await
        {
            // NotFound 哨兵 = 行确认已删 → 放弃剩余目录（否则重建被清掉的
            // 孤儿）。查询失败透传真实错误、不伪装 NotFound（手动命令把
            // NotFound 映射 404，DB 故障折进去误导），不在此中止剩余目录。
            if matches!(&e, CrbsError::NotFound { .. }) {
                warn!(
                    product,
                    error = %e,
                    "Abandoning repo regen round: product row gone"
                );
                return Err(e);
            }
            error!(
                product,
                arch_dir = %arch_dir,
                error = %e,
                "repo dir reconcile failed; continuing with remaining dirs"
            );
            failed_dirs.push(arch_dir.clone());
        }
    }

    info!(
        product,
        arches = ?report.arches,
        linked = report.linked,
        unlinked = report.unlinked,
        skipped_missing = report.skipped_missing,
        skipped_invalid = report.skipped_invalid,
        skipped_exdev = report.skipped_exdev,
        skipped_other = report.skipped_other,
        failed_dirs = ?failed_dirs,
        "Assembled product repo"
    );
    if !failed_dirs.is_empty() {
        return Err(CrbsError::io_message(format!(
            "repo reconcile failed for {} dir(s): {} (remaining dirs converged)",
            failed_dirs.len(),
            failed_dirs.join(", ")
        )));
    }
    Ok(report)
}

/// 产品配置解析出的具体 arch 集（过滤 `noarch`，复用 [`safe_component`]）。
/// 配置不可解析 → 空集（保持 unplaced 不报错）；仅在纯 noarch 落位回退时
/// 调用，常态组装不多这一次 DB 查询。
async fn product_concrete_arches(state: &StateStore, product: &str) -> Vec<String> {
    match state.resolve_any_product_by_name(product).await {
        Ok(resolved) => resolved
            .config
            .arches
            .iter()
            .filter(|a| a.as_str() != NOARCH && safe_component(a))
            .cloned()
            .collect(),
        Err(e) => {
            tracing::debug!(
                product,
                error = %e,
                "cannot resolve product config for noarch placement fallback; leaving unplaced"
            );
            Vec::new()
        }
    }
}

/// 候选行还原为绝对源路径 + basename；行无效记 `skipped_invalid` 返回
/// None，无 result_dir 记 `skipped_missing` 同样返回 None。
async fn resolve_placed_file(
    c: &crate::state::artifacts::PublishableRpm,
    result_root: &Path,
    report: &mut RepoAssembleReport,
) -> Option<PlacedFile> {
    let Some(result_dir) = c.result_dir.as_deref() else {
        warn!(
            build_id = c.build_id,
            "publishable build has no result_dir; skipping"
        );
        report.skipped_missing += 1;
        return None;
    };
    // 复用 result_dir 防穿越校验（源必须位于 result_root 之下）。
    let base = match crate::util::validate_result_dir(result_dir, result_root).await {
        Ok(b) => b,
        Err(e) => {
            warn!(
                build_id = c.build_id,
                result_dir, error = %e,
                "result_dir validation failed; skipping"
            );
            report.skipped_invalid += 1;
            return None;
        }
    };
    // relative_path 防穿越：只接受纯相对路径（绝对路径 join 时会替换 base）。
    if !plain_relative(&c.relative_path) {
        warn!(
            build_id = c.build_id,
            relative_path = %c.relative_path,
            "relative_path is not a plain relative path (absolute/parent/cur dir); skipping"
        );
        report.skipped_invalid += 1;
        return None;
    }
    let source = base.join(&c.relative_path);
    let basename = match source.file_name().and_then(|n| n.to_str()) {
        Some(n) if safe_component(n) => n.to_string(),
        _ => {
            warn!(
                build_id = c.build_id,
                relative_path = %c.relative_path,
                "cannot derive safe basename; skipping"
            );
            report.skipped_invalid += 1;
            return None;
        }
    };
    Some(PlacedFile { source, basename })
}

/// `createrepo_c --outputdir`（staging 构建相）：扫描 `repo_dir`（新树的
/// `Packages/` 已就位），repodata 写进 `outputdir/repodata/`。staging 模式
/// 下扫描源 = outputdir 同目录，写出的 `repodata/` 非 RPM、不入元数据。
async fn run_createrepo_c_staging(repo_dir: &Path, outputdir: &Path) -> crate::Result<()> {
    let label = "createrepo_c --outputdir";
    let mut cmd = tokio::process::Command::new("createrepo_c");
    cmd.arg("--outputdir").arg(outputdir).arg(repo_dir);
    // 10 分钟预算：卡死的 createrepo_c 不得无限占用持 `.repodata-{arch}.lock`
    // 的更新路径。
    let output = crate::engine::command::run_command_capped_output_with_timeout(
        cmd,
        label,
        std::time::Duration::from_secs(600),
    )
    .await
    .map_err(|e| CrbsError::io_message(e.to_string()))?;
    if !output.status.success() {
        return Err(CrbsError::io_message(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// staging 收尾：删除点前缀 `.staging-*` 目录。删除前断言 staging 严格位于
/// `_repo/{product}`（`repo_base`）下且不等于其本身——宁留残不误删共享根。
async fn remove_staging(repo_base: &Path, staging: &Path) {
    if !crate::util::strictly_within(staging, repo_base) {
        warn!(
            staging = %staging.display(),
            repo_base = %repo_base.display(),
            "repo staging dir escapes product repo namespace; refusing removal"
        );
        return;
    }
    match tokio::fs::remove_dir_all(staging).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            staging = %staging.display(),
            error = %e,
            "failed to remove repo staging dir"
        ),
    }
}

/// `renameat2(RENAME_EXCHANGE)` 换位试探：true = 换位已原子完成（staging 与
/// arch_repo 内容互换）。不支持（非 Linux-glibc 编译目标、旧内核、文件系统
/// 拒绝）→ false，调用方走两段 rename 兜底。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
async fn try_exchange_dirs(a: &Path, b: &Path) -> bool {
    let (a, b) = (a.to_path_buf(), b.to_path_buf());
    tokio::task::spawn_blocking(move || {
        nix::fcntl::renameat2::<Path, Path>(
            None,
            &a,
            None,
            &b,
            nix::fcntl::RenameFlags::RENAME_EXCHANGE,
        )
        .is_ok()
    })
    .await
    .unwrap_or(false)
}

/// 非 Linux-glibc 目标无 `renameat2` 入口：恒走两段 rename 兜底。
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
async fn try_exchange_dirs(_a: &Path, _b: &Path) -> bool {
    false
}

/// arch 目录整树换位：`staging`（新树：Packages/ + repodata/）换成
/// `arch_repo`，旧树清出。换位后磁盘只见完整旧树或完整新树（模块 doc
/// 自洽不变量），两段 rename 兜底臂窗口内读者可能瞬态失败。`arch_repo`
/// 不存在（首建）→ staging 直接 rename 入位、无旧树。任一失败臂 staging
/// 已就地清理并返回 Err（调用方计入 failed_dirs）：换位失败 = 本 arch
/// 本轮未重建。
async fn swap_arch_dir_into_place(
    repo_base: &Path,
    arch_repo: &Path,
    staging: &Path,
) -> crate::Result<()> {
    match tokio::fs::try_exists(arch_repo).await {
        Ok(false) => {
            if let Err(e) = tokio::fs::rename(staging, arch_repo).await {
                // 首建入位失败：staging 原地清理（新树可弃，源产物无损）。
                remove_staging(repo_base, staging).await;
                warn!(
                    arch_repo = %arch_repo.display(),
                    error = %e,
                    "failed to move staged repo into place (first publish)"
                );
                return Err(CrbsError::from_io_context(
                    "move staged repo tree into place (first publish)",
                    e,
                ));
            }
            return Ok(());
        }
        Ok(true) => {}
        Err(e) => {
            warn!(
                arch_repo = %arch_repo.display(),
                error = %e,
                "cannot stat arch repo dir; staged tree discarded"
            );
            remove_staging(repo_base, staging).await;
            return Err(CrbsError::from_io_context("stat arch repo dir", e));
        }
    }

    if try_exchange_dirs(arch_repo, staging).await {
        // 换位后旧树位于 staging 路径：整树清出（hardlink 副本，删链不删源）。
        remove_staging(repo_base, staging).await;
        return Ok(());
    }

    // 两段 rename 兜底：旧树挪进 `.staging-{arch}-retired-{uuid}`、新树入位；
    // 第二段失败回滚第一段（旧树原位，等效未换位）。窗口内 arch 目录缺失，
    // 读者可能瞬态失败；该次构建失败重跑即恢复。
    let retired = repo_base.join(format!(".staging-retired-{}", uuid::Uuid::new_v4()));
    if let Err(e) = tokio::fs::rename(arch_repo, &retired).await {
        warn!(
            arch_repo = %arch_repo.display(),
            error = %e,
            "failed to move old repo tree aside; staged tree discarded, retry next round"
        );
        remove_staging(repo_base, staging).await;
        return Err(CrbsError::from_io_context("move old repo tree aside", e));
    }
    if let Err(e) = tokio::fs::rename(staging, arch_repo).await {
        if let Err(rb) = tokio::fs::rename(&retired, arch_repo).await {
            warn!(
                arch_repo = %arch_repo.display(),
                error = %rb,
                "failed to roll back old repo tree after staged swap failure; \
                 arch repo stays absent until the next successful regen"
            );
        }
        warn!(
            arch_repo = %arch_repo.display(),
            error = %e,
            "failed to move staged repo into place; old tree restored"
        );
        remove_staging(repo_base, staging).await;
        return Err(CrbsError::from_io_context(
            "move staged repo tree into place",
            e,
        ));
    }
    remove_staging(repo_base, &retired).await;
    Ok(())
}

/// 单 arch 目录对账上下文（`report`/`skip_log` 持可变借用穿透整个写盘流程）。
struct ReconcileDirCtx<'a> {
    state: &'a StateStore,
    product: &'a str,
    result_root: &'a Path,
    arch_dir: &'a str,
    desired: &'a [PlacedFile],
    run_createrepo: bool,
    report: &'a mut RepoAssembleReport,
    skip_log: &'a mut SkipLogOnce,
}

/// 对账式重建单个 arch repo：createrepo 模式整树 staging 构建 + 原子换位
/// （`(文件, repodata)` 恒自洽，见模块 doc）；非 createrepo 模式（单测用）
/// 维持原地对账 unlink。
///
/// 任何写盘动作之前（建目录与锁文件即写盘）复查 `products` 行仍在：删除
/// 路径先删行后清磁盘，不复查会重建孤儿目录；复查放每目录写盘前，把窗口
/// 收窄到单目录写盘期（锁无法互斥，收窄而非消除）。行已删 → `NotFound`
/// 哨兵（调用方放弃本轮）；查询失败 → 原样透传（服务端 500/503），不伪装
/// NotFound——手动 rebuild-repo 把 NotFound 映射 404，DB 故障折进去误导
/// 操作员。
async fn reconcile_dir(ctx: ReconcileDirCtx<'_>) -> crate::Result<()> {
    let ReconcileDirCtx {
        state,
        product,
        result_root,
        arch_dir,
        desired,
        run_createrepo,
        report,
        skip_log,
    } = ctx;
    match state.product_row_exists(product).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(CrbsError::NotFound {
                message: format!("product row gone, skip repo write for {product}"),
            });
        }
        Err(e) => {
            // 双报收敛：同一 e 由调用方逐目录 error! 统一报告，此处降 debug 留上下文。
            debug!(
                product,
                error = %e,
                "Failed to check product row before repo write; abandoning round"
            );
            return Err(e);
        }
    }

    // 与 impl 的对账目录集合派生同式（{result_root}/_repo/{product}）。
    let repo_base = result_root.join("_repo").join(product);
    let arch_repo = repo_base.join(arch_dir);
    assert_isolated(result_root, &arch_repo)?;
    let packages = arch_repo.join("Packages");
    // 权限不变量：root 首建按 umask 落 0755/root 组，组身份后续 regen 全链
    // EACCES；ensure_directory 只收敛最终目录，故从 `_repo` 根到 `Packages/`
    // 逐级收敛（chmod 失败 warn、非 root chown 失败 debug，不阻断）。
    // createrepo 模式下 arch 树由 staging 换位提供，这里收敛的是既有树
    //（换位后 staging 侧自带收敛）。
    let dirs = vec![
        result_root.join("_repo"),
        repo_base.clone(),
        arch_repo.clone(),
        packages.clone(),
    ];
    tokio::task::spawn_blocking(move || -> crate::Result<()> {
        for d in &dirs {
            crate::privilege::ensure_directory(d, "_repo dir")?;
        }
        Ok(())
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking ensure _repo dirs: {e}")))??;

    // 串行化同 arch 的 regen vs regen（读者无锁）。锁文件必须落在被换位的
    // arch 目录之外：arch 目录整体换入换出，锁在内会随换位分裂锁域——
    // 旧锁 inode 随旧树进 staging 被删，新 regen 在同名路径锁上新文件，
    // 互斥失效。
    let lock_path = repo_base.join(format!(".repodata-{arch_dir}.lock"));
    let _lock = lock_exclusive_async(lock_path, DEFAULT_FILE_LOCK_TIMEOUT).await?;

    let desired_names: BTreeSet<&str> = desired.iter().map(|p| p.basename.as_str()).collect();

    if !run_createrepo {
        reconcile_dir_in_place(&packages, desired, desired_names, report, skip_log).await?;
        report.arches.push(arch_dir.to_string());
        return Ok(());
    }

    // ── createrepo 模式：整树 staging 构建 + 原子换位 ──
    // 旧 Packages 清点（unlinked 计数 + linked 去重判定）；目录缺失（首建）
    // 视为空树。
    let mut old_entries: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    match tokio::fs::read_dir(&packages).await {
        Ok(mut rd) => {
            while let Some(entry) = rd
                .next_entry()
                .await
                .map_err(|e| CrbsError::from_io_context("read old Packages entry", e))?
            {
                let meta = entry
                    .metadata()
                    .await
                    .map_err(|e| CrbsError::from_io_context("stat old Packages entry", e))?;
                if !meta.is_file() {
                    continue; // Packages/ 只含 hardlink 的普通文件
                }
                if let Some(name) = entry.file_name().to_str() {
                    use std::os::unix::fs::MetadataExt;
                    old_entries.insert(name.to_string(), (meta.dev(), meta.ino()));
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(CrbsError::from_io_context("read old Packages dir", e)),
    }
    report.unlinked += old_entries
        .keys()
        .filter(|n| !desired_names.contains(n.as_str()))
        .count();

    // staging 带 uuid 隔离（regen 已被锁串行化，uuid 另防崩溃残留与新轮次
    // 混装）。新树 = 全量候选 hardlink（Packages/）+ createrepo（repodata/），
    // 任一失败臂就地清 staging、旧树全程未动——无隔离回放需求。
    let staging = repo_base.join(format!(".staging-{}-{}", arch_dir, uuid::Uuid::new_v4()));
    let staging_packages = staging.join("Packages");
    // 权限不变量同 `_repo` 树（staging 换位后即服务目录）。
    let dirs = [staging.clone(), staging_packages.clone()];
    let ensured = tokio::task::spawn_blocking(move || -> crate::Result<()> {
        for d in &dirs {
            crate::privilege::ensure_directory(d, "repo staging dir")?;
        }
        Ok(())
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking ensure repo staging: {e}")))
    .and_then(|inner| inner);
    if let Err(e) = ensured {
        // 直测豁免：staging 名含随机 uuid 无法预置碰撞，repo_base 已被上方
        // ensure 臂收敛可写，权限注入也到不了本臂；清理语义由 remove_staging
        // 直测与成功路径无残留断言覆盖。
        remove_staging(&repo_base, &staging).await;
        return Err(e);
    }

    // 缺则全量 link：hardlink 幂等。旧树同名同 (dev, ino) → 未变化不计
    // linked；同名不同 inode（同 NVRA 换胜出构建）→ 新树直接链新源，旧
    // inode 随换位消失。同 basename 多行首行胜出（候选 SQL 按 build_id DESC）。
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    for p in desired {
        if placed.contains(p.basename.as_str()) {
            continue;
        }
        let dest = staging_packages.join(&p.basename);
        let unchanged = match (
            old_entries.get(p.basename.as_str()),
            tokio::fs::metadata(&p.source).await,
        ) {
            (Some(&(odev, oino)), Ok(sm)) => {
                use std::os::unix::fs::MetadataExt;
                odev == sm.dev() && oino == sm.ino()
            }
            _ => false,
        };
        match place_hardlink(&p.source, &dest, skip_log).await {
            Placement::Linked => {
                if !unchanged {
                    report.linked += 1;
                }
                placed.insert(p.basename.as_str());
            }
            Placement::SkippedMissing => report.skipped_missing += 1,
            Placement::SkippedExdev => report.skipped_exdev += 1,
            Placement::SkippedOther => report.skipped_other += 1,
        }
    }

    // 全量 createrepo_c（幂等）：扫描 staging（Packages/ 已就位），repodata
    // 写进 staging/repodata/。失败臂：staging 就地清理，旧树（文件 +
    // repodata）原样服务。
    if let Err(e) = run_createrepo_c_staging(&staging, &staging).await {
        remove_staging(&repo_base, &staging).await;
        return Err(e);
    }
    // repodata 权限收敛（仅 repodata/ 子树，换位前完成）：staged repodata 按
    // 调用方 umask 落 0755/0644，root 首建后组身份 regen 写 repodata 即
    // EACCES。不收敛 Packages/：chmod 会连带改 hardlink 源产物 inode 的 mode。
    // walker：目录 2770、文件 & 0o666 = 0660；失败仅 warn 留下次补齐。
    let staging_repodata = staging.join("repodata");
    if let Err(e) = crate::engine::layer::chmod_recursive(&staging_repodata, 0o2770).await {
        warn!(
            path = %staging_repodata.display(),
            error = %e,
            "converge staged repodata perms to 2770/0660 failed; deferring to next regen"
        );
    }

    // 原子换位 + 旧树清出（含陈旧文件——不在候选集的文件随旧树消失）。
    // 失败 Err 上抛 → failed_dirs（失败臂 staging 已清，本 arch 本轮未重建）。
    swap_arch_dir_into_place(&repo_base, &arch_repo, &staging).await?;
    report.arches.push(arch_dir.to_string());
    Ok(())
}

/// 非 createrepo 模式（单测用）的原地对账：多则 unlink、缺则 link、不跑
/// createrepo 不换位。与 staging 路径的产出等价（无 repodata 重建语义差异
/// 由调用方保证只用于无 createrepo_c 的测试环境）。
async fn reconcile_dir_in_place(
    packages: &Path,
    desired: &[PlacedFile],
    desired_names: BTreeSet<&str>,
    report: &mut RepoAssembleReport,
    skip_log: &mut SkipLogOnce,
) -> crate::Result<()> {
    // 多则摘除：不在候选集的陈旧文件原位 unlink（删除前断言：目标严格位于
    // 本 Packages/ 之下、不等于共享根）。失败聚合单条 warn；未摘除的陈旧
    // 文件下轮对账重试。
    let mut unlink_failures: usize = 0;
    let mut first_unlink_failure: Option<(PathBuf, std::io::Error)> = None;
    let mut rd = tokio::fs::read_dir(packages)
        .await
        .map_err(|e| CrbsError::from_io_context("read Packages dir", e))?;
    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("read Packages entry", e))?
    {
        let ft = entry
            .file_type()
            .await
            .map_err(|e| CrbsError::from_io_context("stat Packages entry", e))?;
        if !ft.is_file() {
            continue; // Packages/ 只含 hardlink 的普通文件
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if desired_names.contains(name_str) {
            continue;
        }
        let victim = entry.path();
        if !crate::util::strictly_within(&victim, packages) {
            warn!(path = %victim.display(), "unlink target escapes Packages namespace; refusing");
            continue;
        }
        match tokio::fs::remove_file(&victim).await {
            Ok(()) => report.unlinked += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                unlink_failures += 1;
                if first_unlink_failure.is_none() {
                    first_unlink_failure = Some((victim.clone(), e));
                }
            }
        }
    }
    if let Some((path, e)) = first_unlink_failure {
        warn!(
            path = %path.display(),
            error = %e,
            failures = unlink_failures,
            "failed to unlink stale repo file(s); leaving them in place for this round"
        );
    }

    // 缺则 link：hardlink 幂等。dest 与源同 `(dev, ino)` 即跳过；同名不同
    // inode（同 NVRA 换胜出构建）→ 摘旧链链新源，否则 repo 服务旧字节。同
    // basename 多行首行胜出（候选 SQL 按 build_id DESC）。
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    for p in desired {
        if placed.contains(p.basename.as_str()) {
            continue;
        }
        let dest = packages.join(&p.basename);
        match (
            tokio::fs::metadata(&dest).await,
            tokio::fs::metadata(&p.source).await,
        ) {
            (Ok(dm), Ok(sm)) if same_dev_ino(&dm, &sm) => {
                placed.insert(p.basename.as_str());
                continue;
            }
            (Ok(_), Ok(_)) => {
                // 陈旧 inode：摘旧再链新（瞬态窗口与对账 unlink 的 404 窗口同款）。
                if let Err(e) = tokio::fs::remove_file(&dest).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(path = %dest.display(), error = %e, "failed to unlink stale-inode repo file");
                    }
                }
            }
            // dest 不存在 / 源不可达：交给 place_hardlink 分类（源缺失保留 dest 旧字节）。
            _ => {}
        }
        match place_hardlink(&p.source, &dest, skip_log).await {
            Placement::Linked => {
                report.linked += 1;
                placed.insert(p.basename.as_str());
            }
            Placement::SkippedMissing => report.skipped_missing += 1,
            Placement::SkippedExdev => report.skipped_exdev += 1,
            Placement::SkippedOther => report.skipped_other += 1,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::artifacts::{ArtifactKind, NewArtifact};
    use crate::state::test_state::create_test_store;

    /// rpmbuild 固化的最小合法 noarch RPM（crbs-test-fixture 1.0-1，1 字节
    /// payload）。文件名与内部 NEVRA 不一致无妨（createrepo_c 只读 header）；
    /// 重生成：装有 rpmbuild 的 Linux 上按 spec `rpmbuild -bb` 后覆盖本文件。
    const FIXTURE_RPM: &[u8] =
        include_bytes!("../../tests/fixtures/rpms/crbs-test-fixture-1.0-1.noarch.rpm");

    /// createrepo_c 是否可用（缺失时跳过依赖它的断言）。
    fn createrepo_available() -> bool {
        std::process::Command::new("createrepo_c")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// 在 `result_root/{build_id}/` 下建一个 build 的结果目录并写入产物文件，
    /// 同时插入 builds 行（可设 phase / repo_publish）与 build_artifacts 行。
    async fn seed_build(
        store: &StateStore,
        result_root: &Path,
        build_id: i64,
        product: &str,
        phase: &str,
        repo_publish: i64,
        artifacts: &[NewArtifact],
    ) {
        let result_dir = result_root.join(build_id.to_string());
        // 写实际文件（用于 hardlink 校验）：真 RPM 字节，createrepo_c 可解析。
        for a in artifacts {
            let full = result_dir.join(&a.relative_path);
            if let Some(parent) = full.parent() {
                tokio::fs::create_dir_all(parent).await.unwrap();
            }
            tokio::fs::write(&full, FIXTURE_RPM).await.unwrap();
        }
        let result_dir_str = result_dir.to_string_lossy().to_string();
        // builds.task_id NOT NULL：先插本地任务行承接。
        let task_id: i64 = sqlx::query_scalar(
            "INSERT INTO tasks (product, pkg_name, \"user\", phase) VALUES ($1, 'pkg', '', 'succeeded') RETURNING id",
        )
        .bind(product)
        .fetch_one(store.pool())
        .await
        .unwrap();
        // 一并 seed products 行（owner_id NULL + public 满足 CHECK）；
        // ON CONFLICT DO NOTHING 兼容双方言与重复 seed（name 全局 UNIQUE）。
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json) VALUES ($1, 'public', '{}') \
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(product)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO builds (id, product, pkg_name, phase, backend, name, version, release, started_at, result_dir, repo_publish, task_id) \
             VALUES ($1, $2, 'pkg', $3, 'mock', 'pkg', '1.0', '1', 'now', $4, $5, $6)",
        )
        .bind(build_id)
        .bind(product)
        .bind(phase)
        .bind(&result_dir_str)
        .bind(repo_publish)
        .bind(task_id)
        .execute(store.pool())
        .await
        .unwrap();

        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(&mut tx, build_id, artifacts, "2026-01-01 00:00:00")
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    fn rpm(rel: &str, name: &str, ver: &str, rel_num: &str, arch: &str) -> NewArtifact {
        NewArtifact {
            relative_path: rel.to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: FIXTURE_RPM.len() as u64,
            sha256: format!("sha-{name}-{ver}-{rel_num}-{arch}"),
            unsigned_sha256: None,
            arch: Some(arch.to_string()),
            name: Some(name.to_string()),
            version: Some(ver.to_string()),
            release: Some(rel_num.to_string()),
            epoch: None,
            metadata_json: None,
            signed: false,
        }
    }

    /// 同一 inode 判定：两个路径的 (dev, ino) 相同即为同一 hardlink。
    async fn same_inode(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let ma = tokio::fs::metadata(a).await.unwrap();
        let mb = tokio::fs::metadata(b).await.unwrap();
        ma.dev() == mb.dev() && ma.ino() == mb.ino()
    }

    /// ①：组装 → Packages/ 含 RPM、hardlink inode 与源一致；createrepo 可用时 repodata 存在。
    #[tokio::test]
    async fn assemble_links_rpm_and_builds_repodata() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/pkg-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "pkg", "1.0", "1", "x86_64")],
        )
        .await;

        // 完整路径（含 createrepo）仅 createrepo_c 可用时跑；否则用 impl 跳过。
        if createrepo_available() {
            assemble_product_repo(&store, "prod", root.path(), true, false)
                .await
                .unwrap();
            let repodata = root.path().join("_repo/prod/x86_64/repodata/repomd.xml");
            assert!(
                tokio::fs::try_exists(&repodata).await.unwrap(),
                "repodata/repomd.xml should exist"
            );
        } else {
            assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
                .await
                .unwrap();
        }

        let linked = root
            .path()
            .join("_repo/prod/x86_64/Packages/pkg-1.0-1.x86_64.rpm");
        assert!(tokio::fs::try_exists(&linked).await.unwrap());
        let src = root.path().join("1").join(rel);
        assert!(
            same_inode(&linked, &src).await,
            "must be a hardlink to source"
        );
    }

    /// `_repo` 树权限不变量：组装后逐级收敛 2770；仅断言 mode（非 root
    /// chown 必 EPERM，见 privilege::ensure_directory）。
    #[tokio::test]
    async fn assemble_converges_repo_tree_dir_modes() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/pkg-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "pkg", "1.0", "1", "x86_64")],
        )
        .await;

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();

        for dir in [
            "_repo",
            "_repo/prod",
            "_repo/prod/x86_64",
            "_repo/prod/x86_64/Packages",
        ] {
            let meta = tokio::fs::metadata(root.path().join(dir)).await.unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                0o2770,
                "{dir} must converge to 2770 (setgid + group rwx)"
            );
        }
    }

    /// 存量坏树自愈：std::fs 预置的 0755 `_repo` 层级，下次 regen 同样收敛
    /// 2770——若收敛只在创建路径生效，本断言必红。
    #[tokio::test]
    async fn assemble_converges_preexisting_0755_repo_tree() {
        use std::os::unix::fs::PermissionsExt;
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/pkg-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "pkg", "1.0", "1", "x86_64")],
        )
        .await;

        // 存量 0755 目录树（无 setgid、无组写）。
        let legacy = [
            "_repo",
            "_repo/prod",
            "_repo/prod/x86_64",
            "_repo/prod/x86_64/Packages",
        ];
        for dir in legacy {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
            std::fs::set_permissions(
                root.path().join(dir),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();

        for dir in legacy {
            let meta = tokio::fs::metadata(root.path().join(dir)).await.unwrap();
            assert_eq!(
                meta.permissions().mode() & 0o7777,
                0o2770,
                "preexisting 0755 {dir} must self-heal to 2770 on regen"
            );
        }
    }

    /// repodata 收敛：`repodata/` 2770、`repomd.xml` 0660（目录全 mode、
    /// 文件 & 0o666）。无 createrepo_c 环境跳过。
    #[tokio::test]
    async fn assemble_converges_repodata_modes() {
        if !createrepo_available() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/pkg-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "pkg", "1.0", "1", "x86_64")],
        )
        .await;

        assemble_product_repo(&store, "prod", root.path(), true, false)
            .await
            .unwrap();

        let repodata = root.path().join("_repo/prod/x86_64/repodata");
        let dir_meta = tokio::fs::metadata(&repodata).await.unwrap();
        assert_eq!(
            dir_meta.permissions().mode() & 0o7777,
            0o2770,
            "repodata dir must converge to 2770"
        );
        let repomd = repodata.join("repomd.xml");
        let file_meta = tokio::fs::metadata(&repomd).await.unwrap();
        assert_eq!(
            file_meta.permissions().mode() & 0o777,
            0o660,
            "repomd.xml must converge to 0660"
        );
    }

    /// 产品行在 regen 在途被删 → 整轮放弃（Err NotFound），`_repo/{product}`
    /// 一个字节都不再重建（连 Packages/ 骨架与 `.repodata-{arch}.lock` 也不落盘）。
    #[tokio::test]
    async fn assemble_aborts_when_product_row_deleted() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/pkg-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "pkg", "1.0", "1", "x86_64")],
        )
        .await;

        // 先删 products 行（磁盘清理由 server 侧；本测试聚焦行删后不再写盘）。
        sqlx::query("DELETE FROM products WHERE name = $1")
            .bind("prod")
            .execute(store.pool())
            .await
            .unwrap();

        let res = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false).await;
        assert!(
            matches!(res, Err(CrbsError::NotFound { .. })),
            "产品行已删必须以 NotFound 哨兵放弃本轮: {res:?}"
        );
        assert!(
            !tokio::fs::try_exists(root.path().join("_repo/prod"))
                .await
                .unwrap(),
            "行删后 regen 不得重建孤儿 _repo 目录"
        );
    }

    /// 不合格产物三态排除：on_disk=0 / phase=failed / repo_publish=0 都不进 repo。
    #[tokio::test]
    async fn excludes_offdisk_failed_and_norepo() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();

        // build 1：failed（不应进）
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "failed",
            1,
            &[rpm(
                "RPMS/x86_64/failed-1.0-1.x86_64.rpm",
                "failed",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;
        // build 2：succeeded 但 repo_publish=0（--no-publish 收紧，不应进）
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            0,
            &[rpm(
                "RPMS/x86_64/norepo-1.0-1.x86_64.rpm",
                "norepo",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;
        // build 3：succeeded 但 artifact on_disk=0（GC 后，不应进）
        seed_build(
            &store,
            root.path(),
            3,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/x86_64/gone-1.0-1.x86_64.rpm",
                "gone",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;
        store.mark_artifacts_off_disk(3).await.unwrap();
        // build 4：正常应进
        seed_build(
            &store,
            root.path(),
            4,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/x86_64/ok-1.0-1.x86_64.rpm",
                "ok",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 1, "only the ok build should be linked");

        let pkgs = root.path().join("_repo/prod/x86_64/Packages");
        assert!(tokio::fs::try_exists(pkgs.join("ok-1.0-1.x86_64.rpm"))
            .await
            .unwrap());
        assert!(!tokio::fs::try_exists(pkgs.join("failed-1.0-1.x86_64.rpm"))
            .await
            .unwrap());
        assert!(!tokio::fs::try_exists(pkgs.join("norepo-1.0-1.x86_64.rpm"))
            .await
            .unwrap());
        assert!(!tokio::fs::try_exists(pkgs.join("gone-1.0-1.x86_64.rpm"))
            .await
            .unwrap());
    }

    /// ③：同 NVRA 两次成功构建 → repo 只含最近一次；再 rebuild 同 NVRA
    ///（新文件 = 新 inode）→ 再组装必须**换链**到新构建、服务新字节。
    #[tokio::test]
    async fn dedups_same_nvra_to_latest_build() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/dup-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "dup", "1.0", "1", "x86_64")],
        )
        .await;
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "dup", "1.0", "1", "x86_64")],
        )
        .await;

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 1, "same NVRA must dedup to a single file");

        let linked = root
            .path()
            .join("_repo/prod/x86_64/Packages/dup-1.0-1.x86_64.rpm");
        let src2 = root.path().join("2").join(rel);
        assert!(
            same_inode(&linked, &src2).await,
            "latest build (MAX(build_id)) must win"
        );

        // 第三次构建同 NVRA、内容不同 → 再组装必须摘旧链、硬链新字节。
        seed_build(
            &store,
            root.path(),
            3,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "dup", "1.0", "1", "x86_64")],
        )
        .await;
        let src3 = root.path().join("3").join(rel);
        let new_bytes = b"rebuilt-different-content";
        tokio::fs::write(&src3, new_bytes).await.unwrap();

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 1, "stale inode must be swapped to new build");
        assert!(
            same_inode(&linked, &src3).await,
            "rebuild must swap the link to the new build's inode"
        );
        let served = tokio::fs::read(&linked).await.unwrap();
        assert_eq!(
            served, new_bytes,
            "repo must serve the rebuilt bytes, not the old inode's"
        );
    }

    /// ④：noarch RPM 出现在每个具体 arch 的 repo。
    #[tokio::test]
    async fn noarch_copied_into_every_concrete_arch() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[
                rpm("RPMS/x86_64/a-1.0-1.x86_64.rpm", "a", "1.0", "1", "x86_64"),
                rpm(
                    "RPMS/aarch64/a-1.0-1.aarch64.rpm",
                    "a",
                    "1.0",
                    "1",
                    "aarch64",
                ),
                rpm("RPMS/noarch/m-1.0-1.noarch.rpm", "m", "1.0", "1", "noarch"),
            ],
        )
        .await;

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();

        for arch in ["x86_64", "aarch64"] {
            let noarch_link = root
                .path()
                .join(format!("_repo/prod/{arch}/Packages/m-1.0-1.noarch.rpm"));
            assert!(
                tokio::fs::try_exists(&noarch_link).await.unwrap(),
                "noarch must appear in {arch} repo"
            );
        }
        assert!(
            !tokio::fs::try_exists(root.path().join("_repo/prod/noarch"))
                .await
                .unwrap()
        );
    }

    /// 产品配置多架构但本轮只有一个具体 arch 候选：noarch 仍须落进全部配置
    /// 架构（否则其余架构已发布的 noarch 副本会被对账摘空）。
    #[tokio::test]
    async fn noarch_union_configured_arches_with_concrete_candidates() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        create_product_with_arches(&store, &["x86_64", "aarch64"]).await;
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[
                rpm("RPMS/x86_64/a-1.0-1.x86_64.rpm", "a", "1.0", "1", "x86_64"),
                rpm("RPMS/noarch/m-1.0-1.noarch.rpm", "m", "1.0", "1", "noarch"),
            ],
        )
        .await;

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();

        for arch in ["x86_64", "aarch64"] {
            let noarch_link = root
                .path()
                .join(format!("_repo/prod/{arch}/Packages/m-1.0-1.noarch.rpm"));
            assert!(
                tokio::fs::try_exists(&noarch_link).await.unwrap(),
                "noarch must appear in every configured concrete arch repo ({arch})"
            );
        }
    }

    // ─── 纯 noarch 产品的落位回退（候选行全是 noarch 时回退产品配置 arches）───

    /// 建 DB 产品（config 须过 validate_resolved_shape 最小形状 + repo 字段校验）。
    async fn create_product_with_arches(store: &StateStore, arches: &[&str]) {
        let cfg = crate::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crate::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                ..Default::default()
            }],
            arches: arches.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        store
            .create_product(crate::state::products::CreateProductInput {
                name: "prod",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &cfg,
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();
    }

    /// 纯 noarch 候选 + 产品配置 [x86_64] → 回退落位到 x86_64。
    #[tokio::test]
    async fn noarch_only_product_falls_back_to_configured_arches() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        create_product_with_arches(&store, &["x86_64"]).await;
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/noarch/m-1.0-1.noarch.rpm",
                "m",
                "1.0",
                "1",
                "noarch",
            )],
        )
        .await;

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(
            report.linked, 1,
            "noarch must be placed via configured-arch fallback"
        );
        let dest = root
            .path()
            .join("_repo/prod/x86_64/Packages/m-1.0-1.noarch.rpm");
        assert!(
            tokio::fs::try_exists(&dest).await.unwrap(),
            "noarch must land in the configured concrete arch repo"
        );
        assert!(
            !tokio::fs::try_exists(root.path().join("_repo/prod/noarch"))
                .await
                .unwrap()
        );
    }

    /// 产品配置也无具体 arch（纯 noarch 配置）→ 保持 warn+unplaced，不创建
    /// 任何 arch 目录。
    #[tokio::test]
    async fn noarch_only_product_without_configured_arches_stays_unplaced() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        create_product_with_arches(&store, &["noarch"]).await;
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/noarch/m-1.0-1.noarch.rpm",
                "m",
                "1.0",
                "1",
                "noarch",
            )],
        )
        .await;

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 0);
        assert!(
            !tokio::fs::try_exists(root.path().join("_repo/prod"))
                .await
                .unwrap(),
            "no arch dirs must be created for a no-concrete-arch product"
        );
    }

    /// ⑤：EXDEV 源 → error 且 skip，绝不降级 copy。单文件系统无法真造
    /// EXDEV，验证分类纯函数 + 源缺失时跳过不创建目标的真实路径。
    #[tokio::test]
    async fn exdev_and_missing_source_skip_without_copy() {
        let exdev = std::io::Error::from_raw_os_error(nix::libc::EXDEV);
        assert_eq!(classify_link_error(&exdev), Placement::SkippedExdev);
        assert!(is_exdev(&exdev));
        let enoent = std::io::Error::from_raw_os_error(nix::libc::ENOENT);
        assert_eq!(classify_link_error(&enoent), Placement::SkippedMissing);
        assert!(!is_exdev(&enoent));

        // 源缺失的真实路径：候选行在 DB，源文件不在盘 → skip+warn，不创建目标。
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/ghost-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "ghost", "1.0", "1", "x86_64")],
        )
        .await;
        // 删除源文件，模拟并发 GC 删除后仍 on_disk=1。
        tokio::fs::remove_file(root.path().join("1").join(rel))
            .await
            .unwrap();

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 0);
        assert_eq!(report.skipped_missing, 1);
        let dest = root
            .path()
            .join("_repo/prod/x86_64/Packages/ghost-1.0-1.x86_64.rpm");
        assert!(
            !tokio::fs::try_exists(&dest).await.unwrap(),
            "must not copy on skip"
        );
    }

    /// ②b：relative_path 绝对路径 / `..` 穿越与不安全 arch 一律拒绝，计入
    /// `skipped_invalid`（数据错误，与 GC 竞态的 `skipped_missing` 区分）。
    #[tokio::test]
    async fn absolute_relative_path_rejected() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        // build 1/2：先安全 seed 再改 DB 行为恶意 relative_path（应在校验处被拒）。
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/x86_64/evil1-1.0-1.x86_64.rpm",
                "evil1",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/x86_64/evil2-1.0-1.x86_64.rpm",
                "evil2",
                "1.0",
                "1",
                "x86_64",
            )],
        )
        .await;
        sqlx::query(
            "UPDATE build_artifacts SET relative_path = '/etc/crbs-evil.rpm' WHERE build_id = 1",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE build_artifacts SET relative_path = '../escape.rpm' WHERE build_id = 2",
        )
        .execute(store.pool())
        .await
        .unwrap();
        // build 3：relative_path 安全但 arch 不安全。
        seed_build(
            &store,
            root.path(),
            3,
            "prod",
            "succeeded",
            1,
            &[rpm(
                "RPMS/x86_64/evil3-1.0-1.x86_64.rpm",
                "evil3",
                "1.0",
                "1",
                "../evil",
            )],
        )
        .await;

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 0);
        assert_eq!(report.skipped_invalid, 3);
        assert_eq!(report.skipped_missing, 0);
        let pkgs = root.path().join("_repo/prod/x86_64/Packages");
        let mut n = 0;
        // 断言式迭代：目录缺失等同"0 个包"容忍，但迭代 IO 错误必须 panic
        // ——`while let Ok(Some(..))` 把错误当结束会令断言假绿。
        match tokio::fs::read_dir(&pkgs).await {
            Ok(mut rd) => {
                while let Some(e) = rd.next_entry().await.unwrap() {
                    if e.file_name().to_string_lossy().ends_with(".rpm") {
                        n += 1;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("read_dir({}): {e}", pkgs.display()),
        }
        assert_eq!(n, 0, "no invalid row may reach Packages/");
        // 绝对路径绝不触盘：join 未替换 base，临时根外无写入（/etc 由权限兜底）。
        assert!(
            !tokio::fs::try_exists("/etc/crbs-evil.rpm").await.unwrap(),
            "absolute relative_path must never be written through"
        );
    }

    /// 单个 arch 目录失败只记录、不中断其余目录：坏目录（Packages 路径被
    /// 普通文件占用）不拖累健康 arch 收敛，但整体仍返回 Err。
    #[tokio::test]
    async fn per_dir_failure_isolates_and_still_errs() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/aarch64/ok-1.0-1.aarch64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "ok", "1.0", "1", "aarch64")],
        )
        .await;

        // 预置坏 arch：x86_64 的 Packages 路径被普通文件占用。
        let bad = root.path().join("_repo/prod/x86_64");
        tokio::fs::create_dir_all(&bad).await.unwrap();
        tokio::fs::write(bad.join("Packages"), b"not a dir")
            .await
            .unwrap();

        let res = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false).await;
        let err = res.expect_err("per-dir failure must still surface as an error");
        assert!(
            err.to_string().contains("x86_64"),
            "error should name the failed dir: {err}"
        );

        let ok = root
            .path()
            .join("_repo/prod/aarch64/Packages/ok-1.0-1.aarch64.rpm");
        assert!(
            tokio::fs::try_exists(&ok).await.unwrap(),
            "healthy arch must converge despite another arch failing"
        );
    }

    // ─── 触发点语义（在数据层复现，run_createrepo=false 以脱离 createrepo_c）───

    /// -（上传成功 → repo 生成）：一个 succeeded + repo_publish=1 的构建完成后，
    /// 触发重建 → 其 RPM 落入 Packages/；重复触发幂等（每次完成都触发）。
    #[tokio::test]
    async fn completed_build_generates_repo_and_reassembly_is_idempotent() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/app-2.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "app", "2.0", "1", "x86_64")],
        )
        .await;

        let dest = root
            .path()
            .join("_repo/prod/x86_64/Packages/app-2.0-1.x86_64.rpm");

        let r1 = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(r1.linked, 1);
        assert!(tokio::fs::try_exists(&dest).await.unwrap());

        // 再次触发（如另一构建完成）：已存在的硬链接不重复建，也不误删。
        let r2 = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(r2.linked, 0, "idempotent: existing link not re-created");
        assert_eq!(r2.unlinked, 0);
        assert!(tokio::fs::try_exists(&dest).await.unwrap());
    }

    /// -（GC 删除后 → repo 文件消失）：产物被 GC 标记 on_disk=0 后，下一次重建
    /// 对账式地把它从 Packages/ 摘除（unlinked=1）。
    #[tokio::test]
    async fn gc_off_disk_unlinks_from_repo() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/tmp-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "tmp", "1.0", "1", "x86_64")],
        )
        .await;

        let dest = root
            .path()
            .join("_repo/prod/x86_64/Packages/tmp-1.0-1.x86_64.rpm");

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert!(tokio::fs::try_exists(&dest).await.unwrap());

        // 模拟 GC：翻 on_disk=0（GC 删文件不删行）。
        store.mark_artifacts_off_disk(1).await.unwrap();

        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.unlinked, 1, "GC'd file must be unlinked from repo");
        assert!(
            !tokio::fs::try_exists(&dest).await.unwrap(),
            "repo file must disappear after GC"
        );
    }

    /// -（unpublish → 摘除且旧构建浮出）：unpublish b2 后 b1 继续提供该
    /// NVRA；b1 也 unpublish 后无发布方 → 文件消失。
    #[tokio::test]
    async fn unpublish_resurfaces_older_build() {
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/lib-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "lib", "1.0", "1", "x86_64")],
        )
        .await;
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "lib", "1.0", "1", "x86_64")],
        )
        .await;

        let pkgs = root.path().join("_repo/prod/x86_64/Packages");
        let dest = pkgs.join("lib-1.0-1.x86_64.rpm");

        async fn count_rpms(dir: &Path) -> usize {
            let mut n = 0;
            // 断言式迭代：IO 错误一律 panic——`while let Ok(..)` 吞错会把去重破坏瞒成 1 个。
            let mut rd = tokio::fs::read_dir(dir).await.unwrap();
            while let Some(e) = rd.next_entry().await.unwrap() {
                if e.file_name().to_string_lossy().ends_with(".rpm") {
                    n += 1;
                }
            }
            n
        }

        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(count_rpms(&pkgs).await, 1, "same NVRA dedups to one file");
        assert!(tokio::fs::try_exists(&dest).await.unwrap());

        // unpublish b2：b1 仍提供该 NVRA，包不消失。
        store.set_build_repo_publish(2, false).await.unwrap();
        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert!(
            tokio::fs::try_exists(&dest).await.unwrap(),
            "older build must keep the package available after unpublishing the newer one"
        );

        // 再 unpublish b1：无任何发布方 → 对账式摘除。
        store.set_build_repo_publish(1, false).await.unwrap();
        let report = assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        assert_eq!(report.unlinked, 1, "no publisher left → file unlinked");
        assert!(!tokio::fs::try_exists(&dest).await.unwrap());

        assert!(
            !has_staging_leftovers(root.path(), "prod").await,
            "swap 成功后 _repo/prod 下不得残留 .staging-* 目录"
        );
    }

    /// 枚举 `_repo/{product}` 下的点前缀（`.staging-*`）残留目录。
    async fn has_staging_leftovers(result_root: &Path, product: &str) -> bool {
        let repo_base = result_root.join("_repo").join(product);
        let Ok(mut rd) = tokio::fs::read_dir(&repo_base).await else {
            return false;
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let name = entry.file_name();
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false)
                && name.to_str().is_some_and(|n| n.starts_with('.'))
            {
                return true;
            }
        }
        false
    }

    /// 回归：createrepo 失败时旧树原样服务（staging 就地清理、live 树全程
    /// 未动）；无 createrepo_c 环境 spawn 失败即天然注入。
    #[tokio::test]
    async fn createrepo_failure_keeps_stale_files_in_packages() {
        if createrepo_available() {
            return;
        }
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/stale-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "stale", "1.0", "1", "x86_64")],
        )
        .await;

        // 先无 createrepo 组装出 Packages/stale-...rpm（首建 + hardlink）。
        assemble_product_repo_impl(&store, "prod", root.path(), true, false, false)
            .await
            .unwrap();
        let dest = root
            .path()
            .join("_repo/prod/x86_64/Packages/stale-1.0-1.x86_64.rpm");
        let src = root.path().join("1").join(rel);
        assert!(tokio::fs::try_exists(&dest).await.unwrap());

        // 模拟 GC：文件变陈旧，下一次 createrepo 模式组装因 spawn 失败而失败。
        store.mark_artifacts_off_disk(1).await.unwrap();
        let res = assemble_product_repo(&store, "prod", root.path(), true, false).await;
        assert!(res.is_err(), "createrepo 失败必须整体报错: {res:?}");

        assert!(
            tokio::fs::try_exists(&dest).await.unwrap(),
            "createrepo 失败后旧树必须原样服务（staging 构建 + 换位失败臂不触 live 树）"
        );
        assert!(
            same_inode(&dest, &src).await,
            "失败臂的文件必须仍是原 hardlink（字节不变）"
        );
        assert!(
            !has_staging_leftovers(root.path(), "prod").await,
            "失败清 staging 后不得残留 .staging-* 目录"
        );
    }

    /// 回归：`remove_staging` 拒绝清理 `_repo/{product}`（repo_base）命名
    /// 空间之外的路径——宁可留残也不误删共享根。
    #[tokio::test]
    async fn remove_staging_refuses_paths_outside_repo_namespace() {
        let root = tempfile::tempdir().unwrap();
        let repo_base = root.path().join("_repo").join("prod");
        tokio::fs::create_dir_all(&repo_base).await.unwrap();
        // 合法布局：staging 在 repo_base 下 → 正常清理。
        let inside = repo_base.join(".staging-x86_64-ok");
        tokio::fs::create_dir_all(&inside).await.unwrap();
        remove_staging(&repo_base, &inside).await;
        assert!(
            !tokio::fs::try_exists(&inside).await.unwrap(),
            "命名空间内的 staging 必须正常清理"
        );
        // 越界：staging 在 repo_base 之外 → 拒绝删除、目录保留。
        let outside = root.path().join("somewhere-else").join(".staging-evil");
        tokio::fs::create_dir_all(&outside).await.unwrap();
        remove_staging(&repo_base, &outside).await;
        assert!(
            tokio::fs::try_exists(&outside).await.unwrap(),
            "命名空间外的路径必须拒绝删除"
        );
        // 越界：恰等于 repo_base 本身 → 拒绝（不等于共享根断言）。
        remove_staging(&repo_base, &repo_base).await;
        assert!(
            tokio::fs::try_exists(&repo_base).await.unwrap(),
            "repo_base 本身必须拒绝删除"
        );
    }

    /// 成功路径回归（需 createrepo_c）：swap 后新 repodata 入位、陈旧摘除、
    /// swap 入位的 repodata 同样收敛 2770/0660、staging 无残留。
    #[tokio::test]
    async fn repodata_swap_unlinks_stale_and_converges_modes() {
        if !createrepo_available() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel_a = "RPMS/x86_64/old-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel_a, "old", "1.0", "1", "x86_64")],
        )
        .await;

        assemble_product_repo(&store, "prod", root.path(), true, false)
            .await
            .unwrap();
        let repomd = root.path().join("_repo/prod/x86_64/repodata/repomd.xml");
        let old_repomd = tokio::fs::read(&repomd).await.unwrap();

        // GC 掉 old，加入 new：下一轮全量组装必须摘 old、链 new。
        store.mark_artifacts_off_disk(1).await.unwrap();
        let rel_b = "RPMS/x86_64/new-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            1,
            &[rpm(rel_b, "new", "1.0", "1", "x86_64")],
        )
        .await;

        let report = assemble_product_repo(&store, "prod", root.path(), true, false)
            .await
            .unwrap();
        assert_eq!(report.unlinked, 1, "stale file must be unlinked after swap");
        let pkgs = root.path().join("_repo/prod/x86_64/Packages");
        assert!(!tokio::fs::try_exists(pkgs.join("old-1.0-1.x86_64.rpm"))
            .await
            .unwrap());
        assert!(tokio::fs::try_exists(pkgs.join("new-1.0-1.x86_64.rpm"))
            .await
            .unwrap());

        let new_repomd = tokio::fs::read(&repomd).await.unwrap();
        assert_ne!(
            old_repomd, new_repomd,
            "repodata must be swapped to fresh metadata"
        );
        let repodata_dir = root.path().join("_repo/prod/x86_64/repodata");
        let dir_meta = tokio::fs::metadata(&repodata_dir).await.unwrap();
        assert_eq!(
            dir_meta.permissions().mode() & 0o7777,
            0o2770,
            "swapped-in repodata dir must converge to 2770"
        );
        let repomd_meta = tokio::fs::metadata(&repomd).await.unwrap();
        assert_eq!(
            repomd_meta.permissions().mode() & 0o777,
            0o660,
            "swapped-in repomd.xml must converge to 0660"
        );
        assert!(
            !has_staging_leftovers(root.path(), "prod").await,
            "swap 成功后不得残留 .staging-* 目录"
        );
    }

    /// 同 NEVR 重发回归（需 createrepo_c）：同 basename、新构建新
    /// inode → 换位后 Packages 链到新构建、repodata 同轮重建——旧 repodata
    /// 配新文件的窗口（读取端 checksum mismatch 根因）被整树换位消除；锁
    /// 文件位于换位树之外（repo_base），arch 目录内无锁残留。字节不同的
    /// 新旧树形态由换位原语测试覆盖（createrepo 需合法 RPM 字节，此处沿用
    /// 同字节 fixture）。
    #[tokio::test]
    async fn republish_same_nevra_swaps_file_and_repodata_together() {
        if !createrepo_available() {
            return;
        }
        let (store, _db) = create_test_store().await;
        let root = tempfile::tempdir().unwrap();
        let rel = "RPMS/x86_64/dup-1.0-1.x86_64.rpm";
        seed_build(
            &store,
            root.path(),
            1,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "dup", "1.0", "1", "x86_64")],
        )
        .await;
        assemble_product_repo(&store, "prod", root.path(), true, false)
            .await
            .unwrap();

        let linked = root
            .path()
            .join("_repo/prod/x86_64/Packages/dup-1.0-1.x86_64.rpm");
        let repomd = root.path().join("_repo/prod/x86_64/repodata/repomd.xml");
        assert!(tokio::fs::try_exists(&repomd).await.unwrap());

        // 同 NEVR 重发：build 2 同 basename（fixture 同字节，新文件新 inode）。
        seed_build(
            &store,
            root.path(),
            2,
            "prod",
            "succeeded",
            1,
            &[rpm(rel, "dup", "1.0", "1", "x86_64")],
        )
        .await;
        let src2 = root.path().join("2").join(rel);

        let report = assemble_product_repo(&store, "prod", root.path(), true, false)
            .await
            .unwrap();
        assert_eq!(report.linked, 1, "same-name republish must re-link");
        assert!(
            same_inode(&linked, &src2).await,
            "republish must swap the link to the new build's inode"
        );

        // 锁在换位树之外：repo_base 持锁、arch 目录内无锁残留。
        assert!(
            tokio::fs::try_exists(root.path().join("_repo/prod/.repodata-x86_64.lock"))
                .await
                .unwrap(),
            "per-arch lock must live outside the swapped tree"
        );
        assert!(
            !tokio::fs::try_exists(root.path().join("_repo/prod/x86_64/.repodata.lock"))
                .await
                .unwrap(),
            "no lock file may remain inside the swapped arch dir"
        );
        assert!(
            !has_staging_leftovers(root.path(), "prod").await,
            "swap 成功后 _repo/prod 下不得残留 .staging-* 目录"
        );
    }

    /// 换位原语：两侧均存在 → 内容整体互换（旧树随后被清出）；live 缺失
    ///（首建）→ staging 直接 rename 入位。
    #[tokio::test]
    async fn swap_arch_dir_into_place_exchanges_or_first_publishes() {
        let root = tempfile::tempdir().unwrap();
        let repo_base = root.path().join("_repo").join("prod");
        let arch_repo = repo_base.join("x86_64");
        let staging = repo_base.join(".staging-x86_64-test");

        // 既有树 + staging 新树 → 换位后 live 持新树、旧树清出、staging 消失。
        tokio::fs::create_dir_all(arch_repo.join("Packages"))
            .await
            .unwrap();
        tokio::fs::write(arch_repo.join("Packages").join("old.rpm"), b"old")
            .await
            .unwrap();
        tokio::fs::create_dir_all(staging.join("Packages").join("..").join("repodata"))
            .await
            .unwrap();
        tokio::fs::write(staging.join("Packages").join("new.rpm"), b"new")
            .await
            .unwrap();
        tokio::fs::write(staging.join("repodata").join("repomd.xml"), b"meta")
            .await
            .unwrap();

        swap_arch_dir_into_place(&repo_base, &arch_repo, &staging)
            .await
            .unwrap();

        assert!(
            tokio::fs::try_exists(arch_repo.join("Packages").join("new.rpm"))
                .await
                .unwrap(),
            "live tree must be the staged new tree after swap"
        );
        assert!(
            tokio::fs::try_exists(arch_repo.join("repodata").join("repomd.xml"))
                .await
                .unwrap(),
            "staged repodata must land with the swap"
        );
        assert!(
            !tokio::fs::try_exists(arch_repo.join("Packages").join("old.rpm"))
                .await
                .unwrap(),
            "old tree files must be gone after swap"
        );
        assert!(
            !tokio::fs::try_exists(&staging).await.unwrap(),
            "staging path (old tree holder) must be removed after swap"
        );

        // 首建臂：live 缺失 → staging rename 入位。
        let arch2 = repo_base.join("aarch64");
        let staging2 = repo_base.join(".staging-aarch64-test");
        tokio::fs::create_dir_all(staging2.join("Packages"))
            .await
            .unwrap();
        tokio::fs::write(staging2.join("Packages").join("first.rpm"), b"first")
            .await
            .unwrap();
        swap_arch_dir_into_place(&repo_base, &arch2, &staging2)
            .await
            .unwrap();
        assert!(
            tokio::fs::try_exists(arch2.join("Packages").join("first.rpm"))
                .await
                .unwrap(),
            "first publish must rename the staged tree into place"
        );
        assert!(!tokio::fs::try_exists(&staging2).await.unwrap());
    }
}
