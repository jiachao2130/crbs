// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! reproduce 的环境准备（读 build_packages.json → 回放仓库模式二态）。供 CLI /
//! 服务端 / worker 复用；调用方拿 [`ReproduceEnv`] 自行拼装 `BuildEngine`。
//!
//! - `Snapshot`（记录集含 sha256 条目）：恢复记录集建快照仓，复现解析域 =
//!   记录快照仓（base 安装与 install-deps 的 dnf builddep 都只看这个域，
//!   版本钉在源构建记录上）。
//! - `BaseOnly`（记录集无任何 sha256 条目——全部 BR 来自 base repo 的旧
//!   构建）：无包可恢复、无法建隔离快照仓，回放退回与源构建相同的正常
//!   解析域（产品 repo / 产品 repos 正常注入）；expected 锚 = 空集，fail-fast
//!   对账自然通过。确定性与无快照仓的普通回放同域：镜像漂移时如实失败，
//!   不静默。

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::build_options::{parse_macros, validate_features};
use crate::config::Config;
use crate::engine::artifact_harvest::rpms_under;
use crate::engine::build::packages::is_gpg_pubkey_nevra;
use crate::engine::cache::restore_packages_to_repo;
use crate::engine::depsolve::probe_srpm_replay_params;
use crate::error::CrbsError;
use crate::state::BuildPackage;
use crate::BuildOptions;

/// 回放仓库模式二态：记录集能否复原出隔离快照仓（判定见
/// `replay_repo_mode_for`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRepoMode {
    /// 记录集含 sha256 条目：恢复建快照仓，回放域 = crbs-local 快照仓（隔离）。
    Snapshot,
    /// 记录集无任何 sha256 条目：不建快照仓、不做 repo 隔离，回放域 = 正常
    /// 解析域（产品 repo 正常注入）。
    BaseOnly,
}

/// 回放仓库模式判定（纯函数）：记录集任一条目带 sha256 → Snapshot；全空
///（含记录集为空——同属"无可恢复包"）→ BaseOnly。混合集维持 Snapshot：
/// 无 sha 条目跳过恢复、不参与校验，带 sha 条目照常锚定（既有口径）。
pub(crate) fn replay_repo_mode_for(packages: &[BuildPackage]) -> ReplayRepoMode {
    if packages.iter().any(|p| !p.sha256.is_empty()) {
        ReplayRepoMode::Snapshot
    } else {
        ReplayRepoMode::BaseOnly
    }
}

/// 回放时间锚：源构建产物头探测的 BUILDHOST + BUILDTIME。一次 rpmbuild 的
/// 全部子包共享同一 BUILDTIME/BUILDHOST，任取一包探头即代表整次构建。
#[derive(Debug)]
pub struct ReplayAnchor {
    /// 源构建 BUILDHOST（头无该标签时 None，罕见）。
    pub build_host: Option<String>,
    /// 源构建 BUILDTIME（epoch 秒；rpm 头必有该标签，None 实际不可达）。
    pub build_time: Option<i64>,
}

/// 锚提取失败形态（调用方按各自入口语义包装错误信封；[`Self::Probe`] 内嵌
/// 完整 rpm -qp 报文含被探测文件路径）。
#[derive(Debug, thiserror::Error)]
pub enum ReplayAnchorError {
    /// RPMS/SRPMS 均无 .rpm 产物（产物缺失/已 GC）。
    #[error("no build artifacts under the task results (cannot pin BUILDTIME)")]
    NoArtifact,
    /// 头既无 BUILDTIME 也无 BUILDHOST：rpm 头必有 BUILDTIME，实际不可达；
    /// 拒绝而非静默不钉——不钉 = 墙钟回放，同源两次字节必不同。
    #[error("artifact carries neither BUILDTIME nor BUILDHOST (cannot pin replay)")]
    MissingBoth,
    /// `rpm -qp` 探测失败（产物损坏/查询超时/被取消）。
    #[error(transparent)]
    Probe(#[from] CrbsError),
}

impl From<ReplayAnchorError> for CrbsError {
    fn from(e: ReplayAnchorError) -> Self {
        match e {
            ReplayAnchorError::Probe(inner) => inner,
            other => CrbsError::ValidationFailed {
                message: other.to_string(),
            },
        }
    }
}

/// 从源构建 result_dir 提取回放时间锚：RPMS 优先，纯源包构建（无二进制
/// 产物）回退 SRPMS——自产 SRPM 的头时间即该次构建打包时刻；任取排序首个
/// 包 `rpm -qp` 探头。探测失败 = 产物缺失/损坏，不降级不静默。
pub async fn resolve_replay_anchor(
    result_dir: &Path,
    cancel_token: Option<&CancellationToken>,
) -> Result<ReplayAnchor, ReplayAnchorError> {
    let mut artifact = None;
    for sub in ["RPMS", "SRPMS"] {
        artifact = rpms_under(&result_dir.join(sub)).await.into_iter().next();
        if artifact.is_some() {
            break;
        }
    }
    let Some(rpm) = artifact else {
        return Err(ReplayAnchorError::NoArtifact);
    };
    match probe_srpm_replay_params(&rpm, cancel_token).await {
        Ok((None, None)) => Err(ReplayAnchorError::MissingBoth),
        Ok((build_host, build_time)) => Ok(ReplayAnchor {
            build_host,
            build_time,
        }),
        Err(err) => Err(ReplayAnchorError::Probe(err)),
    }
}

/// reproduce 环境准备的结果：临时 repo 的 `TempDir` 由本结构持有至构建结束。
/// 正常路径用 [`ReproduceEnv::teardown`] 显式回收（spawn_blocking 删除并**等待
/// 完成**）；Drop 是 abort / 漏调兜底：移交后台线程删除、不等待。
pub struct ReproduceEnv {
    /// 临时 repo 的 TempDir 守卫；`None` = 已被 teardown / preserve_temp_dirs
    /// 消费（或 BaseOnly 模式本就无快照仓），Drop 不处理。
    temp_repo_guard: Option<tempfile::TempDir>,
    /// 回放仓库模式（判定引擎旗标链与验证报告口径）。
    pub mode: ReplayRepoMode,
    /// 临时 repo 目录路径，传入 `BuildEngine::with_local_repo`（复现快照仓，
    /// 内容 = 源构建记录全集）。**BaseOnly 模式为空路径，不得使用**（判
    /// [`Self::mode`]）。
    pub temp_repo: PathBuf,
    /// 实际恢复的环境包数量（用于验证报告）；BaseOnly 恒 0。
    pub restored_count: usize,
    /// 原始构建的包清单（已过滤 gpg-pubkey），用于派生 expected/source maps 与验证。
    pub original_packages: Vec<BuildPackage>,
}

impl ReproduceEnv {
    /// 显式回收临时 repo（consuming）：`spawn_blocking` 删除并等待完成（返回即
    /// 删除已落地；Drop 是 GB 级同步 remove_dir_all，不能上 tokio worker 线程）。
    /// 删除失败仅 warn：残留由系统 tmp 清理兜底。
    pub async fn teardown(mut self) {
        let repo = self.temp_repo_guard.take();
        drop_temp_dir_off_worker(repo).await;
    }

    /// keep-tmp 调试语义（`--reproduce-keep-tmp-on-failure`）：`mem::forget`
    /// 泄漏 guard，目录留盘供人工排查；guard 取空后 Drop 短路。
    pub fn preserve_temp_dirs(mut self) {
        if let Some(g) = self.temp_repo_guard.take() {
            std::mem::forget(g);
        }
    }
}

impl Drop for ReproduceEnv {
    fn drop(&mut self) {
        // abort / 漏调 teardown 的兜底（正常路径 guard 已取空，直接返回）。Drop
        // 不能 await：有 runtime 走 spawn_blocking、无 runtime 走 detached 线程，
        // 都不在当前线程做 GB 级同步 remove_dir_all，且不等待——进程随即退出时
        // 删除可能截断。repo tempdir 残留仍符合形态 B 布局签名（Packages/ +
        // repodata/repomd.xml），由 engine::tmp_sweep 周期清扫回收。
        let repo = self.temp_repo_guard.take();
        if repo.is_none() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || {
                    drop(repo);
                });
            }
            Err(_) => {
                std::thread::spawn(move || {
                    drop(repo);
                });
            }
        }
    }
}

/// 回收 TempDir；[`ReproduceEnv::teardown`] 与构造中途失败早退共用。worker 侧
/// 直删优先（常态 worker 属主、dev 环境无特权层）；直删失败升级 `rm_rf_async`
/// 特权删除，仍失败仅 warn，交系统 tmp 清理。
async fn drop_temp_dir_off_worker(temp_repo_guard: Option<tempfile::TempDir>) {
    let Some(g) = temp_repo_guard else {
        return;
    };
    let path = g.into_path();
    if tokio::fs::remove_dir_all(&path).await.is_ok() {
        return;
    }
    // 命名空间护栏：特权删除仅限 tempfile 形态（.tmpXXXXXX）的引擎自建目录。
    let ours = path
        .file_name()
        .into_iter()
        .any(|n| n.to_string_lossy().starts_with(".tmp"));
    if !ours {
        tracing::error!(
            path = %path.display(),
            "unexpected temp dir name; refusing privileged removal"
        );
        return;
    }
    tracing::warn!(
        path = %path.display(),
        "worker-side temp dir removal failed; escalating to privileged rm-rf"
    );
    if let Err(pe) = crate::privilege::rm_rf_async(&[&path]).await {
        tracing::warn!(
            path = %path.display(),
            error = %pe,
            "privileged rm-rf also failed; temp dir left for OS tmp cleanup"
        );
    }
}

/// 探测 `result_dir` 内 package index 写入中断的残留临时文件（通常只有一条）。
/// 写入方 `write_json_atomic`（cache.rs）的临时名是
/// `build_packages.json.tmp.{pid}.{uuid}`，前缀匹配同时覆盖现行 pid+uuid 名与
/// 早期裸名两种形态；read_dir 限 `result_dir` 内、前缀即断言——只可能命中
/// index 写入方的 tmp。NotFound 视为无残留；其他错误上抛（权限故障折叠成
/// "无残留"会误报成 "predates idempotency"，掩盖真实故障）。
async fn find_interrupted_index_tmps(result_dir: &Path) -> crate::Result<Vec<PathBuf>> {
    let mut entries = match tokio::fs::read_dir(result_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(CrbsError::from_io_context(
                "read result dir for package index tmp",
                e,
            ))
        }
    };
    let mut found = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("iterate result dir for package index tmp", e))?
    {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("build_packages.json.tmp")
        {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// 从原始构建产物目录 `result_dir` 读 build_packages.json 包清单 → 恢复
///（cache-first + url 回退 → sha 校验 → createrepo）建复现快照仓，返回
/// [`ReproduceEnv`]。`config` 取 `tmp_dir`、`package_cache_path`。
pub async fn prepare_reproduce_env(
    result_dir: &Path,
    config: &Config,
    cancel: Option<&tokio_util::sync::CancellationToken>,
) -> crate::Result<ReproduceEnv> {
    // build_packages.json 是 canonical 数据源；DB build_packages 表只是派生索引。
    let packages_json = result_dir.join("build_packages.json");

    // 存在性探测失败（如 EACCES）不得折叠成 false——会误报成 "predates idempotency" 掩盖真实故障。
    let packages_json_exists = tokio::fs::try_exists(&packages_json)
        .await
        .map_err(|e| CrbsError::from_io_context("stat build_packages.json", e))?;
    let interrupted_tmps = find_interrupted_index_tmps(result_dir).await?;

    // gpg-pubkey 是 RPMDB 中的伪包，不参与 reproducibility 校验。
    let is_recordable_package = |p: &BuildPackage| !is_gpg_pubkey_nevra(&p.nevra);

    let original_packages: Vec<BuildPackage> = if packages_json_exists {
        let content = tokio::fs::read_to_string(&packages_json)
            .await
            .map_err(|e| CrbsError::from_io_context("read", e))?;
        let parsed: Vec<BuildPackage> =
            serde_json::from_str(&content).map_err(|e| CrbsError::ValidationFailed {
                message: format!(
                    "{} is corrupt: {}. Manual recovery needed.",
                    packages_json.display(),
                    e
                ),
            })?;
        parsed.into_iter().filter(is_recordable_package).collect()
    } else if !interrupted_tmps.is_empty() {
        // 命中前缀残留：best-effort 回收（单个失败仅 warn 继续删其余）；回收
        // 失败不改变报错语义——仍返回中断错误，不让回收故障掩盖原始判定。
        for tmp in &interrupted_tmps {
            if let Err(e) = tokio::fs::remove_file(tmp).await {
                tracing::warn!(
                    path = %tmp.display(),
                    error = %e,
                    "Failed to remove interrupted package index tmp file"
                );
            }
        }
        return Err(CrbsError::io_message(format!(
            "package index write was interrupted ({} exists). \
             Check disk space / IO and re-run the original build.",
            interrupted_tmps[0].display()
        )));
    } else {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "no build_packages record (build predates idempotency feature, cannot verify): {}",
                packages_json.display()
            ),
        });
    };

    // 回放仓库模式二态：任一条目带 sha256 → Snapshot（建快照仓）；全空 →
    // BaseOnly（不建快照仓，正常解析域回放）。
    let mode = replay_repo_mode_for(&original_packages);
    let (temp_repo_guard, temp_repo, restored_count) = match mode {
        ReplayRepoMode::Snapshot => {
            let (guard, repo, count) = restore_packages_to_repo(
                &original_packages,
                &config.package_cache_path,
                &config.tmp_dir,
                cancel,
            )
            .await
            .map_err(|e| {
                CrbsError::io_message(format!("Failed to restore packages from cache: {}", e))
            })?;
            info!(
                repo = %repo.display(),
                restored = count,
                "Reproduce snapshot repo ready (resolution domain = recorded package set)"
            );
            (Some(guard), repo, count)
        }
        ReplayRepoMode::BaseOnly => {
            // 无任何 sha 条目（全部 BR 来自 base repo）：快照仓无从建起，
            // 回放用与源构建相同的正常解析域，不静默降级隔离语义。
            info!(
                packages = original_packages.len(),
                "Reproduce env base-only: record set has no sha256 entries; \
                 no snapshot repo, replay resolves from the normal repo domain"
            );
            (None, PathBuf::new(), 0)
        }
    };

    Ok(ReproduceEnv {
        temp_repo_guard,
        mode,
        temp_repo,
        restored_count,
        original_packages,
    })
}

/// 从 [`ReproduceEnv`] 派生 expected 映射（NEVRA → SHA256，仅含非空 sha256），
/// 供 `BuildEngine::with_reproduce_expected` 两阶段 fail-fast 校验；空 sha256 与 restore 跳过口径一致。
pub(crate) fn expected_packages_from(env: &ReproduceEnv) -> HashMap<String, String> {
    env.original_packages
        .iter()
        .filter(|p| !p.sha256.is_empty())
        .map(|p| (p.nevra.clone(), p.sha256.clone()))
        .collect()
}

/// 从 [`ReproduceEnv`] 派生 source 包映射（NEVRA → BuildPackage），供
/// `BuildEngine::with_reproduce_source_packages` 继承原始 url 等 provenance。
pub(crate) fn source_packages_from(env: &ReproduceEnv) -> HashMap<String, BuildPackage> {
    env.original_packages
        .iter()
        .map(|p| (p.nevra.clone(), p.clone()))
        .collect()
}

/// 从来源构建 [`BuildOptions`] 派生 rpmbuild 宏覆盖：`--define` 原样保留，
/// `--with F` / `--without F` 转 `with_F=1` / `without_F=1`；特性宏先入表、
/// `--define` 后入表（执行期 "cli 宏最后生效" 的覆盖顺序）。
pub fn source_macro_overrides(opts: &BuildOptions) -> crate::Result<BTreeMap<String, String>> {
    let (with, without) = validate_features(&opts.with_features, &opts.without_features)?;
    let mut macros = BTreeMap::new();
    for feat in with {
        macros.insert(format!("with_{}", feat), "1".to_string());
    }
    for feat in without {
        macros.insert(format!("without_{}", feat), "1".to_string());
    }
    for (k, v) in parse_macros(&opts.define)? {
        macros.insert(k, v);
    }
    Ok(macros)
}

/// 把来源构建选项（宏 + `--nocheck` / `--noclean` / `--nodebuginfo` / `--dist`）
/// 应用到 reproduce engine：不重放则带选项的源构建以默认值复现，产出不同却报
/// 成功。backend / 资源限制不在此列：复现引擎构造一律不读复现请求，走与正常
/// 构建相同的解析链（create_backend ← config.backend 全局→产品→默认）。
pub fn apply_source_build_options(
    engine: crate::engine::BuildEngine,
    opts: &BuildOptions,
) -> crate::Result<crate::engine::BuildEngine> {
    // 与 worker/server 的 apply_options_to_engine 同集（减去 reproduce 有意覆盖的维度）。
    let engine = engine.with_cli_macros(source_macro_overrides(opts)?);
    let engine = match opts.nocheck {
        Some(enabled) => engine.with_nocheck(enabled),
        None => engine,
    };
    let engine = match opts.noclean {
        Some(enabled) => engine.with_noclean(enabled),
        None => engine,
    };
    let engine = match opts.nodebuginfo {
        Some(enabled) => engine.with_nodebuginfo(enabled),
        None => engine,
    };
    let engine = if opts.dist.is_some() {
        engine.with_dist(crate::build_options::normalize_dist(opts.dist.clone())?)
    } else {
        engine
    };
    Ok(engine)
}

/// reproduce 的引擎密闭链（隔离旗标，按回放仓库模式分派）。共用段：
/// `with_shared_layer_disabled`（重放不共享层）+ 比对锚（`expected_packages_from`
/// 仅含非空 sha256；BaseOnly 即空集，fail-fast 对账自然通过）+ source 包
/// 继承（provenance url）。解析域段：
///
/// - Snapshot：`without_product_repo_url` 必须清除：assignment 注入的 hub
///   产品仓是滚动漂移源，与记录包来源的 local_repo 互斥；
///   `with_local_repo` 挂复现快照仓；`with_replay_snapshot_domain` 置复现
///   解析域旗标，base 安装解析域 = 记录快照仓（init 配方不变），install-deps
///   的 builddep disablerepo=* 只看该仓（prepare.rs 密闭判别器）。
/// - BaseOnly：不挂 local_repo、不清产品仓、不置隔离旗标；回放域与源
///   构建相同（产品 repo / 产品 repos 正常注入），镜像漂移如实失败。
pub fn apply_reproduce_engine(
    engine: crate::engine::BuildEngine,
    env: &ReproduceEnv,
) -> crate::engine::BuildEngine {
    let engine = engine
        .with_shared_layer_disabled()
        .with_reproduce_expected(expected_packages_from(env))
        .with_reproduce_source_packages(source_packages_from(env));
    match env.mode {
        ReplayRepoMode::Snapshot => engine
            .without_product_repo_url()
            .with_local_repo(env.temp_repo.clone())
            .with_replay_snapshot_domain(),
        ReplayRepoMode::BaseOnly => engine,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 基线 ReproduceEnv 夹具（guard=repo + Snapshot + 空 temp_repo/计数/包集），
    /// 四个回收路径测试共用；变体场景仍手写字面量。
    fn env_with(repo: tempfile::TempDir) -> ReproduceEnv {
        ReproduceEnv {
            temp_repo_guard: Some(repo),
            mode: ReplayRepoMode::Snapshot,
            temp_repo: PathBuf::new(),
            restored_count: 0,
            original_packages: Vec::new(),
        }
    }

    /// teardown 删除临时 repo、正常返回不报错（macOS 可跑、无特权）。
    #[tokio::test]
    async fn teardown_removes_temp_repo() {
        let repo = tempfile::tempdir().unwrap();
        let env = env_with(repo);
        let repo_path = env.temp_repo_guard.as_ref().unwrap().path().to_path_buf();

        env.teardown().await;

        assert!(!repo_path.exists(), "temp repo must be removed by teardown");
    }

    /// 漏调 teardown 直接 drop：Drop 兜底移交后台删除（runtime 内走
    /// spawn_blocking），目录最终消失。
    #[tokio::test]
    async fn drop_without_teardown_deletes_dir_in_background() {
        let repo = tempfile::tempdir().unwrap();
        let env = env_with(repo);
        let repo_path = env.temp_repo_guard.as_ref().unwrap().path().to_path_buf();

        drop(env);

        // 后台删除无完成信号：轮询等待终态（异步路径毫秒级，上限 5s 防挂）。
        for _ in 0..250 {
            if !repo_path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!(
            "Drop fallback must remove temp dir in background: repo={}",
            repo_path.display()
        );
    }

    /// 无 tokio runtime（如已关闭）走 detached 线程兜底，同样删除目录。
    #[test]
    fn drop_without_runtime_uses_detached_thread() {
        let repo = tempfile::tempdir().unwrap();
        let env = env_with(repo);
        let repo_path = env.temp_repo_guard.as_ref().unwrap().path().to_path_buf();

        // 同步测试线程上 Handle::try_current() 必然失败 → detached 线程路径。
        assert!(tokio::runtime::Handle::try_current().is_err());
        drop(env);

        for _ in 0..250 {
            if !repo_path.exists() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!(
            "detached-thread Drop fallback must remove temp dir: repo={}",
            repo_path.display()
        );
    }

    /// teardown 取空 guard 后，后续 Drop 兜底不做二次清理。
    #[tokio::test]
    async fn teardown_consumes_guards_so_drop_is_noop() {
        let repo = tempfile::tempdir().unwrap();
        let repo_path = repo.path().to_path_buf();
        let mut env = ReproduceEnv {
            temp_repo_guard: Some(repo),
            mode: ReplayRepoMode::Snapshot,
            temp_repo: PathBuf::new(),
            restored_count: 0,
            original_packages: Vec::new(),
        };

        // 模拟 teardown 的 take（不经消费式 teardown，保留 env 以观察 Drop）。
        let repo_guard = env.temp_repo_guard.take();
        drop_temp_dir_off_worker(repo_guard).await;

        assert!(!repo_path.exists());
        // guard 已空：这个 Drop 必须短路（无目录可删，无 panic）。
        drop(env);
    }

    /// preserve_temp_dirs 泄漏 guard：目录留盘供排查，Drop 短路。
    #[test]
    fn preserve_temp_dirs_leaks_dir_and_short_circuits_drop() {
        let repo = tempfile::tempdir().unwrap();
        let repo_path = repo.path().to_path_buf();
        let env = env_with(repo);

        env.preserve_temp_dirs();

        assert!(
            repo_path.exists(),
            "preserve_temp_dirs must keep the dir on disk"
        );
    }

    // ---- 中断写入探测（前缀匹配）----
    // 现行临时名是 build_packages.json.tmp.{pid}.{uuid}，裸名是早期形态；前缀
    // 匹配两种形态：命中 → interrupted 错误 + best-effort 回收。

    /// 构造含指定残留的 result_dir，断言返回 interrupted 错误（而非 predates
    /// idempotency）且残留被回收；中断分支早退于恢复，配置 Default 即可。
    async fn assert_interrupted_detection(residue_names: &[&str]) {
        let result_dir = tempfile::tempdir().unwrap();
        let mut residues = Vec::new();
        for name in residue_names {
            let p = result_dir.path().join(name);
            tokio::fs::write(&p, b"half-written").await.unwrap();
            residues.push(p);
        }

        // .err() 而非 unwrap_err()：ReproduceEnv 未实现 Debug（只在意错误臂）。
        let err = prepare_reproduce_env(result_dir.path(), &Config::default(), None)
            .await
            .err()
            .unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("package index write was interrupted"),
            "expected interrupted-write error, got: {msg}"
        );
        assert!(
            !msg.contains("predates idempotency"),
            "interrupted tmp must not be misreported as predating idempotency: {msg}"
        );
        for p in &residues {
            assert!(
                !tokio::fs::try_exists(p).await.unwrap(),
                "interrupted tmp residue must be recycled: {}",
                p.display()
            );
        }
    }

    /// 早期形态：裸名 `build_packages.json.tmp`。
    #[tokio::test]
    async fn interrupted_index_tmp_bare_name_reports_and_recycles() {
        assert_interrupted_detection(&["build_packages.json.tmp"]).await;
    }

    /// 现行形态：`build_packages.json.tmp.{pid}.{uuid}`（write_json_atomic 产生）。
    #[tokio::test]
    async fn interrupted_index_tmp_pid_uuid_name_reports_and_recycles() {
        assert_interrupted_detection(&[
            "build_packages.json.tmp.12345.67e4c1a2-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
        ])
        .await;
    }

    /// 两种形态并存：全部命中、全部回收（回收循环继续删其余条目）。
    #[tokio::test]
    async fn interrupted_index_tmp_both_forms_all_recycled() {
        assert_interrupted_detection(&[
            "build_packages.json.tmp",
            "build_packages.json.tmp.12345.67e4c1a2-3b4d-4e5f-8a9b-0c1d2e3f4a5b",
        ])
        .await;
    }

    /// 无 index 且无 tmp 残留：仍报 "predates idempotency"（前缀探测不得吞掉）。
    #[tokio::test]
    async fn missing_index_without_tmp_still_reports_predates() {
        let result_dir = tempfile::tempdir().unwrap();

        let err = prepare_reproduce_env(result_dir.path(), &Config::default(), None)
            .await
            .err()
            .unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("predates idempotency"),
            "missing index without tmp residue must keep the predates-idempotency error, got: {msg}"
        );
    }

    /// index 损坏（截断 JSON）→ "is corrupt" 错误，不与"无记录"/"中断"混淆。
    #[tokio::test]
    async fn corrupt_packages_json_reports_corrupt() {
        let result_dir = tempfile::tempdir().unwrap();
        tokio::fs::write(result_dir.path().join("build_packages.json"), b"{")
            .await
            .unwrap();

        let err = prepare_reproduce_env(result_dir.path(), &Config::default(), None)
            .await
            .err()
            .unwrap();
        let msg = err.to_string();
        assert!(msg.contains("is corrupt"), "got: {msg}");
        assert!(msg.contains("Manual recovery"), "got: {msg}");
    }

    /// cache miss 且 url=null → 统一包装为 "Failed to restore packages from
    /// cache: ..." 且内因保留（该前缀是 classify_replay_failure 的判据）。
    #[tokio::test]
    async fn restore_failure_wrapped_with_cache_prefix() {
        let result_dir = tempfile::tempdir().unwrap();
        let manifest = vec![BuildPackage {
            build_id: 1,
            nevra: "gcc-14.0-1.x86_64".to_string(),
            // 64 位 hex：过 is_sha256_hex 前置校验（拦截路径在格式校验之后）。
            sha256: "ab".repeat(32),
            repo: None,
            url: None, // cache miss 后无 url 回退 → ValidationFailed
        }];
        tokio::fs::write(
            result_dir.path().join("build_packages.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .await
        .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let config = Config {
            package_cache_path: cache.path().to_path_buf(),
            tmp_dir: tmp.path().to_path_buf(),
            ..Config::default()
        };

        let err = prepare_reproduce_env(result_dir.path(), &config, None)
            .await
            .err()
            .unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("Failed to restore packages from cache"),
            "got: {msg}"
        );
        assert!(
            msg.contains("not recordable"),
            "inner cause must be preserved inside the wrapper: {msg}"
        );
    }

    /// 三类宏级选项（--define / --with / --without）都进入覆盖表。
    #[test]
    fn test_source_macro_overrides_maps_define_and_features() {
        let opts: BuildOptions = serde_json::from_str(
            r#"{"define": ["optflags=-O3"], "with_features": ["tests"], "without_features": ["docs"]}"#,
        )
        .unwrap();
        let macros = source_macro_overrides(&opts).unwrap();
        assert_eq!(macros.get("optflags"), Some(&"-O3".to_string()));
        assert_eq!(macros.get("with_tests"), Some(&"1".to_string()));
        assert_eq!(macros.get("without_docs"), Some(&"1".to_string()));
        // 空选项 → 空覆盖表（不注入任何宏）。
        assert!(source_macro_overrides(&BuildOptions::default())
            .unwrap()
            .is_empty());
    }

    /// 同名时 `--define` 最后生效（对齐 execution.rs 执行期合并顺序）。
    #[test]
    fn test_source_macro_overrides_define_wins_over_feature_macro() {
        let opts: BuildOptions =
            serde_json::from_str(r#"{"define": ["with_foo=2"], "with_features": ["foo"]}"#)
                .unwrap();
        let macros = source_macro_overrides(&opts).unwrap();
        assert_eq!(macros.get("with_foo"), Some(&"2".to_string()));
    }

    /// 复用提交入口校验：非法 define 与 with/without 冲突都报错，不静默丢弃。
    #[test]
    fn test_source_macro_overrides_rejects_invalid_options() {
        let bad_define: BuildOptions = serde_json::from_str(r#"{"define": ["NOEQUALS"]}"#).unwrap();
        assert!(source_macro_overrides(&bad_define).is_err());

        let conflicting: BuildOptions =
            serde_json::from_str(r#"{"with_features": ["foo"], "without_features": ["foo"]}"#)
                .unwrap();
        assert!(source_macro_overrides(&conflicting).is_err());
    }

    /// `apply_source_build_options` 四臂落位断言。引擎用 crate 内
    /// `minimal_engine` 直构——公共组装路径 create_backend 的 available() 检查
    /// 在 Linux 非 root / macOS 必失败；reproduce 是 engine 子模块，可直读
    /// 私有字段断言。
    #[tokio::test]
    async fn apply_source_build_options_sets_nocheck_noclean_nodebuginfo_dist_arms() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = crate::engine::minimal_engine(tmp.path()).await;

        // 四臂全开：nocheck / noclean / nodebuginfo 落 true，dist 归一化补前导点。
        let opts: BuildOptions = serde_json::from_str(
            r#"{"nocheck": true, "noclean": true, "nodebuginfo": true, "dist": "fc44"}"#,
        )
        .unwrap();
        let engine = apply_source_build_options(engine, &opts).unwrap();
        assert!(
            engine.nocheck,
            "--nocheck source build must skip %check on replay"
        );
        assert!(
            engine.noclean,
            "--noclean source build must skip %clean/rmbuild on replay"
        );
        assert!(
            engine.nodebuginfo,
            "--nodebuginfo source build must skip debuginfo on replay"
        );
        assert_eq!(
            engine.dist.as_deref(),
            Some(".fc44"),
            "dist arm must land normalized (leading dot)"
        );

        // Some(false) 不是缺席、同样落位；dist 缺席（None）保持既有值。
        let opts: BuildOptions =
            serde_json::from_str(r#"{"nocheck": false, "noclean": false, "nodebuginfo": false}"#)
                .unwrap();
        let engine = apply_source_build_options(engine, &opts).unwrap();
        assert!(!engine.nocheck, "Some(false) must land as false");
        assert!(!engine.noclean, "Some(false) must land as false");
        assert!(!engine.nodebuginfo, "Some(false) must land as false");
        assert_eq!(
            engine.dist.as_deref(),
            Some(".fc44"),
            "absent dist must keep the engine value untouched"
        );

        // 全缺席（默认选项）：字段不动、不注入宏。nocheck/noclean/nodebuginfo
        // 预置非默认 true——默认 false 下无法区分"保持不动"与"重置为 false"。
        let tmp = tempfile::tempdir().unwrap();
        let mut engine = crate::engine::minimal_engine(tmp.path()).await;
        engine.nocheck = true;
        engine.noclean = true;
        engine.nodebuginfo = true;
        let engine = apply_source_build_options(engine, &BuildOptions::default()).unwrap();
        assert!(
            engine.nocheck,
            "None arm must keep the pre-set value (true)"
        );
        assert!(
            engine.noclean,
            "None arm must keep the pre-set value (true)"
        );
        assert!(
            engine.nodebuginfo,
            "None arm must keep the pre-set value (true)"
        );
        assert_eq!(engine.dist, None, "None arm must keep default (no dist)");
        assert!(
            engine.cli_macros.is_empty(),
            "no macro overrides may be injected for default options"
        );
    }

    /// Snapshot 模式隔离旗标链一次落位：shared_layer 强制关、产品仓清除、
    /// 复现快照仓 / 复现解析域旗标 / 比对锚就位；复现旗标 → 产品 repo 动态
    /// 注入关（密闭），base_os 走产品标准路径（引擎 base_os_path 无覆写入口）。
    #[tokio::test]
    async fn apply_reproduce_engine_sets_d9_isolation_flags() {
        let tmp = tempfile::tempdir().unwrap();
        // 判别前提：模拟 worker 主路径（已注入 hub 产品仓、shared_layer 开启）。
        let engine = crate::engine::minimal_engine(tmp.path())
            .await
            .enable_shared_layer()
            .with_product_repo_url("http://hub.example.com/repo/prod_a/x86_64".into());

        let env = ReproduceEnv {
            temp_repo_guard: None,
            mode: ReplayRepoMode::Snapshot,
            temp_repo: PathBuf::from("/tmp/fake-temp-repo"),
            restored_count: 1,
            original_packages: vec![BuildPackage {
                build_id: 14,
                nevra: "bash-5.2-1.x86_64".to_string(),
                sha256: "sha-aaa".to_string(),
                repo: None,
                url: Some("http://hub.example.com/pkg/bash-5.2-1.x86_64.rpm".to_string()),
            }],
        };

        let engine = apply_reproduce_engine(engine, &env);

        // 旗标逐项断言（私有字段直读）。
        assert!(
            matches!(
                engine.config.shared_layer,
                crate::config::BoolOrPackages::Bool(false)
            ),
            "shared layer must be force-disabled for replay"
        );
        assert_eq!(
            engine.product_repo_url(),
            None,
            "assignment-injected product repo must be cleared"
        );
        assert_eq!(
            engine.local_repo_dir(),
            Some(Path::new("/tmp/fake-temp-repo")),
            "local repo must point at the temp repo restored from build_packages.json"
        );
        assert!(
            engine.replay_snapshot_domain(),
            "replay snapshot domain flag must be set (base install + builddep resolve from the snapshot)"
        );
        let expected = engine
            .reproduce_expected
            .as_ref()
            .expect("anchor must be set");
        assert_eq!(
            expected.get("bash-5.2-1.x86_64").map(String::as_str),
            Some("sha-aaa"),
            "two-phase fail-fast anchor must be set from the record"
        );
        // BuildPackage 无 PartialEq：按键取字段断言（provenance 继承语义）。
        let sp = engine
            .reproduce_source_packages
            .as_ref()
            .expect("source packages must be set");
        assert_eq!(sp.len(), 1, "exactly the seeded package entry: {sp:?}");
        let pkg = &sp["bash-5.2-1.x86_64"];
        assert_eq!(pkg.sha256, "sha-aaa");
        assert_eq!(
            pkg.url.as_deref(),
            Some("http://hub.example.com/pkg/bash-5.2-1.x86_64.rpm"),
            "provenance url must be inherited from the source build"
        );
        assert!(
            !crate::engine::prepare::dynamic_repo_injection_enabled(
                engine.replay_snapshot_domain()
            ),
            "replay engine must disable product repo injection (hermetic overlay)"
        );
    }

    /// BaseOnly 模式密闭链：不挂 local_repo、不清产品仓、不置隔离旗标
    ///（回放域 = 正常解析域，产品 repo 动态注入照常）；expected 锚 = 空集
    ///（fail-fast 对账自然通过），shared layer 仍强制关。
    #[tokio::test]
    async fn apply_reproduce_engine_base_only_keeps_normal_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = crate::engine::minimal_engine(tmp.path())
            .await
            .enable_shared_layer()
            .with_product_repo_url("http://hub.example.com/repo/prod_a/x86_64".into());

        let env = ReproduceEnv {
            temp_repo_guard: None,
            mode: ReplayRepoMode::BaseOnly,
            temp_repo: PathBuf::new(),
            restored_count: 0,
            original_packages: vec![BuildPackage {
                build_id: 7,
                nevra: "filesystem-3.18-1.x86_64".to_string(),
                sha256: String::new(),
                repo: None,
                url: None,
            }],
        };

        let engine = apply_reproduce_engine(engine, &env);

        assert_eq!(
            engine.product_repo_url(),
            Some("http://hub.example.com/repo/prod_a/x86_64"),
            "base-only replay keeps the product repo (normal resolution domain)"
        );
        assert_eq!(
            engine.local_repo_dir(),
            None,
            "base-only replay has no snapshot repo"
        );
        assert!(
            !engine.replay_snapshot_domain(),
            "base-only replay must not set the isolation discriminator"
        );
        assert!(
            crate::engine::prepare::dynamic_repo_injection_enabled(engine.replay_snapshot_domain()),
            "base-only replay keeps dynamic product repo injection"
        );
        let expected = engine
            .reproduce_expected
            .as_ref()
            .expect("anchor must be set");
        assert!(
            expected.is_empty(),
            "empty sha256 set must yield an empty expected anchor (fail-fast passes trivially)"
        );
        assert!(
            matches!(
                engine.config.shared_layer,
                crate::config::BoolOrPackages::Bool(false)
            ),
            "shared layer must still be force-disabled for replay"
        );
    }

    /// 模式判定纯函数：带 sha 条目 → Snapshot；全空 / 空集 → BaseOnly；
    /// 混合集维持 Snapshot（空 sha 条目跳过恢复、带 sha 条目照常锚定）。
    #[test]
    fn replay_repo_mode_decision() {
        let pkg = |sha: String| BuildPackage {
            build_id: 1,
            nevra: "p-1.0-1.x86_64".to_string(),
            sha256: sha,
            repo: None,
            url: None,
        };
        assert_eq!(
            replay_repo_mode_for(&[pkg("ab".repeat(32))]),
            ReplayRepoMode::Snapshot
        );
        assert_eq!(
            replay_repo_mode_for(&[pkg(String::new())]),
            ReplayRepoMode::BaseOnly,
            "all-empty sha256 record set must replay base-only"
        );
        assert_eq!(replay_repo_mode_for(&[]), ReplayRepoMode::BaseOnly);
        assert_eq!(
            replay_repo_mode_for(&[pkg(String::new()), pkg("cd".repeat(32))]),
            ReplayRepoMode::Snapshot,
            "mixed set stays snapshot (existing skip-unrecordable semantics)"
        );
    }

    /// BaseOnly 环境准备：全空 sha256 记录集 → 不建快照仓（tmp_dir 无
    /// tempdir 落盘）、guard None、restored 0、清单原样保留。
    #[tokio::test]
    async fn prepare_env_all_empty_sha_uses_base_only_mode() {
        let result_dir = tempfile::tempdir().unwrap();
        let manifest = vec![
            BuildPackage {
                build_id: 1,
                nevra: "filesystem-3.18-1.x86_64".to_string(),
                sha256: String::new(),
                repo: None,
                url: None,
            },
            BuildPackage {
                build_id: 1,
                nevra: "bash-5.2-1.x86_64".to_string(),
                sha256: String::new(),
                repo: None,
                url: None,
            },
        ];
        tokio::fs::write(
            result_dir.path().join("build_packages.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .await
        .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let config = Config {
            package_cache_path: cache.path().to_path_buf(),
            tmp_dir: tmp.path().to_path_buf(),
            ..Config::default()
        };

        let env = prepare_reproduce_env(result_dir.path(), &config, None)
            .await
            .unwrap();
        assert_eq!(env.mode, ReplayRepoMode::BaseOnly);
        assert!(env.temp_repo_guard.is_none(), "no snapshot repo guard");
        assert!(env.temp_repo.as_os_str().is_empty());
        assert_eq!(env.restored_count, 0);
        assert_eq!(env.original_packages.len(), 2);
        // 快照仓 tempdir 未创建：tmp_dir 仍为空目录。
        let mut rd = tokio::fs::read_dir(tmp.path()).await.unwrap();
        assert!(
            rd.next_entry().await.unwrap().is_none(),
            "no snapshot repo may be built under tmp_dir in base-only mode"
        );
        env.teardown().await;
    }

    // is_gpg_pubkey_nevra 已抽至 engine::build::packages（保存/消费同口径），单测随迁。

    /// 锚产物扫描：RPMS/{arch} 一层下钻、排序返回；空目录与不存在目录返回空。
    #[tokio::test]
    async fn rpms_under_descends_sorts_and_returns_empty_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let arch_dir = tmp.path().join("RPMS").join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        tokio::fs::write(arch_dir.join("b.rpm"), b"x")
            .await
            .unwrap();
        tokio::fs::write(arch_dir.join("a.rpm"), b"x")
            .await
            .unwrap();
        assert_eq!(
            rpms_under(&tmp.path().join("RPMS")).await,
            vec![arch_dir.join("a.rpm"), arch_dir.join("b.rpm")]
        );
        tokio::fs::create_dir_all(tmp.path().join("SRPMS"))
            .await
            .unwrap();
        assert!(rpms_under(&tmp.path().join("SRPMS")).await.is_empty());
        assert!(rpms_under(&tmp.path().join("missing")).await.is_empty());
    }

    /// 锚提取失败主路径：RPMS/SRPMS 均无产物 → NoArtifact（语义错误，
    /// From 映射 ValidationFailed；产物已 GC 的入口须拒绝而非墙钟回放）。
    #[tokio::test]
    async fn resolve_replay_anchor_without_artifacts_is_no_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let err = resolve_replay_anchor(tmp.path(), None).await.unwrap_err();
        assert!(matches!(err, ReplayAnchorError::NoArtifact));
        let msg = format!("{err}");
        assert!(
            msg.contains("no build artifacts"),
            "error must say artifacts are missing: {msg}"
        );
        let converted: CrbsError = err.into();
        assert!(
            matches!(converted, CrbsError::ValidationFailed { .. }),
            "NoArtifact must map to ValidationFailed: {converted}"
        );
    }

    /// 真实 SRPM 的锚提取主路径（rpmbuild 可用时）：SRPMS 回退可探头、
    /// 探头值与 `rpm -qp` 直查一致、BUILDTIME 恒有值。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn resolve_replay_anchor_probes_rpms_header() {
        let src = tempfile::tempdir().unwrap();
        let Some(srpm) = build_real_srpm(&src) else {
            return; // rpmbuild 不可用的环境跳过（探头能力由集成测试覆盖）。
        };
        let result_dir = tempfile::tempdir().unwrap();
        let arch_dir = result_dir.path().join("RPMS").join("x86_64");
        tokio::fs::create_dir_all(&arch_dir).await.unwrap();
        // RPMS 放非 rpm 占位：验证无二进制产物的纯源包构建回退 SRPMS 探头，
        // 不会误取非 rpm 文件。
        tokio::fs::write(arch_dir.join("placeholder.txt"), b"not an rpm")
            .await
            .unwrap();
        let srpms_dir = result_dir.path().join("SRPMS");
        tokio::fs::create_dir_all(&srpms_dir).await.unwrap();
        let copied = srpms_dir.join(srpm.file_name().unwrap());
        tokio::fs::copy(&srpm, &copied).await.unwrap();

        let anchor = resolve_replay_anchor(result_dir.path(), None)
            .await
            .unwrap();
        let direct = probe_srpm_replay_params(&copied, None).await.unwrap();
        assert_eq!(anchor.build_host.as_deref(), direct.0.as_deref());
        assert_eq!(anchor.build_time, direct.1);
        assert!(
            anchor.build_time.is_some(),
            "rpm header always has BUILDTIME"
        );
    }

    /// 构造真实 SRPM（rpm -qp 解析 header 需要）到 `tmp` 的 SRPMS/ 下，返回
    /// 路径；rpmbuild 不可用返回 None（测试跳过）。dist 钉空防宿主 dist 后缀
    /// 漂移，与 server 集成夹具同口径。
    #[cfg(target_os = "linux")]
    fn build_real_srpm(tmp: &tempfile::TempDir) -> Option<std::path::PathBuf> {
        use std::process::Command;

        let spec = tmp.path().join("SPECS");
        std::fs::create_dir_all(&spec).unwrap();
        for d in ["BUILD", "RPMS", "SOURCES", "SRPMS"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        std::fs::write(
            spec.join("anchorprobe.spec"),
            "Name: anchorprobe\nVersion: 1.0\nRelease: 1\nSummary: t\nLicense: MIT\n\
             %description\nt\n",
        )
        .unwrap();
        // spawn 失败（无 rpmbuild）→ None 跳过；跑起来但失败 → panic（环境坏）。
        let status = Command::new("rpmbuild")
            .arg("-bs")
            .arg("--define")
            .arg(format!("_topdir {}", tmp.path().display()))
            .arg("--define")
            .arg("dist %{nil}")
            .arg(spec.join("anchorprobe.spec"))
            .status()
            .ok()?;
        assert!(status.success(), "rpmbuild -bs failed: {status:?}");
        std::fs::read_dir(tmp.path().join("SRPMS"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .next()
    }
}
