// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! base 快照：init 安装事务输入的物质化（resolve → download → createrepo）。
//!
//! 产物确定性 = 输入配置确定性：base 安装的解析域必须落在一个逐包钉死的
//! 快照仓上，而非滚动漂移的镜像。快照按内容寻址（snap-id = 包闭包摘要），
//! 同闭包同目录、镜像漂移自然换代；manifest（nevra+sha256+url）随 base 落盘
//! （`.snapshot-manifest`），快照目录缺失/不完整时按 manifest 重建
//!（cache 优先 → url 兜底 → sha 校验，骨架复用 [`restore_packages_to_repo`]）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::engine::cache::{
    cache_dnf_cache, restore_packages_to_repo, write_json_atomic, CacheEntry,
};
use crate::error::CrbsError;
use crate::privilege::PrivilegeBackend;
use crate::state::BuildPackage;

use super::base_os_install::{prepare_trusted_dnf_repos, trusted_dnf_repos_dir};

/// manifest 文件名：base_os 旁（与 `.digest` / `.requested` 同层）与快照目录
/// 内（发布形态）同名同内容——manifest 是快照目录自描述的一部分。
pub(crate) const MANIFEST_NAME: &str = ".snapshot-manifest";

/// 快照完整性判定所需的最小文件集合：manifest + repodata 索引。
const REPODATA_INDEX: &str = "repodata/repomd.xml";

/// init 安装事务显式安装的 builddep 插件候选：dnf5 树选前者，其余选后者。
/// 两候选都参与 resolve，但 resolve 侧错误确属 dnf 缺包族（镜像缺候选）才降级
/// warn 跳过——install 侧按 dnf5 存在性只装其一（见 base_os_install 的
/// dnf5_exists 探测）；装侧以"闭包声明了候选则装后 builddep 能力必须在"的
/// 不变量兜底（base_os_install 的 verify_base_builddep_capability）。
pub(crate) const BUILDDEP_PLUGIN_CANDIDATES: [&str; 2] = ["dnf-plugins-core", "dnf5-plugins"];

/// 崩溃残留 staging（`.tmp*`）的回收宽限：url 兜底下载几百包可达小时级，
/// 宽限须覆盖最慢恢复窗口，只按 mtime 回收。
const STAGING_GRACE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// heal 失败冷却窗口：快照缺失期间每次构建的快路径都会走到恢复，url 兜底
/// 可达小时级，无退避会让每次构建串行空转重试；冷却期内跳过，过期重试。
const HEAL_RETRY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(1800);

/// heal 失败时间戳 marker（快照根内，mtime = 失败时刻）：prune 对非目录且非
/// `.tmp` 的条目不动作，marker 不受清理影响。
const HEAL_FAILURE_MARKER: &str = ".heal-failed";

/// 快照 manifest：snap-id 与逐包锚（恢复与对账共用同一份数据）。
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SnapshotManifest {
    /// 内容寻址 id（[`snapshot_id`]）。
    pub snapshot_id: String,
    /// 快照闭包（nevra+sha256+url，按 nevra 排序）。
    pub packages: Vec<BuildPackage>,
}

/// 快照根目录：`{crbs_root}/base-snapshots/{product}/`（按产品隔离，防活跃
/// 产品的换代挤掉其它产品的在用快照）。
fn base_snapshots_root(config: &Config) -> PathBuf {
    config
        .crbs_root
        .join("base-snapshots")
        .join(&config.product)
}

/// 快照内容 id（纯函数）：blake3 over 排序后的 `nevra\n sha256\n` 行。内容寻址
/// ——同闭包必同 id（并发 init 发布竞争收敛到同一目录），镜像漂移换代自然换 id。
fn snapshot_id(packages: &[BuildPackage]) -> String {
    let mut lines: Vec<String> = packages
        .iter()
        .map(|p| format!("{}\n{}\n", p.nevra, p.sha256))
        .collect();
    lines.sort();
    lines.dedup();
    blake3::hash(lines.concat().as_bytes()).to_hex().to_string()
}

/// init 解析域：正常构建 = 镜像 base 快照（先 ensure 再返回 repo 指向）；
/// 复现旗标 = 复现快照仓（引擎 local_repo，即记录全集），不做镜像 resolve。
pub(crate) struct InitSnapshotDomain {
    /// init 安装事务的解析仓（trusted dir 与 installroot 安装期共用）。
    pub repos: Vec<crate::config::RepoConfig>,
    /// 随 base 落盘的 manifest；`None` = 解析域是复现临时仓，无持久快照可锚。
    pub manifest: Option<SnapshotManifest>,
}

/// [`InitSnapshotDomain`] 构造：复现旗标分流（见类型 doc）。
pub(crate) async fn ensure_init_snapshot_domain(
    engine: &crate::engine::BuildEngine,
    config: &Config,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<InitSnapshotDomain> {
    if engine.replay_snapshot_domain() {
        // 复现解析域 = 记录快照仓为主（apply_reproduce_engine 必已
        // with_local_repo）；记录 sha 集只覆盖构建依赖闭包，base 闭包的安装
        // 由产品镜像仓兜底（见 replay_domain_repos）。
        let repo_dir = engine
            .local_repo_dir()
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: "replay snapshot domain requires local_repo (apply_reproduce_engine \
                          must set it before build/init)"
                    .to_string(),
            })?;
        let repos = replay_domain_repos(repo_dir, config)?;
        // 复现域重建 resident base 时补快照锚（对齐正常 base 的 manifest 不变
        // 式）：把记录全集发布为内容寻址快照，manifest 随 base 落盘供自愈。
        // 锚缺失只损失自愈能力，发布失败降级 warn 不阻断复现。
        let manifest = replay_snapshot_anchor(engine, config).await;
        return Ok(InitSnapshotDomain { repos, manifest });
    }

    let packages = resolve_base_closure(engine, config, cancel_token).await?;
    let (snapshot_id, dir) = publish_snapshot(&packages, config).await?;
    info!(
        product = %config.product,
        snapshot_id = %snapshot_id,
        packages = packages.len(),
        path = %dir.display(),
        "Base snapshot ready"
    );
    Ok(InitSnapshotDomain {
        repos: vec![crate::config::RepoConfig {
            name: "crbs-base-snapshot".to_string(),
            baseurl: format!("file://{}", dir.display()),
            gpgcheck: false,
            ..Default::default()
        }],
        manifest: Some(SnapshotManifest {
            snapshot_id,
            packages,
        }),
    })
}

/// 复现解析域 repo 集合：crbs-local（记录快照仓）钉最高解析优先级 + 产品镜像
/// 仓兜底。记录 sha 集只覆盖构建依赖闭包，base 闭包（REQUIRED +
/// base_packages）不在其中——复现域仅凭 crbs-local 装 base 必然 dnf
/// "No match"。镜像兜底只扩大安装来源：钉住的包
/// 是否装到记录版本，仍由两阶段 sha 校验 fail-closed 把关。network=false 时
/// 镜像不可达且无兜底来源，直接给明确语义错误而非 dnf 谜语报错。
fn replay_domain_repos(
    local_repo: &Path,
    config: &Config,
) -> crate::Result<Vec<crate::config::RepoConfig>> {
    if !config.network {
        return Err(CrbsError::ValidationFailed {
            message: "replay-mode base install needs the base closure, but the replay snapshot \
                      repo only carries sha-pinned build-requirement packages and network is \
                      disabled so the product repos cannot backfill. Enable network for this \
                      build, or run a normal build once to recreate base_os on this worker."
                .to_string(),
        });
    }
    let mut repos = vec![crate::config::RepoConfig {
        name: "crbs-local".to_string(),
        baseurl: format!("file://{}", local_repo.display()),
        gpgcheck: false,
        // dnf priority/cost 数值越小优先级越高：base_packages 与 sha 记录包重名
        // 时（如 sqlite-devel）必须命中记录版本，否则两阶段 sha 校验误报失败。
        priority: 1,
        cost: 10,
        ..Default::default()
    }];
    repos.extend(config.repos.iter().cloned());
    Ok(repos)
}

/// 复现域快照锚：把记录全集（`reproduce_source_packages`）发布为内容寻址
/// 快照并返回 manifest。恢复路径刚预热 package cache，发布是硬链级成本；记录
/// 集缺失（旗标被绕过 `apply_reproduce_engine` 置位）或发布失败返回 `None`。
async fn replay_snapshot_anchor(
    engine: &crate::engine::BuildEngine,
    config: &Config,
) -> Option<SnapshotManifest> {
    let mut packages: Vec<BuildPackage> = engine
        .reproduce_source_packages
        .as_ref()?
        .values()
        .cloned()
        .collect();
    if packages.is_empty() {
        return None;
    }
    packages.sort_by(|a, b| a.nevra.cmp(&b.nevra));
    match publish_snapshot(&packages, config).await {
        Ok((snapshot_id, dir)) => {
            info!(
                product = %config.product,
                snapshot_id = %snapshot_id,
                packages = packages.len(),
                // 记录集与 sha 集分开报：物化进快照仓的只有 sha 记录包，
                // 只报记录全集会把残缺仓误读成完整快照。
                with_sha256 = packages.iter().filter(|p| !p.sha256.is_empty()).count(),
                path = %dir.display(),
                "Replay record set published as base snapshot anchor"
            );
            Some(SnapshotManifest {
                snapshot_id,
                packages,
            })
        }
        Err(e) => {
            warn!(
                product = %config.product,
                error = %e,
                "Publishing replay snapshot anchor failed; rebuilt base will lack .snapshot-manifest"
            );
            None
        }
    }
}

/// resolve base 闭包：scratch installroot `--downloadonly` 跑与 init 相同的
/// 安装事务（REQUIRED_BASE + base_packages + 可选 ccache，weak deps 随事务），
/// 下载集收割进 package cache 后按实际事务序补第二段（builddep 插件）。
/// 返回按 nevra 排序的逐包锚（sha256 来自下载收割，url 经 repoquery 解析）。
async fn resolve_base_closure(
    engine: &crate::engine::BuildEngine,
    config: &Config,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<Vec<BuildPackage>> {
    let releasever = config.effective_releasever()?;
    let backend = crate::privilege::get_privilege_backend();
    let trusted_dir = trusted_dnf_repos_dir(config);
    // 受信 repo 集合预置为产品镜像仓：resolve 与 install 两次 spawn_dnf 共用，
    // init 的 flock 保证与并发 init 不互踩。
    prepare_trusted_dnf_repos(&trusted_dir, &config.repos).await?;

    let base_pkgs =
        crate::engine::init::merge_base_packages(&config.base_packages, &config.ccache_enabled);
    let mut index = resolve_transaction(
        config,
        &trusted_dir,
        &releasever,
        backend,
        &base_pkgs,
        cancel_token,
    )
    .await?;

    // 第二段（builddep 插件）：install_base_os 在主事务后单独装插件，其下载集
    // 同样须入快照。主闭包已含候选时跳过（第二事务无新增下载）。
    let mut closure_names: Vec<String> = index
        .keys()
        .map(|nevra| crate::util::rpm_name_of_nevra(nevra))
        .collect();
    for plugin in BUILDDEP_PLUGIN_CANDIDATES {
        if closure_names.iter().any(|n| n == plugin) {
            continue;
        }
        let plugin_pkgs = vec![plugin.to_string()];
        // resolve 错误确属 dnf 缺包族（镜像缺候选，如 EL9 系无 dnf5-plugins）才
        // 降级 warn 跳过，否则上抛使 init 失败——瞬时镜像故障（下载/校验和）吞
        // 掉会让快照静默缺插件、坏 base 上线。
        merge_plugin_candidate(
            &mut index,
            &mut closure_names,
            plugin,
            resolve_transaction(
                config,
                &trusted_dir,
                &releasever,
                backend,
                &plugin_pkgs,
                cancel_token,
            )
            .await,
        )?;
    }

    // url 解析（repoquery --location，带 DB 侧 url 缓存）：manifest 的 url 兜底
    // 依赖它，任一包无 url 即失败（防恢复路径静默缺兜底）。
    let url_map = crate::engine::build::url::resolve_package_urls(
        &index,
        &config.repos,
        engine.state.as_ref(),
        &engine.log_sanitization,
        &config.tmp_dir,
    )
    .await?;

    let mut packages: Vec<BuildPackage> = index
        .into_iter()
        .map(|(nevra, entry)| BuildPackage {
            build_id: 0,
            url: url_map.get(&nevra).cloned(),
            nevra,
            sha256: entry.sha256,
            repo: entry.repo_id,
        })
        .collect();
    packages.sort_by(|a, b| a.nevra.cmp(&b.nevra));
    if packages.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "base snapshot resolve produced an empty package closure".to_string(),
        });
    }
    debug!(
        product = %config.product,
        packages = packages.len(),
        "Resolved base snapshot closure"
    );
    Ok(packages)
}

/// dnf 缺包族错误判定（纯函数）：错误文本命中 [`DNF_NO_MATCH_MARKERS`]（与
/// replay verdict 的 dep 判据同源）才视为"镜像缺候选"。
fn is_dnf_no_match_error(err: &CrbsError) -> bool {
    let text = err.to_string().to_lowercase();
    crate::state::reproducibility::DNF_NO_MATCH_MARKERS
        .iter()
        .any(|m| text.contains(m))
}

/// 单个 builddep 插件候选的探测合并：下载集非空 → 连同包名并入闭包；空集 →
/// warn 跳过、闭包不动；resolve 失败仅当错误确属 dnf 缺包族（镜像缺候选）降级
/// warn 跳过，其余错误（下载/校验和/超时）原样上抛——静默吞掉会让快照缺插件、
/// 坏 base 上线（纯函数便于单测）。
fn merge_plugin_candidate(
    index: &mut std::collections::HashMap<String, crate::engine::cache::CacheEntry>,
    closure_names: &mut Vec<String>,
    plugin: &str,
    probe: crate::Result<std::collections::HashMap<String, crate::engine::cache::CacheEntry>>,
) -> crate::Result<()> {
    match probe {
        Ok(plugin_index) if !plugin_index.is_empty() => {
            closure_names.extend(
                plugin_index
                    .keys()
                    .map(|nevra| crate::util::rpm_name_of_nevra(nevra)),
            );
            index.extend(plugin_index);
        }
        Ok(_) => warn!(
            plugin,
            "Builddep plugin candidate resolved to no packages; skipping (install side picks one candidate by dnf5 detection)"
        ),
        Err(e) if is_dnf_no_match_error(&e) => warn!(
            plugin,
            error = %e,
            "Builddep plugin candidate not present in product repos; skipping (install side picks one candidate by dnf5 detection)"
        ),
        Err(e) => return Err(e),
    }
    Ok(())
}

/// 单次 resolve 事务：scratch installroot `--downloadonly`（无 rpm 事务执行、
/// 无 scriptlet，免伪 fs 挂载），下载集收割进 package cache（顺带为恢复路径
/// 预热 cache-first）。返回 nevra → 缓存条目。下载体与随后 init 安装事务各跑
/// 一遍（双份 IO）：init 是低频路径，换取解析集逐包入快照的可审计闭包。
/// scratch 内是 GB 级下载体，TempDir 回收统一移交 blocking 线程（同
/// [`publish_snapshot`] 的丢弃纪律）。
async fn resolve_transaction(
    config: &Config,
    trusted_dir: &Path,
    releasever: &str,
    backend: &dyn PrivilegeBackend,
    packages: &[String],
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<std::collections::HashMap<String, crate::engine::cache::CacheEntry>> {
    let scratch = crate::engine::cache::spawn_blocking_tempdir_in(
        config.tmp_dir.clone(),
        "snapshot scratch installroot",
    )
    .await?;
    let scratch_path = scratch.path().to_path_buf();
    let mut scratch_guard = crate::engine::cache::TempDirGuard::new(scratch);

    let result = async {
        let mut dnf_args: Vec<String> = vec![
            "install".to_string(),
            "-y".to_string(),
            "--downloadonly".to_string(),
            "--setopt=keepcache=1".to_string(),
        ];
        dnf_args.extend(packages.iter().cloned());
        let cmd = backend.spawn_dnf(&scratch_path, releasever, trusted_dir, &dnf_args)?;
        let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
            tokio::process::Command::from(cmd),
            "dnf install (base snapshot resolve)",
            cancel_token,
            std::time::Duration::from_secs(7200),
        )
        .await?;
        // dnf 非零退出在此显式转错（文本携带 stderr）：quiet 路径不判退出码，
        // 缺包与瞬时镜像故障（下载/校验和）会混同成空下载集错误，no-match
        // 分类失去判据。
        if !output.status.success() {
            return Err(crate::engine::command::classify_command_failure(
                "base snapshot resolve (dnf downloadonly)",
                &output,
            ));
        }

        match cache_dnf_cache(&scratch_path, &config.package_cache_path, None)
            .await
            .map_err(|e| CrbsError::io_message(format!("harvest snapshot resolve cache: {e}")))?
        {
            Some(index) if !index.is_empty() => Ok(index),
            _ => Err(CrbsError::ValidationFailed {
                message: format!(
                    "base snapshot resolve downloaded no RPMs (dnf cache missing under {})",
                    scratch_path.display()
                ),
            }),
        }
    }
    .await;
    discard_staging_off_worker(&mut scratch_guard).await;
    result
}

/// 发布快照：已存在且完整则复用；否则经 [`restore_packages_to_repo`]（cache
/// 优先 → url 兜底 → sha 校验 → createrepo）物化到 staging 后原子 rename 入位。
/// 返回 (snap-id, 目录)。
async fn publish_snapshot(
    packages: &[BuildPackage],
    config: &Config,
) -> crate::Result<(String, PathBuf)> {
    let snapshot_id = snapshot_id(packages);
    let root = base_snapshots_root(config);
    crate::engine::shared_dir::ensure_shared_dir(&root).await?;
    let final_dir = root.join(&snapshot_id);
    if snapshot_complete(&final_dir).await {
        debug!(
            snapshot_id = %snapshot_id,
            path = %final_dir.display(),
            "Reusing existing base snapshot"
        );
        return Ok((snapshot_id, final_dir));
    }

    // staging 建在快照根内（与 final 同文件系统，rename 原子）；TempDir 的
    // 0700 形态在发布时经 ensure_shared_dir 归一为组共享。TempDir 的 Drop 是
    // 同步 remove_dir_all（几百硬链 + repodata），任何丢弃点都必须移交
    // blocking 线程（guard 模式同 engine::cache::TempDirGuard）。
    let (temp_dir, repo_dir, restored) =
        restore_packages_to_repo(packages, &config.package_cache_path, &root, None)
            .await
            .map_err(|e| CrbsError::io_message(format!("materialize base snapshot: {e}")))?;
    let mut staging = crate::engine::cache::TempDirGuard::new(temp_dir);
    debug!(
        snapshot_id = %snapshot_id,
        restored,
        "Base snapshot staged"
    );

    // manifest 先于 rename 落进 staging：rename 后目录即自描述，崩溃残留的
    // staging 也带 manifest 供人工/清扫侧辨识。
    let manifest = SnapshotManifest {
        snapshot_id: snapshot_id.clone(),
        packages: packages.to_vec(),
    };
    let write_result = write_json_atomic(&repo_dir.join(MANIFEST_NAME), &manifest).await;
    // 目录权限归一（2770 + crbs 组）：发布物是跨身份复用的持久资源，须满足
    // crbs 文件权限不变量。
    let perm_result = crate::engine::shared_dir::ensure_shared_dir(&repo_dir).await;
    if let Err(e) = write_result.or(perm_result) {
        discard_staging_off_worker(&mut staging).await;
        return Err(e);
    }

    match tokio::fs::rename(&repo_dir, &final_dir).await {
        Ok(()) => {
            // staging 名已随 rename 消失，Drop 兜底是空操作；仍移交 blocking
            // 线程保持丢弃点纪律一致。
            discard_staging_off_worker(&mut staging).await;
            Ok((snapshot_id, final_dir))
        }
        Err(_) if tokio::fs::try_exists(&final_dir).await.unwrap_or(false) => {
            // 并发 init 已发布同一内容寻址目录：弃 staging 复用胜者。
            discard_staging_off_worker(&mut staging).await;
            if snapshot_complete(&final_dir).await {
                debug!(snapshot_id = %snapshot_id, "Concurrent init published the same base snapshot");
                return Ok((snapshot_id, final_dir));
            }
            Err(CrbsError::io_message(format!(
                "concurrent base snapshot publish at {} is incomplete and owned by another init",
                final_dir.display()
            )))
        }
        Err(e) => {
            // rename 失败（非常见竞争）：收口 staging 后上抛。
            discard_staging_off_worker(&mut staging).await;
            Err(CrbsError::from_io_context(
                "publish base snapshot (rename staging)",
                e,
            ))
        }
    }
}

/// 弃置 staging：spawn_blocking 等待删除完成（TempDir Drop 是同步
/// remove_dir_all，不上 async worker 线程）。失败仅 warn：残留带 `.tmp` 前缀，
/// 由 prune 的 staging 宽限回收兜底。
async fn discard_staging_off_worker(staging: &mut crate::engine::cache::TempDirGuard) {
    let Some(dir) = staging.disarm() else {
        return;
    };
    let path = dir.path().to_path_buf();
    if let Err(e) = tokio::task::spawn_blocking(move || drop(dir)).await {
        warn!(
            path = %path.display(),
            error = %e,
            "Staging discard task failed; left for prune staging grace"
        );
    }
}

/// 快照完整性：manifest 与 repodata 索引都在位。粗粒度即可——init 的 dnf 对
/// 损坏 repodata 会硬失败，逐包校验留给按 manifest 重建路径。
async fn snapshot_complete(dir: &Path) -> bool {
    tokio::fs::try_exists(dir.join(MANIFEST_NAME))
        .await
        .unwrap_or(false)
        && tokio::fs::try_exists(dir.join(REPODATA_INDEX))
            .await
            .unwrap_or(false)
}

/// 读 base 旁的快照 manifest（`.digest` 同层）；无记录返回 `None`（早于快照
/// 锚的旧 base），损坏按错误上抛（静默 None 会丢恢复锚）。
async fn read_base_snapshot_manifest(base_os: &Path) -> crate::Result<Option<SnapshotManifest>> {
    let path = base_os.join(MANIFEST_NAME);
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => {
            serde_json::from_str(&content)
                .map(Some)
                .map_err(|e| CrbsError::ValidationFailed {
                    message: format!("{} is corrupt: {}", path.display(), e),
                })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CrbsError::from_io_context("read snapshot manifest", e)),
    }
}

/// manifest → `.packages.json` 种子索引（纯函数）：base 自钉死的 file:// 快照仓
/// 安装，dnf 缓存不留 RPM，逐包锚只能由 manifest 提供。空 sha 条目（复现记录
/// 集残缺形态）不构成锚，跳过。
pub(crate) fn manifest_package_index(manifest: &SnapshotManifest) -> HashMap<String, CacheEntry> {
    manifest
        .packages
        .iter()
        .filter(|p| !p.sha256.is_empty())
        .map(|p| {
            (
                p.nevra.clone(),
                CacheEntry {
                    sha256: p.sha256.clone(),
                    repo_id: p.repo.clone(),
                },
            )
        })
        .collect()
}

/// 读 base 旁 manifest 并转种子索引；无 manifest（早于快照锚的旧 base）返回
/// `None`，损坏按错误上抛（静默丢弃会让 `.packages.json` 失去播种来源）。
pub(crate) async fn snapshot_package_index(
    base_os: &Path,
) -> crate::Result<Option<HashMap<String, CacheEntry>>> {
    Ok(read_base_snapshot_manifest(base_os)
        .await?
        .map(|manifest| manifest_package_index(&manifest)))
}

/// 缺失自愈（init 快路径顺带执行）：base 在手而快照目录缺失/不完整时，按
/// manifest 重建（cache 优先 → url 兜底）。无 manifest 视为无需自愈；失败进
/// [`HEAL_RETRY_COOLDOWN`] 退避，冷却期内后续构建直接跳过。
pub(crate) async fn heal_base_snapshot(base_os: &Path, config: &Config) -> crate::Result<()> {
    heal_base_snapshot_with_cooldown(base_os, config, HEAL_RETRY_COOLDOWN).await
}

/// [`heal_base_snapshot`] 的可注入冷却形态（单测用短窗口验证退避与过期重试）。
async fn heal_base_snapshot_with_cooldown(
    base_os: &Path,
    config: &Config,
    cooldown: std::time::Duration,
) -> crate::Result<()> {
    let Some(manifest) = read_base_snapshot_manifest(base_os).await? else {
        return Ok(());
    };
    let root = base_snapshots_root(config);
    let dir = root.join(&manifest.snapshot_id);
    if snapshot_complete(&dir).await {
        return Ok(());
    }
    // 失败退避：marker mtime = 上次失败时刻，冷却期内跳过全量恢复。
    let marker = root.join(HEAL_FAILURE_MARKER);
    let in_cooldown = tokio::fs::metadata(&marker)
        .await
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < cooldown);
    if in_cooldown {
        warn!(
            product = %config.product,
            snapshot_id = %manifest.snapshot_id,
            "Base snapshot heal skipped within failure cooldown; retries after the window"
        );
        return Ok(());
    }
    let (id, published) = match publish_snapshot(&manifest.packages, config).await {
        Ok(published) => published,
        Err(e) => {
            // 落失败 marker（best-effort）：冷却期内不再空转重试。
            if let Err(werr) = tokio::fs::create_dir_all(&root).await {
                debug!(error = %werr, "Failed to ensure snapshot root for heal marker");
            }
            if let Err(werr) = tokio::fs::write(&marker, b"").await {
                debug!(error = %werr, "Failed to write heal failure marker");
            }
            return Err(e);
        }
    };
    // 成功即清 marker：下次失败重新计时。
    if let Err(e) = tokio::fs::remove_file(&marker).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            debug!(error = %e, "Failed to clear heal failure marker");
        }
    }
    info!(
        product = %config.product,
        snapshot_id = %id,
        path = %published.display(),
        "Recovered base snapshot from manifest"
    );
    Ok(())
}

/// 快照 GC（init 发布后调用，失败仅 warn）：保留代数（`0` = 不清理）内的新近
/// 快照，base 在用 snap-id 与宽限内的 staging 一律豁免。单产品域内裁剪，不跨
/// 产品计数。
pub(crate) async fn prune_base_snapshots(config: &Config, protect: Option<&str>) {
    let keep = config.base_snapshot_keep_generations;
    if keep == 0 {
        return;
    }
    let root = base_snapshots_root(config);
    let mut entries = match tokio::fs::read_dir(&root).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!(
                root = %root.display(),
                error = %e,
                "Scan base snapshots for prune failed"
            );
            return;
        }
    };
    let now = std::time::SystemTime::now();
    let mut snapshots: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    let mut stale_staging: Vec<PathBuf> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let mtime = meta.modified().unwrap_or(now);
        if name.starts_with(".tmp") {
            // staging 命名空间（restore_packages_to_repo tempdir 形态）：仅按
            // 宽限回收，正在进行的恢复不受影响。
            let age = now.duration_since(mtime).unwrap_or_default();
            if age > STAGING_GRACE {
                stale_staging.push(path);
            }
        } else if meta.is_dir() && Some(name.as_str()) != protect {
            snapshots.push((mtime, path));
        }
    }

    // 新近代数保留，其余删除（root 属主 dnf 无关，普通删即可；硬链包体随
    // package cache 侧最后引用消失）。
    snapshots.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    for (_, path) in snapshots.into_iter().skip(keep as usize) {
        if let Err(e) = tokio::fs::remove_dir_all(&path).await {
            warn!(
                path = %path.display(),
                error = %e,
                "Prune old base snapshot failed, continuing"
            );
        } else {
            debug!(path = %path.display(), "Pruned old base snapshot");
        }
    }
    for path in stale_staging {
        if let Err(e) = tokio::fs::remove_dir_all(&path).await {
            warn!(
                path = %path.display(),
                error = %e,
                "Prune stale base snapshot staging failed, continuing"
            );
        } else {
            debug!(path = %path.display(), "Pruned stale base snapshot staging");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(nevra: &str, sha: &str) -> BuildPackage {
        BuildPackage {
            build_id: 0,
            nevra: nevra.to_string(),
            sha256: sha.to_string(),
            repo: None,
            url: None,
        }
    }

    /// snap-id 内容寻址：同闭包恒等、与输入序无关；任一 nevra/sha 变化即换代。
    #[test]
    fn snapshot_id_is_content_addressed() {
        let a = vec![
            pkg("bash-5.2-1.x86_64", "aa"),
            pkg("coreutils-9-1.x86_64", "bb"),
        ];
        let b = vec![
            pkg("coreutils-9-1.x86_64", "bb"),
            pkg("bash-5.2-1.x86_64", "aa"),
        ];
        assert_eq!(snapshot_id(&a), snapshot_id(&b), "order must not matter");

        let bump_sha = vec![
            pkg("bash-5.2-1.x86_64", "cc"),
            pkg("coreutils-9-1.x86_64", "bb"),
        ];
        assert_ne!(
            snapshot_id(&a),
            snapshot_id(&bump_sha),
            "sha drift = new id"
        );

        let bump_pkg = vec![
            pkg("bash-5.3-1.x86_64", "aa"),
            pkg("coreutils-9-1.x86_64", "bb"),
        ];
        assert_ne!(
            snapshot_id(&a),
            snapshot_id(&bump_pkg),
            "nevra drift = new id"
        );

        assert_eq!(snapshot_id(&a).len(), 64);
        assert!(!snapshot_id(&[]).is_empty(), "empty closure still hashes");
    }

    /// 完整性判定：manifest 与 repodata 索引缺一不可。
    #[tokio::test]
    async fn snapshot_complete_requires_manifest_and_repodata() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("snap");
        tokio::fs::create_dir_all(dir.join("repodata"))
            .await
            .unwrap();
        assert!(!snapshot_complete(&dir).await, "missing manifest");

        tokio::fs::write(dir.join(MANIFEST_NAME), b"{}")
            .await
            .unwrap();
        assert!(
            !snapshot_complete(&dir).await,
            "manifest without repodata index is incomplete"
        );

        tokio::fs::write(dir.join(REPODATA_INDEX), b"<repomd/>")
            .await
            .unwrap();
        assert!(snapshot_complete(&dir).await);
    }

    /// manifest 读写往返：None（缺文件）与损坏（坏 JSON）两臂口径正确。
    #[tokio::test]
    async fn base_snapshot_manifest_roundtrip_and_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_base_snapshot_manifest(tmp.path())
            .await
            .unwrap()
            .is_none());

        let manifest = SnapshotManifest {
            snapshot_id: "abc".to_string(),
            packages: vec![pkg("bash-5.2-1.x86_64", "aa")],
        };
        write_json_atomic(
            &tmp.path().join(MANIFEST_NAME),
            &serde_json::to_value(&manifest).unwrap(),
        )
        .await
        .unwrap();
        let read = read_base_snapshot_manifest(tmp.path())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.snapshot_id, "abc");
        assert_eq!(read.packages.len(), 1);
        assert_eq!(read.packages[0].nevra, "bash-5.2-1.x86_64");

        tokio::fs::write(tmp.path().join(MANIFEST_NAME), b"{")
            .await
            .unwrap();
        assert!(read_base_snapshot_manifest(tmp.path()).await.is_err());
    }

    /// manifest 种子索引：按 nevra 建键、repo 透传、空 sha 不播种（非锚）。
    #[test]
    fn manifest_package_index_seeds_only_sha_anchored_packages() {
        let manifest = SnapshotManifest {
            snapshot_id: "abc".to_string(),
            packages: vec![
                BuildPackage {
                    repo: Some("product-mirror".to_string()),
                    url: Some("https://mirror.example/bash.rpm".to_string()),
                    ..pkg("bash-5.2-1.x86_64", "aa")
                },
                pkg("coreutils-9-1.x86_64", ""),
            ],
        };
        let index = manifest_package_index(&manifest);
        assert_eq!(index.len(), 1, "empty-sha entries must not seed");
        let entry = &index["bash-5.2-1.x86_64"];
        assert_eq!(entry.sha256, "aa");
        assert_eq!(entry.repo_id.as_deref(), Some("product-mirror"));
        assert!(!index.contains_key("coreutils-9-1.x86_64"));
    }

    /// builddep 插件候选钉死：拼写漂移会让快照缺插件、init 第二事务必死。
    #[test]
    fn builddep_plugin_candidates_pinned() {
        assert_eq!(
            BUILDDEP_PLUGIN_CANDIDATES,
            ["dnf-plugins-core", "dnf5-plugins"]
        );
    }

    /// 候选 no-match 降级矩阵：下载集并入闭包；空集 / resolve Err（缺包族文案，
    /// 如 EL9 无 dnf5-plugins）只 warn 跳过，闭包保持不动——快照仍建成，只是
    /// 不含该候选。
    #[test]
    fn merge_plugin_candidate_degrades_no_match_to_skip() {
        let mut index = std::collections::HashMap::new();
        let mut names: Vec<String> = Vec::new();

        merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf-plugins-core",
            Ok(std::collections::HashMap::from([(
                "dnf-plugins-core-1.0-1.noarch".to_string(),
                crate::engine::cache::CacheEntry {
                    sha256: "aa".to_string(),
                    repo_id: None,
                },
            )])),
        )
        .unwrap();
        assert_eq!(names, vec!["dnf-plugins-core".to_string()]);
        assert_eq!(index.len(), 1);

        let before = (names.len(), index.len());
        merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf5-plugins",
            Ok(Default::default()),
        )
        .unwrap();
        // dnf5 "No match for argument"（classify_command_failure 形态）。
        merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf5-plugins",
            Err(CrbsError::io_message(
                "base snapshot resolve (dnf downloadonly) failed: exit_code=Some(1) \
                 stderr=No match for argument: dnf5-plugins"
                    .to_string(),
            )),
        )
        .unwrap();
        // dnf4 builddep 变体文案。
        merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf5-plugins",
            Err(CrbsError::io_message(
                "base snapshot resolve (dnf downloadonly) failed: exit_code=Some(1) \
                 stderr=No matching package to install: 'dnf5-plugins'"
                    .to_string(),
            )),
        )
        .unwrap();
        assert_eq!(
            (names.len(), index.len()),
            before,
            "no-match arms must not pollute the closure"
        );
    }

    /// 非缺包族 resolve 错误必须上抛（init 失败、坏快照不得发布）：镜像元数据
    /// 拉取失败与包下载校验和不匹配都不是"镜像缺候选"。
    #[test]
    fn merge_plugin_candidate_propagates_transient_resolve_errors() {
        let mut index = std::collections::HashMap::new();
        let mut names: Vec<String> = Vec::new();

        // 下载错误：metadata 拉取失败。
        let download_err = merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf-plugins-core",
            Err(CrbsError::Network {
                message: "base snapshot resolve (dnf downloadonly) failed: exit_code=Some(1) \
                          stderr=Errors during downloading metadata for 'product-mirror'"
                    .to_string(),
            }),
        )
        .unwrap_err();
        assert!(
            download_err.to_string().contains("downloading metadata"),
            "download error must propagate unchanged: {download_err}"
        );

        // 校验和错误：包 payload 损坏（python3-six 实弹形态）。
        let checksum_err = merge_plugin_candidate(
            &mut index,
            &mut names,
            "dnf-plugins-core",
            Err(CrbsError::io_message(
                "base snapshot resolve (dnf downloadonly) failed: exit_code=Some(1) \
                 stderr=python3-six-1.16.0-5.noarch: Checksum mismatch"
                    .to_string(),
            )),
        )
        .unwrap_err();
        assert!(
            checksum_err.to_string().contains("Checksum mismatch"),
            "checksum error must propagate unchanged: {checksum_err}"
        );

        assert!(
            index.is_empty() && names.is_empty(),
            "propagated errors must not pollute the closure"
        );
    }

    /// 缺包族判据矩阵：三款 dnf 文案（dnf5/dnf4/builddep）命中，metadata 拉取/
    /// 校验和/超时不命中。
    #[test]
    fn dnf_no_match_error_classification_matrix() {
        for text in [
            "…failed: exit_code=Some(1) stderr=No match for argument: dnf5-plugins",
            "…failed: exit_code=Some(1) stderr=Unable to find a match: dnf5-plugins",
            "…failed: exit_code=Some(1) stderr=No matching package to install",
        ] {
            assert!(
                is_dnf_no_match_error(&CrbsError::io_message(text.to_string())),
                "must classify as no-match: {text}"
            );
        }
        for text in [
            "…failed: exit_code=Some(1) stderr=Errors during downloading metadata for 'x'",
            "…failed: exit_code=Some(1) stderr=python3-six: Checksum mismatch",
            "operation timed out",
        ] {
            assert!(
                !is_dnf_no_match_error(&CrbsError::io_message(text.to_string())),
                "must not classify as no-match: {text}"
            );
        }
    }

    /// staging 回收宽限覆盖最慢恢复窗口（url 兜底逐包下载可达小时级）。
    #[test]
    fn staging_grace_is_conservative() {
        assert!(STAGING_GRACE.as_secs() >= 3600);
    }

    /// 复现解析域：离线（network=false）→ 明确语义报错；在线 → crbs-local 钉
    /// 最高优先级在前、产品镜像仓随后兜底。
    #[test]
    fn replay_domain_repos_offline_fails_and_online_pins_local_first() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        assert!(!config.network, "default test config should be offline");

        let err = replay_domain_repos(Path::new("/tmp/repo"), &config)
            .expect_err("offline replay base install must fail with explicit semantics");
        assert!(err.to_string().contains("network"), "got: {err}");

        config.network = true;
        config.repos = vec![crate::config::RepoConfig {
            name: "base".to_string(),
            baseurl: "https://mirror.example/base/$basearch".to_string(),
            ..Default::default()
        }];
        let repos = replay_domain_repos(Path::new("/tmp/repo"), &config).unwrap();
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0].name, "crbs-local");
        assert!(repos[0].baseurl.starts_with("file:///tmp/repo"));
        // dnf 数值越小优先级越高：记录仓必须压过镜像仓。
        assert_eq!(repos[0].priority, 1);
        assert_eq!(repos[0].cost, 10);
        assert_eq!(repos[1].name, "base");
    }

    fn test_config(root: &Path) -> Config {
        Config {
            product: "mydist".to_string(),
            crbs_root: root.to_path_buf(),
            base_snapshot_keep_generations: 2,
            ..Config::default()
        }
    }

    /// 自愈守卫矩阵：base 无 manifest → no-op；manifest 在手且快照完整 →
    /// no-op（不触发重建路径）。缺失重建臂共享 publish_snapshot（依赖
    /// createrepo_c，编排骨径由 init 集成覆盖）。
    #[tokio::test]
    async fn heal_guard_matrix_skips_when_manifest_missing_or_snapshot_complete() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let base_os = tmp.path().join("products").join("mydist").join("base");
        tokio::fs::create_dir_all(&base_os).await.unwrap();

        // 无 manifest：早于快照锚的旧 base，无需自愈。
        heal_base_snapshot(&base_os, &config).await.unwrap();

        // manifest 在手 + 快照目录完整：不重建。
        let manifest = SnapshotManifest {
            snapshot_id: "feedc0de".to_string(),
            packages: vec![pkg("bash-5.2-1.x86_64", "aa")],
        };
        write_json_atomic(
            &base_os.join(MANIFEST_NAME),
            &serde_json::to_value(&manifest).unwrap(),
        )
        .await
        .unwrap();
        let snap = base_snapshots_root(&config).join("feedc0de");
        tokio::fs::create_dir_all(snap.join("repodata"))
            .await
            .unwrap();
        tokio::fs::write(snap.join(MANIFEST_NAME), b"{}")
            .await
            .unwrap();
        tokio::fs::write(snap.join(REPODATA_INDEX), b"<repomd/>")
            .await
            .unwrap();
        heal_base_snapshot(&base_os, &config).await.unwrap();
        // 守卫路径不得改动快照目录内容。
        assert!(snap.join(REPODATA_INDEX).exists());
    }

    /// heal 失败退避：不可恢复闭包（cache miss + 无 url）首试失败落 marker，
    /// 冷却期内第二次调用短路 Ok 且快照仍缺失；冷却窗口归零时重试再次失败。
    #[tokio::test]
    async fn heal_backoff_skips_within_cooldown_and_retries_after() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let config = Config {
            product: "mydist".to_string(),
            crbs_root: tmp.path().to_path_buf(),
            package_cache_path: cache.path().to_path_buf(),
            tmp_dir: tmp.path().join("tmp"),
            base_snapshot_keep_generations: 2,
            ..Config::default()
        };
        let base_os = tmp.path().join("products").join("mydist").join("base");
        tokio::fs::create_dir_all(&base_os).await.unwrap();
        let manifest = SnapshotManifest {
            snapshot_id: "deadbeef".to_string(),
            packages: vec![pkg("bash-5.2-1.x86_64", &"ab".repeat(32))],
        };
        write_json_atomic(
            &base_os.join(MANIFEST_NAME),
            &serde_json::to_value(&manifest).unwrap(),
        )
        .await
        .unwrap();

        let marker = base_snapshots_root(&config).join(HEAL_FAILURE_MARKER);
        assert!(
            heal_base_snapshot_with_cooldown(&base_os, &config, std::time::Duration::ZERO)
                .await
                .is_err(),
            "unrestorable closure must fail on first attempt"
        );
        assert!(marker.exists(), "failure must land the cooldown marker");

        // 冷却期内：Ok 短路，快照目录仍缺失（不再空转重试）。
        heal_base_snapshot_with_cooldown(&base_os, &config, std::time::Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(!base_snapshots_root(&config).join("deadbeef").exists());

        // 窗口过期：重试真实执行，再次失败。
        assert!(
            heal_base_snapshot_with_cooldown(&base_os, &config, std::time::Duration::ZERO)
                .await
                .is_err(),
            "expired cooldown must retry the restore"
        );
    }

    /// 复现域分流：记录集缺失（旗标被绕过 apply_reproduce_engine 置位）→
    /// 解析域仍是 crbs-local repo 但无锚（manifest None）；带记录集的发布臂
    /// 依赖 createrepo，编排骨径由 init 集成覆盖。
    #[tokio::test]
    async fn replay_domain_without_source_packages_has_no_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let engine = crate::engine::minimal_engine(tmp.path())
            .await
            .with_local_repo(tmp.path().join("repo"))
            .with_replay_snapshot_domain();
        let domain = ensure_init_snapshot_domain(&engine, engine.config(), None)
            .await
            .unwrap();
        assert!(domain.manifest.is_none(), "no record set → no anchor");
        assert_eq!(domain.repos.len(), 1);
        assert_eq!(domain.repos[0].name, "crbs-local");
        assert!(domain.repos[0].baseurl.starts_with("file://"));
    }

    /// prune 选择：只保留新近 `keep` 代，在用代豁免（哪怕最老）；`.tmp` staging
    /// 未过宽限不动。mtime 序由创建先后（间隔 sleep）保证。
    #[tokio::test]
    async fn prune_keeps_newest_generations_and_protects_live_id() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let root = base_snapshots_root(&config);

        // 依创建序（mtime 递增）：old < mid < live。keep=2 → old 出局；live 虽
        // 最新也在保留窗内。
        for (name, pause_ms) in [("000old", 50u64), ("111mid", 50), ("222live", 0)] {
            let d = root.join(name);
            tokio::fs::create_dir_all(&d).await.unwrap();
            if pause_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
            }
        }
        // 未过宽限的 staging 必须豁免。
        let staging = root.join(".tmpABC123");
        tokio::fs::create_dir_all(&staging).await.unwrap();

        prune_base_snapshots(&config, Some("000old")).await;

        assert!(
            root.join("000old").exists(),
            "protected (live base referenced) generation must survive despite being oldest"
        );
        assert!(
            root.join("222live").exists() && root.join("111mid").exists(),
            "newest `keep` generations survive"
        );
        assert!(staging.exists(), "young staging must be exempt");

        // keep=1：mid 代出局（新近序在 protected 之后的第 2 位）。
        let mut config_keep1 = config.clone();
        config_keep1.base_snapshot_keep_generations = 1;
        prune_base_snapshots(&config_keep1, Some("000old")).await;
        assert!(
            !root.join("111mid").exists(),
            "mid generation must be pruned at keep=1"
        );
        assert!(
            root.join("222live").exists() && root.join("000old").exists(),
            "newest and protected survive"
        );

        // keep=0：完全禁用清理（新生成的老代也不动）。
        let newer = root.join("333newer");
        tokio::fs::create_dir_all(&newer).await.unwrap();
        let mut config_keep0 = config.clone();
        config_keep0.base_snapshot_keep_generations = 0;
        prune_base_snapshots(&config_keep0, Some("000old")).await;
        assert!(newer.exists(), "keep=0 must disable pruning");
    }
}
