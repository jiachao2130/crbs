// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain prepare 阶段：工具检查、local repo 初始化、增量缓存、BR 提取、
//! dist 预检、依赖解析与拓扑排序。计划/错误输出经 [`ChainProgressSink`]
//! 回调，本模块不直接打印。

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::config::RepoConfig;
use crate::engine::depsolve::{repoquery_release_args, DepGraph, SrpmInfo};
use crate::engine::repo::rpm_release_suffix_matches;
use crate::error::CrbsError;

use super::{ChainPlanData, ChainProgressSink, ChainRunInput};

/// chain 构建所需上下文，由 `prepare_chain_context` 生成。
pub(crate) struct ChainContext {
    pub(crate) product: String,
    /// local repo 目录；chain 默认总在这里收集 RPM，`--result-repo` 才注入 chroot。
    pub(crate) repo_dir: PathBuf,
    pub(crate) rounds: Vec<Vec<SrpmInfo>>,
    pub(crate) graph: DepGraph,
    pub(crate) cached_names: Vec<String>,
    // 拓扑排不出的节点（环 + 解析残留）；已并入 round 0 尝试构建，仅作展示层标记，不触发 chain 整体退出。
    pub(crate) cycle_attempted: Vec<String>,
    // 恢复轮上限（来自 `Config.chain_max_recovery_rounds`，0 = 禁用恢复）。
    pub(crate) max_recovery_rounds: usize,
    // 有效 %dist 标签（CLI `--dist` 经 `normalize_dist`；`None` = 未显式指定，
    // `update_local_repo` 的注入前 EVR 校验完全旁路）。
    pub(crate) dist: Option<String>,
}

/// chain 构建的公共前置阶段；返回 `Ok(None)` = 已处理完毕（无输入或仅 `--order-only`）。
pub(crate) async fn prepare_chain_context(
    input: &ChainRunInput<'_>,
    out: &mut dyn ChainProgressSink,
) -> Result<Option<ChainContext>> {
    use crate::engine::br_cache::BrCache;
    use crate::engine::depsolve::{
        build_dep_graph, extract_srpm_name, is_built_in_results, parse_arch_from_srpms,
        parse_br_and_arch_from_srpms, topo_sort,
    };
    use crate::engine::repo::init_local_repo;

    let (engine, product, inputs, cancel_token) = (
        input.engine,
        input.product,
        &input.inputs,
        input.cancel_token,
    );
    let (force, use_result_repo) = (input.force, input.use_result_repo);

    // 0. 前置检查（阻塞 PATH/文件系统查询放入 spawn_blocking）
    if let Some(missing) = check_chain_tools().await? {
        // 文案分流（JSON 裸消息 / text ValidationFailed）由 sink 逐字保持。
        return Err(out.missing_required_tool(missing));
    }

    let config = engine.config();
    let repo_dir: PathBuf = engine
        .local_repo_dir()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| config.local_repo_path());

    init_local_repo(&repo_dir).await?;

    let mut br_cache = if use_result_repo {
        BrCache::load(&repo_dir).await.unwrap_or_else(|e| {
            warn!(error = %e, "Failed to load BR cache; treating as empty");
            BrCache::default()
        })
    } else {
        BrCache::default()
    };

    // 1. 提取包名 + 增量检查（缓存命中跳过 rpm -qp BR+ARCH 元数据探测）
    let mut cached_names: Vec<String> = Vec::new();

    let mut infos: Vec<Option<SrpmInfo>> = Vec::with_capacity(inputs.len());
    let mut to_analyze: Vec<(PathBuf, u64, u64, usize)> = Vec::new();

    for (idx, srpm) in inputs.iter().enumerate() {
        infos.push(None);

        // 增量检查：按 srpm_pkg_name(SRPM 文件名)定位，绕开 host vs container %dist
        // 不一致；命中即跳过后续全流程。
        if !force && is_built_in_results(&config.result_dir, product, srpm).await? {
            // 提取不出裸名不进 cached 列表（理论不可达：is_built_in_results 已过名称形状校验）。
            if let Some(name) = extract_srpm_name(srpm) {
                cached_names.push(name);
            }
            continue;
        }

        let (mtime, size) = if use_result_repo {
            // mtime 取纳秒（秒级会让同秒重建的 SRPM 误命中 BR 缓存），与 size 同作缓存 key 输入
            match tokio::fs::metadata(srpm).await {
                Ok(meta) => {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as u64)
                        .unwrap_or(0);
                    (mtime, meta.len())
                }
                Err(e) => {
                    // stat 失败映射 Io（kind 保真，ENVIRONMENT=6）。
                    return Err(CrbsError::Io {
                        context: format!("stat SRPM {}", srpm.display()),
                        kind: e.kind(),
                        detail: e.to_string(),
                    }
                    .into());
                }
            }
        } else {
            (0, 0)
        };

        if use_result_repo && !force {
            if let Some(cached) = br_cache.get(srpm, mtime, size) {
                infos[idx] = Some(cached);
                continue;
            }
        }

        to_analyze.push((srpm.clone(), mtime, size, idx));
    }

    // 第二遍：批量 rpm 分析未命中的包（两路径共用路径清单与长度守护）。
    let to_analyze_paths: Vec<PathBuf> = to_analyze.iter().map(|(p, _, _, _)| p.clone()).collect();
    let expected = to_analyze.len();
    if use_result_repo {
        let parsed = parse_br_and_arch_from_srpms(&to_analyze_paths, Some(cancel_token)).await;
        ensure_parsed_count(parsed.len(), expected, "rpm metadata parser")?;
        for ((srpm, mtime, size, idx), res) in to_analyze.into_iter().zip(parsed) {
            // 底层错误是 CrbsError（DepsolveFailed=2 / Cancelled=3 等），经 anyhow
            // context 链包装保留变体 downcast，不拍平落 INTERNAL(1)。
            let meta = res.map_err(|e| {
                anyhow::Error::new(e).context(format!("extract BR/ARCH from {}", srpm.display()))
            })?;
            let name = srpm_name_or_reject(&srpm)?;
            let info = SrpmInfo {
                name,
                path: srpm.clone(),
                arch: meta.arch,
                build_requires: meta.build_requires,
            };
            br_cache.insert(&srpm, mtime, size, &info);
            infos[idx] = Some(info);
        }
    } else {
        let arches = parse_arch_from_srpms(&to_analyze_paths, Some(cancel_token)).await;
        ensure_parsed_count(arches.len(), expected, "rpm arch parser")?;
        for ((srpm, _, _, idx), arch) in to_analyze.into_iter().zip(arches) {
            // 同 extract BR/ARCH：anyhow context 链保留 CrbsError 变体 downcast。
            let arch = arch.map_err(|e| {
                anyhow::Error::new(e).context(format!("extract ARCH from {}", srpm.display()))
            })?;
            let name = srpm_name_or_reject(&srpm)?;
            infos[idx] = Some(SrpmInfo {
                name,
                path: srpm,
                arch,
                build_requires: Vec::new(),
            });
        }
    }

    let srpms_with_info: Vec<SrpmInfo> = infos.into_iter().flatten().collect();

    if use_result_repo {
        let input_paths: std::collections::HashSet<std::path::PathBuf> =
            inputs.iter().cloned().collect();
        br_cache.prune_to(&input_paths);
        if let Err(e) = br_cache.save(&repo_dir).await {
            warn!(error = %e, "Failed to save BR cache");
        }
    }

    if srpms_with_info.is_empty() && cached_names.is_empty() {
        out.empty_input(product)?;
        return Ok(None);
    }

    // dist 预检：--dist 显式给出时抽样产品仓库 dist tag 比对，错配仅 warn 不阻断
    //（刻意跨 tag 迁移合法）；repoquery/filesystem 缺失静默降级。
    if let Some(effective) = input.dist.as_deref() {
        if let Some(sampled) = sample_product_repo_dist_suffix(&config.repos, cancel_token).await {
            if !rpm_release_suffix_matches(&sampled, effective) {
                warn!(
                    effective_dist = %effective,
                    repo_dist = %sampled,
                    "{}",
                    dist_mismatch_warning(effective, &sampled)
                );
            }
        }
    }

    // 2. 依赖解析 + 拓扑排序：--result-repo 全量 depsolve（graph.edges 判"谁被依赖"），
    // topo 排序让有包间依赖的包按序构建；--no-result-repo 跳过 depsolve，单轮并行、不注入本地仓库。
    let (graph, rounds, cycle_attempted) = if use_result_repo {
        let graph = if srpms_with_info.is_empty() {
            DepGraph {
                nodes: Vec::new(),
                edges: std::collections::HashMap::new(),
            }
        } else {
            // capability 索引的仓库集必须与构建环境一致：产品仓库 + （--result-repo
            // 时注入 chroot 的）local repo，不能依赖宿主 dnf 配置。
            build_dep_graph(
                &srpms_with_info,
                &config.repos,
                Some(repo_dir.as_path()),
                Some(cancel_token),
            )
            .await?
        };
        let (rounds, cycle_attempted) = topo_sort(&graph);
        (graph, rounds, cycle_attempted)
    } else {
        let nodes = srpms_with_info.clone();
        let graph = DepGraph {
            nodes: nodes.clone(),
            edges: std::collections::HashMap::new(),
        };
        let rounds = vec![nodes];
        let cycle_attempted = Vec::new();
        (graph, rounds, cycle_attempted)
    };

    // 3. 输出构建计划（text 轮次表 / JSON 的 order-only chain-plan 文档，
    // 分流由 sink 按 format + order_only 决定，JSON 普通模式静默）。
    out.plan(&ChainPlanData {
        product,
        rounds: rounds
            .iter()
            .map(|r| r.iter().map(|s| s.name.clone()).collect())
            .collect(),
        cached: &cached_names,
        cycle_attempted: &cycle_attempted,
    })?;

    if input.order_only {
        return Ok(None);
    }

    Ok(Some(ChainContext {
        product: product.to_string(),
        repo_dir,
        rounds,
        graph,
        cached_names,
        cycle_attempted,
        max_recovery_rounds: engine.config().chain_max_recovery_rounds,
        dist: input.dist.clone(),
    }))
}

/// 异步检查 chain 必需的外部工具；缺失时返回 `Some(tool)`，调用方须报错退出。
/// zip 长度守护：解析器少吐条目会让尾部 SRPM 静默消失（infos 永不填充）；
/// 契约违反属防御性不变量，报 INTERNAL(1)。
fn ensure_parsed_count(got: usize, expected: usize, parser: &str) -> anyhow::Result<()> {
    if got != expected {
        anyhow::bail!("{parser} returned {got} results for {expected} SRPMs");
    }
    Ok(())
}

/// 裸包名提取失败即报错：图节点键 / 失败登记键依赖它，占位名会让多个
/// 畸形 SRPM 互撞。
fn srpm_name_or_reject(srpm: &std::path::Path) -> anyhow::Result<String> {
    crate::engine::depsolve::extract_srpm_name(srpm).ok_or_else(|| {
        anyhow::Error::new(CrbsError::ValidationFailed {
            message: format!(
                "cannot derive package name from SRPM {}: file name is not \
                 N-V-R.src.rpm (malformed SRPM file name?)",
                srpm.display()
            ),
        })
    })
}

async fn check_chain_tools() -> anyhow::Result<Option<&'static str>> {
    tokio::task::spawn_blocking(|| {
        for tool in &["dnf", "createrepo_c"] {
            if which::which(tool).is_err() {
                return Some(*tool);
            }
        }
        None
    })
    .await
    .context("check chain tools")
}

/// 构造 dist 错配的 warn 文案（纯函数，供单测与调用共用）；
/// 文案必须包含双方 tag 与 `--dist` 指引（单测锁定）。
fn dist_mismatch_warning(effective: &str, sampled: &str) -> String {
    format!(
        "--dist {effective} mismatches the product repo dist tag {sampled}; built RPMs \
         will carry {effective} while product base packages carry {sampled}, risking EVR \
         conflicts in the chain local repo; pass the matching --dist or review the \
         product repo set"
    )
}

/// 查产品仓库集内 `filesystem` 包 release 的 dist 后缀（产品源 tag）。
/// 尽力而为：repoquery 失败 / 输出为空 / release 无 dist 后缀一律返回
/// `None`（debug 日志），不阻断 chain。
async fn sample_product_repo_dist_suffix(
    repos: &[RepoConfig],
    cancel_token: &CancellationToken,
) -> Option<String> {
    let args = repoquery_release_args(repos, "filesystem");
    let mut cmd = tokio::process::Command::new("dnf");
    cmd.args(&args);
    // 600s 预算：黑洞镜像 / 停滞存储上挂死的 dnf 不得无限占用 chain 启动路径。
    let output = match crate::engine::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn dnf repoquery (dist preflight)",
        Some(cancel_token),
        std::time::Duration::from_secs(600),
    )
    .await
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            debug!(
                exit_code = ?o.status.code(),
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "dist preflight repoquery failed; skipping check"
            );
            return None;
        }
        Err(e) => {
            debug!(error = %e, "dist preflight cannot spawn dnf repoquery; skipping check");
            return None;
        }
    };
    let raw = String::from_utf8_lossy(&output.stdout);
    let release = raw.lines().map(str::trim).find(|l| !l.is_empty())?;
    release_dist_suffix(release)
}

/// 从 release（如 `8.oe2203sp4`）提取 dist 后缀（`.oe2203sp4`）。
/// 取最后一个 `.` 之后以 ASCII 字母开头的尾段；无 dist tag（如 `1`、`1.2`）返回 `None`。
pub fn release_dist_suffix(release: &str) -> Option<String> {
    let tail = release.rsplit_once('.')?.1;
    if tail.starts_with(|c: char| c.is_ascii_alphabetic()) {
        Some(format!(".{tail}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// dist 错配文案必须点名双方 tag 并给出 `--dist` 指引。
    #[test]
    fn dist_mismatch_warning_mentions_both_tags() {
        let w = dist_mismatch_warning(".ule3", ".oe2203sp4");
        assert!(w.contains(".ule3") && w.contains(".oe2203sp4"));
        assert!(w.contains("--dist"));
    }
}
