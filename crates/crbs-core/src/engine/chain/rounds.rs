// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Chain 逐轮编排：拓扑轮构建、轮间精准注入、失败策略、恢复轮不动点与
//! 汇总出口。构建执行经 [`ChainBuildExecutor`] 注入、输出经
//! [`ChainProgressSink`] 回调，本模块不接触 worker 池与渲染。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::engine::depsolve::{extract_srpm_name, DepGraph, SrpmInfo};
use crate::error::CrbsError;
use crate::types::{BuildOutputs, BuildSummary};

use super::prepare::ChainContext;
use super::{ChainBuildExecutor, ChainProgressSink, ChainSummaryData};

/// 跨轮失败名共享集（恢复轮候选源，主/恢复轮并发登记）。
type SharedFailedSet = std::sync::Arc<tokio::sync::Mutex<HashSet<String>>>;

/// [`execute_chain_rounds`] 的参数包：取消、失败策略与 chain 汇总元信息；执行器/输出回调保持在参数位（注入边界）。
pub(crate) struct ChainRoundsParams<'a> {
    pub(crate) cancel_token: &'a CancellationToken,
    pub(crate) fail_fast: bool,
    /// chain run 起点（prepare 之前），摘要 wall_time 以此计。
    pub(crate) chain_start: Instant,
    pub(crate) parallelism: usize,
}

/// 执行 chain 的逐轮构建、local repo 更新、失败传播与汇总输出。
/// 每轮构建由 `exec` 完成（worker 池与签名由调用方注入）；用户可见输出经 `out`
/// 回调，错误语义原样上抛由调用方映射退出码。
pub(crate) async fn execute_chain_rounds(
    ctx: ChainContext,
    params: ChainRoundsParams<'_>,
    exec: &dyn ChainBuildExecutor,
    out: &mut dyn ChainProgressSink,
) -> anyhow::Result<()> {
    let ChainRoundsParams {
        cancel_token,
        fail_fast,
        chain_start,
        parallelism,
    } = params;

    let ChainContext {
        product,
        ref repo_dir, // chain 总是维护 local repo；是否注入 chroot 由 engine.local_repo_dir 控制
        rounds,
        graph,
        cached_names,
        cycle_attempted,
        max_recovery_rounds,
        dist,
    } = ctx;

    let mut all_succeeded: Vec<(PathBuf, BuildOutputs, u64)> = Vec::new();
    let mut all_failed: Vec<(PathBuf, CrbsError, u64)> = Vec::new();
    let mut all_cancelled: Vec<(PathBuf, CrbsError, u64)> = Vec::new();
    let mut all_timeout: Vec<(PathBuf, CrbsError, u64)> = Vec::new();
    let mut dep_skipped: Vec<String> = Vec::new();
    // 恢复轮成功包名（RECOVERED 分类；JSON 不开新字段，仍属 `outcome: "succeeded"`）。
    let mut all_recovered: Vec<String> = Vec::new();
    // tokio::sync::Mutex：无毒化——std 锁中毒 Err 路径会静默丢失败名。
    let failed_set: SharedFailedSet = std::sync::Arc::new(tokio::sync::Mutex::new(HashSet::new()));
    let num_rounds = rounds.len();

    // 精准注入：只灌被依赖的产物，避免与 base_os EVR 冲突（详见 filter_injection_rpms 注释）。
    let needed_names = needed_names(&graph.edges);

    // 中途失败（build_round Err / local repo 更新失败中止）先打已积累 summary 再传播错误
    //（静默丢弃使用户/CI 无从得知已成功包）；打印自身失败仅 warn，不遮蔽原始错误。
    macro_rules! print_accumulated_summary {
        () => {
            out.summary(ChainSummaryData {
                product: &product,
                summary: &BuildSummary {
                    succeeded: all_succeeded.clone(),
                    failed: all_failed.clone(),
                    cancelled: all_cancelled.clone(),
                    timeout: all_timeout.clone(),
                },
                cached_names: &cached_names,
                dep_skipped: &dep_skipped,
                cycle_attempted: &cycle_attempted,
                recovered: &all_recovered,
                wall_time: chain_start.elapsed(),
                rounds: num_rounds,
                parallelism,
            })
            .await
        };
    }

    for (round_idx, round) in rounds.into_iter().enumerate() {
        if cancel_token.is_cancelled() {
            break;
        }

        // 过滤 dep-skipped：依赖已在 failed_set（真失败或前序轮转嫁）则本包
        // 跳过，且 dep_skipped 包也入 failed_set（恢复轮统一候选源）。
        // push 与 insert 必须同一锁内，否则并发读漏新进 dep-skipped 包。
        let to_build = partition_round(&round, &graph, &failed_set, &mut dep_skipped).await;

        if to_build.is_empty() {
            continue;
        }

        let round_total = to_build.len();

        out.round_start(round_idx, num_rounds, round_total);

        let round_inputs: Vec<(PathBuf, Option<String>)> = round_build_targets(&to_build);
        let round_names: Vec<String> = to_build.iter().map(|s| s.name.clone()).collect();

        // 构建。transient 失败的重试由 engine-level RetryPolicy 或 daemon 内部处理。
        let round_summary = match exec
            .run_round(round_inputs.clone(), round_names.clone())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                if let Err(pe) = print_accumulated_summary!() {
                    warn!(error = %pe, "Failed to print partial chain summary");
                }
                return Err(e);
            }
        };

        // 精准注入：只灌被依赖的产物；空输入也须调用（内部持锁清悬空 symlink
        // + createrepo，防陈旧 repodata 留到下一非空注入轮）。注入缝传真实
        // rpm_query_release（Timeout 分流为整链中止）。
        let rpm_paths: Vec<PathBuf> =
            filter_injection_rpms(&round_summary.succeeded, &needed_names);
        if let Err(e) = exec
            .inject_rpms(repo_dir, &rpm_paths, dist.as_deref())
            .await
        {
            // 陈旧 repodata 上继续后续轮会产生 "nothing provides X" 误导级联，
            // 中止并如实传播；已完成轮次已随 partial summary 打印。
            if let Err(pe) = print_accumulated_summary!() {
                warn!(error = %pe, "Failed to print partial chain summary");
            }
            // anyhow context 包装保留 CrbsError 变体 downcast
            //（退出码 Io→6 / ValidationFailed→4 / Cancelled→3），不拍平 INTERNAL。
            return Err(anyhow::Error::new(e).context("update local repo failed, aborting chain"));
        }

        register_failed_names(
            &round_summary.failed,
            &round_names,
            &round_inputs,
            &failed_set,
        )
        .await;

        all_succeeded.extend(round_summary.succeeded);
        all_failed.extend(round_summary.failed);
        all_cancelled.extend(round_summary.cancelled);
        all_timeout.extend(round_summary.timeout);

        if fail_fast && !all_failed.is_empty() {
            cancel_token.cancel();
            break;
        }
    }

    // 恢复轮不动点：拓扑轮跑完后重试 failed_set 中依赖已解锁的包，本轮无新
    // 成功产物即止。max_recovery_rounds 来自 Config.chain_max_recovery_rounds，
    // 0 = 禁用恢复。成功包移出 failed_set 并从 all_failed retain 掉（防 summary
    // 双重计数）；失败包重新入 failed_set + 进 all_failed。
    let mut recovery_round = 0usize;
    loop {
        if cancel_token.is_cancelled() {
            break;
        }
        if recovery_round >= max_recovery_rounds {
            break;
        }
        recovery_round += 1;

        let failed_snapshot: HashSet<String> = failed_set.lock().await.clone();
        if failed_snapshot.is_empty() {
            break;
        }

        let candidates: Vec<SrpmInfo> =
            recovery_candidates(&graph.nodes, &graph.edges, &failed_snapshot);

        if candidates.is_empty() {
            break;
        }

        out.recovery_round_start(recovery_round, max_recovery_rounds, candidates.len());

        // 从 failed_set 临时移除候选（让它们能重新构建；失败后再回填）。
        {
            let mut fs = failed_set.lock().await;
            for c in &candidates {
                fs.remove(&c.name);
            }
        }

        let cand_paths: Vec<(PathBuf, Option<String>)> = round_build_targets(&candidates);
        let cand_names: Vec<String> = candidates.iter().map(|s| s.name.clone()).collect();
        let recovery_summary = match exec.run_round(cand_paths.clone(), cand_names.clone()).await {
            Ok(s) => s,
            Err(e) => {
                if let Err(pe) = print_accumulated_summary!() {
                    warn!(error = %pe, "Failed to print partial chain summary");
                }
                return Err(e);
            }
        };

        // 精准注入同主循环（空输入也调；注入缝传真实 rpm_query_release）。
        let rpm_paths: Vec<PathBuf> =
            filter_injection_rpms(&recovery_summary.succeeded, &needed_names);
        if let Err(e) = exec
            .inject_rpms(repo_dir, &rpm_paths, dist.as_deref())
            .await
        {
            if let Err(pe) = print_accumulated_summary!() {
                warn!(error = %pe, "Failed to print partial chain summary");
            }
            // 同主循环——保留 CrbsError 变体 downcast。
            return Err(anyhow::Error::new(e)
                .context("update local repo failed in recovery round, aborting chain"));
        }

        // 记录成功：从 all_failed retain 掉（防 summary 双重计数）；匹配键须用
        // SRPM 路径推导裸名——pkg_name 是 NVR stem 永不相等，否则恢复成功包
        // 误留 all_failed。
        let recovered_names: std::collections::HashSet<String> = recovery_summary
            .succeeded
            .iter()
            // 畸形名 None 不参与匹配，all_failed 对应条目照常保留。
            .filter_map(|(p, _, _)| extract_srpm_name(p))
            .collect();
        all_failed.retain(|(p, _, _)| {
            !extract_srpm_name(p).is_some_and(|n| recovered_names.contains(&n))
        });
        all_succeeded.extend(recovery_summary.succeeded);
        all_recovered.extend(recovered_names.iter().cloned());

        register_failed_names(
            &recovery_summary.failed,
            &cand_names,
            &cand_paths,
            &failed_set,
        )
        .await;
        all_failed.extend(recovery_summary.failed);
        all_cancelled.extend(recovery_summary.cancelled);
        all_timeout.extend(recovery_summary.timeout);

        if recovered_names.is_empty() {
            break;
        }
    }

    let chain_summary = BuildSummary {
        succeeded: all_succeeded,
        failed: all_failed,
        cancelled: all_cancelled,
        timeout: all_timeout,
    };

    out.summary(ChainSummaryData {
        product: &product,
        summary: &chain_summary,
        cached_names: &cached_names,
        dep_skipped: &dep_skipped,
        cycle_attempted: &cycle_attempted,
        recovered: &all_recovered,
        wall_time: chain_start.elapsed(),
        rounds: num_rounds,
        parallelism,
    })
    .await?;

    if !chain_summary.failed.is_empty()
        || !chain_summary.cancelled.is_empty()
        || !chain_summary.timeout.is_empty()
    {
        // cycle_attempted 不作失败原因（round 0 已尝试）；代表错误取 failed→timeout→cancelled 首个。
        let representative =
            chain_summary
                .representative_error()
                .unwrap_or_else(|| CrbsError::DepsolveFailed {
                    message: "chain build did not produce any completed result".to_string(),
                });
        return Err(representative.into());
    }

    Ok(())
}

/// 把一轮的包按"依赖是否被 failed_set 阻塞"分桶：被阻塞包名 push 进
/// `dep_skipped`（展示层 + 兼容旧 JSON）并 insert 进 `failed_set`（恢复轮
/// 统一候选源）。阻塞判定与 insert 必须同一锁内，否则并发读漏新进包。
/// 失败登记进 failed_set（主/恢复轮共用）：zip 按输入路径查名，查无再退
/// SRPM 文件名推导；两者皆无键可提取时 warn 跳过登记（all_failed 仍如实
/// 展示，不误报恢复候选）。
async fn register_failed_names(
    failed: &[(PathBuf, CrbsError, u64)],
    names: &[String],
    inputs: &[(PathBuf, Option<String>)],
    failed_set: &SharedFailedSet,
) {
    for (path, _, _) in failed {
        if let Some(name) = names
            .iter()
            .zip(inputs.iter())
            .find(|(_, (p, _))| *p == *path)
            .map(|(n, _)| n.clone())
            .or_else(|| extract_srpm_name(path))
        {
            failed_set.lock().await.insert(name);
        } else {
            warn!(
                path = %path.display(),
                "cannot derive package name for failed set; skipping recovery registration"
            );
        }
    }
}

async fn partition_round(
    round: &[SrpmInfo],
    graph: &DepGraph,
    failed_set: &SharedFailedSet,
    dep_skipped: &mut Vec<String>,
) -> Vec<SrpmInfo> {
    let mut failed = failed_set.lock().await;
    // guard 直传（deref 强转不复制集合），级联 insert 与回填同锁（见函数注释）。
    let (to_build, blocked_names) = partition_round_core(round, &graph.edges, &mut failed);
    dep_skipped.extend(blocked_names);
    to_build
}

/// `partition_round` 的纯核心：按依赖是否在 failed 集合分桶，返回
/// `(to_build, blocked_names)`。遍历中 blocked 名即时入集——同轮靠后的包
/// 可因前包刚被阻塞而连锁阻塞。
fn partition_round_core(
    round: &[SrpmInfo],
    edges: &HashMap<String, Vec<String>>,
    failed: &mut HashSet<String>,
) -> (Vec<SrpmInfo>, Vec<String>) {
    let mut to_build = Vec::new();
    let mut blocked_names = Vec::new();
    for s in round {
        let blocked = edges
            .get(&s.name)
            .map(|deps| deps.iter().any(|d| failed.contains(d)))
            .unwrap_or(false);
        if blocked {
            blocked_names.push(s.name.clone());
            failed.insert(s.name.clone());
        } else {
            to_build.push(s.clone());
        }
    }
    (to_build, blocked_names)
}

/// 恢复轮候选筛选：从 failed 集合出发，只保留"所有 batch 内依赖都不在
/// failed 集合"（已成功或不在 batch）的包；顺序跟随 HashSet 任意迭代序。
fn recovery_candidates(
    nodes: &[SrpmInfo],
    edges: &HashMap<String, Vec<String>>,
    failed: &HashSet<String>,
) -> Vec<SrpmInfo> {
    let node_by_name: HashMap<&str, &SrpmInfo> =
        nodes.iter().map(|n| (n.name.as_str(), n)).collect();
    failed
        .iter()
        .filter_map(|name| node_by_name.get(name.as_str()).copied())
        .filter(|n| {
            edges
                .get(&n.name)
                .map(|deps| !deps.iter().any(|d| failed.contains(d)))
                .unwrap_or(true)
        })
        .cloned()
        .collect()
}

/// 收集"被 batch 内其他包依赖"的包名集合（精准注入的白名单）。
fn needed_names(edges: &HashMap<String, Vec<String>>) -> HashSet<String> {
    edges.values().flatten().cloned().collect()
}

/// 从一轮成功产物中筛出需灌入 crbs-local 的路径：只保留 `needed`（被其他
/// batch 包依赖）包的产物（rpms+srpms），无人依赖不注入——避免与 base_os
/// 已装包 EVR 冲突。匹配键必须从 SRPM 路径推导裸包名：
/// `pkg_name` 是 NVR stem（如 `nginx-1.21.5-17.oe2203sp4`，见 srpm_display_name），
/// 与 edges 裸名永不相等，直接比较精准注入整体失效；畸形名（None）不注入。
fn filter_injection_rpms(
    succeeded: &[(PathBuf, BuildOutputs, u64)],
    needed: &HashSet<String>,
) -> Vec<PathBuf> {
    succeeded
        .iter()
        .filter(|(path, _, _)| extract_srpm_name(path).is_some_and(|name| needed.contains(&name)))
        .flat_map(|(_, o, _)| o.rpms.iter().chain(o.srpms.iter()).cloned())
        .collect()
}

/// 把一轮的 `SrpmInfo` 映射为 worker 输入：noarch 包显式带 `Some("noarch")`
/// 目标 arch，其余（含空 arch）为 `None`（跟随主机 arch）。
fn round_build_targets(round: &[SrpmInfo]) -> Vec<(PathBuf, Option<String>)> {
    round
        .iter()
        .map(|s| {
            (
                s.path.clone(),
                if s.arch == "noarch" {
                    Some("noarch".to_string())
                } else {
                    None
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::path::Path;
    use std::pin::Pin;

    use crate::engine::chain::ChainPlanData;

    /// 最小 `SrpmInfo` 字面量。
    fn srpm(name: &str, arch: &str) -> SrpmInfo {
        SrpmInfo {
            name: name.into(),
            path: PathBuf::from(format!("{name}-1.0-1.src.rpm")),
            arch: arch.into(),
            build_requires: vec![],
        }
    }

    /// 最小 `BuildOutputs` 字面量：只填注入过滤关心的 pkg_name / rpms / srpms。
    fn outputs(pkg: &str, rpms: &[&str], srpms: &[&str]) -> BuildOutputs {
        BuildOutputs {
            build_id: 1,
            pkg_name: pkg.into(),
            rpms: rpms.iter().map(PathBuf::from).collect(),
            srpms: srpms.iter().map(PathBuf::from).collect(),
            logs: vec![],
            result_dir: PathBuf::from("/tmp/crbs-test"),
            retries: 0,
            signed: false,
        }
    }

    // ---- partition_round_core：分桶 + 锁内级联 ----

    #[test]
    fn partition_round_core_blocks_on_failed_dep_and_records() {
        let round = vec![srpm("app", "x86_64")];
        let edges = HashMap::from([("app".to_string(), vec!["lib".to_string()])]);
        let mut failed = HashSet::from(["lib".to_string()]);
        let (to_build, blocked) = partition_round_core(&round, &edges, &mut failed);
        assert!(to_build.is_empty());
        assert_eq!(blocked, vec!["app".to_string()]);
        assert!(
            failed.contains("app"),
            "blocked name must land in failed set"
        );
    }

    #[test]
    fn partition_round_core_same_round_cascade() {
        // [a, b]：a 被已失败的 x 阻塞后即时入集，同轮 b 连锁阻塞。
        let round = vec![srpm("a", "x86_64"), srpm("b", "x86_64")];
        let edges = HashMap::from([
            ("a".to_string(), vec!["x".to_string()]),
            ("b".to_string(), vec!["a".to_string()]),
        ]);
        let mut failed = HashSet::from(["x".to_string()]);
        let (to_build, blocked) = partition_round_core(&round, &edges, &mut failed);
        assert!(to_build.is_empty());
        assert_eq!(blocked, vec!["a".to_string(), "b".to_string()]);
        assert!(failed.contains("a") && failed.contains("b"));

        // 反序 [b, a] 则 b 不阻塞（级联只沿 round 顺序向后传播）——锁定顺序敏感。
        let round_rev = vec![srpm("b", "x86_64"), srpm("a", "x86_64")];
        let mut failed_rev = HashSet::from(["x".to_string()]);
        let (to_build_rev, blocked_rev) = partition_round_core(&round_rev, &edges, &mut failed_rev);
        assert_eq!(
            to_build_rev
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["b"]
        );
        assert_eq!(blocked_rev, vec!["a".to_string()]);
    }

    #[test]
    fn partition_round_core_passes_clean_and_unfailed_dep_packages() {
        let round = vec![srpm("free", "x86_64"), srpm("app", "x86_64")];
        let edges = HashMap::from([("app".to_string(), vec!["built-ok".to_string()])]);
        let mut failed = HashSet::new();
        let (to_build, blocked) = partition_round_core(&round, &edges, &mut failed);
        assert_eq!(
            to_build.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            vec!["free", "app"],
            "to_build must keep round order"
        );
        assert!(blocked.is_empty());
        assert!(failed.is_empty());
    }

    #[test]
    fn partition_round_core_no_edge_entry_not_blocked() {
        let round = vec![srpm("loner", "x86_64")];
        let edges: HashMap<String, Vec<String>> = HashMap::new();
        let mut failed = HashSet::from(["whatever".to_string()]);
        let (to_build, blocked) = partition_round_core(&round, &edges, &mut failed);
        assert_eq!(to_build.len(), 1);
        assert!(blocked.is_empty());
        assert!(!failed.contains("loner"));
    }

    // ---- recovery_candidates：恢复轮精确筛选（结果顺序跟随 HashSet 任意序，断言前排序）----

    #[test]
    fn recovery_candidates_selects_unlocked_packages() {
        let nodes = vec![srpm("a", "x86_64"), srpm("b", "x86_64")];
        let edges = HashMap::from([("a".to_string(), vec!["gone".to_string()])]);
        let failed = HashSet::from(["a".to_string(), "b".to_string()]);
        let candidates = recovery_candidates(&nodes, &edges, &failed);
        let mut got: Vec<&str> = candidates.iter().map(|n| n.name.as_str()).collect();
        got.sort_unstable();
        // a 的依赖已不在 failed；b 无 edges 条目（unwrap_or(true)）→ 两者都入选。
        assert_eq!(got, vec!["a", "b"]);
    }

    #[test]
    fn recovery_candidates_excludes_packages_with_dep_still_failed() {
        // 候选只能从 failed 出发：free 也曾在 failed，但其无依赖被解锁。
        let nodes = vec![srpm("app", "x86_64"), srpm("free", "x86_64")];
        let edges = HashMap::from([("app".to_string(), vec!["lib".to_string()])]);
        let failed = HashSet::from(["app".to_string(), "free".to_string(), "lib".to_string()]);
        let got = recovery_candidates(&nodes, &edges, &failed);
        assert_eq!(
            got.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            vec!["free"]
        );
    }

    #[test]
    fn recovery_candidates_ignores_names_missing_from_nodes() {
        let nodes = vec![srpm("a", "x86_64")];
        let edges: HashMap<String, Vec<String>> = HashMap::new();
        let failed = HashSet::from(["a".to_string(), "ghost".to_string()]);
        let got = recovery_candidates(&nodes, &edges, &failed);
        assert_eq!(
            got.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            vec!["a"]
        );
    }

    #[test]
    fn recovery_candidates_empty_failed_yields_empty() {
        let nodes = vec![srpm("a", "x86_64")];
        let edges = HashMap::from([("a".to_string(), vec!["x".to_string()])]);
        let got = recovery_candidates(&nodes, &edges, &HashSet::new());
        assert!(got.is_empty());
    }

    // ---- needed_names：精准注入白名单 ----

    #[test]
    fn needed_names_unions_edge_lists_deduped() {
        let edges = HashMap::from([
            ("a".to_string(), vec!["x".to_string(), "y".to_string()]),
            ("b".to_string(), vec!["y".to_string(), "z".to_string()]),
        ]);
        let mut got: Vec<String> = needed_names(&edges).into_iter().collect();
        got.sort_unstable();
        assert_eq!(got, vec!["x".to_string(), "y".to_string(), "z".to_string()]);
    }

    #[test]
    fn needed_names_empty_edges_yields_empty() {
        let got = needed_names(&HashMap::<String, Vec<String>>::new());
        assert!(got.is_empty());
    }

    // ---- filter_injection_rpms：只灌被依赖的产物 ----
    // pkg_name 用生产 NVR stem 形态（见 workers.rs srpm_display_name），needed 是裸包名。

    #[test]
    fn filter_injection_rpms_keeps_needed_collects_rpms_and_srpms() {
        let succeeded = vec![
            (
                PathBuf::from("nginx-1.21.5-17.oe2203sp4.src.rpm"),
                outputs(
                    "nginx-1.21.5-17.oe2203sp4",
                    &["nginx-1.21.5-17.oe2203sp4.x86_64.rpm"],
                    &["nginx-1.21.5-17.oe2203sp4.src.rpm"],
                ),
                1u64,
            ),
            (
                PathBuf::from("tool-2.4-1.oe24.src.rpm"),
                outputs(
                    "tool-2.4-1.oe24",
                    &["tool-2.4-1.oe24.x86_64.rpm"],
                    &["tool-2.4-1.oe24.src.rpm"],
                ),
                2u64,
            ),
        ];
        let needed: HashSet<String> = ["nginx".to_string()].into_iter().collect();
        let got = filter_injection_rpms(&succeeded, &needed);
        assert_eq!(
            got,
            vec![
                PathBuf::from("nginx-1.21.5-17.oe2203sp4.x86_64.rpm"),
                PathBuf::from("nginx-1.21.5-17.oe2203sp4.src.rpm")
            ]
        );
    }

    /// 回归：pkg_name 是 NVR stem、needed 是裸名，直接比较永不匹配（dnf install 缺包）。
    #[test]
    fn filter_injection_rpms_matches_bare_name_despite_nvr_stem_pkg_name() {
        let succeeded = vec![(
            PathBuf::from("nginx-1.21.5-17.oe2203sp4.src.rpm"),
            outputs(
                "nginx-1.21.5-17.oe2203sp4",
                &["nginx-1.21.5-17.oe2203sp4.x86_64.rpm"],
                &[],
            ),
            1u64,
        )];
        let needed: HashSet<String> = ["nginx".to_string()].into_iter().collect();
        let got = filter_injection_rpms(&succeeded, &needed);
        assert_eq!(
            got,
            vec![PathBuf::from("nginx-1.21.5-17.oe2203sp4.x86_64.rpm")],
            "bare name in needed must match despite NVR-stem pkg_name"
        );
    }

    #[test]
    fn filter_injection_rpms_excludes_unneeded() {
        let succeeded = vec![(
            PathBuf::from("orphan-1.0-1.oe24.src.rpm"),
            outputs(
                "orphan-1.0-1.oe24",
                &["orphan-1.0-1.oe24.x86_64.rpm"],
                &["orphan-1.0-1.oe24.src.rpm"],
            ),
            1u64,
        )];
        let needed: HashSet<String> = HashSet::new();
        assert!(filter_injection_rpms(&succeeded, &needed).is_empty());
    }

    // ---- round_build_targets：noarch 目标映射 ----

    #[test]
    fn round_build_targets_maps_noarch() {
        let round = vec![srpm("doc", "noarch"), srpm("lib", "x86_64")];
        let got = round_build_targets(&round);
        assert_eq!(
            got,
            vec![
                (
                    PathBuf::from("doc-1.0-1.src.rpm"),
                    Some("noarch".to_string())
                ),
                (PathBuf::from("lib-1.0-1.src.rpm"), None),
            ]
        );
    }

    #[test]
    fn round_build_targets_other_and_empty_arch_map_none() {
        let round = vec![srpm("lib", "aarch64"), srpm("raw", "")];
        let got = round_build_targets(&round);
        assert_eq!(
            got,
            vec![
                (PathBuf::from("lib-1.0-1.src.rpm"), None),
                (PathBuf::from("raw-1.0-1.src.rpm"), None),
            ]
        );
    }

    // ---- 编排级最小测试：mock executor 跑两轮小图，断言轮间注入与失败策略 ----

    type RoundTargets = Vec<(PathBuf, Option<String>)>;

    /// 记录式执行器 mock：按调用序回放预置 BuildSummary（越界回退空汇总），
    /// 记录每轮 targets 与注入请求；不触真实构建 / local repo（注入缝为记录器）。
    struct MockExecutor {
        rounds_sent: std::sync::Mutex<Vec<RoundTargets>>,
        injections: std::sync::Mutex<Vec<Vec<PathBuf>>>,
        script: Vec<BuildSummary>,
    }

    impl ChainBuildExecutor for MockExecutor {
        fn run_round(
            &self,
            targets: Vec<(PathBuf, Option<String>)>,
            _round_names: Vec<String>,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<BuildSummary>> + Send + '_>> {
            Box::pin(async move {
                let mut rounds = self.rounds_sent.lock().expect("mock rounds lock");
                let idx = rounds.len();
                rounds.push(targets);
                drop(rounds);
                Ok(self.script.get(idx).cloned().unwrap_or_default())
            })
        }

        fn inject_rpms<'a>(
            &'a self,
            _repo_dir: &'a Path,
            rpm_paths: &'a [PathBuf],
            _dist: Option<&'a str>,
        ) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.injections
                    .lock()
                    .expect("mock injections lock")
                    .push(rpm_paths.to_vec());
                Ok(())
            })
        }
    }

    /// 记录式输出 mock：记录轮头事件与每次摘要快照（失败策略断言用）。
    #[derive(Default)]
    struct MockSink {
        events: Vec<String>,
        /// (失败桶计数, dep_skipped 计数, dep_skipped 名单, recovered 名单)。
        summaries: Vec<(usize, usize, Vec<String>, Vec<String>)>,
    }

    impl ChainProgressSink for MockSink {
        fn prepare_error(&mut self, error: anyhow::Error) -> anyhow::Error {
            error
        }
        fn missing_required_tool(&mut self, _tool: &str) -> anyhow::Error {
            unreachable!("tool check runs in prepare, not in rounds")
        }
        fn empty_input(&mut self, _product: &str) -> anyhow::Result<()> {
            unreachable!("empty input handled in prepare, not in rounds")
        }
        fn plan(&mut self, _plan: &ChainPlanData<'_>) -> anyhow::Result<()> {
            unreachable!("plan output handled in prepare, not in rounds")
        }
        fn round_start(&mut self, round_index: usize, total_rounds: usize, packages: usize) {
            self.events.push(format!(
                "round {}/{total_rounds} pkgs={packages}",
                round_index + 1
            ));
        }
        fn recovery_round_start(&mut self, round: usize, max: usize, packages: usize) {
            self.events
                .push(format!("recovery {round}/{max} pkgs={packages}"));
        }
        fn summary<'a>(
            &'a mut self,
            data: ChainSummaryData<'a>,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.summaries.push((
                    data.summary.failed.len()
                        + data.summary.cancelled.len()
                        + data.summary.timeout.len(),
                    data.dep_skipped.len(),
                    data.dep_skipped.to_vec(),
                    data.recovered.to_vec(),
                ));
                Ok(())
            })
        }
    }

    /// 成功项：SRPM 路径 + rpm/srpm 产物（pkg_name 用 NVR stem 生产形态）。
    fn succ(name: &str) -> (PathBuf, BuildOutputs, u64) {
        (
            PathBuf::from(format!("{name}-1.0-1.src.rpm")),
            outputs(
                &format!("{name}-1.0-1"),
                &[&format!("{name}-1.0-1.x86_64.rpm")],
                &[&format!("{name}-1.0-1.src.rpm")],
            ),
            1,
        )
    }

    /// 失败项：SRPM 路径 + DepsolveFailed。
    fn fail(name: &str) -> (PathBuf, CrbsError, u64) {
        (
            PathBuf::from(format!("{name}-1.0-1.src.rpm")),
            CrbsError::DepsolveFailed {
                message: format!("{name} build failed"),
            },
            1,
        )
    }

    /// 两轮小图：app 依赖 lib（edges: app → [lib]），needed = {lib}。
    fn two_round_ctx(max_recovery_rounds: usize) -> ChainContext {
        ChainContext {
            product: "prod_a".to_string(),
            repo_dir: PathBuf::from("/tmp/crbs-chain-test-repo"),
            rounds: vec![vec![srpm("lib", "x86_64")], vec![srpm("app", "x86_64")]],
            graph: DepGraph {
                nodes: vec![srpm("lib", "x86_64"), srpm("app", "x86_64")],
                edges: HashMap::from([("app".to_string(), vec!["lib".to_string()])]),
            },
            cached_names: vec![],
            cycle_attempted: vec![],
            max_recovery_rounds,
            dist: None,
        }
    }

    fn rounds_params(cancel: &CancellationToken) -> ChainRoundsParams<'_> {
        ChainRoundsParams {
            cancel_token: cancel,
            fail_fast: false,
            chain_start: Instant::now(),
            parallelism: 2,
        }
    }

    /// 两轮全成功：轮间只注入被依赖的 lib 产物；第二轮空注入仍调用（repodata 不陈旧）。
    #[tokio::test]
    async fn two_rounds_inject_only_needed_rpms_between_rounds() {
        let cancel = CancellationToken::new();
        let exec = MockExecutor {
            rounds_sent: std::sync::Mutex::new(Vec::new()),
            injections: std::sync::Mutex::new(Vec::new()),
            script: vec![
                BuildSummary {
                    succeeded: vec![succ("lib")],
                    ..BuildSummary::default()
                },
                BuildSummary {
                    succeeded: vec![succ("app")],
                    ..BuildSummary::default()
                },
            ],
        };
        let mut sink = MockSink::default();

        let res =
            execute_chain_rounds(two_round_ctx(0), rounds_params(&cancel), &exec, &mut sink).await;
        assert!(res.is_ok(), "all-success chain must succeed: {res:?}");

        let rounds = exec.rounds_sent.lock().expect("rounds lock");
        assert_eq!(rounds.len(), 2, "two rounds must run in order");
        assert_eq!(rounds[0], vec![(PathBuf::from("lib-1.0-1.src.rpm"), None)]);
        assert_eq!(rounds[1], vec![(PathBuf::from("app-1.0-1.src.rpm"), None)]);

        let injections = exec.injections.lock().expect("injections lock");
        assert_eq!(injections.len(), 2, "injection must run after each round");
        assert_eq!(
            injections[0],
            vec![
                PathBuf::from("lib-1.0-1.x86_64.rpm"),
                PathBuf::from("lib-1.0-1.src.rpm")
            ],
            "round1 must inject lib's rpm+srpm (needed by app)"
        );
        assert!(injections[1].is_empty(), "round2 (app) must inject nothing");

        assert_eq!(sink.events, vec!["round 1/2 pkgs=1", "round 2/2 pkgs=1"]);
        assert_eq!(sink.summaries.len(), 1);
        assert_eq!(sink.summaries[0].0, 0, "final summary must be all-clear");
    }

    /// 失败策略：lib 失败 → app 被 dep-skip、恢复禁用；摘要报 failed=1 + dep_skipped=[app]，lib 错误为代表错误上抛。
    #[tokio::test]
    async fn failed_dep_skips_dependents_and_surfaces_representative_error() {
        let cancel = CancellationToken::new();
        let exec = MockExecutor {
            rounds_sent: std::sync::Mutex::new(Vec::new()),
            injections: std::sync::Mutex::new(Vec::new()),
            script: vec![BuildSummary {
                failed: vec![fail("lib")],
                ..BuildSummary::default()
            }],
        };
        let mut sink = MockSink::default();

        let res =
            execute_chain_rounds(two_round_ctx(0), rounds_params(&cancel), &exec, &mut sink).await;
        let err = res.expect_err("chain with a failed package must error out");
        assert!(
            matches!(err.downcast_ref::<CrbsError>(),
                     Some(CrbsError::DepsolveFailed { message }) if message == "lib build failed"),
            "representative error must be lib's failure, got {err:#}"
        );

        let rounds = exec.rounds_sent.lock().expect("rounds lock");
        assert_eq!(
            rounds.len(),
            1,
            "dep-skipped round must not reach the executor"
        );

        // 空注入（round1 无成功产物）仍调用，保持 repodata 不陈旧。
        let injections = exec.injections.lock().expect("injections lock");
        assert_eq!(injections.len(), 1);
        assert!(injections[0].is_empty());

        assert_eq!(
            sink.events,
            vec!["round 1/2 pkgs=1"],
            "round2 header must not print"
        );
        assert_eq!(sink.summaries.len(), 1);
        assert_eq!(sink.summaries[0].0, 1, "failed count must be 1 (lib)");
        assert_eq!(sink.summaries[0].2, vec!["app".to_string()]);
    }

    /// 恢复轮不动点：lib 失败 → app dep-skip；恢复轮 1 重试 lib、轮 2 重试 app 均成功；摘要 recovered=[lib, app]、failed 清零。
    #[tokio::test]
    async fn recovery_rounds_retry_unlocked_packages_to_success() {
        let cancel = CancellationToken::new();
        let exec = MockExecutor {
            rounds_sent: std::sync::Mutex::new(Vec::new()),
            injections: std::sync::Mutex::new(Vec::new()),
            script: vec![
                BuildSummary {
                    failed: vec![fail("lib")],
                    ..BuildSummary::default()
                },
                BuildSummary {
                    succeeded: vec![succ("lib")],
                    ..BuildSummary::default()
                },
                BuildSummary {
                    succeeded: vec![succ("app")],
                    ..BuildSummary::default()
                },
            ],
        };
        let mut sink = MockSink::default();

        let res =
            execute_chain_rounds(two_round_ctx(2), rounds_params(&cancel), &exec, &mut sink).await;
        assert!(res.is_ok(), "recovered chain must succeed: {res:?}");

        let rounds = exec.rounds_sent.lock().expect("rounds lock");
        assert_eq!(
            rounds
                .iter()
                .map(|r| r
                    .iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![
                vec!["lib-1.0-1.src.rpm".to_string()],
                vec!["lib-1.0-1.src.rpm".to_string()],
                vec!["app-1.0-1.src.rpm".to_string()],
            ],
            "recovery must retry lib first, then unlocked app"
        );

        let injections = exec.injections.lock().expect("injections lock");
        assert_eq!(injections.len(), 3);
        assert_eq!(
            injections[1],
            vec![
                PathBuf::from("lib-1.0-1.x86_64.rpm"),
                PathBuf::from("lib-1.0-1.src.rpm")
            ]
        );
        assert!(injections[2].is_empty());

        assert_eq!(
            sink.events,
            vec![
                "round 1/2 pkgs=1".to_string(),
                "recovery 1/2 pkgs=1".to_string(),
                "recovery 2/2 pkgs=1".to_string(),
            ]
        );
        assert_eq!(sink.summaries.len(), 1);
        assert_eq!(
            sink.summaries[0].0, 0,
            "recovered failures must leave the failed bucket"
        );
        assert_eq!(
            sink.summaries[0].3,
            vec!["lib".to_string(), "app".to_string()],
            "recovered order must follow recovery rounds"
        );
    }
}
