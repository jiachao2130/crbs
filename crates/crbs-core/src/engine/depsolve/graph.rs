// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 批内依赖建图与拓扑排序。

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::RepoConfig;
use crate::error::CrbsError;
use crate::util::extract_rpm_name;

use super::capability::{build_capability_index, resolve_deps_to_pkgs};

/// 单个 SRPM 的解析结果。
#[derive(Clone)]
pub struct SrpmInfo {
    /// SRPM 包名。
    pub name: String,
    /// SRPM 文件路径。
    pub path: PathBuf,
    /// BuildRequires 列表。
    pub build_requires: Vec<String>,
    /// 产物 ARCH："noarch" 表示纯 noarch 包，其他值为构建架构（如 x86_64）。
    pub arch: String,
}

/// SRPM 依赖图。
pub struct DepGraph {
    /// 图节点（每个 SRPM 一项）。
    pub nodes: Vec<SrpmInfo>,
    /// 邻接表：包名 → 其依赖的包名列表。
    pub edges: HashMap<String, Vec<String>>,
}

/// 解析 batch 内依赖图：入口一次构建 capability → providers 索引，逐 SRPM
/// 内存反查（纯内存查询无并发收益）；`cancel_token` 透传索引 repoquery
/// 子进程，chain 取消按进程组终止。
pub async fn build_dep_graph(
    srpms: &[SrpmInfo],
    repos: &[RepoConfig],
    local_repo: Option<&Path>,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<DepGraph> {
    // 同名 SRPM 显式拒绝：edges 按 name 收集、batch_names 是 HashSet，同名后项
    // 静默覆盖前项、拓扑错乱；chain 语义要求批内包名唯一，先于任何 dnf 调用快速失败。
    let mut seen: HashMap<&str, &Path> = HashMap::new();
    for s in srpms {
        if let Some(prev) = seen.get(s.name.as_str()) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "duplicate package name '{}' in batch: {} and {} (chain requires unique names)",
                    s.name,
                    prev.display(),
                    s.path.display()
                ),
            });
        }
        seen.insert(s.name.as_str(), &s.path);
    }

    let batch_names: HashSet<String> = srpms.iter().map(|info| info.name.clone()).collect();

    // 一次构建 capability → providers 索引（per-SRPM 重调 = N 次 dnf repoquery）。
    // 索引仓库集 = 产品仓库 + local repo（构建环境仓库集），不用宿主 dnf 配置。
    let capability_index = build_capability_index(repos, local_repo, cancel_token).await?;

    let mut nodes = Vec::new();
    let mut edges: HashMap<String, Vec<String>> = HashMap::new();
    for info in srpms {
        // BR 由调用方（prepare_chain_context）传入，此处只做内存 capability 反查（无 dnf 调用）。
        let br = &info.build_requires;
        let resolved = resolve_deps_to_pkgs(br, &batch_names, &capability_index);
        let mut deps = Vec::new();
        for dep in br {
            if let Some(pkg) = resolved.get(dep).cloned().flatten() {
                if pkg != info.name {
                    deps.push(pkg);
                }
            }
        }
        deps.sort();
        deps.dedup();

        info!(
            name = %info.name,
            deps = ?deps,
            "resolved dependencies"
        );
        edges.insert(info.name.clone(), deps);
        nodes.push(info.clone());
    }

    Ok(DepGraph { nodes, edges })
}

/// 拓扑排序为可并行的构建轮次；排不出的包（成环等）并入第 0 轮，名字进返回值第二元素。
pub fn topo_sort(graph: &DepGraph) -> (Vec<Vec<SrpmInfo>>, Vec<String>) {
    let node_map: HashMap<String, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.name.clone(), i))
        .collect();

    let n = graph.nodes.len();
    let mut in_degree = vec![0usize; n];
    let mut reverse_edges: HashMap<usize, Vec<usize>> = HashMap::new();

    // 确定性遍历：按 node 索引（= 输入顺序）扫边、依赖下标排序后入 reverse_edges。
    // graph.edges 是 HashMap，直接迭代会同输入产出不同轮次划分（--order-only 计划需跨 run 字节稳定）。
    for (idx, node) in graph.nodes.iter().enumerate() {
        let Some(deps) = graph.edges.get(&node.name) else {
            continue;
        };
        // 只把存在于 batch 节点图中的依赖计入入度；外部依赖（仓库提供）不影响拓扑排序。
        let mut dep_idxs: Vec<usize> = deps
            .iter()
            .filter(|d| node_map.contains_key(d.as_str()))
            .map(|d| node_map[d.as_str()])
            .collect();
        dep_idxs.sort_unstable();
        dep_idxs.dedup();
        in_degree[idx] = dep_idxs.len();
        for dep_idx in dep_idxs {
            reverse_edges.entry(dep_idx).or_default().push(idx);
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }

    let mut sorted_count = 0usize;
    let mut rounds = Vec::new();

    while !queue.is_empty() {
        let round_size = queue.len();
        let mut round = Vec::with_capacity(round_size);

        for _ in 0..round_size {
            let Some(idx) = queue.pop_front() else {
                break;
            };
            round.push(graph.nodes[idx].clone());
            sorted_count += 1;

            if let Some(neighbors) = reverse_edges.get(&idx) {
                for &neighbor in neighbors {
                    in_degree[neighbor] -= 1;
                    if in_degree[neighbor] == 0 {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        rounds.push(round);
    }

    // sorted_count < n 两类成因：真环（BuildRequires 互引），或解析残留（provider
    // 缺失 → in_degree 误 0 / 悬空边）。in_degree > 0 节点并入 round 0，交
    // base_os + upstream repo 实际安装时尝试；失败包进 failed_set 走恢复轮或不动点停止。
    let unordered: Vec<String> = if sorted_count < n {
        let unordered_nodes: Vec<SrpmInfo> = graph
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| in_degree[*i] > 0)
            .map(|(_, n)| n.clone())
            .collect();
        let unordered_names: Vec<String> = unordered_nodes.iter().map(|n| n.name.clone()).collect();

        if let Some(first) = rounds.first_mut() {
            first.extend(unordered_nodes);
        } else {
            rounds.insert(0, unordered_nodes);
        }
        tracing::info!(
            nodes = ?unordered_names,
            "topo_sort could not order all nodes; they will be attempted in round 0 \
             (base_os + upstream repo may satisfy dependencies)"
        );
        unordered_names
    } else {
        Vec::new()
    };

    (rounds, unordered)
}

/// 从 SRPM 文件名提取裸包名（去版本 / 发行号）；不回退 "unknown" 占位名——
/// 占位名会让多个畸形 SRPM 共享图节点/失败登记键，chain 增量与恢复轮误匹配。
/// 形状同 [`crate::engine::build::srpm_pkg_name`]，不匹配返 `None` 交调用方校验。
pub fn extract_srpm_name(srpm: &Path) -> Option<String> {
    let filename = srpm.file_name()?.to_str()?;
    let stem = filename.strip_suffix(".src.rpm")?;
    if stem.is_empty() || !stem.contains('-') {
        return None;
    }
    Some(extract_rpm_name(stem).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topo_sort_linear() {
        let graph = DepGraph {
            nodes: vec![
                SrpmInfo {
                    name: "a".into(),
                    path: PathBuf::from("a.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec![],
                },
                SrpmInfo {
                    name: "b".into(),
                    path: PathBuf::from("b.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["a".into()],
                },
                SrpmInfo {
                    name: "c".into(),
                    path: PathBuf::from("c.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["b".into()],
                },
            ],
            edges: HashMap::from([
                ("a".into(), vec![]),
                ("b".into(), vec!["a".into()]),
                ("c".into(), vec!["b".into()]),
            ]),
        };

        let (rounds, cycles) = topo_sort(&graph);
        assert!(cycles.is_empty());
        assert_eq!(rounds.len(), 3);
        assert_eq!(rounds[0].len(), 1);
        assert_eq!(rounds[0][0].name, "a");
        assert_eq!(rounds[1][0].name, "b");
        assert_eq!(rounds[2][0].name, "c");
    }

    #[test]
    fn test_topo_sort_parallel() {
        let graph = DepGraph {
            nodes: vec![
                SrpmInfo {
                    name: "a".into(),
                    path: PathBuf::from("a.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec![],
                },
                SrpmInfo {
                    name: "b".into(),
                    path: PathBuf::from("b.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec![],
                },
                SrpmInfo {
                    name: "c".into(),
                    path: PathBuf::from("c.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["a".into(), "b".into()],
                },
            ],
            edges: HashMap::from([
                ("a".into(), vec![]),
                ("b".into(), vec![]),
                ("c".into(), vec!["a".into(), "b".into()]),
            ]),
        };

        let (rounds, cycles) = topo_sort(&graph);
        assert!(cycles.is_empty());
        assert_eq!(rounds.len(), 2);
        assert_eq!(rounds[0].len(), 2);
        assert_eq!(rounds[1].len(), 1);
        assert_eq!(rounds[1][0].name, "c");
    }

    /// 轮内顺序确定性：edges 是 HashMap、迭代序不定，round 1 必须稳定为输入顺序。
    #[test]
    fn test_topo_sort_round_order_deterministic() {
        let graph = DepGraph {
            nodes: vec![
                SrpmInfo {
                    name: "a".into(),
                    path: PathBuf::from("a.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec![],
                },
                SrpmInfo {
                    name: "x".into(),
                    path: PathBuf::from("x.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["a".into()],
                },
                SrpmInfo {
                    name: "y".into(),
                    path: PathBuf::from("y.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["a".into()],
                },
            ],
            edges: HashMap::from([
                ("a".into(), vec![]),
                ("x".into(), vec!["a".into()]),
                ("y".into(), vec!["a".into()]),
            ]),
        };

        let (rounds, cycles) = topo_sort(&graph);
        assert!(cycles.is_empty());
        assert_eq!(rounds.len(), 2);
        let round1: Vec<&str> = rounds[1].iter().map(|s| s.name.as_str()).collect();
        assert_eq!(round1, vec!["x", "y"]);
    }

    #[test]
    fn test_topo_sort_cycle() {
        let graph = DepGraph {
            nodes: vec![
                SrpmInfo {
                    name: "a".into(),
                    path: PathBuf::from("a.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["b".into()],
                },
                SrpmInfo {
                    name: "b".into(),
                    path: PathBuf::from("b.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["a".into()],
                },
            ],
            edges: HashMap::from([
                ("a".into(), vec!["b".into()]),
                ("b".into(), vec!["a".into()]),
            ]),
        };

        let (rounds, unordered) = topo_sort(&graph);
        assert_eq!(rounds.len(), 1);
        let round0_names: HashSet<&str> = rounds[0].iter().map(|s| s.name.as_str()).collect();
        assert_eq!(round0_names.len(), 2);
        assert!(round0_names.contains("a"));
        assert!(round0_names.contains("b"));
        assert_eq!(unordered.len(), 2);
        let unordered_set: HashSet<&str> = unordered.iter().map(|s| s.as_str()).collect();
        assert!(unordered_set.contains("a"));
        assert!(unordered_set.contains("b"));
    }

    #[test]
    fn test_topo_sort_cycle_mixed_with_dag() {
        // 环 (c, d) 与依赖环内 c 的 DAG 节点 e 混合：in_degree > 0 全并入 round 0。
        let graph = DepGraph {
            nodes: vec![
                SrpmInfo {
                    name: "c".into(),
                    path: PathBuf::from("c.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["d".into()],
                },
                SrpmInfo {
                    name: "d".into(),
                    path: PathBuf::from("d.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["c".into()],
                },
                SrpmInfo {
                    name: "e".into(),
                    path: PathBuf::from("e.src.rpm"),
                    arch: "x86_64".into(),
                    build_requires: vec!["c".into()],
                },
            ],
            edges: HashMap::from([
                ("c".into(), vec!["d".into()]),
                ("d".into(), vec!["c".into()]),
                ("e".into(), vec!["c".into()]),
            ]),
        };

        let (rounds, unordered) = topo_sort(&graph);
        assert_eq!(rounds.len(), 1);
        let round0: HashSet<&str> = rounds[0].iter().map(|s| s.name.as_str()).collect();
        assert_eq!(round0.len(), 3);
        assert!(round0.contains("c"));
        assert!(round0.contains("d"));
        assert!(round0.contains("e"));
        // unordered 口径 = 所有 in_degree > 0 节点（e 依赖环内 c 也算入），非仅真环。
        let unordered_set: HashSet<&str> = unordered.iter().map(|s| s.as_str()).collect();
        assert_eq!(unordered_set.len(), 3);
        assert!(unordered_set.contains("c"));
        assert!(unordered_set.contains("d"));
        assert!(unordered_set.contains("e"));
    }

    // 同名 SRPM 必须入口显式拒绝：同名后项静默覆盖前项（edges 按 name 收集），拓扑错乱。
    #[tokio::test]
    async fn build_dep_graph_rejects_duplicate_package_names() {
        let srpms = vec![
            SrpmInfo {
                name: "hello".into(),
                path: PathBuf::from("hello-1.0-1.src.rpm"),
                build_requires: vec![],
                arch: "x86_64".into(),
            },
            SrpmInfo {
                name: "hello".into(),
                path: PathBuf::from("hello-2.0-1.src.rpm"),
                build_requires: vec![],
                arch: "x86_64".into(),
            },
        ];

        // DepGraph 未实现 Debug（unwrap_err 需要），用 match 断言 Err 分支。
        let err = match build_dep_graph(&srpms, &[], None, None).await {
            Ok(_) => panic!("duplicate package names should be rejected, got Ok"),
            Err(e) => e,
        };

        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "expected ValidationFailed, got: {:?}",
            err
        );
        let msg = err.to_string();
        assert!(
            msg.contains("hello"),
            "message should name the package: {}",
            msg
        );
        assert!(
            msg.contains("hello-1.0-1.src.rpm") && msg.contains("hello-2.0-1.src.rpm"),
            "message should cite both conflicting paths: {}",
            msg
        );
    }

    #[test]
    fn test_extract_srpm_name() {
        assert_eq!(
            extract_srpm_name(Path::new("kernel-6.12.0-1.el9.src.rpm")).as_deref(),
            Some("kernel")
        );
        assert_eq!(
            extract_srpm_name(Path::new("/tmp/gcc-toolset-14-14.0-1.el9.src.rpm")).as_deref(),
            Some("gcc-toolset-14")
        );
    }

    #[test]
    fn test_extract_srpm_name_rejects_malformed() {
        assert_eq!(
            extract_srpm_name(Path::new("kernel-6.12.0-1.el9.rpm")),
            None
        );
        assert_eq!(extract_srpm_name(Path::new("no-suffix")), None);
        assert_eq!(extract_srpm_name(Path::new("kernel.src.rpm")), None);
        assert_eq!(extract_srpm_name(Path::new(".src.rpm")), None);
        assert_eq!(extract_srpm_name(Path::new("/")), None);
        {
            use std::os::unix::ffi::OsStrExt;
            assert_eq!(
                extract_srpm_name(Path::new(std::ffi::OsStr::from_bytes(b"\xff\xfe.src.rpm"))),
                None
            );
        }
    }
}
