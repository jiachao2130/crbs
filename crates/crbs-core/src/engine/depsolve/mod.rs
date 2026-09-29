// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 依赖解析：从 SRPM 提取 BuildRequires、构建包间依赖图，并拓扑排序为可并行的构建轮次。

mod capability;
mod graph;
mod incremental;
mod probe;

pub use capability::repoquery_release_args;

pub use graph::{build_dep_graph, extract_srpm_name, topo_sort, DepGraph, SrpmInfo};

pub use incremental::is_built_in_results;

pub use probe::{
    parse_arch_and_constraints_from_srpm, parse_arch_and_constraints_from_srpms,
    parse_arch_from_srpm, parse_arch_from_srpms, parse_br_and_arch_from_srpms,
    parse_build_requires_from_srpm, parse_nevr_from_srpms, probe_srpm_replay_params,
    ArchConstraints, SrpmBrArch,
};
