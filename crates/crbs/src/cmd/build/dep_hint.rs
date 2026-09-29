// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crbs_core::engine::depsolve::{extract_srpm_name, parse_build_requires_from_srpm};
use tracing::{debug, warn};

/// 检测批次内跨 SRPM BuildRequires，有则 warn 建议 -C/--chain。不返回错误：rpm -qp 失败或 SRPM 无法解析时降级 debug 日志，不阻断构建。
/// 字面匹配仅识别裸包名；虚拟 provides、文件依赖、.so soname 一律跳过。
pub(crate) async fn warn_if_inter_srpm_deps(inputs: &[PathBuf]) {
    if inputs.len() < 2 {
        return;
    }

    let names: Vec<(String, &Path)> = inputs
        .iter()
        .filter_map(|p| extract_srpm_name(p).map(|n| (n, p.as_path())))
        .collect();
    let batch_names: HashSet<&str> = names.iter().map(|(n, _)| n.as_str()).collect();

    for (name, path) in &names {
        let deps = match parse_build_requires_from_srpm(path).await {
            Ok(d) => d,
            Err(e) => {
                debug!(
                    srpm = %path.display(),
                    err = ?e,
                    "dep hint: parse BuildRequires failed; skipping",
                );
                continue;
            }
        };

        for dep in &deps {
            if let Some(dep_name) = match_batch_dep(dep, &batch_names) {
                if dep_name == name.as_str() {
                    continue;
                }
                warn!(
                    from = %name,
                    to = %dep_name,
                    "detected inter-SRPM BuildRequires: parallel batch may fail. \
                     Use -C/--chain for dependency-ordered build, \
                     or --assume-independent to silence this hint."
                );
            }
        }
    }
}

fn match_batch_dep(dep: &str, batch_names: &HashSet<&str>) -> Option<String> {
    if dep.starts_with("rpmlib(")
        || dep.starts_with('/')
        || dep.contains('(')
        || dep.contains(".so")
    {
        return None;
    }
    let name = dep.split_whitespace().next().unwrap_or(dep);
    if batch_names.contains(name) {
        Some(name.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch<'a>(names: &'a [&'a str]) -> HashSet<&'a str> {
        names.iter().copied().collect()
    }

    #[test]
    fn match_batch_dep_matches_bare_name() {
        let b = batch(&["foo", "bar"]);
        assert_eq!(match_batch_dep("foo", &b), Some("foo".into()));
        assert_eq!(match_batch_dep("bar >= 1.2", &b), Some("bar".to_string()));
    }

    #[test]
    fn match_batch_dep_skips_virtual_provides() {
        let b = batch(&["foo"]);
        assert_eq!(match_batch_dep("pkgconfig(foo)", &b), None);
        assert_eq!(match_batch_dep("python3dist(foo)", &b), None);
        assert_eq!(match_batch_dep("/usr/bin/foo", &b), None);
        assert_eq!(match_batch_dep("libfoo.so.1", &b), None);
        assert_eq!(match_batch_dep("rpmlib(FileDigests)", &b), None);
    }

    #[test]
    fn match_batch_dep_no_match_outside_batch() {
        let b = batch(&["foo"]);
        assert_eq!(match_batch_dep("baz", &b), None);
    }

    #[tokio::test]
    async fn warn_if_inter_srpm_deps_noop_for_single_srpm() {
        warn_if_inter_srpm_deps(&[PathBuf::from("/nonexistent/only.src.rpm")]).await;
    }
}
