// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! capability 索引：repoquery 参数构造、全量 provides 索引构建/解析、
//! 依赖名到批内包名的内存反查。

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::{LogSanitizationConfig, RepoConfig};
use crate::engine::build::url::repo_query_args;
use crate::error::CrbsError;

/// capability 索引 `dnf repoquery` 兜底超时：全量 provides 导出可达分钟级，
/// 停滞存储/黑洞镜像上挂死的 dnf 不得无限占用构建 future。
pub(super) const CAPABILITY_INDEX_REPOQUERY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(600);

/// 依赖条目的首个 token（capability 名；无空白时即整串）。
fn dep_name(dep: &str) -> &str {
    dep.split_whitespace().next().unwrap_or(dep)
}

/// 判断一个依赖是否值得交给 capability 索引查询。
///
/// `rpmlib()`、文件路径（`/...`）、so 依赖不在 `%{provides}` 索引里，查询
/// 无意义走 fallback；`pkgconfig()`/`python3dist()` 等虚拟 provide 在索引
/// 有对应键，必须放行，否则批内虚拟 provide 依赖边静默丢失。
fn needs_repoquery(dep: &str) -> bool {
    let name = dep_name(dep);
    !(name.starts_with("rpmlib(") || name.starts_with('/') || name.contains(".so"))
}

/// 构造 `dnf repoquery` 的仓库限定参数序列（纯函数，便于单测）。
///
/// 每个启用的产品仓库用 `--repofrompath crbs-<name>,<baseurl>` 显式限定（避免与
/// 宿主 `/etc/yum.repos.d` 的 repo id 冲突），local repo 以 `file://` 加入，随后
/// `--repo` 逐个限定；查询仓库集必须与构建环境（chroot 内产品仓库 + crbs-local）
/// 一致，宿主仓库不得串入。无仓库时退化为裸 `dnf repoquery`（宿主仓库集），
/// 调用方 warn。
///
/// [`capability_index_args`] 借此做全量 provides 导出。`parse_capability_index` 的
/// 解析契约（dnf 4.16.2 实测）：包以 `[` `]` 包裹，首行 `name\t<first_provide>`，
/// 后续 provide 行继承包名，首个 token 是 capability name：
/// ```text
/// [gcc\tgcc = 12.3.1-67.mydist
/// gcc(aarch-64) = 12.3.1-67.mydist]
/// ```
///
/// 等价性边界：批量导出无版本过滤，版本约束不参与批内推导；同包名低版本候选
/// 同样建边，代价仅是拓扑序错、依赖包推迟到 builddep 期失败，最终版本裁决
/// 由 chroot 内 dnf 完成。
fn repoquery_repo_scoped_args(
    repos: &[RepoConfig],
    local_repo: Option<&Path>,
    queryformat: &str,
) -> Vec<String> {
    let mut args = vec![
        "repoquery".to_string(),
        format!("--queryformat={queryformat}"),
    ];
    let mut repo_ids: Vec<String> = Vec::new();

    for repo in repos.iter().filter(|r| r.enabled) {
        let id = format!("crbs-{}", repo.name);
        args.extend(repo_query_args(
            repo,
            &id,
            &LogSanitizationConfig::default(),
        ));
        repo_ids.push(id);
    }

    if let Some(dir) = local_repo {
        let id = "crbs-local";
        args.push("--repofrompath".to_string());
        args.push(format!("{},file://{}", id, dir.display()));
        repo_ids.push(id.to_string());
    }

    for id in &repo_ids {
        args.push("--repo".to_string());
        args.push(id.clone());
    }

    args
}

/// capability 索引查询的 `dnf repoquery` 参数（`[%{name}\t%{provides}\n]` 全量导出）。
fn capability_index_args(repos: &[RepoConfig], local_repo: Option<&Path>) -> Vec<String> {
    repoquery_repo_scoped_args(repos, local_repo, "[%{name}\t%{provides}\n]")
}

/// 构造查询指定包在产品仓库集内 `%{release}` 的 `dnf repoquery` 参数
/// （纯函数，便于单测）。
///
/// 供 chain 启动时 dist 一致性预检抽样产品源 tag：不含 local repo——抽样对象
/// 是产品源 dist tag，不是 chain 自身产物。
pub fn repoquery_release_args(repos: &[RepoConfig], package: &str) -> Vec<String> {
    let mut args = repoquery_repo_scoped_args(repos, None, "%{release}");
    args.push(package.to_string());
    args
}

/// 全量导出仓库集 provides，构建 capability → providers 映射。
/// 仓库集必须与构建环境一致：产品仓库 + （`--result-repo` 时的）local repo，
/// 不依赖宿主 dnf 配置，否则宿主未配产品仓库时索引为空 → 批内依赖边静默丢失。
pub(super) async fn build_capability_index(
    repos: &[RepoConfig],
    local_repo: Option<&Path>,
    cancel_token: Option<&CancellationToken>,
) -> crate::Result<HashMap<String, Vec<String>>> {
    let args = capability_index_args(repos, local_repo);
    let mut cmd = tokio::process::Command::new("dnf");
    cmd.args(&args);
    let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn dnf repoquery for capability index",
        cancel_token,
        CAPABILITY_INDEX_REPOQUERY_TIMEOUT,
    )
    .await
    // Cancelled 原样透传，不得包装成 DepsolveFailed。
    .map_err(|e| match e {
        CrbsError::Cancelled => CrbsError::Cancelled,
        other => CrbsError::DepsolveFailed {
            message: other.to_string(),
        },
    })?;

    if !output.status.success() {
        // stderr 呈网络失败特征时归类 Network（is_transient 可重试），而非一律 DepsolveFailed。
        return Err(crate::engine::command::classify_command_failure(
            "dnf repoquery capability index",
            &output,
        ));
    }

    // capped 读取可能截断索引：截断会静默丢依赖边，必须显式失败而非只 warn。
    if crate::engine::command::output_hit_capture_cap(&output) {
        return Err(capability_index_truncation_error());
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let index = parse_capability_index(&raw);

    // 空索引会让批内依赖边全部静默丢失：按仓库来源给出可诊断的 warn。
    if !(repos.iter().any(|r| r.enabled) || local_repo.is_some()) {
        warn!(
            "building capability index from host dnf repos (no product repos configured); \
             batch dependency edges may be missing"
        );
    } else if index.is_empty() {
        warn!(
            "capability index is empty: product repos may be unreachable, disabled, \
             or provide no packages; batch dependency edges will be missing"
        );
    }

    Ok(index)
}

/// capability 索引输出达到 capped 读取上限时的错误（供 [`build_capability_index`]
/// 与单测共用）：截断索引会静默丢边，必须显式失败而非只留 warn。
fn capability_index_truncation_error() -> CrbsError {
    CrbsError::DepsolveFailed {
        message: format!(
            "dnf repoquery capability index output hit the {}-byte capture cap and may be \
             truncated; dependency edges would be silently missing — reduce the number of \
             enabled repos or split the chain batch",
            crate::engine::command::MAX_CAPTURE_BYTES
        ),
    }
}

/// 解析 dnf 全量 repoquery 的 stdout 为 `capability_name → providers` 映射；
/// 格式契约见 `repoquery_repo_scoped_args` 文档。
///
/// 兼容两种包头格式：`[name\t<provide>`（`[` 与 name 同行），以及 `[` 单独
/// 成行、包头在下一行的变体（不同 dnf 版本两种形态都可能出现）。
fn parse_capability_index(raw: &str) -> HashMap<String, Vec<String>> {
    let mut index: HashMap<String, Vec<String>> = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut expect_header = false;

    for line in raw.lines() {
        let line = line.trim();
        if line == "]" {
            current_name = None;
            expect_header = false;
            continue;
        }
        // 包头两形态：`[name\t...` 同行，或 `[` 单独成行后的下一行，共用 `name\t<first_provide>` 解析。
        let header: Option<&str> = if let Some(content) = line.strip_prefix('[') {
            if content.is_empty() {
                expect_header = true;
                continue;
            }
            Some(content)
        } else if expect_header {
            Some(line)
        } else {
            None
        };
        expect_header = false;
        if let Some(content) = header {
            if let Some(pos) = content.find('\t') {
                let name = &content[..pos];
                let prov = &content[pos + 1..];
                current_name = Some(name.to_string());
                let cap = prov.split_whitespace().next().unwrap_or(prov);
                index
                    .entry(cap.to_string())
                    .or_default()
                    .push(name.to_string());
            }
        } else if let Some(ref name) = current_name {
            // 后续 provide 行（无 name 前缀，name 从上文继承）
            let cap = line.split_whitespace().next().unwrap_or(line);
            index.entry(cap.to_string()).or_default().push(name.clone());
        }
    }

    // 每个 capability 的 providers 去重 + 排序（确定性与 pick_provider 一致）
    for providers in index.values_mut() {
        providers.sort();
        providers.dedup();
    }

    index
}

/// 批量把依赖解析为 batch 内包名（纯内存操作，不 spawn 任何子进程）：
/// 包名直接匹配（`fallback_name_match`）→ 值得查询的依赖在 `capability_index`
/// 内存反查；仍未命中的落 `None`（候选匹配优先 batch_names 命中，其次包名
/// 等于 capability 名）。
///
/// `capability_index` 由调用方入口构造一次并以引用共享；repoquery 失败在
/// 那一层已变 `Err`，不会带着空/缺索引走到这里——本函数无 IO 失败路径。
pub(super) fn resolve_deps_to_pkgs(
    deps: &[String],
    batch_names: &HashSet<String>,
    capability_index: &HashMap<String, Vec<String>>,
) -> HashMap<String, Option<String>> {
    let mut result: HashMap<String, Option<String>> = HashMap::new();
    for dep in deps {
        let resolved = fallback_name_match(dep, batch_names).or_else(|| {
            if needs_repoquery(dep) {
                resolve_with_index_single(dep, batch_names, capability_index)
            } else {
                None
            }
        });
        result.insert(dep.clone(), resolved);
    }
    result
}

/// 从 `capability → providers` 索引查单条 dep 的 provider；版本约束在
/// capability name 处被丢弃（与 `pick_provider` 一致）。
fn resolve_with_index_single(
    dep: &str,
    batch_names: &HashSet<String>,
    index: &HashMap<String, Vec<String>>,
) -> Option<String> {
    let cap_name = dep_name(dep);
    index
        .get(cap_name)
        .and_then(|providers| pick_provider(providers, dep, batch_names))
}

/// 从预排序的候选包名列表为单条依赖选 provider：优先 `batch_names` 命中
/// （batch 内包优先建边），其次包名等于依赖 capability 名，否则 `None`。
/// 候选已由调用方排序去重（`build_capability_index` 内统一处理）。
///
/// 不做版本比较：只解析 capability name，版本约束被丢弃（与
/// `fallback_name_match` 一致）；后果见 `repoquery_repo_scoped_args` 等价性边界。
fn pick_provider(
    candidates: &[String],
    dep: &str,
    batch_names: &HashSet<String>,
) -> Option<String> {
    let name_part = dep_name(dep);
    candidates
        .iter()
        .find(|name| batch_names.contains(name.as_str()))
        .or_else(|| candidates.iter().find(|name| name.as_str() == name_part))
        .cloned()
}

fn fallback_name_match(dep: &str, batch_names: &HashSet<String>) -> Option<String> {
    if dep.starts_with("rpmlib(")
        || dep.starts_with('/')
        || dep.contains('(')
        || dep.contains(".so")
    {
        return None;
    }

    let name = dep_name(dep);
    if batch_names.contains(name) {
        Some(name.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_name_match() {
        let batch: HashSet<String> = ["pkg-a".into(), "gcc".into()].into_iter().collect();

        assert_eq!(fallback_name_match("gcc", &batch), Some("gcc".into()));
        assert_eq!(
            fallback_name_match("gcc >= 1.0", &batch),
            Some("gcc".into())
        );
        assert_eq!(fallback_name_match("pkg-a", &batch), Some("pkg-a".into()));
        assert_eq!(fallback_name_match("pkg-b", &batch), None);
        assert_eq!(
            fallback_name_match("rpmlib(CompressedFileNames)", &batch),
            None
        );
        assert_eq!(fallback_name_match("/usr/bin/python3", &batch), None);
        assert_eq!(fallback_name_match("perl(Getopt::Long)", &batch), None);
        assert_eq!(fallback_name_match("libfoo.so.1()", &batch), None);
    }

    #[test]
    fn needs_repoquery_allows_virtual_provides() {
        // 虚拟 provide 必须放行进索引查询，否则批内边静默丢失。
        assert!(needs_repoquery("pkgconfig(lcms2)"));
        assert!(needs_repoquery("pkgconfig(lcms2) >= 2.16"));
        assert!(needs_repoquery("python3dist(setuptools)"));
        assert!(needs_repoquery("cmake(foo)"));
        assert!(needs_repoquery("perl(Getopt::Long)"));
        assert!(needs_repoquery("bundled(libbacktrace)"));
        assert!(needs_repoquery("rubygem(rake)"));
        assert!(needs_repoquery("gcc"));
        assert!(needs_repoquery("gcc >= 7.0"));
        assert!(!needs_repoquery("rpmlib(CompressedFileNames)"));
        assert!(!needs_repoquery("rpmlib(PayloadIsZstd) <= 5.4.18-1"));
        assert!(!needs_repoquery("/usr/bin/python3"));
        assert!(!needs_repoquery("libz.so.1()(64bit)"));
    }

    // ── capability_index_args（索引仓库集 == 构建仓库集）────────────────
    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn capability_index_args_no_repos_is_bare_dnf() {
        // 无产品仓库、无 local repo：回退宿主 dnf 仓库集（由 build_capability_index warn）。
        let args = capability_index_args(&[], None);
        assert_eq!(
            args,
            vec![
                "repoquery".to_string(),
                "--queryformat=[%{name}\t%{provides}\n]".to_string(),
            ]
        );
    }

    #[test]
    fn capability_index_args_restricts_to_enabled_product_repos() {
        let enabled = RepoConfig {
            name: "product".into(),
            baseurl: "https://hub.example.com/repo/product".into(),
            gpgcheck: true,
            gpgkey: Some("https://hub.example.com/key.asc".into()),
            exclude: vec!["foo*".into()],
            ..Default::default()
        };
        let disabled = RepoConfig {
            name: "off".into(),
            baseurl: "https://hub.example.com/repo/off".into(),
            enabled: false,
            ..Default::default()
        };

        let args = capability_index_args(&[enabled, disabled], None);

        assert!(has_pair(
            &args,
            "--repofrompath",
            "crbs-product,https://hub.example.com/repo/product"
        ));
        assert!(has_pair(&args, "--setopt", "crbs-product.gpgcheck=1"));
        assert!(has_pair(
            &args,
            "--setopt",
            "crbs-product.gpgkey=https://hub.example.com/key.asc"
        ));
        assert!(has_pair(&args, "--setopt", "crbs-product.exclude=foo*"));
        assert!(args.iter().any(|a| a.starts_with("crbs-product.priority=")));
        assert!(has_pair(&args, "--repo", "crbs-product"));
        assert!(!args.iter().any(|a| a.contains("crbs-off")));
    }

    #[test]
    fn capability_index_args_no_gpgkey_disables_gpgcheck() {
        let repo = RepoConfig {
            name: "plain".into(),
            baseurl: "http://mirror.example.com/repo".into(),
            gpgcheck: true,
            gpgkey: None,
            ..Default::default()
        };
        let args = capability_index_args(&[repo], None);
        assert!(has_pair(&args, "--setopt", "crbs-plain.gpgcheck=0"));
        assert!(!args.iter().any(|a| a.contains("gpgkey")));
    }

    #[test]
    fn capability_index_args_full_setopts() {
        let repo = RepoConfig {
            name: "full".into(),
            baseurl: "https://x/repo".into(),
            module_hotfixes: true,
            includepkgs: vec!["a".into(), "b".into()],
            extra: Some("sslverify=0\n# comment\nproxy=http://p:8080\n".into()),
            ..Default::default()
        };
        let args = capability_index_args(&[repo], None);
        assert!(has_pair(&args, "--setopt", "crbs-full.module_hotfixes=1"));
        assert!(has_pair(&args, "--setopt", "crbs-full.includepkgs=a,b"));
        assert!(has_pair(&args, "--setopt", "crbs-full.sslverify=0"));
        assert!(has_pair(&args, "--setopt", "crbs-full.proxy=http://p:8080"));
    }

    #[test]
    fn capability_index_args_local_repo_as_file_url() {
        let args = capability_index_args(&[], Some(Path::new("/data/repo/product")));
        assert!(has_pair(
            &args,
            "--repofrompath",
            "crbs-local,file:///data/repo/product"
        ));
        assert!(has_pair(&args, "--repo", "crbs-local"));
    }

    #[test]
    fn capability_index_args_repo_flags_come_after_repofrompath() {
        // --repo 须在全部 --repofrompath 之后（dnf 参数顺序无关，锁定生成确定性）。
        let repos = vec![
            RepoConfig {
                name: "a".into(),
                baseurl: "http://a".into(),
                ..Default::default()
            },
            RepoConfig {
                name: "b".into(),
                baseurl: "http://b".into(),
                ..Default::default()
            },
        ];
        let args = capability_index_args(&repos, Some(Path::new("/r")));
        let last_repofrom = args.iter().rposition(|a| a == "--repofrompath").unwrap();
        let first_repo = args.iter().position(|a| a == "--repo").unwrap();
        assert!(first_repo > last_repofrom);
        assert_eq!(args.iter().filter(|a| *a == "--repo").count(), 3);
    }

    #[test]
    fn pick_provider_prefers_batch_candidate() {
        let batch: HashSet<String> = ["foo".into()].into_iter().collect();
        let candidates = vec!["ext-libfoo".to_string(), "foo".to_string()];
        assert_eq!(
            pick_provider(&candidates, "libfoo", &batch),
            Some("foo".into())
        );
    }

    #[test]
    fn pick_provider_falls_back_to_dep_name_match() {
        let batch: HashSet<String> = HashSet::new();
        let candidates = vec!["gcc".to_string()];
        assert_eq!(
            pick_provider(&candidates, "gcc >= 1.0", &batch),
            Some("gcc".into())
        );
    }

    #[test]
    fn pick_provider_deterministic_across_orderings() {
        // 输入无序也应确定选中（生产路径候选已 sort+dedup，此处更严）。
        let batch: HashSet<String> = HashSet::new();
        let a = vec!["zlib".to_string(), "libcompress".to_string()];
        let b = vec!["libcompress".to_string(), "zlib".to_string()];
        // libcompress 不在 batch、包名 == dep 名：两个顺序下都命中名字匹配分支。
        assert_eq!(
            pick_provider(&a, "libcompress", &batch),
            Some("libcompress".into())
        );
        assert_eq!(
            pick_provider(&b, "libcompress", &batch),
            Some("libcompress".into())
        );

        let none_a = pick_provider(
            &["libz".to_string(), "zlib".to_string()],
            "libcompress",
            &batch,
        );
        let none_b = pick_provider(
            &["zlib".to_string(), "libz".to_string()],
            "libcompress",
            &batch,
        );
        assert_eq!(none_a, None);
        assert_eq!(none_a, none_b);
    }

    #[test]
    fn pick_provider_returns_none_when_no_match() {
        let batch: HashSet<String> = ["foo".into()].into_iter().collect();
        let candidates = vec!["bar".to_string(), "baz".to_string()];
        assert_eq!(pick_provider(&candidates, "libqux", &batch), None);
    }

    // === 解析器测试（build_capability_index 内 spawn dnf 不可 mock；跨 dnf 版本
    // 兼容靠实测真输出确认）===
    #[test]
    fn parse_capability_index_basic() {
        // 真实 dnf 4.16.2 格式：`[` 和 name 在同一行（`[gcc\tgcc = ...`）。
        let raw = "[gcc\tgcc = 12.3.1-67.mydist\n\
                   gcc(aarch-64) = 12.3.1-67.mydist\n\
                   bundled(libbacktrace)\n\
                   ]\n\
                   [zlib\tzlib = 1.2.12-6.mydist\n\
                   libz.so.1()(64bit)\n\
                   ]\n";
        let index = parse_capability_index(raw);
        assert_eq!(index.get("gcc").cloned().unwrap(), vec!["gcc".to_string()]);
        assert_eq!(
            index.get("gcc(aarch-64)").cloned().unwrap(),
            vec!["gcc".to_string()]
        );
        assert_eq!(
            index.get("bundled(libbacktrace)").cloned().unwrap(),
            vec!["gcc".to_string()]
        );
        assert_eq!(
            index.get("zlib").cloned().unwrap(),
            vec!["zlib".to_string()]
        );
        assert_eq!(
            index.get("libz.so.1()(64bit)").cloned().unwrap(),
            vec!["zlib".to_string()]
        );
    }

    #[test]
    fn parse_capability_index_standalone_open_bracket_header() {
        // 变体格式：`[` 单独成行，包头在下一行（不同 dnf 版本可能输出）。
        let raw = "[\ngcc\tgcc = 12.3.1-67.mydist\n\
                   gcc(aarch-64) = 12.3.1-67.mydist\n\
                   bundled(libbacktrace)\n\
                   ]\n\
                   [\nzlib\tzlib = 1.2.12-6.mydist\n\
                   libz.so.1()(64bit)\n\
                   ]\n";
        let index = parse_capability_index(raw);
        assert_eq!(index.get("gcc").cloned().unwrap(), vec!["gcc".to_string()]);
        assert_eq!(
            index.get("gcc(aarch-64)").cloned().unwrap(),
            vec!["gcc".to_string()]
        );
        assert_eq!(
            index.get("bundled(libbacktrace)").cloned().unwrap(),
            vec!["gcc".to_string()]
        );
        assert_eq!(
            index.get("zlib").cloned().unwrap(),
            vec!["zlib".to_string()]
        );
        assert_eq!(
            index.get("libz.so.1()(64bit)").cloned().unwrap(),
            vec!["zlib".to_string()]
        );
    }

    #[test]
    fn parse_capability_index_mixed_header_shapes() {
        let raw = "[foo\tlibfoo\n]\n[\nbar\tlibbar\nextra-bar\n]\n";
        let index = parse_capability_index(raw);
        assert_eq!(
            index.get("libfoo").cloned().unwrap(),
            vec!["foo".to_string()]
        );
        assert_eq!(
            index.get("libbar").cloned().unwrap(),
            vec!["bar".to_string()]
        );
        assert_eq!(
            index.get("extra-bar").cloned().unwrap(),
            vec!["bar".to_string()]
        );
    }

    #[test]
    fn parse_capability_index_single_provide_no_version() {
        // 仅一个 provide，且没有 `= version`：首行 = name\tsame_name
        let raw = "[hello\thello\n]\n";
        let index = parse_capability_index(raw);
        assert_eq!(
            index.get("hello").cloned().unwrap(),
            vec!["hello".to_string()]
        );
    }

    #[test]
    fn parse_capability_index_dedup_and_sort() {
        let raw = "[foo\tlibfoo\n]\n[bar\tlibfoo\n]\n";
        let index = parse_capability_index(raw);
        let providers = index.get("libfoo").unwrap();
        assert_eq!(providers, &vec!["bar".to_string(), "foo".to_string()]);
    }

    #[test]
    fn parse_capability_index_same_pkg_two_capabilities() {
        // 一个包提供两个 capability，每个 capability 都要索引到这个包
        let raw = "[foo\tlibfoo\nlibfoo-extra\n]\n";
        let index = parse_capability_index(raw);
        assert_eq!(
            index.get("libfoo").cloned().unwrap(),
            vec!["foo".to_string()]
        );
        assert_eq!(
            index.get("libfoo-extra").cloned().unwrap(),
            vec!["foo".to_string()]
        );
    }

    #[test]
    fn parse_capability_index_empty_input() {
        let index = parse_capability_index("");
        assert!(index.is_empty());
    }

    /// 截断 → 显式 DepsolveFailed：错误须点名 capture cap 并给出收窄仓库集指引。
    #[test]
    fn capability_index_truncation_error_names_cap_and_remediation() {
        let err = capability_index_truncation_error();
        assert!(matches!(err, CrbsError::DepsolveFailed { .. }));
        let msg = err.to_string();
        assert!(
            msg.contains(&crate::engine::command::MAX_CAPTURE_BYTES.to_string()),
            "message should name the cap constant: {}",
            msg
        );
        assert!(
            msg.contains("repos"),
            "message should suggest reducing enabled repos: {}",
            msg
        );
    }

    #[test]
    fn parse_capability_index_malformed_line_skipped() {
        // `[` 行后 content 无 tab → 跳过（不 panic）
        let raw = "[random-no-tab\n]\n";
        let index = parse_capability_index(raw);
        assert!(
            index.is_empty(),
            "malformed first line should be skipped, got: {:?}",
            index
        );
    }

    // === resolve_deps_to_pkgs 内存反查测试（注入构造 index 不 spawn dnf；集成由端到端覆盖）===
    #[test]
    fn resolve_with_index_picks_batch_candidate() {
        let index: HashMap<String, Vec<String>> = HashMap::from([
            (
                "gcc".to_string(),
                vec!["ext-gcc".to_string(), "foo".to_string()],
            ),
            ("make".to_string(), vec!["make".to_string()]),
        ]);
        let batch: HashSet<String> = ["foo".into()].into_iter().collect();
        let deps = vec!["gcc".to_string(), "make".to_string()];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);
        assert_eq!(result.get("gcc").cloned().flatten(), Some("foo".into()));
        assert_eq!(result.get("make").cloned().flatten(), Some("make".into()));
    }

    #[test]
    fn resolve_with_index_no_match_returns_none() {
        let index: HashMap<String, Vec<String>> = HashMap::new();
        let batch: HashSet<String> = HashSet::new();
        let deps = vec!["ghost-pkg".to_string()];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);
        assert_eq!(result.get("ghost-pkg").cloned().flatten(), None);
    }

    #[test]
    fn resolve_with_index_version_constraint_stripped() {
        let index: HashMap<String, Vec<String>> =
            HashMap::from([("gcc".to_string(), vec!["gcc".to_string()])]);
        let batch: HashSet<String> = HashSet::new();
        let deps = vec!["gcc >= 7.0".to_string()];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);
        assert_eq!(
            result.get("gcc >= 7.0").cloned().flatten(),
            Some("gcc".into())
        );
    }

    #[test]
    fn resolve_with_index_virtual_provide_creates_batch_edge() {
        // 虚拟 provide 不被 needs_repoquery 排除，pkgconfig(foo) 优先建批内边。
        let index: HashMap<String, Vec<String>> = HashMap::from([(
            "pkgconfig(foo)".to_string(),
            vec!["old-foo-devel".to_string(), "foo-devel".to_string()],
        )]);
        let batch: HashSet<String> = ["foo-devel".into()].into_iter().collect();
        let deps = vec![
            "pkgconfig(foo) >= 1.0".to_string(),
            "pkgconfig(foo)".to_string(),
        ];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);
        assert_eq!(
            result.get("pkgconfig(foo) >= 1.0").cloned().flatten(),
            Some("foo-devel".into())
        );
        assert_eq!(
            result.get("pkgconfig(foo)").cloned().flatten(),
            Some("foo-devel".into())
        );
    }

    #[test]
    fn resolve_with_index_soname_still_skips_index() {
        // .so 仍被排除（只放行虚拟 provide）——索引碰巧有同名键也不建边。
        let index: HashMap<String, Vec<String>> =
            HashMap::from([("libz.so.1()(64bit)".to_string(), vec!["zlib".to_string()])]);
        let batch: HashSet<String> = ["zlib".into()].into_iter().collect();
        let deps = vec!["libz.so.1()(64bit)".to_string()];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);
        assert_eq!(result.get("libz.so.1()(64bit)").cloned().flatten(), None);
    }

    /// 锁住"index 由调用方注入"契约：空 index（不 spawn dnf）+ virtual capability
    /// 依赖 → 走 fallback 得 None，不 Err 不 panic。
    #[test]
    fn resolve_deps_to_pkgs_uses_provided_index_no_dnf_call() {
        let index: HashMap<String, Vec<String>> = HashMap::new();
        let batch: HashSet<String> = ["foo".into(), "bar".into()].into_iter().collect();
        let deps = vec![
            "foo".to_string(),
            "pkgconfig(lcms2)".to_string(),
            "ghost".to_string(),
        ];

        let result = resolve_deps_to_pkgs(&deps, &batch, &index);

        assert_eq!(result.get("foo").cloned().flatten(), Some("foo".into()));
        assert_eq!(result.get("pkgconfig(lcms2)").cloned().flatten(), None);
        assert_eq!(result.get("ghost").cloned().flatten(), None);
    }
}
