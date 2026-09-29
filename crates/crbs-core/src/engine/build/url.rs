// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建输入包 URL 解析与仓库 SRPM 枚举。

use crate::config::{LogSanitizationConfig, RepoConfig};
use crate::engine::cache::CacheEntry;
use crate::engine::command;
use crate::error::CrbsError;
use crate::logging::{sanitize_repo_extra_line, sanitize_url};
use crate::state::StateStore;
use std::collections::HashMap;
use tracing::{debug, warn};

/// dnf 临时缓存目录：tempfile 建目录是同步阻塞 IO，spawn_blocking 防卡
/// runtime；须建在调用方可写根下（ProtectSystem=strict 下 /tmp 只读，
/// tempdir() 会 EROFS）。
async fn dnf_temp_cache_dir(tmp_dir: &std::path::Path) -> crate::Result<tempfile::TempDir> {
    crate::engine::cache::spawn_blocking_tempdir_in(tmp_dir.to_path_buf(), "dnf temp cache dir")
        .await
}

/// 通过 `dnf repoquery --location` 批量解析 NEVRA 真实下载 URL：按 repo_id 分组
/// 建临时 repo 配置批量查询；输出 URL 文件名须与 NEVRA 匹配，故不依赖 dnf 输出
/// 顺序（dnf4/dnf5 兼容）。任一失败返回 `CrbsError`，防 `--reproduce` 基于不完整
/// URL 列表误判。
pub(crate) async fn resolve_package_urls(
    dep_index: &HashMap<String, CacheEntry>,
    repos: &[RepoConfig],
    state: &StateStore,
    log_sanitization: &LogSanitizationConfig,
    tmp_dir: &std::path::Path,
) -> crate::Result<HashMap<String, String>> {
    // 只用启用的仓库；禁用仓库按未知仓库处理。
    let repo_map: HashMap<String, &RepoConfig> = repos
        .iter()
        .filter(|r| r.enabled)
        .map(|r| (r.name.clone(), r))
        .collect();

    let mut by_repo: HashMap<String, Vec<String>> = HashMap::new();
    let mut unknown_repo: Vec<String> = Vec::new();
    for (nevra, entry) in dep_index {
        if let Some(repo) = &entry.repo_id {
            // 非产品配置 repo_id（init 生成的 base/crbs-local 等内部仓）按未知仓库跨全部启用产品仓解析，避免 internal repo 包 URL 丢失。
            if repo_map.contains_key(repo) {
                by_repo.entry(repo.clone()).or_default().push(nevra.clone());
            } else {
                unknown_repo.push(nevra.clone());
            }
        } else {
            unknown_repo.push(nevra.clone());
        }
    }

    let mut url_map: HashMap<String, String> = HashMap::new();
    let mut first_error: Option<CrbsError> = None;

    // 共用一个 dnf 临时缓存目录避免多 batch 重复拉元数据；须建在调用方可写根下（ProtectSystem=strict 下 /tmp 只读，tempdir() 会 EROFS）。
    let cache_dir = dnf_temp_cache_dir(tmp_dir).await?;
    let cache_dir_path = cache_dir.path();

    for (repo_id, nevra_list) in by_repo {
        let Some(repo) = repo_map.get(&repo_id) else {
            warn!(repo = %repo_id, "repo config not found for URL resolution");
            continue;
        };

        let baseurl = &repo.baseurl;
        let mut pending: Vec<String> = nevra_list;

        match state.get_package_urls(baseurl, &pending).await {
            Ok(cached) => {
                let hit_count = cached.len();
                if hit_count > 0 {
                    url_map.extend(cached.clone());
                    pending.retain(|n| !cached.contains_key(n));
                    debug!(
                        repo = %repo_id,
                        hits = hit_count,
                        misses = pending.len(),
                        "package url cache hit"
                    );
                }
            }
            Err(e) => {
                warn!(repo = %repo_id, error = %e, "failed to read package url cache");
            }
        }

        if pending.is_empty() {
            continue;
        }

        const BATCH_SIZE: usize = 200;
        for chunk in pending.chunks(BATCH_SIZE) {
            match query_repoquery_location(repo, chunk, cache_dir_path, log_sanitization).await {
                Ok(urls) => {
                    // 完整性校验：dnf 对无匹配 NEVRA 也退出 0（"No matches" 只进 stderr），不核对则 url_map 缺项、provenance 静默 url:None。
                    let missing: Vec<&str> = chunk
                        .iter()
                        .map(|n| n.as_str())
                        .filter(|n| !urls.contains_key(*n))
                        .collect();
                    if !missing.is_empty() {
                        let e = CrbsError::DepsolveFailed {
                            message: format!(
                                "dnf repoquery returned no URL for {} NEVRA(s) in repo {}: {}",
                                missing.len(),
                                repo_id,
                                missing.join(", ")
                            ),
                        };
                        warn!(repo = %repo_id, missing = %missing.len(), "{}", e);
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                    if let Err(e) = state.put_package_urls(baseurl, &urls).await {
                        warn!(repo = %repo_id, error = %e, "failed to cache package urls");
                    }
                    url_map.extend(urls);
                }
                Err(e) => {
                    warn!(repo = %repo_id, error = %e, "dnf repoquery --location failed");
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }
    }

    if !unknown_repo.is_empty() {
        match query_repoquery_location_all_repos(
            &unknown_repo,
            repos,
            cache_dir_path,
            log_sanitization,
        )
        .await
        {
            Ok(fetched) => {
                let mut by_repo_url: HashMap<String, HashMap<String, String>> = HashMap::new();
                for (nevra, url) in &fetched {
                    if let Some(repo) = repos
                        .iter()
                        .filter(|r| r.enabled)
                        .find(|r| url_belongs_to_baseurl(url, &r.baseurl))
                    {
                        by_repo_url
                            .entry(repo.baseurl.clone())
                            .or_default()
                            .insert(nevra.clone(), url.clone());
                    }
                }
                for (baseurl, urls) in by_repo_url {
                    if let Err(e) = state.put_package_urls(&baseurl, &urls).await {
                        // baseurl 可能内嵌 user:pass@ 凭证，落日志前脱敏（与其余 url 日志同规则）。
                        warn!(
                            baseurl = %crate::logging::redact_userinfo(&baseurl),
                            error = %e,
                            "failed to cache package urls for unknown repo"
                        );
                    }
                }
                // 完整性校验（同单仓库路径）：dnf 无匹配也退出 0，不核对则 provenance 静默 url:None，--reproduce 迟至包缓存 GC 后才失败。
                let missing: Vec<&str> = unknown_repo
                    .iter()
                    .map(|n| n.as_str())
                    .filter(|n| !fetched.contains_key(*n))
                    .collect();
                if !missing.is_empty() {
                    let e = CrbsError::DepsolveFailed {
                        message: format!(
                            "dnf repoquery (all repos) returned no URL for {} NEVRA(s): {}",
                            missing.len(),
                            missing.join(", ")
                        ),
                    };
                    warn!(missing = %missing.len(), "{}", e);
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                url_map.extend(fetched);
            }
            Err(e) => {
                warn!(error = %e, "dnf repoquery --location for all repos failed");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }

    // 任一 repoquery 失败即传播首错，避免 --reproduce 基于不完整 URL 误判。
    if let Some(e) = first_error {
        return Err(e);
    }

    Ok(url_map)
}

async fn query_repoquery_location(
    repo: &RepoConfig,
    nevra_list: &[String],
    cache_dir: &std::path::Path,
    log_sanitization: &LogSanitizationConfig,
) -> crate::Result<HashMap<String, String>> {
    // crbs- 前缀临时 id，避免撞宿主 /etc/yum.repos.d/*.repo 的 id。
    let temp_repo_id = format!("crbs-{}", repo.name);

    let mut cmd = tokio::process::Command::new("dnf");
    cmd.arg("repoquery").arg("--location");
    cmd.args(repo_query_args(repo, &temp_repo_id, log_sanitization));
    cmd.arg("--repo").arg(&temp_repo_id);

    cmd.arg("--setopt")
        .arg(format!("cachedir={}", cache_dir.display()));

    push_nevra_args(&mut cmd, nevra_list);

    let label = format!("dnf repoquery --location for repo {}", repo.name);
    run_repoquery_and_parse(cmd, &label, log_sanitization).await
}

/// NEVRA 键来自 repo 提供的 rpm 文件名，可能形如选项（`-` 开头或含空白会被
/// dnf 当选项解析，注入）：拒绝进 dnf argv，跳过告警、完整性校验随后记缺失
///（fail-closed）。
fn push_nevra_args(cmd: &mut tokio::process::Command, nevra_list: &[String]) {
    for nevra in nevra_list {
        if nevra.starts_with('-') || nevra.chars().any(char::is_whitespace) {
            warn!(nevra = %nevra, "skip option-like NEVRA, not passing to dnf argv");
            continue;
        }
        cmd.arg(nevra);
    }
}

/// repoquery 执行收尾：run → exit status → capture cap → stdout 解析；`label`
/// 为 dnf 用途描述（单仓带 repo 名 / all repos），进 spawn、失败分类与 cap 文案。
async fn run_repoquery_and_parse(
    cmd: tokio::process::Command,
    label: &str,
    log_sanitization: &LogSanitizationConfig,
) -> crate::Result<HashMap<String, String>> {
    let output = command::run_command_capped_output_with_timeout(
        cmd,
        &format!("spawn {label}"),
        std::time::Duration::from_secs(300),
    )
    .await?;

    if !output.status.success() {
        return Err(command::classify_command_failure(
            label.to_string(),
            &output,
        ));
    }

    if command::output_hit_capture_cap(&output) {
        return Err(CrbsError::DepsolveFailed {
            message: format!("{label} output exceeded capture cap"),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_repoquery_output(&stdout, log_sanitization))
}

/// 判断 URL 是否归属某 baseurl：前缀须落在路径边界（等于或后随 `/`）；裸
/// `starts_with` 会把 `http://h/repo-updates/...` 误判进 `http://h/repo` 的缓存桶。
fn url_belongs_to_baseurl(url: &str, baseurl: &str) -> bool {
    // 两侧先 trim 尾斜杠：baseurl 常带尾斜杠，不归一则 strip 余文不以 `/` 开头
    // 而永不匹配（回写静默失效）；同口径归一避免多余尾斜杠拼出 `repo//` 假边界。
    let url = url.trim_end_matches('/');
    let base = baseurl.trim_end_matches('/');
    match url.strip_prefix(base) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// 从 RPM URL 中提取 NEVRA（去掉 `.rpm` 后缀的文件名）。
fn nevra_from_rpm_url(url: &str) -> Option<String> {
    let path = url.split('?').next()?;
    let file_name = path.split('/').next_back()?;
    if !file_name.ends_with(".rpm") {
        return None;
    }
    Some(file_name[..file_name.len() - 4].to_string())
}

/// 解析 `dnf repoquery --location` 的 stdout：每行一个 URL，按文件名提取 NEVRA
/// 为 key；非 RPM 文件名的行 warn 跳过。
fn parse_repoquery_output(
    stdout: &str,
    log_sanitization: &LogSanitizationConfig,
) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for line in stdout.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
        if let Some(nevra) = nevra_from_rpm_url(line) {
            result.insert(nevra, line.to_string());
        } else {
            warn!(
                url = %sanitize_url(line, log_sanitization),
                "dnf repoquery returned URL with unexpected filename"
            );
        }
    }
    result
}

/// 通过 `dnf repoquery --location` 在全部启用的产品仓中查 NEVRA URL（base_os
/// 等无归属 repo 的包）；`--repo` 限定仓库集——不限定时宿主 `/etc/yum.repos.d`
/// 系统仓也参与解析，来源 URL 错误归因到产品仓之外。
async fn query_repoquery_location_all_repos(
    nevra_list: &[String],
    repos: &[RepoConfig],
    cache_dir: &std::path::Path,
    log_sanitization: &LogSanitizationConfig,
) -> crate::Result<HashMap<String, String>> {
    let enabled_repos: Vec<&RepoConfig> = repos.iter().filter(|r| r.enabled).collect();
    if nevra_list.is_empty() || enabled_repos.is_empty() {
        return Ok(HashMap::new());
    }

    let mut cmd = tokio::process::Command::new("dnf");
    cmd.arg("repoquery").arg("--location");

    let mut repo_ids: Vec<String> = Vec::new();
    for repo in &enabled_repos {
        let temp_repo_id = format!("crbs-{}", repo.name);
        cmd.args(repo_query_args(repo, &temp_repo_id, log_sanitization));
        repo_ids.push(temp_repo_id);
    }

    for id in &repo_ids {
        cmd.arg("--repo").arg(id);
    }

    cmd.arg("--setopt")
        .arg(format!("cachedir={}", cache_dir.display()));

    push_nevra_args(&mut cmd, nevra_list);

    run_repoquery_and_parse(
        cmd,
        "dnf repoquery --location for all repos",
        log_sanitization,
    )
    .await
}

/// 构造单仓库的 `--repofrompath <id>,<baseurl>` 及该仓库的 gpg / priority / cost /
/// module_hotfixes / exclude / includepkgs / extra `--setopt` 参数序列。`build/url.rs`
/// 与 `engine/depsolve.rs` 共用，两个查询入口对同一仓库的呈现须完全一致。
pub(crate) fn repo_query_args(
    repo: &RepoConfig,
    repo_id: &str,
    log_sanitization: &LogSanitizationConfig,
) -> Vec<String> {
    let mut args = vec![
        "--repofrompath".to_string(),
        format!("{},{}", repo_id, repo.baseurl),
    ];

    // GPG 按仓库独立：有 gpgkey 开校验否则关；用 --setopt 而非 --nogpgcheck/--no-gpgchecks，兼容 dnf4/dnf5。
    if repo.gpgcheck && repo.gpgkey.is_some() {
        let gpgkey = repo.gpgkey.as_deref().unwrap_or("");
        args.push("--setopt".to_string());
        args.push(format!("{}.gpgcheck=1", repo_id));
        args.push("--setopt".to_string());
        args.push(format!("{}.gpgkey={}", repo_id, gpgkey));
    } else {
        args.push("--setopt".to_string());
        args.push(format!("{}.gpgcheck=0", repo_id));
    }

    args.push("--setopt".to_string());
    args.push(format!("{}.priority={}", repo_id, repo.priority));
    args.push("--setopt".to_string());
    args.push(format!("{}.cost={}", repo_id, repo.cost));

    if repo.module_hotfixes {
        args.push("--setopt".to_string());
        args.push(format!("{}.module_hotfixes=1", repo_id));
    }

    if !repo.exclude.is_empty() {
        // 分隔符按消费端语法：--setopt 逗号 join、.repo 文件空格 join（engine/repo.rs）；
        // 包 glob 不含逗号/空格由 validate_repo_config 强制，两种 join 不改语义。
        args.push("--setopt".to_string());
        args.push(format!("{}.exclude={}", repo_id, repo.exclude.join(",")));
    }

    if !repo.includepkgs.is_empty() {
        args.push("--setopt".to_string());
        args.push(format!(
            "{}.includepkgs={}",
            repo_id,
            repo.includepkgs.join(",")
        ));
    }

    if let Some(extra) = &repo.extra {
        for (key, value) in parse_extra_lines(extra, log_sanitization) {
            args.push("--setopt".to_string());
            args.push(format!("{}.{key}={value}", repo_id));
        }
    }

    args
}

// ---------- 整仓重建：源仓 SRPM 枚举 ----------

/// 单个源 RPM 的枚举结果：NEVRA（取自 URL 文件名）与其下载 URL。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrcRpmEntry {
    /// 源包 NEVRA（URL 文件名去 `.rpm`，含 dist 与 `.src` 架构段）。
    pub nevra: String,
    /// 该 SRPM 的下载 URL（repofrompath 呈现下 `--location` 的原样输出）。
    pub url: String,
}

/// 源仓 SRPM 枚举的默认预算（src 包可达数千，全量枚举重于单包查询）。
pub const ENUMERATE_SRC_RPMS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// 枚举源仓内全部 SRPM（`dnf repoquery --location --arch=src`）。仓库呈现与
/// 单仓查询同契约：`--repofrompath crbs-batch-src,<url>` + `--repo` 限定（宿主
/// `/etc/yum.repos.d` 不串入）；NEVRA 经 `nevra_from_rpm_url` 从文件名解析，
/// 不依赖输出顺序（dnf4/dnf5 兼容）。输出 32MB capped，超时由调用方传
/// [`ENUMERATE_SRC_RPMS_TIMEOUT`]。解析失败行 warn 跳过计数；**有输出但全失败**
/// 才报错（空仓与仓库呈现异常须可区分，fail-closed）；结果按包名排序（确定性），
/// 同 NEVRA 保留首条。
pub async fn enumerate_repo_src_rpms(
    source_repo_url: &str,
    timeout: std::time::Duration,
    tmp_dir: &std::path::Path,
) -> crate::Result<Vec<SrcRpmEntry>> {
    if source_repo_url.trim().is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "source repo url must not be empty".to_string(),
        });
    }

    let repo = RepoConfig {
        name: "batch-src".to_string(),
        baseurl: source_repo_url.to_string(),
        ..Default::default()
    };
    let repo_id = "crbs-batch-src";

    // 每次枚举独立 cachedir：不污染宿主缓存、并发批次不互踩（整仓低频，不复用共享缓存）；建在调用方可写根下（ProtectSystem=strict 下 /tmp 只读）。
    let cache_dir = dnf_temp_cache_dir(tmp_dir).await?;

    let mut cmd = tokio::process::Command::new("dnf");
    cmd.arg("repoquery").arg("--location").arg("--arch=src");
    cmd.args(repo_query_args(
        &repo,
        repo_id,
        &LogSanitizationConfig::default(),
    ));
    cmd.arg("--repo").arg(repo_id);
    cmd.arg("--setopt")
        .arg(format!("cachedir={}", cache_dir.path().display()));

    let output = command::run_command_capped_output_with_timeout(
        cmd,
        "spawn dnf repoquery --location (batch src enumeration)",
        timeout,
    )
    .await?;

    if !output.status.success() {
        // 源仓 URL 未暴露 repodata/ 是 rebuild 最高频误用（--repo 指到发布树仓库
        // 根而非 SRPMS 等架构级子仓）；stderr 命中签名返回可自查的校验错误——
        // Network 臂在 HTTP 面恒为脱敏固定文案，明细到不了客户端，误导排障。
        // 其余失败维持既有分类。
        let stderr = String::from_utf8_lossy(&output.stderr);
        if let Some(hint) = repodata_missing_hint(&stderr) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "batch source repo enumeration failed: {} (source repo url: {})",
                    hint,
                    crate::logging::redact_userinfo(source_repo_url)
                ),
            });
        }
        return Err(command::classify_command_failure(
            "dnf repoquery --location (batch src enumeration)",
            &output,
        ));
    }
    if command::output_hit_capture_cap(&output) {
        return Err(CrbsError::DepsolveFailed {
            message: "dnf repoquery --location (batch src enumeration) output exceeded \
                      capture cap"
                .to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (entries, skipped) = parse_src_rpm_listing(&stdout);
    if entries.is_empty() && skipped > 0 {
        return Err(CrbsError::DepsolveFailed {
            message: format!(
                "dnf repoquery returned {skipped} line(s) for the source repo but none \
                 parsed as an src RPM URL; refusing to plan an empty rebuild batch"
            ),
        });
    }
    debug!(
        entries = entries.len(),
        skipped = skipped,
        "Enumerated source repo src RPMs"
    );
    Ok(entries)
}

/// 解析 `dnf repoquery --location --arch=src` 的 stdout：每行一个 URL。空行 /
/// `#` 注释行静默跳过（不计失败）；非 `.rpm` URL 或提取不出裸包名的行 warn
/// 跳过并计数（返回值第二项）；同 NEVRA 保留首条（镜像带签名 query 常成对）；
/// 结果按包名排序（确定性）。
fn parse_src_rpm_listing(stdout: &str) -> (Vec<SrcRpmEntry>, usize) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut entries: Vec<SrcRpmEntry> = Vec::new();
    let mut skipped = 0usize;
    for line in stdout.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(nevra) = nevra_from_rpm_url(line) else {
            warn!(url = %line, "src enumeration returned URL with unexpected filename; skipped");
            skipped += 1;
            continue;
        };
        // 裸包名提取失败（非 N-V-R 形状）按解析失败计数（fail-closed，不留无名条目）。
        if crate::engine::depsolve::extract_srpm_name(std::path::Path::new(&format!("{nevra}.rpm")))
            .is_none()
        {
            warn!(url = %line, "src enumeration URL has no N-V-R shape; skipped");
            skipped += 1;
            continue;
        }
        if !seen.insert(nevra.clone()) {
            debug!(nevra = %nevra, "duplicate src RPM entry; keeping first");
            continue;
        }
        entries.push(SrcRpmEntry {
            nevra,
            url: line.to_string(),
        });
    }
    entries.sort_by(|a, b| {
        let name_of = |e: &SrcRpmEntry| crate::util::rpm_name_of_nevra(&e.nevra);
        (name_of(a), &a.nevra).cmp(&(name_of(b), &b.nevra))
    });
    (entries, skipped)
}

/// 解析 `extra` 的 `key=value` 行（跳过注释和空行）；键值对 trim 后原样交
/// dnf `--setopt`，不验证 key 是否合法。
fn parse_extra_lines(
    extra: &str,
    log_sanitization: &LogSanitizationConfig,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in extra.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            warn!(
                line = %sanitize_repo_extra_line(line, log_sanitization),
                "repo extra line is not a key=value pair, skipped"
            );
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            warn!(
                line = %sanitize_repo_extra_line(line, log_sanitization),
                "repo extra line has empty key, skipped"
            );
            continue;
        }
        out.push((key.to_string(), value.to_string()));
    }
    out
}

/// repodata 缺失签名识别（纯函数便于单测）：stderr 同时命中 repomd.xml 与
/// 元数据获取失败（404 / No more mirrors / Not found）返回修正提示；其余失败
///（真网络故障、认证等）返回 None 走通用分类。小写匹配，容忍镜像文案差异。
fn repodata_missing_hint(stderr: &str) -> Option<String> {
    let lower = stderr.to_ascii_lowercase();
    let repodata_unreachable = lower.contains("repomd.xml")
        && (lower.contains("no more mirrors")
            || lower.contains("404")
            || lower.contains("not found")
            || lower.contains("status code: 404"));
    if !repodata_unreachable {
        return None;
    }
    Some(
        "the source repo URL exposes no repodata/ — point --repo at a repository \
         level whose directory contains a repodata/ directory (e.g. the SRPMS \
         sub-repo of the published product repo for source packages)"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extra_lines_basic() {
        let extra = "sslverify=0\nproxy=http://proxy.example.com:8080\n";
        let cfg = LogSanitizationConfig::default();
        let parsed = parse_extra_lines(extra, &cfg);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ("sslverify".to_string(), "0".to_string()));
        assert_eq!(
            parsed[1],
            (
                "proxy".to_string(),
                "http://proxy.example.com:8080".to_string()
            )
        );
    }

    #[test]
    fn parse_extra_lines_ignores_comments_and_empty() {
        let extra = "\n# comment\n; another comment\n\nkey=value\n";
        let cfg = LogSanitizationConfig::default();
        let parsed = parse_extra_lines(extra, &cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("key".to_string(), "value".to_string()));
    }

    #[test]
    fn parse_extra_lines_trims_whitespace() {
        let extra = "  key = value  \n";
        let cfg = LogSanitizationConfig::default();
        let parsed = parse_extra_lines(extra, &cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("key".to_string(), "value".to_string()));
    }

    #[test]
    fn parse_extra_lines_skips_malformed() {
        let extra = "key=value\nmalformed\n";
        let cfg = LogSanitizationConfig::default();
        let parsed = parse_extra_lines(extra, &cfg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], ("key".to_string(), "value".to_string()));
    }

    #[test]
    fn nevra_from_rpm_url_normal() {
        let url = "http://example.com/repo/Packages/foo-1.0-1.el9.x86_64.rpm";
        assert_eq!(
            nevra_from_rpm_url(url),
            Some("foo-1.0-1.el9.x86_64".to_string())
        );
    }

    #[test]
    fn nevra_from_rpm_url_with_query_params() {
        let url = "http://example.com/repo/foo-1.0-1.el9.x86_64.rpm?token=abc&expires=123";
        assert_eq!(
            nevra_from_rpm_url(url),
            Some("foo-1.0-1.el9.x86_64".to_string())
        );
    }

    #[test]
    fn nevra_from_rpm_url_no_path_segments() {
        assert_eq!(
            nevra_from_rpm_url("foo-1.0-1.el9.x86_64.rpm"),
            Some("foo-1.0-1.el9.x86_64".to_string())
        );
    }

    #[test]
    fn nevra_from_rpm_url_empty_string() {
        assert_eq!(nevra_from_rpm_url(""), None);
    }

    #[test]
    fn nevra_from_rpm_url_not_rpm_extension() {
        assert_eq!(
            nevra_from_rpm_url("http://example.com/repo/foo-1.0-1.el9.x86_64.tar.gz"),
            None
        );
    }

    #[test]
    fn nevra_from_rpm_url_with_special_chars() {
        let url = "http://example.com/repo/c++-tools-2.0-1.el9.x86_64.rpm";
        assert_eq!(
            nevra_from_rpm_url(url),
            Some("c++-tools-2.0-1.el9.x86_64".to_string())
        );
    }

    #[test]
    fn parse_repoquery_output_basic() {
        let stdout = "http://example.com/repo/foo-1.0-1.el9.x86_64.rpm\n\
                       http://example.com/repo/bar-2.0-1.el9.noarch.rpm\n";
        let cfg = LogSanitizationConfig::default();
        let result = parse_repoquery_output(stdout, &cfg);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result.get("foo-1.0-1.el9.x86_64").map(String::as_str),
            Some("http://example.com/repo/foo-1.0-1.el9.x86_64.rpm")
        );
        assert_eq!(
            result.get("bar-2.0-1.el9.noarch").map(String::as_str),
            Some("http://example.com/repo/bar-2.0-1.el9.noarch.rpm")
        );
    }

    #[test]
    fn parse_repoquery_output_skips_non_rpm_urls() {
        let stdout = "http://example.com/repo/repodata/repomd.xml\n\
                       http://example.com/repo/foo-1.0-1.el9.x86_64.rpm\n";
        let cfg = LogSanitizationConfig::default();
        let result = parse_repoquery_output(stdout, &cfg);
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("foo-1.0-1.el9.x86_64"));
    }

    #[test]
    fn parse_repoquery_output_empty() {
        let cfg = LogSanitizationConfig::default();
        let result = parse_repoquery_output("", &cfg);
        assert!(result.is_empty());
    }

    // ── 整仓重建：源仓 SRPM 枚举 ──────────────────────────────────────

    /// fixture 覆盖：空行/注释跳过、非 rpm 与无名条目计数、重复保留首条、按包名排序。
    #[test]
    fn parse_src_rpm_listing_skips_dedups_and_sorts() {
        let stdout = "\
# comment line

http://h/repo/Packages/zlib-1.2-3.el9.src.rpm
http://h/repo/Packages/dbus-tools-2.0-1.el9.src.rpm
http://h/repo/repodata/repomd.xml
http://h/repo/Packages/zlib-1.2-3.el9.src.rpm?sig=abc
totally-not-a-url
";
        let (entries, skipped) = parse_src_rpm_listing(stdout);
        assert_eq!(skipped, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].nevra, "dbus-tools-2.0-1.el9.src");
        assert_eq!(
            entries[0].url,
            "http://h/repo/Packages/dbus-tools-2.0-1.el9.src.rpm"
        );
        assert_eq!(entries[1].nevra, "zlib-1.2-3.el9.src");
        assert_eq!(
            entries[1].url, "http://h/repo/Packages/zlib-1.2-3.el9.src.rpm",
            "duplicate NEVRA keeps the first URL"
        );
    }

    /// 有输出但全失败：entries 空且 skipped 覆盖全部非空行（空仓与呈现异常可区分）。
    #[test]
    fn parse_src_rpm_listing_all_unparseable_counts_every_line() {
        let stdout = "http://h/repo/repodata/repomd.xml\n\n# c\njunk\n";
        let (entries, skipped) = parse_src_rpm_listing(stdout);
        assert!(entries.is_empty());
        assert_eq!(skipped, 2, "comment/blank lines are not failures");
    }

    #[test]
    fn parse_src_rpm_listing_empty_output_is_legal_empty_repo() {
        let (entries, skipped) = parse_src_rpm_listing("");
        assert!(entries.is_empty());
        assert_eq!(skipped, 0);
    }

    /// repodata 缺失签名：仓库根无 repomd.xml 的 stderr 命中提示；真网络故障返回 None。
    #[test]
    fn repodata_missing_hint_matches_metadata_fetch_failures_only() {
        let hint = repodata_missing_hint(
            "failure: repodata/repomd.xml from crbs-batch-src: [Errno 256] No more mirrors to try\n\
             https://hub.example/repo/repodata/repomd.xml: [Errno 14] HTTP Error 404 - Not Found",
        )
        .expect("repomd 404 signature must produce the hint");
        assert!(hint.contains("repodata/"));
        assert!(hint.contains("--repo"));

        assert!(repodata_missing_hint(
            "Curl error (28): Timeout was reached when talking to https://hub.example: Connection timed out"
        )
        .is_none());
        assert!(repodata_missing_hint("").is_none());
    }

    /// 超时透传：1ms 预算内完不成按进程组终止归 `CrbsError::Timeout`（无 dnf 环境跳过）。
    #[tokio::test]
    async fn enumerate_timeout_is_classified_as_timeout() {
        let dnf_ok = std::process::Command::new("dnf")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !dnf_ok {
            eprintln!("skipping: dnf not available");
            return;
        }
        let err = enumerate_repo_src_rpms(
            "https://example.com/no-such-repo",
            std::time::Duration::from_millis(1),
            std::path::Path::new("/tmp"),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, CrbsError::Timeout),
            "expected Timeout, got {err:?}"
        );
    }

    #[test]
    fn enumerate_rejects_empty_url_before_spawning_dnf() {
        // 入参校验不依赖 dnf（无 dnf 环境也跑）。
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(enumerate_repo_src_rpms(
                "   ",
                std::time::Duration::from_secs(1),
                std::path::Path::new("/tmp"),
            ))
            .unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }));
    }

    #[test]
    fn repo_query_args_repofrompath_and_gpg_setopts() {
        // url.rs 与 depsolve.rs 共用呈现契约：锁 --repofrompath 与无 gpgkey 时 gpgcheck=0。
        let repo = RepoConfig {
            name: "p".into(),
            baseurl: "http://example.com/repo".into(),
            gpgcheck: true,
            gpgkey: None,
            ..Default::default()
        };
        let cfg = LogSanitizationConfig::default();
        let args = repo_query_args(&repo, "crbs-p", &cfg);

        assert_eq!(args[0], "--repofrompath");
        assert_eq!(args[1], "crbs-p,http://example.com/repo");
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--setopt" && w[1] == "crbs-p.gpgcheck=0"));
        assert!(!args.iter().any(|a| a.contains("gpgkey")));
    }

    #[test]
    fn repo_query_args_gpgcheck_with_gpgkey() {
        let repo = RepoConfig {
            name: "p".into(),
            baseurl: "http://example.com/repo".into(),
            gpgcheck: true,
            gpgkey: Some("https://example.com/RPM-GPG-KEY".into()),
            ..Default::default()
        };
        let cfg = LogSanitizationConfig::default();
        let args = repo_query_args(&repo, "crbs-p", &cfg);

        assert!(args
            .windows(2)
            .any(|w| w[0] == "--setopt" && w[1] == "crbs-p.gpgcheck=1"));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--setopt"
                    && w[1] == "crbs-p.gpgkey=https://example.com/RPM-GPG-KEY")
        );
        assert!(!args
            .windows(2)
            .any(|w| w[0] == "--setopt" && w[1] == "crbs-p.gpgcheck=0"));
    }

    #[test]
    fn url_belongs_to_baseurl_matches_on_path_boundary() {
        assert!(url_belongs_to_baseurl(
            "http://h/repo/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo"
        ));
        assert!(url_belongs_to_baseurl("http://h/repo", "http://h/repo"));
        assert!(!url_belongs_to_baseurl(
            "http://h/repo-updates/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo"
        ));
        assert!(!url_belongs_to_baseurl(
            "http://other/repo/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo"
        ));
    }

    #[test]
    fn url_belongs_to_baseurl_trailing_slash_normalized() {
        assert!(url_belongs_to_baseurl(
            "http://h/repo/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo/"
        ));
        assert!(url_belongs_to_baseurl("http://h/repo", "http://h/repo/"));
        assert!(!url_belongs_to_baseurl(
            "http://h/repo-updates/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo/"
        ));
        assert!(url_belongs_to_baseurl(
            "http://h/repo/Packages/foo-1.0-1.el9.x86_64.rpm",
            "http://h/repo"
        ));
        // 根路径 baseurl：归一后等价于 host 根，该 host 下所有 URL 均归属。
        assert!(url_belongs_to_baseurl(
            "http://h/any/path/foo-1.0-1.el9.x86_64.rpm",
            "http://h/"
        ));
        assert!(!url_belongs_to_baseurl(
            "http://other/foo-1.0-1.el9.x86_64.rpm",
            "http://h/"
        ));
    }
}
