// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建溯源：工具链、仓库与主机信息的快照记录。

use std::collections::HashMap;

use crate::engine::build::cleanup_guard::BuildCleanupGuard;
use crate::engine::build::url::resolve_package_urls;
use crate::engine::BuildOutcome;
use crate::error::CrbsError;
use crate::types::PROVENANCE_HARD_GATE_MARKER;
use tokio::io::AsyncBufReadExt as _;
use tracing::{debug, error, warn};

/// [`BuildEngine::record_build_provenance`] 的参数包：字段按值移入供 provenance
/// 汇聚，`cleanup_guard` 贯穿构建生命周期。dep_index 恒用源记录锚（Phase-1 已
/// 校验 record ⊆ cache ∪ base_os，见 [`expected_dep_index`]）。
pub(crate) struct ProvenanceParams<'a> {
    pub(crate) outputs: &'a crate::types::BuildOutputs,
    pub(crate) record_provenance: bool,
    /// 确定性模式：溯源完整性硬门 + SDE 卫生检查（软）生效。
    pub(crate) deterministic: bool,
    pub(crate) layer_digest: &'a Option<String>,
    pub(crate) no_layer_index: Option<HashMap<String, crate::engine::cache::CacheEntry>>,
    pub(crate) overlay_installed_packages: Option<Vec<String>>,
    pub(crate) base_os: &'a std::path::Path,
    pub(crate) config: &'a crate::config::Config,
    pub(crate) build_id: i64,
    pub(crate) srpm_name: &'a str,
    pub(crate) ccache_for_this_pkg: bool,
    pub(crate) build_start: std::time::Instant,
    pub(crate) result_dir: &'a std::path::Path,
    pub(crate) cleanup_guard: &'a mut BuildCleanupGuard,
}

impl crate::engine::BuildEngine {
    pub(crate) async fn record_build_provenance(
        &self,
        params: ProvenanceParams<'_>,
    ) -> crate::Result<BuildOutcome> {
        let ProvenanceParams {
            outputs,
            record_provenance,
            deterministic,
            layer_digest,
            no_layer_index,
            overlay_installed_packages,
            base_os,
            config,
            build_id,
            srpm_name,
            ccache_for_this_pkg,
            build_start,
            result_dir,
            cleanup_guard,
        } = params;
        if record_provenance {
            // reproduce 重放下 layer 分支不可达（三入口均 with_shared_layer_disabled），
            // 恒走 expected 分支；repro-from-srpm（replay_mode）不属此列，仍走 layer 分支。
            let dep_index: HashMap<String, crate::engine::cache::CacheEntry> =
                if let Some(ref digest) = layer_digest {
                    shared_layer_dep_index(&config.shared_layers_dir, digest, build_id).await
                } else if let Some(expected) = &self.reproduce_expected {
                    // replay：dep_index 恒用源记录锚，不得混入 worker dnf 缓存的跨构建包
                    // ——url 继承只从源记录取，覆盖不到 → 硬门误拒（builds 111/112）。
                    expected_dep_index(expected, self.reproduce_source_packages.as_ref())
                } else {
                    no_layer_index.unwrap_or_default()
                };

            // 汇聚三源：dep_index（builddep 的 sha256/repo）、.packages.json（base_os 包）、
            // overlay 扫描；dep_index move 进 full_index（免一次整表 clone）。
            let mut full_index: HashMap<String, crate::engine::cache::CacheEntry> = dep_index;

            let packages_json_path = base_os.join(".packages.json");
            let base_package_index = if tokio::fs::try_exists(&packages_json_path).await? {
                match crate::engine::cache::read_packages_json(&packages_json_path).await {
                    Ok(index) => Some(index),
                    Err(e) => {
                        warn!(
                            build_id = %build_id,
                            path = %packages_json_path.display(),
                            error = %e,
                            "read .packages.json failed"
                        );
                        None
                    }
                }
            } else {
                warn!(
                    build_id = %build_id,
                    path = %packages_json_path.display(),
                    ".packages.json not found, base_os packages will have no sha256"
                );
                None
            };

            if let Some(installed) = overlay_installed_packages {
                for nevra in installed {
                    if full_index.contains_key(&nevra) {
                        continue;
                    }
                    // dep_index 未命中后的解析顺序见 [`resolve_overlay_entry`]。
                    match resolve_overlay_entry(
                        self.reproduce_expected.as_ref(),
                        base_package_index.as_ref(),
                        &nevra,
                    ) {
                        ResolvedOverlay::ReproduceAnchor(entry) => {
                            // replay 锚命中是预期路径（重建 base_os 无 dnf cache），降 debug 防噪音误导排障。
                            debug!(
                                build_id = %build_id,
                                nevra = %nevra,
                                "overlay package anchored from recorded build_packages.json (replay)"
                            );
                            full_index.insert(nevra, entry);
                        }
                        ResolvedOverlay::BaseOs(entry) => {
                            full_index.insert(nevra, entry);
                        }
                        ResolvedOverlay::Unresolved => {
                            // 三处皆未命中（replay 下即重放环境相对记录漂移）→ 空 sha +
                            // 告警，防静默降级；deterministic 硬门据此拒构建。
                            warn!(
                                build_id = %build_id,
                                nevra = %nevra,
                                "installed package missing from dnf cache and .packages.json, provenance sha256 will be empty"
                            );
                            full_index.insert(
                                nevra,
                                crate::engine::cache::CacheEntry {
                                    sha256: String::new(),
                                    repo_id: None,
                                },
                            );
                        }
                    }
                }
            }

            let url_map = if self.reproduce_source_packages.is_some() {
                // --reproduce：包来自 crbs-local 临时仓库（config.repos 无此仓库），直接继承原始构建 URL。
                HashMap::new()
            } else {
                match resolve_package_urls(
                    &full_index,
                    &config.repos,
                    &self.state,
                    &self.log_sanitization,
                    &config.tmp_dir,
                )
                .await
                {
                    Ok(map) => map,
                    Err(e) => {
                        warn!(
                            build_id = %build_id,
                            error = %e,
                            "resolve_package_urls failed; build script succeeded but provenance is incomplete, marking build as failed"
                        );
                        cleanup_guard.set_outcome(BuildOutcome::Failed);
                        return Err(CrbsError::io_message(format!(
                            "resolve package URLs for provenance: {}",
                            e
                        )));
                    }
                }
            };

            let mut all_packages: Vec<crate::state::BuildPackage> = full_index
                .iter()
                .map(|(nevra, entry)| {
                    let source_url = self
                        .reproduce_source_packages
                        .as_ref()
                        .and_then(|src| src.get(nevra))
                        .and_then(|pkg| pkg.url.clone());
                    crate::state::BuildPackage {
                        build_id,
                        nevra: nevra.clone(),
                        sha256: entry.sha256.clone(),
                        repo: entry.repo_id.clone(),
                        url: source_url.or_else(|| url_map.get(nevra).cloned()),
                    }
                })
                .collect();
            // HashMap 迭代序不定：排序保证 build_packages.json 逐字节确定，便于 diff/checksum 校验。
            all_packages.sort_by(|a, b| a.nevra.cmp(&b.nevra));

            // 确定性硬门：sha256/url 必须 100% 非空，lockfile/.packages.json/overlay
            // 降级路径在此收严为失败（空锚 → verdict 误记 same、污染复现率分母）；非 deterministic 维持 warn。
            if deterministic {
                let violations = deterministic_provenance_violations(&all_packages);
                let empty = all_packages.is_empty();
                if !violations.is_empty() || empty {
                    // 计数取全量，truncate 只作用于展示串（防"5 of 12"低报）。
                    let detail = if empty {
                        "no provenance entries collected at all".to_string()
                    } else {
                        format!(
                            "{} of {} package entries have empty sha256 or missing url \
                             (first offenders: {})",
                            violations.len(),
                            all_packages.len(),
                            violations_preview(&violations)
                        )
                    };
                    let msg = format!(
                        "deterministic mode {PROVENANCE_HARD_GATE_MARKER}: {}; \
                         refusing to succeed — the replay environment would be silently \
                         unanchored (check shared layer .lockfile / base_os .packages.json / \
                         repo url resolution)",
                        detail
                    );
                    error!(build_id = %build_id, "{}", msg);
                    if let Err(e) = self
                        .state
                        .append_build_note(build_id, &format!("\n{msg}"))
                        .await
                    {
                        warn!(build_id = %build_id, error = %e, "Failed to append hard-gate note to error_summary");
                    }
                    cleanup_guard.set_outcome(BuildOutcome::Failed);
                    return Err(CrbsError::ValidationFailed { message: msg });
                }
            }

            if !all_packages.is_empty() {
                // 原子写 build_packages.json（canonical 数据源），失败则该 build 无法 reproduce。
                let packages_json = result_dir.join("build_packages.json");
                if let Err(e) =
                    crate::engine::cache::write_json_atomic(&packages_json, &all_packages).await
                {
                    warn!(
                        build_id = %build_id,
                        path = %packages_json.display(),
                        error = %e,
                        "write build_packages.json failed"
                    );
                    // cleanup guard 的 Drop/Run 负责 umount 与状态写入。
                    cleanup_guard.set_outcome(BuildOutcome::Failed);
                    return Err(CrbsError::io_message(format!(
                        "write build_packages.json: {}",
                        e
                    )));
                }

                debug!(build_id = %build_id, count = all_packages.len(), "Recorded build packages");
            }
        } else {
            debug!(build_id = %build_id, "Skipping reproducibility artifacts");
        }

        // 解析并写入构建 profile（best effort，失败不影响构建状态）；流式逐行消费，
        // build.log 无大小上限（内核级构建可达 GB），并发构建下避免整载内存。
        let build_log_path = outputs.result_dir.join("build.log");
        match crate::engine::profile::parse_profile_from_log_file(
            &build_log_path,
            build_id,
            srpm_name,
            build_start.elapsed().as_secs_f64(),
            layer_digest.is_some(),
            ccache_for_this_pkg,
        )
        .await
        {
            Ok(profile) => {
                if let Err(e) =
                    crate::engine::profile::write_profile(&outputs.result_dir, &profile).await
                {
                    warn!(
                        build_id = %build_id,
                        path = %outputs.result_dir.display(),
                        error = %e,
                        "write profile.json failed"
                    );
                } else {
                    debug!(build_id = %build_id, "Wrote profile.json");
                }
            }
            Err(e) => {
                warn!(
                    build_id = %build_id,
                    path = %build_log_path.display(),
                    error = %e,
                    "parse build.log for profiling failed"
                );
            }
        }

        // SDE 卫生检查（软；仅 deterministic）：n > now = changelog 未来日期 typo
        // 会把文件 mtime 推向未来；行缺失 = SDE 未从 changelog 推导（如无 changelog 包）。
        // 两者均只记 warning 进构建记录，不失败。
        if deterministic {
            if let Some(warning) = source_date_epoch_hygiene_warning(&build_log_path).await {
                warn!(build_id = %build_id, "{}", warning);
                if let Err(e) = self
                    .state
                    .append_build_note(build_id, &format!("\nwarning: {warning}"))
                    .await
                {
                    warn!(build_id = %build_id, error = %e, "Failed to append SDE hygiene warning to error_summary");
                }
            }
        }

        // 记录 provenance 时必须先持久化 canonical JSON 再标 succeeded，否则进程在
        // complete_build 与 JSON 写入间崩溃会产生"状态成功但无 build_packages.json"的不可复现构建。
        Ok(BuildOutcome::Succeeded)
    }
}

/// 共享层 dep_index 构造（`.lockfile` 消费侧统一降级口径）：lockfile 缺失（GC 竞态/
/// 人工删除）、读取/解析失败或存在性检查失败一律 warn + 空索引降级，交 deterministic
/// 硬门收口（空 sha256 落 [`PROVENANCE_HARD_GATE_MARKER`] → infra_error，不进复现率分母）。
async fn shared_layer_dep_index(
    shared_layers_dir: &std::path::Path,
    digest: &str,
    build_id: i64,
) -> HashMap<String, crate::engine::cache::CacheEntry> {
    let lockfile_path = shared_layers_dir.join(digest).join(".lockfile");
    // try_exists 失败（权限等）与缺失同路降级——任何 Err 早退都会以无判据文案炸构建。
    if !tokio::fs::try_exists(&lockfile_path).await.unwrap_or(false) {
        warn!(
            build_id = %build_id,
            digest = %digest,
            path = %lockfile_path.display(),
            "shared layer .lockfile missing; builddep provenance degrades to empty sha256"
        );
        return HashMap::new();
    }
    match crate::engine::cache::read_lockfile_index(&lockfile_path).await {
        Ok(index) => index,
        Err(e) => {
            warn!(
                build_id = %build_id,
                digest = %digest,
                path = %lockfile_path.display(),
                error = %e,
                "shared layer .lockfile unreadable (corrupt/half-written/permission); \
                 builddep provenance degrades to empty sha256 (deterministic hard gate will refuse)"
            );
            HashMap::new()
        }
    }
}

/// dep_index 未命中后单个 overlay 安装包的解析结果来源。replay 语义：环境锚 =
/// 记录的 sha256，只能来自 worker 注入的 `with_reproduce_expected`（原始构建
/// build_packages.json）——重建的 base_os 无 dnf cache、`.packages.json` 条目无
/// sha256；非 replay 的 `expected` 恒为 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedOverlay {
    /// 命中记录的锚（replay-only）：`CacheEntry { sha256: 记录值, repo_id: None }`。
    ReproduceAnchor(crate::engine::cache::CacheEntry),
    /// 命中 base_os `.packages.json`（非 replay 的既有路径）。
    BaseOs(crate::engine::cache::CacheEntry),
    /// 三处皆未命中（replay 下即环境漂移）：空 sha 占位，deterministic 硬门会拦。
    Unresolved,
}

/// dep_index 未命中后的 overlay 包解析顺序（纯函数，可注入测试）：
/// 1. `expected`（replay 锚，NEVRA → 记录 sha256；**空串视为未命中**）
/// 2. `base_index`（base_os `.packages.json`）
/// 3. 皆未命中 → [`ResolvedOverlay::Unresolved`]（空 sha 占位）。漂移链：记录外包 → 空
///    sha → [`deterministic_provenance_violations`] 计违规 fail-fast，verdict 不误记 same。
pub(crate) fn resolve_overlay_entry(
    expected: Option<&HashMap<String, String>>,
    base_index: Option<&HashMap<String, crate::engine::cache::CacheEntry>>,
    nevra: &str,
) -> ResolvedOverlay {
    if let Some(sha256) = expected
        .and_then(|m| m.get(nevra))
        .filter(|sha| !sha.is_empty())
    {
        return ResolvedOverlay::ReproduceAnchor(crate::engine::cache::CacheEntry {
            sha256: sha256.clone(),
            repo_id: None,
        });
    }
    if let Some(entry) = base_index.and_then(|m| m.get(nevra)) {
        return ResolvedOverlay::BaseOs(entry.clone());
    }
    ResolvedOverlay::Unresolved
}

/// replay 模式 dep_index 的构造（纯函数，可注入测试）：`reproduce_expected`（NEVRA →
/// 记录 sha256）→ CacheEntry，repo 从 `reproduce_source_packages` 同名条目继承（url
/// 继承在 all_packages 汇聚处）。不过滤空 sha256——过滤职责在注入侧
/// `expected_packages_from`，与 [`resolve_overlay_entry`] 空串语义有意相反（防空 sha 洗白）。
pub(crate) fn expected_dep_index(
    expected: &HashMap<String, String>,
    source_packages: Option<&HashMap<String, crate::state::BuildPackage>>,
) -> HashMap<String, crate::engine::cache::CacheEntry> {
    expected
        .iter()
        .map(|(nevra, sha256)| {
            (
                nevra.clone(),
                crate::engine::cache::CacheEntry {
                    sha256: sha256.clone(),
                    repo_id: source_packages
                        .and_then(|m| m.get(nevra))
                        .and_then(|pkg| pkg.repo.clone()),
                },
            )
        })
        .collect()
}

/// 确定性溯源硬门的违规清单（纯函数）：sha256 为空或 url 缺失的条目，**不截断**——
/// 全量计数防"5 of 12"低报，展示串经 [`violations_preview`] 截前 5 条（防超长 error_summary）。
pub(crate) fn deterministic_provenance_violations(
    packages: &[crate::state::BuildPackage],
) -> Vec<String> {
    packages
        .iter()
        .filter(|p| p.sha256.is_empty() || p.url.as_deref().unwrap_or("").is_empty())
        .map(|p| {
            format!(
                "{} (sha256={}, url={})",
                p.nevra,
                if p.sha256.is_empty() { "EMPTY" } else { "ok" },
                if p.url.as_deref().unwrap_or("").is_empty() {
                    "MISSING"
                } else {
                    "ok"
                }
            )
        })
        .collect()
}

/// 违规清单的展示串：仅取前 5 条 join（计数由调用方从全量 Vec 取）。
pub(crate) fn violations_preview(violations: &[String]) -> String {
    violations
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ")
}

/// SDE 卫生检查（软）：流式扫描 build.log 最后一条 `setting SOURCE_DATE_EPOCH=<n>`
/// 行，返回 warning 文案（无问题 `None`）；逐行消费（日志无大小上限，可达 GB）。
async fn source_date_epoch_hygiene_warning(log_path: &std::path::Path) -> Option<String> {
    let file = match tokio::fs::File::open(log_path).await {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %log_path.display(), error = %e, "SDE hygiene: open build.log failed (soft check skipped)");
            return None;
        }
    };
    let mut reader = tokio::io::BufReader::new(file);
    let mut line = String::new();
    let mut last_sde: Option<i64> = None;
    // 标记行在但值不可解析与"无标记行"是两种故障（值损坏 vs 宏未生效），文案必须分开。
    let mut saw_marker = false;
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                // "corrupt" 文案仅在全部标记行均不可解析时出现（saw_marker 置位且
                // last_sde 仍为 None）；混合形态中不可解析行不覆写 last_sde，首个有效值
                // 保留。rpm 单次构建只写一条标记行，多行形态实际不可达——防误读触发面。
                if crate::engine::build::phase::source_date_epoch_marker_present(&line) {
                    saw_marker = true;
                }
                if let Some(n) = crate::engine::build::phase::extract_source_date_epoch(&line) {
                    last_sde = Some(n);
                }
            }
            Err(e) => {
                warn!(path = %log_path.display(), error = %e, "SDE hygiene: read build.log failed (soft check skipped)");
                return None;
            }
        }
    }
    match last_sde {
        Some(n) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(i64::MAX);
            (n > now).then(|| {
                format!(
                    "SOURCE_DATE_EPOCH={} is in the future (now={}); a changelog date typo \
                     would push file mtimes forward — verify the spec changelog",
                    n, now
                )
            })
        }
        None if saw_marker => Some(
            "build.log has a 'setting SOURCE_DATE_EPOCH=<n>' line but its value could not \
             be parsed (corrupt log?) — SDE anchor unavailable, future-date hygiene check \
             skipped"
                .to_string(),
        ),
        None => Some(
            "build.log has no 'setting SOURCE_DATE_EPOCH=<n>' line: SDE was not derived from \
             the changelog (package without changelog?) — determinism macros may not have \
             taken effect"
                .to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(nevra: &str, sha256: &str, url: Option<&str>) -> crate::state::BuildPackage {
        crate::state::BuildPackage {
            build_id: 1,
            nevra: nevra.to_string(),
            sha256: sha256.to_string(),
            repo: None,
            url: url.map(str::to_string),
        }
    }

    /// 硬门违规清单（纯函数）：sha256 空 / url 缺失 / 双缺 / 上限截断。
    #[test]
    fn deterministic_provenance_violations_covers_sha_and_url() {
        assert!(deterministic_provenance_violations(&[
            pkg("a-1.0", "abc", Some("http://r/a.rpm")),
            pkg("b-1.0", "def", Some("http://r/b.rpm")),
        ])
        .is_empty());

        let v = deterministic_provenance_violations(&[
            pkg("sha-empty-1.0", "", Some("http://r/a.rpm")),
            pkg("url-missing-1.0", "abc", None),
            pkg("both-1.0", "", None),
        ]);
        assert_eq!(v.len(), 3, "got: {v:?}");
        assert!(v[0].contains("sha-empty-1.0") && v[0].contains("sha256=EMPTY"));
        assert!(v[1].contains("url-missing-1.0") && v[1].contains("url=MISSING"));
        assert!(v[2].contains("both-1.0") && v[2].contains("EMPTY") && v[2].contains("MISSING"));

        let many: Vec<_> = (0..8)
            .map(|i| pkg(&format!("bad-{i}-1.0"), "", None))
            .collect();
        assert_eq!(deterministic_provenance_violations(&many).len(), 8);
        let preview = violations_preview(&deterministic_provenance_violations(&many));
        assert!(
            preview.contains("bad-4-1.0"),
            "5th offender kept: {preview}"
        );
        assert!(!preview.contains("bad-5-1.0"), "6th+ truncated: {preview}");
        assert_eq!(violations_preview(&[]), "");
    }

    fn cache_entry(sha256: &str, repo_id: Option<&str>) -> crate::engine::cache::CacheEntry {
        crate::engine::cache::CacheEntry {
            sha256: sha256.to_string(),
            repo_id: repo_id.map(|s| s.to_string()),
        }
    }

    /// lockfile 不可用（缺失/存在性检查失败/损坏）均空索引，deterministic 硬门收口；
    /// 合法 lockfile 照常读出。
    #[tokio::test]
    async fn shared_layer_dep_index_degrades_on_unusable_lockfile() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(shared_layer_dep_index(tmp.path(), "deadbeef", 1)
            .await
            .is_empty());

        // 存在但损坏（非法 JSON，新旧两种格式都解析失败）。
        let dir = tmp.path().join("cafe0000");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join(".lockfile"), b"{half-written")
            .await
            .unwrap();
        assert!(shared_layer_dep_index(tmp.path(), "cafe0000", 1)
            .await
            .is_empty());

        // 合法（CacheEntry 新格式）照常读出。
        let dir2 = tmp.path().join("feed0000");
        tokio::fs::create_dir_all(&dir2).await.unwrap();
        tokio::fs::write(
            dir2.join(".lockfile"),
            br#"{"bash-5.2-1.x86_64":{"sha256":"ab","repo_id":"baseos"}}"#,
        )
        .await
        .unwrap();
        let idx = shared_layer_dep_index(tmp.path(), "feed0000", 1).await;
        assert_eq!(idx["bash-5.2-1.x86_64"], cache_entry("ab", Some("baseos")));

        // 旧格式（NEVRA → SHA256）兼容路径同走本函数不回归。
        let dir3 = tmp.path().join("baad0000");
        tokio::fs::create_dir_all(&dir3).await.unwrap();
        tokio::fs::write(dir3.join(".lockfile"), br#"{"bash-5.2-1.x86_64":"cd"}"#)
            .await
            .unwrap();
        let idx = shared_layer_dep_index(tmp.path(), "baad0000", 1).await;
        assert_eq!(idx["bash-5.2-1.x86_64"], cache_entry("cd", None));
    }

    /// replay 锚：expected 命中 → 记录 sha256，且**优先于** base_index（replay 唯一
    /// 可信锚：重建 base_os 无 dnf cache、.packages.json 无 sha256，不先查则全部
    /// 落空——blue 实测 283 条空 sha）。
    #[test]
    fn resolve_overlay_entry_prefers_reproduce_expected() {
        let expected =
            HashMap::from([("pkg-1.0-1.el8.x86_64".to_string(), "recorded".to_string())]);
        let base = HashMap::from([(
            "pkg-1.0-1.el8.x86_64".to_string(),
            cache_entry("from-base", Some("baseos")),
        )]);
        assert_eq!(
            resolve_overlay_entry(Some(&expected), Some(&base), "pkg-1.0-1.el8.x86_64"),
            ResolvedOverlay::ReproduceAnchor(cache_entry("recorded", None)),
            "replay anchor (recorded sha) must win over .packages.json"
        );
    }

    /// expected 未命中但 .packages.json 有 sha → BaseOs；非 replay 下 expected
    /// 恒 None，replay 下记录外漂移包也落此（重建 base_os 有 sha 则如实锚定）。
    #[test]
    fn resolve_overlay_entry_falls_back_to_base_index() {
        let base = HashMap::from([(
            "pkg-2.0-1.el8.x86_64".to_string(),
            cache_entry("from-base", Some("baseos")),
        )]);
        assert_eq!(
            resolve_overlay_entry(None, Some(&base), "pkg-2.0-1.el8.x86_64"),
            ResolvedOverlay::BaseOs(cache_entry("from-base", Some("baseos")))
        );
        let expected = HashMap::from([("other-1.0-1.el8.x86_64".to_string(), "sha".to_string())]);
        assert_eq!(
            resolve_overlay_entry(Some(&expected), Some(&base), "pkg-2.0-1.el8.x86_64"),
            ResolvedOverlay::BaseOs(cache_entry("from-base", Some("baseos")))
        );
    }

    /// 两者皆缺 → Unresolved（空 sha 占位）→ 硬门计违规、构建 fail-fast，
    /// 漂移环境不会被 verdict 误记为 same。
    #[test]
    fn resolve_overlay_entry_unresolved_when_both_missing() {
        assert_eq!(
            resolve_overlay_entry(None, None, "pkg-3.0-1.el8.x86_64"),
            ResolvedOverlay::Unresolved
        );
        let expected = HashMap::from([("other-1.0-1.el8.x86_64".to_string(), "sha".to_string())]);
        assert_eq!(
            resolve_overlay_entry(Some(&expected), None, "pkg-3.0-1.el8.x86_64"),
            ResolvedOverlay::Unresolved
        );
    }

    /// 记录中的空串 sha256 视为未命中：记录本身失真时不得当作锚"洗白"空 sha，
    /// 应回退 base_index，无路可退则 Unresolved（硬门会拦）。
    #[test]
    fn resolve_overlay_entry_treats_empty_expected_sha_as_miss() {
        let expected = HashMap::from([("pkg-4.0-1.el8.x86_64".to_string(), String::new())]);
        let base = HashMap::from([(
            "pkg-4.0-1.el8.x86_64".to_string(),
            cache_entry("from-base", None),
        )]);
        assert_eq!(
            resolve_overlay_entry(Some(&expected), Some(&base), "pkg-4.0-1.el8.x86_64"),
            ResolvedOverlay::BaseOs(cache_entry("from-base", None))
        );
        assert_eq!(
            resolve_overlay_entry(Some(&expected), None, "pkg-4.0-1.el8.x86_64"),
            ResolvedOverlay::Unresolved
        );
    }

    fn source_pkg(nevra: &str, repo: Option<&str>) -> crate::state::BuildPackage {
        crate::state::BuildPackage {
            build_id: 1,
            nevra: nevra.to_string(),
            sha256: String::new(),
            repo: repo.map(str::to_string),
            url: None,
        }
    }

    /// replay 恒用源记录锚（回归钉，builds 111/112）：dep_index 键集与 expected
    /// 严格一致——整缓存扫描会把 worker dnf 缓存的跨构建包（不在源记录）带进
    /// dep_index，url 继承覆盖不到 → 硬门误拒；现签名不收缓存索引，结构上堵死。
    #[test]
    fn expected_dep_index_anchors_exactly_to_source_record() {
        let expected = HashMap::from([
            ("dep-a-1.0-1.el8.x86_64".to_string(), "sha-a".to_string()),
            ("dep-b-2.0-1.el8.x86_64".to_string(), "sha-b".to_string()),
        ]);
        let index = expected_dep_index(&expected, None);
        let mut keys: Vec<_> = index.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec!["dep-a-1.0-1.el8.x86_64", "dep-b-2.0-1.el8.x86_64"]
        );
        assert_eq!(index["dep-a-1.0-1.el8.x86_64"], cache_entry("sha-a", None));
        assert_eq!(index["dep-b-2.0-1.el8.x86_64"], cache_entry("sha-b", None));
    }

    /// repo 继承：源记录带 repo → 继承；缺该条目/repo 为 None/整体缺席 → None。
    #[test]
    fn expected_dep_index_inherits_repo_from_source_packages() {
        let expected = HashMap::from([
            (
                "with-repo-1.0-1.el8.x86_64".to_string(),
                "sha-1".to_string(),
            ),
            (
                "no-repo-field-1.0-1.el8.x86_64".to_string(),
                "sha-2".to_string(),
            ),
            (
                "absent-in-source-1.0-1.el8.x86_64".to_string(),
                "sha-3".to_string(),
            ),
        ]);
        let source = HashMap::from([
            (
                "with-repo-1.0-1.el8.x86_64".to_string(),
                source_pkg("with-repo-1.0-1.el8.x86_64", Some("baseos")),
            ),
            (
                "no-repo-field-1.0-1.el8.x86_64".to_string(),
                source_pkg("no-repo-field-1.0-1.el8.x86_64", None),
            ),
        ]);
        let index = expected_dep_index(&expected, Some(&source));
        assert_eq!(
            index["with-repo-1.0-1.el8.x86_64"],
            cache_entry("sha-1", Some("baseos")),
            "repo must be inherited from the recorded source package"
        );
        assert_eq!(
            index["no-repo-field-1.0-1.el8.x86_64"],
            cache_entry("sha-2", None)
        );
        assert_eq!(
            index["absent-in-source-1.0-1.el8.x86_64"],
            cache_entry("sha-3", None)
        );
        let no_source = expected_dep_index(&expected, None);
        assert!(no_source.values().all(|e| e.repo_id.is_none()));
    }

    /// 空 sha 源条目透传（收什么映射什么），过滤职责在注入侧
    /// `expected_packages_from`；与 [`resolve_overlay_entry`] 的"空串视为未命中"有意不同。
    #[test]
    fn expected_dep_index_passes_through_empty_sha_entries() {
        let expected =
            HashMap::from([("legacy-empty-1.0-1.el8.x86_64".to_string(), String::new())]);
        let index = expected_dep_index(&expected, None);
        assert_eq!(
            index["legacy-empty-1.0-1.el8.x86_64"],
            cache_entry("", None)
        );
    }

    /// SDE 卫生（软）：未来日期 → 返回 warning；正常历史日期 → None。
    #[tokio::test]
    async fn sde_hygiene_warns_on_future_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 86_400;
        tokio::fs::write(
            &log,
            format!("Executing(%prep)\nsetting SOURCE_DATE_EPOCH={future}\nmake -j8\n"),
        )
        .await
        .unwrap();
        let warning = source_date_epoch_hygiene_warning(&log).await;
        let w = warning.expect("future SDE must produce a warning");
        assert!(w.contains("future"), "got: {w}");
        assert!(w.contains(&future.to_string()), "got: {w}");
    }

    /// SDE 卫生（软）：历史日期 → 无 warning。
    #[tokio::test]
    async fn sde_hygiene_silent_on_past_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        tokio::fs::write(&log, "setting SOURCE_DATE_EPOCH=946684800\n")
            .await
            .unwrap();
        assert!(source_date_epoch_hygiene_warning(&log).await.is_none());
    }

    /// SDE 卫生（软）：行缺失 → warning；多条 SDE 行取最后一条。
    #[tokio::test]
    async fn sde_hygiene_warns_when_line_missing_and_takes_last() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        tokio::fs::write(&log, "gcc -c a.c\nmake: Leaving directory\n")
            .await
            .unwrap();
        let w = source_date_epoch_hygiene_warning(&log)
            .await
            .expect("missing SDE line must warn");
        assert!(w.contains("no 'setting SOURCE_DATE_EPOCH"), "got: {w}");

        let log2 = tmp.path().join("build2.log");
        tokio::fs::write(
            &log2,
            "setting SOURCE_DATE_EPOCH=9999999999\nsetting SOURCE_DATE_EPOCH=946684800\n",
        )
        .await
        .unwrap();
        assert!(source_date_epoch_hygiene_warning(&log2).await.is_none());
    }

    /// SDE 卫生（软）：标记行在但值溢出 i64 → 报"值不可解析"，不得误报"无标记行"。
    #[tokio::test]
    async fn sde_hygiene_distinguishes_unparseable_marker_from_missing_line() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        // i64::MAX + 1：parse 溢出失败，但标记行确实存在。
        tokio::fs::write(
            &log,
            "gcc -c a.c\nsetting SOURCE_DATE_EPOCH=9223372036854775808\n",
        )
        .await
        .unwrap();
        let w = source_date_epoch_hygiene_warning(&log)
            .await
            .expect("unparseable marker must warn");
        assert!(
            w.contains("value could not be parsed"),
            "must report unparseable value, got: {w}"
        );
        assert!(
            !w.contains("has no 'setting SOURCE_DATE_EPOCH"),
            "marker line exists; must not be misreported as missing: {w}"
        );
    }

    /// SDE 卫生（软）：build.log 打不开 → 跳过检查（None），不 panic。
    #[tokio::test]
    async fn sde_hygiene_tolerates_missing_log() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            source_date_epoch_hygiene_warning(&tmp.path().join("no-such.log"))
                .await
                .is_none()
        );
    }
}
