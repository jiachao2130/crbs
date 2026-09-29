// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建缓存：dnf 缓存与包文件的保存 / 恢复、packages.json 与 lockfile 读写。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::CrbsError;
use crate::util::is_sha256_hex;
use sha2::Digest;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

/// 单次包下载大小上限（2 GiB）：防仓库源（尤其 http，可被 MITM）的恶意/异常响应灌满磁盘。
const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// 原子写入 JSON 文件。
///
/// 临时名 `{path}.json.tmp.{pid}.{uuid}`（pid 隔离并发进程、uuid 隔离同进程
/// 并发写）；rename 同一文件系统内原子，崩溃不留半写目标文件；中断残留 tmp
/// 由 reproduce 前缀探测分支回收（engine/reproduce.rs）。
pub async fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> crate::Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| CrbsError::io_message(format!("serialize JSON for: {}", e)))?;

    let tmp_path = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    // rename 前 fsync：数据块先于 rename 元数据落盘，断电不留空/半写目标文件。
    let write_result = async {
        let mut file = tokio::fs::File::create(&tmp_path).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, json.as_bytes()).await?;
        file.sync_all().await?;
        Result::<(), std::io::Error>::Ok(())
    }
    .await;

    if let Err(e) = write_result {
        if let Err(e2) = tokio::fs::remove_file(&tmp_path).await {
            warn!(path = %tmp_path.display(), error = %e2, "Failed to clean up temp JSON file");
        }
        return Err(CrbsError::from_io_context("write temp file", e));
    }

    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        if let Err(e2) = tokio::fs::remove_file(&tmp_path).await {
            warn!(path = %tmp_path.display(), error = %e2, "Failed to clean up temp JSON file after rename");
        }
        return Err(CrbsError::from_io_context("rename to", e));
    }

    Ok(())
}

/// rename 前对 tmp 文件 fsync（数据块先于 rename 元数据落盘）。内容寻址
/// 缓存命中后不校验内容（skip-existing 只 try_exists、reproduce 直接
/// 硬链），断电留下的空/半截 RPM 会以正确 sha256 之名无声进入构建。
async fn sync_tmp_before_rename(path: &Path) -> crate::Result<()> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| CrbsError::from_io_context("open cached rpm tmp for fsync", e))?;
    file.sync_all()
        .await
        .map_err(|e| CrbsError::from_io_context("sync cached rpm before rename", e))?;
    Ok(())
}

/// 缓存清单条目（packages.json / lockfile 的值类型）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheEntry {
    /// 包内容 SHA256。
    pub sha256: String,
    /// 来源 repo id（规范化后）。
    pub repo_id: Option<String>,
}

/// 规范化 dnf cache 目录名中的 repo id：dnf5 目录格式 `<repo-name>-<hex-hash>`，
/// 去 hash 后缀才能与用户配置的 repo name 匹配。
fn normalize_repo_id(repo_id: &str) -> String {
    if let Some(pos) = repo_id.rfind('-') {
        let suffix = &repo_id[pos + 1..];
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return repo_id[..pos].to_string();
        }
    }
    repo_id.to_string()
}

/// 并发缓存 RPM 的最大并行度（防大 cache 场景 IO 抖动 / 阻塞 runtime）。
const CACHE_RPM_CONCURRENCY: usize = 4;

/// 找到 dnf cache 目录（有 RPM 的第一个候选）并缓存全部包；`Ok(None)` =
/// 未找到含 RPM 的 dnf cache 目录（调用方按无缓存处理）。`skip_existing`：
/// 已知 NEVRA → 条目映射，命中跳过哈希直接复用（repair 路径，免全量重哈希）。
pub async fn cache_dnf_cache(
    root: &Path,
    package_cache: &Path,
    skip_existing: Option<&HashMap<String, CacheEntry>>,
) -> crate::Result<Option<HashMap<String, CacheEntry>>> {
    for cand in ["var/cache/dnf", "var/cache/libdnf5"] {
        let p = root.join(cand);
        let is_dir = tokio::fs::metadata(&p)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
        if !is_dir {
            continue;
        }
        let rpm_files = unique_rpm_files(&p).await?;
        if rpm_files.is_empty() {
            continue;
        }
        debug!(path = %p.display(), "Found dnf cache dir with RPMs");
        let index = index_rpm_files(rpm_files, package_cache, skip_existing).await?;
        return Ok(Some(index));
    }
    Ok(None)
}

/// 并发缓存一批 RPM 文件到 package_cache（内容寻址），返回 NEVRA → 条目；
/// `skip_existing` 语义见 [`cache_dnf_cache`]。
async fn index_rpm_files(
    rpm_files: Vec<(std::path::PathBuf, Option<String>)>,
    package_cache: &Path,
    skip_existing: Option<&HashMap<String, CacheEntry>>,
) -> crate::Result<HashMap<String, CacheEntry>> {
    // package_cache 根目录规范为 crbs 组共享可写（server/worker/CLI 跨身份写）。
    crate::engine::shared_dir::ensure_shared_dir(package_cache).await?;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(CACHE_RPM_CONCURRENCY));
    let package_cache = package_cache.to_path_buf();
    let skip = skip_existing.cloned().map(std::sync::Arc::new);
    // 逐 RPM hash 失败聚合器（见 `HashFailures`）：drain 后单条 warn 汇总。
    let hash_fails = std::sync::Arc::new(std::sync::Mutex::new(HashFailures::default()));
    let mut set = tokio::task::JoinSet::new();

    for (rpm_path, repo_id) in rpm_files {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| CrbsError::io_message(format!("acquire cache semaphore: {e}")))?;
        let package_cache = package_cache.clone();
        let skip = skip.clone();
        let hash_fails = hash_fails.clone();
        set.spawn(async move {
            let _permit = permit;
            cache_one_rpm(
                &rpm_path,
                repo_id.as_deref(),
                &package_cache,
                skip.as_deref(),
                &hash_fails,
            )
            .await
        });
    }

    let mut index: HashMap<String, CacheEntry> = HashMap::new();
    // 出错不提前 return：drop JoinSet 会中止在拷贝的任务、留无人清理的 .tmp；
    // 记首错 drain 完（各任务错误路径清自己的 tmp）再返回。
    let mut first_err: Option<CrbsError> = None;
    while let Some(result) = set.join_next().await {
        let outcome = match result {
            Ok(inner) => inner,
            Err(e) => Err(CrbsError::io_message(format!(
                "cache rpm task panicked: {e}"
            ))),
        };
        match outcome {
            Ok(Some((nevra, entry))) => {
                index.insert(nevra, entry);
            }
            Ok(None) => {}
            Err(e) if first_err.is_none() => first_err = Some(e),
            Err(e) => warn!(error = %e, "Additional cache rpm task failed"),
        }
    }
    if let Some(e) = first_err {
        return Err(e);
    }
    {
        let agg = hash_fails.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((path, err)) = agg.first.as_ref() {
            warn!(
                path = %path.display(),
                error = %err,
                failures = agg.count,
                "Failed to hash RPM file(s), skipping them"
            );
        }
    }

    if !index.is_empty() {
        debug!(count = index.len(), "Cached RPM packages from dnf cache");
    }
    Ok(index)
}

/// 逐 RPM hash 失败聚合器：只存首条 path + 错误与总数（逐文件刷屏无增量
/// 信息），drain 后单条 warn 透出量级。
#[derive(Default)]
struct HashFailures {
    first: Option<(std::path::PathBuf, String)>,
    count: usize,
}

/// 从 dnf cache 收集 RPM 文件，并按路径排序后去重（同一 NEVRA 只保留第一个）。
async fn unique_rpm_files(
    dnf_cache: &Path,
) -> crate::Result<Vec<(std::path::PathBuf, Option<String>)>> {
    let mut rpm_files = collect_rpm_files(dnf_cache).await?;
    rpm_files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut seen: HashSet<String> = HashSet::new();
    Ok(rpm_files
        .into_iter()
        .filter(|(path, _)| {
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // 单次剥 ".rpm"："foo.rpm.rpm" 的 NEVRA 键是 "foo.rpm"，不与 "foo" 混淆。
            match file_name.strip_suffix(".rpm") {
                Some(nevra) => seen.insert(nevra.to_string()),
                None => false,
            }
        })
        .collect())
}

/// 扫描快照仓 `Packages/` 下的 RPM，返回 NEVRA（文件名去 `.rpm` 后缀）→ 条目，
/// sha256 逐文件现算——reproduce Phase-1 闸门把快照仓并入已验集合时用它独立
/// 自证，不复用恢复时的校验结论（文件可能事后被篡改/半写）。不回写
/// package_cache：恢复阶段已按记录 sha 回填。`Packages/` 缺失按空集放行，闸门
/// 对缺失包自会 fail-safe；单文件 hash 失败跳过（warn 汇总），该包由闸门按
/// missing 判定。
// ponytail: 串行哈希——快照包量级（百级 × MB 级）秒内完成；更大再借
// index_rpm_files 的 JoinSet 并发。
pub async fn scan_repo_packages(repo_dir: &Path) -> crate::Result<HashMap<String, CacheEntry>> {
    let rpm_dir = repo_dir.join("Packages");
    let mut entries = match tokio::fs::read_dir(&rpm_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(CrbsError::from_io_context("read snapshot repo Packages", e)),
    };

    let mut hash_fails = HashFailures::default();
    let mut index: HashMap<String, CacheEntry> = HashMap::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("iterate snapshot repo Packages", e))?
    {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // 单次剥 ".rpm" 口径同 unique_rpm_files / cache_one_rpm。
        let Some(nevra) = file_name.strip_suffix(".rpm") else {
            continue;
        };
        let sha = match compute_file_sha256(&path).await {
            Ok(sha) => sha,
            Err(e) => {
                if hash_fails.first.is_none() {
                    hash_fails.first = Some((path.clone(), e.to_string()));
                }
                hash_fails.count += 1;
                continue;
            }
        };
        index.insert(
            nevra.to_string(),
            CacheEntry {
                sha256: sha,
                repo_id: None,
            },
        );
    }
    if let Some((path, err)) = hash_fails.first.as_ref() {
        warn!(
            path = %path.display(),
            error = %err,
            failures = hash_fails.count,
            "Failed to hash snapshot repo RPM file(s), skipping them"
        );
    }
    Ok(index)
}

/// 缓存单个 RPM：计算 SHA256 并复制到 package_cache。非 `.rpm` 文件名或
/// hash 失败返回 `Ok(None)`，I/O 错误返回 `Err`；`skip_existing` 命中时跳过
/// 哈希直接复用——内容寻址须先 hash 定位 dest，已知映射是唯一免 hash 途径。
async fn cache_one_rpm(
    rpm_path: &Path,
    repo_id: Option<&str>,
    package_cache: &Path,
    skip_existing: Option<&HashMap<String, CacheEntry>>,
    hash_fails: &std::sync::Mutex<HashFailures>,
) -> crate::Result<Option<(String, CacheEntry)>> {
    let file_name = rpm_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !file_name.ends_with(".rpm") {
        return Ok(None);
    }
    // 上方 ends_with 守卫保证后缀存在；单次剥离口径同 unique_rpm_files。
    let nevra = file_name
        .strip_suffix(".rpm")
        .unwrap_or(file_name)
        .to_string();

    if let Some(known) = skip_existing {
        if let Some(entry) = known.get(&nevra) {
            // sha256 来自 lockfile（外部输入，可能损坏/被篡改）：join 前校验格式，
            // 1 字符值会让 `&sha[..2]` panic、`../` 会路径穿越。
            if !is_sha256_hex(&entry.sha256) {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "invalid sha256 {:?} in cache entry for {} (corrupt lockfile?)",
                        entry.sha256, nevra
                    ),
                });
            }
            // 已知映射：仅当缓存文件仍在时才跳过哈希（一次 stat 替代 GB 级
            // 重读）；缓存被 GC 删除的包仍需走正常 hash+copy 补全。
            let dest = package_cache
                .join(&entry.sha256[..2])
                .join(&entry.sha256)
                .join(file_name);
            if tokio::fs::try_exists(&dest).await.unwrap_or(false) {
                return Ok(Some((nevra, entry.clone())));
            }
        }
    }

    let sha = match compute_file_sha256(rpm_path).await {
        Ok(s) => s,
        Err(e) => {
            {
                let mut agg = hash_fails.lock().unwrap_or_else(|p| p.into_inner());
                agg.count += 1;
                if agg.first.is_none() {
                    agg.first = Some((rpm_path.to_path_buf(), e.to_string()));
                }
            }
            return Ok(None);
        }
    };

    let prefix = &sha[..2];
    let prefix_dir = package_cache.join(prefix);
    let cache_dir = prefix_dir.join(&sha);
    let dest = cache_dir.join(file_name);
    let dest_exists = tokio::fs::metadata(&dest)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false);
    if !dest_exists {
        // 缓存目录（含 prefix 层）规范为 crbs 组共享可写（跨身份写入）。
        crate::engine::shared_dir::ensure_shared_dir(&prefix_dir).await?;
        crate::engine::shared_dir::ensure_shared_dir(&cache_dir).await?;
        // 用唯一临时文件 + rename，避免并发拷贝时目标文件被截断。
        let tmp_name = format!(".{}.{}.tmp", file_name, uuid::Uuid::new_v4());
        let tmp_path = cache_dir.join(tmp_name);
        if let Err(e) = tokio::fs::copy(rpm_path, &tmp_path).await {
            if let Err(e2) = tokio::fs::remove_file(&tmp_path).await {
                warn!(path = %tmp_path.display(), error = %e2, "Failed to clean up cache tmp file");
            }
            return Err(CrbsError::from_io_context("copy to cache tmp", e));
        }
        // 源文件可能在 hash 与 copy 之间被改（TOCTOU）：rename 前对 tmp 重算
        // sha256，不一致按 miss 跳过，不得把名实不符文件落进内容寻址缓存。
        match compute_file_sha256(&tmp_path).await {
            Ok(actual) if actual == sha => {}
            Ok(actual) => {
                warn!(
                    path = %rpm_path.display(), expected = %sha, actual,
                    "RPM changed during cache copy, skipping"
                );
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Ok(None);
            }
            Err(e) => {
                warn!(
                    path = %tmp_path.display(), error = %e,
                    "Failed to re-hash cache tmp file, skipping"
                );
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Ok(None);
            }
        }
        sync_tmp_before_rename(&tmp_path).await?;
        if let Err(e) = tokio::fs::rename(&tmp_path, &dest).await {
            if let Err(e2) = tokio::fs::remove_file(&tmp_path).await {
                warn!(path = %tmp_path.display(), error = %e2, "Failed to clean up cache tmp file after rename");
            }
            return Err(CrbsError::from_io_context("rename cache ->", e));
        }
        normalize_cache_file_perms(&dest).await;
    }

    let repo_id = repo_id.map(normalize_repo_id);

    Ok(Some((
        nevra,
        CacheEntry {
            sha256: sha,
            repo_id,
        },
    )))
}

/// 从 package_cache 恢复指定包到临时 repo 目录（--reproduce 用）：cache-first
/// 按 SHA256 取 RPM，未命中按 `url` 下载校验并回填 cache，最后 createrepo_c。
///
/// 空 `sha256` 条目跳过恢复（旧构建 / provenance 缺 .packages.json，与
/// `reproduce::expected_packages_from` 口径一致：不恢复也不校验）。其余失败
/// 即报错退出（非 warning）：
/// - `sha256` 非空但非法 → `ValidationFailed`（join 前拦截路径穿越 / panic）
/// - `nevra` 含路径分隔符 / `..` / NUL / 空 → `ValidationFailed`（单咽喉校验）
/// - cache 未命中且 `url` 为空 → `ValidationFailed`（本就不该复现该包）
/// - 下载 / 校验失败 → 见 `download_url_verified`
///
/// 返回 (TempDir, repo 目录, 恢复数量)；调用者须持有 TempDir 直到不再需要 repo。
pub async fn restore_packages_to_repo(
    packages: &[crate::state::BuildPackage],
    package_cache: &Path,
    tmp_dir: &Path,
    cancel: Option<&tokio_util::sync::CancellationToken>,
) -> crate::Result<(tempfile::TempDir, std::path::PathBuf, usize)> {
    let tmp_dir = tmp_dir.to_path_buf();
    let temp_dir = spawn_blocking_tempdir_in(tmp_dir, "temp repo dir").await?;
    let repo_dir = temp_dir.path().to_path_buf();

    // 主体收进 async 块单点收口：任一 Err 早退不得让含数百硬链的 temp repo
    // 在 async 线程同步 remove_dir_all——统一由 TempDirGuard Drop 移交
    // spawn_blocking 清理。
    let mut temp_dir_guard = TempDirGuard::new(temp_dir);
    let restored = match async {
        let rpm_dir = repo_dir.join("Packages");
        tokio::fs::create_dir_all(&rpm_dir)
            .await
            .map_err(|e| CrbsError::from_io_context("create Packages dir", e))?;

        let mut restored = 0usize;
        for pkg in packages {
            // 取消后不再继续按 url 下载/回填后续包（每个包仍可能较大，
            // 包间检查是低成本上界；已恢复内容随 TempDirGuard 清理）。
            if cancel.is_some_and(|t| t.is_cancelled()) {
                return Err(CrbsError::Cancelled);
            }
            // 空 sha256 跳过恢复（口径见上方 doc）；非空非法在下方拦截。
            if pkg.sha256.is_empty() {
                continue;
            }
            // sha256 来自 build_packages.json（外部输入，可能损坏/被篡改）：join 前校验
            // 格式，1 字符值会让 `&sha[..2]` panic、`../` 会路径穿越。
            if !is_sha256_hex(&pkg.sha256) {
                return Err(CrbsError::ValidationFailed {
                    message: format!(
                        "package {} has invalid sha256 {:?} (corrupt build_packages.json?)",
                        pkg.nevra, pkg.sha256
                    ),
                });
            }
            let cache_subdir = package_cache.join(&pkg.sha256[..2]).join(&pkg.sha256);

            if cache_subdir_has_rpm(&cache_subdir).await? {
                restored += place_cached_rpms(&cache_subdir, &rpm_dir, &pkg.nevra).await?;
            } else {
                // 未命中（含空子目录）：按 url 下载校验、回填 cache 后放入 repo
                let url = pkg.url.as_deref().unwrap_or("");
                if url.is_empty() {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "package {} missing from cache and has no url; \
                             not recordable for reproduce (reproduce may not have been enabled, \
                             or provenance collection failed)",
                            pkg.nevra
                        ),
                    });
                }
                // 回填 cache：下载到子目录内 tmp 后 rename，后续复现免重复下载。
                backfill_cache_from_url(url, &pkg.sha256, &cache_subdir, &pkg.nevra).await?;
                restored += place_cached_rpms(&cache_subdir, &rpm_dir, &pkg.nevra).await?;
            }
        }

        if restored == 0 {
            return Err(CrbsError::io_message("No packages restored from cache"));
        }
        if cancel.is_some_and(|t| t.is_cancelled()) {
            return Err(CrbsError::Cancelled);
        }
        debug!(count = restored, "Restored packages to temp repo");

        // createrepo_c 在 repo 根目录运行生成 repodata/；RPM 在 Packages/ 下
        crate::engine::repo::run_createrepo_c(&repo_dir, false).await?;
        Ok(restored)
    }
    .await
    {
        Ok(restored) => restored,
        // temp repo 清理由 temp_dir_guard Drop 兜底。
        Err(e) => return Err(e),
    };

    // 成功：disarm 取回 TempDir 交还调用方（doc 契约：持有到不再需要 repo）。
    let temp_dir = temp_dir_guard
        .disarm()
        .ok_or_else(|| CrbsError::io_message("temp repo dir guard already disarmed"))?;
    Ok((temp_dir, repo_dir, restored))
}

/// tempdir_in 经 spawn_blocking 创建（tempfile 建目录是同步阻塞 IO，不落
/// async worker；Drop 的同步 remove_dir_all 移交纪律由 TempDirGuard / 调用方
/// 负责）。`label` 进两段错误语境（`spawn_blocking {label}` / `create {label}`）。
pub async fn spawn_blocking_tempdir_in(
    dir: PathBuf,
    label: &str,
) -> crate::Result<tempfile::TempDir> {
    tokio::task::spawn_blocking(move || tempfile::tempdir_in(dir))
        .await
        .map_err(|e| CrbsError::io_message(format!("spawn_blocking {label}: {e}")))?
        .map_err(|e| CrbsError::from_io_context(format!("create {label}"), e))
}

/// 失败路径 tempdir 清理守卫：guard 持有 `TempDir`，任一 Err 早退（含 `?` 与
/// panic）由 Drop 兜底——`TempDir` 的 Drop 是同步 `remove_dir_all`，repo 可能
/// 含数百硬链，须移交 blocking 池而非 tokio worker；成功路径 [`Self::disarm`]
/// 取回所有权。Drop 不能 await：fire-and-forget `spawn_blocking`，完成时序
/// 相对错误返回点放宽（残留兜底同 tmp_sweep `.tmp` 前缀清扫）。
pub struct TempDirGuard {
    dir: Option<tempfile::TempDir>,
}

impl TempDirGuard {
    /// 持有 `TempDir` 建 guard：Drop 兜底清理直至被 [`Self::disarm`] 消解。
    pub fn new(dir: tempfile::TempDir) -> Self {
        Self { dir: Some(dir) }
    }

    /// 消解 Drop 清理并取回 `TempDir` 所有权；已消解过则返回 `None`。
    pub fn disarm(&mut self) -> Option<tempfile::TempDir> {
        self.dir.take()
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            // runtime 之外 Drop 仅 warn 不 panic（泄漏交 tmp_sweep 兜底）。
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn_blocking(move || drop(dir));
                }
                Err(_) => {
                    warn!(
                        "TempDirGuard dropped outside a tokio runtime; temp dir leaks to sweeper"
                    );
                }
            }
        }
    }
}

/// 将 `cache_subdir` 下的 `.rpm` 硬链到 `rpm_dir`，返回放置数量；跨文件
/// 系统回退复制（避免 symlink 在 bind mount/nspawn 中失效）。
async fn place_cached_rpms(
    cache_subdir: &Path,
    rpm_dir: &Path,
    nevra: &str,
) -> crate::Result<usize> {
    let mut entries = tokio::fs::read_dir(cache_subdir)
        .await
        .map_err(|e| CrbsError::from_io_context("read cache dir", e))?;
    let mut placed = 0usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("read cache entry", e))?
    {
        let path = entry.path();
        if path.extension().map(|e| e == "rpm").unwrap_or(false) {
            let name = path.file_name().ok_or_else(|| {
                CrbsError::io_message(format!(
                    "cache rpm path has no file name: {}",
                    path.display()
                ))
            })?;
            let dest = rpm_dir.join(name);
            if tokio::fs::hard_link(&path, &dest).await.is_err() {
                tokio::fs::copy(&path, &dest)
                    .await
                    .map_err(|e| CrbsError::from_io_context("copy", e))?;
            }
            placed += 1;
        }
    }
    if placed == 0 {
        return Err(CrbsError::io_message(format!(
            "package {} cache subdir has no rpm file: {}",
            nevra,
            cache_subdir.display()
        )));
    }
    Ok(placed)
}

/// cache 子目录中是否已有 `.rpm` 文件。命中只看文件而非目录存在：回填中途
/// 失败留空子目录，按目录判定会永久卡命中分支、无法走 url 回退重试。
/// NotFound 视为未命中，其他读目录错误按 I/O 错误上抛。
async fn cache_subdir_has_rpm(dir: &Path) -> crate::Result<bool> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(CrbsError::from_io_context("read cache dir", e)),
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| CrbsError::from_io_context("read cache entry", e))?
    {
        let is_file = entry
            .file_type()
            .await
            .map(|t| t.is_file())
            .unwrap_or(false);
        if is_file
            && entry
                .path()
                .extension()
                .map(|e| e == "rpm")
                .unwrap_or(false)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// url 回退回填 cache：下载到 `cache_subdir` 内 uuid 临时文件，sha256 校验
/// 通过后 rename 到内容寻址路径（镜像 [`cache_one_rpm`] 的 tmp+rename）。
/// 不得直接下载到最终路径：`File::create` 截断会损坏并发进程已硬链进 repo
/// 的同一 inode，或把半写文件硬链走。
async fn backfill_cache_from_url(
    url: &str,
    sha256: &str,
    cache_subdir: &Path,
    nevra: &str,
) -> crate::Result<()> {
    // 镜像漂移可观测：cache 未命中走 url 回填 = 本地缓存已不含记录快照（TTL
    // 淘汰或上游镜像漂移均可致），内容由 sha256 校验兜底（不符即硬失败），措辞
    // 保持中性不预判漂移；留痕 nevra+url 供漂移审计。
    warn!(
        nevra = %nevra,
        url = %url,
        "cache miss (evicted or upstream drift); backfilling from recorded url"
    );
    // nevra 校验前置于任何文件系统副作用：非法值不得留半建 cache 目录。
    let file_name = rpm_name_from_nevra(nevra)?;
    // 补齐全父链权限（2770 目录 + crbs 组），口径同 cache_one_rpm。
    crate::engine::shared_dir::ensure_shared_dir(cache_subdir).await?;
    let dest = cache_subdir.join(&file_name);
    let tmp_name = format!(".{}.{}.tmp", file_name.display(), uuid::Uuid::new_v4());
    let tmp_path = cache_subdir.join(tmp_name);
    // download_url_verified 部分失败路径（如 write chunk）不清理，此处兜底删。
    if let Err(e) = download_url_verified(url, &tmp_path, sha256).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e);
    }
    // rename 前 fsync：download_url_verified 末尾已 sync，此处廉价兜底，使
    // rename 站点不依赖远处不变量。
    sync_tmp_before_rename(&tmp_path).await?;
    if let Err(e) = tokio::fs::rename(&tmp_path, &dest).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(CrbsError::from_io_context("rename cache ->", e));
    }
    normalize_cache_file_perms(&dest).await;
    Ok(())
}

/// 规范化缓存 RPM 文件权限：0660 + crbs 组。
///
/// copy 保留源 bits、下载默认 0644，组内其他身份不可写。chmod 失败仅 warn；
/// chown 失败仅 debug（非 root chown 必然 EPERM，见 privilege 模块）。
pub(crate) async fn normalize_cache_file_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await
        {
            warn!(path = %path.display(), error = %e, "Failed to set cache rpm mode 0660");
        }
    }
    crate::privilege::chown_to_crbs_group_async(path, false, "cache rpm").await;
}

/// 流式下载 `url` 到 `dest`，边写边算 sha256，下完与 `expected_sha256` 比对
///（reproduce 的 url 回退用）。任何失败都视为构建失败（error 退出，非 warning）：
/// - 空 url / 空 `expected_sha256` → `ValidationFailed`
/// - 网络错误 / 非 2xx → `Network`
/// - sha256 与期望不符 → `ValidationFailed`（内容损坏或仓库返回错误的包）
async fn download_url_verified(url: &str, dest: &Path, expected_sha256: &str) -> crate::Result<()> {
    if url.trim().is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "download failed: url is empty (package not recordable for reproduce)".into(),
        });
    }
    if expected_sha256.trim().is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: format!("download failed: expected sha256 is empty for {}", url),
        });
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        // TCP 黑洞（对端不回包）时 10s 即失败，不吃满 600s 总超时。
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| CrbsError::io_message(format!("build http client for download: {}", e)))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("download {}: {}", url, e),
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(CrbsError::Network {
            message: format!("download {}: HTTP {} {}", url, status, text),
        });
    }

    // 确保目标目录存在（幂等兜底）。
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| CrbsError::from_io_context("create download dest dir", e))?;
    }

    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| CrbsError::from_io_context("create download dest file", e))?;

    let mut hasher = sha2::Sha256::new();
    let mut resp = resp;
    let mut downloaded: u64 = 0;
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(CrbsError::Network {
                    message: format!("read chunk from {}: {}", url, e),
                });
            }
        };
        downloaded += chunk.len() as u64;
        if downloaded > MAX_DOWNLOAD_BYTES {
            let _ = tokio::fs::remove_file(dest).await;
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "download {}: exceeds {} byte size limit, aborted",
                    url, MAX_DOWNLOAD_BYTES
                ),
            });
        }
        file.write_all(&chunk)
            .await
            .map_err(|e| CrbsError::from_io_context("write downloaded chunk", e))?;
        hasher.update(&chunk);
    }

    file.flush()
        .await
        .map_err(|e| CrbsError::from_io_context("flush downloaded file", e))?;
    // fsync：数据先于调用方 backfill 的 rename 落盘（见 sync_tmp_before_rename）。
    file.sync_all()
        .await
        .map_err(|e| CrbsError::from_io_context("sync cached rpm before rename", e))?;

    let actual = hex::encode(hasher.finalize());
    if actual != expected_sha256 {
        let _ = tokio::fs::remove_file(dest).await;
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "download {}: sha256 mismatch (expected {}, got {})",
                url, expected_sha256, actual
            ),
        });
    }

    debug!(url = %url, sha256 = %actual, "Downloaded and verified package");

    // 下载后规范到 0660 + crbs 组：root 下载默认 group=root，其他身份覆盖重下
    // 会 EACCES。调用方 rename 后还会再规范化，此处保证 tmp 不违反不变量。
    normalize_cache_file_perms(dest).await;

    Ok(())
}

/// 从 nevra 推导 rpm 文件名（追加 `.rpm`）。
///
/// nevra 来自 build_packages.json（外部输入，可能损坏/被篡改）：裸
/// `PathBuf::from(nevra)` 的绝对路径或 `../` 分量会让 join 逃出 cache 目录
/// 任意路径写——本函数是 nevra→路径消费点的单咽喉，经
/// [`crate::util::validate_pkg_name`] 拒空 / `/` / NUL / `..` 分量，非法
/// 返回 `ValidationFailed`。
fn rpm_name_from_nevra(nevra: &str) -> crate::Result<PathBuf> {
    if let Err(e) = crate::util::validate_pkg_name(nevra) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "package has invalid nevra {nevra:?} (corrupt build_packages.json?): {e}"
            ),
        });
    }
    Ok(PathBuf::from(format!("{}.rpm", nevra)))
}

/// 清单类 JSON（.packages.json/.lockfile）跨身份重写的权限修正：原子写出的
/// 文件受 umask 影响（root 022 → 0644），其他 crbs 身份下次重写会 EACCES。
async fn fix_manifest_perms(path: &Path) {
    fix_shared_file_perms(path, "manifest file", "cross-identity rewrite may fail").await;
}

/// 跨身份重写文件的权限修正（fix_manifest_perms / fix_layer_file_perms 单源）：
/// 创建者 umask 会留 0644，另一 crbs 身份的重写/重建会因截断写 EACCES——条件
/// chmod 0660（失败 warn，`label` 点名文件、`warn_tail` 点名语境后果）+ chown
/// crbs 组（失败 debug，非 root chown 必然 EPERM，见 privilege 模块）。
pub(crate) async fn fix_shared_file_perms(path: &Path, label: &'static str, warn_tail: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let need_fix = match tokio::fs::metadata(path).await {
            Ok(m) => m.permissions().mode() & 0o777 != 0o660,
            // 查不到 metadata 属异常（刚建好即被并发删除等）：仍尝试 chmod，不静默跳过。
            Err(_) => true,
        };
        if need_fix {
            if let Err(e) =
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await
            {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to set {label} mode 0660; {warn_tail}"
                );
            }
        }
        crate::privilege::chown_to_crbs_group_async(path, false, label).await;
    }
}

/// 将 base_os 包清单（NEVRA → CacheEntry）写入指定路径。
pub async fn write_packages_json(
    path: &Path,
    packages: &HashMap<String, CacheEntry>,
) -> crate::Result<()> {
    // 使用 BTreeMap 保证输出顺序确定，便于 diff/checksum 校验。
    let sorted: BTreeMap<String, CacheEntry> = packages
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    write_json_atomic(path, &sorted)
        .await
        .map_err(|e| CrbsError::io_message(format!("write packages.json: {}", e)))?;
    fix_manifest_perms(path).await;
    Ok(())
}

/// 从指定路径读取 base_os 包清单（NEVRA → CacheEntry）。
pub async fn read_packages_json(path: &Path) -> crate::Result<HashMap<String, CacheEntry>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| CrbsError::from_io_context("read packages.json", e))?;
    let packages: HashMap<String, CacheEntry> = serde_json::from_str(&content)
        .map_err(|e| CrbsError::io_message(format!("parse packages.json: {}", e)))?;
    Ok(packages)
}

/// 将 lockfile（NEVRA → CacheEntry JSON）写入指定路径。
pub async fn write_lockfile(path: &Path, index: &HashMap<String, CacheEntry>) -> crate::Result<()> {
    // 使用 BTreeMap 保证输出顺序确定，便于 diff/checksum 校验。
    let sorted: BTreeMap<String, CacheEntry> =
        index.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    write_json_atomic(path, &sorted)
        .await
        .map_err(|e| CrbsError::io_message(format!("write lockfile: {}", e)))?;
    fix_manifest_perms(path).await;
    Ok(())
}

/// 从 lockfile 读取 NEVRA → CacheEntry 索引；兼容旧格式（NEVRA → SHA256
/// 字符串），读取时自动转换为 repo_id=None。
pub async fn read_lockfile_index(path: &Path) -> crate::Result<HashMap<String, CacheEntry>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| CrbsError::from_io_context("read lockfile", e))?;
    if let Ok(index) = serde_json::from_str::<HashMap<String, CacheEntry>>(&content) {
        return Ok(index);
    }
    let old: HashMap<String, String> = serde_json::from_str(&content)
        .map_err(|e| CrbsError::io_message(format!("parse lockfile: {}", e)))?;
    Ok(old
        .into_iter()
        .map(|(k, v)| {
            (
                k,
                CacheEntry {
                    sha256: v,
                    repo_id: None,
                },
            )
        })
        .collect())
}

async fn collect_rpm_files(dir: &Path) -> crate::Result<Vec<(std::path::PathBuf, Option<String>)>> {
    let mut result = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        // read_dir / 迭代出错必须传播：`while let Ok(Some(..))` 会把 IO 错误
        // 当迭代结束，索引静默截断仍伪装成"扫描完成"。
        let mut entries = tokio::fs::read_dir(&current)
            .await
            .map_err(|e| CrbsError::from_io_context("read dnf cache dir", e))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| CrbsError::from_io_context("iterate dnf cache dir", e))?
        {
            let path = entry.path();
            let is_dir = match entry.file_type().await {
                Ok(ft) => ft.is_dir(),
                Err(_) => continue,
            };
            if is_dir {
                dirs.push(path);
            } else if path.extension().map(|e| e == "rpm").unwrap_or(false) {
                let repo_id = path
                    .parent()
                    .and_then(|p| p.parent())
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .map(|s| s.to_string());
                result.push((path, repo_id));
            }
        }
    }
    Ok(result)
}

/// 流式计算文件 sha256（spawn_blocking，64 KiB 分块）。
pub(crate) async fn compute_file_sha256(path: &Path) -> crate::Result<String> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file =
            std::fs::File::open(&path).map_err(|e| CrbsError::from_io_context("open", e))?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| CrbsError::from_io_context("read", e))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking sha256: {}", e)))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_write_json_atomic_creates_valid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.json");
        let mut data = HashMap::new();
        data.insert(
            "key".to_string(),
            CacheEntry {
                sha256: "abc123".to_string(),
                repo_id: Some("base".to_string()),
            },
        );

        write_json_atomic(&path, &data).await.unwrap();

        assert!(path.exists());
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let parsed: HashMap<String, CacheEntry> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["key"].sha256, "abc123");
    }

    #[tokio::test]
    async fn test_write_json_atomic_leaves_no_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.json");
        let data: HashMap<String, CacheEntry> = HashMap::new();

        write_json_atomic(&path, &data).await.unwrap();

        let mut entries = tokio::fs::read_dir(tmp.path()).await.unwrap();
        let mut count = 0;
        while entries.next_entry().await.unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 1, "only the target JSON should exist");
    }

    /// NEVRA 缓存键单次剥 ".rpm"：`x.rpm.rpm` 剥成 `x.rpm`，不与剥成 `x` 的
    /// `x.rpm` 在去重时误合并成一个条目。
    #[tokio::test]
    async fn unique_rpm_files_strips_suffix_once() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("hello-1.0-1.noarch.rpm"), b"x")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("hello-1.0-1.noarch.rpm.rpm"), b"x")
            .await
            .unwrap();

        let files = unique_rpm_files(tmp.path()).await.unwrap();
        assert_eq!(
            files.len(),
            2,
            "double-suffixed file must not dedup-merge with the plain one"
        );
    }

    /// 快照 Packages 扫描：文件名去 `.rpm` 为键、sha256 现算自证（对
    /// TEST_PAYLOAD 算出 TEST_SHA256）、非 `.rpm` 文件跳过；`.rpm.rpm` 单次剥
    /// 离口径与 unique_rpm_files 一致。
    #[tokio::test]
    async fn scan_repo_packages_hashes_flat_packages_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let packages = tmp.path().join("repo").join("Packages");
        tokio::fs::create_dir_all(&packages).await.unwrap();
        tokio::fs::write(packages.join("hello-1.0-1.x86_64.rpm"), TEST_PAYLOAD)
            .await
            .unwrap();
        tokio::fs::write(packages.join("hello-1.0-1.x86_64.rpm.rpm"), b"x")
            .await
            .unwrap();
        tokio::fs::write(packages.join("notes.txt"), b"not an rpm")
            .await
            .unwrap();

        let index = scan_repo_packages(&tmp.path().join("repo")).await.unwrap();
        assert_eq!(index.len(), 2, "only .rpm files enter the index");
        assert_eq!(
            index["hello-1.0-1.x86_64"].sha256, TEST_SHA256,
            "sha256 must be freshly computed from file content"
        );
        assert_eq!(index["hello-1.0-1.x86_64"].repo_id, None);
        // 单次剥 ".rpm"：双后缀文件的键剥成 "hello-1.0-1.x86_64.rpm"。
        assert!(index.contains_key("hello-1.0-1.x86_64.rpm"));
    }

    /// Packages/ 缺失（restore 未建/目录被清）按空集放行：闸门对 expected 缺包
    /// 自会 fail-safe，扫描不得误报 IO 错误。
    #[tokio::test]
    async fn scan_repo_packages_tolerates_missing_packages_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let index = scan_repo_packages(tmp.path()).await.unwrap();
        assert!(index.is_empty());
    }

    // ---- download_url_verified 测试 ----

    const TEST_PAYLOAD: &[u8] = b"hello-reproduce";
    const TEST_SHA256: &str = "4c125c7d2f71d00ef80d442cdb81872b25d448c47e92e92302f3c1f6516c5a60";

    /// 起一个单次请求的最小 HTTP 服务，返回 `http://127.0.0.1:{port}/pkg`。
    /// `corrupt`：200 但 body 篡改；`not_found`：404。
    async fn spawn_http_server(corrupt: bool, not_found: bool) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}/pkg", addr);

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // 读取并丢弃请求行/头部（读到空行或缓冲满即可）。
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; 1024];
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut buf))
                    .await;

            let body = if corrupt {
                b"corrupted-bytes".to_vec()
            } else {
                TEST_PAYLOAD.to_vec()
            };
            let (status_line, body) = if not_found {
                ("HTTP/1.1 404 Not Found", Vec::new())
            } else {
                ("HTTP/1.1 200 OK", body)
            };
            let resp = format!(
                "{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status_line,
                body.len()
            );
            use tokio::io::AsyncWriteExt;
            let _ = sock.write_all(resp.as_bytes()).await;
            if !body.is_empty() {
                let _ = sock.write_all(&body).await;
            }
        });

        url
    }

    #[tokio::test]
    async fn download_url_verified_success() {
        let url = spawn_http_server(false, false).await;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg.rpm");

        download_url_verified(&url, &dest, TEST_SHA256)
            .await
            .unwrap();

        assert_eq!(tokio::fs::read(&dest).await.unwrap(), TEST_PAYLOAD);
    }

    #[tokio::test]
    async fn download_url_verified_404() {
        let url = spawn_http_server(false, true).await;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg.rpm");

        let err = download_url_verified(&url, &dest, TEST_SHA256)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CrbsError::Network { .. }),
            "expected Network, got {:?}",
            err
        );
        assert!(!dest.exists(), "partial file should not remain");
    }

    #[tokio::test]
    async fn download_url_verified_sha256_mismatch() {
        let url = spawn_http_server(true, false).await;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg.rpm");

        let err = download_url_verified(&url, &dest, TEST_SHA256)
            .await
            .unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("mismatch"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
        assert!(!dest.exists(), "corrupt file should be cleaned up");
    }

    #[tokio::test]
    async fn download_url_verified_empty_url_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg.rpm");

        let err = download_url_verified("", &dest, TEST_SHA256)
            .await
            .unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }));
    }

    #[tokio::test]
    async fn download_url_verified_empty_sha256_rejected() {
        let url = spawn_http_server(false, false).await;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("pkg.rpm");

        let err = download_url_verified(&url, &dest, "").await.unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }));
    }

    // ---- sha256 校验（join 前置）测试 ----

    #[test]
    fn test_is_sha256_hex() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(is_sha256_hex(&"0123456789abcdef".repeat(4)));
        assert!(!is_sha256_hex("a")); // 1 字符会让 `&sha[..2]` 切片 panic
        assert!(!is_sha256_hex("../../evil")); // 路径穿越
        assert!(!is_sha256_hex(""));
        assert!(!is_sha256_hex(&"A".repeat(64))); // 大写不接受
        assert!(!is_sha256_hex(&"g".repeat(64))); // 非 hex
    }

    /// nevra→路径单咽喉校验：绝对路径 / `..` 分量 / 路径分隔符 / NUL / 空
    /// 一律 `ValidationFailed`；合法 NEVRA 照常推导 `<nevra>.rpm`。
    #[test]
    fn rpm_name_from_nevra_rejects_traversal_and_illegal_chars() {
        let ok = rpm_name_from_nevra("bzip2-1.0.8-6.ule3.x86_64")
            .unwrap_or_else(|e| panic!("valid nevra rejected: {e}"));
        assert_eq!(ok, PathBuf::from("bzip2-1.0.8-6.ule3.x86_64.rpm"));

        let bads = [
            "/tmp/evil",      // 绝对路径：逃出 cache 目录
            "../../x",        // 显式穿越分量
            "a/../b",         // 内嵌穿越分量
            "pkg-1.0-1\0x86", // NUL
            "",               // 空
        ];
        for bad in bads {
            match rpm_name_from_nevra(bad) {
                Err(CrbsError::ValidationFailed { message }) => {
                    assert!(
                        message.contains("invalid nevra"),
                        "message must name the nevra check, got: {message}"
                    );
                    assert!(
                        message.contains("corrupt build_packages.json?"),
                        "message must hint at the corrupt manifest, got: {message}"
                    );
                }
                other => panic!("expected ValidationFailed for {bad:?}, got {other:?}"),
            }
        }
    }

    fn build_pkg_nevra(sha256: &str, nevra: &str) -> crate::state::BuildPackage {
        crate::state::BuildPackage {
            build_id: 1,
            nevra: nevra.to_string(),
            sha256: sha256.to_string(),
            repo: None,
            url: Some("http://127.0.0.1:1/pkg.rpm".to_string()),
        }
    }

    /// 恶意 nevra（合法 sha256 + 非空 url，走 cache-miss → backfill）在任何
    /// 文件系统副作用前被拒：cache 目录不创建、evil.rpm 不落盘。
    #[tokio::test]
    async fn restore_rejects_malicious_nevra_without_any_write() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_root = tmp.path().join("cache");
        let evil_nevra = tmp.path().join("evil");
        let err = restore_packages_to_repo(
            std::slice::from_ref(&build_pkg_nevra(TEST_SHA256, evil_nevra.to_str().unwrap())),
            &cache_root,
            tmp.path(),
            None,
        )
        .await
        .unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("invalid nevra"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
        assert!(
            !tmp.path().join("evil.rpm").exists(),
            "traversal nevra must not write outside the cache"
        );
        assert!(
            !cache_root.exists(),
            "rejected nevra must leave no cache directories behind"
        );
    }

    fn build_pkg(sha256: &str) -> crate::state::BuildPackage {
        crate::state::BuildPackage {
            build_id: 1,
            nevra: "pkg-1.0-1.x86_64".to_string(),
            sha256: sha256.to_string(),
            repo: None,
            url: Some("http://127.0.0.1:1/pkg.rpm".to_string()),
        }
    }

    #[tokio::test]
    async fn restore_rejects_malformed_sha256_before_any_join() {
        let tmp = tempfile::tempdir().unwrap();
        let bads = [
            "a".to_string(),
            "../../evil".to_string(),
            "A".repeat(64),
            "g".repeat(64),
        ];
        for bad in &bads {
            let err = restore_packages_to_repo(
                std::slice::from_ref(&build_pkg(bad)),
                &tmp.path().join("cache"),
                tmp.path(),
                None,
            )
            .await
            .unwrap_err();
            match err {
                CrbsError::ValidationFailed { message } => {
                    assert!(message.contains("invalid sha256"), "got: {}", message);
                }
                other => panic!("expected ValidationFailed, got {:?}", other),
            }
        }
    }

    /// Err 早退也回收 temp repo 目录：invalid sha256 早退后 tmp 域不得残留
    /// `.tmp` 目录（forget 式"跳过清理"的回归在此变红）。删除线程归属无法
    /// 外部断言，由 Err 臂统一走 TempDirGuard Drop 保证。
    #[tokio::test]
    async fn restore_err_path_removes_temp_repo_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let err = restore_packages_to_repo(
            std::slice::from_ref(&build_pkg(&"g".repeat(64))),
            &tmp.path().join("cache"),
            tmp.path(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "expected ValidationFailed, got {:?}",
            err
        );
        // guard Drop 是 fire-and-forget spawn_blocking，
        // 移除完成时序相对错误返回点放宽——deadline 轮询等待清空后再扫
        // （forget 式"跳过清理"回归在 deadline 后仍红）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut residue = false;
            let mut entries = tokio::fs::read_dir(tmp.path()).await.unwrap();
            while let Some(entry) = entries.next_entry().await.unwrap() {
                if entry.file_name().to_string_lossy().starts_with(".tmp") {
                    residue = true;
                }
            }
            if !residue || std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut entries = tokio::fs::read_dir(tmp.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            assert!(
                !entry.file_name().to_string_lossy().starts_with(".tmp"),
                "temp repo residue must be removed on Err path: {:?}",
                entry.file_name()
            );
        }
    }

    /// TempDirGuard 本体：drop 兜底删目录（fire-and-forget，deadline 轮询断言）。
    #[tokio::test]
    async fn temp_dir_guard_drop_removes_dir() {
        let base = tempfile::tempdir().unwrap();
        let path = {
            let dir = tempfile::tempdir_in(base.path()).unwrap();
            let p = dir.path().to_path_buf();
            let _guard = TempDirGuard::new(dir);
            p
        }; // guard Drop：挪 blocking 池删目录
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while path.exists() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(!path.exists(), "guard Drop must remove the temp dir");
    }

    /// disarm 后 Drop 不清理（目录保留给调用方）；重复消解返回 None。
    #[tokio::test]
    async fn temp_dir_guard_disarm_preserves_dir() {
        let base = tempfile::tempdir().unwrap();
        let mut guard = TempDirGuard::new(tempfile::tempdir_in(base.path()).unwrap());
        let dir = guard.disarm().unwrap();
        assert!(
            guard.disarm().is_none(),
            "second disarm must return None (already consumed)"
        );
        drop(guard); // 已消解：Drop 不得清理
        assert!(
            dir.path().exists(),
            "disarmed guard Drop must preserve the dir for its caller"
        );
    }

    #[tokio::test]
    async fn cache_one_rpm_rejects_malformed_skip_entry_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let rpm_path = tmp.path().join("pkg-1.0-1.x86_64.rpm");
        tokio::fs::write(&rpm_path, b"rpm-bytes").await.unwrap();
        for bad in ["a", "../../evil"] {
            let mut skip = HashMap::new();
            skip.insert(
                "pkg-1.0-1.x86_64".to_string(),
                CacheEntry {
                    sha256: bad.to_string(),
                    repo_id: None,
                },
            );
            // 1 字符值会让 `&entry.sha256[..2]` 切片 panic
            let hash_fails = std::sync::Mutex::new(HashFailures::default());
            let err = cache_one_rpm(
                &rpm_path,
                None,
                &tmp.path().join("cache"),
                Some(&skip),
                &hash_fails,
            )
            .await
            .unwrap_err();
            match err {
                CrbsError::ValidationFailed { message } => {
                    assert!(message.contains("invalid sha256"), "got: {}", message);
                }
                other => panic!("expected ValidationFailed, got {:?}", other),
            }
        }
    }

    // ---- 回填 tmp+rename 与空子目录回退测试 ----

    // ensure_shared_dir 在非 Linux / 无 crbs 组环境硬错，直调 backfill 的测试仅 Linux 跑。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn backfill_downloads_via_tmp_then_rename() {
        let url = spawn_http_server(false, false).await;
        let tmp = tempfile::tempdir().unwrap();
        let cache_subdir = tmp.path().join(&TEST_SHA256[..2]).join(TEST_SHA256);

        backfill_cache_from_url(&url, TEST_SHA256, &cache_subdir, "pkg-1.0-1.x86_64")
            .await
            .unwrap();

        let dest = cache_subdir.join("pkg-1.0-1.x86_64.rpm");
        assert!(dest.is_file(), "final content-addressed file should exist");
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), TEST_PAYLOAD);
        let mut entries = tokio::fs::read_dir(&cache_subdir).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.contains(".tmp"), "tmp file leaked: {}", name);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn backfill_into_preexisting_empty_subdir_succeeds() {
        // 回填中途失败留空子目录：命中判定不得按"目录存在"，须仍能 url 回退重下。
        let url = spawn_http_server(false, false).await;
        let tmp = tempfile::tempdir().unwrap();
        let cache_subdir = tmp.path().join(&TEST_SHA256[..2]).join(TEST_SHA256);
        tokio::fs::create_dir_all(&cache_subdir).await.unwrap();
        assert!(!cache_subdir_has_rpm(&cache_subdir).await.unwrap());

        backfill_cache_from_url(&url, TEST_SHA256, &cache_subdir, "pkg-1.0-1.x86_64")
            .await
            .unwrap();

        assert!(cache_subdir.join("pkg-1.0-1.x86_64.rpm").is_file());
    }

    #[tokio::test]
    async fn cache_subdir_has_rpm_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ab");

        assert!(!cache_subdir_has_rpm(&dir).await.unwrap());

        tokio::fs::create_dir_all(&dir).await.unwrap();
        assert!(!cache_subdir_has_rpm(&dir).await.unwrap());

        tokio::fs::write(dir.join("pkg.rpm"), b"x").await.unwrap();
        assert!(cache_subdir_has_rpm(&dir).await.unwrap());

        // 只有 .tmp 半成品 → 仍未命中
        tokio::fs::remove_file(dir.join("pkg.rpm")).await.unwrap();
        tokio::fs::write(dir.join(".pkg.rpm.uuid.tmp"), b"x")
            .await
            .unwrap();
        assert!(!cache_subdir_has_rpm(&dir).await.unwrap());
    }
}
