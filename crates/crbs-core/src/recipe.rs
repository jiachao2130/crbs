// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配方导出：每任务按需生成 `recipe.json`，拓扑 =
//! "1 canonical SRPM + N 份 per-arch 环境快照"，跨架构重放各取各的快照。
//! 数据源 = hub DB + 各 build 的 `build_packages.json`（落盘 `{result_dir}/{arch}/{build_id}/`）。
//!
//! 存储与引用：不新增 DB 列/表，路径 = `(tasks.result_dir, 固定文件名)` 纯函数，
//! `tasks.result_dir` 提交时落库为权威指针；`generated_at` 承担"已生成 + GC 钉住窗口内"两个判定。
//!
//! `repomd_sha256` 为生成时点的记录值、零缓存影响：正确性锚是 build_packages.json
//! 的 per-package sha256 + restore fail-fast，上游 repo 滚动后自然过期。
//!
//! GC：retention 窗口内（`recipe_retention_days`，默认 90 天）的
//! recipe.json 是免驱逐引用来源之一（`crate::gc` 侧实现）。

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::error::CrbsError;
use crate::state::StateStore;
use crate::util::db_now_utc;

/// recipe.json 固定文件名（存于 `tasks.result_dir` 下）。
pub(crate) const RECIPE_FILE_NAME: &str = "recipe.json";

/// 配方结构版本（不兼容变更递增）。v2 新增 `per_arch[].missing_unsigned_anchor`
///（旧文件不可回填，递增让 API 回读旧版本触发再生成）；`#[serde(default)]`
/// 保 v1 文件可解析。
pub const RECIPE_SCHEMA_VERSION: u32 = 2;

/// GC 钉住窗口默认值（与基线季度级重跑节奏匹配）。
pub(crate) const DEFAULT_RECIPE_RETENTION_DAYS: u64 = 90;

/// repomd.xml 抓取的响应大小上限（16 MiB，纯防御：正常 repomd 为 KB 量级）。
const MAX_REPOMD_BYTES: usize = 16 * 1024 * 1024;

/// repomd 抓取整体预算：全部 enabled repo 并行抓取共享的总 deadline（单请求
/// 另有 5s 短超时）；超预算的 repo 记 `repomd_fetch_error` 降级，不阻塞配方。
const REPOMD_FETCH_BUDGET: Duration = Duration::from_secs(10);

/// spec 插桩披露（如实披露；`deterministic` 不跳过插桩）。
pub const INSTRUMENTATION_DISCLOSURE: &str = "crbs instruments the build spec: \
generate_patch_bash rewrites the spec inside the build environment (echo phase \
markers inserted at the head of the %prep-%check sections, idempotent, executed \
unconditionally after rpm -Uvh); RPMBUILD_SUBPHASE_FILTER only filters rpmbuild \
stdout and never touches the spec or artifacts. The engine additionally redefines \
__brp_strip_static_archive via --define to run the static-archive strip script \
followed by the crbs-normalize helper at the tail of %install (the last step \
touching static archives): embedded timestamps and owner fields in ar/zip/gzip \
payloads under BUILDROOT are rewritten to the build time anchor; this mutates \
payload bytes inside the buildroot, not the spec. Net effect: with -bb (the \
default), binary RPM bytes are NOT affected (echo lines go to stdout only); the \
spec file intentionally differs from upstream; with -bs/-ba the instrumented \
spec would be embedded into a rebuilt SRPM and MUST differ from upstream (one \
reason deterministic mode forbids -ba).";

/// 宏块的来源标注：披露清单与 `merge_build_macros` 实际合并序对齐（product
/// rpm_macros、--dist、--with/--without 特性宏与 deterministic 宏组叠加于其上）。
const MACROS_SOURCE: &str = "task request_json --define set recorded at submit \
time; at build time the engine additionally merges product rpm_macros, --dist, \
--with/--without feature macros and the deterministic macro group on top \
(engine::build::execution::merge_build_macros), \
so the effective macro set can be a superset of this block";

/// env 块的来源标注。
const ENV_SOURCE: &str = "crbs engine injection baseline (single source \
engine::build::phase::DETERMINISTIC_ENV_BASELINE): LC_ALL=C is always injected; \
TZ / hash-seed entries are injected only in deterministic builds";

/// 脚本宏：生成 JSON 配方结构（`recipe.json` 的载荷）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub schema_version: u32,
    pub product: String,
    pub task_id: i64,
    /// 生成时点（DB TEXT 时间帧 `%Y-%m-%d %H:%M:%S` UTC；GC 钉住窗口据此判定）。
    pub generated_at: String,
    /// 血缘锚：输入 SRPM 原样字节的 sha256（builds.canonical_srpm_sha256，
    /// 任务内全部架构子构建共享）。非 deterministic 任务为 null。
    pub srpm_sha256: Option<String>,
    pub macros: LabeledBlock,
    pub env: LabeledBlock,
    pub ccache: CcacheDisclosure,
    pub instrumentation_disclosure: String,
    pub repos: Vec<RecipeRepo>,
    pub per_arch: Vec<RecipePerArch>,
}

/// 带来源标注的键值块（macros / env 共用形态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabeledBlock {
    pub source: String,
    /// BTreeMap：序列化按 key 稳定排序（配方逐字节可复现，同宏合并序惯例）。
    pub values: BTreeMap<String, String>,
}

/// ccache 状态披露（归因辅助）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CcacheDisclosure {
    pub enabled: bool,
    /// deterministic × ccache 时强制注入 `CCACHE_COMPILERCHECK=content`；
    /// 其余为 null（ccache 默认 compiler_check，如 mtime）。
    pub compiler_check: Option<String>,
    /// 守卫剔除的时间类 sloppiness 说明；无剔除时为空串。
    pub sloppy: String,
}

/// 单个 repo 的记录行（环境记录；`repomd_sha256` 见模块注释的"纯记录"语义）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeRepo {
    pub name: String,
    pub baseurl: String,
    /// 生成时点 repomd.xml 的 sha256；抓取失败为 null，原因记 `repomd_fetch_error`（不阻塞）。
    pub repomd_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repomd_fetch_error: Option<String>,
}

/// 单架构环境快照（拓扑的"每架构一份"）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipePerArch {
    pub arch: String,
    pub build_id: i64,
    pub base_os_digest: Option<String>,
    /// 该 build `build_packages.json` 内容的 sha256（快照定位锚；缺失为 null → 重放时重新下载）。
    pub build_packages_sha256: Option<String>,
    /// 签名前产物哈希留档（build_artifacts.unsigned_sha256）。
    pub unsigned_artifacts: Vec<UnsignedArtifactRef>,
    /// RPM 产物行存在但 `unsigned_sha256` 锚缺失（NULL）的文件名清单——不进
    /// 比对集、降级不阻塞但须披露（比对侧 `CompareDetail::missing_unsigned`
    /// 同名同义）；v2 新增，`#[serde(default)]` 保 v1 文件解析（缺字段 = 空 = 未记录）。
    #[serde(default)]
    pub missing_unsigned_anchor: Vec<String>,
}

/// 单个 RPM 产物的引用（文件名 + unsigned sha256）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedArtifactRef {
    pub name: String,
    pub sha256: String,
}

/// recipe.json 在任务结果目录下的固定路径。
pub fn recipe_path(task_result_dir: &Path) -> std::path::PathBuf {
    task_result_dir.join(RECIPE_FILE_NAME)
}

/// 读取已生成的 recipe.json；不存在 → `Ok(None)`。解析失败（半写/损坏）→ warn +
/// `Ok(None)`（调用方按需再生成，自愈优于永久 500）；例外：`schema_version`
///（`serde_json::Value` 宽松读）超前于当前版本 → `Conflict`（409），防再生成覆写丢未来字段。
pub async fn read_recipe_file(path: &Path) -> crate::Result<Option<Recipe>> {
    match tokio::fs::read_to_string(path).await {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(recipe) => Ok(Some(recipe)),
            Err(e) => {
                if raw_schema_version(&content).is_some_and(|v| v > RECIPE_SCHEMA_VERSION as u64) {
                    warn!(
                        path = %path.display(),
                        parse_error = %e,
                        "recipe.json is from a newer schema version and no longer parses; \
                         refusing to regenerate over it"
                    );
                    return Err(CrbsError::Conflict {
                        message: format!(
                            "recipe.json schema version is newer than this build supports ({}); \
                             refusing to regenerate over a future file — upgrade crbs to read it",
                            RECIPE_SCHEMA_VERSION
                        ),
                    });
                }
                warn!(path = %path.display(), error = %e, "Corrupt recipe.json; treating as absent (will regenerate)");
                Ok(None)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CrbsError::from_io_context("read recipe.json", e)),
    }
}

/// 宽松读原始 JSON 的 `schema_version`：结构不兼容也读得出，区分"未来版本文件"
///（拒再生成）与"半写/损坏"（自愈）；非 JSON/缺失/非数值均 `None`（按损坏自愈）。
fn raw_schema_version(content: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(content)
        .ok()?
        .get("schema_version")?
        .as_u64()
}

/// 原子写入 recipe.json 并落实文件权限不变量（group=crbs、mode 0660）：复用 engine
/// `write_json_atomic`（tmp + fsync + rename），并发生成最后 rename 者胜——两次生成
/// 内容可不等价（generated_at / repomd 随时点变化），读侧取 rename 胜者自洽即可；
/// 写后 chown 失败仅 debug（非 root 预期路径）、chmod 失败 warn（权限可能未生效）。
pub async fn write_recipe_atomic(
    task_result_dir: &Path,
    recipe: &Recipe,
) -> crate::Result<std::path::PathBuf> {
    let path = recipe_path(task_result_dir);
    crate::engine::cache::write_json_atomic(&path, recipe).await?;
    crate::privilege::chown_to_crbs_group_async(&path, false, "recipe.json").await;
    if let Err(e) = crate::privilege::chmod_async(&path, 0o660, false).await {
        warn!(path = %path.display(), error = %e, "chmod recipe.json to 0660 failed; permissions may be wider than intended");
    }
    Ok(path)
}

/// 组装任务的配方（不落盘）。失败语义：任务/产品记录缺失 NotFound；子构建未全部
/// 终态成功 Conflict；request_json 解析失败上抛（历史数据损坏显性暴露）；repomd
/// 抓取 / build_packages.json 缺失 / unsigned 锚缺失均降级（null + 说明）不阻塞。
/// 生成门禁：全部子构建 succeeded 才组装（空 children 同拒，空集全称量词恒真）——
/// 半成品缺锚被首次 GET 落盘永久钉进回读路径。
pub async fn build_task_recipe(store: &StateStore, task_id: i64) -> crate::Result<Recipe> {
    let task = store
        .get_task(task_id)
        .await?
        .ok_or_else(|| CrbsError::NotFound {
            message: format!("task {task_id} not found"),
        })?;
    let children = store.get_builds_by_task_id(task_id).await?;
    if children.is_empty() || children.iter().any(|b| b.phase != "succeeded") {
        return Err(CrbsError::Conflict {
            message: format!(
                "task {task_id} not fully succeeded; recipe generation requires terminal success"
            ),
        });
    }

    // 修剪分叉守卫：磁盘旧配方 per_arch 条目数 > 现存 children 数时拒覆写（旧全量
    // 文件原样保留）——retention 修剪 × 再生成触发时，按现存 children 再生成会产
    // 出缩水配方原子覆盖旧全量文件，被修剪 arch 的快照无回填来源，丢即永丢。只比
    // 条目数（同数不同内容的分叉不管）；损坏文件读到 None（自愈优先）不进本守卫。
    if let Some(dir) = task.result_dir.as_deref().filter(|d| !d.is_empty()) {
        if let Some(existing) = read_recipe_file(&recipe_path(Path::new(dir))).await? {
            if existing.per_arch.len() > children.len() {
                warn!(
                    task_id = task_id,
                    on_disk_per_arch = existing.per_arch.len(),
                    live_children = children.len(),
                    "recipe.json covers more per-arch entries than live children \
                     (retention pruned history); refusing to regenerate a shrunken recipe"
                );
                return Err(CrbsError::Conflict {
                    message: format!(
                        "recipe.json for task {task_id} covers {} per-arch entries but only {} \
                         child builds remain (retention pruned history); refusing to \
                         regenerate a shrunken recipe over the full file",
                        existing.per_arch.len(),
                        children.len()
                    ),
                });
            }
        }
    }
    let resolved = store.resolve_any_product_by_name(&task.product).await?;

    // 任务模式判定：子构建全 deterministic 才按 deterministic 记录（混打标保守按非；
    // 空集已在上方 Conflict 早退，此处 children 必非空）。
    let deterministic = children.iter().all(|b| b.deterministic);

    // 宏：tasks.request_json 的 --define 集（提交时已 validated，round-trip 安全）。
    let request_json = store
        .get_task_rebuild_info(task_id)
        .await?
        .and_then(|info| info.request_json);
    let macros: BTreeMap<String, String> = match request_json {
        Some(json) => {
            let opts: crate::BuildOptions = serde_json::from_str(&json).map_err(|e| {
                CrbsError::io_message(format!(
                    "parse recorded request_json of task {task_id} for recipe: {e}"
                ))
            })?;
            crate::build_options::parse_macros(&opts.define)?
        }
        None => {
            debug!(
                task_id = task_id,
                "Task has no request_json (local CLI gap); recipe macros empty"
            );
            BTreeMap::new()
        }
    };

    // env：与 engine 注入同源（DETERMINISTIC_ENV_BASELINE），非 deterministic
    // 任务只含无条件基线 LC_ALL=C；不含 replay 回放值（复刻走原 request_json 的 --define 面）。
    let env = crate::engine::build::phase::build_spawn_env(deterministic, None);

    // ccache（归因辅助）：enabled 按产品配置对本任务 SRPM 逐包判定（与
    // execution.rs 的 ccache_for_this_pkg 同一 helper；Option 缺省 = Bool(false)
    // 与引擎合并语义一致），compiler_check / sloppy 仅 deterministic × ccache 时
    // 为守卫值。精度兜底：srpm_path 缺失按 `{pkg_name}.src.rpm` 约定名推断
    // 可能不符；多 SRPM 任务取任务粒度单一判定（逐包精度以 builds 侧执行判定为准）。
    let srpm_name = task
        .srpm_path
        .as_deref()
        .map(|p| {
            Path::new(p)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{}.src.rpm", task.name));
    let ccache_enabled = resolved
        .config
        .ccache_enabled
        .clone()
        .unwrap_or_default()
        .is_enabled_for(&srpm_name);
    let ccache = CcacheDisclosure {
        enabled: ccache_enabled,
        compiler_check: (ccache_enabled && deterministic).then(|| "content".to_string()),
        sloppy: if ccache_enabled && deterministic {
            "CCACHE_SLOPPY stripped of time_macros/include_file_ctime by the ccache sloppy guard"
                .to_string()
        } else {
            String::new()
        },
    };

    // 血缘锚：任务内全部架构共享，取首个非空即可。
    let srpm_sha256 = children
        .iter()
        .find_map(|b| b.canonical_srpm_sha256.clone());

    let mut children_sorted: Vec<_> = children.iter().collect();
    children_sorted.sort_by_key(|b| (b.arch.clone().unwrap_or_default(), b.id));

    // 产物批量查询一次 IN 收敛 N+1；批量 SQL 排序 (build_id, kind, relative_path) 分组
    // 后组内序与单 build LIST_BY_BUILD (kind, relative_path) 一致，产出逐字节不变。
    let child_ids: Vec<i64> = children_sorted.iter().map(|b| b.id).collect();
    let mut artifacts_by_build: HashMap<i64, Vec<crate::state::artifacts::Artifact>> =
        HashMap::new();
    for a in store.list_artifacts_for_builds(&child_ids).await? {
        artifacts_by_build.entry(a.build_id).or_default().push(a);
    }

    let mut per_arch = Vec::with_capacity(children_sorted.len());
    for child in &children_sorted {
        let build_packages_sha256 = match locate_build_packages_path(child) {
            Some(path) => match crate::engine::cache::compute_file_sha256(&path).await {
                Ok(sha) => Some(sha),
                Err(e) => {
                    debug!(build_id = child.id, error = %e, "Failed to hash build_packages.json for recipe");
                    None
                }
            },
            None => {
                debug!(
                    build_id = child.id,
                    "build_packages.json not located; recipe per-arch snapshot anchor is null"
                );
                None
            }
        };
        // unsigned 留档只收 rpm 行：非 deterministic 任务的重造 SRPM 字节每次
        // 重造必不同，收录会暗示不成立的复现语义。锚缺失 rpm 行按块内
        // 契约降级不阻塞，文件名如实进 missing_unsigned_anchor（不静默丢行）。
        let mut unsigned_artifacts = Vec::new();
        let mut missing_unsigned_anchor = Vec::new();
        for a in artifacts_by_build.get(&child.id).into_iter().flatten() {
            if a.kind.as_str() != "rpm" {
                continue;
            }
            let name = std::path::Path::new(&a.relative_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| a.relative_path.clone());
            match a.unsigned_sha256.clone() {
                Some(sha256) => unsigned_artifacts.push(UnsignedArtifactRef { name, sha256 }),
                None => missing_unsigned_anchor.push(name),
            }
        }
        per_arch.push(RecipePerArch {
            arch: child.arch.clone().unwrap_or_default(),
            build_id: child.id,
            base_os_digest: child.base_os_digest.clone(),
            build_packages_sha256,
            unsigned_artifacts,
            missing_unsigned_anchor,
        });
    }

    // repos：仅记录 enabled 的（disabled repo 不构成构建环境）；$basearch/
    // $releasever 按任务首个架构与产品 releasever 替换后抓取（生成时点记录
    // 值，不参与指纹/正确性判定）。并行共享总预算，超预算记 error 不阻塞。
    let repomd_arch = children_sorted
        .iter()
        .find_map(|b| b.arch.clone())
        .unwrap_or_default();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| CrbsError::io_message(format!("build repomd fetch client: {e}")))?;
    let deadline = tokio::time::Instant::now() + REPOMD_FETCH_BUDGET;
    let mut repo_metas: Vec<(String, String)> = Vec::new();
    let mut fetches = Vec::with_capacity(resolved.config.repos.len());
    for repo in resolved.config.repos.iter().filter(|r| r.enabled) {
        let effective_baseurl = repo.baseurl.replace("$basearch", &repomd_arch).replace(
            "$releasever",
            resolved
                .config
                .releasever
                .as_deref()
                .unwrap_or("$releasever"),
        );
        repo_metas.push((repo.name.clone(), repo.baseurl.clone()));
        let client = client.clone();
        fetches.push(tokio::spawn(async move {
            match tokio::time::timeout_at(
                deadline,
                fetch_repomd_sha256(&client, &effective_baseurl),
            )
            .await
            {
                Ok(res) => res,
                Err(_) => Err(format!(
                    "repomd fetch exceeded overall budget ({REPOMD_FETCH_BUDGET:?})"
                )),
            }
        }));
    }
    let mut repos = Vec::with_capacity(fetches.len());
    for ((name, baseurl), fetched) in repo_metas.into_iter().zip(fetches) {
        // JoinError 仅在任务 panic / 运行时关闭时出现，按抓取失败降级（不阻塞配方）。
        let result = fetched
            .await
            .unwrap_or_else(|e| Err(format!("repomd fetch task aborted: {e}")));
        let (repomd_sha256, repomd_fetch_error) = match result {
            Ok(sha) => (Some(sha), None),
            Err(e) => {
                warn!(
                    task_id = task_id,
                    repo = %name,
                    baseurl = %baseurl,
                    error = %e,
                    "repomd fetch failed; recording null with error (record-only value, generation continues)"
                );
                (None, Some(e))
            }
        };
        repos.push(RecipeRepo {
            name,
            baseurl,
            repomd_sha256,
            repomd_fetch_error,
        });
    }

    Ok(Recipe {
        schema_version: RECIPE_SCHEMA_VERSION,
        product: task.product,
        task_id,
        generated_at: db_now_utc(),
        srpm_sha256,
        macros: LabeledBlock {
            source: MACROS_SOURCE.to_string(),
            values: macros,
        },
        env: LabeledBlock {
            source: ENV_SOURCE.to_string(),
            values: env,
        },
        ccache,
        instrumentation_disclosure: INSTRUMENTATION_DISCLOSURE.to_string(),
        repos,
        per_arch,
    })
}

/// 由 repo baseurl 构造 `repodata/repomd.xml` 的 URL。`Url::join` 按 RFC 3986
/// 相对引用解析，base 无尾斜杠时最后一段会被替换，须先补尾斜杠再按目录拼接。
fn repomd_url(baseurl: &str) -> Result<reqwest::Url, String> {
    let mut url = reqwest::Url::parse(baseurl).map_err(|e| format!("parse baseurl: {e}"))?;
    let path = url.path();
    if !path.ends_with('/') {
        url.set_path(&format!("{path}/"));
    }
    url.join("repodata/repomd.xml")
        .map_err(|e| format!("join repodata/repomd.xml: {e}"))
}

/// 抓取 `{baseurl}/repodata/repomd.xml` 并计算 sha256（5s 短超时，纯记录值）；
/// 任何失败（网络/DNS/非 200/超时/超限）均 Err(String)，调用方记 fetch_error 不阻塞。
async fn fetch_repomd_sha256(client: &reqwest::Client, baseurl: &str) -> Result<String, String> {
    let url = repomd_url(baseurl)?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET repodata/repomd.xml: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET repodata/repomd.xml: HTTP {status}"));
    }
    // Content-Length 预检：超限在读取前拒绝，不为失控响应建立读取面。
    if let Some(len) = resp.content_length() {
        if len > MAX_REPOMD_BYTES as u64 {
            return Err(format!(
                "repomd.xml Content-Length exceeds sanity cap ({len}/{MAX_REPOMD_BYTES} bytes)"
            ));
        }
    }
    // 流式限量读取：chunked / Content-Length 谎报时由累计上限兜底，防失控源撑爆内存。
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    let mut total = 0usize;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("read repomd.xml body: {e}"))?
    {
        total = total.saturating_add(chunk.len());
        if total > MAX_REPOMD_BYTES {
            return Err(format!(
                "repomd.xml exceeds sanity cap (>{MAX_REPOMD_BYTES} bytes)"
            ));
        }
        digest.update(&chunk);
    }
    Ok(hex::encode(digest.finalize()))
}

/// 定位 build 的 `build_packages.json`：`builds.result_dir` 是权威指针，指向
/// 含该文件的 per-build 目录；缺指针/空串返回 `None`（不收 task 根，无可回退布局）。
fn locate_build_packages_path(child: &crate::BuildRecord) -> Option<std::path::PathBuf> {
    if let Some(dir) = child.result_dir.as_deref() {
        if !dir.is_empty() {
            return Some(Path::new(dir).join("build_packages.json"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProductConfig;
    use crate::state::artifacts::{ArtifactKind, NewArtifact};
    use crate::state::test_state::create_test_store;
    use crate::util::parse_db_time;
    use crate::BuildInsert;

    const SHA_A: &str = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000";

    fn det_product(baseurl: &str) -> ProductConfig {
        // 解析 ProductConfig::from_str（TOML），repos 里带 baseurl 供 repomd 抓取。
        ProductConfig::from_str(&format!(
            "base_packages = [\"bash\"]\n\
             deterministic = true\n\
             dnf_cache_enabled = true\n\
             releasever = \"9\"\n\
             [[repos]]\n\
             name = \"base\"\n\
             baseurl = \"{baseurl}\"\n\
             gpgcheck = false\n"
        ))
        .unwrap()
    }

    async fn seed_product(store: &StateStore, name: &str, cfg: &ProductConfig) {
        store
            .create_product(crate::CreateProductInput {
                name,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crate::VISIBILITY_PUBLIC,
                config: cfg,
                changed_by_user_id: None,
                reason: Some("recipe api test seed"),
            })
            .await
            .unwrap();
    }

    /// 种子 deterministic 任务：task + 单 arch 子构建 + build_packages.json + RPM 产物行。
    async fn seed_task_with_build(
        store: &StateStore,
        app_tmp: &Path,
        pkg: &str,
        arch: &str,
        request_json: &str,
    ) -> (i64, i64, std::path::PathBuf) {
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "det",
                pkg_name: pkg,
                user: "tester",
                phase: "succeeded",
                request_json: Some(request_json),
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(BuildInsert {
                product: "det",
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                priority: 0,
                arch: Some(arch),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(build_id, true).await.unwrap();
        store
            .set_build_canonical_srpm_sha256(build_id, SHA_A)
            .await
            .unwrap();

        // per-build 目录 + build_packages.json fixture，然后一次落 result_dir /
        // base_os_digest（update_build_info 是整体覆写语义）。
        let task_dir = app_tmp.join(task_id.to_string());
        let build_dir = task_dir.join(arch).join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::write(build_dir.join("build_packages.json"), b"{\"pkg\":true}")
            .await
            .unwrap();
        store
            .update_build_info(
                build_id,
                Some(build_dir.to_str().unwrap()),
                Some("baseos-digest-1"),
                "chroot",
            )
            .await
            .unwrap();
        store
            .update_task_result_dir(task_id, Some(task_dir.to_str().unwrap()))
            .await
            .unwrap();
        (task_id, build_id, build_dir)
    }

    async fn insert_rpm_artifact(
        store: &StateStore,
        build_id: i64,
        rel: &str,
        unsigned: Option<&str>,
    ) {
        let a = NewArtifact {
            relative_path: rel.to_string(),
            kind: ArtifactKind::Rpm,
            size_bytes: 10,
            sha256: "signed-hash".to_string(),
            unsigned_sha256: unsigned.map(|s| s.to_string()),
            arch: Some("x86_64".to_string()),
            name: None,
            version: None,
            release: None,
            epoch: None,
            metadata_json: None,
            signed: false,
        };
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                std::slice::from_ref(&a),
                "2026-01-01 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// 起一个只响应一次 GET 的本地 HTTP 服务；返回 (baseurl, 响应体 sha256,
    /// 服务句柄)——句柄在请求发出后 await（确认响应已完成写入）。
    async fn spawn_one_shot_repomd_server() -> (String, String, tokio::task::JoinHandle<()>) {
        use sha2::Digest;
        let body = b"<repomd>fixture</repomd>";
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            use tokio::io::AsyncWriteExt;
            sock.write_all(resp.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });
        let sha = hex::encode(sha2::Sha256::digest(body));
        (format!("http://{addr}"), sha, handle)
    }

    /// 组装断言：血缘锚 / per_arch 快照哈希 / unsigned 列表 / macros 来自 request_json / env 同源。
    #[tokio::test]
    async fn recipe_assembly_covers_d8_topology() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;
        let request_json = r#"{"define":["dist=.my9","buildhr_test=1"]}"#;
        let (task_id, build_id, build_dir) =
            seed_task_with_build(&store, &app_tmp, "hello-1.0-1", "x86_64", request_json).await;
        insert_rpm_artifact(
            &store,
            build_id,
            "RPMS/x86_64/hello-1.0-1.x86_64.rpm",
            Some("bbbb1111"),
        )
        .await;

        let recipe = build_task_recipe(&store, task_id).await.unwrap();

        assert_eq!(recipe.schema_version, RECIPE_SCHEMA_VERSION);
        assert_eq!(recipe.product, "det");
        assert_eq!(recipe.task_id, task_id);
        assert_eq!(
            recipe.srpm_sha256.as_deref(),
            Some(SHA_A),
            "deterministic SRPM anchor"
        );
        assert!(
            parse_db_time(&recipe.generated_at).is_some(),
            "generated_at in DB time frame"
        );

        assert_eq!(
            recipe.macros.values.get("dist").map(String::as_str),
            Some(".my9")
        );
        assert_eq!(
            recipe.macros.values.get("buildhr_test").map(String::as_str),
            Some("1")
        );
        assert!(recipe.macros.source.contains("request_json"));

        assert_eq!(
            recipe.env.values.get("LC_ALL").map(String::as_str),
            Some("C")
        );
        for (k, v) in crate::engine::build::phase::DETERMINISTIC_ENV_BASELINE {
            assert_eq!(recipe.env.values.get(*k).map(String::as_str), Some(*v));
        }

        assert!(!recipe.ccache.enabled);
        assert_eq!(recipe.ccache.compiler_check, None);
        assert!(recipe.ccache.sloppy.is_empty());
        assert!(recipe.instrumentation_disclosure.contains("-bb"));

        assert_eq!(recipe.per_arch.len(), 1);
        let pa = &recipe.per_arch[0];
        assert_eq!(pa.arch, "x86_64");
        assert_eq!(pa.build_id, build_id);
        assert_eq!(pa.base_os_digest.as_deref(), Some("baseos-digest-1"));
        let expect_sha =
            crate::engine::cache::compute_file_sha256(&build_dir.join("build_packages.json"))
                .await
                .unwrap();
        assert_eq!(
            pa.build_packages_sha256.as_deref(),
            Some(expect_sha.as_str())
        );
        assert_eq!(pa.unsigned_artifacts.len(), 1);
        assert_eq!(pa.unsigned_artifacts[0].name, "hello-1.0-1.x86_64.rpm");
        assert_eq!(pa.unsigned_artifacts[0].sha256, "bbbb1111");

        assert_eq!(recipe.repos.len(), 1);
        assert_eq!(recipe.repos[0].name, "base");
        assert_eq!(recipe.repos[0].repomd_sha256, None);
        assert!(recipe.repos[0].repomd_fetch_error.is_some());
    }

    /// NULL 锚 RPM 不静默丢弃——文件名进 missing_unsigned_anchor、有锚 RPM
    /// 照常收录；v1 文件（无该字段）仍解析为空表（serde(default)）。
    #[tokio::test]
    async fn recipe_collects_missing_unsigned_anchor_names() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;
        let (task_id, build_id, _dir) =
            seed_task_with_build(&store, &app_tmp, "mixed-1.0-1", "x86_64", "{}").await;
        insert_rpm_artifact(
            &store,
            build_id,
            "RPMS/x86_64/mixed-1.0-1.x86_64.rpm",
            Some("bbbb2222"),
        )
        .await;
        insert_rpm_artifact(
            &store,
            build_id,
            "RPMS/x86_64/anchorless-1.0-1.x86_64.rpm",
            None,
        )
        .await;

        let recipe = build_task_recipe(&store, task_id).await.unwrap();
        let pa = &recipe.per_arch[0];
        assert_eq!(
            pa.unsigned_artifacts.len(),
            1,
            "anchored rpm still collected"
        );
        assert_eq!(pa.unsigned_artifacts[0].name, "mixed-1.0-1.x86_64.rpm");
        assert_eq!(pa.unsigned_artifacts[0].sha256, "bbbb2222");
        assert_eq!(
            pa.missing_unsigned_anchor,
            vec!["anchorless-1.0-1.x86_64.rpm".to_string()],
            "NULL-anchor rpm filename must be disclosed, not dropped"
        );

        let v1_json = r#"{"arch":"x86_64","build_id":1,"base_os_digest":null,
            "build_packages_sha256":null,"unsigned_artifacts":[]}"#;
        let pa_v1: RecipePerArch = serde_json::from_str(v1_json).unwrap();
        assert!(pa_v1.missing_unsigned_anchor.is_empty());
    }

    /// 修剪分叉守卫：磁盘 3 per_arch、现存 children 只剩 2（retention 修剪形态）时
    /// 再生成被拒（Conflict），旧全量文件逐字节保留；同数文件（2 ≤ 2）不拒。
    #[tokio::test]
    async fn recipe_regeneration_refused_when_retention_pruned_children() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;
        let (task_id, _x86_id, _dir) =
            seed_task_with_build(&store, &app_tmp, "pruned-1.0-1", "x86_64", "{}").await;
        let second = store
            .insert_build(BuildInsert {
                product: "det",
                pkg_name: "pruned-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                priority: 0,
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store.set_build_deterministic(second, true).await.unwrap();

        // 磁盘旧全量配方：3 per_arch 条目（第三 arch 行已被 retention 修剪）。
        let per_arch_entry = |arch: &str, build_id: i64| RecipePerArch {
            arch: arch.to_string(),
            build_id,
            base_os_digest: None,
            build_packages_sha256: Some(format!("sha-{arch}")),
            unsigned_artifacts: vec![],
            missing_unsigned_anchor: vec![],
        };
        let old_recipe = Recipe {
            schema_version: RECIPE_SCHEMA_VERSION,
            product: "det".into(),
            task_id,
            generated_at: "2026-01-01 00:00:00".into(),
            srpm_sha256: Some(SHA_A.into()),
            macros: LabeledBlock {
                source: "s".into(),
                values: BTreeMap::new(),
            },
            env: LabeledBlock {
                source: "s".into(),
                values: BTreeMap::new(),
            },
            ccache: CcacheDisclosure {
                enabled: false,
                compiler_check: None,
                sloppy: String::new(),
            },
            instrumentation_disclosure: INSTRUMENTATION_DISCLOSURE.into(),
            repos: vec![],
            per_arch: vec![
                per_arch_entry("x86_64", 1),
                per_arch_entry("aarch64", 2),
                per_arch_entry("ppc64le", 3),
            ],
        };
        let task_dir = app_tmp.join(task_id.to_string());
        write_recipe_atomic(&task_dir, &old_recipe).await.unwrap();
        let bytes_before = tokio::fs::read_to_string(recipe_path(&task_dir))
            .await
            .unwrap();

        let err = build_task_recipe(&store, task_id)
            .await
            .expect_err("shrunken regeneration must be refused");
        assert!(
            matches!(err, CrbsError::Conflict { .. }),
            "prune-divergence refusal must be Conflict, got: {err:?}"
        );
        assert!(
            err.to_string().contains("refusing to regenerate"),
            "message must explain the refusal: {err}"
        );

        let bytes_after = tokio::fs::read_to_string(recipe_path(&task_dir))
            .await
            .unwrap();
        assert_eq!(
            bytes_after, bytes_before,
            "old full recipe.json must survive the refused regeneration verbatim"
        );

        let mut equal_count = old_recipe;
        equal_count.per_arch.truncate(2);
        write_recipe_atomic(&task_dir, &equal_count).await.unwrap();
        let recipe = build_task_recipe(&store, task_id)
            .await
            .expect("same-count file must not trip the guard");
        assert_eq!(recipe.per_arch.len(), 2);
    }

    /// 批量查询收敛 N+1 后 per_arch 产出仍逐字节一致：per_arch 按 (arch, build_id)
    /// 排序、arch 内 unsigned / missing 清单按 (kind, relative_path)，两组序与插入序相反。
    #[tokio::test]
    async fn recipe_multi_arch_artifacts_batch_query_preserves_ordering() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;
        let (task_id, x86_id, _dir) =
            seed_task_with_build(&store, &app_tmp, "multi-1.0-1", "x86_64", "{}").await;
        // aarch64 子构建（后插，arch 序仍在前）。
        let aarch64_id = store
            .insert_build(BuildInsert {
                product: "det",
                pkg_name: "multi-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                priority: 0,
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_build_deterministic(aarch64_id, true)
            .await
            .unwrap();

        // 产物逆序插入 + 一个 NULL 锚行：组内序须仍按 (kind, relative_path) 升序。
        insert_rpm_artifact(
            &store,
            aarch64_id,
            "RPMS/aarch64/z-last-1.0-1.aarch64.rpm",
            Some("cccc1111"),
        )
        .await;
        insert_rpm_artifact(
            &store,
            aarch64_id,
            "RPMS/aarch64/m-anchorless-1.0-1.aarch64.rpm",
            None,
        )
        .await;
        insert_rpm_artifact(
            &store,
            aarch64_id,
            "RPMS/aarch64/a-first-1.0-1.aarch64.rpm",
            Some("cccc2222"),
        )
        .await;
        insert_rpm_artifact(
            &store,
            x86_id,
            "RPMS/x86_64/z-last-1.0-1.x86_64.rpm",
            Some("dddd1111"),
        )
        .await;
        insert_rpm_artifact(
            &store,
            x86_id,
            "RPMS/x86_64/a-first-1.0-1.x86_64.rpm",
            Some("dddd2222"),
        )
        .await;

        let recipe = build_task_recipe(&store, task_id).await.unwrap();

        assert_eq!(recipe.per_arch.len(), 2);
        assert_eq!(recipe.per_arch[0].arch, "aarch64");
        assert_eq!(recipe.per_arch[0].build_id, aarch64_id);
        assert_eq!(recipe.per_arch[1].arch, "x86_64");
        assert_eq!(recipe.per_arch[1].build_id, x86_id);

        let a = &recipe.per_arch[0];
        assert_eq!(
            a.unsigned_artifacts
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a-first-1.0-1.aarch64.rpm", "z-last-1.0-1.aarch64.rpm"],
        );
        assert_eq!(
            a.missing_unsigned_anchor,
            vec!["m-anchorless-1.0-1.aarch64.rpm".to_string()],
        );
        let x = &recipe.per_arch[1];
        assert_eq!(
            x.unsigned_artifacts
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a-first-1.0-1.x86_64.rpm", "z-last-1.0-1.x86_64.rpm"],
        );
        assert!(x.missing_unsigned_anchor.is_empty());
    }

    /// request_json 的两条上抛路径：①反序列化失败（历史数据损坏显性暴露，
    /// 与 auto_replay 同口径）；②define 集非 KEY=VALUE（parse_macros 同样生效）。
    #[tokio::test]
    async fn recipe_rejects_corrupt_and_invalid_request_json() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;

        let (task_id, _build_id, _dir) =
            seed_task_with_build(&store, &app_tmp, "corrupt-1.0-1", "x86_64", "not-json").await;
        let err = build_task_recipe(&store, task_id).await.err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("parse recorded request_json"),
            "corrupt request_json must surface the parse failure, got: {msg}"
        );

        let (task_id, _build_id, _dir) = seed_task_with_build(
            &store,
            &app_tmp,
            "bad-define-1.0-1",
            "x86_64",
            r#"{"define":["NOEQUALS"]}"#,
        )
        .await;
        let err = build_task_recipe(&store, task_id).await.err().unwrap();
        let msg = err.to_string();
        assert!(
            msg.contains("define must be in KEY=VALUE format"),
            "invalid define must propagate parse_macros' error, got: {msg}"
        );
    }

    /// repomd 成功路径：sha256 == fixture 内容哈希；占位符按任务架构/产品 releasever 替换。
    #[tokio::test]
    async fn repomd_fetch_records_sha256() {
        let (baseurl, expect_sha, server) = spawn_one_shot_repomd_server().await;
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(
            &store,
            "det",
            &det_product(&format!("{baseurl}/$basearch/os")),
        )
        .await;
        let (task_id, _build_id, _dir) =
            seed_task_with_build(&store, &app_tmp, "hello-1.0-1", "x86_64", "{}").await;

        let recipe = build_task_recipe(&store, task_id).await.unwrap();
        assert_eq!(
            recipe.repos[0].repomd_sha256.as_deref(),
            Some(expect_sha.as_str()),
            "repomd sha256 is the record of fetched bytes"
        );
        assert_eq!(recipe.repos[0].repomd_fetch_error, None);
        server.await.unwrap();
    }

    /// 非 deterministic：env 只含 LC_ALL、ccache 无守卫值、srpm_sha256 为 null，配方仍完整。
    #[tokio::test]
    async fn recipe_works_for_non_deterministic_task() {
        let (store, tmp) = create_test_store().await;
        let app_tmp = tmp.as_ref().map(|t| t.path().to_path_buf()).unwrap();
        seed_product(&store, "det", &det_product("http://127.0.0.1:9/")).await;
        let task_id = store
            .insert_task(crate::TaskInsert {
                product: "det",
                pkg_name: "plain-1.0-1",
                user: "tester",
                phase: "succeeded",
                request_json: Some("{}"),
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(BuildInsert {
                product: "det",
                pkg_name: "plain-1.0-1",
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                priority: 0,
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        let build_dir = app_tmp
            .join(task_id.to_string())
            .join("x86_64")
            .join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::write(build_dir.join("build_packages.json"), b"{}")
            .await
            .unwrap();
        store
            .update_build_info(build_id, Some(build_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        store
            .update_task_result_dir(
                task_id,
                Some(app_tmp.join(task_id.to_string()).to_str().unwrap()),
            )
            .await
            .unwrap();

        let recipe = build_task_recipe(&store, task_id).await.unwrap();
        assert_eq!(
            recipe.srpm_sha256, None,
            "no canonical anchor outside deterministic mode"
        );
        assert_eq!(
            recipe.env.values.len(),
            1,
            "only LC_ALL for non-deterministic tasks"
        );
        assert_eq!(
            recipe.env.values.get("LC_ALL").map(String::as_str),
            Some("C")
        );
        assert_eq!(recipe.macros.values, BTreeMap::new());
        assert_eq!(recipe.per_arch.len(), 1);
        assert!(recipe.per_arch[0].build_packages_sha256.is_some());
    }

    /// 回写-回读 roundtrip：原子写 + 权限 + 回读一致；损坏文件按缺失处理（自愈入口）。
    #[tokio::test]
    async fn write_then_read_roundtrip_and_corruption_self_heal() {
        let tmp = tempfile::tempdir().unwrap();
        let recipe = Recipe {
            schema_version: RECIPE_SCHEMA_VERSION,
            product: "p".into(),
            task_id: 1,
            generated_at: "2026-09-09 00:00:00".into(),
            srpm_sha256: Some(SHA_A.into()),
            macros: LabeledBlock {
                source: "s".into(),
                values: BTreeMap::new(),
            },
            env: LabeledBlock {
                source: "s".into(),
                values: BTreeMap::new(),
            },
            ccache: CcacheDisclosure {
                enabled: false,
                compiler_check: None,
                sloppy: String::new(),
            },
            instrumentation_disclosure: INSTRUMENTATION_DISCLOSURE.into(),
            repos: vec![],
            per_arch: vec![],
        };
        let path = write_recipe_atomic(tmp.path(), &recipe).await.unwrap();

        // 权限不变量：0660（group 位在 umask 无关的显式 chmod 后成立）。
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o660, "recipe.json must be 0660");

        let back = read_recipe_file(&path).await.unwrap().unwrap();
        assert_eq!(back, recipe);

        tokio::fs::write(&path, b"{half-written").await.unwrap();
        assert!(read_recipe_file(&path).await.unwrap().is_none());
        assert!(read_recipe_file(&tmp.path().join("nope.json"))
            .await
            .unwrap()
            .is_none());
    }

    /// 未来版本 + 结构不兼容（serde 解析失败、Value 可读出超前 schema_version）
    /// → `Conflict`（409）而非 Ok(None) 穿透到再生成覆写；当前版本同类损坏仍自愈。
    #[tokio::test]
    async fn future_version_structurally_incompatible_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("recipe.json");

        let future_bytes = format!(
            r#"{{"schema_version": {}, "product": 42, "future_field": {{"keep": true}}}}"#,
            RECIPE_SCHEMA_VERSION + 1
        );
        tokio::fs::write(&path, &future_bytes).await.unwrap();
        let err = read_recipe_file(&path).await.unwrap_err();
        assert!(
            matches!(err, CrbsError::Conflict { .. }),
            "future-version unparseable file must Conflict, got: {err:?}"
        );
        assert!(
            err.to_string().contains("newer than"),
            "message must explain the refusal: {err}"
        );

        let corrupt_bytes = format!(
            r#"{{"schema_version": {}, "product": 42}}"#,
            RECIPE_SCHEMA_VERSION
        );
        tokio::fs::write(&path, &corrupt_bytes).await.unwrap();
        assert!(read_recipe_file(&path).await.unwrap().is_none());
    }

    /// repomd URL 构造：无尾斜杠 baseurl 规范化后按目录拼接（裸 join 丢最后一段路径）。
    #[test]
    fn repomd_url_normalizes_base_without_trailing_slash() {
        let u = repomd_url("http://mirror.example/repo/x86_64").unwrap();
        assert_eq!(
            u.as_str(),
            "http://mirror.example/repo/x86_64/repodata/repomd.xml"
        );
        let u = repomd_url("http://mirror.example/repo/x86_64/").unwrap();
        assert_eq!(
            u.as_str(),
            "http://mirror.example/repo/x86_64/repodata/repomd.xml"
        );
        let u = repomd_url("http://mirror.example/base/x86_64").unwrap();
        assert_eq!(
            u.as_str(),
            "http://mirror.example/base/x86_64/repodata/repomd.xml"
        );
    }

    /// Content-Length 预检：超限响应在读取 body 前拒绝，不进内存。
    async fn spawn_oversized_repomd_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nshort",
                MAX_REPOMD_BYTES as u64 + 1
            );
            use tokio::io::AsyncWriteExt;
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn repomd_fetch_rejects_oversized_content_length_before_read() {
        let baseurl = spawn_oversized_repomd_server().await;
        let client = reqwest::Client::new();
        let err = fetch_repomd_sha256(&client, &baseurl).await.unwrap_err();
        assert!(
            err.contains("Content-Length exceeds sanity cap"),
            "must reject at Content-Length precheck, got: {err}"
        );
    }

    /// HTTP 非 200 分支：one-shot 服务回 404，错误文案带 "HTTP {status}"（读取 body 前拒绝）。
    async fn spawn_not_found_repomd_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            use tokio::io::AsyncWriteExt;
            sock.write_all(resp.as_bytes()).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn repomd_fetch_reports_http_error_status() {
        let baseurl = spawn_not_found_repomd_server().await;
        let client = reqwest::Client::new();
        let err = fetch_repomd_sha256(&client, &baseurl).await.unwrap_err();
        assert!(
            err.contains("HTTP 404"),
            "must surface the HTTP status in the error, got: {err}"
        );
    }

    /// 占位符替换只影响抓取 URL，baseurl 字段保留原样（配方记录配置原值）。
    #[test]
    fn repo_baseurl_recorded_verbatim() {
        let raw = "http://mirror.example/$contentdir/$basearch/os/";
        let replaced = raw.replace("$basearch", "x86_64");
        assert!(replaced.contains("$contentdir"));
        assert!(replaced.contains("x86_64"));
        assert_ne!(raw, replaced);
        let repo = RecipeRepo {
            name: "m".into(),
            baseurl: raw.into(),
            repomd_sha256: None,
            repomd_fetch_error: Some("fetch failed".into()),
        };
        let v = serde_json::to_value(&repo).unwrap();
        assert_eq!(v["baseurl"], raw);
        assert_eq!(v["repomd_sha256"], serde_json::Value::Null);
        assert_eq!(v["repomd_fetch_error"], "fetch failed");
    }
}
