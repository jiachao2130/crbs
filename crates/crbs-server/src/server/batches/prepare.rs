// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建批次的准备服务：配额检查 → 建批次（preparing）→ dist 硬预检 →
//! 枚举源仓 SRPM → 增量判定 → 并发下载暂存 → 计划项落库 → 交棒 planning。
//!
//! 批次行一旦建立，任何失败路径都收口为 failed（部分落库 items 经
//! `take_failed_and_clear_items` 先减回 `n_failed` 再清行，计数器归零后
//! `finish_batch` 总数对账才能过）；唯一例外：`set_batch_planning`
//! CAS 0 行 = 批次已离开 preparing（并发迁移先到者胜），不动状态只上抛。
//! 增量跳过是包名级（产品下已有 succeeded 构建即跳过，不比 NEVR 版本）：
//! 跳过的包不建 batch_items（项状态机无对应状态），`n_skipped` 只覆盖运行
//! 期 dep_skipped / skipped_conflict，跳过名单仅落批次 notes。
//! 单个 SRPM 下载失败只记 failed item（暂存路径 NULL）、不中止整批——
//! `on_failure = abort` 只作用于 running 轮构建失败；全部源失败才收口
//! 批次 failed，水位跌破时剩余文件同样记 failed item。

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crbs_core::config::RepoConfig;
use crbs_core::engine::chain::release_dist_suffix;
use crbs_core::engine::depsolve::{extract_srpm_name, repoquery_release_args};
use crbs_core::engine::repo::rpm_release_suffix_matches;
use crbs_core::engine::{
    enumerate_repo_src_rpms, run_command_capped_output_with_timeout, SrcRpmEntry,
    ENUMERATE_SRC_RPMS_TIMEOUT,
};
use crbs_core::error::CrbsError;
use crbs_core::http_retry::{retry_with_policy, RetryBreak, RetryCause};
use crbs_core::logging::redact_userinfo;
use crbs_core::{BatchInsert, FailedBatchItem, NewBatchItem};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::server::error::ApiError;
use crate::server::staging::enforce_result_tree_invariant;
use crate::server::state::AppState;

const DOWNLOAD_CONCURRENCY: usize = 4;
/// 单文件下载重试预算（含首次尝试；退避形态由 http_retry 骨架统一）。
const DOWNLOAD_MAX_ATTEMPTS: u32 = 3;
const DOWNLOAD_BASE_DELAY: Duration = Duration::from_secs(1);
/// 单 SRPM 下载大小上限（2GiB，对齐 cache::MAX_DOWNLOAD_BYTES）。
const MAX_SRPM_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// dist 预检采样预算（对齐 chain 预检 repoquery）。
const DIST_PRECHECK_TIMEOUT: Duration = Duration::from_secs(600);

/// 全局在途批次数上限（跨产品；每产品单活另有唯一索引强约束）。
const MAX_ACTIVE_BATCHES: i64 = 2;

/// failed item 的错误码（对齐 state 层 error_code 语义：小写标识）。
const CODE_DOWNLOAD_FAILED: &str = "srpm_download_failed";
const CODE_DISK_WATERMARK: &str = "disk_below_watermark";

/// 批次准备请求（鉴权 / 产品 ACL / 审计事件由路由层管，本层不管）。
#[derive(Debug, Clone)]
pub struct PrepareBatchRequest {
    pub product: String,
    pub source_repo_url: String,
    pub dist: Option<String>,
    pub arch_targets: Vec<String>,
    pub on_failure: String,
    pub force_all: bool,
    /// dist 硬预检显式豁免（默认 false；`force_all` 不覆盖本预检）——错配是 EVR 冲突防线，豁免须独立显式。
    pub allow_dist_mismatch: bool,
    /// 原始请求 JSON，原样透传落库（审计用途，本层不追加内容）。
    pub request_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PrepareOutcome {
    pub batch_id: i64,
    /// 已暂存并建 pending 项的包名。
    pub to_build: Vec<String>,
    /// 准备期下载 / 水位失败、已记 failed item 的包名。
    pub staging_failed: Vec<String>,
    /// 增量跳过（产品下已有 succeeded 构建）的包名；不建 item。
    pub skipped_built: Vec<String>,
}

// 产出注入缝：枚举/dist 采样生产走真实 dnf、测试传 stub；下载重试预算可注入（测试 1ms 退避）。
type EnumFut = Pin<Box<dyn Future<Output = crbs_core::Result<Vec<SrcRpmEntry>>> + Send>>;
type DistFut = Pin<Box<dyn Future<Output = Option<String>> + Send>>;
type EnumFn = Arc<dyn Fn(String, Duration, &Path) -> EnumFut + Send + Sync>;

#[derive(Clone)]
struct PrepareSeams {
    enumerate: EnumFn,
    sample_dist_suffix: Arc<dyn Fn(String) -> DistFut + Send + Sync>,
    download_attempts: u32,
    download_base_delay: Duration,
    /// dnf 临时缓存根：worker ProtectSystem=strict 下 /tmp 只读，须落 ReadWritePaths 白名单内。
    tmp_dir: PathBuf,
}

impl PrepareSeams {
    fn production(tmp_dir: PathBuf) -> Self {
        Self {
            enumerate: Arc::new(move |url: String, timeout: Duration, tmp_dir: &Path| {
                let tmp_dir = tmp_dir.to_path_buf();
                Box::pin(async move { enumerate_repo_src_rpms(&url, timeout, &tmp_dir).await })
            }),
            sample_dist_suffix: Arc::new(|url| {
                Box::pin(async move { sample_source_repo_dist_suffix(&url).await })
            }),
            download_attempts: DOWNLOAD_MAX_ATTEMPTS,
            download_base_delay: DOWNLOAD_BASE_DELAY,
            tmp_dir,
        }
    }
}

/// 测试专用入口：显式注入枚举/采样/下载缝；生产走 [`run_prepare_phase`] 内建 production 缝。
#[cfg(test)]
async fn prepare_batch_with_seams(
    app: &AppState,
    req: PrepareBatchRequest,
    seams: &PrepareSeams,
) -> Result<PrepareOutcome, ApiError> {
    let (batch_id, dist) = validate_and_insert_batch(app, &req).await?;
    run_prepare_phase_with_seams(app, req, dist, batch_id, seams).await
}

/// 准备的快速段：前置校验 + 配额 + 建批次行（DB-only，毫秒级）；路由层"立即返回 batch_id"
/// 依赖本段先建行拿 id，慢段（分钟级）交后台（见 [`run_prepare_phase`]）；返回 (batch_id, 归一后的 dist)。
pub(crate) async fn validate_and_insert_batch(
    app: &AppState,
    req: &PrepareBatchRequest,
) -> Result<(i64, Option<String>), ApiError> {
    let store = &app.state_store;

    // 前置校验：全部在批次行建立之前完成，失败无需清理。
    validate_source_repo_url(&req.source_repo_url)?;
    if !matches!(req.on_failure.as_str(), "continue" | "abort") {
        return Err(ApiError::Validation(format!(
            "on_failure must be 'continue' or 'abort', got {:?}",
            req.on_failure
        )));
    }
    let dist = normalize_dist_input(req.dist.clone())?;

    let product = match store
        .get_product_by_name(&req.product)
        .await
        .map_err(ApiError::from)?
    {
        Some(p) => p,
        None => {
            return Err(ApiError::NotFound(format!(
                "product '{}' not found",
                req.product
            )));
        }
    };

    // 配额（每产品单活 + 全局上限）与插入由 state 层收进同一写事务：跨产品
    // 并发提交曾可双双越过全局上限（check-then-insert 的 TOCTOU），现由
    // SQLite BEGIN IMMEDIATE / PG 事务级 advisory lock 串行化。
    let arch_targets_json = serde_json::to_string(&req.arch_targets)
        .map_err(|e| ApiError::Internal(format!("serialize arch_targets: {e}")))?;
    let batch_id = store
        .insert_batch_quota_checked(
            BatchInsert {
                product_id: Some(product.id),
                created_by: None,
                source_repo_url: &req.source_repo_url,
                dist: dist.as_deref(),
                arch_targets_json: Some(&arch_targets_json),
                on_failure: &req.on_failure,
                force_all: req.force_all,
                request_json: req.request_json.as_deref(),
            },
            MAX_ACTIVE_BATCHES,
        )
        .await
        .map_err(ApiError::from)?;
    info!(
        batch_id = batch_id,
        product = %req.product,
        "Batch row created (preparing)"
    );
    Ok((batch_id, dist))
}

/// 准备的慢段：批次行已建立后的全部工作（预检/枚举/下载/落库 → 交棒 planning），含失败收口。
/// 路由层拿到 batch_id 后可丢后台任务；调用方须以返回 Err 记日志（批次状态已由本段收口）。
pub(crate) async fn run_prepare_phase(
    app: &AppState,
    req: PrepareBatchRequest,
    dist: Option<String>,
    batch_id: i64,
) -> Result<PrepareOutcome, ApiError> {
    run_prepare_phase_with_seams(
        app,
        req,
        dist,
        batch_id,
        &PrepareSeams::production(app.crbs_config.tmp_dir_or_derived()),
    )
    .await
}

async fn run_prepare_phase_with_seams(
    app: &AppState,
    req: PrepareBatchRequest,
    dist: Option<String>,
    batch_id: i64,
    seams: &PrepareSeams,
) -> Result<PrepareOutcome, ApiError> {
    let store = &app.state_store;

    match prepare_inserted_batch(app, &req, dist.as_deref(), batch_id, seams).await {
        Ok(outcome) => Ok(outcome),
        Err(err) => {
            // 失败收口：批次仍 preparing 才动，共享信封见 plan::close_batch_failed；
            // 悬空 preparing 由启动对账兜底扫出。
            super::plan::close_batch_failed(store, batch_id, "preparing", &err).await;
            Err(err)
        }
    }
}

/// dry-run 预览：枚举 + 包名级增量判定（与真实准备同口径），不建批次行、不下载。
/// 返回 (待建包名, 增量跳过包名)；同包名多版本两个列表都按包名保留首条。
pub(crate) async fn dry_run_split(
    app: &AppState,
    product: &str,
    source_repo_url: &str,
    force_all: bool,
) -> Result<(Vec<String>, Vec<String>), ApiError> {
    validate_source_repo_url(source_repo_url)?;
    if app
        .state_store
        .get_product_by_name(product)
        .await
        .map_err(ApiError::from)?
        .is_none()
    {
        return Err(ApiError::NotFound(format!("product '{product}' not found")));
    }

    let entries = enumerate_repo_src_rpms(
        source_repo_url,
        ENUMERATE_SRC_RPMS_TIMEOUT,
        &app.crbs_config.tmp_dir_or_derived(),
    )
    .await
    .map_err(ApiError::from)?;
    if entries.is_empty() {
        return Err(ApiError::Validation(
            "source repo contains no src RPMs; nothing to rebuild".into(),
        ));
    }
    let built_names: HashSet<String> = app
        .state_store
        .list_succeeded_source_names(product)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .collect();
    let (to_build, skipped) = plan_items(&entries, &built_names, force_all);
    let mut seen: HashSet<String> = HashSet::new();
    let to_build: Vec<String> = to_build
        .iter()
        .map(|e| pkg_name_of(&e.nevra))
        .filter(|n| seen.insert(n.clone()))
        .collect();
    let skipped: Vec<String> = skipped
        .into_iter()
        .filter(|n| seen.insert(n.clone()))
        .collect();
    Ok((to_build, skipped))
}

/// 批次行建立后的全部工作。任何 Err 都由调用方收口批次。
async fn prepare_inserted_batch(
    app: &AppState,
    req: &PrepareBatchRequest,
    dist: Option<&str>,
    batch_id: i64,
    seams: &PrepareSeams,
) -> Result<PrepareOutcome, ApiError> {
    let store = &app.state_store;

    // 1. dist 硬预检：显式 dist 时采样源仓 dist tag 比对，错配 fail-closed
    //    （EVR 冲突防线）；采样失败按 chain 预检同款尽力而为——查不到 ≠ 错配。
    if let Some(expected) = dist {
        if !req.allow_dist_mismatch {
            let sampled = (seams.sample_dist_suffix)(req.source_repo_url.clone()).await;
            match sampled.as_deref() {
                Some(suffix) => {
                    if let Some(message) = dist_mismatch_message(expected, suffix) {
                        return Err(ApiError::Validation(message));
                    }
                }
                None => {
                    warn!(
                        batch_id = batch_id,
                        "dist precheck could not sample the source repo dist tag; proceeding"
                    );
                }
            }
        }
    }

    // 2. 枚举源仓 SRPM。空列表 → 批次 failed（合法空仓/全解析失败已在 core 侧区分）。
    let entries = (seams.enumerate)(
        req.source_repo_url.clone(),
        ENUMERATE_SRC_RPMS_TIMEOUT,
        &seams.tmp_dir,
    )
    .await
    .map_err(ApiError::from)?;
    if entries.is_empty() {
        return Err(ApiError::Validation(
            "source repo contains no src RPMs; nothing to rebuild".into(),
        ));
    }
    info!(
        batch_id = batch_id,
        entries = entries.len(),
        "Source repo src RPMs enumerated"
    );

    // 3. 暂存目录：batch_id 命名空间隔离（并发路径隔离准则），逐级补 2770 +
    //    crbs 组权限不变量。result_root 用回退版查询（产品配置损坏不阻断暂存）。
    let result_root = app.result_dir_for_or_default(&req.product).await;
    let staging_dir = result_root
        .join("batches")
        .join(batch_id.to_string())
        .join("srpms");
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("create batch staging dir", e))?;
    enforce_result_tree_invariant(&staging_dir, &result_root).await;

    let built_names: HashSet<String> = store
        .list_succeeded_source_names(&req.product)
        .await
        .map_err(ApiError::from)?
        .into_iter()
        .collect();
    let (to_build, skipped_built) = plan_items(&entries, &built_names, req.force_all);
    // 同包名不同 NEVRA 按包名保留首条（entries 已按包名排序），防 UNIQUE(batch_id, pkg_name) 冲突炸整批。
    let mut seen_names: HashSet<String> = HashSet::new();
    let to_build: Vec<&SrcRpmEntry> = to_build
        .into_iter()
        .filter(|e| seen_names.insert(pkg_name_of(&e.nevra)))
        .collect();
    debug!(
        batch_id = batch_id,
        to_build = to_build.len(),
        skipped = skipped_built.len(),
        "Incremental plan computed"
    );

    // 4. 并发下载暂存。失败文件记 failed item，不中止整批。伴生心跳协程让孤儿
    //    清扫区分"活批次慢"与"hub 崩溃残留"（仅按 created_at 判会误杀，见 sweep_orphan_batches）。
    let min_free_bytes = app.server_config.min_free_disk_bytes();
    super::touch_batch_heartbeat(&app.state_store, batch_id).await;
    // 心跳句柄持有到函数尾：Drop-abort 在 panic unwind 也收协程，直线 abort 不会（见 BatchHeartbeatGuard）。
    let _heartbeat = super::spawn_batch_heartbeat(app.state_store.clone(), batch_id);
    let staged = stage_srpm_files(
        &staging_dir,
        &to_build,
        min_free_bytes,
        seams.download_attempts,
        seams.download_base_delay,
    )
    .await;

    let mut pending_rows: Vec<(String, String, String)> = Vec::new();
    let mut failed_rows: Vec<(String, Option<String>, &'static str, String)> = Vec::new();
    let mut staging_failed: Vec<String> = Vec::new();
    for (entry, result) in to_build.iter().zip(staged) {
        let name = pkg_name_of(&entry.nevra);
        match result {
            Ok(path) => pending_rows.push((
                name,
                entry.nevra.clone(),
                path.to_string_lossy().into_owned(),
            )),
            Err(f) => {
                staging_failed.push(name.clone());
                failed_rows.push((name, Some(entry.nevra.clone()), f.code, f.message));
            }
        }
    }

    if pending_rows.is_empty() && !failed_rows.is_empty() {
        // 全部源失败：批次 failed（无 item 可留账，收口 notes 记原因）。
        return Err(ApiError::ServiceUnavailable(format!(
            "all {} srpm download(s) failed during staging; batch aborted",
            failed_rows.len()
        )));
    }

    // 5. 收尾：跳过名单落 notes → 计划项落库 → planning 交棒。
    if !skipped_built.is_empty() {
        let notes = format!(
            "skipped (already built, package-name level): {}",
            summarize_names(&skipped_built)
        );
        store
            .set_batch_notes(batch_id, &notes)
            .await
            .map_err(ApiError::from)?;
    }

    let new_items: Vec<NewBatchItem<'_>> = pending_rows
        .iter()
        .map(|(pkg, nevra, path)| NewBatchItem {
            pkg_name: pkg,
            srpm_nevra: Some(nevra),
            srpm_staging_path: Some(path),
            // round 0 占位：拓扑轮次由规划重排（delete_batch_items + 重插幂等重入已在 state 层备好）。
            round: 0,
        })
        .collect();
    store
        .insert_batch_items(batch_id, &new_items)
        .await
        .map_err(ApiError::from)?;

    let failed_items: Vec<FailedBatchItem<'_>> = failed_rows
        .iter()
        .map(|(pkg, nevra, code, message)| FailedBatchItem {
            pkg_name: pkg,
            srpm_nevra: nevra.as_deref(),
            error_code: code,
            error_message: message,
        })
        .collect();
    store
        .insert_failed_batch_items(batch_id, &failed_items)
        .await
        .map_err(ApiError::from)?;

    store.set_batch_planning(batch_id).await.map_err(|e| {
        warn!(
            batch_id = batch_id,
            error = %e,
            "set_batch_planning raced a concurrent transition; batch state left untouched"
        );
        ApiError::from(e)
    })?;

    info!(
        batch_id = batch_id,
        to_build = pending_rows.len(),
        staging_failed = failed_rows.len(),
        skipped = skipped_built.len(),
        "Batch prepared and handed to planning"
    );
    Ok(PrepareOutcome {
        batch_id,
        to_build: pending_rows.into_iter().map(|(pkg, _, _)| pkg).collect(),
        staging_failed,
        skipped_built,
    })
}

/// 包名级增量判定：`built_names`（产品下已有 succeeded 构建的包名集合）命中
/// 即跳过，`force_all` 全部重建；返回 (to_build, skipped_built)。跳过名单不落
/// batch_items（见模块头注）；畸形 nevra 提不出包名时保守进构建（宁多建不漏建）。
fn plan_items<'a>(
    entries: &'a [SrcRpmEntry],
    built_names: &HashSet<String>,
    force_all: bool,
) -> (Vec<&'a SrcRpmEntry>, Vec<String>) {
    if force_all {
        return (entries.iter().collect(), Vec::new());
    }
    let mut to_build = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        let name = pkg_name_of(&entry.nevra);
        if built_names.contains(&name) {
            skipped.push(name);
        } else {
            to_build.push(entry);
        }
    }
    (to_build, skipped)
}

/// NEVRA（`name-version-release.src`）→ 裸包名；解析期已保证 N-V-R 形状，防御臂回退 nevra 原文（保证非空键）。
fn pkg_name_of(nevra: &str) -> String {
    extract_srpm_name(Path::new(&format!("{nevra}.rpm"))).unwrap_or_else(|| nevra.to_string())
}

/// dist 错配判定（纯函数）：返回 Some(错误文案) = 错配应拒绝。
fn dist_mismatch_message(requested: &str, sampled_suffix: &str) -> Option<String> {
    if rpm_release_suffix_matches(sampled_suffix, requested) {
        return None;
    }
    Some(format!(
        "requested dist '{requested}' mismatches the source repo dist tag \
         '{sampled_suffix}'; rebuilt RPMs would carry '{requested}' while the source \
         repo's package set carries '{sampled_suffix}', risking EVR conflicts. \
         Pass the matching dist or set allow_dist_mismatch to override explicitly."
    ))
}

/// 采样源仓 `filesystem` 包的 release 提取 dist 后缀（产品源 tag）。
/// filesystem 必存在于 base repo（chain 预检同款锚点）；repoquery 失败 /
/// 输出空 / 无 dist 后缀一律返回 `None`，尽力而为不阻断批次。
async fn sample_source_repo_dist_suffix(source_repo_url: &str) -> Option<String> {
    let repo = RepoConfig {
        name: "batch-src".to_string(),
        baseurl: source_repo_url.to_string(),
        ..Default::default()
    };
    let args = repoquery_release_args(&[repo], "filesystem");
    let mut cmd = tokio::process::Command::new("dnf");
    cmd.args(&args);
    let output = match run_command_capped_output_with_timeout(
        cmd,
        "spawn dnf repoquery (batch dist precheck)",
        DIST_PRECHECK_TIMEOUT,
    )
    .await
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            debug!(
                exit_code = ?o.status.code(),
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "batch dist precheck repoquery failed; skipping check"
            );
            return None;
        }
        Err(e) => {
            debug!(error = %e, "batch dist precheck cannot spawn dnf; skipping check");
            return None;
        }
    };
    let raw = String::from_utf8_lossy(&output.stdout);
    let release = raw.lines().map(str::trim).find(|l| !l.is_empty())?;
    release_dist_suffix(release)
}

/// 单文件暂存失败（错误码 + 已脱敏消息）。
struct StageFailure {
    code: &'static str,
    message: String,
}

/// 并发暂存 SRPM 到 `staging_dir`（每文件：水位检查 → scheme 分派 → http_retry 重试），
/// 返回值与 `entries` 同序对齐。水位：任一文件发现剩余空间低于 `min_free_bytes`
///（0 = 禁用）即置共享标志，其余文件直接记水位失败（在途不强行中断——保护性预算而非精确断言）。
async fn stage_srpm_files(
    staging_dir: &Path,
    entries: &[&SrcRpmEntry],
    min_free_bytes: u64,
    attempts: u32,
    base_delay: Duration,
) -> Vec<Result<PathBuf, StageFailure>> {
    if entries.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .connect_timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let message = format!("build http client: {e}");
            return entries
                .iter()
                .map(|_| {
                    Err(StageFailure {
                        code: CODE_DOWNLOAD_FAILED,
                        message: message.clone(),
                    })
                })
                .collect();
        }
    };

    let semaphore = Arc::new(Semaphore::new(DOWNLOAD_CONCURRENCY));
    let below_watermark = Arc::new(AtomicBool::new(false));

    let mut tasks = Vec::with_capacity(entries.len());
    for entry in entries {
        let url = entry.url.clone();
        let file_name = format!("{}.rpm", entry.nevra);
        let client = client.clone();
        let semaphore = semaphore.clone();
        let below_watermark = below_watermark.clone();
        let staging_dir = staging_dir.to_path_buf();
        tasks.push(tokio::spawn(async move {
            let _permit = match semaphore.acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    return Err(StageFailure {
                        code: CODE_DOWNLOAD_FAILED,
                        message: format!("acquire download slot: {e}"),
                    });
                }
            };

            // 文件名来自 repoquery 输出（core 解析器过滤）；NUL 是路径硬非法字符，其余交文件系统语义。
            if file_name.contains('\0') {
                return Err(StageFailure {
                    code: CODE_DOWNLOAD_FAILED,
                    message: "staged file name contains NUL".into(),
                });
            }

            if below_watermark.load(Ordering::Relaxed) {
                return Err(StageFailure {
                    code: CODE_DISK_WATERMARK,
                    message: "skipped: disk already below free-space watermark".into(),
                });
            }
            if min_free_bytes > 0 {
                let probe = staging_dir.clone();
                let free = tokio::task::spawn_blocking(move || fs4::available_space(&probe))
                    .await
                    .map_err(|e| StageFailure {
                        code: CODE_DISK_WATERMARK,
                        message: format!("spawn_blocking disk check: {e}"),
                    })
                    .and_then(|r| {
                        r.map_err(|e| StageFailure {
                            code: CODE_DISK_WATERMARK,
                            message: format!("available_space: {e}"),
                        })
                    });
                match free {
                    Ok(free) if free < min_free_bytes => {
                        below_watermark.store(true, Ordering::Relaxed);
                        return Err(StageFailure {
                            code: CODE_DISK_WATERMARK,
                            message: format!(
                                "free space {free} bytes below watermark {min_free_bytes}"
                            ),
                        });
                    }
                    // 查不到水位尽力而为放行（warn）：statfs 瞬时故障不阻断整批下载。
                    Ok(_) => {}
                    Err(f) => {
                        warn!(
                            dir = %staging_dir.display(),
                            error = %f.message,
                            "disk watermark check failed; proceeding without it"
                        );
                    }
                }
            }

            let dest = staging_dir.join(&file_name);
            match fetch_srpm_with_retry(&client, &url, &dest, attempts, base_delay).await {
                Ok(()) => Ok(dest),
                Err(e) => Err(StageFailure {
                    code: CODE_DOWNLOAD_FAILED,
                    message: redact_userinfo(&e.to_string()),
                }),
            }
        }));
    }

    let mut out = Vec::with_capacity(tasks.len());
    for task in tasks {
        out.push(match task.await {
            Ok(r) => r,
            Err(e) => Err(StageFailure {
                code: CODE_DOWNLOAD_FAILED,
                message: format!("staging task aborted: {e}"),
            }),
        });
    }
    out
}

/// 重试原因归类（供 on_retry 日志；两种 cause 的调用方文案一致）。
fn retry_reason<T, E>(cause: &RetryCause<'_, T, E>) -> &'static str {
    match cause {
        RetryCause::Error(_) => "transport error",
        RetryCause::Value(_) => "retryable status",
    }
}

/// 单文件下载（含重试）：`file://` 直接路径拷贝，`http(s)` GET + 流式落盘。
/// 可重试：传输错误按 `CrbsError::is_transient`，5xx 走值重试（对齐 CLI http.rs 的 GET 口径）。
async fn fetch_srpm_with_retry(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
    attempts: u32,
    base_delay: Duration,
) -> crbs_core::Result<()> {
    let result = match url_scheme(url).as_deref() {
        Some("file") => {
            let src = match file_url_to_path(url) {
                Some(p) => p.to_string(),
                None => {
                    return Err(CrbsError::ValidationFailed {
                        message: format!(
                            "file url must be an absolute local path (file:///...), got {}",
                            redact_userinfo(url)
                        ),
                    });
                }
            };
            retry_with_policy(
                attempts,
                base_delay,
                None,
                |e: &CrbsError| e.is_transient(),
                |_: &()| false,
                |cause, attempt, delay| {
                    warn!(
                        url = %redact_userinfo(url),
                        attempt = attempt,
                        delay_ms = delay.as_millis() as u64,
                        reason = retry_reason(&cause),
                        "srpm download retrying"
                    );
                },
                move |_| {
                    let src = src.clone();
                    async move { copy_file_srpm(Path::new(&src), dest).await }
                },
            )
            .await
            .map(|_: ()| ())
        }
        Some("http") | Some("https") => {
            retry_with_policy(
                attempts,
                base_delay,
                None,
                |e: &CrbsError| e.is_transient(),
                |resp: &reqwest::Response| resp.status().is_server_error(),
                |cause, attempt, delay| {
                    warn!(
                        url = %redact_userinfo(url),
                        attempt = attempt,
                        delay_ms = delay.as_millis() as u64,
                        reason = retry_reason(&cause),
                        "srpm download retrying"
                    );
                },
                |_attempt| http_download_once(client, url, dest),
            )
            .await
            .and_then(|resp| {
                // 耗尽的 5xx / 不可重试 4xx 都以 Ok(resp) 浮出，在此统一转错误（不再重试）。
                if resp.status().is_success() {
                    Ok(())
                } else {
                    Err(RetryBreak::Inner(CrbsError::Network {
                        message: format!(
                            "download {}: HTTP {}",
                            redact_userinfo(url),
                            resp.status()
                        ),
                    }))
                }
            })
        }
        other => Err(RetryBreak::Inner(CrbsError::ValidationFailed {
            message: format!(
                "unsupported srpm url scheme {:?} (whitelist: http/https/file)",
                other.unwrap_or("<missing>")
            ),
        })),
    };

    match result {
        Ok(()) => Ok(()),
        Err(RetryBreak::Inner(e)) => Err(e),
        // 未注入取消令牌，Cancelled 不可达；防御臂保持变体语义。
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled),
    }
}

/// HTTP 单次尝试：发送 + 成功响应流式落盘（大小上限，半写即清）；非成功状态不读 body，原样交还重试判定。
async fn http_download_once(
    client: &reqwest::Client,
    url: &str,
    dest: &Path,
) -> Result<reqwest::Response, CrbsError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| CrbsError::Network {
            message: format!("download {}: {e}", redact_userinfo(url)),
        })?;
    if !resp.status().is_success() {
        return Ok(resp);
    }

    use tokio::io::AsyncWriteExt;

    let mut resp = resp;
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| CrbsError::from_io_context("create staged srpm file", e))?;
    let mut downloaded: u64 = 0;
    loop {
        let chunk = match resp.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                let _ = tokio::fs::remove_file(dest).await;
                return Err(CrbsError::Network {
                    message: format!("read chunk from {}: {e}", redact_userinfo(url)),
                });
            }
        };
        downloaded += chunk.len() as u64;
        if downloaded > MAX_SRPM_DOWNLOAD_BYTES {
            let _ = tokio::fs::remove_file(dest).await;
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "download {}: exceeds {MAX_SRPM_DOWNLOAD_BYTES} byte size limit, aborted",
                    redact_userinfo(url)
                ),
            });
        }
        if let Err(e) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(dest).await;
            return Err(CrbsError::from_io_context("write staged srpm chunk", e));
        }
    }
    file.flush()
        .await
        .map_err(|e| CrbsError::from_io_context("flush staged srpm", e))?;
    normalize_staged_perms(dest).await;
    Ok(resp)
}

/// `file://` 单次尝试：直接路径拷贝（半写即清）。
async fn copy_file_srpm(src: &Path, dest: &Path) -> crbs_core::Result<()> {
    if let Err(e) = tokio::fs::copy(src, dest).await {
        let _ = tokio::fs::remove_file(dest).await;
        return Err(CrbsError::from_io_context(
            "copy staged srpm from file url",
            e,
        ));
    }
    normalize_staged_perms(dest).await;
    Ok(())
}

/// 暂存文件权限不变量：0660 + crbs 组；chmod 失败 warn、chown 失败仅 debug。
async fn normalize_staged_perms(dest: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o660)).await
        {
            warn!(
                path = %dest.display(),
                error = %e,
                "Failed to chmod staged srpm to 0660; group rw may not be in effect"
            );
        }
    }
    crbs_core::privilege::chown_to_crbs_group_async(dest, false, "staged batch srpm").await;
}

/// URL scheme 提取（小写化）。
fn url_scheme(url: &str) -> Option<String> {
    url.split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
}

/// `file://` URL → 绝对本地路径（拒绝带 host 的形态）。
fn file_url_to_path(url: &str) -> Option<&str> {
    url.strip_prefix("file://").filter(|p| p.starts_with('/'))
}

/// source_repo_url 前置校验：非空 + scheme 白名单（提交与 dry-run 两入口共用）。
fn validate_source_repo_url(url: &str) -> Result<(), ApiError> {
    if url.trim().is_empty() {
        return Err(ApiError::Validation(
            "source_repo_url must not be empty".into(),
        ));
    }
    validate_source_url_scheme(url)
}

/// 源仓 URL scheme 白名单：http/https/file。
fn validate_source_url_scheme(url: &str) -> Result<(), ApiError> {
    match url_scheme(url).as_deref() {
        Some("http") | Some("https") | Some("file") => Ok(()),
        other => Err(ApiError::Validation(format!(
            "source_repo_url scheme must be http/https/file, got {:?}",
            other.unwrap_or("<missing>")
        ))),
    }
}

/// dist 入参归一（补前导 `.`，字符集校验复用 core 白名单）。
fn normalize_dist_input(dist: Option<String>) -> Result<Option<String>, ApiError> {
    crbs_core::build_options::normalize_dist(dist).map_err(|e| ApiError::Validation(e.to_string()))
}

/// 长名单摘要（notes 单行可读；超 50 个折叠计数）。
fn summarize_names(names: &[String]) -> String {
    const MAX: usize = 50;
    if names.len() <= MAX {
        names.join(", ")
    } else {
        format!(
            "{}, … (+{} more)",
            names[..MAX].join(", "),
            names.len() - MAX
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::test_support::{seed_product, setup_app};
    use crbs_core::config::ServerConfig;
    use crbs_core::{BuildInsert, StateStore};

    async fn seed_succeeded_build(store: &StateStore, product: &str, pkg: &str) {
        let task_id = crate::test_support::seed_task(store, product, pkg).await;
        store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase: "succeeded",
                backend: "chroot",
                user: "tester",
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    fn entry(nevra: &str, url: &str) -> SrcRpmEntry {
        SrcRpmEntry {
            nevra: nevra.to_string(),
            url: url.to_string(),
        }
    }

    fn stub_seams(entries: Vec<SrcRpmEntry>, sampled: Option<String>) -> PrepareSeams {
        PrepareSeams {
            enumerate: Arc::new(move |_: String, _: Duration, _: &Path| {
                let entries = entries.clone();
                Box::pin(async move { Ok(entries) }) as EnumFut
            }),
            sample_dist_suffix: Arc::new(move |_: String| {
                let sampled = sampled.clone();
                Box::pin(async move { sampled }) as DistFut
            }),
            // 测试退避压到 1ms；attempts=2 时 5xx 恰好打 2 次。
            download_attempts: 2,
            download_base_delay: Duration::from_millis(1),
            tmp_dir: PathBuf::from("/tmp"),
        }
    }

    fn request(product: &str, url: &str) -> PrepareBatchRequest {
        PrepareBatchRequest {
            product: product.to_string(),
            source_repo_url: url.to_string(),
            dist: None,
            arch_targets: vec!["x86_64".to_string()],
            on_failure: "continue".to_string(),
            force_all: false,
            allow_dist_mismatch: false,
            request_json: None,
        }
    }

    /// 本地 axum 测试 server：`/bad.src.rpm` 固定返回 `bad_status`（计数器验证重试预算），其余路径回 200 fake SRPM 内容。
    async fn spawn_test_server(bad_status: axum::http::StatusCode, hits: Arc<AtomicU32>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route(
                "/bad.src.rpm",
                axum::routing::get(move || {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::Relaxed);
                        bad_status
                    }
                }),
            )
            .fallback(axum::routing::get(|| async { "fake-srpm-bytes" }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[test]
    fn plan_items_skips_built_names_and_force_all_rebuilds_everything() {
        let entries = vec![
            entry("alpha-1.0-1.el9.src", "http://h/alpha-1.0-1.el9.src.rpm"),
            entry("beta-2.0-1.el9.src", "http://h/beta-2.0-1.el9.src.rpm"),
            entry("gamma-3.0-1.el9.src", "http://h/gamma-3.0-1.el9.src.rpm"),
        ];
        let built: HashSet<String> = ["alpha".to_string()].into_iter().collect();

        let (to_build, skipped) = plan_items(&entries, &built, false);
        assert_eq!(
            to_build
                .iter()
                .map(|e| e.nevra.as_str())
                .collect::<Vec<_>>(),
            vec!["beta-2.0-1.el9.src", "gamma-3.0-1.el9.src"]
        );
        assert_eq!(skipped, vec!["alpha".to_string()]);

        let (to_build, skipped) = plan_items(&entries, &built, true);
        assert_eq!(to_build.len(), 3, "force_all rebuilds everything");
        assert!(skipped.is_empty());

        let (to_build, skipped) = plan_items(&entries, &HashSet::new(), false);
        assert_eq!(to_build.len(), 3);
        assert!(skipped.is_empty());
    }

    #[test]
    fn dist_mismatch_fails_closed_on_suffix_mismatch() {
        assert!(dist_mismatch_message(".el9", ".el9").is_none());
        assert!(dist_mismatch_message(".oe2203sp4", ".oe2203sp4").is_none());
        let msg = dist_mismatch_message(".el9", ".fc42").unwrap();
        assert!(msg.contains("allow_dist_mismatch"), "override hint: {msg}");
        assert!(msg.contains("EVR conflicts"), "conflict rationale: {msg}");
    }

    /// 增量跳过按**裸源包名**命中：succeeded 构建行的 `pkg_name` 是 N-V-R（引擎
    /// 落库形态），判定集合必须取拆出的裸名列——取原文则与源仓枚举裸名永不相交。
    #[tokio::test]
    async fn plan_items_skips_bare_source_name_of_nvr_succeeded_build() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;
        seed_succeeded_build(&app.state_store, "p1", "m4a-1.0-1").await;

        let mut names = app
            .state_store
            .list_succeeded_source_names("p1")
            .await
            .unwrap();
        names.sort();
        assert_eq!(names, vec!["m4a".to_string()]);

        let entries = vec![entry(
            "m4a-1.0-1.el9.src",
            "https://h/m4a-1.0-1.el9.src.rpm",
        )];
        let built: HashSet<String> = app
            .state_store
            .list_succeeded_source_names("p1")
            .await
            .unwrap()
            .into_iter()
            .collect();
        let (to_build, skipped) = plan_items(&entries, &built, false);
        assert!(
            to_build.is_empty(),
            "source entry whose bare name has a succeeded build must be skipped"
        );
        assert_eq!(skipped, vec!["m4a".to_string()]);
    }

    /// 回归钉：准备期失败项 bump 过 `n_failed` 后，失败收口清理必须把计数器
    /// 减回，否则 `finish_batch` 总数对账拒绝、批次永久滞留 preparing 占配额。
    /// 旧路径（裸删行）保留对照断言，防回归复发。
    #[tokio::test]
    async fn prepare_failure_cleanup_clears_failed_counter_for_finish() {
        use crbs_core::FailedBatchItem;

        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;
        seed_product(&app.state_store, 2, "p2").await;
        let store = &app.state_store;

        let failed_row = FailedBatchItem {
            pkg_name: "pkg-a",
            srpm_nevra: Some("pkg-a-1.0-1"),
            error_code: "download_failed",
            error_message: "boom",
        };

        // 旧路径对照：裸 delete_batch_items 不减 n_failed → 对账 Internal 拒绝。
        let legacy = store
            .insert_batch(BatchInsert {
                product_id: Some(1),
                created_by: None,
                source_repo_url: "https://r/legacy",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store
            .insert_failed_batch_items(legacy, std::slice::from_ref(&failed_row))
            .await
            .unwrap();
        store.delete_batch_items(legacy).await.unwrap();
        let err = store
            .finish_batch(legacy, "failed", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, CrbsError::Internal(_)),
            "bare delete must leave the batch unfinishable: {err:?}"
        );

        // 收口路径：take_failed_and_clear_items 减回计数器 → finish 通过、批次落 failed。
        let fixed = store
            .insert_batch(BatchInsert {
                product_id: Some(2),
                created_by: None,
                source_repo_url: "https://r/fixed",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        store
            .insert_failed_batch_items(fixed, std::slice::from_ref(&failed_row))
            .await
            .unwrap();
        crate::server::batches::plan::take_failed_and_clear_items(store, fixed)
            .await
            .unwrap();
        store.finish_batch(fixed, "failed", None).await.unwrap();
        let batch = store.get_batch(fixed).await.unwrap().unwrap();
        assert_eq!(batch.status, "failed");
    }

    #[tokio::test]
    async fn prepare_rejects_on_product_or_global_active_batch() {
        let (app, _tmp) = setup_app().await;
        for (id, name) in [(1, "p1"), (2, "p2"), (3, "p3"), (4, "p4")] {
            seed_product(&app.state_store, id, name).await;
        }

        app.state_store
            .insert_batch(BatchInsert {
                product_id: Some(1),
                created_by: None,
                source_repo_url: "https://r/1",
                dist: None,
                arch_targets_json: None,
                on_failure: "continue",
                force_all: false,
                request_json: None,
            })
            .await
            .unwrap();
        let err = prepare_batch_with_seams(
            &app,
            request("p1", "https://r/x"),
            &stub_seams(vec![], None),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ApiError::Conflict(ref m) if m.contains("already has an active batch")),
            "product quota: {err:?}"
        );

        for (pid, url) in [(2, "https://r/2"), (3, "https://r/3")] {
            app.state_store
                .insert_batch(BatchInsert {
                    product_id: Some(pid),
                    created_by: None,
                    source_repo_url: url,
                    dist: None,
                    arch_targets_json: None,
                    on_failure: "continue",
                    force_all: false,
                    request_json: None,
                })
                .await
                .unwrap();
        }
        let err = prepare_batch_with_seams(
            &app,
            request("p4", "https://r/4"),
            &stub_seams(vec![], None),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ApiError::Conflict(ref m) if m.contains("limit")),
            "global quota: {err:?}"
        );
    }

    #[tokio::test]
    async fn prepare_rejects_unsupported_source_scheme_without_batch_row() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let err = prepare_batch_with_seams(
            &app,
            request("p1", "ftp://h/repo"),
            &stub_seams(vec![], None),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)), "{err:?}");
        assert_eq!(
            app.state_store.count_active_batches().await.unwrap(),
            0,
            "rejected before batch row creation"
        );
    }

    #[tokio::test]
    async fn prepare_dist_mismatch_fails_closed_and_override_proceeds() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let seams = stub_seams(
            vec![entry("a-1-1.el9.src", "https://h/a-1-1.el9.src.rpm")],
            Some(".ule3".to_string()),
        );
        let mut req = request("p1", "https://h/repo");
        req.dist = Some("el9".into());
        let err = prepare_batch_with_seams(&app, req.clone(), &seams)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref m) if m.contains("mismatches")),
            "{err:?}"
        );
        let batches = app.state_store.list_batches(10).await.unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].status, "failed", "mismatch must fail the batch");
        assert!(
            batches[0]
                .notes
                .as_deref()
                .unwrap_or("")
                .contains("mismatches"),
            "notes carry the reason"
        );
        assert_eq!(
            app.state_store
                .batch_item_summary(batches[0].id)
                .await
                .unwrap()
                .total(),
            0,
            "no items left behind"
        );

        // override：allow_dist_mismatch 显式放行 → 越过预检（空枚举错误证明流程已到枚举之后）。
        req.allow_dist_mismatch = true;
        let seams_pass = stub_seams(Vec::new(), Some(".ule3".to_string()));
        let err = prepare_batch_with_seams(&app, req, &seams_pass)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref m) if m.contains("no src RPMs")),
            "got past dist precheck: {err:?}"
        );
    }

    #[tokio::test]
    async fn prepare_stages_srpms_records_items_and_hands_to_planning() {
        let (app, tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;
        seed_succeeded_build(&app.state_store, "p1", "built-2.0-1.el9").await;

        let base = spawn_test_server(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Arc::new(AtomicU32::new(0)),
        )
        .await;
        let entries = vec![
            entry(
                "built-2.0-1.el9.src",
                &format!("{base}/built-2.0-1.el9.src.rpm"),
            ),
            entry(
                "good-1.0-1.el9.src",
                &format!("{base}/good-1.0-1.el9.src.rpm"),
            ),
        ];
        let seams = stub_seams(entries, None);
        let outcome =
            prepare_batch_with_seams(&app, request("p1", &format!("{base}/repo")), &seams)
                .await
                .unwrap();

        assert_eq!(outcome.to_build, vec!["good".to_string()]);
        assert_eq!(outcome.skipped_built, vec!["built".to_string()]);
        assert!(outcome.staging_failed.is_empty());

        let rec = app
            .state_store
            .get_batch(outcome.batch_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.status, "planning", "handed to planning");
        assert_eq!(rec.product_id, Some(1));
        assert!(
            rec.notes.unwrap().contains("built"),
            "skip list recorded in notes"
        );

        let pending = app
            .state_store
            .items_in_state(outcome.batch_id, "pending")
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        let item = &pending[0];
        assert_eq!(item.pkg_name, "good");
        assert_eq!(item.round, 0, "round is a placeholder until planning");
        let expected_dir = tmp
            .path()
            .join("results")
            .join("batches")
            .join(outcome.batch_id.to_string())
            .join("srpms");
        let expected = expected_dir.join("good-1.0-1.el9.src.rpm");
        assert_eq!(
            Path::new(item.srpm_staging_path.as_deref().unwrap()),
            expected
        );
        assert_eq!(
            std::fs::read(&expected).unwrap(),
            b"fake-srpm-bytes",
            "downloaded content matches"
        );

        // 权限不变量：目录 2770、文件 0660。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dmode = std::fs::metadata(&expected_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(dmode, 0o2770, "staging dir mode");
            let fmode = std::fs::metadata(&expected).unwrap().permissions().mode() & 0o777;
            assert_eq!(fmode, 0o660, "staged srpm mode");
        }
    }

    #[tokio::test]
    async fn prepare_stages_from_file_url_scheme() {
        let (app, tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let src_dir = tmp.path().join("src-repo");
        tokio::fs::create_dir_all(&src_dir).await.unwrap();
        let src = src_dir.join("local-1.0-1.el9.src.rpm");
        tokio::fs::write(&src, b"local-srpm-bytes").await.unwrap();

        let entries = vec![entry(
            "local-1.0-1.el9.src",
            &format!("file://{}", src.display()),
        )];
        let seams = stub_seams(entries, None);
        let outcome = prepare_batch_with_seams(
            &app,
            request("p1", &format!("file://{}", src_dir.display())),
            &seams,
        )
        .await
        .unwrap();

        assert_eq!(outcome.to_build, vec!["local".to_string()]);
        let pending = app
            .state_store
            .items_in_state(outcome.batch_id, "pending")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(pending[0].srpm_staging_path.as_deref().unwrap()).unwrap(),
            b"local-srpm-bytes"
        );
    }

    #[tokio::test]
    async fn prepare_single_download_failure_records_failed_item_without_aborting() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let hits = Arc::new(AtomicU32::new(0));
        let base =
            spawn_test_server(axum::http::StatusCode::INTERNAL_SERVER_ERROR, hits.clone()).await;
        let entries = vec![
            entry("bad-1.0-1.el9.src", &format!("{base}/bad.src.rpm")),
            entry(
                "good-1.0-1.el9.src",
                &format!("{base}/good-1.0-1.el9.src.rpm"),
            ),
        ];
        let seams = stub_seams(entries, None);
        let outcome =
            prepare_batch_with_seams(&app, request("p1", &format!("{base}/repo")), &seams)
                .await
                .unwrap();

        // 5xx 走值重试路径，恰好烧完注入的 2 次预算。
        assert_eq!(hits.load(Ordering::Relaxed), 2, "exhausted retry budget");
        assert_eq!(outcome.to_build, vec!["good".to_string()]);
        assert_eq!(outcome.staging_failed, vec!["bad".to_string()]);

        // 批次不中止：planning + failed item 记账（暂存路径 NULL、n_failed 同步）。
        let rec = app
            .state_store
            .get_batch(outcome.batch_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.status, "planning");
        assert_eq!(rec.n_failed, 1, "prepare-time failure bumps n_failed");
        let failed = app
            .state_store
            .items_in_state(outcome.batch_id, "failed")
            .await
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].pkg_name, "bad");
        assert_eq!(failed[0].srpm_staging_path, None);
        assert_eq!(
            failed[0].error_code.as_deref(),
            Some("srpm_download_failed")
        );

        let pending = app
            .state_store
            .items_in_state(outcome.batch_id, "pending")
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].pkg_name, "good");
    }

    #[tokio::test]
    async fn prepare_fails_batch_when_every_download_fails() {
        let (app, _tmp) = setup_app().await;
        seed_product(&app.state_store, 1, "p1").await;

        let base = spawn_test_server(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Arc::new(AtomicU32::new(0)),
        )
        .await;
        let entries = vec![
            entry("bad1-1.0-1.el9.src", &format!("{base}/bad.src.rpm")),
            entry("bad2-1.0-1.el9.src", &format!("{base}/bad.src.rpm")),
        ];
        let seams = stub_seams(entries, None);
        let err = prepare_batch_with_seams(&app, request("p1", &format!("{base}/repo")), &seams)
            .await
            .unwrap_err();
        assert!(
            matches!(err,
                ApiError::ServiceUnavailable(ref m) if m.contains("failed during staging")),
            "{err:?}"
        );

        let rec = app.state_store.list_batches(10).await.unwrap().remove(0);
        assert_eq!(rec.status, "failed", "all sources failed → batch failed");
        assert!(
            rec.notes
                .as_deref()
                .unwrap_or("")
                .contains("failed during staging"),
            "notes carry the reason"
        );
        assert_eq!(
            app.state_store
                .batch_item_summary(rec.id)
                .await
                .unwrap()
                .total(),
            0,
            "no dangling items on all-fail path"
        );
    }

    #[tokio::test]
    async fn prepare_disk_watermark_fails_remaining_files_and_batch() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        // 水位拉满 → 每个文件的水位检查都失败。
        let cfg = ServerConfig {
            min_free_disk_gb: usize::MAX,
            ..Default::default()
        };
        let app = Arc::new(AppState::for_test(store, cfg, tmp.path().to_path_buf()));
        seed_product(&app.state_store, 1, "p1").await;

        let base = spawn_test_server(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Arc::new(AtomicU32::new(0)),
        )
        .await;
        let entries = vec![
            entry("a-1.0-1.el9.src", &format!("{base}/a.src.rpm")),
            entry("b-1.0-1.el9.src", &format!("{base}/b.src.rpm")),
        ];
        let seams = stub_seams(entries, None);
        let err = prepare_batch_with_seams(&app, request("p1", &format!("{base}/repo")), &seams)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::ServiceUnavailable(_)),
            "watermark-starved staging must fail the batch: {err:?}"
        );
        let rec = app.state_store.list_batches(10).await.unwrap().remove(0);
        assert_eq!(rec.status, "failed");
    }
}
