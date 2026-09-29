// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建启动：repo 轴解析、链可见性检查与构建行落库。

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Json;
use crbs_core::types::PRIORITY_DEFAULT;

use crate::server::auth::visibility::{check_chain_visibility, is_product_content_visible_to};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::builds::types::BuildResponse;
use crate::server::routes::builds::validation::ensure_disk_space;
use crate::server::routes::builds::BuildOptions;
use crate::server::state::AppState;

use super::super::execute::{mark_build_failed, warn_mark_build_failed};

/// `start_build` 的参数集合，避免函数参数过多。
pub(crate) struct StartBuildArgs {
    pub task_id: i64,
    pub task_dir: PathBuf,
    pub source_srpm: PathBuf,
    pub product: String,
    pub srpm_path: PathBuf,
    pub opts: BuildOptions,
    pub uploaded: bool,
    /// 任务真名覆盖（SRPM header N-V-R）：fan-out 按解析值传入，hub 本地
    /// 直构建为 None（文件名即可信）。优先于 srpm_display_name 派生。
    pub pkg_name: Option<String>,
    pub submit_user: String,
    pub submit_user_id: Option<i64>,
    /// 血缘锚：source SRPM 原样字节 sha256（fan-out 侧每份 source 计算
    /// 一次、任务内全部架构子构建共享；哈希失败降级 None 不落列）。
    pub canonical_srpm_sha256: Option<String>,
    /// 调度宿主约束 CSV：仅 arch='noarch' 行落值（语义见 builds.host_arches
    /// 列注）。None 时 noarch 行按"显式架构集 > 产品偏好集"在 start_build
    /// 内物化；复现入口传入源宿主单架构覆盖。
    pub host_arches: Option<String>,
}

/// noarch 宿主偏好集物化（产品配置 → CSV）：集合语义无序，非空即约束，
/// 空/未配置/解析失败 = None（不限制）。解析失败 fail-open + warn
///——偏好是调度优化不是安全裁决，配置读不到不应阻断构建提交。
async fn materialize_noarch_host_preference(app: &Arc<AppState>, product: &str) -> Option<String> {
    match app.state_store.resolve_any_product_by_name(product).await {
        Ok(r) => {
            // Resolve 出口已拒绝 noarch token；这里再防御一次旧配置/旁路，
            // 避免把内容语义物化成永无 worker 匹配的宿主集。
            let hosts: Vec<&str> = r
                .config
                .noarch_preferred_arches
                .iter()
                .map(String::as_str)
                .filter(|a| *a != "noarch")
                .collect();
            (!hosts.is_empty()).then(|| hosts.join(","))
        }
        Err(e) => {
            tracing::warn!(
                product,
                error = %e,
                "noarch host preference unavailable; dispatching without restriction"
            );
            None
        }
    }
}

/// 消费轴生效值合流（纯函数）：产品可见性 public ∧ 产品 `repo-consume` 未
/// 关闭 ∧ 未逐构建收紧（--no-consume）。private 产品一票否决；逐构建只许
/// 收紧、无放宽旗标。
pub(super) fn repo_consume_effective(
    product_public: bool,
    product_consume: Option<bool>,
    cli_no_consume: bool,
) -> bool {
    product_public && product_consume.unwrap_or(true) && !cli_no_consume
}

/// 双轴生效值合流（提交时快照）：发布轴 = 逐构建未收紧（--no-publish）；消费
/// 轴经 [`repo_consume_effective`] 三因子合流。产品行缺失或链解析失败不阻塞
/// 入队（同 resolve_arches 兜底口径），消费轴按收紧快照（可见性未知 / 坏链
/// 的构建在 dispatch 水合处本就被拒）、发布轴不受牵连；仅 DB 故障如实上抛。
pub(super) async fn resolve_repo_axis_flags(
    app: &Arc<AppState>,
    product: &str,
    opts: &BuildOptions,
) -> Result<(bool, bool), ApiError> {
    let repo_publish = opts.no_publish != Some(true);
    let visibility_public = match app.state_store.get_product_by_name(product).await {
        Ok(Some(record)) => record.visibility == crbs_core::VISIBILITY_PUBLIC,
        Ok(None) => {
            // 历史游离产品：可见性未知按非公开收紧；dispatch 对无产品行本就拒绝派发。
            tracing::warn!(
                product = %product,
                "product row missing at submit; snapshotting repo_consume=0 (fail-closed)"
            );
            return Ok((repo_publish, false));
        }
        Err(e) => {
            return Err(ApiError::log_and_internal_with_context(
                "lookup product for repo axis flags",
                e,
            ));
        }
    };
    let resolved = match app.state_store.resolve_any_product_by_name(product).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                product = %product,
                error = %e,
                "cannot resolve product config at submit; snapshotting repo_consume=0 (fail-closed)"
            );
            return Ok((repo_publish, false));
        }
    };
    let repo_consume = repo_consume_effective(
        visibility_public,
        resolved.config.repo_consume,
        opts.no_consume,
    );
    Ok((repo_publish, repo_consume))
}

pub(crate) async fn start_build(
    app: Arc<AppState>,
    args: StartBuildArgs,
) -> Result<(StatusCode, Json<BuildResponse>), ApiError> {
    let StartBuildArgs {
        task_id,
        task_dir,
        source_srpm,
        product,
        srpm_path,
        opts,
        uploaded,
        submit_user,
        submit_user_id,
        canonical_srpm_sha256,
        pkg_name,
        host_arches,
    } = args;

    ensure_disk_space(&app.crbs_root, app.server_config.min_free_disk_bytes()).await?;

    let pkg_name =
        pkg_name.unwrap_or_else(|| crbs_core::util::srpm_display_name(&srpm_path).to_string());
    let file_name = srpm_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown.src.rpm")
        .to_string();

    // 纯入队：后台调度器统一按优先级消费 pending 任务。
    let identity = crbs_core::engine::BuildIdentity::new(&product, &pkg_name);
    let context = crbs_core::engine::BuildContext::new(opts.priority.unwrap_or(PRIORITY_DEFAULT))
        .with_user(&submit_user, submit_user_id)
        .with_crbs_pid(Some(std::process::id() as i64))
        .with_task_id(Some(task_id))
        // arch 是提交时已知的派发键，随 insert 落定——insert_build 事务内的
        // 活跃去重复查才能按真值 arch 命中（NULL 插入事后补写会让并发双提交
        // 复查 (pkg, 'x86_64') vs NULL 不命中而照样插入）。
        .with_arch(opts.arch.as_deref());

    // noarch 行的调度宿主约束单点物化：调用方覆盖优先（复现钉源宿主；fan-out
    // 的显式架构点名也走覆盖传入——arch_list 在 fan-out 已清空，此处读不到）；
    // 无覆盖时按产品偏好集。覆盖收敛与忠实还原（rebuild）两条产源——所有
    // arch='noarch' 行都经 start_build 落库，此处即唯一咽喉。
    let host_arches_csv = match host_arches {
        Some(v) => Some(v),
        None if opts.arch.as_deref() == Some("noarch") => {
            materialize_noarch_host_preference(&app, &product).await
        }
        None => None,
    };
    let context = context.with_host_arches(host_arches_csv.as_deref());
    // 双轴生效值合流（提交时快照进 builds.repo_publish / repo_consume，发布
    // 候选集与 dispatch 注入各自直读列）：发布轴 = 逐构建未收紧；消费轴 =
    // 产品可见性 public ∧ 产品 repo-consume 未关闭 ∧ 未逐构建收紧。private
    // 产品对消费轴一票否决在提交时落定，逐构建只有收紧旗标、无放宽形态。
    let (repo_publish, repo_consume) = resolve_repo_axis_flags(&app, &product, &opts).await?;
    let context = context.with_repo_flags(repo_publish, repo_consume);
    // 放置契约下限随 insert 落列（req_min_*）：fan_out 子构建继承 = 同一 opts
    // 源逐行传入；rebuild/reproduce 沿 request_json 反序列化 → 同一解析链自动
    // 继承，无需额外搬运。声明落列不受 requirements 开关影响（消费才受开关）。
    let req_min =
        crbs_core::build_options::ReqMinKb::from_options(&opts).map_err(ApiError::from)?;
    let context = context.with_req_min(req_min.mem, req_min.ncpu, req_min.disk);
    let lifecycle = match crbs_core::engine::BuildLifecycle::new_with_task(
        app.state_store.clone(),
        &identity,
        &context,
    )
    .await
    {
        Ok(l) => l,
        // insert_build 事务内复查命中同 product+pkg+arch 活跃构建（入口去重
        // 与 INSERT 之间的并发窗口）→ Conflict 保持 409；其余 500 + 日志。
        Err(e @ crbs_core::error::CrbsError::Conflict { .. }) => return Err(ApiError::from(e)),
        Err(e) => {
            return Err(ApiError::log_and_internal_with_context(
                "create build lifecycle",
                e,
            ));
        }
    };

    let build_id = lifecycle.build_id();

    // 创建该架构的结果子目录。build 行已插入：失败同样 build 级清理
    //（cleanup 对 NotFound 静默）。
    if let Some(ref arch) = opts.arch {
        let arch_dir = task_dir.join(arch);
        if let Err(e) = tokio::fs::create_dir_all(&arch_dir).await {
            cleanup_on_enqueue_failure(&srpm_path, uploaded).await;
            if let Err(e2) =
                mark_build_failed(&app.state_store, build_id, Some(&e.to_string())).await
            {
                warn_mark_build_failed(&e2, "arch dir error");
            }
            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
            return Err(ApiError::log_and_internal_with_context(
                "create arch result dir",
                e,
            ));
        }
    }

    // 暂存 SRPM 到 upload_dir（崩溃可恢复）；多包下各子构建独立 staging 路径，
    // Worker 下载时可用 task source 作为源。
    let staged_path = match crate::server::staging::stage_srpm(
        &app.upload_dir(),
        &build_id.to_string(),
        &srpm_path,
        &file_name,
        uploaded,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            cleanup_on_enqueue_failure(&srpm_path, uploaded).await;
            if let Err(e2) = mark_build_failed(&app.state_store, build_id, Some(e.message())).await
            {
                warn_mark_build_failed(&e2, "staging error");
            }
            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
            return Err(e);
        }
    };

    // heavy steering 的 SRPM 大小落列（staging 后 stat 暂存副本即原样字节；
    // 失败仅 warn 留痕——缺失由消费侧"无值不分桶"兜底，不回滚已建构建）。
    match tokio::fs::metadata(&staged_path).await {
        Ok(meta) => {
            let size = meta.len();
            if let Err(e) = app
                .state_store
                .set_build_srpm_size_bytes(build_id, i64::try_from(size).unwrap_or(i64::MAX))
                .await
            {
                tracing::warn!(
                    build_id = build_id,
                    size = size,
                    error = %e,
                    "Failed to set srpm_size_bytes at enqueue"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                build_id = build_id,
                path = %staged_path.display(),
                error = %e,
                "Failed to stat staged SRPM; leaving srpm_size_bytes NULL"
            );
        }
    }

    // 持久化构建选项，用于崩溃恢复。
    let request_json = match serde_json::to_string(&opts) {
        Ok(s) => s,
        Err(e) => {
            cleanup_on_enqueue_failure(&srpm_path, uploaded).await;
            let _ = tokio::fs::remove_file(&staged_path).await;
            if let Err(e2) =
                mark_build_failed(&app.state_store, build_id, Some(&e.to_string())).await
            {
                warn_mark_build_failed(&e2, "serialization error");
            }
            crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
            return Err(ApiError::log_and_internal_with_context(
                "serialize build options",
                e,
            ));
        }
    };

    if let Err(e) = app
        .state_store
        .set_build_request_info(build_id, source_srpm.to_str().unwrap_or(""), &request_json)
        .await
    {
        cleanup_on_enqueue_failure(&srpm_path, uploaded).await;
        let _ = tokio::fs::remove_file(&staged_path).await;
        if let Err(e2) = mark_build_failed(&app.state_store, build_id, Some(&e.to_string())).await {
            warn_mark_build_failed(&e2, "db error");
        }
        crate::server::replay::spawn_on_build_terminal(app.clone(), build_id);
        return Err(ApiError::log_and_internal_with_context(
            "persist build request info",
            e,
        ));
    }

    // 血缘锚落列（fan-out 侧预算传入，任务内全部架构子构建共享）；
    // 失败仅 warn——锚缺失由比对侧口径暴露，不回滚已建构建。
    if let Some(sha) = canonical_srpm_sha256.as_deref() {
        if let Err(e) = app
            .state_store
            .set_build_canonical_srpm_sha256(build_id, sha)
            .await
        {
            tracing::warn!(
                build_id = build_id,
                error = %e,
                "Failed to set canonical_srpm_sha256 at enqueue"
            );
        }
    }

    // 目标架构已随 insert_build 落定（上方 with_arch），事务内去重复查天然
    // 覆盖，无需事后补写（NULL arch 行会与兄弟构建撞 NULL-NULL 去重致 409）。

    Ok((
        StatusCode::ACCEPTED,
        Json(BuildResponse {
            task_id,
            ids: vec![build_id],
            phase: "pending",
            product,
            submitted_at: chrono::Utc::now(),
            pkg_name: pkg_name.clone(),
            // 单构建入队路径不经 fan-out 预检：恒空。
            skipped_arches: Vec::new(),
            req_min_mem_kb: req_min.mem,
            req_min_ncpu: req_min.ncpu,
            req_min_disk_kb: req_min.disk,
        }),
    ))
}

async fn cleanup_on_enqueue_failure(srpm_path: &std::path::Path, uploaded: bool) {
    if uploaded {
        if let Err(e) = tokio::fs::remove_file(srpm_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %srpm_path.display(), error = %e, "Failed to clean up temp srpm");
            }
        }
    }
}

/// 检查整条继承链上所有节点对当前用户是否可见（build 提交版本）。
/// 向后兼容：产品不在数据库中（磁盘配置产品）时跳过链检查。
pub(crate) async fn check_build_chain_visibility(
    app: &Arc<AppState>,
    product: &str,
    auth_ctx: Option<&AuthContext>,
) -> Result<(), ApiError> {
    let record = match app.state_store.get_product_by_name(product).await? {
        Some(r) => r,
        None => return Ok(()),
    };

    if !is_product_content_visible_to(record.owner_id, &record.visibility, &record.name, auth_ctx) {
        return Err(ApiError::not_found("product", product));
    }

    check_chain_visibility(app, record.id, auth_ctx).await
}

/// 纯 noarch SRPM 的 `--target noarch` 注入判定。CLI 本地构建对
/// 纯 noarch 自动注入 target=noarch（lead archnum=255）；hub 不注入时 lead =
/// worker 宿主 arch——同一 SRPM 的 CLI 重建与 hub 产物恒差 1 字节、异构
/// worker 产出互不相同（cross-arch 互比系统性误报）。显式 target 优先不覆盖；
/// 解析失败：新提交路径保守跳过、重放路径 target 为空时硬失败。
pub(super) fn inject_noarch_target(srpm_arch: &str, existing: Option<&str>) -> Option<String> {
    if srpm_arch == "noarch" && existing.is_none() {
        Some("noarch".to_string())
    } else {
        None
    }
}

/// 输入 arch 列表归一（映射后 sort+dedup）：noarch 对"每架构扇出"无意义
///（扇出维度是具体架构），须映射为具体 arch——目标优先取输入列表首个非
/// noarch 项（取产品首 arch 会无中生有用户未请求的 arch），输入全 noarch 时
/// 退回产品首个具体 arch；非产品子集由调用方校验拒绝。收敛构建的行级 arch
/// 由 fan_out 落语义值 "noarch"，与本映射正交。纯 noarch（或空）产品无从
/// 映射，提交即拒。
pub(crate) fn map_noarch_to_concrete(
    arches: Vec<String>,
    product_arches: &[String],
    product: &str,
) -> Result<Vec<String>, ApiError> {
    if !arches.iter().any(|a| a == "noarch") {
        return Ok(arches);
    }
    let concrete = arches
        .iter()
        .find(|a| a.as_str() != "noarch")
        .cloned()
        .or_else(|| {
            product_arches
                .iter()
                .find(|a| a.as_str() != "noarch")
                .cloned()
        });
    let Some(concrete) = concrete else {
        return Err(ApiError::Validation(format!(
            "product '{}' declares no concrete arch; noarch builds cannot be dispatched",
            product
        )));
    };
    tracing::warn!(
        product = %product,
        concrete_arch = %concrete,
        "noarch is not dispatchable; mapping to input's (or product's) first concrete arch"
    );
    let mut mapped: Vec<String> = arches
        .into_iter()
        .map(|a| if a == "noarch" { concrete.clone() } else { a })
        .collect();
    mapped.sort();
    mapped.dedup();
    Ok(mapped)
}

/// 解析最终架构列表（Hub 层兜底验证）。
pub(crate) async fn resolve_arches(
    app: &Arc<AppState>,
    product: &str,
    cli_arches: Option<&[String]>,
    _auth_ctx: Option<&AuthContext>,
) -> Result<Vec<String>, ApiError> {
    // 产品级 arches 取 resolve_any_product_by_name 返回的 `ResolvedProduct`；
    // miss/失败走兜底（不阻塞入队）。
    let resolved = app.state_store.resolve_any_product_by_name(product).await;

    let cli_arches_flat: Vec<String> = cli_arches
        .iter()
        .flat_map(|slice| slice.iter())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // HTTP 用户输入边界 fail-closed：逐段（含逗号分隔每段）过 validate_arch
    // 白名单，空串/注入/穿越在此 400，不落到 repo baseurl 拼接。
    for entry in cli_arches.iter().flat_map(|slice| slice.iter()) {
        for part in entry.split(',') {
            crbs_core::validation::validate_arch(part.trim())?;
        }
    }

    let product_arches = match resolved {
        Ok(r) => r.config.arches.clone(),
        Err(e) => {
            tracing::warn!(product = %product, error = %e, "Failed to read product config for arch resolution");
            if !cli_arches_flat.is_empty() {
                // CLI noarch 需产品 arches 才能映射成派发键；放行会产出永不
                // 派发的死构建，故拒绝（用户可重试 / 检查产品配置）。
                if cli_arches_flat.iter().any(|a| a == "noarch") {
                    return Err(ApiError::Validation(
                        "cannot resolve product arches to map noarch; product config unavailable"
                            .into(),
                    ));
                }
                let mut unique = cli_arches_flat;
                unique.sort();
                unique.dedup();
                return Ok(unique);
            }
            return Ok(vec![local_arch()]);
        }
    };

    // 产品声明的 arches 同样逐个校验：配置数据不可信边界（DB 历史配置可能
    // 早于本校验写入），fail-closed 拒绝非法值。
    for arch in &product_arches {
        crbs_core::validation::validate_arch(arch)?;
    }

    if !cli_arches_flat.is_empty() {
        let mut unique = cli_arches_flat;
        unique.sort();
        unique.dedup();
        // noarch 只是打包属性不是派发键：先映射为具体 arch（映射值取自输入或产品配置，输入侧产品外 arch 由下方子集校验拒绝）。
        let unique = map_noarch_to_concrete(unique, &product_arches, product)?;
        if !product_arches.is_empty() {
            for arch in &unique {
                if !product_arches.contains(arch) {
                    return Err(ApiError::Validation(format!(
                        "arch '{}' not in product '{}' supported arches: {:?}",
                        arch, product, product_arches
                    )));
                }
            }
        }
        return Ok(unique);
    }

    if !product_arches.is_empty() {
        // 产品声明含 noarch 同样映射——fan-out 不得产出永不派发的 arch='noarch' 子构建（纯 noarch 产品报 Validation）。
        return map_noarch_to_concrete(product_arches.clone(), &product_arches, product);
    }

    Ok(vec![local_arch()])
}

fn local_arch() -> String {
    std::env::consts::ARCH.to_string()
}
