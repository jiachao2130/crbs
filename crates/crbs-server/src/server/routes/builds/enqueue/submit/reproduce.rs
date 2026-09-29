// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 复现提交：重放能力校验、确定性前置与复现扇出参数。

use std::path::PathBuf;
use std::sync::Arc;

use axum::Json;

use crate::server::error::ApiError;
use crate::server::routes::builds::BuildOptions;
use crate::server::state::AppState;

use super::fanout::{compensate_partial_fan_out, create_task, FanOutArgs};
use super::start::{inject_noarch_target, start_build, StartBuildArgs};
use super::{ensure_arch_count_within_limit, MAX_SRPMS_PER_SUBMIT};

/// 重放路径（rebuild/reproduce）复用的提交期 fan-out 上限：SRPM 列表与 arches 来自历史记录，不得绕过规模约束。
pub(crate) fn validate_replay_caps(
    srpms: &[std::path::PathBuf],
    arches: &[String],
) -> Result<(), ApiError> {
    validate_replay_caps_by_len(srpms.len(), arches)
}

/// 长度版：reproduce 路径 SRPM 维度取 entry 条目数、arch 维度取去重 arch 集合。
pub(crate) fn validate_replay_caps_by_len(
    srpm_count: usize,
    arches: &[String],
) -> Result<(), ApiError> {
    if srpm_count > MAX_SRPMS_PER_SUBMIT {
        return Err(ApiError::Validation(format!(
            "too many SRPMs to replay: {} (max {}); split into multiple submissions",
            srpm_count, MAX_SRPMS_PER_SUBMIT
        )));
    }
    ensure_arch_count_within_limit(arches)
}

/// `reproduce_fan_out` 的参数集合（rebuild 与 auto-replay 两个复现入口共用）。
pub(crate) struct ReproduceFanOutArgs {
    pub(crate) product: String,
    pub(crate) result_dir: PathBuf,
    pub(crate) opts: BuildOptions,
    pub(crate) entries: Vec<ReproduceArchEntry>,
    pub(crate) submit_user: String,
    pub(crate) submit_user_id: Option<i64>,
    /// 源任务显示名（NEVR 真名、不带 .src.rpm；复现任务沿用此名）。
    pub(crate) source_pkg_name: String,
}

/// repro-from-srpm 模式 note 文案（纯函数，单测锚点）：声明回放值与"环境未
/// 还原"；BUILDHOST 非产品自产值时追加"仅供参考"；产品值 None 跳过比对。
pub(super) fn repro_mode_note_text(
    host: Option<&str>,
    build_time: Option<i64>,
    product_buildhost: Option<&str>,
) -> String {
    let mut note = format!(
        "\nnote: repro-from-srpm mode: BUILDHOST={} BUILDTIME={} replayed from the \
         SRPM header; build environment NOT restored, payload bytes are not guaranteed",
        host.unwrap_or("(none)"),
        build_time
            .map(|t| t.to_string())
            .unwrap_or_else(|| "(none)".to_string()),
    );
    if let Some(crbs_host) = product_buildhost {
        if host != Some(crbs_host) {
            note.push_str(
                "; BUILDHOST is not the crbs-produced value, parameters are \
                 informational only",
            );
        }
    }
    note
}

/// deterministic 提交前置断言：返回产品 deterministic 标记与
/// 解析出的产品链配置。配置读不到按非 deterministic 处理（不阻塞入队，构建
/// 启动的 merge_configs 仍是权威门）；resolved 带出供 noarch 收敛门同源复用
///（省 batches 逐 item 重复解析）。
pub(super) async fn assert_deterministic_submit_preconditions(
    app: &Arc<AppState>,
    args: &FanOutArgs,
) -> Result<(bool, Option<Arc<crbs_core::ResolvedProduct>>), ApiError> {
    let resolved = match app
        .state_store
        .resolve_any_product_by_name(&args.product)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                product = %args.product,
                error = ?e,
                "deterministic submit check: product config unavailable; skipping pre-check"
            );
            return Ok((false, None));
        }
    };
    if !resolved.config.deterministic {
        return Ok((false, Some(resolved)));
    }
    // 生效值：请求 stage > 产品 build_target > hub 全局 build_target（默认 bb）；
    // dnf_cache：产品覆盖 > hub 全局（worker 侧会用 worker 全局再各校验一次）。
    let build_target = args
        .opts
        .stage
        .as_deref()
        .or(resolved.config.build_target.as_deref())
        .unwrap_or(app.crbs_config.build_target.as_str());
    let dnf_cache_enabled = resolved
        .config
        .dnf_cache_enabled
        .unwrap_or(app.crbs_config.dnf_cache_enabled);
    crbs_core::config::validate_deterministic_preconditions(true, build_target, dnf_cache_enabled)
        .map_err(ApiError::from)?;
    Ok((true, Some(resolved)))
}

/// `reproduce_fan_out` 的单 arch 映射：要复现的来源构建 ID + 该 arch 对应的 SRPM。
pub(crate) struct ReproduceArchEntry {
    pub arch: String,
    pub source_build_id: i64,
    /// 该 arch 下要复现的 SRPM 路径（来源 task 的 source/ 中的）。
    pub srpm_path: PathBuf,
}

/// 逐条目解析回放时间锚：薄封装调 core `resolve_replay_anchor`（产物扫描 +
/// 探头语义单一源在 core），仅补本入口的目录推导与错误信封格式（arch +
/// build_id 上下文，400）；Probe 失败 warn 留痕（报文内嵌被探测文件路径）。
async fn resolve_replay_anchors(
    entries: &[ReproduceArchEntry],
) -> Result<Vec<(Option<String>, Option<i64>)>, ApiError> {
    let mut anchors = Vec::with_capacity(entries.len());
    for e in entries {
        // 源任务目录：srpm_path = {results}/{task}/source/{file}，上两级即之。
        let task_dir = e
            .srpm_path
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or_else(|| {
                ApiError::Validation(format!(
                    "replay time-anchor probe failed for {} build {}: srpm path layout \
                     unexpected",
                    e.arch, e.source_build_id
                ))
            })?;
        let build_dir = task_dir.join(&e.arch).join(e.source_build_id.to_string());
        let anchor = crbs_core::engine::reproduce::resolve_replay_anchor(&build_dir, None)
            .await
            .map_err(|err| {
                if matches!(
                    err,
                    crbs_core::engine::reproduce::ReplayAnchorError::Probe(_)
                ) {
                    tracing::warn!(
                        arch = %e.arch,
                        build_id = e.source_build_id,
                        error = ?err,
                        "reproduce fan-out: replay anchor probe failed"
                    );
                    ApiError::Validation(format!(
                        "replay time-anchor probe failed for {} build {} (corrupt artifact?)",
                        e.arch, e.source_build_id
                    ))
                } else {
                    ApiError::Validation(format!(
                        "replay time-anchor probe failed for {} build {}: {err}",
                        e.arch, e.source_build_id
                    ))
                }
            })?;
        anchors.push((anchor.build_host, anchor.build_time));
    }
    Ok(anchors)
}

/// 创建 Task 并按"来源子构建逐个"展开 reproduce 子构建：每个子构建的
/// `opts.reproduce_from_build_id` 指向各自来源 build（非统一选项重放），task
/// 级 `opts`（priority 等）复用；发布轴例外——入口统一强制不发布（重放隔离，
/// 见函数体注）。展开非原子，补偿取消与守护窗口与 `fan_out_builds` 同型。
pub(crate) async fn reproduce_fan_out(
    app: Arc<AppState>,
    args: ReproduceFanOutArgs,
) -> Result<(i64, Vec<i64>), ApiError> {
    let ReproduceFanOutArgs {
        product,
        result_dir,
        mut opts,
        entries,
        submit_user,
        submit_user_id,
        source_pkg_name,
    } = args;
    // 重放隔离：reproduce 子构建一律不发布——重放 build_id 更大，发布端
    // MAX(build_id) newest-wins 叠加重放跳签，会把未签名且可能字节漂移的 RPM
    // 顶进发布 repo；两条入口在此一次强制，且须先于 request_json 序列化。
    opts.no_publish = Some(true);
    // repro-from-srpm 旗标剥除：环境重放语义独立，task 级 request_json 不携带。
    // 时间锚保留：逐架构探对应源构建产物头，注入 build 级 arch_opts——不钉则
    // 墙钟烧进 BUILDTIME 头与 payload mtime，同源两次回放字节必不同。
    opts.repro_from_srpm = false;
    opts.replay_build_host = None;
    opts.replay_build_time = None;
    let request_json = serde_json::to_string(&opts)
        .map_err(|e| ApiError::log_and_internal_with_context("serialize task build options", e))?;

    // 复用 fan_out 的 task 创建，srpm_paths 取自 entries：单包多 arch 任务下
    // 各 entry 引用同一 SRPM，按文件名去重避免 create_task 报重名。
    let mut srpm_paths: Vec<PathBuf> = Vec::new();
    for e in &entries {
        if !srpm_paths
            .iter()
            .any(|s| s.file_name() == e.srpm_path.file_name())
        {
            srpm_paths.push(e.srpm_path.clone());
        }
    }
    let args = FanOutArgs {
        product: product.clone(),
        result_dir: result_dir.clone(),
        srpm_paths: srpm_paths.clone(),
        opts: opts.clone(),
        arches: vec![],
        submit_user: submit_user.clone(),
        submit_user_id,
        allow_move: false,
        // 该 args 只喂 create_task，不走扇出循环；reproduce 无收敛语义。
        collapse_noarch: false,
        arch_explicit: false,
        // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
        skip_unsupported_arches: true,
        // 复现任务沿用源任务的显示名（NEVR 真名，不从文件名重新派生——用户
        // 可能重命名过 SRPM，文件名与源构建时的包名已不一致）；落盘名带
        // .src.rpm 后缀，与 fan-out 落盘口径一致。
        source_names: vec![format!("{source_pkg_name}.src.rpm")],
        // 复现任务不继承源任务标签：标签是提交时声明的元数据。
        task_labels: Vec::new(),
    };
    let (task_id, task_dir, source_srpms, mut guard) =
        create_task(app.clone(), &args, &request_json).await?;

    // deterministic 打标：reproduce_fan_out 不走 fan_out_builds，hub 行 deterministic 恒 0
    //（引擎打标只写 worker 本地库），与 fan_out_builds 同款按产品配置翻转标记；
    // 重放不经过确定性前置断言（原构建已过，引擎侧仍是权威门）。
    let deterministic = match app.state_store.resolve_any_product_by_name(&product).await {
        Ok(r) => r.config.deterministic,
        Err(e) => {
            tracing::warn!(
                product = %product,
                error = %e,
                "reproduce fan-out: product config unavailable; skipping deterministic tagging"
            );
            false
        }
    };

    // 血缘锚：所有复现构建都落内容哈希（重放与比对以其为锚）。
    let mut canonical_sha_by_source: std::collections::HashMap<PathBuf, String> =
        std::collections::HashMap::new();
    for source in &source_srpms {
        match crbs_core::engine::artifact_harvest::sha256_file(source).await {
            Ok(sha) => {
                canonical_sha_by_source.insert(source.clone(), sha);
            }
            Err(e) => {
                tracing::warn!(
                    path = %source.display(),
                    error = %e,
                    "Failed to hash source SRPM for canonical anchor; leaving NULL"
                );
            }
        }
    }

    // entries 与 source_srpms 按文件名对齐（create_task 按输入序复制）。noarch
    // 注入与 fan_out_builds 同款，但对解析 Err 硬失败：注入只在 opts.target 为
    // 空时生效，此时解析失败 = 注入不可判定——静默跳过会让 noarch 重放以宿主
    // arch lead 落盘、系统性 diff 污染复现率分母（显式 target 下探针整体跳过）。
    // 此处位于首个子构建建成前（guard 仍 armed，Drop 会清理 task），直接返回、
    // 无需补偿。
    let srpm_arches: std::collections::HashMap<PathBuf, String> = if opts.target.is_none() {
        let mut map = std::collections::HashMap::new();
        for (res, path) in crbs_core::engine::depsolve::parse_arch_from_srpms(&source_srpms, None)
            .await
            .into_iter()
            .zip(source_srpms.iter().cloned())
        {
            match res {
                Ok(arch) => {
                    map.insert(path, arch);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = ?e,
                        "reproduce fan-out: SRPM arch parse failed; refusing replay"
                    );
                    // 路径不进 400 信封——只回显文件名；探针错误 Display 内嵌
                    // SRPM 全路径（rpm -qp 报文含文件参数），只在上方 warn 留痕。
                    return Err(ApiError::Validation(format!(
                        "replay arch probe failed for {}: refusing replay that would \
                         compare against mismatched lead arch (noarch target injection \
                         undecidable)",
                        path.file_name().and_then(|n| n.to_str()).unwrap_or("srpm")
                    )));
                }
            }
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    // 时间锚：失败发生在首个子构建建成前（guard armed，Drop 收口 task）。
    let anchors = resolve_replay_anchors(&entries).await?;

    let mut ids = Vec::with_capacity(entries.len());
    for (entry, (anchor_host, anchor_time)) in entries.iter().zip(anchors.iter()) {
        // 不变量：srpm_paths 按 entries 文件名去重生成，匹配键与去重键一致，
        // position 必然命中；不命中即服务端 bug，按 Internal 返回不归咎客户端。
        let src_idx = srpm_paths
            .iter()
            .position(|s| s.file_name() == entry.srpm_path.file_name())
            .ok_or_else(|| {
                ApiError::Internal(format!(
                    "reproduce fan-out: srpm for arch {} not found in task sources",
                    entry.arch
                ))
            })?;
        let source_srpm = source_srpms[src_idx].clone();

        let mut arch_opts = opts.clone();
        arch_opts.arch = Some(entry.arch.clone());
        arch_opts.arch_list.clear();
        arch_opts.reproduce_from_build_id = Some(entry.source_build_id);
        arch_opts.replay_build_host = anchor_host.clone();
        arch_opts.replay_build_time = *anchor_time;
        if let Some(srpm_arch) = srpm_arches.get(&source_srpm) {
            if let Some(t) = inject_noarch_target(srpm_arch, arch_opts.target.as_deref()) {
                arch_opts.target = Some(t);
            }
        }

        let canonical_sha = canonical_sha_by_source.get(&source_srpm).cloned();
        // noarch 复现钉源宿主：依赖快照按源构建宿主架构锁定，任凭其它架构
        // worker 领取必然解析失败（快照包集与宿主架构不符）。源构建无归属
        // 记录时回退开放行 + warn，不阻断复现。
        let noarch_host_pin = if entry.arch == "noarch" {
            match app.state_store.build_host_arch(entry.source_build_id).await {
                Ok(host @ Some(_)) => host,
                Ok(None) => {
                    tracing::warn!(
                        source_build_id = entry.source_build_id,
                        "noarch replay source has no worker attribution; dispatching unrestricted"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(
                        source_build_id = entry.source_build_id,
                        error = %e,
                        "noarch replay host lookup failed; dispatching unrestricted"
                    );
                    None
                }
            }
        } else {
            None
        };
        let (_, Json(resp)) = match start_build(
            app.clone(),
            StartBuildArgs {
                task_id,
                task_dir: task_dir.clone(),
                source_srpm,
                product: product.clone(),
                srpm_path: entry.srpm_path.clone(),
                opts: arch_opts,
                uploaded: false,
                pkg_name: None,
                submit_user: submit_user.clone(),
                submit_user_id,
                canonical_srpm_sha256: canonical_sha,
                host_arches: noarch_host_pin,
            },
        )
        .await
        {
            Ok(ok) => ok,
            // 部分展开：补偿取消已建子构建后返回原始错误（不被补偿噪声掩盖）。
            Err(e) => {
                tracing::warn!(
                    task_id,
                    error = ?e,
                    "fan-out incomplete; cancelling already-created child builds"
                );
                compensate_partial_fan_out(&app, task_id).await;
                return Err(e);
            }
        };
        if deterministic {
            for id in &resp.ids {
                if let Err(e) = app.state_store.set_build_deterministic(*id, true).await {
                    tracing::warn!(
                        task_id,
                        build_id = id,
                        error = %e,
                        "Failed to set builds.deterministic flag at reproduce fan-out"
                    );
                }
            }
        }
        ids.extend(resp.ids);
        guard.disarm();
    }

    Ok((task_id, ids))
}
