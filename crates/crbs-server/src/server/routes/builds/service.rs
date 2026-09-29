// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建路由服务层：取消、发布与查询的共享业务逻辑。

use std::path::Path;
use std::sync::Arc;

use crate::server::auth::visibility::{
    compute_visible_products, ensure_product_visible_for_record,
};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::artifacts::collect_rpm_file_names;
use crate::server::routes::builds::types::{BuildListResponse, ListQuery};
use crate::server::state::AppState;

/// 取消构建的结果。
pub(crate) struct CancelBuildOutcome {
    pub cancelled: bool,
    pub message: String,
}

/// publish/unpublish 构建的结果（供 HTTP 层组装响应）。
pub(crate) struct PublishBuildOutcome {
    /// 翻转后的发布轴值（publish=true / unpublish=false）。
    pub repo_publish: bool,
    /// 该构建所属产品（regen 目标）。
    pub product: String,
    /// 同步 regen 的统计。
    pub report: crbs_core::engine::repo_publish::RepoAssembleReport,
}

/// 翻转某构建的发布轴 `repo_publish` 标志并同步重建该产品发布 repo。
/// ACL 复用 `can_cancel`（admin/operator 或原构建提交者）。产品声明签名策略
/// 时 publish 要求构建已签名（未签名 → 409，先 `sign` 再发布）。失败归属：
/// DB 翻标志毫秒级，同步 regen 撞 `.repodata-{arch}.lock` 超时报 500
/// （可重试 / `rebuild-repo` 兜底），不归于构建。
pub(crate) async fn set_build_publish_for_user(
    app: &Arc<AppState>,
    build_id: i64,
    publish: bool,
    auth: Option<&AuthContext>,
) -> Result<PublishBuildOutcome, ApiError> {
    let ctx = auth.ok_or(ApiError::Unauthorized(
        "authentication required to publish/unpublish".into(),
    ))?;
    let record = app
        .state_store
        .get_build(build_id)
        .await?
        .ok_or_else(|| ApiError::not_found("build", build_id))?;

    if !ctx.can_cancel(&record.user) {
        return Err(ApiError::PermissionDenied(
            "you do not have permission to publish/unpublish this build".into(),
        ));
    }

    // 签名策略门控：产品声明了签名策略时，未签名构建不得发布（显式操作
    // fail-closed：策略解析失败直接拒绝，操作员可重试）。持 `.sign.lock`
    // 跨标志翻转与 regen——与 report_result succeeded 臂同序，防 createrepo
    // 读到并发签名中的字节。unpublish 不受门控。
    let mut _sign_guard = None;
    if publish {
        let requires_signed = match app
            .state_store
            .load_merged_config_for_any_product_by_name(&record.product)
            .await
        {
            Ok(config) => crbs_core::sign::SignConfig::signing_required(&config),
            Err(e) => {
                return Err(ApiError::log_and_internal_with_context(
                    "resolve signing policy for publish",
                    e,
                ))
            }
        };
        if requires_signed {
            if !record.signed {
                return Err(ApiError::Conflict("publish_requires_signed_build".into()));
            }
            if let Some(ref result_dir) = record.result_dir {
                _sign_guard = Some(
                    crbs_core::sign::acquire_result_dir_sign_lock(Path::new(result_dir))
                        .await
                        .map_err(|e| {
                            ApiError::log_and_internal_with_context(
                                "acquire sign lock for publish",
                                e,
                            )
                        })?,
                );
            }
        }
    }

    app.state_store
        .set_build_repo_publish(build_id, publish)
        .await?;

    let report = crate::server::repo_regen::assemble_for_product(app, &record.product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("regenerate product repo", e))?;

    let detail = serde_json::json!({
        "repo_publish": publish,
        "product": record.product,
        "arches": report.arches,
    })
    .to_string();
    let action = if publish {
        "publish_build"
    } else {
        "unpublish_build"
    };
    let _ = app
        .state_store
        .audit_log(
            &ctx.user,
            &ctx.role,
            action,
            Some(&build_id.to_string()),
            Some(&detail),
        )
        .await;

    Ok(PublishBuildOutcome {
        repo_publish: publish,
        product: record.product,
        report,
    })
}

/// 获取单个构建记录并收集 RPM 文件名；可见性为产品级单层（public / owner /
/// ACL / operator+；孤儿产品按公开）。
pub(crate) async fn fetch_build_with_rpms(
    app: &Arc<AppState>,
    build_id: i64,
    auth: Option<&AuthContext>,
) -> Result<crbs_core::BuildRecord, ApiError> {
    let mut record = app
        .state_store
        .get_build(build_id)
        .await?
        .ok_or_else(|| ApiError::not_found("build", build_id))?;

    ensure_product_visible_for_record(app, &record.product, auth).await?;

    // 本路由族以磁盘为展示真值：collect_rpm_file_names 现场扫 result_dir 填
    // record.rpms，不碰 build_artifacts.on_disk 列；产物列表与 UI 产物卡走
    // list_artifacts 的 DB on_disk=1 行（harvest 快照 + GC 软删记账），漂移由
    // GC 收敛——切 DB 源会把"磁盘已删未收敛"窗口错报为有产物。
    // ponytail: 漂移影响面扩大或扫盘成本成问题时，再评估单源化。
    if let Some(ref result_dir) = record.result_dir {
        let result_root = app.result_dir_for_or_default(&record.product).await;
        let _validated = crbs_core::util::validate_result_dir(result_dir, &result_root)
            .await
            .map_err(|e| {
                // Validation 细节含服务端绝对路径，只进日志不进响应（error.rs 同款脱敏），状态码保持 400。
                tracing::warn!(build_id = %build_id, error = %e, "Invalid result_dir while fetching build detail");
                ApiError::Validation("invalid result_dir".into())
            })?;
        record.rpms = match collect_rpm_file_names(Path::new(result_dir)).await {
            Ok(rpms) => rpms,
            Err(e) => {
                tracing::warn!(build_id = %build_id, error = %e, "Failed to collect rpm file names");
                Vec::new()
            }
        };
    }

    Ok(record)
}

/// 列出构建（API 与 UI 共用核心），按认证上下文过滤；`priority` 仅 UI 过滤
/// 下拉使用（API `ListQuery` 不含该字段，恒传 `None`）。
/// 可见性为产品级单层：public 产品 / owner / ACL 授权（operator/admin 全见；
/// 匿名只见 public 产品），过滤下沉 SQL 层（`filter.visible_products` 白名单）
/// 且在分页**前**完成；孤儿豁免（产品已删的构建对所有人可见）由 SQL
/// `NOT IN (SELECT name FROM products)` 负责。可见产品内全部提交者的记录同权可见。
pub(crate) async fn list_builds_for_user(
    app: &Arc<AppState>,
    q: &ListQuery,
    auth: Option<&AuthContext>,
    priority: Option<crbs_core::types::BuildPriority>,
) -> Result<BuildListResponse, ApiError> {
    let visible_products = compute_visible_products(app, auth).await?;
    list_builds_for_user_with_visible(app, q, priority, visible_products).await
}

/// [`list_builds_for_user`] 的预计算可见产品版本：调用方已为 phase chips 算过
/// 一次 `compute_visible_products` 时直传，省每渲染一次全量 `list_products`；可见性语义一致。
pub(crate) async fn list_builds_for_user_with_visible(
    app: &Arc<AppState>,
    q: &ListQuery,
    priority: Option<crbs_core::types::BuildPriority>,
    visible_products: Option<Vec<String>>,
) -> Result<BuildListResponse, ApiError> {
    let filter = crbs_core::types::BuildListFilter {
        product: q.product.as_deref(),
        user: None,
        phase: q.phase.as_deref(),
        name: q.name.as_deref(),
        source_name: None,
        arch: q.arch.as_deref(),
        priority,
        task_id: q.task_id,
        limit: q.limit,
        offset: q.offset,
        order_by: q.sort.as_deref(),
        srpm_sha256: q.srpm_sha256.as_deref(),
        visible_products,
    };
    let (total, builds) = app.state_store.list_builds(&filter).await?;

    Ok(BuildListResponse { total, builds })
}

/// 根据认证上下文推导 diff 查询的 user_filter：operator/viewer 返回 None
/// （可看全部），builder 返回 Some(user)（只看自己）。
pub(crate) fn diff_user_filter(auth: Option<&AuthContext>) -> Option<&str> {
    auth.and_then(|ctx| {
        if ctx.is_operator() || ctx.role == "viewer" {
            None
        } else {
            Some(ctx.user.as_str())
        }
    })
}

/// 取消分布式构建（已分配给 worker 或运行中的构建）：builds.phase 与
/// worker_tasks.status 置 cancelled。软取消——worker 不会立即停止，
/// 上报结果时按 DB 状态处置。
pub(crate) async fn cancel_distributed_build(
    app: &Arc<AppState>,
    build_id: i64,
) -> Result<CancelBuildOutcome, ApiError> {
    // 终态守卫：仅活跃态可取消。与 worker 上报终态竞态时"先到者生效"——
    // 若构建已完成（succeeded 等），这里返回 409 而非覆盖终态。
    let affected = app
        .state_store
        .mark_build_cancelled(build_id)
        .await
        .map_err(|e| {
            tracing::warn!(build_id = %build_id, error = %e, "Failed to mark distributed build as cancelled");
            ApiError::Internal("failed to cancel build".into())
        })?;
    if affected == 0 {
        return Err(ApiError::Conflict("cannot_cancel_terminal_build".into()));
    }
    if let Err(e) = app
        .state_store
        .update_worker_task_status_for_build(build_id, "cancelled")
        .await
    {
        tracing::warn!(
            build_id = %build_id,
            error = %e,
            "Failed to mark worker task as cancelled"
        );
    }
    Ok(CancelBuildOutcome {
        cancelled: true,
        message: "build cancelled; worker may still be running".into(),
    })
}

/// 取消指定构建：权限检查、active build 取消与审计日志统一在此完成。
pub(crate) async fn cancel_build_for_user(
    app: &Arc<AppState>,
    build_id: i64,
    auth: Option<&AuthContext>,
) -> Result<CancelBuildOutcome, ApiError> {
    let ctx = auth.ok_or(ApiError::Unauthorized(
        "authentication required to cancel".into(),
    ))?;
    let record = app
        .state_store
        .get_build(build_id)
        .await?
        .ok_or_else(|| ApiError::not_found("build", build_id))?;

    if !ctx.can_cancel(&record.user) {
        return Err(ApiError::PermissionDenied(
            "you do not have permission to cancel this build".into(),
        ));
    }

    let token = {
        let map = app.active_builds.lock().await;
        map.get(&build_id).cloned()
    };
    let active = token.is_some();

    let result = match token {
        Some(ref cancel) => {
            cancel.cancel();
            Ok(CancelBuildOutcome {
                cancelled: true,
                message: "cancel request accepted; poll until phase is terminal".into(),
            })
        }
        None => match record.phase.as_str() {
            "cancelled" => Err(ApiError::Conflict("already_cancelled".into())),
            "succeeded" | "failed" | "timeout" => {
                Err(ApiError::Conflict("cannot_cancel_terminal_build".into()))
            }
            "pending" | "assigned" | "building" => {
                // 本地未运行或已分发 worker 的构建统一走分布式取消；worker 上报时按 DB cancelled 状态处置。
                cancel_distributed_build(app, build_id).await
            }
            _ => Err(ApiError::Conflict("cannot_cancel_non_active_build".into())),
        },
    };

    if result.is_ok() {
        let detail = serde_json::json!({
            "phase": record.phase,
            "active": active,
        })
        .to_string();
        let _ = app
            .state_store
            .audit_log(
                &ctx.user,
                &ctx.role,
                "cancel_build",
                Some(&build_id.to_string()),
                Some(&detail),
            )
            .await;
    }

    result
}

/// 定位某构建的 `build_packages.json` 所在目录：布局
/// `{result_root}/{task_id}/{arch}/{build_id}/`（每 build 独立 sidecar）。
/// DB `builds.result_dir` 是权威指针，本函数只按布局拼路径并验证文件存在。
pub(crate) async fn resolve_build_packages_dir(
    result_root: &std::path::Path,
    task_id: i64,
    arch: &str,
    build_id: i64,
) -> Option<std::path::PathBuf> {
    let per_build = result_root
        .join(task_id.to_string())
        .join(arch)
        .join(build_id.to_string());
    if tokio::fs::try_exists(per_build.join("build_packages.json"))
        .await
        .unwrap_or(false)
    {
        return Some(per_build);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_context(user: &str, role: &str) -> AuthContext {
        AuthContext {
            user: user.into(),
            role: role.into(),
            ..Default::default()
        }
    }

    #[test]
    fn diff_user_filter_builder_sees_only_own() {
        let ctx = auth_context("alice", "builder");
        assert_eq!(diff_user_filter(Some(&ctx)), Some("alice"));
    }

    #[test]
    fn diff_user_filter_operator_viewer_and_admin_see_all() {
        assert_eq!(
            diff_user_filter(Some(&auth_context("bob", "operator"))),
            None
        );
        assert_eq!(
            diff_user_filter(Some(&auth_context("carol", "admin"))),
            None
        );
        assert_eq!(
            diff_user_filter(Some(&auth_context("dave", "viewer"))),
            None
        );
    }

    #[test]
    fn diff_user_filter_unauthenticated_sees_all() {
        assert_eq!(diff_user_filter(None), None);
    }

    /// 产品声明签名策略时，未签名构建 publish 被 409 拒绝且 repo_publish 不翻转；
    /// 策略从产品合并配置解析（不依赖全局配置）。
    #[tokio::test]
    async fn publish_unsigned_build_rejected_when_signing_required() {
        let (app, tmp) = crate::test_support::setup_app().await;
        let product = "sigprod";
        let config = crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example/repo".into(),
                gpgcheck: false,
                ..Default::default()
            }],
            gpg_signing_key_id: Some("key@example.com".into()),
            ..Default::default()
        };
        app.state_store
            .create_product(crbs_core::CreateProductInput {
                name: product,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &config,
                changed_by_user_id: None,
                reason: Some("test seed"),
            })
            .await
            .unwrap();

        let result_dir = tmp.path().join("results").join("1").join("x86_64");
        std::fs::create_dir_all(&result_dir).unwrap();
        let task_id = crate::test_support::seed_task(&app.state_store, product, "pkg").await;
        let build_id = app
            .state_store
            .insert_build(crbs_core::BuildInsert {
                product,
                pkg_name: "pkg",
                phase: "succeeded",
                result_dir: Some(result_dir.to_str().unwrap()),
                backend: "chroot",
                user: "alice",
                repo_publish: false,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let result =
            set_build_publish_for_user(&app, build_id, true, Some(&auth_context("alice", "admin")))
                .await;
        match result {
            Err(ApiError::Conflict(msg)) => {
                assert_eq!(msg, "publish_requires_signed_build");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("unsigned build must not be publishable under a signing policy"),
        }

        let rec = app.state_store.get_build(build_id).await.unwrap().unwrap();
        assert!(
            !rec.repo_publish,
            "rejected publish must not flip repo_publish"
        );
    }
}
