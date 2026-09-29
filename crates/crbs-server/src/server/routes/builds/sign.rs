// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建签名路由：请求校验、签名执行与响应组装。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Extension, Json, Path as AxumPath, State};
use axum::http::StatusCode;
use serde::Deserialize;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use crbs_core::sign::{SignConfig, Signer};

#[derive(Deserialize)]
pub(crate) struct SignRequest {
    /// GPG key ID（默认使用 server 配置）。
    key_id: Option<String>,
    /// GPG home 目录（默认使用 server 进程用户的 keyring）。
    gpg_home: Option<String>,
}

#[derive(serde::Serialize)]
pub(crate) struct SignResponse {
    signed: bool,
    id: i64,
    message: String,
}

fn is_signable_phase(phase: &str) -> bool {
    matches!(phase, "succeeded")
}

/// 对指定构建的 RPM 产物执行服务端签名。
/// 前置：仅 succeeded 构建；result_dir 存在可访问；key_id 取请求或 server 配置。
pub(crate) async fn sign_build(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<SignRequest>,
) -> Result<(StatusCode, Json<SignResponse>), ApiError> {
    if let Some(ctx) = auth.as_ref() {
        if !ctx.is_operator() {
            return Err(ApiError::PermissionDenied(
                "only operator/admin can sign builds".into(),
            ));
        }
    }

    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get build record", e))?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    if !is_signable_phase(&record.phase) {
        return Err(ApiError::Conflict(format!(
            "build {} must be in succeeded phase to sign (current: {})",
            id, record.phase
        )));
    }

    if let Some(product) = app
        .state_store
        .get_product_by_name(&record.product)
        .await
        .map_err(ApiError::from)?
    {
        if product.owner_id.is_some() {
            return Err(ApiError::PermissionDenied(format!(
                "build {} belongs to private product '{}'; only official products \
                 are signed with the Hub signing key",
                id, record.product
            )));
        }
    }

    if let Some(source_id) = app
        .state_store
        .get_build_reproduce_source(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("check replay marker", e))?
    {
        return Err(ApiError::Conflict(format!(
            "build {} is a replay of build {} (repo_publish=0, not publishable); \
             replay artifacts are not signed — sign the source build instead",
            id, source_id
        )));
    }

    let result_dir_str = record
        .result_dir
        .as_deref()
        .ok_or_else(|| ApiError::Conflict(format!("build {} has no result_dir", id)))?;
    let result_root = app.result_dir_for_or_default(&record.product).await;
    let result_dir = crbs_core::util::validate_result_dir(result_dir_str, &result_root)
        .await
        .map_err(|e| {
            tracing::warn!(build_id = %id, error = %e, "Invalid result_dir while resolving sign");
            ApiError::Validation("invalid result_dir for this build".into())
        })?;

    if !tokio::fs::try_exists(&result_dir).await.unwrap_or(false) {
        tracing::warn!(build_id = %id, path = %result_dir.display(), "sign: result_dir missing");
        return Err(ApiError::Validation(
            "result_dir for this build does not exist".into(),
        ));
    }

    let rpm_paths = crbs_core::util::collect_rpm_paths(&result_dir, false)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("collect rpm files", e))?;

    if rpm_paths.is_empty() {
        tracing::warn!(build_id = %id, path = %result_dir.display(), "sign: no RPM files");
        return Err(ApiError::Validation(
            "no RPM files found in this build's result dir".into(),
        ));
    }

    let mut cfg = app
        .state_store
        .load_merged_config_for_any_product_by_name(&record.product)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("load product config", e))?;
    crate::server::signing::apply_server_gpg_home_default(&mut cfg).await;

    let base_sign_config = SignConfig::from_config_async(&cfg).await;

    let key_id = req
        .key_id
        .or_else(|| base_sign_config.as_ref().map(|c| c.key_id.clone()))
        .ok_or_else(|| {
            ApiError::Validation(
                "no GPG key_id configured; provide key_id in request or set gpg_signing_key_id in config".into(),
            )
        })?;

    let euid = nix::unistd::geteuid().as_raw();
    let gpg_home = match req.gpg_home {
        Some(home) => Some(
            SignConfig::validate_gpg_home_async(home, euid)
                .await
                .map_err(|e| ApiError::Validation(format!("invalid request gpg_home: {e}")))?,
        ),
        None => base_sign_config.and_then(|c| c.gpg_home),
    };

    let sign_config = SignConfig { key_id, gpg_home };

    let signer = Signer::new();
    let paths_refs: Vec<&Path> = rpm_paths.iter().map(|p| p.as_path()).collect();

    let (operator, role) = auth
        .as_ref()
        .map(|ext| (ext.0.user.as_str(), ext.0.role.as_str()))
        .unwrap_or(("anonymous", "anonymous"));
    crate::server::signing::sign_audit(
        &app.state_store,
        "sign_triggered",
        id,
        &sign_config.key_id,
        operator,
        role,
        None,
    )
    .await;

    if let Err(e) = signer
        .sign_rpms(&sign_config, &result_dir, &paths_refs)
        .await
    {
        crate::server::signing::sign_audit(
            &app.state_store,
            "sign_failed",
            id,
            &sign_config.key_id,
            operator,
            role,
            Some(&e.to_string()),
        )
        .await;
        return Err(ApiError::log_and_internal_with_context("sign rpms", e));
    }

    let rpm_tuples: Vec<(PathBuf, String)> = rpm_paths
        .iter()
        .map(|rpm| {
            let rel = rpm
                .strip_prefix(&result_dir)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| rpm.to_string_lossy().replace('\\', "/"));
            (rpm.clone(), rel)
        })
        .collect();
    if let Err(e) =
        crate::server::signing::refresh_signed_and_mark(&app.state_store, id, &rpm_tuples).await
    {
        tracing::warn!(
            build_id = %id,
            count = rpm_paths.len(),
            error = %e,
            "signed RPMs on disk but artifact metadata refresh/mark failed; \
             builds.signed stays 0 — re-run sign API to complete (signing is idempotent)"
        );
        crate::server::signing::sign_audit(
            &app.state_store,
            "sign_failed",
            id,
            &sign_config.key_id,
            operator,
            role,
            Some(&e.to_string()),
        )
        .await;
        return Err(ApiError::Internal(
            "RPMs are signed on disk, but refreshing artifact metadata failed; \
             re-run the sign operation to complete (signing is idempotent)"
                .into(),
        ));
    }

    crate::server::signing::sign_audit(
        &app.state_store,
        "sign_completed",
        id,
        &sign_config.key_id,
        operator,
        role,
        None,
    )
    .await;

    crate::server::repo_regen::regenerate_product_repo(&app, &record.product).await;

    Ok((
        StatusCode::OK,
        Json(SignResponse {
            signed: true,
            id,
            message: format!("Signed {} RPM(s)", rpm_paths.len()),
        }),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::server::auth::AuthContext;
    use crate::server::state::AppState;
    use crbs_core::{BuildInsert, StateStore};

    fn operator_ctx() -> AuthContext {
        AuthContext {
            user: "op".into(),
            role: "operator".into(),
            ..Default::default()
        }
    }

    async fn seed_build(store: &StateStore, phase: &str, result_dir: Option<&str>) -> i64 {
        let task_id = crate::test_support::seed_task(store, "fedora", "pkg").await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase,
                result_dir,
                backend: "chroot",
                user: "test",
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap()
    }

    async fn test_app() -> (Arc<AppState>, StateStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new(tmp.path()).await.unwrap();
        let app = Arc::new(AppState::for_test(
            Arc::new(store.clone()),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, store, tmp)
    }

    #[tokio::test]
    async fn sign_non_succeeded_phase_returns_conflict() {
        let (app, store, _tmp) = test_app().await;
        let build_id = seed_build(&store, "failed", None).await;

        let result = sign_build(
            State(app),
            AxumPath(build_id),
            Some(Extension(operator_ctx())),
            Json(SignRequest {
                key_id: None,
                gpg_home: None,
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => assert!(msg.contains("succeeded"), "{msg}"),
            other => panic!("expected Conflict, got {:?}", other.err()),
        }
    }

    #[tokio::test]
    async fn sign_succeeded_without_result_dir_returns_conflict() {
        let (app, store, _tmp) = test_app().await;
        let build_id = seed_build(&store, "succeeded", None).await;

        let result = sign_build(
            State(app),
            AxumPath(build_id),
            Some(Extension(operator_ctx())),
            Json(SignRequest {
                key_id: None,
                gpg_home: None,
            }),
        )
        .await;

        match result {
            Err(ApiError::Conflict(msg)) => assert!(msg.contains("result_dir"), "{msg}"),
            other => panic!("expected Conflict, got {:?}", other.err()),
        }
    }

    /// official-only：owner 非空的私人产品即使配置链继承 gpg_signing_key_id 也拒签。
    #[tokio::test]
    async fn sign_rejects_private_product_builds() {
        let (app, store, _tmp) = test_app().await;
        let cfg = crbs_core::config::ProductConfig {
            gpg_signing_key_id: Some("KEY".into()),
            gpg_signing_enabled: Some(true),
            ..Default::default()
        };
        let owner_id = store.create_user("forkowner", "builder").await.unwrap();
        store
            .create_product(crbs_core::CreateProductInput {
                name: "mypriv",
                display_name: None,
                owner_id: Some(owner_id),
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PRIVATE,
                config: &cfg,
                changed_by_user_id: Some(owner_id),
                reason: Some("fork for builder"),
            })
            .await
            .unwrap();
        let task_id = crate::test_support::seed_task(&store, "mypriv", "pkg-priv").await;
        let build_id = store
            .insert_build(BuildInsert {
                product: "mypriv",
                pkg_name: "pkg-priv",
                phase: "succeeded",
                backend: "chroot",
                user: "forkowner",
                user_id: Some(owner_id),
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let result = sign_build(
            State(app),
            AxumPath(build_id),
            Some(Extension(operator_ctx())),
            Json(SignRequest {
                key_id: None,
                gpg_home: None,
            }),
        )
        .await;

        match result {
            Err(ApiError::PermissionDenied(msg)) => {
                assert!(msg.contains("private product"), "{msg}")
            }
            other => panic!("expected PermissionDenied, got {:?}", other.err()),
        }
    }
}
