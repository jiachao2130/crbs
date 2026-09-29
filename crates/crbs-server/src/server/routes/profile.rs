// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建 profile 端点。

use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::artifacts::collect_rpm_file_names;
use crate::server::state::AppState;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/builds/{id}/profile", get(get_profile))
}

/// 结构化 profile 响应（与 `profile.json` 原始内容解耦）。
#[derive(Debug, Serialize)]
pub(crate) struct ProfileResponse {
    id: i64,
    pkg_name: String,
    product: String,
    phase: String,
    elapsed_secs: i64,
    rpms: Vec<String>,
    /// 完整 profile 本体嵌套透传（additive）：`status --profile --remote` 的 JSON
    /// 需与本地路径逐字节同形，六个顶层摘要字段不够；顶层字段为既有契约，供旧客户端。
    profile: crbs_core::engine::profile::BuildProfile,
}

pub(crate) async fn get_profile(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ProfileResponse>, ApiError> {
    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("get build record", e))?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    // 产品维度可见性（与 builds 详情同口径）：public 产品照常，private 产品仅
    // owner/ACL/operator 可见，匿名/无关用户 403。worker 是机器身份，不走产品 ACL。
    if auth.as_ref().is_none_or(|ctx| ctx.0.role != "worker") {
        ensure_product_visible_for_record(&app, &record.product, auth.as_ref().map(|ctx| &ctx.0))
            .await?;
    }

    let result_dir = record
        .result_dir
        .as_deref()
        .ok_or_else(|| ApiError::not_found("build result dir", id))?;
    let result_root = app.result_dir_for_or_default(&record.product).await;
    let validated = crbs_core::util::validate_result_dir(result_dir, &result_root)
        .await
        .map_err(|e| {
            // 原始文案含服务器绝对路径，只进日志；对外保持 400 语义但文案脱敏。
            tracing::warn!(
                build_id = %id,
                product = %record.product,
                error = %e,
                "Result dir validation failed"
            );
            ApiError::Validation(
                "build result directory is invalid or outside the result root".into(),
            )
        })?;
    let profile_path = validated.join("profile.json");

    // profile.json 在构建结果目录内（容器可写）：拒绝 symlink，且读取上限
    // 8 MiB——恶意 spec/compromised worker 不能靠巨型 profile 拖垮 hub。
    const MAX_PROFILE_BYTES: u64 = 8 * 1024 * 1024;
    if !crbs_core::util::is_regular_file_no_symlink(&profile_path).await {
        return Err(ApiError::not_found("profile", id));
    }
    let file = match crbs_core::util::open_read_no_follow()
        .open(&profile_path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::not_found("profile", id))
        }
        Err(e) => {
            return Err(ApiError::log_and_internal_with_context(
                "open profile.json",
                e,
            ))
        }
    };
    let mut content = String::new();
    {
        use tokio::io::AsyncReadExt;
        let mut limited = file.take(MAX_PROFILE_BYTES + 1);
        if let Err(e) = limited.read_to_string(&mut content).await {
            return Err(ApiError::log_and_internal_with_context(
                "read profile.json",
                e,
            ));
        }
    }
    if content.len() as u64 > MAX_PROFILE_BYTES {
        return Err(ApiError::Validation(
            "profile.json exceeds the maximum accepted size".into(),
        ));
    }

    let profile: crbs_core::engine::profile::BuildProfile = serde_json::from_str(&content)
        .map_err(|e| ApiError::log_and_internal_with_context("parse profile.json", e))?;

    // as 转换只饱和大值（→ i64::MAX），负值会渲染负耗时，显式钳 [0, i64::MAX]；仅展示层。
    let elapsed_secs = record
        .duration
        .unwrap_or_else(|| profile.total_seconds.clamp(0.0, i64::MAX as f64) as i64);

    let rpms = match collect_rpm_file_names(&validated).await {
        Ok(rpms) => rpms,
        Err(e) => {
            tracing::warn!(build_id = %id, error = %e, "Failed to collect rpm file names");
            Vec::new()
        }
    };

    Ok(Json(ProfileResponse {
        id: record.id,
        pkg_name: record.pkg_name,
        product: record.product,
        phase: record.phase,
        elapsed_secs,
        rpms,
        profile,
    }))
}

#[cfg(test)]
mod tests {
    use super::get_profile;
    use crate::server::auth::AuthContext;
    use crate::server::error::ApiError;
    use crate::server::state::AppState;
    use axum::extract::{Extension, Path as AxumPath, State};
    use std::sync::Arc;

    /// happy-path：完整 `BuildProfile` 嵌套透传在 `profile` 字段，顶层摘要字段照旧。
    #[tokio::test]
    async fn get_profile_nests_full_build_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let results_root = tmp.path().join("results");
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig {
                result_dir: Some(results_root.clone()),
                ..Default::default()
            },
            tmp.path().to_path_buf(),
        ));

        let task_id = crate::test_support::seed_task(&store, "fedora", "hello").await;
        let build_result_dir = results_root.join("hello-1");
        std::fs::create_dir_all(&build_result_dir).unwrap();
        let profile = crbs_core::engine::profile::BuildProfile {
            build_id: 1,
            srpm: "hello-1.0-1.src.rpm".into(),
            total_seconds: 12.5,
            shared_layer_hit: false,
            ccache: None,
            phases: vec![crbs_core::engine::profile::BuildPhase {
                name: "build".into(),
                duration_seconds: 10.0,
                skipped: None,
                reason: None,
                exit_code: None,
            }],
        };
        std::fs::write(
            build_result_dir.join("profile.json"),
            serde_json::to_string(&profile).unwrap(),
        )
        .unwrap();

        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                task_id: Some(task_id),
                result_dir: Some(build_result_dir.to_str().unwrap()),
                ..Default::default()
            })
            .await
            .unwrap();

        let resp = get_profile(State(app), AxumPath(build_id), None)
            .await
            .expect("profile with valid result_dir should succeed");
        let value = serde_json::to_value(&*resp).unwrap();
        assert_eq!(value["pkg_name"], "hello");
        // 嵌套 profile 本体逐字段透传（引擎计时口径，非 elapsed_secs 摘要）。
        assert_eq!(value["profile"]["srpm"], "hello-1.0-1.src.rpm");
        assert_eq!(value["profile"]["total_seconds"], 12.5);
        assert_eq!(value["profile"]["phases"][0]["name"], "build");
        let roundtrip: crbs_core::engine::profile::BuildProfile =
            serde_json::from_value(value["profile"].clone()).unwrap();
        assert_eq!(roundtrip, profile);
    }

    /// elapsed_secs 双口径优先序（CLI status --remote 的注释依赖）：builds.duration
    ///（引擎口径）压过 total_seconds（自报）；缺失回退截断；负值钳 0。
    #[tokio::test]
    async fn get_profile_elapsed_secs_prefers_duration_then_clamps() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let results_root = tmp.path().join("results");
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig {
                result_dir: Some(results_root.clone()),
                ..Default::default()
            },
            tmp.path().to_path_buf(),
        ));

        async fn seed(
            store: &crbs_core::StateStore,
            results_root: &std::path::Path,
            name: &str,
            duration: Option<i64>,
            total_seconds: f64,
        ) -> i64 {
            let dir = results_root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("profile.json"),
                serde_json::json!({
                    "build_id": 1,
                    "srpm": "hello-1.0-1.src.rpm",
                    "total_seconds": total_seconds,
                    "shared_layer_hit": false,
                    "phases": [],
                })
                .to_string(),
            )
            .unwrap();
            let task_id = crate::test_support::seed_task(store, "fedora", "hello").await;
            let build_id = store
                .insert_build(crbs_core::BuildInsert {
                    product: "fedora",
                    pkg_name: "hello",
                    phase: "succeeded",
                    backend: "chroot",
                    user: "test",
                    task_id: Some(task_id),
                    result_dir: Some(dir.to_str().unwrap()),
                    ..Default::default()
                })
                .await
                .unwrap();
            if let Some(d) = duration {
                sqlx::query("UPDATE builds SET duration = $1 WHERE id = $2")
                    .bind(d)
                    .bind(build_id)
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            build_id
        }

        let with_duration = seed(&store, &results_root, "with-duration", Some(30), 12.5).await;
        let resp = get_profile(State(app.clone()), AxumPath(with_duration), None)
            .await
            .expect("profile with duration should succeed");
        assert_eq!(resp.elapsed_secs, 30);

        // duration 缺失 → 回退 total_seconds（12.5 截断为 12）。
        let no_duration = seed(&store, &results_root, "no-duration", None, 12.5).await;
        let resp = get_profile(State(app.clone()), AxumPath(no_duration), None)
            .await
            .expect("profile without duration should fall back to total_seconds");
        assert_eq!(resp.elapsed_secs, 12);

        // 负 total_seconds（脏 profile）→ 钳 0，不渲染负耗时。
        let negative = seed(&store, &results_root, "negative", None, -5.0).await;
        let resp = get_profile(State(app), AxumPath(negative), None)
            .await
            .expect("negative total_seconds must clamp to 0, not error");
        assert_eq!(resp.elapsed_secs, 0);
    }

    /// profile.json 缺失 → 404（文案含 "profile"）；非法 JSON → Internal（细节进日志）；
    /// 坏数据不得静默当空 profile。
    #[tokio::test]
    async fn get_profile_missing_or_corrupt_profile_json_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let results_root = tmp.path().join("results");
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig {
                result_dir: Some(results_root.clone()),
                ..Default::default()
            },
            tmp.path().to_path_buf(),
        ));

        async fn seed(
            store: &crbs_core::StateStore,
            results_root: &std::path::Path,
            name: &str,
            profile_json: Option<&str>,
        ) -> i64 {
            let dir = results_root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            if let Some(json) = profile_json {
                std::fs::write(dir.join("profile.json"), json).unwrap();
            }
            let task_id = crate::test_support::seed_task(store, "fedora", "hello").await;
            store
                .insert_build(crbs_core::BuildInsert {
                    product: "fedora",
                    pkg_name: "hello",
                    phase: "succeeded",
                    backend: "chroot",
                    user: "test",
                    task_id: Some(task_id),
                    result_dir: Some(dir.to_str().unwrap()),
                    ..Default::default()
                })
                .await
                .unwrap()
        }

        // result_dir 有效但 profile.json 缺失 → 404 且文案点名 profile。
        let missing = seed(&store, &results_root, "missing-profile", None).await;
        let err = get_profile(State(app.clone()), AxumPath(missing), None)
            .await
            .expect_err("missing profile.json must be an error");
        assert!(
            matches!(err, ApiError::NotFound(ref msg) if msg.contains("profile")),
            "unexpected error: {err:?}"
        );

        // profile.json 是非法 JSON → Internal（不泄露解析细节）。
        let corrupt = seed(&store, &results_root, "corrupt-profile", Some("{not json")).await;
        let err = get_profile(State(app), AxumPath(corrupt), None)
            .await
            .expect_err("corrupt profile.json must be an error");
        assert!(
            matches!(err, ApiError::Internal(_)),
            "unexpected error: {err:?}"
        );
    }

    /// 匿名/viewer 对 private 产品 build 的 profile 403；public 权限层放行
    ///（无 result_dir 走 404，证明未在权限层拦截）。
    #[tokio::test]
    async fn get_profile_checks_product_visibility() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        let owner_id = store.create_user("owner", "builder").await.unwrap();
        for (name, owner, vis) in [
            ("secret", Some(owner_id), crbs_core::VISIBILITY_PRIVATE),
            ("openfed", None, crbs_core::VISIBILITY_PUBLIC),
        ] {
            store
                .create_product(crbs_core::CreateProductInput {
                    name,
                    display_name: None,
                    owner_id: owner,
                    parent_id: None,
                    visibility: vis,
                    config: &crbs_core::config::ProductConfig::default(),
                    changed_by_user_id: None,
                    reason: None,
                })
                .await
                .unwrap();
        }

        let insert_build = |product: &'static str| {
            let store = store.clone();
            async move {
                let task_id = crate::test_support::seed_task(&store, product, "pkg").await;
                store
                    .insert_build(crbs_core::BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "succeeded",
                        backend: "chroot",
                        // 提交者是别人：产品级检查独立把门，与提交者身份无关。
                        user: "alice",
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };

        let viewer = AuthContext {
            user: "eve".into(),
            role: "viewer".into(),
            ..Default::default()
        };

        // private：匿名 → 403。
        let secret_id = insert_build("secret").await;
        let result = get_profile(State(app.clone()), AxumPath(secret_id), None).await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "anonymous profile of private product build must be denied"
        );

        // private：viewer（非 owner、无 ACL）→ 403。
        let result = get_profile(
            State(app.clone()),
            AxumPath(secret_id),
            Some(Extension(viewer)),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "viewer profile of private product build must be denied"
        );

        // public：权限层放行（无 result_dir → 404，证明未在权限层拦截）。
        let public_id = insert_build("openfed").await;
        let result = get_profile(
            State(app),
            AxumPath(public_id),
            Some(Extension(AuthContext {
                user: "eve".into(),
                role: "viewer".into(),
                ..Default::default()
            })),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::NotFound(_))),
            "public product profile must pass the permission layer"
        );
    }
}
