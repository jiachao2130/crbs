// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `GET /api/v1/tasks/{id}/recipe`：按需组装
//! `recipe.json` 原子写入任务结果目录（权限不变量 group=crbs / 0660），后续请求直接回读。
//! 缺失/损坏/schema 过期 → 再生成自愈（read_recipe_file + handler 版本判定）；
//! schema 超前（含结构不兼容、宽松读判版本）→ 409 不覆写（降级覆写丢未来字段）。
//! DB 不存引用——路径是 `(tasks.result_dir, 固定文件名)` 纯函数（见 `crbs_core::recipe`）；
//! 配方不限于 deterministic 任务，窗口内 recipe 是 GC 钉住的引用源。
//! 终态门禁：子构建未全部 `succeeded` → 409、零落盘（半成品缺锚，落盘即永久）。

use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::routing::get;
use axum::Json;
use tracing::info;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

pub(crate) fn router() -> axum::Router<Arc<AppState>> {
    axum::Router::new().route("/api/v1/tasks/{id}/recipe", get(get_task_recipe))
}

/// 任务配方查询/生成；权限口径与 `get_task` 一致（产品可见性，孤儿按公开）。
pub(crate) async fn get_task_recipe(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<crbs_core::recipe::Recipe>, ApiError> {
    let task = app
        .state_store
        .get_task(id)
        .await?
        .ok_or_else(|| ApiError::not_found("task", id))?;

    ensure_product_visible_for_record(&app, &task.product, auth.as_ref().map(|ext| &ext.0)).await?;

    let task_dir = task
        .result_dir
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| ApiError::not_found("task result_dir (recipe unavailable) for task", id))?;

    // 已生成 → 直接回读（零 repomd 抓取、零 DB 组装）；版本过期 → 再生成 + 原子覆盖自愈。
    // 未来版本覆写 = 按当前结构解析丢未来字段的静默降级 → 409 保底不动原文件，升级 crbs 后自然回读。
    let recipe_path = crbs_core::recipe::recipe_path(std::path::Path::new(&task_dir));
    if let Some(existing) = crbs_core::recipe::read_recipe_file(&recipe_path).await? {
        match existing
            .schema_version
            .cmp(&crbs_core::recipe::RECIPE_SCHEMA_VERSION)
        {
            std::cmp::Ordering::Equal => return Ok(Json(existing)),
            std::cmp::Ordering::Less => {
                info!(
                    task_id = id,
                    path = %recipe_path.display(),
                    stale_version = existing.schema_version,
                    current_version = crbs_core::recipe::RECIPE_SCHEMA_VERSION,
                    "recipe.json schema version stale; regenerating"
                );
            }
            std::cmp::Ordering::Greater => {
                return Err(ApiError::Conflict(format!(
                    "recipe.json schema version {} is newer than this server supports ({}); \
                     refusing to downgrade-overwrite — upgrade crbs to read it",
                    existing.schema_version,
                    crbs_core::recipe::RECIPE_SCHEMA_VERSION
                )));
            }
        }
    }

    // 先生成后落盘：终态门禁（子构建未全部 succeeded → 409）失败时零 FS 副作用（不建目录、
    // 不落 recipe.json）；目录缺失（GC 竞态/老数据）重建 + 共享目录不变量；写失败 500（下次重试，不静默丢引用源）。
    let recipe = crbs_core::recipe::build_task_recipe(&app.state_store, id).await?;
    let dir = std::path::Path::new(&task_dir);
    if !tokio::fs::try_exists(dir).await.unwrap_or(false) {
        tokio::fs::create_dir_all(dir).await.map_err(|e| {
            ApiError::log_and_internal_with_context("create task dir for recipe", e)
        })?;
        crate::server::routes::builds::ensure_shared_result_dir(dir).await;
    }
    let written = crbs_core::recipe::write_recipe_atomic(dir, &recipe).await?;
    info!(task_id = id, path = %written.display(), "recipe.json generated on demand");
    Ok(Json(recipe))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::create_test_app_with_auth;
    use crate::server::seed_user_token_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use crbs_core::config::ServerConfig;
    use crbs_core::{BuildInsert, StateStore};
    use tower::ServiceExt;

    fn det_product() -> crbs_core::config::ProductConfig {
        // baseurl 指向必失败端口：repomd 抓取降级为 null + error 字段（不阻塞）。
        crbs_core::config::ProductConfig::from_str(
            "base_packages = [\"bash\"]\n\
             deterministic = true\n\
             dnf_cache_enabled = true\n\n\
             [[repos]]\n\
             name = \"base\"\n\
             baseurl = \"http://127.0.0.1:9/base/$basearch\"\n\
             gpgcheck = false\n",
        )
        .unwrap()
    }

    /// 测试世界：det 产品 + 已成功 deterministic 任务（result_dir、per-build
    /// build_packages.json fixture、unsigned 产物行）；返回 (router, store, tmp, 任务目录, task_id, token)。
    #[allow(clippy::type_complexity)]
    async fn setup_world() -> (
        axum::Router,
        Arc<StateStore>,
        tempfile::TempDir,
        std::path::PathBuf,
        i64,
        String,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
        store
            .create_product(crbs_core::CreateProductInput {
                name: "det",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &det_product(),
                changed_by_user_id: None,
                reason: Some("recipe API test seed"),
            })
            .await
            .unwrap();
        let token = seed_user_token_for_test(&store, "tester", "builder")
            .await
            .unwrap();

        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
                user: "tester",
                phase: "succeeded",
                request_json: Some(r#"{"define":["dist=.my9"]}"#),
                ..Default::default()
            })
            .await
            .unwrap();
        let build_id = store
            .insert_build(BuildInsert {
                product: "det",
                pkg_name: "hello-1.0-1",
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
        store.set_build_deterministic(build_id, true).await.unwrap();
        store
            .set_build_canonical_srpm_sha256(build_id, &"a".repeat(64))
            .await
            .unwrap();

        let task_dir = tmp.path().join("results").join(task_id.to_string());
        let build_dir = task_dir.join("x86_64").join(build_id.to_string());
        tokio::fs::create_dir_all(&build_dir).await.unwrap();
        tokio::fs::write(build_dir.join("build_packages.json"), b"{}")
            .await
            .unwrap();
        store
            .update_build_info(build_id, Some(build_dir.to_str().unwrap()), None, "chroot")
            .await
            .unwrap();
        store
            .update_task_result_dir(task_id, Some(task_dir.to_str().unwrap()))
            .await
            .unwrap();

        let a = crbs_core::NewArtifact {
            relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
            kind: crbs_core::ArtifactKind::Rpm,
            size_bytes: 10,
            sha256: "signed".to_string(),
            unsigned_sha256: Some("c0ffee".to_string()),
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

        let app_state = Arc::new(AppState::for_test(
            store.clone(),
            ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let app = create_test_app_with_auth(app_state);
        (app, store, tmp, task_dir, task_id, token)
    }

    async fn get_recipe(
        app: &axum::Router,
        task_id: i64,
        token: &str,
    ) -> axum::http::Response<axum::body::Body> {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/tasks/{task_id}/recipe"))
                    .header("Authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// 首次 GET 生成 + 落盘（0660），二次 GET 回读逐字节一致（零再生）。
    #[tokio::test]
    async fn recipe_first_get_generates_second_get_reads_back() {
        let (app, _store, _tmp, task_dir, task_id, token) = setup_world().await;

        let resp = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes1 = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes1).unwrap();
        assert_eq!(json["task_id"], task_id);
        assert_eq!(
            json["schema_version"],
            crbs_core::recipe::RECIPE_SCHEMA_VERSION
        );
        assert_eq!(json["srpm_sha256"], "a".repeat(64));
        assert_eq!(json["macros"]["values"]["dist"], ".my9");
        assert_eq!(json["env"]["values"]["LC_ALL"], "C");
        assert_eq!(json["env"]["values"]["TZ"], "UTC");
        let pa = &json["per_arch"].as_array().unwrap()[0];
        assert_eq!(pa["arch"], "x86_64");
        assert!(pa["build_packages_sha256"].is_string());
        assert_eq!(
            pa["unsigned_artifacts"].as_array().unwrap()[0]["name"],
            "hello-1.0-1.x86_64.rpm"
        );
        assert!(json["repos"].as_array().unwrap()[0]["repomd_sha256"].is_null());
        assert!(json["repos"].as_array().unwrap()[0]["repomd_fetch_error"].is_string());

        let path = task_dir.join("recipe.json");
        assert!(path.exists());
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o660, "recipe.json must be 0660");

        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let resp2 = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let bytes2 = to_bytes(resp2.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            bytes1, bytes2,
            "second GET must read back the stored file verbatim"
        );
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "second GET must not regenerate");
    }

    /// 非 deterministic 任务也能生成：env 只含无条件基线 LC_ALL、srpm 锚 null（块来源标注见 core 侧）。
    #[tokio::test]
    async fn recipe_served_for_non_deterministic_task() {
        let (app, store, tmp, _task_dir, _task_id, token) = setup_world().await;
        let task_id = store
            .insert_task(crbs_core::TaskInsert {
                product: "det",
                pkg_name: "plain-2.0-1",
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
                pkg_name: "plain-2.0-1",
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
        let build_dir = tmp
            .path()
            .join("results")
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
                Some(build_dir.ancestors().nth(2).unwrap().to_str().unwrap()),
            )
            .await
            .unwrap();

        let resp = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["srpm_sha256"].is_null(),
            "no canonical anchor outside deterministic mode"
        );
        let env = json["env"]["values"].as_object().unwrap();
        assert_eq!(env.len(), 1, "only LC_ALL for non-deterministic tasks");
        assert_eq!(env["LC_ALL"], "C");
    }

    /// 旧 schema 版本缓存触发再生成：GET 返回当前版本内容、落盘被原子覆盖（新字段对旧文件无法回填，再生成即升级）。
    #[tokio::test]
    async fn recipe_stale_schema_version_triggers_regeneration() {
        let (app, _store, _tmp, task_dir, task_id, token) = setup_world().await;

        // 落盘一份合法但旧版本的 v1 recipe.json（无 v2 的 missing_unsigned_anchor 字段）；
        // 合法 JSON 不走 corrupt 自愈路径，钉住版本判定这唯一触发面。
        let stale = serde_json::json!({
            "schema_version": 1,
            "product": "det",
            "task_id": task_id,
            "generated_at": "2026-01-01 00:00:00",
            "srpm_sha256": null,
            "macros": {"source": "s", "values": {}},
            "env": {"source": "s", "values": {}},
            "ccache": {"enabled": false, "compiler_check": null, "sloppy": ""},
            "instrumentation_disclosure": "stale-marker",
            "repos": [],
            "per_arch": [],
        });
        tokio::fs::create_dir_all(&task_dir).await.unwrap();
        let path = task_dir.join("recipe.json");
        tokio::fs::write(&path, serde_json::to_string_pretty(&stale).unwrap())
            .await
            .unwrap();

        let resp = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["schema_version"],
            crbs_core::recipe::RECIPE_SCHEMA_VERSION,
            "stale cache must be regenerated at the current version"
        );
        assert_ne!(json["instrumentation_disclosure"], "stale-marker");

        let on_disk: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(
            on_disk["schema_version"],
            crbs_core::recipe::RECIPE_SCHEMA_VERSION
        );
        assert_ne!(on_disk["instrumentation_disclosure"], "stale-marker");
    }

    /// schema 版本超前（来自更新版本 crbs）→ 409 拒绝且不覆写——降级覆写 = 静默丢未来字段。
    #[tokio::test]
    async fn recipe_future_schema_version_refused_without_overwrite() {
        let (app, _store, _tmp, task_dir, task_id, token) = setup_world().await;

        // 合法 JSON、但 schema_version 超前（v(当前+1)）。
        let future_marker = "future-field-must-survive";
        let future = serde_json::json!({
            "schema_version": crbs_core::recipe::RECIPE_SCHEMA_VERSION + 1,
            "product": "det",
            "task_id": task_id,
            "generated_at": "2026-01-01 00:00:00",
            "srpm_sha256": null,
            "macros": {"source": "s", "values": {}},
            "env": {"source": "s", "values": {}},
            "ccache": {"enabled": false, "compiler_check": null, "sloppy": ""},
            "instrumentation_disclosure": future_marker,
            "repos": [],
            "per_arch": [],
        });
        tokio::fs::create_dir_all(&task_dir).await.unwrap();
        let path = task_dir.join("recipe.json");
        let future_bytes = serde_json::to_string_pretty(&future).unwrap();
        tokio::fs::write(&path, &future_bytes).await.unwrap();

        let resp = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("newer than this server supports"),
            "error message must explain the refusal: {json}"
        );

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            on_disk, future_bytes,
            "future-version file must not be overwritten"
        );
    }

    /// 未来版本 + 结构不兼容（serde 解析失败、宽松读版本超前）→ 同样 409 不覆写，不走 corrupt 自愈再生成。
    #[tokio::test]
    async fn recipe_future_version_struct_incompatible_refused() {
        let (app, _store, _tmp, task_dir, task_id, token) = setup_world().await;

        // Value 可解析、Recipe 不可（product 是数字 + 未来字段）。
        let future_bytes = format!(
            "{{\"schema_version\": {}, \"product\": 42, \"future_field\": {{\"keep\": true}}}}",
            crbs_core::recipe::RECIPE_SCHEMA_VERSION + 1
        );
        tokio::fs::create_dir_all(&task_dir).await.unwrap();
        let path = task_dir.join("recipe.json");
        tokio::fs::write(&path, &future_bytes).await.unwrap();

        let resp = get_recipe(&app, task_id, &token).await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("newer than"),
            "error message must explain the refusal: {json}"
        );

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            on_disk, future_bytes,
            "future-version unparseable file must not be overwritten"
        );
    }

    /// 未生成过 recipe 的 404 面：任务不存在。
    #[tokio::test]
    async fn recipe_404_for_missing_task() {
        let (app, _store, _tmp, _task_dir, _task_id, token) = setup_world().await;
        let resp = get_recipe(&app, 999_999, &token).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 终态门禁：子构建未全部 succeeded（running/failed/混打标）→ 409 且零 FS 副作用（半成品配方落盘即被永久回读）。
    #[tokio::test]
    async fn recipe_409_until_all_children_succeeded() {
        let (app, store, tmp, _task_dir, _task_id, token) = setup_world().await;
        for (label, task_phase, build_phases) in [
            ("running", "building", vec!["building"]),
            ("failed", "failed", vec!["failed"]),
            ("mixed", "building", vec!["succeeded", "building"]),
        ] {
            let pkg = format!("gate-{label}-1.0-1");
            let task_id = store
                .insert_task(crbs_core::TaskInsert {
                    product: "det",
                    pkg_name: &pkg,
                    user: "tester",
                    phase: task_phase,
                    request_json: Some("{}"),
                    ..Default::default()
                })
                .await
                .unwrap();
            let task_dir = tmp.path().join("results").join(task_id.to_string());
            store
                .update_task_result_dir(task_id, Some(task_dir.to_str().unwrap()))
                .await
                .unwrap();
            for phase in &build_phases {
                store
                    .insert_build(BuildInsert {
                        product: "det",
                        pkg_name: &pkg,
                        phase,
                        backend: "chroot",
                        user: "tester",
                        priority: 0,
                        arch: Some("x86_64"),
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap();
            }

            let resp = get_recipe(&app, task_id, &token).await;
            assert_eq!(resp.status(), StatusCode::CONFLICT, "case={label}");
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                json["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("not fully succeeded"),
                "error message must explain the gate, case={label}: {json}"
            );
            assert!(
                !task_dir.join("recipe.json").exists(),
                "gate must not write recipe.json, case={label}"
            );
            assert!(
                !task_dir.exists(),
                "gate must fire before any filesystem side effect, case={label}"
            );
        }
    }
}
