// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建产物列表端点（DB 版，不走磁盘）。

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::Json;
use serde::Serialize;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// 单条产物元数据（完整字段版）。
#[derive(Serialize)]
pub(crate) struct ArtifactEntry {
    pub relative_path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<i64>,
    pub signed: bool,
}

/// 带元数据的产物列表响应（向后兼容）：`rpms/srpms/other` 旧格式 String 数组、
/// `artifacts` 完整元数据；不回传 `result_dir` 绝对路径（防信息泄漏），文件走 download 端点。
#[derive(Serialize)]
pub(crate) struct ArtifactsListResponse {
    pub build_id: i64,
    pub rpms: Vec<String>,
    pub srpms: Vec<String>,
    pub other: Vec<String>,
    pub artifacts: Vec<ArtifactEntry>,
}

pub(crate) async fn list_artifacts(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ArtifactsListResponse>, ApiError> {
    list_artifacts_inner(app, id, auth).await
}

/// 匿名受限清单（public 路由，`crbs download` 无 token profile 用）：
/// `public_access.download` 关闭时匿名 401，产品可见性同 protected 版。
/// 响应与 protected 版同构——本就不含 result_dir。
pub(crate) async fn list_artifacts_public(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ArtifactsListResponse>, ApiError> {
    if app.server_config.auth_enabled && !app.server_config.public_access.download {
        auth.as_ref().ok_or(ApiError::Unauthorized(
            "artifact list requires authentication".into(),
        ))?;
    }
    list_artifacts_inner(app, id, auth).await
}

async fn list_artifacts_inner(
    app: Arc<AppState>,
    id: i64,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ArtifactsListResponse>, ApiError> {
    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    // 产品可见性（同 builds 详情）：private 仅 owner/ACL/operator，其余 403；worker 不走产品 ACL。
    if auth.as_ref().is_none_or(|ctx| ctx.0.role != "worker") {
        ensure_product_visible_for_record(&app, &record.product, auth.as_ref().map(|ctx| &ctx.0))
            .await?;
    }

    // 从 DB 读（仅 on_disk=1，GC 后的文件不出现在列表里）
    let artifacts = app
        .state_store
        .list_artifacts(id)
        .await
        .map_err(ApiError::from)?;

    let mut rpms = Vec::new();
    let mut srpms = Vec::new();
    let mut other = Vec::new();
    let mut entries = Vec::new();

    for a in artifacts {
        let kind_str = a.kind.as_str().to_string();
        match a.kind {
            crbs_core::ArtifactKind::Rpm => rpms.push(a.relative_path.clone()),
            crbs_core::ArtifactKind::Srpm => srpms.push(a.relative_path.clone()),
            crbs_core::ArtifactKind::Log
            | crbs_core::ArtifactKind::Metadata
            | crbs_core::ArtifactKind::Script
            | crbs_core::ArtifactKind::Other => other.push(a.relative_path.clone()),
        }
        entries.push(ArtifactEntry {
            relative_path: a.relative_path,
            kind: kind_str,
            size_bytes: a.size_bytes,
            sha256: a.sha256,
            arch: a.arch,
            name: a.name,
            version: a.version,
            release: a.release,
            epoch: a.epoch,
            signed: a.signed,
        });
    }

    rpms.sort();
    srpms.sort();
    other.sort();

    Ok(Json(ArtifactsListResponse {
        build_id: id,
        rpms,
        srpms,
        other,
        artifacts: entries,
    }))
}

/// 收集 result_dir/RPMS 下 RPM 文件名（不含 .src.rpm，排序）；本地磁盘扫描 helper，列表端点走 DB。
pub(crate) async fn collect_rpm_file_names(result_dir: &Path) -> std::io::Result<Vec<String>> {
    let rpms_dir = result_dir.join("RPMS");
    let mut rpms = Vec::new();
    let mut dirs = vec![rpms_dir];
    while let Some(dir) = dirs.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let metadata = tokio::fs::symlink_metadata(&path).await?;
            if metadata.is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                dirs.push(path);
            } else if metadata.is_file() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();
                if name.ends_with(".rpm") && !name.ends_with(".src.rpm") {
                    rpms.push(name);
                }
            }
        }
    }
    rpms.sort();
    Ok(rpms)
}

#[cfg(test)]
mod tests {
    use super::list_artifacts;
    use crate::server::error::ApiError;
    use axum::extract::{Extension, Path as AxumPath, State};
    use std::sync::Arc;

    async fn test_app() -> (
        Arc<crate::server::state::AppState>,
        Arc<crbs_core::StateStore>,
        tempfile::TempDir,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(crate::server::state::AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        (app, store, tmp)
    }

    async fn seed_products_and_builds(store: &crbs_core::StateStore) -> (i64, i64) {
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
        let insert = |product: &'static str| {
            let store = store.clone();
            async move {
                let task_id = crate::test_support::seed_task(&store, product, "pkg").await;
                store
                    .insert_build(crbs_core::BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "succeeded",
                        backend: "chroot",
                        // 提交者是他人：产品级检查独立把门，403 只能来自产品级判定。
                        user: "alice",
                        task_id: Some(task_id),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };
        (insert("secret").await, insert("openfed").await)
    }

    /// 匿名/viewer 对 private 产品 build 的产物列表 403，public 产品照常。
    #[tokio::test]
    async fn list_artifacts_checks_product_visibility() {
        let (app, store, _tmp) = test_app().await;
        let (secret_id, public_id) = seed_products_and_builds(&store).await;

        let result = list_artifacts(State(app.clone()), AxumPath(secret_id), None).await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "anonymous listing of private product build must be denied"
        );

        let viewer = crate::server::auth::AuthContext {
            user: "eve".into(),
            role: "viewer".into(),
            ..Default::default()
        };
        let result = list_artifacts(
            State(app.clone()),
            AxumPath(secret_id),
            Some(Extension(viewer)),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "viewer listing of private product build must be denied"
        );

        let result = list_artifacts(
            State(app.clone()),
            AxumPath(public_id),
            Some(Extension(crate::server::auth::AuthContext {
                user: "eve".into(),
                role: "viewer".into(),
                ..Default::default()
            })),
        )
        .await;
        assert!(result.is_ok(), "public product listing must succeed");
    }

    /// 回归：响应不携带服务器绝对 result_dir。
    #[tokio::test]
    async fn list_artifacts_response_omits_result_dir() {
        let (app, store, _tmp) = test_app().await;
        let (_, public_id) = seed_products_and_builds(&store).await;

        let axum::Json(resp) = list_artifacts(
            State(app),
            AxumPath(public_id),
            Some(Extension(crate::server::auth::AuthContext {
                user: "eve".into(),
                role: "viewer".into(),
                ..Default::default()
            })),
        )
        .await
        .unwrap();
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("result_dir").is_none(),
            "result_dir must not be serialized, got: {json}"
        );
    }
}
