// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! SHA256 指纹反查端点（Jenkins fingerprint 模式）："这个哈希的文件是哪个构建产出的"，事故响应/溯源场景核心。
//! 安全：结果集逐行过可见性过滤，不可见行静默剔除（非 403/404，是消失在结果集里），防私人产品构建存在性泄漏。

use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::Json;
use serde::Serialize;

use crate::server::auth::visibility::{compute_visible_products, is_build_task_visible_to};
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// 指纹反查单条结果（含产物元数据 + 构建标识信息）。
#[derive(Serialize)]
pub(crate) struct FingerprintMatch {
    pub build_id: i64,
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
    pub on_disk: bool,
    pub product: String,
    pub phase: String,
}

/// 指纹反查响应。
#[derive(Serialize)]
pub(crate) struct FingerprintResponse {
    pub sha256: String,
    pub matches: Vec<FingerprintMatch>,
    pub total: usize,
}

/// SHA256 指纹反查端点：返回所有含该哈希的产物，含 GC 已删行（on_disk=0，行保留
/// 设计的目的），调用方自行判断可否下载。
pub(crate) async fn by_sha256(
    State(app): State<Arc<AppState>>,
    AxumPath(sha256): AxumPath<String>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<FingerprintResponse>, ApiError> {
    // 预校验：sha256 路径参数必须 64 位 hex，否则 400，任意字符串不进索引查询与日志。
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::Validation(
            "sha256 must be a 64-character hex string".into(),
        ));
    }

    let auth_ref = auth.as_ref().map(|e| &e.0);
    // 可见性白名单进 SQL 且在 LIMIT 之前：先取 200 行再过滤会在同哈希
    // 重复产出超过 200 时静默丢掉更早的可见行。
    let visible_products = compute_visible_products(&app, auth_ref).await?;
    let rows = app
        .state_store
        .find_artifacts_by_sha256_with_build(&sha256, visible_products.as_ref())
        .await
        .map_err(ApiError::from)?;
    let mut matches = Vec::new();

    // 可见性判定按产品名记忆化：每产品只查一次 products，配合 JOIN 取 build 字段，查询从 2N+1 降到 1+去重产品数。
    let mut visibility_cache: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();

    for row in rows {
        let visible = match visibility_cache.get(&row.product) {
            Some(v) => *v,
            None => {
                // 安全：owner/可见性查 live 数据（不随 unpublish 冻结值失效），与 builds 列表同一 `is_build_task_visible_to` 语义；产品已删 → 不可见静默剔除。
                let v = match app
                    .state_store
                    .get_product_by_name(&row.product)
                    .await
                    .map_err(ApiError::from)?
                {
                    None => false,
                    Some(product) => is_build_task_visible_to(
                        product.owner_id,
                        &product.visibility,
                        &row.product,
                        auth_ref,
                    ),
                };
                visibility_cache.insert(row.product.clone(), v);
                v
            }
        };

        // 安全：不可见行静默剔除，不泄漏"有/无"，也不泄漏"有但你不能看"。
        if !visible {
            continue;
        }

        matches.push(FingerprintMatch {
            build_id: row.artifact.build_id,
            relative_path: row.artifact.relative_path,
            kind: row.artifact.kind.as_str().to_string(),
            size_bytes: row.artifact.size_bytes,
            sha256: row.artifact.sha256,
            arch: row.artifact.arch,
            name: row.artifact.name,
            version: row.artifact.version,
            release: row.artifact.release,
            epoch: row.artifact.epoch,
            signed: row.artifact.signed,
            on_disk: row.artifact.on_disk,
            product: row.product,
            phase: row.phase,
        });
    }

    let total = matches.len();

    Ok(Json(FingerprintResponse {
        sha256,
        matches,
        total,
    }))
}

#[cfg(test)]
mod tests {
    use super::by_sha256;
    use crate::server::auth::AuthContext;
    use crate::server::error::ApiError;
    use crate::server::state::AppState;
    use axum::extract::{Extension, Path as AxumPath, State};
    use std::sync::Arc;

    /// 非法 sha256 路径参数（长度不足 / 非 hex）直接 400，不进查询。
    #[tokio::test]
    async fn by_sha256_rejects_malformed_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        for bad in ["deadbeef", "../foo", &"z".repeat(64), &"a".repeat(63)] {
            let result = by_sha256(State(app.clone()), AxumPath(bad.to_string()), None).await;
            assert!(
                matches!(result, Err(ApiError::Validation(_))),
                "sha256 '{bad}' must be rejected with 400"
            );
        }

        // 64 位 hex（大小写均可）通过预校验（空结果 200）。
        let result = by_sha256(
            State(app),
            AxumPath("A".repeat(64)),
            Some(Extension(AuthContext {
                user: "op".into(),
                role: "operator".into(),
                ..Default::default()
            })),
        )
        .await;
        assert!(result.is_ok(), "64-hex sha256 must pass pre-validation");
    }
}
