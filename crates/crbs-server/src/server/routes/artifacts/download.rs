// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 产物下载路由：可见性门、路径解析与流式响应。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use tokio_util::io::ReaderStream;

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::DownloadQuery;

/// 产物相对路径 → 校验后的绝对路径（防穿越 + canonicalize 起点约束 + 常规文件）。
/// changelog 端点复用（路径组件全部来自 DB 行，不来自用户输入）。
pub(super) async fn resolve_artifact_file(
    base: &Path,
    requested: &str,
) -> Result<PathBuf, ApiError> {
    let requested = Path::new(requested);
    if requested
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ApiError::Validation(
            "artifact path contains parent dir (..)".into(),
        ));
    }

    let full_path = base.join(requested);
    let canonical = tokio::fs::canonicalize(&full_path)
        .await
        .map_err(|_| ApiError::not_found("artifact", requested.display()))?;
    let canonical_base = tokio::fs::canonicalize(base).await.map_err(|e| {
        tracing::error!(base = %base.display(), error = %e, "canonicalize result dir failed");
        ApiError::Internal("failed to resolve artifact directory".into())
    })?;

    if !canonical.starts_with(&canonical_base) {
        return Err(ApiError::not_found("artifact", requested.display()));
    }
    let metadata = tokio::fs::metadata(&canonical)
        .await
        .map_err(|_| ApiError::not_found("artifact", requested.display()))?;
    if !metadata.is_file() {
        return Err(ApiError::not_found("artifact", requested.display()));
    }

    Ok(canonical)
}

/// 生效的 SRPM 可下性：产品配置显式 `allow_srpm_download` 覆盖全局（链合并后
/// 的解析值，父产品策略被子产品继承），省略跟随 server.toml 全局键。产品配置
/// 读取失败回退全局——下载端点不因产品配置临时损坏而不可用（result_dir 同款
/// 口径）。链解析有进程内缓存，与同 handler 的 result_dir 解析共摊成本。
async fn effective_allow_srpm_download(app: &AppState, product: &str) -> bool {
    let global = app.server_config.allow_srpm_download;
    match app.state_store.resolve_any_product_by_name(product).await {
        Ok(resolved) => resolved.config.allow_srpm_download.unwrap_or(global),
        Err(e) => {
            tracing::warn!(
                product = %product,
                error = %e,
                "Failed to load product config for srpm policy; falling back to global"
            );
            global
        }
    }
}

/// 下载构建产物（GET）。HEAD 由 axum 按 GET 路由兜底：前置逻辑（权限、可见性、
/// 路径解析）照常执行、仅剥离响应 body——`ReaderStream` 未 poll 即 drop、文件
/// 字节不读出；流式响应无精确 size hint，故不带 Content-Length。
pub(crate) async fn download_artifact(
    State(app): State<Arc<AppState>>,
    AxumPath(id): AxumPath<i64>,
    Query(q): Query<DownloadQuery>,
    auth: Option<Extension<AuthContext>>,
) -> Result<impl IntoResponse, ApiError> {
    let record = app
        .state_store
        .get_build(id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", id))?;

    // auth_enabled=false 时整站无认证（仅 loopback），public_access 配置不生效。
    if app.server_config.auth_enabled && !app.server_config.public_access.download {
        auth.as_ref().ok_or(ApiError::Unauthorized(
            "artifact download requires authentication".into(),
        ))?;
    }

    // 产品维度可见性：public 照常，private 仅 owner/ACL/operator，匿名/无关 403。
    // worker 是机器身份（dispatch 派发、凭 secret 取件），不走用户产品 ACL。
    if auth.as_ref().is_none_or(|ctx| ctx.0.role != "worker") {
        ensure_product_visible_for_record(&app, &record.product, auth.as_ref().map(|ctx| &ctx.0))
            .await?;
    }

    let result_dir = record
        .result_dir
        .as_deref()
        .ok_or_else(|| ApiError::not_found("build result dir", id))?;
    let result_root = app.result_dir_for_or_default(&record.product).await;
    let base = crbs_core::util::validate_result_dir(result_dir, &result_root)
        .await
        .map_err(|e| {
            // Validation 细节含服务端绝对路径，只进日志不进响应。
            tracing::warn!(build_id = %id, error = %e, "Invalid result_dir while resolving artifact download");
            ApiError::Validation(
                "build result directory is invalid or outside the result root".into(),
            )
        })?;

    let file_name = Path::new(&q.file)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ApiError::Validation("invalid artifact file name".into()))?
        .to_string();

    if file_name.ends_with(".src.rpm")
        && !effective_allow_srpm_download(&app, &record.product).await
    {
        if app.server_config.auth_enabled {
            let ctx = auth.as_ref().ok_or(ApiError::Unauthorized(
                "SRPM download requires authentication".into(),
            ))?;
            if !ctx.is_operator() {
                return Err(ApiError::PermissionDenied(
                    "SRPM download requires operator role or higher".into(),
                ));
            }
        } else {
            return Err(ApiError::PermissionDenied(
                "SRPM download is disabled on this server".into(),
            ));
        }
    }

    let canonical = resolve_artifact_file(&base, &q.file).await?;

    let file = tokio::fs::File::open(&canonical).await.map_err(|e| {
        tracing::error!(path = %canonical.display(), error = %e, "read artifact failed");
        ApiError::Internal("failed to read artifact".into())
    })?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    let content_type = guess_artifact_content_type(&file_name);

    let mut headers = HeaderMap::new();
    // 产物是一次性快照：no-store 禁共享缓存/代理留存。
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_TYPE,
        content_type
            .parse()
            .map_err(|_| ApiError::Internal("failed to build content-type header".into()))?,
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(&file_name)
            .parse()
            .map_err(|_| ApiError::Internal("failed to build content-disposition header".into()))?,
    );

    Ok((StatusCode::OK, headers, body))
}

/// 构造 `Content-Disposition`：`filename*=UTF-8''<percent-encoded>`（RFC 5987
/// ext-value）为主，`filename="<ASCII 兜底>"` 供不支持扩展语法的旧客户端；
/// 非 ASCII 直塞 quoted-string 是 RFC 违规且被部分客户端按 Latin-1 解成乱码。
pub(crate) fn content_disposition(file_name: &str) -> String {
    let ascii_fallback: String = file_name
        .chars()
        .filter(|c| c.is_ascii() && *c != '"' && *c != '\\')
        .collect();
    let fallback = if ascii_fallback.is_empty() {
        "artifact"
    } else {
        ascii_fallback.as_str()
    };
    // urlencoding::encode 只留 ALPHA/DIGIT/-._，attr-char 保守子集 → 恒为合法 ext-value。
    format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        fallback,
        urlencoding::encode(file_name)
    )
}
pub(crate) fn guess_artifact_content_type(file_name: &str) -> &'static str {
    let lower = file_name.to_lowercase();
    if lower.ends_with(".rpm") || lower.ends_with(".src.rpm") {
        "application/x-rpm"
    } else if lower.ends_with(".log") || lower.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".xml") {
        "application/xml"
    } else if lower.ends_with(".gz") {
        "application/gzip"
    } else if lower.ends_with(".xz") {
        "application/x-xz"
    } else {
        "application/octet-stream"
    }
}
#[cfg(test)]
mod tests {
    use super::{content_disposition, guess_artifact_content_type, resolve_artifact_file};
    use crate::server::error::ApiError;

    #[test]
    fn content_disposition_encodes_utf8_filename() {
        let cd = content_disposition("包-1.0.x86_64.rpm");
        assert!(
            cd.contains("filename*=UTF-8''%E5%8C%85-1.0.x86_64.rpm"),
            "ext-value must be percent-encoded, got: {cd}"
        );
        assert!(
            cd.contains("filename=\"-1.0.x86_64.rpm\""),
            "ASCII fallback keeps the ascii tail, got: {cd}"
        );
        let cd = content_disposition("包");
        assert!(
            cd.contains("filename=\"artifact\""),
            "fully non-ASCII name must fall back to placeholder, got: {cd}"
        );
    }

    #[test]
    fn content_disposition_keeps_ascii_and_escapes_quotes() {
        let cd = content_disposition("hello-1.0.rpm");
        assert_eq!(
            cd,
            "attachment; filename=\"hello-1.0.rpm\"; filename*=UTF-8''hello-1.0.rpm"
        );
        // 含引号的文件名从 ASCII 兜底中剔除，避免截断 quoted-string。
        let cd = content_disposition("evil\"name.rpm");
        assert!(
            cd.contains("filename=\"evilname.rpm\""),
            "quotes must be stripped from fallback, got: {cd}"
        );
    }

    #[tokio::test]
    async fn resolve_artifact_file_accepts_valid_relative_path() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path();
        let file_path = base.join("RPMS").join("hello.rpm");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::File::create(&file_path).unwrap();

        let resolved = resolve_artifact_file(base, "RPMS/hello.rpm").await.unwrap();
        assert_eq!(resolved, tokio::fs::canonicalize(&file_path).await.unwrap());
    }

    #[tokio::test]
    async fn resolve_artifact_file_rejects_parent_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(resolve_artifact_file(tmp.path(), "../secret")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn resolve_artifact_file_rejects_symlink_escape() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path();
        let outside_tmp = tempfile::TempDir::new().unwrap();
        let outside = outside_tmp.path().join("outside.txt");
        std::fs::File::create(&outside).unwrap();
        let link = base.join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        #[cfg(not(unix))]
        {
            return;
        }

        assert!(matches!(
            resolve_artifact_file(base, "link.txt").await,
            Err(ApiError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn resolve_artifact_file_rejects_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let base = tmp.path();
        std::fs::create_dir(base.join("RPMS")).unwrap();
        assert!(matches!(
            resolve_artifact_file(base, "RPMS").await,
            Err(ApiError::NotFound(_))
        ));
    }

    #[test]
    fn guess_artifact_content_type_maps_extensions() {
        assert_eq!(guess_artifact_content_type("pkg.rpm"), "application/x-rpm");
        assert_eq!(
            guess_artifact_content_type("pkg.src.rpm"),
            "application/x-rpm"
        );
        assert_eq!(
            guess_artifact_content_type("build.log"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            guess_artifact_content_type("build.json"),
            "application/json"
        );
        assert_eq!(
            guess_artifact_content_type("unknown.bin"),
            "application/octet-stream"
        );
    }

    /// 产品可见性：private 匿名/viewer 403；public 至无 result_dir 的 404（权限层放行）。
    #[tokio::test]
    async fn download_artifact_checks_product_visibility() {
        use super::download_artifact;
        use super::DownloadQuery;
        use crate::server::auth::AuthContext;
        use crate::server::state::AppState;
        use axum::extract::{Extension, Path as AxumPath, Query, State};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        // 公开下载开启 + 关闭强制认证：匿名可达权限层，覆盖 public_access 泄漏面。
        let cfg = crbs_core::config::ServerConfig {
            auth_enabled: false,
            public_access: crbs_core::config::PublicAccessConfig {
                download: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let app = Arc::new(AppState::for_test(
            store.clone(),
            cfg,
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

        let q = || {
            Query(DownloadQuery {
                file: "RPMS/hello.rpm".into(),
            })
        };

        let secret_id = insert_build("secret").await;
        let result = download_artifact(State(app.clone()), AxumPath(secret_id), q(), None).await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "anonymous download of private product build must be denied"
        );

        let viewer = AuthContext {
            user: "eve".into(),
            role: "viewer".into(),
            ..Default::default()
        };
        let result = download_artifact(
            State(app.clone()),
            AxumPath(secret_id),
            q(),
            Some(Extension(viewer)),
        )
        .await;
        assert!(
            matches!(result, Err(ApiError::PermissionDenied(_))),
            "viewer download of private product build must be denied"
        );

        let public_id = insert_build("openfed").await;
        let result = download_artifact(State(app), AxumPath(public_id), q(), None).await;
        assert!(
            matches!(result, Err(ApiError::NotFound(_))),
            "public product download must pass the permission layer"
        );
    }

    /// SRPM 门的产品级覆盖矩阵：全局 false 时匿名 401 / builder 403 / 产品显式
    /// `allow_srpm_download = true` 放行匿名；全局 true 时产品显式 false 收紧为
    /// 匿名 401。门放行后走 result_dir 缺失的 404（同可见性测试口径）。
    #[tokio::test]
    async fn srpm_gate_honors_product_override() {
        use super::download_artifact;
        use super::DownloadQuery;
        use crate::server::auth::AuthContext;
        use crate::server::state::AppState;
        use axum::extract::{Extension, Path as AxumPath, Query, State};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let base = || crbs_core::config::ServerConfig {
            auth_enabled: true,
            public_access: crbs_core::config::PublicAccessConfig {
                download: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let app_off = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig {
                allow_srpm_download: false,
                ..base()
            },
            tmp.path().to_path_buf(),
        ));
        let app_on = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig {
                allow_srpm_download: true,
                ..base()
            },
            tmp.path().to_path_buf(),
        ));

        // 产品配置须过链出口校验（根层 base_packages 非空），否则
        // effective_allow_srpm_download 的链解析失败会静默回退全局。
        let cfg_with = |srpm: Option<bool>| crbs_core::config::ProductConfig {
            base_packages: vec!["bash".into()],
            repos: vec![crbs_core::config::RepoConfig {
                name: "base".into(),
                baseurl: "http://example.com/repo".into(),
                ..Default::default()
            }],
            allow_srpm_download: srpm,
            ..Default::default()
        };
        for (name, srpm) in [
            ("plain", None),
            ("open-srpm", Some(true)),
            ("locked-srpm", Some(false)),
        ] {
            store
                .create_product(crbs_core::CreateProductInput {
                    name,
                    display_name: None,
                    owner_id: None,
                    parent_id: None,
                    visibility: crbs_core::VISIBILITY_PUBLIC,
                    config: &cfg_with(srpm),
                    changed_by_user_id: None,
                    reason: None,
                })
                .await
                .unwrap();
        }

        // result_dir 必须真实存在：handler 里 result_dir 解析先于 SRPM 门，
        // 缺失会在门前 404（可见性测试正是借这一点探权限层）。
        let result_root = tmp.path().join("results");
        let insert_build = |product: &'static str, dir: &'static str| {
            let store = store.clone();
            let result_root = result_root.clone();
            async move {
                let task_id = crate::test_support::seed_task(&store, product, "pkg").await;
                let rd = result_root.join(dir);
                tokio::fs::create_dir_all(&rd).await.unwrap();
                let rd: &'static str = Box::leak(rd.display().to_string().into_boxed_str());
                store
                    .insert_build(crbs_core::BuildInsert {
                        product,
                        pkg_name: "pkg",
                        phase: "succeeded",
                        backend: "chroot",
                        user: "alice",
                        task_id: Some(task_id),
                        result_dir: Some(rd),
                        ..Default::default()
                    })
                    .await
                    .unwrap()
            }
        };

        let q = || {
            Query(DownloadQuery {
                file: "SRPMS/hello.src.rpm".into(),
            })
        };
        let as_role = |role: &str| {
            Some(Extension(AuthContext {
                user: "u".into(),
                role: role.to_string(),
                ..Default::default()
            }))
        };

        let plain = insert_build("plain", "b-plain").await;
        let open = insert_build("open-srpm", "b-open").await;
        let locked = insert_build("locked-srpm", "b-locked").await;

        fn expect<R: axum::response::IntoResponse>(
            result: Result<R, ApiError>,
            what: &str,
            check: fn(&ApiError) -> bool,
        ) {
            assert!(
                result.as_ref().err().is_some_and(check),
                "{what}: expected matching error, got {:?}",
                result.err()
            );
        }
        let is_401 = |e: &ApiError| matches!(e, ApiError::Unauthorized(_));
        let is_403 = |e: &ApiError| matches!(e, ApiError::PermissionDenied(_));
        let is_404 = |e: &ApiError| matches!(e, ApiError::NotFound(_));

        // 全局关：默认产品匿名 401、builder 403（is_operator 不含 builder）。
        expect(
            download_artifact(State(app_off.clone()), AxumPath(plain), q(), None).await,
            "global off / product default / anonymous",
            is_401,
        );
        expect(
            download_artifact(
                State(app_off.clone()),
                AxumPath(plain),
                q(),
                as_role("builder"),
            )
            .await,
            "global off / product default / builder",
            is_403,
        );
        // 全局关 + 产品显式 true：匿名放行（到 result_dir 缺失的 404）。
        expect(
            download_artifact(State(app_off.clone()), AxumPath(open), q(), None).await,
            "global off / product true / anonymous",
            is_404,
        );
        // 全局开 + 产品显式 false：匿名收紧为 401。
        expect(
            download_artifact(State(app_on.clone()), AxumPath(locked), q(), None).await,
            "global on / product false / anonymous",
            is_401,
        );
        // 全局开：默认产品门关（匿名放行）。
        expect(
            download_artifact(State(app_on), AxumPath(plain), q(), None).await,
            "global on / product default / anonymous",
            is_404,
        );
    }
}
