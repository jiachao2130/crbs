// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 路由清单漂移守卫（不引 utoipa/schemars）。
//!
//! axum 0.8 无公开的 `Router` 路径×方法枚举 API，三道防线把手工清单钉在真实
//! 注册行为上，漂移即红：
//! 1. `probe_paths_and_methods`：不存在的 `PROPFIND` 方法探每个清单路径——
//!    非 UI 路径比对 405 + `Allow` 头；UI 路径（自定义 method_not_allowed
//!    fallback 无 `Allow` 头）逐方法探、非 405 即注册；404 = 路径漂移。
//! 2. `probe_gate_boundaries`：认证 app 再探——public 405（optional_auth
//!    放行）、protected/admin 401（auth_middleware 先于方法匹配拒）。
//! 3. `inventory_covers_source_registrations`：扫 routes 源码全部 `.route(`，
//!    按（门控, 路径）与清单双向比对；`merge_app_matches_bootstrap` 对齐
//!    `create_test_app*` 与 `bootstrap::prepare_server` 的 `.merge(` 序列。
//!
//! 清单无生成器（案 B 取舍）：改路由后手工维护 EXPECTED，跑本文件四个测试，
//! 失败信息打印两侧差集与实际方法集合，照增删。HEAD 不入清单（GET 自动附带）。
//! 门控：`Public` = public 组（optional_auth）匿名可达；`Protected` = protected
//! 组（auth_middleware）需任一有效身份；`Admin` = 组内再加 handler `require_admin`。
//! helper 无 `#[test]`，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crbs_core::config::ServerConfig;
use crbs_server::server::state::AppState;
use crbs_server::server::{create_test_app, create_test_app_with_auth};
use crbs_server::test_support::create_test_store;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Gate {
    Public,
    Protected,
    Admin,
}

impl Gate {
    fn as_str(self) -> &'static str {
        match self {
            Gate::Public => "public",
            Gate::Protected => "protected",
            Gate::Admin => "admin",
        }
    }
}

/// 清单条目：门控 × 路径 × 逻辑方法；不含 HEAD（GET 自动附带）。
/// `{param}`/`{*path}` 沿 axum 0.8 源码写法，探测时替换为具体值。
struct Route(Gate, &'static str, &'static [&'static str]);

impl Route {
    fn gate(&self) -> Gate {
        self.0
    }
    fn path(&self) -> &'static str {
        self.1
    }
    fn methods(&self) -> &'static [&'static str] {
        self.2
    }
}

const G: &[&str] = &["GET"];
const P: &[&str] = &["POST"];
const GP: &[&str] = &["GET", "POST"];
const GPD: &[&str] = &["GET", "POST", "DELETE"];
const GUD: &[&str] = &["GET", "PUT", "DELETE"];

/// 期望路由清单（快照）：133 条唯一路径 ← 136 次 `.route(`（builds/tasks/
/// batches 的 GET+POST 分属两个 router 双注册，同路径合并为一行）；
/// `tasks/{id}/recipe` 经 `.merge(` 挂入，由 BUILDERS 单独扫 recipe.rs 覆盖。
static EXPECTED: &[Route] = &[
    Route(Gate::Public, "/api/v1/health", G),
    Route(Gate::Public, "/api/v1/version", G),
    Route(Gate::Public, "/api/v1/status", G),
    // ===== public：nihao（pre-auth 连通性/身份探针，CLI daemon 发现用）=====
    Route(Gate::Public, "/api/v1/nihao", G),
    // ===== public：复现率统计（可见性过滤在 handler 内）=====
    Route(Gate::Public, "/api/v1/reproducibility/stats", G),
    // ===== public：产物下载（public_access.download 门控在 handler 内）=====
    Route(Gate::Public, "/api/v1/builds/{id}/artifacts/download", G),
    // ===== public：匿名受限下载编排元数据（crbs download 无 token profile）=====
    Route(Gate::Public, "/api/v1/public/tasks/{id}", G),
    Route(Gate::Public, "/api/v1/public/builds/{id}/artifacts", G),
    Route(Gate::Public, "/repo/{product}/{arch}/{*path}", G),
    // ===== public：Web UI（routes/ui/mod.rs；web_ui_enabled 关闭时整组不挂载）=====
    Route(Gate::Public, "/", G),
    Route(Gate::Public, "/ui", G),
    Route(Gate::Public, "/ui/", G),
    Route(Gate::Public, "/ui/favicon.svg", G),
    Route(Gate::Public, "/ui/home/recent-tasks", G),
    Route(Gate::Public, "/ui/events", G),
    Route(Gate::Public, "/ui/builds", G),
    Route(Gate::Public, "/ui/builds/{id}", GP),
    Route(Gate::Public, "/ui/builds/{id}/changelog", G),
    Route(Gate::Public, "/ui/builds/{id}/logs", G),
    Route(Gate::Public, "/ui/builds/{id}/logs/stream", G),
    Route(Gate::Public, "/ui/builds/{id}/events", G),
    Route(Gate::Public, "/ui/tasks", G),
    Route(Gate::Public, "/ui/tasks/new", GP),
    Route(Gate::Public, "/ui/tasks/{id}", GP),
    Route(Gate::Public, "/ui/tasks/{id}/changelog", G),
    Route(Gate::Public, "/ui/tasks/{id}/rebuild", P),
    Route(Gate::Public, "/ui/tasks/{id}/reproduce", P),
    Route(Gate::Public, "/ui/tasks/{id}/events", G),
    Route(Gate::Public, "/ui/batches", G),
    Route(Gate::Public, "/ui/batches/{id}", GP),
    Route(Gate::Public, "/ui/products", G),
    Route(Gate::Public, "/ui/products/new", GP),
    Route(Gate::Public, "/ui/products/{name}", G),
    Route(Gate::Public, "/ui/products/{name}/profiles.csv", G),
    Route(Gate::Public, "/ui/products/{name}/packages/{source}", G),
    Route(
        Gate::Public,
        "/ui/products/{name}/packages/{source}/floors",
        P,
    ),
    Route(Gate::Public, "/ui/products/{name}/visibility", P),
    Route(Gate::Public, "/ui/products/{name}/acl", P),
    Route(Gate::Public, "/ui/products/{name}/acl/{username}/revoke", P),
    Route(Gate::Public, "/ui/products/{name}/transfer", P),
    Route(Gate::Public, "/ui/products/{name}/rebuild-repo", P),
    Route(Gate::Public, "/ui/products/{name}/edit", GP),
    Route(Gate::Public, "/ui/products/{name}/history", G),
    Route(Gate::Public, "/ui/products/{name}/history/diff", G),
    Route(Gate::Public, "/ui/packages", G),
    Route(Gate::Public, "/ui/packages/{name}", G),
    Route(Gate::Public, "/ui/search", G),
    Route(Gate::Public, "/ui/reproducibility", G),
    Route(Gate::Public, "/ui/workers", G),
    Route(Gate::Public, "/ui/workers/{id}", GP),
    Route(Gate::Public, "/ui/workers/{id}/events", G),
    Route(Gate::Public, "/ui/workers/{id}/remove", P),
    Route(Gate::Public, "/ui/admin", G),
    Route(Gate::Public, "/ui/admin/users", GP),
    Route(Gate::Public, "/ui/admin/users/{id}", G),
    Route(Gate::Public, "/ui/admin/users/{id}/role", P),
    Route(Gate::Public, "/ui/admin/users/{id}/status", P),
    Route(Gate::Public, "/ui/admin/users/{id}/password", P),
    Route(Gate::Public, "/ui/admin/users/{id}/tokens", P),
    Route(Gate::Public, "/ui/admin/users/{id}/tokens/{tid}/revoke", P),
    Route(Gate::Public, "/ui/admin/users/{id}/acl", P),
    Route(Gate::Public, "/ui/admin/users/{id}/acl/{product}/revoke", P),
    Route(Gate::Public, "/ui/admin/audit", G),
    Route(Gate::Public, "/ui/admin/settings", GP),
    Route(Gate::Public, "/ui/admin/gc", GP),
    Route(Gate::Public, "/ui/logout", P),
    Route(Gate::Public, "/ui/me", G),
    Route(Gate::Public, "/ui/me/password", P),
    Route(Gate::Public, "/ui/me/sessions/{sid}/revoke", P),
    Route(Gate::Public, "/ui/me/sessions/revoke-all", P),
    Route(Gate::Public, "/ui/me/tokens", P),
    Route(Gate::Public, "/ui/me/tokens/{tid}/revoke", P),
    Route(Gate::Public, "/ui/login", G),
    Route(Gate::Public, "/ui/login/password", P),
    Route(Gate::Public, "/ui/login/token", P),
    Route(Gate::Public, "/ui/register", GP),
    Route(Gate::Public, "/ui/set-theme", P),
    Route(Gate::Public, "/ui/set-lang", P),
    Route(Gate::Public, "/ui/set-page-size", P),
    Route(Gate::Protected, "/api/v1/builds", GP),
    Route(Gate::Protected, "/api/v1/builds/{id}", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/cancel", P),
    Route(Gate::Protected, "/api/v1/builds/{id}/publish", P),
    Route(Gate::Protected, "/api/v1/builds/{id}/unpublish", P),
    Route(Gate::Protected, "/api/v1/builds/{id}/diff", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/priority", &["PATCH"]),
    Route(Gate::Protected, "/api/v1/builds/{id}/srpm-download", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/build-packages", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/sign", P),
    Route(Gate::Protected, "/api/v1/builds/{id}/reproducibility", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/logs", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/profile", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/artifacts", G),
    Route(Gate::Protected, "/api/v1/builds/{id}/artifacts/upload", P),
    Route(Gate::Protected, "/api/v1/builds/{id}/changelog", G),
    Route(
        Gate::Protected,
        "/api/v1/builds/artifacts/by-sha256/{sha256}",
        G,
    ),
    // ===== protected：metrics（JSON + Prometheus，operator/admin 在 handler 内）=====
    Route(Gate::Protected, "/api/v1/metrics", G),
    Route(Gate::Protected, "/metrics", G),
    Route(Gate::Protected, "/api/v1/products", GP),
    Route(Gate::Protected, "/api/v1/products/{name}", GUD),
    Route(Gate::Protected, "/api/v1/products/{name}/init", P),
    Route(Gate::Protected, "/api/v1/products/{name}/clean", P),
    Route(Gate::Protected, "/api/v1/products/{name}/resolved", G),
    Route(Gate::Protected, "/api/v1/products/{name}/history", G),
    Route(
        Gate::Protected,
        "/api/v1/products/{name}/history/{revision}",
        G,
    ),
    Route(Gate::Protected, "/api/v1/products/tasks/{id}", G),
    Route(Gate::Protected, "/api/v1/products/{name}/acl", GPD),
    Route(Gate::Protected, "/api/v1/products/{name}/visibility", P),
    Route(Gate::Protected, "/api/v1/products/{name}/transfer", P),
    Route(Gate::Protected, "/api/v1/tasks", GP),
    Route(Gate::Protected, "/api/v1/tasks/{id}", G),
    Route(Gate::Protected, "/api/v1/tasks/{id}/cancel", P),
    Route(Gate::Protected, "/api/v1/tasks/{id}/rebuild", P),
    Route(Gate::Protected, "/api/v1/tasks/{id}/reproduce", P),
    Route(Gate::Protected, "/api/v1/tasks/{id}/recipe", G),
    Route(Gate::Protected, "/api/v1/workers", G),
    Route(Gate::Protected, "/api/v1/workers/register", P),
    Route(Gate::Protected, "/api/v1/workers/{id}/heartbeat", P),
    Route(Gate::Protected, "/api/v1/workers/{id}/assignments", G),
    Route(
        Gate::Protected,
        "/api/v1/workers/{id}/assignments/{assignment_id}/result",
        P,
    ),
    Route(
        Gate::Protected,
        "/api/v1/workers/{id}/assignments/{assignment_id}/logs",
        P,
    ),
    Route(Gate::Protected, "/api/v1/workers/{id}/secret/rotate", P),
    Route(Gate::Protected, "/api/v1/workers/{id}/secret/revoke", P),
    Route(Gate::Protected, "/api/v1/workers/{id}/remove", P),
    Route(Gate::Protected, "/api/v1/gc", P),
    Route(Gate::Protected, "/api/v1/gc/{id}", G),
    // ===== protected：batches（整仓重建，operator 在 handler 内）=====
    Route(Gate::Protected, "/api/v1/batches", GP),
    Route(Gate::Protected, "/api/v1/batches/{id}", G),
    Route(Gate::Protected, "/api/v1/batches/{id}/cancel", P),
    // ===== admin：require_admin（handler 内二级门控）=====
    Route(Gate::Admin, "/api/v1/admin/audit-logs", G),
    Route(Gate::Admin, "/api/v1/admin/users", GP),
    Route(Gate::Admin, "/api/v1/admin/users/{id}", GUD),
    Route(Gate::Admin, "/api/v1/admin/users/{id}/tokens", GP),
    Route(
        Gate::Admin,
        "/api/v1/admin/users/{id}/tokens/{tid}",
        &["DELETE"],
    ),
    Route(Gate::Admin, "/api/v1/admin/products/{product}/acl", GP),
    Route(
        Gate::Admin,
        "/api/v1/admin/products/{product}/acl/{user_id}",
        &["DELETE"],
    ),
    Route(Gate::Admin, "/api/v1/admin/workers/{id}/init", P),
    Route(
        Gate::Admin,
        "/api/v1/admin/products/{product}/rebuild-repo",
        P,
    ),
    // ===== admin：包资源画像管理面（handler 内 require_admin）=====
    Route(Gate::Admin, "/api/v1/resource-profiles", G),
    Route(
        Gate::Admin,
        "/api/v1/resource-profiles/{product}/{source}/{arch}",
        GUD,
    ),
];

/// 源码扫描目标：(文件, builder fn 名, 该 builder 挂载的门控)；门控取
/// `bootstrap::prepare_server` / `create_test_app*` 的 merge 位置。
const BUILDERS: &[(&str, &str, Gate)] = &[
    ("src/server/routes/admin.rs", "router", Gate::Admin),
    (
        "src/server/routes/artifacts/mod.rs",
        "public_router",
        Gate::Public,
    ),
    (
        "src/server/routes/artifacts/mod.rs",
        "protected_router",
        Gate::Protected,
    ),
    ("src/server/routes/builds.rs", "router", Gate::Protected),
    ("src/server/routes/gc.rs", "router", Gate::Protected),
    ("src/server/routes/batches.rs", "router", Gate::Protected),
    ("src/server/routes/health.rs", "public_router", Gate::Public),
    (
        "src/server/routes/health.rs",
        "protected_router",
        Gate::Protected,
    ),
    ("src/server/routes/logs.rs", "router", Gate::Protected),
    ("src/server/routes/nihao.rs", "router", Gate::Public),
    ("src/server/routes/product.rs", "router", Gate::Protected),
    ("src/server/routes/profile.rs", "router", Gate::Protected),
    (
        "src/server/routes/reproducibility.rs",
        "public_router",
        Gate::Public,
    ),
    ("src/server/routes/repo.rs", "router", Gate::Public),
    (
        "src/server/routes/resource_profiles.rs",
        "router",
        Gate::Admin,
    ),
    ("src/server/routes/tasks/mod.rs", "router", Gate::Protected),
    (
        "src/server/routes/tasks/mod.rs",
        "public_router",
        Gate::Public,
    ),
    // recipe router 经 `.merge()` 挂入，`.route(` 扫描盲区，须单独列出。
    (
        "src/server/routes/tasks/recipe.rs",
        "router",
        Gate::Protected,
    ),
    ("src/server/routes/ui/mod.rs", "public_router", Gate::Public),
    ("src/server/worker/routes/mod.rs", "router", Gate::Protected),
];

/// UI 路由判定：挂自定义 405 fallback（无 `Allow` 头），方法探测逐方法进行。
fn is_ui_path(path: &str) -> bool {
    path == "/" || path.starts_with("/ui")
}

/// 清单路径 → 探测用具体路径：`{param}` → `x`，`{*wild}` → `a/b`。
fn concrete_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find('}')
            .expect("unbalanced brace in route path");
        let param = &rest[start..=start + end];
        if param.starts_with("{*") {
            out.push_str("a/b");
        } else {
            out.push('x');
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

/// 清单逻辑方法 → 期望可请求方法集合（GET 自动附带 HEAD）。
fn expected_allow(methods: &[&str]) -> Vec<String> {
    let mut set: Vec<String> = methods.iter().map(|m| m.to_string()).collect();
    if methods.contains(&"GET") && !set.iter().any(|m| m == "HEAD") {
        set.push("HEAD".into());
    }
    set.sort();
    set
}

fn build_request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// 单个清单路径的实际可请求方法集合：非 UI 一次 `PROPFIND` 读 405 `Allow` 头；
/// UI 路径（自定义 405 fallback，无 `Allow` 头）逐方法探，非 405 即注册。
async fn actual_methods(app: axum::Router, route: &Route) -> Vec<String> {
    let uri = concrete_path(route.path());
    if !is_ui_path(route.path()) {
        let response = app
            .clone()
            .oneshot(build_request("PROPFIND", &uri))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "PROPFIND probe on {} ({}): expected 405 (path exists, method unregistered); \
             404 means the path is not registered",
            route.path(),
            route.gate().as_str()
        );
        let allow = response
            .headers()
            .get(axum::http::header::ALLOW)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let mut set: Vec<String> = allow
            .split(',')
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .collect();
        set.sort();
        assert!(
            !set.is_empty(),
            "405 response for {} carried no Allow header; \
             axum routing semantics changed or a custom method-not-allowed fallback leaked; \
             switch this path to per-method probing",
            route.path()
        );
        set
    } else {
        let mut set = Vec::new();
        for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] {
            let response = app
                .clone()
                .oneshot(build_request(method, &uri))
                .await
                .unwrap();
            if response.status() != StatusCode::METHOD_NOT_ALLOWED {
                set.push(method.to_string());
            }
        }
        set.sort();
        set
    }
}

fn setup_state() -> (std::sync::Arc<AppState>, tempfile::TempDir) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (store, tmp) = rt.block_on(async { create_test_store().await });
    let state = std::sync::Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    (state, tmp)
}

/// 防线 1：清单 路径×方法 与真实注册逐一比对。
#[test]
fn probe_paths_and_methods() {
    let (state, _tmp) = setup_state();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let failures = rt.block_on(async {
        let app = create_test_app(state);
        let mut failures = Vec::new();
        for route in EXPECTED {
            let actual = actual_methods(app.clone(), route).await;
            let expected = expected_allow(route.methods());
            if actual != expected {
                failures.push(format!(
                    "[{}] {}\n    expected methods: {expected:?}\n    actual methods:   {actual:?}",
                    route.gate().as_str(),
                    route.path()
                ));
            }
        }
        failures
    });
    assert!(
        failures.is_empty(),
        "route inventory drift detected ({} path(s)):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// 防线 2：门控类别与真实认证边界逐一比对。admin/protected 的区分由防线 3 的
/// builder 归属 + handler `require_admin` 保证，此处只锁 public/protected 边界。
#[test]
fn probe_gate_boundaries() {
    let (state, _tmp) = setup_state();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let failures = rt.block_on(async {
        let app = create_test_app_with_auth(state);
        let mut failures = Vec::new();
        for route in EXPECTED {
            let uri = concrete_path(route.path());
            let status = app
                .clone()
                .oneshot(build_request("PROPFIND", &uri))
                .await
                .unwrap()
                .status();
            let expected = match route.gate() {
                Gate::Public => StatusCode::METHOD_NOT_ALLOWED,
                Gate::Protected | Gate::Admin => StatusCode::UNAUTHORIZED,
            };
            if status != expected {
                failures.push(format!(
                    "[{}] {}: expected {expected}, got {status}",
                    route.gate().as_str(),
                    route.path()
                ));
            }
        }
        failures
    });
    assert!(
        failures.is_empty(),
        "gate drift detected ({} path(s)):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// 从源码文本提取 `.route(` 的路径字面量，归属当前 builder fn；字面量可与
/// `.route(` 跨行、其间只允许空白，动态路径（format! 等）直接 panic（须扩
/// 扫描器），遇 `#[cfg(test)]` 停止（测试 route 不计数）。
fn extract_routes(source: &str, file: &str) -> Vec<(String, String)> {
    let text = match source.find("#[cfg(test)]") {
        Some(idx) => &source[..idx],
        None => source,
    };

    let mut line_builders: Vec<Option<&str>> = Vec::with_capacity(text.lines().count());
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if let Some(idx) = line.find("fn ") {
            let after = &line[idx + 3..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if matches!(
                name.as_str(),
                "router" | "public_router" | "protected_router"
            ) {
                current = Some(match name.as_str() {
                    "router" => "router",
                    "public_router" => "public_router",
                    _ => "protected_router",
                });
            }
        }
        line_builders.push(current);
    }

    let mut routes = Vec::new();
    let mut cursor = 0usize;
    while let Some(rel) = text[cursor..].find(".route(") {
        let pos = cursor + rel;
        let line_idx = text[..pos].matches('\n').count();
        let builder = line_builders[line_idx]
            .unwrap_or_else(|| panic!("{file}: `.route(` found outside a known router builder fn"));
        let after = &text[pos + ".route(".len()..];
        let quote = after.find('"').expect("`.route(` with no path literal");
        assert!(
            after[..quote].trim().is_empty(),
            "{file}: `.route(` with a non-literal path (dynamic routes cannot be inventoried): {}",
            after[..quote + 40].trim()
        );
        let rest = &after[quote + 1..];
        let end = rest
            .find('"')
            .unwrap_or_else(|| panic!("{file}: unterminated path literal"));
        routes.push((builder.to_string(), rest[..end].to_string()));
        cursor = pos + ".route(".len() + quote + 1 + end;
    }
    routes
}

/// 防线 3a：源码全部 `.route(` 注册与清单（门控 × 路径）双向对齐。
#[test]
fn inventory_covers_source_registrations() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    // BUILDERS 按文件分组：一个文件可定义多个 builder（如 health / artifacts）。
    let mut builders_by_file: BTreeMap<&str, Vec<(&str, Gate)>> = BTreeMap::new();
    for (file, builder, gate) in BUILDERS {
        builders_by_file
            .entry(file)
            .or_default()
            .push((*builder, *gate));
    }

    // (gate, path) → 注册次数：同路径多次注册合法（axum 合并同路径 MethodRouter）。
    let mut source: BTreeMap<(Gate, String), usize> = BTreeMap::new();
    for (file, builders) in &builders_by_file {
        let path = format!("{manifest}/{file}");
        let source_text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let extracted = extract_routes(&source_text, file);
        for (builder, _) in builders {
            assert!(
                extracted.iter().any(|(name, _)| name == builder),
                "{file}: scanner found no `.route(` under builder `{builder}`; \
                 the builder was renamed or moved — update BUILDERS"
            );
        }
        for (name, route_path) in extracted {
            let gate = builders
                .iter()
                .find(|(b, _)| *b == name)
                .map(|(_, g)| *g)
                .unwrap_or_else(|| {
                    panic!(
                        "{file}: route {route_path} attributed to builder `{name}`, \
                         which is not in BUILDERS"
                    )
                });
            *source.entry((gate, route_path)).or_insert(0) += 1;
        }
    }

    let mut inventory: BTreeMap<(Gate, String), usize> = BTreeMap::new();
    for route in EXPECTED {
        *inventory
            .entry((route.gate(), route.path().to_string()))
            .or_insert(0) += 1;
    }

    let missing_in_inventory: Vec<String> = source
        .keys()
        .filter(|k| !inventory.contains_key(k))
        .map(|(g, p)| format!("[{}] {p}", g.as_str()))
        .collect();
    let stale_in_inventory: Vec<String> = inventory
        .keys()
        .filter(|k| !source.contains_key(k))
        .map(|(g, p)| format!("[{}] {p}", g.as_str()))
        .collect();
    assert!(
        missing_in_inventory.is_empty() && stale_in_inventory.is_empty(),
        "source registrations and inventory diverged:\n\
         registered in source but missing from EXPECTED (add a row):\n  {}\n\
         listed in EXPECTED but no longer registered (drop the row):\n  {}",
        missing_in_inventory.join("\n  "),
        stale_in_inventory.join("\n  ")
    );
}

/// 防线 3b：`assemble_test_routers`（create_test_app 两变体共用）与
/// `bootstrap::prepare_server` 的 merge 序列对齐——测试 app 是全部探测的
/// 事实基座，分叉则前两防线的"绿"失真。
#[test]
fn merge_app_matches_bootstrap() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let bootstrap = std::fs::read_to_string(format!("{manifest}/src/server/bootstrap.rs"))
        .expect("read bootstrap.rs");
    let server_mod =
        std::fs::read_to_string(format!("{manifest}/src/server/mod.rs")).expect("read mod.rs");

    let prepare = function_body(
        &bootstrap,
        "async fn prepare_server",
        "fn ensure_result_root_writable",
    );
    let test_app = function_body(&server_mod, "fn assemble_test_routers", "\n/// 测试辅助");
    // 两个测试构造器都必须走共享装配（防绕开 helper 手搓出分叉路由集）。
    assert_eq!(
        server_mod
            .matches("assemble_test_routers(&app_state)")
            .count(),
        2,
        "create_test_app / create_test_app_with_auth must both delegate to assemble_test_routers"
    );

    let merges = |body: &str| -> Vec<String> {
        body.split(".merge(")
            .skip(1)
            .filter_map(|tail| {
                // 取实参开头的标识符链，归一化为末两段（`admin::router`）——
                // 消掉 `super::`/`crate::server::` 前缀差异，实参随非标识符字符截断。
                let chain: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                let mut parts: Vec<&str> = chain.split("::").filter(|s| !s.is_empty()).collect();
                if parts.len() == 1 {
                    // 单段 = 合并局部变量：bootstrap 按 auth 开关两分支、测试 app
                    // 只有一份，属中间件布线差异而非路由集合差异，跳过不计。
                    return None;
                }
                assert!(
                    parts.len() >= 2,
                    "unexpected merge target `{chain}` — update the merge scanner"
                );
                let func = parts.pop().expect("merge target fn");
                let owner = parts.pop().expect("merge target module");
                Some(format!("{owner}::{func}"))
            })
            .collect()
    };

    let a = merges(&prepare);
    let b = merges(&test_app);
    assert!(
        !a.is_empty() && !b.is_empty(),
        "merge scan came up empty (prepare={}, test_app={}); \
         function markers in this test no longer match the source — update them",
        a.len(),
        b.len()
    );
    assert_eq!(
        a, b,
        "bootstrap::prepare_server and assemble_test_routers merge different routers; \
         the inventory probes exercise the test app and must see the production set"
    );
}

/// 截取 `start 标记` 到 `end 标记` 之间的函数体文本（标记失效 → panic）。
/// end 缺失不得静默扩区到文件尾：merges 扫描会吞进后续函数的 merge 调用，
/// 让"扫描非空"断言仍绿灯、两侧比较失真——防线在此处先行失败。
fn function_body(source: &str, start: &str, end: &str) -> String {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("marker `{start}` not found"));
    let rest = &source[from..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("end marker `{end}` not found after `{start}`"));
    rest[..to].to_string()
}
