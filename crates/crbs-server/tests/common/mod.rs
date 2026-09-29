#![allow(dead_code)]
// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 集成测试二进制共享基建：各测试文件是独立二进制，`mod common;` 各自 include
//! 本文件，各得一份 `TEST_CONFIG_DIR` 实例（进程间本就隔离）。

// seed_* 等测试辅助函数不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, LazyLock};

/// 集成测试全局可写配置目录：`CRBS_CONFIG_DIR` 指向共享 tempdir，内含把
/// crbs_root 与全部运行时目录一并重定向的 `crbs.toml`——否则配置解析默认读
/// `/etc/crbs/crbs.toml`、运行时目录落 `/var/lib/crbs/*`，engine / CLI funnel
/// 的显式目录确保会写进系统路径。`use_privileged_helper = "never"`：`Auto` 会
/// 选中机器上已装的系统 setuid helper（部署机 /usr/libexec/crbs/crbs-priv-helper）
/// 做特权后端，其按机器全局 allowlist 校验 `--crbs-root`，tempdir 不在名单 →
/// GC 特权 rm 全拒（实测 integration_gc removed=0）；`never` 固定 SetuidBackend
/// 纯 std::fs 直删，自建自删、不依赖机器安装状态。
pub static TEST_CONFIG_DIR: LazyLock<tempfile::TempDir> = LazyLock::new(|| {
    let tmp = tempfile::tempdir().expect("integration test tempdir");
    let root = tmp.path().join("crbs_root");
    let content = format!(
        "crbs_root = \"{}\"\nresult_dir = \"{}\"\nshared_layers_dir = \"{}\"\ntmp_dir = \"{}\"\ntmpfs_dir = \"{}\"\nuse_privileged_helper = \"never\"\n",
        root.display(),
        root.join("results").display(),
        root.join("shared_layers").display(),
        tmp.path().join("tmp").display(),
        tmp.path().join("tmpfs").display(),
    );
    std::fs::write(tmp.path().join("crbs.toml"), content).expect("write test crbs.toml");
    std::env::set_var("CRBS_CONFIG_DIR", tmp.path());
    tmp
});

// 集成测试共享 fixture：提交入口以 SRPM header 的 N-V-R 为任务真名
//（NEVR 解析 fail-fast），假字节 fixture 会被 400 拒——测试用本 helper 现场
// 构造合法最小 SRPM，NEVR 可参数化以驱动去重/重命名断言。

use std::path::{Path, PathBuf};
use std::process::Command;

/// 在 `dir` 下现场构建一个最小合法 SRPM，落盘名 `{name}-{version}-{release}.src.rpm`。
/// rpmbuild 毫秒级；NEVR 由参数化，供同产品去重（同 N-V-R 409）与异名提交分别取用。
pub fn make_minimal_srpm(dir: &Path, name: &str, version: &str, release: &str) -> PathBuf {
    let top = dir.join(format!("rpmbuild-{name}"));
    for sub in ["SPECS", "SRPMS", "BUILD", "RPMS"] {
        std::fs::create_dir_all(top.join(sub)).unwrap();
    }
    let spec = top.join("SPECS").join(format!("{name}.spec"));
    std::fs::write(
        &spec,
        format!(
            "Name: {name}\nVersion: {version}\nRelease: {release}\nSummary: t\nLicense: MIT\n%description\nt\n"
        ),
    )
    .unwrap();
    let out = Command::new("rpmbuild")
        .args(["-bs", "--define"])
        .arg(format!("_topdir {}", top.display()))
        .arg(&spec)
        .output()
        .expect("rpmbuild -bs (minimal SRPM fixture)");
    assert!(
        out.status.success(),
        "rpmbuild fixture failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let srpm = top
        .join("SRPMS")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let dest = dir.join(srpm.file_name().unwrap());
    std::fs::copy(&srpm, &dest).unwrap();
    dest
}

/// 同 [`make_minimal_srpm`]，归档目录固定为 `uploads`（提交入口的暂存域）。
pub async fn make_srpm_in_uploads(dir: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    make_minimal_srpm(dir, name, "1.0", "1")
}

// —— UI 集成测试共享基建 ——

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// 读完整响应体为 UTF-8 文本（lossy 容错）。
pub async fn body_text(response: axum::response::Response) -> String {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 抽取页面中第一个 `name="csrf_token"` hidden input 的值。
pub fn extract_csrf_token(html: &str) -> Option<String> {
    let prefix = r#"name="csrf_token" value=""#;
    let start = html.find(prefix)? + prefix.len();
    let rest = &html[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 偏好写端点（set-theme / set-page-size / set-lang）共享的 Referer 回跳白名单
/// 固定 case：站内 /ui/ 根、站外、非 UI 站内、协议相对一律回 /ui/（防 open
/// redirect）；"保留 path+query" 的采纳 case 各测试自带（query 形态各异，不共享）。
pub const REFERER_FALLBACK_CASES: &[(&str, &str)] = &[
    ("https://crbs.local/ui/", "/ui/"),
    ("https://evil.com/evil", "/ui/"),
    ("https://crbs.local/api/v1/health", "/ui/"),
    ("//evil.com/x", "/ui/"),
];

/// 偏好写端点 POST 探测：urlencoded 表单 + 可选 Referer，返回原始响应（断言留在各测试）。
pub async fn post_preference_form(
    app: &axum::Router,
    uri: &str,
    body: &str,
    referer: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(referer) = referer {
        builder = builder.header(header::REFERER, referer);
    }
    app.clone()
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

/// 偏好写端点仅 POST：GET/HEAD 探测一律 405，且无 Set-Cookie / Location 副作用。
pub async fn assert_preference_writer_rejects_get_head(app: &axum::Router, probe_uri: &str) {
    for method in ["GET", "HEAD"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(probe_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not reach the preference writer"
        );
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "{method} must not set cookies"
        );
        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "{method} must not produce a redirect target"
        );
    }
}

// —— Hub 集成测试共享引导 ——
//
// UI/API 集成测试共享同一 setup_app（内存态存储 + 默认 ServerConfig + 全鉴权
// 路由）；参数化变体（自定义 ServerConfig / 角色 / 时钟）仍在各测试文件就地定义。

use crbs_core::config::ServerConfig;
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::state::AppState;

/// 标准测试 app：内存态存储 + 默认配置 + 全鉴权路由。
pub async fn setup_app() -> (Arc<AppState>, axum::Router, tempfile::TempDir) {
    let (state_store, tmp_dir) = crbs_server::test_support::create_test_store().await;
    let app_state = Arc::new(AppState::for_test(
        state_store,
        ServerConfig::default(),
        tmp_dir.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    (app_state, app, tmp_dir)
}

/// 同 [`setup_app`]，另为 `admin-op` 用户预置 admin token，随返回值第 4 元给出。
pub async fn setup_app_with_admin() -> (Arc<AppState>, axum::Router, tempfile::TempDir, String) {
    let (app_state, app, tmp_dir) = setup_app().await;
    let admin_token =
        crbs_server::server::seed_user_token_for_test(&app_state.state_store, "admin-op", "admin")
            .await
            .expect("seed admin token");
    (app_state, app, tmp_dir, admin_token)
}
