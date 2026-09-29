// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 触发点修复回归测试：regen 触发点挂在 `report_result` 的 succeeded 臂。
//!
//! worker 时序 `upload → report_result`，phase 翻 `succeeded` 只发生在
//! `report_result`，候选 SQL 又过滤 `phase='succeeded'`——触发点必须晚于
//! 翻转。三个 case：succeeded → 硬链存在；building / failed → 0 候选不硬链。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use crbs_core::auth::secret::{Secret, SecretKind};
use crbs_core::config::ServerConfig;
use crbs_core::engine::repo_publish::RepoAssembleReport;
use crbs_core::{ArtifactKind, NewArtifact};
use crbs_server::server::create_test_app_with_auth;
use crbs_server::server::seed_user_token_for_test;
use crbs_server::server::state::AppState;
use tower::ServiceExt;

const PRODUCT: &str = "ule3";
const ARCH: &str = "x86_64";
const PKG: &str = "regen-trigger-test";
const NEVRA: &str = "regen-trigger-test-1.0-1.x86_64.rpm";

async fn setup() -> (Arc<AppState>, tempfile::TempDir) {
    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app_state: Arc<AppState> = Arc::new(AppState::for_test(
        store,
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    (app_state, tmp)
}

/// 造一个 build（指定 phase，phase 决定 SQL 候选是否命中——触发点修复验证的
/// 核心变量）+ 真实 result_dir + 一条 rpm artifact，返回 build_id。
async fn seed_build_with_artifact(state: &AppState, crbs_root: &Path, phase: &str) -> i64 {
    use crbs_core::config::{ProductConfig, RepoConfig};
    use crbs_core::BuildInsert;
    // assemble 写盘前要求 products 行存在，测试一并 seed；ON CONFLICT DO NOTHING
    // 双方言兼容（products.name 全局 UNIQUE 索引），seed 值满足 CHECK 约束。
    // config 须能通过 resolve 出口校验（空 base_packages/repos 会被拒）：
    // report_result / assemble 的签名策略解析走合并配置，空 config 会 fail-closed
    // 跳过 regen。这里用最小合法配置（未配 key = 不要求签名）。
    let config = ProductConfig {
        base_packages: vec!["bash".into()],
        repos: vec![RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            gpgcheck: false,
            ..Default::default()
        }],
        ..Default::default()
    };
    let config_json = serde_json::to_string(&config).unwrap();
    sqlx::query(
        "INSERT INTO products (name, visibility, config_json) VALUES ($1, 'public', $2) \
         ON CONFLICT (name) DO NOTHING",
    )
    .bind(PRODUCT)
    .bind(&config_json)
    .execute(state.state_store.pool())
    .await
    .unwrap();
    let result_dir = crbs_root.join("results").join("99").join(ARCH);
    tokio::fs::create_dir_all(result_dir.join("RPMS").join(ARCH))
        .await
        .unwrap();
    let rpm_path = result_dir.join("RPMS").join(ARCH).join(NEVRA);
    // 合法 RPM 字节：整树 staging + createrepo + 换位（engine::repo_publish）
    // 下 repodata 成功才有发布，假字节会令 createrepo 失败、整树不入位。
    tokio::fs::write(
        &rpm_path,
        include_bytes!("../src/server/replay/fixtures/replay_anchor.rpm"),
    )
    .await
    .unwrap();

    let build_id = state
        .state_store
        .insert_build(BuildInsert {
            product: PRODUCT,
            pkg_name: PKG,
            phase,
            result_dir: Some(result_dir.to_str().unwrap()),
            backend: "nspawn",
            user: "tester",
            arch: Some(ARCH),
            task_id: Some(
                crbs_server::test_support::seed_task(&state.state_store, PRODUCT, PKG).await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    // 与 regen 候选 SQL 匹配的 artifact 行（on_disk=1, kind=rpm, arch=x86_64）。
    let now = chrono::Utc::now()
        .format(crbs_core::util::DB_TIME_FMT)
        .to_string();
    let mut tx = state.state_store.pool().begin().await.unwrap();
    state
        .state_store
        .insert_artifacts_tx(
            &mut tx,
            build_id,
            &[NewArtifact {
                relative_path: format!("RPMS/{}/{}", ARCH, NEVRA),
                kind: ArtifactKind::Rpm,
                size_bytes: 20,
                sha256: "deadbeef".to_string(),
                unsigned_sha256: None,
                arch: Some(ARCH.to_string()),
                name: Some(PKG.to_string()),
                version: Some("1.0".to_string()),
                release: Some("1".to_string()),
                epoch: None,
                metadata_json: None,
                signed: false,
            }],
            &now,
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();

    build_id
}

async fn repo_rpm_exists(crbs_root: &Path) -> bool {
    let p = crbs_root
        .join("results")
        .join("_repo")
        .join(PRODUCT)
        .join(ARCH)
        .join("Packages")
        .join(NEVRA);
    tokio::fs::try_exists(&p).await.unwrap_or(false)
}

/// createrepo_c 是否可用。缺失时整树不入位（engine::repo_publish 语义），
/// succeeded 路径的硬链断言无法成立，用例跳过。
fn createrepo_available() -> bool {
    std::process::Command::new("createrepo_c")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn call_regen(app: &Arc<AppState>) -> RepoAssembleReport {
    // 用 `assemble_for_product`（返回 Result<Report>）而非内部吞错、签名 () 的
    // `regenerate_product_repo`，断言才有链接数 / 跳过数可看。整树 staging +
    // createrepo + 换位（engine::repo_publish）下任一失败都不发布（Err 时旧树
    // 原样），fixture 为合法 RPM、creatrepo_c 可用即整轮成功。
    match crbs_server::server::repo_regen::assemble_for_product(app, PRODUCT).await {
        Ok(report) => report,
        Err(e) => {
            eprintln!("note: assemble_for_product failed: {e}");
            RepoAssembleReport::default()
        }
    }
}

/// 产品声明签名策略：未签名构建不进发布 repo；签名后下一次 regen 正常收录。
#[tokio::test]
async fn signing_policy_excludes_unsigned_build_until_signed() {
    use crbs_core::config::{ProductConfig, RepoConfig};

    let (app, tmp) = setup().await;
    let build_id = seed_build_with_artifact(&app, tmp.path(), "succeeded").await;

    let config = ProductConfig {
        base_packages: vec!["bash".into()],
        repos: vec![RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            gpgcheck: false,
            ..Default::default()
        }],
        gpg_signing_key_id: Some("key@example.com".into()),
        ..Default::default()
    };
    let config_json = serde_json::to_string(&config).unwrap();
    sqlx::query("UPDATE products SET config_json = $1 WHERE name = $2")
        .bind(&config_json)
        .bind(PRODUCT)
        .execute(app.state_store.pool())
        .await
        .unwrap();

    let report = call_regen(&app).await;
    assert_eq!(
        report.linked, 0,
        "unsigned build must not be linked while the product requires signing"
    );
    assert!(!repo_rpm_exists(tmp.path()).await);

    if !createrepo_available() {
        eprintln!("skipping signed half: createrepo_c not available");
        return;
    }
    app.state_store
        .update_build_signed(build_id, true)
        .await
        .unwrap();
    let report = call_regen(&app).await;
    assert_eq!(report.linked, 1, "signed build must publish");
    assert!(repo_rpm_exists(tmp.path()).await);
}

/// phase='succeeded'：regen 看到候选 → _repo/.../Packages/...rpm 被硬链。
#[tokio::test]
async fn succeeded_phase_assembles_repo_with_artifact() {
    if !createrepo_available() {
        eprintln!(
            "skipping: createrepo_c not available; staged repo tree never lands \
             in place, the hardlink assertion cannot hold"
        );
        return;
    }
    let (app, tmp) = setup().await;
    let _build_id = seed_build_with_artifact(&app, tmp.path(), "succeeded").await;

    let report = call_regen(&app).await;
    assert_eq!(report.linked, 1, "succeeded candidate must be linked");
    assert!(
        repo_rpm_exists(tmp.path()).await,
        "hardlink should be in _repo"
    );
}

/// phase='building'：regen 0 候选 → _repo/.../Packages/...rpm 不存在；
/// 触发点若先于 phase 翻转即落此 case（linked=0、目录清空），兼作回归守卫。
#[tokio::test]
async fn building_phase_yields_no_candidates() {
    let (app, tmp) = setup().await;
    let _build_id = seed_build_with_artifact(&app, tmp.path(), "building").await;

    let report = call_regen(&app).await;
    assert_eq!(
        report.arches,
        Vec::<String>::new(),
        "no arch should be assembled"
    );
    assert_eq!(report.linked, 0, "no RPM should be linked");
    assert!(
        !repo_rpm_exists(tmp.path()).await,
        "_repo should not contain the RPM"
    );
}

/// phase='failed'：同 building，0 候选，不进 repo——失败 build 永不发布。
#[tokio::test]
async fn failed_phase_yields_no_candidates() {
    let (app, tmp) = setup().await;
    let _build_id = seed_build_with_artifact(&app, tmp.path(), "failed").await;

    let report = call_regen(&app).await;
    assert_eq!(report.arches, Vec::<String>::new());
    assert_eq!(report.linked, 0);
    assert!(!repo_rpm_exists(tmp.path()).await);
}

// HTTP 层回归：regen 触发 gate 必须用 `record.result_dir`（update_build_info 在
// upload 落盘时写入，Hub 端唯一可信来源），不能用 `req.result_dir`——真实 worker
// 上报 succeeded 时恒不带 result_dir，按 req 判断会静默跳过整段 regen。

/// 走真实 `report_result` HTTP 端点（body 仅 `{"phase":"succeeded"}`，不带
/// result_dir），断言 `_repo/ule3/x86_64/Packages/{NEVRA}` 被硬链。
#[tokio::test]
async fn report_result_with_null_result_dir_triggers_regen_via_record() {
    if !createrepo_available() {
        eprintln!(
            "skipping: createrepo_c not available; staged repo tree never lands \
             in place, the polling hardlink assertion cannot hold"
        );
        return;
    }
    let (app_state, tmp) = setup().await;
    let crbs_root = tmp.path().to_path_buf();

    // 1) seed pending build + artifact：result_dir 在 insert_build 阶段写入 DB
    //    （模拟 upload 的 update_build_info 终态）；assign_build_to_worker 推进到 assigned。
    let build_id = seed_build_with_artifact(&app_state, &crbs_root, "pending").await;

    // 2) 带认证 Router：operator token 注册 worker，worker secret 调 report_result。
    let app = create_test_app_with_auth(app_state.clone());
    let op_token = seed_user_token_for_test(&app_state.state_store, "test-operator", "operator")
        .await
        .unwrap();

    // 3) 注册 worker（operator token）→ worker_id + secret（report_result 的 Bearer）。
    let (worker_id, worker_secret) =
        register_worker(&app, &app_state, "r1b-w", "x86_64", &op_token).await;

    // 4) 分配 build → assignment_id（report_result URL 的 {assignment_id}，对应 worker_tasks.id）。
    let (assignment_id, _task_id) = app_state
        .state_store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();

    // 5) 上报 succeeded，body 只含 phase、不含 result_dir（模拟 worker 实际发包）。
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{}/assignments/{}/result",
                    worker_id, assignment_id
                ))
                .header("Authorization", format!("Bearer {}", worker_secret))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"phase": "succeeded"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "report_result should accept succeeded; body={}",
        String::from_utf8_lossy(&body)
    );

    // 6) 关键断言：_repo/.../Packages/...rpm 被硬链。regen 已 fire-and-forget 化
    //    （repo_regen.rs 内部 spawn，不阻塞调用方），硬链异步落地 → 轮询 + 超时上限防挂死。
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !repo_rpm_exists(&crbs_root).await {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(
        "R1b regen must fire from /result succeeded arm even when body has no \
         result_dir; trigger reads from build record (DB), not from request body",
    );
}

/// 注册 worker（operator 权限）并把 secret 经 `set_worker_secret` 注入 DB
/// （不走 HTTP），返回 (worker_id, secret_token)，供后续 Bearer 走 worker-secret
/// 解析路径。
async fn register_worker(
    app: &axum::Router,
    app_state: &Arc<AppState>,
    name: &str,
    arch: &str,
    op_token: &str,
) -> (i64, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/workers/register")
                .header("Authorization", format!("Bearer {}", op_token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "name": name,
                        "arch": arch,
                        "capacity": 1,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let worker_id = json["id"].as_i64().unwrap();

    let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
    app_state
        .state_store
        .set_worker_secret(worker_id, secret.hash().as_str())
        .await
        .unwrap();

    (worker_id, secret.as_str().to_string())
}
