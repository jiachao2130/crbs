// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! RPM %changelog 端点（build/task 作用域：实时解析、零持久化，无 schema 变更）。
//!
//! API `GET /api/v1/builds/{id}/changelog` 与 UI 页 `/ui/builds/{id}/changelog`、`/ui/tasks/{id}/changelog` 共用
//! [`changelog_for_build`] / [`changelog_for_task`]：可见性检查先于任何解析（build 对齐 download 口径、task 对齐
//! task 详情页），然后对选定源（SRPM 优先，回退首个在盘 rpm/srpm 行）实时执行 `rpm -qp --changelog` 并解析。
//! 全程 fail-soft：rpm 缺失 / 退出非零 / 解析空 / 磁盘文件不可达 → `available=false`（不落盘、不阻塞产物主链路）；
//! build 无在盘 rpm/srpm 行同样 fail-soft（空态页），task 的子构建全无 rpm/srpm 行 → 404。

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::Json;
use serde::Serialize;

use crbs_core::util::rpm_changelog::{parse_rpm_changelog, ChangelogEntry};

use crate::server::auth::visibility::ensure_product_visible_for_record;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

/// changelog 响应。API JSON 契约：`{"entries":[...],"available":bool}`；
/// `skip` 字段是 UI 页渲染上下文（文件名/NEVRA/来源构建），不进 JSON。
#[derive(Debug, Serialize)]
pub(crate) struct ChangelogResponse {
    /// 解析后的 entry 列表（fail-soft 时空 vec）。
    pub entries: Vec<ChangelogEntry>,
    /// false = fail-soft（rpm 缺失 / 退出非零 / 解析空 / 文件不可达）。
    pub available: bool,
    /// 解析源产物行的文件名（UI 页 h1；无 rpm/srpm 行时为空串）。
    #[serde(skip)]
    pub file_name: String,
    /// NEVRA 展示串（`name-version-release[.arch]`；列缺失时 None）。
    #[serde(skip)]
    pub nevra: Option<String>,
    /// 解析源所属构建 id（UI 页上下文；task 作用域 = 胜出子构建）。
    #[serde(skip)]
    pub build_id: Option<i64>,
}

/// 产物行 → 展示用 NEVRA（name-version-release[.arch]；任一核心列缺失返回 None）。
fn artifact_nevra(a: &crbs_core::Artifact) -> Option<String> {
    let (n, v, r) = (
        a.name.as_deref()?,
        a.version.as_deref()?,
        a.release.as_deref()?,
    );
    Some(match a.arch.as_deref().filter(|s| !s.is_empty()) {
        Some(arch) => format!("{n}-{v}-{r}.{arch}"),
        None => format!("{n}-{v}-{r}"),
    })
}

/// 任务子构建选择（纯函数，锁次序语义）：候选 `(build_id, 有在盘 srpm 行, 有在盘 rpm 行)` 按 build id 升序，
/// 第一个有 srpm 行的胜出（SRPM 优先），无则第一个有 rpm 行的，全无 None（调用方 404）。
fn pick_task_changelog_build(candidates: &[(i64, bool, bool)]) -> Option<i64> {
    candidates
        .iter()
        .find(|c| c.1)
        .or_else(|| candidates.iter().find(|c| c.2))
        .map(|c| c.0)
}

/// 定位解析源在磁盘上的绝对路径：`validate_result_dir` 起点约束 + `resolve_artifact_file` 防穿越解析
///（路径组件全部来自 DB 行，不来自用户输入）；任一环不可达 → None（调用方回退 / fail-soft）。
async fn resolve_source_file(
    result_dir: Option<&str>,
    relative_path: &str,
    result_root: &std::path::Path,
) -> Option<PathBuf> {
    let base = match crbs_core::util::validate_result_dir(result_dir?, result_root).await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(result_dir = %result_dir?, error = %e, "result_dir rejected; changelog source unresolved");
            return None;
        }
    };
    match super::download::resolve_artifact_file(&base, relative_path).await {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::debug!(relative_path = %relative_path, error = ?e, "artifact file unresolved; changelog source unreachable");
            None
        }
    }
}

/// 选定构建的解析尾链（[`changelog_for_build`] / [`changelog_for_task`] 共用）：SRPM 行在盘可达则解析之，
/// 否则回退首个在盘 rpm/srpm 行，都不可达 fail-soft；rpm 失败/解析空同样 fail-soft
///（保留所选行的 file_name/NEVRA/build_id 上下文，UI 页 h1 不因 fail-soft 丢失）。
async fn parse_build_changelog(
    app: &AppState,
    build_id: i64,
    product: &str,
    result_dir: Option<&str>,
) -> Result<ChangelogResponse, ApiError> {
    let srpm_row = app
        .state_store
        .find_srpm_for_build(build_id)
        .await
        .map_err(ApiError::from)?;
    let fallback_row = app
        .state_store
        .find_rpm_or_srpm_for_build(build_id)
        .await
        .map_err(ApiError::from)?;

    // UI 上下文行：SRPM 行优先，无则回退行；都缺（无在盘 rpm/srpm 行）空上下文。
    let context_row = srpm_row.as_ref().or(fallback_row.as_ref());
    let file_name = context_row
        .map(|a| {
            std::path::Path::new(&a.relative_path)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| a.relative_path.clone())
        })
        .unwrap_or_default();
    let nevra = context_row.and_then(artifact_nevra);
    let unavailable = || ChangelogResponse {
        entries: Vec::new(),
        available: false,
        file_name: file_name.clone(),
        nevra: nevra.clone(),
        build_id: Some(build_id),
    };

    let result_root = app.result_dir_for_or_default(product).await;
    let srpm_path = match &srpm_row {
        Some(row) => resolve_source_file(result_dir, &row.relative_path, &result_root).await,
        None => None,
    };
    let fallback_path = match &fallback_row {
        Some(row) => resolve_source_file(result_dir, &row.relative_path, &result_root).await,
        None => None,
    };

    // SRPM 优先（header 自带完整 %changelog，不依赖 binary rpm 在盘），
    // 缺失/不可达回退首个在盘行，都不可达 → fail-soft。
    let Some(path) = srpm_path.or(fallback_path) else {
        tracing::debug!(build_id = %build_id, "no changelog source file reachable; changelog unavailable");
        return Ok(unavailable());
    };

    // `rpm -qp --changelog`：Command::arg 传参（无 shell 拼接）；rpm 不在 PATH（io NotFound）→ fail-soft。
    // capped+timeout（32MB/60s）：巨型 %changelog 不占无界内存，停滞 rpm 不无限挂住端点 future；spawn 失败/超时同样 fail-soft。
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qp").arg("--changelog").arg(&path);
    let output = match crbs_core::engine::run_command_capped_output_with_timeout(
        cmd,
        "spawn rpm -qp --changelog",
        std::time::Duration::from_secs(60),
    )
    .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(build_id = %build_id, error = %e, "rpm not runnable or timed out; changelog unavailable");
            return Ok(unavailable());
        }
    };
    if !output.status.success() {
        tracing::debug!(build_id = %build_id, code = ?output.status.code(), "rpm -qp exited non-zero; changelog unavailable");
        return Ok(unavailable());
    }

    let entries = parse_rpm_changelog(&String::from_utf8_lossy(&output.stdout));
    if entries.is_empty() {
        tracing::debug!(build_id = %build_id, "empty changelog parse; changelog unavailable");
        return Ok(unavailable());
    }
    Ok(ChangelogResponse {
        entries,
        available: true,
        file_name,
        nevra,
        build_id: Some(build_id),
    })
}

/// build 作用域 changelog 查询 core（API 与 UI 页共用）：get_build → 404 → 可见性（对齐 download 口径：
/// 产品级可见性，worker 机器身份豁免）→ [`parse_build_changelog`]。
/// 选定源存在但解析失败是 fail-soft 空态，不是 404。
pub(crate) async fn changelog_for_build(
    app: &AppState,
    build_id: i64,
    auth: Option<&AuthContext>,
) -> Result<ChangelogResponse, ApiError> {
    let record = app
        .state_store
        .get_build(build_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", build_id))?;
    // worker 是机器身份（凭 worker secret 取件），不走用户产品 ACL，与 download 口径一致。
    if auth.is_none_or(|ctx| ctx.role != "worker") {
        ensure_product_visible_for_record(app, &record.product, auth).await?;
    }
    parse_build_changelog(app, build_id, &record.product, record.result_dir.as_deref()).await
}

/// task 作用域 changelog 查询 core（UI 页专用）：get_task → 404 → 可见性（对齐 task 详情页）→
/// 子构建批量取在盘 rpm/srpm 行（build id 升序）→ [`pick_task_changelog_build`] 选胜者（srpm 优先）→
/// 胜者走 [`parse_build_changelog`]。子构建全无在盘 rpm/srpm 行 → 404；选定源解析失败仍 fail-soft 空态。
pub(crate) async fn changelog_for_task(
    app: &AppState,
    task_id: i64,
    auth: Option<&AuthContext>,
) -> Result<ChangelogResponse, ApiError> {
    let task = app
        .state_store
        .get_task(task_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("task", task_id))?;
    ensure_product_visible_for_record(app, &task.product, auth).await?;

    let builds = app
        .state_store
        .get_child_build_summaries(task_id)
        .await
        .map_err(ApiError::from)?;
    let build_ids: Vec<i64> = builds.iter().map(|b| b.id).collect();
    let all_artifacts = app
        .state_store
        .list_artifacts_for_builds(&build_ids)
        .await
        .map_err(ApiError::from)?;

    // 候选 (build_id, has_srpm, has_rpm)：按 build_id 升序输入（升序返回 + last_mut 同构建合并），次序由纯函数锁定。
    let mut candidates: Vec<(i64, bool, bool)> = Vec::new();
    for a in &all_artifacts {
        let (is_srpm, is_rpm) = (
            matches!(a.kind, crbs_core::ArtifactKind::Srpm),
            matches!(a.kind, crbs_core::ArtifactKind::Rpm),
        );
        if !is_srpm && !is_rpm {
            continue;
        }
        match candidates.last_mut() {
            Some((id, srpm, rpm)) if *id == a.build_id => {
                *srpm |= is_srpm;
                *rpm |= is_rpm;
            }
            _ => candidates.push((a.build_id, is_srpm, is_rpm)),
        }
    }
    // 全无在盘 rpm/srpm 行 → 404（不泄漏"有但你不能看"；可见性已前置）。
    let Some(winner) = pick_task_changelog_build(&candidates) else {
        return Err(ApiError::not_found("task", task_id));
    };
    let record = app
        .state_store
        .get_build(winner)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("build", winner))?;
    parse_build_changelog(app, winner, &record.product, record.result_dir.as_deref()).await
}

/// `GET /api/v1/builds/{id}/changelog`（protected，可见性按调用方身份检查，对齐 builds 路由族）。
pub(crate) async fn changelog(
    State(app): State<Arc<AppState>>,
    AxumPath(build_id): AxumPath<i64>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<ChangelogResponse>, ApiError> {
    let resp = changelog_for_build(&app, build_id, auth.as_ref().map(|e| &e.0)).await?;
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use super::{changelog, changelog_for_build, changelog_for_task, pick_task_changelog_build};
    use crate::server::auth::AuthContext;
    use crate::server::error::ApiError;
    use crate::server::state::AppState;
    use crate::test_support::seed_task;
    use axum::extract::{Extension, Path as AxumPath, State};
    use axum::Json;
    use std::sync::Arc;

    const SHA: &str = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

    /// pick_task_changelog_build（锁次序语义）：srpm 子构建优先（跨构建亦胜出），无 srpm 回退首个 rpm 子构建，全无 → None。
    #[test]
    fn pick_task_changelog_build_prefers_srpm_then_first_rpm() {
        let candidates = [(1, false, true), (2, true, false)];
        assert_eq!(pick_task_changelog_build(&candidates), Some(2));

        assert_eq!(
            pick_task_changelog_build(&[(3, true, true), (4, true, false)]),
            Some(3)
        );

        assert_eq!(
            pick_task_changelog_build(&[(1, false, false), (2, false, true)]),
            Some(2)
        );

        assert_eq!(pick_task_changelog_build(&[(1, false, false)]), None);
        assert_eq!(pick_task_changelog_build(&[]), None);
    }

    /// 测试装配：公开产品 + 挂任务的 build（result_dir 在 results 根下真实目录）+ 一条 rpm artifact 行；返回 (app, build_id, tmp 守卫)。
    async fn setup_with_artifact() -> (Arc<AppState>, i64, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
        let app = Arc::new(AppState::for_test(
            store.clone(),
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));

        store
            .create_product(crbs_core::CreateProductInput {
                name: "openfed",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: crbs_core::VISIBILITY_PUBLIC,
                config: &crbs_core::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: None,
            })
            .await
            .unwrap();

        // result_root = crbs_root/results（for_test 的派生默认）；result_dir 必须落在其内，validate_result_dir 才放行。
        let build_results = tmp.path().join("results").join("build-1");
        std::fs::create_dir_all(build_results.join("RPMS/x86_64")).unwrap();
        std::fs::write(
            build_results.join("RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
            b"not a real rpm",
        )
        .unwrap();

        let task_id = seed_task(&store, "openfed", "hello").await;
        let build_id = store
            .insert_build(crbs_core::BuildInsert {
                product: "openfed",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                result_dir: Some(&build_results.to_string_lossy()),
                arch: Some("x86_64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();

        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                &[crbs_core::NewArtifact {
                    relative_path: "RPMS/x86_64/hello-1.0-1.x86_64.rpm".to_string(),
                    kind: crbs_core::ArtifactKind::Rpm,
                    size_bytes: 14,
                    sha256: SHA.to_string(),
                    unsigned_sha256: None,
                    arch: Some("x86_64".to_string()),
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                "2026-08-31 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        (app, build_id, tmp)
    }

    /// SRPM 行存在的装配：同构建再插 srpm 行、只写 SRPM 文件并移走 rpm 文件——回退链在此形下不出 500（选择逻辑由纯函数单测锁定）。
    async fn setup_with_srpm_row(app: &Arc<AppState>, build_id: i64, tmp: &tempfile::TempDir) {
        std::fs::create_dir_all(tmp.path().join("results/build-1/SRPMS")).unwrap();
        std::fs::write(
            tmp.path().join("results/build-1/SRPMS/hello-1.0-1.src.rpm"),
            b"not a real srpm",
        )
        .unwrap();
        std::fs::remove_file(
            tmp.path()
                .join("results/build-1/RPMS/x86_64/hello-1.0-1.x86_64.rpm"),
        )
        .unwrap();
        let mut tx = app.state_store.pool().begin().await.unwrap();
        app.state_store
            .insert_artifacts_tx(
                &mut tx,
                build_id,
                &[crbs_core::NewArtifact {
                    relative_path: "SRPMS/hello-1.0-1.src.rpm".to_string(),
                    kind: crbs_core::ArtifactKind::Srpm,
                    size_bytes: 15,
                    sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                    unsigned_sha256: None,
                    arch: None,
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                "2026-08-31 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn changelog_unknown_build_is_404() {
        let (app, _build_id, _tmp) = setup_with_artifact().await;
        let err = changelog_for_build(&app, 9999, None).await.unwrap_err();
        assert!(
            matches!(&err, ApiError::NotFound(msg) if msg.contains("build")),
            "unknown build must 404 mentioning build, got: {err:?}"
        );
    }

    /// fail-soft：macOS / 最小镜像无 rpm（io NotFound）或 Linux 上非 rpm 文件退出非零，
    /// 均 available=false（两种环境同一断言）；渲染上下文（file_name/build_id）仍来自回退行。
    #[tokio::test]
    async fn changelog_for_build_failsoft_when_rpm_unreadable() {
        let (app, build_id, _tmp) = setup_with_artifact().await;
        let resp = changelog_for_build(&app, build_id, None).await.unwrap();
        assert!(
            !resp.available,
            "missing rpm or non-rpm input must fail soft, got: {resp:?}"
        );
        assert!(resp.entries.is_empty());
        assert_eq!(resp.file_name, "hello-1.0-1.x86_64.rpm");
        assert_eq!(resp.build_id, Some(build_id));
    }

    /// SRPM 优先链集成形：同构建 srpm 行在、rpm 文件不放盘 → 走 SRPM 源（或不可达 fail-soft），绝不 500/404，上下文行是 SRPM。
    #[tokio::test]
    async fn changelog_for_build_srpm_row_preferred_keeps_failsoft_shape() {
        let (app, build_id, tmp) = setup_with_artifact().await;
        setup_with_srpm_row(&app, build_id, &tmp).await;
        let resp = changelog_for_build(&app, build_id, None).await.unwrap();
        assert!(
            !resp.available,
            "srpm source without rpm binary must fail soft, got: {resp:?}"
        );
        assert!(resp.entries.is_empty());
        assert_eq!(resp.file_name, "hello-1.0-1.src.rpm");
        assert_eq!(resp.build_id, Some(build_id));
    }

    /// build 无任何在盘 rpm/srpm 行（仅 log）→ fail-soft 空上下文，非 404。
    #[tokio::test]
    async fn changelog_for_build_without_rpm_rows_is_failsoft() {
        let (app, build_id, tmp) = setup_with_artifact().await;
        // GC：全部行翻 off-disk（等价于只剩 log 行的构建）。
        app.state_store
            .mark_artifacts_off_disk(build_id)
            .await
            .unwrap();
        let resp = changelog_for_build(&app, build_id, None).await.unwrap();
        assert!(!resp.available);
        assert_eq!(resp.file_name, "");
        assert_eq!(resp.build_id, Some(build_id));
        let _ = tmp; // 守卫存活至断言结束
    }

    /// handler 直调：JSON 契约字段齐备且无 cached 键（实时解析，不缓存任何结果）。
    #[tokio::test]
    async fn changelog_handler_json_contract_has_no_cached_key() {
        let (app, build_id, _tmp) = setup_with_artifact().await;

        let Json(resp) = changelog(
            State(app.clone()),
            AxumPath(build_id),
            Some(Extension(AuthContext {
                user: "op".into(),
                role: "operator".into(),
                ..Default::default()
            })),
        )
        .await
        .unwrap();
        assert!(!resp.available);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["entries"], serde_json::json!([]));
        assert_eq!(json["available"], serde_json::json!(false));
        assert!(
            json.get("cached").is_none(),
            "cached key must be gone after de-tabling: {json}"
        );
        assert!(json.get("file_name").is_none());
    }

    /// 不存在的 task → 404；存在但子构建全无在盘 rpm/srpm 行 → 同样 404。
    #[tokio::test]
    async fn changelog_for_task_is_404_without_rpm_children() {
        let (app, _build_id, _tmp) = setup_with_artifact().await;
        let err = changelog_for_task(&app, 9999, None).await.unwrap_err();
        assert!(matches!(&err, ApiError::NotFound(msg) if msg.contains("task")));

        let (app2, build_id2, _tmp2) = setup_with_artifact().await;
        app2.state_store
            .mark_artifacts_off_disk(build_id2)
            .await
            .unwrap();
        let record = app2
            .state_store
            .get_build(build_id2)
            .await
            .unwrap()
            .unwrap();
        let err = changelog_for_task(&app2, record.task_id.unwrap(), None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ApiError::NotFound(_)),
            "task without rpm/srpm children must 404, got: {err:?}"
        );
    }

    /// task 作用域集成形：单个 rpm 子构建 → 胜者 = 该构建，fail-soft 契约与 build 作用域一致（两种环境同一断言）。
    #[tokio::test]
    async fn changelog_for_task_picks_rpm_child_and_fails_soft() {
        let (app, build_id, _tmp) = setup_with_artifact().await;
        let record = app.state_store.get_build(build_id).await.unwrap().unwrap();
        let resp = changelog_for_task(&app, record.task_id.unwrap(), None)
            .await
            .unwrap();
        assert!(!resp.available);
        assert_eq!(resp.build_id, Some(build_id));
        assert_eq!(resp.file_name, "hello-1.0-1.x86_64.rpm");
    }

    /// task 作用域 SRPM 优先：两个子构建（rpm-only 在前、srpm-only 在后）→ srpm 子构建胜出（build id 更大也赢），上下文行是 SRPM。
    #[tokio::test]
    async fn changelog_for_task_prefers_srpm_child() {
        let (app, build_id, tmp) = setup_with_artifact().await;
        let store = app.state_store.clone();
        let record = store.get_build(build_id).await.unwrap().unwrap();
        let task_id = record.task_id.unwrap();

        // 第二个子构建：srpm-only（文件不落盘也可——上下文行来自 DB 行）。
        let build2 = store
            .insert_build(crbs_core::BuildInsert {
                product: "openfed",
                pkg_name: "hello",
                phase: "succeeded",
                backend: "chroot",
                result_dir: Some(&tmp.path().join("results/build-2").to_string_lossy()),
                arch: Some("aarch64"),
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        std::fs::create_dir_all(tmp.path().join("results/build-2/SRPMS")).unwrap();
        std::fs::write(
            tmp.path().join("results/build-2/SRPMS/hello-1.0-1.src.rpm"),
            b"not a real srpm",
        )
        .unwrap();
        let mut tx = store.pool().begin().await.unwrap();
        store
            .insert_artifacts_tx(
                &mut tx,
                build2,
                &[crbs_core::NewArtifact {
                    relative_path: "SRPMS/hello-1.0-1.src.rpm".to_string(),
                    kind: crbs_core::ArtifactKind::Srpm,
                    size_bytes: 15,
                    sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                    unsigned_sha256: None,
                    arch: None,
                    name: Some("hello".to_string()),
                    version: Some("1.0".to_string()),
                    release: Some("1".to_string()),
                    epoch: None,
                    metadata_json: None,
                    signed: false,
                }],
                "2026-08-31 00:00:00",
            )
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let resp = changelog_for_task(&app, task_id, None).await.unwrap();
        assert_eq!(resp.build_id, Some(build2), "srpm child must win: {resp:?}");
        assert_eq!(resp.file_name, "hello-1.0-1.src.rpm");
        assert!(!resp.available);
    }
}
