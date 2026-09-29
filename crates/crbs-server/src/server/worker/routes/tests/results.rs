// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! Worker API 测试：构建结果上报与终态处理。

use super::common::*;
use super::*;

use super::super::results::{sanitize_resources, ResourceUsagePayload, ResultRequest};
/// 资源上报解析矩阵：缺 resources / 显式 null → None；未知键忽略；
/// 三值就位经 sanitize 保留；扩展五字段（就位 / 缺省 / 非法口径与
/// 越界降 None）。
#[test]
fn result_request_resources_serde_matrix() {
    let old: ResultRequest = serde_json::from_str(r#"{"phase":"succeeded"}"#).unwrap();
    assert!(old.resources.is_none());

    let new: ResultRequest = serde_json::from_str(
        r#"{"phase":"succeeded","future_key":1,"resources":{"peak_rss_kb":2621440,"cpu_secs":42.5,"cpu_p90_cores":3.7}}"#,
    )
    .unwrap();
    let r = new.resources.expect("resources must parse");
    assert_eq!(r.peak_rss_kb, Some(2_621_440));
    assert_eq!(r.cpu_secs, Some(42.5));
    assert_eq!(r.cpu_p90_cores, Some(3.7));
    assert_eq!(r.peak_total_kb, None, "扩展字段缺省 → None");
    assert_eq!(r.disk_wbytes, None);
    assert_eq!(r.oom_killed, None);
    assert_eq!(r.sample_backend, None);
    assert_eq!(r.sample_ncpu, None);
    assert_eq!(r.peak_tmpfs_kb, None, "扩展字段缺省 → None");

    let nulls: ResultRequest =
        serde_json::from_str(r#"{"phase":"failed","resources":null}"#).unwrap();
    assert!(nulls.resources.is_none());
    let partial: ResultRequest =
        serde_json::from_str(r#"{"phase":"failed","resources":{"peak_rss_kb":1024}}"#).unwrap();
    let r = partial.resources.expect("partial resources must parse");
    assert_eq!(r.peak_rss_kb, Some(1024));
    assert_eq!(r.cpu_secs, None);
    assert_eq!(r.cpu_p90_cores, None);

    // 扩展五字段就位（采集形态）。
    let extended: ResultRequest = serde_json::from_str(
        r#"{"phase":"failed","resources":{"peak_total_kb":524288,"disk_wbytes":1236,
           "oom_killed":true,"sample_backend":"cgroup","sample_ncpu":8}}"#,
    )
    .unwrap();
    let r = extended.resources.expect("extended resources must parse");
    assert_eq!(r.peak_total_kb, Some(524_288));
    assert_eq!(r.disk_wbytes, Some(1236));
    assert_eq!(r.oom_killed, Some(true));
    assert_eq!(r.sample_backend.as_deref(), Some("cgroup"));
    assert_eq!(r.sample_ncpu, Some(8));

    // tmpfs 峰值字段：缺省 → None、就位照常解析。
    let tmpfs: ResultRequest = serde_json::from_str(
        r#"{"phase":"succeeded","resources":{"peak_rss_kb":1024,"peak_tmpfs_kb":65536}}"#,
    )
    .unwrap();
    let r = tmpfs.resources.expect("resources must parse");
    assert_eq!(r.peak_tmpfs_kb, Some(65_536));

    // sanitize：负值 / NaN / 超界一律 NULL，全空 → 整体 None（NaN 无法
    // 经合法 JSON 到达，直接构造结构体验证过滤面）。
    let bad = ResourceUsagePayload {
        peak_rss_kb: Some(-1),
        cpu_secs: Some(f64::NAN),
        cpu_p90_cores: Some(1e12),
        ..Default::default()
    };
    assert_eq!(sanitize_resources(Some(&bad)), None);

    let over: ResultRequest =
        serde_json::from_str(r#"{"phase":"succeeded","resources":{"peak_rss_kb":1000000001}}"#)
            .unwrap();
    assert_eq!(sanitize_resources(over.resources.as_ref()), None);

    let mixed: ResultRequest = serde_json::from_str(
        r#"{"phase":"succeeded","resources":{"peak_rss_kb":2048,"cpu_secs":-3.0}}"#,
    )
    .unwrap();
    let sanitized = sanitize_resources(mixed.resources.as_ref()).unwrap();
    assert_eq!(sanitized.peak_rss_kb, Some(2048));
    assert_eq!(sanitized.cpu_secs, None);
    assert_eq!(sanitized.cpu_p90_cores, None);

    // 新字段过滤面：peak_total_kb / disk_wbytes / sample_ncpu 越界降 None、
    // sample_backend 白名单外降 None；oom_killed 直通；仅 oom_killed 有效
    // 时整体保留（口径可用性证据不与三值绑定）。
    let bad_new = ResourceUsagePayload {
        peak_rss_kb: None,
        cpu_secs: None,
        cpu_p90_cores: None,
        oom_killed: Some(false),
        peak_total_kb: Some(-5),
        disk_wbytes: Some(-1),
        sample_backend: Some("bogus".into()),
        sample_ncpu: Some(0),
        peak_tmpfs_kb: None,
    };
    let s = sanitize_resources(Some(&bad_new)).expect("oom_killed keeps the row");
    assert_eq!(s.oom_killed, Some(false));
    assert_eq!(s.peak_total_kb, None);
    assert_eq!(s.disk_wbytes, None);
    assert_eq!(s.sample_backend, None);
    assert_eq!(s.sample_ncpu, None);

    let over_new: ResultRequest = serde_json::from_str(
        r#"{"phase":"failed","resources":{"peak_total_kb":1000000001,"disk_wbytes":1000000000000001,"sample_ncpu":99999}}"#,
    )
    .unwrap();
    assert_eq!(sanitize_resources(over_new.resources.as_ref()), None);

    // peak_tmpfs_kb 界值：负值与超 512 GiB（512×1024×1024 KB）降 None，
    // 界内保留；仅 tmpfs 值有效时整体同样保留。
    let over_tmpfs: ResultRequest = serde_json::from_str(
        r#"{"phase":"succeeded","resources":{"peak_rss_kb":1024,"peak_tmpfs_kb":536870913}}"#,
    )
    .unwrap();
    let s = sanitize_resources(over_tmpfs.resources.as_ref()).unwrap();
    assert_eq!(s.peak_rss_kb, Some(1024));
    assert_eq!(s.peak_tmpfs_kb, None, "超 512 GiB 界必须降 None");

    let tmpfs_only = ResourceUsagePayload {
        peak_tmpfs_kb: Some(-1),
        ..Default::default()
    };
    assert_eq!(
        sanitize_resources(Some(&tmpfs_only)),
        None,
        "负值非法，全空 → None"
    );

    let tmpfs_ok = ResourceUsagePayload {
        peak_tmpfs_kb: Some(512 * 1024 * 1024),
        ..Default::default()
    };
    let s = sanitize_resources(Some(&tmpfs_ok)).expect("界内峰值整体保留");
    assert_eq!(s.peak_tmpfs_kb, Some(512 * 1024 * 1024));
}

/// 终态（本上报翻转）定点失效包资源画像缓存：report 后 lookup → None，
/// 下次派发回源，EMA 立即见新样本（不等 5min TTL）。
#[tokio::test]
async fn report_result_terminal_invalidates_resource_weight_cache() {
    let (app, app_state, token, assignment_id, _build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;

    let stale = crate::server::scheduler::ResolvedResourceProfile {
        weight: crate::server::scheduler::PackageResourceWeight {
            peak_rss_kb: Some(1024.0),
            cpu_p90_cores: Some(1.0),
            cpu_sample_ncpu: None,
        },
        censored: false,
        ..crate::server::scheduler::ResolvedResourceProfile::default()
    };
    app_state
        .resource_weight_cache
        .fill(&("fedora".into(), "hello".into(), "x86_64".into()), stale);
    assert_eq!(
        app_state
            .resource_weight_cache
            .lookup("fedora", "hello", "x86_64"),
        Some(stale)
    );

    report_terminal(&app, &token, assignment_id).await;

    assert_eq!(
        app_state
            .resource_weight_cache
            .lookup("fedora", "hello", "x86_64"),
        None,
        "terminal hook must invalidate the (product, pkg, arch) weight cache entry"
    );
}

#[tokio::test]
async fn report_result_terminal_evicts_log_buffer_when_log_persisted() {
    let (app, app_state, token, assignment_id, build_id, tmp) =
        setup_worker_build_with_streamed_log().await;

    // 模拟产物上传后的落盘状态（update_build_info 同款路径）。
    let log_dir = tmp.path().join("results").join("persisted");
    tokio::fs::create_dir_all(&log_dir).await.unwrap();
    tokio::fs::write(log_dir.join("build.log"), "hello build")
        .await
        .unwrap();
    app_state
        .state_store
        .update_build_info(build_id, Some(log_dir.to_str().unwrap()), None, "")
        .await
        .unwrap();

    report_terminal(&app, &token, assignment_id).await;

    // 终态后 has=false：读取端回落落盘 build.log，缓冲内存释放（核心断言）。
    assert!(!app_state.log_buffer.has(build_id));
}

#[tokio::test]
async fn report_result_terminal_keeps_buffer_without_persisted_log() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;

    // durable 副本也是 resolve 候选：构造"真无落盘回退"须移除双写副本
    //（模拟结果 GC 清理后形态）——驱逐会把实时缓冲降级 404，必须保留。
    let artifact_log = app_state
        .artifact_dir()
        .join(build_id.to_string())
        .join("build.log");
    assert!(
        tokio::fs::try_exists(&artifact_log).await.unwrap(),
        "setup 的 report_logs 应已双写出 durable 副本"
    );
    tokio::fs::remove_file(&artifact_log).await.unwrap();

    report_terminal(&app, &token, assignment_id).await;

    assert!(app_state.log_buffer.has(build_id));
}

/// 软告警备注通道：成功上报 notes → append 进 error_summary；不带
/// notes 不改动；终态后重复上报 409（不双写）。
#[tokio::test]
async fn report_result_success_notes_appended_to_error_summary() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;

    let report = |phase: &str, notes: Option<&str>| {
        let body = match notes {
            Some(n) => format!(r#"{{"phase":"{phase}","notes":{}}}"#, serde_json::json!(n)),
            None => format!(r#"{{"phase":"{phase}"}}"#),
        };
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
    };

    let response = report(
        "succeeded",
        Some("warning: SOURCE_DATE_EPOCH in the future"),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let record = app_state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.phase, "succeeded");
    assert!(
        record
            .error_summary
            .as_deref()
            .unwrap_or("")
            .contains("SOURCE_DATE_EPOCH in the future"),
        "notes must land in hub error_summary, got: {:?}",
        record.error_summary
    );

    let response = report("succeeded", Some("warning: duplicate"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let record = app_state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !record
            .error_summary
            .as_deref()
            .unwrap_or("")
            .contains("duplicate"),
        "late report must not double-append notes"
    );
}

/// 回归："上传失败仍报 succeeded 且携带 error 标记"——标记必须落
/// error_summary（COALESCE 保留），UI 对非 failed 构建以 warnings/notes
/// 渲染，否则"成功但无产物"不可见。钉住该不变量；同报 notes 照常 append。
#[tokio::test]
async fn report_result_upload_failure_marker_lands_in_error_summary() {
    let (app, app_state, token, assignment_id, build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"phase":"succeeded","error":"artifact upload failed; artifacts must be fetched from the worker","notes":"warning: soft note"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let record = app_state
        .state_store
        .get_build(build_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.phase, "succeeded");
    let summary = record.error_summary.as_deref().unwrap_or("");
    assert!(
        summary.contains("artifact upload failed"),
        "upload-failure marker must be visible in error_summary, got: {summary:?}"
    );
    assert!(
        summary.contains("warning: soft note"),
        "notes still append on top of the marker, got: {summary:?}"
    );
}

/// 终态 assignment 的结果上报 409（先到者生效；worker 重试层映射为成功）。
#[tokio::test]
async fn report_result_returns_conflict_for_terminal_assignment() {
    let (app, _app_state, token, assignment_id, _build_id, _tmp) =
        setup_worker_build_with_streamed_log().await;
    report_terminal(&app, &token, assignment_id).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/1/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"succeeded"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// cancel×终态上报竞态：取消路径在守卫提交点前完整落账（build + wt 均
/// cancelled）时，守卫 0 行拒绝迟到上报，不得把 wt 的 cancelled 覆写成
/// completed。
///
/// 注入：BEFORE UPDATE 触发器（RAISE(IGNORE) 让外层 0 行）在提交点模拟
/// 取消赢者——入口 409 检查看不到该交错（wt 仍 running），必须提交点注入
/// 而非预先落终态。仅 SQLite 形态；PG 腿由 crbs-core builds.rs
/// `complete_build_guarded_rejects_revoked_assignment` 双方言覆盖。
#[tokio::test]
async fn report_result_cancel_race_preserves_worker_task_cancelled() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app_state = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    let app = create_test_app_with_auth(app_state.clone());
    let (worker_id, token) = seed_worker_secret_for_test(&store, "w-cancel-race", "x86_64")
        .await
        .unwrap();

    let build_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crate::test_support::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let (assignment_id, _) = store
        .assign_build_to_worker(build_id, worker_id)
        .await
        .unwrap();
    // 竞态前提：worker 已 claim（running），与真实取消交叠现场一致。
    store
        .update_worker_task_status(assignment_id, "running")
        .await
        .unwrap();

    sqlx::query(
        "CREATE TRIGGER simulate_cancel_wins BEFORE UPDATE ON builds \
         WHEN NEW.phase = 'succeeded' \
         BEGIN \
             UPDATE builds SET phase = 'cancelled', completed_at = CURRENT_TIMESTAMP \
                 WHERE id = NEW.id; \
             UPDATE worker_tasks SET status = 'cancelled', completed_at = CURRENT_TIMESTAMP \
                 WHERE build_id = NEW.id; \
             SELECT RAISE(IGNORE); \
         END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{worker_id}/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"succeeded"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // 迟到上报非 500（语义：留痕丢弃）。
    assert_eq!(response.status(), StatusCode::OK);

    // build 终态保持取消先到者。
    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.phase, "cancelled");

    // 核心断言：wt 不被覆写成 completed，保持取消路径写的 cancelled。
    let (_, _, _, wt_status) = store.get_worker_task_meta(assignment_id).await.unwrap();
    assert_eq!(
        wt_status.as_deref(),
        Some("cancelled"),
        "late report must not overwrite cancel-path worker_task status"
    );
}

/// 活跃 assignment 收 phase=cancelled 上报：build 翻 cancelled，wt 按纯
/// 生命周期词汇映射 cancelled（释放调度容量）。
#[tokio::test]
async fn report_result_cancelled_phase_lands_build_and_worker_task_cancelled() {
    let (app, store, token, worker_id, assignment_id, build_id, _tmp) =
        setup_worker_build("w-cancel-report").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{worker_id}/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"cancelled"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.phase, "cancelled");
    let (_, _, _, wt_status) = store.get_worker_task_meta(assignment_id).await.unwrap();
    assert_eq!(wt_status.as_deref(), Some("cancelled"));
}

/// build 预翻 cancelled 后 succeeded 迟到上报走 preserve 臂：build 不被
/// 覆写，wt 收尾 cancelled（释放调度容量）。
#[tokio::test]
async fn report_result_after_cancel_preserves_build_and_marks_worker_task_cancelled() {
    let (app, store, token, worker_id, assignment_id, build_id, _tmp) =
        setup_worker_build("w-preserve-report").await;

    // 取消先到但故意不写 worker_tasks——preserve 臂的 wt 收尾正是被测行为。
    store.mark_build_cancelled(build_id).await.unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/workers/{worker_id}/assignments/{assignment_id}/result"
                ))
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"phase":"succeeded"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // preserve 臂不写 build，仍 200（取消语义对 worker 透明）。
    assert_eq!(response.status(), StatusCode::OK);

    let record = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(record.phase, "cancelled");
    let (_, _, _, wt_status) = store.get_worker_task_meta(assignment_id).await.unwrap();
    assert_eq!(wt_status.as_deref(), Some("cancelled"));
}
