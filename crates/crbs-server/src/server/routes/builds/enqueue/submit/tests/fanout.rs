// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! fan-out 展开：架构裁决、子构建注入与部分失败补偿。

use super::common::*;
use super::*;

/// fan-out 部分展开补偿：双 arch 提交，第二 arch 的 set_build_request_info
/// 被注入的 SQLite 触发器 ABORT——第一 arch 已建成（pending）由补偿收口
/// cancelled，第二 arch 行已插入由 start_build 清理标 failed；全部子构建
/// 终态 {cancelled, failed} → task 聚合取 failed。触发器 WHEN 须带
/// NEW.phase='pending'（裸 arch 条件会连终态翻转 UPDATE 一并 ABORT）；
/// fan_out_builds 必须返回原始错误（Internal 500）；reproduce 同型不重测。
#[tokio::test]
async fn fan_out_partial_failure_cancels_created_children() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("foo-1.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    // 故障注入：aarch64 pending 行任意 UPDATE 必 ABORT（首个命中点 =
    // start_build 的 set_build_request_info）。
    sqlx::query(
        "CREATE TRIGGER fail_second_arch_pending_update BEFORE UPDATE ON builds \
         WHEN NEW.arch = 'aarch64' AND NEW.phase = 'pending' \
         BEGIN SELECT RAISE(ABORT, 'boom'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-fanout".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts: BuildOptions::default(),
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: false,
            // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, ApiError::Internal(_)),
        "must return the original start_build error, got: {err:?}"
    );

    sqlx::query("DROP TRIGGER fail_second_arch_pending_update")
        .execute(store.pool())
        .await
        .unwrap();

    // fan_out 返回 Err 不带回 task_id：本测试库只有这一个 task 行，直接查。
    let task_id: i64 = sqlx::query_scalar("SELECT id FROM tasks")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let children = store.get_builds_by_task_id(task_id).await.unwrap();
    assert_eq!(children.len(), 2, "both child build rows must exist");
    let phase_of = |arch: &str| {
        children
            .iter()
            .find(|c| c.arch.as_deref() == Some(arch))
            .unwrap_or_else(|| panic!("missing child build for arch {arch}"))
            .phase
            .clone()
    };
    assert_eq!(phase_of("x86_64"), "cancelled");
    assert_eq!(phase_of("aarch64"), "failed");
    assert_eq!(
        store.get_task(task_id).await.unwrap().unwrap().phase,
        "failed"
    );
}

/// 显示名口径 pin：source_names 兼任落盘文件名（带 .src.rpm 后缀），task 行
/// pkg_name/pkg_names 必须是剥后缀的裸 NEVR（split_nvr 的 release 列不受
/// 污染）；落盘文件保留后缀原名。
#[tokio::test]
async fn create_task_strips_src_rpm_suffix_from_display_names() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("hello-1.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    let args = FanOutArgs {
        product: "prod-display".to_string(),
        result_dir: tmp.path().join("results"),
        srpm_paths: vec![srpm],
        opts: BuildOptions::default(),
        arches: vec![],
        submit_user: "tester".to_string(),
        submit_user_id: None,
        allow_move: false,
        collapse_noarch: false,
        arch_explicit: false,
        // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
        skip_unsupported_arches: true,
        source_names: vec!["hello-1.0-1.src.rpm".to_string()],
        task_labels: Vec::new(),
    };
    let (task_id, _task_dir, source_srpms, _guard) =
        create_task(app.clone(), &args, "{}").await.unwrap();

    let task = store.get_task(task_id).await.unwrap().unwrap();
    assert_eq!(task.pkg_name, "hello-1.0-1");
    assert_eq!(task.pkg_names, vec!["hello-1.0-1".to_string()]);

    // insert_task 的 split_nvr 以显示名为源：release 列不带 .src.rpm。
    let release: String = sqlx::query_scalar("SELECT release FROM tasks WHERE id = ?")
        .bind(task_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(release, "1");

    assert_eq!(
        source_srpms[0].file_name().and_then(|n| n.to_str()),
        Some("hello-1.0-1.src.rpm"),
        "落盘文件名保留 .src.rpm 原值"
    );
}

/// 任务标签与任务行同事务落库：多标签全量可读回（读取按 key 排序）。
#[tokio::test]
async fn create_task_persists_task_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    let srpm = tmp.path().join("hello-1.0-1.src.rpm");
    tokio::fs::write(&srpm, b"srpm-bytes").await.unwrap();

    let labels = vec![
        (
            "git-repo".to_string(),
            "https://example.com/a.git".to_string(),
        ),
        ("git-commit".to_string(), "abc123".to_string()),
    ];
    let args = FanOutArgs {
        product: "prod-labels".to_string(),
        result_dir: tmp.path().join("results"),
        srpm_paths: vec![srpm],
        opts: BuildOptions::default(),
        arches: vec![],
        submit_user: "tester".to_string(),
        submit_user_id: None,
        allow_move: false,
        collapse_noarch: false,
        arch_explicit: false,
        skip_unsupported_arches: true,
        source_names: Vec::new(),
        task_labels: labels.clone(),
    };
    let (task_id, _task_dir, _source_srpms, _guard) = create_task(app, &args, "{}")
        .await
        .expect("task with labels should be created");

    let mut expected = labels.clone();
    expected.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(store.get_task_labels(task_id).await.unwrap(), expected);
}

/// 纯 noarch SRPM 经 fan_out_builds 注入 target=noarch（lead archnum=255
/// 与 worker 宿主架构解耦），普通 arch SRPM 不注入；需 rpmbuild 真实构造
/// SRPM，仅 Linux 有意义。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_injects_noarch_target_only_for_noarch_srpm() {
    let (app, tmp) = test_app_with_product("prod-noarch-target", Some("[\"x86_64\"]")).await;
    let noarch_srpm = build_named_srpm(&tmp, "pkgnoarch", Some("noarch"));
    let arch_srpm = build_named_srpm(&tmp, "pkgarch", None);

    let ids = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-noarch-target".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![noarch_srpm, arch_srpm],
            opts: BuildOptions::default(),
            arches: arches(&["x86_64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: false,
            // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap()
    .build_ids;
    assert_eq!(ids.len(), 2);

    for id in &ids {
        let (pkg_name, request_json): (String, String) =
            sqlx::query_as("SELECT pkg_name, request_json FROM builds WHERE id = ?")
                .bind(id)
                .fetch_one(app.state_store.pool())
                .await
                .unwrap();
        let opts: BuildOptions = serde_json::from_str(&request_json).unwrap();
        if pkg_name.starts_with("pkgnoarch") {
            assert_eq!(
                opts.target.as_deref(),
                Some("noarch"),
                "noarch SRPM must get --target noarch injected"
            );
        } else {
            assert_eq!(
                opts.target, None,
                "arch SRPM must not get a target injected"
            );
        }
    }
}

/// 纯 noarch SRPM 收敛：双架构产品 + 4 个纯 noarch SRPM → 恰好 4 个子
/// 构建（每 SRPM 一个），行级 arch 落语义值 "noarch"（UI/download 直接
/// 呈现 noarch；派发由领取谓词放行到任意 worker），target=noarch 注入
/// 不因收敛丢失。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_collapses_pure_noarch_srpm_to_single_build() {
    let (app, tmp) =
        test_app_with_product("prod-noarch-collapse", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpms = ["pkgnoarcha", "pkgnoarchb", "pkgnoarchc", "pkgnoarchd"]
        .map(|n| build_named_srpm(&tmp, n, Some("noarch")));

    let ids = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-noarch-collapse".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: srpms.to_vec(),
            opts: BuildOptions::default(),
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: false,
            // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap()
    .build_ids;
    assert_eq!(ids.len(), 4, "each pure-noarch SRPM builds exactly once");

    for id in &ids {
        let (arch, request_json): (String, String) =
            sqlx::query_as("SELECT arch, request_json FROM builds WHERE id = ?")
                .bind(id)
                .fetch_one(app.state_store.pool())
                .await
                .unwrap();
        assert_eq!(arch, "noarch", "collapsed build keeps the semantic arch");
        let opts: BuildOptions = serde_json::from_str(&request_json).unwrap();
        assert_eq!(
            opts.target.as_deref(),
            Some("noarch"),
            "collapsed build keeps the noarch target injection"
        );
    }
}

/// 放置契约下限物化：fan_out 全部子构建继承同一声明（req_min_* 落列
/// 逐位一致、request_json 携带原始声明串供 rebuild/reproduce 重放）。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_materializes_req_min_columns_for_all_children() {
    let (app, tmp) = test_app_with_product("prod-req-min", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpm = build_named_srpm(&tmp, "pkgreqmin", None);
    let opts: BuildOptions =
        serde_json::from_str(r#"{"min_mem": "4G", "min_disk": "2T", "min_ncpu": 8}"#).unwrap();

    let ids = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-req-min".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: true,
            arch_explicit: false,
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap()
    .build_ids;
    assert_eq!(ids.len(), 2, "one SRPM × two arches");

    for id in &ids {
        let (mem, ncpu, disk): (Option<i64>, Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT req_min_mem_kb, req_min_ncpu, req_min_disk_kb FROM builds WHERE id = ?",
        )
        .bind(id)
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
        assert_eq!(mem, Some(4 * 1024 * 1024), "min_mem 4G = 4 GiB in KB");
        assert_eq!(ncpu, Some(8));
        assert_eq!(
            disk,
            Some(2 * 1024 * 1024 * 1024),
            "min_disk 2T = 2 TiB in KB"
        );

        // request_json 保留原始声明串（rebuild/reproduce 反序列化重放源）。
        let request_json: String =
            sqlx::query_scalar("SELECT request_json FROM builds WHERE id = ?")
                .bind(id)
                .fetch_one(app.state_store.pool())
                .await
                .unwrap();
        let back: BuildOptions = serde_json::from_str(&request_json).unwrap();
        assert_eq!(back.min_mem.as_deref(), Some("4G"));
        assert_eq!(back.min_disk.as_deref(), Some("2T"));
        assert_eq!(back.min_ncpu, Some(8));
    }
}

/// 逃生门矩阵：产品 `noarch_per_arch = true`（互比探针形态）或调用方
/// collapse_noarch=false（rebuild 忠实还原）时，双架构扇出保持 4 个子
/// 构建——既有 cross-arch noarch 互比链路的数据来源不丢。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_noarch_escape_hatches_restore_multi_build() {
    let (app, tmp) =
        test_app_with_product("prod-noarch-perarch", Some("[\"x86_64\", \"aarch64\"]")).await;
    // 产品开关：恢复每架构构建（覆盖 test_app_with_product 的默认配置）。
    let flagged = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\narches = [\"x86_64\", \"aarch64\"]\n\
         noarch_per_arch = true\n\n[[repos]]\n\
         name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    update_test_product(&app, "prod-noarch-perarch", &flagged).await;
    // 各臂用不同包名：构建停留 pending，同 (product, pkg, arch) 再提交会撞
    // 活跃去重守卫（正确行为），换包名绕开、聚焦断言扇出形态。
    let srpm_flag = build_named_srpm(&tmp, "pkgnoarchflag", Some("noarch"));
    let srpm_rebuild = build_named_srpm(&tmp, "pkgnoarchrebuild", Some("noarch"));
    let srpm_plain = build_named_srpm(&tmp, "pkgnoarchplain", Some("noarch"));

    let run = |collapse: bool, srpm: std::path::PathBuf| {
        let app = app.clone();
        let result_dir = tmp.path().join("results");
        async move {
            fan_out_builds(
                app,
                FanOutArgs {
                    product: "prod-noarch-perarch".to_string(),
                    result_dir,
                    srpm_paths: vec![srpm],
                    opts: BuildOptions::default(),
                    arches: arches(&["x86_64", "aarch64"]),
                    submit_user: "tester".to_string(),
                    submit_user_id: None,
                    allow_move: false,
                    collapse_noarch: collapse,
                    arch_explicit: false,
                    // 既有夹具按跳过语义走预检（不拒绝），显式拒绝路径由专项测试覆盖。
                    skip_unsupported_arches: true,
                    source_names: Vec::new(),
                    task_labels: Vec::new(),
                },
            )
            .await
            .unwrap()
            .build_ids
            .len()
        }
    };
    // 产品开关打开：即使路径允许收敛也保持每架构各建。
    assert_eq!(run(true, srpm_flag).await, 2);
    // 开关保持 true，rebuild 语义（collapse=false）同样不收敛。
    assert_eq!(run(false, srpm_rebuild).await, 2);
    // 撤掉产品开关后 collapse=false 仍不收敛——锁定 rebuild 路径接线本身
    //（若实现忽略 args.collapse_noarch 只看产品开关，此臂会收敛成 1 而红）。
    let unflagged = crbs_core::config::ProductConfig::from_str(
        "base_packages = [\"bash\"]\narches = [\"x86_64\", \"aarch64\"]\n\n[[repos]]\n\
         name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\ngpgcheck = false\n",
    )
    .unwrap();
    update_test_product(&app, "prod-noarch-perarch", &unflagged).await;
    assert_eq!(run(false, srpm_plain).await, 2);
}

/// 提交期预检接线：部分不兼容的 SRPM（ExclusiveArch=x86_64）在 fan-out
/// 不为不兼容 arch 创建子构建——请求 [x86_64, aarch64] + skip 旗标开 →
/// 构建列表仅含 x86_64，outcome.skipped_arches 点名 aarch64 与约束来源。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_skips_incompatible_arches_for_constrained_srpm() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) =
        test_app_with_product("prod-arch-skip", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgskipexc",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &["x86_64"],
        exclude: &[],
    });

    let outcome = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-arch-skip".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts: BuildOptions::default(),
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap();

    assert_eq!(outcome.build_ids.len(), 1, "仅可构建 arch 建子构建");
    let (arch, request_json): (String, String) =
        sqlx::query_as("SELECT arch, request_json FROM builds WHERE id = ?")
            .bind(outcome.build_ids[0])
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
    assert_eq!(arch, "x86_64", "唯一子构建必须落在可构建 arch 上");
    let opts: BuildOptions = serde_json::from_str(&request_json).unwrap();
    assert_eq!(opts.arch.as_deref(), Some("x86_64"));

    assert_eq!(
        outcome.skipped_arches.len(),
        1,
        "{:?}",
        outcome.skipped_arches
    );
    assert!(
        outcome.skipped_arches[0].contains("pkgskipexc")
            && outcome.skipped_arches[0].contains("aarch64")
            && outcome.skipped_arches[0].contains("ExclusiveArch"),
        "skip 账目须点名包、arch 与约束来源: {:?}",
        outcome.skipped_arches
    );
}

/// 提交期预检接线：全部请求 arch 不兼容 → kept-empty 错误路径，fan-out
/// 拒绝（裁决矩阵由 plan_srpm_arches 单测覆盖，此处钉 `?` 传播）。预检
/// 先于 create_task：拒绝零副作用——无任务行（失败 tombstone 无从谈起）、
/// 无子构建行。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_rejects_when_no_requested_arch_is_buildable() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) =
        test_app_with_product("prod-arch-empty", Some("[\"aarch64\", \"riscv64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgnokeep",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &["x86_64"],
        exclude: &[],
    });

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-arch-empty".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts: BuildOptions::default(),
            arches: arches(&["aarch64", "riscv64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m) if m.contains("no requested architecture is buildable")),
        "kept-empty must reject as validation error, got: {err:?}"
    );

    // 预检先于 create_task：拒绝零副作用——无任务行、无子构建行。
    let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        task_count, 0,
        "kept-empty rejection must not create a task row"
    );
    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "kept-empty rejection must not create any child build"
    );
}

/// 显式 --arches 撞 spec 约束（部分兼容，非 kept-empty）：400 且零副作用——
/// 预检先于 create_task，无任务行（guard 失败 tombstone 无从谈起）、无子构建
/// 行、无任务结果目录；错误信封与旧时序同源（点名包、arch、约束来源与
/// --skip-unsupported-arches 指引）。拒绝语义（skip vs fail）属产品决策，
/// 此处只钉拒绝时点与副作用。
#[cfg(target_os = "linux")]
#[tokio::test]
async fn fan_out_explicit_unsupported_arch_rejection_leaves_no_side_effects() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) =
        test_app_with_product("prod-arch-explicit", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgexplicit",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &["x86_64"],
        exclude: &[],
    });
    let result_dir = tmp.path().join("results");

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-arch-explicit".to_string(),
            result_dir: result_dir.clone(),
            srpm_paths: vec![srpm],
            opts: BuildOptions::default(),
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: true,
            skip_unsupported_arches: false,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m)
            if m.contains("pkgexplicit")
                && m.contains("aarch64")
                && m.contains("ExclusiveArch")
                && m.contains("requested architecture not supported by spec")
                && m.contains("--skip-unsupported-arches")),
        "explicit unsupported arch must 400 naming pkg/arch/constraint and the skip flag, got: {err:?}"
    );

    // 拒绝零副作用：无任务行、无子构建行、无结果目录。
    let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        task_count, 0,
        "explicit unsupported-arch rejection must not create a task row"
    );
    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "explicit unsupported-arch rejection must not create any child build"
    );
    assert!(
        !result_dir.exists(),
        "explicit unsupported-arch rejection must not create the task result directory"
    );
}

/// --target 门：target 不在产品构建架构集合内时统一 400（unconstrained
/// spec 的错标产物与 constrained spec 的 late-fail 都是这条防线消灭的对象），
/// 报错点名 target、产品集合并引导 --arches。
#[tokio::test]
async fn fan_out_rejects_target_outside_product_arches() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) = test_app_with_product("prod-tgt-out", Some("[\"x86_64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgtgtout",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &[],
        exclude: &[],
    });
    let opts = BuildOptions {
        target: Some("aarch64".to_string()),
        ..Default::default()
    };

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-tgt-out".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: false,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m)
            if m.contains("aarch64") && m.contains("outside this product's build arches")
                && m.contains("--arches")),
        "out-of-family target must 400 naming target and hint --arches, got: {err:?}"
    );
}

/// --target 与 spec 约束冲突（精确匹配）：单 pin 无架构可跳，
/// --skip-unsupported-arches 压不住，恒 400；报错换 pin 专属文案
/// （不带 "adjust --arch"，与 pin 语义不打架）。预检先于 create_task：
/// 拒绝零副作用——无任务行、无子构建行。
#[tokio::test]
async fn fan_out_rejects_conflicting_target_even_with_skip_flag() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) = test_app_with_product("prod-tgt-conf", Some("[\"x86_64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgtgtconf",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &["aarch64"],
        exclude: &[],
    });
    let opts = BuildOptions {
        target: Some("x86_64".to_string()),
        ..Default::default()
    };

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-tgt-conf".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: true,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m)
            if m.contains("pkgtgtconf") && m.contains("not in ExclusiveArch")
                && m.contains("no requested architecture is buildable")
                && m.contains("--target x86_64 conflicts with the spec arch constraints")
                && m.contains("choose another --target or use --arches")
                && !m.contains("adjust --arch")),
        "conflicting target must 400 with pin-specific copy regardless of skip flag, got: {err:?}"
    );
    // 预检先于 create_task：拒绝零副作用——无任务行、无子构建行。
    let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        task_count, 0,
        "target conflict rejection must not create a task row"
    );
    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "target conflict rejection must not create any child build"
    );
}

/// 微架构变体 target 精确匹配拒绝：`ExclusiveArch: x86_64` 对
/// `--target x86_64_v3` 拒（rpm 4.18.2 实测字面裁决），且 target 不在
/// 产品构建架构集合内先被 --target 门 400——该门先于 create_task，
/// 拒绝零副作用（无任务行、无子构建行）。
#[tokio::test]
async fn fan_out_rejects_micro_variant_target() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) =
        test_app_with_product("prod-tgt-micro", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgtgtmicro",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &["x86_64"],
        exclude: &[],
    });
    let opts = BuildOptions {
        target: Some("x86_64_v3".to_string()),
        ..Default::default()
    };

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-tgt-micro".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: false,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m)
            if m.contains("x86_64_v3") && m.contains("outside this product's build arches")
                && m.contains("--arches")),
        "micro-variant target must 400 naming target and hint --arches, got: {err:?}"
    );
    // --target 门先于 create_task：拒绝零副作用——无任务行、无子构建行。
    let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        task_count, 0,
        "target gate rejection must not create a task row"
    );
    let build_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM builds")
        .fetch_one(app.state_store.pool())
        .await
        .unwrap();
    assert_eq!(
        build_count, 0,
        "target gate rejection must not create any child build"
    );
}

/// 显式 `--target noarch` 统一 400：noarch 不是可派发架构（解析层已把
/// noarch 请求映射为具体 arch），产品 arches 集合内永无 noarch。
#[tokio::test]
async fn fan_out_rejects_explicit_noarch_target() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) = test_app_with_product("prod-tgt-noarch", Some("[\"x86_64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgtgtnoarch",
        version: "1.0",
        release: "1",
        buildarch: Some("noarch"),
        build_requires: &[],
        exclusive: &[],
        exclude: &[],
    });
    let opts = BuildOptions {
        target: Some("noarch".to_string()),
        ..Default::default()
    };

    let err = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-tgt-noarch".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: false,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&err, ApiError::Validation(m)
            if m.contains("noarch") && m.contains("outside this product's build arches")),
        "explicit --target noarch must 400, got: {err:?}"
    );
}

/// --target 正常 pin（用户的常规用法，target 当普通 arch 用）：多架构
/// 产品上 pin aarch64 收敛为单子构建（arch=aarch64），target 原样保留
/// 进子构建 options，不产出跳过账目。
#[tokio::test]
async fn fan_out_pinned_target_builds_single_child() {
    if !crbs_core::test_support::rpm_spawnable() || !crbs_core::test_support::rpmbuild_spawnable() {
        eprintln!("skipping: rpm/rpmbuild not available");
        return;
    }
    let (app, tmp) =
        test_app_with_product("prod-tgt-single", Some("[\"x86_64\", \"aarch64\"]")).await;
    let srpm = crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name: "pkgtgtsingle",
        version: "1.0",
        release: "1",
        buildarch: None,
        build_requires: &[],
        exclusive: &[],
        exclude: &[],
    });
    let opts = BuildOptions {
        target: Some("aarch64".to_string()),
        ..Default::default()
    };

    let outcome = fan_out_builds(
        app.clone(),
        FanOutArgs {
            product: "prod-tgt-single".to_string(),
            result_dir: tmp.path().join("results"),
            srpm_paths: vec![srpm],
            opts,
            arches: arches(&["x86_64", "aarch64"]),
            submit_user: "tester".to_string(),
            submit_user_id: None,
            allow_move: false,
            collapse_noarch: false,
            arch_explicit: false,
            skip_unsupported_arches: false,
            source_names: Vec::new(),
            task_labels: Vec::new(),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        outcome.build_ids.len(),
        1,
        "target pin 必须把 fan-out 收敛到 target 单构建"
    );
    let (arch, request_json): (String, String) =
        sqlx::query_as("SELECT arch, request_json FROM builds WHERE id = ?")
            .bind(outcome.build_ids[0])
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
    assert_eq!(arch, "aarch64");
    let child_opts: BuildOptions = serde_json::from_str(&request_json).unwrap();
    assert_eq!(child_opts.arch.as_deref(), Some("aarch64"));
    assert_eq!(
        child_opts.target.as_deref(),
        Some("aarch64"),
        "target pin 必须原样保留进子构建 options"
    );
    assert!(
        outcome.skipped_arches.is_empty(),
        "pin 不产出跳过账目: {:?}",
        outcome.skipped_arches
    );
}
