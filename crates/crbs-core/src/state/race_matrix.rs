// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 方言无关的并发竞态实证矩阵：把"推理级并发正确性"落成可执行断言。
//! 场景（同名创建 / revision 并发更新 / unpublish 竞态 / 指定派发不重复）在双后端运行：
//! SQLite（WAL + `BEGIN IMMEDIATE` + busy_timeout）/ PostgreSQL（READ COMMITTED + 行锁 + 唯一索引）；
//! `CRBS_TEST_DATABASE_URL` 驱动，未配置时只跑 SQLite 腿；并发均由测试内 tokio 多线程制造，PG `--test-threads=1` 兼容。
//! busy 归类：SQLite 写锁等待超 busy_timeout（5s）以 [`CrbsError::DatabaseUnavailable`]
//! （"database is locked" 文案 → 503 transient 族，`is_transient()` 为真）浮出，属"未赢得竞争"而非缺陷，
//! 与 Conflict / AlreadyExists / RevisionConflict 并列为非赢家侧合法落败，不当 panic 处理。

use super::BuildInsert;
use crate::error::CrbsError;
use crate::state::products::{CreateProductInput, VISIBILITY_PRIVATE, VISIBILITY_PUBLIC};
use crate::state::test_state::{create_test_store, seed_task};
use std::sync::Arc;

/// 并发任务数：双方言下稳定制造竞争窗口，不超默认连接池（8 连接）与 SQLite busy_timeout 承受范围。
const RACE_N: usize = 8;

fn race_config(marker: &str) -> crate::config::ProductConfig {
    crate::config::ProductConfig {
        base_packages: vec![marker.to_string()],
        ..Default::default()
    }
}

fn official_input<'a>(
    name: &'a str,
    cfg: &'a crate::config::ProductConfig,
) -> CreateProductInput<'a> {
    CreateProductInput {
        name,
        display_name: None,
        owner_id: None,
        parent_id: None,
        visibility: VISIBILITY_PUBLIC,
        config: cfg,
        changed_by_user_id: None,
        reason: None,
    }
}

/// 同名创建非赢家侧合法落败：`AlreadyExists`（锁内先查后插命中，或唯一索引兜底经
/// `classify_insert_product_error` 归一）、裸唯一键违反文本（分类遗漏防线，等价 409）、transient（见模块注释）。
fn assert_same_name_loser(err: &CrbsError) {
    let legal = matches!(err, CrbsError::AlreadyExists { .. })
        || crate::error::is_unique_violation(err)
        || err.is_transient();
    assert!(legal, "illegal loser error for same-name create: {err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_same_name_product_create_admits_exactly_one() {
    // 不变量：同名并发创建，唯一命名空间（begin_write 锁内先查后插 + products.name 唯一
    // 索引兜底）恰放行一个；败方 409 族或 transient busy；终态该名恰一行且 revision=1。
    let (store, _tmp) = create_test_store().await;
    let store = Arc::new(store);
    let barrier = Arc::new(tokio::sync::Barrier::new(RACE_N));

    let mut handles = Vec::new();
    for _ in 0..RACE_N {
        let store = store.clone();
        let barrier = barrier.clone();
        let cfg = race_config("race-dup-marker");
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            store.create_product(official_input("race-dup", &cfg)).await
        }));
    }

    let mut winners = Vec::new();
    for h in handles {
        match h.await.unwrap() {
            Ok(id) => winners.push(id),
            Err(e) => assert_same_name_loser(&e),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent creator must win, got {winners:?}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM products WHERE name = $1")
        .bind("race-dup")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "the winning name must end up with exactly one row");

    let rec = store
        .get_product_by_name("race-dup")
        .await
        .unwrap()
        .expect("winning row must be readable");
    assert_eq!(rec.id, winners[0]);
    assert_eq!(rec.revision, 1, "creation leaves revision at baseline 1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn race_config_update_same_expected_revision_single_winner() {
    // 不变量：两写者以同一 expected_revision=1 并发提交不同 config，乐观锁恰放行一个
    //（revision 单调 +1 → 2），败方 RevisionConflict { expected: 1, current: 2 } 或
    // transient busy；终态 revision=2、config 与赢家严格一致、history 恰两行，无丢失
    // 更新、无双双成功。SQLite 腿验证 BEGIN IMMEDIATE 串行化（败方锁内快照检查即失败）；
    // PG 腿验证 `AND revision = old_rev` 谓词（快照过期 0 行 → 回读转 RevisionConflict）。
    let (store, _tmp) = create_test_store().await;
    let store = Arc::new(store);
    let seed_cfg = race_config("seed-marker");
    let id = store
        .create_product(official_input("race-rev", &seed_cfg))
        .await
        .unwrap();
    assert_eq!(
        store.get_product_by_id(id).await.unwrap().unwrap().revision,
        1,
        "fixture baseline"
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for marker in ["marker-a", "marker-b"] {
        let store = store.clone();
        let barrier = barrier.clone();
        let cfg = race_config(marker);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = store
                .update_product_config(id, &cfg, None, None, Some(1))
                .await;
            (marker, outcome)
        }));
    }

    let mut winner_pkgs: Option<Vec<String>> = None;
    for h in handles {
        let (marker, outcome) = h.await.unwrap();
        match outcome {
            Ok(won) => {
                assert!(
                    winner_pkgs.is_none(),
                    "at most one writer may win against the same baseline"
                );
                assert_eq!(won.revision, 2, "winner revision must be baseline+1");
                winner_pkgs = Some(vec![marker.to_string()]);
            }
            Err(e) => {
                let legal = match &e {
                    CrbsError::RevisionConflict { expected, current } => {
                        *expected == 1 && *current == 2
                    }
                    _ => e.is_transient(),
                };
                assert!(legal, "illegal loser error for revision race: {e:?}");
            }
        }
    }
    let winner_pkgs = winner_pkgs.expect("at least one writer must win");

    let rec = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(rec.revision, 2, "revision must be monotonic baseline+1");
    assert_eq!(
        rec.config.base_packages, winner_pkgs,
        "final config must be exactly the winner's"
    );

    let revs: Vec<i64> = sqlx::query_scalar(
        "SELECT revision FROM product_config_history \
         WHERE product_id = $1 ORDER BY revision",
    )
    .bind(id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        revs,
        vec![1, 2],
        "history must hold exactly baseline+winner"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn race_unpublish_vs_config_update_single_writer_consistent() {
    // 不变量：已发布产品上 unpublish（visibility 翻转）与 config 更新同 expected_revision=1 并发，
    // 终态单写者一致：恰一操作生效、revision 恒=基线+1、visibility / config / pending 构建
    // 取消各自与赢家严格一致。败方错误方言差异：SQLite（BEGIN IMMEDIATE 串行化）败方在
    // expected_revision 快照检查即 RevisionConflict，history 主键兜底结构性不可达；
    // PG（READ COMMITTED）下 unpublish 的 visibility UPDATE 只按 id 谓词（无
    // `AND revision` 防线），快照早于 config 提交时原地重写 revision 为同值推进到
    // history 插入，被 product_config_history (product_id, revision) 主键以唯一键违反
    // 拒收、事务回滚——败方错误是 Database(唯一键违反) 而非 RevisionConflict；
    // 双双生效仍不可能（同 rev=2 history 行主键只容一行）。
    let (store, _tmp) = create_test_store().await;
    let store = Arc::new(store);
    // 夹具必须是有主产品：官方产品（owner NULL）被 schema CHECK（owner_id IS NOT NULL
    // OR visibility = 'public'）钉死 public；unpublish 只对用户自有产品有意义（生产口径先 transfer 再 unpublish）。
    sqlx::query("INSERT INTO users (name, role) VALUES ('race-owner', 'operator')")
        .execute(store.pool())
        .await
        .unwrap();
    let owner_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE name = 'race-owner'")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let seed_cfg = race_config("seed-marker");
    let id = store
        .create_product(CreateProductInput {
            name: "race-pub",
            display_name: None,
            owner_id: Some(owner_id),
            parent_id: None,
            visibility: VISIBILITY_PUBLIC,
            config: &seed_cfg,
            changed_by_user_id: None,
            reason: None,
        })
        .await
        .unwrap();

    // 挂一条 pending 构建：unpublish 赢须同事务取消、config 赢须原样保留（撕裂检测的第二读数）。
    let task_id = seed_task(&store, "race-pub", "pkg").await;
    let build_id = store
        .insert_build(BuildInsert {
            product: "race-pub",
            pkg_name: "pkg",
            phase: "pending",
            backend: "chroot",
            user: "tester",
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();

    fn assert_visibility_race_loser(err: &CrbsError) {
        let legal = match err {
            CrbsError::RevisionConflict { expected, current } => *expected == 1 && *current == 2,
            other => crate::error::is_unique_violation(other) || other.is_transient(),
        };
        assert!(legal, "illegal loser error for unpublish race: {err:?}");
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let new_cfg = race_config("unpublish-race-marker");
    let s = store.clone();
    let b = barrier.clone();
    let unpublish = tokio::spawn(async move {
        b.wait().await;
        s.update_product_visibility(id, VISIBILITY_PRIVATE, None, None, Some(1))
            .await
    });
    let s = store.clone();
    let b = barrier.clone();
    let config = tokio::spawn(async move {
        b.wait().await;
        s.update_product_config(id, &new_cfg, None, None, Some(1))
            .await
    });

    let (unpublish_r, config_r) = tokio::join!(unpublish, config);
    let unpublish_r = unpublish_r.unwrap();
    let config_r = config_r.unwrap();
    let unpublish_won = unpublish_r.is_ok();
    let config_won = config_r.is_ok();

    assert!(
        unpublish_won ^ config_won,
        "exactly one writer may take effect (unpublish won={unpublish_won}, config won={config_won})"
    );
    if let Err(e) = &unpublish_r {
        assert_visibility_race_loser(e);
    }
    if let Err(e) = &config_r {
        assert_visibility_race_loser(e);
    }

    let rec = store.get_product_by_id(id).await.unwrap().unwrap();
    assert_eq!(
        rec.revision, 2,
        "products.revision must be baseline+1 regardless of winner"
    );
    assert_eq!(
        rec.visibility,
        if unpublish_won {
            VISIBILITY_PRIVATE
        } else {
            VISIBILITY_PUBLIC
        },
        "visibility must track the unpublish outcome exactly"
    );
    let expected_pkgs: Vec<String> = if config_won {
        vec!["unpublish-race-marker".to_string()]
    } else {
        vec!["seed-marker".to_string()]
    };
    assert_eq!(
        rec.config.base_packages, expected_pkgs,
        "config must track the config-update outcome exactly"
    );

    let revs: Vec<i64> = sqlx::query_scalar(
        "SELECT revision FROM product_config_history \
         WHERE product_id = $1 ORDER BY revision",
    )
    .bind(id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(revs, vec![1, 2]);

    let build = store.get_build(build_id).await.unwrap().unwrap();
    assert_eq!(
        build.phase,
        if unpublish_won {
            "cancelled"
        } else {
            "pending"
        },
        "build cancellation must track the unpublish outcome exactly"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn race_concurrent_specific_assign_single_winner() {
    // 不变量（planner 地基）：单个 pending 构建被 N 个并发
    // assign_specific_build_to_worker 竞争（两个 worker 交替争领同一 build），
    // 指定 CAS 恰放行一个：唯一赢家 Ok(Some(..))，其余 Ok(None)（被抢/谓词
    // 失效）或 transient busy；终态该 builds 行恰一处 assigned、worker_tasks
    // 恰一行（kind='build'）——绝不双派发。SQLite 腿验证 begin_write 写锁
    // 串行化；PG 腿验证 `AND phase='pending'` 条件更新行锁下 CAS。
    let (store, _tmp) = create_test_store().await;
    let store = Arc::new(store);
    let w1 = store
        .upsert_worker("race-w1", "x86_64", 4, "test", "online", None)
        .await
        .unwrap();
    let w2 = store
        .upsert_worker("race-w2", "x86_64", 4, "test", "online", None)
        .await
        .unwrap();

    let task_id = seed_task(&store, "race-specific", "pkg").await;
    let build_id = store
        .insert_build(BuildInsert {
            product: "race-specific",
            pkg_name: "pkg",
            phase: "pending",
            backend: "chroot",
            user: "tester",
            arch: Some("x86_64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(build_id, "/tmp/race-specific.src.rpm", "{}")
        .await
        .unwrap();

    let barrier = Arc::new(tokio::sync::Barrier::new(RACE_N));
    let mut handles = Vec::new();
    for i in 0..RACE_N {
        let store = store.clone();
        let barrier = barrier.clone();
        let worker_id = if i % 2 == 0 { w1 } else { w2 };
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .assign_specific_build_to_worker(build_id, worker_id)
                .await
        }));
    }

    let mut winners = Vec::new();
    for h in handles {
        match h.await.unwrap() {
            Ok(Some(a)) => {
                assert_eq!(a.build_id, build_id, "winner must claim the seeded build");
                assert_eq!(a.task_id, Some(task_id));
                assert!(a.assignment_id > 0);
                winners.push(a.assignment_id);
            }
            Ok(None) => {}
            Err(e) => assert!(
                e.is_transient(),
                "illegal specific-assign loser error (only transient busy allowed): {e:?}"
            ),
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one specific assign must win, got {winners:?}"
    );

    let assigned: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM builds WHERE id = $1 AND phase = 'assigned'")
            .bind(build_id)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(assigned, 1, "the build must be assigned exactly once");

    let assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM worker_tasks WHERE build_id = $1 AND kind = 'build'",
    )
    .bind(build_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(assignments, 1, "worker_tasks must hold exactly one row");
}
