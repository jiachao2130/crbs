// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 整仓重建规模压测：2000 项 × 4 轮单批次内由 driver 推进到终态，考察 driver /
//! state / DB 在整仓规模下的正确性与耗时。测规模而非依赖解析：批次经 state API
//! 直落 running（绕过 prepare/plan 的 dnf 依赖），项的暂存路径指向自建 tiny 假
//! 文件（start_build 只 stat/copy），无调度器、子构建停 pending，测试在 tick 间
//! 用 store 层 `complete_build` 伪造 worker 上报。暂存文件与 nevra 同名、每项
//! 独立、内容相同，文件名必须唯一——活跃构建去重键含"暂存文件名派生的包名"，
//! 共享文件名会同 tick 第 2 项起记 skipped_conflict、批次推进形态全变（driver
//! 单测 `tick_marks_item_skipped_conflict_on_active_duplicate`）。后端按
//! `CRBS_TEST_DATABASE_URL` 双选（postgres 前缀连 PG，否则 SQLite 临时库），
//! 天然双后端无需 `#[ignore]`，CI 的 PG job 注入跑同一目标。

// 测试 crate：seed 夹具不带 #[test] 属性，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Instant;

use crbs_core::config::ServerConfig;
use crbs_core::{BatchInsert, BatchProgress, NewBatchItem, StateStore};
use crbs_server::server::state::AppState;
use crbs_server::test_support::{batch_driver_tick, TickReport};

mod common;

const TOTAL_ITEMS: usize = 2000;
const ROUNDS: usize = 4;
const ITEMS_PER_ROUND: usize = TOTAL_ITEMS / ROUNDS;
/// 驱动器每 tick 每批次释放上限（driver.rs RELEASE_CAP_PER_TICK 为 pub(crate)，集成测试按文档值钉住防退化）。
const RELEASE_CAP_PER_TICK: usize = 200;
/// tick 上限防死循环：2000/200=10 个释放 tick + 3 个轮间栅栏 tick + 对账收尾余量。
const TICK_LIMIT: usize = 40;

async fn seed_product(store: &StateStore, id: i64, name: &str) {
    // 轮间栅栏走 assemble_for_product → 签名策略解析要求产品配置过出口校验；
    // 空 config 会被 fail-closed 拒绝（barrier 永不完成），这里给最小合法配置。
    let cfg = crbs_core::config::ProductConfig {
        base_packages: vec!["bash".into()],
        repos: vec![crbs_core::config::RepoConfig {
            name: "base".into(),
            baseurl: "http://example/repo".into(),
            gpgcheck: false,
            ..Default::default()
        }],
        ..Default::default()
    };
    let config_json = serde_json::to_string(&cfg).unwrap();
    sqlx::query(
        "INSERT INTO products (id, name, visibility, config_json, revision, \
         base_os_revision) VALUES ($1, $2, 'public', $3, 1, 1)",
    )
    .bind(id)
    .bind(name)
    .bind(config_json)
    .execute(store.pool())
    .await
    .unwrap();
}

async fn seed_running_batch(store: &StateStore, product_id: i64, total: i64) -> i64 {
    let id = store
        .insert_batch(BatchInsert {
            product_id: Some(product_id),
            created_by: None,
            source_repo_url: "https://example.com/repo",
            dist: None,
            arch_targets_json: Some(r#"["x86_64"]"#),
            on_failure: "continue",
            force_all: false,
            request_json: None,
        })
        .await
        .unwrap();
    store.set_batch_planning(id).await.unwrap();
    store.set_batch_running(id, total).await.unwrap();
    id
}

fn stage_fake_srpms(srpm_dir: &std::path::Path) {
    std::fs::create_dir_all(srpm_dir).unwrap();
    for i in 0..TOTAL_ITEMS {
        let nevra = format!("pkg-{i:04}-1.0-1.el9.src");
        std::fs::write(srpm_dir.join(format!("{nevra}.rpm")), b"fake-srpm-bytes").unwrap();
    }
}

async fn seed_items(store: &StateStore, batch_id: i64, srpm_dir: &std::path::Path) {
    for r in 0..ROUNDS {
        // NewBatchItem 按引用借字段：先持有 String 再组行。
        let mut pkg_names = Vec::with_capacity(ITEMS_PER_ROUND);
        let mut nevras = Vec::with_capacity(ITEMS_PER_ROUND);
        let mut paths = Vec::with_capacity(ITEMS_PER_ROUND);
        for k in 0..ITEMS_PER_ROUND {
            let i = r * ITEMS_PER_ROUND + k;
            let nevra = format!("pkg-{i:04}-1.0-1.el9.src");
            pkg_names.push(format!("pkg-{i:04}"));
            nevras.push(nevra.clone());
            paths.push(
                srpm_dir
                    .join(format!("{nevra}.rpm"))
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        let rows: Vec<NewBatchItem<'_>> = (0..ITEMS_PER_ROUND)
            .map(|k| NewBatchItem {
                pkg_name: &pkg_names[k],
                srpm_nevra: Some(&nevras[k]),
                srpm_staging_path: Some(&paths[k]),
                round: r as i64,
            })
            .collect();
        let inserted = store.insert_batch_items(batch_id, &rows).await.unwrap();
        assert_eq!(inserted, ITEMS_PER_ROUND);
    }
}

/// 把当前 released 项的 task 子构建全部推到 succeeded（模拟 worker 上报；driver 对账按 task 子构建聚合终态，见 driver.rs task_terminal_outcome）。
async fn complete_released_builds(store: &StateStore, batch_id: i64) {
    for item in store.items_in_state(batch_id, "released").await.unwrap() {
        let task_id = item.task_id.expect("released item carries task id");
        for b in store.get_builds_by_task_id(task_id).await.unwrap() {
            store.complete_build(b.id, "succeeded", None).await.unwrap();
        }
    }
}

#[tokio::test]
async fn batches_scale_two_thousand_items_driver_pipeline() {
    let _ = common::TEST_CONFIG_DIR.path();
    crbs_server::test_support::init_test_logging();

    let (store, tmp) = crbs_server::test_support::create_test_store().await;
    let app = Arc::new(AppState::for_test(
        store.clone(),
        ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));

    seed_product(&store, 1, "p1").await;
    let batch_id = seed_running_batch(&store, 1, TOTAL_ITEMS as i64).await;
    let srpm_dir = tmp
        .path()
        .join("results")
        .join("batches")
        .join(batch_id.to_string())
        .join("srpms");
    stage_fake_srpms(&srpm_dir);
    seed_items(&store, batch_id, &srpm_dir).await;

    let seeded = store.batch_item_summary(batch_id).await.unwrap();
    assert_eq!(seeded.total(), TOTAL_ITEMS as i64);
    assert_eq!(
        seeded,
        BatchProgress {
            pending: TOTAL_ITEMS as i64,
            ..Default::default()
        }
    );
    let t_summary = Instant::now();
    let _ = store.batch_item_summary(batch_id).await.unwrap();
    eprintln!(
        "[scale] batch_item_summary over {TOTAL_ITEMS} items: {:?}",
        t_summary.elapsed()
    );

    let started = Instant::now();
    let mut reports: Vec<TickReport> = Vec::new();
    loop {
        assert!(
            reports.len() < TICK_LIMIT,
            "batch {batch_id} not finished within {TICK_LIMIT} ticks"
        );
        let status = store.get_batch(batch_id).await.unwrap().unwrap().status;
        if matches!(
            status.as_str(),
            "completed" | "partial" | "failed" | "cancelled"
        ) {
            break;
        }
        let report = batch_driver_tick(&app).await.unwrap();
        eprintln!(
            "[scale] tick {:2}: released={} reconciled={} advanced_round={} barrier_ran={} finished={}",
            reports.len() + 1,
            report.released,
            report.reconciled,
            report.advanced_round,
            report.barrier_ran,
            report.finished,
        );
        reports.push(report);
        complete_released_builds(&store, batch_id).await;
    }
    let elapsed = started.elapsed();

    let total_released: usize = reports.iter().map(|r| r.released).sum();
    for (i, r) in reports.iter().enumerate() {
        assert!(
            r.released <= RELEASE_CAP_PER_TICK,
            "tick {} released {} items, cap is {RELEASE_CAP_PER_TICK}",
            i + 1,
            r.released
        );
    }
    assert_eq!(total_released, TOTAL_ITEMS);

    let rec = store.get_batch(batch_id).await.unwrap().unwrap();
    assert_eq!(rec.status, "completed");
    assert_eq!(rec.total_items, TOTAL_ITEMS as i64);
    assert_eq!(rec.n_succeeded, TOTAL_ITEMS as i64);
    assert_eq!(rec.n_failed, 0);
    assert_eq!(rec.n_skipped, 0);
    assert_eq!(rec.n_cancelled, 0);

    let summary = store.batch_item_summary(batch_id).await.unwrap();
    assert_eq!(
        summary,
        BatchProgress {
            succeeded: TOTAL_ITEMS as i64,
            ..Default::default()
        }
    );
    assert_eq!(
        store
            .items_in_state(batch_id, "succeeded")
            .await
            .unwrap()
            .len(),
        TOTAL_ITEMS
    );

    eprintln!(
        "[scale] {TOTAL_ITEMS} items / {} rounds / {} items: {} ticks, total {:?} (SQLite/PG single DB)",
        ROUNDS,
        ITEMS_PER_ROUND,
        reports.len(),
        elapsed
    );
}
