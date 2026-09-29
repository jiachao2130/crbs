// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 本地取件：arch 谓词、后台闸与并发相位守卫。

use super::common::*;
use super::*;

/// NULL arch 的 pending 构建可被调度（`arch = ''` 不命中 NULL 行）。
#[tokio::test]
async fn pick_and_lock_pending_picks_null_arch_row() {
    let (_tmp, store) = tmp_store().await;
    let id = store
        .insert_build(BuildInsert {
            phase: "pending",
            arch: None, // NULL = 未指定架构（任意 worker 可执行）
            ..sample_insert(&store).await
        })
        .await
        .unwrap();
    store
        .set_build_request_info(id, "/srv/srpms/hello-1.0-1.fc42.src.rpm", "{}")
        .await
        .unwrap();

    let picked = store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .expect("NULL-arch pending build must be schedulable");
    assert_eq!(picked.id, id);
}

/// 本地取构建同样消费 noarch 宿主约束：钉 aarch64 的 noarch 行不得被
/// x86_64 hub 领取；未限制的 noarch 行照常可领。
#[tokio::test]
async fn pick_and_lock_pending_respects_noarch_host_arches() {
    let (_tmp, store) = tmp_store().await;
    let mk = |pkg: &'static str, hosts: Option<&'static str>| {
        let store = &store;
        async move {
            let id = store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase: "pending",
                    arch: Some("noarch"),
                    host_arches: hosts,
                    ..sample_insert(store).await
                })
                .await
                .unwrap();
            store
                .set_build_request_info(id, "/srv/srpms/hello-1.0-1.fc42.src.rpm", "{}")
                .await
                .unwrap();
            id
        }
    };
    let pinned = mk("pinned", Some("aarch64")).await;
    let free = mk("free", None).await;

    let picked = store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .expect("unpinned noarch build must be schedulable");
    assert_eq!(
        picked.id, free,
        "pinned noarch row must not be picked locally"
    );
    assert!(
        store
            .pick_and_lock_pending_for_local_arch("x86_64", None)
            .await
            .unwrap()
            .is_none(),
        "pinned row must remain pending"
    );
    let phase: String = sqlx::query_scalar("SELECT phase FROM builds WHERE id = $1")
        .bind(pinned)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(phase, "pending");
}

/// 空闲派发闸：存在非后台 pending（priority >= 0）时后台档（< 0，重放）
/// 不被取走；用户队列清空后才可调度。文本锁定 + 行为回归双钉。
#[tokio::test]
async fn pick_and_lock_pending_holds_background_until_user_queue_empty() {
    let (_tmp, store) = tmp_store().await;
    let mk = |pkg: &'static str, priority: i32| {
        let store = &store;
        async move {
            let task_id = crate::state::test_state::seed_task(store, "fedora", pkg).await;
            let id = store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase: "pending",
                    arch: Some("x86_64"),
                    priority,
                    backend: "chroot",
                    user: "alice",
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap();
            store
                .set_build_request_info(id, "/srv/srpms/x.src.rpm", "{}")
                .await
                .unwrap();
            id
        }
    };
    // 先插重放（更早排队、排序权重占先），空闲闸必须压住。
    let replay_id = mk("replay-1.0", -1).await;
    let user_id = mk("user-1.0", 0).await;

    let sql =
        crate::state::builds::sql::pick_and_lock_pending(crate::state::Dialect::Sqlite, false);
    assert!(
        sql.contains("priority >= 0 OR NOT EXISTS"),
        "idle-dispatch gate missing from pick SQL: {sql}"
    );

    let picked = store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .expect("user build must be dispatched");
    assert_eq!(picked.id, user_id, "background replay must wait for idle");

    let picked = store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .expect("replay must be dispatched once user queue is idle");
    assert_eq!(picked.id, replay_id);
}

/// 外层 phase 守卫（PG READ COMMITTED 双重领取防护）：SQL 内外两层都要求
/// phase='pending'；SQLite 下照常取走。
#[tokio::test]
async fn pick_and_lock_pending_has_outer_phase_guard() {
    let (_tmp, store) = tmp_store().await;
    // 文本断言：内层子查询与外层 WHERE 各一处 phase='pending'。
    let sql =
        crate::state::builds::sql::pick_and_lock_pending(crate::state::Dialect::Sqlite, false);
    // 空闲闸 NOT EXISTS 子查询内还有第三处。
    assert_eq!(
        sql.matches("phase = 'pending'").count(),
        3,
        "outer WHERE must re-guard phase, got: {sql}"
    );
    let sql_prio =
        crate::state::builds::sql::pick_and_lock_pending(crate::state::Dialect::Sqlite, true);
    assert_eq!(
        sql_prio.matches("phase = 'pending'").count(),
        3,
        "priority variant must keep the outer guard, got: {sql_prio}"
    );

    let id = store
        .insert_build(BuildInsert {
            phase: "pending",
            arch: None,
            ..sample_insert(&store).await
        })
        .await
        .unwrap();
    store
        .set_build_request_info(id, "/srv/srpms/hello-1.0-1.fc42.src.rpm", "{}")
        .await
        .unwrap();

    let picked = store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .expect("guard must not break normal pick");
    assert_eq!(picked.id, id);

    assert!(store
        .pick_and_lock_pending_for_local_arch("x86_64", None)
        .await
        .unwrap()
        .is_none());
}
