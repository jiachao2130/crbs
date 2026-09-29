// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享测试夹具：临时 store、样板构建与批量插入辅助。

use crate::state::builds::sql;
use crate::state::{BuildInsert, StateStore};

pub(super) async fn tmp_store() -> (tempfile::TempDir, StateStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::new(tmp.path()).await.unwrap();
    (tmp, store)
}

pub(super) async fn repo_publish_of(store: &StateStore, id: i64) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT repo_publish FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

pub(super) async fn repo_consume_of(store: &StateStore, id: i64) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT repo_consume FROM builds WHERE id = $1")
        .bind(id)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// builds.task_id NOT NULL：sample build 挂到先插好的本地任务行上。
pub(super) async fn sample_insert(store: &StateStore) -> BuildInsert<'static> {
    let task_id = crate::state::test_state::seed_task(store, "fedora", "hello-1.0-1.fc42").await;
    BuildInsert {
        product: "fedora",
        pkg_name: "hello-1.0-1.fc42",
        phase: "succeeded",
        backend: "chroot",
        user: "alice",
        task_id: Some(task_id),
        ..Default::default()
    }
}

/// 从 baseline DDL 切出索引 `<name>` 的 CREATE 语句：以 "INDEX <name>"
/// 定位、回溯 CREATE、前扫 `;`；找不到即 panic。
pub(super) fn baseline_index_ddl(baseline: &str, name: &str) -> String {
    let marker = format!("INDEX {name}");
    let pos = baseline
        .find(&marker)
        .unwrap_or_else(|| panic!("baseline must define index {name}"));
    let start = baseline[..pos]
        .rfind("CREATE")
        .expect("CREATE keyword must precede the index definition");
    let end = baseline[start..]
        .find(';')
        .expect("CREATE INDEX statement must be ;-terminated");
    baseline[start..start + end].to_string()
}

/// 直执守卫 INSERT SQL（23 绑定与 insert_build 逐位对应）；None = 0 行拒绝。
pub(super) async fn exec_guarded_insert(
    store: &StateStore,
    task_id: i64,
    phase: &str,
    pkg: &'static str,
) -> Option<i64> {
    let (name, version, release) = crate::util::split_nvr(pkg);
    let sql = sql::insert_build_guarded(store.dialect());
    sqlx::query_scalar::<_, i64>(&sql)
        .bind("fedora")
        .bind(pkg)
        .bind(name)
        .bind(version)
        .bind(release)
        .bind(phase)
        .bind(None::<String>) // result_dir
        .bind(None::<String>) // layer_digest
        .bind(None::<String>) // base_os_digest
        .bind("chroot")
        .bind("alice")
        .bind(None::<i64>) // user_id
        .bind(None::<i64>) // crbs_pid
        // priority 须绑 i32（与公共路径一致）：sqlx 语句缓存按 SQL 文本为键，
        // i64 先 prepare 成 int8 后 i32 命中缓存错写 → PG 报错。
        .bind(0i32) // priority
        .bind(None::<String>) // arch
        .bind(None::<String>) // host_arches
        .bind(task_id)
        .bind(None::<i64>) // product_id
        .bind(1i64) // repo_publish
        .bind(1i64) // repo_consume
        .bind(None::<i64>) // req_min_mem_kb
        .bind(None::<i64>) // req_min_ncpu
        .bind(None::<i64>) // req_min_disk_kb
        .fetch_optional(store.pool())
        .await
        .unwrap()
}
