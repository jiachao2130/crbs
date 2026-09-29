// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 测试状态库夹具：临时 SQLite、schema 初始化与种子数据。

use super::*;
use crate::types::BuildPriority;

/// 测试辅助：按 CRBS_TEST_DATABASE_URL 建 StateStore。未设置走 SQLite 临时库；
/// `postgres:`/`postgresql://` 都要匹配（示例 URL 用 postgresql://，漏匹配
/// 会静默 fallback SQLite，测试全绿但从未连过 PG）。PG 共享测试库每个测试
/// DROP/CREATE SCHEMA 重置（否则写死自增起点/裸 SQL 的测试互相踩）；crbs_root
/// 用独立 tempdir，避免共享挂载点/结果目录。
pub(crate) async fn create_test_store() -> (StateStore, Option<tempfile::TempDir>) {
    match std::env::var("CRBS_TEST_DATABASE_URL") {
        Ok(url) if url.starts_with("postgres:") || url.starts_with("postgresql:") => {
            let tmp = tempfile::tempdir().unwrap();
            {
                StateStore::install_any_drivers();
                let reset = sqlx::any::AnyPoolOptions::new()
                    .max_connections(1)
                    .connect(&url)
                    .await
                    .unwrap();
                sqlx::query("DROP SCHEMA public CASCADE")
                    .execute(&reset)
                    .await
                    .unwrap();
                sqlx::query("CREATE SCHEMA public")
                    .execute(&reset)
                    .await
                    .unwrap();
                reset.close().await;
            }
            let store = StateStore::new_with_url(&url, tmp.path()).await.unwrap();
            (store, Some(tmp))
        }
        _ => {
            let tmp = tempfile::tempdir().unwrap();
            let store = StateStore::new(tmp.path()).await.unwrap();
            (store, Some(tmp))
        }
    }
}

async fn table_exists(store: &StateStore, table: &str) -> bool {
    match store.dialect() {
        Dialect::Sqlite => {
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$1",
            )
            .bind(table)
            .fetch_one(store.pool())
            .await
            .unwrap();
            count > 0
        }
        #[cfg(feature = "postgres")]
        Dialect::Postgres => {
            // 锚 current_schema()：不锚会捞到其他 schema 同名表，误判存在。
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.tables \
                 WHERE table_name=$1 AND table_schema = current_schema()",
            )
            .bind(table)
            .fetch_one(store.pool())
            .await
            .unwrap();
            count > 0
        }
    }
}

async fn column_exists(store: &StateStore, table: &str, column: &str) -> bool {
    match store.dialect() {
        Dialect::Sqlite => {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM pragma_table_info($1) WHERE name=$2")
                    .bind(table)
                    .bind(column)
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            count > 0
        }
        #[cfg(feature = "postgres")]
        Dialect::Postgres => {
            // 同 table_exists：锚 current_schema()，防其他 schema 同名表列误命中。
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_name=$1 AND column_name=$2 \
                 AND table_schema = current_schema()",
            )
            .bind(table)
            .bind(column)
            .fetch_one(store.pool())
            .await
            .unwrap();
            count > 0
        }
    }
}

/// 生成方言感知的时间偏移 SQL（设置 completed_at/started_at 相对时间）；offset 形如 "-10 days"、"+5 minutes"。
pub(crate) fn sql_time_offset(dialect: Dialect, offset: &str) -> String {
    match dialect {
        Dialect::Sqlite => format!("datetime('now', '{}')", offset),
        #[cfg(feature = "postgres")]
        Dialect::Postgres => {
            // PG 渲染单源复用 db::pg_utc_offset_text（与 sql_days_ago/sql_minutes_ago
            // 同 `(NOW() AT TIME ZONE 'UTC')` UTC 帧，裸 NOW() 会话时区帧会歪曲相对
            // 时间）；malformed offset 退化 sql_now 同帧。
            let (sign, rest) = match offset.strip_prefix('-') {
                Some(rest) => ('-', rest),
                None => ('+', offset),
            };
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                crate::state::db::pg_utc_offset_text(sign, parts[0], parts[1])
            } else {
                Dialect::Postgres.sql_now().to_string()
            }
        }
    }
}

/// sql_time_offset 纯格式化契约（不碰 DB）：SQLite 透传 offset 修饰符；PG 落
/// `(NOW() AT TIME ZONE 'UTC')` UTC 帧并输出 SQLite 同型 TEXT，malformed 退化
/// sql_now（裸 NOW() 会话时区帧会歪曲相对时间）。
#[test]
fn sql_time_offset_formats_per_dialect() {
    assert_eq!(
        sql_time_offset(Dialect::Sqlite, "-300 seconds"),
        "datetime('now', '-300 seconds')"
    );
    assert_eq!(
        sql_time_offset(Dialect::Sqlite, "-10 days"),
        "datetime('now', '-10 days')"
    );

    #[cfg(feature = "postgres")]
    {
        assert_eq!(
            sql_time_offset(Dialect::Postgres, "-300 seconds"),
            "to_char((NOW() AT TIME ZONE 'UTC') - INTERVAL '300 seconds', 'YYYY-MM-DD HH24:MI:SS')"
        );
        // 显式 '+'：只剥 '-' 前缀，符号留在 amount 内（PG interval 接受前导符号）。
        assert_eq!(
            sql_time_offset(Dialect::Postgres, "+5 minutes"),
            "to_char((NOW() AT TIME ZONE 'UTC') + INTERVAL '+5 minutes', 'YYYY-MM-DD HH24:MI:SS')"
        );
        assert_eq!(
            sql_time_offset(Dialect::Postgres, "10 days"),
            "to_char((NOW() AT TIME ZONE 'UTC') + INTERVAL '10 days', 'YYYY-MM-DD HH24:MI:SS')"
        );
        assert_eq!(
            sql_time_offset(Dialect::Postgres, "now"),
            "to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')"
        );
    }
}

/// 测试辅助：从 SQL 提取每个 `IN (...)` / `NOT IN (...)` 组内单引号值集合
///（顺序无关），供与 `TERMINAL_BUILD_PHASES` 做集合等值断言——终态词表漂移必红。
pub(crate) fn sql_in_value_sets(sql: &str) -> Vec<std::collections::BTreeSet<&str>> {
    let mut sets = Vec::new();
    // 逐字符扫描 "IN" 词 + 空白 + "("。嵌套括号组是子查询，不作值列表、从 "(" 后
    // 继续主扫描（内层 IN 自会命中）；不用正则 crate（std 即可）。
    let bytes = sql.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if sql[i..].starts_with("IN") {
            let word_before_ok = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
            let rest = &sql[i + 2..];
            let paren_off = rest.find('(');
            let before_paren_all_ws = paren_off
                .map(|o| rest[..o].chars().all(char::is_whitespace))
                .unwrap_or(false);
            if word_before_ok && before_paren_all_ws {
                if let Some(o) = paren_off {
                    // 找配对的 ")"：跟踪深度，跳过单引号字面量内的括号。
                    let group = &rest[o + 1..];
                    let g = group.as_bytes();
                    let (mut depth, mut j, mut nested, mut in_quote) = (1, 0, false, false);
                    let mut close = None;
                    while j < g.len() {
                        match g[j] {
                            b'\'' => in_quote = !in_quote,
                            b'(' if !in_quote => {
                                depth += 1;
                                nested = true;
                            }
                            b')' if !in_quote => {
                                depth -= 1;
                                if depth == 0 {
                                    close = Some(j);
                                    break;
                                }
                            }
                            _ => {}
                        }
                        j += 1;
                    }
                    if nested {
                        i += 2 + o + 1;
                        continue;
                    }
                    if let Some(close) = close {
                        let vals: std::collections::BTreeSet<&str> = group[..close]
                            .split(',')
                            .map(|v| v.trim().trim_matches('\''))
                            .collect();
                        sets.push(vals);
                        i += 2 + o + 1 + close + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    sets
}

/// 测试辅助：断言 `sql` 恰有 `expected_lists` 个终态 IN 列表（含 'succeeded' 的
/// 组，活跃态词表无该词）且各与 `TERMINAL_BUILD_PHASES` 等值；非终态 IN 列表
///（如 `('assigned', 'running')`）不受影响。
pub(crate) fn assert_terminal_in_lists(sql: &str, expected_lists: usize, ctx: &str) {
    let terminal: std::collections::BTreeSet<&str> = crate::types::TERMINAL_BUILD_PHASES
        .iter()
        .copied()
        .collect();
    let sets = sql_in_value_sets(sql);
    let terminal_sets: Vec<_> = sets.iter().filter(|s| s.contains("succeeded")).collect();
    assert_eq!(
        terminal_sets.len(),
        expected_lists,
        "{ctx}: expected exactly {expected_lists} terminal IN list(s), got {:?} (all sets: {:?})",
        terminal_sets,
        sets
    );
    for ts in &terminal_sets {
        assert_eq!(
            **ts, terminal,
            "{ctx}: terminal IN list drifted from TERMINAL_BUILD_PHASES: {:?} vs {:?}",
            ts, terminal
        );
    }
}

/// 测试辅助：插入最小 task 行并返回 id（`builds.task_id` NOT NULL，造
/// build 前必须先有任务）；product/pkg_name 沿用被测 build 字段，避免污染按任务断言。
pub(crate) async fn seed_task(
    store: &StateStore,
    product: impl AsRef<str>,
    pkg_name: impl AsRef<str>,
) -> i64 {
    store
        .insert_task(TaskInsert {
            product: product.as_ref(),
            pkg_name: pkg_name.as_ref(),
            // 非空用户：list_tasks 过滤含 `OR "user" = ''`（空 = 全员共享的遗留语义），空用户任务会泄漏进所有用户视图。
            user: "test",
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 测试辅助：插入 worker 测试通用形态的 build 行并返回 id；恒定字段
/// chroot 后端 / user "test" / user_id / crbs_pid / 三 digest 列 NULL。
/// task_id 先经 seed_task 造好传入——多 build 可共享同一 task，task 行数由调用方控制。
pub(crate) async fn seed_build(
    store: &StateStore,
    product: &str,
    pkg_name: &str,
    phase: &str,
    arch: &str,
    priority: BuildPriority,
    task_id: i64,
) -> i64 {
    store
        .insert_build(BuildInsert {
            product,
            pkg_name,
            phase,
            backend: "chroot",
            user: "test",
            priority,
            arch: Some(arch),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 测试辅助：把 build 的 started_at 调到 offset 之前（制造僵尸/超时记录）。
pub(crate) async fn set_build_started_at(store: &StateStore, id: i64, offset: &str) {
    let time_sql = sql_time_offset(store.dialect(), offset);
    sqlx::query(&format!(
        "UPDATE builds SET started_at = {} WHERE id = $1",
        time_sql
    ))
    .bind(id)
    .execute(store.pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn test_schema_baseline_v1() {
    let (store, _tmp) = create_test_store().await;

    let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(version, crate::state::migrate::SCHEMA_VERSION);

    assert!(
        column_exists(&store, "workers", "secret_hash").await,
        "workers.secret_hash column should exist"
    );

    // workers 表不含 tags 列
    assert!(
        !column_exists(&store, "workers", "tags").await,
        "workers.tags column should not exist"
    );

    for table in ["users", "user_tokens", "product_acl"] {
        assert!(
            table_exists(&store, table).await,
            "expected {} table to exist",
            table
        );
    }

    for table in ["tasks", "builds"] {
        assert!(
            column_exists(&store, table, "user_id").await,
            "expected {}.user_id column to exist",
            table
        );
    }

    // 资源感知链：builds 8 列 + workers 2 列 + telemetry 1 列 + 画像表。
    for (table, column) in [
        ("builds", "req_min_mem_kb"),
        ("builds", "req_min_ncpu"),
        ("builds", "req_min_disk_kb"),
        ("builds", "peak_total_kb"),
        ("builds", "disk_wbytes"),
        ("builds", "oom_killed"),
        ("builds", "sample_backend"),
        ("builds", "sample_ncpu"),
        ("workers", "disk_free_kb"),
        ("workers", "resource_caps"),
        ("worker_telemetry_samples", "disk_free_kb"),
    ] {
        assert!(
            column_exists(&store, table, column).await,
            "expected {table}.{column} column to exist"
        );
    }
    assert!(
        table_exists(&store, "package_resource_profiles").await,
        "expected package_resource_profiles table to exist"
    );

    // 构建溯源：配置快照列 + 任务标签子表。
    assert!(
        column_exists(&store, "builds", "product_config_toml").await,
        "expected builds.product_config_toml column to exist"
    );
    assert!(
        table_exists(&store, "task_labels").await,
        "expected task_labels table to exist"
    );

    assert!(table_exists(&store, "tasks").await);

    assert!(
        !table_exists(&store, "build_packages").await,
        "build_packages table should not exist"
    );

    assert!(table_exists(&store, "package_urls").await);
}

#[tokio::test]
async fn test_package_url_cache_roundtrip() {
    let (store, _tmp) = create_test_store().await;

    let baseurl = "https://example.com/repo";
    let mut urls = std::collections::HashMap::new();
    urls.insert(
        "pkg-1.0-1.fc44.x86_64".to_string(),
        "https://example.com/repo/pkg-1.0-1.fc44.x86_64.rpm".to_string(),
    );
    urls.insert(
        "dep-2.0-1.fc44.x86_64".to_string(),
        "https://example.com/repo/dep-2.0-1.fc44.x86_64.rpm".to_string(),
    );

    store.put_package_urls(baseurl, &urls).await.unwrap();

    let queried = store
        .get_package_urls(
            baseurl,
            &[
                "pkg-1.0-1.fc44.x86_64".to_string(),
                "missing-1.0-1.fc44.x86_64".to_string(),
            ],
        )
        .await
        .unwrap();

    assert_eq!(queried.len(), 1);
    assert_eq!(
        queried.get("pkg-1.0-1.fc44.x86_64"),
        Some(&"https://example.com/repo/pkg-1.0-1.fc44.x86_64.rpm".to_string())
    );
}

#[tokio::test]
async fn test_package_url_cache_purge() {
    let (store, _tmp) = create_test_store().await;

    let baseurl = "https://example.com/repo";
    let mut urls = std::collections::HashMap::new();
    urls.insert(
        "old-1.0-1.fc44.x86_64".to_string(),
        "https://example.com/repo/old.rpm".to_string(),
    );

    store.put_package_urls(baseurl, &urls).await.unwrap();

    // 把 last_used_at 改到很久以前（方言感知）
    let update_sql = match store.dialect() {
        Dialect::Sqlite => {
            "UPDATE package_urls SET last_used_at = strftime('%s','now','-100 days') WHERE repo_baseurl = $1"
        }
        #[cfg(feature = "postgres")]
        Dialect::Postgres => {
            "UPDATE package_urls SET last_used_at = EXTRACT(EPOCH FROM (NOW() - INTERVAL '100 days'))::bigint WHERE repo_baseurl = $1"
        }
    };
    sqlx::query(update_sql)
        .bind(baseurl)
        .execute(store.pool())
        .await
        .unwrap();

    let purged = store.purge_stale_package_urls(30).await.unwrap();
    assert_eq!(purged, 1);

    let remaining = store
        .get_package_urls(baseurl, &["old-1.0-1.fc44.x86_64".to_string()])
        .await
        .unwrap();
    assert!(remaining.is_empty());
}

/// upsert_package_urls_multi（经 put_package_urls 直测）的原地更新语义钉：同键二次
/// upsert 必须走 `ON CONFLICT DO UPDATE`（url 更新、last_used_at 刷新、created_at
/// 哨兵保持）；退回 INSERT OR REPLACE 会重置 created_at 且 rowid 漂移（行身份）。
#[tokio::test]
async fn upsert_package_urls_multi_updates_in_place_keeping_row_identity() {
    let (store, _tmp) = create_test_store().await;
    let baseurl = "https://example.com/repo";
    let nevra = "pkg-1.0-1.fc44.x86_64";

    let mut urls = std::collections::HashMap::new();
    urls.insert(
        nevra.to_string(),
        "https://example.com/repo/pkg-1.rpm".to_string(),
    );
    store.put_package_urls(baseurl, &urls).await.unwrap();

    // SQLite：upsert 前取样行 id（rowid），二次 upsert 后必须不变。
    let mut sqlite_rowid: Option<i64> = None;
    if matches!(store.dialect(), Dialect::Sqlite) {
        sqlite_rowid = Some(
            sqlx::query_scalar(
                "SELECT rowid FROM package_urls WHERE repo_baseurl = $1 AND nevra = $2",
            )
            .bind(baseurl)
            .bind(nevra)
            .fetch_one(store.pool())
            .await
            .unwrap(),
        );
    }

    // created_at 哨兵（双方言）：DO UPDATE 只触 url/last_used_at；REPLACE 会重置为 now。
    sqlx::query("UPDATE package_urls SET created_at = 1234567890 WHERE repo_baseurl = $1")
        .bind(baseurl)
        .execute(store.pool())
        .await
        .unwrap();

    let mut urls = std::collections::HashMap::new();
    urls.insert(
        nevra.to_string(),
        "https://example.com/repo/pkg-1-1.rpm".to_string(),
    );
    store.put_package_urls(baseurl, &urls).await.unwrap();

    let (url, created_at, last_used_at): (String, i64, i64) = sqlx::query_as(
        "SELECT url, created_at, last_used_at FROM package_urls \
         WHERE repo_baseurl = $1 AND nevra = $2",
    )
    .bind(baseurl)
    .bind(nevra)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        url, "https://example.com/repo/pkg-1-1.rpm",
        "url must be updated in place"
    );
    assert_eq!(
        created_at, 1234567890,
        "created_at must survive the upsert (DO UPDATE, not delete+reinsert)"
    );
    assert!(
        last_used_at > created_at,
        "last_used_at must be refreshed on upsert, got {last_used_at}"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM package_urls WHERE repo_baseurl = $1")
        .bind(baseurl)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1, "upsert must not add a row for the same key");

    if let Some(rowid_before) = sqlite_rowid {
        let rowid_after: i64 = sqlx::query_scalar(
            "SELECT rowid FROM package_urls WHERE repo_baseurl = $1 AND nevra = $2",
        )
        .bind(baseurl)
        .bind(nevra)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(
            rowid_before, rowid_after,
            "SQLite rowid must not change on upsert (delete+reinsert would)"
        );
    }
}

/// 合成 put_package_urls 批量数据：nevra 零填充保证字典序 == 数值序（排序分块
/// 切点确定），命名通用词。
fn synthetic_urls(count: usize) -> std::collections::HashMap<String, String> {
    (0..count)
        .map(|i| {
            let nevra = format!("pkg-{i:04}-1.0-1.noarch");
            let url = format!("https://example.com/repo/{nevra}.rpm");
            (nevra, url)
        })
        .collect()
}

/// 跨块写入语义钉：一次 put 601 条（250+250+101 三块），全量 get_package_urls
/// 回读全命中——分块循环无丢失、块间无覆盖。
#[tokio::test]
async fn put_package_urls_multi_chunk_full_readback() {
    let (store, _tmp) = create_test_store().await;
    let baseurl = "https://example.com/repo";
    let urls = synthetic_urls(601);

    store.put_package_urls(baseurl, &urls).await.unwrap();

    let nevras: Vec<String> = urls.keys().cloned().collect();
    let got = store.get_package_urls(baseurl, &nevras).await.unwrap();
    assert_eq!(got, urls, "every put row must roundtrip across chunks");

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM package_urls WHERE repo_baseurl = $1")
        .bind(baseurl)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        rows, 601,
        "exactly 601 rows stored (no dup/loss across chunks)"
    );
}

/// 块边界钉：恰好 PUT_CHUNK_ROWS 条 = 单块单事务，全量回读全命中。
#[tokio::test]
async fn put_package_urls_chunk_boundary_single_chunk() {
    let (store, _tmp) = create_test_store().await;
    let baseurl = "https://example.com/repo";
    let urls = synthetic_urls(250);

    store.put_package_urls(baseurl, &urls).await.unwrap();

    let nevras: Vec<String> = urls.keys().cloned().collect();
    let got = store.get_package_urls(baseurl, &nevras).await.unwrap();
    assert_eq!(got, urls, "single-chunk put must roundtrip exactly");
}

/// 块边界钉：PUT_CHUNK_ROWS+1 条 = 两块（尾块恰 1 行），全量回读全命中。
#[tokio::test]
async fn put_package_urls_chunk_boundary_tail_single_row() {
    let (store, _tmp) = create_test_store().await;
    let baseurl = "https://example.com/repo";
    let urls = synthetic_urls(251);

    store.put_package_urls(baseurl, &urls).await.unwrap();

    let nevras: Vec<String> = urls.keys().cloned().collect();
    let got = store.get_package_urls(baseurl, &nevras).await.unwrap();
    assert_eq!(got, urls, "two-chunk put must roundtrip exactly");
}

#[tokio::test]
async fn test_repair_zombie_active_builds_by_pid() {
    let (store, _tmp) = create_test_store().await;

    let live_pid = std::process::id() as i64;
    let dead_pid = 999_999_i64;

    // 四条 build 用不同 arch/pkg：insert_build 拒同 product+pkg+arch 活跃重复
    //（僵尸修复按 crbs_pid 判定，与 arch 无关）。

    let b_live = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(live_pid),
            arch: Some("x86_64"),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let b_dead = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(dead_pid),
            arch: Some("aarch64"),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .insert_layer("layer-digest-1", "/tmp/layer1", "fedora", 1)
        .await
        .unwrap();
    let b_invalid = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            phase: "building",
            result_dir: Some("/tmp/result"),
            layer_digest: Some("layer-digest-1"),
            backend: "chroot",
            user: "test",
            crbs_pid: Some(-1),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    // NULL-arch pending 行（引擎本地构建无 arch）钉僵尸修复覆盖面；pkg 错开
    // 避开活跃去重——b_invalid 已占 (fedora, hello, NULL) 活跃位。
    let b_null_arch = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello-legacy",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(dead_pid),
            task_id: Some(
                crate::state::test_state::seed_task(&store, "fedora", "hello-legacy").await,
            ),
            ..Default::default()
        })
        .await
        .unwrap();

    let (repaired, live) = store
        .repair_zombie_active_builds_for_product("fedora")
        .await
        .unwrap();

    assert_eq!(repaired, 3, "expected 3 zombie builds to be repaired");
    assert_eq!(live, 1, "expected 1 live build to remain");

    let live_rec = store.get_build(b_live).await.unwrap().unwrap();
    assert_eq!(live_rec.phase, "pending");

    let dead_rec = store.get_build(b_dead).await.unwrap().unwrap();
    assert_eq!(dead_rec.phase, "failed");
    assert!(
        dead_rec.completed_at.is_some(),
        "zombie repair should set completed_at"
    );
    assert!(
        dead_rec.duration >= Some(0),
        "zombie repair should set duration"
    );

    let invalid_rec = store.get_build(b_invalid).await.unwrap().unwrap();
    assert_eq!(invalid_rec.phase, "failed");
    assert_eq!(
        invalid_rec.result_dir.as_deref(),
        Some("/tmp/result"),
        "zombie repair should preserve result_dir"
    );
    assert!(
        invalid_rec.completed_at.is_some(),
        "zombie repair should set completed_at"
    );
    assert!(
        invalid_rec.duration >= Some(0),
        "zombie repair should set duration"
    );

    let null_arch_rec = store.get_build(b_null_arch).await.unwrap().unwrap();
    assert_eq!(
        null_arch_rec.phase, "failed",
        "NULL-arch pending zombie must be repaired like any other"
    );
    assert_eq!(null_arch_rec.arch, None, "fixture row must stay NULL-arch");
    assert!(
        null_arch_rec.completed_at.is_some(),
        "NULL-arch zombie repair should set completed_at"
    );

    let layer_ref = store.get_layer_ref_count("layer-digest-1").await.unwrap();
    assert_eq!(
        layer_ref,
        Some(0),
        "zombie building build should release layer ref"
    );

    // ref 归零按宽限语义安装 GC schedule：scheduled_gc_at 落值且默认宽限（168h）内
    // 不进 GC 候选；只断言非空与非候选，不做精确时间值断言。
    let scheduled_gc_at: Option<String> =
        sqlx::query_scalar("SELECT scheduled_gc_at FROM layers WHERE digest = $1")
            .bind("layer-digest-1")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(
        scheduled_gc_at.is_some(),
        "ref-to-zero on zombie repair must install a GC schedule (grace semantics)"
    );
    let gc_candidates = store.list_layers_for_gc().await.unwrap();
    assert!(
        !gc_candidates.iter().any(|l| l.digest == "layer-digest-1"),
        "default grace window must defer GC eligibility, got {gc_candidates:?}"
    );
}

#[tokio::test]
async fn test_list_leaked_layers_ignores_terminal_build_refs() {
    // 泄漏检测 JOIN 限定活跃 phase：builds 终态行永存，不限 phase 则终态行把
    // 幽灵 inc 伪装成合法引用，泄漏检测对该层永久盲区（层被永久钉死）。
    let (store, _tmp) = create_test_store().await;

    let mk_build = |pkg: &'static str,
                    phase: &'static str,
                    digest: Option<&'static str>,
                    user: &'static str| {
        let store = &store;
        async move {
            let task_id = seed_task(store, "fedora", pkg).await;
            store
                .insert_build(crate::state::BuildInsert {
                    product: "fedora",
                    pkg_name: pkg,
                    phase,
                    layer_digest: digest,
                    backend: "chroot",
                    user,
                    task_id: Some(task_id),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    // digest-leak：ref=1（幽灵 inc 残留），只有终态 build 行引用 → 必须报泄漏。
    mk_build("p-done", "succeeded", Some("d-leak"), "alice").await;
    store
        .insert_layer("d-leak", "/tmp/l-leak", "fedora", 1)
        .await
        .unwrap();

    // digest-active：ref=1，有 building build 引用 → 合法引用，不是泄漏。
    mk_build("p-run", "building", Some("d-active"), "alice").await;
    store
        .insert_layer("d-active", "/tmp/l-active", "fedora", 1)
        .await
        .unwrap();

    let leaked: Vec<String> = store
        .list_leaked_layers()
        .await
        .unwrap()
        .into_iter()
        .map(|l| l.digest)
        .collect();
    assert!(
        leaked.contains(&"d-leak".to_string()),
        "ref>0 with only terminal build refs must be reported as leaked, got {leaked:?}"
    );
    assert!(
        !leaked.contains(&"d-active".to_string()),
        "active building ref must mask the layer from leak detection, got {leaked:?}"
    );
}

#[tokio::test]
async fn test_layer_ref_dec_stops_at_zero() {
    let (store, _tmp) = create_test_store().await;
    store
        .insert_layer("layer-d1", "/tmp/layer-d1", "fedora", 1)
        .await
        .unwrap();

    // 1 -> 0：正常递减并触发 scheduled_gc_at。
    let count = store.layer_ref_dec("layer-d1", 24).await.unwrap();
    assert_eq!(count, 0);

    // 已为 0：守卫阻止递减到负数，按 LayerNotFound 返回。
    let err = store.layer_ref_dec("layer-d1", 24).await.unwrap_err();
    assert!(matches!(err, crate::error::CrbsError::LayerNotFound { .. }));
    assert_eq!(
        store.get_layer_ref_count("layer-d1").await.unwrap(),
        Some(0)
    );
}

#[tokio::test]
async fn test_layer_dec_schedules_gc_on_sqlite() {
    // 回归：datetime('now', $1) 对整数绑定是无效修饰符（SQLite 返回 NULL），
    // scheduled_gc_at 恒 NULL → GC 永不命中；grace=0 时应立即成为 GC 候选。
    let (store, _tmp) = create_test_store().await;
    store
        .insert_layer("layer-gc", "/tmp/layer-gc", "fedora", 1)
        .await
        .unwrap();

    assert_eq!(store.layer_ref_dec("layer-gc", 0).await.unwrap(), 0);
    let candidates = store.list_layers_for_gc().await.unwrap();
    assert!(candidates.iter().any(|l| l.digest == "layer-gc"));
}

#[tokio::test]
async fn test_inc_layer_ref_on_reuse_recovers_after_dec_to_zero() {
    // A 结束 dec 到 0（调度 GC）后并发 B 复用命中——复用路径必须 inc，否则 B 期间层可能被 GC 删。
    let (store, _tmp) = create_test_store().await;
    store
        .insert_layer("layer-d2", "/tmp/layer-d2", "fedora", 1)
        .await
        .unwrap();

    // grace=0 → scheduled_gc_at=now：ref=0 时立刻成为 GC 候选。
    assert_eq!(store.layer_ref_dec("layer-d2", 0).await.unwrap(), 0);
    let candidates = store.list_layers_for_gc().await.unwrap();
    assert!(candidates.iter().any(|l| l.digest == "layer-d2"));

    crate::engine::shared_layer::inc_layer_ref_on_reuse(&store, "layer-d2")
        .await
        .unwrap();
    let candidates = store.list_layers_for_gc().await.unwrap();
    assert!(!candidates.iter().any(|l| l.digest == "layer-d2"));
}

#[test]
fn resolve_pool_max_connections_priority_env_over_config_over_default() {
    use crate::state::{resolve_pool_max_connections, DEFAULT_DB_MAX_CONNECTIONS};

    // 都未配置 → 默认 8。
    assert_eq!(
        resolve_pool_max_connections(None, None),
        DEFAULT_DB_MAX_CONNECTIONS
    );

    // 优先级：env > 配置 > 默认。
    assert_eq!(resolve_pool_max_connections(Some("16"), None), 16);
    assert_eq!(resolve_pool_max_connections(None, Some(32)), 32);
    assert_eq!(resolve_pool_max_connections(Some("16"), Some(32)), 16);

    // env 非法回退下一级：配置合法则用配置，否则默认。
    assert_eq!(resolve_pool_max_connections(Some("0"), Some(32)), 32);
    assert_eq!(
        resolve_pool_max_connections(Some("0"), None),
        DEFAULT_DB_MAX_CONNECTIONS
    );

    // 配置非法（<1）回退：env 合法用 env，否则默认；env 也非法同回退默认。
    assert_eq!(resolve_pool_max_connections(Some("4"), Some(0)), 4);
    assert_eq!(
        resolve_pool_max_connections(Some("abc"), Some(0)),
        DEFAULT_DB_MAX_CONNECTIONS
    );
    assert_eq!(
        resolve_pool_max_connections(Some(""), Some(0)),
        DEFAULT_DB_MAX_CONNECTIONS
    );
}

#[tokio::test]
async fn test_inc_layer_ref_on_reuse_missing_row_fails() {
    // 层已被 GC 删除（记录不存在）时复用必须硬失败，不能静默继续用已删除的层。
    let (store, _tmp) = create_test_store().await;
    let err = crate::engine::shared_layer::inc_layer_ref_on_reuse(&store, "no-such-layer")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no-such-layer"));
}

#[tokio::test]
async fn test_inc_layer_ref_on_reuse_propagates_layer_not_found() {
    // .complete 命中但 DB 行缺失须识别 LayerNotFound 落锁内自愈，不能包装成通用 I/O 错误（否则该 digest 永久失败）。
    let (store, _tmp) = create_test_store().await;
    let err = crate::engine::shared_layer::inc_layer_ref_on_reuse(&store, "no-such-layer")
        .await
        .unwrap_err();
    assert!(matches!(err, crate::error::CrbsError::LayerNotFound { .. }));
}

#[tokio::test]
async fn test_reuse_existing_layer_reregisters_missing_row() {
    // .complete 在磁盘但 DB 行缺失（注册前崩溃 / GC 删行未删目录）→ 自愈重注册（ref=1）复用，非硬失败。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let params = crate::engine::shared_layer::SharedLayerParams {
        product: "fedora",
        build_requires: &[],
        base_os_digest: "base-digest",
        repo_fingerprint: "",
        srpm: std::path::Path::new("/nonexistent.srpm"),
        base_os: std::path::Path::new("/nonexistent"),
        shared_layers_dir: scratch.path(),
        tmp_dir: scratch.path(),
        state: &store,
        poll_interval: std::time::Duration::from_millis(10),
        timeout: std::time::Duration::from_secs(1),
        max_retries: 0,
        staleness: None,
        dnf_cache_enabled: false,
        dnf_cache_path: scratch.path(),
        package_cache_path: scratch.path(),
        record_provenance: false,
        cancel_token: None,
        operation_timeout: None,
    };
    let upperdir = scratch.path().join("layers").join("d-reuse").join("upper");

    // 行缺失 → 自愈注册（ref=1）并复用。
    crate::engine::shared_layer::create::reuse_existing_layer(&params, "d-reuse", &upperdir)
        .await
        .unwrap();
    assert_eq!(store.get_layer_ref_count("d-reuse").await.unwrap(), Some(1));
    assert_eq!(
        store.get_layer_path("d-reuse").await.unwrap().as_deref(),
        Some(upperdir.to_string_lossy().as_ref())
    );

    // 行已存在 → 普通复用 inc（1→2）。
    crate::engine::shared_layer::create::reuse_existing_layer(&params, "d-reuse", &upperdir)
        .await
        .unwrap();
    assert_eq!(store.get_layer_ref_count("d-reuse").await.unwrap(), Some(2));
}

#[tokio::test]
async fn test_run_gc_removes_dir_then_row() {
    // GC 顺序：先删目录、成功后才删行——反序会留下 ".complete 在磁盘、行已缺失"的永久卡死。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let layer_dir = scratch.path().join("d-gc1");
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    let path = layer_dir.join("upper").to_string_lossy().to_string();
    store
        .insert_layer("d-gc1", &path, "fedora", 1)
        .await
        .unwrap();
    // grace=0 → scheduled_gc_at=now，成为 GC 候选。
    assert_eq!(store.layer_ref_dec("d-gc1", 0).await.unwrap(), 0);

    assert_eq!(store.run_gc(scratch.path()).await.unwrap(), 1);
    assert!(!layer_dir.exists(), "layer 目录必须被删除");
    assert_eq!(
        store.get_layer_path("d-gc1").await.unwrap(),
        None,
        "目录删除成功后 DB 行必须删除"
    );
}

#[tokio::test]
async fn test_run_gc_rechecks_ref_count_under_lock() {
    // TOCTOU：list 到拿 flock 之间 ref 被 inc 回 >0（复用快路径不走 flock），
    // 拿锁后必须复检跳过，不能按过期列表删在用层。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let layer_dir = scratch.path().join("d-gc2");
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    let path = layer_dir.join("upper").to_string_lossy().to_string();
    store
        .insert_layer("d-gc2", &path, "fedora", 1)
        .await
        .unwrap();
    assert_eq!(store.layer_ref_dec("d-gc2", 0).await.unwrap(), 0);
    // 模拟并发构建在 list 之后、flock 之前 inc。
    assert_eq!(store.layer_ref_inc("d-gc2").await.unwrap(), 1);

    assert_eq!(store.run_gc(scratch.path()).await.unwrap(), 0);
    assert!(layer_dir.exists(), "在用层目录必须保留");
    assert!(
        store.get_layer_path("d-gc2").await.unwrap().is_some(),
        "在用层 DB 行必须保留"
    );
}

#[tokio::test]
async fn test_run_gc_deletes_row_when_dir_already_gone() {
    // 上次 GC 崩在"删目录后、删行前"：目录已不存在时补删残留行（自愈）。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("d-gc3").join("upper");
    let path_str = path.to_string_lossy().to_string();
    store
        .insert_layer("d-gc3", &path_str, "fedora", 1)
        .await
        .unwrap();
    assert_eq!(store.layer_ref_dec("d-gc3", 0).await.unwrap(), 0);
    // 注意：不创建目录。

    assert_eq!(store.run_gc(scratch.path()).await.unwrap(), 1);
    assert_eq!(
        store.get_layer_path("d-gc3").await.unwrap(),
        None,
        "目录已不存在的残留行必须补删"
    );
}

#[tokio::test]
async fn test_run_gc_keeps_row_when_dir_removal_fails() {
    // 目录删除失败必须保留 DB 行（行缺失 → 该 digest 复用永久 LayerNotFound），下次 GC 重试删除。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let layer_dir = scratch.path().join("d-gc4");
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    // .lock 必须在撤写权限前存在，否则 run_gc 连 lock 都创建不了、测不到 removal 失败分支。
    tokio::fs::write(layer_dir.join(".lock"), "").await.unwrap();
    let path = layer_dir.join("upper").to_string_lossy().to_string();
    store
        .insert_layer("d-gc4", &path, "fedora", 1)
        .await
        .unwrap();
    assert_eq!(store.layer_ref_dec("d-gc4", 0).await.unwrap(), 0);

    // 撤 layer_dir 写权限（r-x）：.lock 仍可打开（文件权限未变），但 remove_dir_all 删不动内容。
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&layer_dir, std::fs::Permissions::from_mode(0o500))
        .await
        .unwrap();

    let _ = store.run_gc(scratch.path()).await.unwrap();
    if nix::unistd::getuid().is_root() {
        // root 不受权限位限制：目录被真正删除，行也应随之删除。
        assert!(!layer_dir.exists());
        assert_eq!(store.get_layer_path("d-gc4").await.unwrap(), None);
    } else {
        assert!(layer_dir.exists(), "删除失败的目录必须保留");
        assert!(
            store.get_layer_path("d-gc4").await.unwrap().is_some(),
            "目录删除失败时 DB 行必须保留"
        );
    }
    // 恢复权限，让 TempDir drop 时能清理。
    let _ = tokio::fs::set_permissions(&layer_dir, std::fs::Permissions::from_mode(0o700)).await;
}

#[tokio::test]
async fn test_run_gc_refuses_layer_dir_outside_shared_root() {
    // path 指向 shared_layers 根之外时 run_gc 拒删目录也不删行（行可疑留人工排查，不按可疑路径删文件）。
    let (store, _tmp) = create_test_store().await;
    let scratch = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let layer_dir = outside.path().join("d-out");
    tokio::fs::create_dir_all(layer_dir.join("upper"))
        .await
        .unwrap();
    let path = layer_dir.join("upper").to_string_lossy().to_string();
    store
        .insert_layer("d-out", &path, "fedora", 1)
        .await
        .unwrap();
    assert_eq!(store.layer_ref_dec("d-out", 0).await.unwrap(), 0);

    assert_eq!(store.run_gc(scratch.path()).await.unwrap(), 0);
    assert!(layer_dir.exists(), "共享根之外的目录不得删除");
    assert!(
        store.get_layer_path("d-out").await.unwrap().is_some(),
        "path 可疑的 DB 行不删"
    );
}

#[tokio::test]
async fn test_list_builds_filters_pagination_and_total() {
    let (store, _tmp) = create_test_store().await;
    for i in 1..=4 {
        let task_seed_1 = seed_task(
            &store,
            if i <= 3 { "fedora" } else { "centos" },
            &format!("pkg{i}"),
        )
        .await;
        store
            .insert_build(BuildInsert {
                product: if i <= 3 { "fedora" } else { "centos" },
                pkg_name: &format!("pkg{i}"),
                phase: if i % 2 == 0 { "succeeded" } else { "pending" },
                backend: "chroot",
                user: if i <= 2 { "alice" } else { "bob" },
                task_id: Some(task_seed_1),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let filter = crate::types::BuildListFilter {
        product: Some("fedora"),
        limit: Some(2),
        ..Default::default()
    };
    let (total, records) = store.list_builds(&filter).await.unwrap();
    assert_eq!(total, 3, "total must count all filtered rows, not the page");
    assert_eq!(records.len(), 2);
    // 默认 id DESC：第一页是 id 最大的两条。
    assert_eq!(records[0].id, 3);
    assert_eq!(records[1].id, 2);

    let filter = crate::types::BuildListFilter {
        product: Some("fedora"),
        phase: Some("succeeded"),
        ..Default::default()
    };
    let (total, records) = store.list_builds(&filter).await.unwrap();
    assert_eq!(total, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, 2);
}

/// product_queries active 集合回归：pending/assigned/building 都算 active，assigned 是修复点。
#[tokio::test]
async fn test_count_active_for_product_covers_pending_assigned_building() {
    let (store, _tmp) = create_test_store().await;

    for (i, phase) in ["pending", "assigned", "building"].iter().enumerate() {
        let task_seed_2 = seed_task(&store, "fedora", &format!("pkg-{i}")).await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: &format!("pkg-{i}"),
                phase,
                backend: "chroot",
                user: "alice",
                task_id: Some(task_seed_2),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    for (product, phase) in [
        ("fedora", "succeeded"),
        ("fedora", "failed"),
        ("centos", "building"),
    ] {
        let task_seed_3 = seed_task(&store, product, "noise").await;
        store
            .insert_build(BuildInsert {
                product,
                pkg_name: "noise",
                phase,
                backend: "chroot",
                user: "alice",
                task_id: Some(task_seed_3),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    assert_eq!(
        store.count_active_for_product("fedora").await.unwrap(),
        3,
        "pending/assigned/building must all count as active"
    );
    assert_eq!(store.count_active_for_product("centos").await.unwrap(), 1);
    assert_eq!(store.count_active_for_product("unknown").await.unwrap(), 0);
}

/// active_builds_for_pkg_names 矩阵：pending/assigned/building 命中；
/// 终态（succeeded/failed/cancelled/timeout）、别的 product、别的 pkg 不命中；
/// 空切片安全；多 pkg 批量。
#[tokio::test]
async fn test_active_builds_for_pkg_names_matches_active_set_only() {
    let (store, _tmp) = create_test_store().await;

    for (i, phase) in ["pending", "assigned", "building"].iter().enumerate() {
        let task_seed = seed_task(&store, "fedora", &format!("dup-{i}")).await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: &format!("dup-{i}"),
                phase,
                backend: "chroot",
                user: "alice",
                task_id: Some(task_seed),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    for (product, pkg, phase) in [
        ("fedora", "done-1", "succeeded"),
        ("fedora", "done-2", "failed"),
        ("fedora", "done-3", "cancelled"),
        ("fedora", "done-4", "timeout"),
        ("centos", "dup-0", "building"),
    ] {
        let task_seed = seed_task(&store, product, pkg).await;
        store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase,
                backend: "chroot",
                user: "alice",
                task_id: Some(task_seed),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // 空切片安全（IN () 双方言非法，Rust 侧短路）。
    assert!(store
        .active_builds_for_pkg_names("fedora", &[])
        .await
        .unwrap()
        .is_empty());

    let hits = store
        .active_builds_for_pkg_names("fedora", &["dup-1"])
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].pkg_name, "dup-1");
    assert_eq!(hits[0].phase, "assigned");
    assert!(hits[0].build_id > 0);
    assert!(hits[0].task_id.is_some());

    let names: Vec<&str> = vec!["dup-0", "dup-1", "dup-2", "done-1", "other"];
    let mut hits = store
        .active_builds_for_pkg_names("fedora", &names)
        .await
        .unwrap();
    hits.sort_by_key(|h| h.pkg_name.clone());
    assert_eq!(hits.len(), 3, "only active rows in this product match");
    assert_eq!(
        hits.iter().map(|h| h.pkg_name.as_str()).collect::<Vec<_>>(),
        vec!["dup-0", "dup-1", "dup-2"]
    );

    assert!(store
        .active_builds_for_pkg_names("unknown", &names)
        .await
        .unwrap()
        .is_empty());
}

/// 动态 IN 占位符上限守卫：MAX_BIND_PARAMS + 1 个名字（$1 起共 30003 个绑定）
/// 超限时 Rust 侧报 ValidationFailed、消息含上限值（db/mod.rs::in_placeholders）。
#[tokio::test]
async fn test_active_builds_for_pkg_names_rejects_oversized_in_list() {
    let (store, _tmp) = create_test_store().await;
    let limit = crate::state::db::MAX_BIND_PARAMS;
    let names: Vec<String> = (0..=limit).map(|i| format!("pkg-{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let msg = store
        .active_builds_for_pkg_names("fedora", &refs)
        .await
        .unwrap_err()
        .to_string();
    assert!(msg.contains("exceed"), "unexpected error: {msg}");
    assert!(msg.contains(&limit.to_string()), "unexpected error: {msg}");
}

/// active 用户列表：同一 active 集合（含 assigned）、排除 exclude_user 与空用户名、DISTINCT 去重、只看本产品。
#[tokio::test]
async fn test_active_build_users_for_product_excludes_self_and_empty() {
    let (store, _tmp) = create_test_store().await;

    let cases: &[(&str, &str)] = &[
        ("bob", "pending"),
        ("carol", "assigned"),
        ("bob", "building"),
        ("alice", "building"),
        ("", "building"),
    ];
    for (i, (user, phase)) in cases.iter().enumerate() {
        let task_seed_4 = seed_task(&store, "fedora", &format!("pkg-{i}")).await;
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: &format!("pkg-{i}"),
                phase,
                backend: "chroot",
                user,
                task_id: Some(task_seed_4),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    let task_seed_5 = seed_task(&store, "centos", "pkg-x").await;
    store
        .insert_build(BuildInsert {
            product: "centos",
            pkg_name: "pkg-x",
            phase: "building",
            backend: "chroot",
            user: "mallory",
            task_id: Some(task_seed_5),
            ..Default::default()
        })
        .await
        .unwrap();

    let mut users = store
        .active_build_users_for_product("fedora", "alice")
        .await
        .unwrap();
    users.sort();
    assert_eq!(
        users,
        vec!["bob".to_string(), "carol".to_string()],
        "must list distinct other-user active builders, excluding self/empty/other products"
    );
}

#[tokio::test]
async fn test_repair_all_zombie_active_builds() {
    let (store, _tmp) = create_test_store().await;

    let live_pid = std::process::id() as i64;

    let b_live_p1 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(live_pid),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let b_dead_p2 = store
        .insert_build(BuildInsert {
            product: "centos",
            pkg_name: "hello",
            phase: "building",
            result_dir: Some("/tmp/result"),
            backend: "chroot",
            user: "test",
            crbs_pid: Some(999_999_i64),
            task_id: Some(crate::state::test_state::seed_task(&store, "centos", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
    assert_eq!(
        repaired_ids,
        vec![b_dead_p2],
        "expected 1 zombie build repaired across products (id set for terminal hooks)"
    );
    assert_eq!(live, 1, "expected 1 live build to remain");

    let live_rec = store.get_build(b_live_p1).await.unwrap().unwrap();
    assert_eq!(live_rec.phase, "pending");

    let dead_rec = store.get_build(b_dead_p2).await.unwrap().unwrap();
    assert_eq!(dead_rec.phase, "failed");
    assert!(
        dead_rec.completed_at.is_some(),
        "zombie repair should set completed_at"
    );
}

/// crbs_pid 为 NULL 的远程构建（worker 进程管理）不得被僵尸修复误杀：真实
/// 远程 building 必有活跃 worker_tasks 行（派发/拉取/回收三写入点保证，见
/// zombie.rs `has_active_worker_task`）；无行的 building+NULL pid 属
/// pick→attach 崩溃窗口，由 zombie repair 重置 pending。
#[tokio::test]
async fn test_repair_zombie_does_not_kill_null_pid_remote_builds() {
    let (store, _tmp) = create_test_store().await;

    // 远程派发到 worker 的构建：crbs_pid 为 NULL（进程不在 server 上）
    let b_remote = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            result_dir: Some("/tmp/result"),
            backend: "nspawn",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    // 模拟远程链路：派发建 worker_tasks 行，worker 拉取后 running + building。
    let worker_id = store
        .upsert_worker("w1", "x86_64", 2, "0.15.0-dev", "online", None)
        .await
        .unwrap();
    store
        .assign_build_to_worker(b_remote, worker_id)
        .await
        .unwrap();
    sqlx::query("UPDATE worker_tasks SET status = 'running' WHERE build_id = $1")
        .bind(b_remote)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET phase = 'building' WHERE id = $1")
        .bind(b_remote)
        .execute(store.pool())
        .await
        .unwrap();

    let (repaired_ids, live) = store.repair_all_zombie_active_builds().await.unwrap();
    assert_eq!(
        repaired_ids.len(),
        0,
        "null crbs_pid must not be repaired as zombie"
    );
    assert_eq!(live, 1, "null crbs_pid build must count as live");

    let rec = store.get_build(b_remote).await.unwrap().unwrap();
    assert_eq!(
        rec.phase, "building",
        "remote build phase must be preserved"
    );
}

#[tokio::test]
async fn test_list_results_exceeding_count_per_pkg() {
    let (store, _tmp) = create_test_store().await;

    // 同一 (product, pkg_name) 下插入 4 条已完成记录，completed_at 递增
    let mut ids = Vec::new();
    for i in 0..4 {
        let id = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "hello",
                phase: "succeeded",
                result_dir: Some(&format!("/tmp/result/{}", i)),
                backend: "chroot",
                user: "test",
                task_id: Some(seed_task(&store, "fedora", "hello").await),
                ..Default::default()
            })
            .await
            .unwrap();
        ids.push(id);
        let seconds_ago = format!("-{} seconds", 100 - i * 10);
        let time_sql = sql_time_offset(store.dialect(), &seconds_ago);
        sqlx::query(&format!(
            "UPDATE builds SET completed_at = {} WHERE id = $1",
            time_sql
        ))
        .bind(id)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    // max_count = 2 -> 只保留 ids[3], ids[2]，淘汰 ids[1], ids[0]
    let candidates = store
        .list_results_exceeding_count_per_pkg(None, 2)
        .await
        .unwrap();
    let c_ids: Vec<_> = candidates.iter().map(|c| c.id).collect();
    assert_eq!(c_ids, vec![ids[0], ids[1]]);

    let counts = store.count_builds_by_phase().await.unwrap();
    assert_eq!(counts.get("succeeded").copied().unwrap_or(0), 4);
    assert_eq!(counts.get("failed").copied().unwrap_or(0), 0);

    let candidates = store
        .list_results_exceeding_count_per_pkg(Some("fedora"), 3)
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, ids[0]);

    let candidates = store
        .list_results_exceeding_count_per_pkg(Some("centos"), 1)
        .await
        .unwrap();
    assert!(candidates.is_empty());
}

/// per-pkg 超额候选防线不变量：活跃 phase 与 completed_at 为空的行绝不入候选；
/// completed_at DESC 编号下最新终态构建（rn=1）在任何有效 max_count 下都不入
/// 候选——改掉分区/排序/过滤即打破最新成功产物的保护，本测试必须变红。
#[tokio::test]
async fn test_per_pkg_excess_never_selects_newest_completed_build() {
    let (store, _tmp) = create_test_store().await;

    let insert = |store: &StateStore, phase: &'static str| {
        let store = store.clone();
        async move {
            store
                .insert_build(BuildInsert {
                    product: "fedora",
                    pkg_name: "guard",
                    phase,
                    result_dir: Some("/tmp/result/guard"),
                    backend: "chroot",
                    user: "test",
                    task_id: Some(seed_task(&store, "fedora", "guard").await),
                    ..Default::default()
                })
                .await
                .unwrap()
        }
    };

    let oldest = insert(&store, "succeeded").await;
    let mid = insert(&store, "succeeded").await;
    let newest = insert(&store, "succeeded").await;
    for (i, id) in [oldest, mid, newest].iter().enumerate() {
        let seconds_ago = format!("-{} seconds", 100 - i * 10);
        let time_sql = sql_time_offset(store.dialect(), &seconds_ago);
        sqlx::query(&format!(
            "UPDATE builds SET completed_at = {} WHERE id = $1",
            time_sql
        ))
        .bind(id)
        .execute(&store.pool)
        .await
        .unwrap();
    }

    // 干扰行：活跃 building（completed_at NULL）与无 completed_at 的终态行，均不得入候选。
    let active = insert(&store, "building").await;
    let no_completed = insert(&store, "failed").await;

    // max_count=1：候选 = oldest + mid（completed_at ASC），newest 恒为 rn=1 保留。
    let candidates = store
        .list_results_exceeding_count_per_pkg(None, 1)
        .await
        .unwrap();
    let c_ids: Vec<_> = candidates.iter().map(|c| c.id).collect();
    assert_eq!(c_ids, vec![oldest, mid]);
    assert!(
        !c_ids.contains(&newest),
        "newest completed build must never be a candidate"
    );
    assert!(!c_ids.contains(&active), "active build must be excluded");
    assert!(
        !c_ids.contains(&no_completed),
        "build without completed_at must be excluded"
    );

    let candidates = store
        .list_results_exceeding_count_per_pkg(None, 2)
        .await
        .unwrap();
    let c_ids: Vec<_> = candidates.iter().map(|c| c.id).collect();
    assert_eq!(c_ids, vec![oldest]);
}

#[tokio::test]
async fn test_list_results_older_than_days() {
    let (store, _tmp) = create_test_store().await;

    let old_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            phase: "succeeded",
            result_dir: Some("/tmp/old"),
            backend: "chroot",
            user: "test",
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let time_sql = sql_time_offset(store.dialect(), "-10 days");
    sqlx::query(&format!(
        "UPDATE builds SET completed_at = {} WHERE id = $1",
        time_sql
    ))
    .bind(old_id)
    .execute(&store.pool)
    .await
    .unwrap();

    let recent_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            phase: "succeeded",
            result_dir: Some("/tmp/recent"),
            backend: "chroot",
            user: "test",
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();
    let time_sql = sql_time_offset(store.dialect(), "-1 days");
    sqlx::query(&format!(
        "UPDATE builds SET completed_at = {} WHERE id = $1",
        time_sql
    ))
    .bind(recent_id)
    .execute(&store.pool)
    .await
    .unwrap();

    let candidates = store.list_results_older_than_days(None, 7).await.unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].id, old_id);

    let candidates = store
        .list_results_older_than_days(Some("fedora"), 7)
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);

    let candidates = store
        .list_results_older_than_days(Some("centos"), 7)
        .await
        .unwrap();
    assert!(candidates.is_empty());
}

#[tokio::test]
async fn test_build_request_info_roundtrip() {
    let (store, _tmp) = create_test_store().await;

    let b_info = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(1234),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    store
        .set_build_request_info(b_info, "/tmp/test.src.rpm", "{\"stage\":\"bb\"}")
        .await
        .unwrap();

    let infos = store.list_pending_with_request_info().await.unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].id, b_info);
    assert_eq!(infos[0].srpm_path, "/tmp/test.src.rpm");
    assert_eq!(infos[0].request_json, "{\"stage\":\"bb\"}");
    assert_eq!(infos[0].crbs_pid, Some(1234));
}

#[tokio::test]
async fn test_update_build_crbs_pid() {
    let (store, _tmp) = create_test_store().await;

    let b_pid = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "hello",
            backend: "chroot",
            user: "test",
            crbs_pid: Some(1),
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "hello").await),
            ..Default::default()
        })
        .await
        .unwrap();

    store.update_build_crbs_pid(b_pid, 9999).await.unwrap();
    let record = store.get_build(b_pid).await.unwrap().unwrap();
    assert_eq!(record.crbs_pid, Some(9999));
    assert_eq!(record.phase, "pending");
}

/// sqlx 驱动 $n 占位符绑定语义的方言契约（四段断言，SQLite/PG 通跑）：
/// 顺序绑定、重复参数、乱序出现、IN 列表。业务 SQL 依赖这些语义，
/// 驱动行为变更时在此一处钉住。
#[tokio::test]
async fn placeholders_driver_binding_contract() {
    let (store, _tmp) = create_test_store().await;

    // 1. 顺序绑定：$1, $2 按绑定顺序取值
    let result: i64 = sqlx::query_scalar("SELECT $1 + $2")
        .bind(3i64)
        .bind(5i64)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(result, 8);

    // 2. 重复参数：$1 出现两次，只绑定一次值，两处都使用它
    let result: i64 = sqlx::query_scalar("SELECT $1 + $1")
        .bind(4i64)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(result, 8);

    // 3. 乱序出现：SQL 中 $2 出现在 $1 之前，但绑定顺序仍是 $1 先，$2 后
    let result: i64 = sqlx::query_scalar("SELECT $2 - $1")
        .bind(3i64)
        .bind(10i64)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(result, 7);

    // 4. IN 列表：IN ($1, $2, $3) 逐位展开
    for id in 1..=3 {
        sqlx::query(&format!("INSERT INTO products (id, name, visibility, config_json, revision, base_os_revision) VALUES ($1, 'p{id}', 'public', '{{}}', 1, 1)"))
            .bind(id)
            .execute(&store.pool)
            .await
            .unwrap();
    }
    let result: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM products WHERE id IN ($1, $2, $3) ORDER BY id")
            .bind(1i64)
            .bind(2i64)
            .bind(3i64)
            .fetch_all(&store.pool)
            .await
            .unwrap();
    assert_eq!(result, vec![1, 2, 3]);
}

/// 回归：两个并发 `StateStore::new` 打到同一全新 SQLite 目录都应成功：
/// busy_timeout=0（默认）时后到连接在 baseline DDL 上立即 SQLITE_BUSY，
/// per-connection `busy_timeout` 等前者提交后再 DROP+CREATE，两者皆成。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_state_store_new_same_dir_both_succeed() {
    // 仅 SQLite 相关（busy_timeout 是 SQLite PRAGMA）；PG 走 MVCC，跳过。
    if std::env::var("CRBS_TEST_DATABASE_URL")
        .map(|u| u.starts_with("postgres:") || u.starts_with("postgresql:"))
        .unwrap_or(false)
    {
        eprintln!("skipped: CRBS_TEST_DATABASE_URL points to PostgreSQL; requires SQLite backend");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let p1 = tmp.path().to_path_buf();
    let p2 = tmp.path().to_path_buf();
    let (a, b) = tokio::join!(
        tokio::spawn(async move { StateStore::new(&p1).await.map(|_| ()) }),
        tokio::spawn(async move { StateStore::new(&p2).await.map(|_| ()) }),
    );
    a.unwrap().expect("first concurrent StateStore::new failed");
    b.unwrap()
        .expect("second concurrent StateStore::new failed");
}

/// `journal_size_limit` 每连接生效（连接级默认 -1 = 不收缩），after_connect 对
/// 池内所有连接重申 64 MiB；仅 SQLite（PRAGMA 特有语法），PG 腿跳过。
#[tokio::test]
async fn sqlite_journal_size_limit_configured_per_connection() {
    if std::env::var("CRBS_TEST_DATABASE_URL")
        .map(|u| u.starts_with("postgres:") || u.starts_with("postgresql:"))
        .unwrap_or(false)
    {
        eprintln!("skipped: CRBS_TEST_DATABASE_URL points to PostgreSQL; requires SQLite backend");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = StateStore::new(tmp.path()).await.unwrap();
    let v: i64 = sqlx::query_scalar("PRAGMA journal_size_limit")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        v,
        64 * 1024 * 1024,
        "-wal must be capped at 64 MiB per connection"
    );
}

/// 回归：同一 StateStore 上多连接并发写入不应报 SQLITE_BUSY。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_do_not_error() {
    if std::env::var("CRBS_TEST_DATABASE_URL")
        .map(|u| u.starts_with("postgres:") || u.starts_with("postgresql:"))
        .unwrap_or(false)
    {
        eprintln!("skipped: CRBS_TEST_DATABASE_URL points to PostgreSQL; requires SQLite backend");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = store.clone();
        handles.push(tokio::spawn(async move {
            s.insert_task(TaskInsert {
                product: "fedora",
                pkg_name: "pkg",
                user: "u",
                phase: "pending",
                ..Default::default()
            })
            .await
        }));
    }
    for h in handles {
        h.await.unwrap().expect("concurrent insert_task failed");
    }
}

/// 回归：两个**独立** StateStore（各自独立池 = 独立连接，模拟 hub server 与
/// 本地 `crbs build`/CLI 跨进程共享同一 `crbs.db`）并发写同一行不应报 SQLITE_BUSY。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_independent_connections_write_same_row() {
    if std::env::var("CRBS_TEST_DATABASE_URL")
        .map(|u| u.starts_with("postgres:") || u.starts_with("postgresql:"))
        .unwrap_or(false)
    {
        eprintln!("skipped: CRBS_TEST_DATABASE_URL points to PostgreSQL; requires SQLite backend");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let seed = StateStore::new(tmp.path()).await.unwrap();
    sqlx::query(
        "INSERT INTO products (id, name, visibility, config_json, revision, base_os_revision) \
         VALUES (1, 'p', 'public', '{}', 1, 1)",
    )
    .execute(&seed.pool)
    .await
    .unwrap();

    let a = StateStore::new(tmp.path()).await.unwrap();
    let b = StateStore::new(tmp.path()).await.unwrap();
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move {
            sqlx::query("UPDATE products SET revision = revision + 1 WHERE id = 1")
                .execute(&a.pool)
                .await
                .map(|_| ())
        }),
        tokio::spawn(async move {
            sqlx::query("UPDATE products SET revision = revision + 1 WHERE id = 1")
                .execute(&b.pool)
                .await
                .map(|_| ())
        }),
    );
    ra.unwrap().expect("independent conn A write failed");
    rb.unwrap().expect("independent conn B write failed");
}

/// 权限不变量：crbs.db mode 必须 0660（root / crbs-server / crbs 组三身份可读写）；
/// chown 到 crbs 组由部署机验证，此处只断言 mode（平台无关部分）。
#[cfg(unix)]
#[tokio::test]
async fn test_crbs_db_file_mode_0660() {
    let (store, tmp) = create_test_store().await;
    // PG 模式无本地库文件，跳过（PG 分支也返回 tempdir，不能以 TempDir None 判后端）。
    #[cfg(feature = "postgres")]
    if matches!(store.dialect(), Dialect::Postgres) {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let Some(tmp) = tmp else {
        return;
    };
    let db_path = tmp.path().join("crbs.db");
    let meta = std::fs::metadata(&db_path).unwrap();
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o660,
        "crbs.db mode must be 0660 (crbs permission invariant)"
    );
    drop(store);
}

/// `recent_task_phase_series`（gauge 计数数据源）：窗口按 id DESC 截取
///（newest-first）、scope 过滤正确、可见性白名单生效（现存产品不在白名单 → 排除）。
#[tokio::test]
async fn test_recent_task_phase_series() {
    let (store, _tmp) = create_test_store().await;
    for phase in ["succeeded", "succeeded", "succeeded", "failed", "failed"] {
        store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: "pkg",
                user: "u",
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    // limit=4 → 窗口为最新 4 条，newest-first（failed 在前）。
    let series = store.recent_task_phase_series(None, 4).await.unwrap();
    assert_eq!(series, vec!["failed", "failed", "succeeded", "succeeded"]);

    // limit 大于总量 → 全量（newest-first）。
    let series = store.recent_task_phase_series(None, 100).await.unwrap();
    assert_eq!(
        series,
        vec!["failed", "failed", "succeeded", "succeeded", "succeeded"]
    );

    // 可见性：创建现存产品 fedora 使任务脱离孤儿豁免，白名单 Some(["other"]) → 全排除。
    store
        .create_product(CreateProductInput {
            name: "fedora",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: VISIBILITY_PUBLIC,
            config: &crate::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("recent phase series test"),
        })
        .await
        .unwrap();
    let series = store
        .recent_task_phase_series(Some(&["other".to_string()]), 100)
        .await
        .unwrap();
    assert!(series.is_empty(), "non-visible tasks must be excluded");
    let series = store
        .recent_task_phase_series(Some(&["fedora".to_string()]), 100)
        .await
        .unwrap();
    assert_eq!(series.len(), 5);
}

/// for_user 镜像（/ui/me 总览带）：只计该用户任务；recent 变体按 id DESC 截窗口。
#[tokio::test]
async fn test_task_phase_counts_for_user_filters_by_user() {
    let (store, _tmp) = create_test_store().await;
    for (user, phase) in [
        ("alice", "succeeded"),
        ("alice", "succeeded"),
        ("alice", "succeeded"),
        ("alice", "failed"),
        ("alice", "failed"),
        ("bob", "succeeded"),
    ] {
        store
            .insert_task(TaskInsert {
                product: "fedora",
                pkg_name: "pkg",
                user,
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let counts = store.count_tasks_by_phase_for_user("alice").await.unwrap();
    assert_eq!(counts.get("succeeded").copied().unwrap_or(0), 3);
    assert_eq!(counts.get("failed").copied().unwrap_or(0), 2);
    let counts = store.count_tasks_by_phase_for_user("bob").await.unwrap();
    assert_eq!(counts.get("succeeded").copied().unwrap_or(0), 1);
    let counts = store.count_tasks_by_phase_for_user("carol").await.unwrap();
    assert!(counts.is_empty());

    // 窗口语义：limit=4 只看 alice 最新 4 条（插入序保证 failed id 更大），bob 行永不进窗口。
    let series = store
        .recent_task_phase_series_for_user("alice", 4)
        .await
        .unwrap();
    assert_eq!(series, vec!["failed", "failed", "succeeded", "succeeded"]);
    let series = store
        .recent_task_phase_series_for_user("alice", 100)
        .await
        .unwrap();
    assert_eq!(series.len(), 5);
    let series = store
        .recent_task_phase_series_for_user("bob", 100)
        .await
        .unwrap();
    assert_eq!(series, vec!["succeeded"]);
    let series = store
        .recent_task_phase_series_for_user("carol", 100)
        .await
        .unwrap();
    assert!(series.is_empty());
}

/// for_product 镜像（产品详情页总览带）：只计该产品任务；recent 变体按
/// id DESC 截窗口；带计数总和必须与 list_tasks(product) 过滤 total 对账。
#[tokio::test]
async fn test_task_phase_counts_for_product_filters_by_product() {
    let (store, _tmp) = create_test_store().await;
    for (product, phase) in [
        ("fedora", "succeeded"),
        ("fedora", "succeeded"),
        ("fedora", "succeeded"),
        ("fedora", "failed"),
        ("fedora", "failed"),
        ("fedora", "building"),
        ("fedora", "pending"),
        ("mydist", "succeeded"),
    ] {
        store
            .insert_task(TaskInsert {
                product,
                pkg_name: "pkg",
                user: "alice",
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let counts = store
        .count_tasks_by_phase_for_product("fedora")
        .await
        .unwrap();
    assert_eq!(counts.get("succeeded").copied().unwrap_or(0), 3);
    assert_eq!(counts.get("failed").copied().unwrap_or(0), 2);
    assert_eq!(counts.get("building").copied().unwrap_or(0), 1);
    assert_eq!(counts.get("pending").copied().unwrap_or(0), 1);
    let counts = store
        .count_tasks_by_phase_for_product("mydist")
        .await
        .unwrap();
    assert_eq!(counts.get("succeeded").copied().unwrap_or(0), 1);
    let counts = store
        .count_tasks_by_phase_for_product("nosuch")
        .await
        .unwrap();
    assert!(counts.is_empty());

    // 窗口语义：limit=4 只看 fedora 最新 4 条（插入序保证 failed id 最大），mydist 行不进窗口。
    let series = store
        .recent_task_phase_series_for_product("fedora", 4)
        .await
        .unwrap();
    assert_eq!(series.len(), 4);
    assert_eq!(series.iter().filter(|p| *p == "failed").count(), 2);
    let series = store
        .recent_task_phase_series_for_product("fedora", 100)
        .await
        .unwrap();
    assert_eq!(series.len(), 7);
    let series = store
        .recent_task_phase_series_for_product("nosuch", 100)
        .await
        .unwrap();
    assert!(series.is_empty());

    let band_total: i64 = store
        .count_tasks_by_phase_for_product("fedora")
        .await
        .unwrap()
        .values()
        .sum();
    let (list_total, rows) = store
        .list_tasks(&crate::types::TaskListFilter {
            product: Some("fedora"),
            limit: Some(2),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(band_total, list_total as i64);
    assert_eq!(rows.len(), 2);
}

/// `&[(phase, count)]` 序列里取指定 phase 的计数（缺省 0）——scoped 计数测试共用。
fn phase_count(counts: &[(String, i64)], phase: &str) -> i64 {
    counts
        .iter()
        .find(|(p, _)| p == phase)
        .map(|&(_, c)| c)
        .unwrap_or(0)
}

/// 相位 chips 内核：count_tasks_by_phase_scoped 与 list_tasks 同口径——
/// product 等值 / name 前缀 / 可见性白名单（现存产品脱离孤儿豁免后白名单外排除）。
#[tokio::test]
async fn test_count_tasks_by_phase_scoped_filters() {
    let (store, _tmp) = create_test_store().await;
    for (product, pkg, phase) in [
        ("fedora", "hello", "succeeded"),
        ("fedora", "hello-docs", "failed"),
        ("fedora", "kernel", "succeeded"),
        ("mydist", "hello", "succeeded"),
    ] {
        store
            .insert_task(TaskInsert {
                product,
                pkg_name: pkg,
                user: "alice",
                phase,
                ..Default::default()
            })
            .await
            .unwrap();
    }

    let counts = store
        .count_tasks_by_phase_scoped(None, None, None, None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 3);
    assert_eq!(phase_count(&counts, "failed"), 1);

    let counts = store
        .count_tasks_by_phase_scoped(None, Some("fedora"), None, None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 2);
    assert_eq!(phase_count(&counts, "failed"), 1);

    let counts = store
        .count_tasks_by_phase_scoped(None, None, Some("hello"), None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 2);
    assert_eq!(phase_count(&counts, "failed"), 1);

    for name in ["fedora", "mydist"] {
        store
            .create_product(CreateProductInput {
                name,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: VISIBILITY_PUBLIC,
                config: &crate::config::ProductConfig::default(),
                changed_by_user_id: None,
                reason: Some("task scoped count test"),
            })
            .await
            .unwrap();
    }
    let counts = store
        .count_tasks_by_phase_scoped(Some(&["fedora".to_string()]), None, None, None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 2);
    assert_eq!(phase_count(&counts, "failed"), 1);
    assert_eq!(counts.len(), 2, "mydist tasks must be excluded: {counts:?}");
}

/// 相位 chips 内核：count_builds_by_phase_scoped 与 list_builds 同口径——arch 等值、可见性白名单。
#[tokio::test]
async fn test_count_builds_by_phase_scoped_filters() {
    let (store, _tmp) = create_test_store().await;
    let task = store
        .insert_task(TaskInsert {
            product: "fedora",
            pkg_name: "pkg",
            user: "alice",
            phase: "succeeded",
            ..Default::default()
        })
        .await
        .unwrap();
    for phase in ["succeeded", "failed"] {
        store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "pkg",
                phase,
                arch: Some("x86_64"),
                user: "alice",
                task_id: Some(task),
                ..Default::default()
            })
            .await
            .unwrap();
    }
    store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "solo-pkg",
            phase: "succeeded",
            arch: Some("aarch64"),
            user: "alice",
            task_id: Some(crate::state::test_state::seed_task(&store, "fedora", "solo-pkg").await),
            ..Default::default()
        })
        .await
        .unwrap();

    let counts = store
        .count_builds_by_phase_scoped(None, None, None, None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 2);
    assert_eq!(phase_count(&counts, "failed"), 1);

    let counts = store
        .count_builds_by_phase_scoped(None, None, None, Some("aarch64"))
        .await
        .unwrap();
    assert_eq!(counts.len(), 1);
    assert_eq!(phase_count(&counts, "succeeded"), 1);

    // 可见性：创建现存产品 fedora 后，白名单外 → 全排除；白名单内 → 全量。
    store
        .create_product(CreateProductInput {
            name: "fedora",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: VISIBILITY_PUBLIC,
            config: &crate::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("build scoped count test"),
        })
        .await
        .unwrap();
    let counts = store
        .count_builds_by_phase_scoped(Some(&["other".to_string()]), None, None, None)
        .await
        .unwrap();
    assert!(counts.is_empty(), "non-visible builds must be excluded");
    let counts = store
        .count_builds_by_phase_scoped(Some(&["fedora".to_string()]), None, None, None)
        .await
        .unwrap();
    assert_eq!(phase_count(&counts, "succeeded"), 2);
    assert_eq!(phase_count(&counts, "failed"), 1);
}

/// `recent_succeeded_build_durations`（构建时长条形图）：只取带 duration 的
/// succeeded 行、completed_at DESC、limit 截断、user/product/可见性 scope 过滤。
#[tokio::test]
async fn test_recent_succeeded_build_durations_scopes() {
    let (store, _tmp) = create_test_store().await;

    // 直插 succeeded 构建并补 duration/completed_at（insert_build 不写终态字段）。
    let ago = |m: i64| {
        (chrono::Utc::now() - chrono::TimeDelta::minutes(m))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    };
    for (pkg, arch, product, user, mins_ago, dur) in [
        // fedora/op：三条 succeeded，完成时间递减（vim 最新）。
        ("vim-9.1-1", "x86_64", "fedora", "op", 10, 612),
        ("httpd-2.4-1", "aarch64", "fedora", "op", 60, 1300),
        ("bash-5.2-1", "x86_64", "fedora", "bob", 1440, 95),
        ("my-pkg-1", "x86_64", "mydist", "op", 30, 42),
    ] {
        let task_id = seed_task(&store, product, pkg).await;
        let id = store
            .insert_build(BuildInsert {
                product,
                pkg_name: pkg,
                phase: "succeeded",
                arch: Some(arch),
                user,
                task_id: Some(task_id),
                ..Default::default()
            })
            .await
            .unwrap();
        sqlx::query(
            "UPDATE builds SET completed_at = $1, duration = $2, started_at = $3 WHERE id = $4",
        )
        .bind(ago(mins_ago))
        .bind(dur)
        .bind(ago(mins_ago + 10))
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    }
    // 干扰行：failed 带 duration、succeeded 无 duration——都必须被排除。
    let failed_task = seed_task(&store, "fedora", "kernel-6.12-1").await;
    let failed_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "kernel-6.12-1",
            phase: "failed",
            arch: Some("x86_64"),
            user: "op",
            task_id: Some(failed_task),
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET completed_at = $1, duration = $2 WHERE id = $3")
        .bind(ago(5))
        .bind(999)
        .bind(failed_id)
        .execute(store.pool())
        .await
        .unwrap();
    let null_dur_task = seed_task(&store, "fedora", "no-dur-1").await;
    let null_dur_id = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "no-dur-1",
            phase: "succeeded",
            arch: Some("x86_64"),
            user: "op",
            task_id: Some(null_dur_task),
            ..Default::default()
        })
        .await
        .unwrap();
    sqlx::query("UPDATE builds SET completed_at = $1 WHERE id = $2")
        .bind(ago(3))
        .bind(null_dur_id)
        .execute(store.pool())
        .await
        .unwrap();

    let samples = store
        .recent_succeeded_build_durations(None, 15)
        .await
        .unwrap();
    let names: Vec<&str> = samples.iter().map(|s| s.pkg_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["vim-9.1-1", "my-pkg-1", "httpd-2.4-1", "bash-5.2-1"]
    );
    assert_eq!(samples[0].duration_secs, 612);
    assert_eq!(samples[0].arch, "x86_64");
    let samples = store
        .recent_succeeded_build_durations(None, 2)
        .await
        .unwrap();
    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].pkg_name, "vim-9.1-1");

    let samples = store
        .recent_succeeded_build_durations_for_user("op", 15)
        .await
        .unwrap();
    assert_eq!(samples.len(), 3);
    assert_eq!(samples[2].pkg_name, "httpd-2.4-1");
    let samples = store
        .recent_succeeded_build_durations_for_user("bob", 15)
        .await
        .unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].pkg_name, "bash-5.2-1");

    let samples = store
        .recent_succeeded_build_durations_for_product("fedora", 15)
        .await
        .unwrap();
    assert_eq!(samples.len(), 3);
    assert!(samples.iter().all(|s| s.pkg_name != "my-pkg-1"));

    // 可见性：创建现存产品后白名单 Some(["mydist"]) 只剩 mydist 行（fedora 脱离孤儿被排除）。
    store
        .create_product(CreateProductInput {
            name: "fedora",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: VISIBILITY_PUBLIC,
            config: &crate::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("duration visibility test"),
        })
        .await
        .unwrap();
    store
        .create_product(CreateProductInput {
            name: "mydist",
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: VISIBILITY_PUBLIC,
            config: &crate::config::ProductConfig::default(),
            changed_by_user_id: None,
            reason: Some("duration visibility test"),
        })
        .await
        .unwrap();
    let samples = store
        .recent_succeeded_build_durations(Some(&["mydist".to_string()]), 15)
        .await
        .unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].pkg_name, "my-pkg-1");
}

/// 复现血缘（双向）：复现任务 builds.request_json 的 reproduce_from_build_id
/// 指向源任务子构建；多架构复现的多条指向去重为单条 replays；普通任务双向
/// 皆空。源任务取最小源 build id（ORDER BY src.id LIMIT 1）。
#[tokio::test]
async fn task_lineage_resolves_both_directions() {
    let (store, _tmp) = create_test_store().await;

    let src_task = seed_task(&store, "fedora", "lineage-src").await;
    let b_x86 = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "lineage-src",
            phase: "succeeded",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(src_task),
            ..Default::default()
        })
        .await
        .unwrap();
    let b_arm = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "lineage-src",
            phase: "succeeded",
            backend: "chroot",
            user: "test",
            arch: Some("aarch64"),
            task_id: Some(src_task),
            ..Default::default()
        })
        .await
        .unwrap();

    let replay_task = seed_task(&store, "fedora", "lineage-rp").await;
    for (src_build, arch) in [(b_x86, "x86_64"), (b_arm, "aarch64")] {
        let rb = store
            .insert_build(BuildInsert {
                product: "fedora",
                pkg_name: "lineage-rp",
                phase: "succeeded",
                backend: "chroot",
                user: "test",
                arch: Some(arch),
                task_id: Some(replay_task),
                ..Default::default()
            })
            .await
            .unwrap();
        store
            .set_build_request_info(
                rb,
                "/tmp/lineage.src.rpm",
                &format!(r#"{{"reproduce_from_build_id": {src_build}}}"#),
            )
            .await
            .unwrap();
    }

    let lin = store.task_lineage(replay_task).await.unwrap();
    let src = lin.replay_source.expect("replay task must carry source");
    assert_eq!((src.build_id, src.task_id), (b_x86, src_task));
    assert!(lin.replays.is_empty(), "复现任务自身无被复现记录");

    let lin = store.task_lineage(src_task).await.unwrap();
    assert!(lin.replay_source.is_none());
    assert_eq!(lin.replays.len(), 1, "多架构指向去重为单任务");
    assert_eq!(lin.replays[0].task_id, replay_task);
    // phase 取任务行（t.phase），非子构建行；seed_task 落 pending。
    assert_eq!(lin.replays[0].phase, "pending");

    let plain_task = seed_task(&store, "fedora", "lineage-plain").await;
    let lin = store.task_lineage(plain_task).await.unwrap();
    assert!(lin.replay_source.is_none());
    assert!(lin.replays.is_empty());
}

/// 血缘查询对畸形 request_json 免疫：提取表达式包在 CASE/LIKE 守卫里，
/// 脏行（非 JSON 文本）不得让任务详情查询报 cast/解析错误。
#[tokio::test]
async fn task_lineage_tolerates_malformed_request_json() {
    let (store, _tmp) = create_test_store().await;

    let task = seed_task(&store, "fedora", "lineage-dirty").await;
    let b = store
        .insert_build(BuildInsert {
            product: "fedora",
            pkg_name: "lineage-dirty",
            phase: "succeeded",
            backend: "chroot",
            user: "test",
            arch: Some("x86_64"),
            task_id: Some(task),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(b, "/tmp/lineage-dirty.src.rpm", "not json{{{")
        .await
        .unwrap();

    let lin = store.task_lineage(task).await.unwrap();
    assert!(lin.replay_source.is_none());
    assert!(lin.replays.is_empty());
}

/// noarch 宿主约束领取谓词三态：host_arches 非成员架构对 noarch 行不可见、
/// 成员架构可领、NULL 行任意可领（谓词单源在指定 CAS 领取 SQL）。
#[tokio::test]
async fn noarch_host_arches_gates_specific_claim() {
    let (store, _tmp) = create_test_store().await;
    let loong = store
        .upsert_worker("loong-a", "loongarch64", 8, "test", "online", None)
        .await
        .unwrap();
    let x86 = store
        .upsert_worker("x86-a", "x86_64", 8, "test", "online", None)
        .await
        .unwrap();

    // noarch 行先建（等待权重更高、排序在前）：loong worker 的领取若未被谓词
    // 排除，会选中它并空手而归——队头阻塞的判别形态。
    let task_id = seed_task(&store, "noarch-gate", "mydist").await;
    let noarch_build = store
        .insert_build(BuildInsert {
            product: "noarch-gate",
            pkg_name: "mydist",
            phase: "pending",
            backend: "chroot",
            user: "test",
            arch: Some("noarch"),
            host_arches: Some("x86_64,aarch64"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(noarch_build, "/tmp/mydist.src.rpm", "{}")
        .await
        .unwrap();

    // 非成员架构对钉宿主 noarch 行不可见。
    assert!(
        store
            .assign_specific_build_to_worker(noarch_build, loong)
            .await
            .unwrap()
            .is_none(),
        "non-member arch must not see the gated noarch row"
    );
    // 成员架构可领。
    let claimed = store
        .assign_specific_build_to_worker(noarch_build, x86)
        .await
        .unwrap()
        .expect("member arch must claim the gated noarch row");
    assert_eq!(claimed.build_id, noarch_build);

    // 队头不阻塞：重摆 noarch 行（再次 pending）+ 一条 loong 架构行，noarch
    // 在前，loong worker 必须越过它领到自己的架构行。
    let task2 = seed_task(&store, "noarch-gate", "mydist2").await;
    let noarch2 = store
        .insert_build(BuildInsert {
            product: "noarch-gate",
            pkg_name: "mydist2",
            phase: "pending",
            backend: "chroot",
            user: "test",
            arch: Some("noarch"),
            host_arches: Some("x86_64"),
            task_id: Some(task2),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(noarch2, "/tmp/mydist2.src.rpm", "{}")
        .await
        .unwrap();
    let loong_build = store
        .insert_build(BuildInsert {
            product: "noarch-gate",
            pkg_name: "mydist-loong",
            phase: "pending",
            backend: "chroot",
            user: "test",
            arch: Some("loongarch64"),
            task_id: Some(task2),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(loong_build, "/tmp/mydist-loong.src.rpm", "{}")
        .await
        .unwrap();

    let picked = store
        .assign_specific_build_to_worker(loong_build, loong)
        .await
        .unwrap()
        .expect("loong worker must claim its own arch row past the gated noarch");
    assert_eq!(
        picked.build_id, loong_build,
        "gated noarch must not block own-arch claim"
    );

    // NULL = 不限制：任意架构可领。
    let task3 = seed_task(&store, "noarch-gate", "mydist3").await;
    let open_noarch = store
        .insert_build(BuildInsert {
            product: "noarch-gate",
            pkg_name: "mydist3",
            phase: "pending",
            backend: "chroot",
            user: "test",
            arch: Some("noarch"),
            task_id: Some(task3),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(open_noarch, "/tmp/mydist3.src.rpm", "{}")
        .await
        .unwrap();
    let open_claimed = store
        .assign_specific_build_to_worker(open_noarch, loong)
        .await
        .unwrap()
        .expect("NULL host_arches must stay claimable by any arch");
    assert_eq!(open_claimed.build_id, open_noarch);
}

/// build_host_arch 与子构建摘要 worker 透出：最新 build 型归属定宿主，摘要
/// JOIN 出 worker 名，无归属为 None。
#[tokio::test]
async fn build_host_arch_and_summary_worker_attribution() {
    let (store, _tmp) = create_test_store().await;
    let worker = store
        .upsert_worker("sw-a", "sw_64", 8, "test", "online", None)
        .await
        .unwrap();

    let task_id = seed_task(&store, "host-arch", "mydist").await;
    let build_id = store
        .insert_build(BuildInsert {
            product: "host-arch",
            pkg_name: "mydist",
            phase: "pending",
            backend: "chroot",
            user: "test",
            arch: Some("noarch"),
            task_id: Some(task_id),
            ..Default::default()
        })
        .await
        .unwrap();
    store
        .set_build_request_info(build_id, "/tmp/mydist.src.rpm", "{}")
        .await
        .unwrap();

    // 无归属：宿主反查 None、摘要 worker None。
    assert!(store.build_host_arch(build_id).await.unwrap().is_none());
    let summaries = store.get_child_build_summaries(task_id).await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert!(summaries[0].worker.is_none());

    // 领取后：宿主 = 领取 worker 绑定架构，摘要透出 worker 名。
    store
        .assign_specific_build_to_worker(build_id, worker)
        .await
        .unwrap()
        .expect("worker must claim the open noarch row");
    assert_eq!(
        store.build_host_arch(build_id).await.unwrap().as_deref(),
        Some("sw_64")
    );
    let summaries = store.get_child_build_summaries(task_id).await.unwrap();
    assert_eq!(summaries[0].worker.as_deref(), Some("sw-a"));
}
