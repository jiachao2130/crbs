// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Bootstrap seed：磁盘 `products/*.toml` 一次性导入 DB，仅官方产品。
//!
//! 契约：
//! - **两阶段**：全部 `.toml` 先 parse 进内存，任一失败整体放弃，DB 一行不写。
//! - **all-in-one-tx**：产品行 + revision=1 history + `app_meta` 门闩同事务，无中间态。
//! - **门闩语义**：`app_meta['products_seeded_at']` 非空 ⇒ no-op（不用空表判断，防清空后回填）。
//! - **只种官方产品**：`owner_id = NULL`、`visibility = 'public'` 显式传（不依赖 DEFAULT）；
//!   私人产品走独立创建路径（fork/CLI/API）。
//! - **slug 校验** `^[a-z0-9_-]+$`：违规中止不静默跳过（静默 = 产品凭空消失，
//!   dispatch fail-closed 报错离根因极远）。
//! - **同名跳过**：DB 已有 ⇒ warn + 跳过磁盘副本，门闩照常写；与 parse/slug
//!   中止不同——磁盘非法才中止，DB 已有权威数据，覆盖才是错。
//! - **并发竞态**：唯一键冲突（产品名/门闩 key）按对方已写处理（跳过/视为已 seed），不中止启动。
//! - **错误上报**：`Err` 带文件路径+原因；tracing 仅用于 skip；退出与否归调用方。

use std::path::Path;

use crate::config::ProductConfig;
use crate::error::CrbsError;
use crate::error::DbResultExt;
use crate::state::products::{
    insert_product_and_history_tx, is_unique_violation_msg, CreateProductInput,
};
use crate::state::rollback_and_return;
use crate::state::StateStore;

mod sql {
    pub(super) const SEED_GATE_KEY: &str = "products_seeded_at";

    pub(super) const SELECT_SEED_GATE: &str = "SELECT value FROM app_meta WHERE key = $1";

    pub(super) const INSERT_SEED_GATE: &str = "INSERT INTO app_meta (key, value) VALUES ($1, $2)";

    pub(super) const SELECT_PRODUCT_EXISTS: &str = "SELECT id FROM products WHERE name = $1";
}

impl StateStore {
    /// 从磁盘目录导入官方产品。幂等：门闩已设 ⇒ no-op。
    /// 触发点：server bootstrap 在状态库版本闩（ensure_schema）后、listener
    /// 就绪前——接客时 products 要么 seed 完整，要么启动因 seed 失败退出。
    ///
    /// # 错误
    /// 目录不存在/不可读 → `Io`（带路径）；slug 非法 / toml parse 失败 →
    /// `ValidationFailed`（带文件路径）；DB/事务失败 → `Database`；任一情况
    /// DB 保持 pre-call 状态（未启动或已回滚），修复文件后重启即可重试。
    pub async fn seed_products_from_dir(&self, dir: &Path) -> crate::Result<()> {
        let gate: Option<String> = sqlx::query_scalar(sql::SELECT_SEED_GATE)
            .bind(sql::SEED_GATE_KEY)
            .fetch_optional(self.pool())
            .await
            .db_ctx("select seed gate")?;
        if let Some(ts) = gate {
            tracing::debug!(
                seeded_at = %ts,
                dir = %dir.display(),
                "seed_products_from_dir: gate already set, skipping"
            );
            return Ok(());
        }

        let parsed = parse_products_dir(dir).await?;

        if parsed.is_empty() {
            // 空目录不设门闩：日后塞 toml 重启仍可 seed，设了就永久堵死。
            tracing::info!(
                dir = %dir.display(),
                "seed_products_from_dir: no product toml files found; gate not set"
            );
            return Ok(());
        }

        let mut inserted = 0_usize;

        // 单事务：所有产品 + 每条 history + 门闩。begin_write()（SQLite BEGIN IMMEDIATE；
        // PG 行为不变）先取写锁，防 DEFERRED 下并发 seed 读后升写锁撞 SQLITE_BUSY_SNAPSHOT。
        let mut conn = self.begin_write().await.db_ctx("seed begin write tx")?;

        // BEGIN 后任何错误（含 COMMIT 自身失败）先 ROLLBACK，防持写锁/污染的连接回池。
        for (slug, config) in &parsed {
            // DB 已有同名（人工导入/旧库恢复）：warn + 跳过，不覆盖、不失败。
            let exists: Option<i64> = match sqlx::query_scalar(sql::SELECT_PRODUCT_EXISTS)
                .bind(slug)
                .fetch_optional(&mut *conn)
                .await
                .db_ctx("seed check product exists")
            {
                Ok(v) => v,
                Err(e) => rollback_and_return!(conn, e),
            };
            if exists.is_some() {
                tracing::warn!(
                    product = %slug,
                    "seed: product already exists in DB, skipping disk copy"
                );
                continue;
            }

            // 手动事务内不得用 `?`（会跳过 ROLLBACK 回池带事务连接）。
            let config_json =
                match serde_json::to_string(config).db_ctx(&format!("seed serialize {}", slug)) {
                    Ok(s) => s,
                    Err(e) => rollback_and_return!(conn, e),
                };
            let input = CreateProductInput {
                name: slug,
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public", // 官方 = public，显式传（不依赖 DEFAULT 'private'）
                config,
                changed_by_user_id: None,
                reason: Some("seeded from disk"),
            };
            match insert_product_and_history_tx(&mut conn, &input, &config_json).await {
                Ok(_) => inserted += 1,
                // 竞态：SELECT-INSERT 间隙对方已提交同名（唯一键冲突归一 AlreadyExists）。
                Err(CrbsError::AlreadyExists { .. }) => {
                    tracing::warn!(
                        product = %slug,
                        "seed: product inserted by concurrent seed, skipping disk copy"
                    );
                    continue;
                }
                Err(e) => rollback_and_return!(conn, e),
            }
        }

        let now = chrono::Utc::now().to_rfc3339();
        match sqlx::query(sql::INSERT_SEED_GATE)
            .bind(sql::SEED_GATE_KEY)
            .bind(&now)
            .execute(&mut *conn)
            .await
        {
            Ok(_) => {}
            // 竞态收口：门闩 key 撞唯一键 = 对方已 seed；ROLLBACK，按已 seed 返回，不中止启动。
            Err(e) if is_unique_violation_msg(&e.to_string()) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                tracing::warn!("seed: gate already set by concurrent seed, treating as seeded");
                return Ok(());
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(e).db_ctx("insert seed gate");
            }
        }

        match sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .db_ctx("seed commit")
        {
            Ok(_) => {}
            Err(e) => rollback_and_return!(conn, e),
        }

        tracing::info!(
            count = inserted,
            dir = %dir.display(),
            "seed_products_from_dir: seeded products from disk"
        );
        Ok(())
    }
}

/// 遍历目录、跳过非 `.toml`/子目录、校验 slug、逐个 parse 到 `(slug, ProductConfig)`。
/// 按文件名排序（BTreeMap 内自然有序）保证 seed 后的 id 顺序稳定，便于测试与运维辨识。
async fn parse_products_dir(dir: &Path) -> crate::Result<Vec<(String, ProductConfig)>> {
    use std::collections::BTreeMap;

    // 目录不存在视同空目录（fresh deploy 合理场景）：不写门闩，日后放 toml 重启仍可 seed。
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                dir = %dir.display(),
                "seed: products dir does not exist; treating as empty (no gate set)"
            );
            return Ok(Vec::new());
        }
        Err(e) => {
            return Err(CrbsError::from_io_context(
                format!("read products dir {}", dir.display()),
                e,
            ));
        }
    };

    let mut parsed: BTreeMap<String, ProductConfig> = BTreeMap::new();

    while let Some(entry) = entries.next_entry().await.map_err(|e| {
        CrbsError::from_io_context(format!("iterate products dir {}", dir.display()), e)
    })? {
        let path = entry.path();
        // 用 metadata（stat 语义，跟随 symlink）：指向文件的链接照常 seed，目录/
        // 断链仍跳过；entry.file_type() 是 lstat 语义，会把 symlink 静默跳过。
        let ft = match tokio::fs::metadata(&path).await {
            Ok(m) => m.file_type(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    path = %path.display(),
                    "seed: skipping broken symlink / missing entry"
                );
                continue;
            }
            Err(e) => {
                return Err(CrbsError::from_io_context(
                    format!("file_type {}", path.display()),
                    e,
                ));
            }
        };

        if !ft.is_file() {
            tracing::warn!(
                path = %path.display(),
                "seed: skipping non-file entry (subdir/other)"
            );
            continue;
        }

        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            tracing::warn!(
                path = %path.display(),
                "seed: skipping entry (not a .toml)"
            );
            continue;
        }

        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => {
                return Err(CrbsError::ValidationFailed {
                    message: format!("seed: cannot derive slug from filename {}", path.display()),
                });
            }
        };
        // 规则在 crate::validation::is_valid_slug；故意从严：过宽字符集在 dispatch/URL/日志添乱。
        if !crate::validation::is_valid_slug(&stem) {
            return Err(CrbsError::ValidationFailed {
                message: format!(
                    "seed: invalid product slug '{}' (allowed: [a-z0-9_-]+): {}",
                    stem,
                    path.display()
                ),
            });
        }

        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| CrbsError::from_io_context(format!("read {}", path.display()), e))?;
        let config: ProductConfig =
            toml::from_str(&content).map_err(|e| CrbsError::ValidationFailed {
                message: format!("seed: parse {}: {}", path.display(), e),
            })?;

        if parsed.insert(stem.clone(), config).is_some() {
            return Err(CrbsError::ValidationFailed {
                message: format!("seed: duplicate slug '{}' in {}", stem, dir.display()),
            });
        }
    }

    Ok(parsed.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn fresh_store() -> (StateStore, TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let store = StateStore::new_with_db_path(&tmp.path().join("state.db"), tmp.path())
            .await
            .unwrap();
        (store, tmp)
    }

    fn write_toml(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    /// 读 seed 门闩（app_meta.products_seeded_at）；None = 未 seed。
    async fn read_gate(store: &StateStore) -> Option<String> {
        sqlx::query_scalar(sql::SELECT_SEED_GATE)
            .bind(sql::SEED_GATE_KEY)
            .fetch_optional(store.pool())
            .await
            .unwrap()
    }

    const VALID_TOML_A: &str = r#"
base_packages = ["bash", "gcc"]
[[repos]]
name = "base"
baseurl = "http://example/repo/a"
"#;

    const VALID_TOML_B: &str = r#"
base_packages = ["bash"]
[[repos]]
name = "base"
baseurl = "http://example/repo/b"
"#;

    const BAD_TOML: &str = r#"
base_packages = ["bash"
# missing closing bracket
[[repos]]
"#;

    #[tokio::test]
    async fn seed_persists_products_history_and_gate_in_one_tx() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "mydist.toml", VALID_TOML_A);
        write_toml(dir.path(), "openeuler.toml", VALID_TOML_B);

        store.seed_products_from_dir(dir.path()).await.unwrap();

        let list = store.list_products().await.unwrap();
        assert_eq!(list.len(), 2);
        let names: Vec<&str> = list.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"mydist"));
        assert!(names.contains(&"openeuler"));

        for stub in &list {
            assert_eq!(stub.owner_id, None);
            assert_eq!(stub.visibility, "public");
            assert_eq!(stub.revision, 1);
            assert_eq!(stub.base_os_revision, 1);
        }

        for stub in &list {
            let hist = store.list_product_history(stub.id).await.unwrap();
            assert_eq!(hist.len(), 1);
            assert_eq!(hist[0].revision, 1);
            assert_eq!(hist[0].reason.as_deref(), Some("seeded from disk"));
            assert_eq!(hist[0].changed_by_user_id, None);
        }

        let gate = read_gate(&store).await;
        assert!(gate.is_some(), "seed gate must be set");
    }

    #[tokio::test]
    async fn seed_partial_failure_leaves_no_rows_and_no_gate() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "a.toml", VALID_TOML_A);
        write_toml(dir.path(), "b.toml", BAD_TOML);
        write_toml(dir.path(), "c.toml", VALID_TOML_B);

        let err = store.seed_products_from_dir(dir.path()).await.unwrap_err();
        assert!(
            matches!(err, CrbsError::ValidationFailed { .. }),
            "expected ValidationFailed, got {:?}",
            err
        );
        assert!(store.list_products().await.unwrap().is_empty());
        let gate = read_gate(&store).await;
        assert!(gate.is_none(), "gate must not be set on partial failure");
    }

    /// 可恢复性契约：半失败不写脏门闩，修好 toml 重试即可完整成功。
    #[tokio::test]
    async fn seed_recovers_after_operator_fixes_bad_toml() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "a.toml", VALID_TOML_A);
        write_toml(dir.path(), "b.toml", BAD_TOML);

        let err = store.seed_products_from_dir(dir.path()).await.unwrap_err();
        assert!(matches!(err, CrbsError::ValidationFailed { .. }));
        assert!(store.list_products().await.unwrap().is_empty());

        std::fs::write(dir.path().join("b.toml"), VALID_TOML_B).unwrap();
        store.seed_products_from_dir(dir.path()).await.unwrap();

        let list = store.list_products().await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn seed_is_idempotent_when_gate_set() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "a.toml", VALID_TOML_A);

        store.seed_products_from_dir(dir.path()).await.unwrap();
        assert_eq!(store.list_products().await.unwrap().len(), 1);

        write_toml(dir.path(), "b.toml", VALID_TOML_B);
        store.seed_products_from_dir(dir.path()).await.unwrap();
        assert_eq!(
            store.list_products().await.unwrap().len(),
            1,
            "second seed call must be a no-op once gate is set"
        );
    }

    /// DB 已有同名产品：跳过磁盘副本，seed 整体成功、门闩照常写、不覆盖已有产品。
    #[tokio::test]
    async fn seed_skips_product_already_in_db() {
        let (store, _tmp) = fresh_store().await;

        // 预置同名产品，reason 与磁盘 seed 的 "seeded from disk" 不同，便于区分来源
        store
            .create_product(CreateProductInput {
                name: "dup",
                display_name: None,
                owner_id: None,
                parent_id: None,
                visibility: "public",
                config: &ProductConfig::default(),
                changed_by_user_id: None,
                reason: Some("pre-existing manual import"),
            })
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "dup.toml", VALID_TOML_A);
        write_toml(dir.path(), "other.toml", VALID_TOML_B);

        store.seed_products_from_dir(dir.path()).await.unwrap();

        let dup = store.get_product_by_name("dup").await.unwrap().unwrap();
        let hist = store.list_product_history(dup.id).await.unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(
            hist[0].reason.as_deref(),
            Some("pre-existing manual import"),
            "existing DB product must not be overwritten by disk copy"
        );

        let list = store.list_products().await.unwrap();
        assert_eq!(list.len(), 2);

        let gate = read_gate(&store).await;
        assert!(
            gate.is_some(),
            "gate must be set even when some products were skipped"
        );
    }

    #[tokio::test]
    async fn seed_rejects_invalid_slug() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "Foo Bar.toml", VALID_TOML_A);

        let err = store.seed_products_from_dir(dir.path()).await.unwrap_err();
        match err {
            CrbsError::ValidationFailed { message } => {
                assert!(message.contains("invalid product slug"), "got: {}", message);
                assert!(message.contains("Foo Bar"), "got: {}", message);
            }
            other => panic!("expected ValidationFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn seed_skips_non_toml_and_subdirs() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        write_toml(dir.path(), "mydist.toml", VALID_TOML_A);
        write_toml(dir.path(), "README.md", "not a product");
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        write_toml(&dir.path().join("subdir"), "nested.toml", VALID_TOML_B);

        store.seed_products_from_dir(dir.path()).await.unwrap();
        let list = store.list_products().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "mydist");
    }

    /// 指向有效 toml 的 symlink 必须被 seed（entry.file_type() 的 lstat 语义会静默跳过）。
    #[cfg(unix)]
    #[tokio::test]
    async fn seed_follows_symlinked_toml() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        let real = tempfile::tempdir().unwrap();
        write_toml(real.path(), "mydist.toml", VALID_TOML_A);
        std::os::unix::fs::symlink(
            real.path().join("mydist.toml"),
            dir.path().join("mydist.toml"),
        )
        .unwrap();

        store.seed_products_from_dir(dir.path()).await.unwrap();
        let list = store.list_products().await.unwrap();
        assert_eq!(list.len(), 1, "symlinked toml must be seeded");
        assert_eq!(list[0].name, "mydist");

        let gate = read_gate(&store).await;
        assert!(gate.is_some(), "symlink-seeded products must set the gate");
    }

    /// 断链 / 指向目录的链接不是产品文件：warn 跳过，不算产品也不设门闩。
    #[cfg(unix)]
    #[tokio::test]
    async fn seed_skips_broken_symlink_and_symlinked_dir() {
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::os::unix::fs::symlink(
            "/nonexistent/crbs-seed-test-broken.toml",
            dir.path().join("broken.toml"),
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.path().join("subdir"), dir.path().join("dirlink.toml"))
            .unwrap();

        store.seed_products_from_dir(dir.path()).await.unwrap();
        assert!(
            store.list_products().await.unwrap().is_empty(),
            "broken symlink / symlinked dir must not be seeded"
        );
    }

    #[tokio::test]
    async fn seed_missing_dir_treated_as_empty() {
        // Fresh deploy/测试环境未创建 products 目录：视同空目录、不设门闩。
        let (store, _tmp) = fresh_store().await;
        let missing = Path::new("/nonexistent/crbs-seed-test-does-not-exist");
        store.seed_products_from_dir(missing).await.unwrap();
        assert!(store.list_products().await.unwrap().is_empty());
        let gate = read_gate(&store).await;
        assert!(gate.is_none(), "gate must not be set for missing dir");
    }

    #[tokio::test]
    async fn seed_empty_dir_does_not_set_gate() {
        // 空目录不设门闩：日后塞 toml 重启仍会 seed。
        let (store, _tmp) = fresh_store().await;
        let dir = tempfile::tempdir().unwrap();
        store.seed_products_from_dir(dir.path()).await.unwrap();
        assert!(store.list_products().await.unwrap().is_empty());
        let gate = read_gate(&store).await;
        assert!(gate.is_none());

        write_toml(dir.path(), "mydist.toml", VALID_TOML_A);
        store.seed_products_from_dir(dir.path()).await.unwrap();
        assert_eq!(store.list_products().await.unwrap().len(), 1);
    }

    #[test]
    fn slug_validator_rules() {
        use crate::validation::is_valid_slug;
        assert!(is_valid_slug("mydist"));
        assert!(is_valid_slug("openeuler-24_03"));
        assert!(is_valid_slug("a"));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("Foo"));
        assert!(!is_valid_slug("a.b"));
        assert!(!is_valid_slug("a b"));
        assert!(!is_valid_slug("a/b"));
        assert!(!is_valid_slug("a\nb"));
    }
}
