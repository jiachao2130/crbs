// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `app_meta` KV 读写：运行时可变开关的泛型 get/set 收口。键包括 seed 门闩
//! `products_seeded_at` 与注册开关 `registration_enabled`（'true'/'false'，缺省视为 false）。

use super::StateStore;
use crate::error::DbResultExt;

mod sql {
    pub(super) const SELECT_APP_META: &str = "SELECT value FROM app_meta WHERE key = $1";

    /// upsert：`app_meta.key` 是 PK，双方言同语义。
    pub(super) const UPSERT_APP_META: &str = "INSERT INTO app_meta (key, value) VALUES ($1, $2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value";

    pub(super) const DELETE_APP_META: &str = "DELETE FROM app_meta WHERE key = $1";

    /// 前缀扫键；调用方前缀不得含 SQL LIKE 通配符（`%`/`_`），`%` 由本处追加。
    pub(super) const SELECT_APP_META_KEYS_BY_PREFIX: &str =
        "SELECT key FROM app_meta WHERE key LIKE $1";
}

impl StateStore {
    /// 读取 `app_meta` 键值；不存在返回 `None`。
    pub async fn get_app_meta(&self, key: &str) -> crate::Result<Option<String>> {
        sqlx::query_scalar(sql::SELECT_APP_META)
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .db_ctx("get app_meta")
    }

    /// 写入（upsert）`app_meta` 键值。
    pub async fn set_app_meta(&self, key: &str, value: &str) -> crate::Result<()> {
        sqlx::query(sql::UPSERT_APP_META)
            .bind(key)
            .bind(value)
            .execute(self.pool())
            .await
            .db_ctx("set app_meta")?;
        Ok(())
    }

    /// 删除 `app_meta` 键；键不存在时为无操作。
    pub async fn delete_app_meta(&self, key: &str) -> crate::Result<()> {
        sqlx::query(sql::DELETE_APP_META)
            .bind(key)
            .execute(self.pool())
            .await
            .db_ctx("delete app_meta")?;
        Ok(())
    }

    /// 列出匹配前缀的全部键（GC/对账用；结果集预期很小）。
    pub async fn list_app_meta_keys_by_prefix(&self, prefix: &str) -> crate::Result<Vec<String>> {
        let pattern = format!("{prefix}%");
        sqlx::query_scalar(sql::SELECT_APP_META_KEYS_BY_PREFIX)
            .bind(pattern)
            .fetch_all(self.pool())
            .await
            .db_ctx("list app_meta by prefix")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn store() -> (StateStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        (StateStore::new(tmp.path()).await.unwrap(), tmp)
    }

    /// 缺键返回 None；写入后可读回；upsert 覆盖旧值。
    #[tokio::test]
    async fn app_meta_roundtrip_and_upsert() {
        let (store, _tmp) = store().await;
        assert_eq!(
            store.get_app_meta("registration_enabled").await.unwrap(),
            None
        );

        store
            .set_app_meta("registration_enabled", "false")
            .await
            .unwrap();
        assert_eq!(
            store.get_app_meta("registration_enabled").await.unwrap(),
            Some("false".to_string())
        );

        store
            .set_app_meta("registration_enabled", "true")
            .await
            .unwrap();
        assert_eq!(
            store.get_app_meta("registration_enabled").await.unwrap(),
            Some("true".to_string())
        );
    }

    /// 与 seed 门闩同表共存：不同 key 互不干扰。
    #[tokio::test]
    async fn app_meta_keys_are_independent() {
        let (store, _tmp) = store().await;
        store.set_app_meta("a", "1").await.unwrap();
        store.set_app_meta("b", "2").await.unwrap();
        assert_eq!(store.get_app_meta("a").await.unwrap().as_deref(), Some("1"));
        assert_eq!(store.get_app_meta("b").await.unwrap().as_deref(), Some("2"));
        assert_eq!(store.get_app_meta("c").await.unwrap(), None);
    }

    /// delete 后读回 None；删不存在的键是无操作；前缀列键只含匹配键。
    #[tokio::test]
    async fn app_meta_delete_and_prefix_listing() {
        let (store, _tmp) = store().await;
        store.set_app_meta("batch:hb:1", "1").await.unwrap();
        store.set_app_meta("batch:hb:2", "2").await.unwrap();
        store.set_app_meta("other", "x").await.unwrap();

        store.delete_app_meta("batch:hb:1").await.unwrap();
        assert_eq!(store.get_app_meta("batch:hb:1").await.unwrap(), None);
        store.delete_app_meta("batch:hb:1").await.unwrap();

        let mut keys = store
            .list_app_meta_keys_by_prefix("batch:hb:")
            .await
            .unwrap();
        keys.sort();
        assert_eq!(keys, vec!["batch:hb:2".to_string()]);
    }
}
