// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! DB-backed UI 会话存储。与 `user_tokens` 同模式：明文 `crbs_sess_` 仅
//! 生成时存在（一次性随登录响应返回），DB 只存 SHA-256 hash；撤销 = `revoked_at` 置位
//!（行保留，认证侧判无效）。时间列均 TEXT 且写入统一 UTC（方言 `sql_now()` / 应用 RFC3339）。

use super::StateStore;
use crate::error::DbResultExt;

mod sql {
    use crate::state::Dialect;

    /// 过期判定按 TEXT 字典序：写入方统一 RFC3339 UTC（`to_rfc3339()`），同格式字典序即时间序
    ///（AutoSi 的 `.xxx` 亚秒变体与整秒 `Z` 混排时不严格单调——crbs 写入方恒整秒，不触此边界）。
    pub(super) const INSERT_SESSION: &str =
        "INSERT INTO sessions (user_id, hash, expires_at, agent) VALUES ($1, $2, $3, $4) \
         RETURNING id";

    pub(super) const SELECT_SESSION_BY_HASH: &str =
        "SELECT id, user_id, hash, created_at, expires_at, revoked_at, agent \
         FROM sessions WHERE hash = $1";

    pub(super) const LIST_SESSIONS_BY_USER: &str =
        "SELECT id, user_id, hash, created_at, expires_at, revoked_at, agent \
         FROM sessions WHERE user_id = $1 ORDER BY id";

    /// 撤销会话（方言感知时间戳）；幂等置位，不覆盖已置位 revoked_at（保留首次撤销时间审计值）。
    pub(super) fn revoke_session(dialect: Dialect) -> String {
        format!(
            "UPDATE sessions SET revoked_at = {} WHERE id = $1 AND revoked_at IS NULL",
            dialect.sql_now()
        )
    }

    /// 撤销用户全部会话但保留指定行（改密码连锁撤销）；同样不覆盖已撤销行 revoked_at。
    pub(super) fn revoke_all_user_sessions_except(dialect: Dialect) -> String {
        format!(
            "UPDATE sessions SET revoked_at = {} \
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
            dialect.sql_now()
        )
    }

    pub(super) const DELETE_EXPIRED_USER_SESSIONS: &str =
        "DELETE FROM sessions WHERE user_id = $1 AND expires_at <= $2";

    pub(super) const DELETE_ALL_EXPIRED_SESSIONS: &str =
        "DELETE FROM sessions WHERE expires_at <= $1";
}

/// 会话记录（`hash` 为 `crbs_sess_` 明文的 SHA-256，非机密，可安全展示/索引）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionRecord {
    pub id: i64,
    pub user_id: i64,
    pub hash: String,
    pub created_at: String,
    /// RFC3339 UTC（绝对过期，无滑动续期）。
    pub expires_at: String,
    pub revoked_at: Option<String>,
    /// 登录时的 User-Agent 摘要（UI 会话列表展示用）。
    pub agent: Option<String>,
}

impl SessionRecord {
    /// 是否有效 = `revoked_at` 未置位且未过期；`expires_at` 解析失败按已过期（fail-closed）。
    pub fn is_active(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        match chrono::DateTime::parse_from_rfc3339(&self.expires_at) {
            Ok(exp) => exp.with_timezone(&chrono::Utc) > now,
            Err(_) => false,
        }
    }
}

impl StateStore {
    /// 创建会话，返回会话 ID；`hash` 为明文 SHA-256 hex，`expires_at` 为 RFC3339 UTC，`agent` 为可选 User-Agent 摘要。
    pub async fn create_session(
        &self,
        user_id: i64,
        hash: &str,
        expires_at: &str,
        agent: Option<&str>,
    ) -> crate::Result<i64> {
        let id = sqlx::query_scalar::<_, i64>(sql::INSERT_SESSION)
            .bind(user_id)
            .bind(hash)
            .bind(expires_at)
            .bind(agent)
            .fetch_one(self.pool())
            .await
            .db_ctx("create session")?;
        self.bump_user_generation();
        Ok(id)
    }

    /// 按 hash 查找会话（认证路径）；有效性判定由调用方或 `SessionRecord::is_active` 完成。
    pub async fn find_session_by_hash(&self, hash: &str) -> crate::Result<Option<SessionRecord>> {
        sqlx::query_as::<_, SessionRow>(sql::SELECT_SESSION_BY_HASH)
            .bind(hash)
            .fetch_optional(self.pool())
            .await
            .db_ctx("find session by hash")
            .map(|row| row.map(|r| r.into()))
    }

    /// 列出用户全部会话（/ui/me 会话管理）。
    pub async fn list_user_sessions(&self, user_id: i64) -> crate::Result<Vec<SessionRecord>> {
        sqlx::query_as::<_, SessionRow>(sql::LIST_SESSIONS_BY_USER)
            .bind(user_id)
            .fetch_all(self.pool())
            .await
            .db_ctx("list user sessions")
            .map(|rows| rows.into_iter().map(|r| r.into()).collect())
    }

    /// 撤销单个会话（登出 / 会话管理 Revoke）。置位式，幂等。
    pub async fn revoke_session(&self, session_id: i64) -> crate::Result<()> {
        sqlx::query(&sql::revoke_session(self.dialect))
            .bind(session_id)
            .execute(self.pool())
            .await
            .db_ctx("revoke session")?;
        self.bump_user_generation();
        Ok(())
    }

    /// 撤销用户全部会话但保留当前会话（改密码连锁撤销）。
    pub async fn revoke_all_user_sessions_except(
        &self,
        user_id: i64,
        keep_session_id: i64,
    ) -> crate::Result<()> {
        sqlx::query(&sql::revoke_all_user_sessions_except(self.dialect))
            .bind(user_id)
            .bind(keep_session_id)
            .execute(self.pool())
            .await
            .db_ctx("revoke all user sessions except current")?;
        self.bump_user_generation();
        Ok(())
    }

    /// 撤销用户全部会话（admin 重置密码连锁）：复用 except，keep id 用 `i64::MAX` 哨兵（自增 id 永不达到，等价不保留）。
    pub async fn revoke_all_user_sessions(&self, user_id: i64) -> crate::Result<()> {
        self.revoke_all_user_sessions_except(user_id, i64::MAX)
            .await
    }

    /// 删除该用户的已过期会话行（登录时懒删）。返回删除行数。
    pub async fn delete_expired_user_sessions(
        &self,
        user_id: i64,
        now: &str,
    ) -> crate::Result<u64> {
        let result = sqlx::query(sql::DELETE_EXPIRED_USER_SESSIONS)
            .bind(user_id)
            .bind(now)
            .execute(self.pool())
            .await
            .db_ctx("delete expired user sessions")?;
        Ok(result.rows_affected())
    }

    /// 删除全部已过期会话行（周期清理任务）。返回删除行数。
    pub async fn delete_all_expired_sessions(&self, now: &str) -> crate::Result<u64> {
        let result = sqlx::query(sql::DELETE_ALL_EXPIRED_SESSIONS)
            .bind(now)
            .execute(self.pool())
            .await
            .db_ctx("delete all expired sessions")?;
        Ok(result.rows_affected())
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: i64,
    user_id: i64,
    hash: String,
    created_at: String,
    expires_at: String,
    revoked_at: Option<String>,
    agent: Option<String>,
}

impl From<SessionRow> for SessionRecord {
    fn from(row: SessionRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            hash: row.hash,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            agent: row.agent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::secret::{Secret, SecretKind};

    async fn store() -> (StateStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        (StateStore::new(tmp.path()).await.unwrap(), tmp)
    }

    fn future(days: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339()
    }

    fn past(days: i64) -> String {
        (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339()
    }

    async fn seed_session(store: &StateStore, user_id: i64, expires_at: &str) -> (Secret, i64) {
        let secret = Secret::generate(SecretKind::Session).unwrap();
        let id = store
            .create_session(
                user_id,
                secret.hash().as_str(),
                expires_at,
                Some("test-agent"),
            )
            .await
            .unwrap();
        (secret, id)
    }

    #[tokio::test]
    async fn session_crud_roundtrip() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();

        let expires = future(7);
        let (secret, id) = seed_session(&store, user_id, &expires).await;
        assert!(id > 0);

        let found = store
            .find_session_by_hash(secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.user_id, user_id);
        assert_eq!(found.hash, secret.hash().as_str());
        assert_eq!(found.agent.as_deref(), Some("test-agent"));
        assert_eq!(found.expires_at, expires);
        assert!(found.revoked_at.is_none());
        assert!(found.is_active(chrono::Utc::now()));

        let listed = store.list_user_sessions(user_id).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, found.id);

        let secret2 = Secret::generate(SecretKind::Session).unwrap();
        store
            .create_session(user_id, secret2.hash().as_str(), &future(7), None)
            .await
            .unwrap();
        let found2 = store
            .find_session_by_hash(secret2.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found2.agent, None);
    }

    /// 撤销后 find 仍返回行（置位式非删除）但 is_active=false；重复撤销幂等不刷新 revoked_at。
    #[tokio::test]
    async fn revoked_session_findable_but_inactive() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let (secret, id) = seed_session(&store, user_id, &future(7)).await;

        store.revoke_session(id).await.unwrap();
        let found = store
            .find_session_by_hash(secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(found.revoked_at.is_some());
        assert!(!found.is_active(chrono::Utc::now()));

        let first_revoked = found.revoked_at.clone();
        store.revoke_session(id).await.unwrap();
        let found = store
            .find_session_by_hash(secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.revoked_at, first_revoked);
    }

    #[tokio::test]
    async fn revoke_all_except_keeps_current() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let other_user = store.create_user("bob", "builder").await.unwrap();

        let (_s1, keep_id) = seed_session(&store, user_id, &future(7)).await;
        let (s2, _) = seed_session(&store, user_id, &future(7)).await;
        let (s3, already_revoked) = seed_session(&store, user_id, &future(7)).await;
        store.revoke_session(already_revoked).await.unwrap();
        let (other_secret, _) = seed_session(&store, other_user, &future(7)).await;

        store
            .revoke_all_user_sessions_except(user_id, keep_id)
            .await
            .unwrap();

        let sessions = store.list_user_sessions(user_id).await.unwrap();
        let keep = sessions.iter().find(|s| s.id == keep_id).unwrap();
        assert!(keep.revoked_at.is_none(), "current session must survive");
        let s2_row = store
            .find_session_by_hash(s2.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(s2_row.revoked_at.is_some());
        let s3_row = store
            .find_session_by_hash(s3.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(s3_row.revoked_at.is_some(), "already-revoked stays revoked");

        let other = store
            .find_session_by_hash(other_secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(other.revoked_at.is_none());
    }

    #[tokio::test]
    async fn revoke_all_user_sessions_revokes_every_row_for_user() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let other_user = store.create_user("bob", "builder").await.unwrap();

        let (s1, _) = seed_session(&store, user_id, &future(7)).await;
        let (s2, _) = seed_session(&store, user_id, &future(7)).await;
        let (other_secret, _) = seed_session(&store, other_user, &future(7)).await;

        store.revoke_all_user_sessions(user_id).await.unwrap();

        for s in [&s1, &s2] {
            let row = store
                .find_session_by_hash(s.hash().as_str())
                .await
                .unwrap()
                .unwrap();
            assert!(row.revoked_at.is_some(), "all user sessions revoked");
        }
        let other = store
            .find_session_by_hash(other_secret.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(other.revoked_at.is_none());
    }

    /// 过期清理（两函数）：只删 expires_at <= now 的行，活跃行保留。
    #[tokio::test]
    async fn expired_session_cleanup() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        let bob = store.create_user("bob", "builder").await.unwrap();

        let (_expired_a, _) = seed_session(&store, alice, &past(1)).await;
        let (_live_a, _) = seed_session(&store, alice, &future(7)).await;
        let (_expired_b, _) = seed_session(&store, bob, &past(2)).await;

        let removed = store
            .delete_expired_user_sessions(alice, &chrono::Utc::now().to_rfc3339())
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.list_user_sessions(alice).await.unwrap().len(), 1);

        let removed = store
            .delete_all_expired_sessions(&chrono::Utc::now().to_rfc3339())
            .await
            .unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.list_user_sessions(alice).await.unwrap().len(), 1);
        assert_eq!(store.list_user_sessions(bob).await.unwrap().len(), 0);
    }

    /// 过期会话 is_active=false；垃圾 expires_at 经 API 直写入库（写入侧不校验）同样 fail-closed。
    #[tokio::test]
    async fn expired_or_corrupt_session_is_inactive() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();

        let (expired, _) = seed_session(&store, user_id, &past(1)).await;
        let found = store
            .find_session_by_hash(expired.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(!found.is_active(chrono::Utc::now()));

        let corrupt = Secret::generate(SecretKind::Session).unwrap();
        store
            .create_session(user_id, corrupt.hash().as_str(), "not-a-timestamp", None)
            .await
            .unwrap();
        let found = store
            .find_session_by_hash(corrupt.hash().as_str())
            .await
            .unwrap()
            .unwrap();
        assert!(!found.is_active(chrono::Utc::now()));
    }

    /// hash UNIQUE：同 hash 二次插入必须失败（认证查表主键语义）。
    #[tokio::test]
    async fn duplicate_session_hash_rejected() {
        let (store, _tmp) = store().await;
        let alice = store.create_user("alice", "builder").await.unwrap();
        let (secret, _) = seed_session(&store, alice, &future(7)).await;

        let bob = store.create_user("bob", "builder").await.unwrap();
        let dup = store
            .create_session(bob, secret.hash().as_str(), &future(7), None)
            .await;
        assert!(dup.is_err(), "duplicate hash must violate UNIQUE");
    }

    /// FK ON DELETE CASCADE：删用户连删其 sessions（sqlx 默认开 FK）。
    #[tokio::test]
    async fn deleting_user_cascades_sessions() {
        let (store, _tmp) = store().await;
        let user_id = store.create_user("alice", "builder").await.unwrap();
        let (secret, _) = seed_session(&store, user_id, &future(7)).await;
        assert!(store
            .find_session_by_hash(secret.hash().as_str())
            .await
            .unwrap()
            .is_some());

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(store.pool())
            .await
            .unwrap();

        assert!(
            store
                .find_session_by_hash(secret.hash().as_str())
                .await
                .unwrap()
                .is_none(),
            "sessions must cascade-delete with the user"
        );
    }
}
