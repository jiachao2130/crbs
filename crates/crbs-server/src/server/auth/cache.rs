// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 认证缓存：凭据 → 身份快照正向缓存，代数失效 + TTL 兜底，消除高频轮询
//! 重复支付认证 SELECT。key = 凭据派生值（SHA-256 hex，非明文），value = 认证判定所需用户快照。
//!
//! - 命中：用户域代数相同 且 填充后 10s 内 且 凭据绝对过期未到，任一不满足
//!   即回源；TTL 只兜代数遗漏写路径，角色/ACL/禁用/会话变更经代数 bump 即时生效；
//! - 只缓存正向结果：无效/撤销/过期不落缓存（401 逐请求精确、新凭据无负缓存遮蔽）；
//! - 不落 token 原文/密码哈希（value 仅 user/role/user_id/allowed_products
//!   等非敏感字段，重启清空）。
//!
//! 并发纪律：`std::sync::Mutex` 短临界区不跨 await、回源全在锁外；容量 4096 + 插入序逐出。
//! 取舍：不上 LRU，直到量级证明需要。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};

use super::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;
use crbs_core::auth::secret::SecretHash;

const CACHE_CAPACITY: usize = 4096;

/// 条目 TTL 兜底：代数收口遗漏的写路径（裸 SQL 等）至多陈旧这么久。单写者
/// 假设：`user_generation` 为进程内计数（当前 hub 单进程成立），多进程共享
/// 库时跨进程即时失效退化为本兜底（≤10s 陈旧窗口）。
const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// key = 凭据派生值（SHA-256 hex，DB 本就存储、不含明文）+ 种类命名空间，撞串不跨类互取。
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    kind: CacheKeyKind,
    hash: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum CacheKeyKind {
    UserToken,
    Session,
    WorkerSecret,
}

impl CacheKey {
    pub(crate) fn user_token(hash: &SecretHash) -> Self {
        Self {
            kind: CacheKeyKind::UserToken,
            hash: hash.as_str().to_string(),
        }
    }

    pub(crate) fn session(hash: &SecretHash) -> Self {
        Self {
            kind: CacheKeyKind::Session,
            hash: hash.as_str().to_string(),
        }
    }

    pub(crate) fn worker_secret(hash: &SecretHash) -> Self {
        Self {
            kind: CacheKeyKind::WorkerSecret,
            hash: hash.as_str().to_string(),
        }
    }
}

struct CacheEntry {
    /// 回源前读取的用户域代数：当前代数不同即失效（即时失效语义的载体）。
    generation: u64,
    ctx: AuthContext,
    /// TTL 到期点（tokio 时钟）。
    expires_at: tokio::time::Instant,
}

/// `order` 与 `map` 的 key 集合恒等（重 fill 已有 key 不重复入队），逐出时从队首同步删两处。
#[derive(Default)]
struct CacheMap {
    map: HashMap<CacheKey, CacheEntry>,
    order: VecDeque<CacheKey>,
}

/// 认证缓存。挂在 [`crate::server::state::AppState`]，进程内共享。
pub(crate) struct AuthCache {
    entries: std::sync::Mutex<CacheMap>,
    /// TTL（生产恒为 `CACHE_TTL`；测试注入短值。tokio paused time 与 sqlx acquire 超时定时器冲突，不可用）。
    ttl: std::time::Duration,
    /// 回源重建计数：`fill` 递增；测试断言"同凭据二连请求只回源一次"的观测面。
    rebuilds: AtomicU64,
}

impl AuthCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(CacheMap::default()),
            ttl: CACHE_TTL,
            rebuilds: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_ttl(ttl: std::time::Duration) -> Self {
        Self { ttl, ..Self::new() }
    }

    /// 持锁期间不执行用户代码，正常不 poison；毒化则恢复数据续服（脏读可兜底、回源恒可用）。
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, CacheMap> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 命中 = 代数相同 且 TTL 未过 且 凭据未到绝对过期；否则 None 回源（陈旧条目留待逐出/覆盖）。
    pub(crate) fn lookup(&self, key: &CacheKey, generation: u64) -> Option<AuthContext> {
        let guard = self.lock_entries();
        let entry = guard.map.get(key)?;
        if entry.generation != generation || entry.expires_at <= tokio::time::Instant::now() {
            return None;
        }
        // 凭据绝对过期在 TTL 窗口内到期时不得续命到 TTL 边界：命中前复核，到期即回源走正常判定（401）。
        if entry
            .ctx
            .token_expires_at
            .is_some_and(|exp| exp <= chrono::Utc::now())
        {
            return None;
        }
        Some(entry.ctx.clone())
    }

    /// 回填（回源成功且为正向结果后调用）。容量满时按插入序逐出最老条目。
    pub(crate) fn fill(&self, key: CacheKey, generation: u64, ctx: AuthContext) {
        let seq = self.rebuilds.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.lock_entries();
        if guard.map.len() >= CACHE_CAPACITY && !guard.map.contains_key(&key) {
            if let Some(oldest) = guard.order.pop_front() {
                guard.map.remove(&oldest);
            }
        }
        let entry = CacheEntry {
            generation,
            ctx,
            expires_at: tokio::time::Instant::now() + self.ttl,
        };
        if guard.map.insert(key.clone(), entry).is_none() {
            guard.order.push_back(key);
        }
        tracing::debug!(seq, generation, "auth cache filled");
    }

    #[cfg(test)]
    pub(crate) fn rebuild_count(&self) -> u64 {
        self.rebuilds.load(Ordering::Relaxed)
    }
}

/// [`super::resolve_session_value`] 的回源实现（查询数 3：会话 → 用户 → 产品 ACL）。
pub(super) async fn resolve_session_value_uncached(
    app_state: &AppState,
    hash: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Some(session) = app_state
        .state_store
        .find_session_by_hash(hash)
        .await
        .map_err(auth_backend_error)?
    else {
        return Ok(None);
    };
    if !session.is_active(chrono::Utc::now()) {
        return Ok(None);
    }

    let Some(user) = app_state
        .state_store
        .get_user(session.user_id)
        .await
        .map_err(auth_backend_error)?
    else {
        return Ok(None);
    };
    if user.status != "active" {
        return Ok(None);
    }

    let allowed_products = app_state
        .state_store
        .list_products_by_user(user.id)
        .await
        .map_err(auth_backend_error)?;

    // expires_at 已在 is_active 中成功解析为未来时间，此处复用；解析失败按
    // 无过期信息处理（is_active 已拒绝，实际不可达，仅保持类型诚实）。
    let expires_at = chrono::DateTime::parse_from_rfc3339(&session.expires_at)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc));

    Ok(Some(AuthContext {
        user: user.name,
        role: user.role,
        user_id: Some(user.id),
        worker_id: None,
        allowed_products,
        token_expires_at: expires_at,
    }))
}

/// 认证路径 StateStore 错误映射：后端故障 → 503 而非 401；原始错误只进日志，对外文案固定、不含内部信息。
pub(super) fn auth_backend_error(err: crbs_core::error::CrbsError) -> ApiError {
    tracing::warn!(error = %err, "State store failure during token authentication");
    ApiError::ServiceUnavailable("authentication backend unavailable".into())
}

/// [`super::resolve_worker_secret`] 的回源实现（缓存未命中路径；查询数 1）。
pub(super) async fn resolve_worker_secret_uncached(
    app_state: &AppState,
    hash: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Some(worker) = app_state
        .state_store
        .find_worker_by_secret(hash)
        .await
        .map_err(auth_backend_error)?
    else {
        return Ok(None);
    };
    Ok(Some(AuthContext {
        user: worker.name,
        role: "worker".to_string(),
        worker_id: Some(worker.id),
        ..Default::default()
    }))
}

/// [`super::resolve_user_token`] 的回源实现（查询数 3：token → 用户 → 产品 ACL）。
pub(super) async fn resolve_user_token_uncached(
    app_state: &AppState,
    hash: &str,
) -> Result<Option<AuthContext>, ApiError> {
    let Some(user_token) = app_state
        .state_store
        .find_user_token_by_hash(hash)
        .await
        .map_err(auth_backend_error)?
    else {
        return Ok(None);
    };

    if user_token.revoked_at.is_some() {
        return Ok(None);
    }
    let token_expires_at: Option<chrono::DateTime<chrono::Utc>> = user_token
        .expires_at
        .as_ref()
        .and_then(|exp| chrono::DateTime::parse_from_rfc3339(exp).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    if let Some(expires) = token_expires_at {
        if expires <= chrono::Utc::now() {
            return Ok(None);
        }
    }

    let Some(user) = app_state
        .state_store
        .get_user(user_token.user_id)
        .await
        .map_err(auth_backend_error)?
    else {
        return Ok(None);
    };
    if user.status != "active" {
        return Ok(None);
    }

    let allowed_products = app_state
        .state_store
        .list_products_by_user(user.id)
        .await
        .map_err(auth_backend_error)?;

    Ok(Some(AuthContext {
        user: user.name,
        role: user.role,
        user_id: Some(user.id),
        worker_id: None,
        allowed_products,
        token_expires_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(name: &str) -> AuthContext {
        AuthContext {
            user: name.to_string(),
            ..Default::default()
        }
    }

    fn key(n: usize) -> CacheKey {
        CacheKey {
            kind: CacheKeyKind::UserToken,
            hash: format!("hash-{n}"),
        }
    }

    /// 代数失配必须未命中（角色/ACL/禁用/会话变更即时失效语义的载体）。
    #[tokio::test]
    async fn lookup_misses_when_generation_differs() {
        let cache = AuthCache::new();
        cache.fill(key(1), 7, ctx("alice"));
        assert_eq!(
            cache.lookup(&key(1), 7).map(|c| c.user),
            Some("alice".to_string())
        );
        assert!(
            cache.lookup(&key(1), 8).is_none(),
            "bumped generation must miss"
        );
        // 旧代数回看同样不命中（代数单调）。
        assert!(cache.lookup(&key(1), 6).is_none());
    }

    /// 容量满按插入序逐出最老条目；重 fill 已有 key 不产生重复队列项。
    #[tokio::test]
    async fn fill_evicts_oldest_beyond_capacity() {
        let cache = AuthCache::new();
        for n in 0..=CACHE_CAPACITY {
            cache.fill(key(n), 0, ctx("u"));
        }
        assert!(
            cache.lookup(&key(0), 0).is_none(),
            "oldest entry must be evicted"
        );
        assert_eq!(
            cache.lookup(&key(1), 0).map(|c| c.user),
            Some("u".to_string())
        );

        // 重 fill 存活 key 不重复入队、不触发逐出；再插新 key 逐出下一个最老项。
        cache.fill(key(1), 0, ctx("u"));
        cache.fill(key(CACHE_CAPACITY + 1), 0, ctx("u"));
        assert!(
            cache.lookup(&key(1), 0).is_none(),
            "next-oldest entry must be evicted by the new insert"
        );
        assert_eq!(
            cache.lookup(&key(2), 0).map(|c| c.user),
            Some("u".to_string())
        );
    }
}
