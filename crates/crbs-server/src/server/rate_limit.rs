// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 提交限流：per-user 固定窗口计数，只作用于提交类写路径（POST /api/v1/builds、
//! POST /api/v1/tasks/{id}/rebuild|reproduce、Web UI 的 POST /ui/tasks/new——
//! 与 API 共用同一限流器与配额）。进程内存态（单 hub 部署前提）；worker 认证
//! 路径豁免；挂载在 auth 中间件内侧，`AuthContext` 已在 request extensions 中。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crbs_core::config::server::SubmitRateLimitConfig;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;

/// 判断请求是否属于提交类端点（限流只作用于这些写路径，其它 GET/查询不受影响）。
fn is_submit_endpoint(method: &Method, path: &str) -> bool {
    method == Method::POST
        && (path == "/api/v1/builds"
            || path == "/ui/tasks/new"
            || path.ends_with("/rebuild")
            || path.ends_with("/reproduce"))
}

/// 进程内存态的 per-user 固定窗口限流器。时钟可注入便于测试。
pub(crate) struct SubmitRateLimiter {
    config: SubmitRateLimitConfig,
    state: Mutex<HashMap<String, (Instant, u64)>>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl SubmitRateLimiter {
    pub(crate) fn new(config: SubmitRateLimitConfig) -> Arc<Self> {
        Self::with_clock(config, Arc::new(Instant::now))
    }

    fn with_clock(
        config: SubmitRateLimitConfig,
        now: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: Mutex::new(HashMap::new()),
            now,
        })
    }

    /// 检查并计数。返回 `None` = 放行；`Some(remaining)` = 超限（窗口剩余时长，
    /// 可作 Retry-After 提示）。`enabled=false` 时恒放行。
    fn check(&self, key: &str) -> Option<Duration> {
        if !self.config.enabled {
            return None;
        }
        let now = (self.now)();
        let window = Duration::from_secs(self.config.per_secs);
        // Mutex 中毒恢复：限流状态不是关键数据，从中毒锁中抢救即可。
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        // 顺手清理过期窗口（键为用户名、量级受用户表约束；清已删用户残留防无限增长），已持锁 retain O(n) 有界。
        guard.retain(|_, (start, _)| now.duration_since(*start) < window);
        let entry = guard.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            entry.0 = now;
            entry.1 = 0;
        }
        if entry.1 >= self.config.requests {
            return Some(window - now.duration_since(entry.0));
        }
        entry.1 += 1;
        None
    }
}

pub(crate) async fn submit_rate_limit_middleware(
    State(limiter): State<Arc<SubmitRateLimiter>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if !is_submit_endpoint(req.method(), req.uri().path()) {
        return Ok(next.run(req).await);
    }

    let key: String = match req.extensions().get::<AuthContext>() {
        Some(ctx) if ctx.worker_id.is_some() => return Ok(next.run(req).await),
        // auth_enabled=false 或匿名请求：统一匿名计数。
        Some(ctx) if ctx.user.is_empty() => "(anonymous)".to_string(),
        Some(ctx) => ctx.user.clone(),
        None => "(anonymous)".to_string(),
    };

    if let Some(remaining) = limiter.check(&key) {
        return Err(ApiError::TooManyRequests(format!(
            "submit rate limit exceeded, retry after {}s",
            remaining.as_secs().max(1)
        )));
    }
    Ok(next.run(req).await)
}

/// 登录/注册限流参数：暴力破解防护是安全基线，固定值不开放配置；
/// 调整需改这里并同步文档。
const LOGIN_RATE_LIMIT_REQUESTS: u64 = 10;
const LOGIN_RATE_LIMIT_WINDOW_SECS: u64 = 300;

/// user 轴 key 的用户名截断上限：表单 username 无长度上限，不截断会把超长输入
/// 原样放大进 HashMap（内存/CPU）；按 chars 截断到 128 字符（字符边界，不劈裂
/// 多字节），同一用户名前 128 字符命中同一桶；IP 轴 key 不经此处。
const LOGIN_USER_KEY_MAX_CHARS: usize = 128;

/// 构造登录/注册限流的 user 轴 key：`user:<小写用户名，截断到 128 chars>`。
pub(crate) fn login_user_key(username: &str) -> String {
    let lowered = username.to_lowercase();
    format!(
        "user:{}",
        lowered
            .chars()
            .take(LOGIN_USER_KEY_MAX_CHARS)
            .collect::<String>()
    )
}

/// 登录/注册限流器：per-IP 与 per-username 双轴固定窗口，双轴各自
/// 计数——单 IP 打多账号 IP 桶先满，分布式打单账号用户名桶先满；进程内存态
/// （单 hub 前提）、时钟可注入；key 由调用方拼接命名空间（`ip:…` / `user:…`），
/// 登录与注册共享同一实例与 key 空间（均未认证写端点，合并计数更保守）。
pub(crate) struct LoginRateLimiter {
    state: Mutex<HashMap<String, (Instant, u64)>>,
    now: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl LoginRateLimiter {
    pub(crate) fn new() -> Arc<Self> {
        Self::with_clock(Arc::new(Instant::now))
    }

    pub(crate) fn with_clock(now: Arc<dyn Fn() -> Instant + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HashMap::new()),
            now,
        })
    }

    /// 检查并计数：两个 key 各自累加，任一超限即拒绝。返回 `None` = 放行；
    /// `Some(remaining)` = 超限桶的窗口剩余时长（换算保守的"分钟后重试"，不展示次数）。
    pub(crate) fn check(&self, ip_key: &str, user_key: &str) -> Option<Duration> {
        let now = (self.now)();
        let window = Duration::from_secs(LOGIN_RATE_LIMIT_WINDOW_SECS);
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        // 顺手清理过期窗口（key 含用户名，量级受输入约束，已持锁 retain 有界）。
        guard.retain(|_, (start, _)| now.duration_since(*start) < window);
        let mut hit: Option<Duration> = None;
        for key in [ip_key, user_key] {
            let entry = guard.entry(key.to_string()).or_insert((now, 0));
            if now.duration_since(entry.0) >= window {
                entry.0 = now;
                entry.1 = 0;
            }
            if entry.1 >= LOGIN_RATE_LIMIT_REQUESTS {
                let remaining = window - now.duration_since(entry.0);
                // 两个桶都超限时上报剩余更久的那个（提示更保守）。
                hit = Some(match hit {
                    Some(prev) if prev >= remaining => prev,
                    _ => remaining,
                });
                continue;
            }
            entry.1 += 1;
        }
        hit
    }
}

#[cfg(test)]
mod login_limiter_tests {
    use super::*;

    struct FakeClock(Mutex<Instant>);
    impl FakeClock {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }
        fn as_fn(self: &Arc<Self>) -> Arc<dyn Fn() -> Instant + Send + Sync> {
            let this = self.clone();
            Arc::new(move || *this.0.lock().unwrap())
        }
        fn advance(&self, d: Duration) {
            *self.0.lock().unwrap() += d;
        }
    }

    /// 同一 key 对第 10 次放行、第 11 次拒绝；互不相干的 key 对独立计数。
    /// 双轴语义：每次 check 两个桶都 +1，(ip:A, user:alice) 打满后换 IP 不解封
    /// alice、换用户名也不解封 IP A（防横向/纵向枚举）。
    #[test]
    fn login_limiter_counts_per_key() {
        let limiter = LoginRateLimiter::with_clock(Arc::new(Instant::now));
        for i in 0..10 {
            assert!(
                limiter.check("ip:1.2.3.4", "user:alice").is_none(),
                "attempt {i} must pass"
            );
        }
        assert!(limiter.check("ip:1.2.3.4", "user:alice").is_some());
        assert!(limiter.check("ip:5.6.7.8", "user:bob").is_none());
    }

    #[test]
    fn login_limiter_blocks_when_either_axis_exhausted() {
        let limiter = LoginRateLimiter::with_clock(Arc::new(Instant::now));
        for i in 0..10 {
            assert!(limiter.check("ip:9.9.9.9", &format!("user:u{i}")).is_none());
        }
        assert!(limiter.check("ip:9.9.9.9", "user:brand-new").is_some());

        for i in 0..10 {
            assert!(limiter
                .check(&format!("ip:10.0.0.{i}"), "user:victim")
                .is_none());
        }
        assert!(limiter.check("ip:10.0.1.1", "user:victim").is_some());
    }

    /// 窗口滚动：推进超过窗口后计数重置；剩余时长换算正确。
    #[test]
    fn login_limiter_window_resets_after_advance() {
        let clock = FakeClock::new();
        let limiter = LoginRateLimiter::with_clock(clock.as_fn());
        for _ in 0..10 {
            assert!(limiter.check("ip:a", "user:a").is_none());
        }
        let remaining = limiter
            .check("ip:a", "user:a")
            .expect("11th must be limited");
        // 刚超限：剩余接近整个窗口（300s 减去已流逝的极小量），>299s。
        assert!(
            remaining > Duration::from_secs(299),
            "remaining: {remaining:?}"
        );

        clock.advance(Duration::from_secs(301));
        assert!(limiter.check("ip:a", "user:a").is_none());
    }

    /// 超长 username 截断：前 128 字符相同即命中同一桶；chars 截断不劈裂多字节。
    #[test]
    fn login_user_key_truncates_long_usernames() {
        let prefix = "u".repeat(LOGIN_USER_KEY_MAX_CHARS);
        let long_a = format!("{prefix}AAAA");
        let long_b = format!("{prefix}BBBB");
        assert_eq!(login_user_key(&long_a), login_user_key(&long_b));

        let limiter = LoginRateLimiter::with_clock(Arc::new(Instant::now));
        for i in 0..10 {
            assert!(limiter
                .check(&format!("ip:10.1.{i}.1"), &login_user_key(&long_a))
                .is_none());
        }
        assert!(limiter
            .check("ip:10.9.9.9", &login_user_key(&long_b))
            .is_some());

        let zh = "汉".repeat(200);
        assert_eq!(
            login_user_key(&zh).chars().count(),
            "user:".len() + LOGIN_USER_KEY_MAX_CHARS
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn config(requests: u64) -> SubmitRateLimitConfig {
        SubmitRateLimitConfig {
            enabled: true,
            requests,
            per_secs: 60,
        }
    }

    fn ctx(user: &str, worker_id: Option<i64>) -> AuthContext {
        AuthContext {
            user: user.into(),
            role: "builder".into(),
            worker_id,
            ..Default::default()
        }
    }

    #[test]
    fn submit_endpoint_classification() {
        assert!(is_submit_endpoint(&Method::POST, "/api/v1/builds"));
        assert!(is_submit_endpoint(
            &Method::POST,
            "/api/v1/tasks/42/rebuild"
        ));
        assert!(is_submit_endpoint(
            &Method::POST,
            "/api/v1/tasks/42/reproduce"
        ));
        assert!(is_submit_endpoint(&Method::POST, "/ui/tasks/new"));
        assert!(!is_submit_endpoint(&Method::GET, "/ui/tasks/new"));
        assert!(!is_submit_endpoint(&Method::GET, "/api/v1/builds"));
        assert!(!is_submit_endpoint(
            &Method::POST,
            "/api/v1/tasks/42/cancel"
        ));
        assert!(!is_submit_endpoint(&Method::POST, "/api/v1/products"));
    }

    #[test]
    fn limiter_windows_and_counts_per_key() {
        let limiter = SubmitRateLimiter::with_clock(
            config(2),
            Arc::new(|| Instant::now() - Duration::from_secs(0)),
        );
        assert!(limiter.check("alice").is_none());
        assert!(limiter.check("alice").is_none());
        assert!(limiter.check("alice").is_some());
        assert!(limiter.check("bob").is_none());
    }

    #[test]
    fn limiter_disabled_always_allows() {
        let limiter = SubmitRateLimiter::with_clock(
            SubmitRateLimitConfig {
                enabled: false,
                requests: 1,
                per_secs: 60,
            },
            Arc::new(Instant::now),
        );
        for _ in 0..10 {
            assert!(limiter.check("alice").is_none());
        }
    }

    #[tokio::test]
    async fn middleware_limits_submit_and_exempts_workers() {
        let limiter = SubmitRateLimiter::with_clock(config(1), Arc::new(Instant::now));
        let router: Router<()> = Router::new()
            .route(
                "/api/v1/builds",
                get(|| async { "ok" }).post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                submit_rate_limit_middleware,
            ));

        let mut req = Request::builder()
            .uri("/api/v1/builds")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx("alice", None));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut req = Request::builder()
            .uri("/api/v1/builds")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx("alice", None));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // worker 认证路径豁免：即使 alice 已超限，worker 上下文放行。
        let mut req = Request::builder()
            .uri("/api/v1/builds")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx("", Some(1)));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut req = Request::builder()
            .uri("/api/v1/builds")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx("alice", None));
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
