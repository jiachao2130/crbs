// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 重试与超时辅助工具（worker 策略层薄封装，服务 Worker→Hub 上报/上传）。循环骨架
//! 已下沉到 [`crbs_core::http_retry::retry_with_policy`]；本模块仅留策略常量、
//! per-attempt 超时包装与 [`is_retryable`]。

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::warn;

use crbs_core::error::CrbsError;
use crbs_core::http_retry::{retry_with_policy, RetryBreak, RetryCause};

pub(crate) use crbs_core::http_retry::wait_for_cancel;

const RETRY_MAX_ATTEMPTS: u32 = 3;
const RETRY_BASE_DELAY: Duration = Duration::from_secs(1);
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// 对异步操作执行带取消与退避的重试（单次尝试默认 30s 超时）；长耗时操作
///（如产物上传）应改用 [`retry_with_timeout`] 传入更长的单次尝试超时。
/// 共 3 次尝试 / 2 次退避，退避满值依次 1s / 2s、按 half jitter 取 [1/2, 1] 随机；
/// 取消立即返回 `CrbsError::Cancelled`；仅重试 transient 错误（见
/// [`CrbsError::is_transient`]），`ValidationFailed` / 非网络 `Io` / `Internal` 直接返回。
pub async fn retry_with_backoff<F, Fut, T>(
    operation: &str,
    cancel_token: Option<&CancellationToken>,
    f: F,
) -> crbs_core::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crbs_core::Result<T>>,
{
    retry_with_timeout(operation, cancel_token, REQUEST_TIMEOUT, f).await
}

/// 对异步操作执行带取消、退避与单次尝试超时上限的重试。
/// `timeout` 为每次尝试的超时上限，超时按可重试错误处理（与客户端兜底超时相等时先到者为准）；其余语义同 [`retry_with_backoff`]。
pub async fn retry_with_timeout<F, Fut, T>(
    operation: &str,
    cancel_token: Option<&CancellationToken>,
    timeout: Duration,
    mut f: F,
) -> crbs_core::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = crbs_core::Result<T>>,
{
    let outcome = retry_with_policy(
        RETRY_MAX_ATTEMPTS,
        RETRY_BASE_DELAY,
        cancel_token,
        is_retryable,
        // worker 的成功值不参与重试决策，恒 false（CLI 的可重试状态码才走值路径）。
        |_| false,
        // 值重试路径不可达（谓词恒 false），只记录错误重试日志。
        |cause, attempt, delay| {
            if let RetryCause::Error(e) = cause {
                warn!(
                    operation,
                    attempt,
                    error = %e,
                    delay_ms = delay.as_millis() as u64,
                    "Request failed, retrying"
                );
            }
        },
        // per-attempt 超时包装：超时映射为可重试的 CrbsError::Timeout。
        |_| {
            let fut = f();
            async move {
                tokio::time::timeout(timeout, fut)
                    .await
                    .unwrap_or_else(|_| Err(CrbsError::Timeout))
            }
        },
    )
    .await;
    match outcome {
        Ok(v) => Ok(v),
        Err(RetryBreak::Cancelled) => Err(CrbsError::Cancelled),
        Err(RetryBreak::Inner(e)) => Err(e),
    }
}

fn is_retryable(e: &CrbsError) -> bool {
    e.is_transient()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test]
    async fn retry_succeeds_on_second_attempt() {
        let counter = AtomicU32::new(0);
        let result = retry_with_backoff("test", None, || async {
            let c = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if c == 1 {
                Err(CrbsError::Network {
                    message: "transient".into(),
                })
            } else {
                Ok(c)
            }
        })
        .await;
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn retry_gives_up_after_max_attempts() {
        let counter = AtomicU32::new(0);
        let result: crbs_core::Result<()> = retry_with_backoff("test", None, || async {
            counter.fetch_add(1, Ordering::Relaxed);
            Err(CrbsError::Network {
                message: "always fails".into(),
            })
        })
        .await;
        assert!(matches!(result, Err(CrbsError::Network { .. })));
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retry_does_not_retry_validation_error() {
        let counter = AtomicU32::new(0);
        let result: crbs_core::Result<()> = retry_with_backoff("test", None, || async {
            counter.fetch_add(1, Ordering::Relaxed);
            Err(CrbsError::ValidationFailed {
                message: "bad request".into(),
            })
        })
        .await;
        assert!(matches!(result, Err(CrbsError::ValidationFailed { .. })));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retry_does_not_retry_non_transient_io_error() {
        let counter = AtomicU32::new(0);
        let result: crbs_core::Result<()> = retry_with_backoff("test", None, || async {
            counter.fetch_add(1, Ordering::Relaxed);
            Err(CrbsError::from(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such file",
            )))
        })
        .await;
        assert!(
            matches!(result, Err(CrbsError::Io { .. })),
            "err: {result:?}"
        );
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn retry_with_timeout_times_out_hanging_operation() {
        let counter = AtomicU32::new(0);
        let started = std::time::Instant::now();
        let result: crbs_core::Result<()> =
            retry_with_timeout("test", None, Duration::from_millis(50), || async {
                counter.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(30)).await;
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(CrbsError::Timeout)));
        // 3 次尝试均按 per-op 超时掐断（超时可重试）；耗时远小于 3×30s，证明未落到默认 30s。
        assert_eq!(counter.load(Ordering::Relaxed), 3);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn retry_with_timeout_allows_slow_operation() {
        let counter = AtomicU32::new(0);
        let result = retry_with_timeout("test", None, Duration::from_secs(2), || async {
            counter.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(counter.load(Ordering::Relaxed))
        })
        .await;
        assert_eq!(result.unwrap(), 1);
    }

    #[tokio::test]
    async fn retry_returns_cancelled_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        let counter = AtomicU32::new(0);
        let result = retry_with_backoff("test", Some(&token), || async {
            counter.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(CrbsError::Cancelled)));
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
