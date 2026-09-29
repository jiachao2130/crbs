// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! transient 失败自动重试：`RetryPolicy` 退避策略与带重试的执行封装。

use std::time::Duration;

use tokio::time::sleep;
use tracing::{info, warn};

use crate::config::Config;
use crate::error::CrbsError;

/// 构建 transient 失败自动重试策略。
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// 最大额外重试次数（0 表示不重试）。
    pub max_retries: u32,
    /// 退避基数（毫秒）：第 n 次重试 base = backoff_ms·2^n，实际等待 [base, 1.5·base)。
    pub backoff_ms: u64,
}

impl RetryPolicy {
    /// 从生效后的 `Config` 构造。
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            max_retries: cfg.build_max_retries,
            backoff_ms: cfg.build_retry_backoff_ms,
        }
    }

    /// 执行带重试的异步操作：仅 `CrbsError::is_transient()` 错误触发重试；每次
    /// 尝试前检查 `cancel_token`，已取消立即返回 `CrbsError::Cancelled`；调用方
    /// 应在每次尝试内新建 `cancel_token.child_token()`，避免上次取消状态污染
    /// 下次尝试。返回 `(value, retries)`，`retries` = 成功前实际执行的额外尝试次数。
    pub async fn run<F, Fut, T>(
        &self,
        desc: &str,
        cancel_token: &tokio_util::sync::CancellationToken,
        mut f: F,
    ) -> Result<(T, u32), CrbsError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, CrbsError>>,
    {
        let mut attempt = 0u32;
        loop {
            if cancel_token.is_cancelled() {
                return Err(CrbsError::Cancelled);
            }

            match f().await {
                Ok(v) => {
                    if attempt > 0 {
                        info!(desc, retries = attempt, "build succeeded after retries");
                    }
                    return Ok((v, attempt));
                }
                Err(e) if !e.is_transient() || attempt >= self.max_retries => {
                    return Err(e);
                }
                Err(e) => {
                    attempt += 1;
                    let wait = self.delay(attempt).await;
                    warn!(
                        desc,
                        attempt,
                        max_retries = self.max_retries,
                        delay_ms = wait.as_millis() as u64,
                        error = %e,
                        "transient build error, retrying"
                    );
                    // 退避睡眠期间取消立即生效（盲区默认 ≤2s，调大 backoff_ms 会放大）。
                    tokio::select! {
                        _ = cancel_token.cancelled() => return Err(CrbsError::Cancelled),
                        _ = sleep(wait) => {}
                    }
                }
            }
        }
    }

    async fn delay(&self, attempt: u32) -> Duration {
        let base = self.backoff_ms.saturating_mul(2u64.saturating_pow(attempt));
        // 延迟 ∈ [base, 1.5·base)：指数满值 base + [0, base/2) 半值抖动。与
        // crbs_core::util::half_jitter_delay_now（[0.5·full, full)）刻意不同，勿收敛。
        // 抖动取 getrandom（避免 NTP 校时影响），其可能阻塞，故放 spawn_blocking。
        let jitter = if base > 1 {
            let base_half = base / 2;
            tokio::task::spawn_blocking(move || {
                let mut buf = [0u8; 8];
                match getrandom::getrandom(&mut buf) {
                    Ok(()) => u64::from_le_bytes(buf) % base_half,
                    Err(_) => 0,
                }
            })
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "getrandom jitter task failed, using zero jitter");
                0
            })
        } else {
            0
        };
        Duration::from_millis(base.saturating_add(jitter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_retry_succeeds_on_transient() {
        let policy = RetryPolicy {
            max_retries: 2,
            backoff_ms: 1,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut calls = 0;
        let result = policy
            .run("test", &cancel, || {
                calls += 1;
                async move {
                    if calls < 2 {
                        Err(CrbsError::Network {
                            message: "transient".into(),
                        })
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;
        assert_eq!(result.unwrap(), (42, 1));
        assert_eq!(calls, 2);
    }

    #[tokio::test]
    async fn test_no_retry_on_non_transient() {
        let policy = RetryPolicy {
            max_retries: 2,
            backoff_ms: 1,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut calls = 0;
        let result: Result<((), u32), CrbsError> = policy
            .run("test", &cancel, || {
                calls += 1;
                async move {
                    Err(CrbsError::ValidationFailed {
                        message: "bad".into(),
                    })
                }
            })
            .await;
        assert!(matches!(result, Err(CrbsError::ValidationFailed { .. })));
        assert_eq!(calls, 1);
    }

    #[tokio::test]
    async fn test_cancel_aborts_retry() {
        let policy = RetryPolicy {
            max_retries: 2,
            backoff_ms: 1,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let mut calls = 0;
        let result: Result<((), u32), CrbsError> = policy
            .run("test", &cancel, || {
                calls += 1;
                async move {
                    Err(CrbsError::Network {
                        message: "transient".into(),
                    })
                }
            })
            .await;
        assert!(matches!(result, Err(CrbsError::Cancelled)));
        assert_eq!(calls, 0);
    }

    /// 钉住：退避睡眠期取消立即返回 Cancelled、不发起下一次尝试；首次重试
    /// 延迟区间 [2·backoff, 3·backoff)（backoff 配置外推依赖该分布）。
    #[tokio::test]
    async fn cancel_during_backoff_returns_cancelled_promptly() {
        let policy = RetryPolicy {
            max_retries: 2,
            backoff_ms: 10_000,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            canceller.cancel();
        });

        let mut calls = 0;
        let started = std::time::Instant::now();
        let result: Result<((), u32), CrbsError> = policy
            .run("test", &cancel, || {
                calls += 1;
                async move {
                    Err(CrbsError::Network {
                        message: "transient".into(),
                    })
                }
            })
            .await;
        assert!(matches!(result, Err(CrbsError::Cancelled)));
        assert_eq!(calls, 1, "cancel during backoff must skip further attempts");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "cancel must preempt the 10s-class backoff, took {:?}",
            started.elapsed()
        );

        let delay = policy.delay(1).await;
        assert!(delay >= std::time::Duration::from_millis(2 * 10_000));
        assert!(delay < std::time::Duration::from_millis(3 * 10_000));
    }
}
