// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 通用重试骨架：attempt 计数、指数退避（half jitter）、取消感知、可注入的
//! 重试谓词；"什么可重试"与 HTTP 客户端留在调用方（不引入 reqwest）。
//!
//! 调用方差异点（禁止顺手统一）：
//! - 重试次数同为 3（含首次），常量各自定义、经参数传入；退避一致（最多 2 次，
//!   1s / 2s）。
//! - worker 用 `tokio::time::timeout` 包整次尝试（默认 30s）；CLI 无 per-attempt
//!   超时，靠 client 总超时 300s + connect_timeout 10s。
//! - 错误谓词：worker `CrbsError::is_transient`（网络/超时；`Cancelled` 恒 false）；
//!   CLI `should_retry_transport`（GET/HEAD 任意传输错误，其余仅连接建立失败）。
//! - 值谓词：CLI 可重试状态码（GET/HEAD 任意 5xx，其余仅 500/503），5xx 藏在
//!   `Ok` 值里，耗尽返回最后值由调用方处理；worker 恒 false。
//! - 取消统一由循环顶检查，尝试与退避期间 select 让路；日志经 `on_retry` 交给
//!   调用方；最终错误形态由调用方包装（worker 返回最后 `CrbsError`，CLI 转
//!   `CrbsError::Network`）。

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::util::half_jitter_delay_now;

/// 提供令牌则等待取消信号；否则永久挂起（无令牌时的 `tokio::select!` 占位）。
pub async fn wait_for_cancel(cancel_token: Option<&CancellationToken>) {
    if let Some(t) = cancel_token {
        t.cancelled().await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// 单次重试决策的原因：错误可重试（`Error`）或成功值需要重试（`Value`）。
/// HTTP 下 5xx 藏在成功值里走 `Value`（worker 值谓词恒 `false`，`Value` 不出现）。
pub enum RetryCause<'a, T, E> {
    /// 错误满足 `error_retryable`，需要重试。
    Error(&'a E),
    /// 成功值满足 `value_retryable`，需要重试。
    Value(&'a T),
}

/// 重试循环终止方式。
pub enum RetryBreak<E> {
    /// 取消令牌触发（尝试前、尝试执行中或退避睡眠中）。
    Cancelled,
    /// 尝试失败且不可重试或预算耗尽，携带最后一次错误。
    Inner(E),
}

/// 泛型指数退避重试循环（worker 上报与 CLI 远程请求共用骨架）。
/// - `max_attempts` 含首次；第 n 次（n 从 1 起）失败且可重试时退避满值为
///   `base_delay * 2^(n-1)`，half jitter 取 `[满值/2, 满值]`，睡眠取消感知。
/// - 判定顺序：错误路径先谓词后预算，值路径先预算后谓词；两侧谓词均为纯函数，顺序不产生行为差异。
/// - 值重试耗尽返回最后一次值（CLI 依赖此语义把耗尽的 5xx 作为 `Ok(响应)` 交调用方处理）。
/// - `on_retry` 每次决定重试时同步回调（原因、attempt 序号、退避延迟）。
/// - `f` 入参为 attempt 序号（1 起）——CLI 借此识别可重试状态码的最后一次尝试以走终态路径。
/// - 取消：尝试前检查令牌；尝试执行（含 body 读取）与退避睡眠期间触发立即
///   返回 [`RetryBreak::Cancelled`]。
pub async fn retry_with_policy<F, Fut, T, E>(
    max_attempts: u32,
    base_delay: Duration,
    cancel_token: Option<&CancellationToken>,
    mut error_retryable: impl FnMut(&E) -> bool,
    mut value_retryable: impl FnMut(&T) -> bool,
    mut on_retry: impl FnMut(RetryCause<'_, T, E>, u32, Duration),
    mut f: F,
) -> Result<T, RetryBreak<E>>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let mut attempt = 0u32;
    loop {
        if cancel_token.is_some_and(|t| t.is_cancelled()) {
            return Err(RetryBreak::Cancelled);
        }
        attempt += 1;

        let attempt_fut = f(attempt);
        let result = tokio::select! {
            _ = wait_for_cancel(cancel_token) => return Err(RetryBreak::Cancelled),
            res = attempt_fut => res,
        };

        match result {
            Ok(v) if attempt >= max_attempts || !value_retryable(&v) => return Ok(v),
            Ok(v) => {
                let delay = half_jitter_delay_now(attempt, base_delay);
                on_retry(RetryCause::Value(&v), attempt, delay);
                tokio::select! {
                    _ = wait_for_cancel(cancel_token) => return Err(RetryBreak::Cancelled),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
            Err(e) if !error_retryable(&e) => return Err(RetryBreak::Inner(e)),
            Err(e) if attempt >= max_attempts => return Err(RetryBreak::Inner(e)),
            Err(e) => {
                let delay = half_jitter_delay_now(attempt, base_delay);
                on_retry(RetryCause::Error(&e), attempt, delay);
                tokio::select! {
                    _ = wait_for_cancel(cancel_token) => return Err(RetryBreak::Cancelled),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use super::*;

    /// 错误谓词路径：可重试错误烧满预算（3 次尝试 2 次退避），返回最后一次错误；
    /// 退避 half jitter 界：首次 ∈ [base/2, base]、末次 ∈ [base, 2·base]。
    #[tokio::test]
    async fn error_retry_path_exhausts_with_bounded_backoff() {
        let attempts = AtomicU32::new(0);
        let attempts_ref = &attempts;
        let delays: Mutex<Vec<(u32, Duration)>> = Mutex::new(Vec::new());
        let result = retry_with_policy(
            3,
            Duration::from_millis(1),
            None,
            |e: &&'static str| *e == "transient",
            |_: &u32| false,
            |cause, attempt, delay| {
                assert!(matches!(cause, RetryCause::Error(&"transient")));
                delays.lock().unwrap().push((attempt, delay));
            },
            |attempt| async move {
                assert_eq!(attempt, attempts_ref.fetch_add(1, Ordering::Relaxed) + 1);
                Err::<u32, &'static str>("transient")
            },
        )
        .await;
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
        assert!(matches!(result, Err(RetryBreak::Inner(e)) if e == "transient"));

        let delays = delays.into_inner().unwrap();
        assert_eq!(delays.len(), 2, "3 次尝试只应有 2 次退避");
        assert_eq!(delays[0].0, 1, "首次退避跟随第 1 次失败");
        assert_eq!(delays[1].0, 2, "末次退避跟随第 2 次失败");
        let base = Duration::from_millis(1);
        assert!(
            delays[0].1 >= base / 2 && delays[0].1 <= base,
            "首次退避 half-jitter 上下界 [0.5ms, 1ms]，got {:?}",
            delays[0].1
        );
        assert!(
            delays[1].1 >= base && delays[1].1 <= base * 2,
            "末次退避 half-jitter 上下界 [1ms, 2ms]，got {:?}",
            delays[1].1
        );
    }

    /// 错误谓词拒绝：立即失败，单次尝试、不触发退避回调。
    #[tokio::test]
    async fn non_retryable_error_fails_without_retry() {
        let attempts = AtomicU32::new(0);
        let result = retry_with_policy(
            3,
            Duration::from_millis(1),
            None,
            |e: &&'static str| *e != "fatal",
            |_: &u32| false,
            |_, _, _| panic!("non-retryable error must not trigger on_retry"),
            |_| async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err::<u32, &'static str>("fatal")
            },
        )
        .await;
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
        assert!(matches!(result, Err(RetryBreak::Inner(e)) if e == "fatal"));
    }

    /// 成功值谓词路径：值需重试时与错误路径同样退避，最终成功值原样返回。
    #[tokio::test]
    async fn value_retry_path_retries_then_succeeds() {
        let attempts = AtomicU32::new(0);
        let value_retries = AtomicU32::new(0);
        let result = retry_with_policy(
            3,
            Duration::from_millis(1),
            None,
            |_: &&'static str| false,
            |v: &u32| *v < 2,
            |cause, _, _| {
                assert!(matches!(cause, RetryCause::Value(v) if *v < 2));
                value_retries.fetch_add(1, Ordering::Relaxed);
            },
            |_| async {
                let c = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                Ok::<u32, &'static str>(c)
            },
        )
        .await;
        assert!(matches!(result, Ok(2)));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        assert_eq!(value_retries.load(Ordering::Relaxed), 1);
    }

    /// 成功值重试耗尽：返回最后一次值（CLI 耗尽 5xx 返回 Ok(响应) 的语义）。
    #[tokio::test]
    async fn value_retry_exhausted_returns_last_value() {
        let attempts = AtomicU32::new(0);
        let result = retry_with_policy(
            2,
            Duration::from_millis(1),
            None,
            |_: &&'static str| false,
            |_: &u32| true,
            |_, _, _| {},
            |_| async {
                let c = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                Ok::<u32, &'static str>(c)
            },
        )
        .await;
        assert!(matches!(result, Ok(2)), "耗尽时应返回最后一个成功值");
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    /// 已取消令牌：进入循环立即返回 Cancelled，不发起任何尝试。
    #[tokio::test]
    async fn cancelled_token_returns_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        let attempts = AtomicU32::new(0);
        let result = retry_with_policy(
            3,
            Duration::from_millis(1),
            Some(&token),
            |_: &&'static str| true,
            |_: &u32| false,
            |_, _, _| panic!("cancelled before start must not trigger on_retry"),
            |_| async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Ok::<u32, &'static str>(0)
            },
        )
        .await;
        assert!(matches!(result, Err(RetryBreak::Cancelled)));
        assert_eq!(attempts.load(Ordering::Relaxed), 0);
    }

    /// 退避睡眠期间取消：立即返回 Cancelled 不再重试（满值 60s，取消必先于睡眠结束让路）。
    #[tokio::test]
    async fn cancel_during_backoff_returns_cancelled() {
        let token = CancellationToken::new();
        let attempts = AtomicU32::new(0);
        let result = retry_with_policy(
            3,
            Duration::from_secs(60),
            Some(&token),
            |_: &&'static str| true,
            |_: &u32| false,
            |_, _, _| token.cancel(),
            |_| async {
                attempts.fetch_add(1, Ordering::Relaxed);
                Err::<u32, &'static str>("transient")
            },
        )
        .await;
        assert!(matches!(result, Err(RetryBreak::Cancelled)));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }
}
