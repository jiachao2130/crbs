// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层时间戳：TTL 标记、读写与过期判定。

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use crate::error::CrbsError;

pub(crate) fn timestamp_marker(layer_dir: &Path) -> PathBuf {
    layer_dir.join(".timestamp")
}

/// stale-upper 文件名内嵌 rename 时间戳的 chrono 格式串，写读两侧共用——
/// 字面量漂移 → parse 恒 None → cleanup 保守永久保留，stale upper 静默泄漏。
pub(crate) const STALE_UPPER_TS_FORMAT: &str = "%Y%m%d-%H%M%S";

/// 解析 `upper.stale.` 文件名内嵌的 rename 时间戳。保留判定（24h TTL）以
/// rename 时刻为准而非 mtime——rename 保留原 mtime，旧 upper 天然早于 TTL，
/// 按 mtime 会立即删掉刚移走、仍被进行中构建引用的 upper；失败 None → 保守保留。
pub(crate) fn parse_stale_upper_timestamp(file_name: &str) -> Option<DateTime<Utc>> {
    let ts = file_name.strip_prefix("upper.stale.")?;
    let naive = chrono::NaiveDateTime::parse_from_str(ts, STALE_UPPER_TS_FORMAT).ok()?;
    Some(naive.and_utc())
}

/// 读取层时间戳。`NotFound` 与解析失败 → `Ok(None)`（视为过期重建）；其他 I/O
/// 错误 → `Err`（fail-closed），不静默复用可能陈旧的层。
pub(crate) async fn read_layer_timestamp(path: &Path) -> crate::Result<Option<DateTime<Utc>>> {
    match tokio::fs::read_to_string(path).await {
        Ok(s) => match DateTime::parse_from_rfc3339(s.trim()) {
            Ok(dt) => Ok(Some(dt.with_timezone(&Utc))),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Ignoring malformed layer timestamp");
                Ok(None)
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CrbsError::from_io_context(
            format!("read layer timestamp {}", path.display()),
            e,
        )),
    }
}

pub(crate) async fn write_layer_timestamp(path: &Path) -> crate::Result<()> {
    let ts = Utc::now().to_rfc3339();
    tokio::fs::write(path, ts)
        .await
        .map_err(|e| CrbsError::from_io_context("write .timestamp", e))
}

/// 判断 SharedLayer 是否已过期。`staleness` 为 `None` 时按缺省 TTL（7 天）
/// 判定，显式配置可覆盖；`.timestamp` 缺失或无法解析 → 过期（创建流程成功后
/// 重写）；读取 I/O 错误向上传播（fail-closed，调用方按过期处理）。
pub(crate) async fn is_layer_stale(
    layer_dir: &Path,
    staleness: Option<std::time::Duration>,
) -> crate::Result<bool> {
    let staleness =
        staleness.unwrap_or_else(crate::config::defaults::default_shared_layer_staleness);

    let ts_path = timestamp_marker(layer_dir);
    let timestamp = match read_layer_timestamp(&ts_path).await? {
        Some(ts) => ts,
        None => {
            // 缺失即过期（创建流程成功后重写）。
            return Ok(true);
        }
    };

    // 时钟回拨产生负 elapsed：钳 0 = 未过期（保守复用，避免回拨引发重建风暴）；
    // 方向与缺失时间戳相反——缺失按过期重建（上方），回拨按未过期复用（此处）。
    let elapsed_secs = (Utc::now().timestamp() - timestamp.timestamp()).max(0);
    let ttl_secs = crate::util::u64_to_i64_saturating(staleness.as_secs());
    Ok(elapsed_secs >= ttl_secs)
}
