// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You can obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! nspawn/cgroup 资源限制输出的解析。

use crate::error::CrbsError;

/// 解析 memory_max 字符串为字节数：纯数字（字节）或 K/M/G/T 后缀（1024 进制），
/// "0" = 无限制；checked_mul 溢出返回 ValidationFailed（含原始输入），不 panic。
pub fn parse_memory_max(s: &str) -> crate::Result<u64> {
    if s == "0" {
        return Ok(0);
    }
    let last = s
        .chars()
        .last()
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: "memory_max cannot be empty".to_string(),
        })?;
    let (num_str, mult) = if last.is_ascii_digit() {
        (s, 1u64)
    } else {
        // 后缀大小写不敏感（"4g" 与 "4G" 等价），与 systemd parse_size 对齐。
        let mult = match last.to_ascii_uppercase() {
            'K' => 1024u64,
            'M' => 1024 * 1024,
            'G' => 1024 * 1024 * 1024,
            'T' => 1024 * 1024 * 1024 * 1024,
            _ => {
                return Err(CrbsError::ValidationFailed {
                    message: format!("Invalid memory_max suffix: {}", s),
                });
            }
        };
        let num_part = &s[..s.len() - 1];
        if num_part.is_empty() {
            return Err(CrbsError::ValidationFailed {
                message: format!("Invalid memory_max format: {}", s),
            });
        }
        (num_part, mult)
    };
    let n: u64 = num_str.parse().map_err(|_| CrbsError::ValidationFailed {
        message: format!("Invalid memory_max number: {}", s),
    })?;
    n.checked_mul(mult)
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!("memory_max overflow: {}", s),
        })
}

/// 解析 cpu_quota 字符串为 (quota, period)："50%" = 半核，"200%" 与 "2" 均为
/// 2 核（quota = n * period，period 固定 100_000 = 100ms）；拒 "0"/"0%"：
/// cpu.max quota=0 是内核 EINVAL 而非无限制，无限制应不配置 cpu_quota。
pub fn parse_cpu_quota(s: &str) -> crate::Result<(u64, u64)> {
    let period = 100_000u64;
    if s == "0" || s == "0%" {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "Invalid cpu_quota '{}': 0 is rejected (kernel cpu.max quota=0 is EINVAL; \
                 leave cpu_quota unconfigured for unlimited)",
                s
            ),
        });
    }
    if let Some(pct_str) = s.strip_suffix('%') {
        let pct: u64 = pct_str.parse().map_err(|_| CrbsError::ValidationFailed {
            message: format!("Invalid cpu_quota percentage: {}", s),
        })?;
        let quota = pct
            .checked_mul(period)
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: format!("cpu_quota overflow: {}", s),
            })?
            / 100;
        Ok((quota, period))
    } else {
        let cores: u64 = s.parse().map_err(|_| CrbsError::ValidationFailed {
            message: format!("Invalid cpu_quota cores: {}", s),
        })?;
        let quota = cores
            .checked_mul(period)
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: format!("cpu_quota overflow: {}", s),
            })?;
        Ok((quota, period))
    }
}
