// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 无状态、带过期时间的 SRPM 下载 token 签名与校验：调度器签发、Worker 用
//! `?token=<token>` 下载。blake3 keyed hash 签名，server 无需内存/数据库存储，
//! 密钥不泄露则无法伪造或篡改。格式 `<expires_at>:<hex_signature>`：`expires_at`
//! 为 Unix 秒、签发后固定 10 分钟过期；`signature` 覆盖 `"{build_id}:{expires_at}"`。

use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;

/// SRPM 下载 token 默认有效期（10 分钟）。
pub const SRPM_TOKEN_EXPIRY_SECONDS: u64 = 600;

/// SRPM 下载 token 签名器。
#[derive(Clone)]
pub struct SrpmTokenSigner {
    key: [u8; 32],
}

// 密钥即主签名密钥，泄漏 = 可伪造任意下载 token；Debug 脱敏同 auth::Secret。
impl std::fmt::Debug for SrpmTokenSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SrpmTokenSigner")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl SrpmTokenSigner {
    /// 使用 32 字节对称密钥构造签名器。
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// 为指定 build 生成带签名的下载 token。
    pub fn generate(&self, build_id: i64) -> String {
        let expires_at = now_seconds() + SRPM_TOKEN_EXPIRY_SECONDS;
        let signature = self.sign(build_id, expires_at);
        format!("{}:{}", expires_at, signature.to_hex())
    }

    /// 校验 token 是否属于指定 build 且未过期。
    pub fn validate(&self, build_id: i64, token: &str) -> bool {
        let Some((expires_at_str, signature_hex)) = token.split_once(':') else {
            return false;
        };
        let Ok(expires_at) = expires_at_str.parse::<u64>() else {
            return false;
        };
        if now_seconds() > expires_at {
            return false;
        }
        let Ok(signature) = blake3::Hash::from_hex(signature_hex) else {
            return false;
        };
        ct_eq_bytes(
            signature.as_bytes(),
            self.sign(build_id, expires_at).as_bytes(),
        )
    }

    fn sign(&self, build_id: i64, expires_at: u64) -> blake3::Hash {
        let payload = format!("{}:{}", build_id, expires_at);
        Hasher::new_keyed(&self.key)
            .update(payload.as_bytes())
            .finalize()
    }
}

/// 常量时间比较，防 token 校验的时序侧信道；`blake3::Hash` 的 `PartialEq`
/// 逐字节短路不可用于校验，故手写异或折叠。
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_for_same_build() {
        let signer = SrpmTokenSigner::new([7u8; 32]);
        let token = signer.generate(42);
        assert!(signer.validate(42, &token));
    }

    #[test]
    fn token_fails_for_wrong_build() {
        let signer = SrpmTokenSigner::new([7u8; 32]);
        let token = signer.generate(42);
        assert!(!signer.validate(43, &token));
    }

    #[test]
    fn token_fails_for_expired_token() {
        let signer = SrpmTokenSigner::new([7u8; 32]);
        // 直接构造一个已过期 token：expires_at = 0，签名正确
        let token = format!("0:{}", signer.sign(42, 0).to_hex());
        assert!(!signer.validate(42, &token));
    }

    #[test]
    fn token_fails_for_bad_signature() {
        let signer = SrpmTokenSigner::new([7u8; 32]);
        let token = signer.generate(42);
        let mut chars: Vec<char> = token.chars().collect();
        // 翻转最后一个字符，破坏签名但不影响过期时间
        if let Some(last) = chars.last_mut() {
            *last = if *last == 'a' { 'b' } else { 'a' };
        }
        let tampered: String = chars.into_iter().collect();
        assert!(!signer.validate(42, &tampered));
    }

    /// 畸形输入一律 fail-closed：解析失败必须返回 false，不得放行。
    #[test]
    fn malformed_tokens_fail_closed() {
        let signer = SrpmTokenSigner::new([7u8; 32]);
        // 缺冒号：expires 与签名无法分离
        assert!(!signer.validate(42, "9999999999999deadbeef"));
        // 非数字过期时间（含负数前缀，parse::<u64> 拒绝）
        assert!(!signer.validate(42, "not-a-number:abcdef"));
        assert!(!signer.validate(42, "-1:abcdef"));
        // 非 hex 签名
        assert!(!signer.validate(42, "9999999999:zzzz"));
        // 多余冒号：签名段 "hex:x" 不是合法 hex
        let extra = format!("{}:x", signer.generate(42));
        assert!(!signer.validate(42, &extra));
        assert!(!signer.validate(42, ""));
        assert!(!signer.validate(42, ":"));
    }
}
