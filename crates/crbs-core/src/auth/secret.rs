// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 统一的高熵密钥抽象：`{prefix}{base64url(32 random bytes)}`，前缀以 `_` 结尾，
//! 标识类型供 [`Secret::kind`] 解析与日志脱敏；`crbs_tok_` 用户 token /
//! `crbs_wkr_` worker secret / `crbs_sess_` UI 会话。base64url 无 pad（URL/header
//! 安全，无 `+`/`/`/`=`），32 字节 → 43 字符，总长固定 `prefix.len() + 43`。
//! 安全：32 字节熵（256 bit，getrandom）；[`Debug`] 永不输出明文；存储只留
//! [`SecretHash`]（SHA-256，不可逆）；[`Secret::parse`] 前缀+长度+字符集校验，垃圾输入零成本拒绝。

use std::fmt;

use sha2::{Digest, Sha256};

/// 用户 token 前缀。
pub const PREFIX_USER_TOKEN: &str = "crbs_tok_";
/// Worker secret 前缀。
pub const PREFIX_WORKER_SECRET: &str = "crbs_wkr_";
/// UI 会话（密码登录）前缀。
pub const PREFIX_SESSION: &str = "crbs_sess_";

/// 随机字节数（256 bit 熵）。
const RANDOM_BYTES_LEN: usize = 32;

/// 密钥类型，决定前缀和认证查表路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// 用户 token，前缀 `crbs_tok_`，查 `user_tokens` 表。
    UserToken,
    /// Worker secret，前缀 `crbs_wkr_`，查 `workers.secret_hash` 列。
    WorkerSecret,
    /// UI 会话，前缀 `crbs_sess_`，查 `sessions` 表；仅用于浏览器会话 cookie
    ///（`crbs_session`），**API Bearer 永不接受**该前缀（`resolve_token_value` 显式返回未认证）。
    Session,
}

impl SecretKind {
    /// 对应的密钥前缀。
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::UserToken => PREFIX_USER_TOKEN,
            Self::WorkerSecret => PREFIX_WORKER_SECRET,
            Self::Session => PREFIX_SESSION,
        }
    }

    /// 根据前缀解析密钥类型。
    pub fn from_prefix(token: &str) -> Option<Self> {
        if token.starts_with(PREFIX_USER_TOKEN) {
            Some(Self::UserToken)
        } else if token.starts_with(PREFIX_WORKER_SECRET) {
            Some(Self::WorkerSecret)
        } else if token.starts_with(PREFIX_SESSION) {
            Some(Self::Session)
        } else {
            None
        }
    }
}

/// 高熵密钥明文；仅在生成、显示（一次性）与校验边界持有，存储/日志只出现 [`SecretHash`]。
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// 生成新密钥：getrandom 取 32 字节密码学随机数，base64url 编码后加前缀。
    pub fn generate(kind: SecretKind) -> Result<Self, SecretError> {
        let mut buf = [0u8; RANDOM_BYTES_LEN];
        getrandom::getrandom(&mut buf).map_err(|e| SecretError::Rng {
            code: e.code().get(),
        })?;
        Ok(Self(format!("{}{}", kind.prefix(), encode_base64url(&buf))))
    }

    /// 解析已有密钥字符串（配置文件/环境变量加载路径），校验前缀、长度和字符集：
    /// 无合法前缀一律 `Err(UnknownPrefix)`，随机部分只允许 base64url（无 pad）字符 `[A-Za-z0-9_-]`。
    pub fn parse(s: &str) -> Result<Self, SecretError> {
        let kind = SecretKind::from_prefix(s).ok_or(SecretError::UnknownPrefix {
            prefix: s.chars().take(4).collect(),
        })?;
        let expected_len = kind.prefix().len() + encoded_len(RANDOM_BYTES_LEN);
        if s.len() != expected_len {
            return Err(SecretError::InvalidLength {
                expected: expected_len,
                actual: s.len(),
            });
        }
        // 字节级校验：多字节 UTF-8（>= 0x80）天然不在 base64url 集合内，前缀 `[a-z_]+` 顺带覆盖。
        if let Some(position) = s
            .bytes()
            .position(|b| !b.is_ascii_alphanumeric() && b != b'-' && b != b'_')
        {
            return Err(SecretError::InvalidCharset { position });
        }
        Ok(Self(s.to_string()))
    }

    /// 返回密钥类型（根据前缀）。
    pub fn kind(&self) -> Option<SecretKind> {
        SecretKind::from_prefix(&self.0)
    }

    /// 返回明文（仅在需要传输/校验时使用）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 计算 SHA-256 hash（hex），用于存储和查表。
    pub fn hash(&self) -> SecretHash {
        SecretHash::from_plain(&self.0)
    }

    /// 返回可用于日志/展示的脱敏前缀（前缀 + 前 8 位 base64）。
    pub fn masked(&self) -> String {
        let prefix_len = SecretKind::from_prefix(&self.0)
            .map(|k| k.prefix().len())
            .unwrap_or(0);
        let take = (prefix_len + 8).min(self.0.len());
        format!("{}...", &self.0[..take])
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 永不输出明文，避免意外泄露到日志
        f.debug_tuple("Secret").field(&"<redacted>").finish()
    }
}

/// 密钥的 SHA-256 hash（hex），可安全存储到数据库、打印到日志、用作索引。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHash(String);

impl SecretHash {
    /// 从明文计算 hash。
    pub fn from_plain(plain: &str) -> Self {
        let digest = Sha256::digest(plain.as_bytes());
        Self(hex::encode(digest))
    }

    /// 返回 hex 字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Secret 操作错误。
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    // getrandom 0.2 的 Error 不 impl std::error::Error（需 std feature），存 code 免引入该依赖。
    /// OS 随机源故障（仅 [`Secret::generate`] 生成路径会出现）。
    #[error("getrandom failed (code {code})")]
    Rng { code: u32 },
    /// 前缀不属于三种已知凭据类型（crbs_tok_ / crbs_wkr_ / crbs_sess_），空串同归此类；
    /// `prefix` 只回显输入前 4 字符，typo token 的熵字符不进错误信息。
    #[error("unknown secret prefix (got '{prefix}…'); expected 'crbs_tok_', 'crbs_wkr_' or 'crbs_sess_'")]
    UnknownPrefix { prefix: String },
    /// 总长不符：合法密钥总长固定 = 前缀长度 + 43（32 字节 base64url 无 pad）。
    #[error("invalid secret length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    /// 随机部分含 base64url 字符集（`[A-Za-z0-9_-]`，无 `=` pad）之外的字节；
    /// `position` 为首个非法字节的字节偏移（非字符偏移）。
    #[error("invalid secret charset: expected base64url [A-Za-z0-9_-], found invalid byte at position {position}")]
    InvalidCharset { position: usize },
}

fn encode_base64url(input: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

#[allow(clippy::manual_div_ceil)]
const fn encoded_len(input_len: usize) -> usize {
    // ceil(input_len * 4 / 3)，无 padding
    (input_len * 4 + 2) / 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_user_token_has_correct_format() {
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let s = secret.as_str();
        assert!(s.starts_with(PREFIX_USER_TOKEN));
        // prefix(9) + 43 = 52
        assert_eq!(s.len(), 52);
        assert_eq!(secret.kind(), Some(SecretKind::UserToken));
    }

    #[test]
    fn generate_worker_secret_has_correct_format() {
        let secret = Secret::generate(SecretKind::WorkerSecret).unwrap();
        let s = secret.as_str();
        assert!(s.starts_with(PREFIX_WORKER_SECRET));
        assert_eq!(s.len(), 52);
        assert_eq!(secret.kind(), Some(SecretKind::WorkerSecret));
    }

    #[test]
    fn generate_session_has_correct_format() {
        let secret = Secret::generate(SecretKind::Session).unwrap();
        let s = secret.as_str();
        assert!(s.starts_with(PREFIX_SESSION));
        assert_eq!(s.len(), PREFIX_SESSION.len() + 43);
        assert_eq!(secret.kind(), Some(SecretKind::Session));
    }

    #[test]
    fn generate_produces_unique_secrets() {
        let a = Secret::generate(SecretKind::UserToken).unwrap();
        let b = Secret::generate(SecretKind::UserToken).unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn parse_valid_user_token() {
        let original = Secret::generate(SecretKind::UserToken).unwrap();
        let parsed = Secret::parse(original.as_str()).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.kind(), Some(SecretKind::UserToken));
    }

    #[test]
    fn parse_valid_worker_secret() {
        let original = Secret::generate(SecretKind::WorkerSecret).unwrap();
        let parsed = Secret::parse(original.as_str()).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.kind(), Some(SecretKind::WorkerSecret));
    }

    #[test]
    fn parse_valid_session() {
        let original = Secret::generate(SecretKind::Session).unwrap();
        let parsed = Secret::parse(original.as_str()).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.kind(), Some(SecretKind::Session));
    }

    #[test]
    fn parse_rejects_unknown_prefix() {
        let err = Secret::parse("unknown_prefix_abc").unwrap_err();
        assert!(matches!(err, SecretError::UnknownPrefix { .. }));
    }

    #[test]
    fn parse_rejects_no_prefix_token() {
        let err = Secret::parse("abc123def456").unwrap_err();
        assert!(matches!(err, SecretError::UnknownPrefix { .. }));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let err = Secret::parse("crbs_tok_short").unwrap_err();
        assert!(matches!(err, SecretError::InvalidLength { .. }));
    }

    #[test]
    fn parse_rejects_correct_length_garbage_charset() {
        let garbage = "=".repeat(43); // base64url no-pad 不含 '='
        let s = format!("{PREFIX_USER_TOKEN}{garbage}");
        let err = Secret::parse(&s).unwrap_err();
        assert!(matches!(err, SecretError::InvalidCharset { .. }));

        // 含 '+'（标准 base64 字符，URL-safe 变体不允许）
        let s = format!("{PREFIX_USER_TOKEN}{}", "+".repeat(43));
        assert!(matches!(
            Secret::parse(&s).unwrap_err(),
            SecretError::InvalidCharset { .. }
        ));
    }

    /// 多字节 UTF-8 字符（长度凑对）必须拒绝：字节级字符集校验天然拦截 >= 0x80。
    #[test]
    fn parse_rejects_multibyte_characters() {
        // '产' 是 3 字节 UTF-8，14 个 '产' + 1 字节 ASCII = 43 字节
        let s = format!("{PREFIX_USER_TOKEN}{}x", "产".repeat(14));
        assert_eq!(s.len(), PREFIX_USER_TOKEN.len() + 43);
        assert!(matches!(
            Secret::parse(&s).unwrap_err(),
            SecretError::InvalidCharset { .. }
        ));
    }

    #[test]
    fn parse_rejects_empty_string() {
        assert!(matches!(
            Secret::parse("").unwrap_err(),
            SecretError::UnknownPrefix { .. }
        ));
    }

    /// 错误信息只回显前 4 字符：typo 的真实 token 不得在错误里泄露熵字符。
    #[test]
    fn parse_error_echoes_at_most_4_chars() {
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let mut typo: String = secret.as_str().to_string();
        typo.replace_range(0..1, "x");
        let err = Secret::parse(&typo).unwrap_err();
        let SecretError::UnknownPrefix { prefix } = err else {
            panic!("expected UnknownPrefix, got {err:?}")
        };
        assert_eq!(prefix, "xrbs");
    }

    #[test]
    fn hash_is_deterministic_and_64_hex() {
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let hash1 = secret.hash();
        let hash2 = secret.hash();
        assert_eq!(hash1.as_str(), hash2.as_str());
        assert_eq!(hash1.as_str().len(), 64);
        assert!(hash1.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_differs_for_different_secrets() {
        let a = Secret::generate(SecretKind::UserToken).unwrap();
        let b = Secret::generate(SecretKind::UserToken).unwrap();
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn debug_never_leaks_plaintext() {
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let debug_str = format!("{:?}", secret);
        assert!(!debug_str.contains(secret.as_str()));
        assert!(debug_str.contains("<redacted>"));
    }

    #[test]
    fn masked_returns_prefix_plus_few_chars() {
        let secret = Secret::generate(SecretKind::UserToken).unwrap();
        let masked = secret.masked();
        assert!(masked.starts_with(PREFIX_USER_TOKEN));
        assert!(masked.ends_with("..."));
        assert!(masked.len() < secret.as_str().len());
        assert!(!masked.contains(&secret.as_str()[PREFIX_USER_TOKEN.len() + 8..]));
    }

    #[test]
    fn kind_from_prefix_roundtrip() {
        assert_eq!(
            SecretKind::from_prefix(PREFIX_USER_TOKEN),
            Some(SecretKind::UserToken)
        );
        assert_eq!(
            SecretKind::from_prefix(PREFIX_WORKER_SECRET),
            Some(SecretKind::WorkerSecret)
        );
        assert_eq!(
            SecretKind::from_prefix(PREFIX_SESSION),
            Some(SecretKind::Session)
        );
        assert_eq!(SecretKind::from_prefix("unknown_"), None);
        assert_eq!(SecretKind::from_prefix(""), None);
    }

    #[test]
    fn prefix_constants() {
        assert_eq!(SecretKind::UserToken.prefix(), PREFIX_USER_TOKEN);
        assert_eq!(SecretKind::WorkerSecret.prefix(), PREFIX_WORKER_SECRET);
        assert_eq!(SecretKind::Session.prefix(), PREFIX_SESSION);
    }

    #[test]
    fn encoded_len_matches_actual() {
        let buf = [0u8; RANDOM_BYTES_LEN];
        let encoded = encode_base64url(&buf);
        assert_eq!(encoded.len(), encoded_len(RANDOM_BYTES_LEN));
        assert_eq!(encoded.len(), 43);
    }

    #[test]
    fn secret_hash_display() {
        let hash = SecretHash::from_plain("display-test");
        assert_eq!(format!("{}", hash), hash.as_str());
        assert_eq!(hash.as_str().len(), 64);
    }
}
