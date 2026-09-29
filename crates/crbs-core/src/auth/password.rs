// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 密码哈希与密码策略：argon2id（默认参数 ≈19MiB）+ 每密码随机盐，PHC
//! 格式串存 `users.password_hash`；明文密码不进日志/审计（调用方只记事件名）。

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

/// 密码最小长度（字符数，非字节数——unicode 密码按字符计）。
pub const PASSWORD_MIN_CHARS: usize = 10;
/// 密码最大长度（字符数）：上限防超长输入对 argon2 的 DoS。
pub const PASSWORD_MAX_CHARS: usize = 1024;

/// 密码策略校验（仅长度 10–1024 字符，NIST 风格无组成规则；不 trim，
/// 允许任意 unicode）；注册与改密（CLI set-password）共用收口。
pub fn validate_password_policy(plain: &str) -> Result<(), PasswordPolicyError> {
    let chars = plain.chars().count();
    if chars < PASSWORD_MIN_CHARS {
        return Err(PasswordPolicyError::TooShort {
            min: PASSWORD_MIN_CHARS,
        });
    }
    if chars > PASSWORD_MAX_CHARS {
        return Err(PasswordPolicyError::TooLong {
            max: PASSWORD_MAX_CHARS,
        });
    }
    Ok(())
}

/// 盐字节数（PHC 推荐的 128 bit）。
const SALT_BYTES_LEN: usize = 16;

/// 哈希密码：argon2id 默认参数 + 每密码随机盐，返回 PHC 标准格式串；盐来自
/// [`getrandom`]（与 [`crate::auth::secret`] 的密钥生成同源）。
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let mut salt_bytes = [0u8; SALT_BYTES_LEN];
    getrandom::getrandom(&mut salt_bytes).map_err(|e| PasswordError::Hash(e.to_string()))?;
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| PasswordError::Hash(e.to_string()))?;
    let hashed = Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(hashed.to_string())
}

/// 校验密码与 PHC 串是否匹配；解析失败（坏 PHC / 空串 / 非 argon2）与不匹配
/// 统一返回 `false`——登录路径不区分两者，不因库内垃圾数据 panic。
pub fn verify_password(plain: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

/// 假验证用的固定明文（仅时序对齐，任何值皆可，勿与真实口令关联）。
const DUMMY_VERIFY_PLAIN: &str = "crbs-dummy-verify-password";

/// 假验证的 PHC 串（首次调用惰性生成一次，进程内复用）。
fn dummy_phc() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| {
        // 生成失败退化为空串：verify_password 对空 PHC 恒 false，登录仍正确、时序对齐弱化。
        hash_password(DUMMY_VERIFY_PLAIN).unwrap_or_default()
    })
}

/// 常数时间纪律的假验证：用户不存在 / 未设密码的登录路径执行一次与真实校验
/// 同开销的 argon2 验证，抹平"用户存在与否"的时序差（防枚举）。
pub fn dummy_verify(plain: &str) {
    let _ = verify_password(plain, dummy_phc());
}

/// 密码哈希错误。
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// argon2 哈希失败（OS 随机源故障等内部错误；不含明文）。
    #[error("password hashing failed: {0}")]
    Hash(String),
    /// 临时密码生成失败（OS 随机源故障；不含明文）。
    #[error("temporary password generation failed: {0}")]
    Temp(String),
}

/// 临时密码长度（admin 重置生成）：16 字符字母数字 ≈ 95 bit 熵。
pub const TEMP_PASSWORD_LEN: usize = 16;

/// 生成临时随机密码（admin 重置）：16 字符 `[A-Za-z0-9]`，随机源 [`getrandom`]
/// （与 [`Secret`](crate::auth::secret::Secret) 同源）；均匀性靠拒绝采样，无模偏置：
/// 只接受 `[0, 248)` 的随机字节（区间内 `% 62` 严格均匀），`[248, 256)` 丢弃重采样。
pub fn generate_temp_password() -> Result<String, PasswordError> {
    const CHARSET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    // 拒绝采样上限：≤ 256 的最大 62 倍数（62 × 4 = 248）；拒绝率 8/256 ≈ 3%。
    const ACCEPT_LIMIT: usize = CHARSET.len() * (256 / CHARSET.len());
    let mut out = String::with_capacity(TEMP_PASSWORD_LEN);
    let mut buf = [0u8; TEMP_PASSWORD_LEN];
    while out.len() < TEMP_PASSWORD_LEN {
        getrandom::getrandom(&mut buf).map_err(|e| PasswordError::Temp(e.to_string()))?;
        for &b in &buf {
            if (b as usize) < ACCEPT_LIMIT {
                out.push(CHARSET[(b as usize) % CHARSET.len()] as char);
                if out.len() == TEMP_PASSWORD_LEN {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// 密码策略错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasswordPolicyError {
    /// 密码长度低于下限：`min` 回显 [`PASSWORD_MIN_CHARS`]（字符数）。
    #[error("password must be at least {min} characters")]
    TooShort { min: usize },
    /// 密码长度超过上限：`max` 回显 [`PASSWORD_MAX_CHARS`]（字符数）。
    #[error("password must be at most {max} characters")]
    TooLong { max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(phc.starts_with("$argon2id$"), "PHC output: {phc}");
        assert!(verify_password("correct horse battery", &phc));
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(!verify_password("correct horse battery!", &phc));
        assert!(!verify_password("", &phc));
    }

    #[test]
    fn verify_rejects_malformed_phc() {
        assert!(!verify_password("whatever", ""));
        assert!(!verify_password("whatever", "not-a-phc-string"));
        // bcrypt 格式（合法 PHC 家族但非 argon2）：算法不匹配 → false
        assert!(!verify_password(
            "whatever",
            "$2b$12$KIXQeQePWr6F1e5mQe5mQeOQeQeQeQeQeQeQeQeQeQ"
        ));
        assert!(!verify_password("whatever", "$argon2id$v=19"));
    }

    #[test]
    fn hash_uses_random_salt() {
        let a = hash_password("same password 1").unwrap();
        let b = hash_password("same password 1").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same password 1", &a));
        assert!(verify_password("same password 1", &b));
    }

    #[test]
    fn policy_length_boundaries() {
        assert_eq!(
            validate_password_policy(&"a".repeat(9)),
            Err(PasswordPolicyError::TooShort { min: 10 })
        );
        assert!(validate_password_policy(&"a".repeat(10)).is_ok());
        assert!(validate_password_policy(&"a".repeat(1024)).is_ok());
        assert_eq!(
            validate_password_policy(&"a".repeat(1025)),
            Err(PasswordPolicyError::TooLong { max: 1024 })
        );
        assert_eq!(
            validate_password_policy(""),
            Err(PasswordPolicyError::TooShort { min: 10 })
        );
    }

    #[test]
    fn policy_counts_chars_not_bytes_and_supports_unicode() {
        let cjk: String = "密码密码密码密码密码".to_string(); // 10 chars, 30 bytes
        assert_eq!(cjk.chars().count(), 10);
        assert!(validate_password_policy(&cjk).is_ok());
        let phc = hash_password(&cjk).unwrap();
        assert!(verify_password(&cjk, &phc));
        // 9 个 CJK 字符（27 字节）按字符计不足 10，拒绝
        assert!(validate_password_policy("密码密码密码密码密").is_err());
    }

    /// 不 trim：前后空白按字面哈希，trim 后的值校验必须失败。
    #[test]
    fn policy_keeps_leading_trailing_whitespace_literal() {
        let padded = "  padded password  ";
        assert!(validate_password_policy(padded).is_ok());
        let phc = hash_password(padded).unwrap();
        assert!(verify_password(padded, &phc));
        assert!(!verify_password(padded.trim(), &phc));
    }

    #[test]
    fn dummy_verify_never_panics_and_reuses_phc() {
        // 静态 PHC 复用：两次取同 &'static 串（零克隆零再哈希）。
        assert!(std::ptr::eq(dummy_phc(), dummy_phc()));
        dummy_verify("whatever");
        dummy_verify("");
        dummy_verify(DUMMY_VERIFY_PLAIN);
    }

    #[test]
    fn temp_password_length_charset_and_randomness() {
        let a = generate_temp_password().unwrap();
        let b = generate_temp_password().unwrap();
        assert_eq!(a.chars().count(), TEMP_PASSWORD_LEN);
        assert!(validate_password_policy(&a).is_ok(), "{a}");
        assert!(
            a.chars().all(|c| c.is_ascii_alphanumeric()),
            "letters+digits only: {a}"
        );
        assert_ne!(a, b, "two generations must differ");
        let phc = hash_password(&a).unwrap();
        assert!(verify_password(&a, &phc));
    }

    /// 统计性抽测：10 万个临时密码（160 万字符）做卡方均匀性检验；无偏时统计量
    /// 服从 df=61 卡方分布（期望 ~61，σ≈11），断言 < 200（>12σ，不会 flaky）。
    #[test]
    fn temp_password_chi_square_uniformity() {
        const CHARSET: &[u8; 62] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const N_PASSWORDS: usize = 100_000;
        let mut counts = [0u64; 256];
        for _ in 0..N_PASSWORDS {
            let pw = generate_temp_password().unwrap();
            assert_eq!(pw.len(), TEMP_PASSWORD_LEN);
            for b in pw.bytes() {
                counts[b as usize] += 1;
            }
        }
        for (b, &c) in counts.iter().enumerate() {
            if !CHARSET.contains(&(b as u8)) {
                assert_eq!(c, 0, "byte {b:#04x} outside charset");
            }
        }
        let expected = (N_PASSWORDS * TEMP_PASSWORD_LEN) as f64 / 62.0;
        let chi2: f64 = CHARSET
            .iter()
            .map(|&c| {
                let d = counts[c as usize] as f64 - expected;
                d * d / expected
            })
            .sum();
        assert!(
            chi2 < 200.0,
            "chi-square = {chi2:.1}, df=61, unbiased expectation ~61±11"
        );
    }
}
