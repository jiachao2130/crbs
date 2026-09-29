// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建内包清单：已安装包读取、base OS 包集与 GPG key 过滤。

use crate::engine::cache::CacheEntry;
use crate::error::CrbsError;
use std::collections::HashSet;
use std::path::Path;

/// `rpm -qa --root` 兜底超时：umount 前扫描窗口内停滞存储挂死的 rpm 不得无限占用构建 future。
const RPM_QA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// NEVRA 是否为 RPMDB 中的 gpg-pubkey 伪包（如 `gpg-pubkey-f4a80eb5-53a7ff4b`）。
///
/// 谓词：strip `gpg-pubkey-` 前缀后首字符须为 ascii hexdigit（VERSION 为 GPG keyid
/// 十六进制），不误杀 `gpg-pubkey-utils-1.0-1` 等真实包；NEVRA 形态包清单的保存/消费
/// 两侧共享本谓词同一口径。已知误杀（保守维持）：hex 字母开头的 `gpg-pubkey-fedora-…`
/// 会被误判为伪包，不收紧"首 token 全 hex"（会翻掉 `gpg-pubkey-1.0-1`）——现状由
/// `test_is_gpg_pubkey_nevra_filters_hex_letter_prefixed_names` 回归披露。
pub(crate) fn is_gpg_pubkey_nevra(nevra: &str) -> bool {
    matches!(
        nevra.strip_prefix("gpg-pubkey-"),
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_hexdigit())
    )
}

/// 扫描指定 root 中已安装的所有 RPM 包（`cancel_token` + 60s 超时兜底 umount 前扫描
/// 窗口；超时 Err 沿调用方 fail-soft 分支：deterministic/replay 收严，其余 warn + None）。
pub(crate) async fn read_overlay_installed_packages(
    root: &Path,
    cancel_token: Option<&tokio_util::sync::CancellationToken>,
) -> crate::Result<Vec<String>> {
    let mut cmd = tokio::process::Command::new("rpm");
    cmd.arg("-qa")
        .arg(format!("--root={}", root.display()))
        .arg("--queryformat=%{NAME}\t%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n");
    let output = crate::engine::command::run_command_capped_output_with_cancel_and_timeout(
        cmd,
        "spawn rpm -qa for root",
        cancel_token,
        RPM_QA_TIMEOUT,
    )
    .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CrbsError::io_message(format!(
            "rpm -qa for root failed: {}",
            stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let pkgs = tokio::task::spawn_blocking(move || {
        let mut pkgs: Vec<String> = stdout
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                if l.is_empty() {
                    return None;
                }
                let (name, nevra) = l.split_once('\t')?;
                // gpg-pubkey 是导入 GPG 密钥写入 RPMDB 的伪包，参与 reproducibility
                // 校验会因密钥导入时机不一致而误报；精确名匹配，口径见 [`is_gpg_pubkey_nevra`]。
                if name == "gpg-pubkey" {
                    return None;
                }
                Some(nevra.to_string())
            })
            .collect();
        pkgs.sort();
        pkgs.dedup();
        pkgs
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("spawn_blocking sort rpm -qa output: {}", e)))?;
    Ok(pkgs)
}

/// 加载 base_os 层记录的包清单（`.packages.json`），供 reproduce Phase 1 校验
/// 区分 base 包与缺失 builddep。文件缺失返回 `Ok(None)`（区别于读取/解析失败的
/// `Err`）：须跳过 base_os 侧 missing 判定，不得把全部依赖推入 missing（误报
/// ValidationFailed）。清单路径由调用方给定（产品 base 路径）。
pub(crate) async fn load_base_os_packages_at(
    packages_json: &std::path::Path,
) -> crate::Result<Option<HashSet<String>>> {
    if !tokio::fs::try_exists(packages_json).await? {
        return Ok(None);
    }
    let content = tokio::fs::read_to_string(packages_json)
        .await
        .map_err(|e| CrbsError::from_io_context("read base_os .packages.json", e))?;
    let packages: std::collections::HashMap<String, CacheEntry> = serde_json::from_str(&content)
        .map_err(|e| CrbsError::ValidationFailed {
            message: format!(
                "parse base_os .packages.json {}: {}",
                packages_json.display(),
                e
            ),
        })?;
    Ok(Some(packages.into_keys().collect()))
}

#[cfg(test)]
mod tests {
    use super::is_gpg_pubkey_nevra;

    #[test]
    fn test_is_gpg_pubkey_nevra_true_for_pseudo_package() {
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-1.0-1"));
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-64d62633-52f3f0bb"));
        // CentOS 7 真实 keyid，字母开头（十六进制），仍是伪包。
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-f4a80eb5-53a7ff4b"));
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-f4a80eb5-53a7ff4b.noarch"));
    }

    #[test]
    fn test_is_gpg_pubkey_nevra_false_for_real_packages() {
        // 误杀回归：gpg-pubkey-utils 是真实包，不得被当伪包过滤。
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-utils-1.0-1"));
        assert!(!is_gpg_pubkey_nevra("foo-1.0-1"));
        assert!(!is_gpg_pubkey_nevra("bzip2-1.0.8-6.ule3.x86_64"));
    }

    #[test]
    fn test_is_gpg_pubkey_nevra_false_for_non_hexdigit_suffix() {
        // `gpg-pubkey-` 后首字符非 hexdigit（`u`/`z`/`.`）→ keyid 形态不匹配，非伪包。
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-x"));
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-z"));
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-.1-1"));
        // 点号形态非伪包 NEVRA：伪包只有 `gpg-pubkey-<keyid>-<release>` 一种形态。
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey.f4a80eb5"));
    }

    #[test]
    fn test_is_gpg_pubkey_nevra_false_for_edge_inputs() {
        // 空串、裸前缀、大小写变体：NEVRA 区分大小写，只精确匹配小写伪包名。
        assert!(!is_gpg_pubkey_nevra(""));
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-"));
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey"));
        assert!(!is_gpg_pubkey_nevra("GPG-PUBKEY-1.0-1"));
        assert!(!is_gpg_pubkey_nevra("gpg_pubkey-1.0-1"));
    }

    /// 回归披露现状：hex 字母开头的 `gpg-pubkey-` 名字被误判为伪包，不收紧理由见谓词 doc。
    #[test]
    fn test_is_gpg_pubkey_nevra_filters_hex_letter_prefixed_names() {
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-fedora-40-1"));
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-admin-1.0-1"));
        assert!(is_gpg_pubkey_nevra("gpg-pubkey-backup-2.0-1.noarch"));
        assert!(!is_gpg_pubkey_nevra("gpg-pubkey-utils-1.0-1"));
    }
}
