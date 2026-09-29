// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 公共校验与配置模板生成，供 `crbs` 和 `crbs-server` 复用。

use crate::error::CrbsError;

/// 列表接口分页参数 limit 上限（单一事实源）：server 硬拒超限（400），CLI 远程 status 预 clamp 防漂移。
pub const MAX_LIST_LIMIT: usize = 200;

/// 单任务标签数量上限（重复键在计数前先拒）。
pub const MAX_TASK_LABELS: usize = 16;
/// 标签键长度上限（字符）。
pub const MAX_TASK_LABEL_KEY_LEN: usize = 64;
/// 标签值长度上限（字符）。
pub const MAX_TASK_LABEL_VALUE_LEN: usize = 256;
/// 单任务全部标签的键值字符总数上限：防大批量长标签占用请求体与表行。
pub const MAX_TASK_LABELS_TOTAL_LEN: usize = 4096;

/// slug 语义谓词：非空且仅含 `[a-z0-9_-]`；单一事实源——`state::seed` 磁盘
/// 文件名 dispatch、server 宽松版产品名校验与 [`validate_user_name`] 均锚定本谓词。
pub fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// 校验产品名称：只允许 [a-zA-Z0-9_-]+，且非空。
/// 与 [`is_valid_slug`] 差异：本侧接受大写（运行时按名加载已入库产品），slug
/// 侧只认小写——大写命名的 `product.toml` 在 server bootstrap 被拒。
pub fn validate_product(name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "product name cannot be empty".into(),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "product name '{}' contains invalid characters. Only [a-zA-Z0-9_-] are allowed",
                name
            ),
        });
    }
    Ok(())
}

/// 校验用户名：**slug 语义**——`^[a-z0-9_-]+$`，非空，长度 ≤128。
/// 私有产品路径 `{owner}/{product}` 的分量，必须 URL-safe 与 filesystem-safe；
/// 权威收口在 `StateStore::create_user`，各入口预检只负责友好错误，不能替代收口。
pub fn validate_user_name(name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "user name cannot be empty".into(),
        });
    }
    if name.len() > 128 {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "user name too long (max 128 characters, got {})",
                name.len()
            ),
        });
    }
    if !is_valid_slug(name) {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "user name '{}' has invalid characters; only [a-z0-9_-] are allowed",
                name
            ),
        });
    }
    Ok(())
}

/// 校验 arch：只允许 [A-Za-z0-9_]+，且非空。
/// 拼进产品 repo baseurl：空白/控制字符可向 `.repo` 注入 dnf 指令
///（`x86_64\ngpgcheck=0`），`/`、`..` 可路径穿越，拼 URL 前收口。比 server 侧
/// `validate_worker_arch`（另允许 `-`/`.`）更严；常见 RPM arch 均在本字符集内。
pub fn validate_arch(arch: &str) -> crate::Result<()> {
    if arch.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "arch cannot be empty".into(),
        });
    }
    if !arch.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "arch '{}' contains invalid characters. Only [a-zA-Z0-9_] are allowed",
                arch
            ),
        });
    }
    Ok(())
}

/// 校验单个任务标签：键为 `[A-Za-z0-9_.-]` 非空且 ≤64 字符，值非空且
/// ≤256 字符；键值均拒绝控制字符（换行/制表会破坏展示与查询日志）。值可含
/// 空格与非 ASCII 可打印文本（URL 查询侧负责编码）。
pub fn validate_task_label(key: &str, value: &str) -> crate::Result<()> {
    if key.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "task label key cannot be empty".into(),
        });
    }
    if key.chars().count() > MAX_TASK_LABEL_KEY_LEN {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "task label key too long (max {MAX_TASK_LABEL_KEY_LEN} characters, got {})",
                key.chars().count()
            ),
        });
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "task label key '{}' contains invalid characters. Only [a-zA-Z0-9_.-] are allowed",
                key
            ),
        });
    }
    if value.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "task label value cannot be empty".into(),
        });
    }
    let value_len = value.chars().count();
    if value_len > MAX_TASK_LABEL_VALUE_LEN {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "task label value too long (max {MAX_TASK_LABEL_VALUE_LEN} characters, got {value_len})"
            ),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(CrbsError::ValidationFailed {
            message: format!("task label '{key}' value contains control characters"),
        });
    }
    Ok(())
}

/// 校验整组任务标签：逐条过 [`validate_task_label`]，再检查重复键、数量
/// 上限与键值总长度上限。键大小写敏感。
pub fn validate_task_labels(labels: &[(String, String)]) -> crate::Result<()> {
    if labels.len() > MAX_TASK_LABELS {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "too many task labels (max {MAX_TASK_LABELS}, got {})",
                labels.len()
            ),
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(labels.len());
    let mut total = 0usize;
    for (key, value) in labels {
        validate_task_label(key, value)?;
        if !seen.insert(key.as_str()) {
            return Err(CrbsError::ValidationFailed {
                message: format!("duplicate task label key '{key}'"),
            });
        }
        total += key.chars().count() + value.chars().count();
    }
    if total > MAX_TASK_LABELS_TOTAL_LEN {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "task labels too large (max {MAX_TASK_LABELS_TOTAL_LEN} characters in total, got {total})"
            ),
        });
    }
    Ok(())
}

/// 解析 `KEY=VALUE` 形式的标签（首个 `=` 切分）；键值均走
/// [`validate_task_label`]。用于 CLI `--label` 与 API `?label=`。
pub fn parse_task_label_arg(raw: &str) -> crate::Result<(String, String)> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| CrbsError::ValidationFailed {
            message: format!("task label '{raw}' is not in KEY=VALUE form"),
        })?;
    validate_task_label(key, value)?;
    Ok((key.to_string(), value.to_string()))
}

/// 校验 RPM 宏键名：只允许 [a-zA-Z0-9_]+，且非空。
/// 拼进 `rpmbuild --define 'KEY VALUE'`：`%`/`%()` 可注入宏语言（`%__cc` 指向
/// 任意可执行），空格/`-`/`.` 破坏 define 解析，各入口统一收口；常见宏名均在
/// 本字符集内。VALUE 默认不过滤（渲染经 shell_quote 单引号包裹）；例外
/// `dist`——值参与 release 后缀比对，经 validate_rpm_macro_entry 走
/// validate_dist_tag 白名单；仅空值在 `parse_macros` 拒（空宏体 rpm 报
/// "empty body" 族错误）。
pub fn validate_rpm_macro_key(key: &str) -> crate::Result<()> {
    if key.is_empty() {
        return Err(CrbsError::ValidationFailed {
            message: "rpm macro key cannot be empty".into(),
        });
    }
    if !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "rpm macro key '{}' contains invalid characters. Only [a-zA-Z0-9_] are allowed",
                key
            ),
        });
    }
    Ok(())
}

/// 确保全局配置、产品配置模板、overlay 目录就绪；产品配置不存在时生成模板并返回错误（提示编辑）。
pub async fn ensure_product_config_ready(product: &str) -> crate::Result<()> {
    use tracing::info;

    validate_product(product)?;

    let global_config_path = crate::config::config_path("crbs.toml")?;
    if !tokio::fs::try_exists(&global_config_path)
        .await
        .map_err(|e| CrbsError::from_io_context("check global config", e))?
    {
        info!(path = %global_config_path.display(), "Generating global config template");
        let parent = global_config_path
            .parent()
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: "global config path has no parent".into(),
            })?;
        // 裸 create_dir_all 是 0755 creator-group：root 先建后，组内身份再写
        // 同目录即 EACCES；ensure_directory 同步阻塞，必须 spawn_blocking。
        let p = parent.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::privilege::ensure_directory(&p, "global config")
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("ensure global config dir: {e}")))??;
        tokio::fs::write(&global_config_path, crate::config::GLOBAL_CONFIG_TEMPLATE)
            .await
            .map_err(|e| CrbsError::from_io_context("write global config template", e))?;
        harden_config_template(&global_config_path).await;
    }

    let product_config_path = crate::config::config_path(format!("products/{}.toml", product))?;
    if !tokio::fs::try_exists(&product_config_path)
        .await
        .map_err(|e| CrbsError::from_io_context("check product config", e))?
    {
        info!(path = %product_config_path.display(), "Generating product config template");
        let parent = product_config_path
            .parent()
            .ok_or_else(|| CrbsError::ValidationFailed {
                message: "product config path has no parent".into(),
            })?;
        let p = parent.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::privilege::ensure_directory(&p, "product config")
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("ensure products dir: {e}")))??;
        let template = crate::config::PRODUCT_CONFIG_TEMPLATE.replace("{product}", product);
        tokio::fs::write(&product_config_path, template)
            .await
            .map_err(|e| CrbsError::from_io_context("write product config template", e))?;
        harden_config_template(&product_config_path).await;
        return Err(CrbsError::ValidationFailed {
            message: format!(
                "Product config template generated at {}. \
                 Please edit it (set base_packages and repos) then run again.",
                product_config_path.display(),
            ),
        });
    }

    let overlay_dir = crate::config::config_path(format!("overlays/{}", product))?;
    if !tokio::fs::try_exists(&overlay_dir)
        .await
        .map_err(|e| CrbsError::from_io_context("check overlay dir", e))?
    {
        let p = overlay_dir.clone();
        tokio::task::spawn_blocking(move || {
            crate::privilege::ensure_directory(&p, "product overlay")
        })
        .await
        .map_err(|e| CrbsError::io_message(format!("ensure overlay dir: {e}")))??;
    }

    Ok(())
}

/// 配置模板落盘后的权限不变量收口：0660 + crbs 组。
/// chmod 失败仅 warn（权限未生效）；chown 失败 helper 内 debug（非 root chown 必然 EPERM）。
async fn harden_config_template(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).await
        {
            tracing::warn!(path = %path.display(), error = %e,
                "Failed to chmod config template to 0660; group rw may not be in effect");
        }
    }
    crate::privilege::chown_to_crbs_group_async(path, false, "config template").await;
}

/// 校验容器参数：backend + 资源限制三合一。
/// Build / Shell / Debug 共用，Shell 额外禁止 resource limits。
/// `config` 由调用方从 hub `/resolved` 预加载传入（与 backend fallback 同源）。
pub async fn validate_container_params(
    backend: &Option<String>,
    memory_max: &Option<String>,
    cpu_quota: &Option<String>,
    config: &crate::config::Config,
    allow_limits: bool,
) -> crate::Result<String> {
    if let Some(ref m) = memory_max {
        crate::config::validate_memory_max(m)?;
    }
    if let Some(ref c) = cpu_quota {
        crate::config::validate_cpu_quota(c)?;
    }
    let effective_backend = match backend {
        Some(b) => b.clone(),
        None => config.backend.clone(),
    };
    // backend 名精确匹配、不 trim（与 create_backend 一致）：`"chroot "` 这类
    // 带空白名按未知 backend 拒，堵住借精确比较绕过 chroot 资源限制。
    crate::build_options::validate_backend_name(&effective_backend)?;
    if effective_backend == "chroot" && (memory_max.is_some() || cpu_quota.is_some()) {
        return Err(CrbsError::ValidationFailed {
            message: "--memory-max/--cpu-quota require --backend nspawn; \
             chroot backend does not support cgroup resource limits"
                .into(),
        });
    }
    if !allow_limits && (memory_max.is_some() || cpu_quota.is_some()) {
        return Err(CrbsError::ValidationFailed {
            message: "--memory-max/--cpu-quota are not allowed with shell; \
             resource limits do not apply to interactive shells"
                .into(),
        });
    }
    Ok(effective_backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(backend: &str) -> crate::config::Config {
        crate::config::Config {
            backend: backend.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn product_name_accepts_ascii_slug() {
        assert!(validate_product("openEuler-24_03_LTS").is_ok());
        assert!(validate_product("a").is_ok());
    }

    /// 非 ASCII 必拒：Unicode 同形字（中文 / Cyrillic）不能借 `is_alphanumeric()` 放行。
    #[test]
    fn product_name_rejects_non_ascii() {
        assert!(validate_product("产品").is_err());
        assert!(validate_product("f\u{430}ke").is_err()); // Cyrillic 'а' 同形字
    }

    #[test]
    fn product_name_rejects_empty_and_space() {
        assert!(validate_product("").is_err());
        assert!(validate_product("my product").is_err());
    }

    #[test]
    fn arch_accepts_common_rpm_arches() {
        assert!(validate_arch("x86_64").is_ok());
        assert!(validate_arch("aarch64").is_ok());
        assert!(validate_arch("riscv64").is_ok());
        assert!(validate_arch("loongarch64").is_ok());
    }

    /// 注入 / 穿越 / 非 ASCII 必拒：换行可注入 dnf 指令，`/`、`..` 可做路径穿越。
    #[test]
    fn arch_rejects_injection_and_traversal() {
        assert!(validate_arch("").is_err());
        assert!(validate_arch("x86_64\ngpgcheck=0").is_err());
        assert!(validate_arch("x86 64").is_err());
        assert!(validate_arch("a/b").is_err());
        assert!(validate_arch("..").is_err());
        // 连字符/点号也不允许（比 server 侧 validate_worker_arch 更严）
        assert!(validate_arch("arm-64").is_err());
        assert!(validate_arch("arm.64").is_err());
        assert!(validate_arch("架构").is_err());
    }

    #[tokio::test]
    async fn container_params_accepts_known_backend_with_limits() {
        let config = test_config("chroot");
        let effective = validate_container_params(
            &Some("nspawn".into()),
            &Some("2G".into()),
            &None,
            &config,
            true,
        )
        .await
        .unwrap();
        assert_eq!(effective, "nspawn");
    }

    #[tokio::test]
    async fn container_params_rejects_unknown_backend() {
        let config = test_config("chroot");
        let err = validate_container_params(&Some("docker".into()), &None, &None, &config, true)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("backend must be 'chroot' or 'nspawn'"),
            "got: {err}"
        );
    }

    /// 回归：`"chroot "`（尾随空格）按未知 backend 拒——不 trim，堵绕过 chroot 资源限制。
    #[tokio::test]
    async fn container_params_rejects_chroot_with_trailing_space() {
        let config = test_config("chroot");
        let err = validate_container_params(
            &Some("chroot ".into()),
            &Some("2G".into()),
            &None,
            &config,
            true,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("backend must be 'chroot' or 'nspawn'"),
            "got: {err}"
        );
    }

    /// backend 回退到产品配置时同样校验：配置里的非法 backend 也要拦下。
    #[tokio::test]
    async fn container_params_validates_config_backend_fallback() {
        let config = test_config("podman");
        let err = validate_container_params(&None, &None, &None, &config, true)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("backend must be 'chroot' or 'nspawn'"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn container_params_rejects_limits_on_chroot() {
        let config = test_config("chroot");
        let err = validate_container_params(
            &Some("chroot".into()),
            &Some("2G".into()),
            &None,
            &config,
            true,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("chroot"), "got: {err}");
    }

    #[test]
    fn task_label_validation_accepts_common_shapes() {
        for (key, value) in [
            ("git-repo", "https://example.com/r.git"),
            ("git_commit", "deadbeef"),
            ("alias.v2", "nightly 构建"),
            ("ticket-123", "=value with = signs"),
        ] {
            validate_task_label(key, value).unwrap();
        }
        assert_eq!(
            parse_task_label_arg("git-commit=abc=def").unwrap(),
            ("git-commit".to_string(), "abc=def".to_string()),
            "split on the first '=' only"
        );
    }

    #[test]
    fn task_label_validation_rejects_invalid_shapes() {
        let cases = [
            ("", "v", "key cannot be empty"),
            ("bad key", "v", "invalid characters"),
            ("bad/key", "v", "invalid characters"),
            ("k", "", "value cannot be empty"),
            ("k", "line\nbreak", "control characters"),
            ("k", "tab\tvalue", "control characters"),
        ];
        for (key, value, needle) in cases {
            let err = validate_task_label(key, value).unwrap_err();
            assert!(err.to_string().contains(needle), "case {key:?}: {err}");
        }
        let err = parse_task_label_arg("no-equals").unwrap_err();
        assert!(
            err.to_string().contains("not in KEY=VALUE form"),
            "got: {err}"
        );
        let long_key = "k".repeat(MAX_TASK_LABEL_KEY_LEN + 1);
        assert!(validate_task_label(&long_key, "v")
            .unwrap_err()
            .to_string()
            .contains("too long"));
        let long_value = "v".repeat(MAX_TASK_LABEL_VALUE_LEN + 1);
        assert!(validate_task_label("k", &long_value)
            .unwrap_err()
            .to_string()
            .contains("too long"));
    }

    #[test]
    fn task_label_set_validation_rejects_duplicates_and_caps() {
        let dup = vec![
            ("a".to_string(), "1".to_string()),
            ("a".to_string(), "2".to_string()),
        ];
        assert!(validate_task_labels(&dup)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        let too_many: Vec<(String, String)> = (0..=MAX_TASK_LABELS)
            .map(|i| (format!("k{i}"), "v".to_string()))
            .collect();
        assert!(validate_task_labels(&too_many)
            .unwrap_err()
            .to_string()
            .contains("too many"));

        let big: Vec<(String, String)> = (0..MAX_TASK_LABELS)
            .map(|i| (format!("k{i}"), "v".repeat(MAX_TASK_LABEL_VALUE_LEN)))
            .collect();
        assert!(validate_task_labels(&big)
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }
}
