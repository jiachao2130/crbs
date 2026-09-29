// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 输入校验。

use std::path::Component;

use crate::server::error::ApiError;

// limit 上限单一事实源：CLI 侧预 clamp 与服务端硬拒共用。
pub(crate) use crbs_core::validation::MAX_LIST_LIMIT;

/// 校验 SRPM 路径：防目录穿越 + 必须存在 + 扩展名 .src.rpm + 必须在 allowed_root 下。
/// 存在性与"是否在 upload 目录内"共用同一固定文案、不回显探测路径——差分报错会向
/// 持有 builder 凭据的调用方泄露服务端 `*.src.rpm` 存在性（canonicalize 失败=不存在，目录外=存在）。
pub(crate) async fn validate_srpm_path(
    path: &str,
    allowed_root: &std::path::Path,
) -> Result<(), ApiError> {
    const SRPM_NOT_FOUND_OR_OUTSIDE: &str = "srpm not found or not within the upload directory";

    if !path.ends_with(".src.rpm") {
        return Err(ApiError::Validation("not a .src.rpm file".into()));
    }

    let p = std::path::Path::new(path);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ApiError::Validation("path contains parent dir (..)".into()));
    }

    let abs_path = tokio::fs::canonicalize(p)
        .await
        .map_err(|_| ApiError::Validation(SRPM_NOT_FOUND_OR_OUTSIDE.into()))?;

    let abs_root = tokio::fs::canonicalize(allowed_root)
        .await
        .map_err(|e| ApiError::log_and_internal_with_context("canonicalize upload_dir", e))?;

    if !abs_path.starts_with(&abs_root) {
        return Err(ApiError::Validation(SRPM_NOT_FOUND_OR_OUTSIDE.into()));
    }

    Ok(())
}

/// product 名校验（宽松版，读/删路径用）：**slug 语义**——`^[a-z0-9_-]+$`，非空。
/// 规则本体在 `crbs_core::validation::is_valid_slug`（单一事实源），此处仅做
/// ApiError 适配；区别于 `validate_product`（`is_ascii_alphanumeric`，允许大写、
/// CLI 读路径用），server 保持更严 slug。不含长度上限：存量 DB 可有 >128 的
/// 合法 slug，读/删不得因长度被挡；新名字写入走 [`validate_product_name_for_write`]。
pub(crate) fn validate_product_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::Validation("product name cannot be empty".into()));
    }
    if !crbs_core::validation::is_valid_slug(name) {
        return Err(ApiError::Validation(format!(
            "product name '{}' has invalid characters; only [a-z0-9_-] are allowed",
            name
        )));
    }
    Ok(())
}

/// product 名校验（严格版，create/update 写入口用）：宽松版全部规则 + 长度 ≤128。
/// 长度上限只在此执行：挡新超长名入库，不影响存量超长名读/删（走宽松版 [`validate_product_name`]）。
pub(crate) fn validate_product_name_for_write(name: &str) -> Result<(), ApiError> {
    validate_product_name(name)?;
    if name.len() > 128 {
        return Err(ApiError::Validation(format!(
            "product name too long (max 128 characters, got {})",
            name.len()
        )));
    }
    Ok(())
}

/// user 名校验：与 product name 同款 **slug 语义**——`^[a-z0-9_-]+$`。
/// 私有产品名 `{owner}/{product}` 的路径分量，须 URL-safe 与 filesystem-safe；
/// 规则本体在 `crbs_core::validation::validate_user_name`（create_user 同一真值），此处仅 ApiError 适配。
pub(crate) fn validate_user_name(name: &str) -> Result<(), ApiError> {
    crbs_core::validation::validate_user_name(name)?;
    Ok(())
}

/// 校验上传的 SRPM 文件名：防目录穿越 + 扩展名 .src.rpm。
pub(crate) fn validate_uploaded_srpm_name(name: &str) -> Result<(), ApiError> {
    let p = std::path::Path::new(name);
    if p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ApiError::Validation(
            "srpm file name contains absolute path or parent dir (..)".into(),
        ));
    }
    let file_name = p
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ApiError::Validation("invalid srpm file name".into()))?;
    if !file_name.ends_with(".src.rpm") {
        return Err(ApiError::Validation(
            "uploaded file must be a .src.rpm".into(),
        ));
    }
    Ok(())
}

/// 校验构建优先级：0-2 范围 + `priority=2 (critical)` 仅 operator 及以上可用。
/// 提交入口与 rebuild / reproduce 重放共用；重放按**当前操作者**权限校验——operator 以下不得借 rebuild 继承原提交者的 critical。
pub(crate) fn validate_build_priority(
    priority: crbs_core::types::BuildPriority,
    is_operator: bool,
) -> Result<(), ApiError> {
    use crbs_core::types::{PRIORITY_CRITICAL, PRIORITY_DEFAULT};
    if !(PRIORITY_DEFAULT..=PRIORITY_CRITICAL).contains(&priority) {
        return Err(ApiError::Validation(
            "priority must be 0 (default), 1 (high), or 2 (critical)".into(),
        ));
    }
    if priority == PRIORITY_CRITICAL && !is_operator {
        return Err(ApiError::PermissionDenied(
            "only operator or admin can set priority=2 (critical)".into(),
        ));
    }
    Ok(())
}

/// 列表接口 offset 上限：防无上限 offset 直达 SQL 造成资源滥用。
pub(crate) const MAX_LIST_OFFSET: usize = 1_000_000;

/// 校验列表 limit / offset 查询参数；超限 fail-closed 返回 400（消息带上限值），不静默截断。
pub(crate) fn validate_list_pagination(
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<(), ApiError> {
    if let Some(l) = limit {
        if l > MAX_LIST_LIMIT {
            return Err(ApiError::Validation(format!(
                "limit must be <= {MAX_LIST_LIMIT} (got {l})"
            )));
        }
    }
    if let Some(o) = offset {
        if o > MAX_LIST_OFFSET {
            return Err(ApiError::Validation(format!(
                "offset must be <= {MAX_LIST_OFFSET} (got {o})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn valid_srpm_inside_upload_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let srpm = upload_dir.join("pkg.src.rpm");
        std::fs::File::create(&srpm).unwrap();
        assert!(validate_srpm_path(srpm.to_str().unwrap(), &upload_dir)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn srpm_outside_upload_dir_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let outside = tmp.path().join("pkg.src.rpm");
        std::fs::File::create(&outside).unwrap();
        let err = validate_srpm_path(outside.to_str().unwrap(), &upload_dir)
            .await
            .unwrap_err();
        // 与"文件不存在"共用同一固定文案（不构成存在性 oracle）。
        assert!(matches!(
            err,
            ApiError::Validation(ref msg)
                if msg == "srpm not found or not within the upload directory"
        ));
    }

    #[tokio::test]
    async fn srpm_with_parent_dir_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let err = validate_srpm_path("../pkg.src.rpm", &upload_dir)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("parent dir")
        ));
    }

    #[tokio::test]
    async fn missing_srpm_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let missing = upload_dir.join("missing.src.rpm");
        let err = validate_srpm_path(missing.to_str().unwrap(), &upload_dir)
            .await
            .unwrap_err();
        // 固定文案不构成存在性 oracle，且不回显探测目标路径。
        assert!(matches!(
            err,
            ApiError::Validation(ref msg)
                if msg == "srpm not found or not within the upload directory"
        ));
    }

    #[tokio::test]
    async fn wrong_extension_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().join("uploads");
        std::fs::create_dir_all(&upload_dir).unwrap();
        let bad = upload_dir.join("pkg.rpm");
        std::fs::File::create(&bad).unwrap();
        let err = validate_srpm_path(bad.to_str().unwrap(), &upload_dir)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains(".src.rpm")
        ));
    }

    #[test]
    fn product_name_too_long_rejected_by_strict_version() {
        let long_name = "a".repeat(129);
        let err = validate_product_name_for_write(&long_name).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("too long")
        ));
    }

    #[test]
    fn product_name_length_split_between_read_and_write() {
        let legacy = "a".repeat(200);
        assert!(
            validate_product_name(&legacy).is_ok(),
            "lenient version must accept legacy long slug names"
        );
        let err = validate_product_name_for_write(&legacy).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("too long")
        ));

        let bad = "Bad-Name";
        assert!(validate_product_name(bad).is_err());
        assert!(validate_product_name_for_write(bad).is_err());
    }

    #[test]
    fn user_name_too_long_rejected() {
        let long_name = "a".repeat(129);
        let err = validate_user_name(&long_name).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("too long")
        ));
    }

    #[test]
    fn list_pagination_within_bounds_accepted() {
        assert!(validate_list_pagination(None, None).is_ok());
        assert!(validate_list_pagination(Some(1), Some(0)).is_ok());
        assert!(validate_list_pagination(Some(MAX_LIST_LIMIT), Some(MAX_LIST_OFFSET)).is_ok());
    }

    #[test]
    fn list_pagination_limit_over_cap_rejected() {
        let err = validate_list_pagination(Some(MAX_LIST_LIMIT + 1), None).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("limit must be <= 200")
        ));
    }

    #[test]
    fn list_pagination_offset_over_cap_rejected() {
        let err = validate_list_pagination(None, Some(MAX_LIST_OFFSET + 1)).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Validation(ref msg) if msg.contains("offset must be <= 1000000")
        ));
    }

    /// priority 门：0/1 对所有人开放；critical(2) 仅 operator 及以上；
    /// 越界（含 background=-1）一律 Validation。
    #[test]
    fn build_priority_gate_matches_operator_rule() {
        use crbs_core::types::{PRIORITY_CRITICAL, PRIORITY_DEFAULT};
        assert!(validate_build_priority(PRIORITY_DEFAULT, false).is_ok());
        assert!(validate_build_priority(1, false).is_ok());
        assert!(validate_build_priority(PRIORITY_CRITICAL, true).is_ok());

        let err = validate_build_priority(PRIORITY_CRITICAL, false).unwrap_err();
        assert!(matches!(err, ApiError::PermissionDenied(_)));

        for out_of_range in [-1, 3] {
            let err = validate_build_priority(out_of_range, true).unwrap_err();
            assert!(matches!(err, ApiError::Validation(_)));
        }
    }
}
