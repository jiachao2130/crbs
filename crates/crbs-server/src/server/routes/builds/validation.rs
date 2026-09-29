// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建请求字段校验：长度上限、布尔/数值解析与错误文案。

use axum::extract::multipart::Field;

use crate::server::error::ApiError;

/// 文本字段大小上限：per-file 流式限额只覆盖 `srpm`，文本字段只受整个 body 限制
///（默认 500MB）——单个 `retry` 字段即可分配 500MB 字符串回显进响应/日志，并发数个即内存耗尽。
pub(crate) const MAX_TEXT_FIELD_BYTES: usize = 64 * 1024;

/// 错误回显长度上限：不回显超长原文（防把大字段内容再复制进响应/日志）。
fn truncate_for_error(text: &str) -> &str {
    text.char_indices()
        .take(64)
        .last()
        .map(|(i, c)| &text[..i + c.len_utf8()])
        .unwrap_or(text)
}

pub(crate) async fn read_text_field(field: Field<'_>) -> Result<String, ApiError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut limited = field;
    while let Some(chunk) = limited
        .chunk()
        .await
        // 流中断（连接切断 / multipart 解析错误）归 500 而非 400：瞬断是传输层
        // 故障，落 400 令 CLI 放弃整传（不重试）；内容校验仍是请求语义错误，维持 400。
        .map_err(|e| ApiError::log_and_internal_with_context("read form field", e))?
    {
        if buf.len() + chunk.len() > MAX_TEXT_FIELD_BYTES {
            return Err(ApiError::Validation(format!(
                "form field exceeds {} bytes",
                MAX_TEXT_FIELD_BYTES
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| {
        ApiError::Validation(format!("form field is not valid UTF-8: {}", e.utf8_error()))
    })
}

pub(crate) async fn parse_bool_field(field: Field<'_>) -> Result<bool, ApiError> {
    let text = read_text_field(field).await?;
    match text.as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ApiError::Validation(format!(
            "invalid boolean value: {}",
            truncate_for_error(&text)
        ))),
    }
}

pub(crate) async fn parse_u64_field(field: Field<'_>) -> Result<u64, ApiError> {
    let text = read_text_field(field).await?;
    text.parse().map_err(|e| {
        ApiError::Validation(format!(
            "invalid integer value '{}': {}",
            truncate_for_error(&text),
            e
        ))
    })
}

pub(crate) async fn parse_u32_field(field: Field<'_>) -> Result<u32, ApiError> {
    let text = read_text_field(field).await?;
    parse_u32_text(&text, "form field")
}

/// 已读文本的 u32 解析（`parse_u32_field` 与 min_ncpu 预清理臂共用）：错误带
/// 调用方语义名（"min_ncpu" / "form field"），回显经 truncate_for_error 截断。
pub(crate) fn parse_u32_text(text: &str, name: &str) -> Result<u32, ApiError> {
    text.parse().map_err(|e| {
        ApiError::Validation(format!(
            "invalid {name} value '{}': {}",
            truncate_for_error(text),
            e
        ))
    })
}

/// 入口磁盘预检：路径所在卷可用空间不足 `required_bytes` 时 400。目标目录
/// 可能尚未创建（`upload_dir` 由首次 extract 才落盘）报 ENOENT——statvfs
/// 回答"路径所在卷"的空间，缺失尾部分量与最近现存祖先同卷，探测点向上收敛。
pub(crate) async fn ensure_disk_space(
    path: &std::path::Path,
    required_bytes: u64,
) -> Result<(), ApiError> {
    if required_bytes == 0 {
        return Ok(());
    }
    let path = path.to_path_buf();
    // 局部名不用 `display`：tracing 事件宏展开含 `field::display`，同名撞名（E0277）。
    let path_display = path.display().to_string();
    let available = tokio::task::spawn_blocking(move || {
        let mut probe = path.as_path();
        while !probe.exists() {
            match probe.parent() {
                Some(parent) => probe = parent,
                None => break,
            }
        }
        fs4::available_space(probe)
    })
    .await
    .map_err(|e| ApiError::log_and_internal_with_context("spawn blocking disk check", e))?
    .map_err(|e| ApiError::log_and_internal_with_context("available_space", e))?;
    if available < required_bytes {
        // 400 信封直达客户端：不回显服务端绝对路径与字节数，路径/数值只进日志，响应固定文案。
        tracing::warn!(
            path = %path_display,
            available = available,
            needed = required_bytes,
            "Insufficient disk space"
        );
        return Err(ApiError::Validation(
            "insufficient disk space on server; free up space and retry".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::server::state::AppState;
    use crate::server::{create_test_app_with_auth, seed_user_token_for_test};

    #[tokio::test]
    async fn ensure_disk_space_passes_when_required_zero() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_disk_space(tmp.path(), 0).await.unwrap();
    }

    /// 钉 read_text_field 分流边界：chunk 读 EOF → 500（瞬断是传输层故障，CLI
    /// 对 500 重试、400 放弃整传）；对照臂内容超限但完整终界 → 400（请求语义错误）。
    #[tokio::test]
    async fn text_field_stream_interruption_returns_500_oversize_stays_400() {
        let (store, tmp) = crate::test_support::create_test_store().await;
        let app_state = std::sync::Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig::default(),
            tmp.path().to_path_buf(),
        ));
        let token = seed_user_token_for_test(&app_state.state_store, "field-io", "builder")
            .await
            .unwrap();
        let app = create_test_app_with_auth(app_state);

        let boundary = "----cut-inside-text-field";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"product\"\r\n\r\n");
        body.extend_from_slice(b"det");
        body.extend_from_slice(b"\r\n");
        // stage 字段：头完整、内容无闭合 boundary 即截断。
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"stage\"\r\n\r\n");
        body.extend_from_slice(b"build");

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/builds")
                    .header("Authorization", format!("Bearer {}", token))
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={}", boundary),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "truncated text field stream must map to 500, not 400"
        );
        let _ = to_bytes(response.into_body(), usize::MAX).await;

        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"product\"\r\n\r\n");
        body.extend_from_slice(b"det");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"stage\"\r\n\r\n");
        body.extend_from_slice(&vec![b'x'; MAX_TEXT_FIELD_BYTES + 1]);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/builds")
                    .header("Authorization", format!("Bearer {}", token))
                    .header(
                        "Content-Type",
                        format!("multipart/form-data; boundary={}", boundary),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "oversized (but complete) text field must stay a 400 validation error"
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        assert!(
            json["message"]
                .as_str()
                .unwrap_or_default()
                .contains("exceeds"),
            "400 message should name the limit: {json}"
        );
    }

    #[tokio::test]
    async fn ensure_disk_space_fails_when_required_too_large() {
        let tmp = tempfile::tempdir().unwrap();
        let err = ensure_disk_space(tmp.path(), u64::MAX).await.unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    /// 目录尚未创建时探测点收敛到最近现存祖先——不落 500，小额度放行、超大配额仍 400。
    #[tokio::test]
    async fn ensure_disk_space_probes_nearest_existing_ancestor_for_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_disk_space(&tmp.path().join("a").join("b").join("c"), 1024)
            .await
            .unwrap();
        let err = ensure_disk_space(&tmp.path().join("a").join("b"), u64::MAX)
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    /// 400 信封直达客户端：不回显服务端绝对路径与字节数细节，定位信息只进日志。
    #[tokio::test]
    async fn ensure_disk_space_error_does_not_leak_server_path() {
        let tmp = tempfile::tempdir().unwrap();
        let err = ensure_disk_space(tmp.path(), u64::MAX).await.unwrap_err();
        let ApiError::Validation(msg) = &err else {
            panic!("expected Validation error, got {err:?}");
        };
        assert!(
            !msg.contains(tmp.path().to_str().unwrap()),
            "must not echo the server path, got: {msg}"
        );
        assert!(
            !msg.contains("bytes"),
            "must not echo byte-count details, got: {msg}"
        );
        assert!(
            msg.contains("insufficient disk space"),
            "fixed client-facing text expected, got: {msg}"
        );
    }
}
