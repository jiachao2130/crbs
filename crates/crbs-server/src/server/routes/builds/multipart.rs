// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建提交的 multipart 解析：字段提取、上传限额与错误排空。

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crbs_core::types::{BuildPriority, PRIORITY_CRITICAL, PRIORITY_DEFAULT};
use crbs_core::util::RPM_MAGIC;
use crbs_core::validate_backend_name;

use crate::server::error::ApiError;
use crate::server::validation::{validate_product_name, validate_uploaded_srpm_name};

use super::validation::{
    parse_bool_field, parse_u32_field, parse_u32_text, parse_u64_field, read_text_field,
};
use super::BuildOptions;

/// [`extract_multipart_build`] 的产出：表单字段 + 已落盘的 SRPM 路径。`csrf_token`
/// 仅 Web UI 表单携带；multipart 单向流中该字段可能出现在文件字段之后，只能在
/// 流式解析中一并捕获，无法提前校验。
#[derive(Debug)]
pub(crate) struct ExtractedMultipartBuild {
    pub product: String,
    pub srpm_paths: Vec<PathBuf>,
    pub opts: BuildOptions,
    pub csrf_token: Option<String>,
    /// 任务标签原始文本（重复 `label` 字段，`KEY=VALUE`）；空白字段
    ///（Web UI 未填写的空行）忽略，语法/上限校验在提交入口统一收口。
    pub labels: Vec<String>,
}

/// 校验已落盘 SRPM 的 RPM 魔数（读前 4 字节比对 [`RPM_MAGIC`]）：坏包提交期即拒，
/// 避免建任务后 worker 才异步失败、留下 failed task 与多份上传副本；不足 4 字节
/// （含空文件）同判，打开/读取失败按 5xx 收口。
async fn validate_srpm_magic(path: &Path, file_name: &str) -> Result<(), ApiError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| {
        ApiError::log_and_internal_with_context(
            format!("open uploaded srpm for magic check {}", file_name),
            e,
        )
    })?;
    let mut head = [0u8; 4];
    let n = file.read(&mut head).await.map_err(|e| {
        ApiError::log_and_internal_with_context(
            format!("read uploaded srpm magic {}", file_name),
            e,
        )
    })?;
    if n < 4 || head != RPM_MAGIC {
        return Err(ApiError::Validation(format!(
            "uploaded srpm '{}' is not a valid RPM package (missing RPM magic bytes)",
            file_name
        )));
    }
    Ok(())
}

/// 解析 multipart 表单，提取 product、SRPM 文件路径和构建选项。SRPM 直接流写入
/// `{upload_dir}/.incoming/` 避免跨文件系统拷贝；单文件超 `max_size_bytes` 整请求
/// 拒绝。任何校验失败早退都先经 [`drain_multipart_for_error`] 吸干剩余请求体再返回。
pub(crate) async fn extract_multipart_build(
    mut multipart: axum::extract::Multipart,
    upload_dir: &Path,
    max_size_bytes: usize,
) -> Result<ExtractedMultipartBuild, ApiError> {
    let mut product = None;
    let mut csrf_token = None;
    let mut srpm_paths: Vec<PathBuf> = Vec::new();
    let mut labels: Vec<String> = Vec::new();
    let mut seen_srpm_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut opts = BuildOptions::default();

    let incoming_dir = upload_dir.join(".incoming");
    // 每请求独立 .incoming/{uuid} 子目录（多 srpm 共用、惰性创建）：防同名并发提交静默覆盖/rename 抢跑。
    let mut request_incoming_dir: Option<PathBuf> = None;

    // 解析主体放进 async 块：所有早退统一落到下方错误回收——submit 侧清理守卫
    // 在 extract 成功后才创建，早退会把已写盘的 .incoming/{uuid} 永久留在磁盘。
    let outcome: Result<ExtractedMultipartBuild, ApiError> = async {
        // 流中断（连接切断/中途解析错误）归 500 而非 400：CLI 对 POST 500 自动重试、
        // 400 不重试，瞬断落 400 会让 CLI 放弃整个 SRPM 重传；代价是真坏请求也
        // 500、重试耗尽后放弃。下方 next_field / 字段 text / chunk 读臂同口径。
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|e| ApiError::log_and_internal_with_context("read multipart field", e))?
        {
            let name = field.name().unwrap_or("").to_string();
            match name.as_str() {
                "product" => {
                    let text = field.text().await.map_err(|e| {
                        ApiError::log_and_internal_with_context("read product field", e)
                    })?;
                    validate_product_name(&text)?;
                    product = Some(text);
                }
                // Web UI 表单的 CSRF 字段（文本）；API / CLI 不携带，保持 None。
                "csrf_token" => {
                    let text = field.text().await.map_err(|e| {
                        ApiError::log_and_internal_with_context("read csrf_token field", e)
                    })?;
                    csrf_token = Some(text);
                }
                "srpm" => {
                    let file_name = field.file_name().unwrap_or("").to_string();
                    validate_uploaded_srpm_name(&file_name)?;

                    if !seen_srpm_names.insert(file_name.clone()) {
                        return Err(ApiError::Validation(format!(
                            "duplicate srpm filename in multipart request: {}",
                            file_name
                        )));
                    }

                    let req_dir = match &request_incoming_dir {
                        Some(d) => d.clone(),
                        None => {
                            let d = incoming_dir.join(uuid::Uuid::new_v4().to_string());
                            tokio::fs::create_dir_all(&d).await.map_err(|e| {
                                ApiError::log_and_internal_with_context(
                                    format!("create incoming request dir {}", d.display()),
                                    e,
                                )
                            })?;
                            // 权限不变量：crbs 创建的目录补 2770 + crbs 组（create_dir_all 受 umask 削减）。
                            crate::server::staging::enforce_dir_invariant(
                                &incoming_dir,
                                "upload incoming root",
                            )
                            .await;
                            crate::server::staging::enforce_dir_invariant(
                                &d,
                                "upload incoming request dir",
                            )
                            .await;
                            request_incoming_dir = Some(d.clone());
                            d
                        }
                    };

                    let temp_path = req_dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
                    let mut file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
                        ApiError::log_and_internal_with_context(
                            format!("create incoming temp file {}", temp_path.display()),
                            e,
                        )
                    })?;

                    let mut written = 0usize;
                    while let Some(chunk) = field.chunk().await.map_err(|e| {
                        // 流中断同 500 口径（见上方 next_field 注）。
                        ApiError::log_and_internal_with_context("read srpm chunk", e)
                    })? {
                        written += chunk.len();
                        if written > max_size_bytes {
                            let _ = tokio::fs::remove_file(&temp_path).await;
                            // per-file 超限 = 请求体过大 → 413，非字段语义错误（与路由层 body 上限同族）。
                            return Err(ApiError::PayloadTooLarge(
                                "uploaded srpm exceeds size limit".into(),
                            ));
                        }
                        file.write_all(&chunk).await.map_err(|e| {
                            ApiError::log_and_internal_with_context("write incoming temp file", e)
                        })?;
                    }
                    file.flush().await.map_err(|e| {
                        ApiError::log_and_internal_with_context("flush incoming temp file", e)
                    })?;

                    // 权限不变量：文件 0660 + chown crbs 组——root 接收后 group=root、
                    // umask 缺省 0644 无组写，hub 侧（staging/INPUT 中转）读不了；
                    // builder 只读 INPUT 内显式 0644 拷贝，不依赖本文件 world-read。
                    #[cfg(unix)]
                    {
                        let perms = std::fs::Permissions::from_mode(0o660);
                        tokio::fs::set_permissions(&temp_path, perms)
                            .await
                            .map_err(|e| {
                                ApiError::log_and_internal_with_context(
                                    format!(
                                        "set uploaded srpm permissions {}",
                                        temp_path.display()
                                    ),
                                    e,
                                )
                            })?;
                        crbs_core::privilege::chown_to_crbs_group_async(
                            &temp_path,
                            false,
                            "uploaded srpm",
                        )
                        .await;
                    }

                    // 保留原始文件名（结果目录/日志包名与上传 SRPM 一致）；落在本请求专属 req_dir 下避免同名并发碰撞。
                    let final_path = if file_name.is_empty() {
                        temp_path
                    } else {
                        let renamed = req_dir.join(&file_name);
                        tokio::fs::rename(&temp_path, &renamed).await.map_err(|e| {
                            ApiError::log_and_internal_with_context(
                                format!("rename uploaded srpm to {}", file_name),
                                e,
                            )
                        })?;
                        renamed
                    };

                    srpm_paths.push(final_path);
                }
                "stage" => {
                    opts.stage = Some(read_text_field(field).await?);
                }
                "backend" => {
                    let v = read_text_field(field).await?;
                    validate_backend_name(&v)?;
                    opts.backend = Some(v);
                }
                "target" => {
                    opts.target = Some(read_text_field(field).await?);
                }
                "dist" => {
                    opts.dist = Some(read_text_field(field).await?);
                }
                "timeout" => {
                    opts.timeout = Some(parse_u64_field(field).await?);
                }
                "memory_max" => {
                    opts.memory_max = Some(read_text_field(field).await?);
                }
                "cpu_quota" => {
                    opts.cpu_quota = Some(read_text_field(field).await?);
                }
                // 放置契约下限（表单留空 = 未声明，不入 opts）：语法与上界
                // 统一在 validate_options 收口（JSON 入口同一校验面）。
                "min_mem" => {
                    let v = read_text_field(field).await?;
                    let v = v.trim();
                    if !v.is_empty() {
                        opts.min_mem = Some(v.to_string());
                    }
                }
                "min_disk" => {
                    let v = read_text_field(field).await?;
                    let v = v.trim();
                    if !v.is_empty() {
                        opts.min_disk = Some(v.to_string());
                    }
                }
                "min_ncpu" => {
                    let text = read_text_field(field).await?;
                    let text = text.trim();
                    if !text.is_empty() {
                        opts.min_ncpu = Some(parse_u32_text(text, "min_ncpu")?);
                    }
                }
                "retry" => {
                    opts.retry = Some(parse_u32_field(field).await?);
                }
                "shared_layer" => {
                    opts.shared_layer = Some(parse_bool_field(field).await?);
                }
                "tmpfs" => {
                    opts.tmpfs = Some(parse_bool_field(field).await?);
                }
                "ccache" => {
                    opts.ccache = Some(parse_bool_field(field).await?);
                }
                "nocheck" => {
                    opts.nocheck = Some(parse_bool_field(field).await?);
                }
                "noclean" => {
                    opts.noclean = Some(parse_bool_field(field).await?);
                }
                "nodebuginfo" => {
                    opts.nodebuginfo = Some(parse_bool_field(field).await?);
                }
                "no_network" => {
                    opts.no_network = Some(parse_bool_field(field).await?);
                }
                "no_publish" => {
                    opts.no_publish = Some(parse_bool_field(field).await?);
                }
                "no_consume" => {
                    opts.no_consume = parse_bool_field(field).await?;
                }
                "no_reproduce" => {
                    opts.no_reproduce = Some(parse_bool_field(field).await?);
                }
                "repro_from_srpm" => {
                    opts.repro_from_srpm = parse_bool_field(field).await?;
                }
                "skip_unsupported_arches" => {
                    opts.skip_unsupported_arches = parse_bool_field(field).await?;
                }
                "priority" => {
                    let text = read_text_field(field).await?;
                    let v = text.parse::<BuildPriority>().map_err(|e| {
                        ApiError::Validation(format!("invalid priority value '{}': {}", text, e))
                    })?;
                    if !(PRIORITY_DEFAULT..=PRIORITY_CRITICAL).contains(&v) {
                        return Err(ApiError::Validation(format!(
                            "priority must be 0 (default), 1 (high), or 2 (critical), got: {}",
                            v
                        )));
                    }
                    // priority=2 的 operator 权限检查在 enqueue.rs 的 submit_multipart_builds 中统一处理。
                    opts.priority = Some(v);
                }
                "define" => {
                    opts.define.push(read_text_field(field).await?);
                }
                "label" => {
                    let text = read_text_field(field).await?;
                    // 空行 = 未填写（Web UI 空输入行）：丢弃，不进枚举校验。
                    if !text.trim().is_empty() {
                        labels.push(text);
                    }
                }
                "with_features" => {
                    opts.with_features.push(read_text_field(field).await?);
                }
                "without_features" => {
                    opts.without_features.push(read_text_field(field).await?);
                }
                "arch" => {
                    let v = read_text_field(field).await?;
                    // 与 JSON 入口（submit::resolve_arches）同一套 fail-closed 校验：
                    // 逐段（逗号分隔）过 validate_arch，注入/穿越在此 400；trim 后空段
                    //（含整字段留空 = noscript 表单"默认架构"）不入 arch_list，非空段仍逐个校验。
                    let parts: Vec<&str> = v
                        .split(',')
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .collect();
                    for part in &parts {
                        crbs_core::validation::validate_arch(part)?;
                    }
                    if !parts.is_empty() {
                        opts.arch_list.push(v);
                    }
                }
                _ => {}
            }
        }

        let product = product
            .take()
            .ok_or_else(|| ApiError::Validation("missing product field".into()))?;
        if srpm_paths.is_empty() {
            return Err(ApiError::Validation("missing srpm file".into()));
        }
        // 坏包预检失败经下方统一错误回收清掉本请求 .incoming/{uuid}，不留上传副本。
        for path in &srpm_paths {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unnamed");
            validate_srpm_magic(path, name).await?;
        }
        Ok(ExtractedMultipartBuild {
            product,
            srpm_paths: std::mem::take(&mut srpm_paths),
            opts: std::mem::take(&mut opts),
            csrf_token,
            labels: std::mem::take(&mut labels),
        })
    }
    .await;

    match outcome {
        Ok(v) => Ok(v),
        Err(e) => {
            // 本请求的 uuid 子目录整体回收（命名空间内删除，见上方注释）。
            if let Some(d) = request_incoming_dir.take() {
                if let Err(rm) = tokio::fs::remove_dir_all(&d).await {
                    if rm.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(
                            path = %d.display(),
                            error = %rm,
                            "Failed to clean up incoming dir after extract failure"
                        );
                    }
                }
            }
            // 先吸干剩余请求体再返回错误，否则客户端因连接早断读不到错误响应。
            drain_multipart_for_error(&mut multipart).await;
            Err(e)
        }
    }
}

/// 上传校验失败后吸干剩余请求体的余量（路由层请求体上限的组成之一）：覆盖
/// multipart 分帧（≤64 个 srpm 字段头 + 文本字段，约 20KB）与 TCP 小额残差。
pub(crate) const UPLOAD_DRAIN_MARGIN_BYTES: usize = 64 * 1024;

/// 上传端点路由层请求体上限：`upload_max × 2 + 余量`。校验失败点至多已读 `upload_max`
///（per-file 上限在 [`extract_multipart_build`] 内），吸干最多再读 `upload_max + 余量`；
/// 超出由 DefaultBodyLimit / RequestBodyLimitLayer 以 length-limit 错误中止并关连接。
pub(crate) fn upload_body_limit_bytes(max_upload_size_bytes: usize) -> usize {
    max_upload_size_bytes
        .saturating_mul(2)
        .saturating_add(UPLOAD_DRAIN_MARGIN_BYTES)
}

/// multipart 校验失败后吸干（drain）剩余请求体：逐字段逐 chunk 读出并丢弃。
/// 不吸干直接返回 4xx 时，hyper 在响应写出后即关闭连接；服务端 socket 接收
/// 缓冲仍有未读请求数据时 close 触发 TCP RST，正在发送大请求体的客户端既发
/// 不完请求也读不到错误响应（curl 报 56、错误响应体截断，浏览器 XHR 同理）。
/// 语义：流式逐块丢弃不聚积内存；上界由路由层请求体上限保证
///（[`upload_body_limit_bytes`]，产物上传为 `ARTIFACT_UPLOAD_BODY_LIMIT`），
/// 超出时 length-limit 中止、由 hyper 关连接；中断字段剩余数据由 multer 在
/// `next_field` 内部跳过读取；读途中客户端断开/解析出错静默返回。
pub(crate) async fn drain_multipart_for_error(multipart: &mut axum::extract::Multipart) {
    while let Ok(Some(mut field)) = multipart.next_field().await {
        loop {
            match field.chunk().await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return,
            }
        }
    }
}

/// 从 `srpm_paths` 推导本次请求的 `.incoming/{uuid}` 子目录供消费后清理；所有 srpm
/// 同在一个 req_dir，取第一个的父目录，仅当位于 `{upload_dir}/.incoming` 之下才返回
/// Some，防误删其它路径。
pub(crate) fn request_incoming_dir_of(
    upload_dir: &Path,
    srpm_paths: &[PathBuf],
) -> Option<PathBuf> {
    let incoming_dir = upload_dir.join(".incoming");
    srpm_paths
        .first()
        .and_then(|p| p.parent())
        .filter(|d| d.parent() == Some(incoming_dir.as_path()))
        .map(|d| d.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    /// 构造一个包含 product + srpm 文件的 multipart body。
    fn make_multipart_body(boundary: &str, product: &str, srpm_content: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"product\"\r\n\r\n");
        body.extend_from_slice(product.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"srpm\"; filename=\"test.src.rpm\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(srpm_content);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        body
    }

    /// 从 raw body 构造 axum Multipart extractor。
    async fn extract_multipart(body: Vec<u8>, boundary: &str) -> axum::extract::Multipart {
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(body))
            .unwrap();
        <axum::extract::Multipart as axum::extract::FromRequest<()>>::from_request(request, &())
            .await
            .unwrap()
    }

    /// 构造带 arch 字段的 multipart body（product + srpm + arch）。
    fn make_multipart_body_with_arch(
        boundary: &str,
        product: &str,
        arch: &str,
        srpm_content: &[u8],
    ) -> Vec<u8> {
        let mut body = make_multipart_body(boundary, product, srpm_content);
        body.truncate(body.len() - format!("--{}--\r\n", boundary).len());
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"arch\"\r\n\r\n");
        body.extend_from_slice(arch.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        body
    }

    /// 带 RPM 魔数前缀的 SRPM 内容（提取期 magic 预检，成功路径必须以真魔数开头）。
    fn srpm_bytes(payload: &[u8]) -> Vec<u8> {
        let mut v = RPM_MAGIC.to_vec();
        v.extend_from_slice(payload);
        v
    }

    /// arch 非法值（穿越/含 `/`/段内注入）解析期 400 拒绝；arch 字段在 srpm 之后
    /// 解析、错误先于尾部 magic 预检，无需真魔数（空段语义见 skips_blank_arch_field）。
    #[tokio::test]
    async fn rejects_invalid_arch_field() {
        for bad_arch in ["../foo", "a/b", "x86_64,evil arch"] {
            let tmp = tempfile::tempdir().unwrap();
            let upload_dir = tmp.path().to_path_buf();
            let boundary = "testboundary";
            let body = make_multipart_body_with_arch(boundary, "testprod", bad_arch, &[b'x'; 10]);
            let multipart = extract_multipart(body, boundary).await;

            let result = extract_multipart_build(multipart, &upload_dir, 1024 * 1024).await;
            let err = result.unwrap_err();
            let msg = format!("{err:?}");
            assert!(
                msg.contains("arch"),
                "arch '{bad_arch}' should be rejected with arch error, got: {msg}"
            );
        }
    }

    /// 整字段 trim 后为空（含纯空白/纯逗号）视为未提交：不入 arch_list、不报错
    ///（noscript 表单"留空=产品默认架构"）；空白段（如尾逗号）跳过、原始值保留。
    #[tokio::test]
    async fn skips_blank_arch_field() {
        for blank in ["", "   ", " , ,"] {
            let tmp = tempfile::tempdir().unwrap();
            let upload_dir = tmp.path().to_path_buf();
            let boundary = "testboundary";
            let body =
                make_multipart_body_with_arch(boundary, "testprod", blank, &srpm_bytes(&[b'x'; 6]));
            let multipart = extract_multipart(body, boundary).await;

            let extracted = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
                .await
                .unwrap_or_else(|e| panic!("blank arch '{blank}' should be skipped, got: {e:?}"));
            assert!(
                extracted.opts.arch_list.is_empty(),
                "blank arch '{blank}' must not enter arch_list"
            );
        }

        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        let body = make_multipart_body_with_arch(
            "testboundary",
            "testprod",
            "x86_64,",
            &srpm_bytes(&[b'x'; 6]),
        );
        let multipart = extract_multipart(body, "testboundary").await;
        let extracted = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .expect("trailing comma arch should pass");
        assert_eq!(extracted.opts.arch_list, vec!["x86_64,".to_string()]);
    }

    /// repro_from_srpm 布尔字段解析：显式 "true" 置旗标，字段缺席保持默认 false。
    #[tokio::test]
    async fn parses_repro_from_srpm_field() {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = "testboundary";
        let mut body = make_multipart_body(boundary, "testprod", &srpm_bytes(&[b'x'; 6]));
        body.truncate(body.len() - format!("--{}--\r\n", boundary).len());
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"repro_from_srpm\"\r\n\r\n");
        body.extend_from_slice(b"true\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        let multipart = extract_multipart(body, boundary).await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("repro_from_srpm=true should parse");
        assert!(extracted.opts.repro_from_srpm);

        let tmp = tempfile::tempdir().unwrap();
        let body = make_multipart_body("testboundary", "testprod", &srpm_bytes(&[b'x'; 6]));
        let multipart = extract_multipart(body, "testboundary").await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("absent repro_from_srpm should keep default");
        assert!(!extracted.opts.repro_from_srpm);
    }

    /// skip_unsupported_arches 布尔字段解析：显式 "true" 置旗标（CLI
    /// --skip-unsupported-arches 远端提交通道），字段缺席保持默认 false。
    #[tokio::test]
    async fn parses_skip_unsupported_arches_field() {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = "testboundary";
        let mut body = make_multipart_body(boundary, "testprod", &srpm_bytes(&[b'x'; 6]));
        body.truncate(body.len() - format!("--{}--\r\n", boundary).len());
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"skip_unsupported_arches\"\r\n\r\n",
        );
        body.extend_from_slice(b"true\r\n");
        body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
        let multipart = extract_multipart(body, boundary).await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("skip_unsupported_arches=true should parse");
        assert!(extracted.opts.skip_unsupported_arches);

        let tmp = tempfile::tempdir().unwrap();
        let body = make_multipart_body("testboundary", "testprod", &srpm_bytes(&[b'x'; 6]));
        let multipart = extract_multipart(body, "testboundary").await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("absent skip_unsupported_arches should keep default");
        assert!(!extracted.opts.skip_unsupported_arches);
    }

    /// 正常 arch（含逗号分隔多值）通过。
    #[tokio::test]
    async fn accepts_valid_arch_field() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        let boundary = "testboundary";
        let body = make_multipart_body_with_arch(
            boundary,
            "testprod",
            "x86_64,aarch64",
            &srpm_bytes(&[b'x'; 6]),
        );
        let multipart = extract_multipart(body, boundary).await;

        let extracted = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .expect("valid arch should pass");
        assert_eq!(extracted.opts.arch_list, vec!["x86_64,aarch64".to_string()]);
    }

    /// 追加一个任意命名的文本字段到 multipart body 尾部。
    fn append_text_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
        body.truncate(body.len() - format!("--{boundary}--\r\n").len());
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    }

    /// 放置契约字段臂：min_mem/min_disk 文本（trim 后空 = 未声明）、min_ncpu
    /// 数字；语法与上界校验统一在 validate_options（此处只做落 opts）。
    #[tokio::test]
    async fn parses_req_min_fields() {
        let srpm = srpm_bytes(&[b'x'; 6]);
        // 全字段齐备。
        let tmp = tempfile::tempdir().unwrap();
        let mut body = make_multipart_body("bnd", "testprod", &srpm);
        append_text_field(&mut body, "bnd", "min_mem", "4G");
        append_text_field(&mut body, "bnd", "min_disk", "2T");
        append_text_field(&mut body, "bnd", "min_ncpu", "8");
        let multipart = extract_multipart(body, "bnd").await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("req_min fields should parse");
        assert_eq!(extracted.opts.min_mem.as_deref(), Some("4G"));
        assert_eq!(extracted.opts.min_disk.as_deref(), Some("2T"));
        assert_eq!(extracted.opts.min_ncpu, Some(8));

        // 表单留空（Web 表单未填的可选输入以空串提交）= 未声明；周边空白 trim。
        let tmp = tempfile::tempdir().unwrap();
        let mut body = make_multipart_body("bnd", "testprod", &srpm);
        append_text_field(&mut body, "bnd", "min_mem", "  ");
        append_text_field(&mut body, "bnd", "min_ncpu", "");
        let multipart = extract_multipart(body, "bnd").await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("blank req_min fields mean unset");
        assert_eq!(extracted.opts.min_mem, None);
        assert_eq!(extracted.opts.min_ncpu, None);
        assert_eq!(extracted.opts.min_disk, None);

        // 字段整体缺席 = 未声明。
        let tmp = tempfile::tempdir().unwrap();
        let body = make_multipart_body("bnd", "testprod", &srpm);
        let multipart = extract_multipart(body, "bnd").await;
        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("absent req_min fields keep defaults");
        assert!(extracted.opts.min_mem.is_none());
        assert!(extracted.opts.min_ncpu.is_none());
        assert!(extracted.opts.min_disk.is_none());
    }

    /// min_ncpu 非数字 → 400（4xx 语义错误，非传输层 500）。
    #[tokio::test]
    async fn rejects_non_numeric_min_ncpu() {
        let tmp = tempfile::tempdir().unwrap();
        let mut body = make_multipart_body("bnd", "testprod", &srpm_bytes(&[b'x'; 6]));
        append_text_field(&mut body, "bnd", "min_ncpu", "eight");
        let multipart = extract_multipart(body, "bnd").await;
        let err = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApiError::Validation(ref m) if m.contains("min_ncpu")),
            "must reject with named field: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_srpm_exceeding_size_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        // max_size = 100 字节，srpm 内容 200 字节 → 应拒绝
        let srpm = vec![b'x'; 200];
        let boundary = "testboundary";
        let body = make_multipart_body(boundary, "testprod", &srpm);
        let multipart = extract_multipart(body, boundary).await;

        let result = extract_multipart_build(multipart, &upload_dir, 100).await;
        let err = result.unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("size limit"),
            "error should mention size limit, got: {msg}"
        );
        // 钉变体（防改回 Validation 仍绿）：per-file 超限 = 请求体过大 = 413。
        assert!(
            matches!(err, ApiError::PayloadTooLarge(_)),
            "size-limit rejection must be PayloadTooLarge, got: {msg}"
        );
    }

    #[tokio::test]
    async fn accepts_srpm_within_size_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        // max_size = 1MB，srpm 内容 100 字节 → 应接受
        let srpm = srpm_bytes(&[b'x'; 96]);
        let boundary = "testboundary";
        let body = make_multipart_body(boundary, "testprod", &srpm);
        let multipart = extract_multipart(body, boundary).await;

        let extracted = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .expect("upload within size limit should succeed");
        assert_eq!(extracted.product, "testprod");
        assert_eq!(extracted.srpm_paths.len(), 1);
        assert_eq!(extracted.csrf_token, None);
    }

    /// 坏包预检：不带 RPM 魔数提交期 400（错误带文件名），.incoming/{uuid} 整体回收。
    #[tokio::test]
    async fn rejects_srpm_with_bad_magic() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        let boundary = "testboundary";
        let body = make_multipart_body(boundary, "testprod", b"garbage not a rpm");
        let multipart = extract_multipart(body, boundary).await;

        let err = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("magic"),
            "error should mention magic bytes, got: {msg}"
        );
        assert!(
            msg.contains("test.src.rpm"),
            "error should carry the file name, got: {msg}"
        );
        let incoming = upload_dir.join(".incoming");
        let left: Vec<_> = std::fs::read_dir(&incoming)
            .map(|rd| rd.filter_map(|e| e.ok()).collect())
            .unwrap_or_default();
        assert!(
            left.is_empty(),
            ".incoming must be cleaned after bad-magic rejection"
        );
    }

    /// 坏包预检：空文件同样被拒绝。
    #[tokio::test]
    async fn rejects_empty_srpm() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        let boundary = "testboundary";
        let body = make_multipart_body(boundary, "testprod", b"");
        let multipart = extract_multipart(body, boundary).await;

        let err = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("magic"),
            "empty file should be rejected as missing magic bytes, got: {msg}"
        );
        assert!(
            msg.contains("test.src.rpm"),
            "error should carry the file name, got: {msg}"
        );
    }

    /// Web UI 表单的 csrf_token 文本字段被捕获（供 UI 入口在入队前校验 CSRF）。
    #[tokio::test]
    async fn captures_csrf_token_field() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();
        let mut body = make_multipart_body("bound1", "testprod", &srpm_bytes(&[b'x'; 6]));
        body.truncate(body.len() - "--bound1--\r\n".len());
        body.extend_from_slice(b"--bound1\r\n");
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
        body.extend_from_slice(b"deadbeef");
        body.extend_from_slice(b"\r\n--bound1--\r\n");
        let multipart = extract_multipart(body, "bound1").await;

        let extracted = extract_multipart_build(multipart, &upload_dir, 1024 * 1024)
            .await
            .expect("csrf form should parse");
        assert_eq!(extracted.csrf_token.as_deref(), Some("deadbeef"));
    }

    #[tokio::test]
    async fn concurrent_extracts_use_separate_incoming_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let upload_dir = tmp.path().to_path_buf();

        // 两个并发请求，相同文件名 → 落在不同 req_dir
        let srpm = srpm_bytes(&[b'x'; 46]);
        let body1 = make_multipart_body("bound1", "testprod", &srpm);
        let body2 = make_multipart_body("bound2", "testprod", &srpm);
        let (m1, m2) = tokio::join!(
            extract_multipart(body1, "bound1"),
            extract_multipart(body2, "bound2"),
        );

        let e1 = extract_multipart_build(m1, &upload_dir, 1024 * 1024)
            .await
            .expect("request 1");
        let p1 = e1.srpm_paths;
        let e2 = extract_multipart_build(m2, &upload_dir, 1024 * 1024)
            .await
            .expect("request 2");
        let p2 = e2.srpm_paths;

        assert_eq!(p1.len(), 1);
        assert_eq!(p2.len(), 1);

        assert_ne!(p1[0], p2[0], "concurrent uploads must use different paths");
        assert_ne!(p1[0].parent(), p2[0].parent());

        assert_eq!(
            tokio::fs::read(&p1[0]).await.unwrap().as_slice(),
            srpm.as_slice()
        );
        assert_eq!(
            tokio::fs::read(&p2[0]).await.unwrap().as_slice(),
            srpm.as_slice()
        );
    }

    #[test]
    fn request_incoming_dir_of_validates_path() {
        let upload_dir = Path::new("/tmp/crbs-upload");
        let valid = vec![
            PathBuf::from("/tmp/crbs-upload/.incoming/abc123/nginx.src.rpm"),
            PathBuf::from("/tmp/crbs-upload/.incoming/abc123/other.src.rpm"),
        ];
        let dir = request_incoming_dir_of(upload_dir, &valid);
        assert_eq!(
            dir,
            Some(PathBuf::from("/tmp/crbs-upload/.incoming/abc123"))
        );

        let outside = vec![PathBuf::from("/tmp/crbs-upload/source/nginx.src.rpm")];
        assert!(request_incoming_dir_of(upload_dir, &outside).is_none());

        assert!(request_incoming_dir_of(upload_dir, &Vec::<PathBuf>::new()).is_none());
    }

    /// 重复 `label` 字段按出现顺序原样收集，空白字段（UI 空行）丢弃；
    /// 语法/上限校验在提交入口统一收口。
    #[tokio::test]
    async fn collects_repeated_label_fields_raw() {
        let tmp = tempfile::tempdir().unwrap();
        let mut body = make_multipart_body("bnd", "testprod", &srpm_bytes(&[b'x'; 6]));
        append_text_field(
            &mut body,
            "bnd",
            "label",
            "git-repo=https://example.com/a.git",
        );
        append_text_field(&mut body, "bnd", "label", "");
        append_text_field(&mut body, "bnd", "label", "   ");
        append_text_field(&mut body, "bnd", "label", "git-commit=abc123");
        let multipart = extract_multipart(body, "bnd").await;

        let extracted = extract_multipart_build(multipart, tmp.path(), 1024 * 1024)
            .await
            .expect("label fields should collect");
        assert_eq!(
            extracted.labels,
            vec![
                "git-repo=https://example.com/a.git".to_string(),
                "git-commit=abc123".to_string(),
            ]
        );
    }
}
