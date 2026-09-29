// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程构建模块根：提交响应、附加构建与本地结果目录。

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::cli::OutputFormat;
use crate::cmd::build::remote::follow::{
    fetch_build_record, follow_remote_build, FollowRemoteParams,
};
use crate::remote::normalize_base_url;
use crbs_core::error::CrbsError;

pub(crate) mod follow;
pub(crate) mod output;
pub(crate) mod submit;

pub(crate) use submit::{submit_build, submit_rebuild, submit_reproduce};

/// 远程构建任务响应。
#[derive(Debug, serde::Deserialize)]
pub(crate) struct BuildResponse {
    #[serde(rename = "task_id")]
    pub task_id: i64,
    pub ids: Vec<i64>,
    /// hub 读自首个 SRPM 头的 NEVR；响应缺该键时为 None。
    pub(crate) pkg_name: Option<String>,
    /// 提交期因 spec 架构约束（ExclusiveArch/ExcludeArch）跳过未创建的子构建，
    /// "pkg: arch (reason)"。响应无此字段 → 空 Vec。
    #[serde(default)]
    pub(crate) skipped_arches: Vec<String>,
    /// 放置契约下限回显（KB/核）。响应缺这些键 → serde default 落 None，
    /// [`warn_req_min_unconfirmed`] 据此检测"声明了但响应缺失"。
    #[serde(default)]
    pub(crate) req_min_mem_kb: Option<i64>,
    #[serde(default)]
    pub(crate) req_min_ncpu: Option<i64>,
    #[serde(default)]
    pub(crate) req_min_disk_kb: Option<i64>,
}

/// 回显契约判定（纯函数）：任一请求维在响应回显 `(mem, ncpu, disk)` 中缺失
/// 确认（hub 静默丢弃声明时缺键落 None）→ true。remote 与 daemon 两
/// 提交通道的响应类型不同，共用三维元组口径。
pub(crate) fn req_min_unconfirmed(
    requested: &crate::cli::BuildBehaviorArgs,
    echoed: (Option<i64>, Option<i64>, Option<i64>),
) -> bool {
    let (mem, ncpu, disk) = echoed;
    (requested.min_mem.is_some() && mem.is_none())
        || (requested.min_ncpu.is_some() && ncpu.is_none())
        || (requested.min_disk.is_some() && disk.is_none())
}

/// 回显契约（stderr 一行告警，不失败）：CLI 请求了某维下限但响应未确认对应
/// 维度，点名"需求可能未被调度采纳"。走 stderr——stdout 在 JSON 模式下是
/// 机器可解析信封，不得混入人读告警。
pub(crate) fn warn_req_min_unconfirmed(
    requested: &crate::cli::BuildBehaviorArgs,
    echoed: &BuildResponse,
) {
    if req_min_unconfirmed(
        requested,
        (
            echoed.req_min_mem_kb,
            echoed.req_min_ncpu,
            echoed.req_min_disk_kb,
        ),
    ) {
        eprintln!(
            "Warning: server did not confirm the requested placement requirements \
             (req_min_* missing from response) — an older hub may have dropped \
             them, so scheduling will not honor these floors"
        );
    }
}

pub(crate) fn make_local_result_dir(
    product: &str,
    pkg_name: &str,
    build_id: i64,
) -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // product/pkg_name 来自服务器任务记录：不校验直接 join，`../` 可让被攻破的
    // server 把 CLI（常 root）产物/签名写到预期目录树之外，非法分量 fail-closed。
    // 两分量口径不同：product 是受控 slug，保持严格白名单（`[A-Za-z0-9_.-]`）；
    // pkg_name 是 RPM 包名，走与提交侧 `crbs_core::util::validate_pkg_name` 同口径
    //（拒 `/`、`\0`、`.`/`..`、空，放行 `+`/`~`），否则 `libstdc++` 类合法包名产物落不了地。
    let product = crate::remote::safe_server_dir_component(product)?;
    crbs_core::util::validate_pkg_name(pkg_name)?;
    Ok(cwd
        .join("results")
        .join(product)
        .join(pkg_name)
        .join(build_id.to_string()))
}

pub(crate) async fn attach_build(
    server_url: &str,
    token: Option<String>,
    ca_cert: Option<PathBuf>,
    attach_id: &str,
    follow_logs: bool,
    format: OutputFormat,
    cancel_token: Option<&CancellationToken>,
) -> Result<()> {
    let base_url = normalize_base_url(server_url)?;
    let target = crate::remote::RemoteTarget::new(base_url.clone(), token.clone(), ca_cert.clone());
    let client = target.client().await?;

    // attach id 仅接受完整数字 build id；解析失败属参数误用 → ValidationFailed（USAGE=4）。
    let record = fetch_build_record(
        client,
        &base_url,
        attach_id
            .parse::<i64>()
            .map_err(|e| CrbsError::ValidationFailed {
                message: format!(
                    "invalid attach id (remote attach requires the full numeric build id): {e}"
                ),
            })?,
    )
    .await?;
    let build_id = record.id;

    if record.phase == "building" && format == OutputFormat::Text {
        println!("Attaching to remote build {}", build_id);
    }

    let result = follow_remote_build(FollowRemoteParams {
        client,
        base_url: &base_url,
        build_id,
        pkg_name: &record.pkg_name,
        follow_logs,
        format,
        cancel_token,
        token,
        ca_cert,
        // attach 纯观看：观看上限放宽到 24h，长构建不在 1h 处被掐断。
        poll_timeout: Duration::from_secs(24 * 3600),
    })
    .await;
    // Ctrl-C 只停止观看，不取消远端构建（与本地 attach 对齐）；显式取消走 `crbs cancel`。
    result
}

pub(crate) async fn request_remote_cancel(client: &reqwest::Client, base_url: &str, build_id: i64) {
    let url = format!("{}/api/v1/builds/{}/cancel", base_url, build_id);
    let req = client.post(&url).timeout(Duration::from_secs(10));
    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(build_id = %build_id, "Requested remote build cancellation");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
            // 服务器数据不可信：body 经共享 truncate_body_for_error 截断/剥终端
            // 控制序列后再入 tracing，防被入侵 hub 破坏终端或刷屏。
            let body = crate::remote::truncate_body_for_error(&body);
            if status == reqwest::StatusCode::CONFLICT || status == reqwest::StatusCode::NOT_FOUND {
                tracing::debug!(
                    build_id = %build_id,
                    status = %status,
                    body = %body,
                    "Remote cancel request skipped"
                );
            } else {
                warn!(
                    build_id = %build_id,
                    status = %status,
                    body = %body,
                    "Remote cancel request returned non-success"
                );
            }
        }
        Err(e) => {
            warn!(build_id = %build_id, error = %e, "Failed to send remote cancel request");
        }
    }
}

/// 判定 follow 结果是否为"用户取消"（submit 三入口据此补发 `request_remote_cancel`，
/// 防客户端放弃后 hub 构建继续跑满预算）。两形态都须判中：text 上抛裸 `Cancelled`，
/// JSON 把错误包成 `SilentExit`——只认裸形态会让 JSON 模式 Ctrl-C 漏发取消。
/// Timeout 与 Cancelled 同映射 INTERRUPTED(3)，JSON 信封无法区分，超时也判中（多发无害）。
/// 放弃等待（`FollowAbandoned`：SIGTERM/SIGHUP detach 与未开 --timeout-cancel 的
/// 超时）刻意不命中本判——构建留在远端继续执行，由 submit 收口映射退出码。
pub(crate) fn is_cancelled_result(result: &Result<()>) -> bool {
    result
        .as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<CrbsError>())
        .is_some_and(|e| match e {
            CrbsError::Cancelled => true,
            CrbsError::SilentExit { code } => *code == crbs_core::exit_code::INTERRUPTED,
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::is_cancelled_result;
    use super::make_local_result_dir;
    use super::{req_min_unconfirmed, BuildResponse};
    use crbs_core::error::CrbsError;
    use crbs_core::exit_code::{BUILD_FAILED, INTERRUPTED};

    /// 带 pkg_name 与不带两形态均可反序列化；缺字段落 None 不报错。
    #[test]
    fn build_response_parses_with_and_without_pkg_name() {
        let with: BuildResponse =
            serde_json::from_str(r#"{"task_id":5,"ids":[21],"pkg_name":"hello-1.0-1"}"#)
                .expect("pkg_name field must deserialize");
        assert_eq!(with.pkg_name.as_deref(), Some("hello-1.0-1"));

        let legacy: BuildResponse = serde_json::from_str(r#"{"task_id":5,"ids":[21]}"#)
            .expect("legacy hub body must parse");
        assert_eq!(legacy.pkg_name, None);
        assert_eq!(legacy.req_min_mem_kb, None);
        assert_eq!(legacy.req_min_ncpu, None);
        assert_eq!(legacy.req_min_disk_kb, None);
    }

    /// 回显契约判定真值表（[`req_min_unconfirmed`] 纯函数）：请求+确认 → false；
    /// 请求+响应缺键 → true；只请求 ncpu 只缺 ncpu 确认 → true；未请求 → false。
    #[test]
    fn req_min_unconfirmed_truth_table() {
        fn behavior(
            min_mem: Option<&str>,
            min_ncpu: Option<u32>,
            min_disk: Option<&str>,
        ) -> crate::cli::BuildBehaviorArgs {
            crate::cli::BuildBehaviorArgs {
                jobs: None,
                shared_layer: false,
                tmpfs: false,
                ccache: false,
                fail_fast: false,
                timeout: None,
                timeout_cancel: false,
                stage: None,
                define: Vec::new(),
                with_features: Vec::new(),
                without_features: Vec::new(),
                nocheck: false,
                noclean: false,
                nodebuginfo: false,
                no_publish: false,
                no_consume: false,
                target: None,
                dist: None,
                chain: false,
                order_only: false,
                force: false,
                repo: None,
                result_repo: false,
                no_result_repo: false,
                retry: None,
                priority: 0,
                arch: Vec::new(),
                skip_unsupported_arches: false,
                assume_independent: false,
                min_mem: min_mem.map(str::to_string),
                min_ncpu,
                min_disk: min_disk.map(str::to_string),
                label: Vec::new(),
            }
        }

        // 新 hub 确认全部请求维 → 不告警。
        assert!(!req_min_unconfirmed(
            &behavior(Some("4G"), Some(8), None),
            (Some(4 * 1024 * 1024), Some(8), None)
        ));
        // 响应全缺键 → 告警。
        assert!(req_min_unconfirmed(
            &behavior(Some("4G"), Some(8), None),
            (None, None, None)
        ));
        // 只请求 ncpu、只缺 ncpu 确认 → 告警；确认了 → 不告警。
        assert!(req_min_unconfirmed(
            &behavior(None, Some(8), None),
            (Some(1024), None, None)
        ));
        assert!(!req_min_unconfirmed(
            &behavior(None, Some(8), None),
            (None, Some(8), None)
        ));
        // 未请求任何下限（响应全 None）→ 不告警。
        assert!(!req_min_unconfirmed(
            &behavior(None, None, None),
            (None, None, None)
        ));
    }

    /// 裸 `Cancelled` 与 JSON 信封 `SilentExit{INTERRUPTED}` 均判中；其他退出码/变体不触发。
    /// `FollowAbandoned`（放弃等待）不判中——防 detach/超时放弃被级联补发取消。
    #[test]
    fn is_cancelled_result_recognises_bare_and_json_envelope_shapes() {
        use crate::cmd::build::FollowAbandoned;

        assert!(is_cancelled_result(&Err(CrbsError::Cancelled.into())));
        assert!(is_cancelled_result(&Err(CrbsError::SilentExit {
            code: INTERRUPTED
        }
        .into())));

        assert!(!is_cancelled_result(&Ok(())));
        assert!(!is_cancelled_result(&Err(CrbsError::SilentExit {
            code: BUILD_FAILED
        }
        .into())));
        assert!(!is_cancelled_result(&Err(
            CrbsError::Internal("x".into()).into()
        )));
        assert!(!is_cancelled_result(&Err(CrbsError::Timeout.into())));
        assert!(!is_cancelled_result(&Err(FollowAbandoned.into())));
    }

    /// pkg_name 按 `validate_pkg_name` 口径放行 RPM 合法字符（`+`/`~`，如 `libstdc++`）。
    #[test]
    fn make_local_result_dir_accepts_rpm_pkg_names() {
        for ok in ["libstdc++", "hello-1.0~rc1", "gcc-toolset-14", "kernel+rt"] {
            let dir = make_local_result_dir("mydist", ok, 7)
                .unwrap_or_else(|e| panic!("{ok} must be accepted: {e}"));
            assert!(
                dir.ends_with(std::path::Path::new(&format!("results/mydist/{ok}/7"))),
                "got {}",
                dir.display()
            );
        }
    }

    /// 越界分量 fail-closed：`..`/绝对路径/空；product 保持严格白名单（拒 `+`）。
    #[test]
    fn make_local_result_dir_rejects_traversal() {
        for evil in ["..", "../x", "/abs", "a/..", ""] {
            assert!(
                make_local_result_dir("mydist", evil, 7).is_err(),
                "pkg_name {evil:?} must be rejected"
            );
        }
        assert!(
            make_local_result_dir("libstdc++", "pkg", 7).is_err(),
            "product component must keep the strict whitelist"
        );
    }
}
