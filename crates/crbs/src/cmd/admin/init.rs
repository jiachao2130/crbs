// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs admin init`：通过 hub 远程 (re)initialize worker 上的 base_os。
//! 单节点：`-w <ID>` 可重复；批量：`--all` 对所有 online worker 派发；两者互斥。

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::cli::{AdminInitArgs, OutputFormat};
use crate::remote::RemoteTarget;

/// 目标 worker 的最小信息，用于 dispatch 前的展示。
#[derive(Debug, Clone, Serialize)]
struct WorkerBrief {
    id: i64,
    name: String,
    arch: String,
}

/// 服务端 `GET /api/v1/workers` 响应体的最小反序列化视图。
#[derive(Debug, Deserialize)]
struct WorkerStatusView {
    id: i64,
    name: String,
    arch: String,
    #[serde(default)]
    status: String,
}

#[derive(Debug, Serialize)]
struct DispatchOutcome {
    worker_id: i64,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    assignment_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub(crate) async fn handle_init(args: AdminInitArgs) -> Result<()> {
    // 缺目标参数 → ValidationFailed（USAGE=4）。
    if !args.all && args.worker.is_empty() {
        return Err(crbs_core::error::CrbsError::ValidationFailed {
            message: "either --all or one or more -w <ID> is required".into(),
        }
        .into());
    }

    // 缺远程目标属调用误用——ValidationFailed（USAGE=4）不落 INTERNAL(1)，九连族同口径。
    let target = crate::remote::resolve(
        args.remote_args.remote,
        args.remote_args.token,
        args.remote_args.ca_cert,
        false,
    )
    .await?
    .ok_or_else(|| crbs_core::error::CrbsError::ValidationFailed {
        message:
            "crbs admin init requires a remote server. Use --remote or configure remote.default"
                .to_string(),
    })?;

    let targets: Vec<WorkerBrief> = if args.all {
        let all = list_online_workers(&target).await?;
        if all.is_empty() {
            // 查无在线 worker 属"未找到"语义——NotFound（USAGE=4）。
            return Err(crbs_core::error::CrbsError::NotFound {
                message: "no online workers found".into(),
            }
            .into());
        }
        // --all arch 预检：产品声明了 arches 时本地滤掉不匹配 worker，省一发
        // 注定 409 的请求；skip 行走 stderr 说明原因（JSON stdout 纯净）。预检
        // 拉取失败 fail-open：warn 后不过滤照常派发——与 server 门禁口径一致
        //（server 侧仍兜底 arch 校验），CLI 预检不拦派发。
        let product_arches = match fetch_product_arches(&target, &args.product).await {
            Ok(arches) => arches,
            Err(e) => {
                eprintln!(
                    "[warn] failed to load product '{}' arches for pre-filter ({}); \
                     dispatching to all online workers without arch filtering, \
                     server-side arch check still applies",
                    args.product, e
                );
                Vec::new()
            }
        };
        let (matched, skipped) = partition_by_product_arches(all, &product_arches);
        for w in &skipped {
            eprintln!(
                "[skip] worker id={} name={} arch={} (product '{}' arches: {})",
                w.id,
                w.name,
                w.arch,
                args.product,
                product_arches.join(",")
            );
        }
        if matched.is_empty() {
            return Err(crbs_core::error::CrbsError::NotFound {
                message: format!(
                    "no online workers match product '{}' arches: {}",
                    args.product,
                    product_arches.join(",")
                ),
            }
            .into());
        }
        matched
    } else {
        args.worker
            .iter()
            .map(|id| WorkerBrief {
                id: *id,
                name: String::new(),
                arch: String::new(),
            })
            .collect()
    };

    print_targets(&args.product, &targets);
    crate::cmd::confirm::confirm_or_bail("Proceed to dispatch init?", args.yes)?;

    let mut first_error: Option<anyhow::Error> = None;
    let mut outcomes: Vec<DispatchOutcome> = Vec::with_capacity(targets.len());
    for w in &targets {
        match dispatch_one(&target, w.id, &args.product).await {
            Ok(assignment_id) => {
                if args.remote_args.format == OutputFormat::Text {
                    println!("[ok]  worker={} assignment_id={}", w.id, assignment_id);
                }
                outcomes.push(DispatchOutcome {
                    worker_id: w.id,
                    status: "ok",
                    assignment_id: Some(assignment_id),
                    error: None,
                });
            }
            Err(e) => {
                if args.remote_args.format == OutputFormat::Text {
                    println!("[err] worker={} error={}", w.id, e);
                }
                let msg = e.to_string();
                if first_error.is_none() {
                    first_error = Some(e);
                }
                outcomes.push(DispatchOutcome {
                    worker_id: w.id,
                    status: "err",
                    assignment_id: None,
                    error: Some(msg),
                });
            }
        }
    }

    let ok = outcomes.iter().filter(|o| o.status == "ok").count();
    let err = outcomes.len() - ok;

    match args.remote_args.format {
        OutputFormat::Json => {
            // command 与错误信封同源（json_error_contract 取 "admin init"）。
            let summary = serde_json::json!({
                "command": "admin init",
                "product": args.product,
                "ok": ok,
                "err": err,
                "results": outcomes,
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        OutputFormat::Text => {
            println!("summary: ok={} err={}", ok, err);
        }
    }

    if err > 0 {
        // 首失败错误作退出码代表：语义 CrbsError 原样透传，退出码随根因契约走；内层
        // 传输/解析失败均已语义化故 downcast 几乎必中，bail 仅兜未来未语义化源（INTERNAL(1)）。
        if let Some(ce) = first_error.and_then(|e| e.downcast::<crbs_core::error::CrbsError>().ok())
        {
            return Err(ce.into());
        }
        anyhow::bail!("{} of {} dispatches failed", err, outcomes.len());
    }
    Ok(())
}

fn print_targets(product: &str, targets: &[WorkerBrief]) {
    // 提示走 stderr，保 --format json 的 stdout 纯净。
    eprintln!(
        "About to dispatch init for product '{}' to {} worker(s):",
        product,
        targets.len()
    );
    for w in targets {
        if w.name.is_empty() && w.arch.is_empty() {
            eprintln!("  - worker id={}", w.id);
        } else {
            eprintln!("  - worker id={} name={} arch={}", w.id, w.name, w.arch);
        }
    }
}

async fn list_online_workers(target: &RemoteTarget) -> Result<Vec<WorkerBrief>> {
    let client = target.client().await?;
    let url = format!("{}/api/v1/workers", target.url);
    // reqwest 传输/body 读取失败属环境域——Network（ENVIRONMENT=6），不落 INTERNAL(1)。
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!("GET {url}: {e}"),
        })?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!("read workers response body: {e}"),
        })?;
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        // 退出码契约：PERMISSION(5)，人话文案保持不变。
        return Err(crbs_core::error::CrbsError::PermissionDenied {
            message: "Permission denied listing workers (admin/operator required)".to_string(),
        }
        .into());
    }
    if !status.is_success() {
        return Err(
            crate::remote::http_status_error("admin init list workers", status, &body).into(),
        );
    }
    // 对端响应不可解（serde 错误）属环境域——Network（ENVIRONMENT=6），不落
    // INTERNAL(1)；不可信 body 经 truncate_body_for_error 截断/剥控制序列后入错误文本。
    let all: Vec<WorkerStatusView> =
        serde_json::from_str(&body).map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!(
                "parse workers response: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })?;
    Ok(all
        .into_iter()
        .filter(|w| w.status == "online")
        .map(|w| WorkerBrief {
            id: w.id,
            name: w.name,
            arch: w.arch,
        })
        .collect())
}

/// 拉取产品 chain-resolved TOML 并解出 arches；server 侧 init_worker 用同源
/// 配置做 arch 门禁，此处预检与之同口径。对端响应不可解属环境域——
/// Network（ENVIRONMENT=6）。非字符串 arch 条目跳过（预检欠约束无害，
/// server 门禁兜底）。
async fn fetch_product_arches(target: &RemoteTarget, product: &str) -> Result<Vec<String>> {
    let toml = crate::cmd::products::fetch_resolved_toml(target, product).await?;
    let doc: toml_edit::DocumentMut =
        toml.parse()
            .map_err(|e| crbs_core::error::CrbsError::Network {
                message: format!("parse product config for '{product}': {e}"),
            })?;
    Ok(doc
        .get("arches")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

/// --all 的 arch 预检纯函数：产品已声明 arches 时按 membership 分组
///（worker arch 与产品 arches 均为具体架构，无需 noarch 特判）；arches 为
/// 空 = 产品未声明 → 全放行，server 侧同口径兜底。
fn partition_by_product_arches(
    workers: Vec<WorkerBrief>,
    product_arches: &[String],
) -> (Vec<WorkerBrief>, Vec<WorkerBrief>) {
    if product_arches.is_empty() {
        return (workers, Vec::new());
    }
    workers
        .into_iter()
        .partition(|w| product_arches.iter().any(|a| a == &w.arch))
}

async fn dispatch_one(target: &RemoteTarget, worker_id: i64, product: &str) -> Result<i64> {
    let client = target.client().await?;
    let url = format!("{}/api/v1/admin/workers/{}/init", target.url, worker_id);
    // reqwest 传输/body 读取失败属环境域——Network（ENVIRONMENT=6），不落 INTERNAL(1)。
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "product": product }))
        .send()
        .await
        .map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!("POST {url}: {e}"),
        })?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!("read init response body: {e}"),
        })?;

    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        // 退出码契约：PERMISSION(5)，人话文案保持不变。
        return Err(crbs_core::error::CrbsError::PermissionDenied {
            message: "permission denied: admin role required".to_string(),
        }
        .into());
    }
    if status == reqwest::StatusCode::CONFLICT {
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        let msg = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or(&body);
        // 退出码契约：Conflict → USAGE(4)，人话文案保持不变。
        return Err(crbs_core::error::CrbsError::Conflict {
            message: format!("cannot init: {}", msg),
        }
        .into());
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        // 退出码契约：USAGE(4)，人话文案保持不变。
        return Err(crbs_core::error::CrbsError::NotFound {
            message: format!("worker {worker_id} not found"),
        }
        .into());
    }
    if !status.is_success() {
        return Err(crate::remote::http_status_error("admin init dispatch", status, &body).into());
    }

    // 对端响应不可解（serde 错误）属环境域——Network（ENVIRONMENT=6），不落
    // INTERNAL(1)；不可信 body 经 truncate_body_for_error 截断/剥控制序列后入错误文本。
    let parsed: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| crbs_core::error::CrbsError::Network {
            message: format!(
                "parse init response: {}: {e}",
                crate::remote::truncate_body_for_error(&body)
            ),
        })?;
    let assignment_id = parsed
        .get("assignment_id")
        .and_then(|v| v.as_i64())
        // 2xx 可解析但缺 assignment_id——远端异常/被攻破（环境域）→ Network（ENVIRONMENT=6）。
        .ok_or_else(|| crbs_core::error::CrbsError::Network {
            message: format!("missing assignment_id in response: {}", body),
        })?;
    Ok(assignment_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::AdminRemoteArgs;
    use crbs_core::exit_code::{crbs_error_exit_code, ENVIRONMENT};
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 2xx 缺 assignment_id → Network（ENVIRONMENT=6）不落 INTERNAL(1)；
    /// message 含原始 body，逐字钉死。
    #[tokio::test]
    async fn missing_assignment_id_maps_to_network() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/admin/workers/3/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":"accepted"}"#))
            .mount(&server)
            .await;
        let target = RemoteTarget::new(server.uri(), None, None);

        let err = dispatch_one(&target, 3, "fedora")
            .await
            .expect_err("missing assignment_id must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::Network { .. }),
            "unexpected variant: {ce:?}"
        );
        assert_eq!(crbs_error_exit_code(ce), ENVIRONMENT);
        assert!(
            format!("{ce}").contains(r#"missing assignment_id in response: {"status":"accepted"}"#),
            "msg must be preserved verbatim: {ce}"
        );
    }

    /// 正常路径：含 assignment_id 的响应原样解出，不受缺字段守护影响。
    #[tokio::test]
    async fn assignment_id_present_parses_through() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/admin/workers/3/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"assignment_id": 91}"#))
            .mount(&server)
            .await;
        let target = RemoteTarget::new(server.uri(), None, None);

        let assignment_id = dispatch_one(&target, 3, "fedora")
            .await
            .expect("assignment_id present must pass");
        assert_eq!(assignment_id, 91);
    }

    /// 无 --remote 且无 remote.default → ValidationFailed（USAGE=4）不落 INTERNAL(1)，
    /// 对齐九连族、文案逐字钉死。HomeIsolatedEnvGuard 隔离 CRBS_CONFIG_DIR/$HOME——
    /// 用户级 remote.default 会让"无远程目标"前提失效；resolve 无网络调用即判 None。
    #[tokio::test]
    async fn missing_remote_target_is_validation_failed_exit_4() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = crate::test_support::HomeIsolatedEnvGuard::new(tmp.path());

        let args = AdminInitArgs {
            product: "fedora".to_string(),
            worker: vec![],
            all: true,
            yes: true,
            remote_args: AdminRemoteArgs {
                remote: None,
                token: None,
                ca_cert: None,
                format: OutputFormat::Text,
            },
        };
        let err = handle_init(args)
            .await
            .expect_err("missing remote target must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").contains(
                "crbs admin init requires a remote server. Use --remote or configure remote.default",
            ),
            "msg must be preserved verbatim: {ce}"
        );
    }

    fn brief(id: i64, name: &str, arch: &str) -> WorkerBrief {
        WorkerBrief {
            id,
            name: name.to_string(),
            arch: arch.to_string(),
        }
    }

    fn arches(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// 预检纯函数：membership 分组正确；产品未声明 arches（空列表）全放行。
    #[test]
    fn partition_by_product_arches_splits_and_passes_through_when_unset() {
        let (matched, skipped) = partition_by_product_arches(
            vec![brief(1, "w1", "x86_64"), brief(2, "w2", "aarch64")],
            &arches(&["aarch64"]),
        );
        assert_eq!(matched.iter().map(|w| w.id).collect::<Vec<_>>(), vec![2]);
        assert_eq!(skipped.iter().map(|w| w.id).collect::<Vec<_>>(), vec![1]);

        let (all, none) = partition_by_product_arches(vec![brief(1, "w1", "x86_64")], &[]);
        assert_eq!(all.len(), 1);
        assert!(none.is_empty());
    }

    /// 带 arches 的产品 resolved TOML fixture（shape 与 products export 一致）。
    fn resolved_toml(arches_toml: &str) -> String {
        format!(
            "base_packages = [\"bash\"]\narches = {arches_toml}\n\n[[repos]]\n\
             name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\n\
             gpgcheck = false\n"
        )
    }

    fn workers_body() -> String {
        serde_json::json!([
            { "id": 1, "name": "w1", "arch": "x86_64", "status": "online" },
            { "id": 2, "name": "w2", "arch": "aarch64", "status": "online" },
        ])
        .to_string()
    }

    fn all_args(server_uri: String) -> AdminInitArgs {
        AdminInitArgs {
            product: "mydist".to_string(),
            worker: vec![],
            all: true,
            yes: true,
            remote_args: AdminRemoteArgs {
                remote: Some(server_uri),
                token: None,
                ca_cert: None,
                format: OutputFormat::Text,
            },
        }
    }

    /// --all 端到端：arch 不匹配 worker 本地跳过（不发请求），匹配者正常派发；
    /// dispatch mock 仅登记 worker 2 路径，worker 1 若被派发即 404 失败。
    #[tokio::test]
    async fn all_dispatch_filters_workers_by_product_arches() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/workers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(workers_body()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(resolved_toml("[\"aarch64\"]")),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(wm_path("/api/v1/admin/workers/2/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"assignment_id": 9}"#))
            .expect(1)
            .mount(&server)
            .await;

        handle_init(all_args(server.uri()))
            .await
            .expect("init must succeed");
        // 不匹配 worker 不得派发：worker 1 的 init 路径无 mock，命中即 404 报错；
        // worker 2 恰一次（expect(1) 由 verify 收口）。
        server.verify().await;
    }

    /// --all 全部被滤掉 → NotFound（USAGE=4），不派发任何请求。
    #[tokio::test]
    async fn all_dispatch_with_no_arch_match_is_not_found() {
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/workers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(workers_body()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(resolved_toml("[\"riscv64\"]")),
            )
            .mount(&server)
            .await;

        let err = handle_init(all_args(server.uri()))
            .await
            .expect_err("no arch match must fail");
        let ce = err
            .downcast_ref::<crbs_core::error::CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, crbs_core::error::CrbsError::NotFound { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(crbs_error_exit_code(ce), USAGE);
        assert!(
            format!("{ce}").contains("no online workers match product 'mydist'"),
            "msg must name the product: {ce}"
        );
    }

    /// --all arch 预检拉取失败（拉不到/不可解）fail-open：warn 后不过滤，
    /// 全部在线 worker 照常派发——server 侧 arch 门禁兜底，命令不因预检失败
    /// 而失败。resolved 端点 404（4xx 不重试），两 worker 各派发恰一次。
    #[tokio::test]
    async fn all_dispatch_fail_open_when_product_arches_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/workers"))
            .respond_with(ResponseTemplate::new(200).set_body_string(workers_body()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/api/v1/products/mydist/resolved"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string(r#"{"message":"no such product"}"#),
            )
            .mount(&server)
            .await;
        for id in [1, 2] {
            Mock::given(method("POST"))
                .and(wm_path(format!("/api/v1/admin/workers/{id}/init")))
                .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"assignment_id": 9}"#))
                .expect(1)
                .mount(&server)
                .await;
        }

        handle_init(all_args(server.uri()))
            .await
            .expect("arch precheck failure must not fail --all dispatch");
        server.verify().await;
    }
}
