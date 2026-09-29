// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程状态查询：通过 HTTP API 获取远程 server 的 Task 记录并格式化输出。

use std::collections::HashSet;

use crate::cli::OutputFormat;
use crate::cmd::status::format::{print_task_detail, print_task_table};
use crate::cmd::status::{filter_tasks, StatusArgs};

/// 远程 status 处理入口。
pub(crate) async fn handle_remote_status(
    target: crate::remote::RemoteTarget,
    args: &StatusArgs,
    filter_set: HashSet<String>,
    label_filter: Option<(String, String)>,
) -> anyhow::Result<()> {
    if let Some(ref task) = args.task {
        if args.profile {
            // profile 输入按子构建 ID 解释；解析失败 ValidationFailed（USAGE=4）。
            let p = crate::remote::fetch_build_profile(
                &target,
                task.parse::<i64>()
                    .map_err(|e| crbs_core::error::CrbsError::ValidationFailed {
                        message: format!("invalid task/build id: {e}"),
                    })?,
            )
            .await?;
            if args.format == OutputFormat::Json {
                match &p.profile {
                    // JSON 对齐目标 = 嵌套 profile 本体（与本地 status.rs 信封同形），
                    // 非整个 RemoteProfileResponse（id/elapsed 是远程契约自有字段）。
                    Some(profile) => println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "command": "status",
                            "profile": profile,
                        }))?
                    ),
                    // 旧 server（无 profile 字段）：降级打印整个响应（平铺加 command）。
                    None => println!(
                        "{}",
                        serde_json::to_string_pretty(&crate::cmd::json_success_envelope(
                            "status",
                            serde_json::to_value(&p)?,
                        ))?
                    ),
                }
            } else {
                print!("{}", render_remote_profile(&p));
            }
            return Ok(());
        }

        let detail = crate::remote::fetch_task_record(
            &target,
            // 解析失败 ValidationFailed（USAGE=4）；消息合串保留 context 链可见文本。
            task.parse::<i64>().map_err(|e| {
                crbs_core::error::CrbsError::ValidationFailed {
                    message: format!(
                        "invalid task id (remote status requires the full numeric task id from the task list): {e}"
                    ),
                }
            })?,
            None,
        )
        .await?;

        if args.format == OutputFormat::Json {
            // 信封平铺加 command:"status"（TaskDetailResponse 本身 flatten，与本地详情同形）。
            let mut body = serde_json::to_value(&detail)?;
            super::shape_task_json(&mut body);
            println!(
                "{}",
                serde_json::to_string_pretty(&crate::cmd::json_success_envelope("status", body,))?
            );
        } else {
            print_task_detail(
                &detail.task,
                &detail.builds,
                detail.lineage.as_ref(),
                &detail.labels,
            );
        }
        return Ok(());
    }

    if args.watch {
        let cancel = crate::cmd::ctrl_c_cancel_token();
        // 取数闭包只捕 Copy 引用；max=10：单次网络抖动不终结长驻视图，重试节奏在共享循环内。
        let target = &target;
        let product = args.product.as_deref();
        let cancel_ref = &cancel;
        let label_filter = &label_filter;
        let fetch = move || {
            let label = label_filter.as_ref().map(|(k, v)| (k.as_str(), v.as_str()));
            async move {
                anyhow::Ok(
                    crate::remote::fetch_task_records(
                        target,
                        product,
                        None,
                        label,
                        None,
                        Some(cancel_ref),
                    )
                    .await?,
                )
            }
        };
        return super::watch_loop(cancel_ref, fetch, &filter_set, args.limit, 10).await;
    }

    // 服务端 limit 先于客户端 filter 生效会漏掉前 N 条外的匹配；单一 phase
    // 过滤下推服务端，多 phase/无过滤全量取回客户端过滤。
    let (phase, remote_limit) = if filter_set.len() == 1 {
        (filter_set.iter().next().map(String::as_str), None)
    } else {
        (None, remote_list_limit(args.limit))
    };
    let tasks = crate::remote::fetch_task_records(
        &target,
        args.product.as_deref(),
        phase,
        label_filter.as_ref().map(|(k, v)| (k.as_str(), v.as_str())),
        remote_limit,
        None,
    )
    .await?;
    let filtered = filter_tasks(tasks, &filter_set);

    // 空结果早退只保留 text 文案；JSON 空态由下方共享信封输出（同本地路径）。
    if filtered.is_empty() && args.format != OutputFormat::Json {
        println!("No tasks found.");
        return Ok(());
    }

    if args.format == OutputFormat::Json {
        let display_limit = if args.limit == 0 {
            filtered.len()
        } else {
            args.limit
        };
        let mut body = serde_json::json!({
            "command": "status",
            "tasks": filtered.iter().take(display_limit).collect::<Vec<_>>(),
        });
        super::shape_task_json(&mut body);
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }

    // 截断提示两态：shown < total（单 phase 下推时服务端未限页）如实给两数；
    // limit 下推且页满（total == limit）= 真实总数不可知，只提示"前 N 条"，
    // 且仅 limit 真被下推（filter_set.len() != 1）时——单 phase 全量在手不算截断。
    let (shown, total) = print_task_table(&filtered, args.limit);
    if shown < total {
        println!("\nshowing {shown} of {total} (use --limit 0 for all)");
    } else if args.limit != 0 && total == args.limit && filter_set.len() != 1 {
        println!("\nshowing first {} (use --limit 0 for all)", args.limit);
    }

    Ok(())
}

/// 远程 profile 的 human 渲染：新 server（含嵌套 profile）= record 摘要头行 +
/// 本地同款 profile 展示；`elapsed_secs`（server 侧）与 `profile.total_seconds`
///（引擎计时）两个口径不可互换——头行打前者、体打后者；旧 server 降级六字段布局。
fn render_remote_profile(p: &crate::remote::RemoteProfileResponse) -> String {
    use crate::cmd::status::format::{format_profile, format_seconds};

    let mut out = format!("Profile for build {}:\n", p.id);
    out.push_str(&format!("  package: {}\n", p.pkg_name));
    out.push_str(&format!("  product: {}\n", p.product));
    out.push_str(&format!("  phase:   {}\n", p.phase));
    out.push_str(&format!("  elapsed: {}\n", format_seconds(p.elapsed_secs)));
    match &p.profile {
        Some(profile) => out.push_str(&format_profile(profile)),
        None => {
            if !p.rpms.is_empty() {
                out.push_str("  rpms:\n");
                for rpm in &p.rpms {
                    out.push_str(&format!("    - {}\n", rpm));
                }
            }
        }
    }
    out
}

/// 把 CLI `--limit`（0 = all）映射为远程列表 limit 参数：上限取服务端同源常量
/// `crbs_core::validation::MAX_LIST_LIMIT`（服务端 400 硬拒，先 clamp 才能让超限
/// `--limit` 以服务端最大页生效，clamp 时 warn 显式化口径差）；0 不下推，返回全量。
fn remote_list_limit(limit: usize) -> Option<usize> {
    let clamped = (limit != 0).then(|| limit.min(crbs_core::validation::MAX_LIST_LIMIT));
    if clamped.is_some_and(|c| c < limit) {
        tracing::warn!(
            limit,
            clamped = clamped.unwrap_or_default(),
            "--limit exceeds the server-side list cap; results clamped to the server maximum page"
        );
    }
    clamped
}

#[cfg(test)]
mod tests {
    use super::{remote_list_limit, render_remote_profile};
    use crate::remote::RemoteProfileResponse;
    use crbs_core::engine::profile::{BuildPhase, BuildProfile};

    #[test]
    fn remote_list_limit_zero_means_all() {
        assert_eq!(remote_list_limit(0), None);
    }

    #[test]
    fn remote_list_limit_passes_small_values_through() {
        assert_eq!(remote_list_limit(20), Some(20));
        assert_eq!(remote_list_limit(200), Some(200));
    }

    /// `--limit > 200` 不触发服务端 400：clamp 到服务端允许的最大页。
    #[test]
    fn remote_list_limit_clamps_to_server_max() {
        assert_eq!(remote_list_limit(201), Some(200));
        assert_eq!(remote_list_limit(10_000), Some(200));
    }

    fn sample_profile() -> BuildProfile {
        BuildProfile {
            build_id: 9,
            srpm: "hello-1.0-1.src.rpm".into(),
            total_seconds: 42.0,
            shared_layer_hit: false,
            ccache: None,
            phases: vec![BuildPhase {
                name: "build".into(),
                duration_seconds: 40.0,
                skipped: None,
                reason: None,
                exit_code: None,
            }],
        }
    }

    /// 旧 server 响应（wire 无 `profile` 字段）：反序列化并降级六字段布局，rpms 照打。
    #[test]
    fn remote_profile_old_response_degrades_to_legacy_layout() {
        let legacy_wire = serde_json::json!({
            "id": 9,
            "pkg_name": "hello",
            "product": "fedora",
            "phase": "succeeded",
            "elapsed_secs": 42,
            "rpms": ["hello-1.0-1.x86_64.rpm"],
        });
        let p: RemoteProfileResponse =
            serde_json::from_value(legacy_wire).expect("legacy wire must deserialize");
        assert!(p.profile.is_none(), "missing field must degrade to None");

        let rendered = render_remote_profile(&p);
        assert!(rendered.contains("Profile for build 9:"), "{rendered}");
        assert!(rendered.contains("  rpms:\n    - hello-1.0-1.x86_64.rpm"));
        assert!(
            !rendered.contains("Phase breakdown:"),
            "degraded layout must not render nested profile: {rendered}"
        );

        // 降级路径序列化回 wire 不冒出 "profile": null。
        let back = serde_json::to_value(&p).expect("serialize back");
        assert!(back.get("profile").is_none());
    }

    /// 新 server 响应（含嵌套 profile）：摘要头行与 profile 本体并存（两个 elapsed 口径）。
    #[test]
    fn remote_profile_new_response_renders_header_plus_local_profile() {
        let wire = serde_json::json!({
            "id": 9,
            "pkg_name": "hello",
            "product": "fedora",
            "phase": "succeeded",
            "elapsed_secs": 55,
            "rpms": ["hello-1.0-1.x86_64.rpm"],
            "profile": sample_profile(),
        });
        let p: RemoteProfileResponse =
            serde_json::from_value(wire).expect("new wire must deserialize");
        let profile = p.profile.as_ref().expect("nested profile present");

        let rendered = render_remote_profile(&p);
        assert!(rendered.contains("Profile for build 9:"), "{rendered}");
        assert!(rendered.contains("  elapsed: 55s"), "{rendered}");
        assert!(
            rendered.contains("Build 9  hello-1.0-1.src.rpm  42.0s"),
            "{rendered}"
        );
        assert!(rendered.contains("Phase breakdown:"), "{rendered}");
        let body = serde_json::to_string_pretty(profile).expect("profile json");
        assert!(body.contains("\"total_seconds\": 42.0"), "{body}");
    }

    /// task id 解析失败 = ValidationFailed（USAGE=4，不落 INTERNAL(1)）；解析先于
    /// 网络调用（bogus target 不触网）；合串消息保留 context 链文本（同族站点同款）。
    #[tokio::test]
    async fn remote_task_id_parse_failure_is_validation_failed_exit_4() {
        use crate::cli::OutputFormat;
        use crate::cmd::status::StatusArgs;
        use crbs_core::exit_code::{crbs_error_exit_code, USAGE};
        use std::collections::HashSet;

        let target = crate::remote::RemoteTarget::new("http://127.0.0.1:1".to_string(), None, None);
        let args = StatusArgs {
            task: Some("abc".into()),
            product: None,
            limit: 20,
            format: OutputFormat::Text,
            all: false,
            filter: Vec::new(),
            label: None,
            watch: false,
            profile: true,
            repair: false,
            remote: None,
            token: None,
            local: false,
        };
        let err = super::handle_remote_status(target, &args, HashSet::new(), None)
            .await
            .expect_err("non-numeric task id must fail");
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
                "validation failed: invalid task/build id: invalid digit found in string"
            ),
            "msg must keep the original context-chain text: {ce}"
        );
    }
}
