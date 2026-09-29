// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 构建模式路由：本地、远程、daemon 与 attach 的选择与约束。

use crate::remote::RemoteTarget;

/// `crbs build` 的执行路径；`determine_route` 把 CLI 参数、远程解析结果与
/// daemon 偏好映射为唯一路径，避免 `handle_build_inner` 深层嵌套。daemon 系
/// 路径只表达"意图"——可用性由 handler 运行时 `local_daemon::ensure_running()`
/// 判定，失败回退本地直接路径。
#[derive(Debug)]
pub(crate) enum BuildRoute {
    /// 远程 attach：通过 HTTP API 连接到远程 server 上的构建任务。
    AttachRemote {
        target: RemoteTarget,
        attach_id: String,
    },
    /// 本地 daemon attach：意图经本地 TCP daemon 连接。
    AttachDaemon { attach_id: String },
    /// 本地直接 attach：读取本地 SQLite 状态并直接跟踪构建日志。
    AttachLocal { attach_id: String },
    /// 远程提交：将构建任务提交到远程 server。
    RemoteSubmit { target: RemoteTarget, wait: bool },
    /// 本地 daemon detach：意图经本地 TCP daemon 提交后立即返回。
    LocalDaemonDetach,
    /// 本地直接 detach：创建 lifecycle 后 spawn 后台进程构建。
    LocalDetach,
    /// 本地 daemon 直接构建：意图经本地 TCP daemon 提交并等待结果。
    LocalDaemonSubmit,
    /// 复现构建：根据已有构建记录还原环境并重新构建。
    Reproduce { task: String },
    /// Chain 构建（直接本地）：恒进程内，不路由 daemon——daemon 构建容器
    /// 不挂载 chain 的 local repo，经 daemon 会静默丢失依赖排序与轮间产物传递。
    ChainDirect,
    /// 普通批量构建：并发 worker 池逐个构建 SRPM。
    Batch,
}

/// 根据 CLI 参数、远程解析与 daemon 偏好确定唯一执行路径。优先级即分支序：
/// `--attach`（远程→daemon→本地）> `--remote` > `--detach`（daemon→本地）>
/// `--reproduce`（须先于 daemon 分支）> daemon 提交（非 chain/reproduce）>
/// `--chain`（恒进程内）> 默认 batch。
pub(crate) fn determine_route(
    runtime: &crate::cli::BuildRuntimeArgs,
    behavior: &crate::cli::BuildBehaviorArgs,
    reproduce: &crate::cli::BuildReproduceArgs,
    remote_target: Option<RemoteTarget>,
    prefer_daemon: bool,
) -> BuildRoute {
    if let Some(ref attach_id) = runtime.attach {
        if let Some(target) = remote_target {
            return BuildRoute::AttachRemote {
                target,
                attach_id: attach_id.clone(),
            };
        }
        if prefer_daemon {
            return BuildRoute::AttachDaemon {
                attach_id: attach_id.clone(),
            };
        }
        return BuildRoute::AttachLocal {
            attach_id: attach_id.clone(),
        };
    }

    if let Some(target) = remote_target {
        return BuildRoute::RemoteSubmit {
            target,
            wait: !runtime.detach,
        };
    }

    if runtime.detach {
        if prefer_daemon {
            return BuildRoute::LocalDaemonDetach;
        }
        return BuildRoute::LocalDetach;
    }

    // reproduce 必须先于 daemon 分支：daemon post_batch 不理解 reproduce 语义，
    // 会把任务当普通 SRPM 提交、静默丢弃 reproduce_from_build_id。
    if let Some(ref task) = reproduce.reproduce {
        return BuildRoute::Reproduce { task: task.clone() };
    }

    if prefer_daemon && !behavior.chain {
        return BuildRoute::LocalDaemonSubmit;
    }

    if behavior.chain {
        return BuildRoute::ChainDirect;
    }

    BuildRoute::Batch
}

#[cfg(test)]
mod tests {
    use crate::cli::{
        BuildArgs, BuildBehaviorArgs, BuildInputArgs, BuildOutputArgs, BuildReproduceArgs,
        BuildRuntimeArgs, ContainerParams, OutputFormat,
    };

    use super::{determine_route, BuildRoute};

    /// 构造一个默认的 `BuildArgs`，所有路由相关字段均为"未设置"状态。
    fn default_build_args() -> BuildArgs {
        BuildArgs {
            input: BuildInputArgs {
                srpm: Vec::new(),
                product: None,
                list: None,
                rebuild: None,
            },
            behavior: BuildBehaviorArgs {
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
                no_publish: false,
                no_consume: false,
                min_mem: None,
                min_ncpu: None,
                min_disk: None,
                label: Vec::new(),
            },
            container: ContainerParams {
                backend: None,
                no_network: false,
                memory_max: None,
                cpu_quota: None,
            },
            runtime: BuildRuntimeArgs {
                detach: false,
                download: false,
                attach: None,
                remote: None,
                token: None,
                ca_cert: None,
                local: false,
                daemon: false,
            },
            output: BuildOutputArgs {
                format: OutputFormat::Text,
                follow_logs: false,
                summary_limit: 20,
                list_failed: false,
                list_succeeded: false,
                concise: false,
                verbose_summary: false,
            },
            reproduce: BuildReproduceArgs {
                reproduce: None,
                reproduce_keep_tmp_on_failure: false,
                no_reproduce: false,
                repro_from_srpm: false,
            },
        }
    }

    fn dummy_remote_target() -> crate::remote::RemoteTarget {
        crate::remote::RemoteTarget::new("https://crbs.example.com".to_string(), None, None)
    }

    fn do_determine_route(
        args: &BuildArgs,
        target: Option<crate::remote::RemoteTarget>,
        prefer_daemon: bool,
    ) -> BuildRoute {
        determine_route(
            &args.runtime,
            &args.behavior,
            &args.reproduce,
            target,
            prefer_daemon,
        )
    }

    #[test]
    fn route_attach_with_remote() {
        let mut args = default_build_args();
        args.runtime.attach = Some("abc123".to_string());
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::AttachRemote { attach_id, .. } => assert_eq!(attach_id, "abc123"),
            other => panic!("expected AttachRemote, got {:?}", other),
        }
    }

    #[test]
    fn route_attach_with_daemon_preference() {
        let mut args = default_build_args();
        args.runtime.attach = Some("abc123".to_string());
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::AttachDaemon { attach_id } => assert_eq!(attach_id, "abc123"),
            other => panic!("expected AttachDaemon, got {:?}", other),
        }
    }

    #[test]
    fn route_attach_fallback_local() {
        let mut args = default_build_args();
        args.runtime.attach = Some("abc123".to_string());
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::AttachLocal { attach_id } => assert_eq!(attach_id, "abc123"),
            other => panic!("expected AttachLocal, got {:?}", other),
        }
    }

    #[test]
    fn route_remote_submit_wait() {
        let args = default_build_args();
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::RemoteSubmit { wait, .. } => assert!(wait),
            other => panic!("expected RemoteSubmit with wait=true, got {:?}", other),
        }
    }

    #[test]
    fn route_remote_submit_detach() {
        let mut args = default_build_args();
        args.runtime.detach = true;
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::RemoteSubmit { wait, .. } => assert!(!wait),
            other => panic!("expected RemoteSubmit with wait=false, got {:?}", other),
        }
    }

    /// reproduce + detach + remote：fire-and-forget 复现提交（wait=false）。
    #[test]
    fn route_reproduce_with_detach_remote_submit() {
        let mut args = default_build_args();
        args.reproduce.reproduce = Some("15".into());
        args.runtime.detach = true;
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::RemoteSubmit { wait, .. } => assert!(!wait),
            other => panic!("expected RemoteSubmit with wait=false, got {:?}", other),
        }
    }

    /// reproduce + detach 无 remote：本地/daemon 不支持 detach 复现（运行时
    /// 守卫在 handle_build_inner；路由层面 reproduce 仍后于 detach 分支）。
    #[test]
    fn route_reproduce_with_detach_without_remote_still_detach_route() {
        let mut args = default_build_args();
        args.reproduce.reproduce = Some("15".into());
        args.runtime.detach = true;
        let route = do_determine_route(&args, None, false);
        assert!(matches!(route, BuildRoute::LocalDetach));
    }

    #[test]
    fn route_detach_prefers_daemon() {
        let mut args = default_build_args();
        args.runtime.detach = true;
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::LocalDaemonDetach => {}
            other => panic!("expected LocalDaemonDetach, got {:?}", other),
        }
    }

    #[test]
    fn route_detach_fallback_local() {
        let mut args = default_build_args();
        args.runtime.detach = true;
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::LocalDetach => {}
            other => panic!("expected LocalDetach, got {:?}", other),
        }
    }

    #[test]
    fn route_daemon_submit() {
        let args = default_build_args();
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::LocalDaemonSubmit => {}
            other => panic!("expected LocalDaemonSubmit, got {:?}", other),
        }
    }

    #[test]
    fn route_daemon_submit_skipped_when_chain() {
        let mut args = default_build_args();
        args.behavior.chain = true;
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::ChainDirect => {}
            other => panic!("expected ChainDirect, got {:?}", other),
        }
    }

    /// 回归：reproduce 不得路由进 daemon（daemon 提交丢弃 reproduce 语义）。
    #[test]
    fn route_daemon_submit_skipped_when_reproduce() {
        let mut args = default_build_args();
        args.reproduce.reproduce = Some("abc123".to_string());
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::Reproduce { task } => assert_eq!(task, "abc123"),
            other => panic!("expected Reproduce, got {:?}", other),
        }
    }

    #[test]
    fn route_reproduce() {
        let mut args = default_build_args();
        args.reproduce.reproduce = Some("task-001".to_string());
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::Reproduce { task } => assert_eq!(task, "task-001"),
            other => panic!("expected Reproduce, got {:?}", other),
        }
    }

    #[test]
    fn route_chain_always_direct_even_with_daemon() {
        let mut args = default_build_args();
        args.behavior.chain = true;
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::ChainDirect => {}
            other => panic!("expected ChainDirect, got {:?}", other),
        }
    }

    #[test]
    fn route_chain_direct() {
        let mut args = default_build_args();
        args.behavior.chain = true;
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::ChainDirect => {}
            other => panic!("expected ChainDirect, got {:?}", other),
        }
    }

    #[test]
    fn route_batch_default() {
        let args = default_build_args();
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::Batch => {}
            other => panic!("expected Batch, got {:?}", other),
        }
    }

    #[test]
    fn route_attach_takes_priority_over_remote() {
        let mut args = default_build_args();
        args.runtime.attach = Some("abc123".to_string());
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::AttachRemote { .. } => {}
            other => panic!("expected AttachRemote, got {:?}", other),
        }
    }

    #[test]
    fn route_remote_takes_priority_over_detach() {
        let mut args = default_build_args();
        args.runtime.detach = true;
        let target = Some(dummy_remote_target());
        let route = do_determine_route(&args, target, false);
        match route {
            BuildRoute::RemoteSubmit { .. } => {}
            other => panic!("expected RemoteSubmit, got {:?}", other),
        }
    }

    #[test]
    fn route_detach_takes_priority_over_daemon_submit() {
        let mut args = default_build_args();
        args.runtime.detach = true;
        let route = do_determine_route(&args, None, true);
        match route {
            BuildRoute::LocalDaemonDetach => {}
            other => panic!("expected LocalDaemonDetach, got {:?}", other),
        }
    }

    #[test]
    fn route_reproduce_takes_priority_over_chain() {
        let mut args = default_build_args();
        args.reproduce.reproduce = Some("task-001".to_string());
        args.behavior.chain = true;
        let route = do_determine_route(&args, None, false);
        match route {
            BuildRoute::Reproduce { task } => assert_eq!(task, "task-001"),
            other => panic!("expected Reproduce, got {:?}", other),
        }
    }
}
