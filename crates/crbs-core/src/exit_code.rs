// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 进程退出码语义规范：稳定对外契约（消费面 CI 脚本 / 集群调度器按类
//! 重试-通知策略），变更需在 CHANGELOG 说明；码 → 含义 → 调度器策略见各常量 doc。

use crate::error::CrbsError;

/// 成功
pub const SUCCESS: i32 = 0;
/// 构建失败（depsolve / 容器执行 / 签名 / 层创建 / 共享层缺失 / 复现校验）；调度器：不重试或换节点重试
pub const BUILD_FAILED: i32 = 2;
/// 中断（超时 / 取消）；调度器：超时可重试，取消不重试
pub const INTERRUPTED: i32 = 3;
/// 配置 / 参数错误（含 RevisionConflict 状态冲突）：重读状态、修正请求后重新提交，勿盲目重试
pub const USAGE: i32 = 4;
/// 权限错误；调度器：不重试，需修正权限
pub const PERMISSION: i32 = 5;
/// 环境错误（IO / 数据库 / cgroup / init / 容器）；调度器：可重试（环境可能恢复）
pub const ENVIRONMENT: i32 = 6;
/// 未分类内部错误；调度器：告警，人工排查
pub const INTERNAL: i32 = 1;

/// 将 [`CrbsError`] 映射到语义退出码。
pub fn crbs_error_exit_code(e: &CrbsError) -> i32 {
    match e {
        CrbsError::DepsolveFailed { .. }
        | CrbsError::LayerCreateFailed { .. }
        | CrbsError::LayerNotFound { .. }
        | CrbsError::ContainerExecFailed { .. }
        | CrbsError::SignFailed { .. }
        | CrbsError::ReproduceVerificationFailed { .. } => BUILD_FAILED,
        CrbsError::Cancelled | CrbsError::Timeout => INTERRUPTED,
        CrbsError::ValidationFailed { .. }
        | CrbsError::NotFound { .. }
        | CrbsError::ProductChainInvalid { .. }
        | CrbsError::ProductChainCycle { .. }
        | CrbsError::ProductChainTooDeep { .. }
        | CrbsError::RevisionConflict { .. }
        | CrbsError::AlreadyExists { .. }
        | CrbsError::Conflict { .. }
        | CrbsError::DeleteRestricted { .. } => USAGE,
        CrbsError::PermissionDenied { .. } => PERMISSION,
        CrbsError::Io { .. }
        | CrbsError::Network { .. }
        | CrbsError::Database(_)
        | CrbsError::DatabaseUnavailable { .. }
        | CrbsError::CgroupSetupFailed(_) => ENVIRONMENT,
        CrbsError::Internal(_) => INTERNAL,
        CrbsError::SilentExit { code } => *code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_failures_map_to_2() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::DepsolveFailed {
                message: "x".into()
            }),
            BUILD_FAILED
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::ContainerExecFailed {
                exit_code: Some(1),
                signal: None,
                stderr: "err".into(),
            }),
            BUILD_FAILED
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::SignFailed {
                message: "x".into()
            }),
            BUILD_FAILED
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::LayerCreateFailed {
                message: "x".into()
            }),
            BUILD_FAILED
        );
    }

    #[test]
    fn test_reproduce_verification_maps_to_2() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::ReproduceVerificationFailed {
                message: "x".into()
            }),
            BUILD_FAILED
        );
    }

    #[test]
    fn test_interrupted_map_to_3() {
        assert_eq!(crbs_error_exit_code(&CrbsError::Cancelled), INTERRUPTED);
        assert_eq!(crbs_error_exit_code(&CrbsError::Timeout), INTERRUPTED);
    }

    #[test]
    fn test_validation_maps_to_4() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::ValidationFailed {
                message: "x".into()
            }),
            USAGE
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::ProductChainInvalid {
                product: "leaf".into(),
                reason: "empty base_packages".into(),
            }),
            USAGE
        );
    }

    #[test]
    fn test_permission_maps_to_5() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::PermissionDenied {
                message: "x".into()
            }),
            PERMISSION
        );
    }

    #[test]
    fn test_environment_maps_to_6() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::io_message("x")),
            ENVIRONMENT
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::Network {
                message: "x".into()
            }),
            ENVIRONMENT
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::Database("x".into())),
            ENVIRONMENT
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::DatabaseUnavailable {
                context: "acquire conn".into(),
                error: "pool timed out".into(),
            }),
            ENVIRONMENT
        );
        assert_eq!(
            crbs_error_exit_code(&CrbsError::CgroupSetupFailed("x".into())),
            ENVIRONMENT
        );
    }

    #[test]
    fn test_internal_maps_to_1() {
        assert_eq!(
            crbs_error_exit_code(&CrbsError::Internal("x".into())),
            INTERNAL
        );
    }
}

/// 退出码的 CLI 展示名与修复提示（与常量一一对应，返回 `(名称, 提示)`）；未知码返回 None（不追加提示行）。
pub fn exit_code_hint(code: i32) -> Option<(&'static str, &'static str)> {
    match code {
        INTERNAL => Some((
            "internal error",
            "unexpected failure - this is a bug; keep the full log output for reporting",
        )),
        BUILD_FAILED => Some((
            "build failed",
            "the build itself failed; inspect the build log for the failing step",
        )),
        INTERRUPTED => Some((
            "interrupted",
            // 码 3 由取消（Ctrl-C / `crbs cancel`，重试无意义）与超时（可放宽预算）共用，措辞须兼顾；拆退出码破坏契约
            "cancelled or timed out; for timeouts consider raising the timeout budget",
        )),
        USAGE => Some((
            "usage error",
            "fix the arguments or configuration and retry; run with --help for details",
        )),
        PERMISSION => Some((
            "permission denied",
            // 本地文件权限与远程 hub 401/403 共用此 hint，措辞须两场景兼顾
            "check file permissions and crbs group membership locally, or your \
             hub credentials (login/token)",
        )),
        ENVIRONMENT => Some((
            "environment error",
            "check config paths, database, disk space, and network reachability",
        )),
        SUCCESS => None,
        // SilentExit 等自定义码不追加提示行。
        _ => None,
    }
}

#[cfg(test)]
mod hint_tests {
    use super::*;

    #[test]
    fn test_exit_code_hint_covers_all_semantic_codes() {
        for code in [
            INTERNAL,
            BUILD_FAILED,
            INTERRUPTED,
            USAGE,
            PERMISSION,
            ENVIRONMENT,
        ] {
            let (name, hint) =
                exit_code_hint(code).unwrap_or_else(|| panic!("code {code} missing hint"));
            assert!(
                !name.is_empty() && !hint.is_empty(),
                "code {code} empty hint"
            );
        }
        assert_eq!(exit_code_hint(SUCCESS), None);
        assert_eq!(exit_code_hint(42), None);
    }
}
