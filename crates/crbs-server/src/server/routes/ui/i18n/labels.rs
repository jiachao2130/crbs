// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 动态值显示名映射：phase、优先级、可见性、Worker/用户状态、错误页状态短语。

use super::{t, Lang, TextKey};
use axum::http::StatusCode;

pub(crate) fn t_phase(lang: Lang, phase: &str) -> &str {
    match lang {
        Lang::En => phase,
        Lang::Zh => match phase {
            "pending" => "等待中",
            "assigned" => "已分配",
            "building" => "构建中",
            "succeeded" => "成功",
            "failed" => "失败",
            "timeout" => "超时",
            "cancelled" => "已取消",
            other => other,
        },
    }
}

/// 过滤下拉 phase 显示名：En 首字母大写（UI/测试钉住的形态），Zh 复用 [`t_phase`]。
pub(crate) fn phase_option_label(lang: Lang, phase: &str) -> &str {
    match lang {
        Lang::En => match phase {
            "pending" => "Pending",
            "assigned" => "Assigned",
            "building" => "Building",
            "succeeded" => "Succeeded",
            "failed" => "Failed",
            "timeout" => "Timeout",
            "cancelled" => "Cancelled",
            other => other,
        },
        Lang::Zh => t_phase(lang, phase),
    }
}

pub(crate) fn priority_label(lang: Lang, priority: crbs_core::types::BuildPriority) -> String {
    let key = match priority {
        0 => Some(TextKey::PriorityNormal),
        1 => Some(TextKey::PriorityHigh),
        2 => Some(TextKey::PriorityCritical),
        _ => None,
    };
    match key {
        Some(k) => t(lang, k).to_string(),
        None => priority.to_string(),
    }
}

pub(crate) fn visibility_label(lang: Lang, visibility: &str) -> &str {
    match visibility {
        crbs_core::VISIBILITY_PUBLIC => t(lang, TextKey::VisPublic),
        crbs_core::VISIBILITY_PRIVATE => t(lang, TextKey::VisPrivate),
        other => other,
    }
}

/// "stale" 降级态不在此映射，由 components::worker_status_badge 另行渲染（需心跳新鲜度上下文）。
pub(crate) fn worker_status_label(lang: Lang, status: &str) -> &str {
    match status {
        "online" => t(lang, TextKey::WorkerOnline),
        "offline" => t(lang, TextKey::WorkerOffline),
        other => other,
    }
}

pub(crate) fn user_status_label(lang: Lang, status: &str) -> &str {
    match status {
        "active" => t(lang, TextKey::UserActive),
        "disabled" => t(lang, TextKey::UserDisabled),
        other => other,
    }
}

/// 用户/ACL 角色显示名，仅用于下拉 label、徽章等展示位：表单 value 与校验值域
/// 保持机器串；En 首字母大写、zh 短形均为刻意钉住形态。
pub(crate) fn role_label(lang: Lang, role: &str) -> &str {
    match role {
        "admin" => t(lang, TextKey::RoleAdmin),
        "operator" => t(lang, TextKey::RoleOperator),
        "builder" => t(lang, TextKey::RoleBuilder),
        "viewer" => t(lang, TextKey::RoleViewer),
        other => other,
    }
}

pub(crate) fn status_reason_localized(lang: Lang, status: StatusCode) -> Option<&'static str> {
    if lang == Lang::En {
        return status.canonical_reason();
    }
    let zh = match status.as_u16() {
        400 => "错误请求",
        401 => "未授权",
        403 => "禁止访问",
        404 => "未找到",
        405 => "方法不允许",
        409 => "冲突",
        429 => "请求过于频繁",
        500 => "服务器内部错误",
        503 => "服务不可用",
        _ => return status.canonical_reason(),
    };
    Some(zh)
}
