// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 页面组件、模板与 SSE 脚本片段。

pub(crate) use crbs_core::util::format_local_time;

mod badge;
mod chart;
mod form;
mod layout;
mod pagination;
mod phase;
mod sse_script;
mod table;
mod telemetry_chart;

pub(crate) use badge::{
    attribution_badge, phase_badge, phase_badge_with_class, phase_modifier, phase_status,
    user_status_badge, worker_heartbeat_older_than, worker_status_badge,
    worker_status_badge_with_class,
};
pub(crate) use chart::{
    donut_chart, duration_chart, gauge_chart, stat_strip, ChartSegment, StatStripItem,
};
pub(crate) use form::{
    admin_inline_form, admin_select, cancel_button, confirm_button, confirm_button_ghost,
    filter_apply, filter_form, rebuild_button, reproduce_button, secret_reveal_box,
    FilterFormParams,
};
pub(crate) use layout::{
    admin_card_grid, ascii_location_value, back_link, detail_grid, detail_page_head, empty_state,
    error_content, error_flash_location, error_title, favicon, format_kb_human, generate_nonce,
    internal_error_flash, list_page_head, load_level, no_store, page_bare_with_csp_status,
    page_with_csp, page_with_csp_status, redirect_body, resource_cap_bits,
    see_other_error_redirect, see_other_redirect, side_card, side_kv, status_message,
    storage_error_flash, PageCspParams,
};
pub(crate) use pagination::{pagination_links, PaginationParams, StatusQuery};
// phase_step_label / HIDDEN_TOOL_PHASES 仅 sse_script 直连 phase 使用，不上本公共面。
pub(crate) use phase::{phase_timeline, HIDDEN_TOOL_PHASES};
pub(crate) use sse_script::{
    build_sse_script, dashboard_sse_script, js_str, log_line_anchor_script, log_sse_script,
    notify_button, pending_log_sse_script, task_sse_script, worker_sse_script,
};
pub(crate) use table::{
    arch_matrix, artifact_table, artifact_tree_script, changelog_header_link,
    clickable_rows_script, count_chip, danger_row, filter_chips, id_link, parent_task_block,
    phase_chips, srpm_download_href, user_cell, AUDIT_ACTIONS,
};
pub(crate) use telemetry_chart::{telemetry_chart, ChartPoint, TelemetryRange};
