// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 远程 server 解析与 HTTP client 共享逻辑，供各 CLI 子命令 `--remote` 模式复用。

mod download;
mod http;
mod target;

pub use download::{download_artifacts, download_task_artifacts, DownloadArtifactsOptions};
pub(crate) use download::{
    is_debug_package, safe_server_dir_component, stream_response_to_stdout, DOWNLOAD_TIMEOUT,
    LONG_BODY_TIMEOUT,
};
pub use http::{
    build_http_client, cancel_task, fetch_build_profile, fetch_public_download_info,
    fetch_task_record, fetch_task_records, list_artifacts, rebuild_task, reproduce_task,
    ArtifactsResponse, RemoteProfileResponse, TaskDetailResponse,
};
pub(crate) use http::{
    http_status_error, remote_send_json, retry_http, strip_terminal_control,
    truncate_body_for_error,
};
pub(crate) use target::is_remote_url;
pub use target::{normalize_base_url, resolve, resolve_config_target, RemoteTarget};
