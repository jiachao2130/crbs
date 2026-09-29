// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `nihao` 端点：连通性与认证自检。

use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::server::auth::AuthContext;
use crate::server::state::AppState;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/nihao", get(nihao))
}

#[derive(Serialize)]
pub(crate) struct NihaoResponse {
    pub message: &'static str,
    pub server_version: &'static str,
    pub server_time: String,
    pub auth: &'static str,
    pub user: String,
    pub role: String,
}

pub(crate) async fn nihao(
    State(_state): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
) -> Json<NihaoResponse> {
    let (auth_status, user, role) = match auth {
        Some(Extension(ctx)) => ("ok", ctx.user, ctx.role),
        // 未认证时不返回具体用户/角色信息，避免向外部泄露认证状态与内部身份。
        None => ("disabled", String::new(), String::new()),
    };
    Json(NihaoResponse {
        message: "nihao",
        server_version: env!("CARGO_PKG_VERSION"),
        server_time: chrono::Utc::now().to_rfc3339(),
        auth: auth_status,
        user,
        role,
    })
}
