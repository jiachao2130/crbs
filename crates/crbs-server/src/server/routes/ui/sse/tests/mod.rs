// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! sse 测试：按端点拆分，共享夹具集中在 [`common`]。

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, Sse};
use axum::response::IntoResponse;
use bytes::Bytes;
use crbs_core::config::ServerConfig;
use crbs_core::StateStore;
use tokio_stream::StreamExt;

use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::routes::logs::LogsQuery;
use crate::server::state::AppState;

use super::build::*;
use super::common::*;
use super::dashboard::*;
use super::log::*;
use super::task::*;
use super::worker::*;

mod build;
mod common;
mod dashboard;
mod log;
mod task;
mod worker;
