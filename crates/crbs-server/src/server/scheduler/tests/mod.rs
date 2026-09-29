// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! scheduler 测试：按域拆分，共享夹具集中在 [`common`]。

use super::local::*;
use super::maintenance::*;
use super::profiles::*;
use super::*;
use crate::server::routes::builds::BuildOptions;
use crate::server::worker::dispatch::WorkerDispatch;
use crbs_core::config::ServerConfig;
use crbs_core::BuildInsert;
use crbs_core::StateStore;
use crbs_core::WorkerStatus;
use std::collections::HashMap;
use std::path::Path;

mod common;
mod dispatch;
mod local;
mod maintenance;
mod weights;
