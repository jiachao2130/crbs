// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! submit 测试：入口校验、fan-out 展开、复现与启动路径。

use super::fanout::*;
use super::reproduce::*;
use super::start::*;
use super::*;
use crate::server::state::AppState;
use crbs_core::test_support::SrpmFixture;

mod common;
mod fanout;
mod labels;
mod plan;
mod reproduce;
mod start;
