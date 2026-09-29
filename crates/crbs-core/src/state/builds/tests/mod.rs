// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! builds state 测试：按写入/终态/查询/取件分域，共享夹具集中在 [`common`]。

use super::completion::truncate_to_bytes;
use super::GuardedBuildInfo;
use crate::state::test_state::create_test_store;
use crate::state::{BatchInsert, BuildInsert, StateStore};

mod common;
mod complete;
mod insert;
mod listing;
mod pick;
