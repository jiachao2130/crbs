// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-server：CRBS 服务端——HTTP REST API、Web 页面（SSR）与 CLI 子命令。
//! 构建、状态存储等能力复用 crbs-core；本 crate 负责 axum 路由（server）、
//! CLI 入口（cli）与本地 daemon 生命周期（local）。

pub mod cli;
pub mod local;
pub mod server;
#[doc(hidden)]
pub mod test_support;
