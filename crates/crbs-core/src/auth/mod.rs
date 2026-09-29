// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 认证与授权。
//!
//! 高熵密钥抽象（`crbs_tok_`/`crbs_wkr_`/`crbs_sess_` 前缀）见 [`secret`]，
//! argon2id 密码哈希与策略见 [`password`]。凭据全存 SQLite，无静态 token 文件。

pub mod password;
pub mod secret;
