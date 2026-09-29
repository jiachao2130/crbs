// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! setuid-root 特权 helper 的安全原语库：路径校验、capability 裁剪、特权系统调用封装。
//! 命令行解析与分发在 main.rs。

pub mod allowed_paths;
pub mod capability;
pub mod ops;
pub mod spawn;
pub mod validate;

/// 操作结果：Success 直接返回 JSON；Exec 携带待执行命令，由调用方 exec 替换本进程。
#[derive(Debug)]
pub enum Outcome {
    Success,

    Exec(std::process::Command),
}

/// helper 统一错误类型。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("validation failed: {0}")]
    Validation(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("capability error: {0}")]
    Capability(String),
}

pub fn success(r: Result<(), Error>) -> Result<Outcome, Error> {
    r.map(|_| Outcome::Success)
}
