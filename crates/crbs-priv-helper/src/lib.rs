// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-priv-helper：CRBS 特权 one-shot helper 安全原语库——setuid-root 的
//! 路径校验、capability 裁剪、特权系统调用封装；`main.rs` 负责命令解析和分发。

pub mod allowed_paths;
pub mod capability;
pub mod ops;
pub mod spawn;
pub mod validate;

/// helper 操作结果：直接返回 JSON（Success）或 exec 替换当前进程（Exec）。
#[derive(Debug)]
pub enum Outcome {
    /// 操作完成，无需替换进程。
    Success,
    /// 以已配置的命令 exec 替换当前进程。
    Exec(std::process::Command),
}

/// helper 统一错误类型。
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 路径或参数校验失败。
    #[error("validation failed: {0}")]
    Validation(String),
    /// 调用者身份或目标权限不足。
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    /// 系统调用或文件 IO 失败。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// 当前平台或配置不支持该操作。
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// capability 查询或裁剪失败。
    #[error("capability error: {0}")]
    Capability(String),
}

/// 把无返回值的操作结果映射为 `Outcome::Success`。
pub fn success(r: Result<(), Error>) -> Result<Outcome, Error> {
    r.map(|_| Outcome::Success)
}
