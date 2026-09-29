// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 测试辅助：跨 `mod` 共享的进程级 env 序列化守卫。`cargo test` 多线程，本
//! crate 全部 `#[cfg(test)]` mod 编进同一测试二进制、进程 env 全局共享——
//! per-mod 自带 `ENV_LOCK` 会互踩 `CRBS_CONFIG_DIR`，故守卫上提 crate 级。

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// 测试进程内把特权后端钉到 SetuidBackend（非 Helper 模式）。
/// `CrbsConfig::load()` 按宿主机状态初始化特权后端（进程级 OnceLock 单次
/// 生效）：装 setuid helper 的机器上，先加载 config 的测试把整个进程钉成
/// HelperBackend、后续测试全部继承——"隔离跑通过、整 target 必现失败"。
/// 约定：任何 config 加载前调用；首次钉死 Setuid、之后同型幂等（已初始化时
/// `Auto`/`Never` 直通）；Err（已被更早加载钉成 Helper）无法挽回，静默忽略。
pub(crate) fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

/// 拿全局锁 + 设 `CRBS_CONFIG_DIR`；drop 时自动 remove。`lock()` poison
///（前次测试 panic 的副作用，非数据损坏）直接 `into_inner()` 强取。
pub(crate) struct EnvGuard {
    _guard: MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub(crate) fn new(dir: &Path) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // set_var 部分平台 unsafe（rustc 1.80+ lint）；ENV_LOCK 已跨线程序列化
        // 本 crate 全部 CRBS_CONFIG_DIR 写入，残余风险仅外部 crate 调 set_var。
        std::env::set_var("CRBS_CONFIG_DIR", dir);
        Self { _guard: guard }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("CRBS_CONFIG_DIR");
    }
}

/// [`EnvGuard`] 的 HOME 隔离变体：同一把锁下额外把 `HOME` 指向 `dir`、
/// drop 恢复原值。`load_merged_async` 会读真实 `$HOME/.config/crbs/crbs.toml`
/// 合并用户级 remote profile——依赖"无远程目标"前提的测试不隔离会触网。
pub(crate) struct HomeIsolatedEnvGuard {
    _guard: MutexGuard<'static, ()>,
    prev_home: Option<std::ffi::OsString>,
}

impl HomeIsolatedEnvGuard {
    pub(crate) fn new(dir: &Path) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("CRBS_CONFIG_DIR", dir);
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", dir);
        Self {
            _guard: guard,
            prev_home,
        }
    }
}

impl Drop for HomeIsolatedEnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("CRBS_CONFIG_DIR");
        match self.prev_home.take() {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}
