// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 测试辅助：跨 mod 共享的进程级 env 访问串行化（互斥锁；cargo test 多线程并行改 env 必须串行）。

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

pub(crate) struct EnvGuard {
    _guard: MutexGuard<'static, ()>,
}

impl EnvGuard {
    pub(crate) fn new(dir: &Path) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        std::env::set_var("CRBS_CONFIG_DIR", dir);
        Self { _guard: guard }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("CRBS_CONFIG_DIR");
    }
}

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
