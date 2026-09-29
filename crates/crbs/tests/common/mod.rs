#![allow(dead_code)]
// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2.
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INDUSTRY,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! CLI 集成测试共享基建：各测试文件是独立二进制，`mod common;` 各自 include
//! 本文件（进程间本就隔离）。

// 测试辅助函数不带 #[test] 属性，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use tempfile::TempDir;

/// 沙箱配置：crbs_root 指向临时目录，open_for_engine 建库成功，失败点收敛在
/// handler 内（信封收口覆盖范围）。
pub fn sandbox() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let crbs_root = tmp.path().join("engine-root");
    fs::create_dir_all(&crbs_root).unwrap();
    fs::write(
        tmp.path().join("crbs.toml"),
        format!("crbs_root = \"{}\"\n", crbs_root.display()),
    )
    .unwrap();
    tmp
}
