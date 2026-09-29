// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 跨 crate 共享的测试工具：rpm/rpmbuild 可用性探测与最小 SRPM 夹具构造。
//!
//! 无条件编译（crbs-server `test_support` 同款先例：集成测试独立 crate 编译，
//! `#[cfg(test)]` 门控覆盖不到下游消费方）。只被测试引用，不进任何生产路径。
//! 消费方混有非 linux-gated 的"探测失败即跳过"式测试，全部符号在任意目标
//! 平台都有调用方，无 dead-code 风险。

// unwrap/expect 白名单：仅测试引用，但随 lib 无条件编译，clippy 测试豁免覆盖不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// rpm 可用性探测（一次 spawn；调用方按"不可用即跳过"或 assert 自行处置）。
pub fn rpm_spawnable() -> bool {
    tool_spawnable("rpm")
}

/// rpmbuild 可用性探测（真实 SRPM 构造的前置，与 [`rpm_spawnable`] 同口径）。
pub fn rpmbuild_spawnable() -> bool {
    tool_spawnable("rpmbuild")
}

fn tool_spawnable(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 用 `rpmbuild -bs` 构造最小 SRPM：`topdir` 下建 rpm 标准子目录，spec 写
/// `SPECS/{name}.spec`，返回 SRPMS/ 产物路径（按包名前缀定位）。调用方按需
/// 把产物拷到目标位置（批次暂存场景）。
///
/// `rpmbuild -bs` 不裁决 arch 约束，`ExclusiveArch`/`ExcludeArch` 写宿主外
/// 取值也能出包——这正是夹具能模拟"不兼容 spec"的原因。`dist %{nil}` 让
/// Release 渲染确定（这些最小 spec 的 Release 字面写死，dist 本不参与，
/// 统一钉死防御宿主机宏漂移）。
/// [`build_srpm`] 的夹具参数：最小 spec 的身份字段与架构约束列表。
pub struct SrpmFixture<'a> {
    pub topdir: &'a Path,
    pub name: &'a str,
    pub version: &'a str,
    pub release: &'a str,
    pub buildarch: Option<&'a str>,
    pub build_requires: &'a [&'a str],
    pub exclusive: &'a [&'a str],
    pub exclude: &'a [&'a str],
}

/// 按 fixture 生成最小 SRPM（调用真实 rpmbuild），供测试走完整 rpm 解析路径。
pub fn build_srpm(fixture: SrpmFixture<'_>) -> PathBuf {
    let SrpmFixture {
        topdir,
        name,
        version,
        release,
        buildarch,
        build_requires,
        exclusive,
        exclude,
    } = fixture;
    for d in ["BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"] {
        std::fs::create_dir_all(topdir.join(d)).unwrap();
    }
    let buildarch_line = buildarch
        .map(|a| format!("BuildArch: {a}\n"))
        .unwrap_or_default();
    let excl_line = if exclusive.is_empty() {
        String::new()
    } else {
        format!("ExclusiveArch: {}\n", exclusive.join(" "))
    };
    let excld_line = if exclude.is_empty() {
        String::new()
    } else {
        format!("ExcludeArch: {}\n", exclude.join(" "))
    };
    let br_lines: String = build_requires
        .iter()
        .map(|b| format!("BuildRequires: {b}\n"))
        .collect();
    std::fs::write(
        topdir.join("SPECS").join(format!("{name}.spec")),
        format!(
            "Name: {name}\nVersion: {version}\nRelease: {release}\nSummary: test\nLicense: MIT\n\
             {buildarch_line}{excl_line}{excld_line}{br_lines}\
             %description\ntest\n%build\necho build\n%install\necho install\n\
             %files\n/usr/bin/{name}\n"
        ),
    )
    .unwrap();
    let status = Command::new("rpmbuild")
        .arg("-bs")
        .arg("--define")
        .arg(format!("_topdir {}", topdir.display()))
        .arg("--define")
        .arg("dist %{nil}")
        .arg(topdir.join("SPECS").join(format!("{name}.spec")))
        .status()
        .expect("spawn rpmbuild");
    assert!(status.success(), "rpmbuild -bs failed for {name}");
    std::fs::read_dir(topdir.join("SRPMS"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with(name))
                .unwrap_or(false)
        })
        .expect("no .src.rpm produced")
}
