// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-worker completions <shell>` 生成护栏（与 crbs 包的 completions_packaging
//! 同一关注点：守护 spec %install 装出的补全）。与 crbs 的差异：spec 从二进制
//! 现场生成、无入库打包文件可逐字节钉死，退而钉最小 CLI 面——三 shell 输出
//! 非空、含二进制名与关键子命令。

use std::process::Command;

fn generate(shell: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_crbs-worker"))
        .args(["completions", shell])
        .output()
        .unwrap_or_else(|e| panic!("spawn crbs-worker completions {shell}: {e}"));
    assert!(
        out.status.success(),
        "crbs-worker completions {shell} must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap_or_else(|e| panic!("completions {shell} output: {e}"))
}

#[test]
fn completions_cover_all_packaged_shells() {
    // fish 旗标格式是 `-l config`（无 `--` 前缀），与 bash/zsh 的 `--config` 不同。
    for shell in ["bash", "zsh", "fish"] {
        let text = generate(shell);
        assert!(
            text.contains("crbs-worker"),
            "{shell} completions must mention the program name"
        );
        let flag_marker = if shell == "fish" {
            "-l config"
        } else {
            "--config"
        };
        assert!(
            text.contains(flag_marker),
            "{shell} completions must cover the --config flag"
        );
        assert!(
            text.contains("register"),
            "{shell} completions must cover the register subcommand"
        );
    }
}
