// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `packaging/completions/` 打包补全与 `crbs completions` 实际输出的逐字节护栏。
//! 测试失败多为真阳性：clap / clap_complete 升级或 CLI 表面变更都会改变补全输出，
//! 处置是重新生成并随变更一起提交，而非改测试：
//!
//! ```text
//! cargo run --quiet -p crbs --bin crbs -- completions bash > packaging/completions/crbs.bash
//! cargo run --quiet -p crbs --bin crbs -- completions zsh  > packaging/completions/_crbs
//! cargo run --quiet -p crbs --bin crbs -- completions fish > packaging/completions/crbs.fish
//! ```

use std::process::Command;

/// (shell, 打包文件) 对；路径相对仓库根；zsh 文件名按惯例固定为 `_crbs`。
const CASES: &[(&str, &str)] = &[
    ("bash", "crbs.bash"),
    ("zsh", "_crbs"),
    ("fish", "crbs.fish"),
];

fn packaged_path(file: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/completions")
        .join(file)
}

fn generate(shell: &str) -> Vec<u8> {
    let out = Command::new(env!("CARGO_BIN_EXE_crbs"))
        .args(["completions", shell])
        .output()
        .unwrap_or_else(|e| panic!("spawn crbs completions {shell}: {e}"));
    assert!(
        out.status.success(),
        "crbs completions {shell} must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.stdout.is_empty(),
        "crbs completions {shell} must emit non-empty output"
    );
    out.stdout
}

/// 失败诊断：只报字节数、首个分歧行号与前后各 3 行，不整文件倾倒（脚本数千行）。
fn report_divergence(shell: &str, file: &str, generated: &[u8], packaged: &[u8]) -> ! {
    eprintln!(
        "packaged completions out of sync for {shell} ({file}): generated {} bytes vs packaged {} bytes",
        generated.len(),
        packaged.len()
    );
    let gen_text = String::from_utf8_lossy(generated);
    let pkg_text = String::from_utf8_lossy(packaged);
    let gen_lines: Vec<&str> = gen_text.lines().collect();
    let pkg_lines: Vec<&str> = pkg_text.lines().collect();
    let mut first_diff = gen_lines.len().max(pkg_lines.len());
    for i in 0..gen_lines.len().min(pkg_lines.len()) {
        if gen_lines[i] != pkg_lines[i] {
            first_diff = i;
            break;
        }
    }
    let lo = first_diff.saturating_sub(3);
    let hi = (first_diff + 4).min(gen_lines.len().max(pkg_lines.len()));
    eprintln!("first divergent line: {} (0-based)", first_diff);
    for i in lo..hi {
        let g = gen_lines.get(i).copied().unwrap_or("<missing>");
        let p = pkg_lines.get(i).copied().unwrap_or("<missing>");
        let mark = if g == p { " " } else { "!" };
        eprintln!("{mark} gen[{i}]: {g}");
        if g != p {
            eprintln!("{mark} pkg[{i}]: {p}");
        }
    }
    eprintln!(
        "regenerate with: cargo run --quiet -p crbs --bin crbs -- completions {shell} > packaging/completions/{file}"
    );
    panic!("packaged completions for {shell} do not match generated output");
}

#[test]
fn packaged_completions_match_generated_output() {
    for (shell, file) in CASES {
        let generated = generate(shell);
        let packaged = std::fs::read(packaged_path(file))
            .unwrap_or_else(|e| panic!("read packaged completions {file}: {e}"));
        if generated != packaged {
            report_divergence(shell, file, &generated, &packaged);
        }
    }
}

/// powershell / elvish 不打包（无消费场景），但生成器仍须跑通且非空——clap_complete 升级破坏生成器时在此暴露。
#[test]
fn unpackaged_shells_still_generate_non_empty_output() {
    for shell in ["powershell", "elvish"] {
        let out = generate(shell);
        assert!(
            String::from_utf8_lossy(&out).contains("crbs"),
            "{shell} completions should mention the program name"
        );
    }
}
