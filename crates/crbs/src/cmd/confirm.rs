// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 交互式确认 helper：破坏性 / 批量操作前的 y/N 确认。
//! 语义：stdin 非 TTY 且未 `--yes` → 拒绝（防脚本误触发破坏性操作）；交互 TTY 仅 `y`/`yes`（大小写不敏感）通过。

use anyhow::Result;
use crbs_core::error::CrbsError;
use std::io::{BufRead, IsTerminal, Write};

/// 交互式确认；`auto_yes=true` 直接放行，返回 `Err` = 未确认。
/// 退出码契约：非 TTY 拒绝=参数/环境误用 → `ValidationFailed`（USAGE=4）；
/// 用户拒绝=主动取消 → `Cancelled`（INTERRUPTED=3，取消不重试）。
pub(crate) fn confirm_or_bail(prompt: &str, auto_yes: bool) -> Result<()> {
    if auto_yes {
        return Ok(());
    }
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(CrbsError::ValidationFailed {
            message: "stdin is not a TTY and --yes was not provided; refusing to proceed with a destructive batch operation".into(),
        }
        .into());
    }
    // 提示走 stderr，保 --format json 的 stdout 纯净。
    eprint!("{} [y/N] ", prompt);
    // 终端写/读 io 失败 → `Io`（kind 保真，ENVIRONMENT=6）；context 保留操作串、detail 内联底层错误文本。
    std::io::stderr().flush().map_err(|e| CrbsError::Io {
        context: "flush stderr".to_string(),
        kind: e.kind(),
        detail: e.to_string(),
    })?;
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| CrbsError::Io {
            context: "read confirmation from stdin".to_string(),
            kind: e.kind(),
            detail: e.to_string(),
        })?;
    let answer = line.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        Ok(())
    } else {
        Err(CrbsError::Cancelled.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_yes_bypasses_prompt() {
        // auto_yes 短路先于非 TTY 检查：非交互环境下也必须直接放行。
        confirm_or_bail("proceed?", true).unwrap();
    }

    #[test]
    fn non_tty_without_auto_yes_bails() {
        // cargo test 下 stdin 通常非 TTY：无 --yes 应拒绝并按契约映射 ValidationFailed（USAGE=4）。
        let err = confirm_or_bail("proceed?", false).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("stdin is not a TTY") || msg.contains("aborted"),
            "unexpected error message: {}",
            msg
        );
        let ce = err
            .downcast_ref::<CrbsError>()
            .expect("must surface as CrbsError");
        assert!(
            matches!(ce, CrbsError::ValidationFailed { .. }),
            "unexpected variant: {ce}"
        );
        assert_eq!(
            crbs_core::exit_code::crbs_error_exit_code(ce),
            crbs_core::exit_code::USAGE
        );
    }
}
