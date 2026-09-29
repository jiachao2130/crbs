// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! RPM %changelog 解析：纯函数解析
//! `rpm -qp --changelog` 文本输出，供服务端端点（实时解析、零持久化）与 UI 展示。

/// 单条 changelog entry。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChangelogEntry {
    /// 头行日期段，如 `Mon Aug 25 2026`。
    pub date: String,
    /// 头行日期之后的全部内容（作者 + 版本），如 `Name <e@h> - 1.2.3-1`。
    pub author: String,
    /// 正文（后续行去掉 `- ` 前缀后按换行拼接）。
    pub text: String,
}

/// 解析 `rpm -qp --changelog` 输出。`* ` 头行（如 `* Mon Aug 25 2026 Name <e@h> - 1.2.3-1`）
/// 开新 entry：date = 头行前 4 个空白 token，author = 其余；后续行去行首 `- ` 前缀追加
/// text。畸形头行（token 不足 4 段）、entry 头之前的行跳过（宽容），空输入 → 空 vec。
pub fn parse_rpm_changelog(input: &str) -> Vec<ChangelogEntry> {
    let mut entries: Vec<ChangelogEntry> = Vec::new();
    for line in input.lines() {
        if let Some(header) = line.strip_prefix("* ") {
            // split_whitespace 对连续空白鲁棒（不产生空 token），date/author 内连续空白并为一。
            let tokens: Vec<&str> = header.split_whitespace().collect();
            if tokens.len() < 4 {
                continue;
            }
            entries.push(ChangelogEntry {
                date: tokens[..4].join(" "),
                author: tokens[4..].join(" "),
                text: String::new(),
            });
        } else if let Some(entry) = entries.last_mut() {
            // 空行保留为段落分隔（保持可读性）。
            let text_line = line.strip_prefix("- ").unwrap_or(line);
            // 残余 CR 剥离：`lines()` 已吃掉 `\r\n` 行终止符，但行尾裸 `\r`（EOF 截断
            // 或 `\r\r\n` 形态）会残留——剥掉，防带进 UI 展示。
            let text_line = text_line.strip_suffix('\r').unwrap_or(text_line);
            if !entry.text.is_empty() {
                entry.text.push('\n');
            }
            entry.text.push_str(text_line);
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rpm 官方包的真实输出形态：多 entry、多行正文、`- ` 前缀。
    #[test]
    fn parses_multi_entry_output() {
        let input = "\
* Mon Aug 25 2026 Alice <alice@example.com> - 2.0-1
- Add new feature
- Fix the bug from 1.0

* Sun Aug 10 2026 Alice <alice@example.com> - 1.0-1
- Initial package";
        let entries = parse_rpm_changelog(input);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].date, "Mon Aug 25 2026");
        assert_eq!(entries[0].author, "Alice <alice@example.com> - 2.0-1");
        assert_eq!(entries[0].text, "Add new feature\nFix the bug from 1.0\n");
        assert_eq!(entries[1].date, "Sun Aug 10 2026");
        assert_eq!(entries[1].author, "Alice <alice@example.com> - 1.0-1");
        assert_eq!(entries[1].text, "Initial package");
    }

    /// 头行日期四段 + 作者带 `- 版本`；正文首行直接追加（不造前导换行）。
    #[test]
    fn header_splits_date_and_author() {
        let entries =
            parse_rpm_changelog("* Tue Jan 02 2026 Bob <b@h> - 1.2.3-1\n- first change\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].date, "Tue Jan 02 2026");
        assert_eq!(entries[0].author, "Bob <b@h> - 1.2.3-1");
        assert_eq!(entries[0].text, "first change");
    }

    /// 空输入 / 纯空白 → 空 vec（端点据此走 available=false）。
    #[test]
    fn empty_input_yields_empty_vec() {
        assert!(parse_rpm_changelog("").is_empty());
        assert!(parse_rpm_changelog("\n\n").is_empty());
    }

    /// 畸形输入宽容：凑不齐日期四段的头行 / entry 头之前的孤立行跳过；连续空白不影响 tokenize。
    #[test]
    fn malformed_lines_are_skipped() {
        let input = "\
stray line before any header
* Mar 2026
* Wed Mar  05 2026 Carol <c@h> - 3-1
- real entry body";
        let entries = parse_rpm_changelog(input);
        assert_eq!(entries.len(), 1, "malformed header must be skipped");
        assert_eq!(entries[0].date, "Wed Mar 05 2026");
        assert_eq!(entries[0].author, "Carol <c@h> - 3-1");
        assert_eq!(entries[0].text, "real entry body");
    }

    /// CR 剥离回归：`\r\n` 行终止符由 `str::lines()` 吃掉，行尾裸 `\r`（EOF 截断
    /// / `\r\r\n` 双 CR）由解析器剥掉；text 任何形态下不得残留 `\r`。
    #[test]
    fn crlf_body_lines_have_carriage_return_stripped() {
        let input = "* Tue Jan 02 2026 Bob <b@h> - 1.2.3-1\r\n- first change\r\n- second\r\n";
        let entries = parse_rpm_changelog(input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "first change\nsecond");

        // 行尾裸 \r 后直接 EOF：lines() 保留该 \r，由 strip_suffix 剥掉。
        let input = "* Tue Jan 02 2026 Bob <b@h> - 1.2.3-1\n- trailing cr\r";
        let entries = parse_rpm_changelog(input);
        assert_eq!(entries[0].text, "trailing cr");
    }

    /// 仅头行无正文：entry 保留、text 为空串。
    #[test]
    fn header_only_entry_has_empty_text() {
        let entries = parse_rpm_changelog("* Fri Feb 14 2026 Dan <d@h> - 0.1-1\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].text, "");
    }

    /// serde 往返：API 响应 JSON 形态固定（snake_case 字段名）。
    #[test]
    fn serde_roundtrip_json_shape() {
        let entries = vec![ChangelogEntry {
            date: "Mon Aug 25 2026".to_string(),
            author: "Alice <alice@example.com> - 2.0-1".to_string(),
            text: "Add new feature".to_string(),
        }];
        let json = serde_json::to_string(&entries).unwrap();
        assert_eq!(
            json,
            r#"[{"date":"Mon Aug 25 2026","author":"Alice <alice@example.com> - 2.0-1","text":"Add new feature"}]"#
        );
        let back: Vec<ChangelogEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entries);
    }
}
