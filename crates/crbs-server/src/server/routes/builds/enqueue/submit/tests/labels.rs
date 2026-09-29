// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! 提交入口标签解析：`KEY=VALUE` 语法、重复键与 400 映射。

use super::*;

/// 首个 `=` 切分，值可含 `=`；顺序保留。
#[test]
fn parse_submit_labels_splits_on_first_equals() {
    let labels = parse_submit_labels(&[
        "git-repo=https://example.com/x.git".to_string(),
        "ref=heads/main?x=1".to_string(),
    ])
    .expect("valid labels");
    assert_eq!(
        labels,
        vec![
            (
                "git-repo".to_string(),
                "https://example.com/x.git".to_string()
            ),
            ("ref".to_string(), "heads/main?x=1".to_string()),
        ]
    );
}

/// 语法错误与重复键按 400（ApiError::Validation）拒绝，不进入 fan-out。
#[test]
fn parse_submit_labels_rejects_malformed_and_duplicates() {
    for raw in [
        vec!["noequals".to_string()],
        vec!["k=1".to_string(), "k=2".to_string()],
    ] {
        let err = parse_submit_labels(&raw).expect_err("malformed labels must be rejected");
        assert!(
            matches!(err, ApiError::Validation(_)),
            "expected validation error, got: {err:?}"
        );
    }
}
