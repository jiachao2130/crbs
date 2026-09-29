// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! worker 测试共用工具（cfg(test) 编译）：HTTP mock 解析 + 配置/任务 fixture。

use crate::config::WorkerConfig;
use crate::poller::AssignedTask;
use tokio::io::AsyncReadExt;

/// 把特权后端在测试进程内固定为 SetuidBackend。init 链加载 CrbsConfig 时会按宿主机
/// 状态初始化特权后端（进程级 OnceLock，只生效一次）；装了 setuid helper 的机器上
/// 不固定的话整个测试进程会变成 HelperBackend，之后走 rm_rf 的测试（如 tmp 域清扫）
/// 在 helper 的 allowed_paths 之外必失败，造成"单独跑通过、整个 target 跑必失败"的
/// 假阳性。须在任何 config 加载之前调用；已初始化时幂等直通。
pub(crate) fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(crate) async fn read_request(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = sock.read(&mut tmp).await.unwrap();
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let content_len = headers
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_len {
        let n = sock.read(&mut tmp).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    buf
}

pub(crate) async fn test_cfg(hub_url: String, build_dir: Option<&std::path::Path>) -> WorkerConfig {
    pin_setuid_privilege_backend();
    let mut content = format!("name = \"w\"\nhub_url = \"{hub_url}\"\ntoken = \"t\"\n");
    if let Some(dir) = build_dir {
        content.push_str(&format!("build_dir = \"{}\"\n", dir.display()));
    }
    let temp = tempfile::NamedTempFile::new().unwrap();
    tokio::fs::write(temp.path(), content).await.unwrap();
    WorkerConfig::load(temp.path()).await.unwrap()
}

pub(crate) fn test_task() -> AssignedTask {
    AssignedTask {
        assignment_id: 7,
        task_id: Some(5),
        build_id: 14,
        product: "ule3".to_string(),
        srpm_url: String::new(),
        build_options: serde_json::Value::Null,
        product_config: String::new(),
        reproduce_packages_url: None,
        kind: "build".to_string(),
        init_product: None,
        product_repo_enabled: true,
        redelivered: false,
    }
}
