// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! worker 测试共用工具（cfg(test) 编译）：HTTP mock 解析 + 配置/任务 fixture，
//! main / heartbeat / poller / executor 测试消费。

use crate::config::WorkerConfig;
use crate::poller::AssignedTask;
use tokio::io::AsyncReadExt;

/// 测试进程内把特权后端确定性钉到 SetuidBackend（同 crbs-server test_support
/// 口径）：init 链内 CrbsConfig::load 会按宿主机状态初始化特权后端（进程级
/// OnceLock 单次生效），装 setuid helper 的机器上会把整个测试进程钉成
/// HelperBackend——后续走 rm_rf 的测试（如 tmp 域清扫）在 helper 的
/// allowed_paths 之外必失败，"隔离跑通过、整 target 跑必现失败"假阳性。
/// 须在任何 config 加载之前调用；已初始化时幂等直通。
pub(crate) fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

/// 字节子串查找（mock 请求头/正文定位用；needle 为空会 panic，调用方传非空定界）。
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 读完一个 HTTP 请求（headers + Content-Length body），返回完整字节（body 断言用）。
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

/// 最小 WorkerConfig fixture：临时 toml（name/hub_url/token）落盘加载；
/// `build_dir` Some 时覆盖（不触 /var/lib/crbs）。先钉特权后端：消费本
/// fixture 的 init 链测试会触发引擎 config 加载。
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

/// 最小 AssignedTask fixture：build 任务（ule3，assignment 7 / task 5 / build 14）。
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
