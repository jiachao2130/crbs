// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 共享层创建锁：跨进程互斥与等待。

use std::fs::OpenOptions;
use std::path::Path;

use fs4::fs_std::FileExt;
use tracing::info;

use crate::error::CrbsError;

/// 获取 SharedLayer 创建锁；`Ok(file)` 的独占锁绑定 open file description（fs4 FileExt），
/// 调用者必须保留 File 直到 `.complete` 写完（drop 即释放锁），并自行判断 `.complete` 是否存在/过期；`Err(_)` = 超时或 I/O 错误。
pub(crate) async fn acquire_layer_lock(
    poll_interval: std::time::Duration,
    timeout: std::time::Duration,
    lock_path: &Path,
    digest: &str,
) -> crate::Result<std::fs::File> {
    let lock_path = lock_path.to_path_buf();
    let digest = digest.to_string();

    tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + timeout;
        let mut logged = false;

        loop {
            let lock_file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)
                .map_err(|e| CrbsError::from_io_context("open layer lock", e))?;

            if lock_file.try_lock_exclusive().is_ok() {
                crate::gc::fix_created_lock_perms(&lock_path);
                return Ok(lock_file);
            }
            drop(lock_file);

            if std::time::Instant::now() >= deadline {
                return Err(CrbsError::Io {
                    context: "wait for SharedLayer creation lock".into(),
                    kind: std::io::ErrorKind::TimedOut,
                    detail: format!("timeout waiting for SharedLayer {} to be created", digest),
                });
            }

            if !logged {
                info!(digest = %digest, "SharedLayer being created by another process, waiting");
                logged = true;
            }

            std::thread::sleep(poll_interval);
        }
    })
    .await
    .map_err(|e| CrbsError::io_message(format!("acquire layer lock task panicked: {}", e)))?
}
