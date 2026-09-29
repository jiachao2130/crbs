// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! `crbs-server worker add --output-config` 端到端：经 handle_worker 真实
//! StateStore upsert + worker.toml 落盘（render/write 闭环单测在 cli/worker.rs
//! tests；此处补 CLI 参数装配到写盘的整段缝合）。

// 测试辅助函数（seed_* 等）不带 #[test]，clippy.toml 的 allow-*-in-tests 豁免不到，按文件放行。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;

use crbs_server::cli::worker::{handle_worker, WorkerCli, WorkerCommand};
use crbs_server::test_support::lock_config_env;

/// 隔离配置目录：server.toml 的 crbs_root 指向临时根（load_state_store 经
/// CRBS_CONFIG_DIR 定位；guard 串行化进程级环境变量）。
async fn config_dir_with_server_toml(root: &std::path::Path) -> tempfile::TempDir {
    let cfg_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        cfg_dir.path().join("server.toml"),
        format!("crbs_root = \"{}\"\n", root.display()),
    )
    .unwrap();
    cfg_dir
}

#[tokio::test]
async fn worker_add_output_config_writes_deployable_toml_end_to_end() {
    let _env = lock_config_env();
    let root = tempfile::tempdir().unwrap();
    let cfg_dir = config_dir_with_server_toml(root.path()).await;
    let out_path = root.path().join("worker-nginx.toml");

    handle_worker(
        Some(cfg_dir.path().to_path_buf()),
        WorkerCli {
            command: WorkerCommand::Add {
                name: "wkr-e2e".into(),
                arch: "x86_64".into(),
                capacity: 2,
                output_config: Some(out_path.clone()),
                hub_url: Some("https://hub.example.com:18443".into()),
                hub_ca_cert: None,
                build_dir: None,
                crbs_root: None,
            },
        },
    )
    .await
    .expect("worker add with --output-config should succeed");

    let content = std::fs::read_to_string(&out_path).expect("worker.toml must be written");
    // 八字段齐 + 默认值回落（ca_cert/build_dir/crbs_root 未传走 DEFAULT_*）。
    for needle in [
        "name = \"wkr-e2e\"",
        "hub_url = \"https://hub.example.com:18443\"",
        "arch = \"x86_64\"",
        "capacity = 2",
        "token = \"crbs_wkr_",
        "/etc/crbs/certs/ca.crt",
        "/var/lib/crbs/worker/builds",
        "crbs_root = \"/var/lib/crbs\"",
    ] {
        assert!(
            content.contains(needle),
            "worker.toml missing {needle:?}:\n{content}"
        );
    }
    let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o640,
        "deployable config must be 0640, got {mode:o}"
    );

    // upsert 侧：同名重复注册被守卫拒绝且文案指路 rotate-secret——证明 CLI
    // 装配真实触达 StateStore 唯一性检查（secret 轮换语义在 admin API 测试钉）。
    let dup = handle_worker(
        Some(cfg_dir.path().to_path_buf()),
        WorkerCli {
            command: WorkerCommand::Add {
                name: "wkr-e2e".into(),
                arch: "x86_64".into(),
                capacity: 2,
                output_config: None,
                hub_url: None,
                hub_ca_cert: None,
                build_dir: None,
                crbs_root: None,
            },
        },
    )
    .await
    .expect_err("re-adding the same name must be refused");
    let msg = format!("{dup}");
    assert!(
        msg.contains("already exists") && msg.contains("rotate-secret"),
        "dup guard should point at rotate-secret: {msg}"
    );
}

#[tokio::test]
async fn worker_add_output_config_without_hub_url_is_rejected() {
    let _env = lock_config_env();
    let root = tempfile::tempdir().unwrap();
    let cfg_dir = config_dir_with_server_toml(root.path()).await;
    let out_path = root.path().join("worker-nohub.toml");

    let err = handle_worker(
        Some(cfg_dir.path().to_path_buf()),
        WorkerCli {
            command: WorkerCommand::Add {
                name: "wkr-nohub".into(),
                arch: "x86_64".into(),
                capacity: 1,
                output_config: Some(out_path.clone()),
                hub_url: None,
                hub_ca_cert: None,
                build_dir: None,
                crbs_root: None,
            },
        },
    )
    .await
    .expect_err("--output-config without --hub-url must fail");

    assert!(
        format!("{err}").contains("--hub-url"),
        "error should name the missing flag: {err}"
    );
    assert!(
        !out_path.exists(),
        "no file should be written on the rejected path"
    );
}
