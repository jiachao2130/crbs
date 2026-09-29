// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 集成测试支撑。读 `CRBS_TEST_DATABASE_URL`：`postgres:` 前缀连 PG，否则 SQLite
//! 临时库。PG 共享库跨 run 残留数据，必须 `--test-threads=1` + 一次性测试库；
//! 进程内由 `PG_TEST_LOCK` 检查强制，并发进入即 panic。

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crbs_core::{StateStore, TaskInsert};

/// 测试进程内把特权后端固定为非 Helper 模式（SetuidBackend）：`CrbsConfig::load()`
/// 会按宿主机状态初始化特权后端（进程级仅首次生效），装有 setuid helper 的
/// 机器上先加载 config 的测试会把整个进程定型为 HelperBackend 并被后续测试
/// 继承，产生"单测通过、整批运行失败"的假阳性。须在任何 config 加载之前
/// 调用；初始化失败（已被更早的 config 加载定型为 Helper）静默忽略。
pub fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

/// 插入最小 task 行并返回 id：`builds.task_id` 非空约束要求造 build 前先有
/// 任务可挂；product 与 pkg_name 由调用方传入，供被测 build 沿用，避免干扰
/// 按任务聚合的断言。
pub async fn seed_task(
    store: &StateStore,
    product: impl AsRef<str>,
    pkg_name: impl AsRef<str>,
) -> i64 {
    store
        .insert_task(TaskInsert {
            product: product.as_ref(),
            pkg_name: pkg_name.as_ref(),

            user: "test",
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 建最小产品行（config_json 为空对象，适用于无需 chain-resolve 校验的用
/// 例）。仅 lib 内部单测可用：集成测试各自定义种子函数；未启用 dev-deps
/// `expose-pool` 的裸 lib check 下 `pool()` 不可见，本函数不得参与该构建
/// 形态。
#[cfg(test)]
pub async fn seed_product(store: &StateStore, id: i64, name: &str) {
    sqlx::query(
        "INSERT INTO products (id, name, visibility, config_json, revision, \
         base_os_revision) VALUES ($1, $2, 'public', '{}', 1, 1)",
    )
    .bind(id)
    .bind(name)
    .execute(store.pool())
    .await
    .unwrap();
}

/// 构造最小测试 AppState：纯 SQLite 临时库，不经 [`create_test_store`] 的
/// PG 分叉。
pub async fn setup_app() -> (Arc<crate::server::state::AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(crate::server::state::AppState::for_test(
        store,
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    (app, tmp)
}

static PG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 供集成测试使用的 tick 结果类型，随测试桥一并重导出。
pub use crate::server::batches::TickReport;

/// 批次驱动 tick 的测试桥：crate 内入口为 `pub(crate)`，集成测试无法直接
/// 调用，经此转发（seed-then-tick 语义与 driver 单测一致）；签名与 crate
/// 内入口相同。
pub async fn batch_driver_tick(
    app: &Arc<crate::server::state::AppState>,
) -> crbs_core::Result<TickReport> {
    crate::server::batches::batch_driver_tick(app).await
}

/// 被测代码设置与清除的进程级环境变量（prepare_server 与 product init、
/// clean 路径使用）。
const CONFIG_ENV_KEY: &str = "CRBS_CONFIG_DIR";

static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// [`lock_config_env`] 返回的守卫：持锁期间阻塞其他测试改写环境变量，
/// drop 时把 `CRBS_CONFIG_DIR` 恢复为进入前的值。
pub struct ConfigEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

impl Drop for ConfigEnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var(CONFIG_ENV_KEY, v),
            None => std::env::remove_var(CONFIG_ENV_KEY),
        }
    }
}

/// 取进程级 `CRBS_CONFIG_DIR` 守卫：prepare_server 系与 product init/clean
/// 系测试对同一进程级变量存在竞态覆盖，本守卫串行化设置与加载窗口，drop
/// 时恢复原值；返回值须绑定命名变量持有，不得绑定为 `_`（下划线绑定立即
/// drop，恢复失效）。
pub fn lock_config_env() -> ConfigEnvGuard {
    let lock = CONFIG_ENV_LOCK.lock().unwrap();
    ConfigEnvGuard {
        _lock: lock,
        prev: std::env::var_os(CONFIG_ENV_KEY),
    }
}

thread_local! {

    static PG_TEST_GUARD: std::cell::RefCell<Option<std::sync::MutexGuard<'static, ()>>> =
        const { std::cell::RefCell::new(None) };
}

fn acquire_pg_test_lock() {
    if PG_TEST_GUARD.with(|g| g.borrow().is_some()) {
        return;
    }
    match PG_TEST_LOCK.try_lock() {
        Ok(guard) => PG_TEST_GUARD.with(|g| *g.borrow_mut() = Some(guard)),
        Err(_) => panic!(
            "another test in this process is still using the shared PG test database; \
             rerun with --test-threads=1"
        ),
    }
}

/// 初始化测试日志，失败忽略（多个测试二进制或线程并发时仅首个安装生效）；
/// `--nocapture` 下可见 server 内部 `tracing::error!` 输出，否则集成测试的
/// 500 响应只剩状态码、无从定位根因。
pub fn init_test_logging() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

/// 构造测试 StateStore 与临时目录：按 `CRBS_TEST_DATABASE_URL` 选择 PG 或
/// SQLite；PG 模式下临时目录仍用于 crbs_root 等文件路径（result_dir、
/// SRPM 上传与日志落盘）。
pub async fn create_test_store() -> (Arc<StateStore>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create test tempdir");
    let store = match std::env::var("CRBS_TEST_DATABASE_URL") {
        Ok(url) if url.starts_with("postgres:") || url.starts_with("postgresql:") => {
            acquire_pg_test_lock();

            {
                crbs_core::StateStore::install_any_drivers();
                let reset = sqlx::any::AnyPoolOptions::new()
                    .max_connections(1)
                    .connect(&url)
                    .await
                    .expect("connect PG for reset");
                sqlx::query("DROP SCHEMA public CASCADE")
                    .execute(&reset)
                    .await
                    .expect("reset PG schema");
                sqlx::query("CREATE SCHEMA public")
                    .execute(&reset)
                    .await
                    .expect("recreate PG schema");
                reset.close().await;
            }
            StateStore::new_with_url(&url, tmp.path())
                .await
                .expect("create PG test state store")
        }
        _ => StateStore::new(tmp.path())
            .await
            .expect("create SQLite test state store"),
    };
    (Arc::new(store), tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_test_lock_serializes_and_hints() {
        use std::sync::mpsc;
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            acquire_pg_test_lock();
            held_tx.send(()).expect("notify holder acquired");
            release_rx.recv().expect("wait release");
        });
        held_rx.recv().expect("holder should acquire");

        let contender = std::thread::spawn(|| {
            std::panic::catch_unwind(acquire_pg_test_lock).expect_err("must panic when contended")
        });
        let payload_box = contender.join().expect("contender thread ends cleanly");
        let payload: String = match payload_box.downcast::<String>() {
            Ok(s) => *s,
            Err(boxed) => match boxed.downcast::<&str>() {
                Ok(s) => (*s).to_string(),
                Err(_) => String::new(),
            },
        };
        assert!(
            payload.contains("--test-threads=1"),
            "panic hint should mention --test-threads=1, got: {payload:?}"
        );

        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread ends cleanly");

        acquire_pg_test_lock();
        acquire_pg_test_lock();
    }
}
