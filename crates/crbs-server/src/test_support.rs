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
//! 进程内由 `PG_TEST_LOCK` 守卫强制，并发进入即 panic。

// unwrap/expect 白名单：仅 tests/ 引用，但集成测试独立 crate 编译、无法
// #[cfg(test)] 门控、随 lib 无条件编译，clippy 测试豁免覆盖不到。
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use crbs_core::{StateStore, TaskInsert};

/// 测试进程内把特权后端确定性钉到非 Helper 模式（SetuidBackend）：`CrbsConfig::load()` 会按
/// 宿主机状态初始化特权后端（进程级 OnceLock 单次生效），装 setuid helper 的机器上
/// 先加载 config 的测试会把整个进程钉成 HelperBackend、被后续测试继承——
/// “隔离跑通过、整 target 跑必现失败”假阳性。须在任何 config 加载之前调用；首次钉死
/// Setuid，之后同型调用幂等（已初始化时 `Auto`/`Never` 直通）；返回 `Err`（已被更早 config 加载钉成 Helper）则静默忽略。
pub fn pin_setuid_privilege_backend() {
    let _ = crbs_core::privilege::init_privilege_backend(
        crbs_core::privilege::PrivilegedHelperMode::Never,
        None,
        &std::env::temp_dir(),
    );
}

/// 插入最小 task 行并返回 id（`builds.task_id` NOT NULL，造 build 前必须
/// 有任务可挂）；product / pkg_name 沿用被测 build 字段，避免污染按任务断言的测试。
pub async fn seed_task(
    store: &StateStore,
    product: impl AsRef<str>,
    pkg_name: impl AsRef<str>,
) -> i64 {
    store
        .insert_task(TaskInsert {
            product: product.as_ref(),
            pkg_name: pkg_name.as_ref(),
            // 非空用户：list_tasks 过滤含 `OR "user" = ''`（空 = 全员共享遗留语义），空用户任务会泄漏进所有用户的个人视图。
            user: "test",
            ..Default::default()
        })
        .await
        .unwrap()
}

/// 建最小产品行（config_json='{}'，无 chain-resolve 非空校验需求的用例适用）。
/// 仅 lib 单测可用：集成测试各自本地定义 seed 夹具；裸 lib check（dev-deps 的
/// expose-pool 未生效）下 `pool()` 私有，本函数必须不参与该构建形态。
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

/// 最小测试 AppState（纯 SQLite 临时库，不走 [`create_test_store`] 的 PG 分叉）。
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

/// 进程内 PG 测试库串行化锁：每个测试线程持有到线程结束（见 `PG_TEST_GUARD`）。
static PG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 批次驱动 tick 的测试桥：driver 入口 `batch_driver_tick` 是 `pub(crate)`，集成测试
/// 无法直接调用，经此暴露（seed-then-tick，与 driver 单测同口径）；[`TickReport`] 一并转正。
pub use crate::server::batches::TickReport;

/// 见 [`batch_driver_tick`] 桥说明；签名与 crate 内入口一致。
pub async fn batch_driver_tick(
    app: &Arc<crate::server::state::AppState>,
) -> crbs_core::Result<TickReport> {
    crate::server::batches::batch_driver_tick(app).await
}

/// 被测代码 set/remove 的进程级环境变量（prepare_server / product init·clean 走它）。
const CONFIG_ENV_KEY: &str = "CRBS_CONFIG_DIR";

/// prepare_server / product init·clean 系测试共享的 CRBS_CONFIG_DIR 守卫：product.rs
/// 裸 set_var/remove_var 与 prepare_server 系测试竞态覆盖同一进程级变量——持
/// CONFIG_ENV_LOCK 串行化 set/load 窗口、drop 时恢复原值；绑定名不得为 `_`（下划线绑定立即 drop，恢复失效）。
static CONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

pub fn lock_config_env() -> ConfigEnvGuard {
    let lock = CONFIG_ENV_LOCK.lock().unwrap();
    ConfigEnvGuard {
        _lock: lock,
        prev: std::env::var_os(CONFIG_ENV_KEY),
    }
}

thread_local! {
    /// 当前测试线程持有的 PG 锁守卫（`#[tokio::test]` 整个测试跑在同一线程，线程退出即释放）。
    static PG_TEST_GUARD: std::cell::RefCell<Option<std::sync::MutexGuard<'static, ()>>> =
        const { std::cell::RefCell::new(None) };
}

/// 让当前测试线程独占共享 PG 测试库（DROP SCHEMA 重置会砸掉并发测试的表）；
/// 同线程重复 `create_test_store` 幂等通过，其他线程仍持有则 panic（共享库必须 `--test-threads=1`）。
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

/// 初始化测试日志（失败忽略——多个测试二进制/线程竞争时只装一次）；`--nocapture`
/// 下可见 server 内部 `tracing::error!`，否则集成测试的 500 只剩状态码无根因。
pub fn init_test_logging() {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();
}

/// 构造测试 StateStore 与临时目录；PG 模式下 `TempDir` 仍用于 crbs_root 等文件路径（result_dir/srpm 上传/日志）。
pub async fn create_test_store() -> (Arc<StateStore>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create test tempdir");
    let store = match std::env::var("CRBS_TEST_DATABASE_URL") {
        // libpq 两种 scheme 等价；只匹配一种会让另一种静默 fallback SQLite，测试“全绿”但从未真正连过 PG。
        Ok(url) if url.starts_with("postgres:") || url.starts_with("postgresql:") => {
            // 串行化：本线程持有进程级锁直到测试结束（见 acquire_pg_test_lock）。
            acquire_pg_test_lock();
            // 共享测试库每个测试重置（与 core test_state 同策略），不重置则固定用户名/产品互撞唯一约束。
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

    /// PG 串行化锁行为：(a) 其他线程持锁期间 acquire → panic 且提示 `--test-threads=1`，
    /// 持锁线程退出后锁可再取；(b) 同线程重复 acquire 幂等（同测试多次 create_test_store
    /// 不误伤自己）；全部放一个测试内：两个 #[test] 并行跑会互相争这把锁。
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
