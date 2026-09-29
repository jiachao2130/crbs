// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 复现率统计 API：`GET /api/v1/reproducibility/stats` 单一
//! 聚合出口（查询本体在 crbs-core `state/reproducibility_stats`）。只出原子
//! 计数，rate 由看板按分母口径（same + diff + build_failed）自行计算。公开
//! 路由 + 可见性过滤（口径同 `/api/v1/status`）：匿名/普通用户只见可见产品，
//! operator/admin 全量。警示：DB retention 级联删除超期 builds 的
//! `build_reproducibility` 行，`days` 越过保留期后长窗口指标是"现存行"而非
//! "曾发生事件"口径（见 crbs-core `state/retention.rs`）。

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use crate::server::auth::visibility::compute_visible_products;
use crate::server::auth::AuthContext;
use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::REPLAY_GROUP_LIMIT;
use super::REPRO_DEFAULT_WINDOW_DAYS as DEFAULT_DAYS;

pub(crate) fn public_router() -> Router<Arc<AppState>> {
    Router::new().route("/api/v1/reproducibility/stats", get(reproducibility_stats))
}

/// `?days=` 查询参数：缺省 30；`all` / `0` = 全部时间；其余须为 `0..=3650` 整数
/// （上限即 state 层 `MAX_STATS_DAYS`，越界由 state 层统一报 ValidationFailed）。
fn parse_days(params: &StatsQuery) -> Result<Option<i64>, ApiError> {
    let Some(raw) = params.days.as_deref() else {
        return Ok(Some(DEFAULT_DAYS));
    };
    if raw.eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    let n = raw.parse::<i64>().map_err(|_| {
        ApiError::Validation(format!("days must be an integer or 'all', got {raw:?}"))
    })?;
    // 0 = 全部时间，归一为 None（同 state 层 repro_stats_cutoff；对外 days 只暴露"窗口天数 | null"两态）。
    if n == 0 {
        return Ok(None);
    }
    Ok(Some(n))
}

#[derive(Deserialize, Default)]
pub(crate) struct StatsQuery {
    pub days: Option<String>,
}

/// 聚合响应。`days = null` 表示全部时间窗口；`verdicts` 恒含五类 verdict 键
/// （缺数据为 0，消费方无需判键）；`series` 为日桶（只含有数据的桶，不零填充）；
/// 聚合口径只计 `kind='replay'`（cross_arch_noarch 观测行不入板）。
#[derive(Debug, serde::Serialize)]
pub(crate) struct ReproducibilityStatsResponse {
    pub days: Option<i64>,
    /// 全部比对行数（五类 verdict 合计）。
    pub total: i64,
    pub verdicts: BTreeMap<String, i64>,
    /// kind 维度（看板口径下恒 `replay`；结构保留供消费方兼容）。
    pub by_kind: Vec<crbs_core::KindVerdictCount>,
    /// 按产品（source build 的 product）。
    pub by_product: Vec<crbs_core::ProductVerdictCount>,
    pub series: Vec<crbs_core::ReproSeriesBucket>,
    /// 复现记录（按重放任务分组，最近比对在前，至多 [`REPLAY_GROUP_LIMIT`] 组；
    /// 全一致组不带构建级明细）。
    pub replays: Vec<crbs_core::ReproReplayGroup>,
}

pub(crate) async fn reproducibility_stats(
    State(app): State<Arc<AppState>>,
    auth: Option<Extension<AuthContext>>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<ReproducibilityStatsResponse>, ApiError> {
    let days = parse_days(&params)?;
    // 与 UI 页同一收紧：复现率统计不进公开访问面（认证开启时匿名 401）。
    let auth_ctx = if app.server_config.auth_enabled {
        Some(
            auth.as_ref()
                .map(|ext| &ext.0)
                .ok_or_else(|| ApiError::Unauthorized("authentication required".into()))?,
        )
    } else {
        auth.as_ref().map(|ext| &ext.0)
    };
    let visible = compute_visible_products(&app, auth_ctx).await?;
    let visible = visible.as_deref();

    let by_kind = app
        .state_store
        .reproducibility_verdict_counts(visible, days)
        .await
        .map_err(ApiError::from)?;
    let mut verdicts = crbs_core::fold_verdict_totals(&by_kind);
    for v in crbs_core::ALL_VERDICTS {
        verdicts.entry(v.as_str().to_string()).or_insert(0);
    }
    let total: i64 = verdicts.values().sum();

    let by_product = app
        .state_store
        .reproducibility_counts_by_product(visible, days)
        .await
        .map_err(ApiError::from)?;
    let series = app
        .state_store
        .reproducibility_series(visible, days)
        .await
        .map_err(ApiError::from)?;
    let replays = app
        .state_store
        .reproducibility_replay_groups(visible, days, REPLAY_GROUP_LIMIT)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(ReproducibilityStatsResponse {
        days,
        total,
        verdicts,
        by_kind,
        by_product,
        series,
        replays,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::AppState;
    use axum::extract::State;
    use std::sync::Arc;

    async fn test_app() -> (Arc<AppState>, tempfile::TempDir) {
        // 经 create_test_store 双方言工厂建库：stats 链在 CI PG 腿真跑（占位符已是编号绑定，无 SQLite 专用面）。
        let (store, tmp) = crate::test_support::create_test_store().await;
        let app = Arc::new(AppState::for_test(
            store,
            crbs_core::config::ServerConfig {
                auth_enabled: false,
                ..crbs_core::config::ServerConfig::default()
            },
            tmp.path().to_path_buf(),
        ));
        (app, tmp)
    }

    /// seed：task + 双 build + 一条 verdict 行。build id 取当前 MAX+1 起连续两号：
    /// 多次调用不串号；可见性按 JOIN 的 source build product 判定，id 写死会挂错产品。
    async fn seed_repro_row(app: &AppState, product: &str, verdict: &str) {
        let task_id = crate::test_support::seed_task(&app.state_store, product, "pkg").await;
        let base: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM builds")
            .fetch_one(app.state_store.pool())
            .await
            .unwrap();
        for i in [base + 1, base + 2] {
            sqlx::query(
                "INSERT INTO builds (id, product, pkg_name, phase, backend, \"user\", task_id) \
                 VALUES ($1, $2, $3, 'succeeded', 'chroot', 'tester', $4)",
            )
            .bind(i)
            .bind(product)
            .bind(format!("pkg-1.0-{i}"))
            .bind(task_id)
            .execute(app.state_store.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO build_reproducibility (kind, source_build_id, replay_build_id, verdict) \
             VALUES ('replay', $1, $2, $3)",
        )
        .bind(base + 1)
        .bind(base + 2)
        .bind(verdict)
        .execute(app.state_store.pool())
        .await
        .unwrap();
    }

    async fn call(
        app: Arc<AppState>,
        days: Option<&str>,
    ) -> Result<Json<ReproducibilityStatsResponse>, ApiError> {
        call_as(app, days, None).await
    }

    async fn call_as(
        app: Arc<AppState>,
        days: Option<&str>,
        auth: Option<AuthContext>,
    ) -> Result<Json<ReproducibilityStatsResponse>, ApiError> {
        let ext = auth.map(Extension);
        reproducibility_stats(
            State(app),
            ext,
            Query(StatsQuery {
                days: days.map(str::to_string),
            }),
        )
        .await
    }

    #[tokio::test]
    async fn stats_returns_aggregates_with_default_window() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "test", "same").await;
        seed_repro_row(&app, "test", "diff").await;

        let resp = call(app, None).await.unwrap().0;
        assert_eq!(resp.days, Some(30));
        assert_eq!(resp.total, 2);
        assert_eq!(resp.verdicts.get("same"), Some(&1));
        assert_eq!(resp.verdicts.get("diff"), Some(&1));
        assert_eq!(resp.verdicts.get("build_failed"), Some(&0), "五类键恒在");
        assert_eq!(resp.by_kind.len(), 2);
        assert!(
            resp.by_kind.iter().all(|k| k.kind == "replay"),
            "board scope is kind='replay'"
        );
        assert_eq!(resp.by_product.len(), 2);
        assert_eq!(resp.series.len(), 1, "同日两行聚一桶");
        // 复现记录：两次 seed = 两个重放任务组；最近 seed（diff）在前。
        assert_eq!(resp.replays.len(), 2);
        assert_eq!(resp.replays[0].verdicts.get("diff"), Some(&1));
        assert_eq!(resp.replays[0].pairs.len(), 1);
        assert_eq!(
            resp.replays[0].pairs[0].source_build_id, 3,
            "diff 组来自第二次 seed（build 3→4）"
        );
        // 全一致组（第一次 seed）不带构建级明细（fixture 行本身无 detail，剥离
        // 契约的判别力在 crbs-core fold_replay_groups 测试）。
        assert_eq!(resp.replays[1].verdicts.get("same"), Some(&1));
        assert!(resp.replays[1].pairs[0].detail_json.is_none());
    }

    #[tokio::test]
    async fn stats_days_param_windows_and_all() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "test", "same").await;

        for param in ["0", "all"] {
            let resp = call(app.clone(), Some(param)).await.unwrap().0;
            assert_eq!(resp.days, None, "days={param}");
            assert_eq!(resp.total, 1);
        }
        // 上限窗口同样覆盖唯一一行（不因上限报错）。
        let resp = call(app.clone(), Some("3650")).await.unwrap().0;
        assert_eq!(resp.total, 1);

        let err = call(app.clone(), Some("yesterday")).await.unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)), "{err:?}");
        let err = call(app, Some("3651")).await.unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)), "{err:?}");
    }

    /// 匿名可见性过滤：私有产品的比对行不出现在公开响应里。
    #[tokio::test]
    async fn stats_filters_private_products_for_anonymous() {
        let (app, _tmp) = test_app().await;
        seed_repro_row(&app, "publicp", "same").await;
        seed_repro_row(&app, "secretp", "diff").await;
        // owner + 私有产品（products CHECK 要求 owner 非空）。
        sqlx::query("INSERT INTO users (id, name, role) VALUES (1, 'alice', 'builder')")
            .execute(app.state_store.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO products (name, visibility, config_json, owner_id) \
             VALUES ('secretp', 'private', '{}', 1)",
        )
        .execute(app.state_store.pool())
        .await
        .unwrap();

        let resp = call(app, None).await.unwrap().0;
        assert_eq!(resp.total, 1, "私有产品的 diff 行被过滤");
        assert_eq!(resp.verdicts.get("same"), Some(&1));
        assert!(
            resp.replays.iter().all(|g| g.product != "secretp"),
            "private product must not leak into replay groups"
        );
    }
}
