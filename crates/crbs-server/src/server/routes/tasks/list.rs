// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 任务列表路由：可见性过滤、分页与状态筛选。

use super::*;

/// 按主 NVR 分组列出任务。可见性过滤下沉 SQL：`visible_products` 白名单 +
/// 孤儿豁免（product 不在 products 表 = 已删产品历史任务放行），per-attempt
/// 粒度（`filter_build_visible` 只能 per-group）。`total` = 当前页可见组数
/// （后过滤 quirk）。产品为唯一读边界：可见产品下全部提交者的记录同权可见。
pub(crate) async fn list_nvr_groups_for_user<'a>(
    app: &Arc<AppState>,
    mut filter: crbs_core::NvrGroupFilter<'a>,
    auth: Option<&'a AuthContext>,
) -> Result<NvrGroupListResponse, ApiError> {
    filter.visible_products = compute_visible_products(app, auth).await?;

    let (_total, groups) = app.state_store.list_nvr_groups(&filter).await?;

    // 无可见 attempts 的 group 整组不出现（inner 子查询按 attempt 过滤）。

    Ok(NvrGroupListResponse {
        total: groups.len(),
        groups,
    })
}

/// 按基础包名（name，去版本）分组列出任务（WebUI packages 列表页数据源）。
/// 可见性口径镜像 `list_nvr_groups_for_user`（auth 收口 + 白名单/孤儿豁免）；
/// 差别：分组粒度 name vs pkg_name、name 过滤为子串（后者为前缀）；`total`
/// 取 store 返回的过滤后全量组数——翻页需全量口径，非当前页 quirk。
pub(crate) async fn list_name_groups_for_user<'a>(
    app: &Arc<AppState>,
    mut filter: crbs_core::NvrGroupFilter<'a>,
    auth: Option<&'a AuthContext>,
) -> Result<NvrGroupListResponse, ApiError> {
    filter.visible_products = compute_visible_products(app, auth).await?;

    let (total, groups) = app.state_store.list_name_groups(&filter).await?;

    Ok(NvrGroupListResponse { total, groups })
}

/// 列出任务。可见性为产品级单层：`visible_products` 白名单 + 孤儿豁免下沉
/// SQL，分页前过滤，`total` 为过滤后总数、has_next 不失效。可见产品内全部
/// 提交者的记录同权可见；匿名用户仅见 public 产品任务（含已删产品历史任务）。
pub(crate) async fn list_tasks_for_user<'a>(
    app: &Arc<AppState>,
    mut filter: crbs_core::types::TaskListFilter<'a>,
    auth: Option<&'a AuthContext>,
) -> Result<TaskListResponse, ApiError> {
    filter.visible_products = compute_visible_products(app, auth).await?;

    let (total, tasks) = app.state_store.list_tasks(&filter).await?;

    Ok(TaskListResponse {
        total,
        tasks: tasks.into_iter().map(super::sanitize_task_record).collect(),
    })
}

/// 列出任务及其子构建各 phase 数量；可见性过滤同 `list_tasks_for_user`
/// （SQL 白名单 + 孤儿豁免），`total` 为过滤后总数。
pub(crate) async fn list_tasks_with_counts_for_user<'a>(
    app: &Arc<AppState>,
    filter: crbs_core::types::TaskListFilter<'a>,
    auth: Option<&'a AuthContext>,
) -> Result<TaskListWithCountsResponse, ApiError> {
    let visible_products = compute_visible_products(app, auth).await?;
    list_tasks_with_counts_for_user_with_visible(app, filter, visible_products).await
}

/// [`list_tasks_with_counts_for_user`] 的预计算变体：调用方已为 phase chips
/// 算过 `compute_visible_products` 时直传，列表页每渲染省一次全量 `list_products`。
pub(crate) async fn list_tasks_with_counts_for_user_with_visible<'a>(
    app: &Arc<AppState>,
    mut filter: crbs_core::types::TaskListFilter<'a>,
    visible_products: Option<Vec<String>>,
) -> Result<TaskListWithCountsResponse, ApiError> {
    filter.visible_products = visible_products;

    let (total, tasks_with_counts) = app.state_store.list_tasks_with_counts(&filter).await?;

    Ok(TaskListWithCountsResponse {
        total,
        tasks: tasks_with_counts
            .into_iter()
            .map(|(task, build_counts)| TaskWithCounts {
                task: super::sanitize_task_record(task),
                build_counts,
            })
            .collect(),
    })
}

pub(crate) async fn list_tasks(
    State(app): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
    auth: Option<Extension<AuthContext>>,
) -> Result<Json<TaskListResponse>, ApiError> {
    // 分页参数上限校验（limit ≤ 200 / offset ≤ 1_000_000，超限 400）。
    // 省略 limit 默认 200（与显式上限一致），杜绝无 LIMIT 全表读取。
    let limit = q.limit.or(Some(crate::server::validation::MAX_LIST_LIMIT));
    crate::server::validation::validate_list_pagination(limit, q.offset)?;
    // 标签过滤语法在入口收口：缺 `=` / 键非法等按 400 返回。
    let label = match q.label.as_deref() {
        Some(raw) => Some(
            crbs_core::validation::parse_task_label_arg(raw)
                .map_err(|e| ApiError::Validation(e.to_string()))?,
        ),
        None => None,
    };
    let filter = crbs_core::types::TaskListFilter {
        product: q.product.as_deref(),
        phase: q.phase.as_deref(),
        name: q.name.as_deref(),
        label,
        limit,
        offset: q.offset,
        order_by: q.sort.as_deref(),
        ..Default::default()
    };
    let resp = list_tasks_for_user(&app, filter, auth.as_ref().map(|ext| &ext.0)).await?;
    Ok(Json(resp))
}
