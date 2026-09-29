// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 可见性规则统一实现：产品/构建/任务的可见性判断集中此处，防重复+漏检。
//! 两层 bypass 有意分歧：产品内容级（配置/详情/历史，可能含 repo
//! token 机密）仅 admin bypass；builds/tasks 运维数据级 admin+operator 双 bypass。

use std::collections::HashSet;

use crate::server::error::ApiError;
use crate::server::state::AppState;

use super::AuthContext;

/// 可见性共用判定：bypass 谓词按级别参数化（产品内容级仅 admin；builds/tasks
/// 级 is_operator 已含 admin），其余链 owner → public → ACL 授权两级完全同序。
fn visible_impl(
    owner_id: Option<i64>,
    visibility: &str,
    product_name: &str,
    auth: Option<&AuthContext>,
    admin_only: bool,
) -> bool {
    if let Some(ctx) = auth {
        let bypass = if admin_only {
            ctx.is_admin()
        } else {
            ctx.is_operator()
        };
        if bypass {
            return true;
        }
    }

    if visibility == crbs_core::VISIBILITY_PUBLIC {
        return true;
    }

    let Some(ctx) = auth else {
        return false;
    };

    if matches!((ctx.user_id, owner_id), (Some(u), Some(o)) if u == o) {
        return true;
    }

    ctx.allowed_products.iter().any(|p| p == product_name)
}

/// 产品内容级可见性（仅 admin bypass）：产品详情/配置/历史等含机密场景。
/// 优先级：admin → owner → public → ACL 授权 → 拒绝（false）
pub(crate) fn is_product_content_visible_to(
    owner_id: Option<i64>,
    visibility: &str,
    product_name: &str,
    auth: Option<&AuthContext>,
) -> bool {
    visible_impl(owner_id, visibility, product_name, auth, true)
}

/// builds/tasks 级可见性（admin + operator 双 bypass）：构建/任务列表、日志等
/// 运维数据场景。优先级：admin/operator → owner → public → ACL 授权 → 拒绝（false）
pub(crate) fn is_build_task_visible_to(
    owner_id: Option<i64>,
    visibility: &str,
    product_name: &str,
    auth: Option<&AuthContext>,
) -> bool {
    visible_impl(owner_id, visibility, product_name, auth, false)
}

/// 单条 build/task 详情的产品可见性判定（与列表口径一致），不可见返回
/// `PermissionDenied`。产品已删除/不存在按"公开"处理（历史记录保留，匿名亦
/// 可见）——与 SQL 列表过滤的孤儿豁免（`product NOT IN (SELECT name FROM
/// products)`）同一语义。
pub(crate) async fn ensure_product_visible_for_record(
    app: &AppState,
    product_name: &str,
    auth: Option<&AuthContext>,
) -> Result<(), ApiError> {
    match app.state_store.get_product_by_name(product_name).await? {
        Some(product) => {
            if is_build_task_visible_to(product.owner_id, &product.visibility, &product.name, auth)
            {
                Ok(())
            } else {
                Err(ApiError::PermissionDenied(
                    "you do not have permission to view this record".into(),
                ))
            }
        }
        None => Ok(()),
    }
}

// 403/404 政策分叉（既定契约，两族有意不同，勿"统一"）：
// - build/task 单条详情（ensure_product_visible_for_record 及 get_task 等
//   同口径调用方）：不可见资源回 **403**。id 自增可枚举，接受存在性可探测
//   的代价，换取错误语义精确——产品级不可见统一 403。
// - product 链（check_chain_visibility 及产品详情/配置/历史）：不可见回
//   **404** 掩码——public child 不得泄漏 private 祖先的存在性，403 会把
//   "有但你不能看"说出去。

/// 任一祖先对用户不可见 → 整体返回 NotFound（核心安全机制：public child 不能
/// 泄漏 private ancestor 的存在性）。已知角落 case：深度上限 8 时第 8 层节点
/// 不检查——publish 守卫挡住了构造满深链的路径，不可达。
pub(crate) async fn check_chain_visibility(
    state: &AppState,
    leaf_id: i64,
    auth: Option<&AuthContext>,
) -> Result<(), ApiError> {
    let mut cursor = Some(leaf_id);
    let mut visited = HashSet::new();

    while let Some(id) = cursor {
        if !visited.insert(id) || visited.len() >= 8 {
            break;
        }
        let record = state
            .state_store
            .get_product_by_id(id)
            .await?
            .ok_or_else(|| ApiError::not_found("product", id))?;
        if !is_product_content_visible_to(record.owner_id, &record.visibility, &record.name, auth) {
            return Err(ApiError::not_found("product", id));
        }
        cursor = record.parent_id;
    }

    Ok(())
}

/// 产品 owner 或 admin 权限门槛（编辑/删除私人产品）；官方产品（owner_id=None）仅 admin。
pub(crate) fn is_owner_or_admin(owner_id: Option<i64>, auth: Option<&AuthContext>) -> bool {
    let Some(ctx) = auth else {
        return false;
    };
    if ctx.is_admin() {
        return true;
    }
    matches!((ctx.user_id, owner_id), (Some(u), Some(o)) if u == o)
}

/// 计算 NVR 分组 SQL 端可见性白名单：返回 `Some(visible_products)` 时 SQL 在
/// inner 子查询追加 `(product IN (...) OR product NOT IN (SELECT name FROM
/// products))`；返回 `None` = admin / operator bypass，SQL 不加任何可见性过滤。
/// **本 helper 不负责孤儿豁免**：孤儿产品（已被删除）不在 `list_products` 结果
/// 里，永远进不了 `visible_products` 集合，豁免由 SQL 层
/// `OR product NOT IN (SELECT name FROM products)` 子句单独处理。
/// 判定直接消费 `list_products` 的 stub 快照（单次查询）——stub 携带与按名
/// 查询同一行的 owner_id / visibility / name，判定输入等价。
pub(crate) async fn compute_visible_products(
    app: &AppState,
    auth: Option<&AuthContext>,
) -> Result<Option<Vec<String>>, ApiError> {
    if let Some(ctx) = auth {
        if ctx.is_admin() || ctx.is_operator() {
            return Ok(None);
        }
    }

    let stubs = app.state_store.list_products().await?;
    let mut visible = Vec::new();
    for stub in stubs {
        if is_build_task_visible_to(stub.owner_id, &stub.visibility, &stub.name, auth) {
            visible.push(stub.name);
        }
    }
    Ok(Some(visible))
}

/// 行级可见性过滤器：`visible=None` = admin/operator bypass；否则可见集合 +
/// 全部产品集合。孤儿产品（已删除，不在 products 表）按 builds/tasks 列表
/// 同口径放行——只在 `all` 中而不在 `visible` 中的产品才是私有隐藏项。
#[derive(Debug, Clone, Default)]
pub(crate) struct ProductVisibility {
    visible: Option<HashSet<String>>,
    all: HashSet<String>,
}

impl ProductVisibility {
    pub(crate) fn allows(&self, product: &str) -> bool {
        match &self.visible {
            None => true,
            Some(visible) => visible.contains(product) || !self.all.contains(product),
        }
    }
}

/// 与 [`compute_visible_products`] 同源判定，额外保留全部产品集合供孤儿豁免。
pub(crate) async fn compute_product_visibility(
    app: &AppState,
    auth: Option<&AuthContext>,
) -> Result<ProductVisibility, ApiError> {
    if let Some(ctx) = auth {
        if ctx.is_admin() || ctx.is_operator() {
            return Ok(ProductVisibility {
                visible: None,
                all: HashSet::new(),
            });
        }
    }

    let stubs = app.state_store.list_products().await?;
    let mut all = HashSet::new();
    let mut visible = HashSet::new();
    for stub in stubs {
        all.insert(stub.name.clone());
        if is_build_task_visible_to(stub.owner_id, &stub.visibility, &stub.name, auth) {
            visible.insert(stub.name);
        }
    }
    Ok(ProductVisibility {
        visible: Some(visible),
        all,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbs_core::{VISIBILITY_PRIVATE, VISIBILITY_PUBLIC};

    /// stub 判定组合逻辑单测：混合 stub 集合过 `is_build_task_visible_to` 验证过滤矩阵。
    #[test]
    fn compute_visible_products_stub_filter_mixed_matrix() {
        // 混合 stub 集合：public / owner 私有 / ACL 授权私有 / 他人私有 / 官方私有。
        let stubs = [
            ("pub-prod", VISIBILITY_PUBLIC, None),
            ("own-prod", VISIBILITY_PRIVATE, Some(7)),
            ("acl-prod", VISIBILITY_PRIVATE, Some(9)),
            ("foreign-prod", VISIBILITY_PRIVATE, Some(9)),
            ("official-prod", VISIBILITY_PRIVATE, None),
        ];
        let visible_via_stub = |auth: Option<&AuthContext>| -> Vec<&'static str> {
            stubs
                .iter()
                .filter_map(|&(name, visibility, owner_id)| {
                    is_build_task_visible_to(owner_id, visibility, name, auth).then_some(name)
                })
                .collect()
        };

        assert_eq!(visible_via_stub(None), vec!["pub-prod"]);

        let owner = AuthContext {
            user: "owner".into(),
            role: "builder".into(),
            user_id: Some(7),
            ..Default::default()
        };
        assert_eq!(visible_via_stub(Some(&owner)), vec!["pub-prod", "own-prod"]);

        let acl_user = AuthContext {
            user: "acl".into(),
            role: "viewer".into(),
            user_id: Some(8),
            allowed_products: vec!["acl-prod".into()],
            ..Default::default()
        };
        assert_eq!(
            visible_via_stub(Some(&acl_user)),
            vec!["pub-prod", "acl-prod"]
        );

        // operator：bypass 全量（compute_visible_products 对 operator 入口即返
        // None，此处验证底层判定同口径全放行）。
        let operator = AuthContext {
            user: "op".into(),
            role: "operator".into(),
            user_id: Some(10),
            ..Default::default()
        };
        assert_eq!(
            visible_via_stub(Some(&operator)),
            vec![
                "pub-prod",
                "own-prod",
                "acl-prod",
                "foreign-prod",
                "official-prod"
            ]
        );
    }
}
