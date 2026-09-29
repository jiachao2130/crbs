// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 发布型产品 repo 的 HTTP 服务端点。
//!
//! `GET /repo/{product}/{arch}/{*path}` 直接服务磁盘上
//! `{result_root}/_repo/{product}/{arch}/{path}` 下的 repodata / RPM 文件，供
//! worker/dnf 匿名读取（无 token）。
//! **可见性门**：仅 `visibility == public` 对外服务，私有 / 不存在
//! / 已删一律 404（不泄露存在性），私有产品依赖注入不经此公开通道；判定带
//! 进程内短缓存（[`RepoVisibilityCache`]），因 dnf 一次元数据同步逐文件拉取几十上百个文件。
//! **路径安全**：product/arch 须为安全组件；trailing path 逐组件拒绝
//! `.`/`..`/分隔符/NUL，杜绝穿越出 `_repo/{product}/{arch}` 命名空间。

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::server::error::ApiError;
use crate::server::state::AppState;

/// `_repo` 命名空间目录名（与 `engine::repo_publish` / `repo_regen` 一致）。
use crate::server::REPO_ROOT_DIR;

/// 可见性缓存容量上限：超过即按插入序逐出最老条目。
const VIS_CACHE_CAPACITY: usize = 1024;

/// 条目 TTL 只兜代数 bump 收口不到的旁路写（裸 SQL 改库等跨进程变更）。
const VIS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);

struct VisCacheEntry {
    generation: u64,
    is_public: bool,
    expires_at: tokio::time::Instant,
}

/// 插入序队列 + 哈希表：`order` 与 `map` key 集合恒等（重 fill 不重复入队），逐出双删。
#[derive(Default)]
struct VisCacheMap {
    map: HashMap<String, VisCacheEntry>,
    order: VecDeque<String>,
}

/// repo 通道的产品可见性短缓存：product name → is_public，用户域代数失效 +
/// TTL 兜底（形态对齐认证缓存 AuthCache）；判定输入只有 visibility。只缓存
/// 真实存在的产品——不存在的产品名可被匿名通道任意枚举，负缓存是容量放大道具，
/// 保持逐请求回源 404；`std::sync::Mutex` 短临界区不跨 await，回源在锁外调用方。
pub(crate) struct RepoVisibilityCache {
    entries: std::sync::Mutex<VisCacheMap>,
    /// 生产恒为 [`VIS_CACHE_TTL`]；测试经 `with_ttl` 注入短值验证过期回源。
    ttl: std::time::Duration,
}

impl RepoVisibilityCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(VisCacheMap::default()),
            ttl: VIS_CACHE_TTL,
        }
    }

    /// 持锁无用户代码、正常不 poison；毒化则取回数据继续服务（缓存可回源兜底）。
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, VisCacheMap> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn lookup(&self, product: &str, generation: u64) -> Option<bool> {
        let guard = self.lock_entries();
        let entry = guard.map.get(product)?;
        (entry.generation == generation && entry.expires_at > tokio::time::Instant::now())
            .then_some(entry.is_public)
    }

    pub(crate) fn fill(&self, product: &str, generation: u64, is_public: bool) {
        let mut guard = self.lock_entries();
        if guard.map.len() >= VIS_CACHE_CAPACITY && !guard.map.contains_key(product) {
            if let Some(oldest) = guard.order.pop_front() {
                guard.map.remove(&oldest);
            }
        }
        let entry = VisCacheEntry {
            generation,
            is_public,
            expires_at: tokio::time::Instant::now() + self.ttl,
        };
        if guard.map.insert(product.to_string(), entry).is_none() {
            guard.order.push_back(product.to_string());
        }
    }
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/repo/{product}/{arch}/{*path}", get(serve_repo_file))
}

/// 单个路径组件安全性：非空、非 `.`/`..`、不含分隔符/NUL。
fn safe_component(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\', '\0'])
}

/// 产品是否 public（repo 门判定），带代数 + TTL 短缓存。DB 错误透传标准 5xx
/// 信封（`ApiError::from`），不得假装"产品不存在"回 404——后端故障会被静默
/// 降级成"服务正常但无此产品"。
async fn product_is_public(app: &Arc<AppState>, product: &str) -> Result<bool, ApiError> {
    // 代数回源前读取：查询中可见性变更会 bump 代数，旧代数回填 → 下次必未命中重回源。
    let generation = app.state_store.user_generation();
    if let Some(is_public) = app.repo_visibility_cache.lookup(product, generation) {
        return Ok(is_public);
    }
    let record = app
        .state_store
        .get_product_by_name(product)
        .await
        .map_err(ApiError::from)?;
    match record {
        Some(r) => {
            let is_public = r.visibility == crbs_core::VISIBILITY_PUBLIC;
            app.repo_visibility_cache
                .fill(product, generation, is_public);
            Ok(is_public)
        }
        // 不存在/已删不落缓存（匿名枚举下负缓存是容量放大），维持逐请求回源。
        None => Ok(false),
    }
}

/// 校验并解析待服务绝对文件路径；不合法 / 不可见 → `Ok(None)`（调用方转 404）；DB 故障 → `Err`（5xx 信封，不折叠成 404）。
async fn resolve_repo_file(
    app: &Arc<AppState>,
    product: &str,
    arch: &str,
    rel_path: &str,
) -> Result<Option<PathBuf>, ApiError> {
    if !safe_component(product) || !safe_component(arch) {
        return Ok(None);
    }

    if !product_is_public(app, product).await? {
        return Ok(None);
    }

    let mut file = app
        .result_dir_for_or_default(product)
        .await
        .join(REPO_ROOT_DIR)
        .join(product)
        .join(arch);
    for comp in rel_path.split('/') {
        if !safe_component(comp) {
            return Ok(None);
        }
        file.push(comp);
    }
    Ok(Some(file))
}

/// 按 `rel_path` 决定 Cache-Control，无匹配则不设该头：
///
/// - `repodata/repomd.xml` → `no-cache`：dnf 新鲜度标记，客户端每次刷新都须
///   重验证（If-Modified-Since 可 304），元数据更新即时生效而非等 TTL；
/// - 其余 `repodata/` → `max-age=300`：dnf 仅经 repomd.xml 引用到达，短 TTL
///   摊薄重验证流量又不致久发陈旧元数据；
/// - `*.rpm` → `public, max-age=3600`：同 NVR 重建会把同名 RPM 文件背后的
///   字节换掉（repo_publish.rs stale-inode 摘旧链新），TTL 过长 = 旧字节对上
///   新 repodata 校验和的 dnf 校验失败窗口，1h 界定该窗口。
fn repo_cache_control(rel_path: &str) -> Option<&'static str> {
    if rel_path == "repodata/repomd.xml" {
        Some("no-cache")
    } else if rel_path.starts_with("repodata/") {
        Some("max-age=300")
    } else if rel_path.ends_with(".rpm") {
        Some("public, max-age=3600")
    } else {
        None
    }
}

/// `GET /repo/{product}/{arch}/{*path}`：委托 [`ServeFile`] 服务磁盘文件
/// （Range / If-Modified-Since / content-type、不存在 404 由其处理），命中后按
/// [`repo_cache_control`] 补 Cache-Control。
async fn serve_repo_file(
    State(app): State<Arc<AppState>>,
    AxumPath((product, arch, path)): AxumPath<(String, String, String)>,
    req: Request<Body>,
) -> Result<Response, ApiError> {
    match resolve_repo_file(&app, &product, &arch, &path).await? {
        Some(file) => match ServeFile::new(file).oneshot(req).await {
            Ok(resp) => {
                let mut resp = resp.into_response();
                if let Some(value) = repo_cache_control(&path) {
                    resp.headers_mut().insert(
                        header::CACHE_CONTROL,
                        axum::http::HeaderValue::from_static(value),
                    );
                }
                Ok(resp)
            }
            // ServeFile 的 Service error 为 Infallible，此分支实际不可达。
            Err(_) => Ok(StatusCode::NOT_FOUND.into_response()),
        },
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl RepoVisibilityCache {
        /// 测试注入短 TTL。须置于测试模块——路由清单防线按首个 `#[cfg(test)]`
        /// 截断扫描，cfg(test) 项不得出现在其前的生产代码（含 router 注册）。
        fn with_ttl(ttl: std::time::Duration) -> Self {
            Self { ttl, ..Self::new() }
        }
    }

    /// 代数失配必须未命中：可见性翻转 bump 用户域代数即时失效的载体，旧代数回看同不命中。
    #[test]
    fn vis_cache_generation_mismatch_misses() {
        let cache = RepoVisibilityCache::new();
        cache.fill("prod", 7, true);
        assert_eq!(cache.lookup("prod", 7), Some(true));
        assert_eq!(cache.lookup("prod", 8), None, "bumped generation must miss");
        assert_eq!(cache.lookup("prod", 6), None, "stale generation must miss");
    }

    /// TTL 到期未命中（旁路写兜底）、回填恢复命中；单测不触 DB，paused time 与 sqlx 定时器无冲突。
    #[tokio::test(start_paused = true)]
    async fn vis_cache_ttl_expiry_misses() {
        let cache = RepoVisibilityCache::with_ttl(std::time::Duration::from_millis(50));
        cache.fill("prod", 1, false);
        assert_eq!(cache.lookup("prod", 1), Some(false));
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert_eq!(cache.lookup("prod", 1), None, "expired entry must miss");
        cache.fill("prod", 1, true);
        assert_eq!(cache.lookup("prod", 1), Some(true));
    }

    #[test]
    fn vis_cache_evicts_oldest_beyond_capacity() {
        let cache = RepoVisibilityCache::new();
        for n in 0..=VIS_CACHE_CAPACITY {
            cache.fill(&format!("p-{n}"), 0, true);
        }
        assert_eq!(cache.lookup("p-0", 0), None, "oldest entry must be evicted");
        assert_eq!(cache.lookup("p-1", 0), Some(true));

        cache.fill("p-1", 0, true);
        cache.fill("p-new", 0, true);
        assert_eq!(cache.lookup("p-1", 0), None, "next-oldest must be evicted");
        assert_eq!(cache.lookup("p-2", 0), Some(true));
        assert_eq!(cache.lookup("p-new", 0), Some(true));
    }
}
