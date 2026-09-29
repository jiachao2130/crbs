// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.
//! submit 测试共享夹具：产品/应用构造与 SRPM 命名辅助。

use super::*;

pub(super) async fn test_app_with_product(
    name: &str,
    arches_toml: Option<&str>,
) -> (Arc<AppState>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(crbs_core::StateStore::new(tmp.path()).await.unwrap());
    let app = Arc::new(AppState::for_test(
        store.clone(),
        crbs_core::config::ServerConfig::default(),
        tmp.path().to_path_buf(),
    ));
    // 带 arches 的配置必须同时给 base_packages/repos，否则 chain_resolve 的
    // 出口校验（validate_resolved_shape）会拒绝，resolve 走 Err 兜底分支。
    let config = arches_toml
        .map(|arches| {
            crbs_core::config::ProductConfig::from_str(&format!(
                "base_packages = [\"bash\"]\narches = {}\n\n[[repos]]\n\
                 name = \"base\"\nbaseurl = \"http://example.com/base/$basearch\"\n\
                 gpgcheck = false\n",
                arches
            ))
            .unwrap()
        })
        .unwrap_or_default();
    store
        .create_product(crbs_core::CreateProductInput {
            name,
            display_name: None,
            owner_id: None,
            parent_id: None,
            visibility: crbs_core::VISIBILITY_PUBLIC,
            config: &config,
            changed_by_user_id: None,
            reason: Some("arch validation test"),
        })
        .await
        .unwrap();
    (app, tmp)
}

pub(super) fn arches(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// 真实构造一个 SRPM（rpm -qp 解析 header 需要），可选 BuildArch。`dist`
/// 钉为空：部分发行版 rpmbuild 会给未写 `%{?dist}` 的 Release 追加宿主
/// dist 后缀、文件名漂移——noarch 槽位按 `srpm_display_name` 哈希，键含
/// dist 会让分落架构随宿主变化。仅 Linux 有意义。
#[cfg(target_os = "linux")]
pub(super) fn build_named_srpm(
    tmp: &tempfile::TempDir,
    name: &str,
    buildarch: Option<&str>,
) -> std::path::PathBuf {
    crbs_core::test_support::build_srpm(SrpmFixture {
        topdir: tmp.path(),
        name,
        version: "1.0",
        release: "1",
        buildarch,
        build_requires: &[],
        exclusive: &[],
        exclude: &[],
    })
}

/// 按名字更新测试产品配置（update_product_config 需要 numeric id）。
pub(super) async fn update_test_product(
    app: &Arc<AppState>,
    name: &str,
    cfg: &crbs_core::config::ProductConfig,
) {
    let record = app
        .state_store
        .get_product_by_name(name)
        .await
        .unwrap()
        .expect("test product exists");
    app.state_store
        .update_product_config(
            record.id,
            cfg,
            None,
            Some("deterministic submit test"),
            None,
        )
        .await
        .unwrap();
}
