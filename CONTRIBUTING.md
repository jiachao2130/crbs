# 参与 CRBS 开发

CRBS 以 Rust 编写，开发与真实构建验证在 Linux 上进行。macOS 可用于格式检查、静态检查与单元测试，但涉及 namespace、mount、cgroup 的路径仅在 Linux 有效。

## 1 环境要求

- Rust 1.82 及以上（stable）。
- Linux 真机构建需要 `systemd-container`、`dnf`、`rpm-build`，以及可用的 `crbs` 组与 priv-helper 安装；详见 [`docs/manual/deploy.md`](docs/manual/deploy.md) 与 [`docs/manual/build.md`](docs/manual/build.md)。
- 端到端构建验证推荐 openEuler、EulerOS、Fedora 或 CentOS Stream。

## 2 构建与验证

提交前必须通过以下门禁：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

文档改动另需通过：

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

PostgreSQL 后端的专属用例仅在 `CRBS_TEST_DATABASE_URL` 指向可用 PG 实例时执行；SQLite 三连绿不代表 PG 面通过：

```bash
CRBS_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/crbs_test \
  cargo test -p crbs-core --features postgres -- --test-threads=1
CRBS_TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/crbs_test \
  cargo test -p crbs-server --features postgres -- --test-threads=1
```

涉及特权操作的用例不进入常规门禁，按需在 Linux 上手动执行：

```bash
sudo ./tests/integration.sh          # 真实构建全链路
cargo test --workspace -- --ignored  # 需 root 或 crbs 组的用例
```

## 3 提交约定

- 采用 Conventional Commits：`type(scope): short description`。
- 常用 type：`feat`、`fix`、`docs`、`refactor`、`chore`、`test`、`ci`；破坏性变更加 `!`。
- 每个提交使用 `git commit -s` 附加 `Signed-off-by`。
- 提交正文可使用中文；行为变化应说明原因、影响面与升级注意事项。
- 涉及配置、CLI 或 API 的改动同步更新 `CHANGELOG.md` 的 `[Unreleased]` 段。
- 不提交构建产物、临时脚本或个人环境配置。

## 4 CHANGELOG 写法

`[Unreleased]` 面向用户描述行为变化与升级影响，每条一句话，按 Keep a Changelog 的 Added / Changed / Fixed / Security 分组。设计论证、方案取舍、工单号与内部批号不写入 CHANGELOG。

## 5 非平凡改动

跨多文件、新增模块、架构调整或破坏性变更，请先在 issue 或 PR 描述中给出：

1. 问题与背景；
2. 至少两个可行方案及取舍；
3. 实现步骤与影响面；
4. 验证方式。

达成一致后再开始实现。

## 6 代码约定

- 非测试代码不使用 `unwrap()` / `expect()`；错误通过 `Result` 向上传递。
- 状态层 SQL 调用携带 `.db_ctx("<语义>")` 上下文，便于定位失败。
- 日志使用 `tracing` 结构化字段；`println!` / `eprintln!` 仅用于 CLI 交互输出。
- 注释解释原因与约束，不复述代码；避免历史对比与调用点清单。
- 新增或修改公开 API 时同步 rustdoc；文档链接与命令示例必须可验证。

## 7 Issue 与 PR

- Bug 报告请附环境（发行版、Rust 版本、crbs 版本或提交）、复现步骤、期望结果与实际结果、相关日志。
- 功能请求请说明使用场景、建议接口与备选方案。
- PR 描述请勾选已执行的门禁项，并说明测试覆盖情况。

## 8 安全问题

请勿在公开 issue 中披露安全问题，通过私有渠道联系维护者，详见 [`SECURITY.md`](SECURITY.md)。

## 9 许可

CRBS 采用 [MulanPSL-2.0](LICENSE)。提交即视为以该许可发布贡献。
