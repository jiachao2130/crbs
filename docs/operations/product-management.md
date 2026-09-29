# 产品配置运维

产品（product）是 CRBS 构建目标的可命名配置，包含基础包
（`base_packages`）、包源（`[[repos]]`）、架构集（`arches`）与构建参数。

产品配置的权威源是 hub 数据库（`products.config_json`）。
`/etc/crbs/products/*.toml` 仅用于两种场景：

- server 首次启动且 `products` 表为空时，从该目录 seed 入库；
- `crbs products export` 将数据库配置写回磁盘。

所有配置变更应通过 CLI、HTTP API 或 Web UI 完成，直接修改磁盘 TOML 不
会生效。

## 1. 创建、更新与删除

```bash
# 创建
crbs products create <name> \
  --config-file /path/to/<name>.toml \
  [--display-name "<display>"] [--parent-id <N>] [--reason "<reason>"]

# 更新（乐观锁）
crbs products update <name> \
  --config-file /path/to/new.toml \
  --expected-revision <N> \
  [--reason "<reason>"] [--parent-id <N> | --detach-parent]

# 删除数据库记录
crbs products delete <name> --yes

# 清理磁盘产物与发布仓库（admin，异步执行，有活跃构建时拒绝）
crbs products clean <name> --yes
```

- 产品名必须匹配 `^[a-z0-9_-]+$`，全局唯一，创建后不可修改。
- `update` 必须携带 `--expected-revision`，不匹配返回 409。更新成功后
  `revision` 加 1，并写入 `product_config_history`。
- `delete` 不清理磁盘上的 results、base OS 与共享层，磁盘清理使用
  `products clean`。

## 2. 元数据与权限

```bash
# 可见性
crbs products publish <name> [--reason "<reason>"]
crbs products unpublish <name> [--reason "<reason>"]

# 所有权转让
crbs products transfer <name> <new_owner> [--reason "<reason>"]

# ACL
crbs products acl list <name>
crbs products acl grant <name> <user> [--role viewer|builder|admin]
crbs products acl revoke <name> <user>
```

`publish`、`unpublish`、`transfer` 不修改 `config_json`，但会使 `revision`
加 1 并写入一条历史记录。ACL 存储在独立的 `product_acl` 表中。

角色含义与可见性规则见 [`../manual/operations.md`](../manual/operations.md)
§2.2。

## 3. 读取与导出

```bash
crbs products show <name>
crbs products history <name> [--revision <N>]
crbs products export <name> [--file /path/to/<name>.toml]
```

`history --revision N` 返回单层配置快照，不含父链合并结果；
`export` 始终导出当前 chain-resolved 配置。

## 4. 派生与继承

```bash
# 挂链 fork：空配置 + parent_id，持续继承父链
crbs products fork <parent> <new_name> [--reason "<reason>"]

# 脱链 fork：快照父级 chain-resolved 配置，parent_id 置空
crbs products fork <parent> <new_name> --detached [--reason "<reason>"]
```

- 挂链产品会随父级更新而改变 effective 配置，自身 `revision` 与
  `config_json` 不变。
- 脱链产品与父级此后无关联。
- fork 默认在子产品配置中写入 `gpg_signing_enabled = false`，签名许可
  不随派生扩散。确需签名时由 admin 显式改为 `true` 并配置
  `gpg_signing_key_id`。

改父使用 `update` 的 `--parent-id` 或 `--detach-parent`，两者互斥。
server 会先做 DFS 环检测再修改，拒绝时 `revision` 不变。同一次 update
同时改配置与改父会触发两次 revision 增长。

## 5. TOML 模板

最小可用配置：

```toml
base_packages = ["rpm-build", "dnf", "make", "gcc", "glibc-devel"]
arches = ["x86_64", "aarch64"]

[[repos]]
name = "<name>-base"
baseurl = "https://repo.example.com/<name>/os/$basearch/"
gpgcheck = true
gpgkey = "/etc/pki/rpm-gpg/RPM-GPG-KEY-<name>"
```

`base_packages` 与 `repos` 为产品必填字段，其余字段省略时继承全局配置。
常用字段：

| 字段 | 用途 |
|------|------|
| `arches` | 目标架构集 |
| `releasever` | dnf `--releasever`，可在 URL 中用 `%{releasever}` 展开 |
| `builder_user` / `builder_uid` / `builder_group` / `builder_gid` | 构建用户与组 |
| `backend` / `memory_max` / `cpu_quota` | 容器后端与资源限制 |
| `build_target` | `bb` / `bs` / `ba` |
| `network` | 构建网络开关 |
| `shared_layer` / `build_tmpfs` / `dnf_cache_enabled` / `ccache_enabled` | 缓存开关 |
| `nocheck` / `noclean` / `nodebuginfo` | 跳过对应阶段 |
| `deterministic` | 确定性构建模式，要求 `dnf_cache_enabled = true` 且 `build_target != ba` |
| `repo-publish` / `repo-consume` | 发布轴与消费轴开关 |
| `gpg_signing_key_id` / `gpg_signing_enabled` | 产物签名 |
| `[rpm_macros]` / `[hooks.*]` | RPM 宏与构建钩子 |
| `+base_packages` / `+repos` / `+arches` / `+post_init` | 子产品追加语法 |

完整字段、类型与默认值见 [`../manual/configuration.md`](../manual/configuration.md)
§3。`+field` 仅存在于数据库与用户输入侧，下发给 worker 的 TOML 已折叠为
最终列表。

路径覆盖字段（`result_dir`、`shared_layers_dir`、`product_root`、
`base_os_path`、`dnf_cache_path`、`ccache_dir`）是机器本地绝对路径，会
原样穿透继承链。同构部署可在父层统一设置；异构部署不得在父层设置，否则
不同机器的结果与缓存位置会不一致。`crbs_root` 是机器级配置，在链出口
被剥离，产品层设置会被忽略并告警。

## 6. 典型操作

### 6.1 新建产品

```bash
cat > /tmp/oe2203sp4.toml <<'EOF'
base_packages = ["bash", "rpm-build", "gcc", "make", "glibc-devel", "dnf"]
arches = ["x86_64", "aarch64"]

[[repos]]
name = "oe2203sp4-base"
baseurl = "https://mirror.example.com/openEuler-22.03-LTS-SP4/everything/$basearch/"
gpgcheck = true
EOF

crbs products create oe2203sp4 \
  --config-file /tmp/oe2203sp4.toml \
  --display-name "openEuler 22.03-LTS-SP4" \
  --reason "initial"
```

### 6.2 修改配置

```bash
# 1. 导出当前配置到本地文件
crbs products export <name> --file /tmp/<name>.toml

# 2. 编辑并确认当前 revision
$EDITOR /tmp/<name>.toml
crbs products show <name>

# 3. 提交更新
crbs products update <name> \
  --config-file /tmp/<name>.toml \
  --expected-revision <N> \
  --reason "<change summary>"
```

### 6.3 撤销错误更新

`product_config_history` 保存每次更新的配置快照，但不保存 diff。回滚方式
是从历史记录或外部备份取出上一版配置，再执行一次正向 update：

```bash
crbs products history <name> --revision <N> > /tmp/<name>-rollback.toml
crbs products update <name> \
  --config-file /tmp/<name>-rollback.toml \
  --expected-revision <current> \
  --reason "rollback to revision <N>"
```

## 7. init 与 clean 端点

`POST /api/v1/products/{name}/init` 与 `/clean` 为异步受理语义：

- 权限为 admin。受理后返回 202：

  ```json
  {"task_id": "<uuid>", "status": "running", "product": "<name>", "op": "init"}
  ```

- 进度通过 `GET /api/v1/products/tasks/{task_id}`（operator+）查询。
- 同一产品同一操作已有运行中任务时返回 409。
- 任务状态保存在 hub 内存中，server 重启后清空；重启后重新调用即可。
- 历史条目按 `product_result_retention` 逐出，运行中的条目豁免。

base OS 重建的完整流程见
[`admin-init-and-reinit.md`](admin-init-and-reinit.md)。

## 8. Web 管理

admin 或产品 owner 可在 Web UI 完成配置管理：

- **Products → New product**：填写产品名、可选父产品、所有者与可见性，
  并录入 TOML 配置。builder 创建的产品强制为 private。
- **产品详情 → Edit config**：编辑产品本层配置，继承关系通过 `+field`
  保留。**Check** 执行语法检查、链级 dry-run 合并与预览；**Save** 执行
  全量校验、乐观锁检查并落库。
- **History**：查看 revision 历史与变更记录。所有新建与编辑操作写入审计
  日志。

## 9. 应急直改数据库

仅在 crbs-server 无法启动、API 不可用的场景使用。正常变更走 API 或 UI，
由应用层维护历史与审计。

以下模板适用于 PostgreSQL 部署。操作前备份当前 `config_json`，并确认
目标 revision 与操作者用户 ID：

```sql
-- 查现状
SELECT id, name, revision, base_os_revision FROM products WHERE name = '<name>';
SELECT id, name FROM users WHERE name = '<operator>';

BEGIN;
UPDATE products
  SET config_json = '<new config json>',
      revision    = revision + 1
  WHERE name = '<name>';

INSERT INTO product_config_history
  (product_id, revision, config_json, parent_id, base_os_revision,
   changed_by_user_id, reason)
SELECT id, revision, config_json, parent_id, base_os_revision, <uid>, '<reason>'
  FROM products WHERE name = '<name>';
COMMIT;
```

完成后重启 crbs-server，并用 `crbs products show` 与
`crbs products history` 验证。大段 JSON 建议先写入临时表再引用，避免手工
拼接 SQL 字面量。

schema 采用单 baseline 加版本闩，不提供增量迁移。跨版本升级时按
[`../manual/deploy.md`](../manual/deploy.md) §8.2 处理数据库，不通过手工
加列绕过版本检查。
