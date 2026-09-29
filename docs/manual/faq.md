# CRBS 常见问题

本页汇总高频问题。完整排查表见 [`operations.md`](operations.md) §6 与
[`build.md`](build.md) §8。

## 安装与升级

### 升级或回滚后 crbs-server 报 schema 版本不匹配并拒绝启动

schema 采用单 baseline 加版本闩（`SCHEMA_VERSION = 1`、
`SCHEMA_EPOCH = 1`，无增量迁移）。数据库戳与二进制预期不完全相等即
fail-closed 拒绝启动，不会自动清库。

- 升级：备份后移走旧 `crbs.db`，重新首启自动建 baseline；新二进制上线前
  对全部节点重新执行 init。
- 回滚：停服，还原升级前的 `.backup` 备份，再启动旧包，不能直接换包重启。

备份使用 `sqlite3 .backup` 在线方式，不要直接复制 WAL 模式的数据库文件。
见 [`deploy.md`](deploy.md) §8.2 与 [`operations.md`](operations.md) §5。

### 同版本热修时 rpm 认为包未变

代码已变但 spec 的 Version/Release 未递增时，使用
`rpm -Uvh --replacepkgs` 强制重装。升级不会自动重启服务，需按
stop → 安装 → start 的顺序操作，停机前确认无 building 任务。见
[`deploy.md`](deploy.md) §8.1 与 [`build.md`](build.md) §5。

### 升级或清库后通过 API 修改的产品配置丢失

清库后 `products` 表为空，重启时从 `/etc/crbs/products/*.toml` 重新 seed，
仅存在于数据库的修改会丢失。升级或 re-init 前对每个产品执行：

```bash
crbs products export <product> --remote hub > /etc/crbs/products/<product>.toml
```

见 [`operations.md`](operations.md) §5。

## 构建失败

### 构建日志含 EROFS 或 read-only file system

systemd unit 使用 `ProtectSystem=strict`，只有 `ReadWritePaths` 中的路径
可写。将自定义 `result_dir`、`build_dir`、`tmp_dir` 追加到对应服务的
`ReadWritePaths`，执行 `daemon-reload` 后重启。见
[`deploy.md`](deploy.md) §6。

### 提交构建返回 409，CLI 退出码 4

同一产品下相同 NVR 已有活跃构建时，submit、rebuild、reproduce 均被拒绝，
错误信息会指出冲突包。等待其结束，或先 `crbs cancel` 再重新提交。见
[`cli-reference.md`](cli-reference.md) 退出码表。

### 构建任务长期 pending

常见原因是无匹配架构或容量的在线 worker，或 `scheduler_mode` 与预期不符。
`auto` 表示 worker 优先分发加本地并发兜底，不是"没有 worker 才使用本地"。
需要纯本地使用 `local_only`，纯分布式使用 `distributed_only`。检查
Workers 页负载与 `/api/v1/status` 的 `workers.online` 字段。见
[`configuration.md`](configuration.md) §4。

### 构建中止，日志含 `suspected stalled storage`

worker 本地存储（常见为 NFS）停滞时，`rpm -qp` 探测会超时，引擎拒绝将
未校验的包注入本地 repo 并中止整链。检查挂载状态与读取性能后重试。见
[`operations.md`](operations.md) §6。

### 构建进行中看不到实时日志

worker 是无监听端口的纯 poller，日志以 chunk 形式上报 hub，存在固有延迟。
可在任务详情页或使用 `crbs logs <id> -f` 查看。Web UI 的 SSE 流有 15s
keepalive，CLI follow 流没有；经反向代理时需调大 `proxy_read_timeout`。
见 [`../architecture/hub-worker.md`](../architecture/hub-worker.md) 与
[`deploy.md`](deploy.md) §5。

## 权限

### 特权操作报 `permission denied: config file/dir`

`/etc/crbs` 与 `/etc/crbs/products` 及其下 `.toml` 不满足 priv-helper 的
fail-closed 校验。目录应为 `0750 root:crbs`，文件应为 `0640 root:crbs`，
group 与 other 不可写。产品配置文件必须由 root 创建。单租户开发机可在
`priv-helper.toml` 设置 `relax_config_permissions = true`，生产环境禁止。
见 [`deploy.md`](deploy.md) §2.2。

### 非 root 用户运行 crbs 报权限错误（退出码 5）

用户不在 `crbs` 组。执行 `sudo usermod -aG crbs <username>` 后重新登录。
见 [`deploy.md`](deploy.md) §2.3 与
[`cli-reference.md`](cli-reference.md) 退出码表。

### server 启动时写 `/var/lib/crbs` 失败

通常是 root 直接操作数据库导致 `crbs.db` 或 WAL 文件属主漂移。执行
`sudo chown crbs-server:crbs /var/lib/crbs/crbs.db*` 后重启。见
[`operations.md`](operations.md) §6。

## 网络与 TLS

### CLI 连接 HTTPS hub 握手失败，但 curl -k 正常

rustls 严格校验 SAN。叶子证书只登记了部分 IP 或 DNS 时，使用未登记地址
连接会失败；`curl -k` 跳过校验，无法暴露该问题。将 profile 的 `url` 改为
证书 SAN 内的地址，并在签发时写入实际使用的全部地址。见
[`deploy.md`](deploy.md) §5。

### 自签证书直接作为服务端证书被拒

`openssl req -x509` 默认生成 `CA:TRUE` 的证书，rustls 会以
`CaUsedAsEndEntity` 拒绝。应建立 CA 与叶子证书两级结构，叶子证书的 SAN
写全客户端使用的地址；证书目录属组应为 `crbs`，CLI profile 配置
`ca_cert`。见 [`deploy.md`](deploy.md) §5。

### worker 一直 offline

常见原因：secret 错误或失效、hub 不可达、CA 不受信任。检查
`journalctl -u crbs-worker` 与 hub 侧 `worker list`。secret 泄漏或丢失时
使用 `worker rotate-secret <name>`，旧 secret 立即失效。同名重复注册会被
拒绝，应使用 rotate 或先 remove。见
[`operations.md`](operations.md) §6。

### CLI 拒绝向 HTTP 地址发送 token

CLI 不允许将 token 发往非 loopback 的 `http://` 主机，以防明文泄漏。
正式环境使用 `https://`；开发隧道可设置 `CRBS_ALLOW_PLAINTEXT_TOKEN=1`。
见 [`configuration.md`](configuration.md) §6。

## 性能与资源

### 磁盘持续增长

三类来源分别处理：

- 构建机的 `target/` 目录，大构建收尾后执行 `cargo clean`。
- server 与 worker 的 results、包缓存、shared layers，按
  [`operations.md`](operations.md) §4.4 的 GC 流程先 dry-run 再清理。
  `crbs gc --cache --all` 会破坏历史构建的 `--reproduce`，生产环境应避免。
- journald 日志，配置 `SystemMaxUse` 上限。

### API 返回 503 `service_unavailable`

瞬态存储或资源问题：SQLite 写锁竞争超过 busy_timeout，或 PostgreSQL
磁盘、内存耗尽。具体原因只出现在服务端日志。检查数据库所在磁盘与内存，
客户端按 transient 语义退避重试。与此区分，返回 500 `database_error`
表示单次 SQL 语义故障，CLI 映射退出码 6，需要定位具体调用点。见
[`operations.md`](operations.md) §6。

## 其他

### `--reproduce` 或 `--rebuild` 时额外 CLI 参数未生效

`--reproduce` 配合 `--remote` 是正常路径，由 server 锁定依赖快照复现，
CLI 传入的构建参数无效。`--rebuild` 同理，服务端重放原任务记录的选项，
只有 `--detach` 与 `--follow-logs` 影响客户端行为。`--reproduce` 与
`--daemon` 同时使用且未指定 `--remote` 时，daemon 不理解复现语义，任务会
退化为普通 SRPM 提交，应避免。见 [`build.md`](build.md) §9、§10。

### task ID 与 build ID 混用

两者属于不同 ID 空间：`crbs status`、`crbs logs`、`crbs cancel` 在本地
使用完整数字 build ID，加 `--remote` 后使用完整数字 server task ID；
`--rebuild` 使用 server task ID。两侧均不支持前缀或 UUID 解析。远程任务
可通过 Web UI 或 `crbs status --remote` 查询。见
[`cli-reference.md`](cli-reference.md)。

### 直接编辑 `/etc/crbs/products/<product>.toml` 不生效

产品配置的权威源是 hub 数据库，磁盘 TOML 仅用于首启 seed 与 `export`。
变更应使用 `crbs products update`（带 `--expected-revision` 乐观锁）、
API 或 Web UI。修改触发 base OS 重建的字段后，需执行
`crbs admin init` 对齐 worker。见 [`operations.md`](operations.md) §3 与
[`../operations/product-management.md`](../operations/product-management.md)。

### 多架构产品中 noarch 包只构建一次

纯 noarch SRPM 默认收敛为单次构建，宿主架构按包全名稳定哈希选择；发布侧
单架构产物仍覆盖各架构 repo。需要每架构分别构建时，设置产品配置
`noarch_per_arch = true`。见 [`configuration.md`](configuration.md) §3。
