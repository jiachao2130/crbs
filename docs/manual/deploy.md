# CRBS 部署手册

适用版本：0.1.0。

本文覆盖部署形态、安装、Hub 与 Worker 配置、TLS、systemd、升级回滚和安全清单。字段级参考见 [configuration.md](configuration.md)。

## 1. 部署形态

| 形态 | 组件 | 适用场景 |
|------|------|----------|
| 单机 | `crbs` + `crbs-server`（可选 `crbs-worker`） | 个人或小团队；Hub 本机同时执行构建 |
| Hub + Worker | Hub 节点运行 `crbs-server`，构建节点运行 `crbs-worker` | 多机、多架构批量构建；并发由各 Worker 的 `capacity` 控制 |

| 组件 | 二进制 | 作用 | 运行身份 |
|------|--------|------|----------|
| CLI | `/usr/bin/crbs` | 本地构建、远程提交 | `crbs` 组用户或 root |
| Hub | `/usr/bin/crbs-server` | HTTP API、Web UI、调度 | 系统用户 `crbs-server` |
| Worker | `/usr/bin/crbs-worker` | 执行远程构建 | 系统用户 `crbs-worker` |
| 特权 helper | `/usr/libexec/crbs/crbs-priv-helper` | setuid-root，执行 mount、chroot、容器启动、`dnf --installroot` | 由上述进程调用 |

`crbs-server` 默认监听 `127.0.0.1:9090`（HTTP）。对外提供服务时配置内置 TLS 或使用反向代理，端口按部署环境确定。

## 2. 安装

### 2.1 RPM

构建并安装：

```bash
bash scripts/build-srpm.sh
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
rpmbuild --rebuild rpmbuild/SRPMS/crbs-0.1.0-1*.src.rpm

ARCH=$(uname -m)
sudo dnf install -y \
    ~/rpmbuild/RPMS/$ARCH/crbs-0.1.0-1.*.$ARCH.rpm \
    ~/rpmbuild/RPMS/$ARCH/crbs-priv-helper-0.1.0-1.*.$ARCH.rpm \
    ~/rpmbuild/RPMS/$ARCH/crbs-server-0.1.0-1.*.$ARCH.rpm
```

rebuild 主机需能访问 crates.io 或已配置 cargo 源镜像，`%build` 按 `Cargo.lock` 拉取依赖并编译。

Worker 节点将 `crbs-server` 子包替换为 `crbs-worker`。RPM 安装会创建系统组 `crbs`、系统用户 `crbs-server` / `crbs-worker`，创建 `/var/lib/crbs` 与 `/etc/crbs/products/`，安装 systemd 单元，但不自动启动服务。

安装后检查特权 helper：

```bash
stat -c "%a %U:%G %n" /usr/libexec/crbs/crbs-priv-helper
# 期望：4750 root:crbs
```

不符时修正。`chgrp` / `chown` 会清除 setuid 位，改属组后必须重设：

```bash
sudo chgrp crbs /usr/libexec/crbs/crbs-priv-helper
sudo chmod 4750 /usr/libexec/crbs/crbs-priv-helper
```

### 2.2 配置权限

`crbs-priv-helper` 在启动时校验配置路径，不满足要求时拒绝所有特权操作：

- `/etc/crbs`、`/etc/crbs/products`：root 所有，group/other 不可写，推荐 `0750 root:crbs`。
- 目录下所有 `.toml`：`0640 root:crbs`。

```bash
sudo chmod 0750 /etc/crbs /etc/crbs/products
sudo chown root:crbs /etc/crbs/*.toml /etc/crbs/products/*.toml
sudo chmod 0640 /etc/crbs/*.toml /etc/crbs/products/*.toml
```

单租户开发机可在 `/etc/crbs/priv-helper.toml` 设置 `relax_config_permissions = true` 跳过检查；多租户或生产环境不得开启。

### 2.3 管理员与启动

数据库无需手工初始化：空库首启自动建立 schema。创建首个管理员与 token：

```bash
sudo -u crbs-server crbs-server user add admin --role admin
sudo -u crbs-server crbs-server token create admin --name setup --expires 30
# Token: crbs_tok_... 仅显示一次
```

启动并验证：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crbs-server
curl http://127.0.0.1:9090/api/v1/health
# {"status":"ok"}
```

普通用户使用 CLI 前加入 `crbs` 组，重新登录后生效：

```bash
sudo usermod -aG crbs <username>
```

### 2.4 源码直装

开发机可执行 `sudo bash scripts/setup.sh <username>`，完成编译、安装二进制、创建目录和加入用户组。生产环境使用 RPM 与 systemd。

## 3. Hub 配置

```bash
sudo cp /etc/crbs/server.toml.example /etc/crbs/server.toml
sudo chmod 0640 /etc/crbs/server.toml
sudo vi /etc/crbs/server.toml
```

最小配置：

```toml
listen = "127.0.0.1:9090"
auth_enabled = true
scheduler_mode = "auto"
max_local_builds = 0

[public_access]
view = true
logs = true
download = true
```

常用键：

| 键 | 默认 | 说明 |
|----|------|------|
| `listen` | `127.0.0.1:9090` | 监听地址；CLI `--listen` 优先 |
| `auth_enabled` | `true` | Bearer 认证；关闭仅允许本地开发 |
| `web_ui_enabled` | `true` | Web UI 与仪表盘路由 |
| `max_local_builds` | `0` | Hub 本机并发，`0` = CPU 核数；Worker 并发由其 `capacity` 控制 |
| `scheduler_mode` | `auto` | `auto` = Worker 优先分发 + 本地兜底；另有 `local_only`、`distributed_only` |
| `min_free_disk_gb` | `1` | 磁盘水位，不足时拒绝新构建 |
| `db_retention_days` | `90` | 数据库历史行保留天数，`0` 禁用 |
| `upload_max_size_mb` | `500` | multipart 上传上限；反向代理需同步对齐 |
| `allow_product_management` | `false` | 产品 init/clean 端点开关 |
| `[public_access]` | 三项均 `true` | 匿名查看 UI、日志、下载产物 |
| `[tls]` | 未配置 | 配置 `cert` / `key` 后监听 HTTPS |
| `force_secure_cookies` | `false` | 反向代理终止 TLS 时必须设为 `true` |

`result_dir`、`upload_dir`、`state_db_path`、`artifact_dir` 未配置时由 `crbs_root`（默认 `/var/lib/crbs`）派生。

### 3.1 PostgreSQL

Hub 状态库默认使用 SQLite。切换 PostgreSQL：

1. 确认二进制包含 PostgreSQL 支持。两种 spec 默认均启用 `postgres`；`crbs.spec` 可用 `--without postgres` 构建纯 SQLite 版本。
2. 在 `/etc/crbs/crbs.toml` 配置 `database_url`（该键不在 `server.toml`）：

```toml
database_url = "postgres://crbs:password@127.0.0.1:5432/crbs"
```

配置后 `server.toml` 的 `state_db_path` 被忽略。该 URL 同时供 `crbs-server` 与 CLI 管理子命令使用。只有 Hub 状态库迁移到 PostgreSQL；Worker 本地库与产物仍保存在本机磁盘。

## 4. Worker 部署

### 4.1 注册

在 Hub 上注册 Worker，并直接生成配置：

```bash
sudo -u crbs-server crbs-server worker add worker-01 \
    --arch x86_64 \
    --capacity 4 \
    --hub-url https://hub.example.com:18443 \
    --output-config /etc/crbs/worker.toml
```

secret 仅显示一次；`--output-config` 生成 `0640 root:crbs` 的 `worker.toml`。不传 `--build-dir` / `--crbs-root` 时写入默认值，重新生成前应回填已有配置中的自定义路径。

### 4.2 安装与启动

Worker 节点安装 `crbs`、`crbs-priv-helper`、`crbs-worker` 三个包，配置 `/etc/crbs/worker.toml`：

```toml
name = "worker-01"
hub_url = "https://hub.example.com:18443"
arch = "x86_64"
capacity = 4
token = "crbs_wkr_..."
```

```bash
sudo systemctl enable --now crbs-worker
```

Worker 以 `crbs-worker:crbs` 运行，特权操作经 `crbs-priv-helper` 委托。默认保留构建结果 3 天（`result_retention_days`，`0` = 永久保留）。

### 4.3 自定义路径

`crbs-worker.service` 设置 `ProtectSystem=strict`，默认可写路径为 `/var/lib/crbs`、`/var/tmp`、`/dev/shm`。`build_dir`、`tmp_dir`、`tmpfs_dir` 或 `crbs_root` 指向其他路径时，需追加 systemd drop-in：

```ini
# /etc/systemd/system/crbs-worker.service.d/readwrite.conf
[Service]
ReadWritePaths=/var/lib/crbs /var/tmp /dev/shm /data/crbs-local
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart crbs-worker
```

Hub 侧同理：`result_dir`、`upload_dir`、`state_db_path`、`artifact_dir` 在默认路径之外时，需加入 `crbs-server.service` 的 `ReadWritePaths`。

### 4.4 后端选择

默认后端为 `nspawn`，隔离 PID 与 mount namespace，适用于开启认证的多租户部署。

`chroot` 后端仅做文件系统隔离，无命名空间边界；具备构建提交权限的用户等价于获得宿主机 root。仅可用于单租户场景（个人开发机、提交者本就是 root 的 CI 节点）。`auth_enabled = true` 且全局后端为 `chroot` 时，服务启动日志会输出告警。产品级 `backend = "chroot"` 同样适用此结论。

## 5. TLS

`crbs-server` 支持内置 TLS：在 `server.toml` 配置 `[tls]` 后直接监听 HTTPS，会话 cookie 自动带 `Secure`。两种接入方式：

- **内置 TLS**：`listen` 直接对外，适合独立内网主机。systemd 单元已授予 `CAP_NET_BIND_SERVICE`，非 root 用户可绑定 443。证书 SAN 必须包含客户端实际访问的主机名或 IP。使用内部 CA 时需签发 CA 与叶子两级证书；不要将 `openssl req -x509` 生成的自签证书直接作为服务端证书。
- **反向代理**：由 nginx 等终止 TLS，`crbs-server` 保持 `127.0.0.1:9090`。必须设置 `force_secure_cookies = true`。

nginx 示例见 [examples/nginx/crbs.conf](../../examples/nginx/crbs.conf)，关键配置：

- `client_max_body_size` 不小于 `upload_max_size_mb`。
- `/api/v1/builds/{id}/logs` 为分块流，构建静默期无数据下发；`proxy_read_timeout` 需覆盖静默窗口（建议 300s）。
- SSE 端点必须 `proxy_buffering off`，否则页面事件延迟。

防火墙仅放行服务端口与 SSH：

```bash
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

反代模式下仅需放行 nginx，后端保持 loopback 监听。

## 6. systemd

| 操作 | 命令 |
|------|------|
| 启停 | `sudo systemctl start|stop|restart crbs-server` |
| 开机自启 | `sudo systemctl enable --now crbs-server` |
| 状态 | `systemctl status crbs-server` |
| 日志 | `journalctl -u crbs-server -f`（Worker：`-u crbs-worker`） |
| 日志级别 | `sudo systemctl edit crbs-server` 添加 `Environment="RUST_LOG=crbs_server=debug"` |

`crbs-server.service` 以 `crbs-server:crbs` 非 root 运行，`Restart=on-failure`，设置 `ProtectSystem=strict`，默认可写路径为 `/var/lib/crbs`、`/run/crbs`、`/etc/crbs`。优雅退出由 `server.toml` 的 `shutdown_timeout_secs`（默认 60s）控制：排空 HTTP 连接并等待活跃构建。升级时 `%postun` 不自动重启服务，避免中断构建。

## 7. Web UI 与公开访问

`web_ui_enabled = true` 时可通过 `https://<hub>/ui/` 访问。`public_access` 仅控制匿名只读面：

| 键 | 默认 | 说明 |
|----|------|------|
| `view` | `true` | 匿名查看 Web UI 页面 |
| `logs` | `true` | 匿名查看构建日志 |
| `download` | `true` | 匿名下载产物 |

写操作、管理端点与 Worker 通道始终需要认证。私有产品仅 owner、operator、admin 及持 ACL 者可见。

内网受信部署可保持默认。暴露到不受信网络时至少关闭日志与下载：

```toml
[public_access]
view = true
logs = false
download = false
```

## 8. 升级与回滚

### 8.1 升级

1. 备份数据库与产品配置，方法见 [operations.md](operations.md) §5。
2. 安装新版本 RPM。
3. `/etc/crbs/*.toml` 为 `%config(noreplace)`，升级保留本地修改；检查是否需要新增字段。
4. 重启：

```bash
sudo systemctl daemon-reload
sudo systemctl restart crbs-server
```

升级前确认无 `building` 任务。同版本号热修需 `rpm -Uvh --replacepkgs`。

### 8.2 数据库 schema

当前机制为单 baseline + 版本闩：

- 空库首启自动建立 baseline。
- 版本戳与当前 `(SCHEMA_VERSION, SCHEMA_EPOCH)` 完全一致时正常启动。
- 其他任何形态（版本更高或更低、世代不符、有业务表但无版本表）一律拒绝启动，不自动迁移、不清库。SQLite 与 PostgreSQL 同口径。
- baseline 内新增对象（列 / 表 / 索引）不改变版本戳，`(1,1)` 仍为当前唯一有效戳。旧库升级新二进制时，启动探测缺失对象会拒绝启动并给出桥接脚本指引——这是防止“闩通过但首次写入爆列错”的 fail-closed 双保险。

因此，跨 schema 变更升级时，二选一：

- 桥接：对已初始化的旧库执行对应脚本（幂等、纯加法、零破坏）——
  hub PostgreSQL 用 `deploy/upgrade-resource-schema-pg.sh`，hub SQLite 用
  `deploy/upgrade-resource-schema-sqlite.sh`，worker 本地库用
  `deploy/upgrade-resource-schema-worker.sh`。执行前先备份并停止服务。
- 重建：备份并移走旧库，重新首启建立 baseline。需要保留历史数据时，在维护窗口按新 baseline 的列定义回灌。

回滚时，若数据库 schema 高于旧二进制预期，旧二进制会拒绝启动。必须先停服，还原升级前的数据库备份，再启动旧版本。

清库后 `products` 表为空，服务重启时会从 `/etc/crbs/products/*.toml` 重新载入。曾通过 API/UI 修改且未导出到磁盘的产品配置会丢失。升级或清库前导出：

```bash
for p in $(crbs products --remote <profile>); do
  crbs products export "$p" --remote <profile> > /etc/crbs/products/"$p".toml
done
```

### 8.3 产品配置与 base OS

产品配置的权威源是 Hub 数据库。`/etc/crbs/products/*.toml` 仅在首次启动时载入，此后直接编辑磁盘文件不生效。修改通过 `crbs products update`、API 或 Web UI 完成。

Worker 不需要本地产品配置，Hub 在派发任务时下发完整配置。base OS 由各节点本地 init 生成，产品配置变更后不会自动更新。修改仓库、base_packages、arch 等触发字段后，需远程重建：

```bash
crbs admin init <product> --all --remote <profile>
```

详见 [product-management.md](../operations/product-management.md)。

## 9. 保留与清理

三类机制相互独立：

| 机制 | 配置 | 默认 | 删除对象 | 触发 |
|------|------|------|----------|------|
| result GC | `result_gc_grace_hours`（`crbs.toml` / 产品配置） | 720h | 超期已完成构建的结果目录，并将 `builds.result_dir` 置 NULL | 手动 `crbs gc --results` |
| result 策略 GC | `result_max_count_per_pkg` / `result_retention_days` | 未启用 | 超过数量或天数的结果目录 | 手动 `crbs gc --policy` 或配置后的裸 `crbs gc` |
| DB 行保留 | `db_retention_days`（`server.toml`） | 90 天，`0` 禁用 | 超期的 `audit_logs`、`worker_tasks`、`builds`、`tasks` 行 | 后台每日执行 |

磁盘 GC 先删目录并将 `result_dir` 置 NULL；DB 行保留只删除 `result_dir` 已为 NULL 的 builds 行，因此不会产生孤儿目录。命令细节见 [operations.md](operations.md) §4.4。

## 10. 安全清单

- [ ] `auth_enabled` 保持 `true`。
- [ ] 多租户部署确认全局及各产品 `backend = "nspawn"`；`chroot` 仅限单租户。
- [ ] `/etc/crbs`、`/etc/crbs/products` 及其中 `.toml` 为 root 所有且 group/other 不可写。
- [ ] 多租户或生产环境未设置 `relax_config_permissions = true`。
- [ ] TLS 证书由可信 CA 签发，或被所有客户端信任。
- [ ] 反向代理终止 TLS 时已设置 `force_secure_cookies = true`。
- [ ] `result_dir`、`upload_dir`、`state_db_path`、`artifact_dir` 位于服务用户可写目录，并已加入 `ReadWritePaths`。
- [ ] 定期轮换用户 token 与 Worker secret。
- [ ] `log_sanitization.redact_tokens` 保持启用。
- [ ] 服务暴露到不受信网络时已收紧 `public_access`。

## 11. 相关文档

- [configuration.md](configuration.md)：全部配置字段与默认值
- [operations.md](operations.md)：巡检、用户与 token、备份恢复、故障排查
- [build.md](build.md)：构建与 RPM 产物
- [../operations/product-management.md](../operations/product-management.md)：产品继承、ACL 与发布
- [../../SECURITY.md](../../SECURITY.md)：信任模型与漏洞报告
