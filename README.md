# CRBS

CRBS（Containerized RPM Batch Build System）是用 Rust 实现的 RPM 批量构建引擎，提供单机构建命令行与 Hub/Worker 分布式部署两种形态。支持 chroot 与 systemd-nspawn 两种隔离后端、OverlayFS 增量构建、共享依赖层、构建复现、产品 ACL 和 Web 管理界面。

当前版本：0.1.0。

## 核心能力

- **构建隔离**：chroot（直接系统调用）或 systemd-nspawn（PID namespace + cgroup）。每次构建在临时 OverlayFS 层上进行，不修改 base OS。
- **三级缓存**：共享依赖层（按 BuildRequires 指纹复用已安装环境）、DNF 缓存、ccache。
- **批量与链式构建**：多 SRPM 并发；`--chain` 按 BuildRequires 拓扑排序、分轮构建并注入本地仓库。
- **构建复现**：内容寻址包缓存与 provenance 记录支持 `--reproduce`；`crbs verify` 对产物逐包比对 SHA-256；产品级 `deterministic` 模式锁定构建环境并自动重放校验。
- **任务标签**：提交时附加 `KEY=VALUE` 元数据（CLI `--label`、JSON `labels`、multipart 重复 `label` 字段），随任务落库；CLI/API/Web UI 均支持按标签过滤与回显。
- **分布式调度**：Hub 维护产品、队列与 Worker 状态，支持三级优先级、按架构与负载派发、构建画像与资源水位调度。
- **产品管理**：产品继承、ACL（viewer/builder/admin）、发布与消费开关、所有权转让。
- **GPG 签名**：私钥仅存在于 Host 侧 keyring，签名在构建容器外执行。
- **可观测性**：流式构建日志、状态查询、构建对比、Web UI、Prometheus 指标。
- **认证与审计**：Bearer token、角色权限、产品可见性隔离、操作审计。
- **数据库后端**：SQLite（默认），可编译启用 PostgreSQL。

## 环境要求

- Linux，内核支持 OverlayFS。
- x86_64 或 aarch64。
- 构建节点需安装 `dnf`、`rpm`、`rpm2cpio`、`cpio`、`createrepo_c`；签名场景需要 `gpg`。
- nspawn 后端需安装 `systemd-nspawn` 并具备相应 capability；chroot 后端无此依赖。
- 源码构建需要 Rust 1.82 或更高版本。

## 安装

### RPM

发行包包含 `crbs`、`crbs-server`、`crbs-worker`、`crbs-priv-helper` 四个子包。构建依赖与产物生成：

```bash
bash scripts/build-srpm.sh
sudo dnf install -y rpm-build rust cargo gcc systemd-rpm-macros pkgconfig(sqlite3)
rpmbuild --rebuild rpmbuild/SRPMS/crbs-0.1.0-1*.src.rpm
```

SRPM 不含 vendored 依赖，rebuild 时由 cargo 按 `Cargo.lock` 拉取依赖，主机需能访问 crates.io 或配置 cargo 源镜像。

安装：

```bash
# 构建机（CLI）
sudo dnf install -y ./crbs-0.1.0-1.*.rpm ./crbs-priv-helper-0.1.0-1.*.rpm

# Hub
sudo dnf install -y ./crbs-server-0.1.0-1.*.rpm

# Worker
sudo dnf install -y ./crbs-worker-0.1.0-1.*.rpm
```

RPM 安装会创建 `crbs` 组及 `crbs-server`、`crbs-worker` 系统用户，安装 setuid-root 的 `crbs-priv-helper`，并注册 `crbs-server.service`、`crbs-worker.service`。打包细节与单元文件见 [packaging/PACKAGING.md](packaging/PACKAGING.md)。

### 源码

```bash
cargo build --release
sudo groupadd -r crbs
sudo install -m 0750 -g crbs target/release/crbs /usr/local/bin/crbs
sudo install -d -m 0755 /usr/libexec/crbs
sudo install -m 4750 -g crbs target/release/crbs-priv-helper /usr/libexec/crbs/crbs-priv-helper
sudo mkdir -p /etc/crbs/products /var/lib/crbs-engine
sudo chown root:crbs /etc/crbs /etc/crbs/products /var/lib/crbs-engine
sudo chmod 0750 /etc/crbs /etc/crbs/products
sudo chmod 2770 /var/lib/crbs-engine
sudo usermod -aG crbs <username>
```

重新登录后组成员身份生效。也可执行 `sudo bash scripts/setup.sh <username>` 完成上述步骤。

### 权限模型

构建相关的特权操作（mount/umount、chroot/nspawn、`dnf --installroot`）由 `crbs-priv-helper` 代理执行，主进程不持有 root 权限。`crbs` 组成员可执行 `init`、`build`、`shell`、`clean`、`debug`、`cancel`、`sign`；`gc` 需要完整特权；`status`、`logs`、`diff`、`verify`、`download` 等查询命令以调用者身份运行。`sudo crbs ...` 仍然可用。

## 快速开始

```bash
# 1. 生成产品配置模板并编辑 base_packages、repos
crbs init fedora --offline
vim /etc/crbs/products/fedora.toml

# 2. 安装 base OS 与构建工具链
crbs init fedora --offline

# 3. 构建
crbs build hello.src.rpm -p fedora

# 4. 查看状态与日志
crbs status
crbs logs <task-id> -f

# 5. 进入构建环境
crbs shell fedora
crbs shell fedora -c "rpm -qa | grep gcc"

# 6. 清理产品环境
crbs clean fedora --yes
```

常用构建选项：

```bash
crbs build *.src.rpm -p fedora -j4              # 多包并发
crbs build *.src.rpm -p fedora -C               # 链式构建
crbs build pkg.src.rpm -p fedora -s --tmpfs     # 共享依赖层 + tmpfs
crbs build pkg.src.rpm -p fedora --backend chroot
crbs build pkg.src.rpm -p fedora --nocheck --nodebuginfo
crbs build pkg.src.rpm -p fedora -D "_smp_mflags=-j16"
crbs build pkg.src.rpm -p fedora --with tests --without docs
crbs build pkg.src.rpm -p fedora --target x86_64_v3 --dist .fc44
```

本地构建默认同步执行；`--detach` 提交到后台后立即返回任务 ID，使用 `crbs status`、`crbs logs <id>`、`crbs cancel <id>` 跟踪与取消。完整命令与选项见 [docs/manual/cli-reference.md](docs/manual/cli-reference.md)。

## Hub 与 Worker

Hub 负责产品、队列、调度、存储与 Web UI；Worker 连接 Hub 并执行构建。两者通过 HTTPS 和 Worker secret 认证。

**Hub**

```bash
# 空库首启自动建立 schema，无需手工初始化
sudo -u crbs-server crbs-server user add admin --role admin
sudo -u crbs-server crbs-server token create admin --name setup --expires 30
sudo -u crbs-server crbs-server worker add worker-01 --arch x86_64
sudo systemctl enable --now crbs-server
```

`crbs-server` 默认监听 `127.0.0.1:9090`（HTTP）。对外提供服务时在 `/etc/crbs/server.toml` 中配置监听地址、TLS 证书与数据库，示例见 [examples/config/server.toml](examples/config/server.toml)。

**Worker**

```toml
# /etc/crbs/worker.toml
hub_url = "https://hub.example.com:18443"
name = "worker-01"
arch = "x86_64"
capacity = 4
token = "crbs_wkr_..."
```

```bash
sudo systemctl enable --now crbs-worker
```

`crbs-server worker add` 输出的 secret 只显示一次；`--output-config` 可直接生成可部署的 `worker.toml`。

**客户端**

```bash
crbs remote add prod --url https://hub.example.com:18443 --token-env CRBS_PROD_TOKEN --use-default
export CRBS_PROD_TOKEN=crbs_tok_...
crbs build pkg.src.rpm -p fedora --remote prod
crbs status --remote prod
crbs logs <id> -f --remote prod
crbs download <id> --remote prod
```

CLI 拒绝向非 loopback 的 `http://` 地址发送 token。部署到互联网前请阅读 [SECURITY.md](SECURITY.md)。

## 配置

配置分三层，优先级为产品配置 > 全局配置 > 内置默认值。

| 文件 | 作用 |
|------|------|
| `/etc/crbs/crbs.toml` | 引擎全局配置：路径、构建用户、缓存、GC、默认后端、重试策略 |
| `/etc/crbs/products/<product>.toml` | 产品配置：`base_packages`、`repos` 必填，其余字段按需覆盖全局值 |
| `/etc/crbs/server.toml` | Hub 配置：监听地址、TLS、数据库、调度与保留策略 |
| `/etc/crbs/worker.toml` | Worker 配置：Hub 地址、架构、并发容量、secret |

完整字段与默认值见 [docs/manual/configuration.md](docs/manual/configuration.md)，示例见 [examples/config/](examples/config/)。配置 schema 可通过 `crbs config schema` 导出。

默认容器后端为 `nspawn`，可在全局或产品配置中改为 `chroot`，也可用 `--backend` 临时覆盖。nspawn 支持 `--memory-max`、`--cpu-quota` 资源限制；chroot 不提供 cgroup 边界。

## HTTP API

`crbs-server` 提供 RESTful API，覆盖构建提交与查询、日志流、产物下载、构建对比、批次重建、产品管理、GC 与指标。健康检查、版本、状态摘要与公开下载等端点可匿名访问，其余端点要求 `Authorization: Bearer crbs_tok_...`；匿名可见范围受 `[public_access]` 控制。

```bash
curl -X POST http://127.0.0.1:9090/api/v1/builds \
  -H "Authorization: Bearer crbs_tok_xxx" \
  -H "Content-Type: application/json" \
  -d '{"product":"fedora","srpms":["/path/to/pkg.src.rpm"],"stage":"bb"}'
```

完整端点、请求体、错误码与示例见 [docs/architecture/api.md](docs/architecture/api.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/manual/README.md](docs/manual/README.md) | 运维手册入口 |
| [docs/manual/build.md](docs/manual/build.md) | 构建流程、产物、确定性构建与常见问题 |
| [docs/manual/deploy.md](docs/manual/deploy.md) | 部署形态、单机与分布式部署、升级回滚 |
| [docs/manual/configuration.md](docs/manual/configuration.md) | 配置字段与默认值 |
| [docs/manual/operations.md](docs/manual/operations.md) | 日常运维、备份恢复、故障排查 |
| [docs/manual/cli-reference.md](docs/manual/cli-reference.md) | CLI 命令与选项参考 |
| [docs/manual/faq.md](docs/manual/faq.md) | 常见问题 |
| [docs/operations/product-management.md](docs/operations/product-management.md) | 产品继承、ACL、发布与转让 |
| [docs/architecture/api.md](docs/architecture/api.md) | HTTP API 参考 |
| [docs/architecture/hub-worker.md](docs/architecture/hub-worker.md) | Hub/Worker 架构与通信 |
| [docs/architecture/database-schema.md](docs/architecture/database-schema.md) | 数据库 schema |
| [packaging/PACKAGING.md](packaging/PACKAGING.md) | RPM 打包与 systemd 单元 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献流程 |
| [SECURITY.md](SECURITY.md) | 信任模型、安全部署与漏洞报告 |

## 许可证

[Mulan Permissive Software License v2](LICENSE)（MulanPSL-2.0）
