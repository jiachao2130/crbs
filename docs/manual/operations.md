# CRBS 运维手册

> 本文适用于 0.1.0。安装与升级见 [`deploy.md`](deploy.md)，命令全量参考见
> [`cli-reference.md`](cli-reference.md)。

## 1. 日常巡检

### 1.1 HTTP 端点

以下路径均相对 hub 地址，示例使用 `https://hub.example.com:18443`，实际
替换为部署地址。

| 端点 | 认证 | 内容 |
|------|------|------|
| `GET /api/v1/health` | 公开 | 存活探测，返回 `{"status":"ok"}` |
| `GET /api/v1/health?deep=1` | 公开 | 就绪探测，追加 DB ping，失败返回 503 |
| `GET /api/v1/version` | 公开 | 服务版本 |
| `GET /api/v1/status` | 公开 | 任务计数与在线 worker 数，按匿名视角过滤私有产品 |
| `GET /api/v1/metrics` | operator+ | uptime、并发、队列、磁盘可用、OOM 分类与画像学习计数 |
| `GET /metrics` | 公开 | Prometheus 文本格式指标 |

```bash
HUB=https://hub.example.com:18443
curl -s --cacert /etc/crbs/certs/ca.crt "$HUB/api/v1/health"
curl -s --cacert /etc/crbs/certs/ca.crt "$HUB/api/v1/status" | jq
curl -s -H "Authorization: Bearer crbs_tok_..." \
     --cacert /etc/crbs/certs/ca.crt "$HUB/api/v1/metrics" | jq
```

`/metrics` 匿名可读；经反向代理对外暴露时应自行加访问控制。

### 1.2 Web UI

仪表盘 `/ui/` 提供任务计数、成功率（最近 200 条可见任务）、系统资源行
（operator+）与 worker 负载。复现率看板 `/ui/reproducibility` 需登录，
展示 deterministic 产品的重放比对结果，按调用者可见产品过滤；同源 API
为 `GET /api/v1/reproducibility/stats`。

复现比对记录的生命周期随 source 构建行保留：source 行被 retention 删除时
比对记录级联删除；重放构建行被删除时仅清空引用，记录本身保留。排查历史
diff 前先确认 source 构建行仍在保留期内。

### 1.3 日志

```bash
journalctl -u crbs-server -f              # 实时
journalctl -u crbs-server --since today   # 当天
journalctl -u crbs-worker -f              # worker 节点
```

构建日志在任务详情页流式查看，或使用
`crbs logs <id> -f --remote <hub>`。日志中的 token 默认脱敏
（`log_sanitization.redact_tokens = true`）。

### 1.4 巡检清单

- health 与 status 正常，failed 数无异常增长。
- metrics 中磁盘可用量高于 `min_free_disk_gb`。
- worker 全部 online（`/api/v1/status` 的 `workers.online` 或 Workers 页）。
- journal 无持续 WARN/ERROR，重点检查 priv-helper 权限拒绝与上传失败。

## 2. 用户与 token

### 2.1 CLI

在 hub 主机以 `crbs-server` 身份执行：

```bash
# 用户
sudo -u crbs-server crbs-server user add alice --role builder
sudo -u crbs-server crbs-server user list
sudo -u crbs-server crbs-server user set-role alice operator
sudo -u crbs-server crbs-server user disable alice

# token（创建时一次性打印）
sudo -u crbs-server crbs-server token create alice -n laptop --expires 30
sudo -u crbs-server crbs-server token list alice
sudo -u crbs-server crbs-server token revoke alice --id 1
```

- token 格式为 `crbs_tok_...`，仅在创建时显示一次，`list` 只返回元数据。
- `--expires` 单位为天，上限 3650；缺省永不过期。
- 禁用用户后无法再签发 token，已有 token 随用户失效。
- 产品级授权：`crbs-server product acl grant <product> <user> --role viewer|builder|admin`。

### 2.2 角色权限

高层级包含低层级：

| 能力 | viewer | builder | operator | admin |
|------|:------:|:-------:|:--------:|:-----:|
| 查看公共 UI / 日志 / 下载（匿名亦可，受 `public_access` 控制） | ✓ | ✓ | ✓ | ✓ |
| 查看可见产品内的构建记录 | ✓ | ✓ | ✓ | ✓ |
| 提交构建 | ✗ | ✓ | ✓ | ✓ |
| 取消构建 | ✗ | 本人任务 | 全部 | 全部 |
| 仪表盘系统行 / metrics / GC 管理页 | ✗ | ✗ | ✓ | ✓ |
| 触发构建签名 | ✗ | ✗ | ✓ | ✓ |
| 整仓重建批次 | ✗ | ✗ | ✓ | ✓ |
| 复现率看板 | ✓（仅可见产品） | ✓ | ✓ | ✓ |
| 调整构建优先级 | ✗ | ✗ | ✓ | ✓ |
| 产品 init / delete / clean | ✗ | ✗ | ✗ | ✓ |
| 用户 / token / worker / UI 管理页 | ✗ | ✗ | ✗ | ✓ |

读边界由产品可见性决定（owner、public、ACL），不按提交者收窄。提交侧
唯一限制是用户在该产品上仅有 viewer 授权（只读）。产品网页新建对 builder
及以上开放（builder 创建的产品强制 private），配置编辑限 owner/admin。
详见 [`../operations/product-management.md`](../operations/product-management.md)。

### 2.3 token 分发与 Web 登录

用户端将 token 写入 profile，推荐使用环境变量：

```toml
# ~/.config/crbs/crbs.toml
[remote]
default = "hub"

[[remote.profiles]]
name = "hub"
url = "https://hub.example.com:18443"
token_env = "CRBS_TOKEN"
ca_cert = "/etc/crbs/certs/ca.crt"
```

CLI 拒绝将 token 发往非 loopback 的 `http://` 地址，避免明文泄漏。

Web UI 登录支持粘贴 token，或使用用户名与密码。`user add` 创建的用户默认
无密码，root 可设置：

```bash
echo "<password>" | sudo /usr/bin/crbs-server user set-password <user>
```

## 3. 产品管理

产品配置的权威源是 hub 数据库（`products.config_json`）。
`/etc/crbs/products/*.toml` 仅用于首次 seed 与 `export`，直接修改磁盘文件
不会生效。变更统一走 CLI、HTTP API 或 Web UI。

```bash
crbs products --remote hub
crbs products show <product> --remote hub
crbs products update <product> --config-file new.toml \
    --expected-revision <N> --remote hub
```

CRUD、fork 与继承、可见性、ACL、回滚流程见
[`../operations/product-management.md`](../operations/product-management.md)；
base OS 重建见 [`deploy.md`](deploy.md) §8.3 与
[`../operations/admin-init-and-reinit.md`](../operations/admin-init-and-reinit.md)。

## 4. 构建任务运维

### 4.1 提交、跟踪与取消

```bash
# 提交（--detach 立即返回任务 ID）
crbs build pkg.src.rpm -p <product> --remote hub
crbs build pkg.src.rpm -p <product> --remote hub --detach

# 跟踪与取消（远程使用完整数字 server task id）
crbs status --remote hub
crbs logs --task <id> -f --remote hub
crbs cancel <task_id> --remote hub
```

重跑与复现可从任务详情页操作，或使用
`crbs build --rebuild <task_id>`（服务端重放原任务选项）与
`crbs build --reproduce <task_id>`。远程构建的 CLI 额外参数在 rebuild 时
无效；复现语义见 [`build.md`](build.md) §9、§10。

任务标签：提交时用 `--label KEY=VALUE`（可重复）附加不透明元数据，便于按
来源或批次归档。`crbs status --label KEY=VALUE`、任务列表页 Labels 输入框
按标签精确过滤，任务详情页徽章点击即跳转过滤；校验与用量见
[`build.md`](build.md) §11.1。

提交期即执行架构约束检查：`--arches` 与 SRPM 的 `ExclusiveArch` /
`ExcludeArch` 冲突时默认拒绝整单，加 `--skip-unsupported-arches` 可跳过
冲突架构；`--target` 按字面精确比对，不在产品构建架构集合内的 target
同样在提交期拒绝。

### 4.2 整仓重建（operator+）

按源仓库批量重建产品存量包：

```bash
# 预览计划
crbs rebuild submit -p <product> --repo <url> --dry-run --remote hub

# 提交（--force 忽略增量缓存，--on-failure abort 失败即停）
crbs rebuild submit -p <product> --repo <url> --remote hub

# 跟踪与取消
crbs rebuild status --id <id> --follow --remote hub
crbs rebuild cancel --id <id> --remote hub
```

- `--repo` 必须指向含 `repodata/` 的仓库层（如发布仓的 `SRPMS` 子仓）。
- 增量跳过按包名判断：产品下已有 succeeded 构建的包默认跳过。
- 批次内每个包落为普通 task/build，签名、溯源与发布语义与单任务一致。

### 4.3 构建签名

构建默认不签名（builder/worker 无钥）。发布签名由 operator/admin 显式
触发，私钥仅存于 hub。

密钥管理（在 hub 主机以 `crbs-server` 身份执行，默认 keyring
`/var/lib/crbs-gnupg`）：

```bash
# 初始化 keyring 并导入 ASCII-armored 私钥
sudo install -d -o crbs-server -g crbs -m 0700 /var/lib/crbs-gnupg
sudo -u crbs-server GNUPGHOME=/var/lib/crbs-gnupg \
    crbs-server gpg import --key-file key.asc

# 查看 key ID
sudo -u crbs-server GNUPGHOME=/var/lib/crbs-gnupg crbs-server gpg list

# 导出公钥，供消费方 rpm --import
sudo -u crbs-server GNUPGHOME=/var/lib/crbs-gnupg \
    crbs-server gpg export --armor > RPM-GPG-KEY-crbs
```

在产品配置中设置 `gpg_signing_key_id = "<key fpr>"` 后，对完成任务触发：

```bash
crbs sign <task_id> --remote hub --token <operator-token>
```

签名仅对 succeeded 构建生效，幂等；签名后自动刷新哈希、设置 `signed`
标记并重建发布仓，操作写入审计。私人产品（fork 或衍生）拒绝使用官方
私钥签名。builder 与 worker 侧无密钥，构建期签名会自动跳过。

消费方验签：

```bash
rpm --import RPM-GPG-KEY-crbs
dnf install --enablerepo=<product-repo> --setopt=<repo>.gpgcheck=1 <pkg>
```

### 4.4 GC 与保留

三套机制相互独立：

| 机制 | 配置 | 触发 | 作用对象 |
|------|------|------|----------|
| result GC（宽限期） | `result_gc_grace_hours`（crbs.toml，默认 720h） | 手动 `crbs gc --results` | 超期已完成构建的 result 目录，DB 行保留 |
| result GC（策略） | `result_max_count_per_pkg` / `result_retention_days` | `crbs gc --policy`，或配置策略后的裸 `crbs gc` | 按条数或天数清理 result 目录 |
| DB 行保留 | `db_retention_days`（server.toml，默认 90） | 后台每日自动 | 超期 audit_logs / worker_tasks / builds / tasks 行，仅限目录已清理的记录 |

Web 入口为 `/ui/admin/gc`（operator+），可组合 results、orphan-mounts、
cache、policy，默认勾选 dry-run。操作惯例是先预览再执行：

```bash
crbs gc --results --dry-run
crbs gc --results
```

`crbs gc --cache --all` 会跳过 DB 引用检查删除整个包缓存，导致历史构建
无法 `--reproduce`，应避免在生产使用。

### 4.5 僵尸记录修复

server 与 worker 启动时都会扫描本地状态库，将属主进程已不存在的
building/pending 记录标记为 failed，断电或 SIGKILL 后的任务无需人工清理。
本地残留仍可用 `crbs status --repair` 修复。

### 4.6 构建调试

`crbs debug` 复现指定构建的环境，并自动完成 rpmbuild 之前的准备：
读取该构建留档的 `result_dir/crbs-build.sh`，截断到 build 步骤之前执行。
进入 shell 时 SRPM 已解包、依赖已安装。

```bash
crbs debug <build-id>                                     # 交互 shell
crbs debug <build-id> -c 'ls /builddir'                   # 执行单条命令
crbs debug <build-id> --bind /tmp/repro:/mnt/repro:rw     # 挂载宿主目录
```

- `<build-id>` 是本地构建 ID（`crbs status` 第一列），不是远程 task id；
  任务必须已结束。
- 必须使用构建时记录的 backend（nspawn / chroot）。
- 准备步骤失败不阻断：告警后进入裸环境 shell，可对照 `/crbs-build.sh`
  手动重放。
- 完整参数见 [`cli-reference.md`](cli-reference.md) 的 `crbs debug` 一节。

## 5. 备份与恢复

### 5.1 备份范围

| 路径 | 内容 | 建议频率 |
|------|------|----------|
| `/var/lib/crbs/crbs.db`（含 WAL） | 用户、token、worker secret、任务、产品配置 | 升级前及定期 |
| `/etc/crbs/` | server.toml、crbs.toml、priv-helper.toml、products | 配置变更后 |
| `/var/lib/crbs/results`、`artifacts` | 构建产物 | 按需 |
| 产品配置逻辑备份 | `crbs products export <p> --remote hub` | 产品变更后 |

### 5.2 SQLite 在线备份

`crbs.db` 使用 WAL 模式，直接复制可能得到不一致快照，应使用在线备份：

```bash
sudo -u crbs-server sqlite3 /var/lib/crbs/crbs.db \
     ".backup '/var/lib/crbs/crbs.db.bak-$(date +%Y%m%d)'"
```

升级前导出所有产品配置：

```bash
for p in $(crbs products --remote hub); do
  crbs products export "$p" --remote hub > "/root/products-$p.toml"
done
```

### 5.3 恢复

```bash
sudo systemctl stop crbs-server
sudo cp /var/lib/crbs/crbs.db.bak-YYYYMMDD /var/lib/crbs/crbs.db
sudo rm -f /var/lib/crbs/crbs.db-wal /var/lib/crbs/crbs.db-shm
sudo chown crbs-server:crbs /var/lib/crbs/crbs.db*
sudo systemctl start crbs-server
```

跨版本恢复（回滚到旧二进制）需将数据库还原到升级前的备份，见
[`deploy.md`](deploy.md) §8.2。

## 6. 故障排查

| 症状 | 可能原因 | 处置 |
|------|----------|------|
| 启动报 bind / address already in use | 端口被占用 | `ss -ltnp \| grep <port>` 定位，修改 `server.toml` 的 `listen` 后重启 |
| 特权操作报 `permission denied: config file/dir` | `/etc/crbs` 权限不满足 priv-helper 校验 | 按 [`deploy.md`](deploy.md) §2.2 恢复 `0750` 目录与 `0640 root:crbs` 文件 |
| 启动时写 `/var/lib/crbs` 失败 | 数据库或 WAL 属主漂移 | `sudo chown crbs-server:crbs /var/lib/crbs/crbs.db*` 后重启 |
| API 返回 503 `service_unavailable` | SQLite 写锁竞争超时，或 PostgreSQL 磁盘/内存耗尽 | 检查 DB 所在磁盘与内存；查看 `journalctl -u crbs-server` 中的具体错误 |
| API 返回 500 `database_error` | 单次 SQL 语义故障 | CLI 映射退出码 6；持续出现时查 journal 定位 SQL 调用点 |
| worker 一直 offline | secret 错误、hub 不可达、CA 不受信任 | 查看 worker 日志与 `crbs-server worker list`；secret 丢失用 `worker rotate-secret <name>` |
| 任务长期 pending | 无匹配架构或容量的在线 worker，或 `scheduler_mode` 配置不符预期 | 查看 Workers 页负载与调度模式 |
| 构建日志含 EROFS | 自定义路径未加入 systemd `ReadWritePaths` | `systemctl edit` 对应服务追加路径 |
| 构建失败，日志含 stalled storage | worker 本地存储（如 NFS）停滞 | 检查挂载与读性能后重试 |
| 提交偶发 HTTP 500 | multipart 上传流中断 | CLI 自动重试 500/503；持续出现时检查网络与反向代理 |
| UI 404 或无法打开 | `web_ui_enabled = false`，端口或防火墙配置错误 | 检查配置与 `/api/v1/health` |
| CLI 返回 401 | token 过期、撤销或用户被禁用；或向非 loopback HTTP 发送 | 核对 token 状态，改用 HTTPS |
| CLI 报 hub-first 配置错误 | 产品不在 hub DB，或 hub 不可达 | `crbs products create` 入库，或加 `--offline` 读磁盘 |
| 磁盘持续增长 | results、cache、shared layers 未清理，或 journal 无配额 | 按 §4.4 执行 GC，配置 retention 与 journald `SystemMaxUse` |
| 回滚后 server 拒绝启动 | 新版数据库 schema 高于旧二进制预期 | 停服，还原升级前备份，再启动旧版本 |
| 批量构建出现 dnf 事务冲突、错版包 | 产品 dist 宏与 base_os 发行版不一致 | 核对产品 dist 宏与 base_os 发行版，重建 base_os |
| 重放命中 provenance 硬门 | 重放环境账目与被重放构建记录不一致 | 确认违例包是否属于该构建；旧构建缺溯源锚时重建基线 |
| 重放日志含 `GPG check FAILED` | 外部镜像启用了全局签名强制策略 | 升级到已中和该策略的版本 |

## 7. TLS 直连

对外服务应使用 HTTPS。两种方式：反向代理终止 TLS（`force_secure_cookies
= true` 必开），或使用内置 `[tls]` 直连。hub 与 worker 之间存在长轮询、
SSE 和无心跳的日志跟随流，直连可省去反向代理的超时与缓冲调参。

```toml
# /etc/crbs/server.toml
listen = "0.0.0.0:443"

[tls]
cert = "/etc/crbs/certs/server.crt"
key  = "/etc/crbs/certs/server.key"
```

- systemd unit 已授予 `CAP_NET_BIND_SERVICE`，非 root 的 `crbs-server`
  可绑定低端口。
- `NoNewPrivileges` 必须保持关闭（setuid 的 priv-helper 依赖 setuid
  exec），不要收窄 `CapabilityBoundingSet`。
- 证书 SAN 必须覆盖客户端实际访问的主机名与 IP。rustls 严格校验 SAN，
  `curl -k` 通过不代表 CLI 可用。
- 启用内置 `[tls]` 后 session cookie 自动带 `Secure`，无需再设
  `force_secure_cookies`。

证书生成与完整配置见 [`deploy.md`](deploy.md) §5。

## 8. 安全要点

- token 仅显示一次，不落日志（默认脱敏）。泄漏后立即
  `token revoke` 或 `worker rotate-secret`。
- `auth_enabled` 保持 `true`；关闭仅限 loopback 开发场景。
- `public_access` 默认 view/logs/download 全开，面向不可信网络时应全部
  关闭。SRPM 下载另有独立开关 `allow_srpm_download`，关闭后仅
  operator/admin 可下载源码包。
- 多租户部署必须使用 `backend = "nspawn"`；chroot 后端下任何可提交构建
  的用户等价于宿主 root。
- CSP 中 `script-src` 以 nonce 为主防线；`style-src 'unsafe-inline'` 为
  兼容浏览器扩展的注入样式而保留，页面输出经全量转义。
- 管理操作（提交、取消、优先级、GC、产品变更等）均写审计，可通过
  `crbs-server audit list --user <u>` 或 `/ui/admin/audit` 查询。
- 上线前核对 [`../../SECURITY.md`](../../SECURITY.md) 与
  [`deploy.md`](deploy.md) §10 安全清单。

## 9. 资源感知调度

`server.toml` 的 `resource_steering_enabled`（默认 `false`）启用后，重型
构建候选按归一化资源余量评分选择节点，而不是固定选择 least-loaded 序列
首位。关闭该开关即回到默认调度行为，无需回退代码。

开启后可通过 `GET /metrics` 与 `GET /api/v1/metrics` 对比以下指标：
重型构建排队时长、`crbs_dispatch_no_candidate_ticks_total`、
`crbs_build_oom_total{kind}`、`crbs_dispatch_soft_fallbacks_total` 与
`crbs_dispatch_admit_rejects_total{dimension}`。若指标未改善或出现恶化，
将 `resource_steering_enabled` 改回 `false` 并重启。

## 10. 相关文档

- [`README.md`](README.md)：手册索引
- [`deploy.md`](deploy.md)：部署、升级与配置
- [`configuration.md`](configuration.md)：配置参考
- [`cli-reference.md`](cli-reference.md)：CLI 命令参考
- [`../operations/product-management.md`](../operations/product-management.md)：产品管理
- [`../operations/admin-init-and-reinit.md`](../operations/admin-init-and-reinit.md)：base OS 重建
- [`../../SECURITY.md`](../../SECURITY.md)：安全策略
