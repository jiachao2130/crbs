# 安全说明

本文说明 CRBS 的信任模型、默认安全配置与部署边界，目标读者是部署和运维 crbs-server 的管理员，以及评估引入 CRBS 的安全负责人。实现细节以代码为准。

## 1 威胁模型与部署场景

CRBS 的默认配置面向内网 RPM 构建仓（类似 Koji）：多名工程师提交 SRPM，一个仓库对内公开只读。

| 场景 | 默认是否适用 | 关键配置 |
| --- | --- | --- |
| 单机私有构建 | 是 | 可设 `auth_enabled = false`，此时 bootstrap 强制 loopback 监听 |
| 内网多用户构建 | 是 | 保留默认 `public_access`；前置 nginx 终止 TLS，并设 `force_secure_cookies = true` |
| 多租户 / 公网 | 否，需收紧 | 见下 |

多租户或暴露于不可信网络时必须额外收紧：

- `[public_access]` 的 `view`、`logs`、`download` 全部设为 `false`。
- 产品配置使用 `backend = "nspawn"`；chroot 后端不可用于多租户。
- 在反向代理层对 `/ui/login` 与认证失败路径限流。
- 定期轮换用户 token 与 worker secret。

## 2 认证与授权

### 2.1 用户认证

- 不透明 Bearer token，前缀 `crbs_tok_`，256 位熵，服务端仅存 SHA-256 哈希。
- 通过 `Authorization: Bearer <token>` 传递；Web UI 使用 `crbs_session` HttpOnly cookie。
- 不要把 token 放入 URL 查询串、日志或长期明文文件；profile 的 `token_file` 除外。
- 轮换：`crbs-server token list <user>` 查询 ID，`token revoke <user> --id <id>` 吊销，`token create <user>` 重新签发。

### 2.2 Worker 认证

- 不透明 secret，前缀 `crbs_wkr_`，256 位熵，DB 中存 SHA-256。
- worker 不开放入站端口，也不自注册；管理员通过 `crbs-server worker add` 创建，`worker rotate-secret` 轮换，`worker remove` 撤销。
- worker 通过长轮询拉取任务；`crbs admin init` 的管理型任务复用同一通道。

### 2.3 角色与 ACL

- 角色：`admin` > `operator` > `builder` > `viewer`；worker 为隐式机器身份。
- 产品是唯一读写边界：public 产品对所有身份可读；private 产品仅 owner、operator、admin 与持 ACL 者可见。可见即见该产品全部构建与任务，不按提交者隔离。
- 提交需 builder+；private 产品还要求产品可见或持 builder ACL。viewer ACL 只读。
- 取消、发布翻转、签名等操作要求 operator+ 或构建提交者本人；无归属记录仅 operator/admin 可操作。

### 2.4 CSRF

- Web UI 表单采用双提交：`crbs_csrf` cookie 与表单 hidden `csrf_token`。
- Token 为 `HMAC-SHA256(csrf_key, session_token)`；`csrf_key` 位于 `<crbs_root>/csrf_key`（0600）。
- JSON API 使用 Bearer 头认证，不依赖 cookie，因此不附加 CSRF。

## 3 信任边界

以下行为属于设计边界，不是缺陷。

- **chroot 后端 = 单租户**：容器内进程与服务用户等价 root，可读写宿主 `/etc/crbs`、GPG 密钥与 result_dir。多租户必须使用 nspawn；`auth_enabled = true` 且全局 backend 为 chroot 时，server 启动会打印警告。
- **`relax_config_permissions` 是降权口子**：开启后 priv-helper 不再强制 `/etc/crbs/*.toml` 的 root / 0640 权限，仅限受控的单租户或开发环境。
- **GPG 私钥与服务端同用户存放**：生产环境应将私钥单独存放并设为 0600，定期轮换与离线备份；日志默认脱敏 token。
- **priv-helper**：umount 目标限定在允许的临时目录域；mount 的 data 参数按合法取值校验；mkdir/chown/write-file/chmod/rm-rf 均 fd 锚定；spawn-dnf 在 exec 前设置 `SECBIT_NOROOT`，阻断 scriptlet 通过 setuid-root 或 file capability 提权。rpm scriptlet 需要 `SYS_CHROOT`，双 chroot 逃逸仍是已知架构级边界。
- **worker 以非特权用户运行**：特权操作（mount/chroot/nspawn）由 setuid helper 代理，取消构建同样经 helper 完成。
- **审计**：管理操作写入 `audit_logs`，可用 `crbs-server audit list` 或 Web UI 的审计页查询。

## 4 传输层与 Cookie

### 4.1 TLS

- 内置 TLS：`[tls] cert` / `key`，server 直接终止 HTTPS。
- 推荐形态：nginx 前置终止 TLS，server 监听 loopback HTTP。配置示例见 [`examples/nginx/crbs.conf`](examples/nginx/crbs.conf) 与 [`docs/manual/deploy.md`](docs/manual/deploy.md) §5。

### 4.2 Cookie `Secure`

server 在以下任一条件下为 session cookie 加 `Secure`：

1. 启用内置 `[tls]`；
2. `force_secure_cookies = true`。

nginx 前置 TLS 时必须设 `force_secure_cookies = true`，否则 cookie 缺少 `Secure`，可能经明文链路回传。

### 4.3 CLI token 明文防护

CLI 拒绝向非 loopback 的 `http://` 主机发送 Bearer token：

```
refusing to send bearer token over plaintext http:// to non-loopback host `<host>`;
use `https://<host>` (recommended) or set `CRBS_ALLOW_PLAINTEXT_TOKEN=1` to override (not recommended)
```

loopback 通信与无 token 的匿名访问不受影响。`CRBS_ALLOW_PLAINTEXT_TOKEN=1` 仅用于受控内网诊断，会记录警告日志。

## 5 公开访问

以下三项默认开启，与 Koji / OBS 的公开构建行为一致：

| 配置 | 默认 | 影响 |
| --- | --- | --- |
| `public_access.view` | true | 匿名可查看任务与构建列表、详情页 |
| `public_access.logs` | true | 匿名可读构建日志（可能包含环境变量、路径、用户名） |
| `public_access.download` | true | 匿名可下载 RPM / SRPM 产物 |

多租户或日志含敏感信息的部署必须把三项全部设为 `false`。写操作始终需要认证。

## 6 限流

应用层内置提交限流（`submit_rate_limit`，默认关闭），按用户固定窗口计数，作用于 `POST /api/v1/builds` 与 `POST /api/v1/tasks/{id}/rebuild|reproduce`；worker 认证路径豁免。进程内存态，多实例各自计数。

```toml
[submit_rate_limit]
enabled = true
requests = 30
per_secs = 60
```

登录与认证路径建议在 nginx 限流：

```nginx
limit_req_zone $binary_remote_addr zone=crbs_login:10m rate=6r/m;

location = /ui/login {
    limit_req zone=crbs_login burst=3 nodelay;
    proxy_pass http://127.0.0.1:9090;
}
```

## 7 无认证模式

`auth_enabled = false` 关闭全部认证，仅用于个人开发。server 启动时校验监听地址必须为 loopback，否则拒绝启动；多网卡机器应显式配置 `listen = "127.0.0.1:9090"`。

## 8 安全清单

- [ ] 生产环境使用 HTTPS；反代终止 TLS 时开启 `force_secure_cookies`。
- [ ] 按部署场景设置 `public_access` 三项。
- [ ] 多租户产品使用 nspawn 后端。
- [ ] `/etc/crbs` 目录 `0750 root:crbs`，配置文件 `0640 root:crbs`。
- [ ] worker secret 与用户 token 定期轮换，离职人员及时禁用并吊销 token。
- [ ] 开启审计日志查询，定期检查异常操作。
- [ ] 不把 token 写入 URL、日志或镜像层。

## 9 漏洞报告

请勿在公开 issue 中披露安全问题。请通过仓库维护者提供的私有渠道报告，并附受影响版本、复现步骤、影响评估与可能的修复建议。维护者确认后会协调修复与披露时间。

## 10 相关文档

- 部署与 TLS：[`docs/manual/deploy.md`](docs/manual/deploy.md)
- 日常运维与故障排查：[`docs/manual/operations.md`](docs/manual/operations.md)
- 配置参考：[`docs/manual/configuration.md`](docs/manual/configuration.md)
- HTTP API：[`docs/architecture/api.md`](docs/architecture/api.md)
