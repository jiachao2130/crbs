# 运维手册

本手册面向部署与运维人员，覆盖构建、部署、配置、日常操作与故障处理。适用版本 0.1.0。

## 手册目录

| 文档 | 内容 |
|------|------|
| [build.md](build.md) | 构建流程、构建路径、产物结构、确定性构建、常见构建问题 |
| [deploy.md](deploy.md) | 部署形态、单机部署、Hub/Worker 部署、TLS、systemd、升级与回滚 |
| [configuration.md](configuration.md) | `crbs.toml`、产品配置、`server.toml`、`worker.toml` 字段说明 |
| [operations.md](operations.md) | 巡检、用户与 token、产品、构建任务、GC、签名、备份恢复、故障排查 |
| [cli-reference.md](cli-reference.md) | CLI 命令、选项、退出码与 JSON 输出 |
| [faq.md](faq.md) | 常见问题 |

## 相关文档

- 项目入口：[../README.md](../README.md)
- RPM 打包与 systemd 单元：[../../packaging/PACKAGING.md](../../packaging/PACKAGING.md)
- 产品管理：[../operations/product-management.md](../operations/product-management.md)
- base OS 远程重建：[../operations/admin-init-and-reinit.md](../operations/admin-init-and-reinit.md)
- HTTP API：[../architecture/api.md](../architecture/api.md)
- 安全边界：[../../SECURITY.md](../../SECURITY.md)

## 快速验证

```bash
# 进程存活（纯 liveness）
curl http://127.0.0.1:9090/api/v1/health

# 就绪检查（追加数据库 ping）
curl "http://127.0.0.1:9090/api/v1/health?deep=1"

# 命令行连通性与身份
crbs ping --remote <profile>
crbs whoami --remote <profile>
```

## 命令约定

- 所有示例以安装后的二进制路径为准：`/usr/bin/crbs`、`/usr/bin/crbs-server`、`/usr/bin/crbs-worker`。
- `sudo -u crbs-server crbs-server ...` 用于操作 Hub 的数据库与密钥，需与 systemd 单元的运行用户一致。
- 远程命令通过 `--remote <profile|URL>` 指定 Hub；token 优先从环境变量或配置文件读取，避免写入 shell 历史。
