# 远程 Base OS 重建

`crbs admin init` 用于从 hub 远程触发指定 worker 重建 base OS。适用场景：产品依赖发生系统级变化、worker 环境损坏或不一致、需要让安全补丁在所有构建环境生效、多架构环境同步 base OS 版本。

仅 admin 角色可执行：

```bash
crbs whoami --remote your-hub   # 返回结果应包含 "role": "admin"
```

## 1 查看 worker

在 hub 上列出已注册 worker：

```bash
crbs-server worker list
```

```
id  name        arch         capacity  status   has_secret
1   worker-01   x86_64       8         online   true
2   worker-02   aarch64      4         online   true
3   worker-03   loongarch64  2         offline  true
```

`-w` 接受输出中的数字 `id`。

## 2 触发重建

```bash
# 指定一个或多个 worker（重复 -w）
crbs admin init fedora --remote your-hub -w 1
crbs admin init fedora --remote your-hub -w 1 -w 2

# 所有当前在线 worker（交互确认；-y 跳过）
crbs admin init fedora --remote your-hub --all
```

`-w` 与 `--all` 互斥；两者都未指定时命令报错（`either --all or one or more -w <ID> is required`），不会默认全量派发。

## 3 执行流程

```
Admin CLI ──> Hub ──> assignment 长轮询通道 ──> Worker
                                              ├── Hub 事务内 409 gate（派发前）
                                              ├── init(force)：临时目录全新安装
                                              ├── 成功后 rename 原子换入 base_os
                                              └── 上报完成状态
```

- **派发前 409 gate**：该 worker 上同一 product 存在活跃构建（`assigned` / `running`）时，hub 拒绝派发并返回 409；其它 product 不受影响，在途构建不会被打断。
- **原子重建**：先在临时目录完整安装（dnf 安装全部包），成功后 rename 换入 base_os；失败只清理临时目录，旧 base_os 保持可用。
- **派发暂停**：init 期间按 (worker, product) 粒度暂停该产品的新任务；同一 worker 上其它产品正常调度。
- 完成后 assignment 状态解除；失败后 gate 同样解除（fail-open），pending 构建使用旧 base_os 继续。
- 建议在业务低峰期执行。

## 4 失败处理

```bash
journalctl -u crbs-worker -f   # 查看 worker 日志
```

确认 worker 能访问软件源与 DNS 后，重试对应 worker：

```bash
crbs admin init fedora --remote your-hub -w <worker_id>
```

init 任务没有独立的超时参数（不存在 `reinit_timeout_secs` 配置项），生命周期由 assignment 状态机与 worker 心跳回收控制：worker 停止心跳后判定 offline，未完成的 assignment 由调度器按心跳超时回收。部署与升级流程见 [`../manual/deploy.md`](../manual/deploy.md) §8.3。
