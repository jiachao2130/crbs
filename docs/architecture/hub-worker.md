# Hub 与 Worker 通信

Worker 是无监听端口的纯 poller：所有连接由 worker 主动发起，hub 不能主动推送。唯一的例外是取消指令，搭心跳响应下行。

## 1 通道

| 方向 | 端点 | 用途 |
|------|------|------|
| worker → hub | `GET /api/v1/workers/{id}/assignments?wait=N` | 长轮询领取任务（claim 语义）；无任务返回 204 |
| worker → hub | `POST /api/v1/workers/{id}/assignments/{aid}/result` | 上报任务终态与资源采样 |
| worker → hub | `POST /api/v1/workers/{id}/assignments/{aid}/logs` | 追加日志 chunk |
| worker → hub | `POST /api/v1/workers/{id}/heartbeat` | 心跳、负载遥测；响应携带已取消任务列表 |
| worker → hub | `POST /api/v1/workers/register` | 注册或更新节点信息 |

`wait` 默认 30 秒、上限 120 秒。所有"worker 本人"端点校验路径 `id` 与 token 绑定的 worker 一致。

## 2 Assignment 生命周期

1. `GET assignments` 即领取：hub 在事务内以 CAS 将 `worker_tasks.status` 置 `running`、对应 build 置 `building`，防止双领。
2. 任务体携带 `kind`、`assignment_id`、`build_id`、`task_id`、`product`、`srpm_url`、`build_options`、`product_config` 等字段；复现任务另带 `reproduce_packages_url`，init 任务带 `init_product`。
3. Worker 执行完毕后 `POST result` 上报 `succeeded` / `failed` / `cancelled` / `timeout`，附 `result_dir`、`error`、`notes` 与资源采样。重复上报终态返回 409。
4. 领取响应丢失时，hub 在 `wait` 到期路径重新投递该 `running` assignment，任务体带 `redelivered` 标记。
5. 终态 assignment 拒绝追加日志（409）。

## 3 心跳与取消

- 心跳周期默认 30 秒；hub 超过 120 秒无心跳将 worker 标记 offline。心跳携带 `load1`、`ncpu`、`mem_used_pct`、`mem_total_kb`、`disk_free_kb` 等遥测。
- 取消不单独建通道：hub 标记 assignment 取消后，在心跳响应 `cancelled_assignments` 中下发；worker 停止对应任务并上报 `cancelled`，延迟不超过一个心跳周期。
- worker offline 后，其未完成的 assignment 由调度器按心跳超时回收。

## 4 管理型 assignment

`kind=init` 的管理型 assignment 复用同一通道，由 `crbs admin init` 触发，worker 收到后执行 `init(force=true)` 原子重建 base OS 并上报结果。

- 派发前有 per-product 409 gate：该 worker 上同一 product 存在活跃构建（`assigned` / `running`）时 hub 拒绝派发。
- init 在途期间，dispatch 按 (worker, product) 排除该产品的新构建；同 worker 同产品同时仅允许一个 init（`uq_worker_tasks_active_init` 索引兜底）。
- init 完成或失败后 gating 随 assignment 终态自动解除，不影响 worker.status。

## 5 模型边界

Pull 模型的好处：worker 无需开放端口、可位于 NAT 之后、hub 不维护长连接、扩容只需注册新节点。

代价：

- 指令延迟至少一个轮询周期；hub 只能在 worker 拉取或心跳时搭载下行消息。
- 实时可观测性有限：日志按 chunk 上报，构建进度与资源指标依赖心跳。
- 每个 worker 占用一个长轮询连接，规模上限由 hub 连接与内存容量决定。
- 远程升级、重启、构建迁移等操作没有专用下行通道；当前仅 init 与取消可由 hub 发起。

是否需要迁移到持久双向连接（WebSocket / gRPC stream），取决于实时推送、构建迁移/抢占、频繁远程管理等需求是否同时出现。

## 6 相关文档

- HTTP 端点与认证：[api.md](api.md)
- `worker_tasks` 等表结构：[database-schema.md](database-schema.md)
- 远程 init 操作：[../operations/admin-init-and-reinit.md](../operations/admin-init-and-reinit.md)
