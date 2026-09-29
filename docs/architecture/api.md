# CRBS HTTP API 参考

本文是 crbs-server HTTP API 的现行参考。**代码是唯一权威源**：路由注册在
`crates/crbs-server/src/server/routes/` 与 `crates/crbs-server/src/server/worker/routes/mod.rs`，
`tests/integration_route_inventory.rs` 用探测测试把路由清单钉在真实注册行为上（漂移即红）。
本文与该清单逐端点对齐；不一致时以代码与测试为准。

## 通用约定

- **Base URL**：`http(s)://<host>:<port>`。默认监听 `127.0.0.1:9090`（server.toml
  `server.listen`，纯 HTTP，供反代终止 TLS 的部署）；配置 `[tls]` 后为原生
  HTTPS，内网独占机推荐直连（两种模式见 [`../manual/deploy.md`](../manual/deploy.md) §5）。
- **认证**：`Authorization: Bearer <token>`，两种前缀：
  - `crbs_tok_…`：DB 用户 token（角色 viewer / builder / operator / admin）；
  - `crbs_wkr_…`：worker secret（机器身份，role=worker）。
  无上述前缀一律 401。UI 会话凭据 `crbs_sess_…` **不被 Bearer 接受**，只经
  `crbs_session` cookie 服务 Web UI 页面与 GET 下载；API 写方法只认 Authorization 头。
- **角色阶梯**：viewer < builder < operator < admin（上层继承下层能力）。
- **读可见性**：以产品可见性为唯一边界——public 产品的构建/任务/日志/产物对登录
  builder 与匿名同权可读；private 产品对 owner / operator / admin / 持 ACL 者全量
  可见（含他人提交的记录）。持 ACL 不限制其它 public 产品的提交；private 产品仍需
  链上可见，viewer ACL 禁提交。取消权限不变（operator 或本人；空提交者的遗留记录
  仅 operator/admin 可取消）。
- **产品可见性**：private 产品的构建/任务/配置对无权限者返回 403 或 404（产品
  详情不区分"不存在"与"无权限"）；worker 是机器身份，不走用户产品 ACL。
- **本地开发**：`server.auth_enabled = false` 时整站无认证（仅建议 loopback）。
- **分页**：列表端点通用 `?limit=&offset=`，limit ≤ 200、offset ≤ 1_000_000，
  超限 400。`total` 为过滤后总数。
- **脱敏**：响应不回显服务端绝对路径——`BuildRecord.result_dir` / `srpm_path`
  序列化为 `null`（键保留）。

### 错误信封

handler 内业务错误统一返回 JSON 信封 `{"error": "<机器码>", "message": "<人话>"}`：

| HTTP | error 码 | 典型场景 |
|------|----------|----------|
| 400 | `validation_failed` | 参数校验失败、产品链非法、depsolve 失败 |
| 401 | `unauthorized` | 缺失/无效 token、cookie 认证用于 API 写方法 |
| 403 | `permission_denied` | 已认证但角色/ACL/可见性不足 |
| 404 | `not_found` | 资源不存在（或 private 产品隐藏存在性） |
| 409 | `conflict` | 重复提交活跃构建、终态守卫、revision 冲突、GC 已在跑 |
| 413 | `payload_too_large` | 请求体超限（JSON 提交 >2MB 等） |
| 429 | `too_many_requests` | 限流 |
| 500 | `internal_error` | 服务端内部错误（消息脱敏） |
| 500 | `database_error` | SQL 语义错误（CLI 据此判 ENVIRONMENT=6 可重试） |
| 503 | `service_unavailable` | 数据库不可达 / 网络类错误 |
| 504 | `gateway_timeout` | 超时 |

axum extractor 拒绝（Query/Path/Json 反序列化失败）保持框架原生 `text/plain`
形态，**不**套 JSON 信封——两族形态有意不同，属既定契约。

## 端点总览

按资源分组。「认证」列给出最低角色要求；可见性/所有者判定见各端点详情。

### 探针与公开端点（public 组，匿名可达）

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/health` | 匿名 | 存活探针（`?deep=1` 加 DB ping，见详情） |
| GET | `/api/v1/version` | 匿名 | 返回版本号 |
| GET | `/api/v1/status` | 匿名 | 脱敏状态摘要（按可见性过滤的任务计数） |
| GET | `/api/v1/nihao` | 匿名 | 连通性/身份探针（CLI daemon 发现用） |
| GET | `/api/v1/reproducibility/stats` | 可见性过滤 | 复现率统计聚合（见详情） |
| GET | `/api/v1/builds/{id}/artifacts/download` | 视配置 | 产物文件下载（`public_access.download` 门控） |
| GET | `/api/v1/public/tasks/{id}` | 视配置 | 匿名受限任务摘要（`crbs download` 无 token 编排元数据，脱敏） |
| GET | `/api/v1/public/builds/{id}/artifacts` | 视配置 | 匿名受限制品清单（同上） |
| GET | `/repo/{product}/{arch}/{*path}` | 匿名 | 发布 repo 文件服务（repodata/RPM，见详情） |

### builds

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/builds` | 任一身份 | 构建列表（过滤 + 分页） |
| POST | `/api/v1/builds` | builder+ 且产品 ACL | 提交构建（JSON 或 multipart） |
| POST | `/api/v1/tasks` | 同上 | 提交别名（与 POST /builds 同 handler） |
| GET | `/api/v1/builds/{id}` | 可见即可读 | 构建详情 |
| POST | `/api/v1/builds/{id}/cancel` | owner 或 operator+ | 取消构建 |
| POST | `/api/v1/builds/{id}/publish` | owner 或 operator+ | 产物链接进产品 repo |
| POST | `/api/v1/builds/{id}/unpublish` | owner 或 operator+ | 从 repo 摘除链接 |
| GET | `/api/v1/builds/{id}/diff` | 可见即可读 | 与另一构建逐文件 diff |
| PATCH | `/api/v1/builds/{id}/priority` | operator+ | 调整排队优先级 |
| GET | `/api/v1/builds/{id}/srpm-download` | 签名 query token / worker / 可见 | 下载源 SRPM |
| GET | `/api/v1/builds/{id}/build-packages` | 同上 | 下载复现环境包清单 |
| POST | `/api/v1/builds/{id}/sign` | operator+ | 服务端 GPG 签名产物 |
| GET | `/api/v1/builds/{id}/reproducibility` | 可见即可读 | 该构建的复现比对行 |
| GET | `/api/v1/builds/{id}/logs` | 可见即可读 | 构建日志流（tail -f，见流式端点） |
| GET | `/api/v1/builds/{id}/profile` | 可见即可读 | 构建 profile（阶段耗时等） |
| GET | `/api/v1/builds/{id}/artifacts` | 可见即可读 | 产物列表（DB 元数据版） |
| POST | `/api/v1/builds/{id}/artifacts/upload` | worker | worker 上传产物 + manifest |
| GET | `/api/v1/builds/{id}/changelog` | 可见即可读 | 构建/任务 changelog |
| GET | `/api/v1/builds/artifacts/by-sha256/{sha256}` | 可见性过滤 | SHA256 指纹反查构建 |

### tasks（任务 = 一次提交的聚合视图）

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/tasks` | 任一身份 | 任务列表（过滤 + 分页） |
| GET | `/api/v1/tasks/{id}` | 可见即可读 | 任务详情 + 子构建摘要 |
| POST | `/api/v1/tasks/{id}/cancel` | owner 或 operator+ | 取消任务（级联子构建） |
| POST | `/api/v1/tasks/{id}/rebuild` | owner 或 operator+ | 按原源码重建新任务 |
| POST | `/api/v1/tasks/{id}/reproduce` | owner 或 operator+ | 锁定依赖快照复现 |
| GET | `/api/v1/tasks/{id}/recipe` | 可见即可读 | 配方导出（recipe.json） |

### batches（整仓重建批次）

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/batches` | operator+ | 批次列表（分页） |
| POST | `/api/v1/batches` | operator+ 且产品 ACL | 提交整仓重建（dry_run 支持预览） |
| GET | `/api/v1/batches/{id}` | operator+ | 批次详情 + 轮次 + 失败分桶 |
| POST | `/api/v1/batches/{id}/cancel` | operator+ | 取消在途批次 |

### products

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/products` | 可见性过滤 | 产品名列表 |
| POST | `/api/v1/products` | builder+ | 创建产品（admin 建 public，builder 强制 private） |
| GET | `/api/v1/products/{name}` | public 或 owner/admin | 合并后配置详情 |
| PUT | `/api/v1/products/{name}` | owner/admin | 更新配置（乐观锁 revision） |
| DELETE | `/api/v1/products/{name}` | owner/admin | 删除产品（级联取消活跃构建） |
| POST | `/api/v1/products/{name}/init` | admin | 远程初始化 base_os（异步） |
| POST | `/api/v1/products/{name}/clean` | admin | 清理产品产物（异步） |
| GET | `/api/v1/products/{name}/resolved` | public 或 owner/admin | 链解析后 TOML（export 桥） |
| GET | `/api/v1/products/{name}/history` | owner/admin | 配置历史列表（revision 降序） |
| GET | `/api/v1/products/{name}/history/{revision}` | owner/admin | 指定历史版本配置 |
| GET | `/api/v1/products/tasks/{id}` | operator+ | init/clean 异步任务状态 |
| GET | `/api/v1/products/{name}/acl` | owner/admin | 产品 ACL 列表 |
| POST | `/api/v1/products/{name}/acl` | owner/admin | 授予用户产品 ACL |
| DELETE | `/api/v1/products/{name}/acl` | owner/admin | 撤销用户产品 ACL |
| POST | `/api/v1/products/{name}/visibility` | owner/admin | publish/unpublish（改可见性） |
| POST | `/api/v1/products/{name}/transfer` | owner/admin | 所有权转让 |

### workers（hub-worker 协议；另见 [hub-worker.md](hub-worker.md)）

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| GET | `/api/v1/workers` | operator+ | worker 列表（含遥测） |
| POST | `/api/v1/workers/register` | worker 自身 / operator+ | 注册（upsert）worker |
| POST | `/api/v1/workers/{id}/heartbeat` | worker 本人 | 心跳 + 遥测 + 取消下行通知 |
| GET | `/api/v1/workers/{id}/assignments` | worker 本人 | 长轮询领取任务（claim 语义） |
| POST | `/api/v1/workers/{id}/assignments/{assignment_id}/result` | worker 本人 | 上报构建结果（终态） |
| POST | `/api/v1/workers/{id}/assignments/{assignment_id}/logs` | worker 本人 | 上传日志 chunk（追加） |
| POST | `/api/v1/workers/{id}/secret/rotate` | operator+ | 轮换 worker secret（明文一次性返回） |
| POST | `/api/v1/workers/{id}/secret/revoke` | operator+ | 吊销 worker secret |
| POST | `/api/v1/workers/{id}/remove` | operator+ | 移除 worker（须离线） |

### admin（全部 require_admin）

| 方法 | 路径 | 用途 |
|------|------|------|
| GET | `/api/v1/admin/audit-logs` | 审计日志查询（过滤 + 分页） |
| GET / POST | `/api/v1/admin/users` | 用户列表 / 创建用户 |
| GET / PUT / DELETE | `/api/v1/admin/users/{id}` | 用户详情 / 改角色状态 / 禁用 |
| GET / POST | `/api/v1/admin/users/{id}/tokens` | token 列表 / 签发 token（明文一次性返回） |
| DELETE | `/api/v1/admin/users/{id}/tokens/{tid}` | 吊销 token |
| GET / POST | `/api/v1/admin/products/{product}/acl` | 产品 ACL 列表 / 授予 |
| DELETE | `/api/v1/admin/products/{product}/acl/{user_id}` | 撤销产品 ACL |
| POST | `/api/v1/admin/workers/{id}/init` | 远程重建 worker 的 base_os |
| POST | `/api/v1/admin/products/{product}/rebuild-repo` | 重组产品发布 repo |
| GET | `/api/v1/resource-profiles?product=X` | 列举产品内包资源画像（declared + learned） |
| GET / PUT / DELETE | `/api/v1/resource-profiles/{product}/{pkg}/{arch}` | 查询 / 写声明 / 清声明 |

### gc 与 metrics

| 方法 | 路径 | 认证 | 用途 |
|------|------|------|------|
| POST | `/api/v1/gc` | operator+ | 触发 GC（异步，dry_run 支持预览） |
| GET | `/api/v1/gc/{id}` | operator+ | GC 任务状态与摘要 |
| GET | `/api/v1/metrics` | operator+ | JSON 运维指标快照 |
| GET | `/metrics` | operator+ | 同源数据的 Prometheus exposition |

### Web UI（public 组，`web_ui_enabled` 关闭时整组不挂载）

HTML 页面与表单端点，非 JSON API；cookie 会话（`crbs_session`）+ CSRF token
认证，仅作完整性列出。页面数据视角按会话身份过滤；操作端点（POST）的权限
口径与对应 API 端点一致（如同名 admin 页面要求 admin）。

| 方法 | 路径 | 用途 |
|------|------|------|
| GET | `/` | 首页（同 `/ui`、`/ui/`） |
| GET | `/ui` | 首页 |
| GET | `/ui/` | 首页 |
| GET | `/ui/favicon.svg` | 图标 |
| GET | `/ui/events` | 仪表盘 SSE（见流式端点） |
| GET | `/ui/builds` | 构建列表页 |
| GET / POST | `/ui/builds/{id}` | 构建详情页 / 页内操作 |
| GET | `/ui/builds/{id}/changelog` | 构建 changelog 页 |
| GET | `/ui/builds/{id}/logs` | 构建日志页 |
| GET | `/ui/builds/{id}/logs/stream` | 日志 SSE（见流式端点） |
| GET | `/ui/builds/{id}/events` | 构建事件 SSE（见流式端点） |
| GET | `/ui/tasks` | 任务列表页 |
| GET / POST | `/ui/tasks/new` | 新建任务表单 / 提交 |
| GET / POST | `/ui/tasks/{id}` | 任务详情页 / 页内操作 |
| GET | `/ui/tasks/{id}/changelog` | 任务 changelog 页 |
| POST | `/ui/tasks/{id}/rebuild` | 重建任务 |
| POST | `/ui/tasks/{id}/reproduce` | 复现任务 |
| GET | `/ui/tasks/{id}/events` | 任务事件 SSE（见流式端点） |
| GET | `/ui/batches` | 批次列表页（operator+；匿名 401，已认证非 operator 403） |
| GET / POST | `/ui/batches/{id}` | 批次详情页 / 页内操作（operator+） |
| GET | `/ui/products` | 产品列表页 |
| GET / POST | `/ui/products/new` | 新建产品表单 / 提交 |
| GET | `/ui/products/{name}` | 产品详情页 |
| POST | `/ui/products/{name}/visibility` | 改可见性 |
| POST | `/ui/products/{name}/acl` | 授予 ACL |
| POST | `/ui/products/{name}/acl/{username}/revoke` | 撤销 ACL |
| POST | `/ui/products/{name}/transfer` | 转让所有权 |
| POST | `/ui/products/{name}/rebuild-repo` | 重建 repo |
| GET / POST | `/ui/products/{name}/edit` | 编辑产品表单 / 提交 |
| GET | `/ui/products/{name}/history` | 配置历史页 |
| GET | `/ui/products/{name}/history/diff` | 历史版本 diff |
| GET | `/ui/packages` | 包列表页 |
| GET | `/ui/packages/{name}` | 包详情页 |
| GET | `/ui/search` | 搜索页 |
| GET | `/ui/reproducibility` | 复现率看板页 |
| GET | `/ui/workers` | worker 列表页 |
| GET / POST | `/ui/workers/{id}` | worker 详情页 / 页内操作 |
| POST | `/ui/workers/{id}/remove` | 移除 worker |
| GET | `/ui/admin` | admin 仪表盘 |
| GET / POST | `/ui/admin/users` | 用户管理页 / 创建 |
| GET | `/ui/admin/users/{id}` | 用户详情页 |
| POST | `/ui/admin/users/{id}/role` | 改角色 |
| POST | `/ui/admin/users/{id}/status` | 改状态 |
| POST | `/ui/admin/users/{id}/password` | 重置密码 |
| POST | `/ui/admin/users/{id}/tokens` | 签发 token |
| POST | `/ui/admin/users/{id}/tokens/{tid}/revoke` | 吊销 token |
| POST | `/ui/admin/users/{id}/acl` | 授予产品 ACL |
| POST | `/ui/admin/users/{id}/acl/{product}/revoke` | 撤销产品 ACL |
| GET | `/ui/admin/audit` | 审计日志页 |
| GET / POST | `/ui/admin/settings` | 系统设置页 / 提交 |
| GET / POST | `/ui/admin/gc` | GC 页 / 触发 GC |
| POST | `/ui/logout` | 登出（清会话 cookie，需 CSRF token） |
| GET | `/ui/me` | 个人信息页 |
| POST | `/ui/me/password` | 改密码 |
| POST | `/ui/me/sessions/{sid}/revoke` | 吊销单个会话 |
| POST | `/ui/me/sessions/revoke-all` | 吊销全部会话 |
| POST | `/ui/me/tokens` | 签发个人 token |
| POST | `/ui/me/tokens/{tid}/revoke` | 吊销个人 token |
| GET | `/ui/login` | 登录页 |
| POST | `/ui/login/password` | 密码登录 |
| POST | `/ui/login/token` | token 粘贴登录 |
| GET / POST | `/ui/register` | 注册页 / 提交（需开放注册配置） |
| POST | `/ui/set-theme` | 切换主题（cookie） |
| POST | `/ui/set-lang` | 切换语言（cookie） |
| POST | `/ui/set-page-size` | 切换分页大小（cookie） |

## 端点详情

### 探针与公开端点

**`GET /api/v1/health`** — 存活探针。响应 `{"status":"ok"}`，带
`Cache-Control: no-store`。`?deep=1|true|yes` 追加 DB ping：可达时
`{"status":"ok","db":"ok"}`，不可达时 503 `{"status":"degraded","db":"error"}`
（readiness 判定用；缺省纯 liveness，DB 瞬断不影响）。

**`GET /api/v1/version`** — `{"version":"<crbs 版本>"}`。

**`GET /api/v1/status`** — 脱敏摘要：`status` / `version` / `timestamp` /
`tasks`（pending/building/succeeded/failed/cancelled/timeout/total 计数）/
`workers.online`。计数按调用方可见性过滤（匿名只见公共产品），不暴露磁盘
容量、crbs_root 等运维信息。

**`GET /api/v1/nihao`** — 连通性/身份探针，CLI daemon 无 token 发现用。已认证
返回 `auth:"ok"` + `user` + `role`；匿名返回 `auth:"disabled"` 且不泄露身份。

**`GET /api/v1/reproducibility/stats?days=`** — 复现率聚合。`days` 缺省 30；
`all` 或 `0` = 全部时间；其余须为 `0..=3650` 整数。响应含 `total`、
`verdicts`（五类 verdict 计数，键集恒定：same/diff/build_failed/
dep_unavailable/infra_error）、`by_kind`、`by_product`、`series`（日桶，不零
填充）、`diffs`（最新差异清单，至多 50 条）。只出原子计数，rate 由看板自算。
认证开启时匿名 401；可见产品之外的数据不可见。注意 `days` 越过 DB retention
保留期时早期行已被修剪，长窗口是"现存行"口径。

**`GET /api/v1/builds/{id}/artifacts/download?file=<相对路径>`** — 流式下载
产物文件（`no-store`，HEAD 由 GET 路由兜底）。`file` 相对 `result_dir`，拒
`..` 穿越。门控：`auth_enabled` 且 `public_access.download=false` 时要求认证
（owner/viewer+ 可读）+ 产品可见性；`public_access.download=true`（默认）时
匿名可读，但仍过 private 产品可见性。`*.src.rpm` 另受 SRPM 下载门约束：
生效的 `allow_srpm_download`（server 全局键，产品配置可逐产品覆盖、链合并
继承）为 false 时匿名 401 / builder·viewer 403（operator/admin 放行）；
worker 取件走 `/builds/{id}/srpm-download`，不经此门。

**`GET /repo/{product}/{arch}/{*path}`** — 发布 repo 文件服务，供 worker/dnf
匿名读取 repodata/RPM。仅 `visibility=public` 的产品对外服务；private/不存在
一律 404（不泄露存在性）。磁盘根为 `{result_root}/_repo/{product}/{arch}/`，
路径组件逐个拒绝 `.`/`..`/分隔符/NUL。

### 提交构建：`POST /api/v1/builds`（别名 `POST /api/v1/tasks`）

按 Content-Type 分流：

- **JSON**（上限 2MB，超限 413）：`{"product": "...", "srpms": ["/srv/upload/x.src.rpm", ...],
  "arch_list": ["x86_64"], "labels": [{"key": "...", "value": "..."}], ...BuildOptions
  拍平到顶层}`。`srpms` 是 **server `upload_dir` 内的路径**（先经其它通道上传
  或本地路径形态），单次至多 64 个 SRPM、8 个架构（超限 400）。
- **multipart/form-data**（上限 `server.upload_max_size`，默认 500MB，约 2×+
  余量的硬上限）：`product`、`arch_list`（可重复）、`label`（可重复，每字段
  `KEY=VALUE`，按首个 `=` 切分）、SRPM 文件字段。流式落盘 `upload_dir`，
  落盘前先预检目标卷磁盘空间。

`labels` / `label` 是任务级通用键值元数据（不透明，无系统保留键；`git-repo`、
`git-commit` 仅为常见用法示例）。校验：至多 16 条；key ≤ 64 字符且限
`[A-Za-z0-9_.-]`；value ≤ 256 字符、不含控制字符；总量 ≤ 4096 字符；同任务
重复键 400。标签随任务行同事务落库，扇出的全部子构建共享。

**BuildOptions 常用字段**（全部可选）：`stage`、`shared_layer`、`tmpfs`、
`ccache`、`timeout`、`nocheck`、`noclean`、`nodebuginfo`、`target`、`dist`、`backend`
（nspawn/chroot）、`no_network`、`no_repo`（true = scratch 构建不进 repo）、
`memory_max`、`cpu_quota`、`define[]`、`with_features[]`、`without_features[]`、
`retry`、`no_reproduce`。

**权限**：viewer 403；builder+ 且（有 ACL 时）目标产品在 `allowed_products`
内，否则 403。**幂等守卫**：同 pkg 已有活跃（pending/building）构建时 409，
消息含 pkg 名与活跃构建定位。

**响应 202**：`{"task_id": <任务 ID>, "ids": [子构建 ID...], "phase": "pending",
"product": "...", "submitted_at": "..."}`——多架构提交 fan-out 为每 arch 一条
子构建；纯 noarch 源码包（header arch=noarch）默认收敛为单条子构建（派发
架构按包全名 NVR 稳定哈希轮转选取，产品 `noarch_per_arch = true` 恢复
每架构各建），混合包与 SRPM 头解析失败的不收敛。

### 构建查询与操作

**`GET /api/v1/builds`** — 过滤参数 `product` / `phase` / `name` / `arch` /
`task_id` / `srpm_sha256` / `sort` + 分页。`srpm_sha256` 按
`canonical_srpm_sha256`（输入 SRPM 原样字节哈希）等值过滤。builder 只见自己
提交的；其余角色按产品可见性见全部。响应 `{"total": n, "builds":
[BuildRecord...]}`（已脱敏路径）。

**`GET /api/v1/builds/{id}`** — 单条 `BuildRecord`（脱敏同上）。不可见 403 /
404（private 产品）。

**`POST /api/v1/builds/{id}/cancel`** — owner 或 operator+（空提交者的遗留记录仅 operator/admin）。**202**
`{"cancelled": bool, "id": ..., "message": "..."}`；已终态时 cancelled=false。

**`POST /api/v1/builds/{id}/publish` / `unpublish`** — 翻 `repo_publish` 标志
并（取消）链接产物进产品 repo，owner 或 operator+。响应含 `arches`、
`linked`/`unlinked`/`skipped_*` 报告字段。

**`GET /api/v1/builds/{id}/diff?against=<build 短 ID>`** — 与右侧构建逐文件
diff；两侧都须可见（右侧非数字 400）。响应为 `DiffResult` 结构。

**`PATCH /api/v1/builds/{id}/priority`** — body `{"priority": <0-2>}`，仅
operator+（priority=2 critical 亦 operator+，与提交侧同门槛）。仅 pending 构建可改，否则 409；不存在
404。**200** `{"id":..., "priority":...}`，写审计日志。

**`GET /api/v1/builds/{id}/srpm-download`** / **`GET /api/v1/builds/{id}/build-packages`**
— 下载源 SRPM / `build_packages.json`（复现环境包清单）。认证三选一：带签名
的 `?token=`（dispatch 派发时生成，10 分钟有效）；worker secret；普通
token（须可读该构建 + 产品可见）。响应 `application/x-rpm` 流（build-packages
为 JSON），`no-store`。

**`POST /api/v1/builds/{id}/sign`** — body `{"key_id"?, "gpg_home"?}`（缺省用
server 配置）。仅 operator+，且仅 succeeded 构建（否则 409）、仅官方产品
（private 产品 403——服务端密钥不为衍生品背书）、重放构建 409（引导签源构建）。
响应 `{"signed": true, "id":..., "message":...}`。

**`GET /api/v1/builds/{id}/reproducibility`** — 该构建作为 source/replay 的全
部比对行：`{"build_id":..., "results": [ReproducibilityRecord...]}`。

**`GET /api/v1/builds/{id}/profile`** — `profile.json` 结构化透传：顶层摘要
（`id`/`pkg_name`/`product`/`phase`/`elapsed_secs`/`rpms`）+ 嵌套 `profile`
（与本地 `status --profile` 同形）。文件缺失 404。

**`GET /api/v1/builds/{id}/artifacts`** — DB 元数据版产物列表：
`{"build_id", "rpms": [...], "srpms": [...], "other": [...],
"artifacts": [{relative_path, kind, size_bytes, sha256, arch?, name?,
version?, release?, epoch?, signed}]}`。前三个数组按类别分组。

**`GET /api/v1/public/tasks/{id}`** — 匿名受限任务摘要（`crbs download`
无 token profile 的编排元数据，与 Web 公共下载对齐）。门控同
`public_access.download`（关闭时匿名 401，认证用户不受影响）+ 产品可见性
（匿名仅 public 产品）；响应脱敏：仅 id/product/pkg_name/phase + 子构建
摘要，子构建的 result_dir/started_at/duration 置 null，无提交者信息。

**`GET /api/v1/public/builds/{id}/artifacts`** — 匿名受限制品清单，响应与
protected 版同构（本就不含 result_dir），门控同上。

**`POST /api/v1/builds/{id}/artifacts/upload`** — worker 上传产物，multipart：
`crbs-artifacts.json` manifest 字段（必须）+ 文件字段（须与 manifest 一致）。
请求体上限 10GB+1GB 余量。终态 assignment 追加上传 409。

**`GET /api/v1/builds/{id}/changelog`** — 构建/任务 changelog（RPM %changelog
解析结果）。

**`GET /api/v1/builds/artifacts/by-sha256/{sha256}`** — 指纹反查：sha256 须为
64 位十六进制（否则 400）。响应 `{"sha256", "matches": [{build_id,
relative_path, kind, ..., on_disk, product, phase}], "total"}`。含 GC 已删行
（`on_disk=false`）；不可见行静默剔除（不泄露存在性）。

### tasks

**`GET /api/v1/tasks`** — 过滤参数 `product` / `phase` / `name` /
`label=KEY=VALUE` / `sort` + 分页（无 `arch`/`task_id`）。`label` 按 (key,
value) 精确匹配，syntax 缺 `=` 时 400。可见性两层：builder 只见自己；产品
可见性 SQL 层分页前过滤（`total` 为过滤后总数）。响应 `{"total", "tasks":
[TaskRecord...]}`。

**`GET /api/v1/tasks/{id}`** — `{"task": TaskRecord（flatten）, "builds":
[ChildBuildSummary...], "lineage": TaskLineage, "labels": [{"key", "value"}...]}`，
标签按 key 排序、无标签为空数组；子构建 `result_dir` 置 null（脱敏）。

**`POST /api/v1/tasks/{id}/cancel`** — owner 或 operator+，认证必填（匿名
401）。**202** `{"task_id", "cancelled_build_ids", "skipped_build_ids",
"failed_build_ids", "message"}`——skipped 是"已终态无需取消"，failed 是
"想取消没取消掉"（DB 错误/竞态）。

**`POST /api/v1/tasks/{id}/rebuild`** — 权限同 cancel。源码取自
`{result_dir}/{task_id}/source/`，构建选项取任务级 `request_json`（剥离
arch）。新任务归属当前操作者。**202** 返回 BuildResponse（同提交）。活跃重
复守卫 409 同提交。

**`POST /api/v1/tasks/{id}/reproduce`** — 权限同 cancel。在锁定依赖快照
（`build_packages.json`）下重建各 arch 子构建（reproduce 模式）。**202** 返回
BuildResponse。

**`GET /api/v1/tasks/{id}/recipe`** — 配方导出（M4）。首次请求组装
`recipe.json` 并原子落盘任务目录，后续回读；schema 版本过期自动再生成（自
愈），**超前**版本 409 拒绝降级覆写。子构建未全部 succeeded 时 409、零落盘。
权限同 `GET /api/v1/tasks/{id}`。

### batches

**`POST /api/v1/batches`** — operator+（匿名 401，已认证非 operator 403）+
产品 ACL。body（上限 64KB）：`{"product", "source_repo_url", "dist"?,
"arch_targets": [], "on_failure"?（默认 continue）, "force_all"?, 
"allow_dist_mismatch"?, "dry_run"?}`。`dry_run=true` 不落库不下载，**200** 返回
增量预览（`to_build`/`skipped` 列表截断 200 条，计数全量）；否则快速段同步建
批次行、慢段（枚举/下载/规划）后台跑，**202**
`{"batch_id":..., "status":"..."}`，终态经查询端点观察。批次内纯 noarch
源码包同样收敛为单条子构建（扇出语义同 `POST /api/v1/builds`，产品
`noarch_per_arch = true` 恢复每架构各建）。

**`GET /api/v1/batches`** — operator+，`?limit=&offset=`（默认 50，上限
200），响应 `{"batches": [BatchSummary...]}`。

**`GET /api/v1/batches/{id}`** — operator+。批次摘要（flatten）+
`source_repo_url`/`dist`/`arch_targets`/`on_failure`/`force_all`/`notes`/
`started_at` + `progress`（项状态计数）+ `rounds`（轮次摘要）+ `failures`
（error_code 分桶，桶数上限 10）。

**`POST /api/v1/batches/{id}/cancel`** — operator+，**响应** `{"batch_id",
"status"}`。

### products

**`GET /api/v1/products`** — 可见产品名列表（排序后 JSON 数组）。

**`POST /api/v1/products`** — builder+。body：`{"name", "display_name"?,
"parent_id"?, "visibility"?, "config": ProductConfig, "reason"?}`。admin 建
public 官方产品（`visibility` 缺省 public；private 时 owner=self）；builder
强制 private + owner=self（传非 private 400）。**201**
`{"id", "name", "revision", "base_os_revision"}`。

**`GET /api/v1/products/{name}`** — 合并后配置详情（product-layer 继承链 +
CrbsConfig + server override），附 `id`/`parent_id`/`parent_name`/`revision`。
private 对无权限者 404（不区分不存在）。链上私有祖先不可见同样 404。

**`PUT /api/v1/products/{name}`** — owner/admin。body 必填
`expected_revision`（乐观锁，缺字段 400；版本冲突 409）+ `config` + 可选
`reason`、`parent_id`（三态：缺席=不改 / null=detach / 数字=set）。响应
`{"revision", "base_os_revision", "base_os_bumped"}`。

**`DELETE /api/v1/products/{name}`** — owner/admin，级联取消活跃构建与任务。
被依赖（delete_restricted）时 409。**204**。

**`POST /api/v1/products/{name}/init` / `clean`** — admin（异步）。body
`{"force"?}`。同产品同操作已有 Running 任务时 409。**202**
`{"task_id": "<uuid>", "status": "running", "product", "op"}`，用
`GET /api/v1/products/tasks/{task_id}` 轮询。

**`GET /api/v1/products/tasks/{id}`** — operator+。`{"task_id", "status":
"running|succeeded|failed", "product", "op", "error"?, "started_at"}`。

**`GET /api/v1/products/{name}/resolved`** — 链解析后 TOML，content-type
`application/toml`、`no-store`。磁盘同步桥：
`crbs products export <name> --remote <profile> > /etc/crbs/products/<name>.toml`。

**`GET /api/v1/products/{name}/history`** — owner/admin，revision 降序，仅本层
config（不含祖先合并）。

**`GET /api/v1/products/{name}/history/{revision}`** — 指定版本条目。

**ACL**：`GET / POST / DELETE /api/v1/products/{name}/acl` — owner/admin
（官方产品只有 admin）。POST body `{"username", "role"?}`（缺省 viewer，
builder/viewer 二值）；DELETE body `{"username"}`。GET 返回
`[{user_id, username, role, created_at}]`。

**`POST /api/v1/products/{name}/visibility`** — owner/admin。body
`{"visibility": "public|private", "reason"?, "expected_revision"}`。官方产品
不能 unpublish（schema 约束，409）。响应同 PUT。

**`POST /api/v1/products/{name}/transfer`** — owner/admin。body
`{"new_owner_username", "reason"?, "expected_revision"}`。官方产品转让（变
private）若有 public 后代 409（防泄漏）。

### workers

协议细节与派发语义见 [hub-worker.md](hub-worker.md)，此处列
HTTP 面要点。所有"worker 本人"端点校验路径 `id` 与 token 绑定的 worker 一致
（403 否则）。

**`GET /api/v1/workers`** — operator+，`[WorkerStatus...]`（name/arch/
capacity/status/版本/遥测）。

**`POST /api/v1/workers/register`** — 认证必填：worker secret 只能注册与
token 绑定同名 worker（防名称劫持）；非 worker 身份须 operator+（代注册）。
body `{"name", "arch", "capacity" (1..=1024), "version"?}`。upsert 语义，
响应 `{"id":..., "status":"...", "has_active_local_builds"?}`（启动 GC 守卫
提示）。

**`POST /api/v1/workers/{id}/heartbeat`** — body `{"status"?（默认 online,
可 offline）, "load1"?, "ncpu"?, "mem_used_pct"?, "mem_total_kb"?}`（越界/NaN
遥测按 NULL 诚实降级）。行不存在 404。响应 `{"accepted": true,
"cancelled_assignments": [id...]}`——搭车下发已取消 assignment 列表。

**`GET /api/v1/workers/{id}/assignments?wait=<秒>`** — 长轮询取任务，wait
缺省 30、钳到 120。**GET 语义 = claim**：200 带体即该 assignment 已置
running、build 已置 building（事务内 CAS 防双领）；无任务 **204**。任务体：
`assignment_id`/`task_id`/`build_id`/`product`/`srpm_url`/`build_options`/
`product_config`/`reproduce_packages_url`?/`kind`/`init_product`?/
`product_repo_enabled`/`redelivered`?（重投递标记）。响应丢失的 running 行会
在 wait 到期路径重投递。

**`POST /api/v1/workers/{id}/assignments/{assignment_id}/result`** — body
`{"phase": "succeeded|failed|cancelled|timeout", "result_dir"?, "error"?,
"notes"?, "resources"? {peak_rss_kb, cpu_secs, cpu_p90_cores}}`。assignment
不属于该 worker 403；已终态 409（幂等截断）。**200** JSON 确认。

**`POST /api/v1/workers/{id}/assignments/{assignment_id}/logs`** — 原始字节
body（日志 chunk，单 chunk 上限见 `log_buffer::MAX_LOG_CHUNK_BYTES`，请求体
超限 413）。终态 assignment 拒绝追加（409）。

**`POST /api/v1/workers/{id}/secret/rotate` / `revoke` / `remove`** —
operator+。rotate 响应 `{"status":"rotated", "worker_id", "secret": "<明文，
仅此一次>"}`；revoke `{"status":"revoked", ...}`；remove 须 worker 离线，
`{"status":"removed", "worker_id", "name"}`。

### admin

全部 `require_admin`：未认证 401、非 admin 403。

**`GET /api/v1/admin/audit-logs`** — 过滤 `user`/`role`/`action`/`target`/
`since`/`until` + 分页。响应 `{"total", "limit", "offset", "logs":
[AuditLog...]}`。

**`POST /api/v1/admin/users`** — body `{"name", "role"}`（role ∈ admin/
operator/builder/viewer）。重名 409。**201** UserResponse
`{id, name, role, status, created_at}`。

**`GET / PUT / DELETE /api/v1/admin/users/{id}`** — GET 详情；PUT body
`{"role"?, "status"?}`（status ∈ active/disabled）；DELETE 禁用用户（软删，
token 失效）。

**token 管理**：`POST /api/v1/admin/users/{id}/tokens` body `{"name"?,
"expires_in_days"?}`——**201** `{id, token: "<crbs_tok_… 明文，仅此一次>",
name, expires_at}`；`GET` 列表（不含明文）；`DELETE .../tokens/{tid}` 吊销。
disabled 用户签发/操作 409。

**产品 ACL（admin 面）**：`POST /api/v1/admin/products/{product}/acl` body
`{"user_id", "role"?}`；GET 列表；`DELETE .../acl/{user_id}`。目标用户不存在
400、非 active 409。

**`POST /api/v1/admin/workers/{id}/init`** — body `{"product"}`，远程重建该
worker 的 base_os。worker 不存在 404；该 (worker, product) 有在途构建 409
（per-product 粒度 building 保护）。

**`POST /api/v1/admin/products/{product}/rebuild-repo`** — 重组产品发布
repo。产品不存在 404。响应 `{"product", "arches", "linked", "unlinked"}`，
写审计日志。

**包资源画像**：`GET /api/v1/resource-profiles?product=X` 返回该产品全部画像行
（declared + learned 全列，`{"product", "total", "profiles": [...]}`）；单键
`GET/PUT/DELETE /api/v1/resource-profiles/{product}/{pkg}/{arch}` 查询 / 写声明 /
清声明。PUT body `{"min_mem_kb"?, "min_ncpu"?, "min_disk_kb"?}`，三维全量语义，
上限同提交期（1 TiB / 1024 核 / 64 TiB）；只写 declared 列组，不触碰 learned。
DELETE 只清 declared 列、不删行（行不存在也返回 204）。写操作分别记
`set_resource_profile` / `unset_resource_profile` 审计，并按包失效调度权重缓存。

### gc

**`POST /api/v1/gc`** — operator+（匿名放行仅限 auth 关闭形态）。body 全可
选：`{"dry_run"?, "results"?, "product"?, "orphan_mounts"?, "cache"?, "all"?,
"policy"?}`。约束：`dry_run` 须搭配 results/orphan_mounts/cache/policy；
`product` 须搭配 results/policy；`all` 须搭配 cache（违反 400）。同一时刻只
允许一个 GC 任务（并发第二个 409）。**202**
`{"task_id": "<uuid>", "status": "running"}`——异步执行，用状态端点轮询。

**`GET /api/v1/gc/{id}`** — operator+。`{"task_id", "status":
"running|succeeded|failed", "summary"?, "error"?}`。

## 流式端点

**`GET /api/v1/builds/{id}/logs?offset=N`** — chunked 日志流，行为类似
`tail -f`：无 `offset` 时从请求发起时刻的文件末尾开始持续推送新增日志，
直到构建进入终态；带 `offset` 时从指定字节偏移回放再续推。日志文件尚未生成
且构建未终态时转入流内等待（不立即 404）。单条流最大存活 1 小时（防悬挂）。
权限与构建详情同口径。未知查询参数被静默忽略。

**Web UI SSE**（`text/event-stream`，cookie 会话认证）：

- `GET /ui/events` — 仪表盘全局事件流（任务/构建相位变化、worker 上下线）；
- `GET /ui/builds/{id}/logs/stream` — 单构建日志增量推送；
- `GET /ui/builds/{id}/events`、`GET /ui/tasks/{id}/events` — 单构建/任务
  相位变化事件。

上述 4 个 UI SSE 路径在路由注册时同时挂了 `HEAD`（连接探测用），
对 `GET` 行为无影响。

DB 瞬断时 SSE 循环按指数退避重连（不中断连接）。

## Prometheus 指标

**`GET /metrics`** — 与 `GET /api/v1/metrics` 同源数据、同门控（operator+；
auth 关闭的本地形态匿名可读），输出 Prometheus text exposition 0.0.4
（`text/plain; charset=utf-8`，不做 Accept 协商）：

| 指标 | 类型 | 含义 |
|------|------|------|
| `crbs_builds_phase{phase=...}` | gauge | 按 phase 的构建计数（pending/building/succeeded/failed/cancelled） |
| `crbs_builds_total` | gauge | 上述五相位合计 |
| `crbs_local_builds_max` | gauge | 本地并发构建上限 |
| `crbs_local_builds_running` | gauge | 当前运行中的本地构建 |
| `crbs_local_builds_available` | gauge | 空闲槽位（= max − running） |
| `crbs_disk_available_bytes` | gauge | crbs_root 所在文件系统剩余字节 |
| `crbs_reproducibility_verdict_total{verdict=...}` | gauge | 复现比对 verdict 计数（五类 label 恒定，缺数据补零） |
| `crbs_uptime_seconds` | gauge | 进程存活秒数 |

`GET /api/v1/metrics`（JSON 版）另含 `status`/`version`/`timestamp`/
`concurrency{max,current,available}`/`disk{crbs_root,available_bytes,
available_gb}`。crbs_root 路径不进 Prometheus exposition（敏感信息不外泄）。
