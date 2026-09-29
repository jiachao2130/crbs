-- crbs state schema (PostgreSQL baseline)
--
-- 方言：PostgreSQL。与 SQLite schema 语义对齐：
--   - 时间戳保持 TEXT 类型（ISO8601 格式），零类型映射风险
--   - INTEGER 作 boolean 保持不变（0/1），避免类型双轨
--   - epoch 时间戳（package_urls）保持 BIGINT
--
-- SQLite → PG 映射规则：
--   - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`
--   - `datetime('now')` → `to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')`（UTC 帧，与会话时区无关）
--   - `strftime('%s','now')` → `EXTRACT(EPOCH FROM NOW())::bigint`（timestamptz 的 EPOCH 即绝对秒，无需 AT TIME ZONE 'UTC'，两种写法数值恒等；TEXT 时间列的会话时区问题不适用于 epoch BIGINT 列）
--   - `TEXT` 列保持 TEXT（PG 无限长文本）
--   - `CHECK` 约束兼容直接复用
--   - 部分索引（partial index）PG 原生支持
--
-- 注意：PG 支持真正的 UNIQUE 约束含 NULL（而 SQLite UNIQUE 允许任意多 NULL）。
-- products.name 使用单列 UNIQUE（产品名全局唯一），与 SQLite 侧语义一致。
--
-- 本文件即唯一 baseline：schema 变更直接修改本文件（与 schema.sql 双侧
-- 同步）即可——未发布阶段不保留兼容迁移，版本闩恒为 (1, 1)，任何旧形态
-- 存量库一律 fail-closed 拒启、按指引重新 init（与 SQLite 侧同步）。
--
-- CHECK 约束族已全量带入本 baseline，与 SQLite 侧逐约束对称（布尔列两侧均
-- INTEGER 0/1，见文件头映射注记）。

-- ===== 表创建顺序：无 FK 表先建，依赖表后建 =====

-- 1. users (无外键)
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    -- 全局角色全集 = API/CLI 共用的 VALID_ROLES。
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'builder', 'viewer')),
    -- status 全集 = 用户管理 API 校验（'active'/'disabled'）。
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    -- 密码登录。password_hash NULL = 未设密码；独立行映射结构读取，
    -- 绝不加进 Serialize 的 User 结构。
    password_hash TEXT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1))
);

-- 2. workers (无外键)
CREATE TABLE workers (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    arch TEXT NOT NULL,
    capacity INTEGER NOT NULL DEFAULT 1,
    -- 生产写入仅 online/offline（注册/离线/恢复收口）；'draining'/
    -- 'suspended' 是状态机守卫显式保护的管理员保留态（guard 谓词与测试
    -- fixture 均引用），故入域。
    status TEXT DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'draining', 'suspended')),
    last_heartbeat TEXT,
    version TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    secret_hash TEXT,
    secret_expires_at TEXT,
    load1 DOUBLE PRECISION,
    ncpu BIGINT,
    -- CPU 利用率百分比 0-100（/proc/stat 相邻两心跳差分，口径见 schema.sql 同列注）。
    cpu_util_pct DOUBLE PRECISION,
    mem_used_pct DOUBLE PRECISION,
    -- 节点内存总量 KB（内存准入门换算基准；心跳随载上报，可空；INTEGER 口径
    -- 避开浮点直绑钉型坑，见 schema.sql 同列注）。
    mem_total_kb BIGINT,
    -- 心跳上报的节点可用磁盘 KB（工件卷 df 1K 块口径；NULL = 未上报）。
    -- 调度读最新值走本列；心跳同时把它追加进 worker_telemetry_samples
    --（历史折线的展示数据源）；其余口径同文见 schema.sql 同列注。
    disk_free_kb BIGINT,
    -- 节点采集能力位图（启动探测，注册/心跳携带；NULL = 未上报）。
    -- 位定义 state 层常量（bit0 cgroup_v2 … bit4 psi），全注同文见
    -- schema.sql 同列注。
    resource_caps INTEGER
);

-- 3. products (FK: users)
CREATE TABLE products (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT,
    owner_id BIGINT REFERENCES users(id) ON DELETE RESTRICT,
    parent_id BIGINT REFERENCES products(id) ON DELETE RESTRICT,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('public', 'private')),
    config_json TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    base_os_revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    updated_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    CHECK (owner_id IS NOT NULL OR visibility = 'public')
);

-- 3b. build_batches (FK: products, users)
-- 整仓重建批次：一次提交的重建实体与进度聚合。语义与列注见 schema.sql
-- 同表注（status 生命周期、FK SET NULL 口径）。建序先于 builds：
-- builds.batch_id 外键要求被引用表先存在（PG 建表即解析 FK 引用；SQLite
-- 惰性解析无此约束，彼侧两表落文件尾，等价守卫按表名归组、不比建序）。
CREATE TABLE build_batches (
    id            BIGSERIAL PRIMARY KEY,
    product_id    BIGINT REFERENCES products(id) ON DELETE SET NULL,
    created_by    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    status        TEXT NOT NULL CHECK (status IN
        ('preparing', 'planning', 'running', 'completed', 'partial', 'failed', 'cancelled')),
    source_repo_url    TEXT NOT NULL,
    -- repodata 指纹，防规划期源仓漂移。
    source_fingerprint TEXT,
    -- NULL = 产品默认 dist；非默认值触发硬预检。
    dist          TEXT,
    -- 序列化列表。
    arch_targets  TEXT,
    on_failure    TEXT NOT NULL DEFAULT 'continue' CHECK (on_failure IN ('continue', 'abort')),
    force_all     INTEGER NOT NULL DEFAULT 0,
    total_items   INTEGER NOT NULL DEFAULT 0,
    n_succeeded   INTEGER NOT NULL DEFAULT 0,
    n_failed      INTEGER NOT NULL DEFAULT 0,
    n_skipped     INTEGER NOT NULL DEFAULT 0,
    n_cancelled   INTEGER NOT NULL DEFAULT 0,
    request_json  TEXT,
    notes         TEXT,
    created_at    TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    started_at    TEXT,
    finished_at   TEXT
);

-- 4. tasks (FK: users, products)
CREATE TABLE tasks (
    id BIGSERIAL PRIMARY KEY,
    product TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    "user" TEXT NOT NULL DEFAULT '',
    -- 与 builds.phase 同一 7 值全集。聚合写路径（aggregate_child_phases）
    -- 不产 'assigned'，但任务 phase 读守卫（lifecycle 活跃态谓词）显式承认
    -- 该中间态，故一并纳入域内。
    phase TEXT NOT NULL DEFAULT 'pending' CHECK (phase IN ('pending', 'assigned', 'building', 'succeeded', 'failed', 'cancelled', 'timeout')),
    priority INTEGER NOT NULL DEFAULT 0,
    srpm_path TEXT,
    result_dir TEXT,
    submitted_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    completed_at TEXT,
    duration BIGINT,
    user_id BIGINT REFERENCES users(id),
    name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    request_json TEXT,
    pkg_names TEXT,
    product_id BIGINT REFERENCES products(id) ON DELETE SET NULL
);

-- 4b. task_labels (FK: tasks)
-- 任务级通用键值标签（语义与列注见 schema.sql 同表）。
CREATE TABLE task_labels (
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (task_id, key)
);
CREATE INDEX idx_task_labels_key_value ON task_labels(key, value);

-- 4c. batch_items (FK: build_batches, tasks)
-- 批次项：持久化的重建计划（崩溃恢复的事实源），语义与列注见 schema.sql
-- 同表注（round 口径、UNIQUE 表级约束、CASCADE/SET NULL 删除语义）。
-- 建序先于 builds：同 build_batches 注。
CREATE TABLE batch_items (
    id            BIGSERIAL PRIMARY KEY,
    batch_id      BIGINT NOT NULL REFERENCES build_batches(id) ON DELETE CASCADE,
    pkg_name      TEXT NOT NULL,
    srpm_nevra    TEXT,
    srpm_staging_path TEXT,
    -- 拓扑轮次；0 = 环/未解析（先试构建）。
    round         INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN
        ('pending', 'released', 'succeeded', 'failed', 'dep_skipped', 'skipped_conflict', 'arch_skipped', 'cancelled')),
    attempt       INTEGER NOT NULL DEFAULT 0,
    task_id       BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    error_code    TEXT,
    error_message TEXT,
    updated_at    TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE (batch_id, pkg_name)
);
CREATE INDEX idx_batch_items_batch_round ON batch_items(batch_id, round);
-- 批次驱动 5s tick 与提交守卫（活跃 partial，批次数小但每 tick 全表扫）。
CREATE INDEX IF NOT EXISTS idx_batches_active
    ON build_batches(product_id, id DESC)
    WHERE status IN ('preparing', 'planning', 'running');
-- 每产品至多一个在途批次：check-then-insert 在 PG READ COMMITTED 下可双插，
-- 唯一索引是 DB 级兜底（NULL product_id 不参与唯一性）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_batches_active_product
    ON build_batches(product_id)
    WHERE status IN ('preparing', 'planning', 'running');

-- 批次对账/摘要的状态过滤（UNIQUE(batch_id, pkg_name) 前缀扫整批 8000 行
-- 再过滤 state 的补集索引）。
CREATE INDEX IF NOT EXISTS idx_batch_items_batch_state
    ON batch_items(batch_id, state);

-- 5. builds (FK: tasks, users, products)
CREATE TABLE builds (
    id BIGSERIAL PRIMARY KEY,
    product TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    -- phase 全集（7 值）= 代码写入点逐一核对——INSERT 恒 'pending'
    --（build_lifecycle），'assigned'/'building'（worker 上报，store 层
    -- update_build_phase 白名单），终态四值（complete_build* 终态守卫）。
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'assigned', 'building', 'succeeded', 'failed', 'cancelled', 'timeout')),
    result_dir TEXT,
    -- 本次执行尝试的计时起点（派发/回收时重置），非入队时刻；排队时长以
    -- 最新 build 型 worker_tasks.assigned_at 为准（见 schema.sql 同列段注）。
    started_at TEXT,
    completed_at TEXT,
    layer_digest TEXT,
    base_os_digest TEXT,
    backend TEXT,
    duration BIGINT,
    "user" TEXT NOT NULL DEFAULT '',
    crbs_pid BIGINT,
    srpm_path TEXT,
    request_json TEXT,
    -- 产品配置快照（合并后的产品 TOML 原文）：构建创建时写入，是 `crbs debug`
    -- 复现 CLI 直接本地构建的配置锚；hub 侧写入供审计与重派复用。NULL =
    -- 未采集（历史行 / 未经快照路径的构建）。
    product_config_toml TEXT,
    -- 重试预算（毒丸封顶）：reclaimer 失败重入每轮 +1，达上限转终态
    -- failed 而非无限重排（杀 worker 型包在全量批次里会循环吃光槽位）。
    attempt INTEGER NOT NULL DEFAULT 0,
    signed INTEGER NOT NULL DEFAULT 0 CHECK (signed IN (0, 1)),
    priority INTEGER NOT NULL DEFAULT 0,
    arch TEXT DEFAULT '',
    -- 调度宿主约束：arch='noarch' 行物化"可领取架构集"CSV（如 "x86_64,aarch64"；
    -- arch 词法白名单 [A-Za-z0-9_] 排除逗号，无注入面）。领取谓词按集合成员
    -- 放行，非成员架构对该行不可见（无队头阻塞）。NULL = 不限制（架构包由
    -- arch 本身约束；未配偏好的产品）。复现 noarch 行写源构建实际宿主单架构
    -- ——依赖快照按宿主架构锁定，跨架构领取必然解析失败。约束在提交时物化，
    -- 产品偏好后续变更不影响已排队构建（与可复现快照哲学一致）。
    host_arches TEXT,
    -- 每条构建必须挂任务（与 SQLite baseline 对齐，见 schema.sql 同列注）。
    task_id BIGINT NOT NULL REFERENCES tasks(id),
    user_id BIGINT REFERENCES users(id),
    product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
    name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    -- 发布开关（发布轴生效值）：1 = 本次构建产物可进产品 repo（默认），
    -- 0 = 逐构建收紧退出（--no-publish / reproduce 隔离 / unpublish）。
    repo_publish INTEGER NOT NULL DEFAULT 1 CHECK (repo_publish IN (0, 1)),
    -- 消费开关（消费轴生效值，提交时合流快照）：1 = 构建 builddep 可注入
    -- 产品 repo（默认）。合流谓词：产品可见性 public ∧ 产品 repo-consume
    -- 未关闭 ∧ 未逐构建收紧（--no-consume）——private 产品一票否决，逐构建
    -- 只许收紧无放宽形态；dispatch 直接读本列，与 repo_publish 正交
    --（发布侧清空候选集不影响本开关，反之亦然）。
    repo_consume INTEGER NOT NULL DEFAULT 1 CHECK (repo_consume IN (0, 1)),
    -- 失败原因摘要：worker / hub-local 失败路径写入，UI 详情页展示。
    error_summary TEXT,
    -- 确定性构建标记：1 = 该构建在 deterministic 产品模式下执行。
    -- 风格与 signed/repo_publish/repo_consume 同族：INTEGER 0/1 双方言同型（不转 BOOLEAN）。
    deterministic INTEGER NOT NULL DEFAULT 0 CHECK (deterministic IN (0, 1)),
    -- 血缘锚：输入 SRPM 原样字节的 sha256，任务内全部架构子构建
    -- 共享同一值；hub 新构建统一计算（?srpm_sha256= 索引键），历史行 /
    -- worker 镜像行 NULL（见 schema.sql 同列注）。
    canonical_srpm_sha256 TEXT,
    -- 批次归属 + 资源采集追加列（全部可空、无 DEFAULT：未采集场景均为
    -- 合法 NULL；列语义见 schema.sql 同列段注）。
    batch_id BIGINT REFERENCES build_batches(id) ON DELETE SET NULL,
    -- 入队时刻（INSERT 写入；历史回灌/镜像行可空）。
    created_at TEXT,
    peak_rss_kb BIGINT,
    -- 浮点列：写入必须走 `Dialect::float_param_cast`（见 schema.sql 同列注）。
    cpu_secs DOUBLE PRECISION,
    cpu_p90_cores DOUBLE PRECISION,
    -- 输入 SRPM 大小（字节）：enqueue staging 后 stat 写入；stat 失败或
    -- 未经该路径的构建为 NULL（见 schema.sql 同列段注）。
    srpm_size_bytes BIGINT,
    -- ============ 资源感知链（一次定稿：声明/采集/画像三面）============
    -- 以下九列可空、无 DEFAULT（沿用上方资源组口径）：缺数据 = NULL =
    -- 调度降级放行，绝不阻塞领取与终态写入。声明面（req_min_*：提交时
    -- 物化、扇出继承）/ 采集包络面（peak_total_kb / disk_wbytes）/ OOM
    -- 检出与采样口径的逐列段注与 schema.sql 同文，见该处资源感知链段。
    req_min_mem_kb BIGINT,
    req_min_ncpu BIGINT,
    req_min_disk_kb BIGINT,
    peak_total_kb BIGINT,
    disk_wbytes BIGINT,
    oom_killed INTEGER CHECK (oom_killed IN (0, 1)),
    sample_backend TEXT CHECK (sample_backend IN ('cgroup', 'proc')),
    sample_ncpu BIGINT,
    -- 构建自身 tmpfs 占用峰值 KB（build_tmpfs 关闭恒 NULL，采样 best-effort；
    -- 列语义见 schema.sql 同列段注）。
    peak_tmpfs_kb BIGINT
);

-- 6. worker_tasks (FK: workers, builds, tasks, products)
CREATE TABLE worker_tasks (
    id BIGSERIAL PRIMARY KEY,
    build_id BIGINT REFERENCES builds(id) ON DELETE SET NULL,
    worker_id BIGINT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    task_id BIGINT REFERENCES tasks(id) ON DELETE SET NULL,
    -- status 全集 = validate_worker_task_status 白名单（INSERT 恒
    -- 'assigned'，running 中间态，completed/failed/cancelled 终态）。
    status TEXT DEFAULT 'assigned' CHECK (status IN ('assigned', 'running', 'completed', 'failed', 'cancelled')),
    assigned_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    started_at TEXT,
    completed_at TEXT,
    result_json TEXT,
    -- 分配行只有 build（默认）/ init 两族（insert_worker_task_build /
    -- insert_init_assignment 两条 INSERT 收口）。
    kind TEXT NOT NULL DEFAULT 'build' CHECK (kind IN ('build', 'init')),
    init_product TEXT,
    init_product_id BIGINT REFERENCES products(id) ON DELETE SET NULL
);
-- 同一 worker 同产品至多一条活跃 init：SQLite BEGIN IMMEDIATE 已串行，
-- PG READ COMMITTED 下 "查活跃→插入" 仍可并发双插，唯一索引是 DB 级兜底。
CREATE UNIQUE INDEX IF NOT EXISTS uq_worker_tasks_active_init
    ON worker_tasks(worker_id, init_product)
    WHERE kind = 'init' AND status IN ('assigned', 'running');


-- 7. user_tokens (FK: users)
CREATE TABLE user_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    hash TEXT NOT NULL UNIQUE,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    revoked_at TEXT
);

-- 7b. sessions (FK: users, ON DELETE CASCADE) — UI 密码登录会话。
-- hash 是 crbs_sess_ 明文的 SHA-256（与 user_tokens 同模式）；时间列 TEXT
-- UTC 墙钟；撤销 = revoked_at 置位。
CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    agent TEXT
);

-- 8. product_acl (FK: products, users)
CREATE TABLE product_acl (
    product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'builder', 'admin')),
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    PRIMARY KEY (product_id, user_id)
);

-- 9. audit_logs (无外键)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    "user" TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
);

-- 10. layer_packages (FK: products)
CREATE TABLE layer_packages (
    digest TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    packages TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    product_id BIGINT REFERENCES products(id) ON DELETE SET NULL
);

-- 11. package_urls (无外键)
CREATE TABLE package_urls (
    repo_baseurl TEXT NOT NULL,
    nevra        TEXT NOT NULL,
    url          TEXT NOT NULL,
    created_at   BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::bigint,
    last_used_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::bigint,
    PRIMARY KEY (repo_baseurl, nevra)
);

-- 12. layers (FK: products)
CREATE TABLE layers (
    digest TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    product TEXT NOT NULL,
    -- 唯一写入点 upsert_layer 恒写 'complete'（GC 扫描谓词同值）。
    status TEXT NOT NULL CHECK (status = 'complete'),
    ref_count INTEGER DEFAULT 0 CHECK(ref_count >= 0),
    created_at TEXT,
    scheduled_gc_at TEXT,
    product_id BIGINT REFERENCES products(id) ON DELETE SET NULL
);

-- 13. product_config_history (FK: products, users)
-- base_os_revision 无 DEFAULT（对齐 SQLite；唯一
-- 插入点 INSERT_HISTORY 恒显式供给该列）。
CREATE TABLE product_config_history (
    product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    parent_id BIGINT,
    base_os_revision INTEGER NOT NULL,
    changed_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    changed_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    reason TEXT,
    PRIMARY KEY (product_id, revision)
);

-- 14. app_meta (无外键)
CREATE TABLE app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
);


-- ===== 索引 =====
-- 列表复合索引：list_builds/list_tasks 的 WHERE + ORDER BY id DESC 查询面
CREATE INDEX IF NOT EXISTS idx_builds_user_id ON builds("user", id DESC);
CREATE INDEX IF NOT EXISTS idx_builds_phase_id ON builds(phase, id DESC);
-- 派发热路径候选集（满载整仓：pending 峰值 ~16k 行，pick 每秒多次）：
-- partial 谓词只留"真可派发"（就绪）行，前导 (priority, started_at) 服务
-- 权重排序的前缀段。权重表达式（priority*86400+等待秒）允许低优先级累计
-- 等待反超，索引序只是缩候选集的缓解而非精确等价——两段式查询留待真实
-- 满载出现慢派发再议。
CREATE INDEX IF NOT EXISTS idx_builds_pending_pick
    ON builds(priority DESC, started_at)
    WHERE phase = 'pending' AND srpm_path IS NOT NULL AND request_json IS NOT NULL;
-- 仪表盘时长图 top-N 与 retention cutoff 删除的排序键（整仓后 succeeded
-- 全集 ~16k 行顺序扫）。
CREATE INDEX IF NOT EXISTS idx_builds_completed
    ON builds(completed_at DESC) WHERE completed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_builds_product_id ON builds(product, id DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_phase_id ON tasks(phase, id DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_product_id ON tasks(product, id DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks("user", id DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_submitted_id ON tasks(submitted_at DESC, id DESC);

-- 索引面按查询点建：单列 phase/product/task_id 与 tasks 单列由对应复合索引
-- 前导列覆盖，build_artifacts 的 build_id 前缀由 UNIQUE (build_id,
-- relative_path) 覆盖；产品名全局唯一，UNIQUE idx_products_name 已定行，不建
-- owner 前缀索引；layers.ref_count 无独立查询面（仅 digest 点查 / GC 扫描
-- 谓词），phase+product 无组合查询面（product 维度由 idx_builds_product_id 服务）。
-- 以下索引对应固定查询点：crbs_pid 僵尸/恢复（builds.rs）、task_id(+arch)
-- 聚合（tasks/query.rs）、worker 认证 partial（workers/mod.rs）、audit action
-- 过滤、layers GC partial（gc_queries.rs 谓词逐字匹配）。
CREATE INDEX idx_builds_phase_pid ON builds(phase, crbs_pid);
CREATE INDEX idx_builds_task_arch ON builds(task_id, arch);
-- 内容检索（?srpm_sha256= 等值过滤）：仅索引已采集血缘锚的行。
CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256
    ON builds(canonical_srpm_sha256) WHERE canonical_srpm_sha256 IS NOT NULL;
-- 活跃去重复查（EXISTS_ACTIVE_DUPLICATE_BUILD：product/pkg_name
-- 等值 + phase 活跃集，跑在每次 submit 的写事务内）的索引支撑——与 schema.sql
-- 同文（WHERE 谓词与查询的 phase 集合逐字一致，planner 识别前提）。
CREATE INDEX idx_builds_product_pkg_active ON builds(product, pkg_name)
    WHERE phase IN ('pending', 'assigned', 'building');
-- 活跃构建去重的数据库级收口（READ COMMITTED 下先查后插语句间隙的并发
-- 双插在提交点被拒）——与 schema.sql 同文。arch 可空而 UNIQUE 默认 NULLS
-- DISTINCT，表达式 COALESCE 归一与查询的 NULL=NULL 命中语义对齐；WHERE
-- phase 集合与查询谓词逐字同文（两侧 baseline 文本互钉，守卫测试见 builds.rs）。
CREATE UNIQUE INDEX uq_active_builds_identity ON builds(product, pkg_name, COALESCE(arch, ''))
    WHERE phase IN ('pending', 'assigned', 'building');
-- 按包聚合历史资源/时长的全行索引（builds 全历史行）。与上方两个 partial
-- 索引（idx_builds_product_pkg_active / uq_active_builds_identity：仅活跃行、
-- 服务提交去重）语义不同——全行 vs 活跃行，查询面互补，并存不可互删；与
-- schema.sql 同名索引对称注记。
CREATE INDEX idx_builds_product_pkg_phase ON builds(product, pkg_name, phase);

CREATE INDEX idx_worker_tasks_status ON worker_tasks(status);
CREATE INDEX idx_worker_tasks_worker ON worker_tasks(worker_id);
CREATE INDEX idx_worker_tasks_build ON worker_tasks(build_id);

CREATE INDEX idx_workers_status ON workers(status);
CREATE INDEX idx_workers_arch ON workers(arch);
CREATE INDEX idx_workers_secret_hash ON workers(secret_hash) WHERE secret_hash IS NOT NULL;

CREATE INDEX idx_products_owner ON products(owner_id);
CREATE INDEX idx_products_parent ON products(parent_id);

-- 产品名全局唯一（命名空间全局）：官方产品 <> 私人产品 <> 不同用户私人产品
-- 之间都不重名；单列 UNIQUE 同时为 READ COMMITTED 下的并发竞态提供兜底。
CREATE UNIQUE INDEX idx_products_name ON products(name);

CREATE INDEX idx_product_acl_user ON product_acl(user_id);

CREATE INDEX idx_user_tokens_user ON user_tokens(user_id);
CREATE UNIQUE INDEX idx_user_tokens_user_name ON user_tokens(user_id, name) WHERE name IS NOT NULL;

-- 与 SQLite 同名索引对齐；audit 列表按 id DESC
-- 排序，created_at 索引服务范围过滤，方向无查询面差异。
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs("user");
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE INDEX idx_package_urls_last_used ON package_urls(last_used_at);

CREATE INDEX idx_layers_product ON layers(product);
CREATE INDEX idx_layers_gc ON layers(scheduled_gc_at)
    WHERE status = 'complete' AND ref_count = 0;

-- 15. build_artifacts (FK: builds)
-- 构建产物元数据：每个 build 对应 N 个 artifact 行
-- 通用约定：TEXT 时间 / INTEGER bool / BIGSERIAL / ON DELETE CASCADE / ON CONFLICT 幂等
CREATE TABLE build_artifacts (
    id            BIGSERIAL PRIMARY KEY,
    build_id      BIGINT NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('rpm', 'srpm', 'log', 'metadata', 'script', 'other')),
    size_bytes    BIGINT NOT NULL,
    sha256        TEXT NOT NULL,
    -- 签名前哈希留档：与 schema.sql 同列同语义（见该处注）。
    unsigned_sha256 TEXT,
    arch          TEXT,
    name          TEXT,
    version       TEXT,
    release       TEXT,
    epoch         INTEGER,
    signed        INTEGER NOT NULL DEFAULT 0 CHECK (signed IN (0, 1)),
    on_disk       INTEGER NOT NULL DEFAULT 1 CHECK (on_disk IN (0, 1)),
    metadata_json TEXT,
    created_at    TEXT NOT NULL,
    UNIQUE (build_id, relative_path)
);

-- idx_artifacts_build 冗余清理：UNIQUE (build_id, relative_path) 约束
-- 索引已覆盖 build_id 前缀。
CREATE INDEX idx_artifacts_sha256 ON build_artifacts(sha256);
CREATE INDEX idx_artifacts_pkg    ON build_artifacts(name, arch);

-- 16. build_reproducibility（语义见 schema.sql 同表注）
CREATE TABLE build_reproducibility (
    id               BIGSERIAL PRIMARY KEY,
    kind             TEXT NOT NULL DEFAULT 'replay' CHECK (kind IN ('replay', 'cross_arch_noarch')),
    source_build_id  BIGINT NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    replay_build_id  BIGINT REFERENCES builds(id) ON DELETE SET NULL,
    verdict          TEXT NOT NULL CHECK (verdict IN ('same', 'diff', 'build_failed', 'dep_unavailable', 'infra_error')),
    detail_json      TEXT,
    compared_at      TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
);
CREATE INDEX idx_build_repro_source ON build_reproducibility(source_build_id);
CREATE INDEX idx_build_repro_replay ON build_reproducibility(replay_build_id);
-- 复现率看板 cutoff 过滤（compared_at 之前无索引，整仓后行数随确定性
-- 构建翻倍增长）。
CREATE INDEX IF NOT EXISTS idx_build_repro_compared
    ON build_reproducibility(compared_at DESC);
-- 任务级收口去重（同一 task 的 cross_arch_noarch 比对只记一行；与 SQLite
-- 侧同 partial UNIQUE，见 schema.sql 同索引注）。
CREATE UNIQUE INDEX idx_build_repro_cross_arch ON build_reproducibility(source_build_id) WHERE kind = 'cross_arch_noarch';

-- 17. worker_telemetry_samples (FK: workers)
-- Worker 遥测历史采样：心跳路径 best-effort 追加写（表/列语义与删除语义见
-- schema.sql 同表注：只 INSERT 不 UPDATE、retention 按 sampled_at 删、
-- worker 删除级联带走；建序在 workers 之后，FK 引用先建）。
CREATE TABLE worker_telemetry_samples (
    id BIGSERIAL PRIMARY KEY,
    worker_id BIGINT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    sampled_at TEXT NOT NULL,
    -- 浮点列：写入必须走 `Dialect::float_param_cast`（见 schema.sql 同列注）。
    cpu_util_pct DOUBLE PRECISION,
    mem_used_pct DOUBLE PRECISION,
    load1 DOUBLE PRECISION,
    ncpu BIGINT,
    mem_total_kb BIGINT,
    -- 节点可用磁盘 KB（逐帧采样；调度读最新值走 workers.disk_free_kb，
    -- 本表是 worker 详情页磁盘折线数据源，见 schema.sql 同列注）。
    disk_free_kb BIGINT
);
-- 详情页趋势图窗口查询（worker + 时间范围）的索引支撑。
CREATE INDEX idx_telemetry_samples_worker_time
    ON worker_telemetry_samples(worker_id, sampled_at);
-- 遥测 retention 的全局时间删（与 worker 维查询索引互补；ORDER BY sampled_at,id）。
CREATE INDEX IF NOT EXISTS idx_telemetry_samples_sampled_at
    ON worker_telemetry_samples(sampled_at, id);

-- 20. package_resource_profiles（无 FK，TEXT 三元组键）
-- 包资源画像：声明面（declared_*，hub admin 显式钉入的放置契约）与学习面
--（learned_*，构建终态自动维护的估计值）同表双列组。键不挂 FK / source_name
-- 口径（= builds.name 源码包基础名，版本维只留在 builds 历史）/ arch 口径 /
-- retention 豁免 / 列组隔离等全注与 schema.sql 同文，见该处同表注。
CREATE TABLE package_resource_profiles (
    product TEXT NOT NULL,
    source_name TEXT NOT NULL,
    arch TEXT NOT NULL,
    declared_min_mem_kb BIGINT,
    declared_min_ncpu BIGINT,
    declared_min_disk_kb BIGINT,
    declared_updated_at TEXT,
    learned_ema_mem_kb BIGINT,
    learned_max_mem_kb BIGINT,
    -- tmpfs 峰值 EMA/最大：与 mem 同语义（EMA 只折叠 succeeded、max 只抬
    -- 不降）；样本不带 tmpfs 值时不折叠，两列维持原值。statfs 绝对值与
    -- 采样口径无关，proc→cgroup 升级重置不清这两列。
    learned_ema_tmpfs_kb BIGINT,
    learned_max_tmpfs_kb BIGINT,
    -- 浮点列：写入必须走 `Dialect::float_param_cast`（见 schema.sql 同列注）。
    learned_ema_ncpu DOUBLE PRECISION,
    learned_max_ncpu DOUBLE PRECISION,
    learned_samples INTEGER NOT NULL DEFAULT 0,
    learned_sample_ncpu BIGINT,
    learned_backend TEXT CHECK (learned_backend IN ('cgroup', 'proc')),
    learned_censored INTEGER NOT NULL DEFAULT 0 CHECK (learned_censored IN (0, 1)),
    learned_updated_at TEXT,
    created_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    updated_at TEXT NOT NULL DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
    PRIMARY KEY (product, source_name, arch)
);
-- 画像面板：产品内 top-N 资源大户。
CREATE INDEX idx_profiles_product_mem ON package_resource_profiles(product, learned_ema_mem_kb);
