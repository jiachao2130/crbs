-- crbs state schema (baseline v1)
--
-- 由 `state/migrate.rs` 通过 `include_str!` 内联并逐语句执行（fresh init 时
-- 建库）。此文件即唯一 baseline：schema 变更直接修改本文件（与
-- schema.pg.sql 双侧同步）即可——未发布阶段不保留兼容迁移，版本闩恒为
-- (1, 1)，任何旧形态存量库一律 fail-closed 拒启、按指引重新 init。
--
-- 运营规则：正式发布后 schema 变更攒批低频 bump，绝不因单列需求单独发版。
--
-- CHECK 约束族已全量带入本 baseline：phase / status / kind / role 枚举列与
-- 布尔列两侧对称加 CHECK，值域与 Rust 写入点逐一核对（见各列 CHECK 注记）。
--
-- 方言：SQLite（Postgres baseline 见 schema.pg.sql）。切换 Postgres 时的机械替换要点：
--   - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`
--   - 时间列两侧保持 TEXT UTC 帧：`DEFAULT (datetime('now'))` →
--     `DEFAULT to_char(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')`
--     （对齐 schema.pg.sql 头注；禁止造 TIMESTAMPTZ 列，会破坏 TEXT 对称）
--   - `INTEGER DEFAULT (strftime('%s','now'))` → `BIGINT DEFAULT EXTRACT(EPOCH FROM NOW())::bigint`
--   - `INTEGER NOT NULL DEFAULT 0` 作 boolean → 保持 INTEGER 0/1（不转 BOOLEAN，避免类型双轨）

-- ===== 表 =====

CREATE TABLE builds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    -- phase 全集（7 值）= 代码写入点逐一核对——INSERT 恒 'pending'
    --（build_lifecycle），'assigned'/'building'（worker 上报，store 层
    -- update_build_phase 白名单），终态四值（complete_build* 终态守卫）。
    phase TEXT NOT NULL CHECK (phase IN ('pending', 'assigned', 'building', 'succeeded', 'failed', 'cancelled', 'timeout')),
    result_dir TEXT,
    -- 本次执行尝试的计时起点（派发/回收时重置），非入队时刻。
    started_at TEXT,
    completed_at TEXT,
    layer_digest TEXT,
    base_os_digest TEXT,
    backend TEXT,
    duration INTEGER,
    user TEXT NOT NULL DEFAULT '',
    crbs_pid INTEGER,
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
    -- 每条构建必须挂任务（引擎本地构建由 BuildLifecycle 先插本地
    -- 任务行承接，结构性杜绝 standalone 行）。
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    user_id INTEGER REFERENCES users(id),
    product_id INTEGER NULL REFERENCES products(id) ON DELETE SET NULL,
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
    -- 共享同一值。hub 新构建统一计算（内容检索 ?srpm_sha256= 的索引键，
    -- 按暂存 SRPM 计算）；历史行 / worker 镜像行 NULL。比对侧不消费本列
    -- （比对锚是 build_artifacts.unsigned_sha256）——本列是配方导出
    --（锁定输入快照）的地基。
    canonical_srpm_sha256 TEXT,
    -- 批次归属：整仓重建批次（build_batches），NULL = 非批次提交的常规构建。
    -- ON DELETE SET NULL：删批次不得被历史 builds 行阻塞（product_id 同口径）。
    batch_id INTEGER REFERENCES build_batches(id) ON DELETE SET NULL,
    -- 入队时刻（INSERT 写入；历史回灌/worker 镜像行可空）。
    -- 排队时长以最新 build 型 worker_tasks.assigned_at 为准。
    -- 以下六列全部可空、无 DEFAULT：未采集场景（chroot 后端无 cgroup、
    -- 无采样上报）都是合法 NULL；NOT NULL 无 DEFAULT 会同时打断 hub 与
    -- worker 本地库（同一份 baseline）的 INSERT。
    created_at TEXT,
    -- 构建期匿名内存峰值 KB；不可得时为保守上界口径（含共享页重复计数的
    -- /proc 求和等，写入点列注为准）。
    peak_rss_kb INTEGER,
    -- 构建期累计 CPU 时间（秒）。REAL 浮点列：写入必须走
    -- `Dialect::float_param_cast`（sqlx Any 驱动 Option<f64> 直绑的 FLOAT4
    -- 钉型坑，心跳遥测 load1/mem_used_pct 同款注释）。
    cpu_secs REAL,
    -- 采样窗内平均占用核数的 90 分位（机器无关的核数口径）；浮点同上。
    cpu_p90_cores REAL,
    -- 输入 SRPM 大小（字节）：enqueue staging 后 stat 写入；stat 失败或
    -- 未经该路径的构建为 NULL（ResourceUsage 三列不含它）。
    srpm_size_bytes INTEGER,
    -- ============ 资源感知链（一次定稿：声明/采集/画像三面）============
    -- 以下九列可空、无 DEFAULT（沿用上方资源组口径）：缺数据 = NULL =
    -- 调度降级放行，绝不阻塞领取与终态写入。
    --
    -- 声明面：提交时从任务显式声明物化，是调度"硬下限"的唯一构建侧输入；
    -- 扇出子构建全部继承；reproduce 沿源构建继承。declared/learned 在调度
    -- 侧逐维回退解析，不在此物化。
    req_min_mem_kb INTEGER,
    req_min_ncpu INTEGER,
    req_min_disk_kb INTEGER,
    -- 采集包络面：anon tick-max 之外的内核原生上界与磁盘足迹，供排查与
    -- 展示；不进准入口径（anon 仍是 sizing 主口径）。仅 worker 能力位
    -- 可用时写入，否则 NULL。
    peak_total_kb INTEGER,
    disk_wbytes INTEGER,
    -- OOM 检出：memory.events oom_kill 增量检出置 1；NULL = 口径不可用。
    -- 删失学习依据；撞自身 memory_max 的 cap-OOM 除外。
    oom_killed INTEGER CHECK (oom_killed IN (0, 1)),
    -- 采样口径：画像学习不跨口径混算（cgroup anon 与 /proc 共享页重复计
    -- 量纲不同）。
    sample_backend TEXT CHECK (sample_backend IN ('cgroup', 'proc')),
    -- 执行节点核数：peak_rss 与 -j$(nproc) 并行度耦合（sample_ncpu 是
    -- 解读画像的必要上下文）；远期并行度感知学习的数据基础。
    sample_ncpu INTEGER,
    -- 构建自身 tmpfs 挂载实例占用峰值 KB：shared_layer 构建读 BUILD tmpfs 挂
    -- 载点、全内存构建读独立 memroot 挂载点，statfs 绝对值。build_tmpfs 关闭
    -- 恒 NULL，采样 best-effort（读失败 tick 不回填，缺数据 = NULL = 降级放行）。
    peak_tmpfs_kb INTEGER
);

CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product TEXT NOT NULL,
    pkg_name TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT '',
    -- 与 builds.phase 同一 7 值全集。聚合写路径（aggregate_child_phases）
    -- 不产 'assigned'，但任务 phase 读守卫（lifecycle 活跃态谓词）显式承认
    -- 该中间态，故一并纳入域内。
    phase TEXT NOT NULL DEFAULT 'pending' CHECK (phase IN ('pending', 'assigned', 'building', 'succeeded', 'failed', 'cancelled', 'timeout')),
    priority INTEGER NOT NULL DEFAULT 0,
    srpm_path TEXT,
    result_dir TEXT,
    submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    duration INTEGER,
    user_id INTEGER REFERENCES users(id),
    name TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    release TEXT NOT NULL DEFAULT '',
    request_json TEXT,
    pkg_names TEXT,
    product_id INTEGER NULL REFERENCES products(id) ON DELETE SET NULL
);

-- 任务级通用键值标签：提交时声明，随任务删除级联清理。键值均为不透明
-- 元数据（示例见文档，无系统保留键）；同一 (key, value) 可被多个任务
-- 共享，任务内按键唯一。
CREATE TABLE task_labels (
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (task_id, key)
);

CREATE TABLE workers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    arch TEXT NOT NULL,
    capacity INTEGER NOT NULL DEFAULT 1,
    -- 生产写入仅 online/offline（注册/离线/恢复收口）；'draining'/
    -- 'suspended' 是状态机守卫显式保护的管理员保留态（guard 谓词与测试
    -- fixture 均引用），故入域。
    status TEXT DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'draining', 'suspended')),
    last_heartbeat TEXT,
    version TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    secret_hash TEXT,
    secret_expires_at TEXT,
    load1 REAL,
    ncpu INTEGER,
    -- CPU 利用率百分比 0-100（/proc/stat 相邻两心跳差分，busy = Δtotal −
    -- Δidle − Δiowait，iowait 不计忙）；可空 = 无采样窗口 / 非 Linux。
    cpu_util_pct REAL,
    mem_used_pct REAL,
    -- 节点内存总量 KB（内存准入门的换算基准；心跳随载上报，可空 = 未上报）。
    -- 定为 INTEGER 而非 REAL：绕开浮点参数直绑的驱动钉型坑（见 builds.cpu_secs
    -- 列注）。
    mem_total_kb INTEGER,
    -- 心跳上报的节点可用磁盘 KB（工件卷 df 1K 块口径；NULL = 未上报，
    -- 磁盘硬下限维度 fail-closed）。INTEGER 直绑避浮点钉型坑
    -- （mem_total_kb 同款先例）。调度读最新值走本列；心跳同时把它追加进
    -- worker_telemetry_samples（历史折线的展示数据源）。
    disk_free_kb INTEGER,
    -- 节点采集能力位图（启动探测，注册/心跳携带；NULL = 未上报，
    -- 全部按不可用降级）。位定义 state 层常量：bit0 cgroup_v2、
    -- bit1 memory_peak、bit2 memory_events、bit3 io_stat、bit4 psi；
    -- 后续新能力只加位不改表。
    resource_caps INTEGER
);

-- 三 FK 对齐 PG：build_id/task_id ON DELETE SET NULL、
-- worker_id ON DELETE CASCADE。
CREATE TABLE worker_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    build_id INTEGER REFERENCES builds(id) ON DELETE SET NULL,
    worker_id INTEGER NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    -- status 全集 = validate_worker_task_status 白名单（INSERT 恒
    -- 'assigned'，running 中间态，completed/failed/cancelled 终态）。
    status TEXT DEFAULT 'assigned' CHECK (status IN ('assigned', 'running', 'completed', 'failed', 'cancelled')),
    assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
    started_at TEXT,
    completed_at TEXT,
    result_json TEXT,
    -- 分配行只有 build（默认）/ init 两族（insert_worker_task_build /
    -- insert_init_assignment 两条 INSERT 收口）。
    kind TEXT NOT NULL DEFAULT 'build' CHECK (kind IN ('build', 'init')),
    init_product TEXT,
    init_product_id INTEGER NULL REFERENCES products(id) ON DELETE SET NULL
);
-- 同一 worker 同产品至多一条活跃 init：SQLite BEGIN IMMEDIATE 已串行，
-- PG READ COMMITTED 下 "查活跃→插入" 仍可并发双插，唯一索引是 DB 级兜底。
CREATE UNIQUE INDEX IF NOT EXISTS uq_worker_tasks_active_init
    ON worker_tasks(worker_id, init_product)
    WHERE kind = 'init' AND status IN ('assigned', 'running');


CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    -- 全局角色全集 = API/CLI 共用的 VALID_ROLES。
    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'builder', 'viewer')),
    -- status 全集 = 用户管理 API 校验（'active'/'disabled'）。
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- 密码登录。password_hash NULL = 未设密码；独立行映射结构读取，
    -- 绝不加进 Serialize 的 User 结构。
    password_hash TEXT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1))
);

CREATE TABLE user_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- ON DELETE CASCADE 对齐 PG：生产无用户删除路径，漂移仅潜伏。
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    hash TEXT NOT NULL UNIQUE,
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at TEXT
);

-- UI 密码登录会话。hash 是 crbs_sess_ 明文的 SHA-256（与
-- user_tokens 同模式）；时间列 TEXT UTC 墙钟；撤销 = revoked_at 置位。
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    agent TEXT
);

CREATE TABLE product_acl (
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'builder', 'admin')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (product_id, user_id)
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE layer_packages (
    digest TEXT PRIMARY KEY,
    product TEXT NOT NULL,
    packages TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    product_id INTEGER NULL REFERENCES products(id) ON DELETE SET NULL
);

CREATE TABLE package_urls (
    repo_baseurl TEXT NOT NULL,
    nevra        TEXT NOT NULL,
    url          TEXT NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_used_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (repo_baseurl, nevra)
);

CREATE TABLE layers (
    digest TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    product TEXT NOT NULL,
    -- 唯一写入点 upsert_layer 恒写 'complete'（GC 扫描谓词同值）。
    status TEXT NOT NULL CHECK (status = 'complete'),
    ref_count INTEGER DEFAULT 0 CHECK(ref_count >= 0),
    created_at TEXT,
    scheduled_gc_at TEXT,
    product_id INTEGER NULL REFERENCES products(id) ON DELETE SET NULL
);

-- 产品配置（DB 权威，替代磁盘 products/*.toml）
--
-- name：产品短名（"mydist"、"openeuler-24.03"）。
-- owner_id：所属用户。官方产品为 NULL；用户私人产品时使用。
-- parent_id：继承的父产品。无父产品时为 NULL。
-- visibility：'public' | 'private'。官方产品（owner_id
--     IS NULL）由 CHECK 约束强制为 'public'。
-- config_json：ProductConfig 的 serde_json 表示。作为唯一权威来源；worker 下发
--     时先反序列化 → 再 to_toml_string()。
-- revision：每次 update 单调递增。用于 history 追踪与 chain-resolve 缓存失效。
-- base_os_revision：仅当"触发 base_os 重建"字段（base_packages / repos /
--     releasever / overlay_dir / post_init / builder_* / arches / shared_layer /
--     backend / product_root / base_os_path / ccache_enabled 等）
--     被修改时 = 当前 revision，否则保持不变。reinit gate 用它判断产物是否过期。
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    display_name TEXT,
    -- ON DELETE RESTRICT：删用户前须先 transfer/delete 其产品，避免 CASCADE
    -- 静默清光其配置与历史（语义：产品所有权是长期契约，用户账号消失不代表产品消失）。
    owner_id INTEGER REFERENCES users(id) ON DELETE RESTRICT,
    parent_id INTEGER REFERENCES products(id) ON DELETE RESTRICT,
    -- DEFAULT 'private'：安全默认，INSERT 省略 visibility 时不会造出"公开的私人产品"。
    -- 官方产品由下方 CHECK 强制 public；private 需 INSERT 显式传值（seed/API 均已显式）。
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('public', 'private')),
    config_json TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    base_os_revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    -- 官方产品（owner_id IS NULL）强制 public
    CHECK (owner_id IS NOT NULL OR visibility = 'public')
);

-- 产品配置历史。每次 update_product_config 事务内追加一条，revision 从 1 起。
-- 删除 product 时随 CASCADE 一并删除。
CREATE TABLE product_config_history (
    product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    parent_id INTEGER,  -- 该 revision 时的父产品，无父产品为 NULL
    base_os_revision INTEGER NOT NULL,
    changed_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    changed_at TEXT NOT NULL DEFAULT (datetime('now')),
    reason TEXT,
    PRIMARY KEY (product_id, revision)
);

-- 应用级元数据：seed 门闩等启动一次性状态。
-- 通过 key/value 存储，避免为每种门闩单独建表。
CREATE TABLE app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ===== 索引 =====

-- 列表复合索引：list_builds/list_tasks 的 WHERE + ORDER BY id DESC 查询面
CREATE INDEX IF NOT EXISTS idx_builds_user_id ON builds(user, id DESC);
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
CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks(user, id DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_submitted_id ON tasks(submitted_at DESC, id DESC);
-- 标签等值过滤（?label=key:value / --label）与按值反查。
CREATE INDEX IF NOT EXISTS idx_task_labels_key_value ON task_labels(key, value);

-- 索引面按查询点建：被 UNIQUE/复合索引前导列完全覆盖的单列索引不建——
-- builds.phase/product、builds.task_id、tasks.phase 各由对应复合索引服务，
-- build_artifacts 的 build_id 前缀由 UNIQUE (build_id, relative_path) 覆盖，
-- worker_tasks.task 与 user_tokens.hash 无独立查询面。
CREATE INDEX idx_builds_phase_pid ON builds(phase, crbs_pid);
CREATE INDEX idx_builds_task_arch ON builds(task_id, arch);
-- 内容检索（?srpm_sha256= 等值过滤）：仅索引已采集血缘锚的行。
CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256
    ON builds(canonical_srpm_sha256) WHERE canonical_srpm_sha256 IS NOT NULL;
-- 活跃去重复查（EXISTS_ACTIVE_DUPLICATE_BUILD：product/pkg_name
-- 等值 + phase 活跃集，跑在每次 submit 的写事务内）的索引支撑。避免退化为
-- idx_builds_product_id（点查 O(该 product 全历史行)）或 idx_builds_phase_id
-- （O(同 phase 全行)），大库上写锁持有时间会随历史线性增长。WHERE 谓词与查询的
-- phase 集合逐字一致（planner 识别 partial 索引可用性的前提）；arch 维度不进
-- 索引列/谓词（查询侧 COALESCE 归一 NULL，任何含 arch 的索引形态都无法匹配）。
CREATE INDEX idx_builds_product_pkg_active ON builds(product, pkg_name)
    WHERE phase IN ('pending', 'assigned', 'building');
-- 活跃构建去重的数据库级收口——先查后插（EXISTS_ACTIVE_DUPLICATE_BUILD）
-- 在 PG READ COMMITTED 下语句间隙仍可漏入并发双插，partial UNIQUE 在提交点
-- 兜底拒绝。arch 可空而 UNIQUE 语义 NULL 互异，索引用表达式 COALESCE 归一
-- （与查询的 NULL=NULL 命中语义对齐）；WHERE phase 集合与查询谓词逐字同文
-- （查询谓词与两侧 baseline 文本互钉，守卫测试见 builds.rs）。
CREATE UNIQUE INDEX uq_active_builds_identity ON builds(product, pkg_name, COALESCE(arch, ''))
    WHERE phase IN ('pending', 'assigned', 'building');
-- 按包聚合历史资源/时长的全行索引（builds 全历史行）。与上方两个 partial
-- 索引（idx_builds_product_pkg_active / uq_active_builds_identity：仅活跃行、
-- 服务提交去重）语义不同——全行 vs 活跃行，查询面互补，并存不可互删。
CREATE INDEX idx_builds_product_pkg_phase ON builds(product, pkg_name, phase);
CREATE INDEX idx_workers_arch ON workers(arch);
CREATE INDEX idx_workers_status ON workers(status);
CREATE INDEX idx_workers_secret_hash ON workers(secret_hash) WHERE secret_hash IS NOT NULL;
CREATE INDEX idx_worker_tasks_build ON worker_tasks(build_id);
CREATE INDEX idx_worker_tasks_worker ON worker_tasks(worker_id);
CREATE INDEX idx_worker_tasks_status ON worker_tasks(status);
CREATE INDEX idx_audit_logs_user ON audit_logs(user);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
-- 方向差（有意，与 schema.pg.sql 同名索引对称注记）：此侧缺省 ASC，pg 侧为
-- `created_at DESC`——audit 列表按 id DESC 排序，created_at 索引仅服务范围
-- 过滤，方向无查询面差异；双 baseline 等价守卫（migrate.rs
-- baseline_equivalence）按索引名比对、不比方向。
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
-- token 按 user 列举（users.rs LIST_USER_TOKENS_*）
-- 与"token 名每用户唯一"（PG baseline 起强制，SQLite 插入无查重的语义
-- 漂移由此对齐）。
CREATE INDEX idx_user_tokens_user ON user_tokens(user_id);
CREATE UNIQUE INDEX idx_user_tokens_user_name ON user_tokens(user_id, name) WHERE name IS NOT NULL;
CREATE INDEX idx_product_acl_user ON product_acl(user_id);
CREATE INDEX idx_package_urls_last_used ON package_urls(last_used_at);
CREATE INDEX idx_layers_gc ON layers(scheduled_gc_at)
    WHERE status = 'complete' AND ref_count = 0;
-- product 维度查询/删除面对齐 PG。
CREATE INDEX idx_layers_product ON layers(product);
CREATE INDEX idx_products_owner ON products(owner_id);
CREATE INDEX idx_products_parent ON products(parent_id);
-- 产品名全局唯一（命名空间全局）：官方产品 <> 私人产品 <> 不同用户私人产品
-- 之间都不重名；单列 UNIQUE 同时为并发竞态提供数据库级兜底。
CREATE UNIQUE INDEX idx_products_name ON products(name);

-- 15. build_artifacts (FK: builds)
-- 构建产物元数据：每个 build 对应 N 个 artifact 行
-- 通用约定：TEXT 时间 / INTEGER bool / ON DELETE CASCADE / ON CONFLICT 幂等
CREATE TABLE build_artifacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    build_id      INTEGER NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('rpm', 'srpm', 'log', 'metadata', 'script', 'other')),
    size_bytes    INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    -- 签名前哈希留档：产物签名前字节的 sha256。worker 路径上传时
    -- 首插（= sha256 初值）；hub-local 路径在签名前预计算落列。签名刷新
    -- （refresh_signed_files）只改 sha256/size/signed，不触碰本列——比对
    -- 永远以它为锚，与签名时序解耦。NULL = 未记录（非 deterministic 构建
    -- 的 hub-local 路径 / 崩溃窗口 reconcile 补采等 best-effort 分支）。
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

-- 16. build_reproducibility
-- 重放比对结果：每行 = 一次 source(原构建) vs replay(重放构建) 的
-- unsigned_sha256 集合比对，或 cross_arch_noarch 的任务级收口互比。
-- verdict 取值 same/diff/build_failed/dep_unavailable/infra_error
--（复现率分母只计 same/diff/build_failed——dep_unavailable
-- 与 infra_error 是基础设施可用性问题，单独统计不进复现率，否则滚动源的
-- 修剪会伪装成"包不可复现"）。
-- kind 取值 replay（自动/手动重放比对）/ cross_arch_noarch（同 task 跨架构
-- noarch 子包互比，指标分开查）。
-- unsigned 血缘：比对输入是 build_artifacts.unsigned_sha256（签名前哈希，
-- 签名刷新 refresh_signed_files 不触碰该列），签名时序漂移不影响比对。
CREATE TABLE build_reproducibility (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    kind             TEXT NOT NULL DEFAULT 'replay' CHECK (kind IN ('replay', 'cross_arch_noarch')),
    source_build_id  INTEGER NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
    replay_build_id  INTEGER REFERENCES builds(id) ON DELETE SET NULL,
    verdict          TEXT NOT NULL CHECK (verdict IN ('same', 'diff', 'build_failed', 'dep_unavailable', 'infra_error')),
    detail_json      TEXT,
    compared_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_build_repro_source ON build_reproducibility(source_build_id);
CREATE INDEX idx_build_repro_replay ON build_reproducibility(replay_build_id);
-- 复现率看板 cutoff 过滤（compared_at 之前无索引，整仓后行数随确定性
-- 构建翻倍增长）。
CREATE INDEX IF NOT EXISTS idx_build_repro_compared
    ON build_reproducibility(compared_at DESC);
-- 任务级收口去重（同一 task 的 cross_arch_noarch 比对只记一行）：source =
-- 该 task 产 noarch 冲突文件的最小 build_id，任务重跑产生新 build 不撞键。
CREATE UNIQUE INDEX idx_build_repro_cross_arch ON build_reproducibility(source_build_id) WHERE kind = 'cross_arch_noarch';

-- 17. build_batches (FK: products, users)
-- 整仓重建批次：一次提交的重建实体与进度聚合（hub 侧写入；worker 本地库
-- 是同一份 baseline 但不产批次行）。SQLite 惰性解析 FK 引用，故本表落文件
-- 尾、builds.batch_id 先于本表声明也无碍；PG 侧受建表即解析约束把本表排在
-- builds 之前（schema.pg.sql 3b 处注记），等价守卫按表名归组、不比建序。
--
-- status 生命周期：preparing/planning/running 为在途态；
-- completed/partial/failed/cancelled 为终态（retention 仅删终态且
-- finished_at 超期的行，在途行保守保留）。
-- product_id/created_by 均 ON DELETE SET NULL：删产品、清用户不得被批次行
-- 阻塞（与 builds.product_id ON DELETE SET NULL 口径一致），product_id 因此
-- 不设 NOT NULL。
CREATE TABLE build_batches (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id    INTEGER REFERENCES products(id) ON DELETE SET NULL,
    created_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
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
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    started_at    TEXT,
    finished_at   TEXT
);

-- 18. batch_items (FK: build_batches, tasks)
-- 批次项：持久化的重建计划，崩溃恢复的事实源。
-- round = 拓扑轮次；0 = 环/未解析（先试构建）。
-- task_id ON DELETE SET NULL：retention 删 task 行不得被批次项阻塞；批次删除
-- 经 batch_id ON DELETE CASCADE 带走全部批次项。
-- UNIQUE (batch_id, pkg_name)：一批内每包至多一项（表级约束，lockstep 守卫
-- 计入表级约束总数钉）。
CREATE TABLE batch_items (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id      INTEGER NOT NULL REFERENCES build_batches(id) ON DELETE CASCADE,
    pkg_name      TEXT NOT NULL,
    srpm_nevra    TEXT,
    srpm_staging_path TEXT,
    round         INTEGER NOT NULL,
    state         TEXT NOT NULL CHECK (state IN
        ('pending', 'released', 'succeeded', 'failed', 'dep_skipped', 'skipped_conflict', 'arch_skipped', 'cancelled')),
    attempt       INTEGER NOT NULL DEFAULT 0,
    task_id       INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    error_code    TEXT,
    error_message TEXT,
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
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

-- 19. worker_telemetry_samples (FK: workers)
-- Worker 遥测历史采样：心跳路径 best-effort 追加写——只 INSERT 不 UPDATE、
-- 无业务删除点，清理仅走 retention 按 sampled_at 删；worker 删除经
-- worker_id ON DELETE CASCADE 带走（与 worker_tasks 同款删除语义）。
-- sampled_at 与 workers.last_heartbeat 同源同帧（DB_TIME_FMT TEXT UTC，
-- 方言感知 sql_now 生成）。
CREATE TABLE worker_telemetry_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id INTEGER NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    sampled_at TEXT NOT NULL,
    -- 浮点列：写入必须走 `Dialect::float_param_cast`（TEXT 绑定 + SQL 侧
    -- CAST，见 builds.cpu_secs 列注的驱动钉型坑说明）。
    cpu_util_pct REAL,
    mem_used_pct REAL,
    load1 REAL,
    ncpu INTEGER,
    mem_total_kb INTEGER,
    -- 节点可用磁盘 KB（逐帧采样；调度读最新值走 workers.disk_free_kb，
    -- 本表是 worker 详情页磁盘折线数据源，见 workers.disk_free_kb 列注）。
    disk_free_kb INTEGER
);
-- 详情页趋势图窗口查询（worker + 时间范围）的索引支撑。
CREATE INDEX idx_telemetry_samples_worker_time
    ON worker_telemetry_samples(worker_id, sampled_at);
-- 遥测 retention 的全局时间删（与 worker 维查询索引互补；ORDER BY sampled_at,id）。
CREATE INDEX IF NOT EXISTS idx_telemetry_samples_sampled_at
    ON worker_telemetry_samples(sampled_at, id);

-- 20. package_resource_profiles（无 FK，TEXT 三元组键）
-- 包资源画像：声明面（declared_*，hub admin 显式钉入的放置契约）与学习面
--（learned_*，构建终态自动维护的估计值）同表双列组。
--
-- 键 (product, source_name, arch) 为 TEXT、不挂 FK：retention 清 builds 行
-- 不得连带画像（画像寿命 = 集群寿命），也不得阻塞 builds 删除——与
-- builds.product 的 TEXT 双轨口径一致。source_name = builds.name（NVR 去掉
-- version/release 后的源码包基础名）：同一源码包的不同版本共享画像与声明，
-- 版本维只留在 builds 历史里。arch = builds.arch 执行口径（noarch 按
-- 'noarch' 聚合跨宿主样本）；'any' 仅作声明面的架构无关哨兵。
-- 本表不进 retention 删除序列（豁免 = 不加 prune 段）；产品删除时的孤儿
-- 清理由产品删除路径负责。
CREATE TABLE package_resource_profiles (
    product TEXT NOT NULL,
    source_name TEXT NOT NULL,
    arch TEXT NOT NULL,
    -- 声明面：放置契约（可故意高于实际需求做路由指令）；仅 hub admin
    -- 经 API/CLI/UI 显式写入；NULL = 该维未声明。
    declared_min_mem_kb INTEGER,
    declared_min_ncpu INTEGER,
    declared_min_disk_kb INTEGER,
    declared_updated_at TEXT,
    -- 学习面（终态上报 best-effort 维护，失败 warn 不阻塞终态）：
    -- ema_* 进准入 Σ 权重；max_* 作删失抬升基线与展示。EMA 只折叠
    -- succeeded；timeout/普通失败不参与。OOM 删失（node-OOM）期间
    --（learned_censored = 1）max = max(max, 样本×headroom) 只抬不降、
    -- ema 不动；消费侧有效权重 = max(ema, max)，任意 succeeded
    -- 解锁。EMA 为指数衰减递推（α=0.4，第 6 个及更早样本残留总和
    -- 0.6^5≈7.8% 的软尾）——等价于带软尾的 5 样本窗口；回填同序播种
    -- 保证权重源切换时逐位连续。
    learned_ema_mem_kb INTEGER,
    learned_max_mem_kb INTEGER,
    -- tmpfs 峰值 EMA/最大：与 mem 同语义（EMA 只折叠 succeeded、max 只抬
    -- 不降）；样本不带 tmpfs 值时不折叠，两列维持原值。statfs 绝对值与
    -- 采样口径无关，proc→cgroup 升级重置不清这两列。
    learned_ema_tmpfs_kb INTEGER,
    learned_max_tmpfs_kb INTEGER,
    -- 核数口径与 builds.cpu_p90_cores 同纲，浮点列须走 Dialect::float_param_cast。
    learned_ema_ncpu REAL,
    learned_max_ncpu REAL,
    -- 累计纳入样本数（含删失样本；置信度展示）。
    learned_samples INTEGER NOT NULL DEFAULT 0,
    -- 末次样本的执行节点核数：peak_rss 与 -j$(nproc) 并行度耦合，无核数
    -- 上下文的 learned 值不可解读。落列而非渲染时 JOIN builds——
    -- builds 行受 retention 清理而画像表豁免，JOIN 语义会随保留期消失。
    -- @nC 注记与 export 字段的直接来源。
    learned_sample_ncpu INTEGER,
    -- 样本主口径（不混算；sticky-cgroup：cgroup 一经建立即粘滞，proc 样本
    -- 仅在该键从未有 cgroup 样本时启用；proc→cgroup 首个样本到达时清零
    -- mem EMA/max 与 samples 重起算并记 profile_updates_total{reset}——只换
    -- 标签不清数值会跨口径混算；tmpfs 两列不清，见上注）。
    learned_backend TEXT CHECK (learned_backend IN ('cgroup', 'proc')),
    learned_censored INTEGER NOT NULL DEFAULT 0 CHECK (learned_censored IN (0, 1)),
    learned_updated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (product, source_name, arch)
);
-- 画像面板：产品内 top-N 资源大户。
CREATE INDEX idx_profiles_product_mem ON package_resource_profiles(product, learned_ema_mem_kb);
