#!/bin/bash
# upgrade-resource-schema-pg.sh — hub PostgreSQL 库 schema 桥接升级（幂等）。
#
# 用途：schema 版本闩恒 (1,1)、无增量迁移——旧库升级新二进制后 ensure_schema
# 戳判等通过但缺新对象，首次相关 UPDATE 才爆列错。本脚本按 baseline
#（crates/crbs-core/src/state/schema.pg.sql）现文本补齐升级对象，纯加法、
# 零破坏、可重复执行（IF NOT EXISTS 幂等）：
#   1. builds +10 列：req_min_mem_kb / req_min_ncpu / req_min_disk_kb /
#      peak_total_kb / disk_wbytes / oom_killed / sample_backend / sample_ncpu /
#      peak_tmpfs_kb / product_config_toml
#   2. workers +2 列：disk_free_kb / resource_caps
#   3. worker_telemetry_samples +1 列：disk_free_kb
#   4. 新表 package_resource_profiles（PK product/source_name/arch）+
#      索引 idx_profiles_product_mem；表已存在的存量库补 +2 列
#      learned_ema_tmpfs_kb / learned_max_tmpfs_kb（tmpfs 峰值画像 EMA/最大）
#   5. 新表 task_labels（PK task_id/key，FK CASCADE）+ 索引 idx_task_labels_key_value
#   6. builds 索引 idx_builds_srpm_sha256（partial，血缘锚内容检索）
# 新二进制启动时另有对象探测 fail-closed 双保险（缺对象拒启并指引到本脚本）。
#
# 画像表以源码包基础名（source_name）为键：检测到以 pkg_name 为键的旧表时
# 本脚本拒绝执行（不自动迁移/改键）。请备份后手动
# DROP TABLE package_resource_profiles 再重跑；重建空表后本脚本清除回填标记，
# 重启 crbs-server 从 builds 历史重建学习面（声明下限需重新录入）。
#
# 用法（hub 本机、root；SQLite 部署请改用 upgrade-resource-schema-sqlite.sh）：
#   sudo bash deploy/upgrade-resource-schema-pg.sh [--db-name NAME]
#     --db-name NAME  业务库名，默认 crbs（reinit-hub.sh 同款）
#
#   连接默认走本机 postgres 系统用户 socket（sudo -u postgres，reinit-hub.sh
#   同款惯例）；远程/非默认连接设标准 PG* 环境变量（PGHOST/PGPORT/PGUSER 等），
#   本脚本经 sudo 透传给 psql——密码建议放 postgres 用户的 ~/.pgpass 而非
#   PGPASSWORD。
#
# 前置与建议：
#   - 目标库已由任意版本 crbs-server 初始化过（builds 表在位）；全新安装直接
#     启动 crbs-server 落全量 baseline，无需本脚本
#   - 建议先备份（pg_dump "$DB_NAME" | gzip > 备份文件）；脚本只加列建表，
#     不改不删任何数据
#   - crbs-server 运行中建议先 systemctl stop crbs-server 再执行（DDL 需短暂
#     表锁，长事务会阻塞）

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[0;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die() { log_error "$*"; exit 1; }

usage() {
    cat <<'EOF'
用法: upgrade-resource-schema-pg.sh [--db-name NAME]

  --db-name NAME  业务库名，默认 crbs
  连接参数化：设 PGHOST/PGPORT/PGUSER 等 PG* 环境变量，本脚本经 sudo
  透传给 postgres 用户下的 psql（默认本机 socket 无需设置）
EOF
}

DB_NAME=crbs

while [[ $# -gt 0 ]]; do
    case "$1" in
        --db-name) DB_NAME="${2:?--db-name 需要一个库名参数}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) log_error "未知参数: $1"; usage >&2; exit 2 ;;
    esac
done

# 标准 PG* 连接参数透传：默认无（本机 socket 部署）；sudo 默认清空环境，
# 显式设置的变量经 --preserve-env 带进 postgres 用户
SUDO_ENV=()
for v in PGHOST PGPORT PGUSER PGPASSWORD PGSSLMODE PGREQUIRESSL PGCONNECT_TIMEOUT; do
    [[ -n ${!v:-} ]] && SUDO_ENV+=(--preserve-env="$v")
done
# set -u 下空数组安全展开
run_as_pg() { sudo ${SUDO_ENV[@]+"${SUDO_ENV[@]}"} -u postgres "$@"; }

# q 固定连业务库（-A 去表线对齐输出，计数比较不受空白干扰）；不带库名会落到
# postgres 用户的默认库 postgres（无业务表），前置检查静默假阴性
q() { run_as_pg psql -d "$DB_NAME" -t -A -c "$1"; }

command -v psql >/dev/null || run_as_pg psql -c '\q' 2>/dev/null || die "psql 不可用"
q "select 1" >/dev/null || die "连不上 ${DB_NAME} 库（sudo -u postgres psql -d ${DB_NAME}；远程部署请设 PGHOST/PGPORT/PGUSER）"

# 探测锚 current_schema()（跟随 search_path，同 state 层 PG 探测口径），
# 不回退硬编码 'public'：非 public schema 部署会把已建表库误判成未初始化
[[ $(q "SELECT COUNT(*) FROM information_schema.tables \
        WHERE table_name='builds' AND table_schema=current_schema()") == 1 ]] \
    || die "builds 表不存在：${DB_NAME} 库未初始化（或库名不对）"

# 旧画像表（pkg_name 主键）与新代码不兼容：拒绝而非 IF NOT EXISTS 跳过，避免
# 留下列探测会拒启的半旧结构。
PROFILES_EXISTED=$(q "SELECT COUNT(*) FROM information_schema.tables \
        WHERE table_name='package_resource_profiles' AND table_schema=current_schema()")
if [[ $PROFILES_EXISTED == 1 ]] \
    && [[ $(q "SELECT COUNT(*) FROM information_schema.columns \
        WHERE table_name='package_resource_profiles' AND column_name='source_name' \
          AND table_schema=current_schema()") == 0 ]]; then
    die "检测到旧 pkg_name 画像表（与新 source_name 主键不兼容）。请备份后手动执行 psql -d \"$DB_NAME\" -c 'DROP TABLE package_resource_profiles;' 再重跑本脚本；重启 crbs-server 会从 builds 历史重建学习面"
fi

log_info "升级计划（幂等：IF NOT EXISTS，已存在的对象一律跳过，不动数据）："
log_info "  库: ${DB_NAME}"
log_info "  ALTER TABLE builds ADD COLUMN IF NOT EXISTS ×10（req_min_* / peak_total_kb / disk_wbytes / oom_killed / sample_backend / sample_ncpu / peak_tmpfs_kb / product_config_toml）"
log_info "  ALTER TABLE workers ADD COLUMN IF NOT EXISTS ×2（disk_free_kb / resource_caps）"
log_info "  ALTER TABLE worker_telemetry_samples ADD COLUMN IF NOT EXISTS ×1（disk_free_kb）"
log_info "  CREATE TABLE IF NOT EXISTS package_resource_profiles + CREATE INDEX IF NOT EXISTS idx_profiles_product_mem"
log_info "  ALTER TABLE package_resource_profiles ADD COLUMN IF NOT EXISTS ×2（learned_ema_tmpfs_kb / learned_max_tmpfs_kb）"
log_info "  CREATE TABLE IF NOT EXISTS task_labels + CREATE INDEX IF NOT EXISTS idx_task_labels_key_value"
log_info "  CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256（partial）"
log_warn "建议先备份（pg_dump ${DB_NAME} | gzip > 备份文件）；服务运行中建议先停 crbs-server"

# ---- DDL ----
# 列定义文本 = baseline（schema.pg.sql）对应对象逐字；全部可空、无 DEFAULT：
# ADD COLUMN 给存量行统一填 NULL，与"缺数据 = 降级放行"的列语义一致。
# ON_ERROR_STOP：多语句任一失败即停，避免半套列静默落地（重跑本脚本补齐）。
log_info "执行 DDL…"
run_as_pg psql -d "$DB_NAME" -v ON_ERROR_STOP=1 <<'SQL' >/dev/null || die "DDL 执行失败（见上）"
ALTER TABLE builds ADD COLUMN IF NOT EXISTS req_min_mem_kb BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS req_min_ncpu BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS req_min_disk_kb BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS peak_total_kb BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS disk_wbytes BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS oom_killed INTEGER CHECK (oom_killed IN (0, 1));
ALTER TABLE builds ADD COLUMN IF NOT EXISTS sample_backend TEXT CHECK (sample_backend IN ('cgroup', 'proc'));
ALTER TABLE builds ADD COLUMN IF NOT EXISTS sample_ncpu BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS peak_tmpfs_kb BIGINT;
ALTER TABLE builds ADD COLUMN IF NOT EXISTS product_config_toml TEXT;

ALTER TABLE workers ADD COLUMN IF NOT EXISTS disk_free_kb BIGINT;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS resource_caps INTEGER;

ALTER TABLE worker_telemetry_samples ADD COLUMN IF NOT EXISTS disk_free_kb BIGINT;

CREATE TABLE IF NOT EXISTS package_resource_profiles (
    product TEXT NOT NULL,
    source_name TEXT NOT NULL,
    arch TEXT NOT NULL,
    declared_min_mem_kb BIGINT,
    declared_min_ncpu BIGINT,
    declared_min_disk_kb BIGINT,
    declared_updated_at TEXT,
    learned_ema_mem_kb BIGINT,
    learned_max_mem_kb BIGINT,
    learned_ema_tmpfs_kb BIGINT,
    learned_max_tmpfs_kb BIGINT,
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
CREATE INDEX IF NOT EXISTS idx_profiles_product_mem ON package_resource_profiles(product, learned_ema_mem_kb);

CREATE TABLE IF NOT EXISTS task_labels (
    task_id BIGINT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (task_id, key)
);
CREATE INDEX IF NOT EXISTS idx_task_labels_key_value ON task_labels(key, value);
CREATE INDEX IF NOT EXISTS idx_builds_srpm_sha256
    ON builds(canonical_srpm_sha256) WHERE canonical_srpm_sha256 IS NOT NULL;

-- 存量库（旧脚本/旧版本建的 18 列表）补 tmpfs 两列；CREATE 已建新表的库
-- 两列在位，IF NOT EXISTS 跳过。
ALTER TABLE package_resource_profiles ADD COLUMN IF NOT EXISTS learned_ema_tmpfs_kb BIGINT;
ALTER TABLE package_resource_profiles ADD COLUMN IF NOT EXISTS learned_max_tmpfs_kb BIGINT;
SQL

# 空表重建后必须让一次性回填重跑，否则标记仍会跳过学习面播种。
if [[ $PROFILES_EXISTED == 0 ]]; then
    q "DELETE FROM app_meta WHERE key = 'resource_profiles_backfilled_at'" >/dev/null \
        || die "清除画像回填标记失败"
    log_info "已清除画像回填标记（重启后从 builds 历史重建学习面）"
fi

# ---- 核对 ----
log_info "核对…"
fail=0
col_exists() { [[ $(q "SELECT COUNT(*) FROM information_schema.columns \
    WHERE table_name='$1' AND column_name='$2' AND table_schema=current_schema()") == 1 ]]; }

while read -r t c; do
    if col_exists "$t" "$c"; then
        log_info "  OK: $t.$c"
    else
        log_error "  缺失: $t.$c"
        fail=1
    fi
done <<'COLS'
builds req_min_mem_kb
builds req_min_ncpu
builds req_min_disk_kb
builds peak_total_kb
builds disk_wbytes
builds oom_killed
builds sample_backend
builds sample_ncpu
builds peak_tmpfs_kb
builds product_config_toml
workers disk_free_kb
workers resource_caps
worker_telemetry_samples disk_free_kb
package_resource_profiles source_name
package_resource_profiles learned_ema_tmpfs_kb
package_resource_profiles learned_max_tmpfs_kb
COLS
if [[ $(q "SELECT COUNT(*) FROM information_schema.tables \
        WHERE table_name='package_resource_profiles' AND table_schema=current_schema()") == 1 ]]; then
    log_info "  OK: package_resource_profiles"
else
    log_error "  缺失: package_resource_profiles"
    fail=1
fi
if [[ $(q "SELECT COUNT(*) FROM information_schema.tables \
        WHERE table_name='task_labels' AND table_schema=current_schema()") == 1 ]]; then
    log_info "  OK: task_labels"
else
    log_error "  缺失: task_labels"
    fail=1
fi
for idx in idx_profiles_product_mem idx_task_labels_key_value idx_builds_srpm_sha256; do
    if [[ $(q "SELECT COUNT(*) FROM pg_indexes \
            WHERE indexname='$idx' AND schemaname=current_schema()") == 1 ]]; then
        log_info "  OK: $idx"
    else
        log_error "  缺失: $idx"
        fail=1
    fi
done
[[ $fail -eq 0 ]] || die "核对未通过：上列对象仍缺失"

log_info "完成：schema 升级对象全部就位（重启 crbs-server 生效）"
