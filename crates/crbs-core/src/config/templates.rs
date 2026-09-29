// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 配置模板：首次初始化的 crbs.toml / 产品配置文本。

/// 全局配置模板（首次 `crbs init` 时生成到 `/etc/crbs/crbs.toml`）。
pub const GLOBAL_CONFIG_TEMPLATE: &str = r#"# crbs 全局配置（引擎世界）
# 所有产品共享，产品 TOML 可通过 Option 字段覆盖其中任意项。
#
# 引擎世界与 server 世界分离：本文件属于引擎世界（crbs CLI 本地构建）；
# crbs-server 的数据根由 /etc/crbs/server.toml 的 crbs_root 决定（默认
# /var/lib/crbs）。两个世界互不读写对方的状态库与结果目录。

# 路径
crbs_root = "/var/lib/crbs-engine"
# 构建结果目录。默认 {crbs_root}/results；如需显式指定再解除注释。
# result_dir = "/var/lib/crbs-engine/results"
# 共享层存储目录。默认 {crbs_root}/shared_layers；如需显式指定再解除注释。
# shared_layers_dir = "/var/lib/crbs-engine/shared_layers"

# 构建用户
builder_user = "ccbuilder"
builder_uid = 10010
builder_group = "ccbuilder"
builder_gid = 10010

# SharedLayer GC
shared_layer_gc_grace_hours = 168

# Result directory GC (build history records are preserved)
result_gc_grace_hours = 720

# shared_layer（依赖缓存，默认关闭）
# false = 不启用，true = 全部启用，["kernel"] = 仅对指定包启用
shared_layer = false

# tmpfs（shared_layer=false 时 overlay 使用 tmpfs 全内存构建；shared_layer=true 时仅 BUILD 目录使用 tmpfs）
build_tmpfs = false

# 运行时控制
max_concurrent_builds = 0           # 0 = num_cpus
shared_layer_poll_interval_ms = 100
shared_layer_timeout_secs = 60
shared_layer_max_retries = 2        # SharedLayer 创建失败后的重试次数
# shared_layer_staleness = "7d"     # SharedLayer TTL：7d/24h/30m/3600s，空或省略 = 缺省 7 天

# ccache（C/C++ 编译缓存）
# false = 不启用，true = 全部启用，["kernel"] = 仅对指定包启用
ccache_enabled = false
# ccache 目录。注意：全局层的 ccache_dir 当前不参与配置合并（生效值为产品级
# ccache_dir 或计算默认 {crbs_root}/ccache/{product}，按产品隔离）；该键仅被
# priv-helper allowed_paths 作为允许路径读取。如需自定义请配置产品 TOML。
# ccache_dir = "/var/lib/crbs/ccache"
ccache_max_size = "4G"

# dnf 缓存（避免重复下载包元数据）
dnf_cache_enabled = false

# dnf --releasever，未配置时从宿主 /etc/os-release 推断
# releasever = "9"

# rpmbuild 目标阶段（bb=二进制包, bs=源码包, ba=两者）
build_target = "bb"

# 是否跳过 %check 阶段（默认 false）
# nocheck = false

# 是否跳过 rpmbuild 收尾清理段 %clean / rmbuild（默认 false；一次性 overlay
# 环境的 BUILD 树由引擎 teardown 统一回收，该段通常无收益且可成为失败源）
# noclean = false

# 是否不生成 debuginfo 包（默认 false）
# nodebuginfo = false

# 容器后端（chroot=稳定，nspawn=默认；需 systemd-nspawn，支持 cgroup v1/v2）
# backend = "nspawn"

# 是否允许构建容器联网（默认 true；安全敏感场景可设为 false 默认无网络构建）
# network = true

# 资源限制（仅 nspawn backend 生效；chroot 下会被忽略）
# memory_max = "4G"   # 硬内存上限，格式：数字 + 可选 K/M/G/T
# cpu_quota = "200%"  # CPU 配额，格式：数字 + 可选 %（200% = 2 核）

# 构建 transient 失败自动重试
# build_max_retries = 1        # 最大额外重试次数，0 = 禁用
# build_retry_backoff_ms = 1000 # 首次重试基础退避毫秒数
# resource_sample_interval_secs = 15 # 构建资源采样间隔秒数（/proc 口径），0 = 关闭
# resource_sample_interval_cgroup_secs = 5 # cgroup 口径采样间隔秒数（采样分级），未配置 = 5，0 = 关闭 cgroup 口径

# GC 磁盘配额策略（未配置则不执行）
# package_cache_max_size_gb = 100      # 包缓存总容量上限（GB），按 0.9 倍 LRU 淘汰
# package_cache_evict_referenced = false # 容量不足时是否淘汰仍被引用的缓存
# result_max_count_per_pkg = 10        # 单包保留的最大 result_dir 数量
# result_retention_days = 90           # result_dir 最长保留天数

# URL 解析缓存 TTL（天），0 表示不清理
# package_url_cache_ttl_days = 90

# base 快照保留代数（init 安装事务输入的物质化，按产品隔离），0 = 不清理
# base_snapshot_keep_generations = 8

# 是否为构建记录 provenance（URL、SHA256、build_packages.json），用于 reproduce
# true = 全部记录，false = 不记录（默认），["pkg1"] = 仅指定包记录
# reproduce_enabled = false
"#;

/// 产品配置模板（首次 `crbs init <product>` 时生成到 `/etc/crbs/products/{product}.toml`）。
pub const PRODUCT_CONFIG_TEMPLATE: &str = r#"# 产品配置：{product}
# 产品特有字段（base_packages、repos）必须配置。
# 与全局同名字段省略则继承全局值。

# ===== 产品特有（必须）=====

# 用户构建工具链。CRBS init 时会自动安装自身运行所需的核心包：
#   bash、coreutils、shadow、sudo
# 若全局或产品启用了 ccache，ccache 也会自动追加到此列表。
# 这里只需要填写你真正想装进 base_os 的构建环境包。
base_packages = ["rpm-build", "dnf", "make", "gcc", "glibc-devel"]

[[repos]]
name = "{product}-base"
baseurl = "https://repo.example.com/{product}/os/x86_64/"
gpgcheck = true
gpgkey = "/etc/pki/rpm-gpg/RPM-GPG-KEY-{product}"

# 产品支持的架构列表（可选）：不写 = 单架构模式（按提交时指定架构构建）；
# 写 = 多架构构建时默认在这些架构上构建
# arches = ["x86_64", "aarch64"]

# noarch 构建的宿主偏好架构集（可选，集合语义无序）：收敛的 noarch 构建只会
# 派发给这些架构的 worker——依赖覆盖不全的架构可经此排除；不写 = 不限制
# noarch_preferred_arches = ["x86_64", "aarch64"]

# 子产品追加语法（仅子产品有意义）："+base_packages" / "+repos" / "+arches" / "+post_init"
# 表达"追加到父链合并值之后"，而不是整体替换父配置（如 "+base_packages" = ["git"]）

# ===== 覆盖全局（可选，省略则用全局值）=====

# builder_user = "ccbuilder"
# builder_uid = 10010
# builder_group = "ccbuilder"
# builder_gid = 10010
# shared_layer_gc_grace_hours = 168
# result_gc_grace_hours = 720
# shared_layer = false
# shared_layer = ["kernel", "glibc"]
# shared_layer_staleness = "7d"     # 空或省略 = 缺省 7 天
# build_tmpfs = false
# SRPM 下载策略覆盖：true = 本产品源码包公开可下，false = 仅 operator/admin；
# 省略 = 跟随 server.toml 全局 allow_srpm_download
# allow_srpm_download = false

# 发布开关（发布轴）：成功构建的 RPM 是否发布进产品 repo。省略 = 默认发布；
# 显式 false = 长期不发布（repo 目录保留零包）。逐构建可用 --no-publish 收紧。
# repo-publish = false

# 消费开关（消费轴）：后续构建的 builddep 是否注入本产品 repo。省略 = 默认
# 消费；显式 false = 长期不注入。与 repo-publish 正交（一侧关闭不影响另一侧）；
# 逐构建可用 --no-consume 收紧。私有产品对消费轴一票否决。
# repo-consume = false

# GPG 签名（Host 侧执行，私钥不进入构建容器）
# gpg_signing_key_id = "admin@example.com"
# gpg_home = "/root/.gnupg"  # 绝对路径，默认使用当前用户 keyring

# 覆盖层文件目录（init 时 cp -a 到 base_os）
# overlay_dir = "/etc/crbs/overlays/{product}"

# init 后在 chroot 内执行的命令
# [[post_init]]
# command = "rustup default stable"

# [[post_init]]
# command = "pip config set global.index-url https://mirrors.example.com/pypi/simple"

# ccache（C/C++ 编译缓存）
# ccache_enabled = false
# ccache_enabled = ["kernel"]
# ccache_dir = "/var/lib/crbs/ccache"
# ccache_max_size = "4G"

# dnf 缓存（避免重复下载包元数据）
# dnf_cache_enabled = false

# dnf builddep 是否安装 weak deps/Recommends（默认省略 = dnf 默认行为，安装）。
# 仅作用于构建依赖解析装包；false 时追加 --setopt=install_weak_deps=False，
# 收窄装包集、降低构建环境方差（同 Fedora Koji/mock 的 install_weak_deps=False）。
# builddep_install_weak_deps = false

# dnf --releasever，未配置时从宿主 /etc/os-release 推断
# releasever = "9"

# rpmbuild 目标阶段（bb=二进制包, bs=源码包, ba=两者）
# build_target = "bb"

# 是否跳过 %check 阶段（覆盖全局）
# nocheck = true

# 是否跳过 rpmbuild 收尾清理段 %clean / rmbuild（覆盖全局）
# noclean = false

# 是否不生成 debuginfo 包（覆盖全局）
# nodebuginfo = false

# 容器后端（chroot=稳定，nspawn=默认；需 systemd-nspawn，支持 cgroup v1/v2）
# backend = "nspawn"

# 网络控制（true = 共享宿主网络，false = 隔离；覆盖全局）
# network = true

# chain 构建的本地 repo 路径（覆盖全局，省略则用 {crbs_root}/repo/{product}）
# local_repo = "/var/lib/crbs/repo/{product}"

# 资源限制（仅 nspawn backend 生效；chroot 下会被忽略）
# memory_max = "4G"   # 硬内存上限，格式：数字 + 可选 K/M/G/T
# cpu_quota = "200%"  # CPU 配额，格式：数字 + 可选 %（200% = 2 核）

# 构建 transient 失败自动重试
# build_max_retries = 1
# build_retry_backoff_ms = 1000

# GC 磁盘配额策略（未配置则继承全局，全局也未配置则不执行）
# package_cache_max_size_gb = 100
# package_cache_evict_referenced = false
# result_max_count_per_pkg = 10
# result_retention_days = 90

# URL 解析缓存 TTL（天），0 表示不清理
# package_url_cache_ttl_days = 90

# 是否记录 provenance 用于 reproduce（覆盖全局）
# reproduce_enabled = true
# reproduce_enabled = ["kernel"]
# 普通构建时间自锚定（非 det 可复现卫生）：构建起点取墙钟 S，BUILDTIME 头与
# payload mtime 统一为 S——回放（锚 = 源构建 BUILDTIME）与源构建逐字节一致。
# 省略 = false；det 产品忽略本开关（changelog-SDE 语义更强）。
# mtime_normalize = true

# 纯 noarch 源码包的扇出策略（默认 false = 收敛单构建）：提交/整仓重建时
# header arch=noarch 的 SRPM 只建一个子构建，派发架构按包全名（NVR）稳定
# 哈希轮转选取（跨提交均匀分摊，同 NVR 恒定同架构）。显式 true = 恢复
# 每架构各建，同时激活跨架构 noarch 字节互比探针（复现率判定的数据来源）。
# rebuild 不受影响（还原）。
# noarch_per_arch = true

# 确定性构建模式（默认 false）：true 时自动注入确定性宏组 / env 基线 /
# hostname 钉死，并强制溯源落盘 + 完整性硬门（无视 reproduce_enabled）。
# 前置条件（缺一即配置报错）：合并后生效值 dnf_cache_enabled = true
# （全局或产品级任一开启即可；产品级显式 false 覆盖全局 true 时仍报错）；
# build_target 不得为 ba（每架构重造 SRPM 与确定性冲突）。
# 链上语义：任一层开启即生效（OR），子层无法关闭——关闭需改开启层
# （防混跑期静默字节漂移）。
# deterministic = true
# _buildhost = "crbs"     # RPM 包头 BUILDHOST 固定值（默认 "crbs"）

# 自动跟跑（deterministic 产品）：构建成功后 hub 自动跟跑一次锁定环境重放
# 做字节比对（默认 true；显式 false 关闭；仅对 deterministic 产品有意义；
# 仅 hub 部署生效，本地磁盘产品不消费）
# auto_replay = true
# 自动跟跑抽样（总量闸）：0-100 整数百分比，按 task 哈希确定性抽样；
# 默认 100 = 全量；0 = 关闭跟跑；>100 触发点按 100 收敛并 warn；
# 仅 hub 部署生效（本地磁盘产品不消费）
# replay_sampling = 100
# recipe GC 钉住窗口（天）：recipe.json 生成后该天数内其引用的 sha256 免
# package cache GC 驱逐（热重放窗口，性能优化非正确性前提）；
# 默认 90；0 = 禁用钉住；hub 自动跟跑与本地 `crbs gc` 钉住窗口均消费此值
# recipe_retention_days = 90

# RPM 宏（rpmbuild --define 参数，_topdir 不可覆盖）
# [rpm_macros]
# dist = ".cc21"
# _vendor = "UnitedLinux"

# 构建脚本钩子（按 step 名注入 pre/post bash 片段）
# 可用 step：ccache-init, install-srpm, install-deps, build, ccache-summary
# [hooks.pre]
# install-srpm = "echo '即将安装 SRPM'"
#
# [hooks.post]
# build = "rpmlint /builddir/RPMS/*/*.rpm || true"
"#;
