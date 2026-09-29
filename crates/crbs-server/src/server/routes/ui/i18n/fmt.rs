// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 带参文案表：[`FmtKey`] 定义、完备性清单与穷尽 match 插值取值（[`t_fmt`]）。

use super::Lang;

// ===== 带参文案（完整句子插值，禁止调用方前后缀拼接——中英语序不同）=====

/// 单表宏：一张 `Key => (en, zh)` 表同源生成 [`FmtKey`] 枚举（doc 随表携带）、
/// [`fmt_pairs`] 的穷尽 match 与 cfg(test) 的 `ALL` 清单；新增 key 只登记一行。
/// mod.rs 的穷尽哨兵保持手写，独立防表内漏登记/重排。
macro_rules! fmt_table {
    (
        $( $(#[$doc:meta])* $variant:ident => $vals:expr ),* $(,)?
    ) => {
        /// 带参文案 key。模板占位 `{0}`/`{1}`… 按位置对应 [`t_fmt`] 的 args；
        /// 两语言模板可各自排列占位（语序差异），未被引用的 arg 允许忽略。
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum FmtKey {
            $( $(#[$doc])* $variant, )*
        }

        // 仅单测消费（双语完备性断言）；与枚举同表生成，不需另行登记。
        #[cfg(test)]
        impl FmtKey {
            /// 全 key 清单。
            pub(crate) const ALL: &'static [FmtKey] = &[ $(FmtKey::$variant,)* ];
        }

        /// 带参文案双语模板取值（穷尽 match）。
        fn fmt_pairs(key: FmtKey) -> (&'static str, &'static str) {
            match key {
                $(FmtKey::$variant => $vals,)*
            }
        }
    };
}

fmt_table! {
    /// 分页区间（start/end/total）。
    PaginationInfo => ("{0}-{1} of {2}", "第 {0}-{1} 条，共 {2} 条"),
    /// 成功率口径：succeeded/total。
    RecentSucceeded => (
        "{0} / {1} recent tasks succeeded",
        "最近 {1} 个任务中 {0} 个成功",
    ),
    /// 成功率窗口（N 个任务）。
    WindowLastTasks => ("window: last {0} tasks", "窗口：最近 {0} 个任务"),
    /// Worker 架构行（online/total）。
    ArchOnline => ("{0}/{1} online", "{0}/{1} 在线"),
    /// 首页架构条 CPU 均值 chip（归一化百分比整数）。
    ArchCpuAvg => ("avg {0}%", "均 {0}%"),
    /// 队列 title：count + 优先级名。
    QueuePriority => ("{0} at priority {1}", "{0} 个{1}优先级任务"),
    /// donut 图例 title：phase 显示名/count/pct/英文复数单位词（zh 忽略）。
    DonutRowTitle => DONUT_ROW_TITLE_TPL,
    /// 相对时间单位（n）。
    RelSecs => ("{0}s ago", "{0} 秒前"),
    RelMins => ("{0} min ago", "{0} 分钟前"),
    RelHours => ("{0} h ago", "{0} 小时前"),
    RelDays => ("{0} d ago", "{0} 天前"),
    /// gauge aria 标签（pct）。
    GaugeAria => ("{0}% success rate", "成功率 {0}%"),
    /// 时长图 aria 摘要（样本数 / 最长时长）。
    DurationAria => (
        "Durations of the last {0} succeeded builds, longest {1}",
        "最近 {0} 个成功构建的时长，最长 {1}",
    ),
    /// 时长图脚注（样本数 + 新鲜度）。
    DurationNote => ("last {0} succeeded builds", "最近 {0} 个成功构建"),
    /// 错误页标题（code + 本地化短语）。
    ErrTitleKnown => ("{0} {1}", "{0} {1}"),
    /// 错误页标题（code，无已知短语时）。
    ErrTitleUnknown => ("Error {0}", "错误 {0}"),
    /// 登录/注册限流提示（保守上取整的剩余分钟数，不带剩余次数）。
    RateLimitedMinutes => (
        "Too many attempts. Try again in {0} minutes.",
        "尝试次数过多，请在约 {0} 分钟后重试。",
    ),
    /// 注册密码过短（最小字符数）。
    RegisterPasswordTooShort => (
        "Password must be at least {0} characters.",
        "密码至少需要 {0} 个字符。",
    ),
    /// 注册密码超长（最大字符数，DoS 上限）。
    RegisterPasswordTooLong => (
        "Password must be at most {0} characters.",
        "密码最多 {0} 个字符。",
    ),
    // ===== 个人中心 /ui/me =====
    /// 身份条："user #N · 注册于 date"。
    MeUserSince => ("user #{0} · registered {1}", "user #{0} · 注册于 {1}"),
    /// 会话表头设备计数："（N 台设备）"。
    MeSessionsDeviceCount => ("({0} devices)", "（{0} 台设备）"),
    /// Admin 重置确认语（用户名）。
    AdminResetConfirm => (
        "Reset the password for '{0}'? All their sessions will be signed out immediately.",
        "重置用户 {0} 的密码？其所有会话将立即登出。",
    ),
    /// Admin 重置一次性页的临时密码标签（用户名）。
    AdminResetTempLabel => ("Temporary password for {0}", "用户 {0} 的临时密码"),
    /// token 有效期下拉选项（天数）。
    MeTokenDays => ("{0} days", "{0} 天"),
    /// 令牌卡超出封顶未展示的活跃 token 计数。
    MeTokensMoreHidden => ("{0} more tokens not shown", "还有 {0} 个令牌未显示"),
    // ===== 全量迁移 =====
    /// arch 矩阵 cell 的 started title（本地时间）。
    StartedAtTitle => ("started: {0}", "开始于 {0}"),
    /// build 详情 h1 / 页标题。
    BuildTitle => ("Build #{0}", "构建 #{0}"),
    /// build 日志页 h1 / 页标题。
    BuildLogsTitle => ("Build #{0} logs", "构建 #{0} 日志"),
    /// task 详情 h1 / 页标题。
    TaskTitle => ("Task #{0}", "任务 #{0}"),
    /// 日志截断提示（已展示 / 全文大小）。
    LogTruncated => (
        "Showing last {0} of {1} total.",
        "已截断：仅显示末尾 {0}（全文 {1}）。",
    ),
    /// task 详情多包计数。
    PackagesCount => ("{0} packages", "{0} 个软件包"),
    /// package 详情（NVR 视图）标题。
    PackageNvrTitle => ("Package: {0} / {1}", "软件包：{0} / {1}"),
    /// package 详情（分组视图）标题。
    PackageTitle => ("Package: {0}", "软件包：{0}"),
    // 同 ThAttempts 术语定则：此计数 = 该 NVR 的任务（提交）数。
    /// package 详情尝试次数 h2。
    AttemptsCount => ("Submissions ({0})", "提交记录（{0}）"),
    /// product 详情 h1 / 页标题。
    ProductTitle => ("Product: {0}", "产品：{0}"),
    /// product 历史页 h1。
    ProductHistoryTitle => ("Product history: {0}", "产品历史：{0}"),
    /// product 历史页 title。
    HistoryTitle => ("History: {0}", "历史：{0}"),
    /// product 配置 diff 页 h1（产品名）。
    ProductHistoryDiffTitle => ("Product config diff: {0}", "产品配置对比：{0}"),
    /// product 配置 diff 页 title（产品名）。
    HistoryDiffTitle => ("Diff: {0}", "对比：{0}"),
    /// diff 页 revision 摘要行：r{0} 变更人 {1}、相对时间 {2}。
    DiffRevMeta => ("r{0} by {1}, {2}", "r{0} 由 {1} 变更，{2}"),
    /// diff 行数超限截断提示（{0} = 上限行数）。
    DiffTruncatedNote => (
        "Diff truncated — showing the first {0} lines.",
        "Diff 已截断——仅显示前 {0} 行。",
    ),
    /// diff 侧快照损坏/旧 schema，回退显示原文（{0} = revision 号）。
    HistoryDiffRawFallback => (
        "revision {0} snapshot is corrupted or from an older schema — showing raw content",
        "revision {0} 快照损坏或来自旧版本 schema——以下显示原文",
    ),
    /// 产品编辑乐观并发冲突 flash（{0} = 期望 revision，{1} = 当前 revision）。
    FlashRevisionConflict => (
        "The product was updated meanwhile (expected revision {0}, current {1}); reload and retry.",
        "产品已被他人更新（期望版本 {0}，当前 {1}）；请刷新后重试。",
    ),
    // ===== 错误 flash（签名 ?error= 通道）；占位语义见各变体注释 =====
    /// 可见性值非法（{0} = 提交值）。
    FlashInvalidVisibility => (
        "invalid visibility '{0}'",
        "无效的可见性值 {0}。",
    ),
    /// 祖先链遍历中父产品消失（{0} = parent id；FK 语义下的异常路径）。
    FlashParentDisappeared => (
        "parent product {0} disappeared while walking the chain",
        "父产品 {0} 在遍历链时已不存在。",
    ),
    /// 发布带私有祖先的产品（{0} = 祖先产品名）。
    FlashPublishPrivateAncestor => (
        "cannot publish product with private ancestor '{0}' (would leak private ancestor chain)",
        "无法发布带私有祖先 {0} 的产品（会泄漏私有祖先链）。",
    ),
    /// 产品页 ACL 表单角色非法（{0} = 提交角色）。
    FlashProductAclInvalidRole => ("invalid role '{0}'", "无效的角色 {0}。"),
    /// 用户不存在（{0} = 用户名）。
    FlashUserNotFoundByName => ("user '{0}' not found", "用户 {0} 不存在。"),
    /// admin 用户角色非法（{0} = 提交角色；期望值列表内嵌在文案里）。
    FlashAdminRoleExpected => (
        "invalid role '{0}'; expected one of: admin, operator, builder, viewer",
        "无效的角色 {0}；应为 admin、operator、builder、viewer 之一。",
    ),
    /// 用户不存在（{0} = 用户 id，admin 各表单共用）。
    FlashUserNotFoundById => ("user {0} not found", "用户 {0} 不存在。"),
    /// 用户已存在（{0} = 用户名）。
    FlashUserExists => ("user '{0}' already exists", "用户 {0} 已存在。"),
    /// 为禁用用户创建 token（{0} = 用户名）。
    FlashTokenDisabledUser => (
        "cannot create token for disabled user '{0}'",
        "无法为已禁用的用户 {0} 创建令牌。",
    ),
    /// token 不存在（{0} = token id，{1} = 用户 id；zh 重排语序）。
    FlashTokenNotFoundForUser => (
        "token {0} not found for user {1}",
        "未找到用户 {1} 的 token {0}。",
    ),
    /// admin ACL 表单角色非法（{0} = 提交角色；与产品页措辞不同，各自保真）。
    FlashAdminAclInvalidRole => ("invalid role: {0}", "无效的角色：{0}。"),
    /// 目标用户非活跃（{0} = 用户名，{1} = 状态）。
    FlashUserNotActive => (
        "user '{0}' is not active (status: {1}); cannot grant ACL",
        "用户 {0} 未处于活跃状态（状态：{1}）；无法授予 ACL。",
    ),
    /// 未授予的 ACL（{0} = 用户 id，{1} = 产品名）。
    FlashAclNotGranted => (
        "ACL not granted for user {0} on {1}",
        "用户 {0} 在 {1} 上没有被授予 ACL。",
    ),
    /// 产品名非法字符（server 侧 slug 校验文案：{0} = 产品名）。
    FlashProductNameInvalidChars => (
        "product name '{0}' has invalid characters; only [a-z0-9_-] are allowed",
        "产品名 {0} 含非法字符；仅允许 [a-z0-9_-]。",
    ),
    /// 产品名非法字符（crbs-core validate_product 文案：{0} = 产品名；与 server 侧各自保真）。
    FlashProductNameInvalidCharsCore => (
        "product name '{0}' contains invalid characters. Only [a-zA-Z0-9_-] are allowed",
        "产品名 {0} 含非法字符。仅允许 [a-zA-Z0-9_-]。",
    ),
    /// worker 不存在（{0} = worker id）。
    FlashWorkerNotFound => ("worker {0} not found", "Worker {0} 不存在。"),
    /// 删除在线 worker（{0} = worker 名；结构化变体 WorkerOnline）。
    FlashWorkerOnlineConflict => (
        "worker '{0}' is online; revoke secret or wait for it to go offline before removing",
        "Worker {0} 在线；请撤销其密钥或等待其离线后再移除。",
    ),
    /// 离线 worker 不能 init（{0} = worker id）。
    FlashWorkerOfflineInit => (
        "worker {0} is offline, cannot init",
        "Worker {0} 离线，无法初始化 base_os。",
    ),
    /// init 冲突：产品有构建进行中（{0} = worker id，{1} = 构建数，{2} = 产品名）。
    FlashInitConflictBuilding => (
        "worker {0} has {1} building build(s) for product {2}; wait for completion or cancel before init",
        "Worker {0} 有 {1} 个产品 {2} 的构建仍在进行；请等待完成或取消后再初始化 base_os。",
    ),
    /// init 冲突：已有活跃 init（{0} = worker id，{1} = 产品名）。
    FlashInitConflictActive => (
        "worker {0} already has an active init assignment for product {1}",
        "Worker {0} 已有产品 {1} 的活跃 base_os 初始化任务。",
    ),
    /// 未知 worker action（{0} = action 名）。
    FlashUnknownWorkerAction => ("unknown worker action: {0}", "未知的 Worker 操作：{0}。"),
    // ===== 错误 flash 第二批（?error= 通道 + product_editor 内联回显）=====
    /// task 取消部分生效（{0} = 已取消数，{1} = 失败数）。
    FlashCancelPartial => (
        "cancel partially applied: {0} cancelled, {1} failed",
        "取消部分生效：{0} 个已取消，{1} 个失败。",
    ),
    /// task 不存在（{0} = task id；取消/重放共用）。
    FlashTaskNotFound => ("task {0} not found", "任务 {0} 不存在。"),
    /// build 不存在（{0} = build id）。
    FlashBuildNotFound => ("build {0} not found", "构建 {0} 不存在。"),
    /// task 重建信息不存在（{0} = task id）。
    FlashReplayInfoNotFound => (
        "task rebuild info {0} not found",
        "任务 {0} 的重建信息不存在。",
    ),
    /// 产品不存在（{0} = 产品名；重放链可见性检查 / noarch 映射）。
    FlashProductNotFound => ("product {0} not found", "产品 {0} 不存在。"),
    /// task 无子构建不可复现（{0} = task id）。
    FlashReplayNoChildBuilds => (
        "task {0} has no child builds; cannot reproduce",
        "任务 {0} 没有子构建；无法复现。",
    ),
    /// task 进行中不可复现（{0} = task id，{1} = 子构建 id）。
    FlashReplayStillInProgress => (
        "task {0} is still in progress (child build {1})",
        "任务 {0} 仍在进行中（子构建 {1}）。",
    ),
    /// 子构建非 succeeded 不可复现（{0} = task id，{1} = 子构建 id，{2} = phase）。
    FlashReplayChildNotSucceeded => (
        "task {0} child build {1} has status '{2}' (only succeeded builds can be reproduced)",
        "任务 {0} 的子构建 {1} 状态为 {2}（只有成功的构建才能复现）。",
    ),
    /// 产品名超长（{0} = 实际长度；validate_product_name_for_write）。
    FlashProductNameTooLong => (
        "product name too long (max 128 characters, got {0})",
        "产品名过长（最多 128 字符，实际 {0}）。",
    ),
    /// product_editor 可见性枚举非法（{0} = 提交值；与产品页 FlashInvalidVisibility 各自保真）。
    FlashInvalidVisibilityEditor => (
        "invalid visibility '{0}'; must be 'public' or 'private'",
        "无效的可见性值 {0}；应为 public 或 private。",
    ),
    /// 新建产品 owner 不存在（{0} = 用户名）。
    FlashOwnerNotFound => ("owner '{0}' not found", "所有者 {0} 不存在。"),
    /// builder 挂私有父产品（{0} = 父产品名）。
    FlashParentPrivateAttach => (
        "parent '{0}' is private; only admin can attach to private products",
        "父产品 {0} 是私有产品；仅管理员可挂到私有产品下。",
    ),
    /// 父产品不存在（{0} = 父产品名）。
    FlashParentProductNotFound => (
        "parent product '{0}' not found",
        "父产品 {0} 不存在。",
    ),
    /// 编辑页乐观锁前置检查（{0} = 当前 revision）。
    FlashProductRevisionMoved => (
        "product has been updated to revision {0}; please refresh and try again",
        "产品已更新到修订版 {0}；请刷新后重试。",
    ),
    /// 产品名已被占用（{0} = 产品名；create_product 的 AlreadyExists）。
    FlashProductNameTaken => (
        "product name '{0}' is taken (namespace is global)",
        "产品名 {0} 已被占用（命名空间全局共享）。",
    ),
    /// store 侧乐观锁冲突（{0} = 期望 revision，{1} = 当前 revision；与
    /// ?status= 的 FlashRevisionConflict 措辞不同，各自保真）。
    FlashRevisionConflictStore => (
        "revision conflict: expected {0}, current {1}",
        "修订冲突：期望 {0}，当前 {1}。",
    ),
    /// 产品链层数超限（{0} = 上限；max 动态进参避免硬编码漂移）。
    FlashProductChainTooDeep => (
        "product chain too deep: max {0}",
        "产品链层数超限：最多 {0} 层。",
    ),
    /// 链遍历中父产品行消失（{0} = 产品 id）。
    FlashChainWalkParentMissing => (
        "product id={0} not found in chain walk",
        "链遍历中找不到产品 id={0}。",
    ),
    /// 产品解析出空链（{0} = 产品 id）。
    FlashChainWalkEmptyChain => (
        "product {0} resolved to empty chain",
        "产品 {0} 解析出了空链。",
    ),
    /// 编辑页 "Parent: X"。
    ParentLabel => ("Parent: {0}", "父产品：{0}"),
    /// General 区块父产品 "name (id=N)"。
    ParentWithId => ("{0} (id={1})", "{0}（id={1}）"),
    /// 编辑页 h1 "Edit: X"。
    EditTitle => ("Edit: {0}", "编辑：{0}"),
    /// 编辑页 title "Edit X"。
    EditPageTitle => ("Edit {0}", "编辑 {0}"),
    /// 编辑页修订行的变更人。
    EditChangedBy => ("by {0}", "由 {0}"),
    /// Effective TOML 解析失败前缀。
    ChainResolveFailed => ("chain resolve failed: {0}", "链解析失败：{0}"),
    /// token 一次性页 "Token ID: N"。
    TokenIdLabel => ("Token ID: {0}", "Token ID：{0}"),
    /// admin 用户详情页 title。
    AdminUserPageTitle => ("Admin · User #{0} {1}", "管理 · 用户 #{0} {1}"),
    /// admin 撤销 token 确认（token 名）。
    ConfirmRevokeToken => (
        "Revoke token '{0}'? It will stop working immediately.",
        "撤销令牌 {0}？它将立即失效。",
    ),
    /// admin 撤销用户产品 ACL 确认（产品名）。
    ConfirmRevokeUserAcl => (
        "Revoke this user's access to product '{0}'?",
        "撤销该用户对产品 {0} 的访问权限？",
    ),
    /// product 页撤销用户 ACL 确认（用户名）。
    ConfirmRevokeAclUser => (
        "Revoke {0}'s access to this product? They will immediately lose access.",
        "撤销 {0} 对该产品的访问权限？其访问将立即失效。",
    ),
    /// worker 密钥轮换确认（worker 名）。
    ConfirmRotateWorkerSecret => (
        "Rotate secret for worker '{0}'? The current secret will stop working.",
        "轮换 Worker {0} 的密钥？当前密钥将立即失效。",
    ),
    /// worker 密钥撤销确认（worker 名）。
    ConfirmRevokeWorkerSecret => (
        "Revoke secret for worker '{0}'? It will no longer be able to authenticate.",
        "撤销 Worker {0} 的密钥？它将无法再通过认证。",
    ),
    /// worker 移除确认（worker 名）。
    ConfirmRemoveWorker => ("Remove worker '{0}' permanently?", "永久移除 Worker {0}？"),
    /// worker 密钥轮换一次性页 "Worker: X"。
    WorkerLabel => ("Worker: {0}", "Worker：{0}"),
    /// worker 详情内存已用百分比。
    MemUsedPct => ("{0}% used", "已用 {0}%"),
    // ===== 提交构建页 /ui/tasks/new =====
    /// 上传上限提示（MB）。
    UploadMaxNote => ("Maximum upload size: {0} MB", "上传大小上限：{0} MB"),
    /// 所选文件超限（实际 MB / 上限 MB）；{0} 由 JS 回填时保留占位符。
    UploadTooLarge => (
        "Selected files total {0} MB, which exceeds the {1} MB limit.",
        "所选文件共 {0} MB，超过 {1} MB 上限。",
    ),
    /// XHR / 重渲染失败消息的外框（机器面错误原文）。
    SubmitFailed => ("Submit failed: {0}", "提交失败：{0}"),
    // ===== 全局搜索 =====
    /// 搜索页 h1 / 页标题（查询词）。
    SearchTitle => ("Search: {0}", "搜索：{0}"),
    // ===== nav chrome 单按钮 =====
    /// 主题单按钮 title/aria：{0}=当前态文案（NavTheme*），{1}=下一态文案。
    ThemeToggleAria => ("Theme: {0} — switch to {1}", "主题：{0} — 切换到 {1}"),
    /// 语言单按钮 title/aria：{0}=当前语言自称（中/EN），{1}=目标语言自称。
    LangToggleAria => ("Language: {0} — switch to {1}", "语言：{0} — 切换到 {1}"),
    // ===== 详情页双栏 =====
    /// task 详情 meta 行的构建数。
    MetaBuildsCount => ("{0} builds", "{0} 个构建"),
    /// meta 行：本任务由某任务复现（链接在渲染侧）。
    MetaReplayedFrom => ("replayed from task {0}", "由任务 {0} 复现"),
    /// meta 行：本任务被复现次数。
    MetaReplayCount => ("replayed {0}×", "被复现 {0} 次"),
    /// task arch 矩阵头部聚合摘要（架构数 / 成功 / 失败，可选增强）。
    MatrixSummary => MATRIX_SUMMARY_TPL,
    // ===== 阶段时间线（失败子阶段面板 + skip chip）=====
    /// 失败子阶段面板头（失败子阶段名）。
    SubPanelFailedAt => (
        "rpmbuild failed at the {0} stage",
        "rpmbuild 在 {0} 阶段失败",
    ),
    /// 子阶段行日志定位跳转（行号）。
    LogAtLine => ("Log line {0} →", "日志第 {0} 行 →"),
    /// 时间线配置性 SKIP 聚合 chip（隐藏步数）。
    SkippedChipFmt => ("+{0} skipped", "+{0} 跳过"),
    /// changelog 页顶部限量摘要行（本页条数 / 总条数）。
    ChangelogPageSummary => ("showing {0} of {1} entries", "显示 {0} 条，共 {1} 条"),
    // ===== 复现率看板 /ui/reproducibility =====
    /// diff 清单截断提示（实际展示条数）。
    ReproShowingLatest => ("showing latest {0}", "最近 {0} 组"),
    // ===== 首页系统条并发 tooltip（集群口径，分母只计启用车道；追加表尾）=====
    /// 并发 tooltip：auto 双车道（本地活跃/本地槽 + worker 活跃/在线容量）。
    ConcurrencyTitleAuto => (
        "cluster-wide: hub local {0}/{1} + online workers {2}/{3}",
        "集群口径：Hub 本地 {0}/{1} + 在线 Worker {2}/{3}",
    ),
    /// 并发 tooltip：仅分发车道（在线 worker 容量）。
    ConcurrencyTitleDistributedOnly => (
        "cluster-wide: distributed only, online worker capacity {0}",
        "集群口径：仅分发，在线 Worker 容量 {0}",
    ),
    /// 并发 tooltip：仅本地车道（Hub 本地槽）。
    ConcurrencyTitleLocalOnly => (
        "cluster-wide: local only, hub local capacity {0}",
        "集群口径：仅本地，Hub 本地容量 {0}",
    ),
    // ===== 复现记录 drill-down（追加表尾，哨兵编号顺延）=====
    /// 第三级折叠的"一致的包"行数（默认只展开差异包，一致的收进二级折叠）。
    ReproSamePkgsFmt => ("{0} identical packages", "{0} 个一致的包"),
    /// 一级组行 verdict 汇总（一致的构建对占比，如 3/4）。
    ReproGroupConsistentFmt => ("{0}/{1} consistent", "一致 {0}/{1}"),
    // ===== worker 列表 CPU 遥测 title（追加表尾，哨兵编号顺延）=====
    /// CPU 利用率主值 + 辅助负载口径：{0}=util%、{1}=load1（两位小数）、{2}=ncpu。
    CpuUtilTitle => (
        "CPU {0}% · load 1m {1} / {2} cores",
        "CPU {0}% · 负载 1m {1} / {2} 核",
    ),
    // ===== 产物卡 crbs-logs 目录树 summary 计数（追加表尾，哨兵编号顺延）=====
    /// 目录树 summary 的递归文件数（crbs-logs 根与各级子目录同用，单复数同形）。
    LogsDirFiles => ("({0} files)", "（{0} 个文件）"),
    // ===== worker 列表 Load 列容量条 title（追加表尾，哨兵编号顺延）=====
    /// Load 列条形 title：active/capacity（{0}=活跃数、{1}=容量）。
    LoadCapacityTitle => ("{0} of {1} slots busy", "{1} 个槽位中 {0} 个占用"),
    // ===== build 详情页 Lifecycle 三段间隙（追加表尾，哨兵编号顺延）=====
    /// Queued 活状态值：{0}= Submitted 起算的时长。zh 借"等"避免与行标重复。
    LifecycleQueuedSoFar => ("{0} so far", "已等 {0}"),
    /// Picked up 已认领值：{0}= Dispatched→Claimed 时长；zh 行标已含"耗时"，
    /// 值直排时长（中英语序差异在 dt/dd 两键间消化，不做调用方拼接）。
    LifecyclePickupDur => ("in {0}", "{0}"),
    /// Ran 活状态值（running 构建）：{0}= Claimed 起算的时长。
    LifecycleRanSoFar => ("{0} so far", "已运行 {0}"),
    // ===== worker 详情页遥测汇总行（追加表尾，哨兵编号顺延）=====
    /// 趋势图汇总：{0}=CPU 峰值%、{1}=峰值时刻（本地 HH:MM，7d 档带日期
    /// M/D HH:MM）、{2}=CPU 均值%、{3}=内存峰值%；序列缺采样时调用方以
    /// "—" 占位。
    TelemetrySummary => (
        "Peak CPU {0}% ({1}) · avg {2}% · memory peak {3}%",
        "CPU 峰值 {0}%（{1}）· 均值 {2}% · 内存峰值 {3}%",
    ),
    // ===== worker init arch 门禁（追加表尾，哨兵编号顺延）=====
    /// init arch 冲突：{0}=worker id、{1}=worker arch、{2}=产品名、{3}=产品 arches。
    FlashInitConflictArch => (
        "worker {0} (arch {1}) cannot init product {2}; supported arches: {3}",
        "Worker {0}（架构 {1}）无法初始化产品 {2}；支持架构：{3}。",
    ),
    // ===== 详情遥测现值条负载 tooltip（追加表尾，哨兵编号顺延）=====
    /// 负载绝对口径：{0}=load1（两位小数，与 SSR/JS 同精度）、{1}=ncpu。
    /// 倍数值 `{ratio:.1}×` 由调用方拼，模板只管 title。
    LoadAvgTitle => (
        "load {0} / {1} cores (runnable + uninterruptible queue, includes IO wait)",
        "负载 {0} / {1} 核（可运行 + 不可中断任务队列，含 IO 等待）",
    ),
    // ===== 归因徽章 title（追加表尾，哨兵编号顺延）=====
    /// 水位阻塞等待时长（{0}=距首次全拒的人读时长，如 25m / 40s）。
    AttribWatermarkWaiting => ("waiting {0}", "已等待 {0}"),
    /// 硬下限维度（{0}=维度名 mem/ncpu/disk，机器值不走文案表）。
    AttribHardReqDim => ("dimension: {0}", "维度：{0}"),
    /// 声明下限编辑：未知 action（{0}=提交值）。
    ProfileInvalidAction => ("invalid action '{0}'", "无效操作 {0}"),
    // ===== 水位归因徽章生效压载（追加表尾，哨兵编号顺延）=====
    /// 内存维水位阻塞：{0}=生效内存人读值、{1}=生效折算核数（一位小数）、
    /// {2}=内存水位系数百分比（配置生效值，如 90% / 92.5%）。
    AttribWatermarkLoadMem => (
        "effective {0} / {1} cores vs mem watermark {2} of node total",
        "生效 {0} / {1} 核（内存水位：节点总量的 {2}）",
    ),
    /// CPU 维水位阻塞：{0}=生效内存人读值、{1}=生效折算核数、{2}=CPU 水位
    /// 系数百分比（配置生效值）。
    AttribWatermarkLoadCpu => (
        "effective {0} / {1} cores vs cpu watermark {2} of ncpu",
        "生效 {0} / {1} 核（CPU 水位：ncpu 的 {2}）",
    ),
}

/// `{n}` 位置插值；缺参保留占位符原文，由调用方与单测保证不缺。
fn interpolate(template: &str, args: &[&str]) -> String {
    // debug 防线：模板最大占位符下标必须 < args.len()——漏参调用会静默
    // 渲染出 "{1}" 字面量，debug 构建直接 panic 暴露。
    debug_assert!(
        template
            .split('{')
            .skip(1)
            .filter_map(|rest| rest.split('}').next())
            .filter_map(|inner| inner.parse::<usize>().ok())
            .max()
            .is_none_or(|max| max < args.len()),
        "t_fmt: template references a placeholder index beyond args (args_len={}): {template}",
        args.len(),
    );
    let mut out = template.to_string();
    for (i, arg) in args.iter().enumerate() {
        out = out.replace(&format!("{{{i}}}"), arg);
    }
    out
}

/// MatrixSummary 模板原文（`{0}/{1}/{2}` 占位）：task 详情页 SSR 与内联 SSE
/// 脚本经 data 属性共用本模板，JS 端同规则 `{n}` replace 整句重算（禁前后缀
/// 拼接）。t_fmt 臂与本函数同源（单 const），一致性由单测钉住（插值 ==
/// t_fmt 输出）。
const MATRIX_SUMMARY_TPL: (&str, &str) = (
    "{0} arches · {1} succeeded · {2} failed",
    "{0} 个架构 · 成功 {1} · 失败 {2}",
);

pub(crate) fn matrix_summary_pattern(lang: Lang) -> &'static str {
    match lang {
        Lang::En => MATRIX_SUMMARY_TPL.0,
        Lang::Zh => MATRIX_SUMMARY_TPL.1,
    }
}

/// DonutRowTitle 模板原文（`{0}/{1}/{2}/{3}`；zh 模板不引用 `{3}` 英文复数
/// 单位词）：首页 donut 图例原生 title 的 SSR（chart.rs `donut_row_title`）
/// 与仪表盘 SSE 脚本共用，data-pattern 规则同 MatrixSummary（JS 端 `{n}`
/// replace 整句重算）。t_fmt 臂与本函数同源（单 const）。
const DONUT_ROW_TITLE_TPL: (&str, &str) = (
    "{0} · {1} {3} · {2}% — click to view list",
    "{0} · {1} 个任务 · {2}% — 点击查看列表",
);

pub(crate) fn donut_row_title_pattern(lang: Lang) -> &'static str {
    match lang {
        Lang::En => DONUT_ROW_TITLE_TPL.0,
        Lang::Zh => DONUT_ROW_TITLE_TPL.1,
    }
}

/// 相对时间四档模板原文（秒/分/时/天，`{0}` 占位）：worker SSE 脚本注入
/// 后由 JS 端 `{0}` replace 本地重算活动行相对时间（SSR [`rel_time_lang`]
/// 同阈值同词）。以 `"{0}"` 为参插值即得模板本身——`replace("{0}", "{0}")`
/// 恒等，单测钉住该性质（见 interpolate_allows_exact_arg_count）。
pub(crate) fn rel_time_patterns(lang: Lang) -> [String; 4] {
    [
        t_fmt(lang, FmtKey::RelSecs, &["{0}"]),
        t_fmt(lang, FmtKey::RelMins, &["{0}"]),
        t_fmt(lang, FmtKey::RelHours, &["{0}"]),
        t_fmt(lang, FmtKey::RelDays, &["{0}"]),
    ]
}

/// 带参文案取值（穷尽 match，完整句子插值）。转义契约（注入面）：`args`
/// 只收纯文本，本函数只做 `{n}` 占位替换、不做 HTML 转义，转义发生在消费端
/// maud `( ... )` 嵌入时（参数文本随之转义）。需带标记的结果由调用方包
/// [`maud::PreEscaped`] 且自证参数无用户可控输入（现例：
/// [`crate::server::routes::ui::pages::success_rate_gauge`]
/// 的服务端整数 `<b>N</b>`）；用户可控文本严禁经 `args` 进任何跳过 maud
/// 转义的通道（`PreEscaped`、script 内 `js_str` 拼接等）——文案表唯一注入路径。
pub(crate) fn t_fmt(lang: Lang, key: FmtKey, args: &[&str]) -> String {
    let (en, zh) = fmt_pairs(key);
    let template = match lang {
        Lang::En => en,
        Lang::Zh => zh,
    };
    interpolate(template, args)
}

/// interpolate 缺参防线单测（测试跑 dev profile，debug_assert 生效）。
#[cfg(test)]
mod interpolate_guard_tests {
    use super::{t_fmt, FmtKey, Lang};

    /// 边界语义：模板最大占位符下标 == args.len()-1 恰好用满，不 panic。
    #[test]
    fn interpolate_allows_exact_arg_count() {
        assert_eq!(
            t_fmt(Lang::En, FmtKey::RecentSucceeded, &["171", "200"]),
            "171 / 200 recent tasks succeeded"
        );
        // 模板无占位符 + 零参数：max 为 None，放行。
        assert_eq!(
            t_fmt(Lang::En, FmtKey::DurationNote, &["3"]),
            "last 3 succeeded builds"
        );
    }

    /// 漏参调用（最大下标 >= args.len()）debug 构建 panic；RelSecs 零参数即触发。
    #[test]
    #[should_panic(expected = "placeholder index beyond args")]
    fn t_fmt_missing_arg_panics_in_debug() {
        let _ = t_fmt(Lang::En, FmtKey::RelSecs, &[]);
    }
}
