// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 无参文案表：[`TextKey`] 定义、完备性清单与穷尽 match 取值（[`t`]）。

use super::Lang;

// ===== 无参文案（穷尽 match：新增 key 漏译 = 编译错误）=====

/// 单表宏：一张 `Key => (en, zh)` 表同源生成 [`TextKey`] 枚举（doc 随表携带）、
/// [`t`] 的穷尽 match 与 cfg(test) 的 `ALL` 清单；新增 key 只登记一行。
/// mod.rs 的穷尽哨兵保持手写，独立防表内漏登记/重排（臂值 0..N 连续唯一，
/// 序不与表声明序绑定）。
macro_rules! text_table {
    (
        $( $(#[$doc:meta])* $variant:ident => $vals:expr ),* $(,)?
    ) => {
        /// 无参文案 key。key 命名按用途而非译文内容；允许不同 key 暂持同译文
        ///（语义点位独立，未来一侧改词不牵连另一场景）。
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum TextKey {
            $( $(#[$doc])* $variant, )*
        }

        // 仅单测消费（双语完备性断言）；与枚举同表生成，不需另行登记。
        #[cfg(test)]
        impl TextKey {
            /// 全 key 清单。
            pub(crate) const ALL: &'static [TextKey] = &[ $(TextKey::$variant,)* ];
        }

        /// 无参文案取值（穷尽 match）。
        pub(crate) fn t(lang: Lang, key: TextKey) -> &'static str {
            let (en, zh) = match key {
                $(TextKey::$variant => $vals,)*
            };
            match lang {
                Lang::En => en,
                Lang::Zh => zh,
            }
        }
    };
}

text_table! {
    NavDashboard => ("Dashboard", "仪表盘"),
    NavBuilds => ("Builds", "构建"),
    NavTasks => ("Tasks", "任务"),
    NavProducts => ("Products", "产品"),
    NavPackages => ("Packages", "软件包"),
    NavWorkers => ("Workers", "Worker"),
    NavGc => ("GC", "垃圾回收"),
    NavAdmin => ("Admin", "管理"),
    NavLogin => ("Login", "登录"),
    NavLogout => ("Logout", "退出"),
    NavThemeAuto => ("Auto", "自动"),
    NavThemeLight => ("Light", "浅色"),
    NavThemeDark => ("Dark", "深色"),
    FooterApiHealth => ("API health", "API 健康"),
    // dashboard（home.rs）
    LiveUpdatesEnabled => ("Live updates enabled", "实时更新已启用"),
    ConnectionLost => ("Connection lost, reconnecting...", "连接已断开，正在重连…"),
    VizAriaSummary => ("Task status summary", "任务状态概览"),
    PanelTaskStates => ("Task states", "任务状态"),
    HintHoverClick => (
        "hover · click → filtered list",
        "悬停查看 · 点击进入过滤列表",
    ),
    DonutAriaLabel => ("Task distribution by phase", "任务阶段分布"),
    DonutSubTasks => ("tasks", "任务"),
    DonutRunning => ("running", "运行中"),
    DonutQueued => ("queued", "排队中"),
    LegendRunning => ("Running", "运行中"),
    LegendQueued => ("Queued", "排队中"),
    LegendSucceeded => ("Succeeded", "成功"),
    LegendFailed => ("Failed", "失败"),
    LegendTimeout => ("Timeout", "超时"),
    LegendCancelled => ("Cancelled", "已取消"),
    PanelSuccessRate => ("Success rate", "成功率"),
    GaugeSubSuccess => ("success", "成功"),
    /// gauge 无样本时的 aria 标签（中心显示 "—"；避免读屏误报 "0% 成功率"）。
    GaugeAriaNoData => ("No success data yet", "暂无成功率数据"),
    /// 统计图：时长卡标题 / 时长空态（空态复用 GaugeAriaNoData，同为"窗口内无任务"）。
    PanelBuildDurations => ("Recent build durations", "最近构建时长"),
    DurationNoData => ("No finished builds yet", "暂无已完成的构建"),
    /// Worker 在线数单位词（`#dash-workers-online` 数字 span 之后；SSE 脚本只改写数字，词不覆盖）。
    WorkersOnlineWord => ("online", "在线"),
    NoWorkersRegistered => ("No workers registered", "尚未注册 Worker"),
    WorkersBarNote => (
        "bar = online ratio · updates on reload · ",
        "条形 = 在线比例 · 重新加载时更新 · ",
    ),
    ViewWorkers => ("View workers →", "查看 Worker →"),
    SectionRecentTasks => ("Recent tasks", "最近任务"),
    ViewAllTasks => ("View all tasks →", "查看全部任务 →"),
    EmptyRecentTitle => ("No recent tasks", "暂无最近任务"),
    EmptyRecentHint => (
        "Submitted tasks appear here; open Tasks to submit or filter them.",
        "提交的任务会显示在这里；打开任务页可提交或过滤任务。",
    ),
    SysStripAria => ("System overview", "系统概览"),
    StatUptime => ("Uptime", "运行时长"),
    StatQueue => ("Queue", "队列"),
    StatConcurrency => ("Concurrency", "并发"),
    StatDiskAvailable => ("Disk available", "磁盘可用"),
    QueueNoPending => ("No pending builds", "没有等待中的构建"),
    PriorityNormal => ("normal", "普通"),
    PriorityHigh => ("high", "高"),
    PriorityCritical => ("critical", "关键"),
    // 共用表头（dashboard 最近任务 / tasks 列表）
    ThId => ("ID", "ID"),
    ThProduct => ("Product", "产品"),
    ThPackage => ("Package", "软件包"),
    // 该列展示结果状态（生命周期态），非构建时间线相位（PhaseTimelineTitle/phase_step_label 通道）。
    ThPhase => ("Status", "状态"),
    ThUser => ("User", "用户"),
    ThSubmitted => ("Submitted", "提交时间"),
    Err404Message => (
        "The page you are looking for does not exist.",
        "你访问的页面不存在。",
    ),
    Err405Message => (
        "This page does not support the requested HTTP method.",
        "该页面不支持此 HTTP 方法。",
    ),
    ErrRequestFailed => ("Request failed", "请求失败"),
    ErrLoginCta => ("Login to continue", "登录以继续"),
    ErrBackToDashboard => ("← Back to dashboard", "← 返回仪表盘"),
    FilterArch => ("Arch", "架构"),
    FilterPriority => ("Priority", "优先级"),
    FilterSort => ("Sort", "排序"),
    FilterAll => ("All", "全部"),
    PaginationPrev => ("Previous", "上一页"),
    PaginationNext => ("Next", "下一页"),
    PlaceholderProduct => ("e.g. mydist", "如 mydist"),
    PlaceholderPackage => ("e.g. hello", "如 hello"),
    PlaceholderArch => ("e.g. x86_64", "如 x86_64"),
    SortNewestId => ("Newest ID", "ID 新→旧"),
    SortOldestId => ("Oldest ID", "ID 旧→新"),
    SortStartedTime => ("Started time", "开始时间"),
    SortSubmittedTime => ("Submitted time", "提交时间"),
    FilterApply => ("Filter", "过滤"),
    FilterReset => ("Reset", "重置"),
    FilterRemove => ("Remove filter", "移除该条件"),
    EmptyTasksTitle => ("No tasks found", "未找到任务"),
    EmptyTasksHint => (
        "Adjust the filters above, or submit a new task to get started.",
        "请调整上方过滤条件，或提交一个新任务。",
    ),
    // 一次性 secret 展示 + 复制脚本
    SecretWarning => (
        "⚠ This secret is shown only once. Copy it now — it cannot be retrieved later.",
        "⚠ 该密钥仅显示一次，请立即复制——之后无法再次获取。",
    ),
    CopyButton => ("Copy", "复制"),
    CopyCopied => ("Copied", "已复制"),
    CopyFailedManual => ("Copy failed — select manually", "复制失败 — 请手动选中复制"),
    // SSE 终态提示（内联 JS 注入的文案）
    HintBuildFinished => (
        "Build finished — refresh to see final fields and artifacts",
        "构建已完成 — 刷新以查看最终字段与产物",
    ),
    HintTaskFinished => (
        "Task finished — refresh to see final fields and artifacts",
        "任务已完成 — 刷新以查看最终字段与产物",
    ),
    RefreshNow => ("Refresh now", "立即刷新"),
    HintLogComplete => (
        "Build finished — log stream complete. Refresh the build page for final fields.",
        "构建已完成 — 日志流结束。刷新构建页可查看最终字段。",
    ),
    ViewBuildPage => ("View build page", "查看构建页"),
    // 构建完成通知（内联 JS 注入的文案）
    NotifyMe => ("Notify me", "通知我"),
    NotifyEnabled => ("Notifications on", "通知已开启"),
    NotifyDeniedHint => (
        "Blocked in browser settings — re-allow notifications for this site, then try again",
        "浏览器已阻止本站通知，请在浏览器设置中重新允许后重试",
    ),
    NotifyTitleBuild => ("Build finished", "构建已完成"),
    NotifyTitleTask => ("Task finished", "任务已完成"),
    PageSizeTitle => ("Rows per page", "每页条数"),
    // ===== 登录页（生而双语）=====
    LoginTitle => ("Sign in to CRBS", "登录 CRBS"),
    LoginSubtitle => ("Build system console", "构建系统控制台"),
    LoginModePassword => ("Password", "密码"),
    LoginModeToken => ("API token", "API 令牌"),
    LoginUsernameLabel => ("Username", "用户名"),
    LoginUsernameHint => ("lowercase letters / digits / _ / -", "小写字母 / 数字 / _ / -"),
    LoginPasswordLabel => ("Password", "密码"),
    LoginTokenLabel => ("Token", "令牌"),
    LoginTokenHint => (
        "Paste your CRBS token (crbs_tok_…) to sign in.",
        "粘贴 CRBS 令牌（crbs_tok_…）登录。",
    ),
    LoginSubmitButton => ("Sign in", "登录"),
    LoginInvalidCredentials => (
        "Invalid username or password.",
        "用户名或密码错误。",
    ),
    LoginInvalidToken => ("Invalid token.", "无效的令牌。"),
    LoginNoTokenHint => (
        "Don't have a token? Ask an administrator to create one for you in the web console (Admin → Users).",
        "没有令牌？请管理员在 Web 控制台创建（管理 → 用户）。",
    ),
    LoginNoAccount => ("No account?", "还没有账号？"),
    LoginRegisterLink => ("Register", "注册"),
    LoginRegisterAdminNote => ("(requires an admin to enable)", "（需管理员开放）"),
    LoginRateLimitHint => (
        "Too many failed attempts will temporarily block sign-in (10 per IP and username every 5 minutes).",
        "失败次数过多将临时锁定登录（同一 IP 与用户名组合，5 分钟内最多 10 次）。",
    ),
    /// auth_enabled=false 免认证模式说明（登录/注册页共用）。
    AuthDisabledNote => (
        "Authentication is disabled on this server; signing in is not required.",
        "本服务器已禁用认证，无需登录即可访问。",
    ),
    RegisterTitle => ("Create account", "创建账号"),
    RegisterSubtitle => (
        "New accounts start as viewer (read-only); an administrator can raise the role.",
        "新账号默认为访客（只读），可由管理员提升角色。",
    ),
    RegisterUsernameHint => (
        "Lowercase letters, digits, _ and -; max 128 characters; cannot be changed later.",
        "小写字母、数字、_ 与 -，最长 128 字符，创建后不可修改。",
    ),
    RegisterConfirmLabel => ("Confirm password", "确认密码"),
    RegisterPasswordHint => ("At least 10 characters.", "至少 10 个字符。"),
    RegisterSubmitButton => ("Create account", "创建账号"),
    RegisterClosedMessage => (
        "Registration is currently closed. Ask an administrator to create an account (Admin → Users → Create user), or to open registration in Admin → Settings.",
        "注册功能当前未开放。请联系管理员创建账号（管理 → 用户 → 创建用户），或让管理员在管理 → 设置中开放注册。",
    ),
    RegisterBackToLogin => ("← Back to login", "← 返回登录"),
    RegisterHasAccount => ("Already have an account?", "已有账号？"),
    RegisterGoLogin => ("Sign in", "去登录"),
    RegisterUsernameTaken => ("This username is already taken.", "该用户名已被占用。"),
    RegisterPasswordMismatch => ("Passwords do not match.", "两次输入的密码不一致。"),
    RegisterInvalidUsername => (
        "Invalid username: use lowercase letters, digits, _ and - (max 128 characters).",
        "用户名不合法：仅可用小写字母、数字、_ 与 -（最长 128 字符）。",
    ),
    /// 强度指示条 aria-label。
    RegisterStrengthLabel => ("Password strength", "密码强度"),
    RegisterStrengthTitle => (
        "Strength grows with length and character variety (letters, digits, symbols).",
        "长度越长、字符类别（字母/数字/符号）越多，强度越高。",
    ),
    SettingsTitle => ("Settings", "设置"),
    SettingsRegistrationCardTitle => ("Registration", "注册"),
    SettingsRegistrationCardDesc => (
        "Allow self-service account creation. New accounts get the viewer role.",
        "允许自助创建账号，新账号默认为访客角色。",
    ),
    SettingsRegistrationToggleLabel => ("Open registration", "开放注册"),
    SettingsRegistrationStateOpen => ("open", "已开放"),
    SettingsRegistrationStateClosed => ("closed", "已关闭"),
    SettingsSaveButton => ("Save", "保存"),
    SettingsSavedMessage => ("Settings saved.", "设置已保存。"),
    SettingsSessionExpired => ("Session expired.", "会话已过期。"),
    MePageTitle => ("My account", "个人中心"),
    MeNoAccountTitle => ("No account page for this credential", "该凭据没有账户页"),
    MeNoAccountHint => (
        "This credential (worker or special login) has no user account. Use the navigation above.",
        "该凭据（Worker 或特殊登录）没有用户账户，请使用上方导航。",
    ),
    MeMustChangeBanner => (
        "An administrator has reset your password. Please set a new password now.",
        "管理员已重置你的密码，请立即设置新密码。",
    ),
    MeMustChangeFlash => (
        "Please set a new password to continue.",
        "请设置新密码后继续。",
    ),
    MeCredModeSession => ("credential: browser session", "凭据：浏览器会话"),
    MeCredModeToken => ("credential: API token", "凭据：API 令牌"),
    MeStatMyTasks => ("My tasks", "我的任务"),
    MeStatBuilding => ("Building", "进行中"),
    MeStatQueued => ("Queued", "排队中"),
    MeStatTokens => ("Tokens", "令牌数"),
    MeStatOwnedProducts => ("Owned products", "持有的产品"),
    MeCardSecurity => ("Security", "安全"),
    MePasswordChangeTitle => ("Change password", "修改密码"),
    MePasswordSetTitle => ("Set password", "设置密码"),
    MePasswordCurrent => ("Current password", "当前密码"),
    MePasswordNew => ("New password", "新密码"),
    MePasswordConfirm => ("Confirm new password", "确认新密码"),
    MePasswordChangeHint => (
        "At least 10 characters. After changing, your other sessions will be signed out.",
        "至少 10 个字符；修改后其它会话将被强制登出。",
    ),
    MePasswordSetHint => ("At least 10 characters.", "至少 10 个字符。"),
    MePasswordChangeSubmit => ("Update password", "更新密码"),
    MePasswordSetSubmit => ("Set password", "设置密码"),
    /// 改密失败 flash：当前密码不正确（校验失败枚举 → 渲染处本地化，非 `?error=` 通道）。
    MePasswordCurrentIncorrect => (
        "Current password is incorrect.",
        "当前密码不正确。",
    ),
    MeCardSessions => ("Active sessions", "活跃会话"),
    MeSessionsDevice => ("Device", "设备"),
    MeSessionsSignedIn => ("Signed in", "登录时间"),
    MeSessionsExpires => ("Expires", "过期时间"),
    MeSessionCurrent => ("This device", "本机"),
    MeSessionLogoutCurrent => ("Log out this device", "登出当前设备"),
    MeSessionRevoke => ("Revoke", "下线"),
    MeSessionRevokeConfirm => (
        "Sign out this device? Its cookie stops working immediately.",
        "将该设备登出？其 cookie 会立即失效。",
    ),
    /// token 行删除按钮（与会话"下线"拆 key，zh 文案不同）。
    MeTokenDelete => ("Delete", "删除"),
    MeSessionsSignOutAll => ("Sign out all other devices", "登出其它所有设备"),
    MeSessionsSignOutAllConfirm => (
        "Sign out all other devices? Their cookies stop working immediately.",
        "将其余设备全部登出？它们的 cookie 会立即失效。",
    ),
    MeSessionsTokenModeNote => (
        "Token mode has no server-side sessions; tokens are managed in the API tokens card.",
        "令牌模式无服务端会话；令牌在下方 API 令牌卡中管理。",
    ),
    MeSessionsUnknownDevice => ("Unknown device", "未知设备"),
    MeCardTokens => ("API tokens", "API 令牌"),
    MeTokenName => ("Name", "名称"),
    MeTokenExpiresIn => ("Valid for", "有效期"),
    MeTokenNamePlaceholder => ("e.g. ci-bot", "例如 ci-bot"),
    /// 创建 token 失败 flash：名称为空（校验失败枚举 → 渲染处本地化）。
    MeTokenNameEmpty => ("Token name cannot be empty.", "令牌名称不能为空。"),
    /// 创建 token 失败 flash：与既有 token（含已撤销行）撞名；不回显输入名。
    MeTokenNameInUse => ("Token name is already in use.", "令牌名称已被占用。"),
    AdminResetTokenNote => (
        "API tokens of this user stay valid until revoked separately - revoke them below to force the password flow.",
        "该用户的 API 令牌仍然有效；如需强制其改密，请在下方令牌卡中逐一撤销。",
    ),
    MeTokenCreate => ("Create token", "创建令牌"),
    MeTokenNever => ("never", "永不"),
    MeTokenRevokeConfirm => (
        "CLI sessions using this token will stop working immediately. Revoke it?",
        "使用该令牌的 CLI 会话将立即失效，确定删除？",
    ),
    MeTokenEmptyTitle => ("No API tokens", "还没有 API 令牌"),
    MeTokenEmptyHint => (
        "Create one for crbs CLI / API calls — tokens are long-lived credentials, store them safely.",
        "创建一个用于 crbs CLI / API 调用——令牌属于长期凭据，请妥善保管。",
    ),
    MeTokenCreatedTitle => ("Token created", "令牌已创建"),
    MeTokenCreatedBack => ("Back to my account", "返回个人中心"),
    MeCardProducts => ("My products", "我的产品"),
    MeProductRelation => ("Relation", "关系"),
    MeRelationOwner => ("owner", "所有者"),
    MeViaAcl => ("via ACL", "经 ACL 授予"),
    MeRevision => ("Revision", "修订版本"),
    MeProductsEmptyTitle => ("No products", "还没有产品"),
    MeProductsEmptyHint => (
        "Products you own or are granted access to will appear here.",
        "你持有或被授权的产品会显示在这里。",
    ),
    MeAllProducts => ("View all products →", "查看全部产品 →"),
    // Running/Queued 复用 Legend*（running→building、queued→pending 相位映射）；Revision 复用 MeRevision。
    ProductStatTasks => ("Tasks", "任务总数"),
    ProductStatLastBuild => ("Last build", "最近构建"),
    ProductStatPackages => ("Packages", "包数"),
    AdminResetCardTitle => ("Reset password", "重置密码"),
    AdminResetCardDesc => (
        "Generates a temporary password shown once, signs out all of this user's sessions, and requires a password change at next sign-in.",
        "生成一次性展示的临时密码，登出该用户全部会话，并要求下次登录后修改密码。",
    ),
    AdminResetButton => ("Reset password", "重置密码"),
    AdminResetDoneTitle => ("Password reset", "密码已重置"),
    AdminResetMustChangeNote => (
        "The user must set a new password at next sign-in.",
        "该用户下次登录后须设置新密码。",
    ),
    AdminResetBackToUser => ("Back to user", "返回用户"),
    // ===== 全量迁移 =====
    // -- flash（status_message 的 ?status= 表，机器值→本地化文案）--
    FlashCancelled => ("Cancel request accepted.", "取消请求已接受。"),
    FlashRebuilt => ("Task rebuild requested.", "已请求重建任务。"),
    FlashReproduced => ("Task reproduction requested.", "已请求复现任务。"),
    FlashUserCreated => ("User created.", "用户已创建。"),
    FlashRoleUpdated => ("Role updated.", "角色已更新。"),
    FlashUserStatusUpdated => ("User status updated.", "用户状态已更新。"),
    FlashTokenRevoked => ("Token revoked.", "令牌已删除。"),
    FlashPasswordChanged => (
        "Password changed. Your other sessions were signed out.",
        "密码已修改，其它会话已登出。",
    ),
    FlashSessionsRevoked => ("Sessions signed out.", "会话已登出。"),
    FlashAclGranted => ("ACL granted.", "ACL 已授予。"),
    FlashAclRevoked => ("ACL revoked.", "ACL 已撤销。"),
    FlashSecretRevoked => ("Worker secret revoked.", "Worker 密钥已撤销。"),
    FlashWorkerRemoved => ("Worker removed.", "Worker 已移除。"),
    FlashInitDispatched => (
        "Base_os init dispatched to worker.",
        "base_os 初始化已下发到 Worker。",
    ),
    FlashProductCreated => ("Product created.", "产品已创建。"),
    FlashProductUpdated => ("Product configuration updated.", "产品配置已更新。"),
    FlashVisibilityUpdated => ("Product visibility updated.", "产品可见性已更新。"),
    FlashOwnershipTransferred => (
        "Product ownership transferred.",
        "产品所有权已转让。",
    ),
    FlashRepoRebuilt => ("Product repo rebuilt.", "产品仓库已重建。"),
    FlashGcStarted => (
        "Garbage collection started. It runs in the background; see the history table below.",
        "垃圾回收已启动，正在后台执行；结果见下方历史表。",
    ),
    /// 存储/DB 类操作失败的固定 flash（storage_error_flash → ?status= 机器码）。
    FlashStorageError => (
        "Storage error, please retry.",
        "存储错误，请重试。",
    ),
    /// 非存储内部错误（口令哈希、密钥生成等）的固定 flash。
    FlashInternalError => (
        "Internal error, please retry.",
        "内部错误，请重试。",
    ),
    /// `?error=` 签名校验失败时的固定文案（不反射原始文本）。
    FlashOperationFailed => ("Operation failed.", "操作失败。"),
    // -- 错误 flash（签名 ?error= 文本通道：en 原文按变体/站点映射双语 key）--
    /// 可见性/转让/ACL 校验失败 flash（0 参）。
    FlashOfficialProductPrivate => (
        "official products cannot be made private; transfer ownership first",
        "官方产品不能设为私有；请先转让所有权。",
    ),
    FlashUnpublishPublicDescendants => (
        "cannot unpublish product with public descendants (would leak private ancestor chain)",
        "无法取消发布含公开后代的产品（会泄漏私有祖先链）。",
    ),
    FlashTransferOfficialPublicDescendants => (
        "cannot transfer official product with public descendants (transfer turns product private which would leak via public children)",
        "无法转让含公开后代的官方产品（转让后转为私有，仍会经公开子产品泄漏）。",
    ),
    FlashTransferToCurrentOwner => (
        "cannot transfer product to the current owner",
        "不能把产品转让给当前所有者。",
    ),
    FlashOwnerFullAccess => (
        "product owner already has full access (ACL not needed)",
        "产品所有者已拥有全部权限（无需 ACL）。",
    ),
    /// admin 用户表单校验失败 flash（0 参）。
    FlashUserNameEmpty => ("user name cannot be empty", "用户名不能为空。"),
    FlashUserNameWhitespace => (
        "user name cannot contain whitespace",
        "用户名不能包含空白字符。",
    ),
    /// 最后活跃管理员守卫（Conflict 变体映射，0 参）。
    FlashLastAdminGuard => (
        "cannot demote or disable the last active admin; promote another admin first",
        "无法降级或禁用最后一名活跃管理员；请先提升另一名管理员。",
    ),
    FlashInvalidUserStatus => (
        "status must be active or disabled",
        "状态必须是 active 或 disabled。",
    ),
    /// 产品名为空（server/core 两套产品名校验共用此文案，0 参）。
    FlashProductNameEmpty => ("product name cannot be empty", "产品名不能为空。"),
    FlashInitProductRequired => (
        "product is required for init",
        "初始化 base_os 需要指定产品。",
    ),
    /// GC 触发参数组合校验 flash（validate_gc_request 三条 scope 规则，字面量精确匹配，0 参）。
    FlashGcDryRunScope => (
        "dry_run must be used with results, orphan_mounts, cache, or policy",
        "dry_run 需与 results、orphan_mounts、cache 或 policy 一起使用。",
    ),
    FlashGcProductScope => (
        "product must be used with results or policy",
        "product 需与 results 或 policy 一起使用。",
    ),
    FlashGcAllScope => ("all must be used with cache", "all 需与 cache 一起使用。"),
    /// GC 并发锁冲突（start_gc_task 唯一 Conflict 源，0 参）。
    FlashGcAlreadyRunning => ("gc already running", "已有 GC 任务在运行。"),
    // -- 错误 flash 第二批（tasks/builds 取消与重放、product_editor 内联回显）--
    /// task 级联取消 Ok 臂：无可取消的子构建（0 参）。
    FlashCancelNoCancellable => (
        "no cancellable child builds",
        "没有可取消的子构建。",
    ),
    FlashCancelTaskPermission => (
        "you do not have permission to cancel this task",
        "你没有权限取消该任务。",
    ),
    /// task 已终态（机器码风格字面量原样进 en，0 参）。
    FlashCancelTaskTerminal => (
        "task_already_terminal",
        "任务已处于终态，无法取消。",
    ),
    /// 取消期间 task 状态变化（空子路径 finalize Superseded，0 参）。
    FlashCancelTaskStateChanged => (
        "task state changed during cancel; retry",
        "取消期间任务状态发生变化，请重试。",
    ),
    /// 获取子构建列表失败（cancel.rs Internal，0 参）。
    FlashCancelGetChildrenFailed => (
        "failed to get child builds",
        "获取子构建列表失败。",
    ),
    /// 无子构建 task 的取消落库失败（cancel.rs Internal，0 参）。
    FlashCancelEmptyTaskFailed => (
        "failed to cancel task without child builds",
        "取消无子构建的任务失败。",
    ),
    FlashCancelBuildPermission => (
        "you do not have permission to cancel this build",
        "你没有权限取消该构建。",
    ),
    /// build 已取消（机器码风格字面量原样进 en，0 参）。
    FlashBuildAlreadyCancelled => ("already_cancelled", "构建已被取消。"),
    /// build 已终态不可取消（机器码风格字面量原样进 en，0 参）。
    FlashBuildCancelTerminal => (
        "cannot_cancel_terminal_build",
        "终态构建无法取消。",
    ),
    /// build 非活跃态不可取消（机器码风格字面量原样进 en，0 参）。
    FlashBuildCancelNonActive => (
        "cannot_cancel_non_active_build",
        "非活跃构建无法取消。",
    ),
    /// 取消 build 落库失败（builds/service Internal，0 参）。
    FlashBuildCancelFailed => ("failed to cancel build", "取消构建失败。"),
    FlashRebuildPermission => (
        "you do not have permission to rebuild this task",
        "你没有权限重建该任务。",
    ),
    FlashReproducePermission => (
        "you do not have permission to reproduce this task",
        "你没有权限复现该任务。",
    ),
    FlashReplaySourceGcRebuild => (
        "source srpms no longer available (results may have been GC'd); cannot rebuild",
        "源码 SRPM 已不可用（结果可能已被 GC）；无法重建。",
    ),
    FlashReplaySourceGcReproduce => (
        "source srpms no longer available (results may have been GC'd); cannot reproduce",
        "源码 SRPM 已不可用（结果可能已被 GC）；无法复现。",
    ),
    FlashReplayNoOptionsRebuild => (
        "task has no recorded build options; cannot rebuild",
        "任务未记录构建选项；无法重建。",
    ),
    FlashReplayNoOptionsReproduce => (
        "task has no recorded build options; cannot reproduce",
        "任务未记录构建选项；无法复现。",
    ),
    FlashReplayNoReproducibleChildren => (
        "no reproducible child builds (none recorded build_packages.json); enable reproduce_enabled and rebuild first",
        "没有可复现的子构建（均未记录 build_packages.json；请启用 reproduce_enabled 并先重建）。",
    ),
    /// 重放优先级越界（validate_build_priority Validation，0 参）。
    FlashReplayPriorityRange => (
        "priority must be 0 (default), 1 (high), or 2 (critical)",
        "priority 必须为 0（默认）、1（高）或 2（紧急）。",
    ),
    /// 重放优先级 critical 仅 operator 及以上（validate_build_priority PermissionDenied，0 参）。
    FlashReplayPriorityOperatorOnly => (
        "only operator or admin can set priority=2 (critical)",
        "仅操作员或管理员可设置 priority=2（紧急）。",
    ),
    /// 私有产品缺 owner（product_editor 新建表单，0 参）。
    FlashPrivateNeedsOwnerPick => (
        "Private products require an owner. Pick an owner or choose Public.",
        "私有产品必须指定所有者。请填写所有者或改为公开。",
    ),
    /// 公开产品挂私有父（product_editor 新建表单，0 参）。
    FlashPublicAttachPrivateParent => (
        "public product cannot attach to private parent",
        "公开产品不能挂到私有父产品下。",
    ),
    Yes => ("yes", "是"),
    No => ("no", "否"),
    ThName => ("Name", "名称"),
    ThStatus => ("Status", "状态"),
    ThStarted => ("Started", "开始时间"),
    ThCreated => ("Created", "创建时间"),
    ThExpires => ("Expires", "过期时间"),
    ThRevoked => ("Revoked", "撤销时间"),
    ThAction => ("Action", "操作"),
    ThRole => ("Role", "角色"),
    ThGranted => ("Granted", "授予时间"),
    ThOwner => ("Owner", "所有者"),
    ThParent => ("Parent", "父产品"),
    ThVisibility => ("Visibility", "可见性"),
    VisPublic => ("public", "公开"),
    VisPrivate => ("private", "私有"),
    LabelTask => ("Task", "任务"),
    LabelBackend => ("Backend", "后端"),
    LabelRepo => ("Repo", "仓库"),
    LabelDuration => ("Duration", "时长"),
    LabelCompleted => ("Completed", "完成时间"),
    LabelNetwork => ("Network", "网络"),
    LabelBuildTmpfs => ("Build tmpfs", "构建 tmpfs"),
    LabelSharedLayer => ("Shared layer", "共享层"),
    LabelMemoryMax => ("Memory max", "内存上限"),
    LabelCpuQuota => ("CPU quota", "CPU 配额"),
    LabelResultDir => ("Result dir", "结果目录"),
    LabelCrbsRoot => ("CRBS root", "CRBS 根目录"),
    ThBuildTarget => ("Build target", "构建目标"),
    ThValue => ("Value", "值"),
    ThBaseUrl => ("Base URL", "基础地址"),
    ThEnabled => ("Enabled", "启用"),
    ThGpgCheck => ("GPG check", "GPG 校验"),
    ThCost => ("Cost", "成本"),
    ThTime => ("Time", "时间"),
    ThTarget => ("Target", "目标"),
    ThDetail => ("Detail", "详情"),
    ThSince => ("Since", "起始时间"),
    ThUntil => ("Until", "结束时间"),
    ThChangedAt => ("Changed at", "变更时间"),
    ThChangedBy => ("Changed by", "变更人"),
    ThReason => ("Reason", "原因"),
    ThFile => ("File", "文件"),
    ThKind => ("Kind", "类型"),
    ThSize => ("Size", "大小"),
    ThSigned => ("Signed", "已签名"),
    ArtifactsTitle => ("Artifacts", "产物"),
    ButtonCancel => ("Cancel", "取消"),
    ButtonRebuild => ("Rebuild", "重建"),
    ButtonReproduce => ("Reproduce", "复现"),
    ButtonRevoke => ("Revoke", "撤销"),
    ButtonCreate => ("Create", "创建"),
    ButtonUpdate => ("Update", "更新"),
    ButtonGrant => ("Grant", "授予"),
    ButtonCheck => ("Check", "检查"),
    ButtonDisable => ("Disable", "禁用"),
    ButtonEnable => ("Enable", "启用"),
    ButtonRotateSecret => ("Rotate secret", "轮换密钥"),
    ButtonRevokeSecret => ("Revoke secret", "撤销密钥"),
    ButtonInitBaseOs => ("Init base_os", "初始化 base_os"),
    ButtonRemoveWorker => ("Remove worker", "移除 Worker"),
    WorkerOnline => ("online", "在线"),
    WorkerOffline => ("offline", "离线"),
    WorkerStale => ("stale", "心跳滞后"),
    UserActive => ("active", "启用"),
    UserDisabled => ("disabled", "禁用"),
    /// phase 时间线的 SKIP 详情回退词（日志页 JS 同款注入）。
    PhaseSkipped => ("skipped", "已跳过"),
    /// build 详情"构建阶段"分区卡标题（phase_timeline 容器）。
    PhaseTimelineTitle => ("Build phases", "构建阶段"),
    /// 时间线 pending 占位步的 detail 词（构建失败未跑到的步骤，如 collect-artifacts）。
    NotRun => ("Not run", "未执行"),
    /// 产物速览侧栏卡标题。
    DownloadSrpm => ("Download SRPM", "下载 SRPM"),
    /// 侧栏 Details 的基础镜像行标签（base_os_digest 摘要）。
    LabelBaseOs => ("Base OS", "基础系统"),
    EmptyBuildsTitle => ("No builds found", "未找到构建"),
    EmptyBuildsHint => (
        "Adjust the filters above, or submit a new task to get started.",
        "请调整上方过滤条件，或提交一个新任务。",
    ),
    ViewLogs => ("View logs", "查看日志"),
    /// 非 failed 构建的 error_summary 分区卡标题（软告警备注，warnings/notes 语义渲染）。
    BuildNotesTitle => ("Warnings / notes", "警告 / 备注"),
    BackToBuilds => ("Back to builds", "返回构建列表"),
    BackToBuild => ("Back to build", "返回构建"),
    EmptyArtifactsTitle => ("No artifacts yet", "暂无产物"),
    EmptyArtifactsHint => (
        "Artifacts appear here once the build finishes and its files are collected.",
        "构建完成并收集产物文件后，会显示在这里。",
    ),
    ConfirmCancelBuild => (
        "Cancel this build only? Sibling builds of the same task keep running; to cancel the whole task, use the task page.",
        "仅取消该构建？同任务的其他架构构建仍继续；取消整个任务请到任务页操作。",
    ),
    DownloadFullLog => ("Download full log", "下载完整日志"),
    NoLogs => ("No logs available.", "没有可用的日志。"),
    LiveLogStream => ("Live log stream enabled", "实时日志流已启用"),
    FollowLabel => ("Follow", "跟随滚动"),
    JumpToBottom => ("Jump to bottom", "跳到底部"),
    Download => ("Download", "下载"),
    LogNotStarted => (
        "Build has not started yet. This page will refresh automatically when it starts.",
        "构建尚未开始；开始后本页将自动刷新。",
    ),
    ConfirmCancelTask => (
        "Cancel this task? All its child builds will be cancelled.",
        "取消该任务？其所有子构建将一并取消。",
    ),
    ConfirmRebuildTask => (
        "Rebuild this task? A new task will be created with the same sources and options.",
        "重建该任务？将使用相同的源与选项创建一个新任务。",
    ),
    ConfirmReproduceTask => (
        "Reproduce this task? A new task will be created, rebuilding in the locked dependency snapshot recorded at the original build.",
        "复现该任务？将创建新任务，并在原构建记录的依赖快照下锁定重建。",
    ),
    BackToTasks => ("Back to tasks", "返回任务列表"),
    LabelPackages => ("Packages", "软件包"),
    ChildBuilds => ("Child builds", "子构建"),
    EmptyChildBuildsTitle => ("No child builds yet", "暂无子构建"),
    EmptyChildBuildsHint => (
        "Child builds appear here once the task is dispatched to workers.",
        "任务下发到 Worker 后，子构建会显示在这里。",
    ),
    TitleDuration => ("duration", "时长"),
    EmptyPackagesTitle => ("No packages found", "未找到软件包"),
    EmptyPackagesHint => (
        "Adjust the product filter above; packages appear after the first build.",
        "请调整上方产品过滤条件；首次构建后软件包会显示在这里。",
    ),
    ThLatestPhase => ("Latest phase", "最新状态"),
    // 术语定则：此列 = 该包任务（提交）数，非单架构构建数；key 名不动。
    ThAttempts => ("Submissions", "提交数"),
    ThLastBuild => ("Last build", "最近构建"),
    // 产品列表页活动列 Tasks 列头短版（详情页带用 ProductStatTasks 长版"任务总数"，列头吃不下）。
    ThTasks => ("Tasks", "任务"),
    AllVersions => ("All versions", "全部版本"),
    // 同 ThAttempts：NVR 维度的"尝试"实为任务（提交）列表。
    EmptyAttemptsTitle => ("No submissions yet", "暂无提交记录"),
    EmptyAttemptsHint => (
        "Tasks for this NVR appear here once they are submitted.",
        "该 NVR 的任务提交后会显示在这里。",
    ),
    BackToPackages => ("Back to packages", "返回软件包列表"),
    Versions => ("Versions", "版本历史"),
    EmptyVersionsTitle => ("No versions", "暂无版本"),
    EmptyVersionsHint => (
        "Submit a task for this package to see its build history here.",
        "为该软件包提交任务后，构建历史会显示在这里。",
    ),
    ThLatest => ("Latest", "最新状态"),
    EmptyWorkersTitle => ("No workers found", "未找到 Worker"),
    EmptyWorkersHint => (
        "Workers register automatically on first heartbeat; adjust the filters above.",
        "Worker 首次心跳后自动注册；可调整上方过滤条件。",
    ),
    ThCapacity => ("Capacity", "容量"),
    ThLoad => ("Load", "负载"),
    ThLastHeartbeat => ("Last heartbeat", "最近心跳"),
    ThVersion => ("Version", "版本"),
    LabelHasSecret => ("Has secret", "持有密钥"),
    BackToWorkers => ("Back to workers", "返回 Worker 列表"),
    ActiveBuilds => ("Active builds", "进行中的构建"),
    EmptyActiveBuildsTitle => ("No active builds on this worker", "该 Worker 暂无进行中的构建"),
    EmptyActiveBuildsHint => (
        "Builds assigned to this worker appear here while they run.",
        "分配给该 Worker 的构建在运行期间会显示在这里。",
    ),
    ConfirmInitBaseOs => (
        "Dispatch base_os init to this worker?",
        "向该 Worker 下发 base_os 初始化任务？",
    ),
    WorkerSecretRotated => ("Worker secret rotated", "Worker 密钥已轮换"),
    BackToWorker => ("Back to worker", "返回 Worker"),
    AdminWorkerSecretTitle => ("Admin · Worker secret", "管理 · Worker 密钥"),
    // -- worker 负载遥测（列表 CPU/内存列头 + 详情 kv 键 + stale 标记）--
    ThCpu => ("CPU", "CPU"),
    ThMemory => ("Memory", "内存"),
    /// 详情遥测现值条 CPU 组标签（与 ThCpu 同词、语义点位独立，列表列头改词不牵连详情）。
    WorkerCpuLoad => ("CPU", "CPU"),
    WorkerTelemetryTime => ("Telemetry time", "遥测时间"),
    /// 详情遥测值旁 stale 标记的 title 说明（标记词复用 WorkerStale）。
    TelemetryStaleNote => (
        "Sampled at the last heartbeat, which is now overdue.",
        "采样自最近一次心跳，该心跳已超时。",
    ),
    /// 首页架构条 CPU 均值 chip 的 title（chip 文案见 FmtKey::ArchCpuAvg）。
    ArchCpuAvgTitle => (
        "Average CPU utilization of online workers",
        "在线 Worker 的 CPU 平均利用率",
    ),
    NewProduct => ("New product", "新建产品"),
    EmptyProductsTitle => ("No products configured", "尚未配置产品"),
    EmptyProductsHint => (
        "Products are created by builders from the \"New product\" action.",
        "产品由开发者及以上角色通过“新建产品”创建。",
    ),
    EmptyProductsMatchTitle => ("No products match", "没有匹配的产品"),
    EmptyProductsMatchHint => (
        "Adjust the filters above, or reset them to see all products.",
        "请调整上方过滤条件，或重置以查看全部产品。",
    ),
    EditConfig => ("Edit config", "编辑配置"),
    BackToProducts => ("Back to products", "返回产品列表"),
    BackToProduct => ("Back to product", "返回产品"),
    HistoryLabel => ("History", "历史"),
    RootProductPlaceholder => ("— (root product)", "—（根产品）"),
    SectionBasePackages => ("Base packages", "基础软件包"),
    EmptyBasePackagesTitle => ("No base packages on this layer", "本层未配置基础软件包"),
    EmptyBasePackagesHint => (
        "Parent products can still provide packages — see the effective config below.",
        "父产品仍可提供软件包——见下方生效配置。",
    ),
    SectionRepos => ("Repositories", "软件源"),
    NoRepos => ("No repositories configured.", "未配置软件源。"),
    SectionRpmMacros => ("RPM macros", "RPM 宏"),
    NoMacros => ("No macros configured.", "未配置宏。"),
    SectionHooks => ("Hooks", "钩子"),
    NoHooks => ("No hooks configured.", "未配置钩子。"),
    ProductPublicNote => ("This product is publicly visible.", "该产品对所有人可见。"),
    ProductPrivateNote => (
        "This product is private (only owner and authorized users can see it).",
        "该产品为私有，仅所有者与被授权用户可见。",
    ),
    MakePrivate => ("Make private", "设为私有"),
    ConfirmMakePrivate => (
        "Make this product private? Only the owner and users granted access via ACL will be able to see it.",
        "将该产品设为私有？此后仅所有者与经 ACL 授权的用户可见。",
    ),
    MakePublic => ("Make public", "设为公开"),
    ConfirmMakePublic => (
        "Make this product public? It will be visible to everyone.",
        "将该产品设为公开？它将对所有人可见。",
    ),
    SectionAcl => ("Access Control (ACL)", "访问控制（ACL）"),
    PlaceholderUsername => ("username", "用户名"),
    GrantAccess => ("Grant access", "授予访问权限"),
    NoAclEntries => ("No ACL entries configured.", "未配置 ACL 条目。"),
    SectionOwnership => ("Ownership", "所有权"),
    OfficialProductNote => (
        "This is an official product (no owner).",
        "这是官方产品（无所有者）。",
    ),
    NewOwnerUsername => ("New owner username", "新所有者用户名"),
    TransferOwnership => ("Transfer ownership", "转让所有权"),
    ConfirmTransferOfficial => (
        "Transfer this official product to the new owner? It will become private (visible only to the new owner and authorized users) and its running builds and tasks will be cancelled.",
        "将该官方产品转让给新所有者？它将变为私有（仅新所有者与被授权用户可见），且其运行中的构建与任务将被取消。",
    ),
    ConfirmTransferOwnership => (
        "Transfer ownership to the new owner? They will have full control of this product.",
        "将所有权转让给新所有者？对方将拥有该产品的全部控制权。",
    ),
    MaintenanceDesc => (
        "Rebuild the repository hardlink layout for this product from published build artifacts. Build results are not affected.",
        "基于已发布的构建产物，重建该产品仓库的硬链接布局；不影响构建结果。",
    ),
    RebuildRepo => ("Rebuild repo", "重建仓库"),
    ConfirmRebuildRepo => (
        "Rebuild the repository structure for this product?",
        "重建该产品的仓库结构？",
    ),
    SectionEffectiveToml => ("Effective TOML", "生效 TOML 配置"),
    EffectiveTomlDesc => (
        "Fully resolved config after walking the parent chain (this is what workers actually see).",
        "沿父链完全解析后的配置（Worker 实际看到的内容）。",
    ),
    NoHistoryEntries => ("No history entries.", "暂无历史记录。"),
    ThDiffFrom => ("From", "起始版本"),
    ThDiffTo => ("To", "目标版本"),
    CompareRevisions => ("Compare revisions", "对比版本"),
    BackToProductHistory => ("Back to product history", "返回产品历史"),
    DiffNoChangesTitle => ("No configuration changes", "配置无变更"),
    DiffNoChangesHint => (
        "The selected revisions have identical configuration content.",
        "所选修订版本的配置内容完全相同。",
    ),
    NewProductPageTitle => ("New Product", "新建产品"),
    LabelProductNameSlug => ("Product name (slug: [a-z0-9_-])", "产品名（slug：[a-z0-9_-]）"),
    LabelDisplayNameOptional => ("Display name (optional)", "显示名（可选）"),
    /// display_name 输入框 placeholder（新建 / 编辑页共用）。
    PlaceholderDisplayName => ("e.g. My Product", "如 我的产品"),
    LabelParentOptional => (
        "Parent product name (optional — leave empty for root)",
        "父产品名（可选——留空为根产品）",
    ),
    PlaceholderEmptyRoot => ("(empty = root product)", "（留空 = 根产品）"),
    LabelOwnerOptional => (
        "Owner (leave empty for official product)",
        "所有者（留空为官方产品）",
    ),
    PlaceholderEmptyOfficial => ("(empty = official, public)", "（留空 = 官方、公开）"),
    PrivateNeedsOwner => (
        "Private products require an owner.",
        "私有产品必须指定所有者。",
    ),
    BuilderVisibilityNote => (
        "Visibility: private on creation (you can publish it later from the product page)",
        "可见性：创建即私有（之后可在产品页公开发布）",
    ),
    LabelConfigToml => ("Product configuration (TOML)", "产品配置（TOML）"),
    LabelChangeReason => ("Change reason (optional)", "变更原因（可选）"),
    PlaceholderDescribeChange => ("describe the change", "描述本次变更"),
    EditLastChanged => ("last changed", "上次变更"),
    YouAreOwner => (
        "You are the owner of this product.",
        "你是该产品的所有者。",
    ),
    ConfigValid => ("✓ Configuration is valid.", "✓ 配置有效。"),
    MergedPreview => (
        "Merged configuration preview (chain-resolved TOML)",
        "合并配置预览（链解析 TOML）",
    ),
    AdminUsersTitle => ("Users", "用户"),
    AdminCardUsersDesc => (
        "Create users, manage roles, disable accounts.",
        "创建用户、管理角色、禁用账户。",
    ),
    AuditLogsTitle => ("Audit Logs", "审计日志"),
    AdminCardAuditDesc => (
        "View administrative actions with filtering.",
        "按条件查看管理操作记录。",
    ),
    AdminCardWorkersDesc => (
        "Rotate secrets and remove offline workers.",
        "轮换密钥、移除离线 Worker。",
    ),
    AdminCardGcTitle => ("Garbage Collection", "垃圾回收"),
    AdminCardGcDesc => (
        "Reclaim disk space: dry-run, then clean results and cache.",
        "回收磁盘空间：先试运行，再清理结果与缓存。",
    ),
    AdminCardSettingsDesc => (
        "Runtime switches: open or close self-service registration.",
        "运行时开关：开放或关闭自助注册。",
    ),
    CreateUser => ("Create user", "创建用户"),
    EmptyUsersTitle => ("No users found", "未找到用户"),
    EmptyUsersHint => (
        "Adjust the filters above, or create a user to get started.",
        "请调整上方过滤条件，或创建一个用户。",
    ),
    BackToUsers => ("Back to users", "返回用户列表"),
    ConfirmDisableUser => (
        "Disable this user? They will be signed out and unable to log in.",
        "禁用该用户？其所有会话将被登出且无法再登录。",
    ),
    SectionTokens => ("Tokens", "令牌"),
    LabelNameOptional => ("Name (optional)", "名称（可选）"),
    LabelExpiresDays => ("Expires in days (optional)", "有效期天数（可选）"),
    EmptyTokensTitle => ("No tokens", "暂无令牌"),
    EmptyTokensHint => (
        "Create a token above to let this user sign in or call the API.",
        "在上方创建令牌，供该用户登录或调用 API。",
    ),
    AdminTokenCreatedTitle => ("Admin · Token created", "管理 · 令牌已创建"),
    AdminUsersPageTitle => ("Admin · Users", "管理 · 用户"),
    AdminAuditPageTitle => ("Admin · Audit Logs", "管理 · 审计日志"),
    SectionProductAcl => ("Product ACL", "产品 ACL"),
    EmptyAclNoProductsHint => (
        "Create a product before granting ACLs; access is granted per product.",
        "请先创建产品再授予 ACL；访问权限按产品授予。",
    ),
    EmptyUserAclsTitle => ("No product ACLs", "暂无产品 ACL"),
    EmptyUserAclsHint => (
        "Grant access above to let this user see and build a private product.",
        "在上方授予访问权限，该用户即可查看并构建私有产品。",
    ),
    EmptyAuditTitle => ("No audit entries", "暂无审计记录"),
    EmptyAuditHint => (
        "Adjust the filters above, or reset them to see all recorded actions.",
        "请调整上方过滤条件，或重置以查看全部记录。",
    ),
    GcPageTitle => ("Garbage collection", "垃圾回收"),
    AdminGcPageTitle => ("Admin · GC", "管理 · 垃圾回收"),
    GcTrigger => ("Trigger", "触发"),
    GcDestructiveWarning => (
        "Destructive: with Dry-run unchecked, garbage collection permanently deletes build results, cache entries and layer data.",
        "危险操作：未勾选试运行时，垃圾回收将永久删除构建结果、缓存与层数据。",
    ),
    GcDryRun => ("Dry run", "试运行"),
    GcDryRunDesc => (
        "Only count what would be cleaned — nothing is deleted (on by default; run once and review before a real run)",
        "仅统计将被清理的内容——不会删除任何数据（默认开启；正式执行前先试运行并确认）",
    ),
    GcOptResults => ("Build results", "构建结果"),
    GcOptResultsDesc => (
        "Delete build artifacts past their retention period",
        "删除超过保留期的构建产物",
    ),
    GcOptMounts => ("Orphan mounts", "孤儿挂载"),
    GcOptMountsDesc => (
        "Clean leftover chroot mount points from failed builds",
        "清理失败构建残留的 chroot 挂载点",
    ),
    GcOptCache => ("Cache", "缓存"),
    GcOptCacheDesc => (
        "Reclaim package cache space (keeps entries referenced by builds)",
        "回收软件包缓存空间（保留构建引用的条目）",
    ),
    GcOptPolicy => ("Apply policy", "应用保留策略"),
    GcOptPolicyDesc => (
        "Run the full retention policy (implies results and cache)",
        "执行完整保留策略（含构建结果与缓存）",
    ),
    GcOptAll => ("All (with Cache)", "全部（含缓存）"),
    GcOptAllDesc => (
        "With Cache: clear the entire package cache, including entries in use by running builds",
        "配合缓存：清空整个软件包缓存，包括运行中构建正在使用的条目",
    ),
    GcProductPlaceholder => ("product (empty = all)", "产品（留空 = 全部）"),
    GcRun => ("Run GC", "执行 GC"),
    GcRunHint => ("Run GC needs confirmation", "执行 GC 需要确认"),
    GcRunConfirm => (
        "Run GC without dry-run: expired build results, cache entries and layer data will be permanently deleted. Deletion cannot be undone. Continue?",
        "非试运行执行 GC：过期的构建结果、缓存与层数据将被永久删除，且不可恢复。继续吗？",
    ),
    GcRecentTasks => ("Recent GC tasks", "最近 GC 任务"),
    GcHistoryNote => (
        "History is kept in memory and cleared on restart.",
        "历史仅保存在内存中，重启后清空。",
    ),
    EmptyGcTitle => ("No GC tasks yet", "暂无 GC 任务"),
    EmptyGcHint => (
        "Trigger a dry-run above to see what GC would clean up.",
        "在上方触发一次试运行，查看 GC 会清理哪些内容。",
    ),
    ThDetails => ("Details", "明细"),
    GcHelpTitle => ("What does GC do?", "GC 做什么？"),
    GcHelpP1 => (
        "Garbage collection reclaims disk space: it deletes expired build results (per product retention policy), cleans orphan mounts, prunes the package cache and removes stale shared layers.",
        "垃圾回收用于回收磁盘空间：删除过期的构建结果（按产品保留策略）、清理孤儿挂载、回收软件包缓存空间并移除过期的共享层。",
    ),
    // 三片段拼 "With **Dry run** checked, …"；中英语序一致，strong 保留在 Dry run 上。
    /// help 第二段的引导词（"With **Dry run** checked…" 的 With）。
    GcHelpWith => ("With", "勾选"),
    /// help 第二段 strong 之后的剩余整句。
    GcHelpCheckedTail => (
        "checked, GC only reports what it would delete — nothing is removed. Uncheck it to actually delete. GC runs in the background after you trigger it.",
        "时，GC 仅报告会删除的内容——不会实际删除；取消勾选才会真正删除。触发后 GC 在后台运行。",
    ),
    GcChipError => ("error: ", "错误："),
    GcChipResults => ("results", "结果"),
    GcChipPolicy => ("policy", "策略"),
    GcChipMounts => ("mounts", "挂载"),
    GcChipCache => ("cache", "缓存"),
    GcChipLayers => ("layers", "层"),
    GcChipDryRun => ("dry-run", "试运行"),
    GcChipWouldFree => ("would free", "将释放"),
    GcChipFreed => ("freed", "已释放"),
    GcMountsTitle => ("cleaned / found", "已清理 / 发现"),
    GcNothingToDo => ("nothing to do", "无可清理"),
    // 术语定则：一次提交创建的是任务（fan_out_builds 先建 Task，再按 arch × srpm 展开子构建），非"构建"。
    TaskNewTitle => ("Submit task", "提交任务"),
    TaskNewAction => ("New task", "新建任务"),
    LabelSrpmFiles => (
        "SRPM files (.src.rpm, multiple allowed)",
        "SRPM 文件（.src.rpm，可多选）",
    ),
    TaskNewDropHint => (
        "Drag and drop .src.rpm files here, or pick files with the button below.",
        "将 .src.rpm 文件拖拽到此处，或用下方按钮选择文件。",
    ),
    LabelArches => ("Architectures (optional)", "架构（可选）"),
    /// noscript 文本输入 arch 的用法说明。
    TaskNewArchNoscript => (
        "Without JavaScript: comma-separated list, e.g. x86_64,aarch64; leave empty to use the product default.",
        "无 JavaScript 时：逗号分隔，如 x86_64,aarch64；留空使用产品默认架构。",
    ),
    /// 产品未声明 arches 时的说明（JS 显隐）。
    TaskNewArchDefaultNote => (
        "This product declares no architectures; the server will pick the default.",
        "该产品未声明架构，服务端将使用默认架构。",
    ),
    TaskNewNoProductsTitle => ("No products available", "没有可提交的产品"),
    TaskNewNoProductsHint => (
        "Ask an administrator to grant you build access to a product.",
        "请联系管理员授予你产品的构建权限。",
    ),
    /// 上传进度条 aria-label。
    TaskNewUploadProgress => ("Upload progress", "上传进度"),
    /// XHR 网络级失败的 JS 提示文案。
    UploadFailed => ("Upload failed — please try again.", "上传失败，请重试。"),
    ButtonSubmit => ("Submit", "提交"),
    // 同 TaskNewTitle：提交的产物是任务。
    /// ?status=submitted flash。
    FlashSubmitted => ("Task submitted.", "任务已提交。"),
    /// nav 搜索框占位 + aria-label（同时是 "/" 快捷键的视觉暗示）。
    SearchPlaceholder => ("Search…", "搜索…"),
    SearchPageTitle => ("Search", "搜索"),
    SearchDirectTitle => ("Direct matches", "直达结果"),
    SearchEmptyTitle => ("No results", "没有找到结果"),
    SearchEmptyHint => (
        "Enter a task/build ID to jump straight to it, or a product/package name prefix.",
        "输入任务/构建 ID 可直达对应页面，或输入产品/软件包名称前缀。",
    ),
    /// 空 q 空态提示。
    SearchEmptyQueryHint => (
        "Type a task/build ID or a name prefix, then press Enter. Tip: press / anywhere to focus the search box.",
        "输入任务/构建 ID 或名称前缀后回车。提示：任意页面按 / 可聚焦搜索框。",
    ),
    /// 侧栏 Details 卡标题（与 GC 表头 ThDetails「明细」分 key，防两处语义漂移）。
    SideDetailsTitle => ("Details", "详细信息"),
    DangerZoneTitle => ("Danger zone", "危险操作"),
    ParentTaskTitle => ("Parent task", "所属任务"),
    DangerCancelBuildDesc => (
        "Only this build is stopped and marked as cancelled; the rest of the task keeps running.",
        "仅停止该构建并标记为已取消；任务其余构建继续运行。",
    ),
    DangerCancelTaskDesc => (
        "All running child builds are stopped.",
        "所有进行中的构建都将停止。",
    ),
    DangerMakePrivateDesc => (
        "Only the owner and admins will see this product.",
        "产品将仅对所有者和管理员可见。",
    ),
    DangerMakePublicDesc => (
        "The product becomes visible to everyone.",
        "产品将对所有人可见。",
    ),
    DangerTransferDesc => (
        "Ownership is transferred to another user.",
        "所有权将转让给其他用户。",
    ),
    DangerDisableUserDesc => (
        "The user can no longer sign in.",
        "该用户将无法再登录。",
    ),
    ChangelogPageTitle => ("RPM changelog", "RPM 变更日志"),
    /// 产物卡头的下钻链接文案（每构建/每任务恰一个入口；同时是链接可读名）。
    ChangelogLink => ("changelog", "变更日志"),
    /// fail-soft 空态标题（rpm 缺失 / 解析空 / 文件不可达）。
    ChangelogEmptyTitle => ("Changelog unavailable", "变更日志不可用"),
    ChangelogEmptyHint => (
        "No changelog was read for this artifact (rpm tool missing, file unreadable, or the package has no changelog).",
        "未能读取该产物的变更日志（缺少 rpm 工具、文件不可读或包内无变更记录）。",
    ),
    /// 服务端分页（零 JS）导航：更旧（下一页，更多历史条目）。
    ChangelogOlder => ("Older entries", "更早的条目"),
    /// 服务端分页（零 JS）导航：更新（上一页，回到较新条目）。
    ChangelogNewer => ("Newer entries", "更新的条目"),
    /// 303 响应体与 title（浏览器自动跟随 303 基本不渲染，仅禁跟随客户端可见）。
    Redirecting => ("Redirecting...", "正在跳转…"),
    /// nav 链接与页 h1（短形，nav 空间有限）。
    NavRepro => ("Repro", "复现率"),
    SectionReproSummary => ("Comparison outcomes", "比对结果分布"),
    SectionReproByProduct => ("By product", "按产品"),
    SectionReproReplays => ("Replay records", "复现记录"),
    ReproRateLabel => ("reproduce rate", "复现率"),
    /// 分母口径说明（面板脚注，复现率口径的看板侧披露）。
    ReproDenominatorNote => (
        "Reproduce rate = same / (same + diff + build_failed). dep_unavailable and infra_error are infrastructure availability issues, counted separately.",
        "复现率 = same / (same + diff + build_failed)。dep_unavailable 与 infra_error 属基础设施可用性问题，单独统计不进分母。",
    ),
    /// 长窗口越过 DB 保留期的现存行口径警示（days=90/all 时显示）。
    ReproRetentionWarning => (
        "Windows beyond the retention period reflect surviving rows only (pruned history is not counted).",
        "统计窗口超出数据保留期时，仅按现存记录计算，已被清理的历史不参与统计。",
    ),
    /// Other 列 hover 说明（dep_unavailable + infra_error 合并列）。
    ThOtherHint => (
        "dep_unavailable + infra_error: environment causes, excluded from the rate denominator",
        "dep_unavailable + infra_error：环境因素，不计入复现率分母",
    ),
    /// 日桶趋势微图：region aria-label 与空序列兜底文案；面板小节标题。
    SectionReproTrend => ("Daily trend", "每日趋势"),
    ReproSeriesAria => (
        "Daily comparison counts, stacked by verdict",
        "每日比对数，按 verdict 分色堆叠",
    ),
    ReproSeriesEmpty => (
        "No daily buckets in this window yet.",
        "该窗口内暂无按日分布数据。",
    ),
    /// 时间窗口“全部时间”chip（7d/30d/90d 为纯数字不译）。
    ReproWindowAll => ("All time", "全部时间"),
    ThSourceBuild => ("Source", "源构建"),
    ThReplayBuild => ("Replay", "重放"),
    ThRate => ("Rate", "复现率"),
    ThTotal => ("Total", "合计"),
    /// 产品表“same”列头（verdict 分布条与单元格值是 CHECK 域标识符，保留机器串不译）。
    ThSame => ("Same", "相同"),
    /// 产品表“diff”列头（同上）。
    ThDiff => ("Diff", "差异"),
    /// 产品表“build_failed”列头（同上）。
    ThBuildFailed => ("Build failed", "构建失败"),
    /// 产品表“other”列头（dep_unavailable + infra_error 合并列，同上）。
    ThOther => ("Other", "其他"),
    EmptyReproTitle => ("No comparisons recorded", "暂无比对记录"),
    EmptyReproHint => (
        "Enable `deterministic = true` on a product; each successful build then runs a replay comparison automatically.",
        "对产品启用 deterministic = true 后，每次成功构建都会自动跟跑一次重放比对，结果在此汇总。",
    ),
    // -- 用户/ACL 角色显示名（下拉/徽章本地化，value 仍是机器串；en 首字母大写 =
    //    产品页 ACL 表单钉住的形态；zh 短形：管理员/运维/开发者/访客）--
    RoleAdmin => ("Admin", "管理员"),
    RoleOperator => ("Operator", "运维"),
    RoleBuilder => ("Builder", "开发者"),
    RoleViewer => ("Viewer", "访客"),
    // SSE 断线终态：英文 "Connection closed" 不得是 ConnectionLost 文案的前缀——终态/瞬态肉眼可辨。
    // -- SSE 断线终态（追加表尾，哨兵编号顺延）--
    /// EventSource CLOSED（复鉴权断流/握手终败）终态 title：浏览器已放弃重连，不声称“正在重连”。
    ConnectionClosed => ("Connection closed", "连接已关闭"),
    // -- 术语表头（追加表尾，哨兵编号顺延）--
    /// NVR 术语表头（packages/builds 列表）：RPM 生态术语不译（LANG_INVARIANT）。
    ThNvr => ("NVR", "NVR"),
    // -- 提交构建页（追加表尾，哨兵编号顺延）--
    /// repro-from-srpm 复选框：SRPM 头参数回放构建（环境不还原）。
    TaskNewReproFromSrpm => (
        "Replay SRPM header parameters (BUILDHOST/BUILDTIME); the build environment is not restored, payload bytes are not guaranteed",
        "回放 SRPM 头参数（BUILDHOST/BUILDTIME）；不还原构建环境，不保证产物字节一致",
    ),
    // -- 整仓重建批次（operator+，追加表尾，哨兵编号顺延）--
    /// nav 链接（operator+ 可见，与页面门槛一致）。
    NavBatches => ("Rebuilds", "整仓重建"),
    BatchesPageTitle => ("Rebuild batches", "整仓重建批次"),
    BatchesEmptyTitle => ("No rebuild batches", "暂无整仓重建批次"),
    BatchesEmptyHint => (
        "Operator-submitted whole-repo rebuild batches appear here.",
        "由运维角色提交的整仓重建批次会显示在这里。",
    ),
    BatchesProgress => ("Progress", "进度"),
    BatchesRounds => ("Rounds", "轮次进度"),
    BatchesRoundCol => ("Round", "轮次"),
    BatchesFailures => ("Failures by error", "失败分桶"),
    BatchesNoFailures => ("No failed items", "无失败项"),
    BatchesCancel => ("Cancel batch", "取消批次"),
    BatchesCancelConfirm => (
        "Cancel this rebuild batch? In-flight builds will be cancelled.",
        "取消该整仓重建批次？在途构建将被取消。",
    ),
    FlashBatchCancelled => ("Batch cancelled.", "批次已取消。"),
    /// 批次状态显示名（build_batches.status 域；与构建相位表分开）。
    BatchStPreparing => ("preparing", "准备中"),
    BatchStPlanning => ("planning", "规划中"),
    BatchStRunning => ("running", "运行中"),
    BatchStCompleted => ("completed", "已完成"),
    BatchStPartial => ("partial", "部分完成"),
    BatchStFailed => ("failed", "失败"),
    BatchStCancelled => ("cancelled", "已取消"),
    // -- 复现记录 drill-down（/ui/reproducibility，追加表尾，哨兵编号顺延）--
    LabelReplaySource => ("Replay source", "复现来源"),
    LabelReplays => ("Replays", "复现任务"),
    ReproBoardEmpty => ("No replay comparisons yet", "暂无复现比对"),
    ThDiffPkgs => ("Needs attention", "需关注"),
    /// 全一致重放任务组的一行徽章（组不可展开，用户要求一致不过多显示）。
    ReproAllSame => ("All consistent", "全部一致"),
    /// 第三级单包徽章（差异形态；verdict 同款机器词在 zh 侧给短中文）。
    ReproBadgeDiff => ("diff", "差异"),
    ReproBadgeOnlySource => ("only in source", "仅源构建"),
    ReproBadgeOnlyReplay => ("only in replay", "仅重放"),
    ReproBadgeNoAnchor => ("unsigned missing", "缺哈希锚"),
    LabelSrpmDownload => ("SRPM download", "SRPM 下载"),
    SrpmPolicyPublic => ("public", "公开可下"),
    SrpmPolicyOperator => ("operator/admin only", "仅 operator/admin"),
    SrpmPolicyFollowGlobal => ("follow global", "跟随全局"),
    // -- worker 详情页重排（追加表尾，哨兵编号顺延）--
    /// 详情页遥测卡标题（主列第一卡）。
    TelemetryTitle => ("Telemetry", "遥测"),
    /// 节点内存总量（遥测卡 Memory 行注记与 Details 行标签共用）。
    WorkerMemTotal => ("Memory total", "内存总量"),
    /// 详情页 Recent builds 卡标题与空态。
    RecentBuildsTitle => ("Recent builds", "最近构建"),
    EmptyRecentBuildsTitle => ("No recent builds", "暂无构建记录"),
    EmptyRecentBuildsHint => (
        "Builds dispatched to this worker appear here.",
        "派发给该 Worker 的构建会显示在这里。",
    ),
    /// 详情页 Base OS inits 卡标题与空态。
    RecentInitsTitle => ("Base OS inits", "base_os 初始化"),
    EmptyRecentInitsTitle => ("No base_os inits", "暂无 base_os 初始化"),
    EmptyRecentInitsHint => (
        "Init tasks dispatched to this worker appear here.",
        "下发给该 Worker 的初始化任务会显示在这里。",
    ),
    /// Active builds 空态（worker 离线分支）。
    EmptyActiveOfflineTitle => ("Worker is offline", "Worker 离线中"),
    EmptyActiveOfflineHint => (
        "Active builds will appear here once the worker is back online.",
        "Worker 恢复在线后，此处显示活动构建。",
    ),
    /// init 分配行活跃态徽章词（终态复用 t_phase 的 succeeded/failed/cancelled）。
    WorkerInitRunning => ("running", "初始化中"),
    // -- worker 详情页 Danger zone 行说明（追加表尾，哨兵编号顺延）--
    DangerRotateWorkerDesc => (
        "Generates a new secret shown once; the old secret stops working immediately.",
        "生成新密钥并一次性展示；旧密钥立即失效。",
    ),
    DangerRevokeWorkerDesc => (
        "The worker can no longer authenticate until re-registered.",
        "该 Worker 将无法再认证，直至重新注册。",
    ),
    DangerInitWorkerDesc => (
        "Dispatch a base_os init task to this worker.",
        "向该 Worker 下发 base_os 初始化任务。",
    ),
    DangerRemoveWorkerDesc => (
        "Deletes the worker; its non-terminal builds are reset to pending.",
        "删除该 Worker；其未终态构建将重置为待排队。",
    ),
    // -- build 详情页 Lifecycle 行标（追加表尾，哨兵编号顺延）--
    // 三段间隙行标：Queued = Submitted→Dispatched、Picked up = Dispatched→
    // Claimed、Ran = Claimed→Finished。En 行标动宾短语、时长进 dd 模板
    //（FmtKey LifecyclePickupDur 的 "in {0}"）；zh 行标名词化、dd 直排时长。
    LifecycleQueued => ("Queued", "排队"),
    LifecyclePickedUp => ("Picked up", "认领耗时"),
    LifecyclePickupWaiting => ("waiting", "等待中"),
    LifecycleRan => ("Ran", "运行"),
    // -- worker 详情页遥测趋势面板（追加表尾，哨兵编号顺延）--
    /// 档位切换链接显示文案（URL `?range=1h|24h|7d`）。
    TelemetryRange1h => ("1h", "1 小时"),
    TelemetryRange24h => ("24h", "24 小时"),
    TelemetryRange7d => ("7d", "7 天"),
    /// 趋势图 CPU 序列图例（内存序列复用 ThMemory 的 "Memory"/"内存"）。
    TelemetryCpuLegend => ("CPU util.", "CPU 利用率"),
    /// 图内离线段标注（连续无采样段中点）。
    TelemetryOffline => ("offline", "离线"),
    /// 窗口内无采样的空态（新部署无历史属预期）。
    TelemetryEmpty => (
        "No telemetry history yet; samples accumulate from deployment.",
        "暂无遥测历史；自部署时刻开始积累。",
    ),
    // -- 现值条负载组（追加表尾，哨兵编号顺延）--
    /// 详情遥测现值条负载组标签（load1/ncpu 倍数；与列表 Load 列头 ThLoad
    /// 分 key，语义点位独立）；绝对口径 title 见 FmtKey::LoadAvgTitle。
    ThLoadAvg => ("Load", "负载"),
    // -- 资源可观测（追加表尾，哨兵编号顺延）--
    /// 构建详情页"资源"卡标题（任一资源字段非 NULL 才渲染整卡）。
    BuildResourcesTitle => ("Resources", "资源"),
    /// 实测峰值内存行标（cgroup memory.peak 口径，KB 人类化展示）。
    ResPeakMem => ("Peak memory (RSS)", "实测峰值内存"),
    /// 采集包络峰值行标与旁注（含页缓存，与 RSS 口径并读）。
    ResPeakTotal => ("Envelope peak", "包络峰值"),
    ResPeakTotalNote => ("incl. page cache", "含页缓存"),
    /// CPU 累计时间行标（秒 → 人类可读时长）。
    ResCpuTime => ("CPU time", "CPU 时间"),
    /// CPU 利用率 p90 行标（单位"核"进行标，值裸数字）。
    ResCpuP90 => ("CPU p90 (cores)", "CPU p90（核）"),
    /// 构建期磁盘写入行标（字节人类化展示）。
    ResDiskWrite => ("Disk written", "磁盘写入"),
    /// OOM 警示徽章词（内核术语两语同形，登记 LANG_INVARIANT_KEYS）。
    ResOomBadge => ("OOM", "OOM"),
    /// OOM 徽章 title（检出机制说明）。
    ResOomTitle => (
        "Killed by the kernel OOM killer (cgroup memory.events)",
        "被内核 OOM 杀死（cgroup memory.events）",
    ),
    /// 采样口径 chip 的 title（chip 文本是机器值 cgroup / proc，不走文案表）。
    ResSamplingLabel => ("Sampling backend", "采样口径"),
    /// 放置需求声明行标（值由调用方按非 NULL 维组合，tokens 语言中立）。
    ResReqLabel => ("Placement requirements", "放置需求"),
    /// Worker 列表 Disk 列头（disk_free_kb 绝对值文本，无分母不做条形）。
    ThDisk => ("Disk", "磁盘"),
    /// 详情遥测现值条磁盘组标签（与列表 Disk 列头分 key，语义点位独立）。
    WorkerDiskFree => ("Disk free", "磁盘可用"),
    /// 详情页采集能力 chips 组标签（chip 文本是能力 token，不走文案表）。
    WorkerCapsLabel => ("Capabilities", "采集能力"),
    // -- 提交表单资源需求折叠区（追加表尾，哨兵编号顺延）--
    /// 折叠区 <summary> 标题（可选声明；默认收起）。
    TaskNewResSection => ("Resource requirements (optional)", "资源需求（可选）"),
    /// 折叠区帮助文案：放置契约语义（声明期望节点档位，过高会 pending）。
    TaskNewResHelp => (
        "Placement contract: declares the node tier this build expects — the scheduler only assigns it to workers satisfying these floors. Declare the peak under full parallelism; declaring higher than actual needs is allowed (deliberate routing) but may leave the build pending.",
        "放置契约：声明该构建期望的节点档位，调度器只把它派给满足下限的节点。建议按满并行时的峰值声明；故意声明高于实际需求可用于路由，但过高会让构建持续等待（pending）。",
    ),
    /// 最低内存输入行标（占位符示例 K/M/G/T 1024 基，纯数字 = KB）。
    TaskNewResMemLabel => ("Min memory (e.g. 4G)", "最低内存（如 4G）"),
    /// 最低 CPU 核数输入行标。
    TaskNewResNcpuLabel => ("Min CPU cores", "最低 CPU 核数"),
    /// 最低可用磁盘输入行标。
    TaskNewResDiskLabel => ("Min free disk (e.g. 20G)", "最低可用磁盘（如 20G）"),
    // -- 产品详情页资源画像卡（追加表尾）--
    /// 画像区标题（declared 契约 + learned 学习面）。
    SectionResourceProfiles => ("Resource requirements & profiles", "资源需求与画像"),
    /// 画像区空态（该产品尚无任何画像行）。
    ProfileNoData => ("No resource profiles yet", "暂无资源画像"),
    /// 架构列头（画像表；与过滤 chips 的 FilterArch 分 key，语义点位独立）。
    ThArch => ("Arch", "架构"),
    /// declared 放置契约列头（三维组合值，调用方按非 NULL 维拼装）。
    ThDeclared => ("Declared floor", "声明下限"),
    /// 学习面内存列头（人间单位 EMA / 最大值）。
    ThLearnedMem => ("Learned memory (EMA / max)", "学习内存（EMA / 最大）"),
    /// CPU p90 列头（核；@nC = 末次样本核数上下文）。
    ThCpuP90 => ("CPU p90 (cores @ sample node)", "CPU p90（核，采样节点）"),
    /// 样本数列头。
    ThSamples => ("Samples", "样本数"),
    /// 采样口径列头（chip 文本是机器值 cgroup / proc）。
    ThBackend => ("Backend", "口径"),
    /// 画像更新时间列头。
    ThUpdated => ("Last learned", "最近学习"),
    /// OOM 删失徽章文本与 title（有效权重取 max(ema, max) 直至成功解锁）。
    ProfileCensored => ("censored", "删失中"),
    ProfileCensoredTitle => (
        "OOM-censored: effective weight uses max(ema, max) until a succeeded build unlocks it",
        "OOM 删失中：有效权重取 max(ema, max)，直至一次成功构建解锁",
    ),
    // -- 派发归因徽章（pending 构建队列/详情，追加表尾）--
    /// 无匹配架构 worker。
    AttribNoFitArch => ("no worker for arch", "无匹配架构节点"),
    /// 架构匹配但容量全满。
    AttribNoFitCapacity => ("all workers at capacity", "节点容量全满"),
    /// 水位门扣留中。
    AttribWatermarkBlocked => ("held by watermark gate", "水位门扣留中"),
    /// init 门（worker 同产品活跃 init）。
    AttribInitGated => ("waiting for worker init", "等待节点 init"),
    /// 硬下限无人满足（title 带维度名）。
    AttribNoFitHardReq => ("placement floor unmet", "硬下限无人满足"),
    /// 后台闸（目前无写入方，枚举完备性占位）。
    AttribBackgroundGated => ("background gated", "后台闸扣留"),
    /// 归因徽章可见性说明（title 通用后缀：内存态诊断、重启清空）。
    AttribDiagnosticNote => (
        "diagnostic in-memory attribution; cleared on restart",
        "内存态诊断归因，重启清空",
    ),
    /// 画像区空态提示（画像随构建终态样本自动生成；声明走源码包页面）。
    ProfileNoDataHint => (
        "Profiles are learned from finished builds. Hub admins can declare floors on each package page.",
        "画像随构建完成自动学习；Hub 管理员可在各源码包页面声明下限。",
    ),
    // -- 资源卡 tmpfs 峰值行（追加表尾，哨兵编号顺延）--
    /// 构建自身 tmpfs 实例占用峰值行标（KB 人类化展示；build_tmpfs 关闭恒
    /// 不渲染该行）。
    ResTmpfsPeak => ("Tmpfs peak", "tmpfs 峰值"),
    // -- 产品页资源画像（源码包维度，追加表尾）--
    /// 画像区说明：画像键为源码包基础名，版本仅贡献历史样本；declared 为
    /// 放置硬约束，有效内存口径随删失切换。
    ProfileHelp => (
        "Profiles are keyed by source package name; versions only contribute history samples. \
         Declared floors are hard placement limits; effective memory uses the learned EMA \
         (max while OOM-censored).",
        "画像以源码包名为键，不同版本只贡献历史样本。声明下限是放置硬约束；\
         有效内存取学习 EMA（OOM 删失期取最大值）。",
    ),
    /// 源码包名筛选框占位。
    ProfileSourcePlaceholder => ("filter by source package", "按源码包筛选"),
    /// 画像状态过滤标签。
    ProfileFilterState => ("Profile state", "画像状态"),
    /// 状态过滤：存在 declared 下限。
    ProfileStateDeclared => ("declared", "已声明"),
    /// 状态过滤：已有学习样本。
    ProfileStateLearned => ("learned", "已学习"),
    /// 排序：有效内存降序（默认）。
    SortProfileMemDesc => ("Effective mem (high → low)", "有效内存（高 → 低）"),
    /// 排序：源码包名升序。
    SortProfileNameAsc => ("Name A → Z", "名称 A → Z"),
    /// 排序：源码包名降序。
    SortProfileNameDesc => ("Name Z → A", "名称 Z → A"),
    /// 排序：样本数降序。
    SortProfileSamplesDesc => ("Samples (high → low)", "样本数（多 → 少）"),
    /// 排序：最近学习时间降序。
    SortProfileUpdatedDesc => ("Recently learned", "最近学习"),
    /// 包级列表：该源码包最近一次构建。
    ThLatestBuild => ("Latest build", "最新构建"),
    /// 包级列表：该源码包已有画像的架构集合。
    ThArches => ("Arches", "架构"),
    /// 包级列表：各架构有效内存权重的最大值。
    ThEffectiveMem => ("Effective mem", "有效内存"),
    /// 源码包详情的 tmpfs 学习列头。
    ThTmpfsMem => ("Tmpfs (EMA / max)", "tmpfs（EMA / 最大）"),
    /// `arch=any` 回退画像的 title 说明。
    ProfileArchAnyTitle => (
        "fallback profile used when no arch-specific record exists",
        "无架构专用画像时的回退画像",
    ),
    /// 源码包详情页画像明细标题。
    ProfileDetailHeading => ("Per-arch profiles", "分架构画像"),
    /// 源码包详情页构建历史标题。
    ProfileHistoryTitle => ("Build history", "构建历史"),
    /// 构建历史说明（版本只作历史维度，成功样本参与学习）。
    ProfileHistoryHint => (
        "Recent builds of this source package across versions; succeeded samples feed the learned profile.",
        "该源码包跨版本的最近构建；成功样本参与学习画像。",
    ),
    /// 构建历史空态。
    ProfileHistoryEmpty => ("No builds found", "暂无构建记录"),
    /// 声明下限编辑折叠标题（仅 hub admin）。
    ProfileEditTitle => ("Edit declared floors", "编辑声明下限"),
    /// 声明下限编辑说明。
    ProfileEditHint => (
        "Blank = not declared. Floors are hard placement constraints for this arch.",
        "留空 = 未声明。下限是该架构的放置硬约束。",
    ),
    /// 声明下限清除按钮。
    ProfileEditClear => ("Clear", "清除"),
    /// 画像 CSV 导出链接。
    ProfileCsvExport => ("Export CSV", "导出 CSV"),
    /// 声明下限更新成功的 flash。
    FlashProfileFloorsUpdated => ("Declared floors updated", "声明下限已更新"),
    /// 画像列表的源码包列头/筛选标签（与二进制包区分）。
    ThSourcePackage => ("Source package", "源码包"),
    /// 为尚无画像行的架构新增声明下限的折叠标题。
    ProfileAddArchTitle => ("Add floors for another arch", "为其他架构新增声明下限"),
    /// 新架构声明说明（`any` 为兜底键；已有行原地更新）。
    ProfileAddArchHint => (
        "Creates a declared-only row when the arch has no profile yet; 'any' applies to all arches. Existing rows are updated in place.",
        "该架构尚无画像时新建仅声明的行；'any' 对所有架构生效，已有行原地更新。",
    ),
    /// 新架构声明表单的架构占位符。
    ProfileArchPlaceholder => ("e.g. x86_64 or any", "如 x86_64 或 any"),
    // -- 画像弹性/固定徽章（追加表尾）--
    /// 弹性徽章：饱和包，权重随目标节点核数折算（`cpu_p90 ≥ 0.5 × 采样核数`）。
    ProfileElastic => ("elastic", "弹性"),
    /// 弹性徽章 title（折算语义：仅小核节点下折，大核节点保持原值）。
    ProfileElasticTitle => (
        "elastic: weight scales down on nodes smaller than the sample node",
        "弹性：权重仅在小核节点按比例下折",
    ),
    /// 固定徽章：权重不折算（含 p90 / 采样核数缺任一的降级）。
    ProfileFixed => ("fixed", "固定"),
    /// 固定徽章 title。
    ProfileFixedTitle => (
        "fixed: weight is not scaled with node size",
        "固定：权重不随节点规模折算",
    ),
    // -- 画像弹性行单核内存单位（追加表尾）--
    /// 弹性内存行的单核值单位（`· 0.4G/核`，值由 EMA/采样核数现算）。
    ProfileMemPerCoreUnit => ("core", "核"),
    // -- 水位归因：学习 tmpfs 门阻塞（追加表尾）--
    /// 归因徽章 title：学习 tmpfs 门阻塞（无水位系数对照，容量 = mem_total/2）。
    AttribTmpfsGate => (
        "blocked by learned tmpfs gate (node capacity = mem_total/2)",
        "被学习 tmpfs 门阻塞（节点容量 = 内存总量/2）",
    ),
    // -- 任务标签 UI（详情徽章 / 列表过滤 / 提交表单，追加表尾）--
    /// 任务标签区标题，兼列表过滤字段名。
    LabelTaskLabels => ("Labels", "标签"),
    /// 标签输入的键值格式占位符。
    PlaceholderTaskLabel => ("key=value", "键=值"),
    /// 提交表单标签区说明。
    TaskNewLabelsHelp => (
        "Optional key=value metadata, e.g. ci=1234 or branch=main.",
        "可选的任务元数据，格式 key=value，如 ci=1234 或 branch=main。",
    ),
    /// 提交表单新增一行标签输入。
    TaskNewAddLabel => ("Add label", "添加标签"),
    /// 移除一行标签输入的按钮 aria-label / title。
    TaskNewRemoveLabel => ("Remove label", "移除标签"),
}
