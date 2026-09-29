// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! Web UI 双语文案表：零依赖、编译期安全。穷尽 match 文案表两类：
//! [`TextKey`]（无参，[`t`] 返回 `&'static str`）与 [`FmtKey`]（带参，[`t_fmt`]
//! 完整句插值），漏译 = 编译错误；动态值映射 [`t_phase`] / [`phase_option_label`]
//! / [`status_reason_localized`]。handler 经 [`lang_from_headers`] 取语言直传
//! 渲染（`?lang=` 覆盖头 > `crbs_lang` cookie > `Accept-Language` zh* > En）；
//! 语言选择 UX 见 [`set_lang`]（cookie + 303 回跳）与 [`lang_query_middleware`]
//!（`?lang=` 写 cookie + 覆盖本次渲染）。不翻译机器面：API JSON、日志、审计 detail、表单 name/value。

use crate::server::error::ApiError;
use crate::server::routes::ui::pages::cookie_secure_suffix;
use crate::server::state::AppState;
use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

mod fmt;
mod labels;
mod text;

pub(crate) use fmt::{
    donut_row_title_pattern, matrix_summary_pattern, rel_time_patterns, t_fmt, FmtKey,
};
pub(crate) use labels::{
    phase_option_label, priority_label, role_label, status_reason_localized, t_phase,
    user_status_label, visibility_label, worker_status_label,
};
pub(crate) use text::{t, TextKey};

/// 语言偏好 cookie 名。
pub(crate) const LANG_COOKIE: &str = "crbs_lang";

/// `?lang=` 覆盖的内部传递头（[`lang_query_middleware`] 注入）。不用 request
/// extensions：page() 骨架只拿得到 `&HeaderMap`，chrome 与 handler 共用
/// [`lang_from_headers`] 才不漂移；信任级同 cookie，非法注入值忽略、落回常规链路。
const LANG_OVERRIDE_HEADER: &str = "x-crbs-lang";

/// 语言 cookie 固定有效期：一年（长寿命显示偏好，非凭证）。
const LANG_COOKIE_MAX_AGE_SECS: i64 = 31_536_000;

/// Set-Cookie 头里 crbs_lang 值的前缀（双 Set-Cookie 收敛判定用）。
const LANG_COOKIE_SET_PREFIX: &str = "crbs_lang=";

/// UI 语言两态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Zh,
}

impl Lang {
    /// cookie / 内部头白名单：仅接受 "en"/"zh"，其余（缺失、非法、大小写）静默回落 En。
    pub(crate) fn from_value(v: Option<&str>) -> Lang {
        match v {
            Some("zh") => Lang::Zh,
            _ => Lang::En,
        }
    }

    /// `<html lang>` 属性值（zh 用中文区域子标签，读屏与字体选择据此工作）。
    pub(crate) fn html_lang(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh-CN",
        }
    }

    /// 写入 `crbs_lang` cookie 的值（同时是 `?lang=` 与内部头的合法值域）。
    pub(crate) fn cookie_value(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Zh => "zh",
        }
    }
}

/// 语言协商：内部覆盖头 > cookie > Accept-Language（zh* 前缀）> En。
pub(crate) fn lang_from_headers(headers: &HeaderMap) -> Lang {
    // 1) middleware 注入的 ?lang= 覆盖：仅合法值到达这里，伪造非法值走常规链路。
    if let Some(v) = headers
        .get(LANG_OVERRIDE_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        match v {
            "en" => return Lang::En,
            "zh" => return Lang::Zh,
            _ => {}
        }
    }
    // 2) crbs_lang cookie：值在即生效，非法按 En 回落、不下探 Accept-Language。
    if let Some(value) = crate::server::csrf::cookie_value_from_headers(headers, LANG_COOKIE) {
        return Lang::from_value(Some(value.as_str()));
    }
    // 3) Accept-Language：取首个语言标签（q 值忽略），zh* 前缀 → Zh。
    if let Some(al) = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
    {
        let first = al
            .split(',')
            .next()
            .and_then(|tag| tag.split(';').next())
            .unwrap_or("")
            .trim();
        if first.len() >= 2 && first[..2].eq_ignore_ascii_case("zh") {
            return Lang::Zh;
        }
    }
    Lang::En
}

// ===== 语言选择 UX（theme.rs 全套模式的 lang 变体）=====

#[derive(serde::Deserialize)]
pub(crate) struct SetLangForm {
    lang: Option<String>,
    csrf_token: Option<String>,
}

/// `POST /ui/set-lang`（表单 `lang=en|zh`）：Set-Cookie + 303 回跳（越界回退
/// en）。公开段（login 页也能切语言）、分级 CSRF、Referer 仅采纳 /ui/ 站内路径。
pub(crate) async fn set_lang(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<SetLangForm>,
) -> Result<impl IntoResponse, ApiError> {
    crate::server::routes::ui::pages::theme::require_preference_csrf(
        &headers,
        form.csrf_token.as_deref(),
        &app.csrf_key,
    )?;
    let lang = Lang::from_value(form.lang.as_deref());
    crate::server::routes::ui::pages::theme::preference_see_other(
        &app,
        headers.get(header::REFERER),
        Some((LANG_COOKIE, lang.cookie_value())),
        // 303 体按刚选中的目标语言：回跳落地的下一页即该语言。
        lang,
    )
}

/// `?lang=` 仅精确 "en"/"zh" 返回 Some；非法不覆盖、不写 cookie（防把 zh cookie 用户翻成英文）。
fn lang_query_value(uri: &Uri) -> Option<Lang> {
    let query = uri.query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "lang" {
                return match v {
                    "en" => Some(Lang::En),
                    "zh" => Some(Lang::Zh),
                    _ => None,
                };
            }
        }
    }
    None
}

/// `?lang=` 分享链接语义：合法 lang 时注入内部头
/// [`LANG_OVERRIDE_HEADER`]（本次渲染即用该语言）+ Set-Cookie 持久化偏好，
/// POST 携带无妨。无合法参数时剥除外部伪造的同名头——内部头只许本
/// middleware 写入，否则客户端可控输入会覆盖 crbs_lang cookie 偏好。
pub(crate) async fn lang_query_middleware(
    State(app): State<Arc<AppState>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let Some(lang) = lang_query_value(request.uri()) else {
        request.headers_mut().remove(LANG_OVERRIDE_HEADER);
        return next.run(request).await;
    };
    request.headers_mut().insert(
        LANG_OVERRIDE_HEADER,
        axum::http::HeaderValue::from_static(lang.cookie_value()),
    );
    let mut response = next.run(request).await;
    // 双 Set-Cookie 收敛：`/ui/set-lang?lang=xx` 的 handler 已自带 crbs_lang
    // Set-Cookie（303 回跳），响应已含 crbs_lang= 时不追加同名 cookie。
    let already_set = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| {
            v.to_str()
                .is_ok_and(|c| c.starts_with(LANG_COOKIE_SET_PREFIX))
        });
    if already_set {
        return response;
    }
    let cookie = format!(
        "{LANG_COOKIE}={}; Path=/; Max-Age={LANG_COOKIE_MAX_AGE_SECS}; SameSite=Lax; HttpOnly{}",
        lang.cookie_value(),
        cookie_secure_suffix(&app),
    );
    if let Ok(value) = cookie.parse() {
        // append 保住其它 Set-Cookie（登录会话等）不被折叠。
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 两语言同文的 key（"ID"/"CPU" 中文 UI 通行、"NVR" 术语不译），豁免不等性断言。
    const LANG_INVARIANT_KEYS: &[TextKey] = &[
        TextKey::ThId,
        TextKey::ThCpu,
        TextKey::WorkerCpuLoad,
        TextKey::ThNvr,
        TextKey::ResOomBadge,
    ];

    fn headers_with(kv: &[(axum::http::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in kv {
            h.insert(name.clone(), value.parse().unwrap());
        }
        h
    }

    #[test]
    fn all_text_keys_nonempty_and_translated() {
        for key in TextKey::ALL {
            let en = t(Lang::En, *key);
            let zh = t(Lang::Zh, *key);
            assert!(!en.is_empty(), "{key:?}: en empty");
            assert!(!zh.is_empty(), "{key:?}: zh empty");
            if !LANG_INVARIANT_KEYS.contains(key) {
                assert_ne!(en, zh, "{key:?}: zh looks like an untranslated placeholder");
            }
        }
    }

    /// 穷尽性哨兵（防 `ALL` 与枚举漂移）：对 [`TextKey`] 每个变体一臂、**无通配臂**，
    /// 臂值 0..N 连续唯一（序不与表声明序绑定）；新增变体本 match 编译失败强制补臂，补臂须同时登记 `ALL`。
    fn text_key_exhaustiveness_helper(key: &TextKey) -> usize {
        match key {
            TextKey::NavDashboard => 0,
            TextKey::NavBuilds => 1,
            TextKey::NavTasks => 2,
            TextKey::NavProducts => 3,
            TextKey::NavPackages => 4,
            TextKey::NavWorkers => 5,
            TextKey::NavGc => 6,
            TextKey::NavAdmin => 7,
            TextKey::NavLogin => 8,
            TextKey::NavLogout => 9,
            TextKey::NavThemeAuto => 10,
            TextKey::NavThemeLight => 11,
            TextKey::NavThemeDark => 12,
            TextKey::FooterApiHealth => 13,
            TextKey::LiveUpdatesEnabled => 14,
            TextKey::ConnectionLost => 15,
            TextKey::VizAriaSummary => 16,
            TextKey::PanelTaskStates => 17,
            TextKey::HintHoverClick => 18,
            TextKey::DonutAriaLabel => 19,
            TextKey::DonutSubTasks => 20,
            TextKey::DonutRunning => 21,
            TextKey::DonutQueued => 22,
            TextKey::LegendRunning => 23,
            TextKey::LegendQueued => 24,
            TextKey::LegendSucceeded => 25,
            TextKey::LegendFailed => 26,
            TextKey::LegendTimeout => 27,
            TextKey::LegendCancelled => 28,
            TextKey::PanelSuccessRate => 29,
            TextKey::GaugeSubSuccess => 30,
            TextKey::GaugeAriaNoData => 31,
            TextKey::PanelBuildDurations => 32,
            TextKey::DurationNoData => 33,
            TextKey::WorkersOnlineWord => 34,
            TextKey::NoWorkersRegistered => 35,
            TextKey::WorkersBarNote => 36,
            TextKey::ViewWorkers => 37,
            TextKey::SectionRecentTasks => 38,
            TextKey::ViewAllTasks => 39,
            TextKey::EmptyRecentTitle => 40,
            TextKey::EmptyRecentHint => 41,
            TextKey::SysStripAria => 42,
            TextKey::StatUptime => 43,
            TextKey::StatQueue => 44,
            TextKey::StatConcurrency => 45,
            TextKey::StatDiskAvailable => 46,
            TextKey::QueueNoPending => 47,
            TextKey::PriorityNormal => 48,
            TextKey::PriorityHigh => 49,
            TextKey::PriorityCritical => 50,
            TextKey::ThId => 51,
            TextKey::ThProduct => 52,
            TextKey::ThPackage => 53,
            TextKey::ThPhase => 54,
            TextKey::ThUser => 55,
            TextKey::ThSubmitted => 56,
            TextKey::Err404Message => 57,
            TextKey::Err405Message => 58,
            TextKey::ErrRequestFailed => 59,
            TextKey::ErrLoginCta => 60,
            TextKey::ErrBackToDashboard => 61,
            TextKey::FilterArch => 62,
            TextKey::FilterPriority => 63,
            TextKey::FilterSort => 64,
            TextKey::FilterAll => 65,
            TextKey::PaginationPrev => 66,
            TextKey::PaginationNext => 67,
            TextKey::PlaceholderProduct => 68,
            TextKey::PlaceholderPackage => 69,
            TextKey::PlaceholderArch => 70,
            TextKey::SortNewestId => 71,
            TextKey::SortOldestId => 72,
            TextKey::SortStartedTime => 73,
            TextKey::SortSubmittedTime => 74,
            TextKey::FilterApply => 75,
            TextKey::FilterReset => 76,
            TextKey::FilterRemove => 77,
            TextKey::EmptyTasksTitle => 78,
            TextKey::EmptyTasksHint => 79,
            TextKey::SecretWarning => 80,
            TextKey::CopyButton => 81,
            TextKey::CopyCopied => 82,
            TextKey::CopyFailedManual => 83,
            TextKey::HintBuildFinished => 84,
            TextKey::HintTaskFinished => 85,
            TextKey::RefreshNow => 86,
            TextKey::HintLogComplete => 87,
            TextKey::ViewBuildPage => 88,
            TextKey::NotifyMe => 89,
            TextKey::NotifyEnabled => 90,
            TextKey::NotifyDeniedHint => 91,
            TextKey::NotifyTitleBuild => 92,
            TextKey::NotifyTitleTask => 93,
            TextKey::PageSizeTitle => 94,
            TextKey::LoginTitle => 95,
            TextKey::LoginSubtitle => 96,
            TextKey::LoginModePassword => 97,
            TextKey::LoginModeToken => 98,
            TextKey::LoginUsernameLabel => 99,
            TextKey::LoginUsernameHint => 100,
            TextKey::LoginPasswordLabel => 101,
            TextKey::LoginTokenLabel => 102,
            TextKey::LoginTokenHint => 103,
            TextKey::LoginSubmitButton => 104,
            TextKey::LoginInvalidCredentials => 105,
            TextKey::LoginInvalidToken => 106,
            TextKey::LoginNoTokenHint => 107,
            TextKey::LoginNoAccount => 108,
            TextKey::LoginRegisterLink => 109,
            TextKey::LoginRegisterAdminNote => 110,
            TextKey::LoginRateLimitHint => 111,
            TextKey::AuthDisabledNote => 112,
            TextKey::RegisterTitle => 113,
            TextKey::RegisterSubtitle => 114,
            TextKey::RegisterUsernameHint => 115,
            TextKey::RegisterConfirmLabel => 116,
            TextKey::RegisterPasswordHint => 117,
            TextKey::RegisterSubmitButton => 118,
            TextKey::RegisterClosedMessage => 119,
            TextKey::RegisterBackToLogin => 120,
            TextKey::RegisterHasAccount => 121,
            TextKey::RegisterGoLogin => 122,
            TextKey::RegisterUsernameTaken => 123,
            TextKey::RegisterPasswordMismatch => 124,
            TextKey::RegisterInvalidUsername => 125,
            TextKey::RegisterStrengthLabel => 126,
            TextKey::RegisterStrengthTitle => 127,
            TextKey::SettingsTitle => 128,
            TextKey::SettingsRegistrationCardTitle => 129,
            TextKey::SettingsRegistrationCardDesc => 130,
            TextKey::SettingsRegistrationToggleLabel => 131,
            TextKey::SettingsRegistrationStateOpen => 132,
            TextKey::SettingsRegistrationStateClosed => 133,
            TextKey::SettingsSaveButton => 134,
            TextKey::SettingsSavedMessage => 135,
            TextKey::SettingsSessionExpired => 136,
            TextKey::MePageTitle => 137,
            TextKey::MeNoAccountTitle => 138,
            TextKey::MeNoAccountHint => 139,
            TextKey::MeMustChangeBanner => 140,
            TextKey::MeMustChangeFlash => 141,
            TextKey::MeCredModeSession => 142,
            TextKey::MeCredModeToken => 143,
            TextKey::MeStatMyTasks => 144,
            TextKey::MeStatBuilding => 145,
            TextKey::MeStatQueued => 146,
            TextKey::MeStatTokens => 147,
            TextKey::MeStatOwnedProducts => 148,
            TextKey::MeCardSecurity => 149,
            TextKey::MePasswordChangeTitle => 150,
            TextKey::MePasswordSetTitle => 151,
            TextKey::MePasswordCurrent => 152,
            TextKey::MePasswordNew => 153,
            TextKey::MePasswordConfirm => 154,
            TextKey::MePasswordChangeHint => 155,
            TextKey::MePasswordSetHint => 156,
            TextKey::MePasswordChangeSubmit => 157,
            TextKey::MePasswordSetSubmit => 158,
            TextKey::MePasswordCurrentIncorrect => 159,
            TextKey::MeCardSessions => 160,
            TextKey::MeSessionsDevice => 161,
            TextKey::MeSessionsSignedIn => 162,
            TextKey::MeSessionsExpires => 163,
            TextKey::MeSessionCurrent => 164,
            TextKey::MeSessionLogoutCurrent => 165,
            TextKey::MeSessionRevoke => 166,
            TextKey::MeSessionRevokeConfirm => 167,
            TextKey::MeTokenDelete => 168,
            TextKey::MeSessionsSignOutAll => 169,
            TextKey::MeSessionsSignOutAllConfirm => 170,
            TextKey::MeSessionsTokenModeNote => 171,
            TextKey::MeSessionsUnknownDevice => 172,
            TextKey::MeCardTokens => 173,
            TextKey::MeTokenName => 174,
            TextKey::MeTokenExpiresIn => 175,
            TextKey::MeTokenNamePlaceholder => 176,
            TextKey::MeTokenNameEmpty => 177,
            TextKey::MeTokenNameInUse => 178,
            TextKey::AdminResetTokenNote => 179,
            TextKey::MeTokenCreate => 180,
            TextKey::MeTokenNever => 181,
            TextKey::MeTokenRevokeConfirm => 182,
            TextKey::MeTokenEmptyTitle => 183,
            TextKey::MeTokenEmptyHint => 184,
            TextKey::MeTokenCreatedTitle => 185,
            TextKey::MeTokenCreatedBack => 186,
            TextKey::MeCardProducts => 187,
            TextKey::MeProductRelation => 188,
            TextKey::MeRelationOwner => 189,
            TextKey::MeViaAcl => 190,
            TextKey::MeRevision => 191,
            TextKey::MeProductsEmptyTitle => 192,
            TextKey::MeProductsEmptyHint => 193,
            TextKey::MeAllProducts => 194,
            TextKey::ProductStatTasks => 195,
            TextKey::ProductStatLastBuild => 196,
            TextKey::ProductStatPackages => 197,
            TextKey::AdminResetCardTitle => 198,
            TextKey::AdminResetCardDesc => 199,
            TextKey::AdminResetButton => 200,
            TextKey::AdminResetDoneTitle => 201,
            TextKey::AdminResetMustChangeNote => 202,
            TextKey::AdminResetBackToUser => 203,
            TextKey::FlashCancelled => 204,
            TextKey::FlashRebuilt => 205,
            TextKey::FlashReproduced => 206,
            TextKey::FlashUserCreated => 207,
            TextKey::FlashRoleUpdated => 208,
            TextKey::FlashUserStatusUpdated => 209,
            TextKey::FlashTokenRevoked => 210,
            TextKey::FlashPasswordChanged => 211,
            TextKey::FlashSessionsRevoked => 212,
            TextKey::FlashAclGranted => 213,
            TextKey::FlashAclRevoked => 214,
            TextKey::FlashSecretRevoked => 215,
            TextKey::FlashWorkerRemoved => 216,
            TextKey::FlashInitDispatched => 217,
            TextKey::FlashProductCreated => 218,
            TextKey::FlashProductUpdated => 219,
            TextKey::FlashVisibilityUpdated => 220,
            TextKey::FlashOwnershipTransferred => 221,
            TextKey::FlashRepoRebuilt => 222,
            TextKey::FlashGcStarted => 223,
            TextKey::FlashStorageError => 224,
            TextKey::FlashInternalError => 225,
            TextKey::FlashOperationFailed => 226,
            TextKey::Yes => 227,
            TextKey::No => 228,
            TextKey::ThName => 229,
            TextKey::ThStatus => 230,
            TextKey::ThStarted => 231,
            TextKey::ThCreated => 232,
            TextKey::ThExpires => 233,
            TextKey::ThRevoked => 234,
            TextKey::ThAction => 235,
            TextKey::ThRole => 236,
            TextKey::ThGranted => 237,
            TextKey::ThOwner => 238,
            TextKey::ThParent => 239,
            TextKey::ThVisibility => 240,
            TextKey::VisPublic => 241,
            TextKey::VisPrivate => 242,
            TextKey::LabelTask => 243,
            TextKey::LabelBackend => 244,
            TextKey::LabelDuration => 245,
            TextKey::LabelCompleted => 246,
            TextKey::LabelNetwork => 247,
            TextKey::LabelBuildTmpfs => 248,
            TextKey::LabelSharedLayer => 249,
            TextKey::LabelMemoryMax => 250,
            TextKey::LabelCpuQuota => 251,
            TextKey::LabelResultDir => 252,
            TextKey::LabelCrbsRoot => 253,
            TextKey::ThBuildTarget => 254,
            TextKey::ThValue => 255,
            TextKey::ThBaseUrl => 256,
            TextKey::ThEnabled => 257,
            TextKey::ThGpgCheck => 258,
            TextKey::ThCost => 259,
            TextKey::ThTime => 260,
            TextKey::ThTarget => 261,
            TextKey::ThDetail => 262,
            TextKey::ThSince => 263,
            TextKey::ThUntil => 264,
            TextKey::ThChangedAt => 265,
            TextKey::ThChangedBy => 266,
            TextKey::ThReason => 267,
            TextKey::ThFile => 268,
            TextKey::ThKind => 269,
            TextKey::ThSize => 270,
            TextKey::ThSigned => 271,
            TextKey::ArtifactsTitle => 272,
            TextKey::ButtonCancel => 273,
            TextKey::ButtonRebuild => 274,
            TextKey::ButtonReproduce => 275,
            TextKey::ButtonRevoke => 276,
            TextKey::ButtonCreate => 277,
            TextKey::ButtonUpdate => 278,
            TextKey::ButtonGrant => 279,
            TextKey::ButtonCheck => 280,
            TextKey::ButtonDisable => 281,
            TextKey::ButtonEnable => 282,
            TextKey::ButtonRotateSecret => 283,
            TextKey::ButtonRevokeSecret => 284,
            TextKey::ButtonInitBaseOs => 285,
            TextKey::ButtonRemoveWorker => 286,
            TextKey::WorkerOnline => 287,
            TextKey::WorkerOffline => 288,
            TextKey::WorkerStale => 289,
            TextKey::UserActive => 290,
            TextKey::UserDisabled => 291,
            TextKey::PhaseSkipped => 292,
            TextKey::PhaseTimelineTitle => 293,
            TextKey::NotRun => 294,
            TextKey::DownloadSrpm => 295,
            TextKey::LabelBaseOs => 296,
            TextKey::EmptyBuildsTitle => 297,
            TextKey::EmptyBuildsHint => 298,
            TextKey::ViewLogs => 299,
            TextKey::BuildNotesTitle => 300,
            TextKey::BackToBuilds => 301,
            TextKey::BackToBuild => 302,
            TextKey::EmptyArtifactsTitle => 303,
            TextKey::EmptyArtifactsHint => 304,
            TextKey::ConfirmCancelBuild => 305,
            TextKey::DownloadFullLog => 306,
            TextKey::NoLogs => 307,
            TextKey::LiveLogStream => 308,
            TextKey::FollowLabel => 309,
            TextKey::JumpToBottom => 310,
            TextKey::Download => 311,
            TextKey::LogNotStarted => 312,
            TextKey::ConfirmCancelTask => 313,
            TextKey::ConfirmRebuildTask => 314,
            TextKey::ConfirmReproduceTask => 315,
            TextKey::BackToTasks => 316,
            TextKey::LabelPackages => 317,
            TextKey::ChildBuilds => 318,
            TextKey::EmptyChildBuildsTitle => 319,
            TextKey::EmptyChildBuildsHint => 320,
            TextKey::TitleDuration => 321,
            TextKey::EmptyPackagesTitle => 322,
            TextKey::EmptyPackagesHint => 323,
            TextKey::ThLatestPhase => 324,
            TextKey::ThAttempts => 325,
            TextKey::ThLastBuild => 326,
            TextKey::ThTasks => 327,
            TextKey::AllVersions => 328,
            TextKey::EmptyAttemptsTitle => 329,
            TextKey::EmptyAttemptsHint => 330,
            TextKey::BackToPackages => 331,
            TextKey::Versions => 332,
            TextKey::EmptyVersionsTitle => 333,
            TextKey::EmptyVersionsHint => 334,
            TextKey::ThLatest => 335,
            TextKey::EmptyWorkersTitle => 336,
            TextKey::EmptyWorkersHint => 337,
            TextKey::ThCapacity => 338,
            TextKey::ThLoad => 339,
            TextKey::ThLastHeartbeat => 340,
            TextKey::ThVersion => 341,
            TextKey::LabelHasSecret => 342,
            TextKey::BackToWorkers => 343,
            TextKey::ActiveBuilds => 344,
            TextKey::EmptyActiveBuildsTitle => 345,
            TextKey::EmptyActiveBuildsHint => 346,
            TextKey::ConfirmInitBaseOs => 347,
            TextKey::WorkerSecretRotated => 348,
            TextKey::BackToWorker => 349,
            TextKey::AdminWorkerSecretTitle => 350,
            TextKey::ThCpu => 351,
            TextKey::ThMemory => 352,
            TextKey::WorkerCpuLoad => 353,
            TextKey::WorkerTelemetryTime => 354,
            TextKey::TelemetryStaleNote => 355,
            TextKey::ArchCpuAvgTitle => 356,
            TextKey::NewProduct => 357,
            TextKey::EmptyProductsTitle => 358,
            TextKey::EmptyProductsHint => 359,
            TextKey::EmptyProductsMatchTitle => 360,
            TextKey::EmptyProductsMatchHint => 361,
            TextKey::EditConfig => 362,
            TextKey::BackToProducts => 363,
            TextKey::BackToProduct => 364,
            TextKey::HistoryLabel => 365,
            TextKey::RootProductPlaceholder => 366,
            TextKey::SectionBasePackages => 367,
            TextKey::EmptyBasePackagesTitle => 368,
            TextKey::EmptyBasePackagesHint => 369,
            TextKey::SectionRepos => 370,
            TextKey::NoRepos => 371,
            TextKey::SectionRpmMacros => 372,
            TextKey::NoMacros => 373,
            TextKey::SectionHooks => 374,
            TextKey::NoHooks => 375,
            TextKey::ProductPublicNote => 376,
            TextKey::ProductPrivateNote => 377,
            TextKey::MakePrivate => 378,
            TextKey::ConfirmMakePrivate => 379,
            TextKey::MakePublic => 380,
            TextKey::ConfirmMakePublic => 381,
            TextKey::SectionAcl => 382,
            TextKey::PlaceholderUsername => 383,
            TextKey::GrantAccess => 384,
            TextKey::NoAclEntries => 385,
            TextKey::SectionOwnership => 386,
            TextKey::OfficialProductNote => 387,
            TextKey::NewOwnerUsername => 388,
            TextKey::TransferOwnership => 389,
            TextKey::ConfirmTransferOfficial => 390,
            TextKey::ConfirmTransferOwnership => 391,
            TextKey::MaintenanceDesc => 392,
            TextKey::RebuildRepo => 393,
            TextKey::ConfirmRebuildRepo => 394,
            TextKey::SectionEffectiveToml => 395,
            TextKey::EffectiveTomlDesc => 396,
            TextKey::NoHistoryEntries => 397,
            TextKey::ThDiffFrom => 398,
            TextKey::ThDiffTo => 399,
            TextKey::CompareRevisions => 400,
            TextKey::BackToProductHistory => 401,
            TextKey::DiffNoChangesTitle => 402,
            TextKey::DiffNoChangesHint => 403,
            TextKey::NewProductPageTitle => 404,
            TextKey::LabelProductNameSlug => 405,
            TextKey::LabelDisplayNameOptional => 406,
            TextKey::PlaceholderDisplayName => 407,
            TextKey::LabelParentOptional => 408,
            TextKey::PlaceholderEmptyRoot => 409,
            TextKey::LabelOwnerOptional => 410,
            TextKey::PlaceholderEmptyOfficial => 411,
            TextKey::PrivateNeedsOwner => 412,
            TextKey::BuilderVisibilityNote => 413,
            TextKey::LabelConfigToml => 414,
            TextKey::LabelChangeReason => 415,
            TextKey::PlaceholderDescribeChange => 416,
            TextKey::EditLastChanged => 417,
            TextKey::YouAreOwner => 418,
            TextKey::ConfigValid => 419,
            TextKey::MergedPreview => 420,
            TextKey::AdminUsersTitle => 421,
            TextKey::AdminCardUsersDesc => 422,
            TextKey::AuditLogsTitle => 423,
            TextKey::AdminCardAuditDesc => 424,
            TextKey::AdminCardWorkersDesc => 425,
            TextKey::AdminCardGcTitle => 426,
            TextKey::AdminCardGcDesc => 427,
            TextKey::AdminCardSettingsDesc => 428,
            TextKey::CreateUser => 429,
            TextKey::EmptyUsersTitle => 430,
            TextKey::EmptyUsersHint => 431,
            TextKey::BackToUsers => 432,
            TextKey::ConfirmDisableUser => 433,
            TextKey::SectionTokens => 434,
            TextKey::LabelNameOptional => 435,
            TextKey::LabelExpiresDays => 436,
            TextKey::EmptyTokensTitle => 437,
            TextKey::EmptyTokensHint => 438,
            TextKey::AdminTokenCreatedTitle => 439,
            TextKey::AdminUsersPageTitle => 440,
            TextKey::AdminAuditPageTitle => 441,
            TextKey::SectionProductAcl => 442,
            TextKey::EmptyAclNoProductsHint => 443,
            TextKey::EmptyUserAclsTitle => 444,
            TextKey::EmptyUserAclsHint => 445,
            TextKey::EmptyAuditTitle => 446,
            TextKey::EmptyAuditHint => 447,
            TextKey::GcPageTitle => 448,
            TextKey::AdminGcPageTitle => 449,
            TextKey::GcTrigger => 450,
            TextKey::GcDestructiveWarning => 451,
            TextKey::GcDryRun => 452,
            TextKey::GcDryRunDesc => 453,
            TextKey::GcOptResults => 454,
            TextKey::GcOptResultsDesc => 455,
            TextKey::GcOptMounts => 456,
            TextKey::GcOptMountsDesc => 457,
            TextKey::GcOptCache => 458,
            TextKey::GcOptCacheDesc => 459,
            TextKey::GcOptPolicy => 460,
            TextKey::GcOptPolicyDesc => 461,
            TextKey::GcOptAll => 462,
            TextKey::GcOptAllDesc => 463,
            TextKey::GcProductPlaceholder => 464,
            TextKey::GcRun => 465,
            TextKey::GcRunHint => 466,
            TextKey::GcRunConfirm => 467,
            TextKey::GcRecentTasks => 468,
            TextKey::GcHistoryNote => 469,
            TextKey::EmptyGcTitle => 470,
            TextKey::EmptyGcHint => 471,
            TextKey::ThDetails => 472,
            TextKey::GcHelpTitle => 473,
            TextKey::GcHelpP1 => 474,
            TextKey::GcHelpWith => 475,
            TextKey::GcHelpCheckedTail => 476,
            TextKey::GcChipError => 477,
            TextKey::GcChipResults => 478,
            TextKey::GcChipPolicy => 479,
            TextKey::GcChipMounts => 480,
            TextKey::GcChipCache => 481,
            TextKey::GcChipLayers => 482,
            TextKey::GcChipDryRun => 483,
            TextKey::GcChipWouldFree => 484,
            TextKey::GcChipFreed => 485,
            TextKey::GcMountsTitle => 486,
            TextKey::GcNothingToDo => 487,
            TextKey::TaskNewTitle => 488,
            TextKey::TaskNewAction => 489,
            TextKey::LabelSrpmFiles => 490,
            TextKey::TaskNewDropHint => 491,
            TextKey::LabelArches => 492,
            TextKey::TaskNewArchNoscript => 493,
            TextKey::TaskNewArchDefaultNote => 494,
            TextKey::TaskNewNoProductsTitle => 495,
            TextKey::TaskNewNoProductsHint => 496,
            TextKey::TaskNewUploadProgress => 497,
            TextKey::UploadFailed => 498,
            TextKey::LabelRepo => 640,
            TextKey::ButtonSubmit => 499,
            TextKey::FlashSubmitted => 500,
            TextKey::SearchPlaceholder => 501,
            TextKey::SearchPageTitle => 502,
            TextKey::SearchDirectTitle => 503,
            TextKey::SearchEmptyTitle => 504,
            TextKey::SearchEmptyHint => 505,
            TextKey::SearchEmptyQueryHint => 506,
            TextKey::SideDetailsTitle => 507,
            TextKey::DangerZoneTitle => 508,
            TextKey::ParentTaskTitle => 509,
            TextKey::DangerCancelBuildDesc => 510,
            TextKey::DangerCancelTaskDesc => 511,
            TextKey::DangerMakePrivateDesc => 512,
            TextKey::DangerMakePublicDesc => 513,
            TextKey::DangerTransferDesc => 514,
            TextKey::DangerDisableUserDesc => 515,
            TextKey::ChangelogPageTitle => 516,
            TextKey::ChangelogLink => 517,
            TextKey::ChangelogEmptyTitle => 518,
            TextKey::ChangelogEmptyHint => 519,
            TextKey::ChangelogOlder => 520,
            TextKey::ChangelogNewer => 521,
            // 错误 flash 批次：变体声明位于 FlashOperationFailed 之后，编号按登记序续排。
            TextKey::FlashOfficialProductPrivate => 522,
            TextKey::FlashUnpublishPublicDescendants => 523,
            TextKey::FlashTransferOfficialPublicDescendants => 524,
            TextKey::FlashTransferToCurrentOwner => 525,
            TextKey::FlashOwnerFullAccess => 526,
            TextKey::FlashUserNameEmpty => 527,
            TextKey::FlashUserNameWhitespace => 528,
            TextKey::FlashLastAdminGuard => 529,
            TextKey::FlashInvalidUserStatus => 530,
            TextKey::FlashProductNameEmpty => 531,
            TextKey::FlashInitProductRequired => 532,
            TextKey::FlashGcDryRunScope => 533,
            TextKey::FlashGcProductScope => 534,
            TextKey::FlashGcAllScope => 535,
            TextKey::FlashGcAlreadyRunning => 536,
            // 错误 flash 第二批：声明位于 FlashGcAlreadyRunning 之后，编号按登记序续排。
            TextKey::FlashCancelNoCancellable => 537,
            TextKey::FlashCancelTaskPermission => 538,
            TextKey::FlashCancelTaskTerminal => 539,
            TextKey::FlashCancelTaskStateChanged => 540,
            TextKey::FlashCancelGetChildrenFailed => 541,
            TextKey::FlashCancelEmptyTaskFailed => 542,
            TextKey::FlashCancelBuildPermission => 543,
            TextKey::FlashBuildAlreadyCancelled => 544,
            TextKey::FlashBuildCancelTerminal => 545,
            TextKey::FlashBuildCancelNonActive => 546,
            TextKey::FlashBuildCancelFailed => 547,
            TextKey::FlashRebuildPermission => 548,
            TextKey::FlashReproducePermission => 549,
            TextKey::FlashReplaySourceGcRebuild => 550,
            TextKey::FlashReplaySourceGcReproduce => 551,
            TextKey::FlashReplayNoOptionsRebuild => 552,
            TextKey::FlashReplayNoOptionsReproduce => 553,
            TextKey::FlashReplayNoReproducibleChildren => 554,
            TextKey::FlashReplayPriorityRange => 555,
            TextKey::FlashReplayPriorityOperatorOnly => 556,
            TextKey::FlashPrivateNeedsOwnerPick => 557,
            TextKey::FlashPublicAttachPrivateParent => 558,
            TextKey::Redirecting => 559,
            TextKey::NavRepro => 560,
            TextKey::SectionReproSummary => 561,
            TextKey::SectionReproByProduct => 562,
            TextKey::SectionReproReplays => 563,
            TextKey::ReproRateLabel => 564,
            TextKey::ReproDenominatorNote => 565,
            TextKey::ReproWindowAll => 566,
            TextKey::ThSourceBuild => 567,
            TextKey::ThReplayBuild => 568,
            TextKey::ThRate => 569,
            TextKey::ThTotal => 570,
            TextKey::ThSame => 571,
            TextKey::ThDiff => 572,
            TextKey::ThBuildFailed => 573,
            TextKey::ThOther => 574,
            TextKey::EmptyReproTitle => 575,
            TextKey::EmptyReproHint => 576,
            TextKey::RoleAdmin => 577,
            TextKey::RoleOperator => 578,
            TextKey::RoleBuilder => 579,
            TextKey::RoleViewer => 580,
            TextKey::ConnectionClosed => 581,
            TextKey::ThNvr => 582,
            TextKey::TaskNewReproFromSrpm => 583,
            TextKey::NavBatches => 584,
            TextKey::BatchesPageTitle => 585,
            TextKey::BatchesEmptyTitle => 586,
            TextKey::BatchesEmptyHint => 587,
            TextKey::BatchesProgress => 588,
            TextKey::BatchesRounds => 589,
            TextKey::BatchesRoundCol => 590,
            TextKey::BatchesFailures => 591,
            TextKey::BatchesNoFailures => 592,
            TextKey::BatchesCancel => 593,
            TextKey::BatchesCancelConfirm => 594,
            TextKey::FlashBatchCancelled => 595,
            TextKey::BatchStPreparing => 596,
            TextKey::BatchStPlanning => 597,
            TextKey::BatchStRunning => 598,
            TextKey::BatchStCompleted => 599,
            TextKey::BatchStPartial => 600,
            TextKey::BatchStFailed => 601,
            TextKey::BatchStCancelled => 602,
            TextKey::ReproRetentionWarning => 603,
            TextKey::ThOtherHint => 604,
            TextKey::SectionReproTrend => 605,
            TextKey::ReproSeriesAria => 606,
            TextKey::ReproSeriesEmpty => 607,
            TextKey::LabelReplaySource => 608,
            TextKey::LabelReplays => 609,
            TextKey::ReproBoardEmpty => 610,
            TextKey::ThDiffPkgs => 611,
            TextKey::ReproAllSame => 612,
            TextKey::ReproBadgeDiff => 613,
            TextKey::ReproBadgeOnlySource => 614,
            TextKey::ReproBadgeOnlyReplay => 615,
            TextKey::ReproBadgeNoAnchor => 616,
            TextKey::LabelSrpmDownload => 617,
            TextKey::SrpmPolicyPublic => 618,
            TextKey::SrpmPolicyOperator => 619,
            TextKey::SrpmPolicyFollowGlobal => 620,
            // worker 详情页重排：变体声明位于 SrpmPolicyFollowGlobal 之后，编号按登记序续排。
            TextKey::TelemetryTitle => 621,
            TextKey::WorkerMemTotal => 622,
            TextKey::RecentBuildsTitle => 623,
            TextKey::EmptyRecentBuildsTitle => 624,
            TextKey::EmptyRecentBuildsHint => 625,
            TextKey::RecentInitsTitle => 626,
            TextKey::EmptyRecentInitsTitle => 627,
            TextKey::EmptyRecentInitsHint => 628,
            TextKey::EmptyActiveOfflineTitle => 629,
            TextKey::EmptyActiveOfflineHint => 630,
            TextKey::WorkerInitRunning => 631,
            TextKey::DangerRotateWorkerDesc => 632,
            TextKey::DangerRevokeWorkerDesc => 633,
            TextKey::DangerInitWorkerDesc => 634,
            TextKey::DangerRemoveWorkerDesc => 635,
            TextKey::LifecycleQueued => 636,
            TextKey::LifecyclePickedUp => 637,
            TextKey::LifecyclePickupWaiting => 638,
            TextKey::LifecycleRan => 639,
            // worker 详情页遥测趋势面板：变体声明位于 LifecycleRan 之后，编号按登记序续排。
            TextKey::TelemetryRange1h => 641,
            TextKey::TelemetryRange24h => 642,
            TextKey::TelemetryRange7d => 643,
            TextKey::TelemetryCpuLegend => 644,
            TextKey::TelemetryOffline => 645,
            TextKey::TelemetryEmpty => 646,
            // 现值条负载组标签：追加表尾。
            TextKey::ThLoadAvg => 647,
            // 资源可观测：变体声明位于 ThLoadAvg 之后，编号按登记序续排。
            TextKey::BuildResourcesTitle => 648,
            TextKey::ResPeakMem => 649,
            TextKey::ResPeakTotal => 650,
            TextKey::ResPeakTotalNote => 651,
            TextKey::ResCpuTime => 652,
            TextKey::ResCpuP90 => 653,
            TextKey::ResDiskWrite => 654,
            TextKey::ResOomBadge => 655,
            TextKey::ResOomTitle => 656,
            TextKey::ResSamplingLabel => 657,
            TextKey::ResReqLabel => 658,
            TextKey::ThDisk => 659,
            TextKey::WorkerDiskFree => 660,
            TextKey::WorkerCapsLabel => 661,
            TextKey::TaskNewResSection => 662,
            TextKey::TaskNewResHelp => 663,
            TextKey::TaskNewResMemLabel => 664,
            TextKey::TaskNewResNcpuLabel => 665,
            TextKey::TaskNewResDiskLabel => 666,
            TextKey::SectionResourceProfiles => 667,
            TextKey::ProfileNoData => 668,
            TextKey::ThArch => 669,
            TextKey::ThDeclared => 670,
            TextKey::ThLearnedMem => 671,
            TextKey::ThCpuP90 => 672,
            TextKey::ThSamples => 673,
            TextKey::ThBackend => 674,
            TextKey::ThUpdated => 675,
            TextKey::ProfileCensored => 676,
            TextKey::ProfileCensoredTitle => 677,
            TextKey::AttribNoFitArch => 678,
            TextKey::AttribNoFitCapacity => 679,
            TextKey::AttribWatermarkBlocked => 680,
            TextKey::AttribInitGated => 681,
            TextKey::AttribNoFitHardReq => 682,
            TextKey::AttribBackgroundGated => 683,
            TextKey::AttribDiagnosticNote => 684,
            TextKey::ProfileNoDataHint => 685,
            TextKey::ResTmpfsPeak => 686,
            TextKey::ProfileHelp => 687,
            TextKey::ProfileSourcePlaceholder => 688,
            TextKey::ProfileFilterState => 689,
            TextKey::ProfileStateDeclared => 690,
            TextKey::ProfileStateLearned => 691,
            TextKey::SortProfileMemDesc => 692,
            TextKey::SortProfileNameAsc => 693,
            TextKey::SortProfileNameDesc => 694,
            TextKey::SortProfileSamplesDesc => 695,
            TextKey::SortProfileUpdatedDesc => 696,
            TextKey::ThLatestBuild => 697,
            TextKey::ThArches => 698,
            TextKey::ThEffectiveMem => 699,
            TextKey::ThTmpfsMem => 700,
            TextKey::ProfileArchAnyTitle => 701,
            TextKey::ProfileDetailHeading => 702,
            TextKey::ProfileHistoryTitle => 703,
            TextKey::ProfileHistoryHint => 704,
            TextKey::ProfileHistoryEmpty => 705,
            TextKey::ProfileEditTitle => 706,
            TextKey::ProfileEditHint => 707,
            TextKey::ProfileEditClear => 708,
            TextKey::ProfileCsvExport => 709,
            TextKey::FlashProfileFloorsUpdated => 710,
            TextKey::ThSourcePackage => 711,
            TextKey::ProfileAddArchTitle => 712,
            TextKey::ProfileAddArchHint => 713,
            TextKey::ProfileArchPlaceholder => 714,
            // 画像弹性/固定徽章：追加表尾。
            TextKey::ProfileElastic => 715,
            TextKey::ProfileElasticTitle => 716,
            TextKey::ProfileFixed => 717,
            TextKey::ProfileFixedTitle => 718,
            // 画像弹性行单核内存单位：追加表尾。
            TextKey::ProfileMemPerCoreUnit => 719,
            // tmpfs 学习门归因说明（无水位系数）：追加表尾。
            TextKey::AttribTmpfsGate => 720,
            // 任务标签 UI：追加表尾。
            TextKey::LabelTaskLabels => 721,
            TextKey::PlaceholderTaskLabel => 722,
            TextKey::TaskNewLabelsHelp => 723,
            TextKey::TaskNewAddLabel => 724,
            TextKey::TaskNewRemoveLabel => 725,
        }
    }

    /// `ALL` 完备性断言：无重复 + 编号集合恰为 `0..ALL.len()`，漏登记非末位变体即红；
    /// 末位缺席运行时不可判（`ALL` 不含缺席者信息），由 [`text_key_exhaustiveness_helper`] 编译拦截。
    #[test]
    fn text_key_all_covers_every_variant_exactly_once() {
        let mut seen = std::collections::HashSet::new();
        let mut indexes = std::collections::HashSet::new();
        for key in TextKey::ALL {
            assert!(
                seen.insert(std::mem::discriminant(key)),
                "{key:?}: duplicate entry in ALL"
            );
            assert!(
                indexes.insert(text_key_exhaustiveness_helper(key)),
                "{key:?}: duplicate helper index"
            );
        }
        let expected: std::collections::HashSet<usize> = (0..TextKey::ALL.len()).collect();
        assert_eq!(
            indexes, expected,
            "ALL drifts from the TextKey enum: a variant is missing from ALL"
        );
    }

    /// FmtKey 版穷尽性哨兵（同 [`text_key_exhaustiveness_helper`]）：每变体一臂、
    /// **无通配臂**，臂值 0..N 连续唯一（序不与表声明序绑定）；新增变体编译失败强制补臂并登记 `ALL`。
    fn fmt_key_exhaustiveness_helper(key: &FmtKey) -> usize {
        match key {
            FmtKey::PaginationInfo => 0,
            FmtKey::RecentSucceeded => 1,
            FmtKey::WindowLastTasks => 2,
            FmtKey::ArchOnline => 3,
            FmtKey::ArchCpuAvg => 4,
            FmtKey::QueuePriority => 5,
            FmtKey::DonutRowTitle => 6,
            FmtKey::RelSecs => 7,
            FmtKey::RelMins => 8,
            FmtKey::RelHours => 9,
            FmtKey::RelDays => 10,
            FmtKey::GaugeAria => 11,
            FmtKey::DurationAria => 12,
            FmtKey::DurationNote => 13,
            FmtKey::ErrTitleKnown => 14,
            FmtKey::ErrTitleUnknown => 15,
            FmtKey::RateLimitedMinutes => 16,
            FmtKey::RegisterPasswordTooShort => 17,
            FmtKey::RegisterPasswordTooLong => 18,
            FmtKey::MeUserSince => 19,
            FmtKey::MeSessionsDeviceCount => 20,
            FmtKey::AdminResetConfirm => 21,
            FmtKey::AdminResetTempLabel => 22,
            FmtKey::MeTokenDays => 23,
            FmtKey::MeTokensMoreHidden => 24,
            FmtKey::StartedAtTitle => 25,
            FmtKey::BuildTitle => 26,
            FmtKey::BuildLogsTitle => 27,
            FmtKey::TaskTitle => 28,
            FmtKey::LogTruncated => 29,
            FmtKey::PackagesCount => 30,
            FmtKey::PackageNvrTitle => 31,
            FmtKey::PackageTitle => 32,
            FmtKey::AttemptsCount => 33,
            FmtKey::ProductTitle => 34,
            FmtKey::ProductHistoryTitle => 35,
            FmtKey::HistoryTitle => 36,
            FmtKey::ProductHistoryDiffTitle => 37,
            FmtKey::HistoryDiffTitle => 38,
            FmtKey::DiffRevMeta => 39,
            FmtKey::DiffTruncatedNote => 40,
            FmtKey::HistoryDiffRawFallback => 41,
            FmtKey::FlashRevisionConflict => 42,
            FmtKey::FlashInvalidVisibility => 43,
            FmtKey::FlashParentDisappeared => 44,
            FmtKey::FlashPublishPrivateAncestor => 45,
            FmtKey::FlashProductAclInvalidRole => 46,
            FmtKey::FlashUserNotFoundByName => 47,
            FmtKey::FlashAdminRoleExpected => 48,
            FmtKey::FlashUserNotFoundById => 49,
            FmtKey::FlashUserExists => 50,
            FmtKey::FlashTokenDisabledUser => 51,
            FmtKey::FlashTokenNotFoundForUser => 52,
            FmtKey::FlashAdminAclInvalidRole => 53,
            FmtKey::FlashUserNotActive => 54,
            FmtKey::FlashAclNotGranted => 55,
            FmtKey::FlashProductNameInvalidChars => 56,
            FmtKey::FlashProductNameInvalidCharsCore => 57,
            FmtKey::FlashWorkerNotFound => 58,
            FmtKey::FlashWorkerOnlineConflict => 59,
            FmtKey::FlashWorkerOfflineInit => 60,
            FmtKey::FlashInitConflictBuilding => 61,
            FmtKey::FlashInitConflictActive => 62,
            FmtKey::FlashUnknownWorkerAction => 63,
            FmtKey::FlashCancelPartial => 64,
            FmtKey::FlashTaskNotFound => 65,
            FmtKey::FlashBuildNotFound => 66,
            FmtKey::FlashReplayInfoNotFound => 67,
            FmtKey::FlashProductNotFound => 68,
            FmtKey::FlashReplayNoChildBuilds => 69,
            FmtKey::FlashReplayStillInProgress => 70,
            FmtKey::FlashReplayChildNotSucceeded => 71,
            FmtKey::FlashProductNameTooLong => 72,
            FmtKey::FlashInvalidVisibilityEditor => 73,
            FmtKey::FlashOwnerNotFound => 74,
            FmtKey::FlashParentPrivateAttach => 75,
            FmtKey::FlashParentProductNotFound => 76,
            FmtKey::FlashProductRevisionMoved => 77,
            FmtKey::FlashProductNameTaken => 78,
            FmtKey::FlashRevisionConflictStore => 79,
            FmtKey::FlashProductChainTooDeep => 80,
            FmtKey::FlashChainWalkParentMissing => 81,
            FmtKey::FlashChainWalkEmptyChain => 82,
            FmtKey::ParentLabel => 83,
            FmtKey::ParentWithId => 84,
            FmtKey::EditTitle => 85,
            FmtKey::EditPageTitle => 86,
            FmtKey::EditChangedBy => 87,
            FmtKey::ChainResolveFailed => 88,
            FmtKey::TokenIdLabel => 89,
            FmtKey::AdminUserPageTitle => 90,
            FmtKey::ConfirmRevokeToken => 91,
            FmtKey::ConfirmRevokeUserAcl => 92,
            FmtKey::ConfirmRevokeAclUser => 93,
            FmtKey::ConfirmRotateWorkerSecret => 94,
            FmtKey::ConfirmRevokeWorkerSecret => 95,
            FmtKey::ConfirmRemoveWorker => 96,
            FmtKey::WorkerLabel => 97,
            FmtKey::MemUsedPct => 98,
            FmtKey::UploadMaxNote => 99,
            FmtKey::UploadTooLarge => 100,
            FmtKey::SubmitFailed => 101,
            FmtKey::SearchTitle => 102,
            FmtKey::ThemeToggleAria => 103,
            FmtKey::LangToggleAria => 104,
            FmtKey::MetaBuildsCount => 105,
            FmtKey::MatrixSummary => 106,
            FmtKey::SubPanelFailedAt => 107,
            FmtKey::LogAtLine => 108,
            FmtKey::SkippedChipFmt => 109,
            FmtKey::ChangelogPageSummary => 110,
            FmtKey::ReproShowingLatest => 111,
            FmtKey::MetaReplayedFrom => 112,
            FmtKey::MetaReplayCount => 113,
            // 首页系统条并发 tooltip：变体声明位于 ReproShowingLatest 之后，编号按声明序续排。
            FmtKey::ConcurrencyTitleAuto => 114,
            FmtKey::ConcurrencyTitleDistributedOnly => 115,
            FmtKey::ConcurrencyTitleLocalOnly => 116,
            // 复现记录 drill-down：变体声明位于并发 tooltip 之后，编号按声明序续排。
            FmtKey::ReproSamePkgsFmt => 117,
            FmtKey::ReproGroupConsistentFmt => 118,
            // worker 列表 CPU 遥测 title：变体声明位于复现 drill-down 之后，编号按声明序续排。
            FmtKey::CpuUtilTitle => 119,
            // 产物卡 crbs-logs 目录树：变体声明位于 CPU 遥测 title 之后，编号按声明序续排。
            FmtKey::LogsDirFiles => 120,
            // worker 列表 Load 列容量条 title：变体声明位于目录树计数之后，编号按声明序续排。
            FmtKey::LoadCapacityTitle => 121,
            // build 详情页 Lifecycle 三段间隙：变体声明位于 Load 容量条之后，编号按声明序续排。
            FmtKey::LifecycleQueuedSoFar => 122,
            FmtKey::LifecyclePickupDur => 123,
            FmtKey::LifecycleRanSoFar => 124,
            // worker 详情页遥测汇总行：变体声明位于 Lifecycle 三段间隙之后，编号按声明序续排。
            FmtKey::TelemetrySummary => 125,
            // worker init arch 门禁：变体声明位于遥测汇总行之后，编号按声明序续排。
            FmtKey::FlashInitConflictArch => 126,
            // 详情遥测现值条负载 tooltip：追加表尾。
            FmtKey::LoadAvgTitle => 127,
            FmtKey::AttribWatermarkWaiting => 128,
            FmtKey::AttribHardReqDim => 129,
            FmtKey::ProfileInvalidAction => 130,
            // 水位归因徽章生效压载（按拒绝维）：追加表尾。
            FmtKey::AttribWatermarkLoadMem => 131,
            FmtKey::AttribWatermarkLoadCpu => 132,
        }
    }

    /// FmtKey 的 `ALL` 完备性断言（与 TextKey 同款）：无重复 + 编号集合恰为
    /// `0..ALL.len()`；漏登记非末位变体即红，末位缺席由 [`fmt_key_exhaustiveness_helper`] 编译拦截。
    #[test]
    fn fmt_key_all_covers_every_variant_exactly_once() {
        let mut seen = std::collections::HashSet::new();
        let mut indexes = std::collections::HashSet::new();
        for key in FmtKey::ALL {
            assert!(
                seen.insert(std::mem::discriminant(key)),
                "{key:?}: duplicate entry in ALL"
            );
            assert!(
                indexes.insert(fmt_key_exhaustiveness_helper(key)),
                "{key:?}: duplicate helper index"
            );
        }
        let expected: std::collections::HashSet<usize> = (0..FmtKey::ALL.len()).collect();
        assert_eq!(
            indexes, expected,
            "ALL drifts from the FmtKey enum: a variant is missing from ALL"
        );
    }

    #[test]
    fn all_fmt_keys_nonempty_and_bilingual() {
        for key in FmtKey::ALL {
            // 各喂 4 个占位参数（多于多数 key 的用量，多余的被忽略）。
            let args = ["1", "2", "3", "tasks"];
            let en = t_fmt(Lang::En, *key, &args);
            let zh = t_fmt(Lang::Zh, *key, &args);
            assert!(!en.is_empty(), "{key:?}: en empty");
            assert!(!zh.is_empty(), "{key:?}: zh empty");
            assert!(!en.contains("{"), "{key:?}: leftover placeholder in {en}");
            assert!(!zh.contains("{"), "{key:?}: leftover placeholder in {zh}");
        }
    }

    /// 代表性完整句断言：含中英语序互换的 key（args 顺序固定，模板各自排列）。
    #[test]
    fn t_fmt_interpolates_full_sentences_per_language() {
        // matrix_summary_pattern 与 t_fmt 模板须逐字一致（data-pattern 进 JS 整句重算，漂移即静默错文案）。
        for lang in [Lang::En, Lang::Zh] {
            let via_pattern = matrix_summary_pattern(lang)
                .replace("{0}", "5")
                .replace("{1}", "3")
                .replace("{2}", "1");
            assert_eq!(
                via_pattern,
                t_fmt(lang, FmtKey::MatrixSummary, &["5", "3", "1"])
            );
        }
        assert_eq!(
            t_fmt(Lang::En, FmtKey::WindowLastTasks, &["200"]),
            "window: last 200 tasks"
        );
        assert_eq!(
            t_fmt(Lang::Zh, FmtKey::WindowLastTasks, &["200"]),
            "窗口：最近 200 个任务"
        );
        // succeeded/total 两参在中英语序中顺序相反。
        assert_eq!(
            t_fmt(Lang::En, FmtKey::RecentSucceeded, &["171", "200"]),
            "171 / 200 recent tasks succeeded"
        );
        assert_eq!(
            t_fmt(Lang::Zh, FmtKey::RecentSucceeded, &["171", "200"]),
            "最近 200 个任务中 171 个成功"
        );
        assert_eq!(t_fmt(Lang::En, FmtKey::RelMins, &["5"]), "5 min ago");
        assert_eq!(t_fmt(Lang::Zh, FmtKey::RelMins, &["5"]), "5 分钟前");
        assert_eq!(t_fmt(Lang::Zh, FmtKey::RelDays, &["4"]), "4 天前");
        assert_eq!(
            t_fmt(Lang::En, FmtKey::PaginationInfo, &["1", "50", "56"]),
            "1-50 of 56"
        );
        assert_eq!(
            t_fmt(Lang::Zh, FmtKey::PaginationInfo, &["1", "50", "56"]),
            "第 1-50 条，共 56 条"
        );
        // donut title 的英文复数单位词参数在 zh 模板中被忽略。
        assert_eq!(
            t_fmt(
                Lang::En,
                FmtKey::DonutRowTitle,
                &["failed", "21", "10.1", "tasks"]
            ),
            "failed · 21 tasks · 10.1% — click to view list"
        );
        assert_eq!(
            t_fmt(
                Lang::Zh,
                FmtKey::DonutRowTitle,
                &["失败", "21", "10.1", "tasks"]
            ),
            "失败 · 21 个任务 · 10.1% — 点击查看列表"
        );
        // donut_row_title_pattern 与 t_fmt 模板须逐字一致（pattern 进 SSE 脚本重算图例 title，漂移即静默错文案）。
        for lang in [Lang::En, Lang::Zh] {
            let via_pattern = donut_row_title_pattern(lang)
                .replace("{0}", "failed")
                .replace("{1}", "21")
                .replace("{2}", "10.1")
                .replace("{3}", "tasks");
            assert_eq!(
                via_pattern,
                t_fmt(
                    lang,
                    FmtKey::DonutRowTitle,
                    &["failed", "21", "10.1", "tasks"]
                ),
                "{lang:?}"
            );
        }
    }

    #[test]
    fn from_value_whitelists_and_falls_back_to_en() {
        assert_eq!(Lang::from_value(Some("en")), Lang::En);
        assert_eq!(Lang::from_value(Some("zh")), Lang::Zh);
        assert_eq!(Lang::from_value(None), Lang::En);
        assert_eq!(Lang::from_value(Some("ZH")), Lang::En);
        assert_eq!(Lang::from_value(Some("zh-CN")), Lang::En);
        assert_eq!(Lang::from_value(Some("hack")), Lang::En);
    }

    /// 协商矩阵：内部覆盖头 > cookie > Accept-Language > En；非法值回退。
    #[test]
    fn lang_from_headers_priority_and_fallback_matrix() {
        use axum::http::header::{ACCEPT_LANGUAGE, COOKIE};
        let override_hdr = axum::http::HeaderName::from_static(LANG_OVERRIDE_HEADER);

        assert_eq!(lang_from_headers(&HeaderMap::new()), Lang::En);
        assert_eq!(
            lang_from_headers(&headers_with(&[(COOKIE, "crbs_lang=zh")])),
            Lang::Zh
        );
        assert_eq!(
            lang_from_headers(&headers_with(&[(COOKIE, "crbs_token=abc; crbs_lang=en")])),
            Lang::En
        );
        // cookie 非法值 → En（不下探 Accept-Language）。
        assert_eq!(
            lang_from_headers(&headers_with(&[
                (COOKIE, "crbs_lang=hack"),
                (ACCEPT_LANGUAGE, "zh-CN,zh;q=0.9"),
            ])),
            Lang::En
        );
        for al in ["zh-CN,zh;q=0.9,en;q=0.8", "zh", "zh-TW,en;q=0.5", "zh-Hans"] {
            assert_eq!(
                lang_from_headers(&headers_with(&[(ACCEPT_LANGUAGE, al)])),
                Lang::Zh,
                "Accept-Language: {al}"
            );
        }
        for al in ["en-US,en;q=0.9", "ja", "*"] {
            assert_eq!(
                lang_from_headers(&headers_with(&[(ACCEPT_LANGUAGE, al)])),
                Lang::En,
                "Accept-Language: {al}"
            );
        }
        assert_eq!(
            lang_from_headers(&headers_with(&[
                (override_hdr.clone(), "zh"),
                (COOKIE, "crbs_lang=en"),
            ])),
            Lang::Zh
        );
        assert_eq!(
            lang_from_headers(&headers_with(&[
                (override_hdr.clone(), "en"),
                (ACCEPT_LANGUAGE, "zh-CN"),
            ])),
            Lang::En
        );
        assert_eq!(
            lang_from_headers(&headers_with(&[
                (override_hdr.clone(), "hack"),
                (COOKIE, "crbs_lang=zh"),
            ])),
            Lang::Zh
        );
    }

    #[test]
    fn t_phase_maps_seven_phases_and_falls_back() {
        assert_eq!(t_phase(Lang::En, "succeeded"), "succeeded");
        assert_eq!(t_phase(Lang::Zh, "pending"), "等待中");
        assert_eq!(t_phase(Lang::Zh, "assigned"), "已分配");
        assert_eq!(t_phase(Lang::Zh, "building"), "构建中");
        assert_eq!(t_phase(Lang::Zh, "succeeded"), "成功");
        assert_eq!(t_phase(Lang::Zh, "failed"), "失败");
        assert_eq!(t_phase(Lang::Zh, "timeout"), "超时");
        assert_eq!(t_phase(Lang::Zh, "cancelled"), "已取消");
        assert_eq!(t_phase(Lang::Zh, "weird"), "weird");
        assert_eq!(t_phase(Lang::En, "weird"), "weird");
    }

    #[test]
    fn phase_option_label_keeps_en_capitalized_and_translates_zh() {
        assert_eq!(phase_option_label(Lang::En, "pending"), "Pending");
        assert_eq!(phase_option_label(Lang::En, "failed"), "Failed");
        assert_eq!(phase_option_label(Lang::Zh, "failed"), "失败");
    }

    #[test]
    fn lang_query_value_accepts_only_exact_whitelist() {
        let parse = |q: &str| lang_query_value(&format!("/ui/tasks?{q}").parse::<Uri>().unwrap());
        assert_eq!(parse("lang=zh"), Some(Lang::Zh));
        assert_eq!(parse("lang=en"), Some(Lang::En));
        assert_eq!(parse("lang=xx"), None);
        assert_eq!(parse("lang="), None);
        assert_eq!(parse("product=x&lang=zh"), Some(Lang::Zh));
        assert_eq!(parse("lang=zh&product=x"), Some(Lang::Zh));
        assert_eq!(parse("product=x"), None);
        assert_eq!(lang_query_value(&"/ui/tasks".parse::<Uri>().unwrap()), None);
        assert_eq!(parse("language=zh"), None);
    }

    #[test]
    fn html_lang_and_cookie_values() {
        assert_eq!(Lang::En.html_lang(), "en");
        assert_eq!(Lang::Zh.html_lang(), "zh-CN");
        assert_eq!(Lang::En.cookie_value(), "en");
        assert_eq!(Lang::Zh.cookie_value(), "zh");
    }

    #[test]
    fn priority_labels_match_documented_values() {
        assert_eq!(priority_label(Lang::En, 0), "normal");
        assert_eq!(priority_label(Lang::En, 1), "high");
        assert_eq!(priority_label(Lang::En, 2), "critical");
        assert_eq!(priority_label(Lang::En, 9), "9");
        assert_eq!(priority_label(Lang::Zh, 1), "高");
        assert_eq!(priority_label(Lang::Zh, 9), "9");
    }

    #[test]
    fn display_name_helpers_translate_known_values_and_fall_back() {
        assert_eq!(visibility_label(Lang::En, "public"), "public");
        assert_eq!(visibility_label(Lang::Zh, "public"), "公开");
        assert_eq!(visibility_label(Lang::Zh, "private"), "私有");
        assert_eq!(visibility_label(Lang::Zh, "weird"), "weird");
        assert_eq!(worker_status_label(Lang::En, "online"), "online");
        assert_eq!(worker_status_label(Lang::Zh, "online"), "在线");
        assert_eq!(worker_status_label(Lang::Zh, "offline"), "离线");
        assert_eq!(worker_status_label(Lang::Zh, "weird"), "weird");
        assert_eq!(user_status_label(Lang::En, "active"), "active");
        assert_eq!(user_status_label(Lang::Zh, "active"), "启用");
        assert_eq!(user_status_label(Lang::Zh, "disabled"), "禁用");
        assert_eq!(user_status_label(Lang::Zh, "weird"), "weird");
        // 角色显示名：四已知值双语（zh 短形：管理员/运维/开发者/访客），未知值回退原串。
        assert_eq!(role_label(Lang::En, "admin"), "Admin");
        assert_eq!(role_label(Lang::En, "operator"), "Operator");
        assert_eq!(role_label(Lang::En, "builder"), "Builder");
        assert_eq!(role_label(Lang::En, "viewer"), "Viewer");
        assert_eq!(role_label(Lang::Zh, "admin"), "管理员");
        assert_eq!(role_label(Lang::Zh, "operator"), "运维");
        assert_eq!(role_label(Lang::Zh, "builder"), "开发者");
        assert_eq!(role_label(Lang::Zh, "viewer"), "访客");
        assert_eq!(role_label(Lang::Zh, "weird"), "weird");
        assert_eq!(role_label(Lang::En, "weird"), "weird");
    }
}
