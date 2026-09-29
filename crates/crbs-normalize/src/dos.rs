// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! epoch 秒 → DOS 日期/时间字段（zip 16 位对）与 UTC 定长文本戳：std 无历法
//! 转换，用 Hinnant civil 算法的 days 正逆变换纯函数实现。

/// DOS 时间字段下界：1980-01-01T00:00:00Z（DOS 纪元起点）。
const DOS_MIN_EPOCH: i64 = 315_532_800;

/// DOS 年份字段 7 位，最大 2107；钳制上限取 2107-12-31 23:59:58 的
/// (date, time) 对（time 秒按 2s 粒度存 29）。
const DOS_MAX_PAIR: (u16, u16) = (0xFF9F, 0xBF7D);

/// 自 1970-01-01 起的天数 → (年, 月, 日)，Hinnant civil_from_days；
/// Jan/Feb 的年偏移（`m <= 2` 时年 +1）在公式内部完成，返回值即民用历日期。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = era * 400 + yoe as i64 + i64::from(m <= 2);
    (y, m, d)
}

/// UTC 定长戳 "YYYY-MM-DD HH:MM:SS UTC" 的字节长度（R DESCRIPTION Built 段
/// 与 javadoc 归一化共用的写入/识别形态）。
pub(crate) const UTC_STAMP_LEN: usize = 23;

/// epoch 秒 → 定长 UTC 戳 "YYYY-MM-DD HH:MM:SS UTC"；年份越出 0000..=9999
/// → None（锚值超出可承载格式，调用方按格式损坏放弃）。写入格式固定为本
/// 串，双侧同值即确定，不模仿目标工具的原生 locale 形态。
pub(crate) fn epoch_to_utc_ascii(epoch: i64) -> Option<[u8; UTC_STAMP_LEN]> {
    let (y, m, d) = civil_from_days(epoch.div_euclid(86_400));
    if !(0..=9999).contains(&y) {
        return None;
    }
    let sod = epoch.rem_euclid(86_400);
    let text = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    );
    text.into_bytes().try_into().ok()
}

/// 归一锚串构造：epoch 越出 UTC 戳可承载范围即 Err（错误串固定）。
pub(crate) fn anchor_stamp(epoch: i64) -> Result<[u8; UTC_STAMP_LEN], String> {
    epoch_to_utc_ascii(epoch).ok_or_else(|| "epoch outside UTC stamp range".to_string())
}

/// 23 字节窗口是否为合法 UTC 戳：逐位数字/分隔校验 + 域值范围（月 01-12、
/// 日 01-31、时 <24、分秒 <60）——只挡明显垃圾，不校验真实历法（04-31 之类
/// 伪日期不影响确定性）。
pub(crate) fn is_utc_stamp(seg: &[u8]) -> bool {
    fn dd(seg: &[u8], at: usize) -> u32 {
        (u32::from(seg[at]) - u32::from(b'0')) * 10 + u32::from(seg[at + 1]) - u32::from(b'0')
    }
    seg.len() == UTC_STAMP_LEN
        && seg[0..4].iter().all(u8::is_ascii_digit)
        && seg[4] == b'-'
        && seg[5..7].iter().all(u8::is_ascii_digit)
        && seg[7] == b'-'
        && seg[8..10].iter().all(u8::is_ascii_digit)
        && seg[10] == b' '
        && seg[11..13].iter().all(u8::is_ascii_digit)
        && seg[13] == b':'
        && seg[14..16].iter().all(u8::is_ascii_digit)
        && seg[16] == b':'
        && seg[17..19].iter().all(u8::is_ascii_digit)
        && seg[19] == b' '
        && seg[20..23] == *b"UTC"
        && (1..=12).contains(&dd(seg, 5))
        && (1..=31).contains(&dd(seg, 8))
        && dd(seg, 11) < 24
        && dd(seg, 14) < 60
        && dd(seg, 17) < 60
}

/// 扫描全部合法 UTC 戳的起始下标（升序、不重叠：命中后跳过整个戳长度，
/// 防止同一段字节被截出伪戳）。
pub(crate) fn find_utc_stamps(data: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    if data.len() >= UTC_STAMP_LEN {
        let mut i = 0;
        while i + UTC_STAMP_LEN <= data.len() {
            if is_utc_stamp(&data[i..i + UTC_STAMP_LEN]) {
                hits.push(i);
                i += UTC_STAMP_LEN;
            } else {
                i += 1;
            }
        }
    }
    hits
}

/// epoch 秒 → (dos_date, dos_time)。
///
/// 早于 1980-01-01Z 钳到 DOS 最小值；DOS 年字段 7 位上限 2107，超界钳到
/// 最大表示。秒按 DOS 2s 粒度向下截断（确定性来源，不做四舍五入）。
pub(crate) fn epoch_to_dos(epoch: i64) -> (u16, u16) {
    let e = epoch.max(DOS_MIN_EPOCH);
    let days = e.div_euclid(86_400);
    let sod = e.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    if y > 2107 {
        return DOS_MAX_PAIR;
    }
    // 钳制后 y ∈ [1980, 2107]，年字段 7 位、月 4 位、日 5 位均不越界
    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time =
        ((sod / 3_600) as u16) << 11 | (((sod % 3_600) / 60) as u16) << 5 | (sod % 60 / 2) as u16;
    (date, time)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// epoch 0 与负值：早于 DOS 纪元，钳到 1980-01-01 00:00:00 = (0x0021, 0)。
    #[test]
    fn clamps_pre_1980_to_dos_minimum() {
        assert_eq!(epoch_to_dos(0), (0x0021, 0));
        assert_eq!(epoch_to_dos(-1), (0x0021, 0));
        assert_eq!(epoch_to_dos(i64::MIN), (0x0021, 0));
    }

    /// 1980 边界：起点恒为最小对；起点后 62 秒 = 00:01:02（秒 2s 截断）。
    #[test]
    fn handles_dos_epoch_boundary() {
        assert_eq!(epoch_to_dos(315_532_800), (0x0021, 0));
        assert_eq!(epoch_to_dos(315_532_801), (0x0021, 0));
        assert_eq!(epoch_to_dos(315_532_862), (0x0021, 33));
    }

    /// 闰日：1984-02-29T12:34:56Z → date=(4,2,29) 位域、time=(12,34,28)。
    #[test]
    fn converts_leap_day() {
        // 1980-01-01Z + 1520 天（4 年含闰日）+ 45296s
        let epoch = 315_532_800 + 1_520 * 86_400 + 12 * 3_600 + 34 * 60 + 56;
        assert_eq!(epoch, 446_906_096);
        assert_eq!(
            epoch_to_dos(epoch),
            ((4 << 9) | (2 << 5) | 29, (12 << 11) | (34 << 5) | 28)
        );
    }

    /// 现在时刻：2026-10-08T11:29:12Z（锚值样例）→ 位域逐项核对。
    #[test]
    fn converts_recent_timestamp() {
        assert_eq!(epoch_to_dos(1_791_458_952), (23_880, 23_462));
    }

    /// u32::MAX（gzip mtime 字段上界）= 2106-02-07T06:28:15Z，秒截断到 14。
    #[test]
    fn converts_u32_max_epoch() {
        assert_eq!(epoch_to_dos(u32::MAX as i64), (64_583, 13_191));
    }

    /// 远超 DOS 上界：钳到 2107-12-31 23:59:58 的最大表示对。
    #[test]
    fn clamps_post_2107_to_dos_maximum() {
        assert_eq!(epoch_to_dos(1 << 40), (0xFF9F, 0xBF7D));
        assert_eq!(epoch_to_dos(i64::MAX), (0xFF9F, 0xBF7D));
    }

    /// 2s 粒度：同 DOS 槽内秒值归并（59s 与 58s 同槽，确定性向下截断）。
    #[test]
    fn truncates_odd_seconds_downward() {
        // 1980-01-01T00:00:59Z 与 :58Z 同槽（sec/2 = 29）
        assert_eq!(
            epoch_to_dos(315_532_800 + 58),
            epoch_to_dos(315_532_800 + 59)
        );
    }

    /// UTC 戳格式化矩阵：纪元起点、闰日、dos.rs 既有锚样例（与 epoch_to_dos
    /// 共用 civil 变换，两侧对同一 epoch 必须落在同一日期）、负 epoch。
    #[test]
    fn utc_ascii_matrix() {
        let stamp = |e: i64| -> String {
            String::from_utf8(epoch_to_utc_ascii(e).unwrap().to_vec()).unwrap()
        };
        assert_eq!(stamp(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(stamp(-1), "1969-12-31 23:59:59 UTC");
        assert_eq!(stamp(446_906_096), "1984-02-29 12:34:56 UTC");
        assert_eq!(stamp(1_791_458_952), "2026-10-08 11:29:12 UTC");
    }

    /// UTC 戳年份承载界：9999-12-31 23:59:59 恰可表示，再进一秒越界 None；
    /// i64 两端极值 None。
    #[test]
    fn utc_ascii_year_bounds() {
        assert_eq!(
            epoch_to_utc_ascii(253_402_300_799).map(|s| s.to_vec()),
            Some(b"9999-12-31 23:59:59 UTC".to_vec())
        );
        assert_eq!(epoch_to_utc_ascii(253_402_300_800), None);
        assert_eq!(epoch_to_utc_ascii(i64::MIN), None);
        assert_eq!(epoch_to_utc_ascii(i64::MAX), None);
    }

    /// 戳识别：合法戳逐域命中；域值越界（月 13、时 24、分 60）与非数字垃圾
    /// 拒绝；短窗口拒绝。
    #[test]
    fn stamp_validation() {
        assert!(is_utc_stamp(b"2026-10-11 07:11:17 UTC"));
        assert!(is_utc_stamp(b"0000-01-01 00:00:00 UTC"));
        assert!(is_utc_stamp(b"9999-12-31 23:59:59 UTC"));
        assert!(!is_utc_stamp(b"2026-13-11 07:11:17 UTC"));
        assert!(!is_utc_stamp(b"2026-10-11 24:11:17 UTC"));
        assert!(!is_utc_stamp(b"2026-10-11 07:60:17 UTC"));
        assert!(!is_utc_stamp(b"2026-10-11 07:11:60 UTC"));
        assert!(!is_utc_stamp(b"2026/10/11 07:11:17 UTC"));
        assert!(!is_utc_stamp(b"2026-10-11 07:11:17 TTT"));
        assert!(!is_utc_stamp(b"2026-10-11 07:11:17 UT"));
    }

    /// 戳扫描：多戳全中且升序、相邻戳不重叠（23B 间距不产出截断伪戳）、
    /// 无戳输入为空、短输入为空。
    #[test]
    fn stamp_scan() {
        let text = b"a2026-10-11 07:11:17 UTCb2026-10-11 07:11:17 UTCc";
        assert_eq!(find_utc_stamps(text), vec![1, 25]);
        assert!(find_utc_stamps(b"no stamps here").is_empty());
        assert!(find_utc_stamps(b"2026-10-11 07:11:17 UT").is_empty());
        assert!(find_utc_stamps(b"").is_empty());
    }
}
