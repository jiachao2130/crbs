// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 在 epoch 秒与两种时间表示之间换算：zip/DOS 文件的 16 位日期时间字段，以及
//! 形如 "2026-10-08 11:29:12 UTC" 的定长字符串。

/// DOS 时间最早表示 1980-01-01 00:00:00 UTC，本常量为对应的 epoch 秒。
const DOS_MIN_EPOCH: i64 = 315_532_800;

/// DOS 的年份字段只有 7 位，最大表示 2107 年。此处取 2107-12-31 23:59:58 对应
/// 的值（秒字段以 2 秒为单位，因此是 58）。
const DOS_MAX_PAIR: (u16, u16) = (0xFF9F, 0xBF7D);

/// 由公历天数计算年月日，采用 Hinnant 的 civil 算法。
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

/// 定长 UTC 时间字符串 "YYYY-MM-DD HH:MM:SS UTC" 的字节数。
pub(crate) const UTC_STAMP_LEN: usize = 23;

/// epoch 秒转定长 UTC 戳 "YYYY-MM-DD HH:MM:SS UTC"；年份越出 0000..=9999
/// 时返回 `None`（超出可承载格式，调用方按格式损坏处理）。写入格式固定为
/// 本串，双侧同值即确定，不模仿目标工具的原生 locale 形态。
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

/// 构造归一化参考串（23 字节定长 UTC 戳）：epoch 越出可承载范围时返回
/// Err（错误文案固定）。
pub(crate) fn anchor_stamp(epoch: i64) -> Result<[u8; UTC_STAMP_LEN], String> {
    epoch_to_utc_ascii(epoch).ok_or_else(|| "epoch outside UTC stamp range".to_string())
}

/// 只检查字符格式和取值范围，不验证日期的真实性；对用途而言已经足够。
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

/// 扫描全部合法 UTC 戳的起始下标（升序、不重叠）：命中后跳过整个戳长度，
/// 防止同一段字节被截出伪戳。
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

/// epoch 秒转 (dos_date, dos_time)。早于 1980-01-01Z 时取 DOS 最小值；超
/// 出 2107 年上限时取最大可表示值。秒按 DOS 的 2s 粒度向下截断（确定性来
/// 源，不做四舍五入）。
pub(crate) fn epoch_to_dos(epoch: i64) -> (u16, u16) {
    let e = epoch.max(DOS_MIN_EPOCH);
    let days = e.div_euclid(86_400);
    let sod = e.rem_euclid(86_400) as u32;
    let (y, m, d) = civil_from_days(days);
    if y > 2107 {
        return DOS_MAX_PAIR;
    }

    let date = (((y - 1980) as u16) << 9) | ((m as u16) << 5) | d as u16;
    let time =
        ((sod / 3_600) as u16) << 11 | (((sod % 3_600) / 60) as u16) << 5 | (sod % 60 / 2) as u16;
    (date, time)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_pre_1980_to_dos_minimum() {
        assert_eq!(epoch_to_dos(0), (0x0021, 0));
        assert_eq!(epoch_to_dos(-1), (0x0021, 0));
        assert_eq!(epoch_to_dos(i64::MIN), (0x0021, 0));
    }

    #[test]
    fn handles_dos_epoch_boundary() {
        assert_eq!(epoch_to_dos(315_532_800), (0x0021, 0));
        assert_eq!(epoch_to_dos(315_532_801), (0x0021, 0));
        assert_eq!(epoch_to_dos(315_532_862), (0x0021, 33));
    }

    #[test]
    fn converts_leap_day() {
        let epoch = 315_532_800 + 1_520 * 86_400 + 12 * 3_600 + 34 * 60 + 56;
        assert_eq!(epoch, 446_906_096);
        assert_eq!(
            epoch_to_dos(epoch),
            ((4 << 9) | (2 << 5) | 29, (12 << 11) | (34 << 5) | 28)
        );
    }

    #[test]
    fn converts_recent_timestamp() {
        assert_eq!(epoch_to_dos(1_791_458_952), (23_880, 23_462));
    }

    #[test]
    fn converts_u32_max_epoch() {
        assert_eq!(epoch_to_dos(u32::MAX as i64), (64_583, 13_191));
    }

    #[test]
    fn clamps_post_2107_to_dos_maximum() {
        assert_eq!(epoch_to_dos(1 << 40), (0xFF9F, 0xBF7D));
        assert_eq!(epoch_to_dos(i64::MAX), (0xFF9F, 0xBF7D));
    }

    #[test]
    fn truncates_odd_seconds_downward() {
        assert_eq!(
            epoch_to_dos(315_532_800 + 58),
            epoch_to_dos(315_532_800 + 59)
        );
    }

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

    #[test]
    fn stamp_scan() {
        let text = b"a2026-10-11 07:11:17 UTCb2026-10-11 07:11:17 UTCc";
        assert_eq!(find_utc_stamps(text), vec![1, 25]);
        assert!(find_utc_stamps(b"no stamps here").is_empty());
        assert!(find_utc_stamps(b"2026-10-11 07:11:17 UT").is_empty());
        assert!(find_utc_stamps(b"").is_empty());
    }
}
