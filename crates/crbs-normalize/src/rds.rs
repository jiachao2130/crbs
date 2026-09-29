// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! package.rds 的 gzip 容器内保存有打包机器的时间。解码后把时间统一替换为
//! --epoch 指定的值，再重新压缩。解码结果用容器尾部的 CRC32 校验，校验失败
//! 则放弃该文件。

use crate::deflate::{crc32, deflate_stored, inflate};
use crate::dos::{anchor_stamp, find_utc_stamps, UTC_STAMP_LEN};
use crate::formats::gzip_mtime_u32;

/// 解压输出的上限，防止恶意数据占用过多内存。
const MAX_INFLATED: usize = 64 * 1024 * 1024;

const GZIP_HDR: usize = 10;

const GZIP_TRAILER: usize = 8;

const FLG_FEXTRA: u8 = 0x04;
const FLG_FNAME: u8 = 0x08;
const FLG_FCOMMENT: u8 = 0x10;

/// 就地归一化 package.rds：提取 Built 时间戳（唯一以 `<戳>; unix` 结尾的
/// UTC 戳），把其在序列化文本中的全部出现（Built 值串与 built$Date）替换
/// 为定长参考串（23 字节），再以 stored 块重编码整个容器。无 Built 戳（非 R
/// 产物或无时钟值）时静默跳过；解码失败或结构不符时整体放弃。
pub(crate) fn normalize_pkg_rds(data: &mut Vec<u8>, epoch: i64) -> Result<bool, String> {
    let header_len = parse_gzip_header(data)?;
    let payload_end = data
        .len()
        .checked_sub(GZIP_TRAILER)
        .ok_or_else(|| "gzip container shorter than trailer".to_string())?;
    let (orig_crc, orig_isize) = {
        let t = &data[payload_end..];
        (
            u32::from_le_bytes([t[0], t[1], t[2], t[3]]),
            u32::from_le_bytes([t[4], t[5], t[6], t[7]]),
        )
    };

    let mut plain = inflate(&data[header_len..payload_end], MAX_INFLATED)?;

    if crc32(&plain) != orig_crc || (plain.len() as u32) != orig_isize {
        return Err("decoded content fails container CRC32/ISIZE".to_string());
    }

    let stamps = find_utc_stamps(&plain);
    let mut stale: Option<[u8; UTC_STAMP_LEN]> = None;
    for &at in &stamps {
        if plain[at + UTC_STAMP_LEN..].starts_with(b"; unix") {
            let value: [u8; UTC_STAMP_LEN] = plain[at..at + UTC_STAMP_LEN]
                .try_into()
                .map_err(|_| "stamp slice length mismatch".to_string())?;
            match stale {
                None => stale = Some(value),
                Some(v) if v == value => {}
                Some(_) => return Err("multiple distinct Built stamps".to_string()),
            }
        }
    }
    let Some(stale) = stale else {
        return Ok(false);
    };
    let anchor = anchor_stamp(epoch)?;

    let mut i = 0;
    while i + UTC_STAMP_LEN <= plain.len() {
        if plain[i..i + UTC_STAMP_LEN] == stale {
            if plain[i..i + UTC_STAMP_LEN] != anchor {
                plain[i..i + UTC_STAMP_LEN].copy_from_slice(&anchor);
            }
            i += UTC_STAMP_LEN;
        } else {
            i += 1;
        }
    }

    let mut out = Vec::with_capacity(GZIP_HDR + plain.len() + GZIP_TRAILER + 5);
    out.extend_from_slice(&[0x1f, 0x8b, 8, 0]);
    out.extend_from_slice(&gzip_mtime_u32(epoch).to_le_bytes());
    out.extend_from_slice(&[0, 3]);
    out.extend_from_slice(&deflate_stored(&plain));
    out.extend_from_slice(&crc32(&plain).to_le_bytes());
    out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    if out == *data {
        return Ok(false);
    }
    *data = out;
    Ok(true)
}

fn parse_gzip_header(data: &[u8]) -> Result<usize, String> {
    if data.len() < GZIP_HDR + GZIP_TRAILER {
        return Err("gzip container too short".to_string());
    }
    if !data.starts_with(&[0x1f, 0x8b]) || data[2] != 8 {
        return Err("not a deflate gzip container".to_string());
    }
    let flg = data[3];
    if flg & 0xE0 != 0 {
        return Err("reserved gzip FLG bits set".to_string());
    }
    if flg & 0x02 != 0 {
        return Err("gzip FHCRC header not supported".to_string());
    }
    let mut pos = GZIP_HDR;
    if flg & FLG_FEXTRA != 0 {
        let xl = data
            .get(pos..pos + 2)
            .ok_or_else(|| "gzip FEXTRA truncated".to_string())?;
        let xlen = usize::from(u16::from_le_bytes([xl[0], xl[1]]));
        pos = pos
            .checked_add(2 + xlen)
            .ok_or_else(|| "gzip FEXTRA length overflow".to_string())?;
    }
    if flg & FLG_FNAME != 0 {
        pos = skip_nul_terminated(data, pos)?;
    }
    if flg & FLG_FCOMMENT != 0 {
        pos = skip_nul_terminated(data, pos)?;
    }
    if pos + GZIP_TRAILER > data.len() {
        return Err("gzip payload truncated".to_string());
    }
    Ok(pos)
}

fn skip_nul_terminated(data: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        match data.get(pos) {
            Some(0) => return Ok(pos + 1),
            Some(_) => pos += 1,
            None => return Err("unterminated gzip header string".to_string()),
        }
    }
}

/// 最小合法 gzip 容器（10 字节头 + stored deflate + CRC32/ISIZE 小端），
/// 供本模块与 main 的测试复用；带 FNAME 等扩展头的形态另行手工拼接。
#[cfg(test)]
pub(crate) fn gzip_container(plain: &[u8]) -> Vec<u8> {
    let mut data = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
    data.extend_from_slice(&deflate_stored(plain));
    data.extend_from_slice(&crc32(plain).to_le_bytes());
    data.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: i64 = 1_791_458_952;
    const ANCHOR_STAMP: &[u8] = b"2026-10-08 11:29:12 UTC";

    const REAL_RDS_HEX: &str = concat!(
        "1f8b08000000000000039d565b6fdb3614566e6b926e6bd10e28b097717e6982d9f235a993b445d324db5ca44920bb45",
        "81a2082889b69950a24052493cec3fec1f773ba448df9660580408e2ed9cf39def5ca84feb9ee72d79cbde8ab7b40243",
        "effbfd936ee7fc53d36f55ea3bdb6dd87c0aabab9eb7f818be3fc0c9353dbf903c6554113b5fa9fb2ffca69d34f75197",
        "26192308a7310a78984b85de754f4fd019169208b3fc1b4989c08a0bd48737b0a24fde777ae817d4a7207cdc39383ae9",
        "1ed99d070951431ecb62baf028da5847f0644400928dd23b2238494b65543ae58984afe0a0e2158a364a38577a3d12a4",
        "b4594624c194c146e9c248bc0989b8248c8c7c12e7a5b2d18950c49384a4cac89f06079d432d5083a7026fa3d2aa35b7",
        "2ab5467ba7b4b9599e817198a71136307ac430708cd3c1044d295261694ee498f151ac257ea70c53c2a64f6743985930",
        "afb42343e08af75198a731233162341ce10b06302c4bcf874a6572b75ac5e2865ef95c0caa3894d53a20f61bedda16da",
        "c8301876c737ddf10155c33cf4c154b5e0a5ea025ca552e6c4d2eefd5cf08c34c9e8e52d14beb607bfbd4ca9126514f8",
        "4266c5dae29ffb48100c7a71c846a88f5d566493ac18b8ac28239e299ad03fc04b9d20526145a5a21166c8d01763858d",
        "881a12744d421f9df6fb40299226f5caa8cfc80d0d8148c5399346c9351797341da06bf0b6304d531494b51aa3934a8d",
        "058ce40c0b8098f16b22fa3933c2614e59aca5339a114653228d799a2a401ca9b15eacd1a0fdb38e5f00ed013e034907",
        "119ce0a9b61362099ec158c34f709669f998c848d09068ad66e38a0e52a214411b9af0326ad4eaad4ddfa8eda408c731",
        "35fa14872449af8830288c63869ebe8078c2668078784122051a9ebbb83ed7220ad3541630fb90b95a99d4daa4824025",
        "65748519054dc45084320158687f34b1e01bef72083552442a09b82396c7e080d169f8d07e6438bac403f087082daf86",
        "5821cc1822312c4640057029082269c4b5b0361693620c2825041eb8838014482118b92485f67894e2844685bfc09a1c",
        "c1d9a4080db0ca20618c57becdcb36643c2457940b06ee454a00271aba86544636694582c565ccaf539bbf6524fbaed1",
        "bdf0eb7edd4d3ef47eadb4ed646934ae929f1ab546a352ab57eadba85edf6d6eedb61ae843ef600f1515638ffd355d4c",
        "9fa1ba0197205fd0c64b57965c443436557c4bf3796d1a49d171d054bb419fa1cb7cd17ba6b520db5760391b82f23bbb",
        "886b0acb07c1fe891d3f1b7bf202d5dae086f5c46ebf0d50cbaff95b7be8a6bd7dbeddaaf08ca4473923a2021592df54",
        "0669be0759db80cb0474eca07a73b7d5daad370b3620716ec0de22685a709442388147cf9bbe6d1e9c15f9e3a61fa1ce",
        "21a84ea447151bef1dd388a4723c3d2480c8dd1adedabe715ebe71f7cdd287e0d80ed7dfe68380645c28777afd3d9487",
        "2e1122eccaa38fb620dfea66305e7e78680a37531350abdd7c30d025e18e04fc6604dded848fefccd5239dee50b176fe",
        "f88490581ef02483804dabb2dec776fe4de18403a9314b0a2d73e4f41c42c556cff2d025bfe349835630f80abd585fea",
        "cbf6725f80f73bf31b60d6ccb3321f978861e9e2b2e42c05e745bd9d5fcd44e491adf7f9e5344fa00144e36503c56874",
        "667ebc3b8fe64e3ebb23abe68e2d4f726ce16fbbb76cf7168231c34038b495c40969061ddba75d35ca88c5fa758abe85",
        "c977c6e4f84f65d6ea1891cef042cdadfb13f1b1a5d53b2c2deb66f6df666e97d52df09eb22ba671de5378d5b5dbfb1a",
        "374dfa9ec26be3d67e5febc50fcdfd8417e11af97f49b13a13e9e9c8cd44629ed919a6fee5f98c2753c84c766bdcdee4",
        "7b2b9a878747dd83a073d6eb9cba8bc236170b248867dbae9b376e6fcbf3cdf2412799eec36bc734d5ff6d3d5ee0599c",
        "67efa9ed37536db8a1ddf9072d96f277dd0c0000",
    );

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn inflate_container(data: &[u8]) -> Vec<u8> {
        let header_len = parse_gzip_header(data).unwrap();
        let end = data.len() - GZIP_TRAILER;
        let plain = inflate(&data[header_len..end], MAX_INFLATED).unwrap();
        assert_eq!(
            crc32(&plain),
            u32::from_le_bytes(data[end..end + 4].try_into().unwrap())
        );
        plain
    }

    fn count(hay: &[u8], needle: &[u8]) -> usize {
        hay.windows(needle.len()).filter(|w| *w == needle).count()
    }

    #[test]
    fn real_rds_replaces_built_stamps_only() {
        let mut data = hex(REAL_RDS_HEX);
        assert!(normalize_pkg_rds(&mut data, ANCHOR).unwrap());

        let plain = inflate_container(&data);
        assert_eq!(count(&plain, ANCHOR_STAMP), 2);
        assert_eq!(
            count(&plain, b"2024-11-19 13:44:13 UTC"),
            0,
            "旧时间戳必须清零"
        );

        assert_eq!(count(&plain, b"2022-01-16 11:35:42 UTC; jeroen"), 1);
        assert_eq!(count(&plain, b"2022-01-17 08:42:42 UTC"), 1);

        let built_tail: &[u8] = b"2026-10-08 11:29:12 UTC; unix";
        assert!(plain.windows(built_tail.len()).any(|w| w == built_tail));

        assert_eq!(&data[4..8], &(ANCHOR as u32).to_le_bytes());
    }

    #[test]
    fn real_rds_is_idempotent() {
        let mut data = hex(REAL_RDS_HEX);
        assert!(normalize_pkg_rds(&mut data, ANCHOR).unwrap());
        let once = data.clone();
        assert!(!normalize_pkg_rds(&mut data, ANCHOR).unwrap());
        assert_eq!(data, once);
    }

    #[test]
    fn corrupt_payload_is_abandoned() {
        let mut data = hex(REAL_RDS_HEX);
        let mid = data.len() / 2;
        data[mid] ^= 0xAA;
        let original = data.clone();
        assert!(normalize_pkg_rds(&mut data, ANCHOR).is_err());
        assert_eq!(data, original);
    }

    #[test]
    fn malformed_containers_are_rejected() {
        let mut data = hex(REAL_RDS_HEX);
        data.truncate(15);
        assert!(normalize_pkg_rds(&mut data, ANCHOR).is_err());

        let mut bad_magic = hex(REAL_RDS_HEX);
        bad_magic[0] = 0x1e;
        assert!(normalize_pkg_rds(&mut bad_magic, ANCHOR).is_err());

        let mut fhcrc = hex(REAL_RDS_HEX);
        fhcrc[3] |= 0x02;
        assert!(normalize_pkg_rds(&mut fhcrc, ANCHOR).is_err());

        let mut reserved = hex(REAL_RDS_HEX);
        reserved[3] |= 0x40;
        assert!(normalize_pkg_rds(&mut reserved, ANCHOR).is_err());
    }

    #[test]
    fn container_without_built_stamp_is_skipped() {
        let plain = b"X\n\x00\x00\x00\x03just some rds-ish bytes without dates";
        let mut data = gzip_container(plain);
        let original = data.clone();
        assert!(!normalize_pkg_rds(&mut data, ANCHOR).unwrap());
        assert_eq!(data, original);
    }

    #[test]
    fn fname_header_is_skipped() {
        let mut plain = b"R 4.4.1; x86_64-pc-linux-gnu; ".to_vec();
        plain.extend_from_slice(b"2030-01-02 03:04:05 UTC; unix");
        let mut data = Vec::new();
        data.extend_from_slice(&[0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3]);
        data.extend_from_slice(b"package.rds\0");
        data.extend_from_slice(&deflate_stored(&plain));
        data.extend_from_slice(&crc32(&plain).to_le_bytes());
        data.extend_from_slice(&(plain.len() as u32).to_le_bytes());

        assert!(normalize_pkg_rds(&mut data, ANCHOR).unwrap());
        let out = inflate_container(&data);
        assert!(out.windows(UTC_STAMP_LEN).any(|w| w == ANCHOR_STAMP));
        assert_eq!(count(&out, b"2030-01-02 03:04:05 UTC"), 0);
    }
}
