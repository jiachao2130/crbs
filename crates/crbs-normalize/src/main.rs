// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! crbs-normalize：构建后内容归一化 helper。递归遍历 buildroot，把 ar 成员
//! 头时间与属主字段、zip（jar）、gzip 内嵌时间戳，以及路径键控的 R DESCRIPTION
//! Built 行、R Meta/package.rds 内容、javadoc 生成 HTML 内嵌时间就地统一到
//! 构建锚，消除"改内容碰脏内嵌时间/凭据"的回放噪声；由 rpmbuild
//! install-post 链在沙箱内调用（宏体见 crbs-core 的 crbs_normalize_payload）。
//! 退出码仅用法错误非零——文件级解析失败按"放弃 + stderr 提示"处理仍返回
//! 0（保守跳过是设计行为）。

mod deflate;
mod dos;
mod formats;
mod rds;
mod text;

use std::path::{Path, PathBuf};

use formats::Format;

const USAGE: &str = "usage: crbs-normalize --root <BUILDROOT> --epoch <EPOCH_SECONDS>\n";

/// CLI 参数集。
#[derive(Debug)]
struct Options {
    root: PathBuf,
    epoch: i64,
}

/// 参数解析结果：--help 走 stdout 退出 0，其余错误走 stderr 退出 2。
#[derive(Debug)]
enum Parsed {
    Options(Options),
    Help,
    Error(String),
}

/// 取 `--flag <值>` / `--flag=<值>` 的值；缺值即用法错误。
/// 返回 (值, 消费掉的 argv 个数)：内联 1 个、分离 2 个。
fn flag_value(
    name: &str,
    inline: Option<&str>,
    next: Option<&String>,
) -> Result<(String, usize), String> {
    match inline {
        Some(v) => Ok((v.to_string(), 1)),
        None => match next {
            Some(v) => Ok((v.clone(), 2)),
            None => Err(format!("missing value for {name}")),
        },
    }
}

/// 解析 `--root <p>` / `--root=<p>` / `--epoch <n>` / `--epoch=<n>`；
/// 未知参数、缺值、重复项、非法整数均为用法错误。
fn parse_args(args: &[String]) -> Parsed {
    let mut root: Option<PathBuf> = None;
    let mut epoch: Option<i64> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        // `--flag=value` 内联形式拆键值；非 -- 前缀一律视为位置参数报错
        let (name, inline): (&str, Option<&str>) = match arg.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v)),
            _ => (arg.as_str(), None),
        };
        match name {
            "--help" | "-h" => return Parsed::Help,
            "--root" => {
                if root.is_some() {
                    return Parsed::Error("--root given more than once".to_string());
                }
                let (value, used) = match flag_value("--root", inline, args.get(index + 1)) {
                    Ok(v) => v,
                    Err(e) => return Parsed::Error(e),
                };
                if value.is_empty() {
                    return Parsed::Error("--root must not be empty".to_string());
                }
                root = Some(PathBuf::from(value));
                index += used;
            }
            "--epoch" => {
                if epoch.is_some() {
                    return Parsed::Error("--epoch given more than once".to_string());
                }
                let (value, used) = match flag_value("--epoch", inline, args.get(index + 1)) {
                    Ok(v) => v,
                    Err(e) => return Parsed::Error(e),
                };
                match value.parse::<i64>() {
                    Ok(e) => epoch = Some(e),
                    Err(_) => {
                        return Parsed::Error(format!(
                            "--epoch expects an i64 epoch-seconds value, got {value:?}"
                        ));
                    }
                }
                index += used;
            }
            other => {
                return Parsed::Error(format!(
                    "unexpected argument {other:?} (positional input is not accepted)"
                ));
            }
        }
    }
    match (root, epoch) {
        (Some(root), Some(epoch)) => Parsed::Options(Options { root, epoch }),
        (None, _) => Parsed::Error("--root is required".to_string()),
        (_, None) => Parsed::Error("--epoch is required".to_string()),
    }
}

/// 遍历 `root` 下全部常规文件：symlink 不跟随不处理、目录递归、其余类型
/// 跳过。按 (magic, buildroot 相对路径) 双因子识别的文件做内容归一化；不
/// 可读目录/条目与识别失败的文件按"放弃 + stderr 一行提示"继续，不中断
/// 遍历（恒成功返回）。
fn normalize_tree(root: &Path, epoch: i64) {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "crbs-normalize: skipping unreadable directory {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!(
                        "crbs-normalize: skipping unreadable entry under {}: {e}",
                        dir.display()
                    );
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("crbs-normalize: skipping {}: {e}", path.display());
                    continue;
                }
            };
            if file_type.is_dir() {
                dirs.push(path);
            } else if file_type.is_file() {
                // 路径因子用 buildroot 相对路径；walk 起点必为 root，兜底
                // 回落全路径（键控只用文件名/父目录/扩展名，仍正确）
                let rel_path = path.strip_prefix(root).unwrap_or(path.as_path());
                if let Err(reason) = normalize_file(&path, rel_path, epoch) {
                    eprintln!("crbs-normalize: skipping {}: {reason}", path.display());
                }
            }
            // symlink（含指向目录的链接）不跟随：归一化只作用于 buildroot
            // 内由本次构建产生的常规文件，链接外的目标一律不触碰
        }
    }
}

/// 单文件归一化：读入 → 识别 → 内存改写（允许变长/重编码）→ 有变化才写
/// 回（未变化的文件 mtime 保持原样，幂等重跑零写放大）。非匹配格式静默
/// 跳过；识别成功但解析失败才回报错误（调用方 stderr 提示，内存残改不落
/// 盘——handler 返回 Err 时 `data` 的中间态不会写回）。
fn normalize_file(path: &Path, rel_path: &Path, epoch: i64) -> Result<(), String> {
    let mut data = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let Some(format) = Format::detect(&data, rel_path) else {
        return Ok(());
    };
    if format.normalize(&mut data, epoch)? {
        std::fs::write(path, &data).map_err(|e| format!("write: {e}"))?;
    }
    Ok(())
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let opts = match parse_args(&argv) {
        Parsed::Help => {
            print!("{USAGE}");
            return;
        }
        Parsed::Error(message) => {
            eprintln!("crbs-normalize: {message}");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
        Parsed::Options(opts) => opts,
    };
    // 根目录必须存在且为目录（环境错误而非文件级跳过，按用法错误退出）
    match std::fs::metadata(&opts.root) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            eprintln!(
                "crbs-normalize: --root {} is not a directory",
                opts.root.display()
            );
            eprint!("{USAGE}");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!(
                "crbs-normalize: cannot access --root {}: {e}",
                opts.root.display()
            );
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
    normalize_tree(&opts.root, opts.epoch);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 进程唯一临时目录（零依赖：pid + 纳秒命名，测试尾清理）。
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> TempRoot {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "crbs-normalize-test-{}-{}-{tag}",
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&path).unwrap();
            TempRoot(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn strs(argv: &[&str]) -> Vec<String> {
        argv.iter().map(|s| s.to_string()).collect()
    }

    /// 用法解析：正常对、--flag=value 形式、缺参、缺值、重复、非法整数、
    /// 空路径、位置参数均落对应分支；--help/-h 走 Help。
    #[test]
    fn parse_args_covers_conventional_forms() {
        let outcome = |argv: &[&str]| parse_args(&strs(argv));
        match outcome(&["--root", "/tmp/broot", "--epoch", "42"]) {
            Parsed::Options(o) => {
                assert_eq!(o.root, PathBuf::from("/tmp/broot"));
                assert_eq!(o.epoch, 42);
            }
            other => panic!("expected options, got {other:?}"),
        }
        match outcome(&["--root=/tmp/x", "--epoch=-7"]) {
            Parsed::Options(o) => {
                assert_eq!(o.root, PathBuf::from("/tmp/x"));
                assert_eq!(o.epoch, -7);
            }
            other => panic!("expected options, got {other:?}"),
        }

        for bad in [
            vec!["--epoch", "1"],
            vec!["--root", "/tmp/x"],
            vec!["--root"],
            vec!["--epoch"],
            vec!["--root", "/a", "--epoch", "1", "--epoch", "2"],
            vec!["--root", "/a", "--root", "/b", "--epoch", "1"],
            vec!["--root", "/a", "--epoch", "abc"],
            vec!["--root", "", "--epoch", "1"],
            vec!["stray"],
            vec!["--root", "/a", "--epoch", "1", "stray"],
        ] {
            assert!(
                matches!(outcome(&bad), Parsed::Error(_)),
                "expected usage error for {bad:?}"
            );
        }
        assert!(matches!(outcome(&["--help"]), Parsed::Help));
        assert!(matches!(outcome(&["-h"]), Parsed::Help));
    }

    /// ar 夹具（与 formats::tests 同构布局，mtime/uid/gid 字段为垃圾值）。
    fn ar_bytes() -> Vec<u8> {
        let mut v = b"!<arch>\n".to_vec();
        v.extend_from_slice(b"member.txt/     ");
        v.extend_from_slice(b"9999999999  ");
        v.extend_from_slice(b"987   ");
        v.extend_from_slice(b"989   ");
        v.extend_from_slice(b"100644  ");
        v.extend_from_slice(b"5         ");
        v.extend_from_slice(b"`\n");
        v.extend_from_slice(b"hello\n");
        v
    }

    /// gzip 夹具：头 10 字节 + 尾部负载。
    fn gzip_bytes() -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0, 3];
        v.extend_from_slice(b"payload");
        v
    }

    /// 端到端遍历：子目录内 ar/gzip 归一化到锚值，symlink 与非匹配文件
    /// 原字节不触碰；再次运行幂等（无新增改写）。
    #[test]
    fn tree_walk_normalizes_matching_files_and_skips_others() {
        let tmp = TempRoot::new("walk");
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();

        let ar_path = root.join("lib.a");
        std::fs::write(&ar_path, ar_bytes()).unwrap();
        let gz_path = root.join("sub/deeper/data.gz");
        std::fs::write(&gz_path, gzip_bytes()).unwrap();

        let plain = root.join("notes.txt");
        std::fs::write(&plain, b"PK\x03\x04 lives in a story").unwrap();

        let link = root.join("link.a");
        std::os::unix::fs::symlink(&ar_path, &link).unwrap();

        normalize_tree(root, 1_791_458_952);

        // ar：mtime 字段 = epoch 十进制左对齐空格填充，uid/gid = 固定 0
        let ar_after = std::fs::read(&ar_path).unwrap();
        assert_eq!(&ar_after[8 + 16..8 + 28], b"1791458952  ");
        assert_eq!(&ar_after[8 + 28..8 + 34], b"0     ");
        assert_eq!(&ar_after[8 + 34..8 + 40], b"0     ");
        // gzip：4..8 = epoch LE
        let gz_after = std::fs::read(&gz_path).unwrap();
        assert_eq!(&gz_after[4..8], &1_791_458_952_u32.to_le_bytes());
        // 非匹配文件原样
        assert_eq!(
            std::fs::read(&plain).unwrap(),
            b"PK\x03\x04 lives in a story"
        );
        // symlink 自身仍是链接，目标文件未被经链接二次处理
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let once = std::fs::read(&ar_path).unwrap();
        normalize_tree(root, 1_791_458_952);
        assert_eq!(std::fs::read(&ar_path).unwrap(), once);
    }

    /// 畸形文件（识别出 ar 但成员头损坏）不阻断遍历：文件原样保留，
    /// 其余文件照常处理。
    #[test]
    fn malformed_file_is_preserved_and_does_not_stop_the_walk() {
        let tmp = TempRoot::new("malformed");
        let root = tmp.path();

        let mut bad = ar_bytes();
        bad[8 + 58] = b'X'; // 破坏成员 end magic
        std::fs::write(root.join("bad.a"), &bad).unwrap();
        std::fs::write(root.join("good.gz"), gzip_bytes()).unwrap();

        normalize_tree(root, 1_791_458_952);
        assert_eq!(std::fs::read(root.join("bad.a")).unwrap(), bad);
        let gz_after = std::fs::read(root.join("good.gz")).unwrap();
        assert_eq!(&gz_after[4..8], &1_791_458_952_u32.to_le_bytes());
    }

    /// 已在锚值上的文件不写回：外层 mtime 保持原样（幂等重跑零写放大）。
    #[test]
    fn already_normalized_file_is_not_rewritten() {
        let tmp = TempRoot::new("no-rewrite");
        let root = tmp.path();
        let gz_path = root.join("anchored.gz");
        // gzip 夹具 mtime 字段预置 = 锚值（LE）
        let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        bytes[4..8].copy_from_slice(&1_791_458_952_u32.to_le_bytes());
        bytes.extend_from_slice(b"payload");
        std::fs::write(&gz_path, &bytes).unwrap();

        // 基线 mtime 落定后稍候，若发生写回 mtime 必然前移
        let before = std::fs::metadata(&gz_path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        normalize_tree(root, 1_791_458_952);

        assert_eq!(std::fs::read(&gz_path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&gz_path).unwrap().modified().unwrap(),
            before
        );
    }

    /// 手搓 package.rds 夹具：内嵌 Built 墙钟戳两处 + 同格式源元数据日期一处。
    fn pkg_rds_bytes(built_stamp: &[u8; 23]) -> Vec<u8> {
        let mut plain = b"R 4.0.5; x86_64-cuos-linux-gnu; ".to_vec();
        plain.extend_from_slice(built_stamp);
        plain.extend_from_slice(b"; unix\x00 2022-01-17 08:42:42 UTC\x00");
        plain.extend_from_slice(built_stamp);
        crate::rds::gzip_container(&plain)
    }

    /// 端到端：路径键控三类（DESCRIPTION / Meta/package.rds / .html）归一到
    /// 锚；扩展名不符的同标记文本与无 Built 行的 DESCRIPTION 不触碰；二次
    /// 运行整树幂等。
    #[test]
    fn tree_walk_normalizes_path_keyed_handlers() {
        let tmp = TempRoot::new("path-keyed");
        let root = tmp.path();
        let built_stamp: &[u8; 23] = b"2026-10-11 07:11:17 UTC";

        let desc_path = root.join("usr/lib64/R/library/jsonlite/DESCRIPTION");
        std::fs::create_dir_all(desc_path.parent().unwrap()).unwrap();
        std::fs::write(
            &desc_path,
            b"Package: jsonlite\nDate/Publication: 2022-01-17 08:42:42 UTC\nBuilt: R 4.0.5; x86_64-cuos-linux-gnu; 2026-10-11 07:11:17 UTC; unix\n",
        )
        .unwrap();

        let rds_path = root.join("usr/lib64/R/library/jsonlite/Meta/package.rds");
        std::fs::create_dir_all(rds_path.parent().unwrap()).unwrap();
        std::fs::write(&rds_path, pkg_rds_bytes(built_stamp)).unwrap();

        let html_path = root.join("usr/share/javadoc/aalto/allclasses-frame.html");
        std::fs::create_dir_all(html_path.parent().unwrap()).unwrap();
        std::fs::write(
            &html_path,
            b"<!DOCTYPE HTML>\n<!-- Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 -->\n",
        )
        .unwrap();

        let stray_path = root.join("usr/share/doc/notes.txt");
        std::fs::create_dir_all(stray_path.parent().unwrap()).unwrap();
        std::fs::write(
            &stray_path,
            b"prose quoting Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 --> stays",
        )
        .unwrap();

        let plain_desc_path = root.join("opt/DESCRIPTION");
        std::fs::create_dir_all(plain_desc_path.parent().unwrap()).unwrap();
        std::fs::write(&plain_desc_path, b"Package: foo\n").unwrap();

        normalize_tree(root, 1_791_458_952);

        let desc = std::fs::read(&desc_path).unwrap();
        let desc_text = std::str::from_utf8(&desc).unwrap();
        assert!(desc_text
            .contains("Built: R 4.0.5; x86_64-cuos-linux-gnu; 2026-10-08 11:29:12 UTC; unix"));
        assert!(desc_text.contains("Date/Publication: 2022-01-17 08:42:42 UTC"));

        let rds = std::fs::read(&rds_path).unwrap();
        let plain =
            String::from_utf8(deflate::inflate(&rds[10..rds.len() - 8], 1 << 20).unwrap()).unwrap();
        assert_eq!(plain.matches("2026-10-08 11:29:12 UTC").count(), 2);
        assert!(!plain.contains("2026-10-11 07:11:17 UTC"));
        assert!(plain.contains("2022-01-17 08:42:42 UTC"));
        assert_eq!(&rds[4..8], &1_791_458_952_u32.to_le_bytes());

        let html = String::from_utf8(std::fs::read(&html_path).unwrap()).unwrap();
        assert!(html.contains("on 2026-10-08 11:29:12 UTC -->"));
        assert!(!html.contains("CST"));

        assert_eq!(
            std::fs::read(&stray_path).unwrap(),
            b"prose quoting Generated by javadoc (1.8.0_462) on Sun Oct 11 15:04:49 CST 2026 --> stays".as_slice()
        );
        assert_eq!(std::fs::read(&plain_desc_path).unwrap(), b"Package: foo\n");

        // 幂等：整树二次运行字节零变化
        let snapshot: Vec<(PathBuf, Vec<u8>)> = [desc_path, rds_path, html_path]
            .iter()
            .map(|p| (p.clone(), std::fs::read(p).unwrap()))
            .collect();
        normalize_tree(root, 1_791_458_952);
        for (p, once) in snapshot {
            assert_eq!(std::fs::read(&p).unwrap(), once, "幂等被破坏: {p:?}");
        }
    }
}
