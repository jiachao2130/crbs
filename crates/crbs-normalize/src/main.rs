// Copyright (c) 2026 Jia Chao
// crbs is licensed under Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//          http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
// EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
// MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
// See the Mulan PSL v2 for more details.

//! 递归遍历 buildroot，把文件内嵌的时间戳统一替换为 --epoch 指定的值。单个文件
//! 解析失败时跳过并继续，只有用法错误才以非零码退出。

mod deflate;
mod dos;
mod formats;
mod rds;
mod text;

use std::path::{Path, PathBuf};

use formats::Format;

const USAGE: &str = "usage: crbs-normalize --root <BUILDROOT> --epoch <EPOCH_SECONDS>\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    epoch: i64,
}

#[derive(Debug)]
enum Parsed {
    Options(Options),
    Help,
    Error(String),
}

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

fn parse_args(args: &[String]) -> Parsed {
    let mut root: Option<PathBuf> = None;
    let mut epoch: Option<i64> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];

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
                let rel_path = path.strip_prefix(root).unwrap_or(path.as_path());
                if let Err(reason) = normalize_file(&path, rel_path, epoch) {
                    eprintln!("crbs-normalize: skipping {}: {reason}", path.display());
                }
            }
        }
    }
}

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

    fn ar_bytes() -> Vec<u8> {
        // ar 测试数据：头部的时间与属主字段为无效值，归一化应将其改写。
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

    fn gzip_bytes() -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0, 3];
        v.extend_from_slice(b"payload");
        v
    }

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

        let ar_after = std::fs::read(&ar_path).unwrap();
        assert_eq!(&ar_after[8 + 16..8 + 28], b"1791458952  ");
        assert_eq!(&ar_after[8 + 28..8 + 34], b"0     ");
        assert_eq!(&ar_after[8 + 34..8 + 40], b"0     ");

        let gz_after = std::fs::read(&gz_path).unwrap();
        assert_eq!(&gz_after[4..8], &1_791_458_952_u32.to_le_bytes());

        assert_eq!(
            std::fs::read(&plain).unwrap(),
            b"PK\x03\x04 lives in a story"
        );

        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let once = std::fs::read(&ar_path).unwrap();
        normalize_tree(root, 1_791_458_952);
        assert_eq!(std::fs::read(&ar_path).unwrap(), once);
    }

    #[test]
    fn malformed_file_is_preserved_and_does_not_stop_the_walk() {
        let tmp = TempRoot::new("malformed");
        let root = tmp.path();

        let mut bad = ar_bytes();
        bad[8 + 58] = b'X';
        std::fs::write(root.join("bad.a"), &bad).unwrap();
        std::fs::write(root.join("good.gz"), gzip_bytes()).unwrap();

        normalize_tree(root, 1_791_458_952);
        assert_eq!(std::fs::read(root.join("bad.a")).unwrap(), bad);
        let gz_after = std::fs::read(root.join("good.gz")).unwrap();
        assert_eq!(&gz_after[4..8], &1_791_458_952_u32.to_le_bytes());
    }

    #[test]
    fn already_normalized_file_is_not_rewritten() {
        let tmp = TempRoot::new("no-rewrite");
        let root = tmp.path();
        let gz_path = root.join("anchored.gz");

        let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        bytes[4..8].copy_from_slice(&1_791_458_952_u32.to_le_bytes());
        bytes.extend_from_slice(b"payload");
        std::fs::write(&gz_path, &bytes).unwrap();

        let before = std::fs::metadata(&gz_path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        normalize_tree(root, 1_791_458_952);

        assert_eq!(std::fs::read(&gz_path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&gz_path).unwrap().modified().unwrap(),
            before
        );
    }

    fn pkg_rds_bytes(built_stamp: &[u8; 23]) -> Vec<u8> {
        let mut plain = b"R 4.0.5; x86_64-cuos-linux-gnu; ".to_vec();
        plain.extend_from_slice(built_stamp);
        plain.extend_from_slice(b"; unix\x00 2022-01-17 08:42:42 UTC\x00");
        plain.extend_from_slice(built_stamp);
        crate::rds::gzip_container(&plain)
    }

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
