// FTP 目录列表解析单元测试

use ut_ftp::listing::{parse_listing, parse_unix_listing, parse_windows_listing, parse_vms_listing};
use chrono::{Datelike, Timelike};

// ========== UNIX 格式列表解析测试 ==========

#[test]
fn test_unix_listing_basic() {
    let raw = r#"drwxr-xr-x  2 owner group       4096 Jan 15 10:30 docs
-rw-r--r--  1 owner group     123456 Jan 15 10:31 file.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 2);

    // 第一个条目是目录
    assert_eq!(entries[0].name, "docs");
    assert!(entries[0].is_dir);
    assert_eq!(entries[0].size, Some(4096));
    assert!(entries[0].perms.is_some());
    assert_eq!(entries[0].perms.as_deref(), Some("drwxr-xr-x"));
    assert_eq!(entries[0].owner.as_deref(), Some("owner"));
    assert_eq!(entries[0].group.as_deref(), Some("group"));

    // 第二个条目是文件
    assert_eq!(entries[1].name, "file.txt");
    assert!(!entries[1].is_dir);
    assert_eq!(entries[1].size, Some(123456));
}

#[test]
fn test_unix_listing_with_symlink() {
    let raw = r#"lrwxrwxrwx  1 owner group          0 Jan 15 10:32 link.html -> index.html
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "link.html -> index.html");
    assert!(!entries[0].is_dir); // 符号链接以 'l' 开头，不是目录
}

#[test]
fn test_unix_listing_with_year() {
    let raw = r#"-rw-r--r--  1 owner group     1024 Jan 15 2023 oldfile.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "oldfile.txt");
    assert!(entries[0].date.is_some());
    let date = entries[0].date.unwrap();
    assert_eq!(date.year(), 2023);
    assert_eq!(date.month(), 1);
    assert_eq!(date.day(), 15);
}
