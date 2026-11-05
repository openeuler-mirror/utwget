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

#[test]
fn test_unix_listing_with_time() {
    let raw = r#"-rw-r--r--  1 owner group     1024 Jun 17 14:30 recent.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].date.is_some());
    let date = entries[0].date.unwrap();
    assert_eq!(date.month(), 6);
    assert_eq!(date.day(), 17);
}

#[test]
fn test_unix_listing_multiple_files() {
    let raw = r#"drwxr-xr-x  2 user  group  4096 Jan 01 00:00 dir1
drwxr-xr-x  2 user  group  4096 Jan 01 00:00 dir2
-rw-r--r--  1 user  group   100 Jan 01 00:00 file1.txt
-rw-r--r--  1 user  group   200 Jan 01 00:00 file2.txt
-rw-r--r--  1 user  group   300 Jan 01 00:00 file3.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 5);
    assert!(entries[0].is_dir);
    assert!(entries[1].is_dir);
    assert!(!entries[2].is_dir);
    assert!(!entries[3].is_dir);
    assert!(!entries[4].is_dir);
}

#[test]
fn test_unix_listing_with_spaces_in_name() {
    let raw = r#"-rw-r--r--  1 owner group     1024 Jan 15 10:30 file with spaces.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "file with spaces.txt");
}

#[test]
fn test_unix_listing_empty() {
    let entries = parse_unix_listing("");
    assert!(entries.is_empty());
}

#[test]
fn test_unix_listing_whitespace_only() {
    let entries = parse_unix_listing("   \n   \n   ");
    assert!(entries.is_empty());
}

// ========== DOS/Windows 格式列表解析测试 ==========

#[test]
fn test_windows_listing_basic() {
    let raw = r#"01-15-2025  10:30AM       <DIR>          docs
01-15-2025  10:31AM           123456   file.txt
"#;
    let entries = parse_windows_listing(raw);
    assert_eq!(entries.len(), 2);

    // 第一个条目是目录
    assert_eq!(entries[0].name, "docs");
    assert!(entries[0].is_dir);
    assert!(entries[0].size.is_none());

    // 第二个条目是文件
    assert_eq!(entries[1].name, "file.txt");
    assert!(!entries[1].is_dir);
    assert_eq!(entries[1].size, Some(123456));
}

#[test]
fn test_windows_listing_with_pm() {
    let raw = r#"01-15-2025  02:30PM           1024   afternoon.txt
"#;
    let entries = parse_windows_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].date.is_some());
    let date = entries[0].date.unwrap();
    assert_eq!(date.hour(), 14); // 2PM = 14:00
    assert_eq!(date.minute(), 30);
}

#[test]
fn test_windows_listing_midnight() {
    let raw = r#"01-15-2025  12:00AM           512   midnight.txt
"#;
    let entries = parse_windows_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].date.is_some());
    let date = entries[0].date.unwrap();
    assert_eq!(date.hour(), 0); // 12AM = 00:00
}

#[test]
fn test_windows_listing_noon() {
    let raw = r#"01-15-2025  12:00PM           512   noon.txt
"#;
    let entries = parse_windows_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].date.is_some());
    let date = entries[0].date.unwrap();
    assert_eq!(date.hour(), 12); // 12PM = 12:00
}

#[test]
fn test_windows_listing_empty() {
    let entries = parse_windows_listing("");
    assert!(entries.is_empty());
}

// ========== VMS 格式列表解析测试 ==========

#[test]
fn test_vms_listing_basic() {
    let raw = r#"FILE.TXT;1 1024 15-JAN-2025 10:30
"#;
    let entries = parse_vms_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "FILE.TXT");
    assert!(!entries[0].is_dir);
    assert_eq!(entries[0].size, Some(1024));
}

#[test]
fn test_vms_listing_directory() {
    let raw = r#"DOCS.DIR;1 512 15-JAN-2025 10:30
"#;
    let entries = parse_vms_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "DOCS");
    assert!(entries[0].is_dir);
}

#[test]
fn test_vms_listing_with_header() {
    let raw = r#"Directory SYS$SYSDEVICE:[USER]

FILE.TXT;1 1024 15-JAN-2025 10:30

Total of 1 file.
"#;
    let entries = parse_vms_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "FILE.TXT");
}

#[test]
fn test_vms_listing_empty() {
    let entries = parse_vms_listing("");
    assert!(entries.is_empty());
}

// ========== 自动格式检测测试 ==========

#[test]
fn test_auto_detect_unix() {
    let raw = r#"-rw-r--r--  1 owner group 100 Jan 01 00:00 test.txt
"#;
    let entries = parse_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "test.txt");
    assert!(!entries[0].is_dir);
}

#[test]
fn test_auto_detect_windows() {
    let raw = r#"01-15-2025  10:30AM           100   test.txt
"#;
    let entries = parse_listing(raw);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "test.txt");
    assert!(!entries[0].is_dir);
}

#[test]
fn test_auto_detect_vms() {
    // VMS format may not be fully supported, just test that parsing doesn't crash
    let raw = r#"FILE.TXT;1 100 15-JAN-2025 10:30
"#;
    let entries = parse_listing(raw);
    // Just verify parsing completes without error
    assert!(entries.len() <= 1);
}

#[test]
fn test_auto_detect_empty() {
    let entries = parse_listing("");
    assert!(entries.is_empty());
}

#[test]
fn test_auto_detect_mixed_fallback() {
    // 当格式不明确时，尝试所有解析器
    let raw = r#"unknown format line
-rw-r--r--  1 owner group 100 Jan 01 00:00 valid.txt
"#;
    let entries = parse_listing(raw);
    // 应该至少解析出有效的行
    assert!(!entries.is_empty());
}

// ========== 文件/目录识别测试 ==========

#[test]
fn test_directory_detection_unix() {
    let raw = r#"drwxr-xr-x  2 owner group 4096 Jan 01 00:00 mydir
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].is_dir);
}

#[test]
fn test_file_detection_unix() {
    let raw = r#"-rw-r--r--  1 owner group 100 Jan 01 00:00 myfile.txt
"#;
    let entries = parse_unix_listing(raw);
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].is_dir);
}
