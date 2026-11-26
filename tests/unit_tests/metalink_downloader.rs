//! Unit tests for Metalink downloader — path traversal protection.
//!
//! Tests `sanitize_metalink_filename()` which prevents arbitrary file
//! writes via crafted `<file name="...">` attributes in Metalink
//! documents (CVE-equivalent to GNU wget's `metalink_check_safe_path`).

use ut_metalink::downloader::sanitize_metalink_filename;

#[test]
fn test_normal_name_unchanged() {
    assert_eq!(sanitize_metalink_filename("file.iso"), "file.iso");
    assert_eq!(
        sanitize_metalink_filename("dir/file.iso"),
        "dir/file.iso",
    );
}

#[test]
fn test_strips_leading_slash() {
    // 绝对路径应被剥离前导斜杠，防止写入任意绝对位置
    assert_eq!(sanitize_metalink_filename("/etc/passwd"), "etc/passwd");
    assert_eq!(sanitize_metalink_filename("//etc/passwd"), "etc/passwd");
}

#[test]
fn test_rejects_parent_traversal() {
    // `..` 组件应被丢弃，防止逃逸 output_dir
    assert_eq!(
        sanitize_metalink_filename("../../etc/cron.d/evil"),
        "etc/cron.d/evil",
    );
    assert_eq!(
        sanitize_metalink_filename("../../../etc/passwd"),
        "etc/passwd",
    );
}

#[test]
fn test_rejects_backslash_traversal() {
    // 反斜杠（Windows 分隔符）也应被处理
    assert_eq!(sanitize_metalink_filename("..\\..\\evil"), "evil");
}

#[test]
fn test_empty_name_fallback() {
    assert_eq!(sanitize_metalink_filename(""), "unnamed");
    assert_eq!(sanitize_metalink_filename("/"), "unnamed");
    assert_eq!(sanitize_metalink_filename("///"), "unnamed");
    assert_eq!(sanitize_metalink_filename(".."), "unnamed");
    assert_eq!(sanitize_metalink_filename("../.."), "unnamed");
}

#[test]
fn test_strips_dot_components() {
    assert_eq!(sanitize_metalink_filename("./file.iso"), "file.iso");
    assert_eq!(
        sanitize_metalink_filename("dir/./file.iso"),
        "dir/file.iso",
    );
}

// ============================================================================
// Mirror fallback (report 8.2-1)
// ============================================================================

#[test]
fn mirror_fallback_tries_next_on_checksum_failure() {
    use std::path::PathBuf;
    use ut_metalink::checksum::{ChecksumType, FileChecksum};
    use ut_metalink::downloader::MetalinkDownloader;
    use ut_metalink::parser::{MetalinkFile, MetalinkResource};

    // Mirror 1 serves BAD content; mirror 2 serves GOOD content. The
    // sha256 matches only the good content. Download must succeed via
    // mirror 2 after mirror 1's checksum failure.
    let good = b"good content";
    use sha2::Digest;
    let good_sha = sha2::Sha256::digest(good)
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let served = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let served2 = served.clone();

    let dl = MetalinkDownloader::new(move |url: &str, out: &std::path::Path| {
        served2.lock().unwrap().push(url.to_string());
        let content: &[u8] = if url.contains("mirror1") { b"bad" } else { good };
        std::fs::write(out, content).map_err(ut_metalink::MetalinkError::Io)
    });

    let file = MetalinkFile {
        name: "f.bin".into(),
        size: None,
        hashes: vec![FileChecksum {
            hash_type: ChecksumType::Sha256,
            expected: good_sha,
        }],
        pieces: vec![],
        resources: vec![
            MetalinkResource { url: "http://mirror1/f.bin".into(), type_: None, preference: Some(100), max_connections: None, location: None },
            MetalinkResource { url: "http://mirror2/f.bin".into(), type_: None, preference: Some(50), max_connections: None, location: None },
        ],
        identity: None,
        version: None,
        description: None,
    };

    let dir = std::env::temp_dir().join(format!("ml_fb_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let result = dl.download(&file, &dir).expect("download must succeed via mirror2");
    assert_eq!(
        *served.lock().unwrap(),
        vec!["http://mirror1/f.bin".to_string(), "http://mirror2/f.bin".to_string()],
        "both mirrors must be tried in order"
    );
    assert!(result.checksum_verified);
    let _ = std::fs::remove_dir_all(&dir);
}
