//! Security tests for Metalink checksum verification (report §7.2 M3).
//!
//! MD5/SHA-1 are collision-broken. When a metalink ships both weak and
//! strong hashes, a weak-hash PASS must never override a strong-hash FAIL
//! (a poisoned mirror can forge md5/sha1, not sha256).

use std::io::Write;
use std::path::PathBuf;

use ut_metalink::checksum::{ChecksumType, FileChecksum};
use ut_metalink::downloader::MetalinkDownloader;
use ut_metalink::parser::MetalinkFile;

fn temp_file(content: &[u8], name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("ml_sec_{}_{}", std::process::id(), name));
    let mut f = std::fs::File::create(&p).expect("create temp file");
    f.write_all(content).expect("write temp file");
    p
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let h = sha2::Sha256::digest(data);
    h.iter().map(|b| format!("{:02x}", b)).collect()
}

fn md5_hex(data: &[u8]) -> String {
    use md5::Digest;
    let h = md5::Md5::digest(data);
    h.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn weak_hash_pass_never_overrides_strong_hash_fail() {
    // Real content: valid sha256, forged md5 (attacker-crafted collision for
    // different content). The metalink expects both; the file matches the
    // weak hash but not the strong one → verification must FAIL.
    let real = b"legitimate payload";
    let forged = b"attacker payload";

    let file = MetalinkFile {
        name: "f".into(),
        size: None,
        hashes: vec![
            FileChecksum { hash_type: ChecksumType::Md5, expected: md5_hex(forged) },
            FileChecksum { hash_type: ChecksumType::Sha256, expected: sha256_hex(real) },
        ],
        pieces: vec![],
        resources: vec![],
        identity: None,
        version: None,
        description: None,
    };
    let path = temp_file(forged, "weak_pass_strong_fail");
    let dl = MetalinkDownloader::new(|_url: &str, _out: &std::path::Path| Ok(()));
    let ok = dl.verify_file(&file, &path).expect("verify");
    std::fs::remove_file(&path).ok();
    assert!(!ok, "weak (md5) PASS must not override strong (sha256) FAIL");
}

#[test]
fn strong_hash_pass_accepts_despite_weak_hash_fail() {
    // Both hashes shipped, file matches sha256 but the md5 line is stale.
    // Verification must PASS (strong hash is authoritative); the weak
    // mismatch is logged only.
    let real = b"legitimate payload";

    let file = MetalinkFile {
        name: "f".into(),
        size: None,
        hashes: vec![
            FileChecksum { hash_type: ChecksumType::Md5, expected: md5_hex(b"stale") },
            FileChecksum { hash_type: ChecksumType::Sha256, expected: sha256_hex(real) },
        ],
        pieces: vec![],
        resources: vec![],
        identity: None,
        version: None,
        description: None,
    };
    let path = temp_file(real, "weak_fail_strong_pass");
    let dl = MetalinkDownloader::new(|_url: &str, _out: &std::path::Path| Ok(()));
    let ok = dl.verify_file(&file, &path).expect("verify");
    std::fs::remove_file(&path).ok();
    assert!(ok, "strong (sha256) PASS is authoritative over weak mismatch");
}

#[test]
fn weak_only_mismatch_still_fails() {
    // Only md5 shipped and it fails — no better option available, the
    // failure must be respected.
    let file = MetalinkFile {
        name: "f".into(),
        size: None,
        hashes: vec![
            FileChecksum { hash_type: ChecksumType::Md5, expected: md5_hex(b"expected") },
        ],
        pieces: vec![],
        resources: vec![],
        identity: None,
        version: None,
        description: None,
    };
    let path = temp_file(b"actual", "weak_only_fail");
    let dl = MetalinkDownloader::new(|_url: &str, _out: &std::path::Path| Ok(()));
    let ok = dl.verify_file(&file, &path).expect("verify");
    std::fs::remove_file(&path).ok();
    assert!(!ok);
}
