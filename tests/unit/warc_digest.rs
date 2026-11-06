// WARC digest 模块单元测试
// 测试 SHA1 计算、digest update/finalize、已知向量验证

use ut_warc::*;

// ========== SHA1 基本计算测试 ==========

#[test]
fn test_compute_sha1_empty() {
    // 空输入的 SHA1 值
    let hash = digest::compute_sha1(b"");
    assert_eq!(hash, "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_compute_sha1_abc() {
    // 已知向量: SHA1("abc")
    let hash = digest::compute_sha1(b"abc");
    assert_eq!(hash, "sha1:a9993e364706816aba3e25717850c26c9cd0d89d");
}

#[test]
fn test_compute_sha1_hello_world() {
    // 已知向量: SHA1("hello world")
    let hash = digest::compute_sha1(b"hello world");
    assert_eq!(hash, "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn test_compute_sha1_format() {
    // 验证输出格式: sha1:前缀 + 40位十六进制
    let hash = digest::compute_sha1(b"test data");
    assert!(hash.starts_with("sha1:"), "hash should start with 'sha1:' prefix");
    let hex_part = &hash[5..];
    assert_eq!(hex_part.len(), 40, "hex part should be 40 characters");
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "hex part should only contain hex digits");
}

#[test]
fn test_compute_sha1_deterministic() {
    // 相同输入应产生相同输出
    let data = b"deterministic test";
    let hash1 = digest::compute_sha1(data);
    let hash2 = digest::compute_sha1(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_compute_sha1_large_input() {
    // 大数据测试
    let data = vec![0u8; 10000];
    let hash = digest::compute_sha1(&data);
    assert!(hash.starts_with("sha1:"));
    assert_eq!(hash.len(), 45); // "sha1:" (5) + hex (40)
}

#[test]
fn test_compute_sha1_different_inputs() {
    // 不同输入应产生不同输出
    let hash1 = digest::compute_sha1(b"input1");
    let hash2 = digest::compute_sha1(b"input2");
    assert_ne!(hash1, hash2);
}

// ========== WarcDigest 增量更新测试 ==========

#[test]
fn test_warc_digest_new() {
    // 创建新的 digest 实例
    let digest = WarcDigest::new();
    // 新实例的 finalize 应该等于空输入的 hash
    let result = digest.finalize();
    assert_eq!(result, "sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn test_warc_digest_update_single() {
    // 单次 update
    let mut digest = WarcDigest::new();
    digest.update(b"hello world");
    let result = digest.finalize();
    assert_eq!(result, "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn test_warc_digest_update_multiple() {
    // 多次 update 应该等于一次 update 合并后的结果
    let mut digest = WarcDigest::new();
    digest.update(b"hello ");
    digest.update(b"world");
    let result = digest.finalize();
    // 应该等于 SHA1("hello world")
    assert_eq!(result, "sha1:2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
}

#[test]
fn test_warc_digest_update_empty() {
    // update 空数据不应该改变结果
    let mut digest = WarcDigest::new();
    digest.update(b"test");
    digest.update(b"");
    let result = digest.finalize();
    assert_eq!(result, digest::compute_sha1(b"test"));
}

#[test]
fn test_warc_digest_update_chunks() {
    // 分块更新测试
    let data = b"abcdefghijklmnopqrstuvwxyz";
    let mut digest = WarcDigest::new();
    // 按 5 字节分块
    for chunk in data.chunks(5) {
        digest.update(chunk);
    }
    let result = digest.finalize();
    let expected = digest::compute_sha1(data);
    assert_eq!(result, expected);
}
