use std::path::Path;
use chrono::{DateTime, Utc};

pub mod digest;
pub mod format;
pub mod writer;

pub use digest::WarcDigest;
pub use format::{WarcHeader, WarcRecordType};
pub use writer::WarcWriterImpl;

#[derive(Debug, thiserror::Error)]
pub enum WarcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("format error: {0}")]
    Format(String),

    #[error("digest error: {0}")]
    Digest(String),

    #[error("file too large: {0} bytes")]
    FileTooLarge(u64),
}

pub type Result<T> = std::result::Result<T, WarcError>;

// 2026-09-08: trait WarcWriter 已删除（仅 WarcWriterImpl 一个 impl，
// 无 dyn 调用）。所有 write_* 方法现在是 WarcWriterImpl 的 inherent pub fn。

pub fn format_date(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn format_record_id() -> Result<String> {
    Ok(format!("<urn:uuid:{}>", generate_uuid_v4()?))
}

pub(crate) fn generate_uuid_v4() -> Result<String> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf)
        .map_err(|e| WarcError::Format(format!("failed to generate random bytes: {}", e)))?;
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5],
        buf[6], buf[7],
        buf[8], buf[9],
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ))
}
