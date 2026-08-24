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
