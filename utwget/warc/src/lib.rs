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

pub trait WarcWriter: Send {
    fn write_request(
        &mut self,
        url: &str,
        method: &str,
        headers: &[u8],
        body: &[u8],
        date: DateTime<Utc>,
    ) -> Result<()>;

    fn write_response(
        &mut self,
        url: &str,
        status_code: u16,
        headers: &[u8],
        body: &[u8],
        content_type: &str,
        date: DateTime<Utc>,
    ) -> Result<()>;

    fn write_resource(
        &mut self,
        url: &str,
        content_type: &str,
        body: &[u8],
        date: DateTime<Utc>,
    ) -> Result<()>;

    fn write_metadata(
        &mut self,
        url: &str,
        metadata: &str,
        concurrent_to: &[String],
        date: DateTime<Utc>,
    ) -> Result<()>;

    fn create_temp_file(&mut self) -> Result<(Box<dyn std::io::Write + Send>, std::path::PathBuf)>;

    fn finalize_temp_file(
        &mut self,
        temp_path: &Path,
        url: &str,
        content_type: &str,
        date: DateTime<Utc>,
        digest_enabled: bool,
    ) -> Result<()>;

    fn uuid(&self) -> String;

    fn timestamp(&self) -> String;

    fn open(&mut self, prefix: &str) -> Result<()>;

    fn close(&mut self) -> Result<()>;
}
