use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::digest::compute_sha1;
use crate::format::{default_content_type, record_separator, WarcHeader, WarcRecordType};
use crate::{format_date, format_record_id, generate_uuid_v4, Result, WarcError, WarcWriter};

/// WARC file writer implementation.
///
/// This struct manages writing WARC records to one or more WARC files,
/// handling file rotation when size limits are reached, optional gzip
/// compression, and CDX index generation.
///
/// # Features
///
/// - Automatic file rotation when `max_size` is exceeded
/// - Optional gzip compression for WARC files
/// - Optional SHA-1 digest computation for records
/// - Optional CDX index file generation
/// - Automatic `warcinfo` record at the start of each file
///
/// # Fields
///
/// * `file` - The current output file handle (may be gzip-compressed)
/// * `filename` - Path to the current WARC file
/// * `gzip_enabled` - Whether to compress output with gzip
/// * `digest_enabled` - Whether to compute block digests
/// * `tempdir` - Directory for temporary files
/// * `max_size` - Maximum file size before rotation (None = unlimited)
/// * `current_size` - Current file size in bytes
/// * `file_counter` - Counter for generating sequential file names
/// * `cdx_enabled` - Whether to generate CDX index files
/// * `cdx_entries` - Accumulated CDX index entries
/// * `base_path` - Base path for WARC file names
/// * `user_headers` - User-defined headers for warcinfo records
pub struct WarcWriterImpl {
    file: Option<Box<dyn Write + Send>>,
    filename: String,
    gzip_enabled: bool,
    digest_enabled: bool,
    tempdir: PathBuf,
    max_size: Option<u64>,
    current_size: u64,
    file_counter: u32,
    cdx_enabled: bool,
    cdx_entries: Vec<String>,
    base_path: PathBuf,
    user_headers: Vec<String>,
}
