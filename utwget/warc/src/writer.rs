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

impl WarcWriterImpl {
    /// Creates a new WARC writer with standard options.
    ///
    /// This constructor creates a WARC writer with default settings:
    /// - System temp directory for temporary files
    /// - No user-defined headers in warcinfo records
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base path for the WARC file (extension will be added)
    /// * `gzip_enabled` - Whether to compress the WARC file with gzip
    /// * `digest_enabled` - Whether to compute SHA-1 digests for records
    /// * `max_size` - Maximum file size in bytes before rotation (None = unlimited)
    /// * `cdx_enabled` - Whether to generate CDX index files
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `WarcWriterImpl` on success,
    /// or a `WarcError` if the file cannot be created.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the WARC file cannot be created.
    pub fn new(
        base_path: PathBuf,
        gzip_enabled: bool,
        digest_enabled: bool,
        max_size: Option<u64>,
        cdx_enabled: bool,
    ) -> Result<Self> {
        Self::with_options(
            base_path,
            gzip_enabled,
            digest_enabled,
            max_size,
            cdx_enabled,
            None,
            Vec::new(),
        )
    }

    /// Creates a new WARC writer with all options.
    ///
    /// This is the full constructor that allows specifying all configuration
    /// options including custom temp directory and user-defined headers.
    ///
    /// # Arguments
    ///
    /// * `base_path` - Base path for the WARC file (extension will be added)
    /// * `gzip_enabled` - Whether to compress the WARC file with gzip
    /// * `digest_enabled` - Whether to compute SHA-1 digests for records
    /// * `max_size` - Maximum file size in bytes before rotation (None = unlimited)
    /// * `cdx_enabled` - Whether to generate CDX index files
    /// * `tempdir` - Custom temp directory for temporary files (None = system default)
    /// * `user_headers` - User-defined headers to include in warcinfo records
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `WarcWriterImpl` on success,
    /// or a `WarcError` if the file cannot be created.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the WARC file cannot be created.
    pub fn with_options(
        base_path: PathBuf,
        gzip_enabled: bool,
        digest_enabled: bool,
        max_size: Option<u64>,
        cdx_enabled: bool,
        tempdir: Option<PathBuf>,
        user_headers: Vec<String>,
    ) -> Result<Self> {
        let tempdir = tempdir.unwrap_or_else(std::env::temp_dir);
        let mut writer = WarcWriterImpl {
            file: None,
            filename: String::new(),
            gzip_enabled,
            digest_enabled,
            tempdir,
            max_size,
            current_size: 0,
            file_counter: 0,
            cdx_enabled,
            cdx_entries: Vec::new(),
            base_path,
            user_headers,
        };
        writer.open_file()?;
        Ok(writer)
    }

    /// Opens a new WARC file for writing.
    ///
    /// Increments the file counter and creates a new file with the appropriate
    /// name and extension. If gzip is enabled, wraps the file in a GzEncoder.
    /// Writes the warcinfo record as the first record in the file.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the file cannot be created.
    fn open_file(&mut self) -> Result<()> {
        self.file_counter += 1;
        let ext = if self.gzip_enabled { ".warc.gz" } else { ".warc" };
        let stem = self
            .base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wget");
        let parent = self
            .base_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let name = if self.file_counter == 1 {
            format!("{}{}", stem, ext)
        } else {
            format!("{}_{:03}{}", stem, self.file_counter - 1, ext)
        };

        let path = parent.join(&name);
        self.filename = path.to_string_lossy().to_string();

        let raw = File::create(&path).map_err(WarcError::Io)?;
        let boxed: Box<dyn Write + Send> = if self.gzip_enabled {
            Box::new(GzEncoder::new(raw, Compression::default()))
        } else {
            Box::new(raw)
        };

        self.file = Some(boxed);
        self.current_size = 0;

        if self.file_counter == 1 {
            self.write_warcinfo()?;
        }

        Ok(())
    }

    /// Writes a warcinfo record to the current WARC file.
    ///
    /// The warcinfo record contains metadata about the WARC file including
    /// software version, format specification, and any user-defined headers.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_warcinfo(&mut self) -> Result<()> {
        let now = Utc::now();
        let mut body = format!(
            "software: wget-rs/0.1.0\r\n\
             format: WARC File Format 1.1\r\n\
             isPartOf: <urn:uuid:{}>\r\n",
            generate_uuid_v4()
        );
        // Add user-defined headers
        for user_header in &self.user_headers {
            body.push_str(user_header);
            body.push_str("\r\n");
        }
        let body_bytes = body.as_bytes();
        let content = if self.gzip_enabled {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(body_bytes).map_err(WarcError::Io)?;
            encoder.finish().map_err(WarcError::Io)?
        } else {
            body_bytes.to_vec()
        };

        let header = WarcHeader {
            record_type: WarcRecordType::Warcinfo,
            record_id: format_record_id(),
            date: format_date(now),
            content_length: content.len() as u64,
            concurrent_to: Vec::new(),
            content_type: default_content_type(self.gzip_enabled).to_string(),
            target_uri: String::new(),
            gzip_compressed: self.gzip_enabled,
            truncated: None,
            wagon: None,
        };

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, body_bytes.len(), "");
        }

        Ok(())
    }

    /// Writes a WARC record to the current file.
    ///
    /// Checks if the record would exceed the maximum file size and rotates
    /// the file if necessary. Writes the header, content, and record separator.
    ///
    /// # Arguments
    ///
    /// * `header` - The WARC header to write
    /// * `content` - The content block bytes
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_record(&mut self, header: &WarcHeader, content: &[u8]) -> Result<()> {
        if let Some(max) = self.max_size {
            let header_size = header.serialize().len() as u64;
            if self.current_size + header_size + content.len() as u64 > max && self.current_size > 0
            {
                self.rotate()?;
            }
        }

        let header_bytes = header.serialize();
        if let Some(ref mut f) = self.file {
            f.write_all(&header_bytes).map_err(WarcError::Io)?;
            f.write_all(content).map_err(WarcError::Io)?;
            f.write_all(record_separator()).map_err(WarcError::Io)?;
        }

        self.current_size += header_bytes.len() as u64 + content.len() as u64 + 4;
        Ok(())
    }

    /// Rotates to a new WARC file.
    ///
    /// Closes the current file and opens a new one with an incremented
    /// sequence number in the filename.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the new file cannot be created.
    fn rotate(&mut self) -> Result<()> {
        self.file = None;
        self.open_file()
    }

    /// Builds the response record payload.
    ///
    /// Constructs a payload containing the request line, headers, and response
    /// status line, headers, and body in the WARC response record format.
    ///
    /// # Arguments
    ///
    /// * `url` - The request URL
    /// * `status_code` - The HTTP response status code
    /// * `headers` - The HTTP headers (both request and response)
    /// * `body` - The response body bytes
    ///
    /// # Returns
    ///
    /// A byte vector containing the formatted response payload.
    fn build_response_payload(url: &str, status_code: u16, headers: &[u8], body: &[u8]) -> Vec<u8> {
        let crlf: &[u8] = b"\r\n";
        let mut payload = Vec::new();
        payload.extend_from_slice(b"GET ");
        payload.extend_from_slice(url.as_bytes());
        payload.extend_from_slice(b" HTTP/1.1");
        payload.extend_from_slice(crlf);
        if !headers.is_empty() {
            payload.extend_from_slice(headers);
        }
        payload.extend_from_slice(crlf);
        payload.extend_from_slice(b"HTTP/1.1 ");
        payload.extend_from_slice(status_code.to_string().as_bytes());
        payload.extend_from_slice(crlf);
        if !headers.is_empty() {
            payload.extend_from_slice(headers);
        }
        payload.extend_from_slice(crlf);
        payload.extend_from_slice(body);
        payload
    }

    /// Compresses the payload if gzip is enabled.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to potentially compress
    ///
    /// # Returns
    ///
    /// A `Result` containing the compressed data if gzip is enabled,
    /// or the original data if not.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if compression fails.
    fn compress_payload(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.gzip_enabled {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(data).map_err(WarcError::Io)?;
            encoder.finish().map_err(WarcError::Io)
        } else {
            Ok(data.to_vec())
        }
    }

    /// Adds an entry to the CDX index.
    ///
    /// CDX is a compact index format for WARC files, containing one line
    /// per record with URL, timestamp, MIME type, and other metadata.
    ///
    /// # Arguments
    ///
    /// * `header` - The WARC header for the record
    /// * `body_len` - The length of the uncompressed body
    /// * `digest` - The SHA-1 digest string (or empty if not computed)
    fn add_cdx_entry(&mut self, header: &WarcHeader, body_len: usize, digest: &str) {
        let url = if header.target_uri.is_empty() {
            "-".to_string()
        } else {
            header.target_uri.clone()
        };
        let ts = header
            .date
            .replace('-', "")
            .replace(':', "")
            .replace('T', "000000")
            .replace('Z', "");
        let mime = if header.content_type.contains(';') {
            header.content_type.split(';').next().unwrap_or("-")
        } else {
            &header.content_type
        };
        let digest_str = if digest.is_empty() {
            "-".to_string()
        } else {
            digest.to_string()
        };
        let line = format!(
            "{} {} {} {} {} {} {} - - {} {} {}",
            url,
            ts,
            "-",
            mime.trim(),
            body_len,
            "-",
            header.record_id,
            "-",
            "-",
            digest_str,
        );
        self.cdx_entries.push(line);
    }

    /// Creates a WARC header with standard fields.
    ///
    /// Constructs a `WarcHeader` with the given parameters and automatically
    /// generated record ID.
    ///
    /// # Arguments
    ///
    /// * `record_type` - The type of WARC record
    /// * `target_uri` - The target URI for the record
    /// * `content_type` - The MIME type of the content
    /// * `content_length` - The length of the content in bytes
    /// * `date` - The ISO 8601 timestamp for the record
    ///
    /// # Returns
    ///
    /// A `WarcHeader` struct with all fields populated.
    fn make_header(
        &self,
        record_type: WarcRecordType,
        target_uri: &str,
        content_type: &str,
        content_length: u64,
        date: String,
    ) -> WarcHeader {
        WarcHeader {
            record_type,
            record_id: format_record_id(),
            date,
            content_length,
            concurrent_to: Vec::new(),
            content_type: content_type.to_string(),
            target_uri: target_uri.to_string(),
            gzip_compressed: self.gzip_enabled,
            truncated: None,
            wagon: None,
        }
    }
}
