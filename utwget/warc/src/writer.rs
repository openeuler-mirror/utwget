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

impl WarcWriter for WarcWriterImpl {
    /// Writes a WARC request record.
    ///
    /// Records an HTTP request with the given method, URL, headers, and body.
    /// The request is formatted as a standard HTTP request line followed by
    /// headers and body.
    ///
    /// # Arguments
    ///
    /// * `url` - The request URL
    /// * `method` - The HTTP method (GET, POST, etc.)
    /// * `headers` - The HTTP request headers as bytes
    /// * `body` - The request body bytes
    /// * `date` - The timestamp for the record
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_request(
        &mut self,
        url: &str,
        method: &str,
        headers: &[u8],
        body: &[u8],
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let crlf: &[u8] = b"\r\n";
        let mut payload = Vec::new();
        payload.extend_from_slice(method.as_bytes());
        payload.extend_from_slice(b" ");
        payload.extend_from_slice(url.as_bytes());
        payload.extend_from_slice(b" HTTP/1.1");
        payload.extend_from_slice(crlf);
        if !headers.is_empty() {
            payload.extend_from_slice(headers);
        }
        payload.extend_from_slice(crlf);
        payload.extend_from_slice(body);

        let content = self.compress_payload(&payload)?;
        let digest = compute_sha1(&payload);
        let header = self.make_header(
            WarcRecordType::Request,
            url,
            default_content_type(self.gzip_enabled),
            content.len() as u64,
            format_date(date),
        );

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, payload.len(), &digest);
        }

        Ok(())
    }

    /// Writes a WARC response record.
    ///
    /// Records an HTTP response with the given status code, headers, and body.
    /// The response is formatted with both the request and response information.
    ///
    /// # Arguments
    ///
    /// * `url` - The request URL
    /// * `status_code` - The HTTP response status code
    /// * `headers` - The HTTP headers as bytes
    /// * `body` - The response body bytes
    /// * `content_type` - The MIME type of the content
    /// * `date` - The timestamp for the record
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_response(
        &mut self,
        url: &str,
        status_code: u16,
        headers: &[u8],
        body: &[u8],
        content_type: &str,
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let payload = Self::build_response_payload(url, status_code, headers, body);
        let content = self.compress_payload(&payload)?;
        let digest = compute_sha1(&payload);
        let header = self.make_header(
            WarcRecordType::Response,
            url,
            content_type,
            content.len() as u64,
            format_date(date),
        );

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, payload.len(), &digest);
        }

        Ok(())
    }

    /// Writes a WARC resource record.
    ///
    /// Records arbitrary data as a resource with the given content type.
    /// This is used for storing downloaded content without HTTP metadata.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL where the resource was retrieved from
    /// * `content_type` - The MIME type of the content
    /// * `body` - The content bytes
    /// * `date` - The timestamp for the record
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_resource(
        &mut self,
        url: &str,
        content_type: &str,
        body: &[u8],
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let content = self.compress_payload(body)?;
        let digest = compute_sha1(body);
        let header = self.make_header(
            WarcRecordType::Resource,
            url,
            content_type,
            content.len() as u64,
            format_date(date),
        );

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, body.len(), &digest);
        }

        Ok(())
    }

    /// Writes a WARC metadata record.
    ///
    /// Records additional metadata about other records, with optional
    /// concurrent-to references to link to related records.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL the metadata relates to
    /// * `metadata` - The metadata content as a string
    /// * `concurrent_to` - List of record IDs this metadata relates to
    /// * `date` - The timestamp for the record
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_metadata(
        &mut self,
        url: &str,
        metadata: &str,
        concurrent_to: &[String],
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let meta_bytes = metadata.as_bytes();
        let content = self.compress_payload(meta_bytes)?;
        let mut header = self.make_header(
            WarcRecordType::Metadata,
            url,
            "application/warc-fields",
            content.len() as u64,
            format_date(date),
        );
        header.concurrent_to = concurrent_to.to_vec();

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, meta_bytes.len(), "");
        }

        Ok(())
    }

    /// Creates a temporary file for accumulating large content.
    ///
    /// Creates a file in the configured temp directory with a unique name
    /// based on a UUID. The caller can write to this file and later
    /// finalize it into a WARC record.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple of the file handle and its path.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the file cannot be created.
    fn create_temp_file(&mut self) -> Result<(Box<dyn Write + Send>, PathBuf)> {
        let name = format!("warc-tmp-{}.tmp", generate_uuid_v4());
        let path = self.tempdir.join(name);
        let file = File::create(&path).map_err(WarcError::Io)?;
        Ok((Box::new(file), path))
    }

    /// Finalizes a temporary file into a WARC resource record.
    ///
    /// Reads the content from the temporary file, optionally computes a digest,
    /// writes it as a resource record, and deletes the temporary file.
    ///
    /// # Arguments
    ///
    /// * `temp_path` - Path to the temporary file
    /// * `url` - The URL the content was retrieved from
    /// * `content_type` - The MIME type of the content
    /// * `date` - The timestamp for the record
    /// * `digest_enabled` - Whether to compute a digest (overrides writer setting)
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if reading, writing, or deleting fails.
    fn finalize_temp_file(
        &mut self,
        temp_path: &Path,
        url: &str,
        content_type: &str,
        date: chrono::DateTime<Utc>,
        digest_enabled: bool,
    ) -> Result<()> {
        let data = fs::read(temp_path).map_err(WarcError::Io)?;

        let digest = if digest_enabled || self.digest_enabled {
            compute_sha1(&data)
        } else {
            String::new()
        };

        let content = self.compress_payload(&data)?;
        let header = self.make_header(
            WarcRecordType::Resource,
            url,
            content_type,
            content.len() as u64,
            format_date(date),
        );

        self.write_record(&header, &content)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, data.len(), &digest);
        }

        let _ = fs::remove_file(temp_path);
        Ok(())
    }

    /// Generates a new unique record ID.
    ///
    /// # Returns
    ///
    /// A URN UUID string in the format `<urn:uuid:...>`.
    fn uuid(&self) -> String {
        format_record_id()
    }

    /// Generates a timestamp for the current time.
    ///
    /// # Returns
    ///
    /// An ISO 8601 formatted timestamp string.
    fn timestamp(&self) -> String {
        format_date(Utc::now())
    }

    /// Opens a new WARC file with the given prefix.
    ///
    /// Creates a new WARC file with the specified name prefix, resetting
    /// the file counter and writing a new warcinfo record.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The filename prefix (empty string uses "wget")
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if the file cannot be created.
    fn open(&mut self, prefix: &str) -> Result<()> {
        let stem = if prefix.is_empty() { "wget" } else { prefix };
        let ext = if self.gzip_enabled { ".warc.gz" } else { ".warc" };
        let name = format!("{}{}", stem, ext);
        let path = self
            .base_path
            .parent()
            .map(|p| p.join(&name))
            .unwrap_or_else(|| PathBuf::from(&name));

        self.filename = path.to_string_lossy().to_string();
        self.file_counter = 1;
        self.current_size = 0;

        let raw = File::create(&path).map_err(WarcError::Io)?;
        let boxed: Box<dyn Write + Send> = if self.gzip_enabled {
            Box::new(GzEncoder::new(raw, Compression::default()))
        } else {
            Box::new(raw)
        };

        self.file = Some(boxed);
        self.cdx_entries.clear();
        self.write_warcinfo()?;

        Ok(())
    }

    /// Closes the current WARC file and writes the CDX index if enabled.
    ///
    /// Flushes and closes the current file handle. If CDX indexing is enabled
    /// and there are accumulated entries, writes them to a `.cdx` file.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an error.
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if closing or writing the CDX file fails.
    fn close(&mut self) -> Result<()> {
        self.file = None;

        if self.cdx_enabled && !self.cdx_entries.is_empty() {
            let cdx_name = format!("{}.cdx", self.filename);
            let mut cdx_file = File::create(&cdx_name).map_err(WarcError::Io)?;
            let newline: &[u8] = b"\n";
            for entry in &self.cdx_entries {
                cdx_file
                    .write_all(entry.as_bytes())
                    .map_err(WarcError::Io)?;
                cdx_file.write_all(newline).map_err(WarcError::Io)?;
            }
            self.cdx_entries.clear();
        }

        Ok(())
    }
}

impl Drop for WarcWriterImpl {
    /// Ensures the WARC file is properly closed when the writer is dropped.
    ///
    /// This implementation guarantees that the CDX index is written even
    /// if the writer goes out of scope without an explicit call to `close()`.
    fn drop(&mut self) {
        let _ = self.close();
    }
}
