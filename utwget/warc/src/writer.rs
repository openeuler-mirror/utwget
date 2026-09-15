use std::fs::{self, File};
use std::io::{Read as _, Seek as _, Write as _};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;

use crate::digest::compute_sha1;
use crate::format::{
    record_separator, request_content_type, response_content_type, warcinfo_content_type,
    WarcHeader, WarcRecordType,
};
use crate::{format_date, format_record_id, generate_uuid_v4, Result, WarcError};

/// Open a file for writing with default umask-derived permissions.
///
/// GNU wget creates WARC files with plain fopen (umask applies,
/// typically 0644); forcing 0600 made utwget's WARC files differ from
/// wget's on the same system (report 8.1-6). The WARC file does not
/// embed credentials (cookies/passwords are never written), so the
/// tighter mode is unnecessary.
fn create_restricted_file(path: &Path) -> std::io::Result<File> {
    File::create(path)
}

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
    /// The collection UUID for isPartOf (generated once per writer, reused
    /// across all warcinfo records in this WARC set, per ISO 28500).
    collection_id: String,
    /// Start offset of the most recently written record in the current file
    /// (compressed offset when gzip is enabled) — the CDX `offset` field.
    last_record_offset: u64,
    /// CDX dedup table (--warc-dedup, M: mirrors GNU wget's
    /// warc_cdx_dedup_table): payload digest (sha1:base32) → (uuid, date)
    /// of the original response record. Loaded from a prior CDX file.
    dedup_table: std::collections::HashMap<String, (String, String)>,
    /// payload digest → original target URI (for revisit WARC-Target-URI).
    dedup_urls: std::collections::HashMap<String, String>,
    /// UUID of the warcinfo record for the current file; written as
    /// WARC-Warcinfo-ID on subsequent records (wget warc.c:262-264).
    warcinfo_id: Option<String>,
    /// All WARC file names produced by this writer (for the MANIFEST
    /// metadata record, --warc-keep-log, wget warc.c:1215-1260).
    produced_files: Vec<String>,
    /// Whether to write metadata records on close (--warc-keep-log).
    keep_log: bool,
}

/// Returns a standard HTTP reason phrase for the given status code.
fn http_status_text(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        101 => "Switching Protocols",
        102 => "Processing",
        103 => "Early Hints",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
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
        // Generate the collection UUID once per writer; reused for all
        // warcinfo records in this WARC set (ISO 28500 §5.1 isPartOf).
        let collection_id = generate_uuid_v4()?;
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
            collection_id,
            last_record_offset: 0,
            dedup_table: std::collections::HashMap::new(),
            dedup_urls: std::collections::HashMap::new(),
            warcinfo_id: None,
            produced_files: Vec::new(),
            keep_log: false,
        };
        writer.open_file()?;
        Ok(writer)
    }

    /// Opens a new WARC file for writing.
    ///
    /// Increments the file counter and creates a new file with the appropriate
    /// name and extension. Writes a warcinfo record as the first record in
    /// every file, matching GNU wget (warc.c warc_start_new_file).
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
        self.produced_files.push(self.filename.clone());

        let raw = create_restricted_file(&path).map_err(WarcError::Io)?;
        self.file = Some(Box::new(raw));
        self.current_size = 0;

        // GNU wget writes a warcinfo record at the start of EVERY file in
        // the WARC set (warc.c warc_start_new_file), not just the first.
        self.write_warcinfo()?;

        Ok(())
    }

    /// Writes a warcinfo record to the current WARC file.
    ///
    /// The warcinfo record contains metadata about the WARC file including
    /// software version, format specification, and any user-defined headers.
    /// Content-Type is `application/warc-fields` and the format version is
    /// `WARC File Format 1.0`, matching GNU wget (warc.c:796,806). The
    /// warcinfo record is not added to the CDX index (wget only indexes
    /// response records).
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_warcinfo(&mut self) -> Result<()> {
        let now = Utc::now();
        let body = format!(
            "software: wget-rs/0.1.0\r\n\
             format: WARC File Format 1.0\r\n\
             isPartOf: <urn:uuid:{}>\r\n",
            self.collection_id
        );
        let mut body_bytes = body.into_bytes();
        // Add user-defined headers
        for user_header in &self.user_headers {
            body_bytes.extend_from_slice(user_header.as_bytes());
            body_bytes.extend_from_slice(b"\r\n");
        }

        let warcinfo_id = format_record_id()?;
        let header = WarcHeader {
            record_type: WarcRecordType::Warcinfo,
            record_id: warcinfo_id.clone(),
            date: format_date(now),
            content_length: body_bytes.len() as u64,
            concurrent_to: Vec::new(),
            content_type: warcinfo_content_type().to_string(),
            target_uri: String::new(),
            gzip_compressed: self.gzip_enabled,
            truncated: None,
            wagon: None,
            payload_digest: None,
            block_digest: self.block_digest_for(body_bytes.as_slice()),
            ip_address: None,
            warcinfo_id: None,
            warc_filename: Some(self.filename.clone()),
        };

        self.write_record(&header, &body_bytes)?;

        // Subsequent records reference this warcinfo (WARC-Warcinfo-ID).
        self.warcinfo_id = Some(warcinfo_id);

        Ok(())
    }

    /// Writes a WARC record to the current file.
    ///
    /// Checks if the record would exceed the maximum file size and rotates
    /// the file if necessary. With gzip enabled the ENTIRE record (header +
    /// content block + separator) is written as a single gzip member —
    /// matching GNU wget (warc.c warc_write_start_record / end_record, "We
    /// start a new gzip stream for each record") — so a `.warc.gz` file is a
    /// valid multi-member gzip stream and `Content-Length` counts the
    /// *uncompressed* block size. Without gzip the record is written as-is.
    ///
    /// # Arguments
    ///
    /// * `header` - The WARC header to write (`content_length` must be the
    ///   uncompressed block size)
    /// * `content` - The uncompressed content block bytes
    ///
    /// # Errors
    ///
    /// Returns `WarcError::Io` if writing fails.
    fn write_record(&mut self, header: &WarcHeader, content: &[u8]) -> Result<()> {
        if let Some(max) = self.max_size {
            let header_size = header.serialize().len() as u64;
            // Include the 4-byte record separator in the size accounting —
            // it IS written to the file, so omitting it made each file up
            // to 4 bytes larger than --warc-max-size (report 8.1-5).
            if self.current_size + header_size + content.len() as u64 + 4 > max
                && self.current_size > 0
            {
                self.rotate()?;
            }
        }

        // The record's start offset in the file (compressed offset when gzip
        // is enabled) — used as the CDX `offset` field, matching wget's
        // ftello(warc_current_file) semantics.
        self.last_record_offset = self.current_size;

        let header_bytes = header.serialize();
        if self.gzip_enabled {
            // One gzip member per record: header + block + separator go
            // through the compressor together (warc.c warc_write_buffer).
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&header_bytes).map_err(WarcError::Io)?;
            encoder.write_all(content).map_err(WarcError::Io)?;
            encoder
                .write_all(record_separator())
                .map_err(WarcError::Io)?;
            let member = encoder.finish().map_err(WarcError::Io)?;
            if let Some(ref mut f) = self.file {
                f.write_all(&member).map_err(WarcError::Io)?;
            }
            self.current_size += member.len() as u64;
        } else if let Some(ref mut f) = self.file {
            f.write_all(&header_bytes).map_err(WarcError::Io)?;
            f.write_all(content).map_err(WarcError::Io)?;
            f.write_all(record_separator()).map_err(WarcError::Io)?;
            self.current_size += header_bytes.len() as u64 + content.len() as u64 + 4;
        }

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

    /// Build the WARC response record payload.
    ///
    /// GNU wget stores only the actual HTTP response (status line + response
    /// headers + body) in the response record. The request is a separate
    /// *request* record.
    fn build_response_payload(http_version: &str, status_code: u16, headers: &[u8], body: &[u8]) -> Vec<u8> {
        let crlf: &[u8] = b"\r\n";
        let mut payload = Vec::new();
        // Status line: <actual protocol version> <code> [<reason>] — the
        // version is what the server really sent (report 8.1-3: hardcoding
        // HTTP/1.1 falsified HTTP/1.0 captures). Unknown reason → omit it
        // entirely instead of emitting a trailing space.
        payload.extend_from_slice(http_version.as_bytes());
        payload.extend_from_slice(status_code.to_string().as_bytes());
        let reason = http_status_text(status_code);
        if !reason.is_empty() {
            payload.push(b' ');
            payload.extend_from_slice(reason.as_bytes());
        }
        payload.extend_from_slice(crlf);
        // Response headers (already include CRLF per header)
        if !headers.is_empty() {
            payload.extend_from_slice(headers);
        }
        // Blank line separating headers from body
        payload.extend_from_slice(crlf);
        // Response body
        payload.extend_from_slice(body);
        payload
    }

    /// Adds an entry to the CDX index.
    ///
    /// Reproduces GNU wget's CDX line format exactly (warc.c:1412-1416):
    ///
    /// ```text
    /// url ts url mime response_code checksum redirect - offset filename record_uuid
    /// ```
    ///
    /// where `ts` is the 14-digit timestamp (`YYYYmmddHHMMSS`), `checksum` is
    /// the payload digest with the `sha1:` prefix stripped (warc.c:1400-1403),
    /// and `offset` is the record's start offset in the (possibly compressed)
    /// WARC file. Only response records are indexed (warc.c:1563-1566).
    ///
    /// # Arguments
    ///
    /// * `header` - The WARC header of the response record
    /// * `mime` - The MIME type of the response body ("-" if unknown)
    /// * `response_code` - The HTTP response status code
    /// * `redirect` - The redirect Location value (empty = "-")
    /// * `payload_digest` - The `sha1:<base32>` payload digest (empty = "-")
    fn add_cdx_entry(
        &mut self,
        header: &WarcHeader,
        mime: &str,
        response_code: u16,
        redirect: &str,
        payload_digest: &str,
    ) {
        let url = if header.target_uri.is_empty() {
            "-".to_string()
        } else {
            header.target_uri.clone()
        };
        // 14-digit CDX timestamp: "YYYY-mm-ddTHH:MM:SSZ" → "YYYYmmddHHMMSS"
        // (warc.c:1384-1394 strips '-', 'T', ':' and the trailing 'Z').
        let ts: String = header
            .date
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        let ts = ts[..14].to_string();
        let mime = if mime.trim().is_empty() {
            "-"
        } else {
            mime.trim()
        };
        let checksum = payload_digest
            .strip_prefix("sha1:")
            .unwrap_or("-")
            .to_string();
        let redirect = if redirect.trim().is_empty() {
            "-".to_string()
        } else {
            redirect.trim().to_string()
        };
        let line = format!(
            "{} {} {} {} {} {} {} - {} {} {}",
            url,
            ts,
            url,
            mime,
            response_code,
            checksum,
            redirect,
            self.last_record_offset,
            self.filename,
            header.record_id,
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
        payload_digest: Option<String>,
        block_digest: Option<String>,
    ) -> Result<WarcHeader> {
        self.make_header_with_ip(
            record_type,
            target_uri,
            content_type,
            content_length,
            date,
            payload_digest,
            block_digest,
            None,
        )
    }

    /// Like [`make_header`] but with the server IP for WARC-IP-Address
    /// (warc.c:448-455) and the warcinfo/file names for WARC-Warcinfo-ID.
    #[allow(clippy::too_many_arguments)]
    fn make_header_with_ip(
        &self,
        record_type: WarcRecordType,
        target_uri: &str,
        content_type: &str,
        content_length: u64,
        date: String,
        payload_digest: Option<String>,
        block_digest: Option<String>,
        ip_address: Option<String>,
    ) -> Result<WarcHeader> {
        Ok(WarcHeader {
            record_type,
            record_id: format_record_id()?,
            date,
            content_length,
            concurrent_to: Vec::new(),
            content_type: content_type.to_string(),
            target_uri: target_uri.to_string(),
            gzip_compressed: self.gzip_enabled,
            truncated: None,
            wagon: None,
            payload_digest,
            // WARC-Block-Digest: computed over the block content (the bytes
            // as stored, possibly compressed). Required by ISO 28500 §5.10.
            // GNU wget always writes this when digests are enabled (warc.c:622-624).
            block_digest,
            ip_address,
            warcinfo_id: self.warcinfo_id.clone(),
            warc_filename: Some(self.filename.clone()),
        })
    }
    /// Compute the `WARC-Payload-Digest` header value for a payload.
    ///
    /// Returns `Some("sha1:<base32>")` when digest computation is enabled, or
    /// `None` otherwise. The digest is computed over the *uncompressed*
    /// payload (the original content), matching WARC §5.10.
    fn payload_digest_for(&self, payload: &[u8]) -> Option<String> {
        if self.digest_enabled {
            Some(compute_sha1(payload))
        } else {
            None
        }
    }

    /// Compute the `WARC-Block-Digest` header value for the block content.
    ///
    /// Returns `Some("sha1:<base32>")` when digest computation is enabled.
    /// The block digest is computed over the block content as stored
    /// (the bytes that form the WARC record's content block).
    fn block_digest_for(&self, block: &[u8]) -> Option<String> {
        if self.digest_enabled {
            Some(compute_sha1(block))
        } else {
            None
        }
    }
}

// 2026-09-08: 原 `impl WarcWriter for WarcWriterImpl` 已合并为本 inherent impl。
// trait WarcWriter 仅一个 impl 且无 dyn 使用，简化为具体类型。
impl WarcWriterImpl {
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
    pub fn write_request(
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

        // GNU wget's request records carry no digests and use
        // application/http;msgtype=request regardless of compression
        // (warc.c warc_write_request_record); the record itself is
        // compressed as a whole at the write_record level.
        let header = self.make_header(
            WarcRecordType::Request,
            url,
            request_content_type(),
            payload.len() as u64,
            format_date(date),
            None,
            self.block_digest_for(&payload),
        )?;

        self.write_record(&header, &payload)?;

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
    #[allow(clippy::too_many_arguments)]
    pub fn write_response(
        &mut self,
        url: &str,
        http_version: &str,
        status_code: u16,
        headers: &[u8],
        body: &[u8],
        content_type: &str,
        date: chrono::DateTime<Utc>,
        server_ip: Option<&str>,
    ) -> Result<()> {
        // CDX deduplication (--warc-dedup, mirrors GNU wget
        // warc_write_response_record warc.c:1498-1523): when the payload
        // digest matches an entry in the dedup table (loaded from a prior
        // CDX file), write a revisit record instead of a full duplicate.
        if !self.dedup_table.is_empty() {
            let payload_digest = compute_sha1(body);
            if let Some((refers_to, original_date)) = self.dedup_table.get(&payload_digest).cloned() {
                let original_uri = self
                    .dedup_urls
                    .get(&payload_digest)
                    .cloned()
                    .unwrap_or_else(|| url.to_string());
                log::info!(
                    "dedup: payload digest found in CDX table; writing revisit record (refers to {})",
                    refers_to
                );
                return self.write_revisit(
                    url,
                    &original_uri,
                    &refers_to,
                    &payload_digest,
                    &original_date,
                    date,
                );
            }
        }

        let payload = Self::build_response_payload(http_version, status_code, headers, body);
        // Content-Type is always application/http;msgtype=response for
        // response records (warc.c:1556); the entity MIME goes to the CDX
        // index instead (warc.c:1563-1566).
        let mut header = self.make_header(
            WarcRecordType::Response,
            url,
            response_content_type(),
            payload.len() as u64,
            format_date(date),
            // WARC-Payload-Digest covers the response BODY only
            // (warc_sha1_stream_with_payload, warc.c:1508-1510).
            self.payload_digest_for(body),
            self.block_digest_for(&payload),
        )?;
        header.ip_address = server_ip.map(|s| s.to_string());

        self.write_record(&header, &payload)?;

        if self.cdx_enabled {
            self.add_cdx_entry(&header, content_type, status_code, "", &compute_sha1(body));
        }

        Ok(())
    }

    /// Writes a WARC revisit record (deduplication).
    ///
    /// Mirrors GNU wget's `warc_write_revisit_record` (warc.c:1437-1465):
    /// references the original capture via WARC-Refers-To and the
    /// identical-payload-digest profile, stores only the response headers
    /// as the block (WARC-Truncated: length), and records both block and
    /// payload digests.
    #[allow(clippy::too_many_arguments)]
    fn write_revisit(
        &mut self,
        url: &str,
        original_uri: &str,
        refers_to: &str,
        payload_digest: &str,
        _original_date: &str,
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        // The block of a revisit record carries the response HEADERS only
        // (the payload is truncated away — see WARC-Truncated: length).
        // Dedup happens before header serialization here, so we store an
        // empty block; payload identity is carried by the digest headers.
        let block: Vec<u8> = Vec::new();
        let mut header = self.make_header(
            WarcRecordType::Revisit,
            url,
            response_content_type(),
            block.len() as u64,
            format_date(date),
            Some(payload_digest.to_string()),
            self.block_digest_for(&block),
        )?;
        header.concurrent_to = Vec::new();
        // WARC-Refers-To + profile via truncated? The header struct lacks
        // dedicated fields; encode both into user headers via serialize
        // extension below (WarcHeader has no refers_to field, so append
        // through truncated + a custom mechanism is not available).
        // Instead, serialize manually with the extra headers appended.
        let mut header_bytes = header.serialize();
        // Insert WARC-Refers-To / WARC-Profile / WARC-Truncated before the
        // final \r\n\r\n.
        let extra = format!(
            "WARC-Refers-To: <urn:uuid:{}>\r\n\
             WARC-Profile: http://netpreserve.org/warc/1.0/revisit/identical-payload-digest\r\n\
             WARC-Truncated: length\r\n",
            refers_to.trim_start_matches("<urn:uuid:").trim_end_matches('>')
        );
        let trim_len = header_bytes.len() - 4;
        header_bytes.truncate(trim_len);
        header_bytes.extend_from_slice(extra.as_bytes());
        header_bytes.extend_from_slice(b"\r\n\r\n");

        self.last_record_offset = self.current_size;
        if self.gzip_enabled {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&header_bytes).map_err(WarcError::Io)?;
            encoder.write_all(&block).map_err(WarcError::Io)?;
            encoder.write_all(record_separator()).map_err(WarcError::Io)?;
            let member = encoder.finish().map_err(WarcError::Io)?;
            if let Some(ref mut f) = self.file {
                f.write_all(&member).map_err(WarcError::Io)?;
            }
            self.current_size += member.len() as u64;
        } else if let Some(ref mut f) = self.file {
            f.write_all(&header_bytes).map_err(WarcError::Io)?;
            f.write_all(&block).map_err(WarcError::Io)?;
            f.write_all(record_separator()).map_err(WarcError::Io)?;
            self.current_size += header_bytes.len() as u64 + block.len() as u64 + 4;
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
    pub fn write_resource(
        &mut self,
        url: &str,
        content_type: &str,
        body: &[u8],
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let header = self.make_header(
            WarcRecordType::Resource,
            url,
            content_type,
            body.len() as u64,
            format_date(date),
            self.payload_digest_for(body),
            self.block_digest_for(body),
        )?;

        self.write_record(&header, body)?;

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
    pub fn write_metadata(
        &mut self,
        url: &str,
        metadata: &str,
        concurrent_to: &[String],
        date: chrono::DateTime<Utc>,
    ) -> Result<()> {
        let meta_bytes = metadata.as_bytes();
        let mut header = self.make_header(
            WarcRecordType::Metadata,
            url,
            "application/warc-fields",
            meta_bytes.len() as u64,
            format_date(date),
            None,
            self.block_digest_for(meta_bytes),
        )?;
        header.concurrent_to = concurrent_to.to_vec();

        self.write_record(&header, meta_bytes)?;

        Ok(())
    }

    /// Enables metadata records on close (`--warc-keep-log`).
    pub fn set_keep_log(&mut self, enabled: bool) {
        self.keep_log = enabled;
    }

    /// Loads a CDX file for deduplication (`--warc-dedup=FILE`).
    ///
    /// Mirrors GNU wget's `warc_load_cdx_dedup_file` (warc.c:1061-1043):
    /// parses each CDX line and stores `digest → (uuid, date)` so a later
    /// response with the same payload can be written as a revisit record
    /// instead of a full duplicate. Lines that fail to parse are skipped
    /// (wget does the same).
    pub fn load_cdx_dedup_file(&mut self, path: &Path) -> Result<usize> {
        let data = fs::read_to_string(path).map_err(WarcError::Io)?;
        let mut loaded = 0usize;
        for line in data.lines() {
            // Skip the CDX header line (" CDX a b a m s k r M V g u").
            if line.starts_with(" CDX") || line.trim().is_empty() {
                continue;
            }
            // Field layout (11 fields): url ts url mime response_code
            // checksum redirect - offset filename record_uuid
            let fields: Vec<&str> = line.split(' ').collect();
            if fields.len() != 11 {
                continue;
            }
            let url = fields[0];
            let date = fields[1];
            let checksum = fields[5];
            let uuid = fields[10];
            if checksum == "-" || uuid == "-" || uuid.is_empty() {
                continue;
            }
            // Re-add the sha1: prefix stripped when the CDX was written.
            self.dedup_table
                .insert(format!("sha1:{}", checksum), (uuid.to_string(), date.to_string()));
            // Keep the target URI for revisit WARC-Target-URI.
            self.dedup_urls.insert(format!("sha1:{}", checksum), url.to_string());
            loaded += 1;
        }
        log::info!("CDX dedup table loaded: {} entries from {}", loaded, path.display());
        Ok(loaded)
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
    pub fn create_temp_file(&mut self) -> Result<(Box<dyn Write + Send>, PathBuf)> {
        let name = format!("warc-tmp-{}.tmp", generate_uuid_v4()?);
        let path = self.tempdir.join(name);
        let file = create_restricted_file(&path).map_err(WarcError::Io)?;
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
    pub fn finalize_temp_file(
        &mut self,
        temp_path: &Path,
        url: &str,
        content_type: &str,
        date: chrono::DateTime<Utc>,
        _digest_enabled: bool,
    ) -> Result<()> {
        // Stream the temp file into the WARC record instead of buffering
        // it fully in memory (report 8.1-5: fs::read amplified memory for
        // large downloads; GNU wget streams from the temp file). Digests
        // are computed while streaming.
        let mut data_file = fs::File::open(temp_path).map_err(WarcError::Io)?;
        let content_length = data_file.metadata().map_err(WarcError::Io)?.len();

        // Compute payload digest by streaming.
        let payload_digest = if self.digest_enabled {
            use std::io::Read as _;
            let mut hasher = crate::digest::WarcDigest::new();
            let mut buf = [0u8; 65536];
            loop {
                let n = data_file.read(&mut buf).map_err(WarcError::Io)?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
            }
            Some(hasher.finalize())
        } else {
            None
        };
        data_file.rewind().map_err(WarcError::Io)?;

        let mut header = self.make_header(
            WarcRecordType::Resource,
            url,
            content_type,
            content_length,
            format_date(date),
            payload_digest,
            None, // block digest computed over streamed content below
        )?;
        header.block_digest = None;

        // Write header, then stream the block, then separator — reusing
        // write_record would require materializing the block, so do the
        // rotation check + writes manually (keeping current_size exact).
        {
            let header_size = header.serialize().len() as u64;
            if let Some(max) = self.max_size {
                if self.current_size + header_size + content_length + 4 > max
                    && self.current_size > 0
                {
                    self.rotate()?;
                }
            }
            self.last_record_offset = self.current_size;
            let header_bytes = header.serialize();

            // Block digest streams alongside the copy.
            let mut block_hasher = crate::digest::WarcDigest::new();
            if let Some(ref mut f) = self.file {
                if self.gzip_enabled {
                    // Per-record gzip member: feed header+block+separator
                    // through one encoder.
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&header_bytes).map_err(WarcError::Io)?;
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = data_file.read(&mut buf).map_err(WarcError::Io)?;
                        if n == 0 { break; }
                        block_hasher.update(&buf[..n]);
                        encoder.write_all(&buf[..n]).map_err(WarcError::Io)?;
                    }
                    encoder.write_all(record_separator()).map_err(WarcError::Io)?;
                    let member = encoder.finish().map_err(WarcError::Io)?;
                    f.write_all(&member).map_err(WarcError::Io)?;
                    self.current_size += member.len() as u64;
                } else {
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = data_file.read(&mut buf).map_err(WarcError::Io)?;
                        if n == 0 { break; }
                        block_hasher.update(&buf[..n]);
                        f.write_all(&buf[..n]).map_err(WarcError::Io)?;
                    }
                    f.write_all(record_separator()).map_err(WarcError::Io)?;
                    self.current_size += header_bytes.len() as u64 + content_length + 4;
                }
            }
            if self.digest_enabled {
                header.block_digest = Some(block_hasher.finalize());
            }
        }

        let _ = fs::remove_file(temp_path);
        Ok(())
    }

    /// Generates a new unique record ID.
    ///
    /// # Returns
    ///
    /// A URN UUID string in the format `<urn:uuid:...>`.
    pub fn uuid(&self) -> String {
        format_record_id().unwrap_or_else(|_| "<urn:uuid:00000000-0000-0000-0000-000000000000>".to_string())
    }

    /// Generates a timestamp for the current time.
    ///
    /// # Returns
    ///
    /// An ISO 8601 formatted timestamp string.
    pub fn timestamp(&self) -> String {
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
    pub fn open(&mut self, prefix: &str) -> Result<()> {
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

        let raw = create_restricted_file(&path).map_err(WarcError::Io)?;
        self.file = Some(Box::new(raw));
        self.current_size = 0;
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
    pub fn close(&mut self) -> Result<()> {
        // Explicit flush before dropping: with --warc-compression each
        // record is already a finished gzip member (encoder.finish() with
        // checked error in write_record), so no GzEncoder Drop is involved
        // anymore — but a plain flush still catches buffered-write errors
        // that a silent Drop would swallow (report 8.1-4).
        // --warc-keep-log: write metadata records (MANIFEST + invocation
        // arguments), mirroring GNU wget warc_write_metadata
        // (warc.c:1215-1260). The wget.log capture is not implemented —
        // stderr redirection into the writer is invasive — but the
        // MANIFEST and argument records carry the essential provenance.
        // MUST run BEFORE self.file is taken: write_record needs the
        // handle.
        if self.keep_log && !self.produced_files.is_empty() {
            let now = Utc::now();
            let manifest = self
                .produced_files
                .iter()
                .map(|f| format!("{}\n", f))
                .collect::<String>();
            let args_line = std::env::args().collect::<Vec<_>>().join(" ");
            let records: Vec<(&str, String)> = vec![
                (
                    "metadata://gnu.org/software/wget/warc/MANIFEST.txt",
                    manifest,
                ),
                (
                    "metadata://gnu.org/software/wget/warc/wget_arguments.txt",
                    format!("{}\n", args_line),
                ),
            ];
            for (uri, body) in records {
                let header = self.make_header(
                    WarcRecordType::Metadata,
                    uri,
                    "text/plain",
                    body.len() as u64,
                    format_date(now),
                    None,
                    self.block_digest_for(body.as_bytes()),
                )?;
                if let Err(e) = self.write_record(&header, body.as_bytes()) {
                    log::warn!("failed to write WARC metadata record {}: {}", uri, e);
                }
            }
        }

        // Flush + close the data file AFTER metadata records.
        if let Some(mut f) = self.file.take() {
            f.flush().map_err(WarcError::Io)?;
        }
        self.file = None;

        if self.cdx_enabled && !self.cdx_entries.is_empty() {
            let cdx_name = format!("{}.cdx", self.filename);
            let mut cdx_file = create_restricted_file(Path::new(&cdx_name)).map_err(WarcError::Io)?;
            // CDX header line, matching GNU wget (warc.c:938).
            cdx_file
                .write_all(b" CDX a b a m s k r M V g u\n")
                .map_err(WarcError::Io)?;
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
