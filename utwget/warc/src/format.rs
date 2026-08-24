use std::fmt;

/// WARC record types as defined in the WARC 1.1 specification.
///
/// Each record type serves a specific purpose in web archiving:
/// - `Warcinfo`: Metadata about the WARC file itself
/// - `Response`: Captured HTTP response data
/// - `Resource`: Arbitrary data resources
/// - `Request`: Captured HTTP request data
/// - `Metadata`: Additional metadata about other records
/// - `Conversion`: Transformed versions of other records
/// - `Continuation`: Segments of records split across files
#[derive(Debug, Clone, PartialEq)]
pub enum WarcRecordType {
    /// WARC file metadata record.
    Warcinfo,
    /// HTTP response record.
    Response,
    /// Arbitrary resource record.
    Resource,
    /// HTTP request record.
    Request,
    /// Metadata record for additional information.
    Metadata,
    /// Converted/transformed record.
    Conversion,
    /// Continuation of a record split across files.
    Continuation,
}

impl fmt::Display for WarcRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WarcRecordType::Warcinfo => write!(f, "warcinfo"),
            WarcRecordType::Response => write!(f, "response"),
            WarcRecordType::Resource => write!(f, "resource"),
            WarcRecordType::Request => write!(f, "request"),
            WarcRecordType::Metadata => write!(f, "metadata"),
            WarcRecordType::Conversion => write!(f, "conversion"),
            WarcRecordType::Continuation => write!(f, "continuation"),
        }
    }
}

/// WARC record header containing all mandatory and optional fields.
///
/// This struct represents the header portion of a WARC record, following
/// the WARC 1.1 specification format. Headers are serialized to the
/// WARC format with CRLF line endings.
///
/// # Fields
///
/// * `record_type` - The type of WARC record (warcinfo, response, etc.)
/// * `record_id` - Unique identifier for this record (URN UUID format)
/// * `date` - ISO 8601 timestamp of record creation
/// * `content_length` - Length of the record body in bytes
/// * `concurrent_to` - List of related record IDs
/// * `content_type` - MIME type of the record content
/// * `target_uri` - Original URI of the captured resource
/// * `gzip_compressed` - Whether the content is gzip compressed
/// * `truncated` - Reason for truncation if record was truncated
/// * `wagon` - Optional wagon metadata
pub struct WarcHeader {
    /// The type of WARC record.
    pub record_type: WarcRecordType,
    /// Unique record identifier in URN UUID format.
    pub record_id: String,
    /// ISO 8601 formatted timestamp.
    pub date: String,
    /// Length of the content block in bytes.
    pub content_length: u64,
    /// List of related record IDs (WARC-Concurrent-To).
    pub concurrent_to: Vec<String>,
    /// MIME type of the content block.
    pub content_type: String,
    /// Original URI of the captured resource.
    pub target_uri: String,
    /// Whether the content block is gzip compressed.
    pub gzip_compressed: bool,
    /// Reason for truncation if the record was truncated.
    pub truncated: Option<String>,
    /// Optional wagon metadata.
    pub wagon: Option<String>,
}

impl WarcHeader {
    /// Serializes the header to WARC format bytes.
    ///
    /// Converts the header fields to the WARC 1.1 format with CRLF line endings.
    /// The output includes the WARC version line followed by all header fields
    /// in the standard format, ending with two CRLF sequences to separate
    /// the header from the content block.
    ///
    /// # Returns
    ///
    /// A byte vector containing the serialized WARC header.
    ///
    /// # Format
    ///
    /// The output format is:
    /// ```text
    /// WARC/1.1\r\n
    /// WARC-Type: <type>\r\n
    /// WARC-Date: <date>\r\n
    /// WARC-Record-ID: <id>\r\n
    /// Content-Type: <content-type>\r\n
    /// Content-Length: <length>\r\n
    /// [WARC-Target-URI: <uri>\r\n]
    /// [WARC-Concurrent-To: <id>\r\n]*
    /// [WARC-Payload-Digest: sha1:\r\n]
    /// [WARC-Truncated: <reason>\r\n]
    /// [WARC-Wagon: <wagon>\r\n]
    /// \r\n
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut lines: Vec<String> = Vec::new();

        lines.push("WARC/1.1".to_string());
        lines.push(format!("WARC-Type: {}", self.record_type));
        lines.push(format!("WARC-Date: {}", self.date));
        lines.push(format!("WARC-Record-ID: {}", self.record_id));
        lines.push(format!("Content-Type: {}", self.content_type));
        lines.push(format!("Content-Length: {}", self.content_length));

        if !self.target_uri.is_empty() {
            lines.push(format!("WARC-Target-URI: {}", self.target_uri));
        }

        for ct in &self.concurrent_to {
            lines.push(format!("WARC-Concurrent-To: {}", ct));
        }

        if self.gzip_compressed {
            lines.push("WARC-Payload-Digest: sha1:".to_string());
        }

        if let Some(ref t) = self.truncated {
            lines.push(format!("WARC-Truncated: {}", t));
        }

        if let Some(ref w) = self.wagon {
            lines.push(format!("WARC-Wagon: {}", w));
        }

        let header_block: String = lines.into_iter().collect::<Vec<_>>().join("\r\n");
        let mut out = header_block.into_bytes();
        out.extend_from_slice(b"\r\n\r\n");
        out
    }
}
