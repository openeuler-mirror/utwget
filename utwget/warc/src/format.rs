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
