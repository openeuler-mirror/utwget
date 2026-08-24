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
