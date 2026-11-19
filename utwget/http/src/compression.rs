//! HTTP Content-Encoding decompression support.
//!
//! This module provides utilities for parsing the `Content-Encoding` header.
//! The actual decompression is performed by the retriever using `flate2`
//! decoders wrapping the file writer (see retriever.rs `stream_response_body`).

/// Extracts the first supported content-encoding token from a `Content-Encoding`
/// HTTP header value.
///
/// The header value may contain a comma-separated list of encodings (e.g.
/// `"gzip, deflate"`). This function returns the first recognized encoding:
/// - `"gzip"` or `"x-gzip"` returns `Some("gzip")`.
/// - `"deflate"` returns `Some("deflate")`.
///
/// Unrecognized encodings are silently skipped. If no recognized encoding is
/// found, or if the header is absent or empty, the function returns `None`.
/// The `"identity"` encoding is also treated as "no encoding" and returns `None`.
///
/// # Arguments
///
/// * `encoding_header` - The raw value of the `Content-Encoding` HTTP header,
///   or `None` if the header was not sent.
///
/// # Returns
///
/// `Some(String)` with the canonical name of the first supported encoding, or
/// `None` if no supported encoding is present.
///
/// # Example
///
/// ```
/// use ut_http::compression::content_encoding_value;
///
/// assert_eq!(content_encoding_value(Some("gzip")), Some("gzip".to_string()));
/// assert_eq!(content_encoding_value(Some("deflate")), Some("deflate".to_string()));
/// assert_eq!(content_encoding_value(Some("identity")), None);
/// assert_eq!(content_encoding_value(None), None);
/// ```
pub fn content_encoding_value(encoding_header: Option<&str>) -> Option<String> {
    let enc = encoding_header?.trim();
    if enc.is_empty() {
        return None;
    }

    let encodings: Vec<&str> = enc.split(',').map(|s| s.trim()).collect();

    for e in &encodings {
        if e.eq_ignore_ascii_case("gzip") || e.eq_ignore_ascii_case("x-gzip") {
            return Some("gzip".to_string());
        }
        if e.eq_ignore_ascii_case("deflate") {
            return Some("deflate".to_string());
        }
    }

    None
}

