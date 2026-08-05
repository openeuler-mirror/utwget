//! HTTP Content-Encoding decompression support.
//!
//! This module provides streaming decompression for HTTP response bodies
//! based on the `Content-Encoding` header. Supported encodings are:
//!
//! - `gzip` / `x-gzip`: gzip compression
//! - `deflate`: raw deflate (zlib) compression
//! - `identity`: no compression (passthrough)

use std::io::{self, Read};

/// A streaming decompressor that wraps a reader with the appropriate decoding
/// algorithm based on the HTTP Content-Encoding header.
///
/// Supports three encoding schemes:
/// - `Gzip`: gunzip/deflate compression using the gzip wrapper format.
/// - `Deflate`: raw deflate (zlib) decompression.
/// - `Identity`: no compression — data is passed through unchanged.
///
/// This enum is used by the HTTP client to transparently decode response bodies
/// without the caller needing to know which encoding was applied on the wire.
///
/// # Example
///
/// ```ignore
/// use utwget_http::compression::Decompressor;
/// use std::io::Cursor;
///
/// let compressed_data = Cursor::new(gzip_bytes);
/// let mut decomp = Decompressor::from_encoding(compressed_data, Some("gzip"))?;
///
/// let mut output = Vec::new();
/// decomp.read_to_end(&mut output)?;
/// ```
pub enum Decompressor {
    /// Wraps a reader with gzip decompression.
    Gzip(flate2::read::GzDecoder<Box<dyn Read>>),
    /// Wraps a reader with deflate (zlib) decompression.
    Deflate(flate2::read::DeflateDecoder<Box<dyn Read>>),
    /// Passthrough reader for identity (uncompressed) data.
    Identity(Box<dyn Read>),
}
