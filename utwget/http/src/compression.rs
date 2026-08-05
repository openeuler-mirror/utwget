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

impl Decompressor {
    /// Creates a `Decompressor` from an inner reader and an optional encoding name.
    ///
    /// The encoding string is compared case-insensitively against the standard
    /// HTTP Content-Encoding values:
    /// - `"gzip"` or `"x-gzip"` selects gzip decompression.
    /// - `"deflate"` selects deflate decompression.
    /// - `"identity"` or an empty string selects passthrough.
    /// - `None` (the HTTP header was absent) also selects passthrough.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying byte source to decompress.
    /// * `encoding` - An optional content-encoding name as received in the
    ///   HTTP `Content-Encoding` header.
    ///
    /// # Returns
    ///
    /// A `Decompressor` configured with the matching decoder, or an error if
    /// the encoding name is not recognized.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` with kind `InvalidData` when an unsupported encoding
    /// name is provided (e.g. `"br"` for Brotli, which is not yet supported).
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Gzip decompression
    /// let decomp = Decompressor::from_encoding(reader, Some("gzip"))?;
    ///
    /// // Passthrough (no compression)
    /// let decomp = Decompressor::from_encoding(reader, None)?;
    /// ```
    pub fn from_encoding<R: Read + 'static>(inner: R, encoding: Option<&str>) -> io::Result<Self> {
        match encoding {
            Some(enc) if enc.eq_ignore_ascii_case("gzip")
                || enc.eq_ignore_ascii_case("x-gzip") =>
            {
                Ok(Decompressor::Gzip(flate2::read::GzDecoder::new(Box::new(
                    inner,
                ))))
            }
            Some(enc) if enc.eq_ignore_ascii_case("deflate") => {
                Ok(Decompressor::Deflate(flate2::read::DeflateDecoder::new(Box::new(
                    inner,
                ))))
            }
            Some(enc) if enc.eq_ignore_ascii_case("identity") || enc.is_empty() => {
                Ok(Decompressor::Identity(Box::new(inner)))
            }
            Some(enc) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Content-Encoding: {}", enc),
            )),
            None => Ok(Decompressor::Identity(Box::new(inner))),
        }
    }

    /// Returns `true` if this decompressor is the identity (passthrough) variant.
    ///
    /// This can be used to skip unnecessary wrapping or buffer allocations when
    /// the response body is not compressed.
    ///
    /// # Returns
    ///
    /// `true` if this is an `Identity` decompressor, `false` otherwise.
    pub fn is_identity(&self) -> bool {
        matches!(self, Decompressor::Identity(_))
    }
}

impl Read for Decompressor {
    /// Reads decompressed bytes from the inner reader into the provided buffer.
    ///
    /// Delegates to the underlying decoder (gzip, deflate, or identity) depending
    /// on which variant was constructed.
    ///
    /// # Arguments
    ///
    /// * `buf` - The byte buffer to fill with decompressed data.
    ///
    /// # Returns
    ///
    /// The number of bytes read, or an I/O error if decompression fails.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Decompressor::Gzip(r) => r.read(buf),
            Decompressor::Deflate(r) => r.read(buf),
            Decompressor::Identity(r) => r.read(buf),
        }
    }
}
