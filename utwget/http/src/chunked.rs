//! HTTP Chunked Transfer Encoding support.
//!
//! This module provides a reader for HTTP response bodies using chunked
//! transfer encoding as specified in RFC 7230 Section 4.1.
//!
//! # Chunked Transfer Encoding
//!
//! When a server uses chunked encoding, the response body is sent as a series
//! of chunks, each prefixed with its size in hexadecimal. The body is terminated
//! by a zero-sized chunk. This allows the server to send dynamically generated
//! content without knowing the total size in advance.
//!
//! # Example
//!
//! ```ignore
//! use utwget_http::chunked::ChunkedReader;
//! use std::io::Cursor;
//!
//! // HTTP chunked response body: "5\r\nhello\r\n0\r\n\r\n"
//! let data = b"5\r\nhello\r\n0\r\n\r\n";
//! let mut cursor = Cursor::new(&data[..]);
//! let mut reader = ChunkedReader::new(&mut cursor);
//!
//! // Read all chunks
//! let mut output = Vec::new();
//! let total = reader.read_to_end(&mut output).unwrap();
//! assert_eq!(output, b"hello");
//! ```

use std::io::{self, Read, Write};

/// Internal state machine for chunk parsing.
enum ChunkState {
    /// Waiting to read the next chunk size line.
    ReadSize,
    /// Currently reading chunk data with `remaining` bytes left.
    ReadData { remaining: usize },
    /// Reading trailer headers after the final zero-sized chunk.
    ReadTrailer,
    /// All chunks have been read; no more data available.
    Done,
}
