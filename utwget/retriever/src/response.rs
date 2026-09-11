//! HTTP response head/body parsing and streaming utilities.
//!
//! This module encapsulates the low-level HTTP response reading logic:
//! - Reading and parsing the response head (status line + headers)
//! - Streaming the response body to disk (chunked, content-length, or EOF-delimited)
//! - Handling informational (1xx) interim responses
//!
//! These functions were extracted from the monolithic `retriever.rs` to improve
//! readability and testability (代码审查 P0 #1.3, second step).

use std::io::{Read, Write};

use log::debug;
use ut_core::WgetError;
use ut_http::response::HttpResponse;
use ut_progress::ProgressDisplay;

use crate::types::{RetrieveError, RetrieveOutcome};

/// I/O buffer size for streaming response bodies (64KB).
///
/// Larger buffers reduce the number of system calls for read/write operations,
/// significantly improving throughput for large file downloads.
/// 64KB is a good balance between memory usage and syscall reduction.
pub(crate) const IO_BUFFER_SIZE: usize = 64 * 1024;

/// Result of streaming a response body to disk.
pub(crate) struct BodyReadResult {
    /// Number of bytes written (after de-chunking / decompression where applicable).
    pub bytes: u64,
    /// Whether the connection was fully drained and is safe to reuse.
    ///
    /// This is `false` for close-delimited bodies (EOF terminated), where the
    /// server has already closed the connection, and for truncated bodies.
    pub connection_reusable: bool,
}

/// Stream the HTTP response body to a writer.
///
/// Handles three body transfer modes:
/// 1. **Chunked transfer encoding** (`Transfer-Encoding: chunked`)
/// 2. **Content-Length delimited** (known body size)
/// 3. **Close-delimited** (read until EOF; connection not reusable)
///
/// When `ignore_length` is `true` (set by `--ignore-length`), the
/// Content-Length header is ignored and the body is read until EOF.
pub(crate) fn stream_response_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    response: &HttpResponse,
    progress: &mut dyn ProgressDisplay,
    resume_from: u64,
    ignore_length: bool,
) -> Result<BodyReadResult, RetrieveError> {
    let start = std::time::Instant::now();
    if response.is_chunked() {
        let mut received = 0u64;
        let mut chunked = ut_http::chunked::ChunkedReader::new(reader);
        while let Some(chunk) = chunked
            .read_next_chunk()
            .map_err(|e| RetrieveError::Protocol(WgetError::ProtocolIo(format!("chunked body read error: {}", e))))?
        {
            writer.write_all(&chunk).map_err(RetrieveError::Io)?;
            received += chunk.len() as u64;
            progress.update(resume_from + received, start.elapsed());
        }
        // Chunked bodies are terminated by a 0-length chunk (and optional
        // trailers), so the connection is fully drained and reusable.
        Ok(BodyReadResult {
            bytes: received,
            connection_reusable: true,
        })
    } else if !ignore_length {
        if let Some(len) = response.content_length() {
            let mut received = 0u64;
            let mut tmp = [0u8; IO_BUFFER_SIZE];
            while received < len {
                let want = ((len - received) as usize).min(tmp.len());
                let n = reader
                    .read(&mut tmp[..want])
                    .map_err(|e| RetrieveError::Protocol(WgetError::ProtocolIo(format!("body read error: {}", e))))?;
                if n == 0 {
                    // Truncated body: the server closed the connection before
                    // delivering all promised bytes. Return an error so the caller
                    // discards the connection (never returns it to the pool) and
                    // may retry with a Range request, matching wget's behavior.
                    return Err(RetrieveError::Protocol(WgetError::BodyTruncated {
                        received,
                        expected: len,
                    }));
                }
                writer.write_all(&tmp[..n]).map_err(RetrieveError::Io)?;
                received += n as u64;
                progress.update(resume_from + received, start.elapsed());
            }
            Ok(BodyReadResult {
                bytes: received,
                connection_reusable: true,
            })
        } else {
            read_until_eof(reader, writer, progress, resume_from)
        }
    } else {
        read_until_eof(reader, writer, progress, resume_from)
    }
}

/// Read the response body until EOF, writing each chunk to `writer`.
///
/// The body is terminated by the connection closing (close-delimited body),
/// so the connection can never be reused afterwards.
fn read_until_eof<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    progress: &mut dyn ProgressDisplay,
    resume_from: u64,
) -> Result<BodyReadResult, RetrieveError> {
    let start = std::time::Instant::now();
    let mut received = 0u64;
    let mut tmp = [0u8; IO_BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut tmp)
            .map_err(|e| RetrieveError::Protocol(WgetError::ProtocolIo(format!("body read error: {}", e))))?;
        if n == 0 {
            break;
        }
        writer.write_all(&tmp[..n]).map_err(RetrieveError::Io)?;
        received += n as u64;
        progress.update(resume_from + received, start.elapsed());
    }
    Ok(BodyReadResult {
        bytes: received,
        // EOF-terminated bodies mean the server closed the connection.
        connection_reusable: false,
    })
}

/// Reads only the HTTP response head (status line + headers), returning any
/// leftover body bytes that were read together with the headers.
///
/// Informational (1xx) interim responses such as `100 Continue` are skipped,
/// matching wget's behavior, so the caller only ever sees a final response.
pub(crate) fn read_response_head<R: Read>(
    reader: &mut R,
) -> Result<(HttpResponse, Vec<u8>), RetrieveError> {
    let mut leftover: Vec<u8> = Vec::new();
    loop {
        // Prepend any leftover bytes from the previous 1xx response so they
        // are not lost. If the server sent `100 Continue\r\n\r\n` and the final
        // response in the same TCP segment, the final response bytes are in
        // `leftover` and must be parsed before reading more from the socket.
        let buf_to_parse = if leftover.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut leftover))
        };

        let (response, new_leftover) = if let Some(buf) = buf_to_parse {
            // Try to parse the leftover bytes first; if they contain a complete
            // response, use it; otherwise prepend to the next read.
            match try_parse_from_buf(&buf) {
                Some(result) => result,
                None => {
                    // Not enough bytes in leftover; need to read more.
                    leftover = buf;
                    read_one_response_head_with_prefix(reader, &mut leftover)?
                }
            }
        } else {
            read_one_response_head(reader)?
        };

        if response.is_informational() {
            debug!(
                "skipping informational response: {} {}",
                response.status_code, response.reason
            );
            leftover = new_leftover;
            continue;
        }
        return Ok((response, new_leftover));
    }
}

/// Try to parse a complete response head from a buffer, returning the
/// response and any leftover body bytes.
fn try_parse_from_buf(buf: &[u8]) -> Option<(HttpResponse, Vec<u8>)> {
    let body_start = ut_http::response::find_header_end(buf)?;
    let response = ut_http::response::parse_response_head(&buf[..body_start])?;
    let leftover: Vec<u8> = buf[body_start..].to_vec();
    Some((response, leftover))
}

/// Reads a single response head, using `prefix` as pre-existing bytes
/// before reading from the reader.
fn read_one_response_head_with_prefix<R: Read>(
    reader: &mut R,
    prefix: &mut Vec<u8>,
) -> Result<(HttpResponse, Vec<u8>), RetrieveError> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(body_start) = ut_http::response::find_header_end(prefix) {
            let response = ut_http::response::parse_response_head(&prefix[..body_start])
                .ok_or_else(|| RetrieveError::Protocol(WgetError::ProtocolIo("failed to parse HTTP response".into())))?;
            let leftover: Vec<u8> = prefix[body_start..].to_vec();
            return Ok((response, leftover));
        }
        if prefix.len() > 64 * 1024 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "HTTP response headers too large (>64KB)".into(),
            )));
        }
        let n = reader
            .read(&mut tmp)
            .map_err(|e| RetrieveError::Protocol(WgetError::ProtocolIo(format!("read response head: {}", e))))?;
        if n == 0 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "connection closed before response headers received".into(),
            )));
        }
        prefix.extend_from_slice(&tmp[..n]);
    }
}

/// Reads a single response head (status line + headers), returning any
/// leftover body bytes that were read together with the headers.
fn read_one_response_head<R: Read>(
    reader: &mut R,
) -> Result<(HttpResponse, Vec<u8>), RetrieveError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];
    let body_start = loop {
        if let Some(end) = ut_http::response::find_header_end(&buf) {
            break end;
        }
        if buf.len() > 64 * 1024 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "HTTP response headers too large (>64KB)".into(),
            )));
        }
        let n = reader
            .read(&mut tmp)
            .map_err(|e| RetrieveError::Protocol(WgetError::ProtocolIo(format!("read response head: {}", e))))?;
        if n == 0 {
            return Err(RetrieveError::Protocol(WgetError::Other(
                "connection closed before response headers received".into(),
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let response = ut_http::response::parse_response_head(&buf[..body_start])
        .ok_or_else(|| RetrieveError::Protocol(WgetError::ProtocolIo("failed to parse HTTP response".into())))?;
    let leftover: Vec<u8> = buf[body_start..].to_vec();
    Ok((response, leftover))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Reader that yields fixed byte slices one at a time, then EOF.
    struct ChunkReader {
        parts: Vec<Cursor<Vec<u8>>>,
    }

    impl ChunkReader {
        fn new(parts: &[&[u8]]) -> Self {
            ChunkReader {
                parts: parts.iter().map(|p| Cursor::new(p.to_vec())).collect(),
            }
        }
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            while !self.parts.is_empty() {
                let n = self.parts[0].read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                self.parts.remove(0);
            }
            Ok(0)
        }
    }

    #[test]
    fn bare_lf_head_split_across_reads_does_not_panic() {
        // Regression (P0): a bare-LF terminated response head arriving exactly
        // at a read boundary must not slice out of bounds (remote DoS).
        // Terminator in its own read, body not yet read → leftover empty.
        let mut reader = ChunkReader::new(&[b"HTTP/1.1 200 OK\nX-Foo: a", b"\n\n", b"BODY"]);
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.headers.get("X-Foo"), Some("a"));
        assert!(leftover.is_empty());
        // Body bytes already in the same read must be fully preserved.
        let mut reader = ChunkReader::new(&[b"HTTP/1.1 200 OK\nX-Foo: a", b"\n\nBODY"]);
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(leftover, b"BODY");
        // Remaining body bytes are still readable from the underlying reader.
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn bare_lf_head_body_fully_preserved() {
        // Regression: with \n\n terminators the old +4 arithmetic silently
        // swallowed the first 2 body bytes.
        let mut reader = Cursor::new(b"HTTP/1.1 200 OK\nA: b\n\nBODY".to_vec());
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(leftover, b"BODY");
    }

    #[test]
    fn crlf_head_leftover_correct() {
        let mut reader = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nBODY".to_vec());
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.headers.content_length(), Some(4));
        assert_eq!(leftover, b"BODY");
    }

    #[test]
    fn mixed_line_endings_head_parsed() {
        // Header line ends with \n and the blank line is \r\n.
        let mut reader = Cursor::new(b"HTTP/1.1 200 OK\nA: b\n\r\nBODY".to_vec());
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.headers.get("A"), Some("b"));
        assert_eq!(leftover, b"BODY");
    }

    #[test]
    fn body_terminator_lookalike_does_not_misalign_head() {
        // A \r\n\r\n sequence inside the body must not move the header
        // boundary: the earliest terminator wins.
        let mut reader = Cursor::new(b"HTTP/1.1 200 OK\nA: b\n\nX\r\n\r\nBODY".to_vec());
        let (resp, leftover) = read_response_head(&mut reader).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(leftover, b"X\r\n\r\nBODY");
    }
}
