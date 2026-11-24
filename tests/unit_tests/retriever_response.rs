//! Unit tests for HTTP response head reading (ut_retriever::response).
//!
//! Regression coverage for the P0 bare-LF fix: `find_header_end` now returns
//! the body-start offset, so a bare-LF terminated head arriving exactly at a
//! read boundary must neither panic nor swallow body bytes.

use std::io::{Cursor, Read};

use ut_retriever::response::read_response_head;

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

#[test]
fn informational_response_is_skipped() {
    // 100 Continue followed by the final response in one buffer.
    let mut reader = Cursor::new(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\nFINAL".to_vec(),
    );
    let (resp, leftover) = read_response_head(&mut reader).unwrap();
    assert_eq!(resp.status_code, 200);
    assert_eq!(leftover, b"FINAL");
}
