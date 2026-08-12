//! HTTP/1.x protocol codec implementation.
//!
//! This module provides the codec for sending HTTP/1.x requests and
//! reading HTTP/1.x responses over a transport.

use crate::request::HttpRequest;
use crate::response::{find_header_end, parse_response_head, HttpResponse};
use std::io::{self, Read};

/// HTTP/1.x codec for sending requests and reading responses.
///
/// This is a stateless codec that can serialize requests and parse
/// response headers from any transport implementing `Read` and `Write`.
pub struct H1Codec;

impl H1Codec {
    /// Sends an HTTP request over a writer.
    ///
    /// Serializes the request to bytes and writes them to the transport.
    ///
    /// # Arguments
    ///
    /// * `writer` - The transport to write to.
    /// * `request` - The request to send.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an I/O error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use utwget_http::h1::H1Codec;
    /// use utwget_http::request::{HttpRequest, HttpMethod};
    ///
    /// let req = HttpRequest::new(HttpMethod::Get, "/".into(), "example.com".into());
    /// H1Codec::send_request(&mut transport, &req)?;
    /// ```
    pub fn send_request<W: io::Write>(writer: &mut W, request: &HttpRequest) -> io::Result<()> {
        let bytes = request.serialize()?;
        writer.write_all(&bytes)?;
        writer.flush()?;
        Ok(())
    }

    /// Reads an HTTP response header from a reader.
    ///
    /// Reads bytes until the complete header section (ending with `\r\n\r\n`)
    /// is received, then parses it into an `HttpResponse`.
    ///
    /// # Arguments
    ///
    /// * `reader` - The transport to read from.
    ///
    /// # Returns
    ///
    /// The parsed `HttpResponse` on success, or an I/O error.
    ///
    /// # Errors
    ///
    /// - `UnexpectedEof` if the connection closes before headers are complete.
    /// - `InvalidData` if headers are malformed or exceed 64KB.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use utwget_http::h1::H1Codec;
    ///
    /// let response = H1Codec::read_response_head(&mut transport)?;
    /// println!("Status: {}", response.status_code);
    /// ```
    pub fn read_response_head<R: Read>(reader: &mut R) -> io::Result<HttpResponse> {
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 4096];

        loop {
            let n = reader.read(&mut tmp)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed before response headers received",
                ));
            }
            buf.extend_from_slice(&tmp[..n]);

            if let Some(end) = find_header_end(&buf) {
                let header_bytes = &buf[..end + 4];
                match parse_response_head(header_bytes) {
                    Some(resp) => return Ok(resp),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "failed to parse HTTP response status line",
                        ));
                    }
                }
            }

            if buf.len() > 64 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP response headers too large (>64KB)",
                ));
            }
        }
    }
}
