//! HTTP Client implementation.
//!
//! This module provides the main HTTP client for making requests and handling
//! responses, including authentication, redirects, and content decoding.

use std::io::{self, Read, Write};
use std::sync::Arc;

use ut_core::config::Config;
use ut_core::types::{Credentials, HttpMethod, Scheme};
use ut_core::url::ParsedUrl;

use crate::auth::{self, AuthChallenge, AuthDispatcher};
use crate::chunked::ChunkedReader;
use crate::headers;
use crate::h1::H1Codec;
use crate::request::{self, HttpRequest};
use crate::response::HttpResponse;

/// Options for customizing an HTTP fetch request.
///
/// These options control how the request is built and sent, including
/// the HTTP method, body content, headers, and authentication behavior.
pub struct FetchOptions {
    /// The HTTP method to use (defaults to GET).
    pub method: Option<HttpMethod>,
    /// The request body for POST/PUT requests.
    pub body: Option<Vec<u8>>,
    /// Additional headers to include in the request.
    pub extra_headers: Vec<(String, String)>,
    /// Whether to route the request through a proxy.
    pub use_proxy: bool,
    /// Byte offset to resume from (for partial downloads).
    pub resume_from: Option<u64>,
    /// If-Modified-Since header value for conditional requests.
    pub if_modified_since: Option<chrono::DateTime<chrono::Utc>>,
    /// If-None-Match header value for conditional requests.
    pub if_none_match: Option<String>,
    /// Cookie header value.
    pub cookies: Option<String>,
}

impl Default for FetchOptions {
    /// Creates default fetch options for a simple GET request.
    fn default() -> Self {
        FetchOptions {
            method: None,
            body: None,
            extra_headers: Vec::new(),
            use_proxy: false,
            resume_from: None,
            if_modified_since: None,
            if_none_match: None,
            cookies: None,
        }
    }
}

/// Result of an HTTP fetch operation.
///
/// Contains the response status, headers, and an optional body reader.
pub struct FetchResult {
    /// The HTTP status code (e.g., 200, 404).
    pub status_code: u16,
    /// The complete HTTP response with headers.
    pub response: HttpResponse,
    /// A reader for the response body, if present.
    pub body_reader: Option<BodyReaderEnum>,
    /// Whether the response is a redirect.
    pub redirected: bool,
    /// Whether authentication was handled automatically.
    pub auth_handled: bool,
}

/// Enumeration of different body transfer modes.
///
/// HTTP response bodies can be transferred in different ways depending
/// on the headers present in the response.
pub enum BodyReaderEnum {
    /// Body with a known Content-Length.
    ContentLength {
        /// Number of bytes remaining to read.
        remaining: u64,
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
    /// Body using chunked transfer encoding.
    Chunked {
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
    /// Body with unknown length (read until connection close).
    ReadToEnd {
        /// The underlying transport.
        transport: Box<dyn Read + Send>,
        /// Optional decompressor for compressed content.
        #[cfg(feature = "compression")]
        decompressor: Option<crate::compression::Decompressor>,
    },
}

impl BodyReaderEnum {
    /// Reads the entire body and writes it to the output.
    ///
    /// Handles all three transfer modes transparently.
    ///
    /// # Arguments
    ///
    /// * `output` - The writer to receive the body data.
    ///
    /// # Returns
    ///
    /// The total number of bytes written.
    pub fn read_to_end(self, output: &mut dyn Write) -> io::Result<u64> {
        match self {
            BodyReaderEnum::ContentLength { remaining, transport, #[cfg(feature = "compression")] decompressor } => {
                read_exact(output, transport, remaining, decompressor)
            }
            BodyReaderEnum::Chunked { transport, #[cfg(feature = "compression")] decompressor } => {
                read_chunked(output, transport, decompressor)
            }
            BodyReaderEnum::ReadToEnd { transport, #[cfg(feature = "compression")] decompressor } => {
                read_until_eof(output, transport, decompressor)
            }
        }
    }
}

/// Wraps a transport with a decompressor if needed.
///
/// # Arguments
///
/// * `transport` - The underlying transport.
/// * `encoding` - The Content-Encoding header value.
///
/// # Returns
///
/// A decompressor if compression is detected, otherwise None.
#[cfg(feature = "compression")]
fn wrap_with_decompressor(
    transport: Box<dyn Read + Send>,
    encoding: Option<&str>,
) -> Option<crate::compression::Decompressor> {
    crate::compression::Decompressor::from_encoding(DecompressorRead(transport), encoding).ok().filter(|d| !d.is_identity())
}

/// Adapter to implement Read for boxed transport.
#[cfg(feature = "compression")]
struct DecompressorRead(Box<dyn Read + Send>);

#[cfg(feature = "compression")]
impl Read for DecompressorRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// Reads exactly `remaining` bytes from the transport.
///
/// # Arguments
///
/// * `output` - The output writer.
/// * `transport` - The transport reader.
/// * `remaining` - The exact number of bytes to read.
/// * `decompressor` - Optional decompressor for compressed content.
///
/// # Returns
///
/// The number of bytes written.
#[cfg(feature = "compression")]
fn read_exact(
    output: &mut dyn Write,
    transport: Box<dyn Read + Send>,
    mut remaining: u64,
    decompressor: Option<crate::compression::Decompressor>,
) -> io::Result<u64> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];

    if let Some(mut decomp) = decompressor {
        loop {
            if remaining == 0 {
                break;
            }
            let to_read = (remaining as usize).min(buf.len());
            let n = decomp.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            output.write_all(&buf[..n])?;
            total += n as u64;
            remaining -= n as u64;
        }
    } else {
        loop {
            if remaining == 0 {
                break;
            }
            let to_read = (remaining as usize).min(buf.len());
            let n = transport.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            output.write_all(&buf[..n])?;
            total += n as u64;
            remaining -= n as u64;
        }
    }

    Ok(total)
}

/// Reads a chunked transfer-encoded body.
///
/// # Arguments
///
/// * `output` - The output writer.
/// * `transport` - The transport reader.
/// * `decompressor` - Optional decompressor for compressed content.
///
/// # Returns
///
/// The number of bytes written.
#[cfg(feature = "compression")]
fn read_chunked(
    output: &mut dyn Write,
    transport: Box<dyn Read + Send>,
    decompressor: Option<crate::compression::Decompressor>,
) -> io::Result<u64> {
    let mut reader = ChunkedReaderAdapter { inner: transport };

    let mut total = 0u64;
    loop {
        let line = read_chunk_line(&mut reader)?;
        if line.is_empty() {
            continue;
        }

        let size = parse_chunk_size(&line)?;
        if size == 0 {
            break;
        }

        let mut read_so_far = 0usize;
        while read_so_far < size {
            let to_read = (size - read_so_far).min(8192);
            let mut buf = vec![0u8; to_read];

            let n = if let Some(ref mut decomp) = decompressor {
                decomp.read(&mut buf)?
            } else {
                reader.read(&mut buf)?
            };

            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF in chunk data",
                ));
            }

            output.write_all(&buf[..n])?;
            read_so_far += n;
        }

        total += size as u64;
    }

    Ok(total)
}

/// Reads a chunked body without compression support.
#[cfg(not(feature = "compression"))]
fn read_chunked(
    output: &mut dyn Write,
    transport: Box<dyn Read + Send>,
) -> io::Result<u64> {
    let mut reader = ChunkedReaderAdapter { inner: transport };
    let mut total = 0u64;

    loop {
        let line = read_chunk_line(&mut reader)?;
        if line.is_empty() {
            continue;
        }

        let size = parse_chunk_size(&line)?;
        if size == 0 {
            break;
        }

        io::copy(&mut reader.by_ref().take(size as u64), output)?;
        total += size as u64;
    }

    Ok(total)
}

/// Reads until end of file (connection close).
///
/// # Arguments
///
/// * `output` - The output writer.
/// * `transport` - The transport reader.
/// * `decompressor` - Optional decompressor for compressed content.
///
/// # Returns
///
/// The number of bytes written.
#[cfg(feature = "compression")]
fn read_until_eof(
    output: &mut dyn Write,
    transport: Box<dyn Read + Send>,
    decompressor: Option<crate::compression::Decompressor>,
) -> io::Result<u64> {
    if let Some(mut decomp) = decompressor {
        io::copy(&mut decomp, output)
    } else {
        io::copy(&mut transport.take(u64::MAX), output)
    }
}

/// Reads until EOF without compression support.
#[cfg(not(feature = "compression"))]
fn read_until_eof(
    output: &mut dyn Write,
    transport: Box<dyn Read + Send>,
) -> io::Result<u64> {
    io::copy(&mut transport.take(u64::MAX), output)
}

/// Adapter to implement Read for boxed transport.
struct ChunkedReaderAdapter {
    inner: Box<dyn Read + Send>,
}

impl Read for ChunkedReaderAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

/// Reads a single line from a chunked stream.
///
/// # Arguments
///
/// * `reader` - The reader to read from.
///
/// # Returns
///
/// The line content without CRLF.
fn read_chunk_line(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF reading chunk size",
            ));
        }
        line.push(byte[0]);
        if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if line.len() > 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk size line too long",
            ));
        }
    }
}

/// Parses a chunk size from a line.
///
/// # Arguments
///
/// * `line` - The chunk size line.
///
/// # Returns
///
/// The parsed size in bytes.
fn parse_chunk_size(line: &[u8]) -> io::Result<usize> {
    let s = std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size not utf8"))?;
    let hex = s.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(hex, 16).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid chunk size: {}", hex))
    })
}

/// Returns None when compression is not enabled.
#[cfg(not(feature = "compression"))]
fn no_decompressor() -> Option<()> {
    None
}

/// Creates a body reader based on the response headers.
///
/// # Arguments
///
/// * `response` - The HTTP response.
/// * `transport` - The transport reader.
///
/// # Returns
///
/// The appropriate body reader variant.
#[cfg(feature = "compression")]
fn make_body_reader(
    response: &HttpResponse,
    transport: Box<dyn Read + Send>,
) -> BodyReaderEnum {
    let encoding = response.headers.content_encoding();

    if response.is_chunked() {
        BodyReaderEnum::Chunked {
            transport,
            decompressor: wrap_with_decompressor(transport, encoding),
        }
    } else if let Some(len) = response.content_length() {
        BodyReaderEnum::ContentLength {
            remaining: len,
            transport,
            decompressor: wrap_with_decompressor(transport, encoding),
        }
    } else {
        BodyReaderEnum::ReadToEnd {
            transport,
            decompressor: wrap_with_decompressor(transport, encoding),
        }
    }
}

/// Creates a body reader without compression support.
#[cfg(not(feature = "compression"))]
fn make_body_reader(
    response: &HttpResponse,
    transport: Box<dyn Read + Send>,
) -> BodyReaderEnum {
    if response.is_chunked() {
        BodyReaderEnum::Chunked { transport }
    } else if let Some(len) = response.content_length() {
        BodyReaderEnum::ContentLength {
            remaining: len,
            transport,
        }
    } else {
        BodyReaderEnum::ReadToEnd { transport }
    }
}

/// HTTP client for making requests.
///
/// The client handles request building, authentication, and response parsing.
/// It is configured with a `Config` object that controls behavior like
/// user agent, timeouts, and authentication settings.
///
/// # Example
///
/// ```ignore
/// use utwget_http::client::{HttpClient, FetchOptions};
/// use ut_core::config::Config;
/// use std::sync::Arc;
///
/// let config = Arc::new(Config::default());
/// let mut client = HttpClient::new(config);
///
/// let url = ParsedUrl::parse("http://example.com/").unwrap();
/// let opts = FetchOptions::default();
/// let result = client.fetch(&url, &opts, &mut transport);
/// ```
pub struct HttpClient {
    /// Configuration for the client.
    config: Arc<Config>,
    /// Authentication dispatcher for handling auth challenges.
    auth_dispatch: AuthDispatcher,
}

impl HttpClient {
    /// Creates a new HTTP client with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to use for requests.
    ///
    /// # Returns
    ///
    /// A new `HttpClient` instance.
    pub fn new(config: Arc<Config>) -> Self {
        let mut auth_dispatch = AuthDispatcher::new();
        if config.auth_without_challenge {
        }
        HttpClient {
            config,
            auth_dispatch,
        }
    }

    /// Sets a custom authentication dispatcher.
    ///
    /// # Arguments
    ///
    /// * `dispatch` - The authentication dispatcher to use.
    ///
    /// # Returns
    ///
    /// The modified client instance.
    pub fn with_auth_dispatcher(mut self, dispatch: AuthDispatcher) -> Self {
        self.auth_dispatch = dispatch;
        self
    }

    /// Performs an HTTP fetch operation.
    ///
    /// This is the main entry point for making HTTP requests. It builds
    /// the request, sends it, and handles authentication challenges if needed.
    ///
    /// # Arguments
    ///
    /// * `url` - The parsed URL to fetch.
    /// * `opts` - Options for the request.
    /// * `transport` - The transport to use for I/O.
    ///
    /// # Returns
    ///
    /// A `FetchResult` containing the response status, headers, and body reader.
    pub fn fetch<T>(
        &mut self,
        url: &ParsedUrl,
        opts: &FetchOptions,
        transport: &mut T,
    ) -> io::Result<FetchResult>
    where
        T: Read + Write,
    {
        let authorization = self.resolve_authorization(url, opts);
        let cookies = opts.cookies.as_deref();

        let mut req = request::build_request(
            url,
            &self.config,
            &opts.extra_headers,
            opts.method,
            opts.body.clone(),
            opts.resume_from,
            opts.if_modified_since.as_ref(),
            opts.if_none_match.as_deref(),
            cookies,
            authorization.as_deref(),
        );

        H1Codec::send_request(transport, &req)?;
        let mut response = H1Codec::read_response_head(transport)?;

        if response.status_code == 401 {
            let auth_headers = response.headers.www_authenticate();
            if !auth_headers.is_empty() {
                let challenges = auth::parse_www_authenticate(&auth_headers);
                if let Some(challenge) = challenges.iter().find(|c| {
                    matches!(
                        c.scheme,
                        auth::AuthScheme::Basic
                            | auth::AuthScheme::Digest
                    )
                }) {
                    let credentials = self.resolve_credentials(url);
                    if let Some(creds) = credentials {
                        let auth_header = self.auth_dispatch.authenticate(
                            challenge,
                            &creds,
                            req.method.as_str(),
                            &req.path,
                            opts.body.as_deref(),
                        ).map_err(|e| {
                            io::Error::new(io::ErrorKind::Other, e.to_string())
                        })?;

                        if let Some(auth_val) = auth_header {
                            req.remove_header("Authorization");
                            req.header("Authorization", &auth_val);

                            H1Codec::send_request(transport, &req)?;
                            response = H1Codec::read_response_head(transport)?;

                            return Ok(FetchResult {
                                status_code: response.status_code,
                                body_reader: None,
                                response,
                                redirected: false,
                                auth_handled: true,
                            });
                        }
                    }
                }
            }
        }

        if response.status_code == 407 {
            let proxy_auth_headers = response.headers.proxy_authenticate();
            let _proxy_challenges = auth::parse_www_authenticate(&proxy_auth_headers);
        }

        let redirected = response.is_redirect();
        let status_code = response.status_code;
        let response_clone = HttpResponse {
            version: response.version.clone(),
            status_code: response.status_code,
            reason: response.reason.clone(),
            headers: response.headers.clone(),
            body: None,
        };

        let body_reader = if (200..400).contains(&status_code) || self.config.http.content_on_error {
            Some(make_body_reader(&response, Box::new(DummyRead)))
        } else {
            None
        };

        Ok(FetchResult {
            status_code,
            response: response_clone,
            body_reader,
            redirected,
            auth_handled: false,
        })
    }

    /// Resolves the Authorization header value for a request.
    ///
    /// Returns credentials for preemptive authentication if enabled.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL being requested.
    /// * `_opts` - The fetch options.
    ///
    /// # Returns
    ///
    /// The Authorization header value, if any.
    fn resolve_authorization(&self, url: &ParsedUrl, _opts: &FetchOptions) -> Option<String> {
        let credentials = self.resolve_credentials(url)?;

        if self.config.auth_without_challenge {
            let request_uri = url.full_path();
            return self.auth_dispatch.preemptive_auth(&credentials, &request_uri);
        }

        None
    }

    /// Resolves credentials for a URL.
    ///
    /// Credentials can come from the URL itself (user:pass@host) or
    /// from the configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL being requested.
    ///
    /// # Returns
    ///
    /// The credentials to use, if any.
    fn resolve_credentials(&self, url: &ParsedUrl) -> Option<Credentials> {
        if let (Some(ref user), Some(ref password)) = (&url.user, &url.password) {
            return Some(Credentials {
                username: user.clone(),
                password: password.clone(),
            });
        }

        if let (Some(ref user), Some(ref password)) = (&self.config.http.user, &self.config.http.password) {
            return Some(Credentials {
                username: user.clone(),
                password: password.clone(),
            });
        }

        None
    }
}
