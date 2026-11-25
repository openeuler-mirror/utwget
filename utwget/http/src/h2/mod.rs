//! HTTP/2 protocol support.
//!
//! This module provides HTTP/2 client implementation using the `h2` crate.
//! HTTP/2 offers significant performance improvements over HTTP/1.1 through:
//! - Binary framing with streams and multiplexing
//! - Header compression (HPACK)
//! - Server push
//! - Stream priorities
//!
//! # Features
//!
//! - Connection coalescing
//! - Stream multiplexing
//! - Header compression
//! - Flow control
//! - TLS with ALPN negotiation
//!
//! # Limitations
//!
//! - Server push is not currently supported
//! - Stream priorities are not implemented

use std::sync::Arc;

use bytes::Bytes;
pub use h2::client;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use http::{Request, Response};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use std::sync::OnceLock;
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;

/// Shared global tokio runtime for HTTP/2 operations.
/// Using a single runtime avoids creating one per H2Client, which would
/// spawn a fresh thread pool each time.
static H2_RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// 获取共享 H2 tokio runtime，或在不存在时创建。
///
/// 代码审查 S5：原 3 处 .expect("failed to create H2 runtime") 在系统资源
/// 耗尽时会 panic。现在统一返回 Result，调用方可优雅降级。
fn h2_runtime_or_err() -> Result<&'static Runtime, Box<dyn std::error::Error>> {
    if let Some(rt) = H2_RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let _ = H2_RUNTIME.set(rt); // 竞争时 set 失败正常，后续 get() 获取已有的
    Ok(H2_RUNTIME.get().expect("runtime was just set"))
}

/// Returns the process-wide tokio runtime shared by all HTTP/2 code.
///
/// Single source of truth: both `ut-http` (client) and `ut-retriever`
/// (integration layer) drive their H2 work on THIS runtime (arch 6.3-3:
/// previously each crate lazily built its own 2-worker runtime).
pub fn shared_h2_runtime() -> Result<&'static Runtime, Box<dyn std::error::Error>> {
    h2_runtime_or_err()
}

/// HTTP/2 client for making requests.
pub struct H2Client {
    /// The h2 send-request handle.
    sender: SendRequest<Bytes>,
    /// Tokio runtime for async operations. This is a static reference
    /// to a shared runtime, avoiding one-runtime-per-connection overhead.
    runtime: &'static tokio::runtime::Runtime,
}

impl H2Client {
    /// Create a new HTTP/2 client from an existing sender.
    ///
    /// This is used when the connection is established externally (e.g., through a proxy tunnel).
    ///
    /// # Arguments
    ///
    /// * `sender` - An existing h2 SendRequest handle.
    ///
    /// # Returns
    ///
    /// A new `H2Client` instance.
    pub fn from_sender(sender: SendRequest<Bytes>) -> Result<Self, Box<dyn std::error::Error>> {
        // Use a shared global runtime to avoid creating one per connection.
        let runtime: &'static tokio::runtime::Runtime = h2_runtime_or_err()?;
        Ok(H2Client { sender, runtime })
    }

    /// Create a new HTTP/2 client connected to the given host and port.
    ///
    /// Performs a TLS handshake using the supplied `rustls::ClientConfig`
    /// (which the caller is expected to have configured with ALPN `h2`,
    /// `--no-check-certificate`, custom CAs, client certificates, etc.) and
    /// then the HTTP/2 handshake.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target port (typically 443 for HTTPS).
    /// * `tls_config` - A pre-built rustls client config with ALPN `h2` set.
    ///
    /// # Returns
    ///
    /// A new `H2Client` instance.
    pub fn connect(
        host: &str,
        port: u16,
        tls_config: ClientConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime: &'static Runtime = h2_runtime_or_err()?;

        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        let tcp = runtime.block_on(TcpStream::connect(format!("{}:{}", host, port)))?;

        // Parse server name for TLS
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;

        // Perform TLS handshake
        let tls_stream = runtime.block_on(tls_connector.connect(server_name, tcp))?;

        // Check if HTTP/2 was negotiated
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        let use_http2 = alpn.map(|p| p == b"h2").unwrap_or(false);

        if !use_http2 {
            return Err("Server does not support HTTP/2".into());
        }

        // Perform HTTP/2 handshake
        let (sender, conn) = runtime.block_on(client::handshake(tls_stream))?;

        // Spawn the connection driver
        runtime.spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("HTTP/2 connection error: {}", e);
            }
        });

        Ok(H2Client { sender, runtime })
    }

    /// Send an HTTP/2 request and receive the response.
    ///
    /// # Arguments
    ///
    /// * `request` - The HTTP request to send (body should be empty, use send_body for body data).
    ///
    /// # Returns
    ///
    /// The HTTP response with body stream and a send stream for body data.
    pub fn send_request(
        &mut self,
        request: Request<()>,
    ) -> Result<(Response<RecvStream>, SendStream<Bytes>), Box<dyn std::error::Error>> {
        self.send_request_with_end(request, true)
    }

    /// Send a request, with explicit control over END_STREAM.
    ///
    /// `end_of_stream = false` must be used when the request carries a body
    /// that will be sent afterwards via [`Self::send_body`] — sending a
    /// POST/PUT with END_STREAM set and no data makes the server wait for a
    /// body that never arrives (M3).
    pub fn send_request_with_end(
        &mut self,
        request: Request<()>,
        end_of_stream: bool,
    ) -> Result<(Response<RecvStream>, SendStream<Bytes>), Box<dyn std::error::Error>> {
        self.runtime.block_on(async {
            let (response_future, send_stream) = self.sender.send_request(request, end_of_stream)?;
            let response = response_future.await?;
            Ok((response, send_stream))
        })
    }

    /// Check whether the connection is still usable, without sending data.
    ///
    /// Drives `SendRequest::ready()`: it resolves immediately when the
    /// connection can accept a new request and errors when the connection
    /// has been closed or reset (e.g. the peer closed an idle connection).
    /// A 500ms cap guards against a stalled link. Used by the connection
    /// pool to avoid handing out dead connections (M4).
    pub fn is_healthy(&mut self) -> bool {
        use std::future::poll_fn;
        use std::time::Duration;
        self.runtime.block_on(async {
            match tokio::time::timeout(
                Duration::from_millis(500),
                poll_fn(|cx| self.sender.poll_ready(cx)),
            )
            .await
            {
                Ok(Ok(())) => true,
                _ => false,
            }
        })
    }

    /// Send body data on a stream.
    ///
    /// # Arguments
    ///
    /// * `send_stream` - The send stream to write body data to.
    /// * `body` - The body data to send.
    ///
    /// # Returns
    ///
    /// Ok(()) on success.
    pub fn send_body(
        &mut self,
        send_stream: &mut SendStream<Bytes>,
        body: Bytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.runtime.block_on(async {
            send_stream.send_data(body, true)?;
            Ok(())
        })
    }

    /// Read the response body up to a maximum size to prevent OOM on huge
    /// responses (e.g. multi-GB ISO downloads over HTTP/2). The HTTP/1.x
    /// path streams the body to disk chunk-by-chunk, but the H2 path
    /// accumulates into a Vec. We cap accumulation at `max_bytes` and return
    /// an error if exceeded, so the caller can fall back to HTTP/1.1 or report
    /// a clear error instead of being OOM-killed.
    ///
    /// # Arguments
    ///
    /// * `stream` - The response body stream.
    /// * `max_bytes` - Maximum body size in bytes. If the body exceeds this,
    ///   returns an error.
    ///
    /// # Returns
    ///
    /// The response body as bytes, or an error if the body exceeds `max_bytes`.
    pub fn read_body_limited(
        &self,
        stream: &mut RecvStream,
        max_bytes: usize,
    ) -> Result<Bytes, Box<dyn std::error::Error>> {
        self.runtime.block_on(async {
            let mut body = Vec::new();
            while let Some(chunk_result) = stream.data().await {
                let chunk = chunk_result?;
                if body.len().saturating_add(chunk.len()) > max_bytes {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "HTTP/2 response body exceeds {} byte limit; use HTTP/1.1 for large downloads (or increase --quota)",
                            max_bytes
                        ),
                    ))
                        as Box<dyn std::error::Error>);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Bytes::from(body))
        })
    }

    /// Read the entire response body.
    ///
    /// **Warning**: This reads the entire body into memory. For large
    /// downloads use [`Self::read_body_limited`] with a cap, or prefer the
    /// HTTP/1.x path which streams to disk.
    ///
    /// # Arguments
    ///
    /// * `stream` - The response body stream.
    ///
    /// # Returns
    ///
    /// The response body as bytes.
    pub fn read_body(&self, stream: &mut RecvStream) -> Result<Bytes, Box<dyn std::error::Error>> {
        self.runtime.block_on(async {
            let mut body = Vec::new();
            while let Some(chunk_result) = stream.data().await {
                let chunk = chunk_result?;
                body.extend_from_slice(&chunk);
            }
            Ok(Bytes::from(body))
        })
    }
}

