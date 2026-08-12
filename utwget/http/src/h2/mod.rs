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
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;
use webpki_roots::TLS_SERVER_ROOTS;

/// HTTP/2 client for making requests.
pub struct H2Client {
    /// The h2 send-request handle.
    sender: SendRequest<Bytes>,
    /// Tokio runtime for async operations.
    runtime: Runtime,
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
    pub fn from_sender(sender: SendRequest<Bytes>) -> Self {
        let runtime = Runtime::new().expect("failed to create tokio runtime");
        H2Client { sender, runtime }
    }

    /// Create a new HTTP/2 client connected to the given host and port.
    ///
    /// Performs TLS handshake with ALPN negotiation for HTTP/2.
    ///
    /// # Arguments
    ///
    /// * `host` - The target hostname.
    /// * `port` - The target port (typically 443 for HTTPS).
    ///
    /// # Returns
    ///
    /// A new `H2Client` instance.
    pub fn connect(host: &str, port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let runtime = Runtime::new()?;
        
        // Build TLS config with ALPN for HTTP/2
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
        
        let mut tls_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        // Set ALPN protocol to h2 for HTTP/2 negotiation
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        
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
        self.runtime.block_on(async {
            let (response_future, send_stream) = self.sender.send_request(request, true)?;
            let response = response_future.await?;
            Ok((response, send_stream))
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

    /// Read the entire response body.
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

/// Check if the server supports HTTP/2 via ALPN.
///
/// This function performs TLS ALPN negotiation to determine if the server
/// supports HTTP/2.
pub fn check_http2_support(host: &str, port: u16) -> bool {
    let runtime = match Runtime::new() {
        Ok(r) => r,
        Err(_) => return false,
    };
    
    let tcp = match runtime.block_on(TcpStream::connect(format!("{}:{}", host, port))) {
        Ok(t) => t,
        Err(_) => return false,
    };
    
    // Build TLS config with ALPN for HTTP/2
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    
    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    
    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    let tls_stream = match runtime.block_on(tls_connector.connect(server_name, tcp)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    // Check if HTTP/2 was negotiated
    tls_stream.get_ref().1.alpn_protocol() == Some(b"h2")
}

/// Convert HTTP/1.1 headers to HTTP/2 format.
///
/// HTTP/2 requires lowercase header names and removes the "Connection" header.
pub fn convert_headers_to_h2(headers: &http::HeaderMap) -> http::HeaderMap {
    let mut h2_headers = http::HeaderMap::new();
    
    for (name, value) in headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if name_str != "connection" && name_str != "transfer-encoding" {
            if let Ok(name) = http::header::HeaderName::from_bytes(name_str.as_bytes()) {
                h2_headers.insert(name, value.clone());
            }
        }
    }
    
    h2_headers
}
