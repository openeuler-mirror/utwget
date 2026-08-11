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
