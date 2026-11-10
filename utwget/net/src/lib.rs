//! Network layer for utwget.
//!
//! This crate provides low-level networking functionality including:
//! - TCP connections with IPv4/IPv6 support
//! - TLS/SSL connections using rustls
//! - DNS resolution
//! - Connection pooling and management
//! - Proxy support

pub mod connection;
pub mod dns;
pub mod proxy;
pub mod tcp;
pub mod tls;
pub mod transport;

pub use connection::{ConnectionKey, ConnectionManager, ManagedConnection};
pub use dns::{DnsError, DnsResolver};
pub use tcp::connect_to_host;
pub use tls::{TlsConfig, TlsConnector};
pub use transport::{Interest, Transport, TcpTransport};

#[cfg(feature = "tls-rustls")]
pub use tls::RustlsConnector;
