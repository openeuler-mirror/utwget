//! File retrieval and download logic for utwget.
//!
//! This crate provides the core download functionality including:
//! - Single file retrieval with retry support
//! - Recursive downloading with URL filtering
//! - Spider mode for checking URLs without downloading
//! - Extended file attributes (xattr) support
//! - Download registry for tracking downloaded files
//! - Async download support (with `async` feature)
//! - HTTP/2 support (with `http2` feature)
//! - TLS connection pooling for connection reuse

pub mod types;
pub mod download_registry;
pub mod url_queue;
pub mod protocol;
pub mod retriever;
pub mod recursive;
pub mod spider;
pub mod xattr;
pub mod utils;
pub mod tls_pool;

#[cfg(feature = "async")]
pub mod async_retriever;

#[cfg(feature = "http2")]
pub mod h2_integration;

pub use types::{
    RequestOptions, ResponseMeta, BodyResult, ProtocolState, DocumentFlags,
    RetrieveOutcome, RetrieveError, Protocol,
};
pub use download_registry::DownloadRegistry;
pub use url_queue::{QueueEntry, UrlQueue};
pub use retriever::Retriever;
pub use recursive::{RecursiveRetriever, ExitStatus};
pub use spider::Spider;
pub use xattr::{FileMetadata, set_xattr, get_xattr, RemotePermissions, apply_permissions};
pub use tls_pool::TlsConnectionPool;

#[cfg(feature = "async")]
pub use async_retriever::{AsyncRetriever, download, download_many};

#[cfg(feature = "http2")]
pub use h2_integration::{H2Retriever, should_use_http2, download_with_http2};
