//! HTTP protocol implementation for utwget.
//!
//! This crate provides HTTP/1.1 and HTTP/2 client functionality including:
//! - Request and response handling
//! - Authentication (Basic, Digest, NTLM)
//! - Chunked transfer encoding
//! - Compression (gzip, deflate)
//! - Header parsing and manipulation
//! - HTTP/2 support (with `http2` feature)

pub mod auth;
pub mod chunked;
#[cfg(feature = "compression")]
pub mod compression;
pub mod h1;
pub mod headers;
pub mod request;
pub mod response;

#[cfg(feature = "http2")]
pub mod h2;

pub use request::{HttpRequest, HttpVersion};
pub use response::{HeaderMap, HttpResponse};
pub use auth::{AuthChallenge, AuthDispatcher, Authenticator, AuthScheme, AuthError};
pub use auth::basic::BasicAuthenticator;
#[cfg(feature = "auth-digest")]
pub use auth::digest::DigestAuthenticator;
#[cfg(feature = "auth-ntlm")]
pub use auth::ntlm::NtlmAuthenticator;
