//! HTTP/1.x protocol support.
//!
//! This module provides the codec for HTTP/1.0 and HTTP/1.1 protocols,
//! including request serialization and response parsing.

pub mod mod_file;

pub use mod_file::H1Codec;
