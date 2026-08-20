//! HTTP/2 integration with the retriever.
//!
//! This module provides integration between the HTTP/2 client and the retriever,
//! allowing transparent use of HTTP/2 when available, including over proxies.

use std::io::{Read, Write};
use std::sync::Arc;
use log::debug;

use crate::types::RetrieveError;
use ut_core::{Config, WgetError};
use ut_core::url::ParsedUrl;

/// HTTP/2 client wrapper that integrates with the retriever.
pub struct H2Retriever {
    /// HTTP/2 client for making requests.
    client: ut_http::h2::H2Client,
    /// Target host.
    host: String,
    /// Target port.
    port: u16,
}
