//! Connection management module.
//!
//! This module provides connection pooling, DNS caching, and unified connection
//! management for both plain TCP and TLS connections. It supports:
//!
//! - Idle connection reuse for improved performance
//! - DNS result caching with configurable TTL
//! - Automatic connection cleanup for expired idle connections
//! - Support for both direct and proxy connections
//! - TLS upgrade with configurable options

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ut_core::AddressFamily;
use ut_core::error::TlsError;

use crate::dns::{DnsError, DnsResolver};
use crate::proxy;
use crate::tcp;
use crate::tls::{TlsConfig, TlsConnector};
use crate::transport::{Interest, Transport};

/// Default TTL for DNS cache entries (5 minutes).
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Maximum number of idle connections per connection key.
const MAX_IDLE_PER_KEY: usize = 5;

/// Maximum age of an idle connection before it's considered expired (2 minutes).
const MAX_IDLE_AGE: Duration = Duration::from_secs(120);
