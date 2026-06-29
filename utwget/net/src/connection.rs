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
