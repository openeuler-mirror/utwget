//! TLS connection pool for reusing secure connections.
//!
//! This module provides a connection pool that supports both plain TCP
//! and TLS connections, allowing reuse of established connections to
//! improve performance for multiple requests to the same host.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use ut_net::transport::Transport;
use ut_net::tls::TlsError;

/// Maximum age of an idle connection before it's considered expired (5 minutes).
const MAX_IDLE_AGE: std::time::Duration = std::time::Duration::from_secs(300);
