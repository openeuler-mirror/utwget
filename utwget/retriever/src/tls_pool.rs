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

/// A pooled connection that can be either TCP or TLS.
enum PooledConnection {
    /// Plain TCP connection.
    Tcp(std::net::TcpStream),
    /// TLS connection wrapped in a trait object.
    Tls(Box<dyn Transport<Error = TlsError>>),
}

impl PooledConnection {
    /// Check if the connection is still alive.
    fn is_alive(&self) -> bool {
        match self {
            PooledConnection::Tcp(stream) => stream.peer_addr().is_ok(),
            PooledConnection::Tls(transport) => transport.is_alive(),
        }
    }
}
