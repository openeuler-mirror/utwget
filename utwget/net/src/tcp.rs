//! TCP connection utilities.
//!
//! This module provides functions for establishing TCP connections with:
//!
//! - Configurable timeouts
//! - Address family filtering (IPv4/IPv6)
//! - Optional local address binding
//! - Multi-address resolution and connection attempts

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::dns::DnsError;
use crate::transport::TcpTransport;
use ut_core::AddressFamily;

/// Establishes a TCP connection to a host.
///
/// This function resolves the hostname to one or more IP addresses,
/// filters them by the requested address family, and attempts to
/// connect to each address until one succeeds.
///
/// # Arguments
///
/// * `host` - The hostname to connect to.
/// * `port` - The port number to connect to.
/// * `family` - The address family preference (IPv4, IPv6, or unspecified).
/// * `timeout` - Connection timeout for each address attempt.
/// * `bind_address` - Optional local address to bind for the connection.
///
/// # Returns
///
/// A `TcpStream` connected to the host on success.
///
/// # Errors
///
/// Returns a `ConnectError` if:
/// - DNS resolution fails
/// - All resolved addresses fail to connect
///
/// # Example
///
/// ```ignore
/// use std::time::Duration;
/// use ut_core::AddressFamily;
///
/// let stream = connect_to_host(
///     "example.com",
///     443,
///     AddressFamily::Unspecified,
///     Duration::from_secs(30),
///     None,
/// )?;
/// ```
pub fn connect_to_host(
    host: &str,
    port: u16,
    family: AddressFamily,
    timeout: Duration,
    bind_address: Option<std::net::IpAddr>,
) -> Result<TcpStream, ConnectError> {
    let addrs = resolve_addresses(host, port, family)?;

    if addrs.is_empty() {
        return Err(ConnectError::DnsFailed(DnsError::HostNotFound(
            host.to_string(),
        )));
    }

    let mut last_err = None;

    for addr in &addrs {
        match connect_single(addr, timeout, bind_address) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                log::debug!("connect to {} failed: {}", addr, e);
                last_err = Some(e);
            }
        }
    }

    Err(ConnectError::AllAddressesFailed {
        host: host.to_string(),
        tried: addrs.len(),
        last_error: last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no addresses available")
        }),
    })
}

/// Resolves a hostname to socket addresses with address family filtering.
///
/// # Arguments
///
/// * `host` - The hostname to resolve.
/// * `port` - The port number to associate with addresses.
/// * `family` - The address family to filter by.
///
/// # Returns
///
/// A vector of `SocketAddr` values matching the address family.
///
/// # Errors
///
/// Returns a `ConnectError` if resolution fails or returns no matching addresses.
fn resolve_addresses(
    host: &str,
    port: u16,
    family: AddressFamily,
) -> Result<Vec<SocketAddr>, ConnectError> {
    let addr = format!("{}:{}", host, port);
    let addrs: Vec<SocketAddr> = (addr.as_str(), 0u16)
        .to_socket_addrs()
        .map_err(|e| ConnectError::DnsFailed(DnsError::ResolveFailed {
            host: host.to_string(),
            detail: e.to_string(),
        }))?
        .filter(|a| matches_family(a, family))
        .map(|mut a| {
            a.set_port(port);
            a
        })
        .collect();

    if addrs.is_empty() {
        return Err(ConnectError::DnsFailed(DnsError::NoAddresses {
            host: host.to_string(),
            port,
        }));
    }

    Ok(addrs)
}
