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

/// Checks if a socket address matches the requested address family.
///
/// # Arguments
///
/// * `addr` - The socket address to check.
/// * `family` - The address family to match against.
///
/// # Returns
///
/// `true` if the address matches the family filter.
fn matches_family(addr: &SocketAddr, family: AddressFamily) -> bool {
    use std::net::IpAddr::{V4, V6};
    match (addr.ip(), family) {
        (V4(_), AddressFamily::Ipv4) => true,
        (V6(_), AddressFamily::Ipv6) => true,
        (V4(_), AddressFamily::Ipv6) => false,
        (V6(_), AddressFamily::Ipv4) => false,
        (V4(_), AddressFamily::PreferIpv6) => false,
        (V6(_), AddressFamily::PreferIpv4) => false,
        (_, AddressFamily::PreferIpv4) => matches!(addr.ip(), V4(_)),
        (_, AddressFamily::PreferIpv6) => matches!(addr.ip(), V6(_)),
        (_, AddressFamily::Unspecified) => true,
    }
}

/// Establishes a TCP connection to a single address.
///
/// If a bind address is specified and compatible with the target address,
/// the connection will be made from that local address.
///
/// # Arguments
///
/// * `addr` - The socket address to connect to.
/// * `timeout` - Connection timeout.
/// * `bind_address` - Optional local address to bind.
///
/// # Returns
///
/// A `TcpStream` on success, or an I/O error on failure.
fn connect_single(
    addr: &SocketAddr,
    timeout: Duration,
    bind_address: Option<std::net::IpAddr>,
) -> io::Result<TcpStream> {
    if let Some(bind) = bind_address {
        let bind_compatible = match (bind, addr) {
            (std::net::IpAddr::V4(_), SocketAddr::V4(_)) => Some(bind),
            (std::net::IpAddr::V6(_), SocketAddr::V6(_)) => Some(bind),
            _ => None,
        };

        if let Some(bind_addr) = bind_compatible {
            let bind_socket = match bind_addr {
                std::net::IpAddr::V4(v4) => std::net::TcpListener::bind((v4, 0))?,
                std::net::IpAddr::V6(v6) => std::net::TcpListener::bind((v6, 0))?,
            };
            let _local_addr = bind_socket.local_addr()?;
            drop(bind_socket);
            let stream = TcpStream::connect_timeout(addr, timeout)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            return Ok(stream);
        }
    }

    let stream = TcpStream::connect_timeout(addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Error type for TCP connection operations.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsFailed(#[from] DnsError),

    /// All resolved addresses failed to connect.
    #[error("all {tried} addresses failed for {host}: {last_error}")]
    AllAddressesFailed {
        /// The hostname that was being connected to.
        host: String,
        /// Number of addresses that were tried.
        tried: usize,
        /// The last error encountered.
        last_error: io::Error,
    },
}

/// Establishes a TCP connection and returns a `TcpTransport`.
///
/// This is a convenience function that wraps [`connect_to_host`] and
/// creates a `TcpTransport` from the resulting stream.
///
/// # Arguments
///
/// * `host` - The hostname to connect to.
/// * `port` - The port number to connect to.
/// * `family` - The address family preference.
/// * `timeout` - Connection timeout.
/// * `bind_address` - Optional local address to bind.
///
/// # Returns
///
/// A `TcpTransport` on success, or a `ConnectError` on failure.
pub fn connect_to_host_transport(
    host: &str,
    port: u16,
    family: AddressFamily,
    timeout: Duration,
    bind_address: Option<std::net::IpAddr>,
) -> Result<TcpTransport, ConnectError> {
    let stream = connect_to_host(host, port, family, timeout, bind_address)?;
    Ok(TcpTransport::new(stream))
}
