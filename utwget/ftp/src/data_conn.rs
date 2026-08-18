//! FTP data connection management.
//!
//! This module handles the establishment of data connections for FTP
//! file transfers. It supports both passive mode (PASV/EPSV) and
//! active mode (PORT/EPRT) for IPv4 and IPv6.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};

use crate::command::{FtpCommand, FtpCommandError, FtpResponse, Transport};

/// The mode for establishing FTP data connections.
pub enum DataConnectionMode {
    /// Passive mode: client connects to server-specified address (PASV/EPSV).
    Passive,
    /// Active mode: server connects to client-specified address (PORT/EPRT).
    Active,
}

/// An established FTP data connection.
///
/// This wraps a transport that can be used for file transfers.
pub struct DataConnection {
    /// The underlying transport for data transfer.
    pub stream: Box<dyn Transport<Error = io::Error>>,
}

impl DataConnection {
    /// Create a new data connection from a transport.
    ///
    /// # Arguments
    ///
    /// * `stream` - The transport to wrap.
    pub fn new(stream: Box<dyn Transport<Error = io::Error>>) -> Self {
        DataConnection { stream }
    }
}

/// Enter passive mode for data transfer.
///
/// If IPv6 is preferred, tries EPSV first, falling back to PASV.
/// Otherwise, uses PASV directly.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
/// * `prefer_ipv6` - Whether to prefer IPv6 (EPSV) over IPv4 (PASV).
///
/// # Returns
///
/// The established data connection.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails or the response
/// cannot be parsed.
pub fn enter_passive_mode(
    ctrl: &mut dyn Transport<Error = io::Error>,
    prefer_ipv6: bool,
) -> Result<DataConnection, FtpCommandError> {
    if prefer_ipv6 {
        match enter_epsv(ctrl) {
            Ok(conn) => return Ok(conn),
            Err(_) => {}
        }
    }

    enter_pasv(ctrl)
}

/// Enter passive mode using the PASV command (IPv4 only).
///
/// Parses the server response to extract the IP address and port
/// for the data connection.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
///
/// # Returns
///
/// The established data connection.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails or the response
/// cannot be parsed.
pub fn enter_pasv(
    ctrl: &mut dyn Transport<Error = io::Error>,
) -> Result<DataConnection, FtpCommandError> {
    FtpCommand::send(ctrl, "PASV")?;
    let resp = FtpResponse::read(ctrl)?;

    if resp.is_positive_completion {
        let addr = parse_pasv_response(&resp.text)?;
        let stream = TcpStream::connect(addr).map_err(FtpCommandError::Io)?;
        stream.set_nonblocking(false).ok();
        log::debug!("FTP PASV data connection to {}", addr);
        return Ok(DataConnection::new(Box::new(stream)));
    }

    Err(FtpCommandError::UnexpectedCode {
        expected: 227,
        actual: resp.code,
        message: resp.text,
    })
}

/// Enter passive mode using the EPSV command (IPv6-capable).
///
/// EPSV is the extended passive mode command that works with both
/// IPv4 and IPv6 addresses.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
///
/// # Returns
///
/// The established data connection.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails or the response
/// cannot be parsed.
pub fn enter_epsv(
    ctrl: &mut dyn Transport<Error = io::Error>,
) -> Result<DataConnection, FtpCommandError> {
    FtpCommand::send(ctrl, "EPSV")?;
    let resp = FtpResponse::read(ctrl)?;

    if resp.is_positive_completion {
        let addr = parse_epsv_response(&resp.text)?;
        let stream = TcpStream::connect(addr).map_err(FtpCommandError::Io)?;
        stream.set_nonblocking(false).ok();
        log::debug!("FTP EPSV data connection to {}", addr);
        return Ok(DataConnection::new(Box::new(stream)));
    }

    Err(FtpCommandError::UnexpectedCode {
        expected: 229,
        actual: resp.code,
        message: resp.text,
    })
}

/// Enter active mode for data transfer.
///
/// If IPv6 is preferred, tries EPRT first, falling back to PORT.
/// Otherwise, uses PORT directly.
///
/// Note: Active mode requires the client to listen for incoming
/// connections, which is handled externally.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
/// * `prefer_ipv6` - Whether to prefer IPv6 (EPRT) over IPv4 (PORT).
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails.
pub fn enter_active_mode(
    ctrl: &mut dyn Transport<Error = io::Error>,
    prefer_ipv6: bool,
) -> Result<(), FtpCommandError> {
    if prefer_ipv6 {
        match enter_eprt(ctrl) {
            Ok(()) => return Ok(()),
            Err(_) => {}
        }
    }
    enter_port(ctrl)
}

/// Enter active mode using the PORT command (IPv4 only).
///
/// Binds a local socket and sends the PORT command with the
/// address and port for the server to connect to.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails or the local
/// address is IPv6.
pub fn enter_port(
    ctrl: &mut dyn Transport<Error = io::Error>,
) -> Result<(), FtpCommandError> {
    let listener = TcpListenerBind::bind_any()?;
    let local_addr = listener.socket.local_addr().map_err(FtpCommandError::Io)?;

    match local_addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            let port_hi = v4.port() / 256;
            let port_lo = v4.port() % 256;
            let cmd = format!(
                "PORT {},{},{},{},{},{}",
                octets[0], octets[1], octets[2], octets[3], port_hi, port_lo
            );
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP PORT {}", cmd);
            Ok(())
        }
        SocketAddr::V6(_) => {
            Err(FtpCommandError::MalformedResponse(
                "PORT command requires IPv4 address".into(),
            ))
        }
    }
}

/// Enter active mode using the EPRT command (IPv6-capable).
///
/// EPRT is the extended port command that works with both
/// IPv4 and IPv6 addresses.
///
/// # Arguments
///
/// * `ctrl` - The control connection transport.
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns `FtpCommandError` if the command fails.
pub fn enter_eprt(
    ctrl: &mut dyn Transport<Error = io::Error>,
) -> Result<(), FtpCommandError> {
    let listener = TcpListenerBind::bind_any()?;
    let local_addr = listener.socket.local_addr().map_err(FtpCommandError::Io)?;

    match local_addr {
        SocketAddr::V4(v4) => {
            let cmd = format!("EPRT |1|{}|{}|", v4.ip(), v4.port());
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP EPRT {}", cmd);
            Ok(())
        }
        SocketAddr::V6(v6) => {
            let cmd = format!("EPRT |2|{}|{}|", v6.ip(), v6.port());
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP EPRT {}", cmd);
            Ok(())
        }
    }
}

/// Helper for binding a TCP listener on an arbitrary port.
struct TcpListenerBind {
    /// The bound TCP listener socket.
    socket: std::net::TcpListener,
}

impl TcpListenerBind {
    /// Bind a TCP listener on any available port.
    ///
    /// Tries IPv4 first, falling back to IPv6 if needed.
    fn bind_any() -> Result<Self, FtpCommandError> {
        let socket = std::net::TcpListener::bind("0.0.0.0:0")
            .or_else(|_| std::net::TcpListener::bind("[::]:0"))
            .map_err(FtpCommandError::Io)?;
        Ok(TcpListenerBind { socket })
    }
}
