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
