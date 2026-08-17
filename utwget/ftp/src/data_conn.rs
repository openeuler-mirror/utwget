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
