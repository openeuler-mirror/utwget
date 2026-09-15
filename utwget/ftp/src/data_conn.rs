//! FTP data connection management.
//!
//! This module handles the establishment of data connections for FTP
//! file transfers. It supports both passive mode (PASV/EPSV) and
//! active mode (PORT/EPRT) for IPv4 and IPv6.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};

use crate::command::{FtpCommand, FtpCommandError, FtpResponse, IntoTcpStream, Transport};

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
/// In active mode, the transport is a [`LazyActiveTransport`] that defers
/// `accept()` until the first `read()` call, so the data transfer command
/// (LIST/RETR) can be sent on the control connection before the server
/// initiates the data connection — matching RFC 959 and GNU wget's
/// `ftp.c:1383-1389` behavior.
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

    /// Create a new active-mode data connection from a listener.
    ///
    /// The listener's `accept()` is deferred until the first `read()` call,
    /// so the caller can send the data transfer command (LIST/RETR) on the
    /// control connection before the server initiates the data connection.
    pub fn new_active(listener: TcpListener) -> Self {
        Self::new_active_with_timeout(listener, None)
    }

    /// Active-mode connection with a configurable data timeout (M14).
    pub fn new_active_with_timeout(listener: TcpListener, data_timeout: Option<std::time::Duration>) -> Self {
        DataConnection {
            stream: Box::new(LazyActiveTransport::new(listener, data_timeout)),
        }
    }
}

/// A transport adapter for active-mode FTP that lazily accepts the server's
/// data connection on the first `read()` or `write_all()` call.
///
/// This is necessary because in active mode the client must send the
/// transfer command (LIST/RETR) on the control connection *before* the
/// server will initiate the data connection.  If `accept()` is called
/// before the transfer command, the connection deadlocks.
struct LazyActiveTransport {
    /// Read/write timeout applied to the accepted data socket (M14: was
    /// hardcoded 60s; honors --timeout/--read-timeout).
    data_timeout: Option<std::time::Duration>,
    listener: Option<TcpListener>,
    stream: Option<TcpStream>,
}

impl LazyActiveTransport {
    fn new(listener: TcpListener, data_timeout: Option<std::time::Duration>) -> Self {
        LazyActiveTransport {
            data_timeout,
            listener: Some(listener),
            stream: None,
        }
    }

    /// Lazily accept the incoming data connection if not already done.
    fn ensure_accepted(&mut self) -> io::Result<&mut TcpStream> {
        if self.stream.is_none() {
            let listener = self.listener
                .take()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "listener already consumed"))?;
            let (stream, addr) = listener.accept()?;
            stream.set_nonblocking(false).ok();
            let dt = self.data_timeout.unwrap_or(std::time::Duration::from_secs(60));
            stream.set_read_timeout(Some(dt)).ok();
            stream.set_write_timeout(Some(dt)).ok();
            log::debug!("FTP active mode data connection accepted from {} (timeout {:?})", addr, dt);
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "data connection not established"))?;
        Ok(stream)
    }
}

impl Transport for LazyActiveTransport {
    type Error = io::Error;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let stream = self.ensure_accepted()?;
        stream.read(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        let stream = self.ensure_accepted()?;
        stream.write_all(buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if let Some(ref mut stream) = self.stream {
            return stream.flush();
        }
        Ok(())
    }

    fn peer_addr(&self) -> Result<std::net::SocketAddr, Self::Error> {
        if let Some(ref stream) = self.stream {
            return stream.peer_addr();
        }
        Err(io::Error::new(io::ErrorKind::NotConnected, "connection not yet accepted"))
    }
}

impl IntoTcpStream for LazyActiveTransport {
    fn into_tcp_stream(self: Box<Self>) -> Result<std::net::TcpStream, io::Error> {
        match (self.listener, self.stream) {
            (_, Some(stream)) => Ok(stream),
            (Some(listener), None) => {
                let (stream, _) = listener.accept()?;
                Ok(stream)
            }
            (None, None) => Err(io::Error::new(io::ErrorKind::Other, "no listener or stream")),
        }
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
    data_timeout: Option<std::time::Duration>,
) -> Result<DataConnection, FtpCommandError> {
    if prefer_ipv6 {
        match enter_epsv(ctrl, data_timeout) {
            Ok(conn) => return Ok(conn),
            Err(_) => {}
        }
    }

    enter_pasv(ctrl, data_timeout)
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
    data_timeout: Option<std::time::Duration>,
) -> Result<DataConnection, FtpCommandError> {
    FtpCommand::send(ctrl, "PASV")?;
    let resp = FtpResponse::read(ctrl)?;

    if resp.is_positive_completion {
        let addr = parse_pasv_response(&resp.text)?;

        // FTP bounce attack mitigation: a malicious server can instruct the
        // client to connect to an arbitrary third-party IP:port via PASV,
        // enabling port scanning or abuse of trust relationships. We compare
        // PASV bounce-attack AWARENESS: GNU wget does NOT validate the
        // PASV IP at all (ftp.c just calls connect_to_ip on the advertised
        // address). The previous hard reject broke legitimate NAT setups
        // where the data server's advertised IP differs from the control
        // peer (M12). Stay compatible: WARN on mismatch and connect anyway.
        match ctrl.peer_addr() {
            Ok(peer) => {
                let pasv_ip = match addr {
                    SocketAddr::V4(v4) => std::net::IpAddr::V4(*v4.ip()),
                    SocketAddr::V6(v6) => std::net::IpAddr::V6(*v6.ip()),
                };
                if peer.ip() != pasv_ip {
                    log::warn!(
                        "PASV advertises {} but control connection peer is {} (possible FTP bounce attack); connecting anyway (GNU wget behavior)",
                        pasv_ip,
                        peer.ip()
                    );
                }
            }
            Err(e) => {
                // If we can't determine the peer, proceed.
                log::warn!("cannot determine control connection peer for PASV validation: {}", e);
            }
        }

        let stream = TcpStream::connect(addr).map_err(FtpCommandError::Io)?;
        stream.set_nonblocking(false).ok();
        // Timeout to prevent an indefinite hang if the server stops
        // mid-transfer. Honors --timeout/--read-timeout via data_timeout;
        // defaults to 60s when no configuration reached us (M14).
        let dt = data_timeout.unwrap_or(std::time::Duration::from_secs(60));
        stream.set_read_timeout(Some(dt)).ok();
        stream.set_write_timeout(Some(dt)).ok();
        log::debug!("FTP PASV data connection to {} (timeout {:?})", addr, dt);
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
    data_timeout: Option<std::time::Duration>,
) -> Result<DataConnection, FtpCommandError> {
    FtpCommand::send(ctrl, "EPSV")?;
    let resp = FtpResponse::read(ctrl)?;

    if resp.is_positive_completion {
        let parsed = parse_epsv_response(&resp.text)?;
        let addr = match parsed {
            EpsvAddr::Resolved(a) => a,
            EpsvAddr::UseControlPort(port) => {
                let peer = ctrl.peer_addr().map_err(FtpCommandError::Io)?;
                let mut sa = peer;
                sa.set_port(port);
                sa
            }
        };
        let stream = TcpStream::connect(addr).map_err(FtpCommandError::Io)?;
        stream.set_nonblocking(false).ok();
        // Timeout to prevent an indefinite hang if the server stops
        // mid-transfer. Honors --timeout/--read-timeout via data_timeout;
        // defaults to 60s when no configuration reached us (M14).
        let dt = data_timeout.unwrap_or(std::time::Duration::from_secs(60));
        stream.set_read_timeout(Some(dt)).ok();
        stream.set_write_timeout(Some(dt)).ok();
        log::debug!("FTP EPSV data connection to {} (timeout {:?})", addr, dt);
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
/// Bind an active-mode listener and return the address to advertise.
///
/// Public wrapper so `client.rs`/`ftps.rs` share the same control-IP logic
/// as `enter_port`/`enter_eprt` (H-7). `ctrl_local_ip` is the control
/// connection's local IP when known (see `Transport::local_addr`); without
/// it the listener defaults to IPv4 wildcard behavior.
/// See [`bind_for_control`].
pub fn bind_active_listener(
    ctrl_local_ip: Option<std::net::IpAddr>,
) -> Result<(TcpListener, IpAddr, u16), FtpCommandError> {
    bind_for_control(ctrl_local_ip)
}

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
    let (_listener, ip, port) = bind_for_control(ctrl.local_addr().map(|a| a.ip()))?;

    match ip {
        // Advertise the control connection's local IP (H-7), not 0.0.0.0.
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let port_hi = port / 256;
            let port_lo = port % 256;
            let cmd = format!(
                "PORT {},{},{},{},{},{}",
                octets[0], octets[1], octets[2], octets[3], port_hi, port_lo
            );
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP PORT {}", cmd);
            Ok(())
        }
        IpAddr::V6(_) => Err(FtpCommandError::MalformedResponse(
            "PORT command requires IPv4 address; use EPRT".into(),
        )),
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
    let (_listener, ip, port) = bind_for_control(ctrl.local_addr().map(|a| a.ip()))?;

    match ip {
        IpAddr::V4(v4) => {
            let cmd = format!("EPRT |1|{}|{}|", v4, port);
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP EPRT {}", cmd);
            Ok(())
        }
        IpAddr::V6(v6) => {
            let cmd = format!("EPRT |2|{}|{}|", v6, port);
            FtpCommand::send(ctrl, &cmd)?;
            FtpResponse::expect(ctrl, 200)?;
            log::debug!("FTP EPRT {}", cmd);
            Ok(())
        }
    }
}

/// Bind an active-mode listener and resolve the IP to advertise.
///
/// GNU wget advertises the CONTROL connection's local IP (getsockname,
/// ftp-basic.c). Binding to 0.0.0.0 and reading the listener's
/// `local_addr()` would advertise `0,0,0,0` in the PORT command, which
/// compliant servers reject (H-7). The advertised address family also
/// selects the listener family: a control connection over IPv6 gets an
/// IPv6 listener (the previous hardcoded 0.0.0.0 bind made EPRT
/// unreachable on dual-stack hosts).
///
/// Returns the bound listener and the (ip, port) pair to advertise.
fn bind_for_control(
    ctrl_local_ip: Option<std::net::IpAddr>,
) -> Result<(std::net::TcpListener, std::net::IpAddr, u16), FtpCommandError> {
    // Prefer the control connection's local IP for family + address.
    let want_ipv4 = ctrl_local_ip.map_or(true, |a| a.is_ipv4());
    let ctrl_ip = ctrl_local_ip;

    // Bind on the matching family first, then fall back.
    let bind_addr: &str = if want_ipv4 { "0.0.0.0:0" } else { "[::]:0" };
    let socket = std::net::TcpListener::bind(bind_addr)
        .or_else(|_| {
            let fallback = if want_ipv4 { "[::]:0" } else { "0.0.0.0:0" };
            std::net::TcpListener::bind(fallback)
        })
        .map_err(FtpCommandError::Io)?;

    let port = socket.local_addr().map_err(FtpCommandError::Io)?.port();
    // Advertised IP: control connection's local IP if known, else the
    // wildcard address (last resort — same as the old behavior but the
    // port is at least correct).
    let advertise_ip = ctrl_ip.unwrap_or_else(|| {
        if want_ipv4 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
    });
    Ok((socket, advertise_ip, port))
}

/// Parse a PASV response to extract the data connection address.
///
/// The response format is: `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)`
/// where the IP is h1.h2.h3.h4 and the port is p1*256 + p2.
pub fn parse_pasv_response(text: &str) -> Result<SocketAddr, FtpCommandError> {
    let text = text.trim();
    // RFC 959 recommends the (h1,h2,h3,h4,p1,p2) form in parentheses, but
    // plenty of old/embedded servers omit them: "227 Entering Passive
    // Mode 10,0,0,1,20,30". GNU wget's parse_pasv_host_and_port jumps to
    // the first digit (ftp-basic.c:652-654), accepting both forms — do the
    // same: prefer the parenthesized section, fall back to the first
    // 6-comma-number run anywhere in the line.
    let inner = if let (Some(start), Some(end)) = (text.find('('), text.find(')')) {
        if start + 1 < end {
            text[start + 1..end].to_string()
        } else {
            return Err(FtpCommandError::MalformedResponse(
                "PASV: empty or inverted parenthesis range".into(),
            ));
        }
    } else {
        match find_pasv_number_run(text) {
            Some(run) => run,
            None => {
                return Err(FtpCommandError::MalformedResponse(
                    "PASV: no (h1,h2,h3,h4,p1,p2) numbers found".into(),
                ))
            }
        }
    };
    let parts: Vec<&str> = inner.split(',').collect();
    if parts.len() != 6 {
        return Err(FtpCommandError::MalformedResponse(
            format!("PASV: expected 6 comma-separated values, got {}", parts.len()),
        ));
    }

    let nums: Vec<u8> = parts
        .iter()
        .map(|p| p.trim().parse::<u8>().map_err(|_| {
            FtpCommandError::MalformedResponse(format!("PASV: invalid number: {}", p.trim()))
        }))
        .collect::<Result<_, _>>()?;

    let ip = Ipv4Addr::new(nums[0], nums[1], nums[2], nums[3]);
    let port = (nums[4] as u16) * 256 + (nums[5] as u16);
    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Find the first run of 6 comma-separated 0-255 numbers in `text`
/// (paren-less PASV fallback, matching GNU wget's digit-scan behavior).
fn find_pasv_number_run(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            // Try to parse 6 comma-separated numbers starting here.
            let mut end = i;
            let mut ok = true;
            for field in 0..6 {
                let start = end;
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                if end == start || text[start..end].parse::<u8>().is_err() {
                    ok = false;
                    break;
                }
                if field < 5 {
                    if end < bytes.len() && bytes[end] == b',' {
                        end += 1;
                    } else {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                return Some(text[i..end].to_string());
            }
            // Not a valid run here: skip past the leading digits.
            while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b',') {
                end += 1;
            }
            i = end;
        } else {
            i += 1;
        }
    }
    None
}

/// Parsed result from an EPSV response.
enum EpsvAddr {
    /// A fully resolved address (when protocol and address are provided).
    Resolved(SocketAddr),
    /// Only the port was provided; the caller should use the control connection's address.
    UseControlPort(u16),
}

/// Parse an EPSV response to extract the data connection address.
///
/// The response format is: `229 Entering Extended Passive Mode (|||port|)`
/// where the protocol and address fields are empty (meaning use the
/// same as the control connection).
fn parse_epsv_response(text: &str) -> Result<EpsvAddr, FtpCommandError> {
    let text = text.trim();
    let start = text.find('(').ok_or_else(|| {
        FtpCommandError::MalformedResponse("EPSV: no opening parenthesis".into())
    })?;
    let end = text.find(')').ok_or_else(|| {
        FtpCommandError::MalformedResponse("EPSV: no closing parenthesis".into())
    })?;
    if start + 1 >= end {
        return Err(FtpCommandError::MalformedResponse(
            "EPSV: empty or inverted parenthesis range".into(),
        ));
    }
    let inner = &text[start + 1..end];
    let parts: Vec<&str> = inner.split('|').collect();
    if parts.len() < 4 {
        return Err(FtpCommandError::MalformedResponse(
            format!("EPSV: expected |proto|addr|port|, got {}", inner),
        ));
    }

    let proto = parts[1].trim();
    let addr_str = parts[2].trim();
    let port_str = parts[3].trim();
    let port: u16 = port_str.parse().map_err(|_| {
        FtpCommandError::MalformedResponse(format!("EPSV: invalid port: {}", port_str))
    })?;

    // When protocol and address are empty, use the control connection's address with the given port.
    if proto.is_empty() && addr_str.is_empty() {
        return Ok(EpsvAddr::UseControlPort(port));
    }

    match proto {
        "1" => {
            let ip: Ipv4Addr = addr_str.parse().map_err(|_| {
                FtpCommandError::MalformedResponse(format!("EPSV: invalid IPv4: {}", addr_str))
            })?;
            Ok(EpsvAddr::Resolved(SocketAddr::V4(SocketAddrV4::new(ip, port))))
        }
        "2" => {
            let ip: Ipv6Addr = addr_str.parse().map_err(|_| {
                FtpCommandError::MalformedResponse(format!("EPSV: invalid IPv6: {}", addr_str))
            })?;
            Ok(EpsvAddr::Resolved(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))))
        }
        other => Err(FtpCommandError::MalformedResponse(
            format!("EPSV: unsupported protocol: {}", other),
        )),
    }
}
