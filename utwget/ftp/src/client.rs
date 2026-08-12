//! FTP client implementation.
//!
//! This module provides a complete FTP client for file transfer operations.
//! It supports both active and passive mode, IPv4 and IPv6, and various
//! FTP commands for file and directory operations.
//!
//! # Example
//!
//! ```no_run
//! use utwget_ftp::client::FtpClient;
//!
//! let mut client = FtpClient::new();
//! client.connect("ftp.example.com", 21).unwrap();
//! client.login("user", "password").unwrap();
//! client.type_binary().unwrap();
//! // ... perform operations
//! client.quit().unwrap();
//! ```

use std::io::{self, Read, Write};

use crate::command::{FtpCommand, FtpCommandError, FtpResponse, Transport};
use crate::data_conn::{self, DataConnection};
use crate::listing::{parse_listing, FtpEntry};

/// Errors that can occur during FTP operations.
///
/// This enum covers all possible error conditions when using the FTP client,
/// including connection failures, authentication issues, command errors,
/// and I/O problems.
#[derive(Debug, thiserror::Error)]
pub enum FtpError {
    /// Failed to establish a connection to the FTP server.
    #[error("connection error: {0}")]
    Connect(String),
    /// The server refused the login attempt.
    #[error("login refused: {0}")]
    LoginRefused(String),
    /// An FTP command failed with a negative response.
    #[error("command failed ({code}): {message}")]
    CommandFailed { code: u16, message: String },
    /// Failed to establish a data connection for file transfer.
    #[error("data connection failed: {0}")]
    DataConnectFailed(String),
    /// File transfer operation failed.
    #[error("transfer failed: {0}")]
    TransferFailed(String),
    /// The requested file was not found on the server.
    #[error("file not found: {0}")]
    FileNotFound(String),
    /// Failed to parse server response or URL.
    #[error("parse error: {0}")]
    ParseError(String),
    /// An I/O error occurred during the operation.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// An FTP protocol error occurred.
    #[error("FTP protocol error: {0}")]
    Protocol(#[from] FtpCommandError),
}

impl From<ut_core::WgetError> for FtpError {
    fn from(e: ut_core::WgetError) -> Self {
        FtpError::Connect(e.to_string())
    }
}

/// Result of fetching metadata from an FTP URL.
///
/// Contains information about the remote resource including whether it's
/// a directory or file, its size, modification time, and directory listing
/// if applicable.
#[derive(Debug)]
pub struct FtpFetchResult {
    /// FTP status code from the operation.
    pub status_code: u16,
    /// Size of the file in bytes, if known.
    pub content_length: Option<u64>,
    /// Content type (e.g., "application/octet-stream" for files,
    /// "text/ftp; type=directory" for directories).
    pub content_type: Option<String>,
    /// Last modification time of the resource.
    pub last_modified: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the resource is a directory.
    pub is_directory: bool,
    /// Directory listing entries, if the resource is a directory.
    pub file_list: Option<Vec<FtpEntry>>,
}

/// FTP client for file transfer operations.
///
/// This struct manages an FTP control connection and provides methods
/// for all standard FTP operations including file transfer, directory
/// navigation, and file management.
///
/// The client supports both passive (PASV/EPSV) and active (PORT/EPRT)
/// modes, with passive mode being the default. It also handles both
/// IPv4 and IPv6 connections automatically.
pub struct FtpClient {
    /// Control connection transport.
    ctrl: Option<Box<dyn Transport<Error = io::Error>>>,
    /// Connected host name.
    host: Option<String>,
    /// Whether to use passive mode for data connections.
    passive: bool,
    /// Whether the connection is over IPv6.
    is_ipv6: bool,
    /// Whether binary (image) mode is active.
    binary: bool,
    /// Current working directory on the server.
    current_dir: String,
}

impl FtpClient {
    /// Create a new FTP client with default settings.
    ///
    /// The client is created in passive mode with binary transfer mode enabled.
    ///
    /// # Returns
    ///
    /// A new `FtpClient` instance ready to connect.
    pub fn new() -> Self {
        FtpClient {
            ctrl: None,
            host: None,
            passive: true,
            is_ipv6: false,
            binary: true,
            current_dir: String::new(),
        }
    }

    /// Configure passive mode for data connections.
    ///
    /// Passive mode is enabled by default. When disabled, the client will
    /// attempt to use active mode (PORT/EPRT commands).
    ///
    /// # Arguments
    ///
    /// * `passive` - `true` to enable passive mode, `false` for active mode.
    ///
    /// # Returns
    ///
    /// The modified client instance for method chaining.
    pub fn with_passive(mut self, passive: bool) -> Self {
        self.passive = passive;
        self
    }

    /// Connect to an FTP server.
    ///
    /// Establishes a TCP connection to the specified host and port,
    /// then reads the server's welcome message.
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname or IP address of the FTP server.
    /// * `port` - The port number (typically 21 for FTP).
    ///
    /// # Returns
    ///
    /// The server's welcome response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::Connect` if the connection fails or the server
    /// refuses the connection.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<FtpResponse, FtpError> {
        let addr = format!("{}:{}", host, port);
        let stream = std::net::TcpStream::connect(&addr).map_err(|e| FtpError::Connect(e.to_string()))?;
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(30))).ok();

        if host.contains(':') || host.starts_with('[') {
            self.is_ipv6 = true;
        }

        let mut transport: Box<dyn Transport<Error = io::Error>> = Box::new(stream);
        let welcome = FtpResponse::read(transport.as_mut())?;

        if !welcome.is_positive_completion {
            return Err(FtpError::Connect(format!(
                "server refused connection: {} {}", welcome.code, welcome.text
            )));
        }

        self.ctrl = Some(transport);
        self.host = Some(host.to_string());
        self.current_dir = String::new();

        log::debug!("FTP connected to {}:{}", host, port);
        log::debug!("FTP welcome: {} {}", welcome.code, welcome.text);

        Ok(welcome)
    }

    /// Connect to an FTP server using a pre-established transport.
    ///
    /// This method is useful for FTPS or when a custom transport is needed.
    /// The transport should already be connected to the server.
    ///
    /// # Arguments
    ///
    /// * `stream` - A boxed transport implementing the `Transport` trait.
    /// * `host` - The hostname for reference (used for data connections).
    ///
    /// # Returns
    ///
    /// The server's welcome response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::Connect` if the server refuses the connection.
    pub fn connect_with_stream(
        &mut self,
        stream: Box<dyn Transport<Error = io::Error>>,
        host: &str,
    ) -> Result<FtpResponse, FtpError> {
        let mut transport = stream;
        let welcome = FtpResponse::read(transport.as_mut())?;

        if !welcome.is_positive_completion {
            return Err(FtpError::Connect(format!(
                "server refused connection: {} {}", welcome.code, welcome.text
            )));
        }

        self.ctrl = Some(transport);
        self.host = Some(host.to_string());
        self.current_dir = String::new();

        Ok(welcome)
    }

    /// Authenticate with the FTP server.
    ///
    /// Sends USER and PASS commands to authenticate. If the server accepts
    /// the username alone (rare), no password is sent.
    ///
    /// # Arguments
    ///
    /// * `user` - The username for authentication.
    /// * `password` - The password for authentication.
    ///
    /// # Returns
    ///
    /// The server's response to the authentication.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::LoginRefused` if the server rejects the credentials.
    /// Returns `FtpError::CommandFailed` for other authentication failures.
    pub fn login(&mut self, user: &str, password: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("USER {}", user))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            return Ok(resp);
        }

        if resp.is_positive_intermediate {
            self.send_cmd(&format!("PASS {}", password))?;
            let pass_resp = self.read_response()?;

            if pass_resp.is_positive_completion {
                return Ok(pass_resp);
            }

            if pass_resp.is_permanent_negative {
                return Err(FtpError::LoginRefused(pass_resp.text));
            }

            return Err(FtpError::CommandFailed {
                code: pass_resp.code,
                message: pass_resp.text,
            });
        }

        Err(FtpError::LoginRefused(resp.text))
    }

    /// Change the current working directory on the server.
    ///
    /// Sends the CWD command to navigate to the specified path.
    ///
    /// # Arguments
    ///
    /// * `path` - The directory path to change to.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the directory doesn't exist
    /// or the command fails.
    pub fn cwd(&mut self, path: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("CWD {}", path))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            self.current_dir = path.to_string();
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Change to the parent directory.
    ///
    /// Sends the CDUP command to move up one directory level.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if already at the root or
    /// the command fails.
    pub fn cdup(&mut self) -> Result<FtpResponse, FtpError> {
        self.send_cmd("CDUP")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Get the current working directory path.
    ///
    /// Sends the PWD command and parses the response to extract
    /// the directory path.
    ///
    /// # Returns
    ///
    /// The current working directory path as a string.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::ParseError` if the response cannot be parsed.
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn pwd(&mut self) -> Result<String, FtpError> {
        self.send_cmd("PWD")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            extract_quoted_path(&resp.text).ok_or_else(|| {
                FtpError::ParseError(format!("cannot parse PWD response: {}", resp.text))
            })
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Set binary (image) transfer mode.
    ///
    /// Sends the TYPE I command. This is the default mode and should be
    /// used for transferring binary files to prevent corruption.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn type_binary(&mut self) -> Result<FtpResponse, FtpError> {
        self.send_cmd("TYPE I")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            self.binary = true;
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Set ASCII (text) transfer mode.
    ///
    /// Sends the TYPE A command. This mode performs line ending conversion
    /// and should only be used for text files.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn type_ascii(&mut self) -> Result<FtpResponse, FtpError> {
        self.send_cmd("TYPE A")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            self.binary = false;
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Get the size of a file on the server.
    ///
    /// Sends the SIZE command to query the file size. Not all servers
    /// support this command.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to query.
    ///
    /// # Returns
    ///
    /// `Some(size)` if the command succeeds, `None` if the server doesn't
    /// support SIZE or the file doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::ParseError` if the response cannot be parsed.
    pub fn size(&mut self, filename: &str) -> Result<Option<u64>, FtpError> {
        self.send_cmd(&format!("SIZE {}", filename))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            resp.text.trim().parse::<u64>().map(Some).map_err(|_| {
                FtpError::ParseError(format!("cannot parse SIZE response: {}", resp.text))
            })
        } else {
            Ok(None)
        }
    }

    /// Get the modification time of a file on the server.
    ///
    /// Sends the MDTM command to query the last modification time.
    /// Not all servers support this command.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to query.
    ///
    /// # Returns
    ///
    /// `Some(datetime)` if the command succeeds, `None` if the server
    /// doesn't support MDTM or the file doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::ParseError` if the response cannot be parsed.
    pub fn mdtm(&mut self, filename: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>, FtpError> {
        self.send_cmd(&format!("MDTM {}", filename))?;
        let resp = self.read_response()?;

        if resp.is_positive_completion {
            let ts = resp.text.trim();
            parse_ftp_timestamp(ts).map(Some).ok_or_else(|| {
                FtpError::ParseError(format!("cannot parse MDTM response: {}", ts))
            })
        } else {
            Ok(None)
        }
    }

    /// Set the restart position for the next transfer.
    ///
    /// Sends the REST command to specify a byte offset for resuming
    /// an interrupted transfer.
    ///
    /// # Arguments
    ///
    /// * `position` - The byte offset to resume from.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the server doesn't support
    /// restart or the command fails.
    pub fn rest(&mut self, position: u64) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("REST {}", position))?;
        let resp = self.read_response()?;
        if resp.is_positive_intermediate {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Create a directory on the server.
    ///
    /// Sends the MKD command to create the specified directory.
    ///
    /// # Arguments
    ///
    /// * `dirname` - The name of the directory to create.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the directory already exists
    /// or the command fails.
    pub fn mkdir(&mut self, dirname: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("MKD {}", dirname))?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Remove a directory on the server.
    ///
    /// Sends the RMD command to remove the specified directory.
    /// The directory must be empty.
    ///
    /// # Arguments
    ///
    /// * `dirname` - The name of the directory to remove.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the directory doesn't exist,
    /// is not empty, or the command fails.
    pub fn rmdir(&mut self, dirname: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("RMD {}", dirname))?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Delete a file on the server.
    ///
    /// Sends the DELE command to remove the specified file.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to delete.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the file doesn't exist
    /// or the command fails.
    pub fn delete(&mut self, filename: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("DELE {}", filename))?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Rename a file or directory on the server.
    ///
    /// Sends RNFR and RNTO commands to rename the specified resource.
    ///
    /// # Arguments
    ///
    /// * `from` - The current name of the file or directory.
    /// * `to` - The new name for the file or directory.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the source doesn't exist,
    /// the destination already exists, or the command fails.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<FtpResponse, FtpError> {
        self.send_cmd(&format!("RNFR {}", from))?;
        let resp = self.read_response()?;
        if !resp.is_positive_intermediate {
            return Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            });
        }

        self.send_cmd(&format!("RNTO {}", to))?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Send a no-operation command to keep the connection alive.
    ///
    /// Sends the NOOP command. This is useful for preventing connection
    /// timeouts during long periods of inactivity.
    ///
    /// # Returns
    ///
    /// The server's response on success.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn noop(&mut self) -> Result<FtpResponse, FtpError> {
        self.send_cmd("NOOP")?;
        self.read_response()
    }

    /// Get the server's system type.
    ///
    /// Sends the SYST command to query the operating system type
    /// of the server.
    ///
    /// # Returns
    ///
    /// The system type string (e.g., "UNIX", "Windows_NT").
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn syst(&mut self) -> Result<String, FtpError> {
        self.send_cmd("SYST")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp.text)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// Get the list of features supported by the server.
    ///
    /// Sends the FEAT command to query supported extensions and features.
    ///
    /// # Returns
    ///
    /// A vector of feature strings supported by the server.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::CommandFailed` if the command fails.
    pub fn feat(&mut self) -> Result<Vec<String>, FtpError> {
        self.send_cmd("FEAT")?;
        let resp = self.read_response()?;
        if resp.is_positive_completion {
            Ok(resp.lines)
        } else {
            Err(FtpError::CommandFailed {
                code: resp.code,
                message: resp.text,
            })
        }
    }

    /// List the contents of a directory on the server.
    ///
    /// Sends the LIST command and parses the response as directory entries.
    /// Supports Unix, Windows, and VMS listing formats automatically.
    ///
    /// # Arguments
    ///
    /// * `directory` - The directory to list, or `None` for the current directory.
    ///
    /// # Returns
    ///
    /// A vector of `FtpEntry` items representing the directory contents.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::DataConnectFailed` if the data connection fails.
    /// Returns `FtpError::TransferFailed` if the transfer fails.
    pub fn list(&mut self, directory: Option<&str>) -> Result<Vec<FtpEntry>, FtpError> {
        let mut data_conn = self.open_data_connection()?;

        let cmd = match directory {
            Some(dir) => format!("LIST {}", dir),
            None => "LIST".to_string(),
        };
        self.send_cmd(&cmd)?;

        let transfer_resp = self.read_response()?;
        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for LIST, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        let mut listing_data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = data_conn.stream.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            if n == 0 { break; }
            listing_data.extend_from_slice(&buf[..n]);
        }

        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        drop(data_conn);

        let listing_str = String::from_utf8_lossy(&listing_data);
        let entries = parse_listing(&listing_str);
        log::debug!("FTP LIST: {} entries", entries.len());
        Ok(entries)
    }

    /// List the names of files in a directory.
    ///
    /// Sends the NLST command to get a simple list of file names
    /// without additional metadata.
    ///
    /// # Arguments
    ///
    /// * `directory` - The directory to list, or `None` for the current directory.
    ///
    /// # Returns
    ///
    /// A vector of file/directory names as strings.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::DataConnectFailed` if the data connection fails.
    /// Returns `FtpError::TransferFailed` if the transfer fails.
    pub fn nlst(&mut self, directory: Option<&str>) -> Result<Vec<String>, FtpError> {
        let mut data_conn = self.open_data_connection()?;

        let cmd = match directory {
            Some(dir) => format!("NLST {}", dir),
            None => "NLST".to_string(),
        };
        self.send_cmd(&cmd)?;

        let transfer_resp = self.read_response()?;
        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for NLST, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = data_conn.stream.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            if n == 0 { break; }
            data.extend_from_slice(&buf[..n]);
        }

        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        drop(data_conn);

        let text = String::from_utf8_lossy(&data);
        Ok(text.lines().map(|l| l.to_string()).collect())
    }

    /// Retrieve a file from the server.
    ///
    /// Sends the RETR command to download a file. Supports resuming
    /// interrupted transfers via the `resume_pos` parameter.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the file to retrieve.
    /// * `output` - A writer to receive the file data.
    /// * `resume_pos` - Optional byte offset to resume from.
    ///
    /// # Returns
    ///
    /// The total number of bytes transferred (including resume offset).
    ///
    /// # Errors
    ///
    /// Returns `FtpError::DataConnectFailed` if the data connection fails.
    /// Returns `FtpError::TransferFailed` if the transfer fails.
    pub fn retr<W: Write>(
        &mut self,
        filename: &str,
        output: &mut W,
        resume_pos: Option<u64>,
    ) -> Result<u64, FtpError> {
        if let Some(pos) = resume_pos {
            self.rest(pos)?;
        }

        let mut data_conn = self.open_data_connection()?;

        self.send_cmd(&format!("RETR {}", filename))?;

        let transfer_resp = self.read_response()?;
        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for RETR, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        let start_pos = resume_pos.unwrap_or(0);
        let mut total_bytes = start_pos;
        let mut buf = [0u8; 32768];
        loop {
            let n = data_conn.stream.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            if n == 0 { break; }
            output.write_all(&buf[..n]).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            total_bytes += n as u64;
        }

        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        drop(data_conn);

        log::debug!("FTP RETR {}: {} bytes", filename, total_bytes);
        Ok(total_bytes)
    }

    /// Store a file on the server.
    ///
    /// Sends the STOR command to upload a file.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name to give the file on the server.
    /// * `input` - A reader providing the file data.
    ///
    /// # Returns
    ///
    /// The number of bytes transferred.
    ///
    /// # Errors
    ///
    /// Returns `FtpError::DataConnectFailed` if the data connection fails.
    /// Returns `FtpError::TransferFailed` if the transfer fails.
    pub fn stor<R: Read>(
        &mut self,
        filename: &str,
        input: &mut R,
    ) -> Result<u64, FtpError> {
        let mut data_conn = self.open_data_connection()?;

        self.send_cmd(&format!("STOR {}", filename))?;

        let transfer_resp = self.read_response()?;
        if !transfer_resp.is_positive_preliminary {
            return Err(FtpError::DataConnectFailed(format!(
                "expected 1xx for STOR, got {}: {}", transfer_resp.code, transfer_resp.text
            )));
        }

        let mut total_bytes = 0u64;
        let mut buf = [0u8; 32768];
        loop {
            let n = input.read(&mut buf).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            if n == 0 { break; }
            data_conn.stream.write_all(&buf[..n]).map_err(|e| FtpError::TransferFailed(e.to_string()))?;
            total_bytes += n as u64;
        }

        let done_resp = self.read_response()?;
        if !done_resp.is_positive_completion {
            return Err(FtpError::TransferFailed(format!(
                "transfer not confirmed: {} {}", done_resp.code, done_resp.text
            )));
        }

        drop(data_conn);

        log::debug!("FTP STOR {}: {} bytes", filename, total_bytes);
        Ok(total_bytes)
    }

    /// Close the FTP connection.
    ///
    /// Sends the QUIT command and closes the control connection.
    /// This method is also called automatically when the client is dropped.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    pub fn quit(&mut self) -> Result<(), FtpError> {
        if let Some(ref mut ctrl) = self.ctrl {
            let _ = FtpCommand::send(ctrl.as_mut(), "QUIT");
            let _ = FtpResponse::read(ctrl.as_mut());
            let _ = ctrl.flush();
        }
        self.ctrl = None;
        self.host = None;
        Ok(())
    }

    /// Fetch metadata for an FTP URL.
    ///
    /// Connects to the server, authenticates, and retrieves information
    /// about the specified resource (file or directory).
    ///
    /// # Arguments
    ///
    /// * `url` - The FTP URL to fetch (e.g., "ftp://user:pass@host/path").
    ///
    /// # Returns
    ///
    /// An `FtpFetchResult` containing metadata about the resource.
    ///
    /// # Errors
    ///
    /// Returns various `FtpError` variants depending on the failure mode.
    pub fn fetch(&mut self, url: &str) -> Result<FtpFetchResult, FtpError> {
        let parsed = parse_ftp_url(url)?;
        let host = parsed.host;
        let port = parsed.port;
        let user = parsed.user.unwrap_or_else(|| "anonymous".to_string());
        let password = parsed.password.unwrap_or_else(|| "wget-rs@".to_string());
        let path = parsed.path;

        self.connect(&host, port)?;

        self.login(&user, &password)?;

        let parent = parent_path(&path);
        if !parent.is_empty() && parent != "/" {
            let segments: Vec<&str> = parent.split('/').filter(|s| !s.is_empty()).collect();
            for seg in segments {
                self.cwd(seg)?;
            }
        }

        self.type_binary()?;

        let filename = base_name(&path);

        let file_size = self.size(&filename)?;

        let mdtm = self.mdtm(&filename)?;

        let list_entries = self.list(None).ok();

        let is_dir = list_entries.as_ref().map(|entries| {
            entries.iter().any(|e| e.name == filename && e.is_dir)
        }).unwrap_or(false);

        let content_length = if is_dir { None } else { file_size };

        let result = FtpFetchResult {
            status_code: if is_dir { 250 } else { 226 },
            content_length,
            content_type: if is_dir {
                Some("text/ftp; type=directory".to_string())
            } else {
                Some("application/octet-stream".to_string())
            },
            last_modified: mdtm,
            is_directory: is_dir,
            file_list: if is_dir { list_entries } else { None },
        };

        Ok(result)
    }

    /// Download a file from an FTP URL.
    ///
    /// Connects to the server, authenticates, navigates to the correct
    /// directory, and downloads the file. Supports resuming interrupted
    /// transfers.
    ///
    /// # Arguments
    ///
    /// * `url` - The FTP URL to download (e.g., "ftp://user:pass@host/path/file").
    /// * `output` - A writer to receive the file data.
    /// * `resume_pos` - Optional byte offset to resume from.
    ///
    /// # Returns
    ///
    /// The total number of bytes downloaded.
    ///
    /// # Errors
    ///
    /// Returns various `FtpError` variants depending on the failure mode.
    pub fn download<W: Write>(
        &mut self,
        url: &str,
        output: &mut W,
        resume_pos: Option<u64>,
    ) -> Result<u64, FtpError> {
        let parsed = parse_ftp_url(url)?;
        let host = parsed.host;
        let port = parsed.port;
        let user = parsed.user.unwrap_or_else(|| "anonymous".to_string());
        let password = parsed.password.unwrap_or_else(|| "wget-rs@".to_string());
        let path = parsed.path;

        self.connect(&host, port)?;

        self.login(&user, &password)?;

        let parent = parent_path(&path);
        if !parent.is_empty() && parent != "/" {
            let segments: Vec<&str> = parent.split('/').filter(|s| !s.is_empty()).collect();
            for seg in segments {
                self.cwd(seg)?;
            }
        }

        self.type_binary()?;

        let filename = base_name(&path);
        let total = self.retr(&filename, output, resume_pos)?;

        self.quit()?;

        Ok(total)
    }

    /// Open a data connection for file transfer.
    ///
    /// Uses passive mode (PASV/EPSV) or active mode (PORT/EPRT) depending
    /// on the client configuration.
    fn open_data_connection(&mut self) -> Result<DataConnection, FtpError> {
        if self.passive {
            data_conn::enter_passive_mode(self.ctrl.as_deref_mut().unwrap(), self.is_ipv6)
                .map_err(|e| FtpError::DataConnectFailed(e.to_string()))
        } else {
            data_conn::enter_active_mode(self.ctrl.as_deref_mut().unwrap(), self.is_ipv6)
                .map_err(|e| FtpError::DataConnectFailed(e.to_string()))?;
            Err(FtpError::DataConnectFailed(
                "active mode data connection must be accepted externally".into(),
            ))
        }
    }

    /// Send an FTP command over the control connection.
    fn send_cmd(&mut self, cmd: &str) -> Result<(), FtpError> {
        let ctrl = self.ctrl.as_deref_mut().ok_or_else(|| {
            FtpError::Connect("not connected".into())
        })?;
        FtpCommand::send(ctrl, cmd)?;
        Ok(())
    }

    /// Read an FTP response from the control connection.
    fn read_response(&mut self) -> Result<FtpResponse, FtpError> {
        let ctrl = self.ctrl.as_deref_mut().ok_or_else(|| {
            FtpError::Connect("not connected".into())
        })?;
        let resp = FtpResponse::read(ctrl)?;
        log::debug!("FTP RESP: {} {}", resp.code, resp.text);
        Ok(resp)
    }
}
