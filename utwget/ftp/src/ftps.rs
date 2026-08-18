//! FTPS (FTP over TLS/SSL) implementation
//!
//! Supports both explicit and implicit FTPS:
//! - Explicit FTPS: Connect to standard FTP port (21), then upgrade with AUTH TLS
//! - Implicit FTPS: Connect directly to TLS port (990) with TLS handshake

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::command::FtpResponse;
use crate::client::FtpError;

/// FTPS configuration
#[derive(Debug, Clone)]
pub struct FtpsConfig {
    /// Whether to verify server certificate
    pub verify_certificate: bool,
    /// Path to CA certificate file
    pub ca_cert: Option<std::path::PathBuf>,
    /// Path to client certificate file
    pub client_cert: Option<std::path::PathBuf>,
    /// Path to client private key file
    pub client_key: Option<std::path::PathBuf>,
    /// Whether to require TLS for data connection
    pub require_data_tls: bool,
}
