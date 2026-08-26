use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ut_core::error::WgetError;
use ut_core::url::ParsedUrl;
use ut_retriever::{AsyncRetriever, Retriever, RetrieveOutcome, RecursiveRetriever};
use ut_html::converter::{LinkConverter, ConvertOptions};
use std::collections::HashMap;

#[cfg(feature = "metalink")]
use ut_metalink::{MetalinkParser, MetalinkDownloader};

use crate::args::Args;

/// Represents the exit status of the application, returned to the operating system.
///
/// Maps to the standard wget exit codes (see `exits.h` in original wget):
///
/// | Code | Name              | Meaning                                     |
/// |------|-------------------|---------------------------------------------|
/// |  0   | SUCCESS           | All URLs downloaded successfully            |
/// |  1   | GENERIC_ERROR     | Generic error                               |
/// |  2   | PARSE_ERROR       | Command-line or config parse error          |
/// |  3   | IO_FAIL           | File I/O error                              |
/// |  4   | NETWORK_FAIL      | Network/connectivity failure                |
/// |  5   | SSL_AUTH_FAIL     | SSL/TLS certificate verification failure    |
/// |  6   | SERVER_AUTH_FAIL  | Server authentication failure               |
/// |  7   | PROTOCOL_ERROR    | Remote server returned invalid response     |
/// |  8   | SERVER_ERROR      | Remote server returned error                |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExitStatus {
    /// All URLs completed successfully (exit code 0).
    Success,
    /// Generic error (exit code 1).
    Error,
    /// File I/O error: cannot open, write, or close a local file (exit code 3).
    IoFail,
    /// Network failure: DNS, connection, timeout (exit code 4).
    NetworkFail,
    /// SSL/TLS certificate verification failed (exit code 5).
    SslAuthFail,
    /// Server authentication failed: bad credentials (exit code 6).
    ServerAuthFail,
    /// Protocol error: malformed response from server (exit code 7).
    ProtocolError,
    /// Server returned an error response (exit code 8).
    ServerError,
}

impl ExitStatus {
    /// Maps a `WgetError` to the corresponding exit status code.
    ///
    /// Uses the same priority logic as the original wget: the "worst"
    /// (highest numeric) status wins across all URLs.
    pub fn from_error(err: &ut_core::error::WgetError) -> Self {
        use ut_core::error::{TlsError, FtpError};
        match err {
            WgetError::FtpFileNotFound(_)
            | WgetError::FileNotFound(_)
            | WgetError::FileExists(_)
            | WgetError::CannotCreateDir(_)
            | WgetError::WriteError(_) => ExitStatus::IoFail,

            WgetError::HostNotFound(_)
            | WgetError::ConnectionRefused
            |             WgetError::ConnectionTimeout(_)
            | WgetError::SocketError(_) => ExitStatus::NetworkFail,

            WgetError::Tls(TlsError::HandshakeFailed(_))
            | WgetError::Tls(TlsError::CertError(_))
            | WgetError::Tls(TlsError::HostnameMismatch { .. })
            | WgetError::Tls(TlsError::CertExpired)
            | WgetError::Tls(TlsError::CertNotYetValid)
            | WgetError::Tls(TlsError::SelfSigned)
            | WgetError::Tls(TlsError::UnknownAuthority(_))
            | WgetError::CertVerificationFailed { .. }
            | WgetError::TlsInitFailed => ExitStatus::SslAuthFail,

            WgetError::AuthFailed(_)
            | WgetError::FtpLoginRefused
            | WgetError::Ftp(FtpError::UnexpectedResponse { code: 530..=539, .. }) => ExitStatus::ServerAuthFail,

            WgetError::Http { status: 400..=499, .. }
            | WgetError::TooManyRedirects { .. }
            | WgetError::UnsupportedMethod(_)
            | WgetError::UrlParse(_)
            | WgetError::UnsupportedScheme(_) => ExitStatus::ProtocolError,

            WgetError::Http { status: 500..=599, .. }
            | WgetError::FtpServerError(_)
            | WgetError::Ftp(FtpError::UnexpectedResponse { .. })
            | WgetError::Ftp(FtpError::ConnectionLost)
            | WgetError::Ftp(FtpError::DataConnectionFailed(_))
            | WgetError::Ftp(FtpError::PasvFailed(_))
            | WgetError::Ftp(FtpError::PortFailed(_)) => ExitStatus::ServerError,

            WgetError::RetryLimitExceeded { .. }
            | WgetError::QuotaExceeded { .. }
            | WgetError::MetalinkParse(_)
            | WgetError::MetalinkDownload(_)
            | WgetError::MetalinkChecksum { .. }
            | WgetError::Warc(_)
            | WgetError::Config(_) => ExitStatus::Error,

            WgetError::Other(msg) => {
                if msg.contains("DNS") || msg.contains("resolve") || msg.contains("lookup") {
                    ExitStatus::NetworkFail
                } else {
                    ExitStatus::Error
                }
            }

            _ => ExitStatus::Error,
        }
    }

    /// Converts the exit status to the numeric exit code.
    pub fn to_exit_code(self) -> u8 {
        match self {
            ExitStatus::Success => 0,
            ExitStatus::Error => 1,
            ExitStatus::IoFail => 3,
            ExitStatus::NetworkFail => 4,
            ExitStatus::SslAuthFail => 5,
            ExitStatus::ServerAuthFail => 6,
            ExitStatus::ProtocolError => 7,
            ExitStatus::ServerError => 8,
        }
    }
}
