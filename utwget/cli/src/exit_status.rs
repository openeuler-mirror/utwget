//! Application exit status (GNU wget exits.h semantics).
//!
//! Extracted from the monolithic `app.rs` (arch review 3.2): a
//! self-contained enum + mapping with no App dependencies.

use ut_core::error::WgetError;

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
    /// Mirrors GNU wget's exit-code mapping from `exits.c` and `http.c`:
    /// - HTTP 4xx/5xx → `ServerError` (8)
    /// - FTP file not found → `ServerError` (8) (FTPNSFOD)
    /// - Retry limit exceeded → `NetworkFail` (4) (TRYLIMEXC)
    /// - TLS init failed → `Error` (1) (SSLINITFAILED → UNKNOWN)
    /// - URL parse / unsupported scheme → `Error` (1) (URLERROR → UNKNOWN)
    pub fn from_error(err: &ut_core::error::WgetError) -> Self {
        use ut_core::error::TlsError;
        match err {
            WgetError::FileNotFound(_)
            | WgetError::FileExists(_)
            | WgetError::CannotCreateDir(_)
            | WgetError::WriteError(_) => ExitStatus::IoFail,

            WgetError::HostNotFound(_)
            | WgetError::ConnectionRefused
            | WgetError::ConnectionTimeout(_)
            | WgetError::SocketError(_)
            // DNS failures are network failures (arch 6.3-1: previously
            // matched via msg.contains("DNS") on WgetError::Other, which
            // broke silently when the message wording changed).
            | WgetError::DnsResolution(_)
            | WgetError::DnsTimeout => ExitStatus::NetworkFail,

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
            | WgetError::FtpLoginRefused => ExitStatus::ServerAuthFail,

            WgetError::Http { status: 400..=599, .. }
            | WgetError::FtpServerError(_)
            | WgetError::FtpFileNotFound(_)
            | WgetError::TooManyRedirects { .. } => ExitStatus::ServerError,

            WgetError::UnsupportedMethod(_)
            | WgetError::UrlParse(_)
            | WgetError::UnsupportedScheme(_) => ExitStatus::Error,

            WgetError::RetryLimitExceeded { .. } => ExitStatus::NetworkFail,

            WgetError::QuotaExceeded { .. }
            | WgetError::MetalinkParse(_)
            | WgetError::MetalinkDownload(_)
            | WgetError::MetalinkChecksum { .. }
            | WgetError::Warc(_)
            | WgetError::Config(_) => ExitStatus::Error,

            WgetError::Other(_) => ExitStatus::Error,

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

    /// Update `current` with `new` using GNU wget's aggregation logic
    /// (exits.c:74-84): the first non-zero status wins, but a lower
    /// non-zero status replaces a higher one.
    ///
    /// ```text
    /// if new != 0 && (current == 0 || new < current)
    ///     current = new
    /// ```
    pub fn aggregate(current: ExitStatus, new: ExitStatus) -> ExitStatus {
        if new != ExitStatus::Success
            && (current == ExitStatus::Success || new < current)
        {
            new
        } else {
            current
        }
    }

    /// Converts a `u8` discriminant back to an `ExitStatus`.
    ///
    /// This is the inverse of `as u8` for use with atomic counters.
    /// Returns `ExitStatus::Error` for invalid values.
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            0 => ExitStatus::Success,
            1 => ExitStatus::Error,
            3 => ExitStatus::IoFail,
            4 => ExitStatus::NetworkFail,
            5 => ExitStatus::SslAuthFail,
            6 => ExitStatus::ServerAuthFail,
            7 => ExitStatus::ProtocolError,
            8 => ExitStatus::ServerError,
            _ => ExitStatus::Error,
        }
    }
}
