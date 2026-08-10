//! NTLM (NT LAN Manager) authentication implementation.
//!
//! Supports NTLM and NTLMv2 authentication as used by Windows servers and proxies.
//! NTLM is a challenge-response authentication protocol that uses a series of
//! messages (Type 1, Type 2, Type 3) exchanged between client and server.
//!
//! # Security Note
//!
//! NTLMv1 is considered weak and vulnerable to various attacks. NTLMv2 is
//! the recommended version and is used by default. Use [`with_ntlm_v1()`]
//! only when connecting to legacy servers that do not support NTLMv2.
//!
//! # Protocol Flow
//!
//! 1. Client sends Type 1 (Negotiate) message
//! 2. Server responds with Type 2 (Challenge) message
//! 3. Client sends Type 3 (Authenticate) message with proof of credentials

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::{AuthChallenge, AuthError, AuthScheme, Authenticator};

/// NTLM authenticator supporting NTLMv1 and NTLMv2.
///
/// This authenticator handles the three-message NTLM protocol:
/// - Type 1 (Negotiate): Client advertises capabilities
/// - Type 2 (Challenge): Server provides challenge and its capabilities
/// - Type 3 (Authenticate): Client proves knowledge of password
///
/// # Example
///
/// ```ignore
/// use utwget_http::auth::ntlm::NtlmAuthenticator;
/// use utwget_http::auth::{Authenticator, AuthChallenge, AuthScheme};
///
/// // Create NTLMv2 authenticator (default, more secure)
/// let mut auth = NtlmAuthenticator::new();
///
/// // Or use NTLMv1 for legacy servers
/// let mut auth = NtlmAuthenticator::new().with_ntlm_v1();
/// ```
pub struct NtlmAuthenticator {
    /// Whether to use NTLMv2 (true) or NTLMv1 (false).
    ntlm_v2: bool,
}
