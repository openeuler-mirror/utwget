//! HTTP Basic Authentication implementation.
//!
//! This module provides a simple Basic authenticator that encodes credentials
//! using Base64 as specified in RFC 7617.

use super::{AuthChallenge, AuthError, AuthScheme, Authenticator};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Authenticator for HTTP Basic Access Authentication (RFC 7617).
///
/// Basic authentication encodes the username and password as
/// `base64(username:password)` and sends it in the `Authorization` header.
///
/// # Security Note
///
/// Basic authentication sends credentials in an easily decodable form.
/// It should only be used over HTTPS connections to protect credentials
/// from interception.
///
/// # Example
///
/// ```ignore
/// use utwget_http::auth::basic::BasicAuthenticator;
/// use utwget_http::auth::{Authenticator, AuthChallenge, AuthScheme};
///
/// let mut auth = BasicAuthenticator;
/// let challenge = AuthChallenge {
///     scheme: AuthScheme::Basic,
///     // ... other fields
/// };
/// let creds = ut_core::types::Credentials {
///     username: "alice".into(),
///     password: "secret".into(),
/// };
/// let header = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
/// ```
pub struct BasicAuthenticator;

impl Authenticator for BasicAuthenticator {
    /// Generates the `Authorization` header value for Basic authentication.
    ///
    /// The credentials are combined as `username:password`, Base64-encoded,
    /// and prefixed with `"Basic "`.
    ///
    /// # Arguments
    ///
    /// * `_challenge` - The authentication challenge from the server (unused for Basic auth).
    /// * `credentials` - The username and password to authenticate with.
    /// * `_request_method` - The HTTP method (unused for Basic auth).
    /// * `_request_uri` - The request URI (unused for Basic auth).
    /// * `_body` - The request body (unused for Basic auth).
    ///
    /// # Returns
    ///
    /// `Ok(Some(header))` where `header` is `"Basic <base64-encoded-credentials>"`.
    fn authenticate(
        &mut self,
        _challenge: &AuthChallenge,
        credentials: &ut_core::types::Credentials,
        _request_method: &str,
        _request_uri: &str,
        _body: Option<&[u8]>,
    ) -> Result<Option<String>, AuthError> {
        let combined = format!("{}:{}", credentials.username, credentials.password);
        let encoded = STANDARD.encode(combined);
        Ok(Some(format!("Basic {}", encoded)))
    }

    /// Returns `true` because Basic authentication can be sent preemptively.
    ///
    /// Unlike Digest or NTLM, Basic authentication does not require a server
    /// challenge before sending credentials. This allows clients to send
    /// credentials with the first request to reduce round trips.
    fn supports_preemptive(&self) -> bool {
        true
    }

    /// Returns the authentication scheme identifier.
    ///
    /// # Returns
    ///
    /// `AuthScheme::Basic`
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Basic
    }
}
