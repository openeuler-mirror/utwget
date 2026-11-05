//! Unit tests for HTTP authentication module.
//!
//! Tests cover Basic, Digest, and NTLM authentication schemes,
//! as well as WWW-Authenticate header parsing.

use ut_http::auth::{
    AuthChallenge, AuthDispatcher, AuthScheme, Authenticator,
    basic::BasicAuthenticator,
};
use ut_core::types::Credentials;

/// Helper to create credentials.
fn make_credentials(username: &str, password: &str) -> Credentials {
    Credentials {
        username: username.to_string(),
        password: password.to_string(),
    }
}

/// Helper to create a Basic challenge.
fn make_basic_challenge(realm: Option<&str>) -> AuthChallenge {
    AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: realm.map(|s| s.to_string()),
        nonce: None,
        opaque: None,
        qop: None,
        algorithm: None,
        charset: None,
        userhash: None,
        stale: None,
        domain: None,
        ntlm_type2_msg: None,
    }
}

// =============================================================================
// Basic Authentication Tests
// =============================================================================

#[test]
fn test_basic_auth_simple() {
    let mut auth = BasicAuthenticator;
    let challenge = make_basic_challenge(Some("test"));
    let creds = make_credentials("alice", "secret");

    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());

    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
    // Base64 of "alice:secret" is "YWxpY2U6c2VjcmV0"
    assert!(header.contains("YWxpY2U6c2VjcmV0"));
}

#[test]
fn test_basic_auth_empty_password() {
    let mut auth = BasicAuthenticator;
    let challenge = make_basic_challenge(None);
    let creds = make_credentials("user", "");

    let result = auth.authenticate(&challenge, &creds, "POST", "/api", None).unwrap();
    assert!(result.is_some());

    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
}

#[test]
fn test_basic_auth_special_characters() {
    let mut auth = BasicAuthenticator;
    let challenge = make_basic_challenge(Some("realm"));
    let creds = make_credentials("user@domain.com", "p@ss:w0rd!");

    let result = auth.authenticate(&challenge, &creds, "GET", "/path", None).unwrap();
    assert!(result.is_some());

    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
}

#[test]
fn test_basic_auth_unicode() {
    let mut auth = BasicAuthenticator;
    let challenge = make_basic_challenge(None);
    let creds = make_credentials("用户", "密码");

    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
}

#[test]
fn test_basic_supports_preemptive() {
    let auth = BasicAuthenticator;
    assert!(auth.supports_preemptive());
}

#[test]
fn test_basic_scheme() {
    let auth = BasicAuthenticator;
    assert_eq!(auth.scheme(), AuthScheme::Basic);
}

// =============================================================================
// WWW-Authenticate Header Parsing Tests
// =============================================================================

#[test]
fn test_parse_basic_challenge() {
    let challenges = AuthChallenge::from_www_authenticate(
        r#"Basic realm="WallyWorld""#
    );

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Basic);
    assert_eq!(challenges[0].realm.as_deref(), Some("WallyWorld"));
}
