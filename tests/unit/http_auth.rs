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
