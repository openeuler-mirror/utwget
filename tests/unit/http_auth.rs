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

#[test]
fn test_parse_basic_challenge_no_quotes() {
    let challenges = AuthChallenge::from_www_authenticate("Basic realm=test");

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Basic);
    assert_eq!(challenges[0].realm.as_deref(), Some("test"));
}

#[test]
fn test_parse_digest_challenge_md5() {
    let header = r#"Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth,auth-int", algorithm=MD5, opaque="5ccc069c403ebaf9f0171e9517a40e""#;
    let challenges = AuthChallenge::from_www_authenticate(header);

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Digest);
    assert_eq!(challenges[0].realm.as_deref(), Some("testrealm@host.com"));
    assert_eq!(challenges[0].nonce.as_deref(), Some("dcd98b7102dd2f0e8b11d0f600bfb0c093"));
    assert_eq!(challenges[0].qop.as_deref(), Some("auth,auth-int"));
    assert_eq!(challenges[0].algorithm.as_deref(), Some("MD5"));
    assert_eq!(challenges[0].opaque.as_deref(), Some("5ccc069c403ebaf9f0171e9517a40e"));
}

#[test]
fn test_parse_digest_challenge_sha256() {
    let header = r#"Digest realm="api", nonce="abc123", algorithm=SHA-256, qop="auth""#;
    let challenges = AuthChallenge::from_www_authenticate(header);

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Digest);
    assert_eq!(challenges[0].algorithm.as_deref(), Some("SHA-256"));
}

#[test]
fn test_parse_ntlm_challenge() {
    let challenges = AuthChallenge::from_www_authenticate("NTLM");

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Ntlm);
}

#[test]
fn test_parse_bearer_challenge() {
    let challenges = AuthChallenge::from_www_authenticate(
        r#"Bearer realm="api", scope="read write""#
    );

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, AuthScheme::Bearer);
    assert_eq!(challenges[0].realm.as_deref(), Some("api"));
}

#[test]
fn test_parse_multiple_challenges() {
    let header = r#"Basic realm="foo", Digest realm="bar", nonce="abc""#;
    let challenges = AuthChallenge::from_www_authenticate(header);

    assert_eq!(challenges.len(), 2);
    assert_eq!(challenges[0].scheme, AuthScheme::Basic);
    assert_eq!(challenges[0].realm.as_deref(), Some("foo"));
    assert_eq!(challenges[1].scheme, AuthScheme::Digest);
    assert_eq!(challenges[1].realm.as_deref(), Some("bar"));
}

#[test]
fn test_parse_multiple_schemes_on_separate_headers() {
    use ut_http::auth::parse_www_authenticate;

    let headers = [
        r#"Basic realm="simple""#,
        r#"Digest realm="secure", nonce="xyz123""#,
    ];
    let challenges = parse_www_authenticate(&headers);

    assert_eq!(challenges.len(), 2);
    assert_eq!(challenges[0].scheme, AuthScheme::Basic);
    assert_eq!(challenges[1].scheme, AuthScheme::Digest);
}

#[test]
fn test_parse_challenge_with_stale() {
    let header = r#"Digest realm="test", nonce="abc", stale=true"#;
    let challenges = AuthChallenge::from_www_authenticate(header);

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].stale, Some(true));
}

#[test]
fn test_parse_challenge_with_charset() {
    let header = r#"Digest realm="test", nonce="abc", charset=UTF-8"#;
    let challenges = AuthChallenge::from_www_authenticate(header);

    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].charset.as_deref(), Some("UTF-8"));
}

// =============================================================================
// AuthScheme Tests
// =============================================================================

#[test]
fn test_auth_scheme_from_str() {
    assert_eq!(AuthScheme::from_str("Basic"), Some(AuthScheme::Basic));
    assert_eq!(AuthScheme::from_str("basic"), Some(AuthScheme::Basic));
    assert_eq!(AuthScheme::from_str("BASIC"), Some(AuthScheme::Basic));

    assert_eq!(AuthScheme::from_str("Digest"), Some(AuthScheme::Digest));
    assert_eq!(AuthScheme::from_str("digest"), Some(AuthScheme::Digest));

    assert_eq!(AuthScheme::from_str("NTLM"), Some(AuthScheme::Ntlm));
    assert_eq!(AuthScheme::from_str("ntlm"), Some(AuthScheme::Ntlm));

    assert_eq!(AuthScheme::from_str("Bearer"), Some(AuthScheme::Bearer));
    assert_eq!(AuthScheme::from_str("bearer"), Some(AuthScheme::Bearer));

    assert_eq!(AuthScheme::from_str("Unknown"), None);
}

#[test]
fn test_auth_scheme_display() {
    assert_eq!(format!("{}", AuthScheme::Basic), "Basic");
    assert_eq!(format!("{}", AuthScheme::Digest), "Digest");
    assert_eq!(format!("{}", AuthScheme::Ntlm), "NTLM");
    assert_eq!(format!("{}", AuthScheme::Bearer), "Bearer");
}

// =============================================================================
// AuthDispatcher Tests
// =============================================================================

#[test]
fn test_dispatcher_basic_auth() {
    let mut dispatcher = AuthDispatcher::new();
    let challenge = make_basic_challenge(Some("test"));
    let creds = make_credentials("user", "pass");

    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().starts_with("Basic "));
}

#[test]
fn test_dispatcher_preemptive_auth() {
    let mut dispatcher = AuthDispatcher::new();
    let creds = make_credentials("user", "pass");

    let result = dispatcher.preemptive_auth(&creds, "/");
    assert!(result.is_some());
    assert!(result.unwrap().starts_with("Basic "));
}

#[test]
fn test_dispatcher_unknown_scheme() {
    let mut dispatcher = AuthDispatcher::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Bearer, // Bearer not implemented in dispatcher by default
        realm: Some("api".to_string()),
        nonce: None,
        opaque: None,
        qop: None,
        algorithm: None,
        charset: None,
        userhash: None,
        stale: None,
        domain: None,
        ntlm_type2_msg: None,
    };
    let creds = make_credentials("user", "pass");

    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    // Bearer authenticator is not registered by default
    assert!(result.is_none());
}

// =============================================================================
// Digest Authentication Tests (requires auth-digest feature)
// =============================================================================

#[cfg(feature = "auth-digest")]
mod digest_tests {
    use super::*;
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::AuthError;

    fn make_digest_challenge(realm: &str, nonce: &str, qop: Option<&str>, algorithm: &str) -> AuthChallenge {
        AuthChallenge {
            scheme: AuthScheme::Digest,
            realm: Some(realm.to_string()),
            nonce: Some(nonce.to_string()),
            opaque: Some("opaque-value".to_string()),
            qop: qop.map(|s| s.to_string()),
            algorithm: Some(algorithm.to_string()),
            charset: None,
            userhash: None,
            stale: None,
            domain: None,
            ntlm_type2_msg: None,
        }
    }

    #[test]
    fn test_digest_auth_md5() {
        let mut auth = DigestAuthenticator::new();
        let challenge = make_digest_challenge(
            "testrealm@host.com",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            Some("auth"),
            "MD5",
        );
        let creds = make_credentials("Mufasa", "Circle Of Life");

        let result = auth.authenticate(&challenge, &creds, "GET", "/dir/index.html", None).unwrap();
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"Mufasa\""));
        assert!(header.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""));
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc="));
        assert!(header.contains("cnonce="));
    }

    #[test]
    fn test_digest_auth_sha256() {
        let mut auth = DigestAuthenticator::new();
        let challenge = make_digest_challenge(
            "api",
            "abc123",
            Some("auth"),
            "SHA-256",
        );
        let creds = make_credentials("user", "password");

        let result = auth.authenticate(&challenge, &creds, "GET", "/resource", None).unwrap();
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.starts_with("Digest "));
        assert!(header.contains("algorithm=SHA-256"));
    }

    #[test]
    fn test_digest_auth_no_qop() {
        let mut auth = DigestAuthenticator::new();
        let mut challenge = make_digest_challenge("test", "nonce123", None, "MD5");
        challenge.qop = None;
        let creds = make_credentials("user", "pass");

        let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.starts_with("Digest "));
        // Without qop, nc and cnonce should not be present
        assert!(!header.contains("nc="));
    }

    #[test]
    fn test_digest_missing_nonce() {
        let mut auth = DigestAuthenticator::new();
        let challenge = AuthChallenge {
            scheme: AuthScheme::Digest,
            realm: Some("test".to_string()),
            nonce: None,
            opaque: None,
            qop: None,
            algorithm: None,
            charset: None,
            userhash: None,
            stale: None,
            domain: None,
            ntlm_type2_msg: None,
        };
        let creds = make_credentials("user", "pass");

        let result = auth.authenticate(&challenge, &creds, "GET", "/", None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::MissingNonce));
    }

    #[test]
    fn test_digest_unsupported_algorithm() {
        let mut auth = DigestAuthenticator::new();
        let challenge = make_digest_challenge("r", "n", Some("auth"), "SHA-512");
        let creds = make_credentials("user", "pass");

        let result = auth.authenticate(&challenge, &creds, "GET", "/", None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::AlgorithmUnsupported(_)));
    }

    #[test]
    fn test_digest_nonce_count_increments() {
        let mut auth = DigestAuthenticator::new();
        let challenge = make_digest_challenge("r", "n", Some("auth"), "MD5");
        let creds = make_credentials("user", "pass");

        // First authentication
        auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
        // Second authentication - nc should increment
        let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();

        let header = result.unwrap();
        // nc should be 00000002 for second request
        assert!(header.contains("nc=00000002"));
    }

    #[test]
    fn test_digest_not_preemptive() {
        let auth = DigestAuthenticator::new();
        assert!(!auth.supports_preemptive());
    }

    #[test]
    fn test_digest_scheme() {
        let auth = DigestAuthenticator::new();
        assert_eq!(auth.scheme(), AuthScheme::Digest);
    }
}

// =============================================================================
// NTLM Authentication Tests (requires auth-ntlm feature)
// =============================================================================

#[cfg(feature = "auth-ntlm")]
mod ntlm_tests {
    use super::*;
    use ut_http::auth::ntlm::NtlmAuthenticator;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn test_ntlm_type1_message() {
        let mut auth = NtlmAuthenticator::new();
        let challenge = AuthChallenge {
            scheme: AuthScheme::Ntlm,
            realm: None,
            nonce: None, // No Type 2 message yet
            opaque: None,
            qop: None,
            algorithm: None,
            charset: None,
            userhash: None,
            stale: None,
            domain: None,
            ntlm_type2_msg: None,
        };
        let creds = make_credentials("user", "pass");

        let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
        assert!(result.is_some());

        let header = result.unwrap();
        assert!(header.starts_with("NTLM "));

        // Decode and verify it's a Type 1 message
        let msg_b64 = header.strip_prefix("NTLM ").unwrap();
        let msg = STANDARD.decode(msg_b64).unwrap();
        assert!(msg.starts_with(b"NTLMSSP\x00"));
        // Message type should be 1
        let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        assert_eq!(msg_type, 1);
    }

    #[test]
    fn test_ntlm_not_preemptive() {
        let auth = NtlmAuthenticator::new();
        assert!(!auth.supports_preemptive());
    }

    #[test]
    fn test_ntlm_scheme() {
        let auth = NtlmAuthenticator::new();
        assert_eq!(auth.scheme(), AuthScheme::Ntlm);
    }

    #[test]
    fn test_ntlm_v1_mode() {
        let auth = NtlmAuthenticator::new().with_ntlm_v1();
        // Should still work, just using NTLMv1 instead of NTLMv2
        assert_eq!(auth.scheme(), AuthScheme::Ntlm);
    }
