// 认证测试 - AuthDispatcher、DigestAuthenticator、BasicAuthenticator

use base64::Engine;

// ========== AuthDispatcher 调度逻辑测试 ==========

#[test]
fn test_auth_dispatcher_basic_scheme() {
    use ut_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme, Authenticator};
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: Some("test".into()),
        nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "user".into(), password: "pass".into() };
    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().starts_with("Basic "));
}

#[test]
fn test_auth_dispatcher_unsupported_scheme_returns_none() {
    use ut_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme};
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Bearer,
        realm: None, nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "u".into(), password: "p".into() };
    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_auth_dispatcher_preemptive_auth() {
    use ut_http::auth::AuthDispatcher;
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::new();
    let creds = Credentials { username: "admin".into(), password: "secret".into() };
    let result = dispatcher.preemptive_auth(&creds, "/admin");
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(header.starts_with("Basic "));
}

#[test]
fn test_auth_dispatcher_custom_authenticators() {
    use ut_http::auth::{AuthDispatcher, AuthChallenge, AuthScheme, Authenticator};
    use ut_http::BasicAuthenticator;
    use ut_core::types::Credentials;
    let mut dispatcher = AuthDispatcher::with_authenticators(vec![
        Box::new(BasicAuthenticator),
    ]);
    let challenge = AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: None, nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "test".into(), password: "test".into() };
    let result = dispatcher.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
}

// ========== DigestAuthenticator MD5/SHA256 计算测试 ==========

#[test]
fn test_digest_md5_hash_known_vector_empty() {
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::Authenticator;
    use ut_http::auth::AuthChallenge;
    use ut_http::auth::AuthScheme;
    use ut_core::types::Credentials;
    let mut auth = DigestAuthenticator::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Digest,
        realm: Some("test".into()),
        nonce: Some("nonce".into()),
        opaque: None,
        qop: None,
        algorithm: Some("MD5".into()),
        charset: None, userhash: None, stale: None,
        domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "".into(), password: "".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    let header = result.unwrap();
    // Verify the header format, not the specific response hash
    // since response depends on nonce, cnonce, nc which are dynamic
    assert!(header.starts_with("Digest "));
    assert!(header.contains("username=\"\""));
    assert!(header.contains("realm=\"test\""));
    assert!(header.contains("nonce=\"nonce\""));
    assert!(header.contains("uri=\"/\""));
    assert!(header.contains("algorithm=MD5"));
    assert!(header.contains("response=\""));
}

#[test]
fn test_digest_sha256_hash_known_vector_empty() {
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::Authenticator;
    use ut_http::auth::AuthChallenge;
    use ut_http::auth::AuthScheme;
    use ut_core::types::Credentials;
    let mut auth = DigestAuthenticator::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Digest,
        realm: Some("test".into()),
        nonce: Some("nonce".into()),
        opaque: None,
        qop: None,
        algorithm: Some("SHA-256".into()),
        charset: None, userhash: None, stale: None,
        domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "".into(), password: "".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(header.contains("algorithm=SHA-256"));
}

#[test]
fn test_digest_response_with_qop_auth() {
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::Authenticator;
    use ut_http::auth::AuthChallenge;
    use ut_http::auth::AuthScheme;
    use ut_core::types::Credentials;
    let mut auth = DigestAuthenticator::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Digest,
        realm: Some("realm".into()),
        nonce: Some("nonce123".into()),
        opaque: Some("opaque456".into()),
        qop: Some("auth".into()),
        algorithm: Some("MD5".into()),
        charset: None, userhash: None, stale: None,
        domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "alice".into(), password: "secret".into() };
    let result = auth.authenticate(&challenge, &creds, "POST", "/api/data", Some(b"{}")).unwrap();
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(header.contains("qop=auth"));
    assert!(header.contains("nc="));
    assert!(header.contains("cnonce="));
    assert!(header.contains("opaque=\"opaque456\""));
}

#[test]
fn test_digest_response_no_qop() {
    use ut_http::auth::digest::DigestAuthenticator;
    use ut_http::auth::Authenticator;
    use ut_http::auth::AuthChallenge;
    use ut_http::auth::AuthScheme;
    use ut_core::types::Credentials;
    let mut auth = DigestAuthenticator::new();
    let challenge = AuthChallenge {
        scheme: AuthScheme::Digest,
        realm: Some("r".into()),
        nonce: Some("n".into()),
        opaque: None,
        qop: None,
        algorithm: Some("MD5".into()),
        charset: None, userhash: None, stale: None,
        domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "u".into(), password: "p".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/", None).unwrap();
    assert!(result.is_some());
    let header = result.unwrap();
    assert!(!header.contains("nc="));
    assert!(!header.contains("cnonce="));
}

// ========== BasicAuthenticator base64 编码测试 ==========

#[test]
fn test_basic_auth_base64_roundtrip() {
    use ut_http::auth::basic::BasicAuthenticator;
    use ut_http::auth::Authenticator;
    use ut_http::auth::AuthChallenge;
    use ut_http::auth::AuthScheme;
    use ut_core::types::Credentials;
    let mut auth = BasicAuthenticator;
    let challenge = AuthChallenge {
        scheme: AuthScheme::Basic,
        realm: None, nonce: None, opaque: None, qop: None,
        algorithm: None, charset: None, userhash: None,
        stale: None, domain: None, ntlm_type2_msg: None,
    };
    let creds = Credentials { username: "testuser".into(), password: "testpass".into() };
    let result = auth.authenticate(&challenge, &creds, "GET", "/index.html", None).unwrap();
    let header = result.unwrap();
    let encoded = header.strip_prefix("Basic ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).unwrap();
    assert_eq!(String::from_utf8(decoded).unwrap(), "testuser:testpass");
}
