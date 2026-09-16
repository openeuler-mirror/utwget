//! TLS policy helpers extracted from `rustls_impl.rs` (arch review 3.2):
//! public-key pinning verifier, `--pinnedpubkey` parsing, cipher-list
//! parsing, and CRL loading.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// A certificate verifier that enforces public-key pinning (--pinnedpubkey).
///
/// Wraps an inner verifier (either the standard `WebPkiServerVerifier` or
/// `SkipServerVerification`). After the inner verifier runs, this verifier
/// additionally checks that the SHA-256 hash of the server's public key
/// (SubjectPublicKeyInfo) matches one of the pinned hashes.
///
/// Format: `sha256//<base64-hash>` (matching curl/wget --pinnedpubkey syntax).
/// Multiple pins separated by `;`.
pub(super) struct PinnedPubKeyVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    /// Pinned SHA-256 hashes (raw 32-byte digests, base64-decoded).
    pins: Vec<Vec<u8>>,
}

impl PinnedPubKeyVerifier {
    pub(super) fn new(inner: Arc<dyn ServerCertVerifier>, pins: Vec<Vec<u8>>) -> Self {
        PinnedPubKeyVerifier { inner, pins }
    }
}

impl std::fmt::Debug for PinnedPubKeyVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedPubKeyVerifier")
            .field("pins_count", &self.pins.len())
            .finish()
    }
}

impl ServerCertVerifier for PinnedPubKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // First, let the inner verifier do its job (chain validation, etc.)
        let verified = self.inner.verify_server_cert(
            end_entity, intermediates, server_name, ocsp_response, now,
        )?;

        // Then, check public key pinning.
        let spki = extract_spki(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("pinnedpubkey: failed to extract SubjectPublicKeyInfo".into())
        })?;
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(spki);

        for pin in &self.pins {
            if pin == hash.as_slice() {
                return Ok(verified);
            }
        }

        Err(rustls::Error::General(
            "pinnedpubkey: server public key does not match any pinned hash".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Parse a --pinnedpubkey string into a list of SHA-256 hash digests.
///
/// Format: `sha256//<base64>` (matching curl/wget). Multiple pins
/// separated by `;`. Returns an empty vec if no valid pins found.
pub(super) fn parse_pinnedpubkey(s: &str) -> Vec<Vec<u8>> {
    let mut pins = Vec::new();
    for entry in s.split(';') {
        let entry = entry.trim();
        if let Some(rest) = entry.strip_prefix("sha256//") {
            // base64 standard (with padding) or URL-safe
            let hash = base64_decode(rest);
            if hash.len() == 32 {
                pins.push(hash);
            } else {
                log::warn!("--pinnedpubkey: invalid sha256 hash length ({}), expected 32", hash.len());
            }
        } else {
            log::warn!("--pinnedpubkey: unsupported format '{}' (only sha256// is supported)", entry);
        }
    }
    pins
}

/// Base64 decoder supporting both standard and URL-safe alphabets.
fn base64_decode(s: &str) -> Vec<u8> {
    // Try standard base64 first, then URL-safe
    use base64::Engine;
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s) {
        return v;
    }
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE.decode(s) {
        return v;
    }
    Vec::new()
}

/// Extract the SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate.
///
/// The SPKI is the raw DER bytes including the outer SEQUENCE tag, matching
/// what curl/wget hash for --pinnedpubkey. Uses a minimal DER walker.
fn extract_spki(cert_der: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    // Outer SEQUENCE (Certificate)
    let (_, body) = read_der_tlv(cert_der, &mut pos)?;
    // Inner SEQUENCE (TBSCertificate)
    let mut tbs_pos = 0;
    let (tbs_tag, tbs_body) = read_der_tlv(body, &mut tbs_pos)?;
    if tbs_tag != 0x30 { return None; } // must be SEQUENCE
    // Now walk through TBSCertificate fields:
    let mut field_pos = 0;
    // 1. version: [0] EXPLICIT (optional, context-specific tag 0xA0)
    let (_, _) = read_der_tlv(tbs_body, &mut field_pos)?;
    // Actually, version may or may not be present (context tag [0]).
    // Let's handle both cases: if first byte is 0xA0, skip version;
    // otherwise it's serialNumber.
    // Re-parse more carefully:
    let mut fp = 0;
    // Optional: version [0] (0xA0)
    if tbs_body.first() == Some(&0xA0) {
        let _ = read_der_tlv(tbs_body, &mut fp)?;
    }
    // serialNumber (INTEGER)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // signature (AlgorithmIdentifier SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // issuer (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // validity (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // subject (SEQUENCE)
    let _ = read_der_tlv(tbs_body, &mut fp)?;
    // Next field: SubjectPublicKeyInfo (SEQUENCE) - this is what we want
    let spki_start = fp;
    let (spki_tag, _) = read_der_tlv(tbs_body, &mut fp)?;
    if spki_tag != 0x30 { return None; } // must be SEQUENCE
    let spki_end = fp;
    Some(&tbs_body[spki_start..spki_end])
}

/// Read a DER Tag-Length-Value element, returning (tag_byte, value_slice)
/// and advancing `pos` past the entire TLV.
fn read_der_tlv<'a>(buf: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    if *pos >= buf.len() { return None; }
    let tag = buf[*pos];
    *pos += 1;
    if *pos >= buf.len() { return None; }
    let first_len_byte = buf[*pos];
    *pos += 1;
    let len = if first_len_byte & 0x80 == 0 {
        // Short form: length is the byte itself
        first_len_byte as usize
    } else {
        // Long form: lower 7 bits give number of subsequent length bytes
        let num_bytes = (first_len_byte & 0x7F) as usize;
        if num_bytes > 4 || *pos + num_bytes > buf.len() { return None; }
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | (buf[*pos + i] as usize);
        }
        *pos += num_bytes;
        l
    };
    if *pos + len > buf.len() { return None; }
    let value = &buf[*pos..*pos + len];
    *pos += len;
    Some((tag, value))
}
///
/// Supports the following formats (colon or comma separated):
///
/// - **IANA names**: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
/// - **OpenSSL short names**: `AES256-GCM-SHA384`
/// - **Keywords**: `ALL` (all available), `HIGH` (all AES/ChaCha suites)
///
/// Unknown names are silently skipped (with a debug log). The returned list
/// preserves the order of the input, matching the server's preference.
pub(super) fn parse_cipher_list(ciphers: &str) -> Vec<rustls::SupportedCipherSuite> {
    use rustls::crypto::ring;

    // Build a lookup table mapping various cipher names to rustls suites.
    let all_suites = ring::ALL_CIPHER_SUITES;

    let mut result: Vec<rustls::SupportedCipherSuite> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for token in ciphers.split(|c| c == ':' || c == ',') {
        let token = token.trim().to_uppercase();
        if token.is_empty() {
            continue;
        }

        // Handle keywords
        match token.as_str() {
            "ALL" => {
                for suite in all_suites {
                    let key = format!("{:?}", suite.suite());
                    if seen.insert(key) {
                        result.push(*suite);
                    }
                }
                continue;
            }
            "HIGH" => {
                // HIGH = all AEAD suites (AES-GCM, ChaCha20-Poly1305)
                for suite in all_suites {
                    let name = format!("{:?}", suite.suite());
                    if (name.contains("GCM") || name.contains("CHACHA20"))
                        && seen.insert(name.clone())
                    {
                        result.push(*suite);
                    }
                }
                continue;
            }
            _ => {}
        }

        // Match by IANA name or OpenSSL short name
        let matched = all_suites.iter().find(|suite| {
            let iana = format!("{:?}", suite.suite());
            // IANA name match (case-insensitive)
            if iana.eq_ignore_ascii_case(&token) {
                return true;
            }
            // OpenSSL short name mapping
            let openssl = iana_to_openssl(&iana);
            if openssl.eq_ignore_ascii_case(&token) {
                return true;
            }
            false
        });

        if let Some(suite) = matched {
            let key = format!("{:?}", suite.suite());
            if seen.insert(key) {
                result.push(*suite);
            }
        } else {
            log::debug!("--ciphers: unknown cipher \"{}\" (skipped)", token);
        }
    }

    result
}

/// Map IANA cipher suite name to OpenSSL short name.
fn iana_to_openssl(iana: &str) -> String {
    // Common mappings: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> AES256-GCM-SHA384
    // This is a simplified mapping for the most common suites.
    match iana {
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" | "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "AES256-GCM-SHA384".into(),
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "AES128-GCM-SHA256".into(),
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" | "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "CHACHA20-POLY1305".into(),
        "TLS13_AES_256_GCM_SHA384" => "TLS_AES_256_GCM_SHA384".into(),
        "TLS13_AES_128_GCM_SHA256" => "TLS_AES_128_GCM_SHA256".into(),
        "TLS13_CHACHA20_POLY1305_SHA256" => "TLS_CHACHA20_POLY1305_SHA256".into(),
        _ => iana.to_string(),
    }
}

/// Load CRLs (Certificate Revocation Lists) from a file.
///
/// Supports both PEM (-----BEGIN X509 CRL-----) and DER formats.
/// A PEM file may contain multiple CRLs; a DER file contains exactly one.
///
/// # Arguments
///
/// * `path` - Path to the CRL file.
///
/// # Returns
///
/// A vector of `CertificateRevocationListDer` on success.
pub(super) fn load_crls_from_file(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateRevocationListDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;

    // Check if the file is PEM (ASCII armor) or DER (binary).
    let is_pem = data.windows(5).any(|w| w == b"-----");
    if is_pem {
        // Parse PEM using rustls_pemfile::crls()
        let cursor = std::io::Cursor::new(&data);
        let mut buf_reader = std::io::BufReader::new(cursor);
        let mut crls = Vec::new();
        for item in rustls_pemfile::crls(&mut buf_reader) {
            match item {
                Ok(crl) => crls.push(crl),
                Err(e) => {
                    log::warn!("skipping unparseable CRL block in {}: {}", path.display(), e);
                }
            }
        }
        if crls.is_empty() {
            return Err(format!("no valid CRLs found in PEM file {}", path.display()));
        }
        Ok(crls)
    } else {
        // DER format: single CRL
        Ok(vec![rustls::pki_types::CertificateRevocationListDer::from(data)])
    }
}
