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

impl NtlmAuthenticator {
    /// Creates a new NTLM authenticator using NTLMv2 (the secure default).
    ///
    /// # Returns
    ///
    /// A new `NtlmAuthenticator` configured for NTLMv2.
    pub fn new() -> Self {
        Self { ntlm_v2: true } // Default to NTLMv2
    }

    /// Configures the authenticator to use NTLMv1 instead of NTLMv2.
    ///
    /// NTLMv1 is less secure and should only be used for compatibility
    /// with legacy servers that do not support NTLMv2.
    ///
    /// # Returns
    ///
    /// The modified authenticator instance.
    pub fn with_ntlm_v1(mut self) -> Self {
        self.ntlm_v2 = false;
        self
    }

    /// Parses an NTLM Type 2 (Challenge) message from the server.
    ///
    /// Extracts the target name, server challenge, and target info block
    /// from the binary message structure.
    ///
    /// # Arguments
    ///
    /// * `challenge_data` - The raw bytes of the Type 2 message.
    ///
    /// # Returns
    ///
    /// The parsed challenge data, or an error if the message is invalid.
    fn parse_challenge(&self, challenge_data: &[u8]) -> Result<NtlmChallenge, AuthError> {
        if challenge_data.len() < 48 {
            return Err(AuthError::InvalidChallenge("challenge too short".into()));
        }

        // Check NTLM signature
        if &challenge_data[0..8] != b"NTLMSSP\x00" {
            return Err(AuthError::InvalidChallenge("invalid NTLM signature".into()));
        }

        // Check message type (should be 2)
        let msg_type = u32::from_le_bytes([challenge_data[8], challenge_data[9], challenge_data[10], challenge_data[11]]);
        if msg_type != 2 {
            return Err(AuthError::InvalidChallenge(format!("expected type 2, got {}", msg_type)));
        }

        // Parse target name
        let target_name_len = u16::from_le_bytes([challenge_data[12], challenge_data[13]]) as usize;
        let target_name_offset = u32::from_le_bytes([challenge_data[16], challenge_data[17], challenge_data[18], challenge_data[19]]) as usize;

        let target_name = if target_name_len > 0 && target_name_offset + target_name_len <= challenge_data.len() {
            String::from_utf16_lossy(
                &challenge_data[target_name_offset..target_name_offset + target_name_len]
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>()
            )
        } else {
            String::new()
        };

        // Parse challenge (8 bytes at offset 24)
        let mut challenge = [0u8; 8];
        challenge.copy_from_slice(&challenge_data[24..32]);

        // Parse target info (for NTLMv2)
        let target_info_len = u16::from_le_bytes([challenge_data[40], challenge_data[41]]) as usize;
        let target_info_offset = u32::from_le_bytes([challenge_data[44], challenge_data[45], challenge_data[46], challenge_data[47]]) as usize;

        let target_info = if target_info_len > 0 && target_info_offset + target_info_len <= challenge_data.len() {
            challenge_data[target_info_offset..target_info_offset + target_info_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(NtlmChallenge {
            target_name,
            challenge,
            target_info,
        })
    }

    /// Creates a Type 1 (Negotiate) message to send to the server.
    ///
    /// This message advertises the client's capabilities and initiates
    /// the NTLM authentication handshake.
    ///
    /// # Returns
    ///
    /// The binary Type 1 message ready to be Base64-encoded and sent.
    fn create_type1_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(40);

        // Signature
        msg.extend_from_slice(b"NTLMSSP\x00");

        // Message type (1)
        msg.extend_from_slice(&1u32.to_le_bytes());

        // Flags
        let flags = NTLMSSP_NEGOTIATE_UNICODE
            | NTLMSSP_NEGOTIATE_NTLM
            | NTLMSSP_REQUEST_TARGET
            | NTLMSSP_NEGOTIATE_SIGN
            | NTLMSSP_NEGOTIATE_SEAL
            | NTLMSSP_NEGOTIATE_ALWAYS_SIGN;
        msg.extend_from_slice(&flags.to_le_bytes());

        // Domain (empty)
        msg.extend_from_slice(&0u16.to_le_bytes()); // length
        msg.extend_from_slice(&0u16.to_le_bytes()); // allocated
        msg.extend_from_slice(&0u32.to_le_bytes()); // offset

        // Workstation (empty)
        msg.extend_from_slice(&0u16.to_le_bytes()); // length
        msg.extend_from_slice(&0u16.to_le_bytes()); // allocated
        msg.extend_from_slice(&0u32.to_le_bytes()); // offset

        msg
    }

    /// Creates a Type 3 (Authenticate) message in response to a Type 2 challenge.
    ///
    /// This message proves the client knows the password without sending it directly.
    /// The actual computation differs between NTLMv1 and NTLMv2.
    ///
    /// # Arguments
    ///
    /// * `username` - The user's account name.
    /// * `password` - The user's password.
    /// * `domain` - The authentication domain (often empty).
    /// * `workstation` - The client workstation name (often empty).
    /// * `challenge` - The parsed Type 2 challenge from the server.
    ///
    /// # Returns
    ///
    /// The binary Type 3 message ready to be Base64-encoded and sent.
    fn create_type3_message(
        &self,
        username: &str,
        password: &str,
        domain: &str,
        workstation: &str,
        challenge: &NtlmChallenge,
    ) -> Vec<u8> {
        // Convert strings to UTF-16LE
        let username_bytes = username.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        let password_bytes = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        let domain_bytes = domain.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();
        let workstation_bytes = workstation.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>();

        if self.ntlm_v2 {
            self.create_type3_message_v2(
                &username_bytes,
                &password_bytes,
                &domain_bytes,
                &workstation_bytes,
                challenge,
            )
        } else {
            self.create_type3_message_v1(
                &username_bytes,
                &password_bytes,
                &domain_bytes,
                &workstation_bytes,
                challenge,
            )
        }
    }

    /// Creates a Type 3 message using NTLMv1 protocol.
    ///
    /// NTLMv1 uses LM and NT hashes computed from the password, then
    /// encrypts the server challenge with these hashes.
    fn create_type3_message_v1(
        &self,
        username: &[u8],
        password: &[u8],
        domain: &[u8],
        workstation: &[u8],
        challenge: &NtlmChallenge,
    ) -> Vec<u8> {
        // Calculate NTLM hash
        let nt_hash = ntlm_hash(password);

        // Calculate LM hash
        let lm_hash = lm_hash(password);

        // Calculate NT response
        let nt_response = nt_response(&nt_hash, &challenge.challenge);

        // Calculate LM response
        let lm_response = lm_response(&lm_hash, &challenge.challenge);

        // Build message
        let mut msg = Vec::with_capacity(256);

        let base_offset = 64u32; // Header size

        // Signature
        msg.extend_from_slice(b"NTLMSSP\x00");

        // Message type (3)
        msg.extend_from_slice(&3u32.to_le_bytes());

        // LM response
        let lm_offset = base_offset;
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&lm_offset.to_le_bytes());

        // NT response
        let nt_offset = lm_offset + lm_response.len() as u32;
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&nt_offset.to_le_bytes());

        // Domain
        let domain_offset = nt_offset + nt_response.len() as u32;
        msg.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        msg.extend_from_slice(&domain_offset.to_le_bytes());

        // Username
        let username_offset = domain_offset + domain.len() as u32;
        msg.extend_from_slice(&(username.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(username.len() as u16).to_le_bytes());
        msg.extend_from_slice(&username_offset.to_le_bytes());

        // Workstation
        let workstation_offset = username_offset + username.len() as u32;
        msg.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
        msg.extend_from_slice(&workstation_offset.to_le_bytes());

        // Session key (empty)
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&(workstation_offset + workstation.len() as u32).to_le_bytes());

        // Flags
        let flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM;
        msg.extend_from_slice(&flags.to_le_bytes());

        // Payload
        msg.extend_from_slice(&lm_response);
        msg.extend_from_slice(&nt_response);
        msg.extend_from_slice(domain);
        msg.extend_from_slice(username);
        msg.extend_from_slice(workstation);

        msg
    }

    /// Creates a Type 3 message using NTLMv2 protocol.
    ///
    /// NTLMv2 uses HMAC-MD5 with the NT hash as the key, providing
    /// stronger security than NTLMv1 and protection against various attacks.
    fn create_type3_message_v2(
        &self,
        username: &[u8],
        password: &[u8],
        domain: &[u8],
        workstation: &[u8],
        challenge: &NtlmChallenge,
    ) -> Vec<u8> {
        // Calculate NTLMv2 hash
        let nt_hash = ntlm_hash(password);
        let nt_v2_hash = ntlm_v2_hash(&nt_hash, username, domain);

        // Generate client challenge
        let client_challenge = generate_client_challenge();

        // Calculate NTLMv2 response
        let (nt_response, lm_response) = ntlm_v2_response(
            &nt_v2_hash,
            &challenge.challenge,
            &client_challenge,
            &challenge.target_info,
        );

        // Build message
        let mut msg = Vec::with_capacity(512);

        let base_offset = 64u32;

        // Signature
        msg.extend_from_slice(b"NTLMSSP\x00");

        // Message type (3)
        msg.extend_from_slice(&3u32.to_le_bytes());

        // LM response
        let lm_offset = base_offset;
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(lm_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&lm_offset.to_le_bytes());

        // NT response
        let nt_offset = lm_offset + lm_response.len() as u32;
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
        msg.extend_from_slice(&nt_offset.to_le_bytes());

        // Domain
        let domain_offset = nt_offset + nt_response.len() as u32;
        msg.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        msg.extend_from_slice(&domain_offset.to_le_bytes());

        // Username
        let username_offset = domain_offset + domain.len() as u32;
        msg.extend_from_slice(&(username.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(username.len() as u16).to_le_bytes());
        msg.extend_from_slice(&username_offset.to_le_bytes());

        // Workstation
        let workstation_offset = username_offset + username.len() as u32;
        msg.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
        msg.extend_from_slice(&(workstation.len() as u16).to_le_bytes());
        msg.extend_from_slice(&workstation_offset.to_le_bytes());

        // Session key (empty)
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&0u16.to_le_bytes());
        msg.extend_from_slice(&(workstation_offset + workstation.len() as u32).to_le_bytes());

        // Flags
        let flags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM;
        msg.extend_from_slice(&flags.to_le_bytes());

        // Payload
        msg.extend_from_slice(&lm_response);
        msg.extend_from_slice(&nt_response);
        msg.extend_from_slice(domain);
        msg.extend_from_slice(username);
        msg.extend_from_slice(workstation);

        msg
    }
}

impl Default for NtlmAuthenticator {
    /// Creates a new NTLM authenticator with default settings (NTLMv2).
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for NtlmAuthenticator {
    /// Performs NTLM authentication for the given challenge.
    ///
    /// On the first call (no Type 2 challenge yet), returns a Type 1
    /// Negotiate message. On subsequent calls with a Type 2 challenge,
    /// returns a Type 3 Authenticate message.
    ///
    /// # Arguments
    ///
    /// * `challenge` - The authentication challenge (contains Type 2 message for second step).
    /// * `credentials` - The user's username and password.
    /// * `_request_method` - Unused for NTLM.
    /// * `_request_uri` - Unused for NTLM.
    /// * `_body` - Unused for NTLM.
    ///
    /// # Returns
    ///
    /// The `Authorization: NTLM <message>` header value.
    fn authenticate(
        &mut self,
        challenge: &AuthChallenge,
        credentials: &ut_core::types::Credentials,
        _request_method: &str,
        _request_uri: &str,
        _body: Option<&[u8]>,
    ) -> Result<Option<String>, AuthError> {
        // Get NTLM challenge from the challenge data
        let challenge_data = STANDARD.decode(challenge.nonce.as_deref().unwrap_or(""))
            .map_err(|e| AuthError::InvalidChallenge(format!("base64 decode error: {}", e)))?;

        // Check if this is a Type 2 challenge
        if challenge_data.starts_with(b"NTLMSSP\x00") && challenge_data.len() >= 12 {
            let msg_type = u32::from_le_bytes([
                challenge_data[8], challenge_data[9], challenge_data[10], challenge_data[11]
            ]);

            if msg_type == 2 {
                // Parse the challenge
                let ntlm_challenge = self.parse_challenge(&challenge_data)?;

                // Create Type 3 response
                let response = self.create_type3_message(
                    &credentials.username,
                    &credentials.password,
                    "", // domain
                    "", // workstation
                    &ntlm_challenge,
                );

                let response_b64 = STANDARD.encode(&response);
                return Ok(Some(format!("NTLM {}", response_b64)));
            }
        }

        // Initial request - send Type 1 message
        let type1 = self.create_type1_message();
        let type1_b64 = STANDARD.encode(&type1);
        Ok(Some(format!("NTLM {}", type1_b64)))
    }

    /// Returns `false` — NTLM cannot be used preemptively.
    ///
    /// NTLM requires a server challenge (Type 2 message) before
    /// the client can prove its identity.
    fn supports_preemptive(&self) -> bool {
        false
    }

    /// Returns the authentication scheme identifier.
    ///
    /// # Returns
    ///
    /// `AuthScheme::Ntlm`
    fn scheme(&self) -> AuthScheme {
        AuthScheme::Ntlm
    }
}

/// Parsed NTLM Type 2 challenge data.
struct NtlmChallenge {
    /// The target (server) name.
    #[allow(dead_code)]
    target_name: String,
    /// The 8-byte server challenge.
    challenge: [u8; 8],
    /// Target info block for NTLMv2.
    target_info: Vec<u8>,
}

// NTLM negotiation flags
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x00000001;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x00000200;
const NTLMSSP_REQUEST_TARGET: u32 = 0x00000004;
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x00000010;
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x00000020;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x00008000;

/// Calculates the NTLM hash (MD4 of UTF-16LE password).
///
/// # Arguments
///
/// * `password` - The password in UTF-16LE encoding.
///
/// # Returns
///
/// The 16-byte NTLM hash.
fn ntlm_hash(password: &[u8]) -> [u8; 16] {
    // Use MD4 hash
    md4_hash(password)
}

/// Calculates the LM hash (deprecated legacy hash).
///
/// The LM hash is considered insecure but is still computed for
/// compatibility with older servers.
///
/// # Arguments
///
/// * `password` - The password bytes.
///
/// # Returns
///
/// The 16-byte LM hash.
fn lm_hash(password: &[u8]) -> [u8; 16] {
    // Convert to uppercase and pad/truncate to 14 bytes
    let mut pwd = [0u8; 14];
    for (i, &b) in password.iter().take(14).enumerate() {
        pwd[i] = b.to_ascii_uppercase();
    }

    // DES encrypt two 7-byte blocks with known key
    let mut hash = [0u8; 16];

    // First half: DES(pwd[0..7], "KGS!@#$%")
    let key1 = create_des_key(&pwd[0..7]);
    des_encrypt(&[0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25], &key1, &mut hash[0..8]);

    // Second half: DES(pwd[7..14], "KGS!@#$%")
    let key2 = create_des_key(&pwd[7..14]);
    des_encrypt(&[0x4b, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25], &key2, &mut hash[8..16]);

    hash
}

/// Calculates the NT response by encrypting the challenge with the NT hash.
///
/// # Arguments
///
/// * `nt_hash` - The 16-byte NT hash.
/// * `challenge` - The 8-byte server challenge.
///
/// # Returns
///
/// The 24-byte NT response.
fn nt_response(nt_hash: &[u8; 16], challenge: &[u8; 8]) -> Vec<u8> {
    // NT response = DES(NT hash, challenge)
    let mut response = vec![0u8; 24];

    // Use NT hash as three DES keys
    let key1 = create_des_key(&nt_hash[0..7]);
    des_encrypt(challenge, &key1, &mut response[0..8]);

    let key2 = create_des_key(&nt_hash[7..14]);
    des_encrypt(challenge, &key2, &mut response[8..16]);

    let key3 = create_des_key(&[nt_hash[14], nt_hash[15], 0, 0, 0, 0, 0]);
    des_encrypt(challenge, &key3, &mut response[16..24]);

    response
}

/// Calculates the LM response (same algorithm as NT response).
///
/// # Arguments
///
/// * `lm_hash` - The 16-byte LM hash.
/// * `challenge` - The 8-byte server challenge.
///
/// # Returns
///
/// The 24-byte LM response.
fn lm_response(lm_hash: &[u8; 16], challenge: &[u8; 8]) -> Vec<u8> {
    nt_response(lm_hash, challenge) // Same algorithm
}

/// Calculates the NTLMv2 hash using HMAC-MD5.
///
/// # Arguments
///
/// * `nt_hash` - The base NT hash.
/// * `username` - The username in UTF-16LE.
/// * `domain` - The domain in UTF-16LE.
///
/// # Returns
///
/// The 16-byte NTLMv2 hash.
fn ntlm_v2_hash(nt_hash: &[u8; 16], username: &[u8], domain: &[u8]) -> [u8; 16] {
    // HMAC-MD5(NT hash, uppercase(username) + domain)
    let mut data = Vec::with_capacity(username.len() + domain.len());
    for &b in username {
        data.push(b.to_ascii_uppercase());
    }
    data.extend_from_slice(domain);

    hmac_md5(nt_hash, &data)
}

/// Generates a random 8-byte client challenge.
///
/// Uses the current timestamp and process ID as entropy sources.
///
/// # Returns
///
/// An 8-byte client challenge value.
fn generate_client_challenge() -> [u8; 8] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let pid = std::process::id();

    [
        (timestamp & 0xFF) as u8,
        ((timestamp >> 8) & 0xFF) as u8,
        ((timestamp >> 16) & 0xFF) as u8,
        ((timestamp >> 24) & 0xFF) as u8,
        (pid & 0xFF) as u8,
        ((pid >> 8) & 0xFF) as u8,
        ((pid >> 16) & 0xFF) as u8,
        ((pid >> 24) & 0xFF) as u8,
    ]
}

/// Calculates the NTLMv2 response pair (NT response and LM response).
///
/// # Arguments
///
/// * `nt_v2_hash` - The NTLMv2 hash.
/// * `server_challenge` - The 8-byte server challenge.
/// * `client_challenge` - The 8-byte client challenge.
/// * `target_info` - The target info block from Type 2 message.
///
/// # Returns
///
/// A tuple of (NT response, LM response) byte vectors.
fn ntlm_v2_response(
    nt_v2_hash: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // Build temp = server_challenge + client_challenge + timestamp + target_info
    let mut temp = Vec::with_capacity(8 + 8 + 8 + target_info.len());
    temp.extend_from_slice(server_challenge);
    temp.extend_from_slice(client_challenge);

    // Add timestamp (Windows FILETIME, 64-bit)
    let timestamp = get_ntlm_timestamp();
    temp.extend_from_slice(&timestamp.to_le_bytes());

    temp.extend_from_slice(target_info);
    temp.extend_from_slice(&[0, 0, 0, 0]); // Null terminator

    // NT response = HMAC-MD5(NTv2 hash, temp) + temp
    let nt_proof = hmac_md5(nt_v2_hash, &temp);
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&temp);

    // LM response = HMAC-MD5(NTv2 hash, server_challenge + client_challenge) + client_challenge
    let mut lm_data = Vec::with_capacity(16);
    lm_data.extend_from_slice(server_challenge);
    lm_data.extend_from_slice(client_challenge);
    let lm_proof = hmac_md5(nt_v2_hash, &lm_data);
    let mut lm_response = Vec::with_capacity(16 + 8);
    lm_response.extend_from_slice(&lm_proof);
    lm_response.extend_from_slice(client_challenge);

    (nt_response, lm_response)
}

/// Gets the current time as a Windows FILETIME value.
///
/// FILETIME is the number of 100-nanosecond intervals since January 1, 1601.
///
/// # Returns
///
/// The current time as a 64-bit FILETIME value.
fn get_ntlm_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Windows FILETIME: 100-nanosecond intervals since January 1, 1601
    // Unix epoch: January 1, 1970
    // Difference: 11644473600 seconds

    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let windows_time = (unix_time + 11644473600) * 10_000_000;
    windows_time
}

/// Computes the MD4 hash of the input data.
///
/// # Arguments
///
/// * `data` - The data to hash.
///
/// # Returns
///
/// The 16-byte MD4 digest.
fn md4_hash(data: &[u8]) -> [u8; 16] {
    let mut md4 = Md4::new();
    md4.update(data);
    md4.finalize()
}

/// Simple MD4 hash implementation.
struct Md4 {
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
    state: [u32; 4],
}

impl Md4 {
    /// Creates a new MD4 hash context with initial state.
    fn new() -> Self {
        Self {
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        }
    }

    /// Updates the hash with more data.
    ///
    /// # Arguments
    ///
    /// * `data` - Additional data to hash.
    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.total_len += data.len() as u64;

        // Process buffered data
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            let take = needed.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while data.len() >= 64 {
            self.process_block(&data[..64]);
            data = &data[64..];
        }

        // Buffer remaining
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalizes the hash and returns the digest.
    ///
    /// # Returns
    ///
    /// The 16-byte MD4 digest.
    fn finalize(&mut self) -> [u8; 16] {
        // Pad message
        let pad_len = if self.buffer_len < 56 { 56 - self.buffer_len } else { 120 - self.buffer_len };
        let mut padding = vec![0u8; pad_len as usize];
        padding[0] = 0x80;

        self.update(&padding);

        // Append length in bits
        let bit_len = (self.total_len * 8).to_le_bytes();
        self.update(&bit_len);

        // Output state
        let mut result = [0u8; 16];
        for (i, &s) in self.state.iter().enumerate() {
            result[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
        }
        result
    }

    /// Processes a single 64-byte block.
    fn process_block(&mut self, block: &[u8]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;

        // Round 1
        for &k in &[0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15] {
            a = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(3);
            let t = d; d = c; c = b; b = a; a = t;
        }

        // Round 2
        for &k in &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
            a = a.wrapping_add(g(b, c, d)).wrapping_add(x[k]).wrapping_add(0x5a827999).rotate_left(5);
            let t = d; d = c; c = b; b = a; a = t;
        }

        // Round 3
        for &k in &[0, 2, 1, 3, 4, 6, 5, 7, 8, 10, 9, 11, 12, 14, 13, 15] {
            a = a.wrapping_add(h(b, c, d)).wrapping_add(x[k]).wrapping_add(0x6ed9eba1).rotate_left(9);
            let t = d; d = c; c = b; b = a; a = t;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

/// MD4 round 1 function.
fn f(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
/// MD4 round 2 function.
fn g(x: u32, y: u32, z: u32) -> u32 { (x & y) | (x & z) | (y & z) }
/// MD4 round 3 function.
fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

/// Computes HMAC-MD5 with a 16-byte key.
///
/// # Arguments
///
/// * `key` - The 16-byte key.
/// * `data` - The data to authenticate.
///
/// # Returns
///
/// The 16-byte HMAC-MD5 digest.
fn hmac_md5(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    // Simplified HMAC-MD5 for 16-byte key
    let mut inner = Vec::with_capacity(64 + data.len());
    for &k in key.iter() {
        inner.push(k ^ 0x36);
    }
    inner.extend_from_slice(&[0x36; 48]); // Pad to 64 bytes
    inner.extend_from_slice(data);

    let inner_hash = md5_hash(&inner);

    let mut outer = Vec::with_capacity(64 + 16);
    for &k in key.iter() {
        outer.push(k ^ 0x5c);
    }
    outer.extend_from_slice(&[0x5c; 48]);
    outer.extend_from_slice(&inner_hash);

    md5_hash(&outer)
}

/// Computes the MD5 hash of the input data.
///
/// # Arguments
///
/// * `data` - The data to hash.
///
/// # Returns
///
/// The 16-byte MD5 digest.
fn md5_hash(data: &[u8]) -> [u8; 16] {
    // Use the md-5 crate if available, otherwise use a simple implementation
    // For now, we'll use a placeholder that returns zeros
    // In production, you'd use the `md-5` crate
    let mut result = [0u8; 16];

    // Simple MD5 implementation
    let mut ctx = Md5Ctx::new();
    ctx.update(data);
    ctx.finalize(&mut result);

    result
}

/// Simple MD5 context.
struct Md5Ctx {
    state: [u32; 4],
    count: [u32; 2],
    buffer: [u8; 64],
}

impl Md5Ctx {
    /// Creates a new MD5 context with initial state.
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: [0, 0],
            buffer: [0; 64],
        }
    }

    /// Updates the hash with more data.
    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        let mut index = ((self.count[0] >> 3) & 0x3f) as usize;

        self.count[0] = self.count[0].wrapping_add((data.len() << 3) as u32);
        if self.count[0] < (data.len() << 3) as u32 {
            self.count[1] = self.count[1].wrapping_add(1);
        }
        self.count[1] = self.count[1].wrapping_add((data.len() >> 29) as u32);

        let part_len = 64 - index;
        if data.len() >= part_len {
            self.buffer[index..64].copy_from_slice(&data[..part_len]);
            let block = self.buffer;
            self.transform(&block);
            let mut i = part_len;
            while i + 63 < data.len() {
                self.transform(&data[i..i + 64]);
                i += 64;
            }
            index = 0;
            data = &data[i..];
        }

        if !data.is_empty() {
            self.buffer[index..index + data.len()].copy_from_slice(data);
        }
    }

    /// Finalizes the hash and writes the digest.
    fn finalize(&mut self, digest: &mut [u8]) {
        let mut bits = [0u8; 8];
        for (i, &c) in self.count.iter().enumerate() {
            bits[i * 4..i * 4 + 4].copy_from_slice(&c.to_le_bytes());
        }

        let index = ((self.count[0] >> 3) & 0x3f) as usize;
        let pad_len = if index < 56 { 56 - index } else { 120 - index };

        let mut padding = [0u8; 64];
        padding[0] = 0x80;
        self.update(&padding[..pad_len]);
        self.update(&bits);

        for (i, &s) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
        }
    }

    /// Transforms a single 64-byte block.
    fn transform(&mut self, block: &[u8]) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;

        // Round 1
        a = b.wrapping_add((a.wrapping_add(f_md5(b, c, d)).wrapping_add(x[0]).wrapping_add(0xd76aa478)).rotate_left(7));
        d = c.wrapping_add((d.wrapping_add(f_md5(a, b, c)).wrapping_add(x[1]).wrapping_add(0xe8c7b756)).rotate_left(12));
        c = b.wrapping_add((c.wrapping_add(f_md5(d, a, b)).wrapping_add(x[2]).wrapping_add(0x242070db)).rotate_left(17));
        b = a.wrapping_add((b.wrapping_add(f_md5(c, d, a)).wrapping_add(x[3]).wrapping_add(0xc1bdceee)).rotate_left(22));
        a = b.wrapping_add((a.wrapping_add(f_md5(b, c, d)).wrapping_add(x[4]).wrapping_add(0xf57c0faf)).rotate_left(7));
        d = c.wrapping_add((d.wrapping_add(f_md5(a, b, c)).wrapping_add(x[5]).wrapping_add(0x4787c62a)).rotate_left(12));
        c = b.wrapping_add((c.wrapping_add(f_md5(d, a, b)).wrapping_add(x[6]).wrapping_add(0xa8304613)).rotate_left(17));
        b = a.wrapping_add((b.wrapping_add(f_md5(c, d, a)).wrapping_add(x[7]).wrapping_add(0xfd469501)).rotate_left(22));
        a = b.wrapping_add((a.wrapping_add(f_md5(b, c, d)).wrapping_add(x[8]).wrapping_add(0x698098d8)).rotate_left(7));
        d = c.wrapping_add((d.wrapping_add(f_md5(a, b, c)).wrapping_add(x[9]).wrapping_add(0x8b44f7af)).rotate_left(12));
        c = b.wrapping_add((c.wrapping_add(f_md5(d, a, b)).wrapping_add(x[10]).wrapping_add(0xffff5bb1)).rotate_left(17));
        b = a.wrapping_add((b.wrapping_add(f_md5(c, d, a)).wrapping_add(x[11]).wrapping_add(0x895cd7be)).rotate_left(22));
        a = b.wrapping_add((a.wrapping_add(f_md5(b, c, d)).wrapping_add(x[12]).wrapping_add(0x6b901122)).rotate_left(7));
        d = c.wrapping_add((d.wrapping_add(f_md5(a, b, c)).wrapping_add(x[13]).wrapping_add(0xfd987193)).rotate_left(12));
        c = b.wrapping_add((c.wrapping_add(f_md5(d, a, b)).wrapping_add(x[14]).wrapping_add(0xa679438e)).rotate_left(17));
        b = a.wrapping_add((b.wrapping_add(f_md5(c, d, a)).wrapping_add(x[15]).wrapping_add(0x49b40821)).rotate_left(22));

        // Round 2
        a = b.wrapping_add((a.wrapping_add(g_md5(b, c, d)).wrapping_add(x[1]).wrapping_add(0xf61e2562)).rotate_left(5));
        d = c.wrapping_add((d.wrapping_add(g_md5(a, b, c)).wrapping_add(x[6]).wrapping_add(0xc040b340)).rotate_left(9));
        c = b.wrapping_add((c.wrapping_add(g_md5(d, a, b)).wrapping_add(x[11]).wrapping_add(0x265e5a51)).rotate_left(14));
        b = a.wrapping_add((b.wrapping_add(g_md5(c, d, a)).wrapping_add(x[0]).wrapping_add(0xe9b6c7aa)).rotate_left(20));
        a = b.wrapping_add((a.wrapping_add(g_md5(b, c, d)).wrapping_add(x[5]).wrapping_add(0xd62f105d)).rotate_left(5));
        d = c.wrapping_add((d.wrapping_add(g_md5(a, b, c)).wrapping_add(x[10]).wrapping_add(0x02441453)).rotate_left(9));
        c = b.wrapping_add((c.wrapping_add(g_md5(d, a, b)).wrapping_add(x[15]).wrapping_add(0xd8a1e681)).rotate_left(14));
        b = a.wrapping_add((b.wrapping_add(g_md5(c, d, a)).wrapping_add(x[4]).wrapping_add(0xe7d3fbc8)).rotate_left(20));
        a = b.wrapping_add((a.wrapping_add(g_md5(b, c, d)).wrapping_add(x[9]).wrapping_add(0x21e1cde6)).rotate_left(5));
        d = c.wrapping_add((d.wrapping_add(g_md5(a, b, c)).wrapping_add(x[14]).wrapping_add(0xc33707d6)).rotate_left(9));
        c = b.wrapping_add((c.wrapping_add(g_md5(d, a, b)).wrapping_add(x[3]).wrapping_add(0xf4d50d87)).rotate_left(14));
        b = a.wrapping_add((b.wrapping_add(g_md5(c, d, a)).wrapping_add(x[8]).wrapping_add(0x455a14ed)).rotate_left(20));
        a = b.wrapping_add((a.wrapping_add(g_md5(b, c, d)).wrapping_add(x[13]).wrapping_add(0xa9e3e905)).rotate_left(5));
        d = c.wrapping_add((d.wrapping_add(g_md5(a, b, c)).wrapping_add(x[2]).wrapping_add(0xfcefa3f8)).rotate_left(9));
        c = b.wrapping_add((c.wrapping_add(g_md5(d, a, b)).wrapping_add(x[7]).wrapping_add(0x676f02d9)).rotate_left(14));
        b = a.wrapping_add((b.wrapping_add(g_md5(c, d, a)).wrapping_add(x[12]).wrapping_add(0x8d2a4c8a)).rotate_left(20));

        // Round 3
        a = b.wrapping_add((a.wrapping_add(h_md5(b, c, d)).wrapping_add(x[5]).wrapping_add(0xfffa3942)).rotate_left(4));
        d = c.wrapping_add((d.wrapping_add(h_md5(a, b, c)).wrapping_add(x[8]).wrapping_add(0x8771f681)).rotate_left(11));
        c = b.wrapping_add((c.wrapping_add(h_md5(d, a, b)).wrapping_add(x[11]).wrapping_add(0x6d9d6122)).rotate_left(16));
        b = a.wrapping_add((b.wrapping_add(h_md5(c, d, a)).wrapping_add(x[14]).wrapping_add(0xfde5380c)).rotate_left(23));
        a = b.wrapping_add((a.wrapping_add(h_md5(b, c, d)).wrapping_add(x[1]).wrapping_add(0xa4beea44)).rotate_left(4));
        d = c.wrapping_add((d.wrapping_add(h_md5(a, b, c)).wrapping_add(x[4]).wrapping_add(0x4bdecfa9)).rotate_left(11));
        c = b.wrapping_add((c.wrapping_add(h_md5(d, a, b)).wrapping_add(x[7]).wrapping_add(0xf6bb4b60)).rotate_left(16));
        b = a.wrapping_add((b.wrapping_add(h_md5(c, d, a)).wrapping_add(x[10]).wrapping_add(0xbebfbc70)).rotate_left(23));
        a = b.wrapping_add((a.wrapping_add(h_md5(b, c, d)).wrapping_add(x[13]).wrapping_add(0x289b7ec6)).rotate_left(4));
        d = c.wrapping_add((d.wrapping_add(h_md5(a, b, c)).wrapping_add(x[0]).wrapping_add(0xeaa127fa)).rotate_left(11));
        c = b.wrapping_add((c.wrapping_add(h_md5(d, a, b)).wrapping_add(x[3]).wrapping_add(0xd4ef3085)).rotate_left(16));
        b = a.wrapping_add((b.wrapping_add(h_md5(c, d, a)).wrapping_add(x[6]).wrapping_add(0x04881d05)).rotate_left(23));
        a = b.wrapping_add((a.wrapping_add(h_md5(b, c, d)).wrapping_add(x[9]).wrapping_add(0xd9d4d039)).rotate_left(4));
        d = c.wrapping_add((d.wrapping_add(h_md5(a, b, c)).wrapping_add(x[12]).wrapping_add(0xe6db99e5)).rotate_left(11));
        c = b.wrapping_add((c.wrapping_add(h_md5(d, a, b)).wrapping_add(x[15]).wrapping_add(0x1fa27cf8)).rotate_left(16));
        b = a.wrapping_add((b.wrapping_add(h_md5(c, d, a)).wrapping_add(x[2]).wrapping_add(0xc4ac5665)).rotate_left(23));

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

/// MD5 round 1 function.
fn f_md5(x: u32, y: u32, z: u32) -> u32 { (x & y) | (!x & z) }
/// MD5 round 2 function.
fn g_md5(x: u32, y: u32, z: u32) -> u32 { (x & z) | (y & !z) }
/// MD5 round 3 function.
fn h_md5(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

/// Creates an 8-byte DES key from 7 input bytes.
///
/// Expands the 7-byte key to 8 bytes and adds parity bits.
///
/// # Arguments
///
/// * `key7` - The 7-byte input key.
///
/// # Returns
///
/// The 8-byte DES key with parity bits.
fn create_des_key(key7: &[u8]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = key7[0];
    key[1] = (key7[0] << 7) | (key7[1] >> 1);
    key[2] = (key7[1] << 6) | (key7[2] >> 2);
    key[3] = (key7[2] << 5) | (key7[3] >> 3);
    key[4] = (key7[3] << 4) | (key7[4] >> 4);
    key[5] = (key7[4] << 3) | (key7[5] >> 5);
    key[6] = (key7[5] << 2) | (key7[6] >> 6);
    key[7] = key7[6] << 1;

    // Add parity bits
    for i in 0..8 {
        let mut parity = 1u8;
        let mut b = key[i];
        for _ in 0..7 {
            parity ^= b & 1;
            b >>= 1;
        }
        key[i] = (key[i] & 0xFE) | parity;
    }

    key
}
