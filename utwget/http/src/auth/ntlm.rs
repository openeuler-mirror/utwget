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
