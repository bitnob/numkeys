//! Attestation creation logic.

use crate::attestation::claims::Claims;
use crate::attestation::jwt::encode_jwt;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use hex;
use numkeys_crypto::{
    create_binding_signature, generate_nonce, hash_phone_number_spec, BindingMessage,
};
use numkeys_types::{Attestation, NumKeysResult, PhoneNumber, PrivateKey, ProxyNumber, PublicKey};
use uuid::Uuid;

/// Builder for creating attestations.
pub struct AttestationBuilder<'a> {
    issuer_domain: String,
    issuer_private_key: &'a PrivateKey,
    phone_number: PhoneNumber,
    proxy_number: ProxyNumber,
    user_pubkey: PublicKey,
    generation_nonce: Option<String>,
}

impl<'a> AttestationBuilder<'a> {
    /// Create a new attestation builder.
    pub fn new(
        issuer_domain: String,
        issuer_private_key: &'a PrivateKey,
        phone_number: PhoneNumber,
        proxy_number: ProxyNumber,
        user_pubkey: PublicKey,
    ) -> Self {
        Self {
            issuer_domain,
            issuer_private_key,
            phone_number,
            proxy_number,
            user_pubkey,
            generation_nonce: None,
        }
    }

    /// Set the proxy-generation nonce to embed in the attestation.
    pub fn generation_nonce(mut self, nonce: String) -> Self {
        self.generation_nonce = Some(nonce);
        self
    }

    /// Build the attestation.
    pub fn build(self) -> NumKeysResult<Attestation> {
        let now = Utc::now();
        let iat = now.timestamp();
        let nonce = self
            .generation_nonce
            .map(numkeys_types::Nonce::new)
            .unwrap_or_else(generate_nonce);
        let jti = Uuid::new_v4().to_string();

        // Hash phone number according to spec
        let phone_hash_str = hash_phone_number_spec(&self.phone_number);

        // Generate binding signature using the canonical binding fields.
        let user_pubkey_b64 = self.user_pubkey.to_base64();
        let binding_message = BindingMessage {
            iss: &self.issuer_domain,
            sub: self.proxy_number.as_str(),
            phone_hash: &phone_hash_str,
            user_pubkey: &user_pubkey_b64,
            nonce: nonce.as_str(),
            iat,
            jti: &jti,
        };
        let binding_proof_str =
            create_binding_signature(&binding_message, self.issuer_private_key)?;

        // Parse hash from "sha256:..." format
        let hash_hex = phone_hash_str.strip_prefix("sha256:").ok_or_else(|| {
            numkeys_types::NumKeysError::CryptoError("Invalid hash format".into())
        })?;
        let hash_bytes: [u8; 32] = hex::decode(hash_hex)
            .map_err(|_| numkeys_types::NumKeysError::CryptoError("Invalid hash hex".into()))?
            .try_into()
            .map_err(|_| numkeys_types::NumKeysError::CryptoError("Invalid hash length".into()))?;

        let proof_base64 = binding_proof_str.strip_prefix("sig:").ok_or_else(|| {
            numkeys_types::NumKeysError::CryptoError("Invalid proof format".into())
        })?;
        let sig_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(proof_base64)
            .map_err(|_| numkeys_types::NumKeysError::CryptoError("Invalid proof base64".into()))?;

        let proof_bytes: [u8; 64] = sig_bytes
            .get(..64)
            .ok_or_else(|| numkeys_types::NumKeysError::CryptoError("Invalid proof length".into()))?
            .try_into()
            .map_err(|_| numkeys_types::NumKeysError::CryptoError("Invalid proof length".into()))?;

        Ok(Attestation {
            proxy_number: self.proxy_number,
            phone_hash: numkeys_types::PhoneHash::from_bytes(hash_bytes),
            iss: self.issuer_domain,
            exp: None,
            iat: now,
            user_pubkey: self.user_pubkey,
            binding_proof: numkeys_types::BindingProof::from_bytes(proof_bytes),
            salt: vec![], // Not used in spec-compliant version
            jti,
            nonce,
        })
    }

    /// Build the attestation and encode as JWT.
    pub fn build_jwt(self) -> NumKeysResult<String> {
        // Store reference to issuer key before consuming self
        let issuer_key = self.issuer_private_key;
        let attestation = self.build()?;

        encode_jwt(&Claims::from_attestation(&attestation), issuer_key)
    }
}

/// Create a signed JWT attestation.
///
/// # Security Considerations
/// - Uses Ed25519 for signing
/// - Includes all required security fields
/// - Binding signature prevents proxy number substitution and is verifiable
pub fn create_attestation(
    issuer_domain: &str,
    issuer_private_key: &PrivateKey,
    phone_number: &PhoneNumber,
    proxy_number: &ProxyNumber,
    user_pubkey: &PublicKey,
) -> NumKeysResult<String> {
    AttestationBuilder::new(
        issuer_domain.to_string(),
        issuer_private_key,
        phone_number.clone(),
        proxy_number.clone(),
        user_pubkey.clone(),
    )
    .build_jwt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use numkeys_crypto::generate_keypair;

    #[test]
    fn test_attestation_creation() {
        let issuer_key = generate_keypair().unwrap();
        let user_key = generate_keypair().unwrap();
        let phone = PhoneNumber::new("+1234567890").unwrap();
        let proxy = ProxyNumber::new("+23400123456789").unwrap();

        let attestation = AttestationBuilder::new(
            "issuer.com".to_string(),
            &issuer_key.private,
            phone.clone(),
            proxy.clone(),
            user_key.public.clone(),
        )
        .build()
        .unwrap();

        assert_eq!(attestation.iss, "issuer.com");
        assert_eq!(attestation.proxy_number, proxy);
        assert_eq!(attestation.user_pubkey, user_key.public);
        assert!(attestation.exp.is_none());
    }

    #[test]
    fn test_jwt_creation() {
        let issuer_key = generate_keypair().unwrap();
        let user_key = generate_keypair().unwrap();
        let phone = PhoneNumber::new("+1234567890").unwrap();
        let proxy = ProxyNumber::new("+23400123456789").unwrap();

        let jwt = create_attestation(
            "issuer.com",
            &issuer_key.private,
            &phone,
            &proxy,
            &user_key.public,
        )
        .unwrap();

        // JWT should have three parts
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_attestation_preserves_generation_nonce() {
        let issuer_key = generate_keypair().unwrap();
        let user_key = generate_keypair().unwrap();
        let phone = PhoneNumber::new("+1234567890").unwrap();
        let proxy = ProxyNumber::new("+23400123456789").unwrap();
        let generation_nonce = "a1b2c3d4e5f67890a1b2c3d4e5f67890".to_string();

        let attestation = AttestationBuilder::new(
            "issuer.com".to_string(),
            &issuer_key.private,
            phone,
            proxy,
            user_key.public,
        )
        .generation_nonce(generation_nonce.clone())
        .build()
        .unwrap();

        assert_eq!(attestation.nonce.as_str(), generation_nonce);
    }
}
