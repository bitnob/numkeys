//! Attestation types and JWT claims.

use crate::{
    crypto::{BindingProof, Nonce, PublicKey, Signature},
    phone::{PhoneHash, ProxyNumber},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// JWT attestation claims.
///
/// This is the core data structure that proves a user owns a phone number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The proxy number assigned to the user.
    pub proxy_number: ProxyNumber,

    /// SHA256 hash of the normalized phone number.
    pub phone_hash: PhoneHash,

    /// Issuer domain (e.g., "example.com").
    pub iss: String,

    /// Optional expiration time.
    ///
    /// Core protocol freshness is based on `iat` + verifier policy.
    /// Legacy issuers MAY still include `exp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<DateTime<Utc>>,

    /// Issued at time.
    pub iat: DateTime<Utc>,

    /// User's public key for challenge-response.
    pub user_pubkey: PublicKey,

    /// Cryptographic binding between phone_hash and proxy_number.
    pub binding_proof: BindingProof,

    /// Salt used for phone hashing in legacy/internal flows.
    #[serde(with = "base64_serde")]
    pub salt: Vec<u8>,

    /// JWT ID for uniqueness.
    pub jti: String,

    /// Nonce for replay protection.
    pub nonce: Nonce,
}

impl Attestation {
    /// Check if the attestation has expired when an explicit `exp` exists.
    pub fn is_expired(&self) -> bool {
        self.exp.is_some_and(|exp| Utc::now() > exp)
    }

    /// Get the time until expiration, if `exp` exists.
    pub fn time_until_expiry(&self) -> Option<chrono::Duration> {
        self.exp.map(|exp| exp - Utc::now())
    }
}

/// Challenge sent by a service for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The proxy number being verified.
    pub proxy_number: ProxyNumber,

    /// Service identifier (e.g., "signal.org").
    pub service_id: String,

    /// Random nonce from the service.
    pub challenge_nonce: Nonce,

    /// Identifier for this verification attempt.
    pub verification_id: String,

    /// Challenge expiry timestamp in Unix milliseconds.
    pub expires_at: i64,

    /// Optional callback URL where the wallet should return the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

/// Canonical payload signed by the user during verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponsePayload {
    /// Service identifier copied from the challenge.
    pub service_id: String,

    /// Challenge nonce copied from the challenge.
    pub challenge_nonce: Nonce,

    /// Fresh wallet-generated nonce for this response.
    pub response_nonce: Nonce,

    /// Identifier for this verification attempt.
    pub verification_id: String,

    /// Response timestamp in Unix milliseconds.
    pub timestamp: i64,
}

/// User's response to a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The proxy number being verified.
    pub proxy_number: ProxyNumber,

    /// The attestation JWT being presented.
    pub attestation_jwt: String,

    /// Canonical payload signed by the user.
    pub challenge_response: ChallengeResponsePayload,

    /// User signature over canonical JSON of `challenge_response`.
    pub user_signature: Signature,
}

/// Issuer information for key discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerInfo {
    /// Issuer's public key.
    pub public_key: PublicKey,

    /// Algorithm (always "Ed25519" for now).
    pub algorithm: String,

    /// When the key was created.
    pub created_at: DateTime<Utc>,

    /// Optional key ID for rotation.
    pub key_id: Option<String>,

    /// Service discovery information published by the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_info: Option<ServiceDiscovery>,
}

/// Optional service discovery information for issuer metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscovery {
    /// Service URL (e.g., "https://api.example.com").
    pub service_url: String,

    /// Relationship type or metadata classification.
    pub relationship: String,

    /// Additional metadata for verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Result of attestation verification.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// The validated attestation.
    pub attestation: Attestation,

    /// Issuer that signed it.
    pub issuer: String,

    /// When it was verified.
    pub verified_at: DateTime<Utc>,
}

// Helper module for base64 serialization
mod base64_serde {
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::BindingProof;

    #[test]
    fn test_attestation_expiry() {
        let attestation = Attestation {
            proxy_number: ProxyNumber::new("+23400123456789").unwrap(),
            phone_hash: PhoneHash::from_bytes([0u8; 32]),
            iss: "example.com".to_string(),
            exp: Some(Utc::now() - chrono::Duration::hours(1)),
            iat: Utc::now() - chrono::Duration::hours(2),
            user_pubkey: PublicKey::from_bytes([0u8; 32]),
            binding_proof: BindingProof::from_bytes([0u8; 64]),
            salt: vec![0u8; 16],
            jti: "test-jti".to_string(),
            nonce: Nonce::new("test-nonce"),
        };

        assert!(attestation.is_expired());
    }

    #[test]
    fn test_attestation_serialization() {
        let attestation = Attestation {
            proxy_number: ProxyNumber::new("+23400123456789").unwrap(),
            phone_hash: PhoneHash::from_bytes([42u8; 32]),
            iss: "example.com".to_string(),
            exp: None,
            iat: Utc::now(),
            user_pubkey: PublicKey::from_bytes([1u8; 32]),
            binding_proof: BindingProof::from_bytes([2u8; 64]),
            salt: vec![3u8; 16],
            jti: "unique-id".to_string(),
            nonce: Nonce::new("random-nonce"),
        };

        let json = serde_json::to_string(&attestation).unwrap();
        let decoded: Attestation = serde_json::from_str(&json).unwrap();

        assert_eq!(attestation.jti, decoded.jti);
        assert_eq!(attestation.proxy_number, decoded.proxy_number);
    }
}
