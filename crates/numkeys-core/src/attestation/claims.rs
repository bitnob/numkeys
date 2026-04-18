//! JWT claims structure for attestations.

use hex;
use numkeys_types::{BindingProof, Nonce, PhoneHash, ProxyNumber, PublicKey};
use serde::{Deserialize, Serialize};

/// JWT claims for NumKeys attestations.
///
/// This matches the NumKeys Protocol specification for JWT attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject - the proxy number (standard JWT claim).
    pub sub: String,

    /// SHA256 hash of the phone number in format "sha256:hexhash".
    pub phone_hash: String,

    /// User's Ed25519 public key (base64url encoded).
    pub user_pubkey: String,

    /// Issuer domain (standard JWT claim).
    pub iss: String,

    /// Optional expiration time (legacy compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Issued at time (standard JWT claim).
    pub iat: i64,

    /// JWT ID for uniqueness (standard JWT claim).
    pub jti: String,

    /// Cryptographic binding proof in format "sig:base64url".
    pub binding_proof: String,

    /// The proxy-generation nonce in lowercase hex.
    pub nonce: String,
}

impl Claims {
    /// Convert to numkeys-types Attestation.
    pub fn to_attestation(&self) -> numkeys_types::NumKeysResult<numkeys_types::Attestation> {
        use chrono::{TimeZone, Utc};

        // Extract hash from "sha256:hexhash" format
        let hash_hex = self.phone_hash.strip_prefix("sha256:").ok_or_else(|| {
            numkeys_types::NumKeysError::InvalidAttestation("Invalid phone hash format".into())
        })?;

        let binding_proof = self
            .binding_proof
            .strip_prefix("sig:")
            .ok_or(numkeys_types::NumKeysError::InvalidBindingProof)
            .and_then(BindingProof::from_base64)?;

        Ok(numkeys_types::Attestation {
            proxy_number: ProxyNumber::new(&self.sub)?,
            phone_hash: PhoneHash::from_bytes(
                hex::decode(hash_hex)
                    .map_err(|_| {
                        numkeys_types::NumKeysError::InvalidAttestation(
                            "Invalid phone hash hex".into(),
                        )
                    })?
                    .try_into()
                    .map_err(|_| {
                        numkeys_types::NumKeysError::InvalidAttestation(
                            "Invalid phone hash length".into(),
                        )
                    })?,
            ),
            iss: self.iss.clone(),
            exp: self
                .exp
                .map(|exp| {
                    Utc.timestamp_opt(exp, 0).single().ok_or_else(|| {
                        numkeys_types::NumKeysError::InvalidAttestation(
                            "Invalid expiry timestamp".into(),
                        )
                    })
                })
                .transpose()?,
            iat: Utc.timestamp_opt(self.iat, 0).single().ok_or_else(|| {
                numkeys_types::NumKeysError::InvalidAttestation("Invalid issued timestamp".into())
            })?,
            user_pubkey: PublicKey::from_base64(&self.user_pubkey)?,
            binding_proof,
            // Default values for fields not in JWT
            salt: vec![], // Not stored in JWT
            jti: self.jti.clone(),
            nonce: Nonce::new(self.nonce.clone()),
        })
    }

    /// Create from numkeys-types Attestation.
    pub fn from_attestation(attestation: &numkeys_types::Attestation) -> Self {
        Claims {
            sub: attestation.proxy_number.to_string(),
            phone_hash: format!("sha256:{}", attestation.phone_hash.to_hex()),
            user_pubkey: attestation.user_pubkey.to_base64(),
            iss: attestation.iss.clone(),
            exp: attestation.exp.map(|exp| exp.timestamp()),
            iat: attestation.iat.timestamp(),
            jti: attestation.jti.clone(),
            binding_proof: format!("sig:{}", attestation.binding_proof.to_base64()),
            nonce: attestation.nonce.to_string(),
        }
    }
}
