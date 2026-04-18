//! Attestation verification logic.

use crate::attestation::claims::Claims;
use crate::attestation::jwt::decode_jwt;
use crate::attestation::parse::{parse_attestation, validate_attestation};
use crate::verification::discovery::discover_issuer_key;
use chrono::Utc;
use numkeys_crypto::BindingMessage;
use numkeys_types::{NumKeysResult, PublicKey, VerifiedAttestation};

/// Verify an attestation by discovering the issuer's public key.
///
/// # Security Considerations
/// - Verifies JWT signature with issuer's key
/// - Validates binding proof
/// - Checks issued-at sanity and other fields
pub async fn verify_attestation(jwt: &str) -> NumKeysResult<VerifiedAttestation> {
    // Parse attestation to get issuer
    let attestation = parse_attestation(jwt)?;
    validate_attestation(&attestation)?;

    // Discover the signing issuer directly from the signed issuer identifier.
    let issuer_key = discover_issuer_key(&attestation.iss).await?;

    // Verify with discovered key
    verify_attestation_with_key(jwt, &issuer_key)
}

/// Verify an attestation with a known issuer public key.
pub fn verify_attestation_with_key(
    jwt: &str,
    issuer_key: &PublicKey,
) -> NumKeysResult<VerifiedAttestation> {
    // Verify JWT signature using our implementation
    let claims: Claims = decode_jwt(jwt, issuer_key)?;

    // Convert to attestation and validate
    let attestation = claims.to_attestation()?;
    validate_attestation(&attestation)?;

    // Verify binding signature with issuer's public key
    // The binding proof is stored in claims as the full "sig:..." string.
    let phone_hash = format!("sha256:{}", attestation.phone_hash.to_hex());
    let user_pubkey = attestation.user_pubkey.to_base64();
    let binding_message = BindingMessage {
        iss: &attestation.iss,
        sub: attestation.proxy_number.as_str(),
        phone_hash: &phone_hash,
        user_pubkey: &user_pubkey,
        nonce: attestation.nonce.as_str(),
        iat: attestation.iat.timestamp(),
        jti: &attestation.jti,
    };
    let binding_valid = numkeys_crypto::verify_binding_signature(
        &binding_message,
        &claims.binding_proof, // This already contains "sig:..."
        issuer_key,
    );

    if !binding_valid {
        return Err(numkeys_types::NumKeysError::InvalidAttestation(
            "Invalid binding signature".to_string(),
        ));
    }

    Ok(VerifiedAttestation {
        attestation: attestation.clone(),
        issuer: claims.iss,
        verified_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::create::create_attestation;
    use numkeys_crypto::generate_keypair;
    use numkeys_types::{PhoneNumber, ProxyNumber};

    #[test]
    fn test_verify_with_key() {
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

        let verified = verify_attestation_with_key(&jwt, &issuer_key.public).unwrap();

        assert_eq!(verified.issuer, "issuer.com");
        assert_eq!(verified.attestation.proxy_number, proxy);
        assert_eq!(verified.attestation.user_pubkey, user_key.public);
    }

    #[test]
    fn test_verify_with_wrong_key() {
        let issuer_key = generate_keypair().unwrap();
        let wrong_key = generate_keypair().unwrap();
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

        // Should fail with wrong key
        assert!(verify_attestation_with_key(&jwt, &wrong_key.public).is_err());
    }

    #[test]
    fn test_verify_attestation_uses_signed_issuer_domain() {
        let issuer_key = generate_keypair().unwrap();
        let user_key = generate_keypair().unwrap();
        let phone = PhoneNumber::new("+1234567890").unwrap();
        let proxy = ProxyNumber::new("+23400123456789").unwrap();

        let jwt = create_attestation(
            "api.example.com",
            &issuer_key.private,
            &phone,
            &proxy,
            &user_key.public,
        )
        .unwrap();

        let attestation = parse_attestation(&jwt).unwrap();
        assert_eq!(attestation.iss, "api.example.com");
    }
}
