//! Ed25519 signing operations.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use numkeys_types::{
    ChallengeResponsePayload, KeyPair, NumKeysResult, PrivateKey, PublicKey, Signature,
};
use rand::{rngs::OsRng, RngCore};

/// Generate a new Ed25519 key pair.
///
/// # Security Considerations
/// - Uses OS random number generator
/// - Keys are immediately wrapped in our types for safety
pub fn generate_keypair() -> NumKeysResult<KeyPair> {
    // Generate 32 random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);

    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    let private_key = PrivateKey::from_bytes(signing_key.to_bytes());
    let public_key = PublicKey::from_bytes(verifying_key.to_bytes());

    Ok(KeyPair::new(public_key, private_key))
}

/// Derive a key pair from a private key.
///
/// # Security Considerations
/// - Derives the public key from the private key
/// - Used for loading existing keys
pub fn keypair_from_private(private_key: &PrivateKey) -> NumKeysResult<KeyPair> {
    let signing_key = SigningKey::from_bytes(private_key.as_bytes());
    let verifying_key = signing_key.verifying_key();

    let public_key = PublicKey::from_bytes(verifying_key.to_bytes());

    Ok(KeyPair::new(public_key, private_key.to_owned()))
}

/// Sign a message with a private key.
///
/// # Security Considerations
/// - Uses deterministic signature scheme (Ed25519)
/// - Message is signed as-is without additional encoding
pub fn sign_message(private_key: &PrivateKey, message: &[u8]) -> NumKeysResult<Signature> {
    let signing_key = SigningKey::from_bytes(private_key.as_bytes());
    let signature = signing_key.sign(message);

    Ok(Signature::from_bytes(signature.to_bytes()))
}

/// Verify a signature against a message and public key.
///
/// # Security Considerations
/// - Uses constant-time verification
/// - Returns false for any verification failure
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key.as_bytes()) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let sig = match ed25519_dalek::Signature::try_from(signature.as_bytes().as_slice()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verifying_key.verify(message, &sig).is_ok()
}

fn canonicalize_challenge_response(
    challenge_response: &ChallengeResponsePayload,
) -> NumKeysResult<Vec<u8>> {
    serde_json::to_vec(challenge_response)
        .map_err(|e| numkeys_types::NumKeysError::SerializationError(e.to_string()))
}

/// Create a signature over the canonical JSON challenge response payload.
pub fn sign_challenge_response(
    private_key: &PrivateKey,
    challenge_response: &ChallengeResponsePayload,
) -> NumKeysResult<Signature> {
    let message = canonicalize_challenge_response(challenge_response)?;
    sign_message(private_key, &message)
}

/// Verify a challenge response signature.
pub fn verify_challenge_response(
    public_key: &PublicKey,
    challenge_response: &ChallengeResponsePayload,
    signature: &Signature,
) -> bool {
    let message = match canonicalize_challenge_response(challenge_response) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    verify_signature(public_key, &message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = generate_keypair().unwrap();

        // Keys should be different each time
        let keypair2 = generate_keypair().unwrap();
        assert_ne!(keypair.public, keypair2.public);
        assert_ne!(keypair.private.as_bytes(), keypair2.private.as_bytes());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let keypair = generate_keypair().unwrap();
        let message = b"test message";

        let signature = sign_message(&keypair.private, message).unwrap();
        assert!(verify_signature(&keypair.public, message, &signature));

        // Should fail with wrong message
        assert!(!verify_signature(
            &keypair.public,
            b"wrong message",
            &signature
        ));

        // Should fail with wrong key
        let keypair2 = generate_keypair().unwrap();
        assert!(!verify_signature(&keypair2.public, message, &signature));
    }

    #[test]
    fn test_challenge_response_signing() {
        let keypair = generate_keypair().unwrap();
        let payload = ChallengeResponsePayload {
            service_id: "signal.org".to_string(),
            challenge_nonce: numkeys_types::Nonce::new("nonce123"),
            response_nonce: numkeys_types::Nonce::new("wallet456"),
            verification_id: "verify-123".to_string(),
            timestamp: 1_704_067_200_000,
        };

        let signature = sign_challenge_response(&keypair.private, &payload).unwrap();

        assert!(verify_challenge_response(
            &keypair.public,
            &payload,
            &signature
        ));

        // Should fail with wrong parameters
        let mut wrong_payload = payload.clone();
        wrong_payload.response_nonce = numkeys_types::Nonce::new("wrong-nonce");
        assert!(!verify_challenge_response(
            &keypair.public,
            &wrong_payload,
            &signature,
        ));
    }

    #[test]
    fn test_invalid_signatures() {
        let keypair = generate_keypair().unwrap();
        let message = b"test";

        // Invalid signature bytes
        let invalid_sig = Signature::from_bytes([0u8; 64]);
        assert!(!verify_signature(&keypair.public, message, &invalid_sig));

        // Invalid public key should return false, not panic
        let invalid_pubkey = PublicKey::from_bytes([0u8; 32]);
        let valid_sig = sign_message(&keypair.private, message).unwrap();
        assert!(!verify_signature(&invalid_pubkey, message, &valid_sig));
    }
}
