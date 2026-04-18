use chrono::{TimeZone, Utc};
use numkeys_core::attestation::claims::Claims;
use numkeys_core::attestation::jwt::encode_jwt;
use numkeys_core::{generate_proxy_number, ProxyGenerationInput};
use numkeys_crypto::{create_binding_signature, keypair_from_private, sign_challenge_response};
use numkeys_types::{
    Attestation, BindingProof, Challenge, ChallengeResponsePayload, Nonce, PhoneHash, PrivateKey,
};
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct VectorSet {
    protocol_version: &'static str,
    attestation: serde_json::Value,
    challenge_response: serde_json::Value,
}

fn main() -> anyhow::Result<()> {
    let issuer_private = PrivateKey::from_bytes([7u8; 32]);
    let user_private = PrivateKey::from_bytes([9u8; 32]);
    let wrong_issuer_private = PrivateKey::from_bytes([11u8; 32]);

    let issuer_keypair = keypair_from_private(&issuer_private)?;
    let user_keypair = keypair_from_private(&user_private)?;
    let wrong_issuer_keypair = keypair_from_private(&wrong_issuer_private)?;

    let phone_number = "+1234567890";
    let scope = "1";
    let issuer = "issuer.example.com";
    let generation_nonce = "0123456789abcdef0123456789abcdef";

    let proxy_number = generate_proxy_number(&ProxyGenerationInput {
        phone_number: phone_number.to_string(),
        user_pubkey: user_keypair.public.to_base64(),
        issuer_domain: issuer.to_string(),
        scope: scope.to_string(),
        nonce: generation_nonce.to_string(),
    })?;

    let iat = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0).unwrap();
    let jti = "11111111-1111-4111-8111-111111111111".to_string();
    let phone_hash =
        numkeys_crypto::hash_phone_number_spec(&numkeys_types::PhoneNumber::new(phone_number)?);
    let binding_proof = create_binding_signature(
        issuer,
        proxy_number.as_str(),
        &phone_hash,
        &user_keypair.public.to_base64(),
        generation_nonce,
        iat.timestamp(),
        &jti,
        &issuer_private,
    )?;
    let binding_bytes = BindingProof::from_base64(binding_proof.trim_start_matches("sig:"))?;

    let attestation = Attestation {
        proxy_number: proxy_number.clone(),
        phone_hash: PhoneHash::from_bytes(
            hex::decode(phone_hash.trim_start_matches("sha256:"))?
                .try_into()
                .expect("hash length"),
        ),
        iss: issuer.to_string(),
        exp: None,
        iat,
        user_pubkey: user_keypair.public.clone(),
        binding_proof: binding_bytes,
        salt: vec![],
        jti,
        nonce: Nonce::new(generation_nonce),
    };

    let claims = Claims::from_attestation(&attestation);
    let valid_jwt = encode_jwt(&claims, &issuer_private)?;

    let expired_attestation = Attestation {
        exp: Some(Utc.with_ymd_and_hms(2024, 2, 1, 0, 0, 0).unwrap()),
        iat: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
        jti: "22222222-2222-4222-8222-222222222222".to_string(),
        ..attestation.clone()
    };
    let expired_jwt = encode_jwt(
        &Claims::from_attestation(&expired_attestation),
        &issuer_private,
    )?;

    let tampered_signature_jwt = tamper_signature(&valid_jwt);

    let challenge = Challenge {
        proxy_number: proxy_number.clone(),
        service_id: "chat.example.com".to_string(),
        challenge_nonce: Nonce::new("challenge-nonce-001"),
        verification_id: "verify-123".to_string(),
        expires_at: 1_738_454_800_000,
        callback_url: Some("https://chat.example.com/numkeys/callback".to_string()),
    };

    let challenge_payload = ChallengeResponsePayload {
        service_id: challenge.service_id.clone(),
        challenge_nonce: challenge.challenge_nonce.clone(),
        response_nonce: Nonce::new("response-nonce-001"),
        verification_id: challenge.verification_id.clone(),
        timestamp: 1_738_454_200_000,
    };
    let challenge_signature =
        sign_challenge_response(&user_private, &challenge_payload)?.to_base64();
    let tampered_challenge_signature = tamper_signature_str(&challenge_signature);

    let vectors = VectorSet {
        protocol_version: "1.1",
        attestation: json!({
            "issuer_private_key": issuer_private.to_base64(),
            "issuer_public_key": issuer_keypair.public.to_base64(),
            "wrong_issuer_public_key": wrong_issuer_keypair.public.to_base64(),
            "user_private_key": user_private.to_base64(),
            "user_public_key": user_keypair.public.to_base64(),
            "phone_number": phone_number,
            "scope": scope,
            "generation_nonce": generation_nonce,
            "proxy_number": proxy_number.to_string(),
            "claims": claims,
            "valid_jwt": valid_jwt,
            "expired_jwt": expired_jwt,
            "tampered_signature_jwt": tampered_signature_jwt,
        }),
        challenge_response: json!({
            "challenge": challenge,
            "payload": challenge_payload,
            "user_signature": challenge_signature,
            "tampered_user_signature": tampered_challenge_signature,
        }),
    };

    println!("{}", serde_json::to_string_pretty(&vectors)?);
    Ok(())
}

fn tamper_signature(jwt: &str) -> String {
    let mut chars: Vec<char> = jwt.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

fn tamper_signature_str(signature: &str) -> String {
    let mut chars: Vec<char> = signature.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}
