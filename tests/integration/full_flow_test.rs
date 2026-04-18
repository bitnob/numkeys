//! Full protocol flow integration test.

use numkeys_core::{
    attestation::AttestationBuilder, create_attestation, generate_proxy_number, parse_attestation,
    verify_attestation_with_key, ProxyGenerationInput,
};
use numkeys_crypto::{
    generate_hex_nonce, generate_keypair, hash_phone_number_spec, sign_challenge_response,
    verify_challenge_response,
};
use numkeys_types::{
    Challenge, ChallengeResponse, ChallengeResponsePayload, Nonce, PhoneNumber, Signature,
};

#[tokio::test]
async fn test_full_attestation_flow() {
    // 1. Generate keys
    let issuer_key = generate_keypair().unwrap();
    let user_key = generate_keypair().unwrap();
    
    // 2. Generate proxy number
    let phone = PhoneNumber::new("+1234567890").unwrap();
    let generation_input = ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_key.public.to_base64(),
        issuer_domain: "issuer.example.com".to_string(),
        scope: "990".to_string(),
        nonce: generate_hex_nonce(),
    };
    let proxy = generate_proxy_number(&generation_input).unwrap();
    
    // 3. Create attestation
    let jwt = create_attestation(
        "issuer.example.com",
        &issuer_key.private,
        &phone,
        &proxy,
        &user_key.public,
    ).unwrap();
    
    println!("Created JWT: {}", &jwt[..50]);
    
    // 4. Parse attestation (without verification)
    let parsed = parse_attestation(&jwt).unwrap();
    assert_eq!(parsed.iss, "issuer.example.com");
    assert_eq!(parsed.proxy_number, proxy);
    assert_eq!(parsed.user_pubkey, user_key.public);
    
    // 5. Verify attestation with key
    let verified = verify_attestation_with_key(&jwt, &issuer_key.public).unwrap();
    assert_eq!(verified.issuer, "issuer.example.com");
    assert_eq!(verified.attestation.proxy_number, proxy);
    
    // 6. Check phone number hash
    let computed_hash = hash_phone_number_spec(&phone);
    let attestation_hash = format!("sha256:{}", parsed.phone_hash.to_hex());
    assert_eq!(computed_hash, attestation_hash);
    
    // 7. Verify binding proof would be done internally during attestation creation
    // The binding proof is already validated when parsing the attestation
}

#[test]
fn test_proxy_number_generation() {
    use numkeys_core::{generate_proxy_number, ProxyGenerationInput};
    use numkeys_crypto::generate_hex_nonce;
    
    let user_pubkey = "MCowBQYDK2VwAyEAa7bsa2eI7T6w9P6KVJdLvmSGq2uPmTqz2R0RBAl6R2E".to_string();
    let phone = "+1234567890".to_string();
    let nonce = generate_hex_nonce();
    
    // Test scoped proxy number
    let input1 = ProxyGenerationInput {
        phone_number: phone.clone(),
        user_pubkey: user_pubkey.clone(),
        issuer_domain: "issuer.com".to_string(),
        scope: "990".to_string(),
        nonce: nonce.clone(),
    };
    let global1 = generate_proxy_number(&input1).unwrap();
    let global2 = generate_proxy_number(&input1).unwrap();
    assert_eq!(global1, global2); // Should be deterministic
    assert!(global1.is_global());
    
    // Test local proxy number
    let input2 = ProxyGenerationInput {
        phone_number: phone.clone(),
        user_pubkey: user_pubkey.clone(),
        issuer_domain: "issuer.com".to_string(),
        scope: "1".to_string(),
        nonce: nonce.clone(),
    };
    let local1 = generate_proxy_number(&input2).unwrap();
    let local2 = generate_proxy_number(&input2).unwrap();
    assert_eq!(local1, local2); // Should be deterministic
    assert!(!local1.is_global());
    
    // Different nonces should give different numbers
    let mut input3 = input1.clone();
    input3.nonce = generate_hex_nonce();
    let global3 = generate_proxy_number(&input3).unwrap();
    assert_ne!(global1, global3);
}

#[test]
fn test_attestation_jwt_preserves_generation_nonce_and_binding_proof() {
    let issuer_key = generate_keypair().unwrap();
    let user_key = generate_keypair().unwrap();
    let phone = PhoneNumber::new("+1234567890").unwrap();
    let generation_nonce = "a1b2c3d4e5f67890a1b2c3d4e5f67890".to_string();

    let generation_input = ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_key.public.to_base64(),
        issuer_domain: "issuer.example.com".to_string(),
        scope: "990".to_string(),
        nonce: generation_nonce.clone(),
    };
    let proxy = generate_proxy_number(&generation_input).unwrap();

    let built = AttestationBuilder::new(
        "issuer.example.com".to_string(),
        &issuer_key.private,
        phone,
        proxy.clone(),
        user_key.public.clone(),
    )
    .generation_nonce(generation_nonce.clone())
    .build()
    .unwrap();

    let jwt = AttestationBuilder::new(
        "issuer.example.com".to_string(),
        &issuer_key.private,
        PhoneNumber::new("+1234567890").unwrap(),
        proxy.clone(),
        user_key.public.clone(),
    )
    .generation_nonce(generation_nonce.clone())
    .build_jwt()
    .unwrap();

    let parsed = parse_attestation(&jwt).unwrap();

    assert_eq!(parsed.nonce.as_str(), generation_nonce);
    assert_eq!(parsed.binding_proof, built.binding_proof);
    assert_eq!(parsed.proxy_number, proxy);
}

#[test]
fn test_end_to_end_verification_flow() {
    let issuer_key = generate_keypair().unwrap();
    let user_key = generate_keypair().unwrap();
    let phone = PhoneNumber::new("+1234567890").unwrap();
    let generation_input = ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_key.public.to_base64(),
        issuer_domain: "issuer.example.com".to_string(),
        scope: "1".to_string(),
        nonce: generate_hex_nonce(),
    };
    let proxy = generate_proxy_number(&generation_input).unwrap();

    let attestation_jwt = AttestationBuilder::new(
        "issuer.example.com".to_string(),
        &issuer_key.private,
        phone,
        proxy.clone(),
        user_key.public.clone(),
    )
    .generation_nonce(generation_input.nonce)
    .build_jwt()
    .unwrap();

    let challenge = Challenge {
        proxy_number: proxy.clone(),
        service_id: "chat.example.com".to_string(),
        challenge_nonce: Nonce::new("service-challenge-001"),
        verification_id: "verify-001".to_string(),
        expires_at: 1_900_000_000_000,
        callback_url: Some("https://chat.example.com/numkeys/callback".to_string()),
    };

    let payload = ChallengeResponsePayload {
        service_id: challenge.service_id.clone(),
        challenge_nonce: challenge.challenge_nonce.clone(),
        response_nonce: Nonce::new("wallet-response-001"),
        verification_id: challenge.verification_id.clone(),
        timestamp: 1_899_999_950_000,
    };
    let signature = sign_challenge_response(&user_key.private, &payload).unwrap();

    let response = ChallengeResponse {
        proxy_number: proxy.clone(),
        attestation_jwt: attestation_jwt.clone(),
        challenge_response: payload.clone(),
        user_signature: signature.clone(),
    };

    let verified = verify_attestation_with_key(&response.attestation_jwt, &issuer_key.public).unwrap();
    assert_eq!(verified.attestation.proxy_number, proxy);
    assert_eq!(verified.attestation.user_pubkey, user_key.public);
    assert!(verify_challenge_response(
        &verified.attestation.user_pubkey,
        &response.challenge_response,
        &response.user_signature,
    ));
    assert_eq!(response.challenge_response.service_id, challenge.service_id);
    assert_eq!(
        response.challenge_response.challenge_nonce,
        challenge.challenge_nonce
    );
    assert_eq!(
        response.challenge_response.verification_id,
        challenge.verification_id
    );
}

#[test]
fn test_end_to_end_verification_rejects_tampered_challenge_response() {
    let issuer_key = generate_keypair().unwrap();
    let user_key = generate_keypair().unwrap();
    let phone = PhoneNumber::new("+1234567890").unwrap();
    let proxy = generate_proxy_number(&ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_key.public.to_base64(),
        issuer_domain: "issuer.example.com".to_string(),
        scope: "1".to_string(),
        nonce: generate_hex_nonce(),
    })
    .unwrap();

    let attestation_jwt = create_attestation(
        "issuer.example.com",
        &issuer_key.private,
        &phone,
        &proxy,
        &user_key.public,
    )
    .unwrap();
    let verified = verify_attestation_with_key(&attestation_jwt, &issuer_key.public).unwrap();

    let payload = ChallengeResponsePayload {
        service_id: "chat.example.com".to_string(),
        challenge_nonce: Nonce::new("service-challenge-001"),
        response_nonce: Nonce::new("wallet-response-001"),
        verification_id: "verify-001".to_string(),
        timestamp: 1_899_999_950_000,
    };
    let signature = sign_challenge_response(&user_key.private, &payload).unwrap();

    let tampered_payload = ChallengeResponsePayload {
        response_nonce: Nonce::new("wallet-response-999"),
        ..payload
    };
    assert!(!verify_challenge_response(
        &verified.attestation.user_pubkey,
        &tampered_payload,
        &signature,
    ));

    let bogus_signature = Signature::from_bytes([0u8; 64]);
    assert!(!verify_challenge_response(
        &verified.attestation.user_pubkey,
        &tampered_payload,
        &bogus_signature,
    ));
}
