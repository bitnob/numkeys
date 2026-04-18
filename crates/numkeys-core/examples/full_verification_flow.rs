//! Full end-to-end verification flow demonstration.

use numkeys_core::{
    attestation::AttestationBuilder, generate_proxy_number, parse_attestation,
    verify_attestation_with_key, ProxyGenerationInput,
};
use numkeys_crypto::{
    generate_hex_nonce, generate_keypair, sign_challenge_response, verify_challenge_response,
};
use numkeys_types::{Challenge, ChallengeResponse, ChallengeResponsePayload, Nonce, PhoneNumber};

fn main() -> anyhow::Result<()> {
    println!("=== NumKeys End-to-End Verification Demo ===\n");

    println!("1. Generate issuer and wallet keys");
    let issuer_key = generate_keypair()?;
    let user_wallet = generate_keypair()?;
    println!("   Issuer pubkey: {}", issuer_key.public.to_base64());
    println!("   Wallet pubkey: {}\n", user_wallet.public.to_base64());

    println!("2. Issuer verifies a real phone number and generates a proxy");
    let phone = PhoneNumber::new("+1234567890")?;
    let generation_input = ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_wallet.public.to_base64(),
        issuer_domain: "issuer.example.com".to_string(),
        scope: "1".to_string(),
        nonce: generate_hex_nonce(),
    };
    let proxy = generate_proxy_number(&generation_input)?;
    println!("   Real phone: {}", phone);
    println!("   Proxy:      {}\n", proxy);

    println!("3. Issuer creates the attestation JWT");
    let attestation_jwt = AttestationBuilder::new(
        "issuer.example.com".to_string(),
        &issuer_key.private,
        phone.clone(),
        proxy.clone(),
        user_wallet.public.clone(),
    )
    .generation_nonce(generation_input.nonce.clone())
    .build_jwt()?;
    println!(
        "   Attestation JWT: {}...\n",
        &attestation_jwt[..100.min(attestation_jwt.len())]
    );

    println!("4. Service creates a challenge for the wallet");
    let challenge = Challenge {
        proxy_number: proxy.clone(),
        service_id: "chat.example.com".to_string(),
        challenge_nonce: Nonce::new("service-challenge-001"),
        verification_id: "verify-001".to_string(),
        expires_at: 1_900_000_000_000,
        callback_url: Some("https://chat.example.com/numkeys/callback".to_string()),
    };
    println!("   Service ID:       {}", challenge.service_id);
    println!("   Verification ID:  {}", challenge.verification_id);
    println!("   Challenge nonce:  {}\n", challenge.challenge_nonce);

    println!("5. Wallet approves and signs the canonical response payload");
    let payload = ChallengeResponsePayload {
        service_id: challenge.service_id.clone(),
        challenge_nonce: challenge.challenge_nonce.clone(),
        response_nonce: Nonce::new("wallet-response-001"),
        verification_id: challenge.verification_id.clone(),
        timestamp: 1_899_999_950_000,
    };
    let user_signature = sign_challenge_response(&user_wallet.private, &payload)?;
    let response = ChallengeResponse {
        proxy_number: proxy.clone(),
        attestation_jwt: attestation_jwt.clone(),
        challenge_response: payload.clone(),
        user_signature: user_signature.clone(),
    };
    println!(
        "   Response nonce:   {}",
        response.challenge_response.response_nonce
    );
    println!(
        "   User signature:   {}\n",
        response.user_signature.to_base64()
    );

    println!("6. Verifier checks the issuer attestation");
    let verified_attestation =
        verify_attestation_with_key(&response.attestation_jwt, &issuer_key.public)?;
    println!(
        "   ✓ Attestation valid for issuer {}",
        verified_attestation.issuer
    );
    println!(
        "   ✓ Proxy {} is bound to wallet {}\n",
        verified_attestation.attestation.proxy_number, verified_attestation.attestation.user_pubkey
    );

    println!("7. Verifier checks the wallet signature over the challenge response");
    let matches_original_challenge = response.challenge_response.service_id == challenge.service_id
        && response.challenge_response.challenge_nonce == challenge.challenge_nonce
        && response.challenge_response.verification_id == challenge.verification_id;
    let user_signature_valid = verify_challenge_response(
        &verified_attestation.attestation.user_pubkey,
        &response.challenge_response,
        &response.user_signature,
    );

    if matches_original_challenge && user_signature_valid {
        println!("   ✓ Wallet signature valid");
        println!("   ✓ Response matches the original challenge");
    } else {
        println!("   ✗ Verification failed");
    }

    println!("\n8. Optional verifier-side parsing");
    let parsed = parse_attestation(&response.attestation_jwt)?;
    println!("   Parsed issuer: {}", parsed.iss);
    println!(
        "   Parsed phone hash: sha256:{}",
        parsed.phone_hash.to_hex()
    );

    println!("\n=== End-to-End Demo Complete ===");
    Ok(())
}
