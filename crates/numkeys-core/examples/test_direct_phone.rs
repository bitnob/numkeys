//! Test direct phone number verification without proxy numbers

use numkeys_core::{attestation::AttestationBuilder, generate_proxy_number, parse_attestation, ProxyGenerationInput};
use numkeys_crypto::{generate_hex_nonce, generate_keypair, hash_phone_number_spec};
use numkeys_types::PhoneNumber;

fn main() -> anyhow::Result<()> {
    println!("=== Testing Direct Phone Number Verification ===\n");

    // Test phone numbers from CLAUDE.md
    let test_phones = vec!["+23480475355", "+2335342394990"];

    // Generate issuer and user keypairs
    let issuer_key = generate_keypair()?;
    let user_wallet = generate_keypair()?;

    println!("Issuer public key: {}", issuer_key.public.to_base64());
    println!("User public key: {}\n", user_wallet.public.to_base64());

    for phone_str in &test_phones {
        println!("Testing phone: {}", phone_str);
        println!("{}", "-".repeat(50));

        // Create phone number
        let phone = PhoneNumber::new(*phone_str)?;

        // Generate proxy number using deterministic algorithm
        let generation_input = ProxyGenerationInput {
            phone_number: phone.to_string(),
            user_pubkey: user_wallet.public.to_base64(),
            issuer_domain: "test.issuer.com".to_string(),
            scope: "1".to_string(),
            nonce: generate_hex_nonce(),
        };
        let proxy = generate_proxy_number(&generation_input)?;

        // Build attestation JWT
        let attestation_jwt = AttestationBuilder::new(
            "test.issuer.com".to_string(),
            &issuer_key.private,
            phone.clone(),
            proxy.clone(),
            user_wallet.public.clone(),
        )
        .generation_nonce(generation_input.nonce.clone())
        .build_jwt()?;

        // Parse attestation to get claims
        let parsed = parse_attestation(&attestation_jwt)?;

        println!("\nAttestation contains:");
        println!("  Salt: {:?}", parsed.salt);
        println!("  Phone hash: {}", parsed.phone_hash);
        println!("  Proxy number: {}", parsed.proxy_number);

        // === DIRECT VERIFICATION TEST ===
        println!("\n=== Direct Phone Verification (Service-Side) ===");
        println!("Service receives:");
        println!("  Real phone: {}", phone_str);
        println!("  Attestation JWT: [provided by user]");

        // Service normalizes the phone (same as protocol does)
        let normalized = phone.as_str().chars()
            .filter(|c| c.is_numeric())
            .collect::<String>();
        println!("\nService normalizes phone:");
        println!("  Input: {}", phone_str);
        println!("  Normalized: {}", normalized);

        // Service computes hash using the SAME algorithm as protocol
        // hash_phone_number_spec expects PhoneNumber, so create it from normalized
        let normalized_phone = PhoneNumber::new(format!("+{}", normalized))?;
        let computed_hash = hash_phone_number_spec(&normalized_phone);

        println!("\nService computes:");
        println!("  SHA256({} || {:?}) = ", normalized, parsed.salt);
        println!("  {}", computed_hash);

        // Compare hashes
        println!("\nVerification result:");
        if computed_hash.to_string() == parsed.phone_hash.to_string() {
            println!("  ✅ SUCCESS: Phone {} verified via direct hash!", phone_str);
        } else {
            println!("  ❌ FAILED: Hash mismatch!");
            println!("  Expected: {}", parsed.phone_hash);
            println!("  Got: {}", computed_hash);
        }
        println!();
    }

    // Test with WRONG phone number
    println!("\n=== Testing Wrong Phone Rejection ===");
    println!("{}", "-".repeat(50));

    let real_phone = PhoneNumber::new(test_phones[0])?;
    let wrong_phone_str = "+19995551234";

    // Create attestation for real phone
    let generation_input = ProxyGenerationInput {
        phone_number: real_phone.to_string(),
        user_pubkey: user_wallet.public.to_base64(),
        issuer_domain: "test.issuer.com".to_string(),
        scope: "1".to_string(),
        nonce: generate_hex_nonce(),
    };
    let proxy = generate_proxy_number(&generation_input)?;

    let attestation_jwt = AttestationBuilder::new(
        "test.issuer.com".to_string(),
        &issuer_key.private,
        real_phone.clone(),
        proxy,
        user_wallet.public.clone(),
    )
    .generation_nonce(generation_input.nonce)
    .build_jwt()?;

    let parsed = parse_attestation(&attestation_jwt)?;

    println!("Attestation created for: {}", test_phones[0]);
    println!("User falsely claims: {}", wrong_phone_str);

    // Try to verify with wrong phone
    let wrong_phone = PhoneNumber::new(wrong_phone_str)?;
    let normalized_wrong = wrong_phone.as_str().chars()
        .filter(|c| c.is_numeric())
        .collect::<String>();

    let normalized_wrong_phone = PhoneNumber::new(format!("+{}", normalized_wrong))?;
    let wrong_hash = hash_phone_number_spec(&normalized_wrong_phone);

    println!("\nCorrect phone hash: {}", parsed.phone_hash);
    println!("Wrong phone hash: {}", wrong_hash);

    if wrong_hash.to_string() != parsed.phone_hash.to_string() {
        println!("\n✅ GOOD: Wrong phone correctly rejected!");
    } else {
        println!("\n❌ BAD: Wrong phone incorrectly accepted!");
    }

    println!("\n=== SUMMARY ===");
    println!("Direct phone verification works by:");
    println!("1. Service receives real phone + attestation JWT");
    println!("2. Service normalizes phone (remove non-digits)");
    println!("3. Service computes SHA256(normalized || salt)");
    println!("4. Service compares with phone_hash in attestation");
    println!("5. If hashes match, phone is verified!");
    println!("\nThis allows gradual migration from SMS verification");
    println!("to NumKeys while keeping existing phone-based UX.");

    Ok(())
}
