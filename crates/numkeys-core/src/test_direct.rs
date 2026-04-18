use crate::attestation::AttestationBuilder;
use crate::{generate_proxy_number, ProxyGenerationInput};
use numkeys_crypto::{generate_hex_nonce, generate_keypair, hash_phone_number_spec};
use numkeys_types::PhoneNumber;

#[test]
fn test_direct_phone_verification_actually_works() {
    // Generate keys
    let issuer_key = generate_keypair().unwrap();
    let user_key = generate_keypair().unwrap();

    // Test phone
    let phone_str = "+23480475355";
    let phone = PhoneNumber::new(phone_str).unwrap();

    // Generate proxy number using the actual API
    let generation_input = ProxyGenerationInput {
        phone_number: phone.to_string(),
        user_pubkey: user_key.public.to_base64(),
        issuer_domain: "test.issuer.com".to_string(),
        scope: "1".to_string(),
        nonce: generate_hex_nonce(),
    };
    let proxy = generate_proxy_number(&generation_input).unwrap();

    // Create attestation
    let attestation = AttestationBuilder::new(
        "test.issuer.com".to_string(),
        &issuer_key.private,
        phone.clone(),
        proxy.clone(),
        user_key.public.clone(),
    )
    .generation_nonce(generation_input.nonce.clone())
    .build()
    .unwrap();

    println!("\n=== ACTUAL ATTESTATION CONTENTS ===");
    println!("Phone hash in attestation: {}", attestation.phone_hash);
    println!("Salt in attestation: {:?}", attestation.salt);
    println!("Proxy number: {}", attestation.proxy_number);

    // Now let's see how the phone_hash is computed
    let normalized = phone.as_str().trim_start_matches('+');
    println!("\nNormalized phone (no +): {}", normalized);

    // Compute using the spec function
    let spec_hash = hash_phone_number_spec(&phone);
    println!("Spec hash computation: {}", spec_hash);

    // Extract just the hex part if it has "sha256:" prefix
    let spec_hex = spec_hash.strip_prefix("sha256:").unwrap_or(&spec_hash);

    // Get attestation hash as string
    let attestation_hash_str = attestation.phone_hash.to_string();

    println!("\n=== COMPARISON ===");
    println!("Attestation stores: {}", attestation_hash_str);
    println!("Spec computes: {}", spec_hex);

    // Now simulate service-side verification
    println!("\n=== SERVICE-SIDE VERIFICATION ===");
    println!("Service receives real phone: {}", phone_str);

    // Service would compute the same hash
    let service_phone = PhoneNumber::new(phone_str).unwrap();
    let service_hash = hash_phone_number_spec(&service_phone);
    let service_hex = service_hash.strip_prefix("sha256:").unwrap_or(&service_hash);

    println!("Service computes: {}", service_hex);

    if service_hex == attestation_hash_str {
        println!("\n✅ DIRECT VERIFICATION WORKS!");
        println!("Service can verify phone {} by comparing hashes", phone_str);
    } else {
        // Check if maybe there's a salt involved
        if !attestation.salt.is_empty() {
            println!("\n⚠️  Attestation uses salt: {:?}", attestation.salt);
            println!("Need to compute SHA256(normalized || salt) instead");

            // For salted version, we'd need the raw hash function
            // but let's check what's actually happening
            panic!("Salt-based hashing detected - need different computation!");
        } else {
            panic!("\n❌ HASHES DON'T MATCH!\nExpected: {}\nGot: {}",
                   attestation_hash_str, service_hex);
        }
    }

    // Test with wrong phone
    println!("\n=== TESTING WRONG PHONE ===");
    let wrong_phone = PhoneNumber::new("+19995551234").unwrap();
    let wrong_hash = hash_phone_number_spec(&wrong_phone);
    let wrong_hex = wrong_hash.strip_prefix("sha256:").unwrap_or(&wrong_hash);

    println!("Wrong phone hash: {}", wrong_hex);
    println!("Correct hash: {}", attestation_hash_str);

    assert_ne!(wrong_hex, attestation_hash_str,
               "Wrong phone should produce different hash!");

    println!("\n✅ ALL TESTS PASSED!");
    println!("NumKeys supports direct phone verification!");
}