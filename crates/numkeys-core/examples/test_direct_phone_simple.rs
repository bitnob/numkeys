//! Simple test to verify direct phone number verification works.

use numkeys_crypto::hash_phone_number_spec;
use numkeys_types::PhoneNumber;

fn main() {
    println!("=== Direct Phone Number Verification Test ===\n");

    let phone_number = "+23480475355";
    let phone = PhoneNumber::new(phone_number).expect("valid phone number");

    println!("Original phone: {}", phone_number);
    println!("Normalized: {}", phone.as_str().trim_start_matches('+'));

    let phone_hash = hash_phone_number_spec(&phone);

    println!("\nPhone hash in attestation: {}", phone_hash);

    // Step 3: Service-side verification
    println!("\n--- Service-Side Verification ---");
    println!("Service receives:");
    println!("  Phone: {}", phone_number);
    println!("  Hash from attestation: {}", phone_hash);

    let service_phone = PhoneNumber::new(phone_number).expect("valid phone number");
    let service_hash = hash_phone_number_spec(&service_phone);

    println!("\nService computes:");
    println!("  Normalized: {}", service_phone.as_str().trim_start_matches('+'));
    println!("  Hash: {}", service_hash);

    // Step 4: Compare
    if service_hash == phone_hash {
        println!("\n✅ SUCCESS: Direct phone verification works!");
        println!("   The hashes match, proving phone ownership.");
    } else {
        println!("\n❌ FAILED: Hashes don't match");
    }

    // Test with wrong phone
    println!("\n--- Testing Wrong Phone ---");
    let wrong_phone = "+19995551234";
    let wrong_phone = PhoneNumber::new(wrong_phone).expect("valid phone number");
    let wrong_hash = hash_phone_number_spec(&wrong_phone);

    println!("Wrong phone: {}", wrong_phone.as_str());
    println!("Wrong hash: {}", wrong_hash);
    println!("Correct hash: {}", phone_hash);

    if wrong_hash != phone_hash {
        println!("\n✅ GOOD: Wrong phone correctly rejected!");
    } else {
        println!("\n❌ BAD: Wrong phone incorrectly accepted!");
    }

    println!("\n=== CONCLUSION ===");
    println!("Direct phone verification is supported by NumKeys:");
    println!("1. Attestation contains phone_hash = SHA256(normalized_phone)");
    println!("2. Service can verify by computing the same hash");
    println!("3. This allows existing services to use real phone numbers");
    println!("4. Services can gradually migrate to proxy numbers later");
}
