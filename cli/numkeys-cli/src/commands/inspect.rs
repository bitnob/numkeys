//! Attestation inspection command.

use colored::*;
use numkeys_core::parse_attestation_jwt;
use std::fs;

/// Execute inspection.
pub fn execute(attestation: &str) -> anyhow::Result<()> {
    // Load attestation (from file or direct JWT)
    let jwt = if attestation.starts_with("eyJ") {
        attestation.to_string()
    } else {
        fs::read_to_string(attestation)?
    };

    // Parse attestation
    let attestation = parse_attestation_jwt(&jwt)?;

    println!("{}", "Attestation Details".cyan().bold());
    println!("{}", "===================".cyan());

    println!("\n{}", "Basic Information:".yellow());
    println!("  Issuer:         {}", attestation.iss);
    println!("  Proxy Number:   {}", attestation.proxy_number);
    println!("  Issued At:      {}", attestation.iat);
    println!(
        "  Expires:        {}",
        attestation
            .exp
            .map(|exp| exp.to_rfc3339())
            .unwrap_or_else(|| "none".to_string())
    );
    println!("  JWT ID:         {}", attestation.jti);

    println!("\n{}", "Cryptographic Data:".yellow());
    println!(
        "  Phone Hash:     sha256:{}",
        attestation.phone_hash.to_hex()
    );
    println!("  User Public Key: {}", attestation.user_pubkey.to_base64());
    println!(
        "  Binding Proof:  {}",
        format!("sig:{}", attestation.binding_proof.to_base64())
    );
    println!("  Salt:           {}", hex::encode(&attestation.salt));
    println!("  Nonce:          {}", attestation.nonce);

    println!("\n{}", "JWT Token:".yellow());
    println!("  Length:         {} bytes", jwt.len());
    println!("  First 50 chars: {}...", &jwt[..50.min(jwt.len())]);

    Ok(())
}
