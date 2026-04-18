//! Info command to display protocol information.

use colored::*;

/// Execute info command.
pub fn execute() -> anyhow::Result<()> {
    println!("{}", "NumKeys Protocol Information".bold().cyan());
    println!("{}", "=========================".cyan());
    println!();

    println!("{}", "Overview:".bold());
    println!("The NumKeys Protocol provides privacy-preserving proxy phone numbers that can be");
    println!("verified cryptographically without revealing your real phone number.");
    println!();

    println!("{}", "Key Concepts:".bold());
    println!(
        "• {} - Anonymized phone numbers that preserve privacy",
        "Proxy Numbers".yellow()
    );
    println!("  - Format: +<country_code>00XXXXXXXX");
    println!("  - Example: +23400123456 (Nigeria), +4400987654 (UK)");
    println!();

    println!(
        "• {} - Signed JWTs proving phone ownership",
        "Attestations".yellow()
    );
    println!("  - Issued by trusted issuer nodes");
    println!("  - Bind proxy numbers to user public keys");
    println!("  - Include cryptographic binding proofs");
    println!();

    println!(
        "• {} - Challenge-response authentication",
        "Verification".yellow()
    );
    println!("  - Services challenge users to prove key ownership");
    println!("  - Users sign verification response payloads with their private keys");
    println!("  - No phone number revealed during verification");
    println!();

    println!("{}", "Common Commands:".bold());
    println!(
        "• {} - Generate a new Ed25519 keypair",
        "numkeys keygen".green()
    );
    println!(
        "• {} - Request proxy number attestation",
        "numkeys attest".green()
    );
    println!("• {} - Verify an attestation", "numkeys verify".green());
    println!("• {} - View attestation details", "numkeys inspect".green());
    println!();

    println!("{}", "Example Workflow:".bold());
    println!(
        "1. Generate keypair: {}",
        "numkeys keygen -f json > keys.json".dimmed()
    );
    println!(
        "2. Request attestation: {}",
        "numkeys attest -i https://issuer.com -p +1234567890 -k keys.json".dimmed()
    );
    println!("3. Use proxy number in apps that support NumKeys Protocol");
    println!();

    println!("{}", "Environment Variables:".bold());
    println!(
        "• {} - Default private key for attestations",
        "NUMKEYS_PRIVATE_KEY".yellow()
    );
    println!("• {} - Enable debug logging", "RUST_LOG=debug".yellow());
    println!();

    println!("{}", "Learn More:".bold());
    println!(
        "• Documentation: {}",
        "https://github.com/numkeys-protocol/numkeys".blue()
    );
    println!(
        "• Specification: {}",
        "https://github.com/numkeys-protocol/numkeys/docs".blue()
    );
    println!();

    Ok(())
}
