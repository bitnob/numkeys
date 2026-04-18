//! Attestation request command.

use crate::{config, output};
use colored::*;
use numkeys_client::NumkeysNodeClient;
use numkeys_types::PhoneNumber;
use std::fs;

/// Execute attestation request.
pub async fn execute(
    issuer: &str,
    phone: &str,
    scope: &str,
    key_path: Option<&str>,
    output: Option<&str>,
) -> anyhow::Result<()> {
    output::info("Requesting attestation...");

    // Load private key
    let keypair = config::load_keypair(key_path)?;

    // Parse phone number
    let phone_number = PhoneNumber::new(phone)?;

    // Create client
    let client = NumkeysNodeClient::new(issuer)?;

    // Request attestation with specified scope
    let response = client
        .request_attestation(&phone_number, &keypair.public, scope)
        .await?;

    output::success("Attestation received!");
    println!("Proxy number: {}", response.proxy_number.yellow());

    // Save attestation
    if let Some(output_path) = output {
        fs::write(output_path, &response.attestation)?;
        println!("Saved to: {}", output_path.cyan());
    } else {
        println!("\nAttestation JWT:");
        println!("{}", response.attestation);
    }

    Ok(())
}
