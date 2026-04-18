//! Attestation endpoint.

use crate::state::AppState;
use axum::{extract::State, Json};
use numkeys_core::{attestation::AttestationBuilder, generate_proxy_number, ProxyGenerationInput};
use numkeys_crypto::generate_hex_nonce;
use numkeys_types::{PhoneNumber, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Request for attestation.
#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    /// Phone number (already verified by issuer's external process).
    pub phone_number: String,
    /// User's Ed25519 public key (base64url encoded).
    pub user_pubkey: String,
    /// Scope - 1-4 digit calling code (e.g., "1", "44", "234").
    pub scope: String,
}

/// Response containing attestation.
#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    /// The proxy number assigned.
    pub proxy_number: String,
    /// JWT attestation.
    pub attestation: String,
}

/// Handle attestation request.
///
/// This endpoint assumes the issuer has already verified the phone number
/// through their own mechanism (SMS, carrier API, etc).
pub async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, (axum::http::StatusCode, Json<serde_json::Value>)> {
    // Parse phone number
    let phone_number = PhoneNumber::new(&req.phone_number).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_phone_number",
                "error_description": format!("Invalid phone number: {}", e)
            })),
        )
    })?;

    // Parse public key
    let user_pubkey = PublicKey::from_base64(&req.user_pubkey).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_public_key",
                "error_description": format!("Invalid public key: {}", e)
            })),
        )
    })?;

    // Generate proxy number using new algorithm
    let nonce = generate_hex_nonce();
    let generation_input = ProxyGenerationInput {
        phone_number: req.phone_number.clone(),
        user_pubkey: req.user_pubkey.clone(),
        issuer_domain: state.config.domain.clone(),
        scope: req.scope.clone(),
        nonce,
    };

    let proxy_number = generate_proxy_number(&generation_input).map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "proxy_generation_failed",
                "error_description": format!("Failed to generate proxy number: {}", e)
            })),
        )
    })?;

    // Create attestation using builder
    let builder = AttestationBuilder::new(
        state.config.domain.clone(),
        &state.issuer_key.private,
        phone_number.clone(),
        proxy_number.clone(),
        user_pubkey.clone(),
    )
    .generation_nonce(generation_input.nonce.clone());

    let attestation = builder.build_jwt().map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "attestation_failed",
                "error_description": format!("Failed to create attestation: {}", e)
            })),
        )
    })?;

    tracing::info!(
        "Issued attestation for {} -> {}",
        phone_number,
        proxy_number
    );

    Ok(Json(AttestationResponse {
        proxy_number: proxy_number.to_string(),
        attestation,
    }))
}
