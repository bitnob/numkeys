//! Public key discovery endpoint.

use crate::state::AppState;
use axum::{extract::State, Json};
use chrono::Utc;
use numkeys_types::IssuerInfo;

/// Handle .well-known public key request.
pub async fn pubkey(State(state): State<AppState>) -> Json<IssuerInfo> {
    Json(IssuerInfo {
        public_key: state.issuer_key.public.clone(),
        algorithm: "Ed25519".to_string(),
        created_at: Utc::now(), // In production, this would be the key creation time
        key_id: Some("default".to_string()),
        service_info: None,
    })
}
