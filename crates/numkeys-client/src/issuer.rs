//! Client for interacting with NumKeys nodes.

use crate::error::{ClientError, ClientResult};
use numkeys_types::{PhoneNumber, PublicKey};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Request for attestation.
#[derive(Debug, Serialize)]
pub struct AttestationRequest {
    /// Phone number (already verified by issuer).
    pub phone_number: String,
    /// User's public key.
    pub user_pubkey: String,
    /// Scope for proxy number generation (e.g., "1" for US, "44" for UK, "234" for Nigeria).
    pub scope: String,
}

/// Response containing attestation.
#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    /// JWT attestation.
    pub attestation: String,
    /// The proxy number assigned.
    pub proxy_number: String,
}

/// Client for NumKeys node operations.
#[derive(Clone)]
pub struct NumkeysNodeClient {
    client: Client,
    base_url: Url,
}

impl NumkeysNodeClient {
    /// Create a new NumKeys node client.
    pub fn new(base_url: &str) -> ClientResult<Self> {
        let base_url = Url::parse(base_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;

        // Ensure HTTPS for security
        if base_url.scheme() != "https"
            && !base_url.host_str().unwrap_or("").starts_with("localhost")
        {
            return Err(ClientError::InvalidUrl(
                    "Node URL must use HTTPS".to_string(),
                ));
        }

        let client = build_http_client()?;

        Ok(Self { client, base_url })
    }

    /// Create a client for testing (allows HTTP).
    #[cfg(any(test, debug_assertions))]
    pub fn new_insecure(base_url: &str) -> ClientResult<Self> {
        let base_url = Url::parse(base_url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;

        let client = build_http_client()?;

        Ok(Self { client, base_url })
    }

    /// Request attestation for a verified phone number.
    ///
    /// Note: scope is now required by the protocol. Use the phone's country code
    /// or specify a different scope for the proxy number.
    pub async fn request_attestation(
        &self,
        phone_number: &PhoneNumber,
        user_pubkey: &PublicKey,
        scope: &str,
    ) -> ClientResult<AttestationResponse> {
        let url = self
            .base_url
            .join("issue-attestation")
            .map_err(|e| ClientError::InvalidUrl(e.to_string()))?;

        let request = AttestationRequest {
            phone_number: phone_number.to_string(),
            user_pubkey: user_pubkey.to_base64(),
            scope: scope.to_string(),
        };

        let response = self.client.post(url).json(&request).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ClientError::ServerError { status, message });
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::InvalidResponse(e.to_string()))
    }
}

/// Backward-compatible alias; prefer `NumkeysNodeClient`.
pub type IssuerClient = NumkeysNodeClient;

fn build_http_client() -> ClientResult<Client> {
    Client::builder()
        .timeout(Duration::from_secs(30))
        // Avoid platform-specific proxy discovery paths during construction.
        .no_proxy()
        .build()
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        // HTTPS required
        assert!(NumkeysNodeClient::new("https://issuer.com").is_ok());
        assert!(NumkeysNodeClient::new("http://issuer.com").is_err());

        // Localhost allowed
        assert!(NumkeysNodeClient::new("http://localhost:8080").is_ok());

        // Invalid URL
        assert!(NumkeysNodeClient::new("not a url").is_err());
    }
}
