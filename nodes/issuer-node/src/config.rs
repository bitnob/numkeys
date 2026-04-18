//! Configuration for the issuer node.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Issuer node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Socket address to bind to.
    pub bind_address: SocketAddr,

    /// Issuer domain (e.g., "issuer.com").
    pub domain: String,

    /// Path to issuer's private key file.
    pub private_key_path: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: ([127, 0, 0, 1], 3000).into(),
            domain: "localhost:3000".to_string(),
            private_key_path: None,
        }
    }
}
