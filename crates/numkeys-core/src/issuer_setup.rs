//! Issuer setup and initialization functionality.

use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use numkeys_crypto::signing::generate_keypair;
use numkeys_types::{IssuerConfig, IssuerIdentity, KeyPair, NumKeysError, NumKeysResult};
use std::fs;
use std::path::Path;

/// Issuer setup builder for interactive configuration.
pub struct IssuerSetupBuilder {
    name: Option<String>,
    domain: Option<String>,
    contact_email: Option<String>,
    port: u16,
}

impl Default for IssuerSetupBuilder {
    fn default() -> Self {
        Self {
            name: None,
            domain: None,
            contact_email: None,
            port: 3000,
        }
    }
}

impl IssuerSetupBuilder {
    /// Create a new issuer setup builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the issuer name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the issuer domain.
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set the contact email.
    pub fn contact_email(mut self, email: impl Into<String>) -> Self {
        self.contact_email = Some(email.into());
        self
    }

    /// Set the server port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Build and generate the issuer configuration.
    pub fn build(self) -> NumKeysResult<IssuerSetup> {
        let name = self
            .name
            .ok_or_else(|| NumKeysError::ConfigError("Issuer name is required".to_string()))?;
        let domain = self
            .domain
            .ok_or_else(|| NumKeysError::ConfigError("Issuer domain is required".to_string()))?;
        let contact_email = self
            .contact_email
            .ok_or_else(|| NumKeysError::ConfigError("Contact email is required".to_string()))?;

        // Validate issuer domain format
        if !is_valid_domain(&domain) {
            return Err(NumKeysError::ConfigError(
                "Invalid issuer domain format".to_string(),
            ));
        }

        // Validate email format
        if !is_valid_email(&contact_email) {
            return Err(NumKeysError::ConfigError(
                "Invalid email format".to_string(),
            ));
        }

        // Generate keypair
        let keypair = generate_keypair().map_err(|e| NumKeysError::CryptoError(e.to_string()))?;
        let public_key_base64url =
            general_purpose::URL_SAFE_NO_PAD.encode(keypair.public.as_bytes());

        let config = IssuerConfig {
            identity: IssuerIdentity {
                name,
                domain,
                contact_email,
                public_key_base64url,
                key_id: "default".to_string(),
                created_at: Utc::now().to_rfc3339(),
            },
            port: self.port,
            attestation_validity_days: 365,
        };

        Ok(IssuerSetup { config, keypair })
    }
}

/// Result of issuer setup containing configuration and keys.
pub struct IssuerSetup {
    /// The generated configuration.
    pub config: IssuerConfig,
    /// The generated keypair.
    pub keypair: KeyPair,
}

impl IssuerSetup {
    /// Save the configuration and keys to disk.
    pub fn save(&self, base_dir: impl AsRef<Path>) -> NumKeysResult<()> {
        let base_dir = base_dir.as_ref();

        // Create directories
        let config_dir = base_dir.join("config");
        let keys_dir = base_dir.join("keys");

        fs::create_dir_all(&config_dir).map_err(|e| {
            NumKeysError::ConfigError(format!("Failed to create config directory: {}", e))
        })?;
        fs::create_dir_all(&keys_dir).map_err(|e| {
            NumKeysError::ConfigError(format!("Failed to create keys directory: {}", e))
        })?;

        // Save configuration
        let config_path = config_dir.join("issuer.toml");
        let config_toml = toml::to_string_pretty(&self.config)
            .map_err(|e| NumKeysError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        fs::write(&config_path, config_toml)
            .map_err(|e| NumKeysError::ConfigError(format!("Failed to write config: {}", e)))?;

        // Save private key as base64 (with restricted permissions)
        let private_key_path = keys_dir.join("private.key");
        let private_key_base64 = self.keypair.private.to_base64();
        fs::write(&private_key_path, private_key_base64).map_err(|e| {
            NumKeysError::ConfigError(format!("Failed to write private key: {}", e))
        })?;

        // Set restrictive permissions on private key (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&private_key_path, permissions).map_err(|e| {
                NumKeysError::ConfigError(format!("Failed to set key permissions: {}", e))
            })?;
        }

        // Save public key as base64
        let public_key_path = keys_dir.join("public.key");
        let public_key_base64 = self.keypair.public.to_base64();
        fs::write(&public_key_path, public_key_base64)
            .map_err(|e| NumKeysError::ConfigError(format!("Failed to write public key: {}", e)))?;

        // Generate public key endpoint JSON
        let pubkey_endpoint = serde_json::json!({
            "public_key": self.config.identity.public_key_base64url,
            "algorithm": "Ed25519",
            "key_id": self.config.identity.key_id,
            "created_at": self.config.identity.created_at,
        });

        let pubkey_path = config_dir.join("public-key-endpoint.json");
        let pubkey_json = serde_json::to_string_pretty(&pubkey_endpoint).map_err(|e| {
            NumKeysError::ConfigError(format!("Failed to serialize pubkey endpoint: {}", e))
        })?;
        fs::write(&pubkey_path, pubkey_json).map_err(|e| {
            NumKeysError::ConfigError(format!("Failed to write pubkey endpoint: {}", e))
        })?;

        Ok(())
    }

    /// Get the public key discovery URL.
    pub fn public_key_url(&self) -> String {
        self.config.public_key_url()
    }
}

/// Validate domain format (basic validation).
fn is_valid_domain(domain: &str) -> bool {
    // Allow localhost for development
    if domain == "localhost" || domain.starts_with("localhost:") {
        return true;
    }

    // Allow IP addresses for development (e.g., 127.0.0.1:3000)
    if domain.parse::<std::net::IpAddr>().is_ok()
        || domain
            .split(':')
            .next()
            .map(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            .unwrap_or(false)
    {
        return true;
    }

    // Basic domain validation for production domains
    let parts: Vec<&str> = domain.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

/// Validate email format (basic validation).
fn is_valid_email(email: &str) -> bool {
    email.contains('@') && email.split('@').count() == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_builder() {
        let setup = IssuerSetupBuilder::new()
            .name("Test Issuer")
            .domain("issuer.example.com")
            .contact_email("admin@example.com")
            .build()
            .unwrap();

        assert_eq!(setup.config.identity.name, "Test Issuer");
        assert_eq!(setup.config.identity.domain, "issuer.example.com");
        assert!(!setup.config.identity.public_key_base64url.is_empty());
    }

    #[test]
    fn test_invalid_domain() {
        let result = IssuerSetupBuilder::new()
            .name("Test")
            .domain("invalid_domain")
            .contact_email("test@example.com")
            .build();

        assert!(result.is_err());
    }
}
