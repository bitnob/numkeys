//! Configuration loader for issuer.toml files.

use crate::config::Config;
use numkeys_types::IssuerConfig;
use std::{env, fs, net::SocketAddr, path::PathBuf};

impl Config {
    /// Load configuration from issuer.toml file.
    pub fn load() -> anyhow::Result<Self> {
        // Check for config file path from environment
        let config_path = if let Ok(path) = env::var("CONFIG_PATH") {
            PathBuf::from(path)
        } else if let Ok(dir) = env::var("NUMKEYS_CONFIG_DIR") {
            // Support pointing to setup output directory
            PathBuf::from(dir).join("config").join("issuer.toml")
        } else {
            // Default to current directory
            PathBuf::from("issuer.toml")
        };

        // Load from issuer.toml
        if config_path.exists() {
            let contents = fs::read_to_string(&config_path)?;
            let issuer_config: IssuerConfig = toml::from_str(&contents)?;

            // Build config from IssuerConfig
            let bind_address: SocketAddr = format!("127.0.0.1:{}", issuer_config.port).parse()?;

            // Derive private key path from config directory
            let private_key_path = config_path
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("keys").join("private.key"))
                .and_then(|p| p.to_str().map(|s| s.to_string()));

            Ok(Config {
                bind_address,
                domain: issuer_config.identity.domain.clone(),
                private_key_path,
            })
        } else {
            // Fall back to environment/defaults
            Ok(Config {
                bind_address: env::var("BIND_ADDRESS")
                    .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
                    .parse()?,
                domain: env::var("ISSUER_DOMAIN").unwrap_or_else(|_| "localhost:3000".to_string()),
                private_key_path: env::var("PRIVATE_KEY_PATH").ok(),
            })
        }
    }
}
