//! Issuer public key discovery via .well-known.

use numkeys_types::{IssuerInfo, NumKeysError, NumKeysResult, PublicKey};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Cache for issuer public keys.
#[derive(Clone)]
pub struct IssuerKeyCache {
    cache: Arc<Mutex<HashMap<String, (PublicKey, Instant)>>>,
    ttl: Duration,
}

impl IssuerKeyCache {
    /// Create a new cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Get a key from the cache if not expired.
    pub fn get(&self, domain: &str) -> Option<PublicKey> {
        let cache = self.cache.lock().ok()?;
        let (key, inserted) = cache.get(domain)?;

        if inserted.elapsed() < self.ttl {
            Some(key.clone())
        } else {
            None
        }
    }

    /// Insert a key into the cache.
    pub fn insert(&self, domain: String, key: PublicKey) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(domain, (key, Instant::now()));
        }
    }

    /// Clear the cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

impl Default for IssuerKeyCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(3600)) // 1 hour default
    }
}

/// Discover an issuer's public key via .well-known endpoint.
///
/// # Security Considerations
/// - Always use HTTPS
/// - Validate the response format
/// - Cache results to prevent DoS
pub async fn discover_issuer_key(domain: &str) -> NumKeysResult<PublicKey> {
    // Build URL - use HTTP for localhost, HTTPS for everything else
    let url = if domain.starts_with("http://") || domain.starts_with("https://") {
        return Err(NumKeysError::InvalidAttestation(
            "Domain should not include protocol".to_string(),
        ));
    } else if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        format!("http://{}/.well-known/numkeys/pubkey.json", domain)
    } else {
        format!("https://{}/.well-known/numkeys/pubkey.json", domain)
    };

    // Make request with timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| NumKeysError::CryptoError(format!("HTTP client error: {}", e)))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| NumKeysError::CryptoError(format!("Key discovery failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(NumKeysError::CryptoError(format!(
            "Key discovery failed with status: {}",
            response.status()
        )));
    }

    let issuer_info: IssuerInfo = response
        .json()
        .await
        .map_err(|e| NumKeysError::CryptoError(format!("Invalid issuer info JSON: {}", e)))?;

    // Validate algorithm
    if issuer_info.algorithm != "Ed25519" {
        return Err(NumKeysError::CryptoError(format!(
            "Unsupported algorithm: {}",
            issuer_info.algorithm
        )));
    }

    Ok(issuer_info.public_key)
}

/// Discover an issuer's public key with caching.
pub async fn discover_issuer_key_cached(
    domain: &str,
    cache: &IssuerKeyCache,
) -> NumKeysResult<PublicKey> {
    // Check cache first
    if let Some(key) = cache.get(domain) {
        return Ok(key);
    }

    // Discover and cache
    let key = discover_issuer_key(domain).await?;
    cache.insert(domain.to_string(), key.clone());

    Ok(key)
}

/// Discover issuer information including service discovery metadata.
pub async fn discover_issuer_info(domain: &str) -> NumKeysResult<IssuerInfo> {
    // Build URL - use HTTP for localhost, HTTPS for everything else
    let url = if domain.starts_with("http://") || domain.starts_with("https://") {
        return Err(NumKeysError::InvalidAttestation(
            "Domain should not include protocol".to_string(),
        ));
    } else if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        format!("http://{}/.well-known/numkeys/pubkey.json", domain)
    } else {
        format!("https://{}/.well-known/numkeys/pubkey.json", domain)
    };

    // Make request with timeout
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| NumKeysError::CryptoError(format!("HTTP client error: {}", e)))?;

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| NumKeysError::CryptoError(format!("Key discovery failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(NumKeysError::CryptoError(format!(
            "Key discovery failed with status: {}",
            response.status()
        )));
    }

    let issuer_info: IssuerInfo = response
        .json()
        .await
        .map_err(|e| NumKeysError::CryptoError(format!("Invalid issuer info JSON: {}", e)))?;

    // Validate algorithm
    if issuer_info.algorithm != "Ed25519" {
        return Err(NumKeysError::CryptoError(format!(
            "Unsupported algorithm: {}",
            issuer_info.algorithm
        )));
    }

    Ok(issuer_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_operations() {
        let cache = IssuerKeyCache::new(Duration::from_secs(1));
        let key = PublicKey::from_bytes([42u8; 32]);

        // Insert and retrieve
        cache.insert("example.com".to_string(), key.clone());
        assert_eq!(cache.get("example.com"), Some(key.clone()));

        // Cache miss
        assert_eq!(cache.get("other.com"), None);

        // Expiry
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(cache.get("example.com"), None);
    }

    #[test]
    fn test_cache_clear() {
        let cache = IssuerKeyCache::default();
        let key = PublicKey::from_bytes([42u8; 32]);

        cache.insert("example.com".to_string(), key);
        assert!(cache.get("example.com").is_some());

        cache.clear();
        assert!(cache.get("example.com").is_none());
    }
}
