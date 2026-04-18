//! Proxy number generation according to NumKeys Protocol specification.

pub mod algorithm;

use numkeys_types::{NumKeysResult, ProxyNumber};

/// Input parameters for proxy number generation according to spec.
#[derive(Debug, Clone)]
pub struct ProxyGenerationInput {
    /// The phone number in E.164 format (e.g., "+1234567890")
    pub phone_number: String,
    /// User's Ed25519 public key (base64url encoded)
    pub user_pubkey: String,
    /// Issuer's domain (e.g., "example.com")
    pub issuer_domain: String,
    /// Scope: country calling code (1-4 digits, e.g., "1", "44", "234", "1264")
    pub scope: String,
    /// 128-bit random nonce (lowercase hex, 32 chars)
    pub nonce: String,
}

/// Generate a proxy number according to the NumKeys Protocol specification.
pub fn generate_proxy_number(input: &ProxyGenerationInput) -> NumKeysResult<ProxyNumber> {
    algorithm::generate(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use numkeys_crypto::generate_hex_nonce;

    #[test]
    fn test_generate_proxy_number() {
        let input = ProxyGenerationInput {
            phone_number: "+1234567890".to_string(),
            user_pubkey: "MCowBQYDK2VwAyEAa7bsa2eI7T6w9P6KVJdLvmSGq2uPmTqz2R0RBAl6R2E".to_string(),
            issuer_domain: "example.com".to_string(),
            scope: "1".to_string(),
            nonce: generate_hex_nonce(),
        };

        let proxy = generate_proxy_number(&input).unwrap();
        assert!(proxy.as_str().starts_with("+100"));

        // Test determinism
        let proxy2 = generate_proxy_number(&input).unwrap();
        assert_eq!(proxy, proxy2);
    }
}
