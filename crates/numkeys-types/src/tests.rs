//! Integration tests for numkeys-types.

#[cfg(test)]
mod integration_tests {
    use crate::*;
    use chrono::Utc;

    #[test]
    fn test_full_attestation_creation() {
        // Test phone numbers from CLAUDE.md
        let _phone1 = PhoneNumber::new("+23480475355").unwrap();
        let _phone2 = PhoneNumber::new("+2335342394990").unwrap();

        // Create proxy numbers
        let proxy1 = ProxyNumber::new("+23400123456789").unwrap();
        let _proxy2 = ProxyNumber::new_local("233", "5342394990").unwrap();

        // Create attestation
        let attestation = Attestation {
            proxy_number: proxy1,
            phone_hash: PhoneHash::from_bytes([0u8; 32]),
            iss: "example.com".to_string(),
            exp: Some(Utc::now() + chrono::Duration::days(30)),
            iat: Utc::now(),
            user_pubkey: PublicKey::from_bytes([1u8; 32]),
            binding_proof: BindingProof::from_bytes([2u8; 64]),
            salt: vec![3u8; 16],
            jti: uuid::Uuid::new_v4().to_string(),
            nonce: Nonce::new(uuid::Uuid::new_v4().to_string()),
        };

        assert!(!attestation.is_expired());
        assert!(attestation.time_until_expiry().is_some());
    }

    #[test]
    fn test_challenge_response_flow() {
        // Create a challenge
        let challenge = Challenge {
            proxy_number: ProxyNumber::new("+23400123456789").unwrap(),
            service_id: "signal.org".to_string(),
            challenge_nonce: Nonce::new("service-nonce-123"),
            verification_id: "verify-123".to_string(),
            expires_at: 1_720_000_300_000,
            callback_url: Some("https://signal.org/callback".to_string()),
        };

        let payload = ChallengeResponsePayload {
            service_id: challenge.service_id.clone(),
            challenge_nonce: challenge.challenge_nonce.clone(),
            response_nonce: Nonce::new("wallet-nonce-456"),
            verification_id: challenge.verification_id.clone(),
            timestamp: 1_720_000_100_000,
        };

        // Create response
        let response = ChallengeResponse {
            proxy_number: challenge.proxy_number.clone(),
            attestation_jwt: "attestation-jwt".to_string(),
            challenge_response: payload,
            user_signature: Signature::from_bytes([0u8; 64]),
        };

        assert_eq!(response.challenge_response.service_id, "signal.org");
        assert_eq!(response.challenge_response.verification_id, "verify-123");
    }

    #[test]
    fn test_issuer_info() {
        let issuer = IssuerInfo {
            public_key: PublicKey::from_bytes([42u8; 32]),
            algorithm: "Ed25519".to_string(),
            created_at: Utc::now(),
            key_id: Some("key-2024-01".to_string()),
            service_info: None,
        };

        let json = serde_json::to_string(&issuer).unwrap();
        let decoded: IssuerInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.algorithm, "Ed25519");
        assert_eq!(decoded.key_id, Some("key-2024-01".to_string()));
    }

    #[test]
    fn test_error_handling() {
        // Test various invalid inputs
        assert!(matches!(
            PhoneNumber::new("123456789"),
            Err(NumKeysError::InvalidPhoneNumber(_))
        ));

        assert!(matches!(
            ProxyNumber::new("+123456789"),
            Err(NumKeysError::InvalidProxyNumber(_))
        ));

        assert!(matches!(
            PublicKey::try_from_slice(&[0u8; 31]),
            Err(NumKeysError::InvalidPublicKey(_))
        ));
    }
}

// Property-based tests using proptest
#[cfg(test)]
mod property_tests {
    use crate::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_phone_number_roundtrip(s in r"\+[0-9]{7,15}") {
            if let Ok(phone) = PhoneNumber::new(&s) {
                let json = serde_json::to_string(&phone).unwrap();
                let decoded: PhoneNumber = serde_json::from_str(&json).unwrap();
                assert_eq!(phone, decoded);
            }
        }

        #[test]
        fn test_proxy_number_local_format(cc in "[1-9][0-9]{0,2}", digits in "[0-9]{8,10}") {
            let number = format!("+{}00{}", cc, digits);
            if let Ok(proxy) = ProxyNumber::new(&number) {
                assert_eq!(proxy.as_str(), number);
                assert!(proxy.as_str().contains("00"));
            }
        }

        #[test]
        fn test_nonce_arbitrary(s in r"[a-zA-Z0-9\-_]{16,64}") {
            let nonce = Nonce::new(&s);
            assert_eq!(nonce.as_str(), s);

            let json = serde_json::to_string(&nonce).unwrap();
            let decoded: Nonce = serde_json::from_str(&json).unwrap();
            assert_eq!(nonce, decoded);
        }
    }
}
