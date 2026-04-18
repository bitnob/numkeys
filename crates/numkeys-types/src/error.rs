//! Error types for the NumKeys Protocol.

use thiserror::Error;

/// Errors that can occur in the NumKeys Protocol.
#[derive(Debug, Error)]
pub enum NumKeysError {
    /// Invalid phone number format.
    #[error("Invalid phone number format: {0}")]
    InvalidPhoneNumber(String),

    /// Invalid proxy number format.
    #[error("Invalid proxy number format: {0}")]
    InvalidProxyNumber(String),

    /// Invalid attestation format.
    #[error("Invalid attestation format: {0}")]
    InvalidAttestation(String),

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    InvalidSignature,

    /// Attestation has expired.
    #[error("Attestation expired at {0}")]
    AttestationExpired(chrono::DateTime<chrono::Utc>),

    /// Invalid public key format.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid private key format.
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid nonce.
    #[error("Invalid nonce")]
    InvalidNonce,

    /// Invalid binding proof.
    #[error("Invalid binding proof")]
    InvalidBindingProof,

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<serde_json::Error> for NumKeysError {
    fn from(err: serde_json::Error) -> Self {
        NumKeysError::SerializationError(err.to_string())
    }
}

/// Result type for NumKeys operations.
pub type NumKeysResult<T> = Result<T, NumKeysError>;
