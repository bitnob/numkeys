//! Core protocol logic for the NumKeys Protocol.
//!
//! This crate provides the main protocol operations:
//!
//! - Attestation creation and parsing
//! - Attestation verification with key discovery
//! - Proxy number generation
//! - Challenge-response verification
//!
//! # Security Design
//!
//! - All attestations are JWT-based with Ed25519 signatures
//! - Binding proofs prevent proxy number substitution
//! - Key discovery uses HTTPS with caching
//! - Deterministic proxy generation prevents collisions

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

pub mod attestation;
pub mod generator;
pub mod issuer_setup;
pub mod verification;

#[cfg(test)]
mod test_direct;

// Re-export main functionality
pub use attestation::{
    create_attestation, parse_attestation, parse_attestation_jwt, validate_attestation,
    AttestationBuilder,
};
pub use generator::{generate_proxy_number, ProxyGenerationInput};
pub use issuer_setup::{IssuerSetup, IssuerSetupBuilder};
pub use verification::{
    discover_issuer_key, verify_attestation, verify_attestation_with_key, IssuerKeyCache,
};
// Re-export types from numkeys-types for convenience
pub use numkeys_types::{
    Attestation, Challenge, ChallengeResponse, IssuerInfo, NumKeysError, NumKeysResult,
    PhoneNumber, ProxyNumber, VerifiedAttestation,
};
