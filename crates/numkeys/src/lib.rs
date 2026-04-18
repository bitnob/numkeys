//! Unified SDK for building NumKeys-compatible services and applications.
//!
//! This crate re-exports the stable public surfaces of:
//!
//! - `numkeys-types`
//! - `numkeys-crypto`
//! - `numkeys-core`
//! - `numkeys-client`

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub use numkeys_client as client;
pub use numkeys_core as core;
pub use numkeys_crypto as crypto;
pub use numkeys_types as types;

// Convenience re-exports for common integration paths.
pub use numkeys_client::{
    AttestationRequest, AttestationResponse, IssuerClient, NumkeysNodeClient,
};
pub use numkeys_core::{
    create_attestation, discover_issuer_key, generate_proxy_number, parse_attestation,
    parse_attestation_jwt, validate_attestation, verify_attestation, verify_attestation_with_key,
    AttestationBuilder, IssuerKeyCache, ProxyGenerationInput,
};
pub use numkeys_crypto::{
    create_binding_signature, generate_hex_nonce, generate_keypair, hash_phone_number_spec,
    sign_challenge_response, verify_binding_signature, verify_challenge_response,
};
pub use numkeys_types::{
    Attestation, BindingProof, Challenge, ChallengeResponse, ChallengeResponsePayload, IssuerInfo,
    KeyPair, Nonce, NumKeysError, NumKeysResult, PhoneHash, PhoneNumber, PrivateKey, ProxyNumber,
    PublicKey, Signature, VerifiedAttestation,
};
