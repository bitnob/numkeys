//! Attestation verification logic.

pub mod discovery;
pub mod verify;

pub use discovery::{discover_issuer_info, discover_issuer_key, IssuerKeyCache};
pub use verify::{verify_attestation, verify_attestation_with_key};
