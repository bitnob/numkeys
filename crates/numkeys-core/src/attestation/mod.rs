//! Attestation creation and management.

pub mod claims;
pub mod create;
pub mod jwt;
pub mod parse;

pub use claims::{Claims, KeyBinding};
pub use create::{create_attestation, AttestationBuilder};
pub use parse::{parse_attestation, parse_attestation_jwt, validate_attestation};
