//! HTTP client library for the NumKeys Protocol.
//!
//! This crate provides typed HTTP clients for interacting with
//! NumKeys Protocol nodes:
//!
//! - `NumkeysNodeClient`: For requesting attestations
//! - Helper types for requests and responses
//!
//! # Security
//!
//! - Enforces HTTPS for production use
//! - Includes timeout protection
//! - Validates response formats

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod error;
pub mod issuer;

pub use error::{ClientError, ClientResult};
pub use issuer::{AttestationRequest, AttestationResponse, IssuerClient, NumkeysNodeClient};
