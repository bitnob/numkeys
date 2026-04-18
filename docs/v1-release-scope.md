# NumKeys v1 Release Scope

This document defines what is in scope for the v1.1 core release candidate and what is intentionally out of scope.

## In Scope

- issuer-signed JWT attestations
- deterministic proxy-number generation from phone number, user public key, issuer, scope, and nonce
- `iss` as the sole issuer identity and trust anchor
- issuer public-key discovery through `/.well-known/numkeys/pubkey.json`
- canonical challenge-response payloads signed by the user key
- reference issuer node
- CLI workflows for setup, issuance, inspection, and verification
- published protocol test vectors

## Out of Scope

- registries and third-party key mirrors
- signed delegation from one issuer domain to another
- account aliasing or crypto-address resolution
- revocation protocol beyond expiry
- advanced wallet portability profiles
- pairwise/service-derived proxy identifiers
- metadata registries, trust registries, or on-chain resolution

## Stability Rules

- wire-format changes require a version change
- claim-set changes require a version change
- challenge payload changes require a version change
- trust-model changes require a version change

## Release Candidate Meaning

`v1.1.0-rc1` means:

- the core semantics are frozen for review
- the code and docs are expected to match
- only bug fixes, editorial corrections, and release-blocking clarifications should land before final release
