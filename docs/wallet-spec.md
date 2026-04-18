# NumKeys Wallet Specification

**Version**: 1.0 (Draft)  
**Contract Version**: `wallet/v1`  
**Status**: Active Working Spec  
**Scope**: Wallet product requirements only

## 1. Scope

This specification defines requirements for NumKeys-compatible wallets.

This document covers:
- user key management
- attestation custody and local validation
- consent UX
- deep link and QR challenge handling
- challenge signing and response creation

This document does **not** define:
- issuer attestation issuance APIs or policies
- relying-service verification policy
- protocol claim semantics beyond what wallets must consume

Normative protocol semantics remain in:
- `docs/numkeys-protocol-specification.md`
- `docs/v1-operational-notes.md`

Wallet SDK API and canonical payload details are specified in:
- `docs/wallet-sdk-spec.md`

## 2. Conformance Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 / RFC 8174.

### 2.1 Versioning Rules

- Changes that alter required wallet behavior `MUST` produce a new contract version.
- Editorial clarifications that do not alter behavior `MAY` update the current document without changing the contract version.
- Implementations `SHOULD` advertise supported contract versions in SDK/package metadata.

## 3. Wallet Boundaries

A wallet implementation:
- `MUST` generate and control user private keys locally.
- `MUST NOT` send user private keys to issuers, services, or third parties.
- `MUST` treat the user as the final authorization decision-maker for consent actions.
- `SHOULD` expose a clear separation between wallet core (crypto/state) and UI layer.

## 4. User Key Management

### 4.1 Key Generation

- Wallets `MUST` generate user signing keys using a cryptographically secure RNG.
- Wallets `MUST` use Ed25519 for user challenge signatures.
- Wallets `SHOULD` support generating multiple user keypairs for account separation.

### 4.2 Key Storage

- Private keys `MUST` be encrypted at rest.
- Wallets `MUST` use platform secure storage when available.
- Wallets `MUST` prevent plaintext private key logging.
- Wallets `SHOULD` support passcode/biometric gates for signing operations.

### 4.3 Key Lifecycle

- Wallets `MUST` support key backup and recovery flows.
- Wallets `MUST` support key rotation.
- Wallets `SHOULD` support secure deletion of retired keys.
- Wallets `MAY` support hardware-backed key storage.

## 5. Attestation Custody

### 5.1 Stored Fields

Wallets `MUST` store:
- the full JWT attestation
- parsed core claims used by wallet workflows: `iss`, `sub`, `phone_hash`, `user_pubkey`, `binding_proof`, `nonce`, `iat`, `jti`

Wallets:
- `MAY` store `exp` if present
- `MUST NOT` require `exp` for core wallet validity decisions unless local policy explicitly opts in

### 5.2 Local Validation at Import

On attestation import, wallets `MUST`:
1. parse JWT structure (`header.payload.signature`)
2. validate claim presence required by wallet workflows
3. verify issuer signature using issuer key discovered from signed `iss`
4. verify binding proof using canonical binding input:
`numkeys-binding|iss|sub|phone_hash|user_pubkey|nonce|iat|jti`
5. enforce `iat` future-skew checks

Wallets `SHOULD` cache issuer keys with bounded TTL.

## 6. Consent UX Requirements

Before signing any challenge response, wallets `MUST` show a consent screen containing:
- requesting service identifier (`service_id` or equivalent)
- proxy number (`sub`) being used
- verification intent summary
- explicit user actions: approve or deny

Wallets:
- `MUST NOT` auto-approve challenge signatures without explicit user action
- `MUST` provide a denial path
- `SHOULD` warn on suspicious or malformed challenge metadata
- `SHOULD` display trusted issuer identity for the selected attestation

## 7. Challenge Inputs (Deep Links and QR)

Wallets `MUST` support at least one machine-readable challenge transport:
- deep link payload, or
- QR payload

Wallets `SHOULD` support both.

Wallets `MUST`:
- validate payload schema and required fields
- validate challenge freshness (`expires_at` if provided by challenge format)
- validate callback/deep-link destinations against safety rules

Wallets `SHOULD` reject non-HTTPS callback URLs except explicit development mode.

## 8. Signing Flow

When user approves, wallets `MUST`:
1. construct the canonical challenge-response payload
2. sign canonical bytes with user Ed25519 private key
3. return response package containing attestation JWT, payload, and user signature

Wallets `MUST` bind signature generation to:
- the challenge nonce
- verification/session identifier
- service identifier
- current response timestamp

Wallets `SHOULD` track used local response nonces to reduce replay risk.

## 9. Security and Privacy Requirements

Wallet implementations:
- `MUST` redact secrets and sensitive identifiers in logs
- `MUST` avoid telemetry that leaks private keys or full sensitive payloads
- `SHOULD` minimize metadata included in callbacks
- `SHOULD` support per-service proxy/account separation where available
- `MAY` include anti-phishing affordances (trusted badges, warning heuristics)

## 10. Error Handling and Recovery

Wallets `MUST` produce structured errors for:
- invalid/malformed challenge input
- attestation verification failure
- issuer-key discovery failure
- binding proof mismatch
- user denial
- signing failure

Wallets `SHOULD` provide actionable recovery messages to users without exposing sensitive internals.

## 11. Conformance Checklist (Minimum)

A conforming wallet implementation:
1. `MUST` protect private keys at rest and in logs.
2. `MUST` perform signature + binding verification on imported attestations.
3. `MUST` enforce explicit user consent before challenge signing.
4. `MUST` support deep link or QR challenge ingestion.
5. `MUST` sign canonical challenge-response payload bytes with Ed25519.
6. `MUST` enforce `iat` sanity checks and challenge freshness checks.
7. `MUST` expose clear denial/failure paths.

## 12. Changelog

- `wallet/v1` (2026-04-05): Initial split wallet product specification with normative `MUST/SHOULD/MAY` requirements.
