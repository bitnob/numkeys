# NumKeys Wallet SDK Specification

**Version**: 1.0 (Draft)  
**Contract Version**: `wallet-sdk/v1`  
**Status**: Active Working Spec  
**Scope**: Wallet SDK API contracts and canonical payload behavior

## 1. Scope

This specification defines SDK-facing interfaces and deterministic behavior for building NumKeys wallets.

This document covers:
- SDK API surfaces
- canonical payload construction
- signing and verification helpers
- challenge transport parsing contracts
- SDK error model and conformance tests

## 2. Conformance Language

The key words `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are to be interpreted as described in RFC 2119 / RFC 8174.

### 2.1 Versioning Rules

- Changes to canonicalization, signature inputs, required fields, or API contracts `MUST` increment the contract version.
- Additive optional helpers `MAY` be introduced without version changes if they do not alter required behavior.
- SDKs `SHOULD` expose supported contract versions programmatically.

## 3. SDK Design Requirements

Wallet SDK implementations:
- `MUST` keep canonicalization deterministic across platforms.
- `MUST` preserve byte-for-byte signing inputs across language bindings.
- `MUST` expose typed errors.
- `SHOULD` provide pure functions for canonical builders and validators.
- `SHOULD` isolate network discovery from cryptographic primitives.

## 4. Recommended API Surface

### 4.1 Keys

SDKs `SHOULD` expose:
- `generate_user_keypair() -> KeyPair`
- `sign_bytes(private_key, bytes) -> signature`
- `verify_bytes(public_key, bytes, signature) -> bool`

### 4.2 Attestations

SDKs `MUST` expose:
- `parse_attestation(jwt) -> ParsedAttestation`
- `verify_attestation_signature(jwt, issuer_pubkey) -> ParsedAttestation`
- `verify_binding_proof(parsed_attestation, issuer_pubkey) -> bool`

### 4.3 Discovery

SDKs `SHOULD` expose:
- `discover_issuer_key(iss) -> public_key`
- `discover_issuer_key_cached(iss, cache_policy) -> public_key`

### 4.4 Challenges

SDKs `MUST` expose:
- `parse_challenge(input) -> Challenge`
- `build_challenge_response_payload(challenge, response_nonce, timestamp) -> Payload`
- `canonicalize_challenge_response_payload(payload) -> bytes`
- `sign_challenge_response(private_key, payload) -> signature`
- `verify_challenge_response(public_key, payload, signature) -> bool`

## 5. Canonical Binding Reconstruction

SDKs `MUST` reconstruct attestation binding messages exactly as:

`numkeys-binding|{iss}|{sub}|{phone_hash}|{user_pubkey}|{nonce}|{iat}|{jti}`

Where:
- `iss` and `sub` come from signed claims.
- `phone_hash` is the full `sha256:...` string.
- `user_pubkey` is base64url (no padding).
- `nonce`, `iat`, `jti` are exact signed claim values.

SDKs `MUST` verify binding signatures against UTF-8 bytes of this canonical string.

## 6. Challenge Response Canonicalization

SDKs `MUST` sign canonical JSON bytes of the challenge response payload.

Required payload fields:
- `service_id`
- `challenge_nonce`
- `response_nonce`
- `verification_id`
- `timestamp`

SDKs `MUST` preserve deterministic JSON key order per SDK-defined canonicalizer and `MUST` use the same canonicalizer for verify operations.

## 7. Transport Parsing Contracts

### 7.1 Deep Links

SDKs `SHOULD` support a `numkeys://` verification URI format.

SDKs `MUST`:
- reject malformed payloads
- return typed parse errors
- validate required challenge fields before returning parsed results

### 7.2 QR Payloads

SDKs `SHOULD` accept QR payloads equivalent to deep-link payload content.

SDKs `MUST` treat decoded QR payloads and deep-link payloads identically at schema-validation stage.

## 8. Error Model

SDKs `MUST` define typed errors at minimum for:
- invalid_attestation_format
- invalid_attestation_signature
- invalid_binding_proof
- issuer_key_discovery_failed
- challenge_parse_failed
- challenge_validation_failed
- signing_failed
- verification_failed

SDKs `SHOULD` include machine-readable error codes and stable text-safe messages.

## 9. Minimal Type Contracts

Example SDK data contracts:

```json
{
  "ParsedAttestation": {
    "iss": "issuer.example.com",
    "sub": "+10012345678",
    "phone_hash": "sha256:...",
    "user_pubkey": "base64url...",
    "binding_proof": "sig:...",
    "nonce": "0123456789abcdef0123456789abcdef",
    "iat": 1720000000,
    "jti": "uuid"
  }
}
```

```json
{
  "ChallengeResponsePayload": {
    "service_id": "chat.example.com",
    "challenge_nonce": "challenge-nonce-001",
    "response_nonce": "response-nonce-001",
    "verification_id": "verify-123",
    "timestamp": 1738454200000
  }
}
```

## 10. Conformance Tests (SDK)

An SDK implementation is conformant if it passes tests that:
1. verify canonical binding reconstruction and signature verification.
2. verify deterministic challenge payload canonicalization.
3. reject malformed JWT and challenge inputs.
4. preserve cross-platform signature compatibility for the same payload bytes.
5. verify vector fixtures from `crates/numkeys-core/tests/fixtures/v1.json`.

## 11. Changelog

- `wallet-sdk/v1` (2026-04-05): Initial SDK contract spec with canonical binding reconstruction and challenge payload signing requirements.
