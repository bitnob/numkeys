# NumKeys v1 Test Vectors

This document publishes the deterministic v1.1 protocol vectors used by the reference implementation.

The machine-readable fixture lives at [`../crates/numkeys-core/tests/fixtures/v1.json`](../crates/numkeys-core/tests/fixtures/v1.json). The generator used to produce it lives at [`../crates/numkeys-core/examples/generate_v1_test_vectors.rs`](../crates/numkeys-core/examples/generate_v1_test_vectors.rs).

## Coverage

The published fixture covers:

- one valid attestation JWT
- one expired attestation JWT
- one tampered-signature attestation JWT
- one wrong-issuer-key case
- one valid challenge-response payload and signature
- one tampered challenge-response signature

## Expected Results

Attestation verification:

- `valid_jwt` must decode and verify with `issuer_public_key`
- `valid_jwt` must fail verification with `wrong_issuer_public_key`
- `expired_jwt` must parse, and `validate_attestation` should still accept it in core validation
- `tampered_signature_jwt` must fail JWT signature verification

Challenge-response verification:

- `user_signature` must verify against `payload` using `user_public_key`
- `tampered_user_signature` must fail against the same payload
- `challenge.service_id`, `challenge.challenge_nonce`, and `challenge.verification_id` must match the signed payload fields exactly

## Vector Summary

Primary identifiers:

- issuer: `issuer.example.com`
- phone number: `+1234567890`
- scope: `1`
- proxy number: `+1002002040155`
- generation nonce: `0123456789abcdef0123456789abcdef`

Attestation timestamps:

- `iat`: `1738368000`
- `exp`: `1740787200`

Challenge timestamps:

- `payload.timestamp`: `1738454200000`
- `challenge.expires_at`: `1738454800000`

## Usage

For implementation work, use the JSON fixture directly rather than copying values from this page. The fixture is exercised by [`../crates/numkeys-core/tests/vectors_test.rs`](../crates/numkeys-core/tests/vectors_test.rs), so any drift between the published vectors and the protocol code will fail CI.
