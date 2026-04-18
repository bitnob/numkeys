# NumKeys v1 Operational Notes

This document defines the operational expectations around the v1.1 core protocol.

## Issuer Discovery

- Issuer identity is the signed `iss` claim in the attestation.
- Verifiers fetch the issuer public key from `https://{iss}/.well-known/numkeys/pubkey.json`.
- The token does not provide alternate trust or discovery inputs.

## Key Rotation

- Issuers should publish `key_id` values in the discovery document when rotating keys.
- Rotation should use an overlap window where old and new public keys are both published.
- New attestations should be signed only after the new key is published.
- Verifiers should tolerate active overlap windows but must still verify against the key belonging to `iss`.

## Clock and Time Handling

- JWT `iat` uses Unix seconds.
- Challenge `expires_at` and response `timestamp` use Unix milliseconds.
- Verifiers should allow up to 5 minutes of clock skew for nonce- and challenge-related time checks.
- Issuers should avoid issuing attestations with future `iat` values.

## Freshness Policy

- Core verification freshness is based on `iat` plus service-specific maximum age policy.
- Core protocol verification does not require `exp` enforcement.
- Issuers may include `exp` as informational metadata for ecosystem compatibility.
- Challenge lifetime: short-lived, typically 1 to 5 minutes.

## Caching

- Public-key discovery responses may be cached by verifiers.
- Cache invalidation should be conservative around issuer key rotation.
- Verifiers should treat discovery failures as verification failures, not as permission to skip signature validation.

## Environment and Runtime Surface

- CLI private key environment variable: `NUMKEYS_PRIVATE_KEY`
- Issuer config directory environment variable: `NUMKEYS_CONFIG_DIR`
- Direct issuer config file override: `CONFIG_PATH`

## Explicit Non-Goals for v1 Operations

- no registry protocol in core v1
- no signed issuer delegation chain
- no revocation/status endpoint in core v1
- no unlinkability guarantees beyond user-managed proxy separation
