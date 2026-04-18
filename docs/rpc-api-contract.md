# NumKeys RPC API Contract (v1.1)

This document defines the stable HTTP/RPC route contract for `numkeys-node` in v1.1.

## Stability Statement

For v1.1, the following routes and top-level request/response shapes are treated as stable:

- `GET /health`
- `GET /status`
- `GET /.well-known/numkeys/pubkey.json`
- `POST /create-challenge`
- `POST /issue-attestation`
- `POST /verify-attestation`
- `POST /verify-challenge-response`

Compatibility policy:

- Existing routes above will not be renamed or removed in v1.1 patch releases.
- Additive fields may be introduced in JSON responses.
- Existing required fields and semantics remain unchanged.
- Breaking route or schema changes require a new protocol/API version designation.

## Route Semantics

## `GET /health`

Returns process liveness.

Example response:

```json
{ "ok": true }
```

## `GET /status`

Returns node runtime status and issuer identity material.

Required response fields:

- `ok`
- `issuer`
- `issuer_public_key`
- `node_dir`
- `private_key_path`

## `GET /.well-known/numkeys/pubkey.json`

Returns issuer public key metadata.

## `POST /create-challenge`

Creates a challenge payload for wallet signing.

Required input fields:

- `proxy_number`
- `service_id`

Optional input fields:

- `ttl_seconds`
- `callback_url`

Required response fields:

- `challenge.proxy_number`
- `challenge.service_id`
- `challenge.challenge_nonce`
- `challenge.verification_id`
- `challenge.expires_at`

## `POST /issue-attestation`

Issues an attestation JWT.

Required input fields:

- `phone_number`
- `user_pubkey`
- `scope`

Required response fields:

- `proxy_number`
- `attestation`
- `issuer`
- `issuer_public_key`

Node bootstrap behavior:

- node initializes persistent issuer key material on first startup
- subsequent startups reuse persisted key material

## `POST /verify-attestation`

Validates attestation signature and binding proof.

Required input fields:

- `attestation_jwt`

Optional input fields:

- `issuer_public_key` (skip discovery)
- `max_attestation_age_seconds`

Required response fields:

- `valid`
- `issuer`
- `sub`
- `iat`
- `jti`
- `user_pubkey`

## `POST /verify-challenge-response`

Validates challenge-response linkage, attestation validity, user signature, and replay policy.

Required input fields:

- `challenge`
- `response`

Optional input fields:

- `issuer_public_key`
- `max_attestation_age_seconds`
- `enforce_single_use`

Required response fields:

- `valid`
- `issuer`
- `sub`

## Error Envelope

All error responses use:

```json
{
  "error": "error_code",
  "error_description": "human readable description"
}
```
