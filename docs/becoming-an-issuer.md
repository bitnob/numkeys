# Becoming an Issuer

This checklist defines what a company needs to operate as a NumKeys issuer.

## 1. Identity and Domain

- Control the issuer domain used as signed `iss`.
- Serve public key discovery at `https://{iss}/.well-known/numkeys/pubkey.json`.
- Ensure `iss` exactly matches the domain where discovery is served.

## 2. Key Management

- Generate an Ed25519 issuer signing key.
- Store private keys in secure infrastructure (KMS/HSM or equivalent).
- Define key rotation and incident response procedures.
- Publish new public keys before signing with new private keys.

## 3. Issuance Policy

- Verify user control of the submitted identifier (`sub`) before issuing.
- Enforce abuse controls (rate limits, anti-automation, audit logging).
- Reject malformed public keys and malformed request inputs.

## 4. Attestation Construction

- Build JWT claims with protocol-required binding fields:
`iss`, `sub`, `phone_hash`, `user_pubkey`, `nonce`, `iat`, `jti`, `binding_proof`.
- Create `binding_proof` using the canonical string:
`numkeys-binding|iss|sub|phone_hash|user_pubkey|nonce|iat|jti`
- Sign JWTs with EdDSA (Ed25519).
- Do not rely on `exp` for core freshness; verifiers use `iat` policy.

## 5. Service Endpoints

- Expose an attestation issuance endpoint (for example `POST /attest`).
- Expose `GET /.well-known/numkeys/pubkey.json`.
- Run over HTTPS in production.

## 6. Conformance Before Launch

- Verify issuance and verification against published protocol vectors.
- Confirm canonical binding signature checks pass with independent verifiers.
- Confirm replay controls and nonce handling are implemented for your environment.

## 7. Go-Live Operations

- Monitor issuance success/failure rates and verification errors.
- Track key-discovery uptime and cache behavior.
- Maintain operational runbooks for key rotation and issuer outage recovery.

## Notes

- The protocol is defined by `numkeys-core`, specs, and conformance vectors.
- `issuer-node` in this repository is a reference implementation, not a protocol requirement.
