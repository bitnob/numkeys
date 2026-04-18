# NumKeys Node (HTTP/RPC)

`numkeys-node` is a language-agnostic issue-and-verify node for NumKeys Protocol.

It exposes HTTP endpoints so any backend stack can integrate without an SDK.
It starts in full-capability mode by default (issue + verify).

## Run

```bash
cargo run --bin numkeys-node
```

Environment variables:

- `BIND_ADDRESS` (default: `127.0.0.1:3200`)
- `NUMKEYS_NODE_DIR` (default: `~/.numkeys/node`)
- `ISSUER_DOMAIN` (default: `localhost:<port>`)
- `PRIVATE_KEY_PATH` (default: `<NUMKEYS_NODE_DIR>/keys/private.key`)

## Endpoints

- `GET /health`
- `GET /status`
- `GET /.well-known/numkeys/pubkey.json`
- `POST /create-challenge`
- `POST /issue-attestation`
- `POST /verify-attestation`
- `POST /verify-challenge-response`

## Bootstrap behavior

On first startup, the node will:

1. resolve a node directory
2. load existing issuer private key if present
3. otherwise generate and persist a new issuer private key
4. derive and expose issuer public key via `/.well-known/numkeys/pubkey.json`

This makes issuance and verification available by default.

## Example: Create Challenge

Request:

```json
{
  "proxy_number": "+1002002040155",
  "service_id": "chat.example.com",
  "ttl_seconds": 300
}
```

Response:

```json
{
  "challenge": {
    "proxy_number": "+1002002040155",
    "service_id": "chat.example.com",
    "challenge_nonce": "0123456789abcdef0123456789abcdef",
    "verification_id": "uuid",
    "expires_at": 1738454800000,
    "callback_url": null
  }
}
```

## Example: Issue Attestation

Request:

```json
{
  "phone_number": "+1234567890",
  "user_pubkey": "base64url-ed25519-pubkey",
  "scope": "1"
}
```

Response:

```json
{
  "proxy_number": "+1002002040155",
  "attestation": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "issuer": "issuer.example.com",
  "issuer_public_key": "base64url-ed25519-pubkey"
}
```

## Example: Verify Attestation

Request:

```json
{
  "attestation_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "max_attestation_age_seconds": 2592000
}
```

`issuer_public_key` can be provided to skip discovery:

```json
{
  "attestation_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "issuer_public_key": "base64url-ed25519-pubkey"
}
```

## Example: Verify Challenge Response

Request:

```json
{
  "challenge": { "...": "challenge object" },
  "response": { "...": "challenge response object" },
  "max_attestation_age_seconds": 2592000,
  "enforce_single_use": true
}
```

The node validates:

- attestation signature + binding proof
- challenge/response field matching
- user signature over canonical challenge payload
- optional attestation age policy (`iat`)
- single-use replay checks (`jti`, `challenge_nonce`, `response_nonce`)
