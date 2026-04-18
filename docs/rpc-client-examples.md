# NumKeys RPC Client Examples

This document shows copy-paste integration examples for the `numkeys-node` HTTP/RPC surface.

Assume:

- node base URL: `http://127.0.0.1:3200`
- JSON requests over HTTPS in production

## cURL

Create challenge:

```bash
curl -X POST http://127.0.0.1:3200/create-challenge \
  -H 'content-type: application/json' \
  -d '{
    "proxy_number": "+1002002040155",
    "service_id": "chat.example.com",
    "ttl_seconds": 300
  }'
```

Verify attestation:

```bash
curl -X POST http://127.0.0.1:3200/verify-attestation \
  -H 'content-type: application/json' \
  -d '{
    "attestation_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
    "max_attestation_age_seconds": 2592000
  }'
```

Verify challenge response:

```bash
curl -X POST http://127.0.0.1:3200/verify-challenge-response \
  -H 'content-type: application/json' \
  -d '{
    "challenge": { "...": "challenge object" },
    "response": { "...": "challenge response object" },
    "enforce_single_use": true
  }'
```

## Node.js (Fetch)

```js
const base = "http://127.0.0.1:3200";

async function main() {
  const challengeRes = await fetch(`${base}/create-challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proxy_number: "+1002002040155",
      service_id: "chat.example.com",
      ttl_seconds: 300
    })
  });
  const challenge = await challengeRes.json();

  const verifyRes = await fetch(`${base}/verify-attestation`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      attestation_jwt: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
      max_attestation_age_seconds: 2592000
    })
  });
  const verify = await verifyRes.json();

  console.log({ challenge, verify });
}

main().catch(console.error);
```

## Python (requests)

```python
import requests

base = "http://127.0.0.1:3200"

challenge = requests.post(
    f"{base}/create-challenge",
    json={
        "proxy_number": "+1002002040155",
        "service_id": "chat.example.com",
        "ttl_seconds": 300,
    },
).json()

verify = requests.post(
    f"{base}/verify-attestation",
    json={
        "attestation_jwt": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
        "max_attestation_age_seconds": 2592000,
    },
).json()

print(challenge)
print(verify)
```
