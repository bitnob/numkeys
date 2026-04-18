#!/usr/bin/env bash
set -euo pipefail

PORT="${NUMKEYS_SMOKE_PORT:-3210}"
BASE_URL="http://127.0.0.1:${PORT}"
KEY_FILE="/tmp/numkeys-node-smoke.private"
LOG_FILE="/tmp/numkeys-node-smoke.log"

# Deterministic test private key (32 bytes of 0x07, base64url).
printf '%s' 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc' > "${KEY_FILE}"

echo "[smoke] Starting numkeys-node on ${BASE_URL}"
ISSUER_DOMAIN="localhost:${PORT}" \
PRIVATE_KEY_PATH="${KEY_FILE}" \
BIND_ADDRESS="127.0.0.1:${PORT}" \
  cargo run --bin numkeys-node > "${LOG_FILE}" 2>&1 &
PID=$!
trap 'kill ${PID} >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/health" >/tmp/numkeys-node-smoke-health.json 2>/dev/null; then
    break
  fi
  sleep 0.2
done

echo "[smoke] Checking health"
curl -fsS "${BASE_URL}/health" >/tmp/numkeys-node-smoke-health.json

echo "[smoke] Checking issuer discovery endpoint"
curl -fsS "${BASE_URL}/.well-known/numkeys/pubkey.json" >/tmp/numkeys-node-smoke-pubkey.json

echo "[smoke] Issuing attestation"
curl -fsS -X POST "${BASE_URL}/issue-attestation" \
  -H 'content-type: application/json' \
  -d '{"phone_number":"+1234567890","user_pubkey":"_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqwdXp9hg","scope":"1"}' \
  >/tmp/numkeys-node-smoke-issue.json

ATTESTATION="$(sed -E 's/.*"attestation":"([^"]+)".*/\1/' /tmp/numkeys-node-smoke-issue.json)"
ISSUER_PUB="$(sed -E 's/.*"issuer_public_key":"([^"]+)".*/\1/' /tmp/numkeys-node-smoke-issue.json)"

if [[ -z "${ATTESTATION}" || -z "${ISSUER_PUB}" ]]; then
  echo "[smoke] Failed to parse attestation response"
  cat /tmp/numkeys-node-smoke-issue.json
  exit 1
fi

echo "[smoke] Verifying attestation"
curl -fsS -X POST "${BASE_URL}/verify-attestation" \
  -H 'content-type: application/json' \
  -d "{\"attestation_jwt\":\"${ATTESTATION}\",\"issuer_public_key\":\"${ISSUER_PUB}\",\"max_attestation_age_seconds\":3600}" \
  >/tmp/numkeys-node-smoke-verify.json

echo "[smoke] Success"
echo "health: $(cat /tmp/numkeys-node-smoke-health.json)"
echo "pubkey: $(cat /tmp/numkeys-node-smoke-pubkey.json)"
echo "issue: $(cat /tmp/numkeys-node-smoke-issue.json)"
echo "verify: $(cat /tmp/numkeys-node-smoke-verify.json)"
