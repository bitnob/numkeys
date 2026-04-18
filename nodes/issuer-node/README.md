# NumKeys Issuer Node

Reference implementation of a NumKeys Protocol issuer node.

## Quick Start

1. First, run the setup command to create your issuer configuration:
   ```bash
   numkeys setup
   ```

2. Start the issuer node with your configuration:
   ```bash
   # Using config directory
   NUMKEYS_CONFIG_DIR=~/.numkeys/issuer/default cargo run --bin issuer-node

   # Or using config file path directly
   CONFIG_PATH=~/.numkeys/issuer/default/config/issuer.toml cargo run --bin issuer-node
   ```

## Configuration

The issuer node loads configuration from `issuer.toml` created by the setup command. The configuration includes:

- **Identity**: Issuer name, issuer domain, and public key
- **Port**: Server port (default: 3000)

Attestations are issued without a required `exp` claim. Verifiers enforce freshness from `iat`
using their own policy.

The private key is loaded from `keys/private.key` relative to the config file.

## Endpoints

- `POST /attest` - Request attestation with user public key
- `GET /.well-known/numkeys/pubkey.json` - Public key discovery

## Environment Variables

- `NUMKEYS_CONFIG_DIR` - Directory containing config/issuer.toml
- `CONFIG_PATH` - Direct path to issuer.toml file
- `BIND_ADDRESS` - Override bind address (fallback only)
- `ISSUER_DOMAIN` - Override domain (fallback only)
- `PRIVATE_KEY_PATH` - Override private key path (fallback only)
