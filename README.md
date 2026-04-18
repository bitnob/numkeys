# NumKeys Protocol

> Release candidate workspace for the v1.1 core protocol.

NumKeys is a protocol for issuing privacy-preserving phone number attestations. A trusted issuer verifies control of a real phone number, binds that verification to a user public key, and issues a signed attestation plus a proxy number. Services can verify the attestation without learning the underlying phone number.

[![License: Apache--2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/docs-protocol-blue)](docs/numkeys-protocol-specification.md)

## Scope

The current core protocol covers:

- issuer-signed JWT attestations
- deterministic proxy-number generation
- issuer key discovery via `/.well-known/numkeys/pubkey.json`
- wallet-mediated challenge-response verification

The current core model uses `iss` as the sole authoritative issuer identity.

## Documentation

- [Protocol Specification](docs/numkeys-protocol-specification.md)
- [Becoming an Issuer](docs/becoming-an-issuer.md)
- [RPC API Contract (v1.1)](docs/rpc-api-contract.md)
- [RPC Client Examples (cURL / Node.js / Python)](docs/rpc-client-examples.md)
- [LLM Integration Index](llms.txt)
- [Issuer Node Specification (Reference Implementation, Non-Normative)](docs/numkeys-issuer-node-specification.md)
- [Wallet Specification](docs/wallet-spec.md)
- [Wallet SDK Specification](docs/wallet-sdk-spec.md)
- [Sequence Diagrams](docs/sequence-diagrams.md)
- [v1 Test Vectors](docs/v1-test-vectors.md)
- [v1 Operational Notes](docs/v1-operational-notes.md)
- [v1 Release Scope](docs/v1-release-scope.md)

## Workspace

```text
crates/
  numkeys-types    Core protocol types
  numkeys-crypto   Cryptographic operations
  numkeys-core     Protocol logic and verification
  numkeys-client   HTTP client helpers
nodes/
  issuer-node      Reference issuer implementation (non-normative)
  numkeys-node     HTTP/RPC issue-and-verify node for any backend language
cli/
  numkeys-cli      Command-line tooling
docs/
  Protocol specifications and diagrams
```

## Development

Prerequisites:

- Rust 1.70+

Build the workspace:

```bash
cargo build
```

Run tests:

```bash
cargo test
```

## Prebuilt Binaries

Tagged releases publish prebuilt binaries for:

- Linux (`x86_64-unknown-linux-gnu`)
- macOS Intel (`x86_64-apple-darwin`)
- macOS Apple Silicon (`aarch64-apple-darwin`)
- Windows (`x86_64-pc-windows-msvc`)

Each release asset includes:

- `numkeys` (CLI)
- `numkeys-node` (RPC node)
- `issuer-node` (reference issuer)
- `.sha256` checksum file

To create a release:

```bash
git tag v1.1.0-rc.1
git push origin v1.1.0-rc.1
```

Then download assets from GitHub Releases:

- `https://github.com/bitnob/numkeys/releases`

Run the reference issuer:

```bash
NUMKEYS_CONFIG_DIR=~/.numkeys/issuer/default cargo run --bin issuer-node
```

See [nodes/issuer-node/README.md](nodes/issuer-node/README.md) for issuer setup details.

Run the HTTP/RPC node:

```bash
cargo run --bin numkeys-node
```

See [nodes/numkeys-node/README.md](nodes/numkeys-node/README.md) for endpoint usage.

`numkeys-node` bootstraps persistent issuer keys by default and exposes node state at `GET /status`.

Run the end-to-end smoke script for the node:

```bash
bash scripts/smoke-numkeys-node.sh
```

## Using as a Dependency

For most integrations, use the unified SDK crate:

```bash
cargo add numkeys
```

If you prefer smaller surfaces, install specific crates:

```bash
cargo add numkeys-core
cargo add numkeys-types
cargo add numkeys-crypto
cargo add numkeys-client
```

Before crates are published, consume directly from GitHub:

```toml
[dependencies]
numkeys = { git = "https://github.com/bitnob/numkeys.git" }
```

Minimal service-side verification example:

```rust
use numkeys::verify_attestation;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = std::fs::read_to_string("attestation.jwt")?;
    let verified = verify_attestation(&jwt).await?;
    println!("issuer={}", verified.issuer);
    Ok(())
}
```

`numkeys-core` + protocol specs + test vectors define the normative protocol behavior.

## Status

This repository is the reference implementation for the NumKeys v1.1 release-candidate surface. The core protocol is frozen for review; changes from this point should be release-blocking fixes or explicit versioned follow-on work.

Normative protocol behavior is defined by `numkeys-core`, protocol specs, and conformance vectors.
`nodes/issuer-node` is a reference service profile and is not the protocol definition.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

Licensed under Apache-2.0. See [LICENSE](LICENSE).
