# LocalPass

A fully local, self-hosted password and secrets manager — an open-source alternative to 1Password with a strong developer focus: `.env` secrets, API keys, SSH keys, certificates, and secure sharing across your own machines without any cloud dependency.

> **Work in progress.** LocalPass is under active development and is not yet ready for real secrets. The storage format may still change before the first release.

## What exists today

| Component | Status |
|-----------|--------|
| [PRD](PRD.md) + [format specs](docs/specs/) | ✅ Ratified v1.0 (vault format, encrypted search index, sync protocol) |
| `lp-crypto` — crypto core | ✅ Argon2id + Secret Key KDF, XChaCha20-Poly1305 envelopes, key wrapping, X25519 sealing, Ed25519 signing, BLAKE3 chaining |
| `lp-vault` — storage core | ✅ Account store, vaults, item CRUD with per-version keys, immutable history, trash, signed op log with hash chain, encrypted incremental search index |
| `lp-cli` — `localpass` binary | ✅ Foundations: init/vault/item/search/generate/password commands |
| Daemon, `localpass run` env injection, SSH agent | 🔜 next |
| Import/export, backup, file-based sync, pairing | 🔜 |
| Browser extension, Tauri GUI | planned (see [PRD §9](PRD.md)) |

## Building

Requires stable Rust (MSVC toolchain on Windows).

```sh
cargo build --workspace
cargo test --workspace
```

## Trying the CLI

```sh
cargo run -p lp-cli -- init                       # creates your account + Emergency Kit
cargo run -p lp-cli -- item add --title GitHub --username you --generate
cargo run -p lp-cli -- item get GitHub            # masked by default
cargo run -p lp-cli -- item get GitHub --field password   # raw value for scripting
cargo run -p lp-cli -- search git
cargo run -p lp-cli -- generate --words 5
```

**Print your Emergency Kit and store it offline.** There is no cloud reset: losing your master password, Secret Key, and devices means the data is gone — by design.

## Security model (short version)

Everything on disk is encrypted (XChaCha20-Poly1305) under a key hierarchy rooted in your master password **and** a locally generated 128-bit Secret Key, so a stolen vault file cannot be brute-forced offline. Every ciphertext is bound to its exact location (vault, item, version) so blobs cannot be cut-and-pasted. Every change is a signed, hash-chained operation. Read the full [threat model in the PRD](PRD.md) and the [format specs](docs/specs/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — and read [LESSONS.md](LESSONS.md) for conventions and the decision log before proposing changes.

## License

AGPL-3.0 for core/daemon crates ([LICENSE](LICENSE)); MPL-2.0 for future GUI code ([LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt)).
