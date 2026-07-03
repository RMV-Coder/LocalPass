# Contributing to LocalPass

Thanks for your interest! LocalPass is early — the spec is [PRD.md](PRD.md) and the running decision log is [LESSONS.md](LESSONS.md). Read both before proposing changes.

## Licensing

- Core, daemon, CLI, and sync code (`crates/*` unless stated otherwise): **AGPL-3.0-only** ([LICENSE](LICENSE)).
- GUI / desktop apps (`apps/*`): **MPL-2.0** ([LICENSES/MPL-2.0.txt](LICENSES/MPL-2.0.txt)).
- Client libraries and import/export format code will be MIT/Apache-2.0 dual-licensed (marked per-crate when they exist).

Contributions are accepted under the license of the component you're touching. No CLA — we use the [Developer Certificate of Origin](https://developercertificate.org/): sign off your commits with `git commit -s`.

## Ground rules

- **Security first.** Anything touching `lp-crypto`, key handling, or the threat model (PRD §8) gets extra scrutiny. `lp-crypto` is the only crate that may depend on cryptographic primitive crates.
- **Small, focused PRs** with conventional-commit messages.
- **Quality gates** (CI enforces): `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, cargo-deny clean.
- New public APIs need doc comments; new behavior needs tests.

## Building

```sh
rustup toolchain install stable   # rustfmt + clippy components
cargo build --workspace
cargo test --workspace
```

Windows needs the MSVC toolchain (VS Build Tools with the C++ workload).

## Reporting security issues

Please do **not** open public issues for suspected vulnerabilities. A `SECURITY.md` with a disclosure process will be added before the first release; until then, contact the maintainers privately.
