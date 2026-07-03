# LESSONS.md — decisions, conventions, and lessons learned

Living log for the LocalPass build. [PRD.md](PRD.md) is the *what*; this file records *how* we're building it and what we learned along the way. Read this before starting any new work unit.

## Conventions

- **Commits:** conventional commits, small atomic diffs, one reviewable unit each.
- **Workspace:** crates live under `crates/*` (globbed in the root `Cargo.toml`, so adding a crate never touches the root manifest).
- **Delegation:** major implementation tasks go to Opus subagents with scoped prompts and explicit acceptance criteria. The orchestrator reviews output, runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test`, then commits. Subagents never run git commands.
- **Crypto boundary:** `lp-crypto` is the only crate allowed to depend on crypto primitive crates. Everything else consumes its misuse-resistant high-level API.
- **Fixed cross-crate contracts** (mirrored in `docs/specs/`):
  - Envelope v1: `0x01 || nonce(24 bytes) || ciphertext+tag`, XChaCha20-Poly1305, AAD carried out-of-band.
  - HKDF label namespace: `localpass/v1/<purpose>` (labels mandatory, never empty).
  - Key hierarchy names: MUK → AccountKey → VaultKey → ItemKey; IndexKey derived from VaultKey with label `localpass/v1/index`.

## Decisions

- **2026-07-04 — PRD v1.0 ratified** including the 8 decision-log items (PRD §11): server-enforced token scopes (P2), persisted incremental encrypted search index, MPL-2.0 for GUI, `localpass://` with `op://` alias, best-effort passkeys (macOS/iOS → Windows → Linux), file-based sync as onboarding default, pairing-code-gated relay enrollment, keep-forever retention + visible stats + prune tooling.
- **2026-07-04 — Toolchain:** Rust stable (1.96.1 at time of setup), edition 2024, resolver 2. `rust-version = 1.90` floor.
- **2026-07-04 — Supply chain:** cargo-deny gates in CI from day one (advisories, license allowlist, unknown sources).

## Environment notes

- Dev box: Windows 11 Home, no prior Rust install. Installed rustup (stable-msvc) and VS 2022 Build Tools (VC workload) via winget on 2026-07-04.
- Cargo is at `%USERPROFILE%\.cargo\bin` — fresh shells may need it on PATH.

## Lessons learned

- (add entries as they happen — include *why* and *how to apply*)
