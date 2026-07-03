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
- **2026-07-04 — On-disk layout:** one **account store** SQLite file (KDF params, wrapped AccountKey, device keys, vault registry, settings) plus **one SQLite file per vault**. Rationale: per-vault portability and sync, blast-radius isolation, matches PRD "single-file vaults". Specified in `docs/specs/vault-format.md`.
- **2026-07-04 — Durability:** uniform `PRAGMA synchronous=FULL` (WAL) on the account store AND vault files. NORMAL could lose the last committed write on power loss — unacceptable for a just-saved credential; human-scale write rates make the fsync cost irrelevant.
- **2026-07-04 — Plaintext minimization:** `item_type`, `favorite`, `folder_id` live INSIDE the encrypted item payload, not as plaintext columns (spec-review tightening). PRD §6.3 fixes plaintext to ids/counters/timestamps; type distribution is targeting info. Type/folder/favorite filters run via the encrypted index.
- **2026-07-04 — Sync MVP boundary confirmed:** single-user multi-device only; team membership-change ops are a named P2 extension point (new signed op_kind gated on admin keys), not designed now.

## Environment notes

- Dev box: Windows 11 Home, no prior Rust install. Installed rustup (stable-msvc) and VS 2022 Build Tools (VC workload) via winget on 2026-07-04.
- Cargo is at `%USERPROFILE%\.cargo\bin` — fresh shells may need it on PATH.

## Lessons learned

- **2026-07-04 — Review subagent crypto with a hardening checklist, not just tests.** The lp-crypto delivery was excellent (constructions, hygiene, oracle-resistance all correct), yet still missed X25519 low-order-point rejection (`SharedSecret::was_contributory()`), added in review. **How to apply:** for crypto deliveries, walk a fixed checklist (nonce sourcing, contributory ECDH, domain separation, zeroization on every early-return path, error-oracle collapse) rather than relying on the test suite the same author wrote.

- **2026-07-04 — Cross-artifact consistency review pays.** Orchestrator review of the spec drafts caught a wire/DDL mismatch (op wire field `target_ver` had no `ops.target_version` column, which would have broken canonical-byte reconstruction for hash-chain verification) and a plaintext-set overreach vs PRD §6.3. **How to apply:** after any subagent delivers multi-document or code+spec output, diff the artifacts against each other and against the PRD before committing — don't review documents only in isolation.
