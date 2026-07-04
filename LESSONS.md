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
- **2026-07-04 — Index prefix matching at query time**, not stored prefix tokens (BTreeMap range scan over posting keys). Stored prefixes bloated segments ~4×; query-time scan gives identical results at far lower write amplification. Spec §2/§6 semantics preserved.
- **2026-07-04 — Index segment tuning knobs** (`LP_INDEX_SPLIT`/`TARGET`/`MERGE` env vars) exist for tests only; production uses spec constants (256/512/256). Tuning is explicitly non-format-fixed per spec §3.
- **2026-07-04 — Typed key transport across devices:** moving a key between devices goes through `lp_crypto::seal_key_for` / `SealingKeyPair::open_key` (SymmetricKey in, SymmetricKey out) — never a raw-bytes accessor. Share-blob AADs bind vault id + recipient device id. Pattern: when a layer above needs "the impossible" from lp-crypto, add a narrow typed primitive to lp-crypto rather than widening byte access.
- **2026-07-04 — Sync merge causality is scalar-Lamport** (a→b iff a.lamport < b.lamport): deterministic and convergent, but treats some genuinely-concurrent delete/edit pairs as causal (task #17 tracks strengthening before 1.0).
- **2026-07-04 — Foreign-format crypto boundary:** lp-crypto stays the sole home of LocalPass's OWN vault crypto; `lp-porter` may use the `age` crate for foreign-format archive crypto (it resolves to the exact same primitive crate versions — no duplicated crypto surface). KDBX import stubbed for this reason: the `keepass` crate pulls a parallel crypto stack (~85 transitive crates); revisit as a feature-gated opt-in.
- **2026-07-04 — Standalone `age` CLI cannot decrypt non-interactively** (passphrase input is TTY-only by design; winpty can't fake a console headless). Exit-hatch compatibility is proven by construction: exact `age-encryption.org/v1` magic + standard scrypt stanza + official-crate provenance + in-crate round-trip. A one-time manual `age -d backup.age` check by a human is still worth doing before 1.0.
- **2026-07-04 — CLI secret-key storage:** `<profile>/secret-key` file (0600 on Unix) is the MVP stand-in for OS-keychain storage (keychain is P2). Documented in `--help` and the Emergency Kit output.

## Environment notes

- Dev box: Windows 11 Home, no prior Rust install. Installed rustup (stable-msvc) and VS 2022 Build Tools (VC workload) via winget on 2026-07-04.
- Cargo is at `%USERPROFILE%\.cargo\bin` — fresh shells may need it on PATH.

## Lessons learned

- **2026-07-04 — Verify crypto outputs against an independent consumer, not just round-trips.** ssh-key 0.6.7 has a real RSA bug (CRT primes passed as `p,p` instead of `p,q`) that a self-round-trip test can mask; it surfaced because signatures were verified against the public key and then against real `ssh-add`. **How to apply:** for any signing/encryption path involving a third-party format, include at least one test that validates output with an independent implementation (another crate's verifier, a system tool), not only our own decoder.

- **2026-07-04 — Interrupted subagents leave recoverable work.** A machine restart killed the Wave 6 agent mid-flight, but its working-tree output survived (~1,900 lines, compiling, 6/7 tests passing). Recovery cost was one bad test assumption (a CLI-layer `secret-key` file referenced from an lp-vault-layer test), a missing `cargo fmt`, and absent CLI-level tests. **How to apply:** after any interrupted agent, run the gates on the working tree first — finishing partial work is usually far cheaper than relaunching from zero; look specifically for layer-confusion mistakes near where the work stopped.
- **2026-07-04 — Timing-window tests need process-spawn headroom.** The daemon autolock test used a 1s idle window; post-reboot process spawn ate it and the test flaked. Windows CLI process spawn + connect can cost ~1s cold. **How to apply:** in tests where a fresh CLI process must land inside a timing window, size the window ≥4s.

- **2026-07-04 — Daemon transport & access control (decision):** Windows named pipe `\\.\pipe\localpass-<user>` with a DACL granting only the current user's SID (`D:(A;;GA;;;<sid>)`) + `PIPE_REJECT_REMOTE_CLIENTS` + `FILE_FLAG_FIRST_PIPE_INSTANCE`; Unix UDS 0700/0600 + `SO_PEERCRED` euid check. The OS-enforced same-user restriction is the authentication (PRD §8 T8); the master password crosses the channel in clear only because of it. Detached spawn MUST use `CreateProcessW` with `bInheritHandles=FALSE` — `std::process::Command` inherits the launcher's stdout pipe and deadlocks a piped `daemon start`. Threaded std, no tokio; one mutex serializes the `!Sync` Session; request read/write happens outside the lock so a hung client can't block auto-lock.
- **2026-07-04 — PowerShell `'text' | exe --password-stdin` is unreliable for password piping** (5.1 encoding/newline quirks made a correct password read as wrong). The env-var and interactive paths are fine. **How to apply:** when smoke-testing stdin secret input on Windows, prefer `$env:LOCALPASS_PASSWORD` or a real pipe from a file; don't trust a PowerShell string-literal pipe, and don't treat its failure as a code bug without cross-checking another input path.
- **2026-07-04 — Smoke-test Windows CLIs from PowerShell, not git-bash.** MSYS argument conversion turns a bare `/c` into `C:\`, so `localpass run -- cmd /c ...` appeared broken from bash (interactive cmd banner, wrong exit codes) while the binary was correct. **How to apply:** for Windows child-process behavior, verify via the PowerShell tool; treat git-bash smoke failures involving `/`-prefixed args as suspect before blaming the code.

- **2026-07-04 — Gate commits on `cargo test`'s exit code, never a grep'd pipeline.** A `cargo test | grep "test result" && git commit` chain committed a broken test because grep's exit code masked the failure (caught and amended immediately). **How to apply:** run tests as their own command, branch on `$?`, and only then commit.
- **2026-07-04 — AAD component encoding (fixed contract):** AAD strings are UTF-8, joined with a single `|`: labels verbatim, ids as 32-char lowercase hex (no hyphens), integers as decimal ASCII. Chain-genesis hash input is raw-byte framed: `label_utf8 || vault_id(16) || device_id(16)`.
- **2026-07-04 — Review subagent crypto with a hardening checklist, not just tests.** The lp-crypto delivery was excellent (constructions, hygiene, oracle-resistance all correct), yet still missed X25519 low-order-point rejection (`SharedSecret::was_contributory()`), added in review. **How to apply:** for crypto deliveries, walk a fixed checklist (nonce sourcing, contributory ECDH, domain separation, zeroization on every early-return path, error-oracle collapse) rather than relying on the test suite the same author wrote.

- **2026-07-04 — Cross-artifact consistency review pays.** Orchestrator review of the spec drafts caught a wire/DDL mismatch (op wire field `target_ver` had no `ops.target_version` column, which would have broken canonical-byte reconstruction for hash-chain verification) and a plaintext-set overreach vs PRD §6.3. **How to apply:** after any subagent delivers multi-document or code+spec output, diff the artifacts against each other and against the PRD before committing — don't review documents only in isolation.
