# LocalPass MVP Acceptance Scorecard

**Date:** 2026-07-04
**Scope:** an honest, line-by-line status of the PRD §9.1 "MVP (v1.0)" IN and OUT
lists against what the code actually implements. This is the anti-overclaiming
document: where something is a stub, partial, or a documented-but-unbuilt
extension point, it says exactly what is missing.

Legend: ✅ **Done** · ◑ **Partial** · ⛔ **Deferred / not built**

Cross-references: [PRD.md](../PRD.md) §9.1 (the checklist source), §4 (functional
requirements), §11 (decision log); [docs/architecture.md](architecture.md);
[SECURITY.md](../SECURITY.md); the format specs under [specs/](specs/); and
[LESSONS.md](../LESSONS.md) (build history / decisions).

---

## 1. MVP "In" scope (PRD §9.1)

### 1.1 Rust core: key hierarchy, crypto, storage, versioning, search

| PRD MVP item | Status | Implemented in | Note |
|--------------|--------|----------------|------|
| Key hierarchy (MUK → AccountKey → VaultKey → ItemKey) | ✅ | `lp-crypto` (`keys`, `kdf`, `wrap`, `seal`), `lp-vault` (`account`, `vault`) | Fresh ItemKey per item *and per version*; AccountKey invariant across password change. |
| Argon2id + 128-bit Secret Key | ✅ | `lp-crypto` (`derive_master_unlock_key`, `SecretKey`) | HKDF mixes Argon2id output + Secret Key under label `localpass/v1/muk`. |
| XChaCha20-Poly1305 | ✅ | `lp-crypto` (`SymmetricKey::seal/open`, `Envelope`) | Envelope v1 `0x01 ‖ nonce(24) ‖ ct+tag`, AAD out-of-band. |
| SQLite envelope-encrypted vaults | ✅ | `lp-vault` (`db`, `account`, `vault`) | Account store + one file per vault; WAL + `synchronous=FULL`; per-item app-layer encryption, not SQLCipher (vault-format.md §6.3). |
| Versioning + trash | ✅ | `lp-vault` (`Vault::update_item`/`history`/`restore_version`/`delete_item`/`list_trash`/`purge_expired_trash`) | Immutable `item_versions`; 30-day default trash then shred; keep-forever + `prune_versions` (PRD §11 #8). |
| Encrypted search index | ✅ | `lp-vault` (`index`, `Vault::search`/`rebuild_index`) | Persisted, encrypted under IndexKey, incremental (updates in the item write transaction), generation-checked; linear fallback on index miss (search-index.md). |

### 1.2 CLI + daemon

| PRD MVP item | Status | Command / crate | Note |
|--------------|--------|-----------------|------|
| Full item CRUD | ✅ | `localpass item add/get/list/edit/rm/history/restore` | Masked by default; `--reveal` / `--field` to print secrets; `--json` throughout. |
| `generate` | ✅ | `localpass generate` (`lp-cli/generate.rs`) | Char passwords + EFF-wordlist passphrases; entropy shown; OS CSPRNG. |
| TOTP | ✅ | `localpass totp` (`lp-crypto/totp.rs`) | RFC 6238; `--watch`, `--json`; code computed in daemon when unlocked (secret never crosses the wire). |
| `run` / `env` / reference resolution | ✅ | `localpass run`, `localpass env export/import/diff` | `localpass://` + `op://` references; `--env-set`/`--env-file`/`-e` layering; Unix `exec`, Windows spawn-and-wait. |
| ssh-agent | ✅ | `localpass ssh list/generate/public`; `lp-daemon/sshagent` | Vault-backed SSH agent on a second same-user-only endpoint (Windows `\\.\pipe\openssh-ssh-agent`, Unix `ssh-agent.sock`); Ed25519 + RSA; keys never touch disk. |
| backup / restore / verify | ✅ | `localpass backup create/list/verify/restore` | SQLite Online Backup snapshot; verify checks hashes + integrity + (with password) recoverability; full and single-item restore. |
| import / export | ✅ | `localpass import`, `localpass export`; `lp-porter` | Works for all MVP formats, including KDBX 4 (KeePass) — see §1.7. |
| Daemon | ✅ | `localpass daemon start/stop/status`, `unlock`, `lock`; `lp-daemon` | Holds one unlocked `Session` behind same-user-only IPC; idle auto-lock (default 600s); zeroize on lock. CLI falls back to direct-unlock when no daemon / `--no-daemon`. |

### 1.3 Desktop GUI (Win/macOS/Linux)

| PRD MVP item | Status | Implemented in | Note |
|--------------|--------|----------------|------|
| Browse, search, CRUD-view, generator, TOTP, history, settings | ◑ | `apps/desktop` (Tauri 2 + Svelte 5) | Built as a **daemon-client shell**: unlock, browse vaults, search, masked item view, reveal/copy on gesture, live TOTP, local generator. See caveats below. |
| Item **create/edit/delete** from the GUI | ⛔ | — | The daemon protocol *has* `CreateItem`/`UpdateItem`/`DeleteItem`/`RestoreVersion`, but the GUI command surface (`commands.rs`) exposes only read/search/reveal/totp/generate — no write commands are wired into the GUI. Item mutation is CLI-only today. |
| Tray quick-search | ⛔ | — | Not implemented in the MVP GUI shell (README scopes the GUI to unlock/browse/search/view/generate). |
| Keyboard-first + accessibility (WCAG 2.2 AA target) | ◑ | `apps/desktop` | Keyboard-operable list, semantic controls, `aria-live`, honors `prefers-color-scheme`/`prefers-reduced-motion`; formal WCAG AA validation not asserted. |

> The GUI is licensed **MPL-2.0** and lives in its own Cargo workspace so the
> AGPL core's gates never build it (PRD §5.6 / §11 #3; architecture §2).

### 1.4 Secret types (logins, notes, API keys, env-sets, SSH keys, TOTP)

| Type | Status | Where | Note |
|------|--------|-------|------|
| Login | ✅ | `lp-vault` `TypeData::Login`; `item add --type login` | Username/password/URL/custom fields. |
| Secure note (Markdown) | ✅ | `TypeData::Note`; `--type note` | Body stored in `notes`. |
| API key / token | ✅ | `TypeData::ApiKey`; `--type api-key` | key/secret/endpoint/expiry/rotate fields (vault-format.md §4). |
| Environment variable set | ✅ | `TypeData::EnvSet`; `--type env-set` | Ordered KEY=value map; drives `run`/`env`. |
| SSH key pair | ✅ | `TypeData::SshKey`; `--type ssh-key`, `ssh generate` | Ed25519 + RSA-4096 generation; private key encrypted, public/fingerprint served by the agent. |
| TOTP secret | ✅ | `TypeData::Totp`; `--type totp --otpauth-uri` | RFC 6238; `otpauth://totp` import (HOTP rejected). |

All six MVP types are the exact `ItemType` enum in the CLI and the `TypeData`
variants in `lp-vault`. Non-MVP types (attachment holder, certificate, passkey,
db credential) are reserved in the payload schema but not implemented
(vault-format.md §4).

### 1.5 Device pairing (SAS) + sync (direct LAN/overlay + file-based)

| PRD MVP item | Status | Where | Note |
|--------------|--------|-------|------|
| **File-based** log-shipping sync | ✅ | `localpass sync setup/push/pull/status/adopt`; `lp-sync` (`engine`, `shipping`) | The MVP-default sync (PRD §11 #6): immutable E2EE `.oplog` segments over a dumb channel; ingest verifier (signature/seq/hash-chain/Lamport) + deterministic merge with loser-preservation. |
| Device pairing | ◑ | `localpass device export-identity/trust`; `lp-sync` (`identity`) | Offline pairing groundwork only: exchange identity strings out-of-band, confirm the fingerprint by hand, then trust. Only trusted devices are accepted as op authors. |
| **SAS** pairing (6-word phrase, mDNS discovery) | ⛔ | — | The spoken-SAS + mDNS live-pairing UX is a **documented later wave** (sync-protocol.md §6; CLI `sync`/`device` long-help both say so). Today it is manual fingerprint confirmation. |
| **Direct LAN / overlay** live transport (Noise XX/IK, mDNS) | ⛔ | — | **Not built.** A documented extension point: the ingest verifier + merge are transport-agnostic and would be reused, but no Noise handshake / mDNS code exists (sync-protocol.md §7.4, §10). PRD §9.1 lists "direct LAN/overlay" as MVP — **this is a gap vs. the PRD** (see §3). |
| Cross-device VaultKey sharing (single-user multi-device) | ◑ | `localpass vault share-to-device`, `sync adopt`; `lp-sync` (`share_vault_to_device`/`import_shared_key`) | Sealed-key transport + shipping are wired; the CLI reports that the **final unwrap step needs a key-transport primitive held behind the crypto boundary** (a documented `lp-crypto` `from_bytes`/`to_bytes` gap — see §3). Op sync + pairing are fully functional without it. |

### 1.6 Browser extension (Chrome/Firefox): fill + save, native messaging

| PRD MVP item | Status | Where | Note |
|--------------|--------|-------|------|
| Native-messaging **host** | ✅ | `localpass-native-host` (`lp-native-host`) | Built: native-endian u32-framed stdio, 1 MiB cap, fill-scoped (`Status`/`MatchLogins`/`FillLogin` only), holds no keys. |
| Host **registration** | ✅ | `localpass browser register/unregister`; `lp-native-host/register.rs` | Writes the `com.localpass.host` manifest per-OS (+ Windows HKCU registry key); `allowed_origins`/`allowed_extensions` allowlist; placeholder extension id until a real one is published. |
| Server-side origin re-validation | ✅ | `lp-daemon/origin.rs` (`registrable_domain`) | eTLD+1 match is the authoritative server-side check on `FillLogin`; lookalikes never match; bare suffixes/IP/localhost refused. **MVP limitation:** conservative heuristic, no full PSL (see §3). |
| Browser **extension UI** (the WebExtension itself: fill on gesture, inline save prompt, no auto-submit, no cross-origin iframe fill) | ⛔ | — | **Not in this repository.** No `extension/` directory or webextension `manifest.json` exists. The host provides the trustworthy primitive; the extension that would call it — and enforce the PRD §4.7 gesture/no-auto-submit/no-iframe rules — is a separate, unbuilt deliverable. So **fill + save from a browser does not work end-to-end yet.** |

### 1.7 Import / Export

| PRD MVP item | Status | Where | Note |
|--------------|--------|-------|------|
| Import: 1Password (1PUX) | ✅ | `lp-porter/import/onepux.rs` | ZIP-wrapped `export.data`. |
| Import: Bitwarden (JSON) | ✅ | `lp-porter/import/bitwarden.rs` | Unencrypted JSON export. |
| Import: LastPass (CSV) | ✅ | `lp-porter/import/lastpass.rs` | |
| Import: KeePass (KDBX 4) | ✅ | `lp-porter/import/kdbx.rs` | Implemented as a focused reader on RustCrypto primitives **aligned to `lp-crypto`'s versions** (cipher 0.4 aes/cbc/chacha20, argon2 0.5, digest-0.10 sha2/hmac) under `lp-porter`'s foreign-format crypto exception — avoiding the 85-crate `keepass` dependency that drove the earlier stub. Scope: AES-256-CBC outer cipher + Argon2d/id KDF + ChaCha20 inner stream (the KeePass/KeePassXC default). ChaCha20/Twofish **outer** ciphers and KDBX 3.x return an actionable "re-save with AES-256" error. Verified end-to-end against a real `pykeepass`-generated database (`lp-porter/tests/kdbx_import.rs`). |
| Import: generic CSV (column mapping) | ✅ | `lp-porter/import/csv_generic.rs` | `--map field=COLUMN`. CLI provides mapping flags; a GUI mapping UI is not built (CLI-only). |
| Import: `.env` | ✅ | `lp-porter/import/dotenv.rs`, `env import` | → one env-set item. |
| Import: plain SSH keys from `~/.ssh` | ◑ | — | No dedicated `~/.ssh` bulk importer; SSH keys are created via `ssh generate` or `item add --type ssh-key`. A direct "import from `~/.ssh`" path is not implemented. |
| Import shred-after-success (best-effort overwrite + delete) | ⛔ | — | Import files are only **read**, never modified or deleted (CLI `import` long-help states this explicitly). The PRD §4.6 "shred after import" behavior is **not** implemented. |
| Export: age archive (recoverable) | ✅ | `lp-porter/export/archive.rs`, `export age` | `age -d`-decryptable tar of item JSON — the exit hatch. |
| Export: dotenv | ✅ | `lp-porter/export/dotenv.rs`, `export dotenv` / `env export` | One env-set → KEY=value. |
| Export: guarded plaintext (JSON/CSV) | ✅ | `lp-porter/export/plaintext.rs`, `export json/csv` | Refused without `--i-understand-plaintext-export`. |

### 1.8 Emergency Kit, automatic local backups, local audit log

| PRD MVP item | Status | Where | Note |
|--------------|--------|-------|------|
| Emergency Kit | ✅ | `localpass init` (auto), `localpass kit`; `lp-cli/commands/kit.rs` | Text or HTML; contains the Secret Key + recovery instructions + no-recovery doctrine; refuses to write inside the profile dir. |
| Automatic local backups | ◑ | `localpass backup create --to --keep`; `lp-vault/backup.rs` | Rotating encrypted snapshots with `--keep` (default 30) pruning **exist**, but they are **on-demand / user-or-scheduler-driven** — there is no built-in daily scheduler/timer. PRD §4.11 "automatic (default: daily)" scheduling is not implemented in-process; the mechanism is present, the automatic cadence is not. |
| Local audit log (hash-chained: unlocks, failed unlocks, item reads, edits, exports, shares, token uses) | ✅ | `localpass audit [--since --json --verify]`; `lp-vault/audit.rs` (`audit_log` table in the account store) | Device-local, append-only, BLAKE3-chained log of unlock success/failure, item create/update/delete/restore, secret reads (reveal/`--field`/`localpass://`/totp/daemon reveal/resolve/fill), export, vault-share, and device-trust. Plaintext **metadata only** — ids, kinds, timestamps, field *names*; never a secret value or vault/item name (verified by dumping the table after a real reveal). `--verify` checks the chain + sequence for tamper. **`TokenUse` is the one §4.9 event with no source yet** (scoped API tokens are P2/unbuilt). |

### 1.9 Signed releases + published format specs

| PRD MVP item | Status | Where | Note |
|--------------|--------|-------|------|
| Format specs published in-repo | ✅ | `docs/specs/{vault-format,search-index,sync-protocol}.md` | Ratified v1.0, implementation-grade. |
| Signed releases for all platforms | ⛔ | `.github/workflows/ci.yml` (CI only) | **Not built.** A plain CI workflow (build/test/lint) exists, but there is **no** `cargo-dist` config, release/signing workflow, signing keys, SBOM, or provenance (the `lp-crypto` `sign` module reserves an Ed25519 `CONTEXT_RELEASE` context, but nothing produces or verifies a release signature). There are no releases at all (SECURITY.md: `main` only). Mark **deferred** — a pre-release engineering task, not a core code gap. |

---

## 2. MVP "Out" scope (PRD §9.1) — confirmation

These are explicitly out of MVP in the PRD and are correctly **not** built:

| Explicitly-out item | Status | Note |
|---------------------|--------|------|
| Team sharing (shared vaults, roles, revocation) | ⛔ (as intended) | Single-user multi-device only; team ops are a named P2 extension point (a new signed `op_kind` gated on admin keys). |
| Relay (`localpass-relay`) | ⛔ (as intended) | Documented §7.4 extension point; no relay binary. |
| Local web UI | ⛔ (as intended) | |
| Attachments | ✅ (post-MVP add) | Implemented (vault-format.md §8): content-addressed encrypted blobs, per-attachment key wrapped by the ItemKey, encrypted filenames, 50 MiB cap. `localpass attach add/list/get/rm`; daemon path-based requests; GUI Attachments section with native file/save pickers. **Syncs** across devices — metadata via the signed op-log (AttachAdd/AttachDelete ops), encrypted blobs via the shared folder with blake3 tamper-verification on fetch (sync-protocol.md §2/§7). |
| Passkeys | ⛔ (as intended) | Payload type reserved (code 9), not implemented. |
| Biometric / YubiKey unlock | ⛔ (as intended) | Password path only; Secret Key in a file (not OS keychain) at MVP. |
| Plugins | ⛔ (as intended) | |
| Mobile | ⛔ (as intended) | |

---

## 3. Known gaps / follow-ups before 1.0

The items below are where the build diverges from the PRD's MVP claims, plus the
tracked follow-ups. They are the real content of this document.

1. **External security audit (PRD §10 R1, §2.2, §9.1 gate).** Not done. It is a
   hard gate before 1.0. Until then, do not store real secrets (SECURITY.md).

2. **LAN / mDNS live sync transport (PRD §9.1 lists it as MVP).** Not built —
   only file-based log shipping exists. The Noise XX/IK + mDNS live path is a
   documented extension point (sync-protocol.md §7.4); the ingest verifier and
   merge are transport-agnostic and would be reused unchanged. **Discrepancy:**
   PRD §9.1 "sync: direct LAN/overlay + file-based" — only the file-based half is
   built. (LESSONS.md confirms the sync MVP boundary was consciously set to
   single-user multi-device, file-based.)

3. **Browser extension UI (PRD §9.1 "browser extension: fill + save").** Only the
   native-messaging **host** is built; the WebExtension itself is not in the
   repo. So browser autofill/save does not function end-to-end. The host is the
   secure primitive; the extension is a separate unbuilt deliverable.

4. **Local audit log (PRD §4.9 / §9.1). — RESOLVED.** Implemented in
   `lp-vault/audit.rs` (`localpass audit`): a device-local, append-only,
   BLAKE3-chained log of unlocks/failed-unlocks/secret-reads/edits/exports/
   shares/device-trust, holding metadata only (never secret values or names),
   with `--verify` tamper detection. The one §4.9 event still unsourced is
   `TokenUse` (scoped API tokens are P2/unbuilt).

5. **KDBX (KeePass) import (PRD §9.1 / §4.6).** Implemented — a focused KDBX 4
   reader (`import::kdbx::parse_file`) on RustCrypto primitives aligned to
   `lp-crypto`'s versions (no `keepass` dependency), verified against a real
   `pykeepass` database. Scope: AES-256 outer + Argon2d/id + ChaCha20 inner (the
   KeePass default); ChaCha20/Twofish-outer and KDBX 3.x give an actionable
   "re-save with AES-256" error.
   Workaround documented: KeePass → CSV → `import csv`.

6. **OS-keychain integration for the Secret Key (PRD §4.3, P2).** At MVP the
   128-bit Secret Key lives in a `<profile>/secret-key` file (owner-only on Unix)
   as the documented stand-in. OS-keychain + biometric/hardware unlock are Phase
   2. This is a *known* deviation, documented in CLI `--help`, the Emergency Kit,
   and LESSONS.md — but worth restating: the file stand-in is weaker than a
   keychain against a same-user attacker.

7. **Sync causality: delete-vs-edit (tracked follow-up #17).** The merge uses a
   scalar Lamport comparator (`a→b iff a.lamport < b.lamport`), which is
   deterministic and convergent but treats some genuinely-concurrent delete/edit
   pairs as causal. Data-preservation is still guaranteed (edit-wins over delete;
   losers preserved as versions), but strengthening the causality model is a
   tracked pre-1.0 follow-up (LESSONS.md 2026-07-04; sync-protocol.md §4).

8. **TOTP title-from-URI (tracked follow-up).** A minor open item: deriving an
   item title from an `otpauth://` URI's issuer/account. Tracked; not a
   correctness issue (the URI's secret/issuer/account/algo/digits/period are all
   parsed correctly).

9. **age-CLI manual verification (LESSONS.md).** Exit-hatch compatibility of the
   age export archive is proven by construction (exact `age-encryption.org/v1`
   magic + standard scrypt stanza + official-crate provenance + in-crate
   round-trip). The standalone `age` CLI cannot decrypt non-interactively
   (passphrase input is TTY-only), so a **one-time manual `age -d backup.age`
   check by a human is still worth doing before 1.0.**

10. **Cross-device VaultKey unwrap primitive.** `vault share-to-device` ships a
    sealed VaultKey but the final unwrap needs an `lp-crypto`
    `SigningKeyPair`/`SealingKeyPair` `from_bytes`/`to_bytes` primitive that is
    intentionally still behind the crypto boundary (also the reason device
    identity keys are session-scoped rather than reconstructed from stored
    wrapped seeds — lp-vault lib docs). Two small additive `lp-crypto` methods
    close this with no schema change. Op sync + pairing work without it.

11. **Signed releases / release engineering (PRD §9.1, §5.1, §6.9).** No release
    pipeline, signing, SBOM, or provenance yet. Deferred until the audit and
    format-freeze gates pass.

12. **Automatic backup scheduling (PRD §4.11).** The backup *mechanism* (create,
    rotate/`--keep`, verify, restore) is complete, but the "default daily"
    automatic scheduling is not implemented in-process; today it is on-demand or
    via an external scheduler.

13. **GUI write path + tray quick-search (PRD §9.1).** The GUI shell is read /
    search / reveal / totp / generate only; item create/edit/delete and tray
    quick-search are not wired into the GUI (the daemon protocol supports the
    writes; the GUI does not expose them). Item mutation is CLI-only.

14. **Import file shredding (PRD §4.6).** Not implemented — import files are only
    read, never overwritten/deleted.

### Documentation discrepancies noted in passing

- The [README.md](../README.md) "What exists today" table is **stale**: it lists
  the daemon, `localpass run`, SSH agent, import/export, backup, file-based sync,
  and pairing as "🔜 next / planned", but all of those are now built (this
  scorecard supersedes it). The GUI and browser-extension rows remain accurate
  (GUI shell built; extension UI not).
- The `lp-cli` `Cargo.toml` package description still says "direct-unlock CLI
  (no daemon yet)"; the daemon and daemon-client path are in fact built.

These are documentation-only lags (no code impact) and are recorded here rather
than fixed, per this task's constraints.
