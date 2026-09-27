# LocalPass 1.0 release checklist

**Last reviewed:** 2026-09-28, against `main` at `fa174fa`.

What stands between the current `main` and a 1.0 release. The source of truth
for *what 1.0 is* is [PRD.md](../PRD.md) §9.1 (scope and acceptance gates) and
§10 (risks); the line-by-line status of each feature is
[mvp-acceptance.md](mvp-acceptance.md). This file is the **actionable** list:
tick an item when the PR that closes it merges, and link the PR.

Until every box in §1 is ticked, SECURITY.md's "do not store real secrets"
warning stands.

---

## 1. Acceptance gates (PRD §9.1) — all must pass

- [ ] **External security audit passed**, all criticals and highs resolved
  (PRD §10 R1, §2.2). Scope at least: `lp-crypto` and the key hierarchy, the
  vault and sync formats, daemon IPC, the MCP server, the native host and
  extension, and the Tauri command boundary.
- [ ] **Fuzzing corpus green.** No fuzz harness exists yet. Targets: the
  KDBX, 1PUX, Bitwarden, LastPass/CSV and `.env` importers; sync segment and
  op ingest; the vault-key share blob; the native-messaging frame decoder.
  Run the corpus in CI.
- [ ] **Performance targets met** (PRD §2.2), measured by a benchmark that runs
  in CI: unlock < 1.5 s and search < 50 ms p95 with 10k items on a mid-range
  laptop; daemon idle RSS < 50 MB.
- [ ] **Zero known data-loss defects.** Close the sync causality follow-up for
  concurrent delete vs edit (mvp-acceptance.md §3 #7). Nothing is lost today
  (edit wins, losers are preserved), but it is a tracked pre-1.0 fix.
- [ ] **Signed releases for all platforms** — see §4.

## 2. MVP scope — build, or formally re-scope

Each of these is in PRD §9.1's "In" list but not (fully) built. For each,
decide: **build for 1.0**, or **move to 1.x** by amending PRD §9.1 and
recording the decision in §11.

- [ ] Direct LAN / overlay live sync (Noise XX/IK + mDNS). Only file-based
  sync exists (the PRD's default onboarding path, §11 #6).
- [ ] SAS pairing (6-word phrase). Today: manual fingerprint comparison.
- [ ] Desktop tray quick-search.
- [ ] Desktop version history: browse and restore an item's versions (CLI
  `item history/restore` works).
- [ ] Browser extension: **save** new logins (the host is fill-scoped by
  design today), and verify fill live in Chrome and Firefox.
- [ ] Automatic daily local backups (the backup mechanism is complete; nothing
  schedules it).
- [ ] Import-file shredding after a successful import (PRD §4.6).
- [ ] Import SSH keys directly from `~/.ssh`.
- [ ] Desktop builds for macOS and Linux, and a formal WCAG 2.2 AA review.

## 3. Security follow-ups (2026-09 internal review)

The review's confirmed findings are fixed: #40 (MCP secret boundary), #41
(autofill origin matching), #42 (clipboard hygiene), #43 (signed vault-key
shares), #44 (Firefox extension id). Remaining work — details of anything
unfixed are held privately, per [SECURITY.md](../SECURITY.md):

- [x] Daemon-side **human-presence check** while an MCP session is active:
  consent and change requests need the master password
  (docs/specs/mcp-server.md §7.1). Reads stay open by design, since
  `run_with_secrets` can already inject any secret.
- [ ] Review the subsystems the internal review did not cover: Android
  storage, the SSH agent, backup/restore, the search index, and `run` /
  `env export`.
- [ ] Reproduce the fixed findings dynamically in a sandbox (the review was
  source-only).
- [ ] Desktop workspace `cargo deny`: clear the advisories, unmaintained and
  yanked crates, and add `publish = false` so path-dependency checks pass.
- [ ] Hardening items from the review (tracked privately): webview boundary
  configuration, input size limits in parsers, and server-side enforcement of
  fill conditions.
- [ ] Origin matching: replace the built-in suffix sets with the full Public
  Suffix List (mvp-acceptance.md §1.6).
- [ ] Choose and reserve the Firefox add-on id: set
  `browser_specific_settings.gecko.id` in `apps/extension/manifest.json` and
  claim it on addons.mozilla.org.
- [ ] Manual checks: Windows clipboard history exclusion and the 30 s clear
  (#42); a one-time `age -d` of an exported archive (mvp-acceptance.md §3 #9).
- [ ] Bug bounty ready for GA (PRD §10 R1).

## 4. Release engineering (PRD §6.9)

Today `desktop-release.yml` builds an unsigned Windows bundle and a signed
Android APK; nothing else below exists.

- [ ] Release pipeline (`cargo-dist` or equivalent) for the CLI, daemon and
  native host on Windows, macOS (universal) and Linux (static musl).
- [ ] Desktop app: code-signed Windows MSI/NSIS; notarized macOS `.dmg`; Linux
  AppImage plus `.deb`/`.rpm`.
- [ ] Release signatures: Ed25519 (minisign-compatible) and Sigstore, keys
  published in the repo and on the website and cross-attested; produce and
  verify them under `lp-crypto`'s `CONTEXT_RELEASE`.
- [ ] Checksums, a CycloneDX SBOM, and build provenance for every artifact.
- [ ] Distribution: winget, Homebrew formula and cask, AUR, and a `curl | sh`
  installer with checksum-verification instructions.
- [ ] Reproducible builds for the CLI and daemon.

## 5. Format freeze and documentation

- [ ] **Freeze the on-disk and wire formats** at 1.0 — vault-format,
  sync-protocol (including the `LPS2` share format), search-index — and add a
  compatibility test that opens fixtures written by the frozen version.
- [ ] SECURITY.md: a real disclosure channel — enable GitHub private
  vulnerability reporting and publish a security contact (with a PGP key) in
  place of the placeholders.
- [ ] README: drop the work-in-progress banner and point installation at the
  signed artifacts, once §1 passes.
- [ ] Keep the Secret Key file stand-in documented as a known 1.0 deviation
  (OS keychain and hardware unlock are Phase 2).
- [ ] Governance and sustainability doc (PRD §10 R9).
- [ ] mvp-acceptance.md: every row ✅ or explicitly re-scoped.
- [ ] Minor: derive a TOTP item's title from the `otpauth://` issuer/account.
