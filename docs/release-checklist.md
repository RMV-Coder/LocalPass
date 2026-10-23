# LocalPass 1.0 release checklist

**Last reviewed:** 2026-10-22, against `main` at `178804d` (after #46–#48 and
#50; #49 open). Previous review: 2026-09-28 at `fa174fa`.

What stands between the current `main` and a 1.0 release. The source of truth
for *what 1.0 is* is [PRD.md](../PRD.md) §9.1 (scope and acceptance gates) and
§10 (risks); the line-by-line status of each feature is
[mvp-acceptance.md](mvp-acceptance.md). This file is the **actionable** list:
tick an item when the PR that closes it merges, and link the PR.

Until every box in §1 is ticked, SECURITY.md's "do not store real secrets"
warning stands.

**Since the last review:** the human-presence check landed (#46); the GUI
redesign (#47) added Windows Hello unlock and a signed in-app updater, which
are new attack surface (§1, §2, §3); Windows code signing through SignPath is
in review (#49). No §1 gate has moved.

---

## 1. Acceptance gates (PRD §9.1) — all must pass

- [ ] **External security audit passed**, all criticals and highs resolved
  (PRD §10 R1, §2.2). Scope at least: `lp-crypto` and the key hierarchy, the
  vault and sync formats, the LAN transport (handshake identity binding,
  record layer, listener), daemon IPC, the MCP server, the native host and
  extension, the Tauri command boundary, and (new in #47) the Windows Hello
  unlock and the in-app updater.
- [ ] **Fuzzing corpus green.** No fuzz harness exists yet. Targets: the
  KDBX, 1PUX, Bitwarden, LastPass/CSV and `.env` importers; sync segment and
  op ingest; the vault-key share blob; the native-messaging frame decoder;
  the LAN transport's record layer and message decoders
  (`lp_sync::nearby`).
  Run the corpus in CI.
- [ ] **Performance targets met** (PRD §2.2), measured by a benchmark that runs
  in CI: unlock < 1.5 s and search < 50 ms p95 with 10k items on a mid-range
  laptop; daemon idle RSS < 50 MB. No benchmark exists yet.
- [ ] **Zero known data-loss defects.** Close the sync causality follow-up for
  concurrent delete vs edit (mvp-acceptance.md §3 #7). Nothing is lost today
  (edit wins, losers are preserved), but it is a tracked pre-1.0 fix.
- [ ] **Signed releases for all platforms** — see §4. Windows code signing is
  merged (#49) and waits for SignPath to approve the project.

## 2. MVP scope — build, or formally re-scope

Each of these is in PRD §9.1's "In" list but not (fully) built. For each,
decide: **build for 1.0**, or **move to 1.x** by amending PRD §9.1 and
recording the decision in §11.

- [ ] Direct LAN / overlay live sync (Noise XX/IK + mDNS). Built for the core,
  daemon, CLI (`localpass sync nearby`), the desktop Devices screen and the
  Android in-process backend ([lan-transport.md](specs/lan-transport.md)).
  Still to do: mDNS discovery (NSD + multicast lock on Android), and verify a
  phone dialing a desktop on real Wi-Fi.
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

The reverse also needs a decision: these are **built**, but PRD §9.1 lists
them as Out of 1.0 (or the PRD does not mention them). For each, record in
PRD §11 whether it ships in 1.0 (then amend §9.1 and keep it in the §1 audit
scope) or ships marked experimental.

- [ ] File attachments (§9.1 Out; P2 in §4.1, 1.x in §9.2).
- [ ] The Android app (§9.1 Out: mobile; Future in §4.4 and §9.2).
- [ ] Windows Hello unlock (#47; §9.1 Out: biometric unlock). It also departs
  from the design in §4.3 and §6.8: instead of an OS keystore holding a
  wrapped MUK, it seals the master password under a key derived from a
  TPM-backed Windows Hello signature (`apps/desktop/src-tauri/src/hello.rs`).
- [ ] The in-app updater (#47): the app's only outbound network request, made
  only when the user checks or has opted in ([updates.md](updates.md)). The
  PRD does not mention updates.

## 3. Security follow-ups (2026-09 internal review)

The review's confirmed findings are fixed: #40 (MCP secret boundary), #41
(autofill origin matching), #42 (clipboard hygiene), #43 (signed vault-key
shares), #44 (Firefox extension id). Remaining work — details of anything
unfixed are held privately, per [SECURITY.md](../SECURITY.md):

- [x] Daemon-side **human-presence check** while an MCP session is active:
  consent and change requests need the master password
  (docs/specs/mcp-server.md §7.1). Reads stay open by design, since
  `run_with_secrets` can already inject any secret. (#46)
- [ ] Review the subsystems the internal review did not cover: Android
  storage, the SSH agent, backup/restore, the search index, `run` /
  `env export`, and (new in #47) the Windows Hello unlock and the in-app
  updater.
- [ ] Reproduce the fixed findings dynamically in a sandbox (the review was
  source-only).
- [ ] Desktop workspace `cargo deny`: clear the advisories, unmaintained and
  yanked crates, and add `publish = false` so path-dependency checks pass.
  Still failing on 2026-10-22, and CI's deny job checks only the core
  workspace:
  - 5 vulnerabilities. Three are in `zip` 4.6.1 (RUSTSEC-2026-0367/0368/0369),
    which the in-app updater brought in (#47). They are not reachable on
    Windows today: the updater checks the minisign signature before
    installing, and unzips only when the signed download is a zip, while the
    feed serves raw `.msi`/`.exe` files. Disabling the updater's default `zip`
    feature on Windows removes the crate; macOS updates would need it back.
    Two are in `quick-xml` 0.39.4 (RUSTSEC-2026-0194/0195) through Tauri's
    `plist`; the fix needs 0.41, so it waits for Tauri.
  - 6 unmaintained crates through Tauri and GTK (`unic-*`, `proc-macro-error`),
    with no upgrade available: accept them in `deny.toml` with a reason.
  - 1 yanked crate: `spin` 0.9.8 (`cargo update -p spin` gives 0.9.9).
  - 3 licences missing from the allow-list: BSL-1.0 (`clipboard-win`,
    `error-code`) and CDLA-Permissive-2.0 (`webpki-root-certs`).
- [ ] Hardening items from the review (tracked privately): webview boundary
  configuration, input size limits in parsers, and server-side enforcement of
  fill conditions.
- [ ] Origin matching: replace the built-in suffix sets with the full Public
  Suffix List (mvp-acceptance.md §1.6).
- [ ] Choose and reserve the Firefox add-on id: set
  `browser_specific_settings.gecko.id` in `apps/extension/manifest.json` and
  claim it on addons.mozilla.org.
- [ ] Manual check: Windows clipboard history exclusion and the 30 s clear
  (#42).
- [x] Manual check: a one-time `age -d` of an exported archive
  (mvp-acceptance.md §3 #9). Done 2026-10-22 with age v1.3.1, whose
  `age-plugin-batchpass` takes the passphrase non-interactively: a CLI export
  from a test profile decrypted to a tar holding `vault.json` with the
  exported item.
- [ ] Bug bounty ready for GA (PRD §10 R1).

## 4. Release engineering (PRD §6.9)

Today `desktop-release.yml` builds the Windows bundle and a signed Android
APK, plus (once the updater key is in the repo secrets) a minisign-signed feed
for the in-app updater ([updates.md](updates.md)). Windows code signing through
SignPath Foundation is wired into the workflow ([CODE_SIGNING.md](../CODE_SIGNING.md))
but stays off until the project's SignPath application is approved and its
secret and variables are set; until then the Windows installers ship unsigned.
Nothing else below exists.

- [ ] Release pipeline (`cargo-dist` or equivalent) for the CLI, daemon and
  native host on Windows, macOS (universal) and Linux (static musl).
- [ ] Desktop app: code-signed Windows MSI/NSIS; notarized macOS `.dmg`; Linux
  AppImage plus `.deb`/`.rpm`. Windows: SignPath Foundation signing is
  merged (#49) and needs the project's SignPath application approved first.
- [ ] Release signatures: Ed25519 (minisign-compatible) and Sigstore, keys
  published in the repo and on the website and cross-attested; produce and
  verify them under `lp-crypto`'s `CONTEXT_RELEASE`. The updater's minisign
  signatures (#47) cover only the desktop installers, with Tauri's key format,
  not `CONTEXT_RELEASE`.
- [ ] Updater signing key: an offline backup and a written rotation plan.
  The key lives on the maintainer's machine and in the repo secrets; losing
  it means every user reinstalls by hand once (updates.md).
- [ ] The first updater release (0.1.5) is installed by hand: 0.1.4 has no
  updater. Say so in its release notes.
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
  place of the placeholders. Still off on 2026-10-22 (the repo setting
  reports `enabled: false`).
- [ ] README: drop the work-in-progress banner and point installation at the
  signed artifacts, once §1 passes.
- [ ] Keep the Secret Key file stand-in documented as a known 1.0 deviation
  (OS keychain and hardware unlock are Phase 2). Windows Hello unlock (#47)
  seals the master password, not the Secret Key, so the stand-in is
  unchanged.
- [ ] Governance and sustainability doc (PRD §10 R9).
- [ ] mvp-acceptance.md: every row ✅ or explicitly re-scoped.
- [x] Minor: derive a TOTP item's title from the `otpauth://` issuer/account.
  Already done in the CLI (`item add --type totp --otpauth-uri` without
  `--title`) since `470ac88`, tested in `crates/lp-cli/tests/totp.rs`; the
  previous review missed it.
