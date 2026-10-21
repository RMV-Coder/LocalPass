# In-app updates and Windows Hello unlock

Two desktop-only conveniences that live entirely in the MPL GUI crate
(`apps/desktop/src-tauri`). Neither changes the daemon protocol or the AGPL
core.

## Updates

**Settings → Updates** checks for, downloads and installs a newer release.

- **Feed:** `https://github.com/RMV-Coder/LocalPass/releases/latest/download/latest.json`,
  written by `.github/workflows/desktop-release.yml` next to the installers.
  The MSI install looks up `windows-x86_64-msi`, the NSIS install
  `windows-x86_64-nsis`.
- **Trust:** every installer carries a minisign signature (`<installer>.sig`)
  that the app verifies against the public key compiled into
  `tauri.conf.json` (`plugins.updater.pubkey`) before running anything. A feed
  or installer that is not signed with the matching private key is rejected.
  This is release-artifact integrity (PRD §8 T10), not Windows code signing:
  SmartScreen still sees an unsigned installer until a code-signing certificate
  exists (release-checklist.md §4).
- **Network:** the check is the app's only outbound request. It runs when the
  user presses *Check for updates*, or at unlock only if they turned on
  *Check when LocalPass unlocks* (off by default). It sends nothing but the
  HTTPS request itself.
- **Install:** the download is verified, then just before the installer runs
  the app locks the vault, clears a copied secret, and stops the background
  service (`Lock` + `Shutdown`), because the installer must replace that
  service's executable. The installer relaunches the app; the new app starts
  the new service on its own.
- **Changelog:** the release notes (GitHub's generated notes) are shown before
  installing and again once after the first unlock on the new version. They
  are rendered as plain text; links are not followed.

### Maintainer setup (one time)

The signing keypair was generated with `npx tauri signer generate` and lives
outside the repo at `~/.tauri/localpass-updater.key` (password in the sibling
`localpass-updater.key.password.txt`), like the Android release keystore. Add
two repository secrets:

| Secret | Value |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | the contents of `localpass-updater.key` |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | the contents of the password file |

```sh
gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/localpass-updater.key
gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD < ~/.tauri/localpass-updater.key.password.txt
```

Without them the workflow builds the release exactly as before and publishes no
feed (the app reports that it could not check). Losing the private key means
shipping a release with a new public key that every user installs by hand once.

Builds from `npm run bundle` stay unsigned unless `TAURI_SIGNING_PRIVATE_KEY`
is set in the shell and `--config src-tauri/tauri.updater.conf.json` is passed.

## Windows Hello unlock

**Settings → Unlock → Windows Hello** (Windows only, and only once Hello has a
PIN). Design and threat notes are in `src-tauri/src/hello.rs`; in short:

- A Windows Hello **key credential** (RSA, TPM-backed, usable only after a
  Hello gesture) signs a random challenge; HKDF-SHA256 turns that signature into
  the key that seals the master password (XChaCha20-Poly1305, bound to the
  profile path). RSASSA-PKCS1-v1_5 is deterministic, so the same challenge
  always yields the same key.
- Turning it on requires the master password, which the service checks first
  (it counts toward the same lock-out as a presence confirmation).
- The sealed blob sits in the app's local, non-roaming data dir. It is useless
  without this machine's TPM key and is never synced.
- Unlocking replays the unsealed password into the ordinary `Unlock` request,
  inside Rust; the password never enters the webview.
- If the master password changes, the next Hello unlock fails, deletes the
  enrolment, and says so.
- macOS Touch ID and Android biometrics would implement the same four calls in
  `hello::platform`; they are not built yet.
