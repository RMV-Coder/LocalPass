# LocalPass Desktop (GUI)

The LocalPass desktop app — a **Tauri 2 + Svelte 5** shell for browsing and
using your vaults. Licensed **MPL-2.0** (the core/daemon is AGPL-3.0; the GUI is
separately licensed per PRD §5.6).

> This is the MVP GUI shell: unlock, browse vaults, search, view items with
> masked-by-default fields, reveal/copy on explicit action, live TOTP codes, and
> a password/passphrase generator.

## Architecture at a glance

- **The backend is a daemon client.** `src-tauri/` is a small Rust backend that
  connects to the running `localpass` **daemon** over the same-user-only local
  IPC channel (Windows named pipe / Unix socket) — exactly like the CLI and the
  browser native-messaging host. It holds **no** key material.
- **The webview renders and requests; all secret handling stays in Rust.** The
  complete bridge is the `#[tauri::command]` set in `src-tauri/src/commands.rs`.
  Secret values reach the webview **only** through `reveal_field` and `totp`
  (explicit user gesture) and the generator, are held in component-local state,
  never a store, and are cleared on navigation. `get_item` returns a **masked**
  view (secret field values stripped in `model::item_view_masked`).
- **Strict CSP, no remote content, no eval** (`src-tauri/tauri.conf.json`): only
  `'self'`; no CDNs, fonts, or telemetry. The frontend is fully self-contained.
- **Its own Cargo workspace.** `src-tauri/Cargo.toml` declares an empty
  `[workspace]` so the AGPL core's `cargo test/clippy --workspace` never build
  the GUI. It reaches the core only via the `lp-daemon` path dependency.

### Design choices worth noting

- **Generation is local.** The daemon protocol has no `generate` op, so password
  and passphrase generation are implemented in the Tauri backend
  (`src-tauri/src/generate.rs`), mirroring `lp-cli`'s `generate.rs` verbatim
  (same OS-CSPRNG source, rejection sampling, entropy accounting, EFF short
  wordlist). No new daemon surface was needed and no key material originates in
  the GUI. **No `lp-daemon` changes were required.**
- **Profile.** The GUI uses the same default profile directory as the CLI
  (`%APPDATA%\localpass`, `~/Library/Application Support/localpass`,
  `~/.local/share/localpass`). Override with the `LOCALPASS_PROFILE` env var.

### The daemon is auto-started

On launch the app calls `ensure_service`, which **starts the daemon for you** if
one isn't already running (via `lp_daemon::spawn::spawn_detached` — the same path
`localpass unlock` uses on the CLI), then shows the unlock screen. A first-time
user never has to start a daemon by hand. It locates the `localpass-daemon`
binary next to the app (in a packaged install — see [Build](#build)) or on
`PATH` (a `cargo install`ed dev setup).

## Prerequisites

- The `localpass-daemon` binary must be **findable**: bundled beside the app in a
  packaged install, or on your `PATH` in development
  (`cargo install --path crates/lp-daemon`). If it can't be found, the unlock
  screen shows install guidance instead of failing opaquely.
- Rust (stable, MSVC on Windows) and Node.js (v24+). On Windows, **WebView2**
  (bundled with Windows 11).

## Develop

```bash
cd apps/desktop
npm install
npm run tauri dev      # launches the app against the Vite dev server
```

Frontend only (no window):

```bash
npm run dev            # Vite dev server on http://localhost:1420
```

## Build

```bash
cd apps/desktop
npm run build          # Vite frontend build -> dist/
npm run bundle         # self-contained installer (recommended)
```

**`npm run bundle`** is the way to produce a shareable installer. It:

1. builds `localpass-daemon` in release and stages it as a Tauri **sidecar**
   (`scripts/prepare-sidecar.mjs` → `src-tauri/binaries/`), then
2. runs `tauri build`, which bundles the daemon **beside** the app binary and
   produces the platform installer under
   `src-tauri/target/release/bundle/` (NSIS `.exe` / MSI on Windows).

Because the daemon ships inside the install, the app's auto-start finds it as a
sibling — the installed app is fully self-contained (no separate
`localpass-daemon` needed on the target machine). Plain `npm run tauri build`
still works but **requires the sidecar to be staged first** (run the
`prepare-sidecar` step, or just use `npm run bundle`).

> The installer is **unsigned** (pre-1.0), so Windows SmartScreen shows an
> "unrecognized app" prompt — click **More info → Run anyway**. Testers should
> not store real secrets yet (see the repo `SECURITY.md`).

## Checks

```bash
npm run check          # svelte-check / tsc type-check
npm test               # Vitest unit tests (format helpers)
cd src-tauri && cargo test    # Rust command-mapping + generator tests
```

## Keyboard & accessibility

Keyboard-operable end to end: the item list is arrow-key navigable, all controls
are real semantic elements with labels, errors and copy feedback use `aria-live`,
and the app honors `prefers-color-scheme` (light/dark) and
`prefers-reduced-motion`. Targets WCAG 2.2 AA (PRD §5.5).
