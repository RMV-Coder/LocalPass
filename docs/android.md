# Android port — architecture & setup plan

Status: **planned, not yet built.** This document is the groundwork for an
Android (and, later, iOS) companion app. It captures the one non-obvious
architectural decision the port hinges on, the exact toolchain setup, and the
step-by-step to stand up a working scaffold. Mobile is a PRD "Future" item
(§9.2); this is the on-ramp.

## TL;DR

- The desktop GUI (`apps/desktop`) is **Tauri 2 + Svelte 5**, and Tauri 2
  targets Android/iOS. The Svelte UI can be reused almost verbatim.
- The one thing that must change: on desktop the backend is a **daemon client**
  (every `#[tauri::command]` does `daemon::call(...)`). **Android has no
  background daemon / IPC**, so the mobile backend must **embed `lp-vault` /
  `lp-crypto` in-process** and hold the unlocked `Session` itself.
- The Tauri mobile entry point already exists: `run()` in
  `apps/desktop/src-tauri/src/lib.rs` is annotated
  `#[cfg_attr(mobile, tauri::mobile_entry_point)]`.
- A **building** scaffold needs the Android toolchain (SDK + NDK + JDK), which
  is a large, interactive install — see [Prerequisites](#prerequisites).

## Why the backend must change for mobile

On desktop, keys live in the long-lived `localpass-daemon` process; the GUI and
CLI are thin clients that talk to it over a same-user-only named pipe / UDS.
That model does not exist on Android:

- there is no persistent user-level background service with the same lifetime
  guarantees, and no named-pipe/UDS peer-credential channel;
- the OS may kill and restart the app process at will.

So on mobile the **app process is the vault**: the Tauri Rust backend opens the
account store and vault files directly (via `lp-vault`), derives the key
hierarchy (`lp-crypto`), and holds the `Session` in memory with an app-lifecycle
auto-lock (lock on background / after idle). This is the same in-process model
the CLI already uses in its **`--no-daemon` / direct** path — so the logic
exists; it just needs to be reachable from the Tauri backend behind a `cfg`.

### The plan: a `Backend` split behind the command layer

Introduce one seam so the `#[tauri::command]` functions don't care how they're
served:

```
             ┌────────────── #[tauri::command] fns (unchanged surface) ──────────────┐
             │  status / unlock / list_items / get_item / reveal_field / password_    │
             │  health / create_item / … — call `backend()` instead of `daemon::call` │
             └───────────────────────────────────────────────────────────────────────┘
                                   │
             ┌─────────────────────┴─────────────────────┐
   #[cfg(not(mobile))]                          #[cfg(mobile)]
   DaemonBackend (today's daemon::call)         InProcessBackend
                                                  holds Mutex<Option<Session>>,
                                                  opens vaults via lp-vault,
                                                  reuses render::* + model::* masking
```

Crucially, the **secret boundary is identical**: the in-process backend returns
the exact same masked `model::*` view types, so the webview still only ever sees
secrets through `reveal_field` / `totp`. The `render::*` and
`model::item_view_masked` code is reused unchanged. The Watchtower
(`password_health`) and every other command map straight over.

Scope of the refactor (desktop stays byte-for-byte behaviour):

1. Add `apps/desktop/src-tauri/src/backend/mod.rs` with a `Backend` trait (or a
   thin enum) exposing the operations the commands need.
2. `daemon.rs` becomes `backend::daemon` (desktop default).
3. New `backend::inprocess` (mobile): a `Mutex<Option<lp_vault::Session>>`, an
   `unlock` that runs the KDF, and vault-open helpers — mirroring `lp-cli`'s
   direct path. Gate `lp-vault`/`lp-crypto` as **mobile-only** dependencies so
   the desktop client stays daemon-only (and the AGPL core is not linked into
   the desktop MPL binary).
4. Commands call `backend::current()` instead of `daemon::call`.

This refactor is testable on desktop (behind a temporary feature flag) **before**
any device is involved, which is the recommended first step.

## Prerequisites (the toolchain that must be installed first)

`tauri android init` / `dev` / `build` will not run without all of these:

- **Android Studio** (for the SDK manager + emulator) or the command-line SDK
  tools, with **Platform SDK API 34+** and **Build-Tools**.
- **Android NDK** (r26+). Set `NDK_HOME` (or `ANDROID_NDK_ROOT`).
- **JDK 17** (Android Gradle Plugin requirement). Set `JAVA_HOME`.
- `ANDROID_HOME` pointing at the SDK.
- Rust Android targets:
  ```sh
  rustup target add aarch64-linux-android armv7-linux-androideabi \
      i686-linux-android x86_64-linux-android
  ```
- The Tauri CLI (already present: `tauri-cli 2.11.4`).

> On the current dev machine none of these are installed (no `ANDROID_HOME`, no
> NDK, no JDK, no Android Rust targets), which is why the scaffold has not been
> generated here — it would fail immediately at `tauri android init`.

## Standing up the scaffold (once the toolchain is present)

```sh
cd apps/desktop

# 1. Generate the Android Gradle project under src-tauri/gen/android.
npm run tauri android init

# 2. Run on an emulator or attached device (reuses the Svelte dev server).
npm run tauri android dev

# 3. Build an APK/AAB.
npm run tauri android build
```

`tauri android init` creates `src-tauri/gen/android/` (Gradle, a Kotlin
`MainActivity` wrapper, and manifest). Commit that directory. Add a
`bundle > android` block to `tauri.conf.json` for the app id / min-SDK when
customizing.

## Mobile-specific work beyond the scaffold

- **Storage location.** Use the app's private files dir for the profile
  (`account.localpass` + `*.vault`), not the desktop `ProjectDirs` path.
- **Secret Key.** The desktop stores it in a `secret-key` file; on mobile prefer
  the **Android Keystore** (hardware-backed) for the Secret Key / a device
  unlock key — this is the mobile analogue of the P2 OS-keychain item.
- **Biometric unlock.** `androidx.biometric` → unlock the in-process session.
- **Auto-lock on background.** Lock (zeroize the `Session`) on
  `onStop`/`onPause`, not just idle.
- **Sync.** File-based sync via the Storage Access Framework (a user-picked
  folder / cloud provider) is the natural first transport; the op-log engine is
  transport-agnostic and reused unchanged.
- **Signing & Play Store.** A release keystore + Play App Signing; out of scope
  until the desktop 1.0 gates (audit, format freeze) pass.

## Suggested sequencing

1. **In-process backend refactor** — ✅ **done** (2026-07-14). `src-tauri/src/daemon.rs`
   now has two compile-time backends behind the unchanged `call(&Request) ->
   Response` seam: the desktop daemon client (`cfg(not(any(mobile, feature =
   "inprocess")))`) and an in-process backend (`cfg(any(mobile, feature =
   "inprocess"))`) that runs `lp_daemon::engine::handle` against a `State` held
   in the app process — the same audited engine, no IPC, no duplicated logic. The
   mobile `setup()` hook points `LOCALPASS_PROFILE` at the Android app-private
   dir. **Verified on desktop** via `--features inprocess`: a create-account →
   unlock → list-vaults integration test passes, and the desktop IPC build is
   byte-for-byte unchanged. Test/compile the mobile path on desktop with:
   ```sh
   cd apps/desktop/src-tauri && cargo test --features inprocess
   ```
2. **Toolchain + `tauri android init`** — ✅ **done**. Scaffold generates under
   `src-tauri/gen/android/` (gitignored; regenerate per-machine). Windows note:
   use **WHPX** (Windows Hypervisor Platform), not AEHD, for the emulator — AEHD
   is Intel-only and conflicts with the Win11 Hyper-V stack; a physical device
   over USB avoids the emulator entirely. `rustup target add` must be **one line**
   (PowerShell has no `\` continuation).
3. **Runs on a real device** — ✅ **done** (2026-07-15). `tauri android build
   --debug --apk --target aarch64` produces an APK; installed via `adb install`
   on a physical arm64 device (Redmi Note 10). **Verified end-to-end on-device:**
   the Svelte UI renders, and the in-process backend created an account — it ran
   the real Argon2id KDF on the phone, generated the Secret Key, and wrote the
   account store to the Android app-private dir (`/data/user/0/org.localpass.desktop`),
   with **no daemon**. See [Windows build gotchas](#windows-build-gotchas).
4. Keystore-backed Secret Key + biometric unlock.
5. SAF-based sync; then release signing.

## Live-reload dev server on a physical device

`tauri android dev` serves the Svelte UI from the dev machine and the app loads
it over the network. Two things must line up on a USB-attached phone:

- **The phone often can't reach the PC over the LAN.** Many phone/router setups
  (mobile hotspots, "AP/client isolation") drop device→PC traffic — `ping <PC>`
  from the phone fails. Don't rely on the auto-detected LAN IP. Instead force
  loopback and tunnel the ports over USB:
  ```sh
  adb reverse tcp:1420 tcp:1420   # dev server
  adb reverse tcp:1421 tcp:1421   # HMR websocket
  npx tauri android dev --host 127.0.0.1
  ```
  `--host` sets `TAURI_DEV_HOST`, which `vite.config.ts` reads to bind the dev
  server and point HMR at that host (see the `host`/`hmr` block there).
- **Exclude `src-tauri/**` from Vite's watcher.** The Android build writes churn
  under `src-tauri/gen/android/build`, which otherwise triggers a full webview
  reload. `vite.config.ts` sets `server.watch.ignored: ["**/src-tauri/**"]`.
- If a build dies mid-run, a **stale Gradle daemon** can hold a file lock
  (`Blocking waiting for file lock on Android`). Clear it with
  `gen/android/gradlew.bat --stop` (or kill stray `java` processes).

## Storage: the debug APK is too big for a full phone

The debug APK is ~**169 MB** (the debug `.so` carries full debuginfo). On a
near-full device Android rejects the install with
`INSTALL_FAILED_INSUFFICIENT_STORAGE` (it needs several × the APK size
transiently). For on-device testing without freeing space, build a **stripped
release APK** (`[profile.release]` has `strip="symbols"`, `lto="thin"` → tens of
MB) and sign it with the **existing debug keystore** so it reinstalls in place
(same signer ⇒ no uninstall, on-device account preserved):

```sh
npx tauri android build --apk --target aarch64        # -> app-arm64-release-unsigned.apk
BT="$LOCALAPPDATA/Android/Sdk/build-tools/36.0.0"
"$BT/zipalign.exe" -f 4 app-arm64-release-unsigned.apk aligned.apk
"$BT/apksigner.bat" sign --ks ~/.android/debug.keystore \
    --ks-pass pass:android --ks-key-alias androiddebugkey --key-pass pass:android aligned.apk
adb install -r aligned.apk
```

## App icon (all platforms from one source)

The canonical logo is `apps/desktop/app-icon.png` (1024² padlock). Regenerate
every platform's icons — desktop `.ico`/`.png`, the `.exe`/`.msi` installer, iOS
AppIcons, and the Android launcher mipmaps — with one command:

```sh
cd apps/desktop && npx tauri icon app-icon.png
```

`icons/` is tracked; the Android mipmaps land in the **gitignored** `gen/android`
tree, so re-run `tauri icon` after `android init`. The Android adaptive-icon
background color (`gen/.../res/values/ic_launcher_background.xml`) is set to the
logo's navy `#0F2A2E` so the padlock sits seamlessly under the launcher mask
(the default `#fff` shows white slivers at the mask edge).

## Windows build gotchas

Three things bit us on Windows 11; all are one-time fixes:

1. **Drop the daemon sidecar on Android.** The desktop bundle ships
   `localpass-daemon` via `bundle.externalBin`, but mobile has no daemon, so the
   Android build fails looking for `binaries/localpass-daemon-aarch64-linux-android`.
   Fixed with `src-tauri/tauri.android.conf.json` (a platform-override merged
   automatically for `android`) that sets `bundle.externalBin: []`.
2. **Enable Developer Mode** (Settings → For developers). Tauri **symlinks** the
   built `.so` into the APK's `jniLibs`, and Windows blocks symlink creation
   without Developer Mode (`Creation symbolic link is not allowed for this
   system`). No admin/reboot needed.
3. **Use JDK 17, not Android Studio's JBR.** Recent Android Studio bundles a
   **JDK 25** JBR, which the scaffold's Gradle 8.14 can't run on
   (`Unsupported class file major version 69`). Install a JDK 17 (e.g. Temurin)
   and point `JAVA_HOME` at it for CLI Android builds — Android Studio keeps
   using its own JBR internally, so this doesn't affect the IDE.

## References

- Tauri 2 mobile: <https://v2.tauri.app/develop/> (Android/iOS guides).
- The CLI's in-process/direct path (`--no-daemon`) is the reference
  implementation for the mobile backend: `crates/lp-cli` (`unlock`, `resolve`,
  and the `*_direct` command paths).
- Secret boundary the mobile backend must preserve:
  `apps/desktop/src-tauri/src/model.rs` (`item_view_masked`).
