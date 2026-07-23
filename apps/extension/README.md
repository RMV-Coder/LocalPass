# LocalPass Browser Extension

A Manifest V3 browser extension that autofills logins from your **local, offline**
LocalPass vault. It talks to the LocalPass desktop app over a native-messaging
host (`com.localpass.host`) — there is **no** network, no localhost port, and no
cloud. The extension holds no keys and never sees a password until you click a
specific login to fill.

Licensed **MPL-2.0** (the same license as the LocalPass desktop GUI).

## Install (load unpacked)

1. Open your browser's extensions page:
   - Chrome / Edge / Chromium: `chrome://extensions`
   - Firefox: `about:debugging#/runtime/this-firefox` (Load Temporary Add-on)
2. Enable **Developer mode**.
3. Click **Load unpacked** and select this folder (`apps/extension/`).
4. Copy the **Extension ID** the browser generates for the loaded extension.
   You need it in the next step so the native host will accept the connection.

## Register the native-messaging host for this extension ID

The host manifest must allowlist your extension's ID, otherwise the browser
refuses the native connection. Register it with the LocalPass CLI:

```
localpass browser register --chrome --extension-id <ID>
```

- Use `--firefox` (with the Firefox add-on ID) instead of/in addition to
  `--chrome`, or `--all` for every supported browser. With no browser flag it
  targets all supported browsers.
- If the `localpass-native-host` binary isn't a sibling of the `localpass`
  executable, pin it explicitly: `--host-path <PATH>`.
- To confirm the exact flags on your build: `localpass browser register --help`
  (and `localpass browser --help`).

> Note on the Firefox ID: Chrome derives the extension ID from the unpacked
> folder, while Firefox uses the add-on ID from the manifest / signing. Register
> with the ID your browser actually shows on its extensions page.

To undo: `localpass browser unregister --all`.

## Use

1. Make sure the **LocalPass desktop app / daemon is running** and the vault is
   **unlocked** (the extension cannot unlock it — only the desktop app / CLI can).
2. Navigate to a site's login page.
3. Click the LocalPass toolbar icon. The popup shows the saved logins for the
   current site.
4. Click a login. LocalPass fetches that one credential and fills the username
   and password fields on the page. It **never submits** the form — you review
   and submit yourself.

If the popup says:

- **"LocalPass isn't running. Start the desktop app."** — the daemon/host is not
  reachable. Start the desktop app.
- **"Vault locked — unlock LocalPass to autofill."** — unlock the vault in the
  desktop app or CLI.
- **"native host unavailable — is LocalPass installed and registered?"** — the
  native-messaging host isn't registered for this extension ID; re-run the
  `localpass browser register` step above with the correct ID.

## How it works / security

- **The extension holds no keys and stores no secrets.** There is no
  `chrome.storage` of credentials, no globals that retain a password.
- **Candidate lists carry no passwords.** When you open the popup, the extension
  asks the host for *non-secret* descriptors only (title, username, vault) for
  the current page origin.
- **A password is fetched for exactly one item — the one you click** — and only
  after the LocalPass daemon **re-checks the page origin against the stored URL**
  server-side. If they don't match, the fill is refused (`origin_mismatch`).
- **The password is used transiently.** It is passed straight into the page's
  fields via the native value setter (dispatching `input`/`change` so web apps
  notice) and is never logged or kept.
- **Nothing is auto-filled and nothing is auto-submitted.** Filling happens only
  on your explicit click, injected via `chrome.scripting.executeScript` on the
  `activeTab` — there are no always-on content scripts and no `<all_urls>` host
  permission.
- **No data leaves your machine.** No network requests, no CDNs, fonts,
  analytics, or telemetry of any kind. Everything is self-contained.

## Permissions

| Permission       | Why                                                             |
| ---------------- | -------------------------------------------------------------- |
| `nativeMessaging`| Talk to the local `com.localpass.host` native host.            |
| `activeTab`      | Read the current tab's URL and inject the fill on your click.  |
| `scripting`      | Inject the one-shot fill function into the active tab.         |
| `tabs`           | Read the active tab's URL to derive its origin.                |

## Files

- `manifest.json` — MV3 manifest (minimal permissions, no broad content scripts).
- `background.js` — service worker; owns the persistent native-messaging port.
- `popup.html` / `popup.css` / `popup.js` — the popup UI and fill logic.
- `icons/` — toolbar/action icons (16/32/48/128 px).
