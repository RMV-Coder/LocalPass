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

## Agent-triggered autofill

An AI agent can ask LocalPass to fill a login **without ever receiving the
password** (see `docs/specs/agent-fill.md`). The agent works by reference — "fill
the GitHub login in this tab" — and gets back booleans, never a value.

How the extension participates:

1. You **arm** a 3-minute, per-item agent-fill window in the desktop app. Until
   you do, the extension does not poll for intents at all.
2. While the window is open, the extension asks the host for a pending intent
   about once a second. Almost every poll gets "nothing".
3. When an intent arrives it is redeemed **only** against the tab the agent
   named, and only if that tab's *current* origin still matches. With no tab id,
   exactly one tab must match the origin — several is a refusal, never a guess.
4. The **password field must be empty**. A password already in the box is
   refused (`field_not_empty`) rather than clobbered, unless the agent explicitly
   asked to overwrite. A username already in the box does not block the fill — it
   is not a secret, and the item's username is the account you chose to log in
   as — so it is overwritten as normal. Both fields' before/after states are
   reported either way.
5. The credential comes from the same `fill` request the popup uses, is injected,
   and is gone. The form is **not** submitted.
6. **Every agent fill raises a notification** naming the item and the origin —
   never the value. That is the compensating control for the missing click, so it
   is not skippable; if the notification API fails, the toolbar badge is used
   instead.

The extension reports back only `empty` / `filled` per field. No value, length,
prefix, or hash of a credential is ever reported, logged, or returned — the
report type on the LocalPass side has no free-form string at all, so such a body
would fail to parse rather than be filtered.

**Page access, one site at a time.** The click-gated popup flow injects under
`activeTab`. An agent fill has no click to ride on, so it needs a page-access
grant, declared as an *optional* host permission and requested from a button that
appears in the popup while a window is armed.

What is actually requested is the **single origin in front of you** —
`https://github.com/*` — never the broad `http(s)://*` pattern the manifest
merely declares as requestable. The browser prompt therefore reads "read and
change your data on github.com", not "on all websites", and an agent fill checks
that same per-origin grant before it touches a page. Until you grant it for a
site, agent fills there are refused (`page_access_denied`, and the notification
says so); the popup flow is unaffected either way.

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
- **Nothing is auto-submitted, ever** — not by the popup, not by an agent fill.
  There are still no always-on content scripts, and no host permission is granted
  at install: the popup fill injects on your click under `activeTab`, and the
  only other grant is the *optional*, **per-site** one above, which you grant
  deliberately and which is used solely to redeem an intent you armed.
- **No data leaves your machine.** No network requests, no CDNs, fonts,
  analytics, or telemetry of any kind. Everything is self-contained.

## Permissions

| Permission       | Why                                                             |
| ---------------- | -------------------------------------------------------------- |
| `nativeMessaging`| Talk to the local `com.localpass.host` native host.            |
| `activeTab`      | Read the current tab's URL and inject the fill on your click.  |
| `scripting`      | Inject the one-shot fill function into the active tab.         |
| `tabs`           | Read the active tab's URL to derive its origin.                |
| `notifications`  | The "LocalPass filled a login" notice on every agent fill.     |
| `alarms`         | Wake the MV3 worker to notice an armed agent-fill window.      |

| Optional permission         | Why                                                  |
| --------------------------- | ---------------------------------------------------- |
| `http://*/*`, `https://*/*` | **Declared, not requested.** The sites cannot be enumerated at build time, so this says what *may* be asked for. What is actually requested — and checked before an agent fill — is one origin at a time (`https://github.com/*`), from the popup, never at install, and never needed for the popup's own fill. |

## Files

- `manifest.json` — MV3 manifest (minimal permissions, no broad content scripts).
- `background.js` — service worker; owns the persistent native-messaging port.
- `agentfill.js` — agent-fill controller: polls for intents while armed, does the
  before/after emptiness checks, reports the outcome, notifies.
- `popup.html` / `popup.css` / `popup.js` — the popup UI and fill logic.
- `icons/` — toolbar/action icons (16/32/48/128 px).
