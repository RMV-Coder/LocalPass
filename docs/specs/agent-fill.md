# Agent-triggered autofill (`fill_login`)

**Status:** specification — not implemented
**Audience:** implementers of the MCP server, the native-messaging host, and the browser extension
**Related:** [mcp-server.md](mcp-server.md), PRD §4.7 (browser autofill), §4.9 (audit), §8 T7 (phishing)

---

## 1. Purpose

Let an AI coding agent log into a site on the user's behalf **without the
credential entering the agent's transcript**. The agent works by *reference* —
"fill the GitHub login on this page" — and never receives the password.

This is the third instance of the invariant the MCP server already holds
(`mcp-server.md` §1): LocalPass does not *return* secrets to an agent, it
*spends* them. `run_with_secrets` spends a secret into a child process's
environment; `fill_login` spends one into a page's login form.

## 2. The guarantee, and its honest limit

**Guaranteed.** The password never appears in an MCP result, an MCP log line, a
tool argument, or any daemon/host log. The agent names a vault item and an
origin; it receives `{filled: true, fields: [...]}`.

**Not guaranteed — and no design can.** A browser form submits the value from
the page's DOM, so the value *must* land in the DOM. An agent with page-read
access (a DOM dump, injected JavaScript, an accessibility tree) that chooses to
read `input.value` after the fill will see it. The same is true of any
OS-level auto-type.

So the property is **"by reference, not by value, by default"** — it removes the
credential from the agent's normal working set and from its transcript. It is
not a cryptographic barrier against an agent that goes looking. Implementers
must not describe it as one, in docs or in tool descriptions.

## 3. What this changes about the current security model

Today the extension fills **only on a user click** in the popup
(`apps/extension/popup.js`), and there is deliberately no always-on content
script. Agent-triggered fill removes that click. That is the entire security
delta of this feature and it must be paid for explicitly, not waived.

The mitigation is the pattern this codebase already uses for device pairing
(`device-pairing.md` §4): a **time-boxed arm window** the user opens
deliberately. Outside the window, `fill_login` is refused. The window lapses on
its own so an accidentally-left-on toggle cannot linger.

What an armed window does **not** grant: it never lets a credential reach a page
whose origin does not match the item (§5), never submits a form (§6), and never
returns a secret to the agent (§2).

## 4. Architecture

Native messaging is **browser-initiated**: the extension opens a port to the
host (`chrome.runtime.connectNative`), and the host is a child of the browser.
The daemon therefore *cannot* call into the extension. The intent must be
**pulled**.

```
agent -> MCP `fill_login`   ->  daemon: ARM a single-use fill intent
                                          ^ (pull)
extension (armed, polling)  ->  host  ->  daemon: TAKE the intent
extension -> host -> daemon: FillLogin{item_id, origin}    <- existing request
daemon: re-check origin <-> item URL, return {username, password} to the EXTENSION
extension: chrome.scripting fill into the active tab       <- existing mechanism
extension -> host -> daemon: report outcome (audit)
agent <- {filled: true, fields: ["username","password"]}
```

**No new secret-bearing request is introduced.** The intent carries only ids and
an origin. The one request that returns a credential is the existing
`FillLogin`, unchanged, answering to the extension exactly as it does today.

### 4.1 Delivery: how the extension learns of an intent

**Chosen: the extension polls while armed.** `status` gains `agent_fill_secs`;
the extension polls `take_fill_intent` (about once a second) **only** while
armed, and not at all otherwise. Arming is a deliberate, time-boxed user action,
so the polling is bounded to that window. Port activity also keeps the MV3
service worker alive for the window's duration, which the alternative does not
guarantee.

**Rejected: the host pushes over the existing port.** The port is bidirectional,
so this is possible, but it costs two structural changes for no security gain.
The host's single-threaded `run<R, W>` loop
(`crates/lp-native-host/src/host.rs`) would need a poller thread plus a mutex on
stdout; and `background.js` correlates replies **FIFO** against an `inflight`
queue and explicitly ignores unsolicited messages, so an unprompted push would
resolve the wrong pending request. Recorded here so the next reader does not
rediscover it as a bug.

## 5. Origin binding (two independent checks)

1. **The extension** checks the active tab's origin equals the intent's origin.
   A tab that navigated after the intent was armed invalidates it.
2. **The daemon** re-checks the item's stored URL against the origin on
   `FillLogin`, by registrable domain (`crates/lp-daemon/src/origin.rs`), as it
   does for the human path. The caller cannot lie its way past this.

Both must pass. Check 2 is the authority; check 1 exists so a stale intent
cannot be redeemed against a page the user has since navigated away from.

## 6. Rules

- **Never submit.** The fill sets values and dispatches `input`/`change`; the
  agent may click the submit button itself, as a user would. This preserves
  today's behaviour.
- **Single use.** Taking an intent removes it. No replay.
- **Short TTL.** An intent expires quickly (§10) independently of the arm
  window.
- **One at a time.** Arming replaces any unredeemed intent; there is no queue.
- **A locked daemon refuses**, as every other credential path does.

## 7. Wire protocol

### Daemon (`crates/lp-daemon/src/protocol.rs`)

| Request | Answer | Secret? |
|---|---|---|
| `ArmFillIntent { profile, item_id, origin }` | `FillIntentArmed { expires_in_secs }` | no |
| `TakeFillIntent { profile }` | `FillIntent { item_id, origin, expires_in_secs }` or `NoFillIntent` | no |
| `SetAgentFillMode { profile, on }` | `Ok` | no |
| `FillLogin { profile, item_id, origin }` | **existing, unchanged** | yes, to the extension only |

`Status` gains `agent_fill_secs: Option<u64>` (remaining window, `None` = off),
mirroring `pairing_mode_secs`.

State lives **in memory only**, like `pairing_mode_until` — never persisted.

### Host (`crates/lp-native-host/src/protocol.rs`)

Two request types, both non-secret: `take_fill_intent` and `fill_outcome`.
`status` relays `agent_fill_secs`. The host stays single-threaded and keyless.

### MCP (`crates/lp-cli/src/mcp/tools.rs`)

`fill_login` arguments:

- `vault` — string, optional, defaults to `personal`
- `item` — string, required: title or id
- `origin` — string, required: the page origin, e.g. `https://github.com/login`

Result: `{ "filled": true, "fields": ["username","password"], "origin": "..." }`.
On refusal, an MCP tool error (`isError: true`) naming the reason from §9 —
never a value, never a partial credential.

The tool description must state that the value lands in the page DOM (§2), so a
model reasoning about its own capabilities is not misled.

## 8. Audit

Redeeming an intent writes the existing `AuditKind::ItemSecretRead` with
`source = mcp`, attributed to the calling process (§4.9 caller attribution), so
every agent-triggered fill is visible in the Dev tab alongside CLI and GUI
activity. Arming and lapsing are recorded as their own kinds, mirroring
`PairingModeEnabled` / `PairingModeDisabled`. A refusal is an `AccessDenied`.

An agent that arms an intent it never redeems still leaves the arm record.

## 9. Failure taxonomy

| Condition | Answer to the agent |
|---|---|
| Agent-fill window not armed | `agent_fill_not_armed` — the user must arm it |
| Daemon locked | `locked` |
| No item matches / ambiguous title | `item_not_found` / `ambiguous_item` |
| Item URL does not match origin | `origin_mismatch` |
| No extension connected / no host | `extension_unavailable` |
| Intent expired before redemption | `intent_expired` |
| Active tab navigated away | `origin_changed` |
| No fillable password field found | `no_login_form` |

The agent must be able to distinguish "you may not" from "it did not work", so
these are separate codes rather than one generic failure.

## 10. Open decisions

These need the owner's call before implementation:

1. **Arm window length.** Pairing mode uses 3 minutes. A single login is
   shorter; an agent doing several logins wants longer. Proposal: 3 minutes,
   matching the existing precedent.
2. **Intent TTL.** Proposal: 30 seconds — long enough for a page to settle,
   short enough that a forgotten intent is not redeemable later.
3. **Per-fill visibility.** Should each agent fill raise a notification, or is
   the audit log enough? A notification is honest but noisy during a login run.
4. **Scope of the arm window.** Any item, or only items the user selects when
   arming? Per-item is stronger and more tedious.
5. **Tab binding.** This spec binds to origin, not tab id. Binding to a tab id
   is tighter but couples the MCP surface to browser state the agent must
   discover first.

## 11. Non-goals

- Filling non-browser applications — that is OS-level auto-type, a separate
  surface with no origin verification, deliberately not specified here.
- Submitting forms, solving MFA, or navigating.
- Protecting against an agent that reads the DOM after the fill (§2).
- Any change to the human popup flow, which keeps its user-click gate.
