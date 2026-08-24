# Agent-triggered autofill (`fill_login`)

**Status:** specification — not implemented
**Audience:** implementers of the MCP server, the native-messaging host, and the browser extension
**Related:** [mcp-server.md](mcp-server.md), PRD §4.7 (browser autofill), §4.9 (audit), §8 T7 (phishing)

---

## 1. Purpose

Let an AI coding agent log into a site on the user's behalf **without the
credential entering the agent's transcript**. The agent works by *reference* —
"fill the GitHub login in this tab" — and never receives the password.

This is the third instance of the invariant the MCP server already holds
(`mcp-server.md` §1): LocalPass does not *return* secrets to an agent, it
*spends* them. `run_with_secrets` spends a secret into a child process's
environment; `fill_login` spends one into a page's login form.

## 2. The leak surface, measured

A browser form submits the value from the page's DOM, so the value **must** land
in the DOM. The question is not whether it is present — it is whether an agent's
ordinary work puts it in the transcript. That was measured rather than assumed,
against a page holding a canary password:

| What an agent does | Password in the result? | Email in the result? |
|---|---|---|
| Accessibility-tree read (`read_page`) | **no** — labels and `type` only | **no** |
| Visible-text read (`get_page_text`) | **no** | **no** |
| Deliberate JS evaluation of `.value` | **yes** | yes |

The accessibility tree returned `textbox "Password" type="password"` with no
value node at all, and the text extraction returned only `Email Password Sign
in`. So the routine reads an agent performs to navigate a page **do not leak the
credential**. The residual surface is exactly one thing: evaluating JavaScript
that returns `.value`.

That narrows the design problem from "hide the value" (impossible) to "make sure
the agent never has a reason to read it" (achievable) — which is what §3
specifies.

## 3. Verification without reading

The agent needs to know two things: is the field empty before, and did the fill
land. Neither requires the value.

**LocalPass supplies both, so the agent never needs to touch the page.** The
extension performs the emptiness checks itself and reports booleans:

```jsonc
{
  "filled": true,
  "fields": ["username", "password"],
  "before": { "username": "empty", "password": "empty" },
  "after":  { "username": "filled", "password": "filled" },
  "tab": { "id": 42, "origin": "https://github.com" }
}
```

`empty` / `filled` are derived from `value.length > 0` **inside the extension**.
The length is not reported; no substring, prefix, or hash of the value ever
crosses. If a field was already non-empty before the fill, the extension reports
`before: "filled"` and — by default — refuses to overwrite (§6).

**The prohibition.** The `fill_login` tool description must state that the agent
must not read `input.value`, and must identify fields by label, `aria-label`, or
`name` instead. Since the before/after state is handed to it, an agent has no
legitimate reason to evaluate JavaScript against a login form.

**What that prohibition is, honestly: a contract, not a control.** LocalPass
cannot police tools it does not own — a browser-automation MCP server in the same
session can evaluate arbitrary JavaScript, and no amount of wording here stops
it. What the contract buys is real but bounded: combined with §2, it means the
credential does not reach a transcript *incidentally*, which is how transcript
leaks actually happen. It does not defend against a compromised or
prompt-injected agent that deliberately goes looking. Implementers must not
describe this as a guarantee, in docs or in tool descriptions.

## 4. What this changes about the current security model

Today the extension fills **only on a user click** in the popup
(`apps/extension/popup.js`), and there is deliberately no always-on content
script. Agent-triggered fill removes that click. That is the entire security
delta of this feature and it is paid for, not waived, by three things:

1. A **time-boxed arm window** the user opens deliberately (§7), modelled on
   device pairing (`device-pairing.md` §4).
2. **Per-item scope** — arming covers only the items the user selects, not the
   vault (§7).
3. A **notification on every fill** (§9), so a fill is never silent.

## 5. Architecture

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
extension: emptiness check -> chrome.scripting fill -> emptiness check
extension -> host -> daemon: report outcome (audit + notification)
agent <- {filled: true, before: {...}, after: {...}}       <- booleans only
```

**No new secret-bearing request is introduced.** The intent carries only ids, a
tab id, and an origin. The one request that returns a credential is the existing
`FillLogin`, unchanged, answering to the extension exactly as it does today.

### 5.1 Delivery: how the extension learns of an intent

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

## 6. Target binding: tab first, origin as fallback

The intent binds to a **tab id**, with the origin carried alongside it:

1. **Tab.** The extension redeems the intent only against the tab the agent
   named. A tab id is unambiguous when several tabs share an origin, which is
   exactly when an origin-only rule would be loosest.
2. **Origin, on that tab.** The tab's *current* origin must still equal the
   intent's origin — a tab that navigated after arming invalidates the intent
   (`origin_changed`). This is what makes a stale intent unredeemable.
3. **Daemon re-check.** The daemon re-checks the item's stored URL against the
   origin on `FillLogin`, by registrable domain
   (`crates/lp-daemon/src/origin.rs`), as it does for the human path. The caller
   cannot lie its way past this.

If the agent cannot supply a tab id, it may arm with origin only; the extension
then requires that **exactly one** tab matches the origin and refuses when
several do (`ambiguous_tab`). Falling back must never become "pick the first
match".

Check 3 is the authority. Checks 1 and 2 exist so a credential cannot be
redeemed against a page the user has since navigated away from, or a different
tab than the one the agent reasoned about.

## 7. Consent: the arm window

- **Length: 3 minutes**, matching pairing mode's precedent, then it lapses on
  its own.
- **Per-item scope.** Arming names the specific items it covers. `fill_login`
  for an item outside that set is refused (`item_not_armed`) even inside an open
  window.
- **Intent TTL: 30 seconds**, independent of and nested inside the arm window —
  long enough for a page to settle, short enough that a forgotten intent is not
  redeemable later.
- **Single use.** Taking an intent removes it. No replay.
- **One at a time.** Arming replaces any unredeemed intent; there is no queue.
- **In memory only**, like `pairing_mode_until` — never persisted.
- **A locked daemon refuses**, as every other credential path does.

## 8. Rules

- **Never submit.** The fill sets values and dispatches `input`/`change`; the
  agent may click the submit button itself, as a user would. Preserves today's
  behaviour.
- **Never overwrite a non-empty field** by default. If `before` is `filled`, the
  extension refuses (`field_not_empty`) rather than clobbering something the
  user typed. An explicit `overwrite: true` argument may override this.
- **Never report a value, a length, a prefix, or a hash** — only `empty` /
  `filled`.

## 9. Notification and audit

**Every fill raises a user-visible notification** naming the item and the
origin — never the value. A fill is never silent, which is the compensating
control for the missing user click (§4).

**Every fill is an audit event.** Redeeming an intent writes the existing
`AuditKind::ItemSecretRead` with `source = mcp`, attributed to the calling
process (§4.9 caller attribution), so agent fills appear in the Dev tab
alongside CLI and GUI activity. Arming and lapsing are recorded as their own
kinds, mirroring `PairingModeEnabled` / `PairingModeDisabled`. Every refusal in
§10 is an `AccessDenied` with its reason.

An agent that arms an intent it never redeems still leaves the arm record.

## 10. Failure taxonomy

| Condition | Answer to the agent |
|---|---|
| Agent-fill window not armed | `agent_fill_not_armed` |
| Item outside the armed set | `item_not_armed` |
| Daemon locked | `locked` |
| No item matches / ambiguous title | `item_not_found` / `ambiguous_item` |
| Item URL does not match origin | `origin_mismatch` |
| Named tab is gone | `tab_not_found` |
| Origin-only arm, several tabs match | `ambiguous_tab` |
| Tab navigated after arming | `origin_changed` |
| Intent expired before redemption | `intent_expired` |
| Target field already non-empty | `field_not_empty` |
| No extension connected / no host | `extension_unavailable` |
| No fillable password field found | `no_login_form` |

The agent must be able to distinguish "you may not" from "it did not work", so
these are separate codes rather than one generic failure.

## 11. Wire protocol

### Daemon (`crates/lp-daemon/src/protocol.rs`)

| Request | Answer | Secret? |
|---|---|---|
| `ArmFillIntent { profile, item_id, tab_id, origin }` | `FillIntentArmed { expires_in_secs }` | no |
| `TakeFillIntent { profile }` | `FillIntent { item_id, tab_id, origin, expires_in_secs }` or `NoFillIntent` | no |
| `SetAgentFillMode { profile, on, item_ids }` | `Ok` | no |
| `ReportFillOutcome { profile, item_id, outcome }` | `Ok` | no |
| `FillLogin { profile, item_id, origin }` | **existing, unchanged** | yes, to the extension only |

`Status` gains `agent_fill_secs: Option<u64>` (remaining window, `None` = off),
mirroring `pairing_mode_secs`.

### Host (`crates/lp-native-host/src/protocol.rs`)

Two request types, both non-secret: `take_fill_intent` and `fill_outcome`.
`status` relays `agent_fill_secs`. The host stays single-threaded and keyless.

### MCP (`crates/lp-cli/src/mcp/tools.rs`)

`fill_login` arguments:

- `vault` — string, optional, defaults to `personal`
- `item` — string, required: title or id
- `tab_id` — integer, optional but preferred (§6)
- `origin` — string, required: the page origin, e.g. `https://github.com`
- `overwrite` — boolean, optional, default `false` (§8)

Result: the booleans in §3. On refusal, an MCP tool error (`isError: true`)
naming the reason from §10 — never a value, never a partial credential.

## 12. Non-goals

- Filling non-browser applications — that is OS-level auto-type, a separate
  surface with no origin verification, deliberately not specified here.
- Submitting forms, solving MFA, or navigating.
- Defending against an agent that deliberately evaluates JavaScript to read the
  filled value (§3). Out of reach by construction; stated rather than implied.
- Any change to the human popup flow, which keeps its user-click gate.
