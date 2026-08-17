# LocalPass MCP Server — tools, arguments, and the redaction contract

Status: **implemented** in `lp-cli` (`localpass mcp`, module `lp-cli/src/mcp`).
Covers the Model Context Protocol surface LocalPass exposes to AI coding agents.
It changes **no** cryptography, adds **no** storage format, and introduces **no**
new trust boundary: the server is an ordinary CLI subcommand and therefore an
ordinary daemon client (`architecture.md` §3).

## Scope

An agent working in a repository routinely needs a secret — a database URL to
run a migration, an API token to hit a staging endpoint, a 2FA code to finish a
login. Today it either gets a `.env` file (secrets on disk, forever) or the
human pastes the value into the chat (secrets in the transcript, forever). This
spec covers a third option: the agent gets a **capability to spend** the secret
without a **copy** of it.

Non-goals are in §8.

---

## 1. The invariant

> **No MCP tool result ever contains a raw secret value.**

Everything an MCP tool returns is copied verbatim into the agent's transcript.
That transcript is logged, replayed on resume, summarized into other contexts,
and — for hosted models — sent to a third party. A password that reaches a
transcript must be treated as **disclosed**, permanently, with no way to recall
it. So the server never returns secrets; it **spends** them.

The one place a plaintext value goes is a child process's environment, via
`run_with_secrets` (§5.4). That is the same disclosure `localpass run` already
makes, and it is bounded: the value lives in one process's environment for one
command's lifetime, and never lands on disk or in a transcript.

### 1.1 How the invariant is enforced (three layers)

1. **Structural masking.** An item leaves the backend as `mask::ItemView`, which
   is deliberately **not** `Serialize`. The only way to obtain a serializable
   item is `mask::item_view_masked`, which consumes the view and drops every
   secret value. A call site cannot forget to mask, because it is never handed a
   maskable-but-unmasked serializable shape. This is the same choke-point
   pattern as the desktop GUI's `model::item_view_masked` (`LESSONS.md`),
   reimplemented independently — the AGPL core must not depend on the MPL-2.0
   app (PRD §5.6).
2. **Masked at the source too.** On the daemon route items are fetched with
   `reveal = false`, so the daemon masks them before the values cross the IPC
   pipe. The choke point then runs over already-masked values. Two independent
   layers, one code path.
3. **Output redaction.** `run_with_secrets` scrubs every injected value out of
   the child's captured stdout/stderr (§6) and then **re-checks** that none
   survived; if any did, it refuses to build a result at all.

### 1.2 The one deliberate exception

`totp_code` returns a six-digit code. A code is a **short-lived derivative** of
the seed, not the seed: it expires within the current 30-second window, and the
seed cannot be recovered from any number of observed codes. The seed itself
never leaves the vault (on the daemon route it never leaves the daemon). This
matches the existing `localpass totp` and daemon `Request::Totp` posture.

---

## 2. Transport

MCP **stdio transport**: newline-delimited JSON-RPC 2.0 on the process's stdin
and stdout, one JSON value per line, no embedded newlines.

- **stdout carries protocol frames and nothing else.** No part of the MCP module
  calls `println!`.
- **All logging goes to stderr**, through one function, and carries method and
  tool names and counts only — never an argument value, never a secret, never
  the master password.
- **stdin EOF is a clean shutdown** (exit 0). That is how an MCP host stops a
  stdio server.

Protocol version: **`2025-06-18`**. On `initialize`, a `protocolVersion` the
server supports is echoed back verbatim; anything else is answered with
`2025-06-18` and the client decides whether to proceed. Supported set:
`2025-06-18`, `2025-03-26`, `2024-11-05`.

The protocol is implemented by hand on `serde_json`. No MCP SDK is taken as a
dependency: the required subset is small and well specified, and the repo's
dependency policy prefers a focused hand-written implementation over a large
transitive tree (the KDBX decision, `LESSONS.md`).

### 2.1 Methods

| Method | Behaviour |
|--------|-----------|
| `initialize` | Version negotiation + `{ tools: { listChanged: false } }` capability + `serverInfo` + human-readable `instructions`. |
| `notifications/initialized` | Accepted; **never answered** (a JSON-RPC notification has no `id`). |
| `ping` | `{}`. |
| `tools/list` | The five tools of §5 with their JSON Schemas. |
| `tools/call` | Dispatch; see §4. |
| anything else | JSON-RPC error `-32601`. |

Frames that are not valid JSON get `-32700` with `id: null`; a request missing
`method` gets `-32600`; `tools/call` without a string `name` gets `-32602`.

---

## 3. Unlock and session lifetime

The server acquires a session **once at startup**, through the same
`daemonctl::route` matrix every other subcommand uses (`architecture.md` §3):

| Condition | Route |
|-----------|-------|
| daemon running **and** unlocked for this profile, no `--no-daemon` | **proxy** — reads go over the same-user-only IPC channel; the server holds no keys |
| otherwise (no daemon / locked / wrong profile / `--no-daemon`) | **direct** — the server unlocks itself and holds an `lp_vault::Session` |

`--profile`, `--no-daemon`, `--password-stdin` and `LOCALPASS_PASSWORD` behave
exactly as documented for every other command. It then serves until stdin EOF.

There is **no MCP tool to unlock, lock, create, edit, delete, or export**. The
surface is read-plus-inject only, by construction — an agent that is confused,
prompt-injected, or adversarial cannot mutate a vault through it.

Recommended posture: run `localpass unlock` first so the server takes the proxy
route and never holds key material itself.

---

## 4. Tool results and errors

Every tool returns **one JSON text content block**: a `content` array of exactly
one `{ "type": "text", "text": "<pretty-printed JSON>" }`.

```json
{ "content": [ { "type": "text", "text": "{\n  \"vaults\": [...]\n}" } ],
  "isError": false }
```

A **tool failure** (unknown vault or item, unresolvable reference, wrong item
type, spawn failure, unknown tool name) is a normal result with
`"isError": true` and a body of `{"error": "<message>"}` — per MCP, a tool
failure is data the model can react to, not a transport fault. Only a malformed
frame or an unknown *method* is a JSON-RPC error (§2.1).

Error messages come from the CLI's existing error taxonomy
(`lp-cli/src/error.rs`), which is already required never to contain a secret
value.

---

## 5. The tools

`vault` is optional everywhere and defaults to `personal`, matching the CLI's
`--vault` flag.

### 5.1 `list_vaults`

Arguments: none.

```json
{ "vaults": [ { "id": "<uuid>", "name": "personal" } ] }
```

No secret.

### 5.2 `list_items`

| Argument | Type | Required | Default |
|----------|------|----------|---------|
| `vault` | string | no | `personal` |

```json
{ "vault": "personal",
  "items": [ { "id": "<uuid>", "title": "Prod DB", "type": "login",
               "version": 1, "created_at": 0, "updated_at": 0,
               "tags": [], "favorite": false, "notes": "",
               "fields": [ { "name": "username", "secret": false, "value": "alice" },
                           { "name": "password", "secret": true,  "value": "••••••" } ] } ] }
```

Field **names** are the point: they tell the agent what references exist. Secret
**values** are the mask. An `env_set` item's entry keys are its field names, so
an agent can discover `APP_SECRET` without ever seeing it.

### 5.3 `get_item`

| Argument | Type | Required | Default |
|----------|------|----------|---------|
| `vault` | string | no | `personal` |
| `item` | string | **yes** | — |

`item` is a title or a hyphenated id. Returns `{ "vault": ..., "item": <the
same masked shape as §5.2> }`.

There is deliberately **no `reveal` argument**. `item get --reveal` exists for a
human at a terminal; the equivalent for an agent would be the whole problem this
surface avoids.

Empty secret values are masked too, not rendered as `""` — an
empty-versus-non-empty distinction is a (small) oracle and an agent has no use
for it. This is the one place the MCP masking is stricter than `item get`'s.

### 5.4 `run_with_secrets`

| Argument | Type | Required | Default |
|----------|------|----------|---------|
| `vault` | string | no | `personal` |
| `item` | string | no | — |
| `env` | object (VAR → reference) | no | — |
| `command` | string **or** array of strings | **yes** | — |
| `cwd` | string | no | inherited |
| `timeout_secs` | integer 1..3600 | no | `120` |

Injection sources, layered in this order (later wins on a name clash), matching
`localpass run`'s precedence:

1. `item` — an `env_set` item; **every** entry is injected under its own key.
2. `env` — explicit `VAR` → `localpass://<vault>/<item>/<field>` (or the `op://`
   alias) mappings, resolved through the same reference resolver `run` uses.

`command` is **not run through a shell**. An array is used verbatim as
`[program, ...args]`. A string is split on whitespace honouring `'` and `"`
grouping; backslash is **not** an escape (it is a Windows path separator). On
Windows the program is resolved through `PATH` × `PATHEXT` exactly as
`localpass run` does, so `npm` finds `npm.cmd`.

Child environment: this process's environment, **minus `LOCALPASS_PASSWORD`**,
plus the injected variables. Stripping the password variable is stricter than
`localpass run`, which inherits it harmlessly because its child writes to the
user's own terminal; here the child's output is captured and returned to a
model, so a child running `env` must not be able to read the master password
back out.

The child gets a null stdin (an MCP tool call is non-interactive), piped
stdout/stderr, and a wall-clock budget. Past `timeout_secs` it is killed and
`timed_out` is `true`.

```json
{ "exit_code": 0,
  "timed_out": false,
  "stdout": "connected as [REDACTED:DATABASE_URL]\n",
  "stderr": "",
  "injected_vars": ["DATABASE_URL"],
  "redaction": { "marker": "[REDACTED:<VAR>]", "min_value_length": 4 } }
```

`exit_code` is `null` when the child was killed or died by signal.

### 5.5 `totp_code`

| Argument | Type | Required | Default |
|----------|------|----------|---------|
| `vault` | string | no | `personal` |
| `item` | string | **yes** | — |

```json
{ "code": "123456", "seconds_remaining": 17,
  "period": 30, "digits": 6, "algo": "SHA1" }
```

A non-`totp` item is a tool error. See §1.2 for why a code — and only a code —
may cross this boundary.

---

## 6. The redaction contract

Applied to **both** captured streams of every `run_with_secrets` call, before
the result is built.

1. For each injected `(VAR, value)`, **every** occurrence of `value` in the text
   is replaced by `[REDACTED:VAR]`.
2. **Length threshold.** Values shorter than **4 characters** are not redacted.
   A one- or two-character value (`0`, `1`, `on`) appears constantly in ordinary
   output; redacting it would shred the output into noise while protecting
   nothing an attacker could not guess in a handful of tries. `LOG_LEVEL=1` stays
   readable; `AWS_SECRET_ACCESS_KEY=…` does not survive. The threshold is
   reported in the result as `redaction.min_value_length`, so a caller never has
   to guess it.
3. **Longest first.** Values are applied in descending length order, so when one
   injected value contains another (`postgres://u:pw@host` and `pw`) the longer,
   more specific one is redacted before a shorter match can chop it in half.
   Ties break on variable name, so the result is deterministic.
4. **Self-check.** After redaction the server re-scans both streams for every
   injected value. If any survives — a bug, by construction — the tool returns an
   error instead of the output. Redaction failing closed is the point.

Redaction is a **defense-in-depth** measure, not a guarantee against a hostile
child: a child that holds the value can encode it (base64, reversed, one
character per line) and defeat any substring scrubber. It defends against the
ordinary case — a program that logs its own configuration — which is how secrets
actually leak in practice. The primary defense remains that no *tool* returns a
secret at all.

---

## 7. Threat notes

- **A prompt-injected agent** can call any tool with any arguments. The worst it
  achieves is running a command with a secret in its environment — which is
  exactly the capability the user granted by starting the server. It cannot read
  a value back, and it cannot mutate or export a vault (§3).
- **A hostile child process** can exfiltrate the value it was given, by any
  channel it likes. `run_with_secrets` is a capability grant to the command the
  agent chose to run; scope it by choosing which references to inject, not by
  trusting the child.
- **Transcript capture** is the threat this surface exists to defeat, and §1
  covers it.
- **The server holds an unlocked session for its whole lifetime** on the direct
  route, so an MCP host that keeps the server alive keeps the vault unlocked for
  that process. Prefer the daemon route (`localpass unlock` first), where the
  daemon's idle auto-lock still applies.

---

## 8. Non-goals

- **No write tools.** Create/edit/delete/import/export stay human-driven.
- **No `reveal`.** See §5.3.
- **No resources or prompts.** Only the `tools` capability is advertised.
- **No HTTP/SSE transport.** stdio only; a local network listener is exactly the
  class of bug PRD §4.7 avoids for the browser host.
- **No multi-profile serving.** One server serves the one `--profile` it was
  started for, like the daemon.
