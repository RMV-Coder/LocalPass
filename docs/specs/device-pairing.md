# LocalPass Device Pairing — QR transport, pairing mode, channel announce

Status: **specification, not yet implemented.** Expands `sync-protocol.md` §6
("Device pairing & trust") with the *transport* of the identity string and the
ceremony around it. It changes **no** cryptography and **no** trust rule: the
pinned-key model of §6 and the author check of §5 step 1 are unchanged.

## Scope

Today a user pairs two devices by copying a `LPDEV1-…` identity string from one
device to the other — in practice via Messenger, email, or a notes app — and
comparing a fingerprint out-of-band. This spec covers three additions:

1. **§3 QR transport** — render the identity string as a QR code and scan it.
2. **§4 Pairing mode** — a deliberate, time-boxed window for accepting new trust.
3. **§5 Channel announce** — a typing-free pairing path once two devices already
   share a sync folder.

Non-goals are in §7.

---

## 1. What the identity string is (and what it is not)

Design here hinges on being precise about this, so it is restated from
`lp-sync/src/identity.rs`:

```text
LPDEV1-<hex( device_id(16) || ed25519_pub(32) || x25519_pub(32) || crc(4) )>
```

It is **entirely public key material** — an Ed25519 op-author verification
anchor, an X25519 key-share recipient key, a device id, and a CRC. It contains
**no secret**, and it is not a credential.

### 1.1 What an attacker who holds your identity string can do

**Nothing to you.** Concretely:

- They **cannot read your vaults.** Reading requires a VaultKey sealed *to* their
  X25519 key by *you* (`share_vault_to_device`). Holding *your* public key does
  not invert that.
- They **cannot inject a single op into your vault.** §5 step 1: an author whose
  `device_id` is not in your `peer_devices` is rejected (`Alarm::UnknownDevice`).
  Your device only ever accepts ops from devices **you** pinned.
- There is **no listener to reach.** The MVP channel (§7) is a dumb, untrusted
  folder. Nothing in LocalPass accepts an inbound pairing request.

The one real attack on pairing is **substitution**: an attacker who can tamper
with the channel you use to *transport* the string swaps in their own identity,
and you pin the attacker instead of your device. That is exactly, and only, what
the out-of-band fingerprint comparison exists to defeat.

> **Design consequence.** The protection that matters is *your* pin + the
> fingerprint compare. Any feature framed as "stop other people from using my
> identity string" is protecting a value that needs no protection. Features below
> are justified against **substitution** and **local misuse**, never against
> "someone has my string".

### 1.2 Why QR is a security improvement, not just convenience

Sending the string through Messenger/email puts an attacker-manipulable hop in
the transport — precisely the substitution attack. Scanning a QR **off the other
device's screen, in person** is a strong out-of-band channel: the attacker would
need to control the physical screen you are looking at.

So QR **narrows** the attack surface relative to today's realistic user
behaviour. It does not replace the fingerprint compare (§3.3).

---

## 2. Trust is mutual

§5 step 1 is symmetric: A accepts B's ops only if A pinned B, and B accepts A's
ops only if B pinned A. So a pairing is **two** pins, and both directions need
the identity to travel. This shapes every flow in §6.

Pinning is also **not** access. After a mutual pin, a vault is still unreadable
by the peer until `share_vault_to_device` seals that vault's VaultKey to the
peer's X25519 key — a separate, deliberate step, per vault. Pairing and sharing
stay distinct.

---

## 3. QR transport

### 3.1 Payload

The QR encodes the **`LPDEV1-…` string verbatim** — byte-for-byte what the paste
box already accepts. No JSON wrapper, no URL scheme, no extra fields.

Rationale: one canonical representation means a scan and a paste converge on the
identical code path (`trust_device(identity_string, expected_fingerprint, …)`),
so the QR feature adds **no new trust primitive** and cannot drift from the
pasted-string parser. A wrapper would be a second, divergent format to keep
secure.

### 3.2 Encoding parameters

- Payload length: `LPDEV1-` (7) + 168 hex chars = **175 bytes**.
- Mode: **byte (8-bit)**. The hex is lowercase, so QR *alphanumeric* mode (which
  is uppercase-only) does not apply.
  - Deliberately **not** uppercasing to reach alphanumeric mode's higher density.
    It would save a few versions but requires case-folding in a
    security-critical parser to keep scan and paste equivalent. Not worth it; a
    ~version 10 symbol scans fine on any phone camera.
- ECC level: **M** (~15%). A mis-scan is not a silent risk: the identity string
  carries its own **CRC-32**, and the fingerprint compare (§3.3) is a second,
  human check. A corrupted scan fails the CRC and is rejected outright — it
  cannot yield a valid-but-wrong key.
- Render: **generated in Rust** (`qrcode` crate → SVG string) and returned by a
  Tauri command for inline display.
  - Rationale: no JS QR library (matches the project's standing "no JS crypto /
    no remote assets" posture), inline SVG is CSP-safe, and it crosses no secret
    boundary because the value is public (§1). The webview renders; it does not
    compute.

The **fingerprint must be displayed adjacent to the QR** — the scanning user
needs something to compare against (§3.3).

### 3.3 Scanning must not imply trust

**A scan replaces the transport of the string, not its verification.**

On scan, the app MUST:

1. Parse and CRC-check the string (existing parser; reject on failure).
2. Display the derived **fingerprint** and require an **explicit confirmation**
   that it matches the fingerprint shown on the other device's screen.
3. Only then call the existing `trust_device(identity_string,
   expected_fingerprint, label)`.

It MUST NOT auto-trust on a successful decode. A QR *image* forwarded over
Messenger is exactly as substitutable as the string was; only scanning a live
screen in person carries the out-of-band property. The app cannot tell those
apart, so the human check stays in both cases.

### 3.4 Platform surfaces

| | Display QR | Scan QR |
|---|---|---|
| Android | yes | yes — `tauri-plugin-barcode-scanner` (camera permission) |
| Desktop | yes | **no** (out of scope — no camera flow; paste remains) |

The asymmetry is intentional and drives §6.1: desktop displays, phone scans.

---

## 4. Pairing mode

A per-device, **time-boxed** (suggested 3 min) window, off by default.

**Gates:**

- displaying this device's QR (§3), and
- accepting a **new** pin (`TrustDevice` returns an error while off).

**Does not gate** — already-pinned peers keep working exactly as before:
push/pull, op acceptance, key shares. Turning pairing mode off never desyncs an
established device. (This is the property that makes the control safe to leave
off permanently.)

**Enforced in the engine** (`lp-daemon`'s `engine::handle`, hence both the
desktop daemon and the mobile in-process backend), not in the webview — a
UI-only toggle would be decoration, and the CLI would bypass it.

### 4.1 What this is and is not

**It is not** a defence against a remote attacker. Per §1.1 there is nothing to
defend: no listener exists, and a stranger's possession of your identity string
already achieves nothing. Framing it as "sync will fail if someone has my string
while discoverability is off" would be **false** — sync from an unpinned device
fails *always*, discoverability or not.

**It is** worth having for three honest reasons:

1. **Local misuse.** Someone with brief physical access to your *unlocked* app
   cannot silently pin their own device; pinning becomes a deliberate act.
   (Modest: an attacker at your unlocked vault can also just toggle it on. This
   is a speed bump and an audit-log moment, not a boundary.)
2. **Accidental trust.** A deliberate ceremony is harder to fumble than an
   always-live "paste and go" box.
3. **It is the correct home for the control that *will* be load-bearing.** When
   the LAN/mDNS live transport lands (PRD backlog), "discoverable" gates whether
   this device *announces itself and accepts inbound connections* — a real
   network control with real teeth. Specifying it now means that arrives as a
   familiar toggle rather than a new concept.

Toggling pairing mode SHOULD be recorded in the local audit log (PRD §4.9).

---

## 5. Channel announce (the typing-free path)

Once two devices point at the same sync folder, no string needs to move by hand
at all.

### 5.1 Layout

At the **sync root** (device-level, not per-vault — pairing is not a vault
property):

```text
<sync-root>/pairing/<device_id>.identity
```

Content (plaintext JSON):

```json
{
  "identity": "LPDEV1-…",
  "label": "Ray's phone",
  "announced_at": 1752537600000
}
```

This maps cleanly onto the `Store` trait merged in #10 — the store is rooted at
the sync root, so `pairing/` is reachable through the same seam as `ops/` and
`chain/`, and an eventual SAF-backed store gets it for free.

### 5.2 It is untrusted — deliberately

`pairing/` has **exactly the posture of `manifest.json` (§7.2): a discovery hint,
not an authority.** The channel is untrusted, so anyone who can write to the
folder can drop a forged identity. That is acceptable and requires no defence,
because:

- an announce file **never** causes a pin by itself; it only populates a
  "pending devices" list, and
- the user still confirms the **fingerprint against the other device's screen**
  before pinning (the §3.3 rule, unchanged).

A forged announce therefore achieves at most a pending entry whose fingerprint
does not match anything the user is looking at → rejected. It cannot inject
state, exactly as a forged manifest cannot.

### 5.3 Flow

1. Each device writes its own `pairing/<device_id>.identity` when sync is
   configured (and refreshes `announced_at` on push).
2. Each device lists `pairing/`, ignoring its own id and any already-pinned id.
3. Remaining entries surface as **"Pending devices"**, each showing its
   fingerprint and label.
4. The user confirms the fingerprint matches the other device's screen → the
   existing `trust_device` runs. Zero typing, both directions, and the
   out-of-band comparison is fully preserved.

An implementation MAY prune `pairing/` entries for pinned devices; it MUST NOT
treat absence of an entry as a reason to distrust a pinned device.

### 5.4 Relationship to QR

They are complementary, not redundant:

- **QR** needs no shared folder — it is the *bootstrap*, and today it is the only
  option on mobile (a shared folder there needs SAF; see `android.md`).
- **Announce** needs the shared folder but removes all typing — it is the better
  steady-state path, and it is what makes the *second* pin (§2) painless given
  desktop cannot scan (§3.4).

---

## 6. Flows

### 6.1 Desktop ↔ phone, first pair (QR bootstrap)

1. Both: pairing mode on (§4).
2. Desktop shows QR + fingerprint. Phone scans → compares fingerprint → pins
   desktop. *(one pin done)*
3. Phone shows its QR + fingerprint; desktop cannot scan (§3.4), so either:
   - the user pastes the phone's string on desktop, comparing the fingerprint; or
   - once a shared folder exists, the desktop picks the phone up as a **pending
     device** (§5) and confirms the fingerprint — no typing.
4. Both: pairing mode off.
5. Per vault to share: `share_vault_to_device` (§2).

### 6.2 Steady state (announce)

Any new device pointed at the existing folder appears on the others as a pending
device with a fingerprint; each side confirms once. QR is not needed.

---

## 7. Non-goals

- **Bluetooth transport.** Rejected: a radio, a runtime permission, and a
  separate pairing stack per platform — a large, always-present attack surface
  and substantial per-OS code, to solve a problem QR already solves with **zero
  runtime surface** (a QR is a rendered image; it listens to nothing). It also
  cuts against the "fully local, offline" posture. If cable-free sync is wanted,
  the planned LAN/mDNS transport is the place, not BT.
- **Auto-trust on scan.** See §3.3.
- **Network discovery / a real "discoverable" service.** Deferred to the LAN/mDNS
  transport; §4 is where its toggle will live.
- **Encoding anything but the identity string in the QR** (vault offers, folder
  locations, tokens). One canonical payload (§3.1).
- **Changing the trust model.** No new pin path, no relaxation of §5 step 1.

---

## 8. Implementation plan

| Phase | Work | Depends on |
|---|---|---|
| 1 | **QR display** — `qrcode` crate → SVG; Tauri command; render in Devices & Sync beside the fingerprint. Desktop + Android. | — |
| 2 | **QR scan (Android)** — `tauri-plugin-barcode-scanner`, camera permission, → fingerprint confirm → existing `trust_device`. | 1 |
| 3 | **Pairing mode** — engine state + `SetPairingMode` op + `TrustDevice` gate + audit entry + UI toggle. | — |
| 4 | **Channel announce** — `pairing/` read/write via the `Store` seam, pending-devices UI, spec'd into `sync-protocol.md` §7. | #35 (SAF) for mobile |

Phases 1–3 are independent of SAF and can land first; phase 4 is only useful on
mobile once a shared folder is reachable there.

New dependencies (both verified to exist and to fit the licence policy; both
still get a `cargo-deny` advisories+licences pass at adoption time):

- **`qrcode` 0.14** — `MIT OR Apache-2.0`, pure Rust. Take it as
  `default-features = false, features = ["svg"]`: the default feature set enables
  `image` (and `pic`), pulling the whole `image` crate in for raster output we do
  not want. SVG-only keeps the dependency footprint — and the audit surface —
  minimal.
- **`tauri-plugin-barcode-scanner` 2.4** — Android/iOS only; must be registered
  for mobile targets only so the desktop build (which has no scan surface, §3.4)
  does not link it.

---

## 9. Summary of security properties

| Property | Before | After |
|---|---|---|
| Ops accepted only from pinned devices | yes (§5 step 1) | **unchanged** |
| Out-of-band fingerprint compare required to pin | yes | **unchanged** (§3.3, §5.2) |
| Identity string is public, confers nothing | yes | **unchanged** (§1.1) |
| Transport of the string | user-chosen, often a tamperable app | **QR off a live screen** — substitution gets materially harder (§1.2) |
| Pinning a new device | always possible while unlocked | requires a **deliberate window** (§4) |
| Forged data in the channel | manifest is advisory (§7.2) | `pairing/` is advisory the same way (§5.2) |

No cryptographic primitive, key, wire format, or acceptance rule changes.
