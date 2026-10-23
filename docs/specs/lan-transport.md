# LocalPass LAN Transport — direct device-to-device sync ("Sync with a nearby device")

**Protocol version: 1** (carried in the Noise prologue)
**Status: implemented (core, daemon, CLI, desktop Devices screen, Android
in-process backend); mDNS discovery is a follow-up — see §12**
**Date: 2026-10-22**

## Scope

This spec defines the live transport PRD §4.5 calls "Direct LAN / overlay
network" and lists as MVP (§9.1): two devices that **already trust each other**
(`device-pairing.md`, `sync-protocol.md` §6) sync their vaults, and one may
hand the other a vault key, over a direct TCP connection on the same Wi-Fi or
the same Tailscale/WireGuard network. No shared folder, no third-party sync
application, no server of any kind.

It fills the extension point `sync-protocol.md` §7.4 left open ("ships the same
canonical op bytes over a mutually-authenticated stream instead of files; the
ingest verifier (§5) and merge (§4) are transport-agnostic and unchanged"). It
changes **no** op format, no merge rule, no verifier rule, no key-share format,
and no pairing rule. It adds one Ed25519 signing context, one handshake, one
framing layer, and a small exchange protocol on top.

What it is **not**:

- Not a pairing protocol. Trust is still established out-of-band (QR or
  pasted identity string plus a fingerprint compare). A device that is not
  pinned cannot complete the handshake (§4.4).
- Not an internet transport. Both ends refuse addresses outside private,
  link-local, loopback and CGNAT/ULA ranges (§7.3). There is no relay, no
  discovery server, no NAT traversal (PRD §6.4: users who need it get it from
  Tailscale/WireGuard, which they control).
- Not libp2p (rejected in PRD §6.4) and not a custom crypto construction: one
  standard Noise pattern (`XX`) with standard primitives, via the `snow` crate
  PRD §6.2 names.

---

## 1. Goals and threat model

New attack surface, stated plainly: **a listening TCP socket in a password
manager.** Everything below exists to keep that surface small, short-lived, and
useless to anyone who is not one of the user's own pinned devices.

| Goal | How |
|------|-----|
| Opt-in | Nothing listens unless the user turns on "Sync with a nearby device" (§7.1). Off by default; there is no setting that makes it permanent. |
| Time-limited | The listen window closes after 3 minutes by default (10 at most), after one completed session, after 8 failed handshakes, or when the vault locks — whichever comes first (§7.1). |
| Local-network only | Peer addresses outside loopback / RFC 1918 / link-local / CGNAT `100.64.0.0/10` (Tailscale) / IPv6 ULA are dropped before a byte is read (§7.3). |
| Authenticated before data | Mutual authentication against the pinned-peer list completes inside the Noise handshake; no application message is read, and no vault is opened, before it does (§4.4). |
| No new trust | Only devices already in `peer_devices` can authenticate. Op ingest still runs the unchanged §5 verifier, so even an authenticated peer cannot inject an op the file channel would refuse. |
| Bounded | Every read has a size cap checked before allocation, and every phase has a deadline (§5.4). |

Threats (PRD §8):

- **T4 network MITM (ARP spoof, rogue AP, hostile Wi-Fi).** Defeated by mutual
  authentication pinned to SAS/fingerprint-verified keys (§4) and by the
  payloads being E2EE regardless (ops are VaultKey-encrypted and Ed25519-signed
  before they reach the transport; a vault-key share is sealed and signed). A
  MITM sees a Noise handshake and ciphertext; it cannot impersonate either side
  without a pinned device's Ed25519 private key, cannot read the traffic, and
  cannot modify, drop, reorder or replay a record without the AEAD failing.
- **T13 rollback / tamper by a peer.** Unchanged: ops go through the §5
  verifier (signature, seq contiguity, prev_hash chain, Lamport monotonicity).
  An authenticated but compromised device can at most author ops under its own
  key — exactly what it could already do through the file channel.
- **Unauthenticated LAN neighbour probing the listener.** Learns that a
  LocalPass listener is open (and, because XX reveals the responder first, the
  responder's device id — which is public, `device-pairing.md` §1.1). Cannot
  get past message 3. Each failed attempt is counted and the window closes at 8.
- **Resource exhaustion.** Size caps before allocation, one connection at a
  time, a handshake deadline that a byte-trickling client cannot extend, and
  the window's own timeout.

Honest residual risks:

- The listener exists for up to 10 minutes on every interface the OS routes
  to; on a hostile network a neighbour can see it is there.
- The responder's device id is visible to an active initiator (§4.5).
- An authenticated, compromised pinned device can push ops and shares — the
  same capability it has through the file channel. Unpinning it
  (`peer_devices`) ends that on both transports.

---

## 2. Overview

```text
 Device L ("listener", Noise responder)        Device D ("dialer", Noise initiator)
 ───────────────────────────────────────       ─────────────────────────────────────
 user: Sync with a nearby device  → listen     user types L's host:port (or scans it)
   bind 0.0.0.0:47823, 3-min window                  │
   show "192.168.1.20:47823"                          │ TCP connect (local address only)
        │ ◄──────────────────────────────────────────┘
        │  address policy check (§7.3)
        │  Noise XX handshake, ≤ 10 s (§4)  ◄──────►  pins checked on both sides
        │  ── authenticated; nothing read before here ──
        │  exchange rounds (§6), D speaks first in each round:
        │    1 HELLO      (signed vault-key shares, if the user asked)
        │    2 INVENTORY  (vault ids + per-device seq heads)
        │    3 OPS…/END   (canonical op bytes the other side lacks → §5 verify → §4 merge)
        │    4 BLOB_WANT  (attachment blobs still missing)
        │    5 BLOB…/END  (content-addressed blobs, re-hashed on arrival)
        │    6 DONE
 window closes (one session per window)            report printed / shown
```

The two roles differ only in who connects and who speaks first; the exchange is
otherwise symmetric — both sides send, both sides ingest, and a session leaves
both devices converged on every vault they share.

---

## 3. Keys and key separation

### 3.1 Decision: a dedicated, per-connection Noise static key, certified by the device's Ed25519 identity key

Each device's pinned identity is `(device_id, ed25519_pub, x25519_pub)`
(`LPDEV1-…`, `device-pairing.md` §1). The Noise static key could be the
existing X25519 key. **It is not.** Instead:

- Every connection generates a **fresh X25519 keypair** used as the Noise
  static `s` (inside `lp-crypto`; the private half never leaves the handshake
  object and is dropped with it).
- Each side proves that this key belongs to it by **signing** it, together with
  the handshake transcript, with the device's existing **Ed25519 identity key**
  under a new, dedicated signing context:

  ```text
  context  = "localpass/v1/sign/lan-handshake"
  message  = role (1 byte: 0x01 initiator, 0x02 responder)
          || h   (32 bytes: the Noise handshake hash just before the signer writes its message)
          || s   (32 bytes: the signer's Noise static public key for this connection)
  ```

  The proof travels in the Noise handshake payload (§4.2), so it is encrypted.

### 3.2 Why not reuse the X25519 sealing key

The X25519 key already has one job: it is the recipient key for sealed
vault-key shares (`seal_key_for`, `sync-protocol.md` §7.1). Using it as a Noise
static key would make one private key compute Diffie-Hellman with
attacker-chosen points in two unrelated protocols. No concrete cross-protocol
attack is known — both protocols hash the DH output into different KDF chains —
but "no known attack" is a weak argument for a product awaiting its first
external audit, and the PRD's own rule is "boring crypto, domain-separated
labels everywhere" (§5.1, §5.2). Key separation removes the question instead of
arguing it.

### 3.3 Why not a new long-term Noise key

A dedicated *long-term* Noise key would have to reach the peer somehow. Putting
it in the identity string means an `LPDEV2` format and re-pairing every device;
storing it unannounced would mean a new long-term secret at rest that still
needs certifying. A per-connection key certified by the existing Ed25519 key
needs neither: pairing, the identity string, the stored peer rows and the
fingerprint are all unchanged, and there is no new secret to protect on disk.

### 3.4 Why the Ed25519 key may sign this

The Ed25519 identity key already signs two message types (ops, vault-key
shares) under two contexts. `lp-crypto` frames every signature as
`LE_u64(len(context)) || context || message`, so a handshake signature can never
verify as an op or a share and vice versa (`lp-crypto` `sign` module docs). The
new context is the third member of that family, not a new use of raw keys.

### 3.5 What the proof binds

- **Possession of the identity key** — only the pinned device can produce the
  signature.
- **This connection** — `h` commits to the prologue (protocol version) and to
  both ephemeral keys, so a proof cannot be replayed into another session.
- **This Noise static key** — and the handshake's `es`/`se` DH operations prove
  possession of its private half, so a relayed proof is useless without it.
- **The role** — a responder's proof cannot be reflected back as an
  initiator's.

This is the identity-binding construction other deployed Noise protocols use
(a static key certified by a separate identity signing key in the handshake
payload), tightened with transcript binding. It needs no change to Noise.

---

## 4. Handshake

### 4.1 Parameters

```text
protocol name  Noise_XX_25519_ChaChaPoly_SHA256
prologue       "localpass/v1/lan-sync/1"
```

- **XX**, not IK: IK needs the responder's static key in advance, and the
  static key is per-connection (§3). XX also never reveals the *initiator's*
  identity to a responder that failed authentication (§4.5).
- **ChaChaPoly + SHA256 + 25519**: the primitives `lp-crypto` already uses
  (ChaCha20-Poly1305, SHA-256, X25519 via the same `chacha20poly1305`, `sha2`
  and `curve25519-dalek` versions). BLAKE2 and AES-GCM are not compiled in.
- The prologue carries the protocol version. A device speaking another version
  fails the handshake; versions are never negotiated (PRD §5.1).

### 4.2 Messages

```text
-> e                       payload: empty
<- e, ee, s, es            payload: IdentityProof(responder)
-> s, se                   payload: IdentityProof(initiator)

IdentityProof = device_id (16) || signature (64)        -- exactly 80 bytes
```

Each handshake message is framed like every Noise message on the stream
(§5.1) and capped at **1024 bytes** (real sizes: 32, 176 and 144).

### 4.3 Who signs what

| Signer | Signs `role` | `h` is the handshake hash… | `s` |
|--------|--------------|----------------------------|-----|
| responder (in msg 2) | `0x02` | after reading msg 1 | responder's static |
| initiator (in msg 3) | `0x01` | after reading msg 2 | initiator's static |

Both sides can compute both values: `h` at a message boundary is the same on
both ends, and the verifier reads the signer's static key from the handshake
(`snow::HandshakeState::get_remote_static`).

### 4.4 Verification order (fail closed, before any application data)

**Initiator, on msg 2:**

1. Noise decrypts msg 2 (any failure → abort).
2. Payload is exactly 80 bytes.
3. `device_id` is a pinned peer (`peer_devices`) and is not this device.
4. If the caller named an expected peer, `device_id` equals it.
5. The signature verifies under that peer's pinned `ed25519_pub` over
   `0x02 || h_after_msg1 || remote_static`.
6. Only then is msg 3 written. An initiator never reveals its own identity to an
   unauthenticated responder.

**Responder, on msg 3:** the same checks with role `0x01` and `h_after_msg2`.
Only after they pass does the responder read its first transport message.

Any failure closes the TCP connection without a reply. An unauthenticated
initiator therefore costs the responder one handshake and nothing else: no vault
is opened, no session state is read beyond the pinned-peer lookup, and no
transport message is decrypted.

### 4.5 Identity exposure

XX sends the responder's static key and proof in msg 2, before it knows who the
initiator is. An active initiator therefore learns the listener's device id
(and that it is a LocalPass device). Device ids and their public keys are
public by design (`device-pairing.md` §1.1), the listener only exists while the
user is actively syncing, and the alternative (`IK` with the long-term X25519
key) would give up key separation. Accepted and documented.

The initiator's identity is never sent to an unauthenticated responder.

### 4.6 Low-order points

The Noise spec does not require rejecting low-order DH outputs, and `snow` does
not. Here it does not matter: authentication rests on the Ed25519 signature over
a transcript hash that includes both ephemerals, so a peer that forces a
known DH output still cannot produce a valid proof for a pinned identity.

---

## 5. Record layer and framing

### 5.1 Noise messages on the stream

Every Noise message — handshake or transport — is sent as

```text
u16 big-endian length || noise message      (length ≤ 65535, the Noise maximum)
```

the stream framing recommended by the Noise specification (§3). A length above
the current phase's cap (1024 during the handshake, 65535 after) is refused
before the body is read.

### 5.2 Application messages

After the handshake every application message is encrypted as one or more
Noise transport messages ("records"). Each record carries at most 65519
plaintext bytes (65535 minus the 16-byte tag). The plaintext of a message's
**first** record starts with a 5-byte header:

```text
type u8 || body_len u32 LE
```

followed by the start of the body; the next records carry the rest of the body
until `body_len` bytes have arrived. A record never carries bytes of two
messages. `body_len` is checked against the per-type cap **before** anything is
allocated:

| Type | Name | Cap |
|------|------|-----|
| `0x01` | `HELLO` | 4 MiB |
| `0x02` | `INVENTORY` | 4 MiB |
| `0x03` | `OPS` | 16 MiB |
| `0x04` | `OPS_END` | 0 |
| `0x05` | `BLOB_WANT` | 4 MiB |
| `0x06` | `BLOB` | 50 MiB + 48 (the attachment cap plus its 48-byte header) |
| `0x07` | `BLOBS_END` | 0 |
| `0x08` | `DONE` | 0 |

An unknown type, a record that overruns the declared length, a record that
fails to decrypt, or a stream that ends inside a message aborts the session.
Noise's implicit nonces make reordered, dropped, duplicated or replayed records
fail to decrypt. A stream that ends cleanly but before `DONE` is reported as
an incomplete session (whatever was already verified and applied stays — every
ingest is atomic and idempotent, `sync-protocol.md` §7.3).

### 5.3 Integers and ids

Little-endian fixed-width integers; 16-byte raw ids (vault, device); 32-byte
raw attachment hashes (`BLAKE3(ciphertext)`, the value `attach_add` carries).
No JSON on this wire.

### 5.4 Limits and deadlines

| Limit | Value | Why |
|-------|-------|-----|
| TCP connect (dialer) | 10 s | an unreachable address fails quickly |
| Handshake, total | 10 s from accept/connect | enforced as a deadline across reads, so a client trickling one byte at a time cannot extend it |
| Handshake message | 1024 bytes | real messages are ≤ 176 bytes |
| Waiting for the next record, or writing one | 120 s | covers the other side's ingest of a large batch |
| Noise message | 65535 bytes | the Noise maximum |
| Messages | per-type caps, §5.2 | checked before allocation |
| Shares per `HELLO` | 64 | |
| Vaults per `INVENTORY` | 1024 | PRD §5.7 targets 50 |
| Device heads per vault | 4096 | PRD §5.7 targets 10 devices |
| Hashes per `BLOB_WANT` | 65536 total | |
| Ops batch (sender) | ~1 MiB per `OPS` message | keeps records flowing and memory flat |
| Ingest buffer (receiver) | 32 MiB of op bytes before an ingest | bounds memory; ingest is incremental |
| Concurrent connections (listener) | 1 | sessions are serialized |
| Failed handshakes per window | 8 | then the window closes |

---

## 6. Exchange protocol

### 6.1 Rounds

The session is six rounds. In each round the **initiator writes first**, the
responder reads the initiator's message (or stream) and then writes its own,
and the initiator reads that. What a side writes in a round depends only on
earlier rounds, never on the other side's message in the same round, so the two
directions never wait on each other and a TCP buffer filling up cannot
deadlock the session.

| Round | Each side sends | Then each side… |
|-------|-----------------|-----------------|
| 1 | `HELLO`: the signed vault-key shares the user asked to send to this peer | imports the shares it received (§6.6) |
| 2 | `INVENTORY`: every vault it holds, with per-device seq heads | computes the common vaults (in both inventories) |
| 3 | `OPS` messages for each common vault, then `OPS_END` | ingests what it received (§6.4) |
| 4 | `BLOB_WANT`: attachment blobs it still lacks per common vault | — |
| 5 | `BLOB` for each wanted blob it holds, then `BLOBS_END` | stores and re-hashes what it received (§6.5) |
| 6 | `DONE` | closes the connection |

### 6.2 Message bodies

```text
HELLO      u16 n || n × ( vault_id[16] || u32 len || LPS2 share blob )
INVENTORY  u16 n || n × ( vault_id[16] || u16 m || m × ( device_id[16] || seq u64 ) )
OPS        vault_id[16] || segment body
OPS_END    (empty)
BLOB_WANT  u16 n || n × ( vault_id[16] || u32 k || k × hash[32] )
BLOB       vault_id[16] || hash[32] || blob bytes (the rest of the body)
BLOBS_END  (empty)
DONE       (empty)
```

`segment body` is **exactly** the `.oplog` file body of `sync-protocol.md` §7.1:
repeated `u32 LE len || canonical op bytes` (wire version 2, fields 0..12). The
same encoder (`lp_sync::wire::encode_segment`) writes both, and the same decoder
reads both. Lists are strictly ascending by id and free of duplicates; a decoder
refuses anything else.

### 6.3 Heads and what to send

A vault's **heads** are, per author device, the highest `seq` the vault holds
from that device. For a common vault, a side sends every op it holds whose
`seq` is above the peer's head for that author (0 if the peer listed none),
**except** ops authored by the peer itself (the peer's own ops are never
re-ingested — `pull` drops them too). Ops go out ascending by `(device_id,
seq)`, in `OPS` messages of about 1 MiB. Because the sender holds only ops it
already verified, each author's run is contiguous from the peer's head.

This is store-and-forward for free: ops a third device authored travel through
whichever device has them, exactly as through the file channel.

### 6.4 Ingest — the §5 verifier and §4 merge, unchanged

A receiver checks only framing at this layer (each op decodes, and its
`vault_id` matches the message's vault). It then hands the ops to
`lp_sync::engine::ingest` — the function `pull` itself now calls — which builds
the chain state from local storage and pinned keys, runs
`verify::verify_batch` (§5: signature, seq, prev_hash, Lamport), and folds the
complete op set through `merge::materialize` (§4) before applying it in one
transaction. Nothing about verification or merge is LAN-specific; quarantines
and pending holds are reported exactly as a file pull reports them.

Ingest is incremental: the receiver applies what it has whenever it holds about
32 MiB of op bytes, and at `OPS_END`. Each ingest is atomic and idempotent, so
an interrupted session keeps what it verified and the next one resumes from the
new heads.

### 6.5 Attachment blobs

After round 3, each side computes, per common vault, the blobs its live
attachments reference but it does not hold (the same
"referenced-but-missing" set `pull` computes, `sync-protocol.md` §7.3 step 5),
and sends them in `BLOB_WANT`. In round 5 each side sends a `BLOB` for each
wanted hash that its own vault references and holds — never an unreferenced
blob, so a peer cannot probe for arbitrary content. A receiver accepts only
hashes it asked for, and stores each through `Vault::store_attachment_blob`,
which re-hashes and refuses a mismatch (`AttachmentBlobTampered`, an alarm).
A blob the other side does not have stays pending, as in file sync.

### 6.6 Vault-key shares

A share is the unchanged signed `LPS2` blob (`sync-protocol.md` §7.1), built by
`Session::share_vault_key_to_peer` for the **authenticated** peer after the
handshake (so it is sealed to the peer's pinned X25519 key and signed by this
device). It is sent in `HELLO` with its vault id.

The receiver:

1. Refuses a share whose sender field (bytes 4..20 of the blob) is not the
   authenticated peer — a share can only come from the device on the other end
   of this connection.
2. Calls `Session::import_shared_vault_key`, which (unchanged) requires the
   sender to be pinned, verifies the signature over the vault id, recipient and
   sender **before** unsealing, then registers the vault.
3. A refused share is reported as an alarm; it never blocks the rest of the
   session.

The imported vault is then in the receiver's round-2 inventory, so the same
session delivers its full op log: one "Sync with a nearby device" both hands
over a vault and fills it.

Sending a share requires the caller to name the expected peer (§9). A listener
that would share a vault refuses a connection from any other pinned device.

### 6.7 Report

Each side reports: the peer (device id, pinned label), per common vault the ops
sent, applied, skipped and pending, quarantines, blobs sent, fetched, pending
and tampered, the shares sent, adopted and refused, and whether the session
reached `DONE`.

---

## 7. When anything listens

### 7.1 The listen window ("Sync with a nearby device")

Listening is a deliberate, time-boxed act, modelled on pairing mode
(`device-pairing.md` §4):

- **Off by default.** Turned on per use: `localpass sync nearby --listen`, or
  the daemon's `NearbyListen` request (the GUI entry point, §12).
- **Window:** 180 s by default, at most 600 s. The window bounds *accepting* a
  connection; a session that started inside it runs to completion.
- **One session per window.** The listener closes as soon as one
  authenticated session ends, whether it completed or failed after the
  handshake. A connection refused *in* the handshake does not end the window
  (it counts toward the failure cap).
- **8 failed handshakes** (unauthenticated or malformed peers, address-policy
  rejects) close the window early.
- **The vault locking closes it.** The listener needs the unlocked session to
  authenticate, so a lock — by the user or by the idle timer — stops it. Listening
  does not count as activity and does not hold the vault open.
- **Stoppable:** `NearbyStop`, or Ctrl-C for the CLI.
- **Audited:** opening and closing the window, and each completed session,
  are recorded in the local audit log (§10). Best-effort, like every audit
  write: a window closed *by* the vault locking has no session left to write
  the closing record through.
- **While an AI agent is connected**, opening the window and any session that
  sends a share need the master password first (`mcp-server.md` §7.1), like
  pairing mode and `ShareVaultToDevice`.

### 7.2 Bind address and port

- Default `0.0.0.0:47823`. `--port 0` picks a free port; `--bind` picks an
  interface (e.g. a Tailscale address, or `[::]` for IPv6).
- The listener reports the address to show the user: the interface address the
  OS would use for the local network, found by asking the routing table (a UDP
  socket "connected" to a private address, which sends nothing). Tailscale users
  use their tailnet address.

### 7.3 Address policy (both directions)

A connection is allowed only if the peer IP is:

| Range | Why |
|-------|-----|
| `127.0.0.0/8`, `::1` | loopback (tests, same machine) |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 LANs |
| `169.254.0.0/16`, `fe80::/10` | link-local |
| `100.64.0.0/10` | CGNAT shared space — Tailscale's IPv4 range |
| `fc00::/7` | IPv6 unique-local — Tailscale's IPv6 range |

IPv4-mapped IPv6 addresses are judged as their IPv4 form. Anything else is
dropped before a byte is read (listener) or refused before connecting (dialer).
The dialer accepts **IP literals only**: resolving a host name would send it to
a DNS server, and the point of this transport is that nothing leaves the local
network. Host names are a possible later addition (§12).

---

## 8. Discovery

1. **Manual address (built).** The listener shows `host:port`; the user types
   it on the other device. On Tailscale, the tailnet IP.
2. **QR (built, GUI).** The listener displays the same address as a QR code
   next to the text. The payload is `LPNEAR1-` followed by `IP:port` (for
   example `LPNEAR1-192.168.1.20:47823`), so a scan can tell it apart from a
   device-identity QR (`LPDEV1-…`); the app's scanner also accepts a bare
   `IP[:port]`. The backend renders a QR only for a local-network address. The
   QR is a convenience for typing only: it carries no key and grants nothing —
   the handshake authenticates the device that answers, whatever the QR said.
   A wrong or forged address can at worst connect to a device that then fails
   the handshake. Typical use: the desktop waits, the phone scans and
   connects, so the phone never needs an inbound socket.
3. **mDNS (follow-up).** The listener announces `_localpass-sync._tcp.local.`
   only while its window is open, with a random per-window instance name and a
   TXT record carrying the protocol version and nothing identifying (no device
   id, label or vault). The dialer lists instances and the user picks one; the
   handshake still decides who it is. Implementation via `mdns-sd` (PRD §6.4)
   on desktop and `NsdManager` plus a `WifiManager.MulticastLock` on Android.
   Discovery stays advisory in exactly the `sync-protocol.md` §7.2 sense: it can
   suggest an address, never confer trust.

---

## 9. Interfaces

### 9.1 Daemon requests (additive; every new field is `#[serde(default)]`)

| Request | Fields | Answer |
|---------|--------|--------|
| `NearbyListen` | `profile`, `bind?`, `port?`, `timeout_secs?`, `peer?`, `share[]` | `NearbyListening { addresses, port, expires_in_secs }` |
| `NearbyStatus` | `profile` | `NearbyStatus { listening, addresses, port, expires_in_secs, last }` |
| `NearbyStop` | `profile` | `Ok` |
| `NearbyConnect` | `profile`, `addr`, `peer?`, `share[]` | `NearbySynced { report }` |

`peer` is a device id; `share` is a list of vault names or ids and requires
`peer`. `NearbyConnect` runs the whole session on the requesting connection's
worker thread; the daemon's state mutex is taken only around each local step
(an inventory, an ingest batch, a blob read), never across network I/O, so
other clients and the auto-lock are never blocked by a slow peer. `NearbyListen`
returns once bound; the session runs on a listener thread and `NearbyStatus`
reports its outcome.

### 9.2 CLI

```text
localpass sync nearby --listen [--bind ADDR] [--port N] [--timeout SECS] [--peer DEVICE] [--share VAULT]… [--json]
localpass sync nearby --connect IP[:PORT]  [--peer DEVICE] [--share VAULT]… [--json]
```

Like every `localpass sync` command it unlocks directly and runs in the
foreground; `--listen` blocks until the window closes. An alarm (quarantine,
tampered blob, refused share) exits non-zero, as `sync pull` does.

### 9.3 Layering

| Layer | Crate | Contents |
|-------|-------|----------|
| Noise handshake + transport | `lp-crypto` (`noise`) | the only crate that touches `snow` and the primitives (PRD §6.2 crypto boundary) |
| Handshake signing | `lp-vault` | `Session::sign_lan_handshake` — signs under the one LAN context only; the signing key never leaves the session |
| Channel, exchange, ingest | `lp-sync` (`nearby`, `engine::ingest`) | transport-agnostic: runs over any `Read + Write` stream and a `Local` trait that lends the unlocked `Session` |
| Sockets, address policy, windows, requests | `lp-daemon` (`nearby`) | the listener and dialer, shared by the daemon and the CLI |
| Command | `lp-cli` | `sync nearby` |

---

## 10. Audit

Three new device-local audit kinds (metadata only, `lp-vault` audit format):

| Kind | Code | Carries |
|------|------|---------|
| `nearby_listen_enabled` | 16 | nothing |
| `nearby_listen_disabled` | 17 | nothing |
| `nearby_sync` | 18 | the peer device id |

Shares sent over the link are recorded by the existing `vault_share` kind
(written by `share_vault_key_to_peer`).

---

## 11. Security summary

| Property | File channel | LAN transport |
|----------|--------------|---------------|
| Ops accepted only from pinned authors, §5-verified | yes | **same code path** |
| Merge | §4 | **same code path** |
| Vault-key share | signed `LPS2`, pinned sender | same blob, plus: sender must be the authenticated peer |
| Transport confidentiality | none (ops are E2EE) | Noise (ops are still E2EE) |
| Who can connect | — (no listener) | pinned devices only, local addresses only, inside an opt-in window |
| New long-term secret | — | none |
| New signing context | — | `localpass/v1/sign/lan-handshake` |
| Pairing / identity string / fingerprint | — | unchanged |

---

## 12. Not built in this version (follow-ups)

Built since the first version: the desktop Devices screen's "Sync with a
nearby device" section (wait with a countdown, the address and its QR;
connect by typing or scanning; optionally share a vault), and the Android /
in-process backend running the deferred nearby jobs (`apps/desktop/src-tauri`
`daemon.rs`). Still not built:

- **mDNS discovery** (§8.3) on both platforms. On Android it needs
  `CHANGE_WIFI_MULTICAST_STATE`, a `MulticastLock` held only while the window
  is open, and `NsdManager`.
- **On-device verification** of the Android path (a phone dialing a desktop on
  real Wi-Fi), including the `INTERNET` permission in the generated manifest
  (`gen/android/` is not in the repository).
- **Host names** for `--connect` (today: IP literals only, §7.3).
- **IPv6 by default** (today: bind `[::]` explicitly).
- Fuzz targets for the record layer and message decoders (release-checklist §1).

## 13. Test plan

Covered in `crates/lp-crypto/src/noise.rs` (unit), `crates/lp-sync/src/nearby/`
(unit: framing, limits, proofs, a MITM that flips a bit), `crates/lp-sync/tests/nearby.rs`
(two and three real devices over loopback TCP), `crates/lp-daemon/src/nearby.rs`
(unit: address policy, window), `crates/lp-daemon/tests/nearby.rs` (the daemon
requests) and `crates/lp-cli/tests/nearby.rs` (two `localpass` processes):

- Two real devices over loopback TCP converge, and a following file sync
  between them applies nothing (the LAN session produced exactly the file-sync
  state); edits on both sides cross in one session; a third device's ops are
  forwarded.
- A vault-key share over the link: adopted and filled in one session; a share
  from a sender other than the authenticated peer is refused.
- An untrusted peer is refused in the handshake and no application data is read
  or vault touched (counted through the `Local` seam) — both when the dialer is
  untrusted and when the listener is.
- A tampered record and a truncated stream abort the session.
- An oversize handshake message, an oversize application message, a handshake
  that never completes, and a byte-trickling handshake are all rejected within
  their limits.
- The address policy, the listen window (expiry, one session, failure cap) and
  the daemon requests.
