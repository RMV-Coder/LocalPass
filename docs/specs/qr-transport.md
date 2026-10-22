# LocalPass QR Transport — offline sync by animated QR ("Sync by QR code")

**Protocol version: 1** (carried in every frame, bundle and "what I have" code)
**Status: implemented (core, daemon, CLI, desktop and Android GUI); continuous
camera scanning prototyped and measured on a real Android phone; the production
GUI not yet run on a phone — see §12, §13**
**Date: 2026-10-22**

## Scope

A third sync channel, next to the shared folder (`sync-protocol.md` §7) and
"Sync with a nearby device" ([`lan-transport.md`](lan-transport.md)): two
devices that **already trust each other** move sync data — and, if the user
asks, a vault key — with **no network at all**. One device plays an animated
stream of QR codes on its screen; the other films it with its camera.

The channel is one-way. The receiver never answers the stream, so the stream
uses a fountain code (§5): any large-enough subset of frames, in any order,
with any duplicates, rebuilds the data. An optional still "what I have" code
(§4) lets the receiver tell the sender, before the stream starts, which
changes it already holds; without it the sender sends everything.

It changes **no** op format, no merge rule, no verifier rule, no key-share
format and no pairing rule. It adds:

- one file format, the **bundle** (§3), built from the encodings
  `lan-transport.md` §6.2 already defines;
- one still code, **"what I have"** (§4), whose body is the `INVENTORY`
  encoding;
- one **frame** format (§6) wrapping RaptorQ symbols (RFC 6330), and the QR
  parameters that carry it (§7).

Received data goes through the same ingest function as the folder and the
nearby link (`lp_sync::engine::ingest`), so the §5 verifier and §4 merge decide
everything (§9).

What it is **not**:

- Not a pairing channel. Both devices must already have pinned each other
  (`device-pairing.md`). The stream carries no identity and grants no trust.
- Not a secure channel. It has no confidentiality and no authentication of its
  own, and needs none: everything it carries is already encrypted and signed
  (§1). A camera, a screen recording or a bystander's phone sees exactly what a
  copy of the sync folder would show.
- Not new cryptography. It uses BLAKE3 and CRC-32 only as integrity checks
  against accidental corruption, and RaptorQ, an erasure code with no secret.

---

## 1. Goals and threat model

The QR channel is **untrusted**, in exactly the sense the sync folder is
(`sync-protocol.md` §7, §9): anyone may show anything to the camera, and anyone
may film the screen. The design rests on what is already true of the data:

- **Ops** are encrypted under the vault key and signed by their author device
  (`sync-protocol.md` §1). The receiver accepts an op only if its author is a
  pinned peer and the §5 chain checks pass.
- **Vault-key shares** are the signed `LPS2` blob (`sync-protocol.md` §7.1):
  sealed to the recipient's X25519 key, signed by the sender's Ed25519 key, and
  adopted only if the sender is pinned and the signature verifies before
  unsealing.
- **Attachment blobs** (opt-in, §3.5) are content-addressed ciphertext; the
  receiver re-hashes each one and stores only blobs its own vault references.

| Goal | How |
|------|-----|
| Security does not depend on the channel | Every accept/reject decision is made by the §5 verifier, the `LPS2` checks or a content hash — the same code as the folder (§9). The bundle header, the frames and the "what I have" code are advisory. |
| No network | Nothing is sent or received on any socket. The only inputs are camera frames and (CLI) a file. |
| One-way | RaptorQ fountain code (§5): the receiver never replies; lost, reordered and duplicated frames cost only time. |
| Bounded against a hostile stream | Every field is validated before allocation or before it reaches the RaptorQ decoder, which panics on some malformed inputs (§8). Size, symbol and time caps. |
| Fail closed | A bundle whose hash does not match, whose structure is malformed or whose version is unknown is refused whole; nothing is ingested (§9.1). |
| Only what is needed | The optional "what I have" code (§4) reduces the bundle to the ops the receiver lacks. It can only change *what is sent*. |

Threats (PRD §8):

- **T4 / T5 — a hostile "channel".** Here the channel is the air between a
  screen and a camera. An attacker can film it (confidentiality: §11.1), show
  their own codes to the camera (forgery: §11.2), or show a modified "what I
  have" code to the sender (§11.3). None of these can inject an op, a vault
  key or a blob the folder channel would refuse.
- **T13 — rollback / replay.** Unchanged: a replayed stream re-delivers ops
  the receiver already holds (idempotent skip) or ops that fail the seq /
  prev_hash checks (alarm).
- **Resource exhaustion by a hostile stream.** Caps on the declared bundle
  size, symbol size and symbol count, checked before allocation; a cap on the
  symbols held; a stall timeout and an overall timeout (§8).

Honest residual risks:

- **Metadata is visible to anyone who films the screen**: vault ids, device
  ids, seq numbers, Lamport clocks, op kinds' sizes, and the timing — the same
  set the sync folder exposes (`sync-protocol.md` §9 T5). The ciphertext
  reveals nothing else.
- **A hostile "what I have" code makes the sender omit ops** (it claims the
  receiver already has them). The receiver then simply lacks them until the
  next sync; nothing is corrupted (§11.3).
- **A stream someone else shows the camera** can fill the receiver's buffer
  with junk symbols carrying the right transfer id; the transfer then fails its
  hash check and must be restarted (denial of service only; §11.2).

---

## 2. Overview

```text
 Device R (receiver, has a camera)               Device S (sender, has a screen)
 ─────────────────────────────────               ───────────────────────────────
 Receive by QR                                    Send by QR
  (optional) show "what I have" — one still QR ──► (optional) scan it: per-vault,
   receiver id + per-vault per-device seq heads       per-device heads (§4)
                                                    build the bundle (§3):
                                                      shares + ops R lacks
                                                    RaptorQ-encode it (§5)
  scan continuously  ◄─── frames: QR codes, ~N/s ──  play frames full-screen (§6, §7)
   reject bad frames (CRC, transfer id, caps)          source symbols first, then repair
   feed symbols to the RaptorQ decoder                 symbols, forever, until stopped
   ── enough symbols ──►  bundle bytes
   check the BLAKE3 hash, parse with caps (§3, §8)
   adopt shares (§9.2), ingest ops (engine::ingest)
   show the report                                  user stops the player
```

Both devices hold every vault they sync; S decides what to send from R's
heads, exactly as a nearby session's round 3 does (`lan-transport.md` §6.3).
A full sync of both directions is two transfers, one each way.

---

## 3. The bundle

The bundle is the unit a transfer moves: one byte string, at most
`MAX_BUNDLE_BYTES` (§8). It is also a file (`.lpqr`) for the CLI, so a bundle
can travel on a USB stick and be tested without cameras.

### 3.1 Layout

```text
bundle = header || body

header
  magic            4   "LPQB"
  version          1   0x01
  flags            1   bit 0: the body has an attachments section (§3.5);
                       bits 1..7 must be 0
  sender           16  device id of the device that built the bundle
  recipient        16  device id the bundle was built for, or 16 zero bytes
  vault_count      2   u16 LE, n ≤ MAX_VAULTS
  vault_ids        16 × n   the vaults whose ops the body carries, strictly
                       ascending
  body_len         4   u32 LE
  hash             32  BLAKE3( every header byte before this field || body )

body
  shares           u32 len || HELLO body (lan-transport.md §6.2):
                     u16 m || m × ( vault_id[16] || u32 len || LPS2 share blob )
  ops              n × ( u32 len || OPS body )      one per vault_ids entry, same order
                     OPS body = vault_id[16] || segment body   (lan-transport.md §6.2)
  attachments      present iff flags bit 0:
                     u32 k || k × ( u32 len || BLOB body )
                     BLOB body = vault_id[16] || hash[32] || blob bytes
```

- Integers are little-endian, ids are raw 16-byte UUIDs, as in
  `lan-transport.md` §5.3.
- `segment body` is exactly the `.oplog` body (`sync-protocol.md` §7.1),
  written and read by `lp_sync::wire::encode_segment` / `decode_segment`. The
  `HELLO`, `OPS` and `BLOB` bodies are written and read by the nearby message
  codecs (`lp_sync::nearby::message`), unchanged.
- The `OPS` body's own vault id must equal `vault_ids[i]`, and every op inside
  must belong to that vault (the nearby decoder already checks the second).
- Every section is length-prefixed so the nearby decoders, which refuse
  trailing bytes, read each body exactly.
- Lists are strictly ascending by id; a decoder refuses anything else, and
  refuses trailing bytes after the last section and after the bundle.

### 3.2 What the header is for

The header lets the receiver show *what arrived* before ingesting it ("2
vaults, from Ray's laptop, built for this phone") and lets a decoder refuse a
wrong or damaged bundle before parsing the body. **It is advisory.** Nothing
in it is authenticated, and no security decision rests on it:

- `sender` is used only to require that every share's own sender field (bytes
  4..20 of the `LPS2` blob) equals it — the closest a one-way channel can come
  to `lan-transport.md` §6.6 step 1. The share's signature, checked by
  `lp-vault` against the sender's **pinned** key, is what authenticates it.
- `recipient` lets the receiver say "this was made for another device". A
  share sealed to another device fails to unseal regardless.
- `hash` catches corruption and a stream of two bundles' frames mixed
  together. It is not a MAC: an attacker who builds their own bundle computes
  their own hash (§11.2).

A bundle is **not signed** as a whole. A signature would need a fourth Ed25519
signing context and would protect nothing the per-op signatures, the `LPS2`
signature and the content hashes do not already protect: the receiver ingests
ops and shares, never "a bundle".

### 3.3 What the sender puts in it

The user picks the vaults to send (default: every vault on the device) and,
optionally, vaults to share and the pinned device to share them with.

- **With a "what I have" code** (§4): for each picked vault that the code also
  lists, every op the sender holds with `seq` above the code's head for its
  author (0 if not listed), except ops authored by the code's device — the
  rule of `lan-transport.md` §6.3, ascending by `(device_id, seq)`. A picked
  vault the code does not list is left out, unless it is also being shared:
  the receiver could not decrypt it.
- **Without a code:** every op of every picked vault, and of every vault being
  shared.
- **A shared vault** always travels in full, together with its share. The
  receiver adopts the share first (§9.2), so one transfer both hands over a
  vault and fills it — the same property `lan-transport.md` §6.6 gives the
  nearby link.
- A vault with nothing to send is left out of `vault_ids`.

The sender refuses to build a bundle above `MAX_BUNDLE_BYTES` and says how
large it would be; the user can pick fewer vaults, scan a "what I have" code,
or use the folder or the nearby link.

### 3.4 Shares

A share is the unchanged signed `LPS2` blob, built by
`Session::share_vault_key_to_peer` for the device the user picked from their
pinned peers. It is sealed to that device's pinned X25519 key and signed by
this device. Sharing requires naming the device, exactly as for the folder and
the nearby link; the "what I have" code's device id may **pre-select** it in
the GUI, if that device is pinned, but never sends a share by itself (§4.3).
When the bundle carries shares, `recipient` must be that device.

### 3.5 Attachments: excluded by default

Attachment blobs are left out unless the user asks for them, because a QR
stream moves kilobytes per second (§12) and one attachment may be 50 MiB. When
asked (`--attachments`, a GUI checkbox):

- the sender adds, for each vault in `vault_ids`, the blobs its live
  attachments reference — or, with a "what I have" code, the same set (the
  code does not list blobs; a blob the receiver already holds is skipped on
  arrival) — as long as the bundle stays under `MAX_BUNDLE_BYTES`, and reports
  how many it left out;
- the receiver stores a blob only if it is in the "referenced but missing"
  set its vault computes after ingesting the ops (`sync-protocol.md` §7.3 step
  5), through `Vault::store_attachment_blob`, which re-hashes it and refuses a
  mismatch (an alarm). A blob nobody asked for is ignored.

Attachments that did not travel stay pending, exactly as in file sync, and
arrive with a later folder or nearby sync.

---

## 4. The "what I have" code

An optional, **single still QR code** the receiver shows before the stream
starts. The sender scans it once.

### 4.1 Layout

```text
have = magic "LPQH" (4) || version 0x01 (1) || device_id (16)
       || INVENTORY body || crc32 (4)

INVENTORY body = u16 n || n × ( vault_id[16] || u16 m || m × ( device_id[16] || seq u64 ) )
                                                         (lan-transport.md §6.2)
crc32 = CRC-32 (IEEE 802.3, the one LPDEV1 uses) of every preceding byte, LE
```

- `device_id` is the receiver; `INVENTORY` lists every vault it holds (or the
  vaults its user picked) with, per author device, the highest seq held —
  `lp_sync::engine::vault_heads`, the same value a nearby session sends.
- The decoder is the nearby `INVENTORY` decoder (counts checked against
  `MAX_VAULTS` / `MAX_HEADS` before allocating, strictly ascending lists, no
  trailing bytes), behind a total size cap of **`MAX_HAVE_BYTES` = 2953**, the
  byte-mode capacity of the largest QR symbol (version 40, ECC L).
- Text form, for the CLI and for pasting: `LPHAVE1-` followed by lowercase hex
  of the same bytes. Scan and paste decode to the same bytes and go through the
  same parser (the `LPDEV1` rationale, `device-pairing.md` §3.1).

A receiver whose inventory does not fit says so and offers to receive
everything instead (or to list fewer vaults). With the target sizes of PRD
§5.7 most devices fit easily: a vault with three devices is 90 bytes.

### 4.2 QR parameters of the still code

Byte mode, ECC level **M**, the smallest version that fits (version 40 at most;
a code that does not fit M at version 40 uses L). A still code can be scanned
at leisure, so its density matters less than the stream's; the CRC rejects a
misread.

### 4.3 It is unauthenticated — so it may only change what gets sent

The code comes from a screen the sender's camera sees; anyone could show a
different one. Its effect is therefore limited **by construction** to the set
of ops the sender selects (§3.3):

- It never adds a vault to the bundle that the sender's user did not pick, and
  never causes a share. Its `device_id` may pre-select the share recipient in
  the GUI, which the user still confirms, and only among pinned devices.
- It never reaches the receiver's ingest: the receiver does not read its own
  code back, and nothing in the bundle records it except `recipient`.
- A malformed, oversized or CRC-failing code is refused with an error; the
  sender's user can scan again or send everything.

A hostile code can make the sender omit ops (heads too high) or send more than
needed (heads too low). Both are bounded by the bundle cap, and neither changes
what the receiver accepts (§11.3).

---

## 5. Fountain code: RaptorQ

### 5.1 Choice

RaptorQ (RFC 6330) is a systematic fountain code: the first `K` encoding
symbols are the data itself, followed by an unlimited supply of repair
symbols, and **any** `K` received symbols — source or repair, in any order —
decode with probability about 99%, `K + 2` with about 99.9999% (RFC 6330 §1).
That is what a one-way, lossy, reordering channel needs: the sender loops
forever, the receiver collects whatever it catches, and no frame is special.

Alternatives considered: a plain carousel (re-show frames 0..K−1 in a loop)
needs the receiver to catch *every* frame, so the last missing frame costs a
whole extra loop; LT codes need more overhead and a hand-written implementation;
a bespoke code is novel code in a security product.

Implementation: the [`raptorq`](https://crates.io/crates/raptorq) crate
(version 2.x, **Apache-2.0** — on the `deny.toml` allowlist; no required
dependencies; edition 2024 within the workspace MSRV). It is an erasure code,
not a cryptographic primitive, so it lives in `lp-sync` rather than behind the
`lp-crypto` boundary. Its own code contains `unsafe` (SIMD symbol arithmetic);
`lp-sync` keeps `#![forbid(unsafe_code)]` for its own code.

### 5.2 Parameters

- **One source block**, **one sub-block**, **symbol alignment 1**. The bundle
  is padded with zeros to `K × T` bytes, `K = ceil(F / T)`, where `F` is the
  bundle length and `T` the symbol size. The decoder output is truncated to
  `F`.
- The transmission parameters are **not** RaptorQ's serialized OTI: the
  receiver builds them itself from the frame's `bundle_len` and `symbol_size`
  after checking them (§8). The `raptorq` constructors assert on bad
  parameters (a panic), so nothing unchecked ever reaches them.
- Encoding symbol ids (ESI) `0..K` are the source symbols; repair symbols use
  ESI `K, K+1, …` up to `2^24 − 1` (RFC 6330's 24-bit ESI).
- The sender plays all source symbols first, then repair symbols, and keeps
  going until the user stops it. A receiver that starts late simply collects
  repair symbols.

### 5.3 Decoding

The receiver keeps one `SourceBlockDecoder` per transfer, feeds it each
accepted symbol (or a batch), and tries to decode once it holds `K` distinct
symbols. It holds at most `K + MAX_EXTRA_SYMBOLS` (§8); if decoding still
fails, or the decoded bundle fails its hash check, the transfer is abandoned
and the user starts it again (§9.1). Normal decoding never comes near that
cap.

---

## 6. Frames

### 6.1 Layout

Each QR code in the stream carries exactly one frame:

```text
offset  size  field
0       2     magic          "LQ"
2       1     version        0x01
3       8     transfer_id    the first 8 bytes of the bundle's `hash` field (§3.1)
11      4     bundle_len     u32 LE: F, the bundle length in bytes
15      2     symbol_size    u16 LE: T
17      4     esi            u32 LE: the encoding symbol id, < 2^24
21      T     symbol         the RaptorQ encoding symbol
21+T    4     crc32          CRC-32 (IEEE) of bytes 0..21+T, LE
```

A frame is exactly `25 + T` bytes. The source block number is always 0 and is
not sent.

### 6.2 What each field is for

- **`crc32`** rejects frames the QR decoder misread. QR's own Reed–Solomon
  correction makes that rare, but a single corrupt symbol would make the whole
  RaptorQ decode produce garbage, and the receiver could not tell which frame
  was bad (§5.3). A frame that fails the CRC is dropped and counted.
- **`transfer_id`** ties frames to one bundle. The receiver locks onto the
  first valid frame's `(transfer_id, bundle_len, symbol_size)`; frames that
  differ in any of the three are dropped and counted (another stream, or a
  sender that restarted with different data). Deriving it from the bundle
  hash means the receiver checks it again after decoding (§9.1).
- **`bundle_len`, `symbol_size`** let a receiver that missed the start build
  its decoder from any frame.

### 6.3 Why not RaptorQ's own packet format

RFC 6330's packet is `SBN (1) || ESI (3) || symbol`, and its transmission
parameters travel out-of-band. A camera receiver can join at any frame, so
every frame must carry them, and it must say which transfer it belongs to. The
frame above is that, plus a version byte and a CRC, in LocalPass's
little-endian convention.

---

## 7. QR symbols: mode, version, error correction, frame rate

> This section's numbers were chosen from the on-device measurements in §12.
> Each one is a sender-side default: the receiver accepts any `T` within its
> caps and does not care which QR version carried a frame.

### 7.1 Mode: byte

Each frame is encoded as **one byte-mode segment**, raw bytes, no ECI. Both
decoders LocalPass uses are jsQR — on desktop (webcam) and on Android (the
WebView's camera, §10.4) — and jsQR returns a byte-mode segment's raw bytes
(`binaryData`), so binary frames need no text encoding. Alphanumeric mode with
base45 would be decodable by more generic scanners but carries ~3% less, and
is not needed: only LocalPass reads these codes.

### 7.2 Version, error correction and frame rate

| | Default | Why |
|---|---|---|
| Error correction | **L** (~7%) | A misread frame fails its CRC (§6.2) and the fountain code replaces any lost frame, so correction capacity buys little; L carries the most bytes per code. ECC M did not catch more frames in the measurements (§12). |
| Version, desktop sender | **25** (117 × 117 modules; 1 273 bytes in byte mode, `T` = 1 248) | The receiver is usually a phone camera filming a laptop screen. Every measured catch rate was limited by the phone's decode speed, not by the code's size, so the largest code the camera still resolved carried the most per second: version 25 gave the best rate in all three runs (§12). Version 30 was harder to hold in view and slower. |
| Version, phone sender | **15** (77 × 77 modules; 520 bytes, `T` = 495) | The receiver is usually a laptop's fixed-focus webcam filming a phone screen. It could not read version 25 at all (it blurs at the distance that makes the code large enough) and read version 15 best (§12). |
| Frame rate | **10 frames/s**, adjustable 3–15 | Each code must be on screen for at least two camera frames (30 fps → ≥ 66 ms) or the camera sees two codes blended. 15 frames/s caught fewer frames than 10 in every measured pair, because the decoder — not the display — is the limit. |

The sender's platform picks the default code size and the user can switch it
("Large — when a phone camera films this screen" / "Small — when a laptop
webcam films this screen"). The receiver accepts either: it learns `T` from
the frames.

**Decoding on the receiver.** The camera loop samples the middle square of each
camera frame, scaled to at most 720 pixels, and hands it to jsQR running in
Web Workers (two where the device has at least four cores), so decoding does
not block the page and a multi-core phone examines more frames per second.
Only one frame is in flight per worker; a camera frame that arrives while every
worker is busy is skipped.

---

## 8. Limits against a hostile stream

Everything a camera sees is attacker-controlled. Each check happens before
the allocation or call it protects.

| Limit | Value | Checked |
|-------|-------|---------|
| Frame length | exactly `25 + T`; at most `25 + MAX_SYMBOL_SIZE` | before parsing |
| Frame magic, version, CRC | `"LQ"`, `1`, valid | before anything is kept |
| `symbol_size` T | `MIN_SYMBOL_SIZE` 256 ≤ T ≤ `MAX_SYMBOL_SIZE` 2928 (the byte capacity of QR version 40-L minus the frame overhead) | before building a decoder |
| `bundle_len` F | 1 ≤ F ≤ `MAX_BUNDLE_BYTES` (8 MiB) | before building a decoder |
| Source symbols K | `ceil(F / T)` ≤ `MAX_SOURCE_SYMBOLS` 32 768 (RaptorQ's own maximum is 56 403; the two caps above already imply ≤ 32 768) | before building a decoder |
| `esi` | < 2^24 | before the symbol reaches the decoder |
| Symbols held | distinct ESIs only, at most `K + MAX_EXTRA_SYMBOLS` (64); further symbols are dropped | per frame |
| Memory | ≈ F plus 64 × T (symbols are T bytes and F ≤ 8 MiB) | follows from the caps |
| Frames from another transfer | dropped and counted; after 10 000 of them with no progress the receiver stops and says so | per frame |
| Stall | no new symbol for 60 s → stop with "the stream stopped" | timer |
| Whole transfer | 30 minutes from the first accepted frame → stop | timer |
| Bundle | structure checked against the caps of §3.1 and `lan-transport.md` §5.4 (shares ≤ 64, vaults ≤ 1024, heads ≤ 4096), strictly ascending lists, no trailing bytes | before ingest |
| "What I have" code | ≤ 2953 bytes, CRC, the `INVENTORY` caps | before use |

The RaptorQ decoder is reached only with a source block number of 0, a symbol
of exactly `T` bytes, and transmission parameters the receiver built from
checked values — the three inputs on which the `raptorq` crate asserts.

---

## 9. Receiving and ingest

### 9.1 Reassembly (fail closed)

When the decoder yields `F` bytes:

1. The first 8 bytes of the bundle's `hash` field equal the frames'
   `transfer_id`, and `BLAKE3(header-before-hash || body)` equals `hash`.
   Otherwise the transfer is refused whole ("the stream was damaged"), nothing
   is ingested, and the user can start again.
2. The header and body parse within every cap (§8); otherwise refused whole.
3. Unknown `version` or a set reserved flag bit → refused ("made by a newer
   LocalPass").

Only then does anything touch the vault.

### 9.2 Shares first

For each share in the body, in order:

1. Its sender field (bytes 4..20 of the `LPS2` blob) must equal the header's
   `sender`; otherwise refused ("the share was not made by the sending device").
2. `Session::import_shared_vault_key`, unchanged: the sender must be **pinned**
   (or this device), and the signature over vault id, recipient and sender is
   verified **before** unsealing. A share sealed to another device fails here.
3. A refused share is reported as an alarm and never blocks the rest — the
   rule of `sync-protocol.md` §7.1 and `lan-transport.md` §6.6.

### 9.3 Ops — the §5 verifier and §4 merge, unchanged

For each `OPS` section, if the vault is held here (including one just adopted
in §9.2), its ops go to `lp_sync::engine::ingest` — the function `pull` and the
nearby link call — which drops this device's own ops, builds the chain state
from local storage and pinned keys, runs `verify::verify_batch` (signature,
seq, prev_hash, Lamport), folds the full op set through `merge::materialize`
and applies it in one transaction. Quarantines and pending holds are reported
as a file pull reports them. A section for a vault this device does not hold
is skipped and reported ("not on this device").

Because the ingest is the same function over the same op bytes, receiving a
bundle leaves the vault in **exactly** the state a folder pull of the same ops
would (tested: §14).

### 9.4 Attachments

After the ops, as in §3.5: only blobs in the referenced-but-missing set are
stored, each re-hashed by `Vault::store_attachment_blob`; a mismatch is an
alarm.

### 9.5 Report

Per vault: ops in the bundle, applied, skipped (already held), pending,
quarantines; blobs stored, ignored, tampered; shares adopted and refused; and
the header's sender and recipient, labelled as the sender **claims**.

---

## 10. Interfaces

### 10.1 Layering

| Layer | Crate | Contents |
|-------|-------|----------|
| Bundle, "what I have", frames, fountain | `lp-sync` (`qr`) | build and ingest bundles over the unlocked `Session`; `FrameEncoder` / `FrameDecoder` over bytes only — no camera, no QR rendering, no Tauri |
| Requests | `lp-daemon` | `QrHaveCode`, `QrExport`, `QrImport` (path-based, §10.2) |
| Command | `lp-cli` | `sync qr have / export / import` (§10.3) |
| QR rendering, player, scanner | `apps/desktop` | the Rust backend renders frames to QR module matrices with the `qrcode` crate; the webview draws them and runs the camera + jsQR loop (§10.4) |

### 10.2 Daemon requests (additive; every new field is `#[serde(default)]`)

| Request | Fields | Answer |
|---------|--------|--------|
| `QrHaveCode` | `profile`, `vaults[]` | `QrHaveCode { code, vaults }` — `code` is the `LPHAVE1-…` text (§4.1) |
| `QrExport` | `profile`, `out_path`, `vaults[]`, `have?`, `peer?`, `share[]`, `attachments`, `force` | `QrExported { summary }` |
| `QrImport` | `profile`, `path`, `transfer_id?` | `QrImported { report }` — `transfer_id` is the id the frames carried (16 hex chars), which must match the bundle (§9.1 step 1) |

Like attachments, bundles move **by path**: the daemon writes and reads the
file itself, so bundle bytes never cross the IPC pipe (whose frame cap is 16
MiB) and the GUI never holds a vault-side object. `QrExport` refuses to
overwrite an existing file unless `force`. `vaults` and `share` take names or
ids; `share` requires `peer`. **While an AI agent is connected**, a `QrExport`
with a non-empty `share` needs the master password first (`mcp-server.md`
§7.1), like `ShareVaultToDevice` and a nearby session that shares.

No new audit kind: an export is the folder's push and an import its pull,
neither of which is audited; a share sent by QR is recorded by the existing
`vault_share` kind, written by `share_vault_key_to_peer`.

### 10.3 CLI

```text
localpass sync qr have   [--vault V]… [--json]
localpass sync qr export --out FILE [--vault V]… [--have LPHAVE1-…] [--peer DEVICE --share V…] [--attachments] [--force] [--json]
localpass sync qr import FILE [--json]
```

The bundle file is byte-identical to what a QR stream carries, so `export` on
one device and `import` on another is the whole channel minus the camera —
useful for a USB stick and for testing. Like every `localpass sync` command it
unlocks directly; an alarm (quarantine, refused share, tampered blob) exits
non-zero, as `sync pull` does.

### 10.4 GUI (desktop and Android)

New components, with one small entry point on the Devices screen:

- **Send by QR** (`QrSend.svelte`): pick vaults (default all); optionally
  "Share a vault" with a pinned device; optionally "Include attachments
  (slow)"; optionally scan the receiver's "what I have" code. Then a
  full-screen player: the QR as large as the screen allows, a frame counter,
  pause, speed and stop, and the estimate of §12.
- **Receive by QR** (`QrReceive.svelte`): optionally show "what I have" first;
  then a continuous scanner with a progress bar (symbols held of `K`), the
  rejected-frame counts, Cancel; then the report.

The webview **renders and samples**; Rust **decides**. The backend builds the
bundle (via the daemon), runs the RaptorQ encoder, and renders each frame to a
QR module matrix with the `qrcode` crate (the same crate the pairing QR uses);
the webview draws the matrix on a canvas. On the receiving side the webview
runs the camera and jsQR and passes each decoded frame's bytes to the backend,
which validates frames (§8), runs the decoder and the checks of §9.1, and hands
the finished bundle to the daemon by path.

**Camera.** Desktop: `getUserMedia` + jsQR, the loop `CameraScan.svelte`
already uses, in continuous mode, with jsQR in Web Workers (§7.2). Android: the
same loop inside the app's WebView (§12.1 records why this, and not a native
plugin): the WebView's `WebChromeClient` (generated by Tauri's `wry`) turns the
page's camera request into the Android `CAMERA` runtime permission, which the
app already declares. **Not** ML Kit or the `BarcodeDetector` web API (backed
by Google Play services on Android): both are proprietary.

**Code size.** The sender offers "Large" (version 25) and "Small" (version 15)
and defaults by its own platform (§7.2).

---

## 11. Threat notes

### 11.1 Someone films the screen

They get the bundle: ciphertext ops, sealed shares and metadata — the same
thing a copy of the sync folder gives (`sync-protocol.md` §9 T5). Ops are
encrypted under the vault key; a share is sealed to the recipient's X25519 key
and useless to anyone else. What they *learn* is the metadata of §1. Showing
the stream in a private place is good practice, not a security requirement.

### 11.2 Someone shows the camera a forged stream

- Frames with another `transfer_id` are dropped.
- Frames with the right `transfer_id` but forged symbols make the decode
  produce garbage, which fails the BLAKE3 check: the transfer is refused and
  nothing is ingested (denial of service).
- A whole forged bundle with a correct hash of its own: every op in it is
  checked by the §5 verifier against pinned keys — an op not signed by a pinned
  device is rejected and alarmed (`UnknownDevice`, bad signature, broken chain);
  a genuine op replayed from an old stream is skipped as already held, or
  alarmed as a replay. A share is adopted only if a **pinned** device signed it
  for **this** device; one from an untrusted sender is refused. A blob is
  stored only if this vault references it and its hash matches.

### 11.3 Someone shows the sender a forged "what I have" code

It changes only which ops the sender selects (§4.3): the receiver may get
fewer ops than it needed (it gets the rest at the next sync) or more (skipped
as already held). It cannot add a vault the sender's user did not pick, cannot
trigger a share, and never reaches the receiver.

### 11.4 Security summary

| Property | Folder | Nearby link | QR stream |
|----------|--------|-------------|-----------|
| Ops accepted only from pinned authors, §5-verified | yes | same code path | **same code path** |
| Merge | §4 | same code path | **same code path** |
| Vault-key share | signed `LPS2`, pinned sender | + sender is the authenticated peer | + sender matches the bundle's claimed sender (advisory) |
| Transport confidentiality | none (ops are E2EE) | Noise | none (ops are E2EE) |
| Who can inject | anyone with folder access | pinned devices only | anyone in front of the camera — and the verifier rejects them |
| Network | the folder's sync tool | local network | none |
| New signing context | — | `localpass/v1/sign/lan-handshake` | none |

---

## 12. Measurements

### 12.1 Continuous scanning on Android: getUserMedia in the Tauri WebView

The main risk was whether an Android phone can scan a stream continuously at
all: the existing `tauri-plugin-barcode-scanner` scans one code and stops, and
ML Kit (what most Android scanners use) is proprietary and ruled out.

A throwaway Tauri 2 app (`org.localpass.qrproto`, installed beside LocalPass,
release build with `devtools`) ran a getUserMedia + jsQR loop on a real phone
(Xiaomi 21061110AG, Android 11, Android System WebView 155) and was driven
over the WebView's DevTools socket:

- The page is a **secure context** (`http://tauri.localhost`), so
  `navigator.mediaDevices` and `requestVideoFrameCallback` exist.
- `getUserMedia({ video: { facingMode: "environment" } })` opened the back
  camera at 1080 × 1920, 30 frames/s, with continuous focus. The WebView's
  permission request reached the Android `CAMERA` runtime permission through
  the `WebChromeClient` Tauri's `wry` generates (`onPermissionRequest` maps
  `VIDEO_CAPTURE` to `CAMERA` and grants the page once the user allows it). The
  only app-side requirement is the `CAMERA` permission in the manifest, which
  LocalPass already declares (through the barcode-scanner plugin).
- The loop decoded the stream continuously for minutes.

**Decision:** the Android receiver uses the same getUserMedia + jsQR loop as the
desktop. A Kotlin CameraX + ZXing plugin was not needed and was not built; it
remains the fallback if a WebView version regresses camera access. It would
add a native plugin, a JNI surface and Gradle dependencies to keep current, for
a decoder that is not obviously faster than jsQR in a worker.

### 12.2 Throughput, measured

Method: the sender shows a stream of distinct test frames full-screen; the
receiver's page counts **distinct frames decoded per second** (each frame of a
fountain stream is new information, so this is the useful rate) over 12–15 s
per configuration. Hand-held, indoor lighting, 2026-10-22. Laptop: 15.6"
1920 × 1080 panel at 125% scaling (the code about 18 cm wide). Receiver decode:
**jsQR on the main thread** (the worker pool of §7.2 came after these runs and
was not measured on the phone).

**Phone camera filming the laptop screen** (three runs; the phone grew warm
and slowed down over the ~15 minutes, see the decode times):

| Run (sample, mean decode) | QR | fps | Frames/s caught | Throughput |
|---|---|---|---|---|
| 1 (720 px, ~92 ms) | 15-L | 10 | 5.9 | **3.1 KB/s** |
| 1 | 25-L | 10 | 5.6 | **7.1 KB/s** |
| 2 (800 px, ~190 ms) | 15-M | 10 | 4.0 | 1.7 KB/s |
| 2 | 20-M | 10 | 3.0 | 2.0 KB/s |
| 2 | 25-L | 10 | 2.5 | 3.2 KB/s |
| 2 | 25-M | 10 | 2.6 | 2.6 KB/s |
| 2 | 25-L | 15 | 1.9 | 2.4 KB/s |
| 2 | 30-L | 10 | 1.5 | 2.6 KB/s |
| 3 (600 px, ~150 ms) | 25-L | 10 | 3.9 | **4.9 KB/s** |
| 3 | 25-M | 10 | 2.7 | 2.7 KB/s |
| 3 | 15-L | 15 | 3.0 | 1.5 KB/s |

**Laptop webcam (integrated, 1280 × 720, fixed focus) filming the phone
screen** (one run, 720 px sample, ~50–80 ms decode):

| QR | fps | Frames/s caught | Throughput |
|---|---|---|---|
| 25-L, 25-M | 10 | 0 (never decoded: blurred at the distance that makes it large enough) | — |
| 20-L | 15 | 1.8 | 1.6 KB/s |
| 15-L | 15 | 5.0 | **2.6 KB/s** |

Runs and configurations not listed (20-L in runs 1–3, 20-L at 15 fps in run
3) did not collect enough decodes to report: the phone was still being aimed.

What this means in practice, from these numbers only: a **100 KB** bundle (a
few hundred changes) takes **about 15–40 seconds** from a laptop to a phone and
**about 40 seconds** from a phone to a laptop webcam; **1 MB** takes minutes.
That is why the "what I have" code (§4) is recommended and attachments are off
by default (§3.5).

### 12.3 Not measured

- The production components (`QrSend` / `QrReceive` / `QrCamera` with the
  worker pool) on a phone: they were checked on desktop with unit tests and
  `svelte-check`, not run on the device. The worker pool is expected to raise
  the phone's rate (two decodes at once), but that is not measured.
- Other phones, tablets, iOS, external webcams, daylight or very dim rooms, and
  OLED flicker at low brightness.
- A full transfer of a real vault from camera to import on a phone.

**Plan for the missing measurements:** build LocalPass for Android (separate
application id so the installed app is untouched), then for each direction and
code size send a real bundle of a known size (`localpass sync qr export` prints
it) with and without a "what I have" code, and record the time from the first
accepted frame to `complete`, the frames shown (player counter) and the frames
received (progress line). Repeat with the phone propped up at 25 and 40 cm, and
once after 10 minutes of use to see thermal throttling.

---

## 13. Built in this version, and not

Built: the spec; `lp-sync::qr` (bundle build and ingest, "what I have",
frame codec and RaptorQ fountain over bytes); the `QrHaveCode` / `QrExport` /
`QrImport` daemon requests; `localpass sync qr have|export|import`; the GUI
(`QrSend.svelte`, `QrReceive.svelte`, `QrCamera.svelte`, `lib/qrstream.ts`,
`lib/qrworker.ts`, `src-tauri/src/qrsync.rs`) with a small entry on the
Devices screen; Help text.

Not built / follow-ups:

- An on-device run of the production GUI on Android (§12.3).
- A native CameraX + ZXing scanner — not needed (§12.1); the fallback if the
  WebView path regresses.
- Fuzz targets for the frame, bundle and "what I have" decoders
  (release-checklist §1).
- Structured append or multi-code frames (more than one code on screen at a
  time); colour QR codes.
- Signing a bundle as a whole — deliberately not done (§3.2).

## 14. Test plan

Covered in `crates/lp-sync/src/qr/` (unit), `crates/lp-sync/tests/qr.rs`
(real accounts), `crates/lp-daemon/src/qr.rs`, `crates/lp-cli/tests/qr.rs` (two
real `localpass` profiles), `apps/desktop/src-tauri/src/qrsync.rs` (unit) and
`apps/desktop/src/lib/qrstream.test.ts` (vitest):

- A bundle that shares and fills a 50-op vault goes through the encoder, a
  channel that **drops 30%** of frames, **shuffles** the rest and **duplicates**
  some, the decoder and the import: the vault is adopted, every op applies,
  and a folder push + pull between the two devices afterwards applies
  **nothing** — the QR stream produced exactly the file-sync state. Importing
  again is idempotent.
- Edits on both sides cross in two transfers; with a "what I have" code each
  bundle carries only the missing ops (and never the receiver's own); without
  one, everything travels and the receiver skips what it holds.
- A **hostile "what I have" code** — heads claimed too high, a vault the user did
  not pick, a code from another device than the share recipient, heads of zero
  — changes only what is selected; it never adds a vault or a share and never
  changes what the receiver accepts.
- A **tampered bundle** is refused whole by its hash (no state change); the
  same tampering with a recomputed hash is caught by the §5 verifier
  (`SignatureInvalid` quarantine, nothing applied); frames whose transfer id
  does not match the bundle are refused at import.
- A share from a device the receiver **did not pin** is refused and no vault
  appears; ops a pinned author made, forwarded by an unpinned sender, verify,
  while the unpinned sender's own ops are quarantined (`UnknownDevice`).
- Attachments stay behind by default (reported missing) and travel on request,
  re-hashed, once.
- Frames: every flipped bit fails the CRC; out-of-range declared sizes, a
  symbol of the wrong length, an ESI beyond 24 bits, a wrong magic or version
  are refused before a decoder exists; a frame of another transfer is dropped
  and counted; junk symbols under the right transfer id are capped at `K + 64`
  and never decode to the data; a stalled transfer times out; a stream mixed
  with another transfer's frames, corrupt frames and unrelated codes still
  completes.
- Bundles: every flipped bit is refused; unknown flags, trailing bytes,
  unsorted vault ids, an oversize vault count and a 4 GiB body length are
  refused before allocation. "What I have": round trip, a bit flip anywhere, an
  oversize input, a checksummed code claiming 65 535 vaults, non-hex text.
- CLI: share by file, then a delta with `--have`; `--force`; "nothing to send";
  a damaged file; an untrusted sender (non-zero exit, no vault); a non-bundle.
- GUI backend: the stream symbol exactly fills its QR code at both sizes;
  module packing; still-code version choice; frames of a real encoder render
  and decode back.
- JS: module reading, pixel sizing, frame-rate clamps, estimates, the frame
  feed (ESI order, no repeats, one fetch in flight, no blocking), the code
  collector (repeat suppression, bounded batches) and the decoder pool (one
  frame per worker, skipping when busy, transferred buffers, close).
