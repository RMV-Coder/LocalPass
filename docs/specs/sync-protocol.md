# LocalPass Sync Protocol — Encrypted Op Log

**Format version: 1**
**Op wire version: 2**
**Status: draft-for-implementation**
**Date: 2026-07-04**

## Scope

This document specifies LocalPass's sync model: a per-vault, op-based,
end-to-end-encrypted operation log (op-CRDT-lite, PRD §6.4). It defines the op
envelope, the deterministic total-merge algorithm (field-level LWW with
loser-preservation), the per-peer sequence hash chain that detects
rollback/tamper/drop (PRD §8 T13), a brief device-pairing trust summary, and the
**file-based log-shipping layout** — the MVP-default "dumb file channel" sync
(PRD §11 #6). Live network transports (Noise XX/IK over TCP/QUIC) and the P2
relay are out of scope here except where the on-disk log layout constrains them;
only their extension points are noted.

Fixed contracts honored: ops are encrypted with **Envelope v1** under the
`VaultKey`; ops are **signed with the device Ed25519 key** over the full op
*including* the ciphertext (sign-after-encrypt). Op rows persist in the vault
file's `ops` table (`vault-format.md` §3).

---

## 1. Op envelope structure

An **op** is the atomic unit of change and of sync. On-disk it is the `ops` row
(`vault-format.md` §3); on the wire / in a log segment it is the canonical
serialization of a **wire-version byte plus these fields**, in this exact order:

```
Op wire version 2 (signed region = version byte + fields 1..11, signature = field 12):
 0  wire_ver     : u8         = 2                -- op-format version discriminator
 1  op_id        : 16 bytes   UUIDv7            -- globally unique op identity
 2  vault_id     : 16 bytes                     -- which vault
 3  device_id    : 16 bytes                     -- authoring device
 4  seq          : u64                          -- per-device monotonic (§5)
 5  prev_hash    : 32 bytes   BLAKE3            -- hash chain link (§5)
 6  lamport      : u64                          -- Lamport clock (§3), LWW tiebreak only
 7  op_kind      : u8         enum (§2)
 8  target_item  : 16 bytes   (zero if vault-scope)
 9  target_ver   : u32        (0 if n/a)         -- item version this op establishes
10  payload_env  : var        Envelope v1 over the op payload, VaultKey-wrapped
11  observed     : var        observed-heads causal summary (§3) -- version vector
12  signature    : 64 bytes   Ed25519 over canonical bytes of version byte + fields 1..11
```

- **Wire version discriminator (field 0):** a leading `u8` a reader checks
  before parsing. Version 2 is the sole accepted version; there are **no
  released version-1 ops** (the pre-vector layout was never shipped or persisted
  in the wild), so a clean format change is safe. A reader rejects any other
  version byte as malformed.
- **Canonical serialization:** fixed-order, fixed-width integers (little-endian),
  length-prefixed `payload_env` (u32 length) and `observed` (u32 entry count +
  fixed-width entries). Deterministic so the signed bytes are reproducible on
  any device. (JSON is *not* used on the wire; the item *payload inside*
  `payload_env` is the canonical-JSON body of `vault-format.md` §4.)
- **`observed` (field 11) — the causal summary:** a compact version vector
  (device_id → highest observed `seq`) the author stamps at author time; see §3.
  It is **authenticated metadata**: encoded as `u32` entry count then each entry
  as `device_id(16) || seq(u64 LE)` with entries **ascending by device_id**
  (canonical byte order). It carries no secret (device ids and seqs are already
  plaintext structural metadata) and is covered by both the signature (field 12)
  and the hash chain (§5), so a channel cannot forge or rewrite an op's causal
  past.
- **payload_env AAD** (out-of-band): `localpass/v1/op/payload | vault_id | op_id`
  (matches `vault-format.md` §3). The VaultKey encrypts it, so any peer holding
  the vault can read it; a relay/file channel cannot.
- **Sign-after-encrypt (stated, with rationale):** the Ed25519 signature (field
  12) covers the version byte + fields 1..11 — including the **ciphertext**
  `payload_env` and the `observed` causal summary, not the plaintext. This binds
  the signature to exactly the bytes that traverse the untrusted channel, so a
  relay or file host cannot substitute, truncate, or splice ciphertext, nor
  rewrite an op's declared causal past, without invalidating the signature (PRD
  §8 T5). Because the payload is authenticated *twice* (the AEAD Poly1305 tag
  under VaultKey for confidential integrity, and Ed25519 for
  authorship/non-repudiation over the wire form), we never expose plaintext to
  the signature path and never trust a decrypted payload before its op's
  signature and chain position verify.

### Op payload shapes (plaintext inside `payload_env`, canonical JSON §4)

| `op_kind` | value | payload |
|-----------|-------|---------|
| `create`  | 1 | full item payload (`vault-format.md` §4) + wrapped ItemKey material |
| `update`  | 2 | changed **fields** with per-field values (field-level, §4) + new wrapped ItemKey |
| `delete`  | 3 | `{}` (tombstone; metadata in header) |
| `restore` | 4 | `{ restore_to_version }` |
| `rewrap`  | 5 | new wrapped ItemKey(s) for new recipient/rotated VaultKey; **no** payload change |

`update` payloads carry field-level deltas so the merge (§4) can resolve
per-field, not per-item.

---

## 2. Op kinds

`create` / `update` / `delete` / `restore` / `rewrap` (enum above). `rewrap`
exists so sharing and key-rotation (PRD §4.3, §4.5) ship as ops without
re-encrypting payloads. All op kinds are signed and chained identically.

---

## 3. Causality: Lamport clock (total order) + observed-heads vector (happens-before)

Two distinct mechanisms, with two distinct jobs. **Do not conflate them.**

### 3.1 Lamport clock — the LWW total-order tiebreak (only)

- Each device keeps a monotonic `lamport: u64` per vault.
- On authoring an op: `lamport = local_lamport + 1; local_lamport = lamport`.
- On ingesting a remote op with clock `L`:
  `local_lamport = max(local_lamport, L)` (do **not** +1 on ingest; +1 only on
  authoring).
- The Lamport clock is used **solely** as the last-writer-wins total-order key
  `(lamport, device_id, op_id)` (§4.1) — i.e. to decide *who wins* among
  concurrent writers. It is **not** used to decide *whether* two ops are
  concurrent. (A scalar Lamport clock only guarantees `a → b ⟹ a.lamport <
  a.lamport`, never the converse, so a higher Lamport does **not** imply a
  causal-after relationship. Deriving concurrency from it — as an earlier draft
  did — misclassifies some genuinely-concurrent delete/edit pairs as causal.)

### 3.2 Observed-heads version vector — true happens-before

Every op carries an **observed-heads causal summary** `observed` (field 11): at
author time, the highest `seq` the authoring device had **applied** from every
device, itself included (its own self-entry is its previous op's `seq`). This is
a compact version vector.

Happens-before is then **exact**, for ops `a` and `b`:

```
a → b  (a happens-before b)  iff
    a.device == b.device  ?  a.seq < b.seq                     -- same-device chain order
                          :  b.observed[a.device] >= a.seq     -- b had applied a (or later) at author time
```

Two ops are **concurrent** iff neither `a → b` nor `b → a`. Because `observed`
is computed from applied state and is signed + chained (§1, §5), the relation is
identical on every device and cannot be forged by a channel — so it is both
deterministic (convergence-safe) and exact. §4.3 (delete/edit) is decided by
this relation; §4.1 (LWW winner) is decided by the Lamport total order.

---

## 4. Deterministic total-merge algorithm

**Goal / invariant — convergence:** any set of ops, applied in any order, on
any device, yields **identical** vault state, and **nothing is ever silently
discarded** (PRD §5.4, §6.4). The merge is a pure function of the op set.

### 4.1 Total order

Ops are totally ordered by the comparator:

```
op_a < op_b  iff  (a.lamport, a.device_id) < (b.lamport, b.device_id)
                   compared as (u64, then 16-byte big-endian device_id)
```

`op_id` is a final tiebreak (it cannot collide — UUIDv7 — but is specified so
the order is total even in adversarial constructions). This order is the
**last-writer-wins (LWW)** order: "later" = greater in this comparator.

### 4.2 Per-field LWW with loser preservation

State is materialized by folding ops in ascending total order. Per item, per
**field** (fields are keyed by their `name`, plus the pseudo-fields
`title`, `notes`, `tags`, `type_data.*`):

```
for each field F of item I:
    winner(F) = the update/create op with the greatest (lamport, device_id)
                that sets F
    I.F.value = winner(F).payload[F]
```

- **Concurrent same-field edits** (two ops set the same field F, neither
  happens-before the other): the greater `(lamport, device_id)` wins; the
  **loser is preserved** as an item version (a real row in `item_versions`,
  `vault-format.md` §3) and a **passive conflict badge** is set on the item.
  The badge is derived state — recomputable from the op set, cached in memory
  or the encrypted index, never a plaintext column (surfaced in the UI,
  PRD §6.4). The loser is never dropped — it is a retrievable version.
- Different fields edited concurrently simply both apply (no conflict).

### 4.3 Delete / restore / edit interactions

| Situation | Resolution | Rationale |
|-----------|-----------|-----------|
| concurrent `update` vs `delete` | **edit-wins**: the item is *not* deleted; the delete is recorded but overridden, and a conflict badge is set | data-preservation bias (PRD §6.4) |
| `delete` then later `update` (causally after) | update-wins (item revived), tombstone superseded | later real edit is intentional |
| `update` then later `delete` (causally after) | delete-wins (tombstone stands) | later delete is intentional |
| concurrent `delete` vs `delete` | single tombstone; the greater `(lamport, device_id)` op is canonical (its `deleted_at` used) | idempotent |
| `restore` | materializes the target version's fields as a new update at the restore op's clock; participates in LWW like any update | restore is an edit |

"Concurrent" strictly means neither op is in the other's causal past under the
**observed-heads happens-before** of §3.2 (`a → b` iff `a.seq <=
b.observed[a.device]` cross-device, or `a.seq < b.seq` same-device) — **not** a
scalar-Lamport comparison. A concurrent delete therefore never wins over an
edit even when the delete carries the higher Lamport clock. Edit-wins over
delete is the one place the pure LWW comparator is overridden — and it is
overridden *toward preservation*, never toward loss.

Concretely, an item is **deleted** iff there is a delete op that no snapshot
happens-after (a delete a later edit observed is superseded — revive), and
**every** snapshot happens-before that canonical delete. Otherwise the item is
**live**. Among mutually-concurrent surviving deletes the greatest
`(lamport, device_id, op_id)` one is canonical (idempotent delete-vs-delete).

### 4.4 Determinism requirements (for property tests)

- Materialization must depend only on the **set** of ops, never on arrival
  order (fold in total order, §4.1).
- Loser-preservation must be deterministic: given the same op set, the same
  versions are created with the same version numbers (assign version numbers by
  ascending total order of the ops that produced them).
- **Property to test:** for any permutation of any op multiset, final
  `(items, item_versions, tombstones)` state is byte-identical after
  re-canonicalization; and `|item_versions|` after merge ≥ number of distinct
  conflicting writes (nothing discarded).

---

## 5. Per-peer sequence hash chain (T13)

Every device maintains, **per vault**, a strictly increasing `seq: u64` over the
ops it authors, and a hash chain:

```
seq(first op by device) = 1, incrementing by 1 with no gaps
prev_hash(op) = BLAKE3( canonical_bytes(previous op by SAME device, version byte + fields 1..12) )
prev_hash(first op by a device) = BLAKE3("localpass/v1/chain-genesis" | vault_id | device_id)
```

Note the chain covers the **whole canonical form** (version byte + fields 1..12,
including the `observed` causal summary and the signature) of the prior op, so
the chain commits to the signed bytes, the causal past, *and* the signature — a
peer cannot swap a validly-signed but different prior op, nor rewrite an op's
declared `observed` vector.

**On ingest, a peer verifies for each incoming op:**

1. Ed25519 `signature` valid over the version byte + fields 1..11 under
   `device_id`'s known public key (from `peer_devices`, `vault-format.md` §2).
   Unknown device → reject.
2. `seq` is exactly `last_seen_seq(device_id) + 1` — no gap (**drop detection**),
   no repeat (**replay detection**), no regression (**rollback detection**,
   T13).
3. `prev_hash` equals the locally recomputed hash of that device's previous op
   (**tamper/fork detection**: a rewritten history breaks the chain).
4. `lamport` ≥ that device's previous op's lamport (monotone per author).

Any failure → the op (and everything after it from that device) is quarantined
and the user is **alarmed** (PRD §8 T13: "peers detect regression and alarm");
sync from that peer halts rather than silently accepting a divergent chain. Gaps
that are merely *not-yet-received* (out-of-order file delivery) are held pending,
not alarmed, until either filled or a timeout escalates them.

This makes a malicious relay/file host unable to (a) drop an op without leaving
a `seq` gap, (b) replay/roll back without a `seq`/`prev_hash` mismatch, or
(c) forge/alter an op without breaking the Ed25519 signature — satisfying T5 and
T13 for a zero-trust channel.

---

## 6. Device pairing & trust (summary — see PRD §4.5, §5.4)

- New devices pair via **SAS**: both show a 6-word phrase derived from the
  handshake transcript; the user compares them out-of-band (PRD §4.5). Match →
  each device stores the other's long-term **static** Ed25519 + X25519 public
  keys in `peer_devices` (`vault-format.md` §2), `verified_at` set.
- All live sync is **mutually authenticated** by those pinned static keys
  (Noise XX/IK, PRD §5.2/§6.4) — MITM (T4) is defeated by the pinning + SAS.
- Only paired devices' `device_id`s are accepted as op authors (§5 step 1).
- Team membership, roles, and revocation are **P2** (PRD §4.5); this MVP spec
  covers single-user multi-device only. Extension point: membership-change ops
  will be a new signed `op_kind` gated on admin keys — not defined here.

---

## 7. File-based log-shipping layout (MVP default)

The default onboarding sync (PRD §11 #6): the encrypted op log is written as
append-only segment files that **any dumb file channel** (Syncthing, USB, network
share, git) can replicate. Zero networking code in the critical path; the channel
is fully untrusted (§5 protects it).

### 7.1 Directory & file naming

```
<sync-root>/<vault_id>/
  manifest.json                          -- plaintext channel metadata (NOT trusted)
  ops/
    <device_id>/
      <device_id>-<seq_lo>-<seq_hi>.oplog   -- a contiguous seq range from one device
  chain/
    <device_id>.head                     -- last seq + head hash this writer published
```

- **Per-device subdirectories** so two devices writing concurrently never touch
  the same file (append-only, no write conflicts on the dumb channel — the exact
  property that makes Syncthing/USB safe).
- File name encodes `device_id` and an inclusive `[seq_lo, seq_hi]` range;
  segments are immutable once written. A device appends by writing a **new**
  segment file for the next range, never rewriting an existing one.
- `<device_id>-<seq_lo>-<seq_hi>.oplog` body = length-prefixed concatenation of
  canonical op bytes (wire version 2: version byte + fields 1..12 each), same
  encoding as §1. The ops are already E2EE (`payload_env`) and signed; the file
  adds no security, only framing.

### 7.2 Manifest (untrusted convenience only)

`manifest.json` lists known `device_id`s and their highest published `seq` — a
hint to speed discovery. It is **plaintext and unauthenticated**; readers treat
it as advisory. Trust comes only from §5 verification of the actual op chain, so
a tampered manifest can at worst cause a peer to look for segments (which then
fail chain checks if forged) — it can never inject state.

### 7.3 Reader algorithm

1. For each `<device_id>` dir, read `.oplog` segments, ordered by `seq_lo`.
2. Feed ops into the §5 ingest verifier (signature, seq-contiguity, prev_hash).
3. Apply verified ops via the §4 merge into the local vault (in a transaction;
   each applied op inserts its `ops` row + resulting state, `vault-format.md`
   §7).
4. Update `chain/<device_id>.head` for devices whose ops this peer re-publishes
   (store-and-forward for offline peers).

Idempotent: re-reading an already-applied segment is a no-op (op_id/seq already
present; `UNIQUE(device_id, seq)` in `ops`).

### 7.4 Extension points (out of scope, noted)

- **Live transport (Noise XX/IK over TCP, QUIC P2):** ships the same canonical op
  bytes over a mutually-authenticated stream instead of files; the ingest
  verifier (§5) and merge (§4) are transport-agnostic and unchanged.
- **Relay (P2):** stores the same per-device segments as opaque blobs keyed by
  `device_id`+`seq`; pairing-code-gated enrollment (PRD §11 #7). The relay sees
  only ciphertext + `device_id`/`seq` (all §5 protections apply); it is a
  §7-shaped dumb channel with a network API.

---

## 8. Invariants

1. **Convergence:** any set of ops applied in any order on any device yields
   byte-identical materialized vault state (§4.4).
2. **No silent loss:** every write that loses a conflict is preserved as an
   `item_versions` row; edit always wins over delete (§4.2, §4.3).
3. Every op is Ed25519-signed over its full canonical form **including
   ciphertext** (sign-after-encrypt, §1) and encrypted under the VaultKey.
4. Per-device `seq` is gapless and strictly increasing; `prev_hash` chains each
   device's ops; any gap/replay/regression/tamper is detected on ingest and
   alarmed (§5).
5. Only paired devices (`peer_devices`) are accepted as op authors (§5, §6).
6. The Lamport total order `(lamport, device_id, op_id)` is the sole tiebreak
   basis for LWW winner selection; it is deterministic and total (§4.1). It is
   **not** the basis for deciding concurrency — that is the observed-heads
   version vector (§3.2), which gives exact happens-before. The two roles are
   split: Lamport decides *who wins* among concurrent ops, the vector decides
   *whether* two ops are concurrent.
7. Applying an op is atomic with recording its `ops` row (`vault-format.md` §7);
   local state and local log never diverge.
8. Ops are immutable and append-only; there is no "edit op" — corrections are
   new ops.

## 9. Threat notes (PRD §8)

- **T5 (malicious relay / team server / file host):** sees only `payload_env`
  ciphertext + `device_id`/`seq`/`lamport`. Cannot forge (no device signing
  key), cannot relocate/alter ciphertext (Ed25519 over the wire form + AEAD
  AAD binds `vault_id|op_id`), cannot silently drop/replay/reorder (§5 chain).
- **T13 (sync-log tampering / rollback):** per-device `seq` gaplessness +
  `prev_hash` chain + Lamport monotonicity make any rollback, drop, or replay
  detectable and alarmed; a peer cannot be silently regressed to old state.
- **T4 (network MITM on LAN/relay path):** live transport is Noise mutual auth
  pinned to SAS-verified static keys (§6); payloads are E2EE regardless of
  channel, so even a broken transport leaks nothing and injects nothing.
- **T6 (departed member / insider — P2 preview):** `rewrap` ops rotate the
  VaultKey for remaining members; past-readable secrets are handled by the
  rotation checklist (PRD §4.5) since E2EE cannot un-disclose — noted, not
  implemented in this MVP spec.

## 10. Non-goals

- **Live network transport internals** (Noise handshake state machine, mDNS
  discovery, QUIC): out of scope; only the shared op format and the ingest
  contract are fixed here.
- **Relay protocol details** (enrollment API, store-and-forward GC): P2; only
  the extension point and its zero-trust posture are noted (§7.4).
- **Team membership / roles / revocation cryptography:** P2 (PRD §4.5); MVP is
  single-user multi-device.
- **Automatic hand-merge UI:** by design the merge never *requires* user
  intervention to unblock sync (PRD §6.4); conflict badges are passive.
- **Compaction / log truncation:** not specified for v1 (keep-forever bias,
  PRD §11 #8); a future compaction op must preserve chain verifiability and is
  out of scope here.
- **Byzantine peers beyond detection:** the protocol *detects and alarms* on a
  cheating peer/channel; it does not attempt automatic recovery from a
  maliciously forked history beyond quarantine (§5).
