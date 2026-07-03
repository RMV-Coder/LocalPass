# LocalPass Encrypted Search Index

**Format version: 1**
**Status: draft-for-implementation**
**Date: 2026-07-04**

## Scope

This document specifies the persisted, encrypted, incrementally-updated search
index for a LocalPass vault. Per the ratified decision (PRD §11 #2) the index is
**persisted encrypted and updated incrementally — never a full rebuild on
unlock** — so the < 50 ms p95 search target over 10k items (PRD §5.3) is met
without an unlock-time index cost. This spec is deliberately light: it defines
the index content model, the on-disk segment format, the chunking strategy that
keeps single-item updates cheap, the atomicity mechanism (SQLite transaction +
generation counter), and corruption recovery. It lives inside the vault SQLite
file; see `vault-format.md` §3 (`index_segments`, `meta.index_generation`) for
the tables and AAD, and for the `IndexKey = HKDF(VaultKey, "localpass/v1/index")`
derivation.

Cost model target: index update is **O(changed items)** on an item write, not
O(vault size).

---

## 1. Keys and crypto

- `IndexKey = HKDF(VaultKey, "localpass/v1/index")` (fixed contract, LESSONS.md).
- Every segment on disk is an **Envelope v1** blob
  (`0x01 || nonce(24) || ct+tag(16)`) encrypted under `IndexKey`.
- AAD (out-of-band, per `vault-format.md` §3):
  `localpass/v1/index/segment | vault_id | segment_id | generation`.
  Binding `generation` means a stale segment ciphertext cannot be replayed as
  current — the AEAD tag fails against the current generation's AAD.

---

## 2. Index content model — what is indexed

Indexed fields (never secret values, PRD §4.2):

| Source | Indexed? | Notes |
|--------|----------|-------|
| Title | ✔ | tokenized + fuzzy (trigram, §3) |
| Username field value | ✔ | it is the searchable handle, not a "secret value" per PRD §4.2 |
| URLs | ✔ | registrable domain + full, for match/filter |
| Tags | ✔ | exact + prefix |
| Custom field **names** | ✔ | names only |
| Item type, folder, favorite | ✔ | filter tokens (`type:ssh-key`, `folder:`, `fav:`); these live only inside encrypted payloads (vault-format.md §3), so the index is the sole filter path |
| Custom field **values** | ✘ | never |
| Password / secret / key material | ✘ | never |
| Note body | ✘ MVP / opt-in **P2** | per-vault opt-in (PRD §4.2, §11); increases index sensitivity; still encrypted at rest |

The index stores **postings** (token → item_ids) plus a small per-item token
set for incremental delete. It never stores decrypted secret values. Because the
whole index is encrypted under IndexKey, even the indexed tokens (titles, etc.)
are confidential at rest — a file thief learns nothing from the index that they
did not already learn from `vault-format.md` §6.

Token model (informative, not wire-fixed beyond the segment envelope):

- Text fields: Unicode-normalized (NFKC), casefolded, split on
  whitespace/punctuation.
- Fuzzy title match: character **trigrams** of the title (PRD §4.2 fuzzy on
  titles). Trigram postings are just more tokens in the same map.
- URLs: both the full URL token and the registrable-domain token.

---

## 3. On-disk format: segmented postings

The index is **segmented** so a single-item write re-encrypts only small
segments, not the whole index. Each row of `index_segments`
(`vault-format.md` §3) is one encrypted segment.

### 3.1 Segment 0 — manifest

`segment_id = 0` is the **manifest**. Plaintext structure (before encryption):

```
manifest {
  index_format_version : u16   = 1
  generation           : u64          -- matches meta.index_generation
  segment_count        : u32
  item_count           : u32
  segments : [ {
      segment_id : u32,
      item_lo    : u128,             -- inclusive item_id range start
      item_hi    : u128,             -- inclusive item_id range end
      token_est  : u32               -- for rebalancing heuristics
  } ]
}
```

### 3.2 Data segments (`segment_id ≥ 1`)

Each data segment owns a contiguous **item_id range** (item_ids are UUIDv7, so
range-partitioning is stable and evenly distributed). A segment holds the
postings for exactly the items whose id falls in its `[item_lo, item_hi]` range:

```
segment {
  index_format_version : u16 = 1
  segment_id           : u32
  generation           : u64
  postings : map<token(string) -> sorted list<item_id(u128)>>
  item_tokens : map<item_id(u128) -> set<token(string)>>   -- reverse map for delete
}
```

Serialization inside the envelope is canonical (deterministic key order) so a
segment's ciphertext is reproducible for a given plaintext — same discipline as
`vault-format.md` §4. Target segment size: ~256 items per segment (≈ 40
segments at 10k items); split a segment when it exceeds ~512 items, merge two
adjacent under-full segments when the pair drops below ~256 combined. These are
tuning constants, not format-fixed.

**Why range-partition by item_id, not by token:** an item write touches exactly
one segment (the one owning its id range), so re-encryption is O(1 segment) =
O(changed items). Token-sharded layouts would touch many segments per write.

---

## 4. Atomicity & generations

The index shares the vault's write transaction (`vault-format.md` §7):

1. Item write (insert `item_versions`, etc.) and the affected segment
   re-encryption happen in the **same SQLite transaction**.
2. `meta.index_generation` is **bumped** in that same transaction, and the new
   generation is written into every re-encrypted segment's plaintext **and** its
   AAD.
3. The manifest (segment 0) is re-encrypted with the new generation in the same
   transaction whenever `segment_count` or the segment ranges change; on a
   pure-postings update within existing ranges the manifest's `generation` field
   is still bumped so the manifest and data segments always agree.

**Torn/stale detection:** at unlock the reader opens the manifest and checks
`manifest.generation == meta.index_generation`. On any read of a data segment it
checks the segment's `generation` (verified via AAD) against
`meta.index_generation`.

- Match on all touched segments → index is authoritative, use it (the hot path;
  **no rebuild**).
- A segment whose `generation` is **older** than `meta.index_generation` →
  that segment is stale (a partially-applied older state); it, and only it, is
  rebuilt from its item_id range's items in the background. Search over other
  segments proceeds normally meanwhile.
- Because step 1–3 are one transaction, a crash yields either the full old
  generation (all segments + manifest at gen N) or the full new one (gen N+1) —
  never a mix; the generation check is a belt-and-suspenders defense against
  bit-rot and manual file surgery, not against SQLite tearing.

---

## 5. Incremental update algorithm

On item **create/update**:

1. Compute the item's token set from indexed fields (§2).
2. Locate the owning segment by item_id range (from the manifest).
3. Decrypt that segment, diff against `item_tokens[item_id]` (empty on create):
   remove the item from postings of dropped tokens, add it to postings of new
   tokens, replace `item_tokens[item_id]`.
4. Re-encrypt the segment at the new generation; split if oversized.
5. All within the item's write transaction (§4).

On item **delete** (tombstone): same, but remove the item from every posting in
its `item_tokens` set and drop the reverse entry. A tombstoned item is absent
from results even if a stale segment still lists it — the search layer filters
tombstoned ids as a final pass (defense in depth).

On **version restore**: treat as an update to the item's current indexed fields.

Cost: one segment decrypt + re-encrypt per changed item = O(changed items).

---

## 6. Query path

1. Ensure unlocked → `IndexKey` available.
2. Load manifest (cached in memory after first load; invalidated on generation
   change).
3. Tokenize the query; for filter tokens (`type:`, `tag:`, `vault:`) resolve
   structurally.
4. Fetch candidate item_ids from the relevant segments' postings, intersect per
   AND semantics, rank (exact > prefix > trigram/fuzzy).
5. Filter out tombstoned ids.
6. Return item_ids; the caller decrypts only the items it displays
   (< 10 ms/item, PRD §5.3).

In-memory postings caching across queries is allowed (keys stay zeroized on
lock like all key material); the persisted form is always the encrypted segments.

---

## 7. Corruption recovery

The index is **always derivable from the items** — it is a cache, never a
source of truth. Recovery ladder:

1. Single stale/failed segment (generation mismatch or AEAD failure) → rebuild
   that segment's item_id range in the background; never blocks unlock.
2. Manifest unreadable → rebuild the manifest by scanning `items` for id ranges
   (cheap: ids + counts only), then rebuild segments lazily/background.
3. Whole index unreadable/absent (e.g. IndexKey rotation, format bump) →
   schedule a **full background rebuild**; until it completes, search falls back
   to a linear scan of decrypted item metadata (correct, just slower). The
   full rebuild is **never** run on the unlock hot path (PRD §11 #2).

A background rebuild writes into a new generation and swaps atomically via the
same transaction+generation mechanism (§4), so a search never sees a
half-rebuilt index.

---

## 8. Invariants

1. The index is a cache: it is always fully derivable from `items` +
   `item_versions`; losing it never loses data.
2. The index never stores secret values or key material — only the tokens in
   §2 (and note-body tokens only when the per-vault P2 opt-in is on).
3. Every persisted segment is Envelope v1 under `IndexKey`, with AAD binding
   `vault_id | segment_id | generation`.
4. Index updates are atomic with the item write and bump
   `meta.index_generation` in the same transaction (§4).
5. A segment whose embedded/AAD generation < `meta.index_generation` is treated
   as stale and rebuilt (only that segment), never trusted.
6. Unlock never triggers a full rebuild; at worst it triggers a background
   rebuild while serving results via linear fallback.
7. Update cost is O(changed items): one segment re-encrypt per changed item.

## 9. Non-goals

- **Ranking sophistication** (BM25/TF-IDF scoring, phrase queries): out of scope
  for v1; exact/prefix/trigram ordering is sufficient for the 10k-item target.
- **Note-body search at MVP** (P2, per-vault opt-in).
- **Cross-vault search index:** each vault has its own IndexKey and its own
  segments; no shared index (matches vault isolation, `vault-format.md` §11).
- **Structural-metadata hiding:** the index reveals nothing beyond what
  `vault-format.md` §6 already exposes to a file thief; it does not attempt to
  hide token counts or postings-set sizes via padding.
- **Search over encrypted data without the key** (searchable-encryption /
  oblivious-index schemes): explicitly not attempted; the index is decrypted
  in-process after unlock like everything else.
