# LocalPass Vault Format

**Format version: 1**
**Status: draft-for-implementation**
**Date: 2026-07-04**

## Scope

This document specifies the on-disk storage format for LocalPass: the account
store, the per-vault SQLite files, their DDL, and the envelope-encryption rules
that govern every ciphertext blob. It defines the canonical plaintext item
payload, the key lifecycle (create / unlock / lock / password change / per-item
keys), durability guarantees, and the format's own versioning policy. It is
implementation-grade: a Rust engineer should be able to build `lp-vault`
against it without further decisions. The search index (`search-index.md`) and
the sync op log (`sync-protocol.md`) are specified in sibling documents; this
doc owns the tables they live in but defers their internal formats.

Fixed cross-crate contracts (from `LESSONS.md`, non-negotiable here):

- **Envelope v1:** `0x01 || nonce(24) || ciphertext+tag(16)`, XChaCha20-Poly1305,
  AAD carried out-of-band (never stored inside the blob).
- **HKDF labels:** `localpass/v1/<purpose>`, mandatory, never empty.
- **Key hierarchy:** MUK → AccountKey → VaultKey → ItemKey.
  `IndexKey = HKDF(VaultKey, "localpass/v1/index")`.

---

## 1. File layout

Two file *kinds* live under the per-OS-user profile directory, all with
owner-only permissions (0600 / owner-only ACLs, PRD §4.3):

```
<profile>/
  account.localpass          -- the account store (exactly one)
  vaults/
    <vault_id>.vault         -- one SQLite file per vault
    <vault_id>.vault-wal     -- SQLite WAL sidecar (transient)
    <vault_id>.vault-shm     -- SQLite shared-memory sidecar (transient)
  attachments/               -- P2, content-addressed blobs (see §8)
  sync/                      -- file-based log shipping (see sync-protocol.md)
  backups/                   -- rotating encrypted snapshots (PRD §4.11)
```

`<vault_id>` is the vault's UUIDv7 rendered lowercase-hyphenated. The account
store holds the vault **registry** (the authoritative list of vault ids, names,
and wrapped VaultKeys); the file layout is a cache derivable from it.

**Why split (decision already made — spec, don't re-decide):** account-level
data (KDF params, wrapped AccountKey, device identity, settings) is separated
from per-vault data so that each vault file is independently portable, syncable,
and blast-radius-isolated. Copying one `.vault` file to another machine leaks
nothing about other vaults; per-vault sync ships only that vault's op log; a
corrupted vault file cannot take down the account store.

Both file kinds are SQLite databases in **WAL mode** (§7).

---

## 2. Account store DDL (`account.localpass`)

```sql
-- Format/header: exactly one row (id = 1).
CREATE TABLE meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    format_version    INTEGER NOT NULL,        -- = 1
    file_kind         TEXT    NOT NULL,         -- 'account-store'
    cipher_suite      INTEGER NOT NULL,         -- 1 = XChaCha20-Poly1305 (default)
    created_at        INTEGER NOT NULL,         -- unix millis, plaintext
    schema_migrated_at INTEGER NOT NULL
);

-- KDF parameters + salt for deriving the MUK. Plaintext by necessity:
-- they are needed *before* any key exists. See §5, §12 threat notes.
CREATE TABLE kdf_params (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    kdf               INTEGER NOT NULL,         -- 1 = Argon2id
    argon2_m_kib      INTEGER NOT NULL,         -- memory cost (KiB)
    argon2_t          INTEGER NOT NULL,         -- iterations
    argon2_p          INTEGER NOT NULL,         -- parallelism
    salt              BLOB    NOT NULL,         -- 16 bytes, CSPRNG
    secret_key_id     BLOB    NOT NULL          -- 16 bytes; identifies (not stores) the Secret Key
);

-- The AccountKey, wrapped by the MUK. Exactly one row. Password change
-- rewraps THIS ROW ONLY (AccountKey plaintext is unchanged). See §5.4.
CREATE TABLE wrapped_account_key (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    envelope          BLOB    NOT NULL,         -- Envelope v1 over AccountKey bytes
    wrapped_at        INTEGER NOT NULL
);

-- This device's long-term identity keys (Ed25519 signing + X25519 static).
-- Private halves are ciphertext (wrapped by AccountKey); publics are plaintext.
CREATE TABLE device_identity (
    device_id         BLOB    PRIMARY KEY,      -- 16 bytes (UUIDv7), this device
    ed25519_pub       BLOB    NOT NULL,         -- 32 bytes, plaintext
    x25519_pub        BLOB    NOT NULL,         -- 32 bytes, plaintext
    ed25519_priv_env  BLOB    NOT NULL,         -- Envelope v1 over 32-byte seed
    x25519_priv_env   BLOB    NOT NULL,         -- Envelope v1 over 32-byte scalar
    created_at        INTEGER NOT NULL,
    label             TEXT                       -- plaintext, user-set ("laptop")
);

-- Public keys of OTHER paired devices (trust anchors for sync). Verified
-- via SAS at pairing (sync-protocol.md §6). No private material here.
CREATE TABLE peer_devices (
    device_id         BLOB    PRIMARY KEY,      -- 16 bytes, remote device
    ed25519_pub       BLOB    NOT NULL,
    x25519_pub        BLOB    NOT NULL,
    verified_at       INTEGER NOT NULL,         -- SAS confirmation time
    label             TEXT
);

-- Vault registry: authoritative list. Names are encrypted; ids plaintext.
CREATE TABLE vault_registry (
    vault_id          BLOB    PRIMARY KEY,      -- 16 bytes (UUIDv7)
    name_env          BLOB    NOT NULL,         -- Envelope v1 over vault name (AccountKey-wrapped context)
    wrapped_vault_key BLOB    NOT NULL,         -- Envelope v1 over VaultKey, wrapped by AccountKey
    cipher_suite      INTEGER NOT NULL,         -- must match the vault file's meta
    created_at        INTEGER NOT NULL,
    deleted_at        INTEGER                    -- soft-delete; NULL = live
);

-- User/app settings. Non-sensitive scalars plaintext; anything that could
-- leak content (e.g. per-vault note-index opt-in is fine plaintext) — but
-- default rule: if in doubt, store the value_env ciphertext column.
CREATE TABLE settings (
    key               TEXT PRIMARY KEY,
    value             TEXT,                      -- plaintext for non-sensitive
    value_env         BLOB                       -- Envelope v1 for sensitive; exactly one of value/value_env
);
```

**AAD for account-store envelopes** (out-of-band, reconstructed at
decrypt time — never stored):

| Column | AAD byte string (UTF-8, `\|`-joined) |
|--------|--------------------------------------|
| `wrapped_account_key.envelope` | `localpass/v1/wrap/account-key` |
| `device_identity.ed25519_priv_env` | `localpass/v1/wrap/device-ed25519` \| `device_id` |
| `device_identity.x25519_priv_env` | `localpass/v1/wrap/device-x25519` \| `device_id` |
| `vault_registry.name_env` | `localpass/v1/meta/vault-name` \| `vault_id` |
| `vault_registry.wrapped_vault_key` | `localpass/v1/wrap/vault-key` \| `vault_id` |
| `settings.value_env` | `localpass/v1/meta/setting` \| `key` |

The wrapping key is implicit in the purpose: account-key envelope is opened
with the MUK; everything else in this file is opened with the AccountKey.

---

## 3. Vault file DDL (`<vault_id>.vault`)

```sql
CREATE TABLE meta (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    format_version    INTEGER NOT NULL,        -- = 1
    file_kind         TEXT    NOT NULL,         -- 'vault'
    vault_id          BLOB    NOT NULL,         -- 16 bytes, matches file name & registry
    cipher_suite      INTEGER NOT NULL,
    created_at        INTEGER NOT NULL,
    index_generation  INTEGER NOT NULL DEFAULT 0 -- see search-index.md §4
);

-- Wrapped ItemKeys. One row per (item, version): every version has its own
-- ItemKey, wrapped by the VaultKey. See §5.3.
CREATE TABLE wrapped_keys (
    item_id           BLOB    NOT NULL,          -- 16 bytes (UUIDv7)
    version           INTEGER NOT NULL,          -- 1-based, monotonic per item
    envelope          BLOB    NOT NULL,          -- Envelope v1 over 32-byte ItemKey
    PRIMARY KEY (item_id, version)
);

-- Item head row: the current state pointer only. The item's SECRET payload is
-- NOT here; it lives per-version in item_versions. Type, favorite flag, and
-- folder membership live INSIDE the encrypted payload (§4) and are surfaced
-- via the encrypted index — PRD §6.3 fixes the plaintext set to
-- ids/counters/timestamps, and type distribution is targeting information.
CREATE TABLE items (
    item_id           BLOB    PRIMARY KEY,       -- 16 bytes (UUIDv7)
    current_version   INTEGER NOT NULL,          -- FK -> item_versions.version
    created_at        INTEGER NOT NULL,          -- plaintext
    updated_at        INTEGER NOT NULL           -- plaintext
);

-- Immutable version-per-edit (PRD §4.10). Never UPDATEd, only INSERTed.
-- The encrypted payload is the whole canonical item body (§4).
CREATE TABLE item_versions (
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,
    payload_env       BLOB    NOT NULL,          -- Envelope v1 over canonical payload, ItemKey-wrapped
    created_at        INTEGER NOT NULL,          -- plaintext (edit time)
    author_device_id  BLOB    NOT NULL,          -- 16 bytes; which device wrote it
    op_id             BLOB,                       -- 16 bytes; the sync op that produced it (NULL for local pre-sync)
    PRIMARY KEY (item_id, version)
);

-- Folders (single-level). Names encrypted.
CREATE TABLE folders (
    folder_id         BLOB    PRIMARY KEY,       -- 16 bytes (UUIDv7)
    name_env          BLOB    NOT NULL,          -- Envelope v1 over folder name
    created_at        INTEGER NOT NULL
);

-- Trash / tombstones (PRD §4.10: 30-day default trash, then shred).
-- A tombstone is authoritative for "deleted"; the item + versions rows may
-- linger until shred for restore, but a tombstone hides the item.
CREATE TABLE tombstones (
    item_id           BLOB    PRIMARY KEY,
    deleted_at        INTEGER NOT NULL,          -- plaintext
    purge_after       INTEGER NOT NULL,          -- deleted_at + retention window
    deleted_by_device BLOB    NOT NULL,
    op_id             BLOB                         -- sync op that deleted it
);

-- Op log: the unit of sync (see sync-protocol.md). Stored here so a vault
-- file is self-contained and shippable. Rows are append-only & immutable.
CREATE TABLE ops (
    op_id             BLOB    PRIMARY KEY,       -- 16 bytes (UUIDv7)
    vault_id          BLOB    NOT NULL,
    lamport           INTEGER NOT NULL,          -- Lamport clock, plaintext
    device_id         BLOB    NOT NULL,          -- author device, plaintext
    op_kind           INTEGER NOT NULL,          -- create/update/delete/restore/rewrap (§sync)
    target_item_id    BLOB,                       -- item the op mutates (NULL for vault-scope ops)
    target_version    INTEGER NOT NULL DEFAULT 0, -- wire field 9 (sync-protocol.md §1); stored so canonical op bytes are reconstructible for chain verification
    payload_env       BLOB    NOT NULL,          -- Envelope v1 over op payload, VaultKey-wrapped
    signature         BLOB    NOT NULL,          -- Ed25519 over the full op incl. ciphertext (sign-after-encrypt)
    seq               INTEGER NOT NULL,          -- per-device monotonic sequence (hash-chain, sync-protocol.md §5)
    prev_hash         BLOB    NOT NULL,          -- 32 bytes; hash-chain link
    created_at        INTEGER NOT NULL,
    UNIQUE (device_id, seq)
);

-- Search index segments (see search-index.md). Encrypted under IndexKey.
CREATE TABLE index_segments (
    segment_id        INTEGER PRIMARY KEY,
    generation        INTEGER NOT NULL,          -- must equal meta.index_generation when valid
    payload_env       BLOB    NOT NULL           -- Envelope v1 over segment, IndexKey-wrapped
);

-- Attachments. Content-addressed encrypted blobs live in a sibling directory
-- (<profile>/attachments/<vault_id>/<content_hash_hex>.blob); this table holds
-- references + wrapped per-attachment keys. Local-only in the MVP: attachment
-- blobs are NOT part of the op log and do not sync (a follow-up ships them
-- through the file channel).
CREATE TABLE attachments (
    attachment_id     BLOB    PRIMARY KEY,       -- 16 bytes (UUIDv7)
    item_id           BLOB    NOT NULL,
    version           INTEGER NOT NULL,          -- attachment belongs to an item version
    content_hash      BLOB    NOT NULL,          -- 32 bytes BLAKE3 of CIPHERTEXT blob (addressing)
    size_plain        INTEGER NOT NULL,          -- plaintext length, structural
    wrapped_key_env   BLOB    NOT NULL,          -- Envelope v1 over attachment key, ItemKey-wrapped
    filename_env      BLOB    NOT NULL,          -- Envelope v1 over filename
    created_at        INTEGER NOT NULL DEFAULT 0 -- unix millis, plaintext (structural)
);

CREATE INDEX idx_versions_item   ON item_versions (item_id, version);
CREATE INDEX idx_ops_lamport     ON ops (lamport, device_id);
CREATE INDEX idx_ops_device_seq  ON ops (device_id, seq);
CREATE INDEX idx_attach_item     ON attachments (item_id);
CREATE INDEX idx_attach_hash     ON attachments (content_hash);
```

**AAD for vault-file envelopes** (out-of-band, reconstructed at decrypt time):

| Column | AAD byte string (UTF-8, `\|`-joined) | Wrapping key |
|--------|--------------------------------------|--------------|
| `wrapped_keys.envelope` | `localpass/v1/wrap/item-key` \| `vault_id` \| `item_id` \| `version` | VaultKey |
| `item_versions.payload_env` | `localpass/v1/item/payload` \| `vault_id` \| `item_id` \| `version` | ItemKey |
| `folders.name_env` | `localpass/v1/meta/folder-name` \| `vault_id` \| `folder_id` | VaultKey |
| `attachments.wrapped_key_env` | `localpass/v1/wrap/attachment-key` \| `vault_id` \| `attachment_id` | ItemKey |
| `attachments.filename_env` | `localpass/v1/meta/attachment-name` \| `vault_id` \| `attachment_id` | ItemKey |
| `attachments` blob (on disk) | `localpass/v1/attachment/blob` \| `vault_id` \| `attachment_id` | attachment key |
| `ops.payload_env` | `localpass/v1/op/payload` \| `vault_id` \| `op_id` | VaultKey |
| `index_segments.payload_env` | `localpass/v1/index/segment` \| `vault_id` \| `segment_id` \| `generation` | IndexKey |

**Why this AAD binding matters (anti-cut-and-paste):** because every payload
binds `vault_id + item_id + version` (and, for keys, the wrapping purpose),
a ciphertext blob cannot be lifted from one row and pasted into another —
not into a different item, a different version of the same item, or a
different vault — because AEAD verification will fail against the reconstructed
AAD. This closes ciphertext relocation attacks across the entire schema without
storing AAD on disk (it is derived from the plaintext structural columns).
The `generation` in the index-segment AAD additionally means a stale segment
cannot masquerade as a current one (search-index.md §4).

---

## 4. Item payload — canonical plaintext structure

**Encoding choice: canonical JSON (RFC 8785 JCS profile).** Rationale: JSON is
human-auditable in a recovery context, trivially serializable in Rust
(`serde_json`), and the JCS canonicalization rules (sorted object keys, no
insignificant whitespace, fixed number formatting, UTF-8) give a deterministic
byte string. Determinism matters because the payload bytes feed AEAD and (via
the enclosing op) an Ed25519 signature — the same logical item must always
produce the same bytes. Binary formats (bincode, CBOR) were rejected for v1 on
auditability grounds; the payload is small (secrets, not attachments), so the
size cost is irrelevant. Attachment *bodies* are never JSON — they are raw
ciphertext blobs (§8); only their metadata is in the item payload.

Canonical rules (all mandatory):

- Object member keys sorted by UTF-16 code unit (JCS).
- No insignificant whitespace.
- Numbers: integers only in this schema (timestamps as unix-millis integers);
  no floats, so JCS number canonicalization edge cases do not arise.
- Strings UTF-8, minimal escaping per JCS.
- Top-level `"v"` (payload schema version) is always present and first-by-sort.

Payload envelope (the JSON object encrypted into `item_versions.payload_env`):

```json
{
  "v": 1,
  "type": "login",
  "title": "ACME prod DB",
  "notes": "markdown body ...",
  "tags": ["prod", "db"],
  "favorite": false,
  "folder_id": null,
  "fields": [
    { "name": "username", "kind": "text",   "value": "svc_acme" },
    { "name": "password", "kind": "hidden", "value": "..." },
    { "name": "url",      "kind": "url",     "value": "https://db.acme.internal" },
    { "name": "expires",  "kind": "date",    "value": 1788134400000 }
  ],
  "type_data": { "...": "type-specific, see below" }
}
```

**Field kinds** (`fields[].kind`): `text` | `hidden` | `url` | `date`
(PRD §4.1 "custom fields (text/hidden/URL/date)"). `date` values are unix-millis
integers. `hidden` is a display/UX hint (masked by default); it carries no
crypto meaning — the entire payload is encrypted regardless.

**Secret types** (`type`; the integer codes are used in op materialization and
index filter tokens — there is no plaintext type column, PRD §4.1/§6.3):

| `type` string | type code | MVP | `type_data` shape (informative) |
|---------------|-----------------|-----|---------------------------------|
| `login`       | 1 | ✔ | urls[] beyond the primary field, for autofill matching |
| `note`        | 2 | ✔ | body in `notes`; `type_data` empty |
| `api_key`     | 3 | ✔ | `{ key, secret, endpoint, expiry, rotate_after }` |
| `env_set`     | 4 | ✔ | `{ entries: [ {key, value}, ... ] }` ordered map (PRD §4.8) |
| `ssh_key`     | 5 | ✔ | `{ algo, private_pem, public_openssh, fingerprint }` |
| `totp`        | 6 | ✔ | `{ secret_b32, algo, digits, period, issuer, account }` (RFC 6238) |
| `attachment_holder` | 7 | P2 | attachment refs only; see §8 |
| `certificate` | 8 | P2 | `{ pem, pkcs12, not_after }` |
| `passkey`     | 9 | P2 | WebAuthn credential material |
| `db_cred`     | 10 | P2 | `{ host, port, user, password, conn_template }` |

Note-body **indexing** is opt-in P2 (search-index.md §2); note-body *storage* is
MVP and lives in `notes` here regardless of indexing.

---

## 5. Key lifecycle

All keys are 256-bit unless noted. All live in `zeroize`-on-drop containers in
memory (PRD §5.1); nothing below writes a plaintext key to disk.

### 5.1 Vault create

1. Generate `VaultKey` (CSPRNG, 32 bytes) and `vault_id` (UUIDv7).
2. Wrap `VaultKey` under the AccountKey → `vault_registry.wrapped_vault_key`
   (AAD `localpass/v1/wrap/vault-key | vault_id`).
3. Create `<vault_id>.vault` with `meta`, empty tables, WAL enabled.
4. Insert the registry row in the account store. Both writes are committed
   before the vault is considered to exist (§7 atomicity).

### 5.2 Unlock (MUK → AccountKey → VaultKey chain)

```
1. Read kdf_params + salt (plaintext) from account store.
2. Read Secret Key (OS keychain / Emergency Kit) — 128-bit, PRD §4.3.
3. MUK = Argon2id(password, salt, params) then
        HKDF(ikm = argon2_output || secret_key, label "localpass/v1/muk").
4. AccountKey = open(wrapped_account_key.envelope, key = MUK,
        AAD "localpass/v1/wrap/account-key").      -- MUK verified here
5. For each vault to open:
     VaultKey = open(vault_registry.wrapped_vault_key, key = AccountKey,
        AAD "localpass/v1/wrap/vault-key | vault_id").
6. Per item read on demand:
     ItemKey = open(wrapped_keys.envelope, key = VaultKey, AAD as §3).
     payload = open(item_versions.payload_env, key = ItemKey, AAD as §3).
7. IndexKey = HKDF(VaultKey, "localpass/v1/index").   -- search-index.md
```

A wrong password/Secret Key fails at step 4 (AEAD tag mismatch); no partial
key material is exposed. Unlock cost is Argon2id-dominated by design
(PRD §5.3, < 1.5 s target).

### 5.3 Per-item keys

Each `(item_id, version)` has its own `ItemKey`, wrapped by the VaultKey in
`wrapped_keys`. Consequences:

- Sharing an item = re-wrapping its ItemKey for a recipient (PRD §4.3), never
  re-encrypting the vault.
- A new version generates a **new** ItemKey (fresh key per version) so that a
  compromised single ItemKey never spans versions and nonce reuse is
  structurally impossible across edits.

### 5.4 Lock

Zeroize MUK, AccountKey, all VaultKeys, all cached ItemKeys, and IndexKey from
memory (PRD §4.3 auto-lock). On-disk state is untouched — lock is a
memory-only operation.

### 5.5 Master-password change (re-wrap only)

1. Derive `MUK_new` from the new password (fresh `salt`, possibly recalibrated
   Argon2 params).
2. `AccountKey` is unwrapped with `MUK_old`, then re-wrapped under `MUK_new`.
   **AccountKey plaintext is unchanged** (PRD §4.3): VaultKeys, ItemKeys, and
   all payloads are untouched. Only `kdf_params` and
   `wrapped_account_key.envelope` are rewritten, in one transaction.
3. The Secret Key is unchanged by a password change.

---

## 6. What is plaintext, and why

Minimal structural columns are plaintext so the DB is queryable and the KDF is
bootstrappable. Everything a plaintext value could leak is enumerated in §12.

| Plaintext | Reason |
|-----------|--------|
| `kdf_params` (params, salt, secret_key_id) | Needed to derive the MUK before any key exists |
| All `*_id` columns (UUIDv7, 16 bytes) | Random identifiers; join keys; reveal no content. UUIDv7's time prefix leaks *creation ordering*, accepted (see §12 T1) |
| `version`, `current_version`, `lamport`, `seq` | Counters; enable ordering/merge without decryption |
| `*_at` timestamps (unix millis) | Edit cadence; needed for trash/retention/sort |
| `ed25519_pub`, `x25519_pub`, `device_id` | Public keys / device ids are non-secret by definition |
| `content_hash`, `size_plain` (attachments) | Content-addressing + quota; hash is over ciphertext |

Everything else — titles, usernames, URLs, tags, custom-field names AND values,
notes, all `type_data`, item types, favorite flags, folder membership, and
vault/folder names — is ciphertext. Every ciphertext
column (enumerated in the AAD tables of §2 and §3) is an Envelope v1 blob.

---

## 7. Durability

- **WAL mode** on both file kinds (`PRAGMA journal_mode=WAL`), and
  `synchronous=FULL` on **both** file kinds. WAL+NORMAL would be
  corruption-safe but can lose the most recently committed transactions on
  power loss — unacceptable here: a just-saved credential that the user
  immediately relies on must survive a power cut. Write rates are human-scale,
  so the extra fsync per commit is irrelevant (PRD §5.3 targets unaffected).
- **`PRAGMA foreign_keys=ON`.**
- **Atomic transaction boundaries** — the following are each a single
  transaction; a power cut leaves the DB either fully before or fully after:

  | Operation | Must be atomic together |
  |-----------|-------------------------|
  | Item create | insert `items` + `item_versions` v1 + `wrapped_keys` v1 + `ops`(create) + affected `index_segments` + bump `meta.index_generation` |
  | Item edit | insert new `item_versions` + `wrapped_keys` row + update `items.current_version`/`updated_at` + `ops`(update) + index segment update + generation bump |
  | Item delete | insert `tombstones` + `ops`(delete) + index segment update + generation bump |
  | Restore version | update `items.current_version` (+ new version row if forward-restore) + `ops`(restore) + index update + bump |
  | Rewrap (share/rotate) | rewrite `wrapped_keys` rows + `ops`(rewrap) — payloads untouched |
  | Password change | rewrite `kdf_params` + `wrapped_account_key` (account store) |
  | Vault create | `<vault>.vault` init committed, then `vault_registry` row committed |

- The op log row is committed **in the same transaction** as the state change
  it describes, so the log can never diverge from vault state on this device
  (sync-protocol.md relies on this).
- The search index update is in the **same transaction** as the item write
  (search-index.md §4); a torn write is impossible and a stale generation is
  detectable.

---

## 8. Attachments (P2 placeholder)

Attachment *bodies* are stored as content-addressed encrypted blobs under
`attachments/<content_hash-hex>` (sibling dir, PRD §6.3), not in the DB. Each
blob is Envelope v1 encrypted under a per-attachment key, which is itself
wrapped by the owning item's ItemKey (`attachments.wrapped_key_env`). The
`content_hash` addresses the **ciphertext** blob (BLAKE3), giving dedup across
identical ciphertexts without a plaintext oracle. Not implemented for MVP;
the table and directory are reserved so the format need not change to add it.

---

## 9. Format versioning & migration

- `meta.format_version = 1` in every file. A reader that finds a higher
  `format_version` than it supports **must refuse to open** (no silent
  best-effort) — crypto agility is via versioned headers, not negotiation
  (PRD §5.1, downgrade resistance).
- Migrations are forward-only, run in a single transaction that bumps
  `schema_migrated_at`, and are idempotent (safe to re-run after a crash).
- `cipher_suite` is a separate axis (1 = XChaCha20-Poly1305; 2 reserved for
  AES-256-GCM, PRD §5.2). A vault's suite is fixed at create time; changing it
  is a full re-encrypt migration, not an in-place edit.
- The Envelope v1 first byte (`0x01`) is the crypto-format version and is
  independent of `format_version`; a future Envelope v2 can coexist because
  each blob is self-describing.

---

## 10. Invariants

1. No plaintext secret value, key, title, username, URL, tag, field name/value,
   note, or vault/folder name is ever written to disk. Only the columns in §6
   are plaintext.
2. Every ciphertext blob is Envelope v1 and binds AAD covering at minimum its
   `vault_id` + row identity + purpose label (§2, §3). No blob is portable to
   another row/vault.
3. `item_versions` and `ops` rows are immutable and append-only. Edits create
   new versions; they never mutate an existing version.
4. Every `(item_id, version)` has exactly one `wrapped_keys` row and one
   `item_versions` row; each version is encrypted under its own ItemKey.
5. The AccountKey is invariant across master-password changes; password change
   rewraps but never regenerates it (§5.5).
6. The op-log row for a change is committed in the same transaction as the
   change (§7); local vault state and local op log never diverge.
7. `format_version` mismatch (reader < file) is a hard open failure (§9).
8. A wrong password or Secret Key fails closed at the AccountKey unwrap
   (§5.2 step 4) with no partial key exposure.
9. All key material is zeroized on lock and on drop (§5.4).

## 11. Non-goals

- **Whole-file/SQLCipher encryption.** Rejected in favor of app-layer envelope
  encryption for per-item sharing and audited-Rust crypto (PRD §6.3).
- **Hiding structural metadata** (item count, edit timestamps, creation
  ordering). Out of scope for v1 — the threat model (§12) states plainly what
  a file thief learns. Padding/oblivious storage is not attempted.
- **Encrypting `kdf_params`.** Impossible by construction (needed pre-key).
- **Attachments as MVP.** Table reserved, not implemented (§8).
- **Cross-vault deduplication of item payloads.** Vaults are isolated; no
  shared key material or shared ciphertext across vaults.

## 12. Threat notes (PRD §8)

- **T1 (stolen device / stolen vault file):** a thief with a `.vault` file and
  no keys learns only §6 plaintext: item **count**, per-item creation/edit
  **timestamps** and thus **edit cadence**, op-log length,
  and — via UUIDv7 time prefixes — the **relative creation order** of items.
  Item types, favorite flags, and folder membership are inside the encrypted
  payloads and leak nothing.
  They learn **no** titles, usernames, URLs, tags, field names/values, notes,
  secrets, or vault/folder names. Confidentiality of secrets rests entirely on
  Argon2id + the 128-bit Secret Key (offline brute force infeasible even with a
  weak master password).
- **T2 (malware, same OS user, vault locked):** on-disk state is all ciphertext
  + §6 metadata; nothing usable is recoverable without unlocking, and the
  Secret Key lives in the OS keychain, not the vault file, raising the bar.
- **T5 (malicious relay / team server):** relevant to sync — a hostile channel
  handling `ops.payload_env` blobs sees only ciphertext with per-op AAD; it
  cannot forge, relocate, or silently alter ops (the Ed25519 signature and the
  hash chain in `ops` are checked on import — see sync-protocol.md).
- **T13 (sync-log rollback/tamper):** the `ops` table carries per-device `seq`
  and `prev_hash` so a dropped or reordered op is detectable on merge
  (sync-protocol.md §5); the vault file alone cannot be silently rolled back
  past a peer's known sequence.
