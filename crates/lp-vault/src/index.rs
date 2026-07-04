//! The persisted, encrypted, incrementally-updated search index
//! (`docs/specs/search-index.md`).
//!
//! # What this is
//!
//! A per-vault token index that makes [`Vault::search`](crate::Vault::search)
//! fast (< 50 ms p95 over 10k items, PRD §5.3) **without** an unlock-time index
//! cost. It is a *cache*: always derivable from the items, so losing it never
//! loses data (spec §8 invariant 1). Every persisted segment is an
//! [`Envelope`](lp_crypto::Envelope) v1 under the vault's `IndexKey`
//! (`derive_subkey("localpass/v1/index")`), and index updates ride the **same
//! SQLite transaction** as the item write, bumping `meta.index_generation` once
//! per write (spec §4).
//!
//! # Layout on disk (`index_segments` table, vault-format.md §3)
//!
//! - `segment_id = 0` is the **manifest** ([`Manifest`]): format version,
//!   generation, and the id-range + counts of every data segment.
//! - `segment_id >= 1` are **data segments** ([`SegmentData`]): each owns a
//!   contiguous `[item_lo, item_hi]` range of item ids (UUIDv7 → `u128`) and
//!   holds `token -> sorted item_ids` postings plus a reverse
//!   `item_id -> tokens` map for O(1)-per-item incremental delete.
//!
//! Because item ids are UUIDv7 (time-ordered, evenly distributed), an item
//! write touches exactly **one** data segment — the one owning its id range —
//! so re-encryption is O(1 segment) = O(changed items) (spec §3, §5).
//!
//! # Determinism
//!
//! Both plaintexts serialize through
//! [`canonical::to_canonical_vec`](crate::canonical::to_canonical_vec): sorted
//! keys, sorted posting lists, no whitespace. The same logical index therefore
//! produces byte-identical segment plaintext, matching the discipline the item
//! payloads use (vault-format.md §4).
//!
//! # Recovery ladder (spec §7)
//!
//! The index is never an unlock precondition. On a per-segment generation
//! mismatch or AEAD failure, only that segment is rebuilt from its id range. If
//! the manifest is unreadable, it is rebuilt by scanning item ids. If the whole
//! index is absent/unreadable, [`Vault::search`](crate::Vault::search) serves
//! results from the linear fallback and rebuilds lazily. All of that is
//! synchronous lazy repair at query time, which is acceptable for the MVP
//! (spec §7).

use std::collections::{BTreeMap, BTreeSet};

use lp_crypto::{Envelope, SymmetricKey, VaultKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::aad;
use crate::canonical;
use crate::error::{Error, Result};
use crate::ids::{Id, ItemId, VaultId};
use crate::payload::{FieldKind, ItemPayload, TypeData};

// --- Tuning constants (NOT format-fixed; spec §3) --------------------------

/// The HKDF label deriving the vault `IndexKey` from the `VaultKey`
/// (fixed contract, LESSONS.md / vault-format.md §1).
pub const INDEX_KEY_LABEL: &str = "localpass/v1/index";

/// On-disk index format version, stored in the manifest and every segment
/// (spec §3.1/§3.2). Independent of `meta.format_version` and the Envelope
/// version byte.
pub const INDEX_FORMAT_VERSION: u16 = 1;

/// The manifest always lives at this segment id (spec §3.1).
pub const MANIFEST_SEGMENT_ID: i64 = 0;

/// Target items per data segment (~40 segments at 10k items). Tuning only,
/// **not** format-fixed (spec §3): changing it re-partitions on the next full
/// rebuild without a format bump.
const DEFAULT_TARGET_ITEMS_PER_SEGMENT: usize = 256;

/// Split a data segment once it exceeds this many items. Tuning only.
const DEFAULT_SPLIT_THRESHOLD: usize = 512;

/// Merge two adjacent segments when their combined item count drops below this.
/// Tuning only.
const DEFAULT_MERGE_THRESHOLD: usize = 256;

/// Trigram length for fuzzy title matching (spec §2).
const TRIGRAM_LEN: usize = 3;

/// Read the split threshold. In production this is the spec constant
/// [`DEFAULT_SPLIT_THRESHOLD`]. The `LP_INDEX_SPLIT` environment variable
/// overrides it **for tests only** so the split/merge/multi-segment paths can
/// be exercised with a handful of items instead of hundreds (keeping the test
/// suite fast); no production code sets it. The tuning is not format-fixed
/// (spec §3), so an override changes only segmentation, never on-disk
/// compatibility.
fn split_threshold() -> usize {
    env_usize("LP_INDEX_SPLIT", DEFAULT_SPLIT_THRESHOLD)
}

/// Read the target items-per-segment (see [`split_threshold`] for the env hook).
fn target_items_per_segment() -> usize {
    env_usize("LP_INDEX_TARGET", DEFAULT_TARGET_ITEMS_PER_SEGMENT)
}

/// Read the merge threshold (see [`split_threshold`] for the env hook).
fn merge_threshold() -> usize {
    env_usize("LP_INDEX_MERGE", DEFAULT_MERGE_THRESHOLD)
}

/// Parse a `usize` tuning override from `var`, falling back to `default` if the
/// variable is unset or unparseable. Used only by the tuning knobs above.
fn env_usize(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default)
}

// --- Ranked-match kinds ----------------------------------------------------

/// How strongly a query token matched an item, for ranking (spec §6:
/// exact > prefix > trigram/fuzzy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MatchRank {
    /// A fuzzy/trigram hit (weakest).
    Trigram = 0,
    /// A prefix hit.
    Prefix = 1,
    /// An exact token hit (strongest).
    Exact = 2,
}

// --- On-disk plaintext models ----------------------------------------------

/// A per-segment id-range descriptor stored in the manifest (spec §3.1).
///
/// `item_lo`/`item_hi` are the inclusive UUIDv7-as-`u128` bounds the segment
/// owns; they are serialized as decimal strings so the canonical-JSON
/// integers-only rule (no floats, no precision loss past 2^53) holds for the
/// full 128-bit range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SegmentRange {
    /// The data segment's id (>= 1).
    segment_id: i64,
    /// Inclusive lower bound of the owned id range (u128 as decimal string).
    item_lo: String,
    /// Inclusive upper bound of the owned id range (u128 as decimal string).
    item_hi: String,
    /// Item count in the segment, for rebalancing heuristics.
    item_count: u32,
    /// Rough token count, for rebalancing heuristics (`token_est`, spec §3.1).
    token_est: u32,
}

/// Segment 0 — the manifest (spec §3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    /// Index format version ([`INDEX_FORMAT_VERSION`]).
    index_format_version: u16,
    /// Matches `meta.index_generation` when valid.
    generation: u64,
    /// Number of data segments.
    segment_count: u32,
    /// Total item count across all data segments.
    item_count: u32,
    /// The id-range descriptor of every data segment, sorted by `item_lo`.
    segments: Vec<SegmentRange>,
}

impl Manifest {
    /// The next unused data segment id (max existing + 1, min 1).
    fn next_segment_id(&self) -> i64 {
        self.segments
            .iter()
            .map(|s| s.segment_id)
            .max()
            .unwrap_or(0)
            .max(0)
            + 1
    }

    /// Locate the data segment owning `key`, returning its `segment_id`.
    fn owning_segment(&self, key: u128) -> Result<i64> {
        for s in &self.segments {
            let lo = parse_u128(&s.item_lo)?;
            let hi = parse_u128(&s.item_hi)?;
            if key >= lo && key <= hi {
                return Ok(s.segment_id);
            }
        }
        // The segment set always tiles [0, u128::MAX], so this is unreachable
        // for a well-formed manifest; treat a gap as corruption.
        Err(Error::Invalid("manifest has an id-range gap"))
    }
}

/// A data segment's postings (spec §3.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SegmentData {
    /// Index format version ([`INDEX_FORMAT_VERSION`]).
    index_format_version: u16,
    /// This segment's id (>= 1).
    segment_id: i64,
    /// Generation embedded in the plaintext (must equal the AAD generation and
    /// `meta.index_generation` when current; spec §4).
    generation: u64,
    /// `token -> sorted, de-duplicated item ids` (ids as decimal `u128` strings).
    postings: BTreeMap<String, Vec<String>>,
    /// Reverse map `item_id -> its token set`, for O(1)-per-item delete (spec §5).
    item_tokens: BTreeMap<String, Vec<String>>,
}

impl SegmentData {
    /// An empty data segment at the given id/generation.
    fn empty(segment_id: i64, generation: u64) -> Self {
        Self {
            index_format_version: INDEX_FORMAT_VERSION,
            segment_id,
            generation,
            postings: BTreeMap::new(),
            item_tokens: BTreeMap::new(),
        }
    }

    /// Number of distinct items indexed in this segment.
    fn item_count(&self) -> usize {
        self.item_tokens.len()
    }

    /// Remove an item from all its postings and drop its reverse entry.
    fn remove_item(&mut self, item_key: &str) {
        if let Some(tokens) = self.item_tokens.remove(item_key) {
            for tok in tokens {
                if let Some(ids) = self.postings.get_mut(&tok) {
                    ids.retain(|id| id != item_key);
                    if ids.is_empty() {
                        self.postings.remove(&tok);
                    }
                }
            }
        }
    }

    /// Insert (or replace) an item with a fresh token set: diff against any
    /// existing tokens so postings for dropped tokens shrink and postings for
    /// new tokens grow (spec §5 create/update).
    fn upsert_item(&mut self, item_key: &str, tokens: &BTreeSet<String>) {
        // Simplest correct diff: fully remove then re-add. Cost is O(tokens for
        // this one item), which is the spec's O(changed items) budget.
        self.remove_item(item_key);
        let mut token_list: Vec<String> = Vec::with_capacity(tokens.len());
        for tok in tokens {
            let ids = self.postings.entry(tok.clone()).or_default();
            // Keep each posting list sorted + de-duplicated for determinism.
            if let Err(pos) = ids.binary_search(&item_key.to_string()) {
                ids.insert(pos, item_key.to_string());
            }
            token_list.push(tok.clone());
        }
        // token_list is already sorted because `tokens` is a BTreeSet.
        self.item_tokens.insert(item_key.to_string(), token_list);
    }

    /// Total posting entries, an estimate for `token_est`.
    fn token_est(&self) -> u32 {
        u32::try_from(self.postings.len()).unwrap_or(u32::MAX)
    }
}

// --- u128 <-> item id helpers ----------------------------------------------

/// Map a 16-byte id to a `u128` via big-endian bytes: the UUIDv7 time prefix is
/// the most-significant bits, so numeric order matches creation order and the
/// range partition is stable and even (spec §3.2).
#[must_use]
fn id_to_u128(id: &Id) -> u128 {
    u128::from_be_bytes(*id.as_bytes())
}

/// Decimal-string form of an id-as-`u128` (the posting/reverse-map key).
fn id_key(id: &Id) -> String {
    id_to_u128(id).to_string()
}

/// Parse a decimal `u128` (segment range bound or posting key).
fn parse_u128(s: &str) -> Result<u128> {
    s.parse::<u128>()
        .map_err(|_| Error::Invalid("index: malformed u128 in segment plaintext"))
}

/// Recover a 16-byte [`ItemId`] from a decimal `u128` posting key.
fn key_to_id(key: &str) -> Result<ItemId> {
    Ok(Id::from_bytes(parse_u128(key)?.to_be_bytes()))
}

// --- Tokenizer (spec §2) ---------------------------------------------------

/// The token set produced from an item's indexed fields, plus the query-side
/// tokenizer. Never sees secret values (spec §2, PRD §4.2).
pub(crate) struct Tokenizer;

impl Tokenizer {
    /// Normalize free text: NFKC, lowercase, then split on any character that is
    /// not alphanumeric, yielding word tokens (spec §2). Empty pieces dropped.
    fn words(text: &str) -> Vec<String> {
        let normalized: String = text.nfkc().collect::<String>().to_lowercase();
        normalized
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Character trigrams of a normalized string, for fuzzy title match
    /// (spec §2). A string shorter than [`TRIGRAM_LEN`] yields the whole string
    /// as one gram (so short titles remain fuzzily findable). Prefixed with
    /// `tri:` so trigrams never collide with word/prefix tokens.
    fn trigrams(text: &str) -> Vec<String> {
        let normalized: String = text.nfkc().collect::<String>().to_lowercase();
        let chars: Vec<char> = normalized.chars().filter(|c| !c.is_whitespace()).collect();
        let mut out = Vec::new();
        if chars.is_empty() {
            return out;
        }
        if chars.len() < TRIGRAM_LEN {
            out.push(format!("tri:{}", chars.iter().collect::<String>()));
            return out;
        }
        for window in chars.windows(TRIGRAM_LEN) {
            out.push(format!("tri:{}", window.iter().collect::<String>()));
        }
        out
    }

    /// Split a URL into a full-URL token and a host token (spec §2). Best-effort
    /// host extraction without a URL-parser dependency: strip scheme, take up to
    /// the first `/`, `?`, or `#`, drop any userinfo and port.
    fn url_tokens(url: &str) -> Vec<String> {
        let lowered = url.nfkc().collect::<String>().to_lowercase();
        let mut out = vec![format!("url:{lowered}")];
        let after_scheme = lowered.split_once("://").map_or(lowered.as_str(), |x| x.1);
        let authority = after_scheme
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(after_scheme);
        // Drop userinfo (user:pass@host) and port.
        let host = authority
            .rsplit_once('@')
            .map_or(authority, |x| x.1)
            .split(':')
            .next()
            .unwrap_or(authority);
        if !host.is_empty() {
            // `host:<host>` is the structural host token (for a future `host:`
            // filter). The host's individual words (e.g. `github`, `com`) are
            // also stored as plain tokens so a query like `github.com` — which
            // the query tokenizer splits into those words — matches by AND.
            out.push(format!("host:{host}"));
            for w in Self::words(host) {
                out.push(w);
            }
        }
        out
    }

    /// The full token set for an item (spec §2). Indexes ONLY: title (words +
    /// trigrams; prefix matching is done at query time), the username field
    /// value, URLs (field values of kind `url` and `login` extra urls), tags
    /// (exact word tokens; prefix + `tag:` filter), custom field **names**, and
    /// the structural filter tokens. NEVER indexes secret values,
    /// custom field values, or the note body.
    pub(crate) fn item_tokens(payload: &ItemPayload) -> BTreeSet<String> {
        let mut tokens = BTreeSet::new();

        // Title: exact words + trigrams (fuzzy). Prefix matching is done at query
        // time by range-scanning the postings' word keys (see `match_term`), so
        // no per-prefix tokens are stored — that keeps segments small and each
        // segment re-encrypt cheap (spec §3 O(changed items)), while still
        // supporting the prefix rank tier (spec §6).
        for word in Self::words(&payload.title) {
            tokens.insert(word);
        }
        for g in Self::trigrams(&payload.title) {
            tokens.insert(g);
        }

        // Tags: exact word tokens (prefix handled at query time). Also a
        // structural `tag:` filter token for the `tag:` query filter (spec §2).
        for tag in &payload.tags {
            for word in Self::words(tag) {
                tokens.insert(word);
            }
            let normalized_tag = tag.nfkc().collect::<String>().to_lowercase();
            if !normalized_tag.is_empty() {
                tokens.insert(format!("tag:{normalized_tag}"));
            }
        }

        // Custom fields: NAMES are indexed as words; VALUES are indexed only for
        // the username handle and url fields (spec §2, PRD §4.2). Field values
        // of any other kind are NEVER indexed.
        for field in &payload.fields {
            for word in Self::words(&field.name) {
                tokens.insert(word);
            }
            let is_username = field.name.eq_ignore_ascii_case("username")
                || field.name.eq_ignore_ascii_case("user");
            match field.kind {
                FieldKind::Url => {
                    if let Some(v) = field.value.as_str() {
                        for t in Self::url_tokens(v) {
                            tokens.insert(t);
                        }
                    }
                }
                FieldKind::Text if is_username => {
                    if let Some(v) = field.value.as_str() {
                        for word in Self::words(v) {
                            tokens.insert(word);
                        }
                    }
                }
                // hidden / date / non-username text: value never indexed.
                _ => {}
            }
        }

        // Type-specific URLs (login extra urls) — these are searchable handles.
        if let TypeData::Login { urls } = &payload.type_data {
            for u in urls {
                for t in Self::url_tokens(u) {
                    tokens.insert(t);
                }
            }
        }

        // Structural filter tokens (spec §2/§6): type:, folder:, fav:.
        tokens.insert(format!("type:{}", payload.type_data.type_str()));
        if let Some(folder) = &payload.folder_id {
            let f = folder.nfkc().collect::<String>().to_lowercase();
            if !f.is_empty() {
                tokens.insert(format!("folder:{f}"));
            }
        }
        if payload.favorite {
            tokens.insert("fav:true".to_string());
        }

        tokens
    }
}

// --- The parsed query ------------------------------------------------------

/// A tokenized search query: free tokens (AND-intersected, ranked) plus the
/// resolved structural filters (`type:`/`tag:`/`folder:`/`fav:`).
struct ParsedQuery {
    /// One entry per free-text query term; each is `(exact_word, is_prefixable)`.
    terms: Vec<String>,
    /// Structural filter tokens that must all be present (spec §6).
    filters: Vec<String>,
}

impl ParsedQuery {
    /// Parse a raw query string. Recognizes `type:`, `tag:`, `folder:`,
    /// `fav:`/`favorite:`, and `vault:` (the latter is a structural no-op here —
    /// a single [`Vault`](crate::Vault) is one vault — accepted for CLI parity,
    /// spec §6). Everything else is a free term.
    fn parse(query: &str) -> Self {
        let mut terms = Vec::new();
        let mut filters = Vec::new();
        for raw in query.split_whitespace() {
            if let Some((key, val)) = raw.split_once(':') {
                let key_l = key.to_lowercase();
                let val_n = val.nfkc().collect::<String>().to_lowercase();
                match key_l.as_str() {
                    "type" => filters.push(format!("type:{val_n}")),
                    "tag" => filters.push(format!("tag:{val_n}")),
                    "folder" => filters.push(format!("folder:{val_n}")),
                    "fav" | "favorite" => {
                        // fav:, fav:true, fav:1, fav:yes all mean "favorited".
                        if val_n.is_empty() || matches!(val_n.as_str(), "true" | "1" | "yes" | "y")
                        {
                            filters.push("fav:true".to_string());
                        } else if matches!(val_n.as_str(), "false" | "0" | "no" | "n") {
                            // fav:false → no filter (matches everything).
                        } else {
                            filters.push(format!("fav:{val_n}"));
                        }
                    }
                    // vault: is a structural scope handled by the caller choosing
                    // which Vault to search; ignore it here.
                    "vault" => {}
                    // Unknown prefix like `foo:bar` → treat the whole thing as a
                    // free term so it still narrows results.
                    _ => Self::push_free_term(&mut terms, raw),
                }
            } else {
                Self::push_free_term(&mut terms, raw);
            }
        }
        Self { terms, filters }
    }

    /// Turn one whitespace-delimited free token into query terms by word-split
    /// (NFKC + lowercase + split on punctuation). A dotted token like
    /// `github.com` becomes the AND of its words (`github`, `com`), which match
    /// the per-host word tokens the indexer stores (see
    /// [`Tokenizer::url_tokens`]); each term is AND-combined with the rest
    /// (spec §6).
    fn push_free_term(terms: &mut Vec<String>, raw: &str) {
        for w in Tokenizer::words(raw) {
            terms.push(w);
        }
    }

    /// Whether the query has no constraints at all (empty query, empty filters):
    /// then every live item matches (matches the linear-fallback semantics).
    fn is_unconstrained(&self) -> bool {
        self.terms.is_empty() && self.filters.is_empty()
    }
}

// --- The index handle ------------------------------------------------------

/// A live, transaction-aware handle to one vault's encrypted search index.
///
/// Constructed per operation from the vault id and the derived `IndexKey`. It
/// holds no long-lived key material of its own (the `IndexKey` is derived from
/// the live [`VaultKey`] on demand and dropped with this handle), so lock/unlock
/// never touches the index (spec §6/§7 invariant: unlock is index-free).
pub(crate) struct SearchIndex {
    vault_id: VaultId,
    index_key: SymmetricKey,
}

impl SearchIndex {
    /// Derive the `IndexKey` from the `VaultKey` and build a handle (spec §1).
    pub(crate) fn new(vault_id: VaultId, vault_key: &VaultKey) -> Result<Self> {
        let index_key = vault_key
            .derive_subkey(INDEX_KEY_LABEL)
            .map_err(Error::from_crypto)?;
        Ok(Self {
            vault_id,
            index_key,
        })
    }

    // --- AAD + envelope helpers -------------------------------------------

    /// The AAD for a segment at a given id + generation (spec §1;
    /// vault-format.md §3 index-segment row).
    fn segment_aad(&self, segment_id: i64, generation: u64) -> Vec<u8> {
        aad::index_segment(&self.vault_id, segment_id, generation)
    }

    /// Encrypt a canonical plaintext into an [`Envelope`] under the IndexKey.
    fn seal_bytes(&self, plaintext: &[u8], segment_id: i64, generation: u64) -> Result<Vec<u8>> {
        let env = self
            .index_key
            .seal(plaintext, &self.segment_aad(segment_id, generation))
            .map_err(Error::from_crypto)?;
        Ok(env.to_bytes())
    }

    /// Decrypt a stored segment envelope, verifying it against the expected
    /// generation via AAD (a stale/tampered blob fails here; spec §4).
    fn open_bytes(&self, env_bytes: &[u8], segment_id: i64, generation: u64) -> Result<Vec<u8>> {
        let env = Envelope::from_bytes(env_bytes).map_err(Error::from_crypto)?;
        self.index_key
            .open(&env, &self.segment_aad(segment_id, generation))
            .map_err(Error::from_crypto)
    }

    // --- Raw segment IO ----------------------------------------------------

    /// Read `(generation, payload_env)` for a segment id, if present.
    fn read_segment_row(conn: &Connection, segment_id: i64) -> Result<Option<(i64, Vec<u8>)>> {
        Ok(conn
            .query_row(
                "SELECT generation, payload_env FROM index_segments WHERE segment_id = ?1",
                params![segment_id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?)
    }

    /// Upsert a segment row `(segment_id, generation, payload_env)`.
    fn write_segment_row(
        conn: &Connection,
        segment_id: i64,
        generation: i64,
        payload_env: &[u8],
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO index_segments (segment_id, generation, payload_env)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(segment_id) DO UPDATE SET generation = ?2, payload_env = ?3",
            params![segment_id, generation, payload_env],
        )?;
        Ok(())
    }

    /// Delete a segment row (used when merging removes a segment).
    fn delete_segment_row(conn: &Connection, segment_id: i64) -> Result<()> {
        conn.execute(
            "DELETE FROM index_segments WHERE segment_id = ?1",
            params![segment_id],
        )?;
        Ok(())
    }

    // --- Manifest load / persist ------------------------------------------

    /// Read `meta.index_generation`.
    fn read_generation(conn: &Connection) -> Result<u64> {
        let g: i64 = conn.query_row("SELECT index_generation FROM meta WHERE id = 1", [], |r| {
            r.get(0)
        })?;
        u64::try_from(g).map_err(|_| Error::Invalid("index_generation out of range"))
    }

    /// Bump `meta.index_generation` to `new_gen`.
    fn write_generation(conn: &Connection, new_gen: u64) -> Result<()> {
        let g = i64::try_from(new_gen).map_err(|_| Error::Invalid("generation overflow"))?;
        conn.execute(
            "UPDATE meta SET index_generation = ?1 WHERE id = 1",
            params![g],
        )?;
        Ok(())
    }

    /// Load and decrypt the manifest at the current generation. Returns `None`
    /// if the manifest row is absent or fails to decrypt / mismatches its
    /// generation (the caller then rebuilds; spec §7 rung 2).
    fn load_manifest(&self, conn: &Connection, generation: u64) -> Option<Manifest> {
        let (row_gen, env) = Self::read_segment_row(conn, MANIFEST_SEGMENT_ID).ok()??;
        // The manifest must be at the current generation to be trusted (spec §4).
        if u64::try_from(row_gen).ok()? != generation {
            return None;
        }
        let plaintext = self
            .open_bytes(&env, MANIFEST_SEGMENT_ID, generation)
            .ok()?;
        let manifest: Manifest = canonical::from_canonical_slice(&plaintext).ok()?;
        if manifest.index_format_version != INDEX_FORMAT_VERSION
            || manifest.generation != generation
        {
            return None;
        }
        Some(manifest)
    }

    /// Encrypt + write the manifest row at `generation`.
    fn persist_manifest(
        &self,
        conn: &Connection,
        manifest: &Manifest,
        generation: u64,
    ) -> Result<()> {
        let plaintext = canonical::to_canonical_vec(manifest)?;
        let env = self.seal_bytes(&plaintext, MANIFEST_SEGMENT_ID, generation)?;
        let g = i64::try_from(generation).map_err(|_| Error::Invalid("generation overflow"))?;
        Self::write_segment_row(conn, MANIFEST_SEGMENT_ID, g, &env)?;
        Ok(())
    }

    /// Load and decrypt a data segment at the current generation. `None` if the
    /// row is absent, stale (generation mismatch), or fails AEAD (spec §7 rung 1
    /// — the caller then rebuilds that one segment).
    fn load_segment(
        &self,
        conn: &Connection,
        segment_id: i64,
        generation: u64,
    ) -> Option<SegmentData> {
        let (row_gen, env) = Self::read_segment_row(conn, segment_id).ok()??;
        if u64::try_from(row_gen).ok()? != generation {
            return None;
        }
        let plaintext = self.open_bytes(&env, segment_id, generation).ok()?;
        let seg: SegmentData = canonical::from_canonical_slice(&plaintext).ok()?;
        if seg.index_format_version != INDEX_FORMAT_VERSION
            || seg.segment_id != segment_id
            || seg.generation != generation
        {
            return None;
        }
        Some(seg)
    }

    /// Encrypt + write a data segment row at `generation` (also stamps the
    /// generation into the plaintext; spec §4).
    fn persist_segment(
        &self,
        conn: &Connection,
        segment: &SegmentData,
        generation: u64,
    ) -> Result<()> {
        let mut seg = segment.clone();
        seg.generation = generation;
        let plaintext = canonical::to_canonical_vec(&seg)?;
        let env = self.seal_bytes(&plaintext, seg.segment_id, generation)?;
        let g = i64::try_from(generation).map_err(|_| Error::Invalid("generation overflow"))?;
        Self::write_segment_row(conn, seg.segment_id, g, &env)?;
        Ok(())
    }
}

// --- Read-side: item id + payload access over a connection -----------------

/// Read every live (non-tombstoned) item's `(item_id, payload)` over `conn`
/// using `decrypt`, which the vault supplies (it owns the item keys). Used for
/// full and per-segment rebuilds.
pub(crate) type PayloadReader<'a> = dyn Fn(&Connection, &ItemId) -> Result<ItemPayload> + 'a;

impl SearchIndex {
    /// Collect the ids of all live items whose id-as-`u128` falls in
    /// `[lo, hi]`, ordered by id.
    fn live_ids_in_range(conn: &Connection, lo: u128, hi: u128) -> Result<Vec<ItemId>> {
        let ids: Vec<Vec<u8>> = {
            let mut stmt = conn.prepare(
                "SELECT i.item_id FROM items i
                 WHERE NOT EXISTS (SELECT 1 FROM tombstones t WHERE t.item_id = i.item_id)",
            )?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut out = Vec::new();
        for b in ids {
            let id = Id::from_slice(&b)?;
            let k = id_to_u128(&id);
            if k >= lo && k <= hi {
                out.push(id);
            }
        }
        out.sort_by_key(id_to_u128);
        Ok(out)
    }

    /// All live item ids (for a manifest rebuild by scanning, spec §7 rung 2).
    fn all_live_ids(conn: &Connection) -> Result<Vec<ItemId>> {
        Self::live_ids_in_range(conn, u128::MIN, u128::MAX)
    }

    // --- Manifest availability (with lazy repair) -------------------------

    /// Return the current manifest, rebuilding it (and all segments) from the
    /// items if it is absent/unreadable (spec §7 rung 2/3). This is the entry
    /// every read/write uses to guarantee an authoritative manifest. All work
    /// happens inside the caller's transaction/connection.
    ///
    /// Returns the manifest **and** whether a rebuild was performed (so a caller
    /// on a read-only path knows a generation bump already happened).
    fn ensure_manifest(&self, conn: &Connection, decrypt: &PayloadReader<'_>) -> Result<Manifest> {
        let generation = Self::read_generation(conn)?;
        if let Some(m) = self.load_manifest(conn, generation) {
            return Ok(m);
        }
        // No valid manifest at the current generation. Two cases:
        let has_rows: bool =
            conn.query_row("SELECT EXISTS(SELECT 1 FROM index_segments)", [], |r| {
                r.get::<_, i64>(0)
            })? != 0;
        if has_rows {
            // The index exists but its manifest is unreadable/stale → full
            // rebuild at a BUMPED generation (spec §7 rung 2/3), superseding the
            // stale rows.
            self.full_rebuild(conn, decrypt)?;
        } else {
            // Virgin index (never built, or fully wiped): establish it at the
            // CURRENT generation without a bump, so the first item write is the
            // one that bumps exactly once (spec §4). Build from whatever items
            // already exist (usually none on a fresh vault).
            self.rebuild_at_generation(conn, generation, decrypt)?;
        }
        let cur = Self::read_generation(conn)?;
        self.load_manifest(conn, cur)
            .ok_or(Error::Invalid("index: manifest unreadable after rebuild"))
    }

    /// Load a data segment, lazily rebuilding it from its id range if it is
    /// stale/corrupt (spec §7 rung 1). The rebuild happens in-transaction and
    /// re-persists the single segment at the current generation.
    fn ensure_segment(
        &self,
        conn: &Connection,
        manifest: &Manifest,
        segment_id: i64,
        generation: u64,
        decrypt: &PayloadReader<'_>,
    ) -> Result<SegmentData> {
        if let Some(seg) = self.load_segment(conn, segment_id, generation) {
            return Ok(seg);
        }
        // Stale/corrupt single segment → rebuild ONLY its id range and
        // re-persist at the current generation (no generation bump: the segment
        // is being brought up to the already-current generation; spec §7 rung 1).
        let range = manifest
            .segments
            .iter()
            .find(|s| s.segment_id == segment_id)
            .ok_or(Error::Invalid("index: segment id not in manifest"))?;
        let lo = parse_u128(&range.item_lo)?;
        let hi = parse_u128(&range.item_hi)?;
        let seg = self.build_segment_from_range(conn, segment_id, generation, lo, hi, decrypt)?;
        self.persist_segment(conn, &seg, generation)?;
        Ok(seg)
    }

    /// Build a data segment's postings by decrypting every live item in
    /// `[lo, hi]` and tokenizing it (spec §5/§7). Pure in-memory build; the
    /// caller persists it.
    fn build_segment_from_range(
        &self,
        conn: &Connection,
        segment_id: i64,
        generation: u64,
        lo: u128,
        hi: u128,
        decrypt: &PayloadReader<'_>,
    ) -> Result<SegmentData> {
        let mut seg = SegmentData::empty(segment_id, generation);
        for id in Self::live_ids_in_range(conn, lo, hi)? {
            let payload = decrypt(conn, &id)?;
            let tokens = Tokenizer::item_tokens(&payload);
            seg.upsert_item(&id_key(&id), &tokens);
        }
        Ok(seg)
    }

    // --- Full rebuild (spec §7 rung 3) ------------------------------------

    /// Rebuild the entire index from the items at a **bumped** generation,
    /// writing the manifest + all data segments and deleting any stale segment
    /// rows, all in the caller's transaction. Used when the index exists but its
    /// manifest is unreadable, or on an explicit [`rebuild`](Self::rebuild).
    fn full_rebuild(&self, conn: &Connection, decrypt: &PayloadReader<'_>) -> Result<()> {
        let new_gen = Self::read_generation(conn)?.saturating_add(1);
        self.rebuild_at_generation(conn, new_gen, decrypt)
    }

    /// Rebuild the entire index from the items **at `gen`** (writing `gen` into
    /// `meta.index_generation`, the manifest, and every segment) after wiping
    /// any existing index rows. Shared by [`full_rebuild`] (which passes a
    /// bumped `gen`) and the virgin-index init in [`ensure_manifest`] (which
    /// passes the *current* `gen`, so establishing the index costs no bump).
    fn rebuild_at_generation(
        &self,
        conn: &Connection,
        generation: u64,
        decrypt: &PayloadReader<'_>,
    ) -> Result<()> {
        // Partition all live ids into contiguous chunks of ~TARGET items,
        // producing one data segment per chunk (ids sorted ascending).
        let ids = Self::all_live_ids(conn)?;

        // Wipe every existing segment row (manifest + data) so no stale row at a
        // now-superseded generation lingers.
        conn.execute("DELETE FROM index_segments", [])?;

        let mut ranges: Vec<SegmentRange> = Vec::new();
        let mut segment_id: i64 = 1;

        if ids.is_empty() {
            // A single empty full-range segment so the next write finds an owner.
            let seg = SegmentData::empty(segment_id, generation);
            self.persist_segment(conn, &seg, generation)?;
            ranges.push(SegmentRange {
                segment_id,
                item_lo: u128::MIN.to_string(),
                item_hi: u128::MAX.to_string(),
                item_count: 0,
                token_est: 0,
            });
        } else {
            let target = target_items_per_segment();
            let mut idx = 0;
            while idx < ids.len() {
                let end = (idx + target).min(ids.len());
                let chunk = &ids[idx..end];
                // This segment owns [lo, hi]. The first segment starts at u128::MIN
                // and the last ends at u128::MAX so the ranges fully tile the
                // space (any future id lands in exactly one segment).
                let lo = if idx == 0 {
                    u128::MIN
                } else {
                    id_to_u128(&chunk[0])
                };
                let hi = if end == ids.len() {
                    u128::MAX
                } else {
                    // Up to (but not including) the next chunk's first id.
                    id_to_u128(&ids[end]) - 1
                };
                let seg =
                    self.build_segment_from_range(conn, segment_id, generation, lo, hi, decrypt)?;
                ranges.push(SegmentRange {
                    segment_id,
                    item_lo: lo.to_string(),
                    item_hi: hi.to_string(),
                    item_count: u32::try_from(seg.item_count()).unwrap_or(u32::MAX),
                    token_est: seg.token_est(),
                });
                self.persist_segment(conn, &seg, generation)?;
                segment_id += 1;
                idx = end;
            }
        }

        let manifest = Manifest {
            index_format_version: INDEX_FORMAT_VERSION,
            generation,
            segment_count: u32::try_from(ranges.len()).unwrap_or(u32::MAX),
            item_count: ranges.iter().map(|r| r.item_count).sum(),
            segments: ranges,
        };
        self.persist_manifest(conn, &manifest, generation)?;
        Self::write_generation(conn, generation)?;
        Ok(())
    }

    /// Public entry for an explicit full rebuild (maintenance;
    /// [`Vault::rebuild_index`](crate::Vault::rebuild_index)). Runs in its own
    /// transaction on `conn`.
    pub(crate) fn rebuild(&self, conn: &mut Connection, decrypt: &PayloadReader<'_>) -> Result<()> {
        let tx = conn.transaction()?;
        self.full_rebuild(&tx, decrypt)?;
        tx.commit()?;
        Ok(())
    }

    // --- Incremental update (spec §4/§5) ----------------------------------

    /// Apply a single item's create/update to the index **inside the caller's
    /// transaction** (spec §4 step 1–5): locate the owning segment, upsert the
    /// item's tokens, bump the generation, and re-persist the touched segment +
    /// manifest at the new generation. Only the owning segment's ciphertext
    /// changes (plus the manifest); every other segment row is left byte-for-byte
    /// untouched.
    ///
    /// `new_payload` is the item's current indexed payload.
    pub(crate) fn apply_upsert(
        &self,
        tx: &Connection,
        item_id: &ItemId,
        new_payload: &ItemPayload,
        decrypt: &PayloadReader<'_>,
    ) -> Result<()> {
        let manifest = self.ensure_manifest(tx, decrypt)?;
        let key = id_to_u128(item_id);
        let owner = manifest.owning_segment(key)?;
        let cur_gen = Self::read_generation(tx)?;
        let new_gen = cur_gen.saturating_add(1);

        // Load (repairing if needed) the owning segment at the current gen.
        let mut segment = self.ensure_segment(tx, &manifest, owner, cur_gen, decrypt)?;
        let tokens = Tokenizer::item_tokens(new_payload);
        segment.upsert_item(&id_key(item_id), &tokens);

        // An upsert only ever GROWS the segment, so only a split can apply.
        self.commit_touched_segment(
            tx,
            manifest,
            segment,
            new_gen,
            RebalanceMode::MaySplit,
            decrypt,
        )
    }

    /// Apply a single item's delete (tombstone) to the index inside the caller's
    /// transaction (spec §5 delete): remove the item from its owning segment,
    /// bump the generation, re-persist the touched segment + manifest.
    pub(crate) fn apply_delete(
        &self,
        tx: &Connection,
        item_id: &ItemId,
        decrypt: &PayloadReader<'_>,
    ) -> Result<()> {
        let manifest = self.ensure_manifest(tx, decrypt)?;
        let key = id_to_u128(item_id);
        let owner = manifest.owning_segment(key)?;
        let cur_gen = Self::read_generation(tx)?;
        let new_gen = cur_gen.saturating_add(1);

        let mut segment = self.ensure_segment(tx, &manifest, owner, cur_gen, decrypt)?;
        segment.remove_item(&id_key(item_id));

        // A delete only ever SHRINKS the segment, so only a merge can apply.
        self.commit_touched_segment(
            tx,
            manifest,
            segment,
            new_gen,
            RebalanceMode::MayMerge,
            decrypt,
        )
    }

    /// Persist a single touched segment + the manifest at `new_gen`, applying
    /// the applicable split/merge tuning to the touched segment, and bump the
    /// meta generation. Shared by upsert/delete. Every other segment row is left
    /// untouched (so its ciphertext bytes do not change; spec §4).
    fn commit_touched_segment(
        &self,
        tx: &Connection,
        mut manifest: Manifest,
        segment: SegmentData,
        new_gen: u64,
        mode: RebalanceMode,
        decrypt: &PayloadReader<'_>,
    ) -> Result<()> {
        // Rebalance: split if oversized (on growth) or merge with an adjacent
        // under-full neighbour (on shrink). Returns the set of segments to
        // (re)persist and the segment ids to delete, plus the updated manifest.
        let RebalanceOutcome { persist, delete } =
            self.rebalance(tx, &mut manifest, segment, new_gen, mode, decrypt)?;

        for seg in &persist {
            self.persist_segment(tx, seg, new_gen)?;
        }
        for seg_id in delete {
            Self::delete_segment_row(tx, seg_id)?;
        }

        manifest.generation = new_gen;
        manifest.index_format_version = INDEX_FORMAT_VERSION;
        manifest.segment_count = u32::try_from(manifest.segments.len()).unwrap_or(u32::MAX);
        manifest.item_count = manifest.segments.iter().map(|r| r.item_count).sum();
        self.persist_manifest(tx, &manifest, new_gen)?;
        Self::write_generation(tx, new_gen)?;
        Ok(())
    }

    /// Apply the split-or-merge tuning appropriate to `mode`, updating the
    /// manifest ranges in place. Returns which segments to (re)persist and which
    /// rows to delete. A split touches only the affected segment (partitioned
    /// **in memory**, no DB scan); a merge touches it and at most one neighbour.
    /// This keeps an update O(changed items) (spec §3): re-encrypt one (or two)
    /// bounded segments, never a whole-index rebuild.
    fn rebalance(
        &self,
        tx: &Connection,
        manifest: &mut Manifest,
        segment: SegmentData,
        new_gen: u64,
        mode: RebalanceMode,
        decrypt: &PayloadReader<'_>,
    ) -> Result<RebalanceOutcome> {
        let seg_id = segment.segment_id;
        let count = segment.item_count();

        // Update the manifest range's counts for the touched segment first.
        Self::update_range_stats(manifest, &segment);

        match mode {
            // On growth: split if the segment is now oversized.
            RebalanceMode::MaySplit if count > split_threshold() => {
                self.split_segment(manifest, segment, new_gen)
            }
            // On shrink: merge with an adjacent under-full neighbour if the
            // combined size stays under the merge threshold (spec §3).
            RebalanceMode::MayMerge if count < merge_threshold() => {
                if let Some(outcome) =
                    self.try_merge(tx, manifest, seg_id, count, new_gen, decrypt)?
                {
                    Ok(outcome)
                } else {
                    Ok(RebalanceOutcome {
                        persist: vec![segment],
                        delete: Vec::new(),
                    })
                }
            }
            _ => Ok(RebalanceOutcome {
                persist: vec![segment],
                delete: Vec::new(),
            }),
        }
    }

    /// Recompute a manifest range's item_count/token_est from a segment.
    fn update_range_stats(manifest: &mut Manifest, segment: &SegmentData) {
        if let Some(range) = manifest
            .segments
            .iter_mut()
            .find(|r| r.segment_id == segment.segment_id)
        {
            range.item_count = u32::try_from(segment.item_count()).unwrap_or(u32::MAX);
            range.token_est = segment.token_est();
        }
    }

    /// Split an oversized segment at the median id into two contiguous
    /// segments, **partitioning the postings in memory** (no DB scan / decrypt;
    /// spec §3/§5 "split if oversized"). The lower half keeps the original id;
    /// the upper half gets a fresh id. This is what keeps a split O(the touched
    /// segment), not O(vault).
    fn split_segment(
        &self,
        manifest: &mut Manifest,
        segment: SegmentData,
        new_gen: u64,
    ) -> Result<RebalanceOutcome> {
        let seg_id = segment.segment_id;
        // The segment's item ids, sorted, to pick a median split point.
        let mut keys: Vec<u128> = segment
            .item_tokens
            .keys()
            .map(|k| parse_u128(k))
            .collect::<Result<_>>()?;
        keys.sort_unstable();
        let mid = keys.len() / 2;
        let split_key = keys[mid];

        let range = manifest
            .segments
            .iter()
            .find(|r| r.segment_id == seg_id)
            .ok_or(Error::Invalid("index: split target missing from manifest"))?;
        // The lower half keeps the original `item_lo`; only `item_hi` moves.
        let hi = parse_u128(&range.item_hi)?;

        // Lower half owns [item_lo, split_key - 1]; upper half owns [split_key, hi].
        let lower_hi = split_key - 1;
        let upper_lo = split_key;
        let new_id = manifest.next_segment_id();

        // Re-partition the in-memory postings by re-inserting each item into the
        // half its id falls in — no item decryption needed, the tokens are
        // already in hand.
        let mut lower = SegmentData::empty(seg_id, new_gen);
        let mut upper = SegmentData::empty(new_id, new_gen);
        for (item_key, tokens) in &segment.item_tokens {
            let k = parse_u128(item_key)?;
            let set: BTreeSet<String> = tokens.iter().cloned().collect();
            if k < upper_lo {
                lower.upsert_item(item_key, &set);
            } else {
                upper.upsert_item(item_key, &set);
            }
        }

        // Rewrite the manifest ranges: shrink the original, add the new one.
        if let Some(r) = manifest
            .segments
            .iter_mut()
            .find(|r| r.segment_id == seg_id)
        {
            r.item_hi = lower_hi.to_string();
            r.item_count = u32::try_from(lower.item_count()).unwrap_or(u32::MAX);
            r.token_est = lower.token_est();
        }
        manifest.segments.push(SegmentRange {
            segment_id: new_id,
            item_lo: upper_lo.to_string(),
            item_hi: hi.to_string(),
            item_count: u32::try_from(upper.item_count()).unwrap_or(u32::MAX),
            token_est: upper.token_est(),
        });
        sort_ranges(&mut manifest.segments);

        Ok(RebalanceOutcome {
            persist: vec![lower, upper],
            delete: Vec::new(),
        })
    }

    /// If the touched segment plus an adjacent neighbour together stay under
    /// the merge threshold, merge them into the lower segment and drop the
    /// higher one (spec §3 "merge adjacent under-full"). Returns `None` if no
    /// beneficial merge applies (e.g. only one segment, or the neighbour is
    /// large).
    fn try_merge(
        &self,
        tx: &Connection,
        manifest: &mut Manifest,
        seg_id: i64,
        count: usize,
        new_gen: u64,
        decrypt: &PayloadReader<'_>,
    ) -> Result<Option<RebalanceOutcome>> {
        // Order ranges by numeric lo to find neighbours.
        let mut order: Vec<(usize, u128)> = manifest
            .segments
            .iter()
            .enumerate()
            .map(|(i, r)| Ok((i, parse_u128(&r.item_lo)?)))
            .collect::<Result<_>>()?;
        order.sort_by_key(|(_, lo)| *lo);
        let pos = order
            .iter()
            .position(|(i, _)| manifest.segments[*i].segment_id == seg_id);
        let Some(pos) = pos else {
            return Ok(None);
        };
        if manifest.segments.len() < 2 {
            return Ok(None);
        }

        // Prefer merging with the right neighbour, else the left.
        let neighbour = if pos + 1 < order.len() {
            Some(order[pos + 1].0)
        } else if pos >= 1 {
            Some(order[pos - 1].0)
        } else {
            None
        };
        let Some(nidx) = neighbour else {
            return Ok(None);
        };
        let neighbour_count = manifest.segments[nidx].item_count as usize;
        // Merge when the pair is genuinely under-full (combined below the merge
        // threshold, spec §3) OR when the touched segment is now empty — an
        // empty segment is pure overhead whose id range should fold into a
        // neighbour regardless of the neighbour's fill.
        if count > 0 && count + neighbour_count >= merge_threshold() {
            return Ok(None);
        }

        // Determine the surviving (lower) and dropped (higher) segment.
        let this_idx = order[pos].0;
        let this_lo = parse_u128(&manifest.segments[this_idx].item_lo)?;
        let nb_lo = parse_u128(&manifest.segments[nidx].item_lo)?;
        let (keep_idx, drop_idx) = if this_lo <= nb_lo {
            (this_idx, nidx)
        } else {
            (nidx, this_idx)
        };
        let keep_id = manifest.segments[keep_idx].segment_id;
        let drop_id = manifest.segments[drop_idx].segment_id;

        let merged_lo = parse_u128(&manifest.segments[keep_idx].item_lo)?;
        let merged_hi = parse_u128(&manifest.segments[drop_idx].item_hi)?;

        let merged =
            self.build_segment_from_range(tx, keep_id, new_gen, merged_lo, merged_hi, decrypt)?;

        // Update the manifest: extend keep's range, remove drop.
        manifest.segments[keep_idx].item_hi = merged_hi.to_string();
        manifest.segments[keep_idx].item_count =
            u32::try_from(merged.item_count()).unwrap_or(u32::MAX);
        manifest.segments[keep_idx].token_est = merged.token_est();
        manifest.segments.retain(|r| r.segment_id != drop_id);

        Ok(Some(RebalanceOutcome {
            persist: vec![merged],
            delete: vec![drop_id],
        }))
    }
}

/// The result of a rebalance: segments to (re)persist and rows to delete.
struct RebalanceOutcome {
    persist: Vec<SegmentData>,
    delete: Vec<i64>,
}

/// Which rebalancing may apply after a single-item change. An upsert only grows
/// a segment (so only a split can apply); a delete only shrinks it (so only a
/// merge can apply). Restricting the direction is what keeps an update
/// O(changed items): we never attempt an expensive merge on every insert.
#[derive(Clone, Copy)]
enum RebalanceMode {
    /// Growth path (create/update/restore): consider splitting an oversized
    /// segment.
    MaySplit,
    /// Shrink path (delete): consider merging an under-full segment.
    MayMerge,
}

/// Sort manifest ranges numerically by their `item_lo` bound. The bounds are
/// decimal `u128` strings, so we parse to compare (length-then-lexicographic
/// would also work for non-negative decimals, but parsing is unambiguous).
fn sort_ranges(ranges: &mut [SegmentRange]) {
    ranges.sort_by(|a, b| {
        let la = parse_u128(&a.item_lo).unwrap_or(0);
        let lb = parse_u128(&b.item_lo).unwrap_or(0);
        la.cmp(&lb)
    });
}

// --- Query path (spec §6) --------------------------------------------------

impl SearchIndex {
    /// Answer a query against the index, returning matching live item ids in
    /// rank order (exact > prefix > trigram; ties by ascending id for
    /// determinism). AND semantics across free terms and filters (spec §6).
    ///
    /// Repairs the manifest and any touched-but-stale segment lazily and
    /// in-transaction. Tombstoned ids are filtered as a final pass, so a stale
    /// segment that still lists a deleted item can never surface it (spec §5/§6
    /// defense-in-depth).
    ///
    /// A `type_filter` (from the legacy [`Vault::search`](crate::Vault::search)
    /// signature) is applied as an additional `type:` filter.
    pub(crate) fn query(
        &self,
        conn: &mut Connection,
        query: &str,
        type_filter: Option<&str>,
        decrypt: &PayloadReader<'_>,
    ) -> Result<Vec<ItemId>> {
        // All index reads happen in a transaction so any lazy repair commits.
        let tx = conn.transaction()?;
        let result = self.query_in_tx(&tx, query, type_filter, decrypt)?;
        tx.commit()?;
        Ok(result)
    }

    /// The query body, running inside `tx` (lazy repairs persist on commit).
    fn query_in_tx(
        &self,
        tx: &Connection,
        query: &str,
        type_filter: Option<&str>,
        decrypt: &PayloadReader<'_>,
    ) -> Result<Vec<ItemId>> {
        let mut parsed = ParsedQuery::parse(query);
        if let Some(t) = type_filter {
            let t_norm = t.nfkc().collect::<String>().to_lowercase();
            if !t_norm.is_empty() {
                parsed.filters.push(format!("type:{t_norm}"));
            }
        }

        let manifest = self.ensure_manifest(tx, decrypt)?;
        let generation = Self::read_generation(tx)?;

        // Load every data segment (repairing stale ones), building a unified
        // in-memory view. For a 10k-item vault this is ~40 small segments.
        let mut segments = Vec::with_capacity(manifest.segments.len());
        for range in &manifest.segments {
            let seg = self.ensure_segment(tx, &manifest, range.segment_id, generation, decrypt)?;
            segments.push(seg);
        }

        // Unconstrained query → every live item (matches linear-fallback).
        if parsed.is_unconstrained() {
            let mut ids: Vec<ItemId> = segments
                .iter()
                .flat_map(|s| s.item_tokens.keys())
                .filter_map(|k| key_to_id(k).ok())
                .collect();
            ids.sort_by_key(id_to_u128);
            return self.drop_tombstoned(tx, ids);
        }

        // Candidate set + per-item best rank, intersected across terms/filters
        // (AND semantics, spec §6).
        let mut candidates: Option<BTreeMap<u128, MatchRank>> = None;

        for term in &parsed.terms {
            let matches = Self::match_term(&segments, term);
            candidates = Some(Self::intersect(candidates, matches));
            if candidates.as_ref().is_some_and(BTreeMap::is_empty) {
                return Ok(Vec::new());
            }
        }

        for filter in &parsed.filters {
            let matches: BTreeMap<u128, MatchRank> = Self::posting_ids(&segments, filter)
                .into_iter()
                .map(|id| (id, MatchRank::Exact))
                .collect();
            candidates = Some(Self::intersect(candidates, matches));
            if candidates.as_ref().is_some_and(BTreeMap::is_empty) {
                return Ok(Vec::new());
            }
        }

        let candidates = candidates.unwrap_or_default();

        // Rank: exact > prefix > trigram, tie-break by ascending id.
        let mut ranked: Vec<(MatchRank, u128)> = candidates
            .into_iter()
            .map(|(id, rank)| (rank, id))
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

        let ids: Vec<ItemId> = ranked
            .into_iter()
            .map(|(_, id)| Id::from_bytes(id.to_be_bytes()))
            .collect();
        self.drop_tombstoned(tx, ids)
    }

    /// The postings (as `u128` keys) for an exact token across all segments.
    fn posting_ids(segments: &[SegmentData], token: &str) -> BTreeSet<u128> {
        let mut out = BTreeSet::new();
        for seg in segments {
            if let Some(ids) = seg.postings.get(token) {
                for k in ids {
                    if let Ok(v) = parse_u128(k) {
                        out.insert(v);
                    }
                }
            }
        }
        out
    }

    /// Item ids whose indexed WORDS include one strictly extending `prefix`
    /// (i.e. `prefix` is a proper prefix of an indexed word). Range-scans each
    /// segment's sorted `postings` map over `[prefix, prefix++)`, skipping the
    /// structural namespaces (`tag:`/`type:`/`folder:`/`fav:`/`url:`/`host:`/
    /// `tri:`) and the exact-equal key (that is the Exact tier). Because
    /// `postings` is a `BTreeMap`, the scan visits only the matching keys.
    fn prefix_ids(segments: &[SegmentData], prefix: &str) -> BTreeSet<u128> {
        let mut out = BTreeSet::new();
        if prefix.is_empty() {
            return out;
        }
        for seg in segments {
            for (key, ids) in seg.postings.range(prefix.to_string()..) {
                if !key.starts_with(prefix) {
                    break; // past the prefix run (keys are sorted).
                }
                if key == prefix {
                    continue; // exact match is the Exact tier, not Prefix.
                }
                // Only plain word keys participate in prefix search; structural
                // namespaces carry a `:` and are matched exactly via filters.
                if key.contains(':') {
                    continue;
                }
                for k in ids {
                    if let Ok(v) = parse_u128(k) {
                        out.insert(v);
                    }
                }
            }
        }
        out
    }

    /// Compute the best match rank per item for one free query term, trying the
    /// exact word, then prefix, then trigram/fuzzy tiers (spec §6). A term
    /// contributes a candidate iff it matches in at least one tier.
    fn match_term(segments: &[SegmentData], term: &str) -> BTreeMap<u128, MatchRank> {
        let mut best: BTreeMap<u128, MatchRank> = BTreeMap::new();

        // Exact word hit.
        for id in Self::posting_ids(segments, term) {
            best.entry(id)
                .and_modify(|r| *r = (*r).max(MatchRank::Exact))
                .or_insert(MatchRank::Exact);
        }
        // Prefix hit: the query term is a prefix of an indexed WORD. We
        // range-scan each segment's postings for word keys in `[term, term++)`
        // (all keys that start with `term`), skipping the `tag:`/`type:`/`tri:`
        // structural namespaces and the exact-equal key (already Exact above).
        for id in Self::prefix_ids(segments, term) {
            best.entry(id)
                .and_modify(|r| *r = (*r).max(MatchRank::Prefix))
                .or_insert(MatchRank::Prefix);
        }
        // Trigram/fuzzy: count, per item, how many of the term's distinct
        // trigrams it shares, and match when the overlap clears a similarity
        // threshold. This tolerates a typo (which perturbs only a few grams)
        // while a query sharing almost nothing with a title does not match.
        let grams: BTreeSet<String> = Tokenizer::trigrams(term).into_iter().collect();
        if !grams.is_empty() {
            let mut shared: BTreeMap<u128, usize> = BTreeMap::new();
            for g in &grams {
                for id in Self::posting_ids(segments, g) {
                    *shared.entry(id).or_insert(0) += 1;
                }
            }
            // Similarity threshold: require sharing at least HALF of the query's
            // distinct trigrams (min 1). A single-character substitution or
            // transposition — the common typo classes — perturbs only a couple
            // of grams, so a genuinely mistyped title still clears half; but two
            // distinct real words that merely share a common stem (e.g. "github"
            // vs "gitlab", sharing only "git") stay below half and do NOT
            // collide. Trigram hits rank LAST (spec §6), demoted below any
            // exact/prefix hit.
            let need = grams.len().div_ceil(2).max(1);
            for (id, count) in shared {
                if count >= need {
                    best.entry(id).or_insert(MatchRank::Trigram);
                }
            }
        }
        best
    }

    /// Intersect a running candidate map with the next term's matches, keeping
    /// the WEAKER of the two ranks so a term only ever demotes an item's rank
    /// (AND semantics; an item's final rank is the weakest tier any term used).
    fn intersect(
        acc: Option<BTreeMap<u128, MatchRank>>,
        next: BTreeMap<u128, MatchRank>,
    ) -> BTreeMap<u128, MatchRank> {
        match acc {
            None => next,
            Some(prev) => prev
                .into_iter()
                .filter_map(|(id, r1)| next.get(&id).map(|r2| (id, r1.min(*r2))))
                .collect(),
        }
    }

    /// Final tombstone pass (spec §6 step 5): drop any id that has a tombstone,
    /// so a stale segment can never surface a deleted item.
    fn drop_tombstoned(&self, conn: &Connection, ids: Vec<ItemId>) -> Result<Vec<ItemId>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let tombstoned: bool = conn
                .query_row(
                    "SELECT 1 FROM tombstones WHERE item_id = ?1",
                    params![id.to_vec()],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if !tombstoned {
                out.push(id);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{Field, FieldKind, TypeData};
    use serde_json::json;

    #[test]
    fn id_u128_roundtrips_and_preserves_order() {
        let a = Id::from_bytes([0x00; 16]);
        let b = Id::from_bytes([0xFF; 16]);
        assert!(id_to_u128(&a) < id_to_u128(&b));
        // Round-trip via the decimal key form.
        let k = id_key(&b);
        assert_eq!(key_to_id(&k).unwrap(), b);
        // u128::MAX and MIN survive the string round-trip.
        assert_eq!(parse_u128(&u128::MAX.to_string()).unwrap(), u128::MAX);
        assert_eq!(parse_u128(&u128::MIN.to_string()).unwrap(), u128::MIN);
    }

    #[test]
    fn words_normalize_lowercase_and_split_on_punctuation() {
        let w = Tokenizer::words("ACME  prod-DB, v2!");
        assert_eq!(w, vec!["acme", "prod", "db", "v2"]);
    }

    #[test]
    fn nfkc_folds_compatibility_forms() {
        // Fullwidth "ＡＢＣ" (U+FF21..) NFKC-folds to ascii "abc".
        let w = Tokenizer::words("\u{ff21}\u{ff22}\u{ff23}");
        assert_eq!(w, vec!["abc"]);
    }

    #[test]
    fn trigrams_cover_typos() {
        // "github" and a typo "guthub" share most trigrams.
        let a: BTreeSet<String> = Tokenizer::trigrams("github").into_iter().collect();
        let b: BTreeSet<String> = Tokenizer::trigrams("guthub").into_iter().collect();
        let shared = a.intersection(&b).count();
        assert!(shared >= 2, "typo should still share trigrams: {shared}");
    }

    #[test]
    fn url_tokens_extract_host() {
        let t = Tokenizer::url_tokens("https://user:pw@Sub.Example.COM:8443/path?q=1");
        assert!(t.contains(&"host:sub.example.com".to_string()));
        assert!(t.iter().any(|x| x.starts_with("url:")));
    }

    #[test]
    fn item_tokens_never_index_password_values() {
        let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, "GitHub");
        p.fields = vec![
            Field {
                name: "username".into(),
                kind: FieldKind::Text,
                value: json!("octocat"),
            },
            Field {
                name: "password".into(),
                kind: FieldKind::Hidden,
                value: json!("s3cr3t-value"),
            },
        ];
        let tokens = Tokenizer::item_tokens(&p);
        // The username value IS indexed (searchable handle).
        assert!(tokens.contains("octocat"));
        // The field NAME "password" is indexed...
        assert!(tokens.contains("password"));
        // ...but the secret VALUE never is.
        assert!(!tokens.iter().any(|t| t.contains("s3cr3t")));
    }

    #[test]
    fn item_tokens_index_filters_and_tags() {
        let mut p = ItemPayload::new(
            TypeData::SshKey {
                algo: String::new(),
                private_pem: "-----BEGIN-----secret".into(),
                public_openssh: String::new(),
                fingerprint: String::new(),
            },
            "deploy key",
        );
        p.tags = vec!["prod".into()];
        p.favorite = true;
        p.folder_id = Some("Work".into());
        let tokens = Tokenizer::item_tokens(&p);
        assert!(tokens.contains("type:ssh_key"));
        assert!(tokens.contains("tag:prod"));
        assert!(tokens.contains("folder:work"));
        assert!(tokens.contains("fav:true"));
        // The private key material must never be indexed.
        assert!(!tokens.iter().any(|t| t.contains("secret")));
        assert!(!tokens.iter().any(|t| t.contains("begin")));
    }

    #[test]
    fn segment_upsert_and_remove_are_symmetric() {
        let mut seg = SegmentData::empty(1, 0);
        let mut toks = BTreeSet::new();
        toks.insert("alpha".to_string());
        toks.insert("beta".to_string());
        seg.upsert_item("42", &toks);
        assert_eq!(seg.item_count(), 1);
        assert_eq!(seg.postings["alpha"], vec!["42".to_string()]);
        seg.remove_item("42");
        assert_eq!(seg.item_count(), 0);
        assert!(seg.postings.is_empty(), "postings cleaned up on remove");
    }

    #[test]
    fn segment_upsert_diffs_dropped_tokens() {
        let mut seg = SegmentData::empty(1, 0);
        let mut t1 = BTreeSet::new();
        t1.insert("old".to_string());
        seg.upsert_item("7", &t1);
        let mut t2 = BTreeSet::new();
        t2.insert("new".to_string());
        seg.upsert_item("7", &t2);
        assert!(!seg.postings.contains_key("old"), "dropped token removed");
        assert_eq!(seg.postings["new"], vec!["7".to_string()]);
    }

    #[test]
    fn parsed_query_splits_filters_and_terms() {
        let q = ParsedQuery::parse("github type:login tag:dev fav:");
        assert_eq!(q.terms, vec!["github"]);
        assert!(q.filters.contains(&"type:login".to_string()));
        assert!(q.filters.contains(&"tag:dev".to_string()));
        assert!(q.filters.contains(&"fav:true".to_string()));
    }

    #[test]
    fn match_rank_ordering() {
        assert!(MatchRank::Exact > MatchRank::Prefix);
        assert!(MatchRank::Prefix > MatchRank::Trigram);
    }

    #[test]
    fn same_tokens_yield_identical_segment_plaintext() {
        // The determinism guarantee (spec §3, vault-format.md §4): the same
        // logical segment content serializes to byte-identical canonical
        // plaintext, so the ciphertext is reproducible for a given plaintext.
        let build = || {
            let mut seg = SegmentData::empty(3, 7);
            // Insert two items in DIFFERENT orders across the two builds; the
            // BTreeMap + sorted posting lists must canonicalize both identically.
            let mut a = BTreeSet::new();
            a.insert("zeta".to_string());
            a.insert("alpha".to_string());
            let mut b = BTreeSet::new();
            b.insert("alpha".to_string());
            b.insert("mid".to_string());
            seg.upsert_item("200", &b);
            seg.upsert_item("100", &a);
            canonical::to_canonical_vec(&seg).unwrap()
        };
        let build_reordered = || {
            let mut seg = SegmentData::empty(3, 7);
            let mut a = BTreeSet::new();
            a.insert("alpha".to_string());
            a.insert("zeta".to_string());
            let mut b = BTreeSet::new();
            b.insert("mid".to_string());
            b.insert("alpha".to_string());
            // Reverse insertion order of the two items.
            seg.upsert_item("100", &a);
            seg.upsert_item("200", &b);
            canonical::to_canonical_vec(&seg).unwrap()
        };
        assert_eq!(
            build(),
            build_reordered(),
            "segment plaintext must be independent of insertion order"
        );
    }

    #[test]
    fn manifest_owning_segment_tiles_the_space() {
        let m = Manifest {
            index_format_version: INDEX_FORMAT_VERSION,
            generation: 1,
            segment_count: 2,
            item_count: 0,
            segments: vec![
                SegmentRange {
                    segment_id: 1,
                    item_lo: u128::MIN.to_string(),
                    item_hi: "999".to_string(),
                    item_count: 0,
                    token_est: 0,
                },
                SegmentRange {
                    segment_id: 2,
                    item_lo: "1000".to_string(),
                    item_hi: u128::MAX.to_string(),
                    item_count: 0,
                    token_est: 0,
                },
            ],
        };
        assert_eq!(m.owning_segment(0).unwrap(), 1);
        assert_eq!(m.owning_segment(999).unwrap(), 1);
        assert_eq!(m.owning_segment(1000).unwrap(), 2);
        assert_eq!(m.owning_segment(u128::MAX).unwrap(), 2);
    }
}
