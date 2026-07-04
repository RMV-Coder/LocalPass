#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! # LocalPass sync engine (`lp-sync`)
//!
//! `lp-sync` implements the sync model specified in `docs/specs/sync-protocol.md`:
//! op-log **ingest verification** (§5), the deterministic **total-merge** (§4),
//! and **file-based log shipping** (§7), plus the offline **device-pairing
//! groundwork** (§6). It drives the storage core through `lp-vault`'s additive
//! foreign-op API (`lp_vault::foreign`) so the op log, materialized item state,
//! and the encrypted search index stay consistent in one transaction
//! (vault-format.md §7). It consumes only the high-level `lp-crypto` API and
//! holds **no** cryptographic primitive (the crypto-boundary rule, `LESSONS.md`).
//!
//! ## The three layers
//!
//! - [`verify`] — the §5 ingest verifier: per-device signature, `seq`
//!   contiguity (gap → pending, replay/regression → alarm), `prev_hash` chain,
//!   and Lamport monotonicity, with typed [`Alarm`]s and quarantine.
//! - [`merge`] — the §4 deterministic total-merge: total order
//!   `(lamport, device_id, op_id)`, per-field (whole-snapshot) LWW with loser
//!   preservation, delete/restore/edit resolution, and version-number
//!   assignment by ascending total order — a pure function of the op set.
//! - [`shipping`] — the §7 file layout: immutable `.oplog` segments per device,
//!   the advisory (untrusted) `manifest.json`, chain heads, and the `keys/`
//!   share dir; a writer and a reader that round-trips through [`wire`].
//!
//! [`engine`] ties them together for the CLI: `setup` / `push` / `pull` /
//! `status`. [`identity`] provides the export/trust pairing strings + fingerprint.
//!
//! ## Convergence guarantee (§4.4)
//!
//! Materialization depends only on the **set** of ops, folded in total order —
//! never on arrival order. Version numbers are assigned deterministically by
//! ascending total order, so every device produces byte-identical
//! `(items, item_versions, tombstones)` state, and no conflicting write is ever
//! discarded (losers are preserved as real version rows). This is exercised by
//! the permutation-convergence property test (`tests/convergence.rs`).
//!
//! ## Zero-trust channel (§5, §9)
//!
//! The file channel is fully untrusted. A malicious host cannot forge an op (no
//! device signing key), cannot relocate/alter ciphertext (Ed25519 over the wire
//! form + AEAD AAD), and cannot silently drop/replay/reorder (per-device `seq`
//! gaplessness + `prev_hash` chain + Lamport monotonicity, all checked on
//! ingest — PRD §8 T5/T13). The `manifest.json` is advisory only and can never
//! inject state.
//!
//! ## Cross-device VaultKey sharing
//!
//! `vault share-to-device` seals the VaultKey (and the vault name) to a peer's
//! X25519 key through `lp-crypto`'s **typed key transport**
//! (`seal_key_for` → `SealingKeyPair::open_key`) — raw key bytes never cross
//! any public API. The blob ships via the channel's `keys/` dir; the peer
//! imports it with `sync adopt` (or automatically during `pull` when already
//! enrolled), which registers the vault locally and re-wraps the key under the
//! peer's own AccountKey. AADs bind vault id + recipient device id, so a blob
//! cannot be replayed for a different vault or presented to a different device.

pub mod engine;
pub mod error;
pub mod identity;
pub mod merge;
pub mod shipping;
pub mod verify;
pub mod wire;

pub use error::{Alarm, Error, Quarantine, Result};
pub use identity::DeviceIdentity;
