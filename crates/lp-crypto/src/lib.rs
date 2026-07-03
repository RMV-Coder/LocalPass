#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_errors_doc)]
//! # LocalPass cryptographic core (`lp-crypto`)
//!
//! This crate is the **only** place in the LocalPass workspace that may depend
//! on cryptographic primitive crates (RustCrypto + dalek). Everything else
//! consumes the misuse-resistant, high-level API exposed here (PRD §6.2).
//! It is designed for auditability: small modules, one construction each, heavy
//! doc comments tying every choice back to the PRD.
//!
//! ## Design invariants
//!
//! - `#![forbid(unsafe_code)]` — no `unsafe` anywhere (PRD §5.1 memory safety).
//! - Every secret type is [`zeroize`]d on drop, has a redacting `Debug`, and is
//!   deliberately **not** `Clone`/`Serialize` unless justified.
//! - Every derivation and purpose label is domain-separated and **must** start
//!   with `localpass/v1/` (enforced at runtime, see [`kdf`]).
//! - All authentication/decryption failures collapse to a single opaque
//!   [`Error::DecryptionFailed`] (no oracles, see [`error`]).
//! - Crypto agility is by **versioned format headers**, never runtime
//!   negotiation (PRD §5.1) — every wire format leads with a version byte.
//!
//! ## Key hierarchy (PRD §4.3)
//!
//! ```text
//!   master password ─┐
//!                    ├─ derive_master_unlock_key ─▶ MasterUnlockKey (MUK)
//!        SecretKey ──┘        (Argon2id → HKDF)             │ wrap_key / unwrap_key
//!                                                           ▼
//!                                                        AccountKey
//!                                                           │ wrap_key / unwrap_key
//!                                                           ▼
//!                                                        VaultKey ──▶ IndexKey
//!                                                           │          (derive_subkey
//!                                                           │           "localpass/v1/index")
//!                                                           ▼
//!                                                        ItemKey ──▶ seal / open item payloads
//! ```
//!
//! - [`SecretKey`] — 128-bit second KDF factor (1Password-style), with a
//!   printable, checksummed [`SecretKey::to_display_string`] encoding.
//! - [`derive_master_unlock_key`] — Argon2id over the password, then HKDF
//!   combining it with the Secret Key (label `localpass/v1/muk`).
//! - [`MasterUnlockKey`] / [`AccountKey`] / [`VaultKey`] / [`ItemKey`] —
//!   distinct newtypes over the same 256-bit [`SymmetricKey`] core so roles
//!   cannot be cross-used by accident.
//! - [`SymmetricKey::seal`] / [`SymmetricKey::open`] — XChaCha20-Poly1305 AEAD
//!   producing an [`Envelope`] (`0x01 || nonce(24) || ct+tag`), AAD out-of-band.
//! - [`wrap_key`] / [`unwrap_key`] — wrap one key under another, bound to a
//!   mandatory namespaced purpose.
//! - [`seal_for`] / [`SealingKeyPair::open`] — X25519 age-style sealing to a
//!   recipient public key.
//! - [`SigningKeyPair`] / [`VerifyingKey`] — Ed25519 signatures with a
//!   mandatory, length-prefixed domain-separation context.
//!
//! ## Cryptographic standards (PRD §5.2)
//!
//! | Purpose | Primitive |
//! |---------|-----------|
//! | Password KDF | Argon2id (`argon2`) |
//! | Key mixing / subkeys | HKDF-SHA256 (`hkdf` + `sha2`) |
//! | Symmetric AEAD | XChaCha20-Poly1305 (`chacha20poly1305`) |
//! | Asymmetric sealing | X25519 (`x25519-dalek`) + XChaCha20-Poly1305 |
//! | Signatures | Ed25519 (`ed25519-dalek`) |
//! | RNG | OS CSPRNG only (`getrandom` / `OsRng`) |

// --- Modules -------------------------------------------------------------

pub mod envelope;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod keys;
pub mod params;
pub mod seal;
pub mod sign;
pub mod wrap;

// Internal-only implementation modules (not part of the public surface).
mod muk;
mod secretkey;
mod symmetric;

// --- Curated re-exports (the ergonomic top-level API) --------------------

pub use envelope::Envelope;
pub use error::{Error, Result};
pub use hash::blake3_256;
pub use keys::{
    AccountKey, ItemKey, MasterUnlockKey, SECRET_KEY_LEN, SYMMETRIC_KEY_LEN, SecretKey,
    SymmetricKey, VaultKey,
};
pub use muk::derive_master_unlock_key;
pub use params::KdfParams;
pub use seal::{PublicSealingKey, SealingKeyPair, seal_for};
pub use sign::{SigningKeyPair, VerifyingKey};
pub use wrap::{unwrap_key, wrap_key};
