#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! # LocalPass import/export (`lp-porter`)
//!
//! `lp-porter` parses foreign password-manager exports into LocalPass
//! [`ItemPayload`](lp_vault::ItemPayload) values, and writes/reads the
//! **recoverable age-encrypted archive** and the guarded plaintext exports
//! (PRD §4.6 import/export, §6.9 the age exit hatch).
//!
//! The crate is deliberately **I/O-only**: importers turn bytes into a `Vec<`
//! [`ItemPayload`](lp_vault::ItemPayload)`>` and exporters turn items into
//! bytes. It never opens a vault, never persists anything, and never deletes the
//! user's input files — the caller (the CLI) owns storage and the daemon/unlock
//! path.
//!
//! ## The crypto boundary (read this)
//!
//! LocalPass's rule is that `lp-crypto` is the **sole** home for LocalPass's
//! *own* vault crypto — envelopes, KDF, key wrapping, sealing, signing. This
//! crate does **not** touch any of that. It never derives a vault key, never
//! wraps an item key, never constructs a LocalPass envelope.
//!
//! What this crate *does* do is read and write **foreign** cryptographic
//! formats, which are I/O against external standards, not LocalPass crypto:
//!
//! - The [`age`] archive ([`export::archive`]) is written and read with the
//!   `age` crate directly, using a passphrase (scrypt) recipient. This is the
//!   *whole point* of the exit hatch: the archive must be decryptable by the
//!   standalone `age` CLI, so we produce the standard age binary format rather
//!   than anything LocalPass-specific.
//! - KDBX import decryption, *if* implemented, would use the `keepass` crate the
//!   same way — reading someone else's format.
//!
//! That is the entire exception. `lp-porter` is allowed to depend on `age`
//! (and, for KDBX, `keepass`) for **foreign-format** reading/writing; it is
//! still forbidden from reimplementing or calling LocalPass envelope crypto.
//!
//! ## Importers (parse a foreign export → `Vec<ItemPayload>`)
//!
//! | Format | Module | Status |
//! |--------|--------|--------|
//! | 1Password `.1pux` | [`import::onepux`] | implemented |
//! | Bitwarden JSON | [`import::bitwarden`] | implemented |
//! | LastPass CSV | [`import::lastpass`] | implemented |
//! | Generic CSV (column map) | [`import::csv_generic`] | implemented |
//! | `.env` file | [`import::dotenv`] | implemented |
//! | KeePass KDBX 4 | [`import::kdbx`] | implemented (AES-256 / Argon2) |
//!
//! Every importer returns an [`ImportOutcome`]: the successfully parsed items
//! plus a list of **skipped** entries reported by *title only* — a partial parse
//! imports what it can and never surfaces a secret value in a skip report.
//!
//! ## Exporters (items → bytes)
//!
//! - [`export::archive`] — the age-encrypted, tar-wrapped, documented JSON
//!   archive (the recoverable exit hatch). Also re-importable here.
//! - [`export::plaintext`] — full-secret JSON and CSV, for callers that have
//!   already obtained explicit user consent (the CLI gates this behind
//!   `--i-understand-plaintext-export`).
//! - [`export::dotenv`] — one env-set item → `KEY=value` lines.
//!
//! ## Secret hygiene
//!
//! No secret value is ever placed in a log line, an error message, or a skip
//! report anywhere in this crate. Errors carry only structural context (a line
//! number, a field *name*, a title). The age passphrase is handled as
//! [`zeroize`]-on-drop bytes.

pub mod error;
pub mod export;
pub mod import;
pub mod model;

pub use error::{PorterError, Result};
pub use model::{ImportOutcome, SkippedEntry};
